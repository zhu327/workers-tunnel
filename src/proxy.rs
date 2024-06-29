use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::utils::is_cloudflare;
use crate::ws::WebSocketStream;
use base64::{decode_config, URL_SAFE_NO_PAD};
use tokio::io::{copy_bidirectional, AsyncReadExt};
use uuid::Uuid;
use worker::{console_debug, Socket};

pub fn parse_early_data(data: Option<String>) -> Result<Option<Vec<u8>>> {
    if let Some(data) = data {
        if !data.is_empty() {
            let s = data.replace('+', "-").replace('/', "_").replace("=", "");
            match decode_config(s, URL_SAFE_NO_PAD) {
                Ok(early_data) => return Ok(Some(early_data)),
                Err(err) => return Err(Error::new(ErrorKind::Other, err.to_string())),
            }
        }
    }
    Ok(None)
}

pub async fn run_tunnel(
    mut client_socket: WebSocketStream<'_>,
    user_id: &Uuid,
    proxy_ip: &str,
) -> Result<()> {
    // process request

    // read version
    let mut prefix = [0u8; 18];
    client_socket.read_exact(&mut prefix).await?;

    if prefix[0] != 0 {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "invalid client protocol version, expected 0, got {}",
                prefix[0]
            ),
        ))?
    }

    // verify user id
    if &prefix[1..17] != user_id.as_bytes().as_slice() {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid user id",
        ))?
    }

    {
        // ignore addons
        let addon_length = prefix[17];
        let mut addon_bytes = vec![0; addon_length as usize];
        client_socket.read_exact(addon_bytes.as_mut()).await?;
    }

    // parse remote address
    let mut address_prefix = [0u8; 4];
    client_socket.read_exact(&mut address_prefix).await?;

    match address_prefix[0] {
        1 => {
            // tcp, noop.
        }
        2 => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "UDP was requested",
        ))?,
        unknown_protocol_type => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid requested protocol: {}", unknown_protocol_type),
        ))?,
    }

    let port = ((address_prefix[1] as u16) << 8) | (address_prefix[2] as u16);
    let mut remote_addr = match address_prefix[3] {
        1 => {
            // 4 byte ipv4 address
            let mut address_bytes = [0u8; 4];
            client_socket.read_exact(&mut address_bytes).await?;

            Ipv4Addr::new(
                address_bytes[0],
                address_bytes[1],
                address_bytes[2],
                address_bytes[3],
            )
            .to_string()
        }
        2 => {
            // domain name
            let mut domain_name_len = [0u8; 1];
            client_socket.read_exact(&mut domain_name_len).await?;

            let mut domain_name_bytes = vec![0; domain_name_len[0] as usize];
            client_socket.read_exact(&mut domain_name_bytes).await?;

            let address_str = match std::str::from_utf8(&domain_name_bytes) {
                Ok(s) => s,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid address: {}", e),
                    ));
                }
            };
            address_str.to_string()
        }
        3 => {
            // 16 byte ipv6 address
            let mut address_bytes = [0u8; 16];
            client_socket.read_exact(&mut address_bytes).await?;

            let v6addr = Ipv6Addr::new(
                ((address_bytes[0] as u16) << 8) | (address_bytes[1] as u16),
                ((address_bytes[2] as u16) << 8) | (address_bytes[3] as u16),
                ((address_bytes[4] as u16) << 8) | (address_bytes[5] as u16),
                ((address_bytes[6] as u16) << 8) | (address_bytes[7] as u16),
                ((address_bytes[8] as u16) << 8) | (address_bytes[9] as u16),
                ((address_bytes[10] as u16) << 8) | (address_bytes[11] as u16),
                ((address_bytes[12] as u16) << 8) | (address_bytes[13] as u16),
                ((address_bytes[14] as u16) << 8) | (address_bytes[15] as u16),
            );
            format!("[{}]", v6addr)
        }
        invalid_type => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid address type: {}", invalid_type),
            ));
        }
    };

    // connect to remote socket
    if is_cloudflare(&remote_addr).await.unwrap_or(false) {
        console_debug!("remote {} is cloudflare, using proxy_ip", remote_addr);
        remote_addr = proxy_ip.to_string();
    }

    let mut remote_socket = match Socket::builder().connect(remote_addr.clone(), port) {
        Ok(socket) => socket,
        Err(e) => {
            console_debug!(
                "connect to remote {}:{} error: {}",
                remote_addr,
                port,
                e.to_string()
            );
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                e.to_string(),
            ))?
        }
    };

    copy_bidirectional(&mut client_socket, &mut remote_socket).await?;

    Ok(())
}
