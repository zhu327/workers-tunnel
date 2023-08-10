use crate::proxy::{parse_early_data, run_tunnel};
use crate::websocket::WebSocketConnection;
use worker::*;

const CLIENT_ID: &str = "18ad2c9c-a88b-48e8-aa64-5dee0045c282";

#[event(fetch)]
async fn main(req: Request, _env: Env, _: Context) -> Result<Response> {
    // ready early data
    let early_data = req.headers().get("sec-websocket-protocol")?;
    let early_data = parse_early_data(early_data)?;

    // Accept / handle a websocket connection
    let pair = WebSocketPair::new()?;
    let server = pair.server;
    server.accept()?;

    wasm_bindgen_futures::spawn_local(async move {
        console_debug!("websocket connection established");
        let event_stream = server.events().expect("could not open stream");

        let socket = WebSocketConnection::new(&server, event_stream, early_data);
        run_tunnel(socket).await.unwrap_or_default();
    });

    Response::from_websocket(pair.client)
}

mod proxy {
    use std::io::Result;
    use std::io::{Error, ErrorKind};
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::websocket::WebSocketConnection;
    use crate::CLIENT_ID;
    use base64::decode;
    use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
    use worker::Socket;
    use worker::console_debug;

    pub fn parse_early_data(data: Option<String>) -> Result<Option<Vec<u8>>> {
        if let Some(data) = data {
            if data.len() > 0 {
                match decode(&data) {
                    Ok(early_data) => return Ok(Some(early_data)),
                    Err(err) => return Err(Error::new(ErrorKind::Other, err)),
                }
            }
        }
        Ok(None)
    }

    pub async fn run_tunnel(mut server_socket: WebSocketConnection<'_>) -> Result<()> {
        console_debug!("run_tunnel");
        let mut prefix = [0u8; 18];
        server_socket.read_exact(&mut prefix).await?;

        console_debug!("prefix: {:?}", prefix);

        if prefix[0] != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "invalid client protocol version, expected 0, got {}",
                    prefix[0]
                ),
            ));
        }

        let target_id = &prefix[1..17];
        for (b1, b2) in parse_hex(CLIENT_ID).iter().zip(target_id.iter()) {
            if b1 != b2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Unknown client id",
                ));
            }
        }

        {
            // ignore addons
            let addon_length = prefix[17];
            let mut addon_bytes = allocate_vec(addon_length as usize).into_boxed_slice();
            server_socket.read_exact(&mut addon_bytes).await?;
        }

        let mut address_prefix = [0u8; 4];
        server_socket.read_exact(&mut address_prefix).await?;

        match address_prefix[0] {
            1 => {
                // tcp, noop.
            }
            2 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "UDP was requested",
                ));
            }
            unknown_protocol_type => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unknown requested protocol: {}", unknown_protocol_type),
                ));
            }
        }

        let port = ((address_prefix[1] as u16) << 8) | (address_prefix[2] as u16);

        let remote_addr = match address_prefix[3] {
            1 => {
                // 4 byte ipv4 address
                let mut address_bytes = [0u8; 4];
                server_socket.read_exact(&mut address_bytes).await?;

                let v4addr: Ipv4Addr = Ipv4Addr::new(
                    address_bytes[0],
                    address_bytes[1],
                    address_bytes[2],
                    address_bytes[3],
                );
                v4addr.to_string()
            }
            2 => {
                // domain name
                let mut domain_name_len = [0u8; 1];
                server_socket.read_exact(&mut domain_name_len).await?;

                let mut domain_name_bytes = allocate_vec(domain_name_len[0] as usize);
                server_socket.read_exact(&mut domain_name_bytes).await?;

                let address_str = match std::str::from_utf8(&domain_name_bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Failed to decode address: {}", e),
                        ));
                    }
                };
                address_str.to_string()
            }
            3 => {
                // 16 byte ipv6 address
                let mut address_bytes = [0u8; 16];
                server_socket.read_exact(&mut address_bytes).await?;

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
                v6addr.to_string()
            }
            invalid_type => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid address type: {}", invalid_type),
                ));
            }
        };

        console_debug!("{}:{}", remote_addr, port);

        let mut remote_socket = match Socket::builder().connect(remote_addr, port) {
            Ok(socket) => socket,
            Err(e) => {
                server_socket.close();

                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    e.to_string(),
                ));
            }
        };

        // write response
        server_socket
            .write(&[
                0u8, // version
                0u8, // addons length
            ])
            .await?;

        copy_bidirectional(&mut server_socket, &mut remote_socket).await?;

        Ok(())
    }

    fn parse_hex(hex_asm: &str) -> Box<[u8]> {
        let mut hex_bytes = hex_asm
            .as_bytes()
            .iter()
            .filter_map(|b| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            })
            .fuse();

        let mut bytes = Vec::new();
        while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
            bytes.push(h << 4 | l)
        }
        bytes.into_boxed_slice()
    }

    fn allocate_vec<T>(len: usize) -> Vec<T> {
        let mut ret = Vec::with_capacity(len);
        unsafe {
            ret.set_len(len);
        }
        ret
    }
}

mod websocket {
    use futures_util::Stream;
    use std::io::Error;
    use std::io::Result;
    use std::{
        io::ErrorKind,
        pin::Pin,
        task::{Context, Poll},
    };

    use pin_project::pin_project;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use worker::{EventStream, WebSocket, WebsocketEvent};
    use worker::console_debug;

    #[pin_project]
    pub struct WebSocketConnection<'a> {
        ws: &'a WebSocket,
        #[pin]
        stream: EventStream<'a>,

        early_data: Option<Vec<u8>>,
    }

    impl<'a> WebSocketConnection<'a> {
        pub fn new(
            ws: &'a WebSocket,
            stream: EventStream<'a>,
            early_data: Option<Vec<u8>>,
        ) -> Self {
            Self {
                ws,
                stream,
                early_data: early_data,
            }
        }

        pub fn close(self) {
            self.ws
                .close(Some(1000), Some("Normal close"))
                .unwrap_or(());
        }
    }

    impl<'a> AsyncRead for WebSocketConnection<'a> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<()>> {
            console_debug!("poll_read");
            let this = self.project();

            if let Some(early_data) = this.early_data {
                buf.put_slice(early_data);

                *this.early_data = None;
                return Poll::Ready(Ok(()));
            }

            let item = futures_util::ready!(this.stream.poll_next(cx));
            match item {
                Some(Ok(WebsocketEvent::Message(msg))) => {
                    if let Some(data) = msg.bytes() {
                        console_debug!("poll_read: {:?}", data);
                        buf.put_slice(&data);
                        console_debug!("poll_read put ok");
                    };
                    return Poll::Ready(Ok(()));
                }
                Some(Ok(WebsocketEvent::Close(_))) => {
                    Poll::Ready(Err(Error::new(ErrorKind::Other, "Connection closed")))
                }
                Some(Err(e)) => Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string()))),
                None => Poll::Ready(Err(Error::new(ErrorKind::Other, "Connection closed"))),
            }
        }
    }

    impl<'a> AsyncWrite for WebSocketConnection<'a> {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize>> {
            let this = self.project();

            match this.ws.send_with_bytes(buf) {
                Ok(()) => Poll::Ready(Ok(buf.len())),
                Err(e) => Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string()))),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
            let this = self.project();
            match this.ws.close(Some(1000), Some("Normal close")) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(e) => Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string()))),
            }
        }
    }
}
