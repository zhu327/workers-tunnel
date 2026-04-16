use crate::proxy::{parse_early_data, parse_user_id, run_tunnel};
use crate::websocket::WebSocketStream;
use worker::*;

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    let uuid_str = env.var("USER_ID")?.to_string();

    let is_websocket = req
        .headers()
        .get("Upgrade")?
        .map(|up| up == "websocket")
        .unwrap_or(false);

    if !is_websocket {
        let show_uri: bool = env.var("SHOW_URI")?.to_string().parse().unwrap_or(false);
        if show_uri && req.path().contains(uuid_str.as_str()) {
            let host_str = req.url()?.host_str().unwrap_or_default().to_string();
            let vless_uri = format!(
                "vless://{uuid}@{host}:443?encryption=none&security=tls&sni={host}&fp=chrome&type=ws&host={host}&path=ws#workers-tunnel",
                uuid = uuid_str,
                host = host_str
            );
            return Response::ok(vless_uri);
        }

        let fallback_site = env
            .var("FALLBACK_SITE")
            .map(|v| v.to_string())
            .unwrap_or_default();
        if !fallback_site.is_empty() {
            return Fetch::Url(Url::parse(&fallback_site)?).send().await;
        }

        return Response::ok("ok");
    }

    let user_id = parse_user_id(&uuid_str);

    let proxy_ip: Vec<String> = env
        .var("PROXY_IP")?
        .to_string()
        .split_ascii_whitespace()
        .map(String::from)
        .collect();

    let early_data = req.headers().get("sec-websocket-protocol")?;
    let early_data = parse_early_data(early_data)?;

    let WebSocketPair { client, server } = WebSocketPair::new()?;
    server.accept()?;

    wasm_bindgen_futures::spawn_local(async move {
        let events = match server.events() {
            Ok(events) => events,
            Err(err) => {
                console_error!("error: could not open websocket stream: {}", err);
                _ = server.close(Some(1011), Some("websocket stream error"));
                return;
            }
        };

        let socket = WebSocketStream::new(&server, events, early_data);

        if let Err(err) = run_tunnel(socket, user_id, &proxy_ip).await {
            console_error!("error: {}", err);
            _ = server.close(Some(1003), Some("invalid request"));
        }
    });

    Response::from_websocket(client)
}

mod protocol {
    pub const VERSION: u8 = 0;
    pub const RESPONSE: [u8; 2] = [0u8; 2];
    pub const NETWORK_TYPE_TCP: u8 = 1;
    pub const NETWORK_TYPE_UDP: u8 = 2;
    pub const ADDRESS_TYPE_IPV4: u8 = 1;
    pub const ADDRESS_TYPE_DOMAIN: u8 = 2;
    pub const ADDRESS_TYPE_IPV6: u8 = 3;
}

mod proxy {
    use std::io::{Error, ErrorKind, Result};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use crate::ext::ReadStringExt;
    use crate::protocol;
    use crate::websocket::WebSocketStream;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use worker::*;

    const COPY_BUF_SIZE: usize = 32 * 1024;

    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    const RELAY_TIMEOUT: Duration = Duration::from_secs(900);
    const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
    const DNS_TIMEOUT: Duration = Duration::from_secs(10);

    struct TunnelRequest {
        network_type: u8,
        remote_port: u16,
        remote_addr: String,
    }

    pub fn parse_early_data(data: Option<String>) -> Result<Option<Vec<u8>>> {
        if let Some(data) = data {
            if !data.is_empty() {
                let mut raw = Vec::with_capacity(data.len());
                raw.extend(data.bytes().filter(|&b| b != b'=').map(|b| match b {
                    b'+' => b'-',
                    b'/' => b'_',
                    _ => b,
                }));
                match URL_SAFE_NO_PAD.decode(&raw) {
                    Ok(early_data) => return Ok(Some(early_data)),
                    Err(err) => return Err(Error::new(ErrorKind::Other, err.to_string())),
                }
            }
        }
        Ok(None)
    }

    pub fn parse_user_id(user_id: &str) -> [u8; 16] {
        let mut iter = user_id.as_bytes().iter().filter_map(|b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        });

        let mut bytes = [0u8; 16];
        for b in &mut bytes {
            let (Some(h), Some(l)) = (iter.next(), iter.next()) else {
                break;
            };
            *b = (h << 4) | l;
        }
        bytes
    }

    pub async fn run_tunnel(
        mut client_socket: WebSocketStream<'_>,
        user_id: [u8; 16],
        proxy_ip: &[String],
    ) -> Result<()> {
        let request = tokio::select! {
            result = read_tunnel_request(&mut client_socket, &user_id) => result?,
            _ = Delay::from(HANDSHAKE_TIMEOUT) => {
                return Err(Error::new(
                    ErrorKind::TimedOut,
                    "tunnel handshake timed out",
                ));
            }
        };

        // process outbound
        match request.network_type {
            protocol::NETWORK_TYPE_TCP => {
                let mut last_error = None;

                for target in std::iter::once(request.remote_addr.as_str())
                    .chain(proxy_ip.iter().map(|s| s.as_str()))
                {
                    match process_tcp_outbound(&mut client_socket, target, request.remote_port)
                        .await
                    {
                        Ok(_) => return Ok(()),
                        Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                            last_error = Some(e);
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }

                Err(last_error.unwrap_or_else(|| {
                    Error::new(ErrorKind::ConnectionRefused, "no target to connect")
                }))
            }
            protocol::NETWORK_TYPE_UDP => {
                process_udp_outbound(&mut client_socket, request.remote_port).await
            }
            unknown => Err(Error::new(
                ErrorKind::InvalidData,
                format!("unsupported network type: {}", unknown),
            )),
        }
    }

    async fn read_tunnel_request(
        client_socket: &mut WebSocketStream<'_>,
        user_id: &[u8; 16],
    ) -> Result<TunnelRequest> {
        if client_socket.read_u8().await? != protocol::VERSION {
            return Err(Error::new(ErrorKind::InvalidData, "invalid version"));
        }

        let mut id_buf = [0u8; 16];
        client_socket.read_exact(&mut id_buf).await?;
        if id_buf != *user_id {
            return Err(Error::new(ErrorKind::InvalidData, "invalid user id"));
        }

        let addon_len = client_socket.read_u8().await? as usize;
        if addon_len > 0 {
            let mut addon_buf = [0u8; 255];
            client_socket
                .read_exact(&mut addon_buf[..addon_len])
                .await?;
        }

        // read network type
        let network_type = client_socket.read_u8().await?;

        // read remote port
        let remote_port = client_socket.read_u16().await?;

        // read remote address
        let remote_addr = match client_socket.read_u8().await? {
            protocol::ADDRESS_TYPE_DOMAIN => {
                let length = client_socket.read_u8().await?;
                client_socket.read_string(length as usize).await?
            }
            protocol::ADDRESS_TYPE_IPV4 => {
                Ipv4Addr::from_bits(client_socket.read_u32().await?).to_string()
            }
            protocol::ADDRESS_TYPE_IPV6 => format!(
                "[{}]",
                Ipv6Addr::from_bits(client_socket.read_u128().await?)
            ),
            _ => {
                return Err(Error::new(ErrorKind::InvalidData, "invalid address type"));
            }
        };

        Ok(TunnelRequest {
            network_type,
            remote_port,
            remote_addr,
        })
    }

    async fn process_tcp_outbound(
        client_socket: &mut WebSocketStream<'_>,
        target: &str,
        port: u16,
    ) -> Result<()> {
        let mut remote_socket = Socket::builder().connect(target, port).map_err(|e| {
            Error::new(
                ErrorKind::ConnectionRefused,
                format!("connect to remote failed: {}", e),
            )
        })?;

        tokio::select! {
            result = remote_socket.opened() => { result.map_err(|e| {
                Error::new(ErrorKind::ConnectionRefused, format!("remote socket not opened: {}", e))
            })?; }
            _ = Delay::from(CONNECT_TIMEOUT) => {
                return Err(Error::new(ErrorKind::TimedOut, "connect to remote timed out"));
            }
        }

        client_socket
            .write_all(&protocol::RESPONSE)
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("send response header failed: {}", e),
                )
            })?;
        client_socket.flush().await?;

        let (mut cr, mut cw) = tokio::io::split(client_socket);
        let (mut rr, mut rw) = tokio::io::split(&mut remote_socket);

        let c2r = async {
            let mut buf = vec![0u8; COPY_BUF_SIZE];
            loop {
                let n = cr.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                rw.write_all(&buf[..n]).await?;
            }
            rw.shutdown().await?;
            Ok::<_, Error>(())
        };
        tokio::pin!(c2r);

        let r2c = async {
            let mut buf = vec![0u8; COPY_BUF_SIZE];
            loop {
                let n = rr.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                cw.write_all(&buf[..n]).await?;
            }
            cw.flush().await?;
            cw.shutdown().await?;
            Ok::<_, Error>(())
        };
        tokio::pin!(r2c);

        let result = tokio::select! {
            result = &mut c2r => {
                let _ = tokio::select! {
                    _ = &mut r2c => {}
                    _ = Delay::from(DRAIN_TIMEOUT) => {}
                };
                result
            }
            result = &mut r2c => {
                let _ = tokio::select! {
                    _ = &mut c2r => {}
                    _ = Delay::from(DRAIN_TIMEOUT) => {}
                };
                result
            }
            _ = Delay::from(RELAY_TIMEOUT) => {
                console_log!("relay timed out: {}:{}", target, port);
                return Ok(());
            }
        };

        if let Err(e) = result {
            console_log!("forward data ended: {}:{} - {}", target, port, e);
        }

        Ok(())
    }

    async fn process_udp_outbound(
        client_socket: &mut WebSocketStream<'_>,
        port: u16,
    ) -> Result<()> {
        if port != 53 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "not supported udp proxy yet",
            ));
        }

        client_socket
            .write_all(&protocol::RESPONSE)
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("send response header failed: {}", e),
                )
            })?;
        client_socket.flush().await?;

        const MAX_DNS_PACKET: usize = 4096;
        let mut buf = [0u8; MAX_DNS_PACKET];

        loop {
            let Ok(len) = client_socket.read_u16().await else {
                return Ok(());
            };
            let len = len as usize;
            if len > MAX_DNS_PACKET {
                return Err(Error::new(ErrorKind::InvalidData, "dns packet too large"));
            }
            client_socket.read_exact(&mut buf[..len]).await?;

            let mut init = RequestInit::new();
            init.method = Method::Post;
            init.headers = Headers::new();
            init.body = Some(buf[..len].to_vec().into());
            _ = init.headers.set("Content-Type", "application/dns-message");

            let request =
                Request::new_with_init("https://1.1.1.1/dns-query", &init).map_err(|e| {
                    Error::new(
                        ErrorKind::Other,
                        format!("create DNS request failed: {}", e),
                    )
                })?;

            let dns_fetch = async {
                let mut response = Fetch::Request(request).send().await.map_err(|e| {
                    Error::new(
                        ErrorKind::ConnectionAborted,
                        format!("send DNS-over-HTTP request failed: {}", e),
                    )
                })?;
                response.bytes().await.map_err(|e| {
                    Error::new(
                        ErrorKind::ConnectionAborted,
                        format!("DNS-over-HTTP response body error: {}", e),
                    )
                })
            };

            let data = tokio::select! {
                result = dns_fetch => result?,
                _ = Delay::from(DNS_TIMEOUT) => {
                    return Err(Error::new(ErrorKind::TimedOut, "DNS query timed out"));
                }
            };

            client_socket.write_u16(data.len() as u16).await?;
            client_socket.write_all(&data).await?;
            client_socket.flush().await?;
        }
    }
}

mod ext {
    use std::io::Result;
    use tokio::io::AsyncReadExt;
    pub trait ReadStringExt {
        async fn read_string(&mut self, n: usize) -> Result<String>;
    }

    impl<T: AsyncReadExt + Unpin + ?Sized> ReadStringExt for T {
        async fn read_string(&mut self, n: usize) -> Result<String> {
            let mut buffer = vec![0u8; n];
            self.read_exact(&mut buffer).await?;
            String::from_utf8(buffer).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid string: {}", e),
                )
            })
        }
    }
}

mod websocket {
    use futures_core::Stream;
    use std::{
        future::Future,
        io::{Error, ErrorKind, Result},
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    use bytes::{BufMut, BytesMut};
    use pin_project::pin_project;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use worker::{Delay, EventStream, WebSocket, WebsocketEvent};

    const WRITE_BUFFER_HIGH_WATERMARK: u32 = 1024 * 1024;
    const FLUSH_BUFFER_LOW_WATERMARK: u32 = 128 * 1024;
    const BACKPRESSURE_POLL_INTERVAL: Duration = Duration::from_millis(50);

    #[pin_project]
    pub struct WebSocketStream<'a> {
        ws: &'a WebSocket,
        #[pin]
        stream: EventStream<'a>,
        #[pin]
        write_delay: Option<Delay>,
        read_buffer: BytesMut,
        closed: bool,
    }

    impl<'a> WebSocketStream<'a> {
        pub fn new(
            ws: &'a WebSocket,
            stream: EventStream<'a>,
            early_data: Option<Vec<u8>>,
        ) -> Self {
            let mut read_buffer = BytesMut::new();
            if let Some(data) = early_data {
                read_buffer.put_slice(&data)
            }

            Self {
                ws,
                stream,
                write_delay: None,
                read_buffer,
                closed: false,
            }
        }

        fn poll_backpressure(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            max_buffered_amount: u32,
        ) -> Poll<Result<()>> {
            let mut this = self.project();

            loop {
                if this.ws.as_ref().buffered_amount() <= max_buffered_amount {
                    this.write_delay.set(None);
                    return Poll::Ready(Ok(()));
                }

                match this.write_delay.as_mut().as_pin_mut() {
                    Some(delay) => match delay.poll(cx) {
                        Poll::Ready(()) => {
                            this.write_delay
                                .set(Some(Delay::from(BACKPRESSURE_POLL_INTERVAL)));
                        }
                        Poll::Pending => return Poll::Pending,
                    },
                    None => {
                        this.write_delay
                            .set(Some(Delay::from(BACKPRESSURE_POLL_INTERVAL)));
                    }
                }
            }
        }
    }

    impl AsyncRead for WebSocketStream<'_> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<()>> {
            let mut this = self.project();

            // If we already saw Close/None, return EOF immediately
            if *this.closed {
                return Poll::Ready(Ok(()));
            }

            // If buffer is empty, we must get at least one message (blocking)
            if this.read_buffer.is_empty() {
                match this.stream.as_mut().poll_next(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Ok(WebsocketEvent::Message(msg)))) => {
                        if let Some(data) = msg.bytes() {
                            this.read_buffer.put_slice(&data);
                        }
                    }
                    Poll::Ready(Some(Ok(WebsocketEvent::Close(_)))) | Poll::Ready(None) => {
                        *this.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Some(Err(e))) => {
                        *this.closed = true;
                        return Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string())));
                    }
                }
            }

            // Drain additional ready messages without blocking,
            // but stop on Close/Error to avoid consuming them
            while this.read_buffer.len() < buf.remaining() {
                match this.stream.as_mut().poll_next(cx) {
                    Poll::Ready(Some(Ok(WebsocketEvent::Message(msg)))) => {
                        if let Some(data) = msg.bytes() {
                            this.read_buffer.put_slice(&data);
                        }
                    }
                    Poll::Ready(Some(Ok(WebsocketEvent::Close(_)))) | Poll::Ready(None) => {
                        *this.closed = true;
                        break;
                    }
                    Poll::Ready(Some(Err(e))) => {
                        // If we already have data buffered, deliver it first;
                        // the error will surface on the next poll_read
                        if !this.read_buffer.is_empty() {
                            *this.closed = true;
                            break;
                        }
                        *this.closed = true;
                        return Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string())));
                    }
                    Poll::Pending => break,
                }
            }

            let amt = std::cmp::min(this.read_buffer.len(), buf.remaining());
            if amt > 0 {
                buf.put_slice(&this.read_buffer.split_to(amt));
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for WebSocketStream<'_> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize>> {
            match self
                .as_mut()
                .poll_backpressure(cx, WRITE_BUFFER_HIGH_WATERMARK)
            {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }

            if let Err(e) = self.ws.send_with_bytes(buf) {
                return Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string())));
            }

            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
            self.as_mut()
                .poll_backpressure(cx, FLUSH_BUFFER_LOW_WATERMARK)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
            match self
                .as_mut()
                .poll_backpressure(cx, FLUSH_BUFFER_LOW_WATERMARK)
            {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }

            if let Err(e) = self.ws.close(Some(1000), Some("normal close")) {
                return Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string())));
            }

            Poll::Ready(Ok(()))
        }
    }
}
