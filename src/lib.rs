use crate::proxy::{parse_early_data, parse_user_id, run_tunnel};
use crate::websocket::WebSocketStream;
use wasm_bindgen::JsValue;
use worker::*;

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    // get user id
    let user_id = env.var("USER_ID")?.to_string();
    let user_id = parse_user_id(&user_id);

    // get proxy ip list
    let proxy_ip = env.var("PROXY_IP")?.to_string();
    let proxy_ip = proxy_ip
        .split_ascii_whitespace()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect::<Vec<String>>();

    // better disguising;
    let fallback_site = env
        .var("FALLBACK_SITE")
        .unwrap_or(JsValue::from_str("").into())
        .to_string();
    let should_fallback = req
        .headers()
        .get("Upgrade")?
        .map(|up| up != *"websocket")
        .unwrap_or(true);

    // show uri
    let show_uri = env.var("SHOW_URI")?.to_string().parse().unwrap_or(false);
    let request_path = req.path().to_string();
    let uuid_str = env.var("USER_ID")?.to_string();
    let host_str = req.url()?.host_str().unwrap().to_string();

    if should_fallback && show_uri && request_path.contains(uuid_str.as_str()) {
        let vless_uri = format!(
            "vless://{uuid}@{host}:443?encryption=none&security=tls&sni={host}&fp=chrome&type=ws&host={host}&path=ws#workers-tunnel",
            uuid = uuid_str,
            host = host_str
        );
        return Response::ok(vless_uri);
    }

    if should_fallback && !fallback_site.is_empty() {
        let req = Fetch::Url(Url::parse(&fallback_site)?);
        return req.send().await;
    }

    // ready early data
    let early_data = req.headers().get("sec-websocket-protocol")?;
    let early_data = parse_early_data(early_data)?;

    // Accept / handle a websocket connection
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

        // create websocket stream
        let socket = WebSocketStream::new(&server, events, early_data);

        // into tunnel
        if let Err(err) = run_tunnel(socket, user_id, proxy_ip).await {
            // log error
            console_error!("error: {}", err);

            // close websocket connection
            _ = server.close(Some(1003), Some("invalid request"));
        }
    });

    Response::from_websocket(client)
}

#[allow(dead_code)]
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

    use crate::ext::StreamExt;
    use crate::protocol;
    use crate::websocket::WebSocketStream;
    use base64::{decode_config, URL_SAFE_NO_PAD};
    use futures_util::future::{select, Either};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use worker::*;

    const COPY_BUF_SIZE: usize = 64 * 1024;

    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

    struct TunnelRequest {
        network_type: u8,
        remote_port: u16,
        remote_addr: String,
    }

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

    pub fn parse_user_id(user_id: &str) -> Vec<u8> {
        let mut hex_bytes = user_id
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
            bytes.push((h << 4) | l)
        }
        bytes
    }

    pub async fn run_tunnel(
        mut client_socket: WebSocketStream<'_>,
        user_id: Vec<u8>,
        proxy_ip: Vec<String>,
    ) -> Result<()> {
        let request = match select(
            Box::pin(read_tunnel_request(&mut client_socket, &user_id)),
            Box::pin(Delay::from(HANDSHAKE_TIMEOUT)),
        )
        .await
        {
            Either::Left((result, _)) => result?,
            Either::Right((_, _)) => {
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

                // try the requested address first, then configured proxy IPs
                for target in [vec![request.remote_addr], proxy_ip].concat() {
                    match process_tcp_outbound(&mut client_socket, &target, request.remote_port)
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
                process_udp_outbound(
                    &mut client_socket,
                    &request.remote_addr,
                    request.remote_port,
                )
                .await
            }
            unknown => Err(Error::new(
                ErrorKind::InvalidData,
                format!("unsupported network type: {}", unknown),
            )),
        }
    }

    async fn read_tunnel_request(
        client_socket: &mut WebSocketStream<'_>,
        user_id: &[u8],
    ) -> Result<TunnelRequest> {
        // read version
        if client_socket.read_u8().await? != protocol::VERSION {
            return Err(Error::new(ErrorKind::InvalidData, "invalid version"));
        }

        // verify user_id
        if client_socket.read_bytes(16).await? != user_id {
            return Err(Error::new(ErrorKind::InvalidData, "invalid user id"));
        }

        // ignore addons
        let length = client_socket.read_u8().await?;
        _ = client_socket.read_bytes(length as usize).await?;

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
        // connect to remote socket
        let mut remote_socket = Socket::builder().connect(target, port).map_err(|e| {
            Error::new(
                ErrorKind::ConnectionRefused,
                format!("connect to remote failed: {}", e),
            )
        })?;

        // check remote socket
        remote_socket.opened().await.map_err(|e| {
            Error::new(
                ErrorKind::ConnectionRefused,
                format!("remote socket not opened: {}", e),
            )
        })?;

        // send response header
        client_socket
            .write(&protocol::RESPONSE)
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("send response header failed: {}", e),
                )
            })?;

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

        let r2c = async {
            let mut buf = vec![0u8; COPY_BUF_SIZE];
            loop {
                let n = rr.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                cw.write_all(&buf[..n]).await?;
                cw.flush().await?;
            }
            cw.shutdown().await?;
            Ok::<_, Error>(())
        };

        // When one direction ends (EOF or error), let the other drain
        let result = match select(Box::pin(c2r), Box::pin(r2c)).await {
            Either::Left((c2r_res, r2c_fut)) => {
                let _ = r2c_fut.await;
                c2r_res
            }
            Either::Right((r2c_res, c2r_fut)) => {
                let _ = c2r_fut.await;
                r2c_res
            }
        };

        result.map_err(|e| {
            Error::new(
                ErrorKind::ConnectionAborted,
                format!("forward data failed: {}", e),
            )
        })?;

        Ok(())
    }

    async fn process_udp_outbound(
        client_socket: &mut WebSocketStream<'_>,
        _: &str,
        port: u16,
    ) -> Result<()> {
        // check port (only support dns query)
        if port != 53 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "not supported udp proxy yet",
            ));
        }

        // send response header
        client_socket
            .write(&protocol::RESPONSE)
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("send response header failed: {}", e),
                )
            })?;

        // forward data
        loop {
            // read packet length
            let length = client_socket.read_u16().await;
            if length.is_err() {
                return Ok(());
            }

            // read dns packet
            let packet = client_socket.read_bytes(length.unwrap() as usize).await?;

            // create request
            let request = Request::new_with_init("https://1.1.1.1/dns-query", &{
                // create request
                let mut init = RequestInit::new();
                init.method = Method::Post;
                init.headers = Headers::new();
                init.body = Some(packet.into());

                // set headers
                _ = init.headers.set("Content-Type", "application/dns-message");

                init
            })
            .unwrap();

            // invoke dns-over-http resolver
            let mut response = Fetch::Request(request).send().await.map_err(|e| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("send DNS-over-HTTP request failed: {}", e),
                )
            })?;

            // read response
            let data = response.bytes().await.map_err(|e| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("DNS-over-HTTP response body error: {}", e),
                )
            })?;

            // write response
            client_socket.write_u16(data.len() as u16).await?;
            client_socket.write_all(&data).await?;
        }
    }
}

mod ext {
    use std::io::Result;
    use tokio::io::AsyncReadExt;
    #[allow(dead_code)]
    pub trait StreamExt {
        async fn read_string(&mut self, n: usize) -> Result<String>;
        async fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>>;
    }

    impl<T: AsyncReadExt + Unpin + ?Sized> StreamExt for T {
        async fn read_string(&mut self, n: usize) -> Result<String> {
            self.read_bytes(n).await.map(|bytes| {
                String::from_utf8(bytes).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid string: {}", e),
                    )
                })
            })?
        }

        async fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
            let mut buffer = vec![0u8; n];
            self.read_exact(&mut buffer).await?;

            Ok(buffer)
        }
    }
}

mod websocket {
    use futures_util::Stream;
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
