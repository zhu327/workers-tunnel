use crate::proxy::{parse_early_data, parse_user_id, run_tunnel};
use crate::websocket::WebSocketStream;
use worker::*;

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    let user_id_str = setting(&env, "USER_ID").unwrap_or_default();

    let is_websocket = req
        .headers()
        .get("Upgrade")?
        .is_some_and(|up| up.eq_ignore_ascii_case("websocket"));

    if !is_websocket {
        return serve_http(&req, &env, &user_id_str).await;
    }

    // Fail closed on a malformed USER_ID.
    let Some(user_id) = parse_user_id(&user_id_str) else {
        console_error!("USER_ID is missing or is not a valid UUID; refusing tunnel traffic");
        return Response::error("Bad Request", 400);
    };

    let proxy_ip: Vec<String> = setting(&env, "PROXY_IP")
        .unwrap_or_default()
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
                console_error!("could not open websocket stream: {}", err);
                _ = server.close(Some(1000), None::<&str>);
                return;
            }
        };

        let socket = WebSocketStream::new(&server, events, early_data);

        if let Err(err) = run_tunnel(socket, user_id, &proxy_ip).await {
            // Generic close: do not advertise this as a tunnel.
            console_error!("tunnel closed: {}", err);
            _ = server.close(Some(1000), None::<&str>);
        }
    });

    Response::from_websocket(client)
}

/// Reads a var or secret, blank meaning unset. `Env::var` resolves both.
fn setting(env: &Env, name: &str) -> Option<String> {
    env.var(name)
        .ok()
        .map(|value| value.to_string())
        .filter(|value| !value.is_empty())
}

/// Serves anything that is not a tunnel upgrade.
async fn serve_http(req: &Request, env: &Env, user_id: &str) -> Result<Response> {
    let show_uri = setting(env, "SHOW_URI").is_some_and(|value| value.eq_ignore_ascii_case("true"));

    // Exact match, not a substring.
    if show_uri && !user_id.is_empty() && req.path() == format!("/{user_id}") {
        let host = req.url()?.host_str().unwrap_or_default().to_string();
        // Encoded `/ws?ed=512`; `ed` is what enables early data.
        return Response::ok(format!(
            "vless://{user_id}@{host}:443?encryption=none&security=tls&sni={host}&fp=chrome&type=ws&host={host}&path=%2Fws%3Fed%3D512#workers-tunnel"
        ));
    }

    let Some(site) = setting(env, "FALLBACK_SITE") else {
        return Response::error("Not Found", 404);
    };

    match Url::parse(&site) {
        Ok(url) => Fetch::Url(url).send().await,
        // `?` would surface the parse error in the response body.
        Err(err) => {
            console_error!("FALLBACK_SITE is not a valid URL: {err}");
            Response::error("Not Found", 404)
        }
    }
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
    use std::cell::Cell;
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
    const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
    const DNS_TIMEOUT: Duration = Duration::from_secs(10);

    /// Torn down once *both* directions have been silent this long.
    const IDLE_TIMEOUT: Duration = Duration::from_secs(900);

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
                    Err(err) => return Err(Error::other(err.to_string())),
                }
            }
        }
        Ok(None)
    }

    /// Decodes a UUID into the 16-byte credential. Hyphens optional, case
    /// ignored, anything else rejected.
    pub fn parse_user_id(user_id: &str) -> Option<[u8; 16]> {
        fn nibble(byte: u8) -> Option<u8> {
            match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            }
        }

        let mut hex = user_id.bytes().filter(|&byte| byte != b'-');

        let mut bytes = [0u8; 16];
        for byte in &mut bytes {
            let high = nibble(hex.next()?)?;
            let low = nibble(hex.next()?)?;
            *byte = (high << 4) | low;
        }

        // Reject trailing input.
        hex.next().is_none().then_some(bytes)
    }

    /// No early exit on the first differing byte. Not hardened constant-time.
    fn user_id_matches(received: &[u8; 16], expected: &[u8; 16]) -> bool {
        let mut diff = 0u8;
        for (a, b) in received.iter().zip(expected.iter()) {
            diff |= a ^ b;
        }
        // `diff` only ever gains bits, so LLVM is free to restore the early
        // exit; `black_box` denies it that.
        std::hint::black_box(diff) == 0
    }

    /// Splits an optional port off a `PROXY_IP` entry; else the requested port.
    fn split_proxy_target(entry: &str, default_port: u16) -> (&str, u16) {
        let Some((host, port)) = entry.rsplit_once(':') else {
            return (entry, default_port);
        };

        // A bare IPv6 literal also splits on ':'.
        let host_is_complete = !host.is_empty() && (host.ends_with(']') || !host.contains(':'));

        match port.parse() {
            Ok(port) if host_is_complete => (host, port),
            _ => (entry, default_port),
        }
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

                for (target, port) in
                    std::iter::once((request.remote_addr.as_str(), request.remote_port)).chain(
                        proxy_ip
                            .iter()
                            .map(|entry| split_proxy_target(entry, request.remote_port)),
                    )
                {
                    match process_tcp_outbound(&mut client_socket, target, port).await {
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
                format!("unsupported network type: {unknown}"),
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
        if !user_id_matches(&id_buf, user_id) {
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
                format!("connect to remote failed: {e}"),
            )
        })?;

        tokio::select! {
            result = remote_socket.opened() => { result.map_err(|e| {
                Error::new(ErrorKind::ConnectionRefused, format!("remote socket not opened: {e}"))
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
                    format!("send response header failed: {e}"),
                )
            })?;
        client_socket.flush().await?;

        let ws = client_socket.socket();
        let (mut cr, mut cw) = tokio::io::split(client_socket);
        let (mut rr, mut rw) = tokio::io::split(&mut remote_socket);

        // Traffic either way keeps the relay alive.
        let active = Cell::new(false);

        let c2r = async {
            let mut buf = vec![0u8; COPY_BUF_SIZE];
            loop {
                let n = cr.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                active.set(true);
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
                active.set(true);
                cw.write_all(&buf[..n]).await?;
            }
            cw.flush().await?;
            cw.shutdown().await?;
            Ok::<_, Error>(())
        };
        tokio::pin!(r2c);

        // Sampled, so a quiet relay survives up to two intervals.
        let idle = async {
            loop {
                Delay::from(IDLE_TIMEOUT).await;
                if !active.replace(false) {
                    return;
                }
            }
        };

        let result = tokio::select! {
            result = &mut c2r => {
                tokio::select! {
                    _ = &mut r2c => {}
                    _ = Delay::from(DRAIN_TIMEOUT) => {}
                };
                result
            }
            result = &mut r2c => {
                tokio::select! {
                    _ = &mut c2r => {}
                    _ = Delay::from(DRAIN_TIMEOUT) => {}
                };
                result
            }
            _ = idle => {
                console_log!(
                    "relay idle for {}s: {}:{}",
                    IDLE_TIMEOUT.as_secs(),
                    target,
                    port
                );
                Ok(())
            }
        };

        if let Err(e) = result {
            console_log!("forward data ended: {}:{} - {}", target, port, e);
        }

        // `poll_shutdown` only runs when the client half completes, so the idle
        // and drain-timeout exits would otherwise leave the peer with a 1006.
        _ = ws.close(Some(1000), None::<&str>);

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
                    format!("send response header failed: {e}"),
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

            let request = Request::new_with_init("https://1.1.1.1/dns-query", &init)
                .map_err(|e| Error::other(format!("create DNS request failed: {e}")))?;

            let dns_fetch = async {
                let mut response = Fetch::Request(request).send().await.map_err(|e| {
                    Error::new(
                        ErrorKind::ConnectionAborted,
                        format!("send DNS-over-HTTP request failed: {e}"),
                    )
                })?;
                response.bytes().await.map_err(|e| {
                    Error::new(
                        ErrorKind::ConnectionAborted,
                        format!("DNS-over-HTTP response body error: {e}"),
                    )
                })
            };

            let data = tokio::select! {
                result = dns_fetch => result?,
                _ = Delay::from(DNS_TIMEOUT) => {
                    return Err(Error::new(ErrorKind::TimedOut, "DNS query timed out"));
                }
            };

            // Truncating to the 16-bit prefix would desynchronise the stream.
            let Ok(response_len) = u16::try_from(data.len()) else {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "DNS response exceeds the 16-bit length prefix",
                ));
            };

            client_socket.write_u16(response_len).await?;
            client_socket.write_all(&data).await?;
            client_socket.flush().await?;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{parse_early_data, parse_user_id, split_proxy_target, user_id_matches};

        const RAW: [u8; 16] = [
            0xc5, 0x5b, 0xa3, 0x5f, 0x12, 0xf6, 0x43, 0x6e, 0xa4, 0x51, 0x4c, 0xe9, 0x82, 0xc4,
            0xec, 0x1c,
        ];

        #[test]
        fn parses_a_canonical_uuid() {
            assert_eq!(
                parse_user_id("c55ba35f-12f6-436e-a451-4ce982c4ec1c"),
                Some(RAW)
            );
        }

        #[test]
        fn accepts_uppercase_and_unhyphenated_forms() {
            assert_eq!(
                parse_user_id("C55BA35F-12F6-436E-A451-4CE982C4EC1C"),
                Some(RAW)
            );
            assert_eq!(parse_user_id("c55ba35f12f6436ea4514ce982c4ec1c"), Some(RAW));
        }

        #[test]
        fn rejects_anything_that_is_not_a_uuid() {
            // All of these once produced a usable key.
            for id in [
                "",
                "c55ba35f",
                "not-a-uuid",
                "c55ba35f-12f6-436e-a451-4ce982c4ec1",
                "c55ba35f-12f6-436e-a451-4ce982c4ec1c0",
                "c55ba35f-12f6-436e-a451-4ce982c4ec1z",
            ] {
                assert_eq!(parse_user_id(id), None, "{id:?} should be rejected");
            }
        }

        #[test]
        fn credential_comparison_agrees_with_equality() {
            assert!(user_id_matches(&RAW, &RAW));

            // Both ends, not just the first byte.
            for index in [0, 15] {
                let mut received = RAW;
                received[index] ^= 0x80;
                assert!(!user_id_matches(&received, &RAW), "byte {index}");
            }
        }

        #[test]
        fn proxy_entry_without_a_port_inherits_the_requested_one() {
            assert_eq!(
                split_proxy_target("proxy.example", 443),
                ("proxy.example", 443)
            );
            assert_eq!(split_proxy_target("192.0.2.1", 8080), ("192.0.2.1", 8080));
        }

        #[test]
        fn proxy_entry_may_pin_its_own_port() {
            assert_eq!(
                split_proxy_target("proxy.example:8443", 443),
                ("proxy.example", 8443)
            );
            assert_eq!(
                split_proxy_target("[2001:db8::1]:8443", 443),
                ("[2001:db8::1]", 8443)
            );
        }

        #[test]
        fn bare_ipv6_is_not_read_as_a_host_port_pair() {
            // Splitting on the last colon would yield ("2001:db8:", 1).
            assert_eq!(split_proxy_target("2001:db8::1", 443), ("2001:db8::1", 443));
        }

        #[test]
        fn unusable_port_suffixes_fall_back_to_the_requested_port() {
            for entry in [
                "proxy.example:",
                "proxy.example:https",
                "proxy.example:99999",
                ":443",
            ] {
                assert_eq!(split_proxy_target(entry, 8080), (entry, 8080));
            }
        }

        #[test]
        fn early_data_is_absent_unless_the_header_carries_it() {
            assert_eq!(parse_early_data(None).unwrap(), None);
            assert_eq!(parse_early_data(Some(String::new())).unwrap(), None);
        }

        #[test]
        fn early_data_accepts_both_base64_alphabets() {
            let standard = parse_early_data(Some("/+/+".to_owned())).unwrap();
            let url_safe = parse_early_data(Some("_-_-".to_owned())).unwrap();

            assert_eq!(standard, Some(vec![0xff, 0xef, 0xfe]));
            assert_eq!(standard, url_safe);
        }

        #[test]
        fn early_data_ignores_padding() {
            assert_eq!(
                parse_early_data(Some("QQ==".to_owned())).unwrap(),
                Some(vec![b'A'])
            );
        }

        #[test]
        fn early_data_rejects_undecodable_input() {
            assert!(parse_early_data(Some("!!!!".to_owned())).is_err());
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
                    format!("invalid string: {e}"),
                )
            })
        }
    }
}

mod websocket {
    use futures_core::Stream;
    use std::{
        future::Future,
        io::{Error, Result},
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

        /// The underlying socket, for exits that never reach `poll_shutdown`.
        pub fn socket(&self) -> &'a WebSocket {
            self.ws
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

            if *this.closed {
                return Poll::Ready(Ok(()));
            }

            // A `Ready` filling nothing is EOF; `bytes()` is `None` on text.
            while this.read_buffer.is_empty() {
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
                        return Poll::Ready(Err(Error::other(e.to_string())));
                    }
                }
            }

            // Coalesce what is already queued, stopping at anything terminal.
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
                    Poll::Ready(Some(Err(_))) => {
                        // Deliberately unlike the loop above: bytes are already
                        // buffered, so deliver them and end the stream next call.
                        *this.closed = true;
                        break;
                    }
                    Poll::Pending => break,
                }
            }

            let amt = std::cmp::min(this.read_buffer.len(), buf.remaining());
            buf.put_slice(&this.read_buffer.split_to(amt));
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
                return Poll::Ready(Err(Error::other(e.to_string())));
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

            // No reason string: every close should look alike.
            if let Err(e) = self.ws.close(Some(1000), None::<&str>) {
                return Poll::Ready(Err(Error::other(e.to_string())));
            }

            Poll::Ready(Ok(()))
        }
    }
}
