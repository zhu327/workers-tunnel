use crate::proxy::{parse_early_data, run_tunnel};
use crate::ws::WebSocketStream;
use worker::*;

mod proxy;
mod utils;
mod ws;

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    let user_id = env.var("USER_ID")?.to_string();
    let proxy_ip = env.var("PROXY_IP")?.to_string();

    // ready early data
    let swp = req.headers().get("sec-websocket-protocol")?;
    let early_data = parse_early_data(swp)?;

    // Accept / handle a websocket connection
    let pair = WebSocketPair::new()?;
    let server = pair.server;
    server.accept()?;

    wasm_bindgen_futures::spawn_local(async move {
        let event_stream = server.events().expect("could not open stream");

        let socket = WebSocketStream::new(&server, event_stream, early_data);

        // run vless tunnel
        let user_id = uuid::Uuid::parse_str(&user_id).unwrap();
        if let Err(err) = run_tunnel(socket, &user_id, &proxy_ip).await {
            if err.kind() == std::io::ErrorKind::InvalidData
                || err.kind() == std::io::ErrorKind::ConnectionAborted
            {
                server
                    .close(Some(1003), Some("invalid request"))
                    .unwrap_or_default()
            }
            console_debug!("run tunnel error: {}", err);
        }
    });

    Response::from_websocket(pair.client)
}
