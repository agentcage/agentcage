//! WebSocket relay after a `101 Switching Protocols`.
//!
//! Both sides are framed by tungstenite: the client side in the server
//! role, the upstream side in the client role (so frames we send upstream
//! are masked and frames from the client must be). Every complete text or
//! binary message, from either side, goes through
//! [`FlowHandler::websocket_message`], which may rewrite or drop it; it is
//! forwarded with its type kept. Pings and pongs are forwarded as they
//! are; a close from either side is forwarded and ends the relay.

use futures_util::{SinkExt as _, StreamExt as _};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};

use super::conn::Shared;
use super::io::{BoxIo, Buffered};
use super::{ConnInfo, FlowEnd, FlowHandler, WsMessage, WsVerdict};
use crate::message::Request;

type Ws = WebSocketStream<BoxIo>;

pub(crate) async fn relay<H: FlowHandler>(
    shared: &Shared<H>,
    conn: &ConnInfo,
    mut flow: H::Flow,
    req: &Request,
    client: Buffered,
    upstream: Buffered,
) {
    let max = shared.settings.load().max_body;
    let config = WebSocketConfig::default()
        .max_message_size(Some(max))
        .max_frame_size(Some(max));
    let (cio, cbuf) = client.into_parts();
    let (uio, ubuf) = upstream.into_parts();
    let mut client = Ws::from_partially_read(cio, cbuf, Role::Server, Some(config)).await;
    let mut upstream = Ws::from_partially_read(uio, ubuf, Role::Client, Some(config)).await;
    let end = loop {
        let (from_client, message) = tokio::select! {
            m = client.next() => (true, m),
            m = upstream.next() => (false, m),
        };
        let (src, dst) = if from_client {
            (&mut client, &mut upstream)
        } else {
            (&mut upstream, &mut client)
        };
        let message = match message {
            Some(Ok(message)) => message,
            Some(Err(e)) => {
                let _ = dst.close(None).await;
                break FlowEnd::Aborted(format!("WebSocket error: {e}"));
            }
            None => {
                let _ = dst.close(None).await;
                break FlowEnd::WebSocketClosed;
            }
        };
        let outgoing = match message {
            Message::Text(text) => {
                hook(
                    shared,
                    conn,
                    &mut flow,
                    req,
                    from_client,
                    true,
                    text.as_bytes().to_vec(),
                )
                .await
            }
            Message::Binary(data) => {
                hook(
                    shared,
                    conn,
                    &mut flow,
                    req,
                    from_client,
                    false,
                    data.to_vec(),
                )
                .await
            }
            Message::Ping(p) => Some(Message::Ping(p)),
            Message::Pong(p) => Some(Message::Pong(p)),
            Message::Close(frame) => {
                let _ = dst.send(Message::Close(frame)).await;
                let _ = src.flush().await;
                break FlowEnd::WebSocketClosed;
            }
            Message::Frame(_) => None,
        };
        if let Some(outgoing) = outgoing {
            if let Err(e) = dst.send(outgoing).await {
                let _ = src.close(None).await;
                break FlowEnd::Aborted(format!("WebSocket error: {e}"));
            }
        }
    };
    shared.handler.flow_end(conn, flow, end);
}

#[allow(clippy::too_many_arguments)]
async fn hook<H: FlowHandler>(
    shared: &Shared<H>,
    conn: &ConnInfo,
    flow: &mut H::Flow,
    req: &Request,
    from_client: bool,
    is_text: bool,
    content: Vec<u8>,
) -> Option<Message> {
    let mut msg = WsMessage {
        from_client,
        is_text,
        content,
    };
    match shared
        .handler
        .websocket_message(conn, flow, req, &mut msg)
        .await
    {
        WsVerdict::Drop => None,
        WsVerdict::Forward if msg.is_text => Some(Message::text(
            String::from_utf8_lossy(&msg.content).into_owned(),
        )),
        WsVerdict::Forward => Some(Message::binary(msg.content)),
    }
}
