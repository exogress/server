use crate::termination::StopReason;
use futures::{FutureExt, SinkExt, StreamExt};
use redis::AsyncCommands;
use std::net::SocketAddr;
use stop_handle::StopWait;
use tracing_futures::Instrument;
use warp::Filter;

// TODO: add pings

pub async fn server(
    listen_addr: SocketAddr,
    redis: redis::Client,
    stop_wait: StopWait<StopReason>,
) {
    info!("Will spawn HTTP server on {}", listen_addr);

    let api = warp::path!("api" / "v1" / "gateways" / String / "notifications")
        .and(warp::filters::ws::ws())
        .map({
            move |gw_hostname: String, ws: warp::ws::Ws| {
                shadow_clone!(mut redis);

                ws.on_upgrade(move |mut websocket| {
                    async move {
                        match redis.get_async_connection().await {
                            Ok(mut conn) => {
                                let mut pubsub = conn.into_pubsub();

                                if let Ok(_) = pubsub.subscribe("invalidations").await {
                                    let mut messages = pubsub.into_on_message();

                                    while let Some(msg) = messages.next().await {
                                        match msg.get_payload::<String>() {
                                            Ok(p) => {
                                                if let Err(e) = websocket
                                                    .send(warp::filters::ws::Message::text(p))
                                                    .await
                                                {
                                                    error!("error sending to websocket: {}", e);
                                                    return;
                                                }
                                            }
                                            Err(e) => {
                                                error!("error getting redis payload: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("redis server connection  error: {}", e);
                            }
                        }

                        let _ = websocket.send(warp::filters::ws::Message::close()).await;
                    }
                    .instrument(tracing::info_span!("gw", host = gw_hostname.as_str()))
                })
            }
        });

    info!("Spawning...");
    let (_, server) = warp::serve(api.with(warp::trace::request())).bind_with_graceful_shutdown(
        listen_addr,
        stop_wait.map(move |r| info!("private HTTP server stop request received: {}", r)),
    );

    server.await;

    info!("private HTTP server stopped");
}

#[derive(Debug)]
pub struct InternalServerError {}

impl warp::reject::Reject for InternalServerError {}
