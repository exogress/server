use crate::termination::StopReason;
use futures::{FutureExt, SinkExt, StreamExt};
use redis::AsyncCommands;
use std::net::SocketAddr;
use stop_handle::StopWait;
use tokio::sync::mpsc;
use tokio::time::{delay_for, Duration};
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

                                    let (mut to_ws_tx, mut to_ws_rx) = mpsc::channel(16);

                                    let forward_channel_to_ws = async {
                                        while let Some(msg) = to_ws_rx.next().await {
                                            websocket.send(msg).await?;
                                        }

                                        Ok::<_, anyhow::Error>(())
                                    };

                                    let forward_from_redis = {
                                        shadow_clone!(mut to_ws_tx);

                                        async move {
                                            while let Some(msg) = messages.next().await {
                                                match msg.get_payload::<String>() {
                                                    Ok(p) => {
                                                        if let Err(e) = to_ws_tx
                                                            .send(warp::filters::ws::Message::text(
                                                                p,
                                                            ))
                                                            .await
                                                        {
                                                            error!(
                                                                "error sending to websocket: {}",
                                                                e
                                                            );
                                                            return;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!(
                                                            "error getting redis payload: {}",
                                                            e
                                                        );
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    };

                                    let periodically_send_ping = async move {
                                        loop {
                                            delay_for(Duration::from_secs(15)).await;

                                            to_ws_tx
                                                .send(warp::filters::ws::Message::ping(""))
                                                .await?;
                                        }

                                        Ok::<_, anyhow::Error>(())
                                    };

                                    tokio::select! {
                                        _ = forward_channel_to_ws => {},
                                        _ = forward_from_redis => {},
                                        _ = periodically_send_ping => {},
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
