use std::net::SocketAddr;

use futures::{pin_mut, select_biased, FutureExt, SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::time::Duration;

use exogress_config_core::Config;
use exogress_entities::InstanceId;
use warp::Filter;

use crate::presence;
use crate::termination::StopReason;
use stop_handle::StopWait;

const CONFIG_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const PING_INTERVAL: Duration = Duration::from_secs(15);

pub async fn server(
    listen_addr: SocketAddr,
    presence_client: presence::Client,
    redis: redis::Client,
    stop_wait: StopWait<stop_handle::StopReason<StopReason>>,
) {
    let presence = warp::path!("channel" / String)
        .and_then(|instance_id: String| async move {
            match instance_id.parse::<InstanceId>() {
                Err(_e) => Err(warp::reject::custom(BadInstanceId {})),
                Ok(instance_id) => Ok(instance_id),
            }
        })
        .and(warp::ws())
        .and(warp::header("authorization"))
        .map({
            move |instance_id: InstanceId, ws: warp::ws::Ws, authorization: String| {
                let redis = redis.clone();
                let presence_client = presence_client.clone();

                ws.on_upgrade(move |mut websocket| async move {
                    let wait_first = async move {
                        loop {
                            let msg = websocket.next().await;
                            match msg {
                                Some(Ok(m)) if m.is_text() => {
                                    return Ok((
                                        serde_json::from_str::<Config>(m.to_str().unwrap())?,
                                        websocket,
                                    ));
                                }
                                Some(Err(e)) => {
                                    return Err(e.into());
                                }
                                Some(_) => {}
                                None => {
                                    return Err(anyhow::Error::msg(
                                        "WS connection closed before config received",
                                    ));
                                }
                            }
                        }
                    };

                    match tokio::time::timeout(CONFIG_WAIT_TIMEOUT, wait_first).await {
                        Ok(Ok((config, websocket))) => {
                            if let Err(e) = presence_client
                                .set_online(&instance_id, &authorization, &config)
                                .await
                            {
                                info!("could not set presence: {}", e);
                                return;
                            }

                            let r = {
                                let presence_client = presence_client.clone();

                                let authorization = authorization.clone();

                                async move {
                                    let mut pubsub =
                                        redis.get_tokio_connection_tokio().await?.into_pubsub();
                                    let redis_subscription =
                                        format!("signaler.config.{}", config.name);
                                    info!("subscribe to {}", redis_subscription);
                                    pubsub.subscribe(redis_subscription).await?;
                                    let mut messages = pubsub.on_message();

                                    let (mut tx, mut rx) = websocket.split();

                                    let (mut to_ws_tx, mut to_ws_rx) = mpsc::channel(4);

                                    let forward_from_channel_to_ws = async move {
                                        while let Some(msg) = to_ws_rx.next().await {
                                            tx.send(msg).await?;
                                        }

                                        Ok::<_, anyhow::Error>(())
                                    }
                                    .fuse();

                                    let forward_from_redis_to_ws_channel = {
                                        let mut to_ws_tx = to_ws_tx.clone();

                                        async move {
                                            while let Some(msg) = messages.next().await {
                                                let payload: String = msg.get_payload()?;
                                                to_ws_tx
                                                    .send(warp::filters::ws::Message::text(payload))
                                                    .await?;
                                            }

                                            Ok::<_, anyhow::Error>(())
                                        }
                                    }
                                    .fuse();

                                    let (mut incoming_ping_tx, incoming_ping_rx) = mpsc::channel(2);

                                    let process_incoming = {
                                        let mut to_ws_tx = to_ws_tx.clone();
                                        let presence_client = presence_client.clone();
                                        let authorization = authorization.clone();

                                        async move {
                                            while let Some(msg_res) = rx.next().await {
                                                match msg_res? {
                                                    msg if msg.is_text() => {
                                                        let config = serde_json::from_str::<Config>(
                                                            msg.to_str().unwrap(),
                                                        )?;
                                                        presence_client
                                                            .update_presence(
                                                                &instance_id,
                                                                &authorization,
                                                                &config,
                                                            )
                                                            .await?;
                                                    }
                                                    msg if msg.is_ping() => {
                                                        incoming_ping_tx.send(()).await?;
                                                        to_ws_tx
                                                            .send(warp::filters::ws::Message::pong(
                                                                "",
                                                            ))
                                                            .await?;
                                                    }
                                                    msg if msg.is_pong() => {}
                                                    _ => {}
                                                }
                                            }

                                            Ok::<_, anyhow::Error>(())
                                        }
                                    }
                                    .fuse();

                                    #[allow(unreachable_code)]
                                    let send_pings = async move {
                                        let mut period = tokio::time::interval(PING_INTERVAL);
                                        loop {
                                            period.tick().await;
                                            to_ws_tx
                                                .send(warp::filters::ws::Message::ping([]))
                                                .await?;
                                        }

                                        Ok::<_, anyhow::Error>(())
                                    }
                                    .fuse();

                                    let accept_pings = async move {
                                        use tokio::stream::StreamExt;

                                        let mut timeout_stream =
                                            incoming_ping_rx.timeout(PING_INTERVAL * 2);
                                        while let Some(r) =
                                            futures::StreamExt::next(&mut timeout_stream).await
                                        {
                                            r?;
                                        }

                                        Ok::<_, anyhow::Error>(())
                                    }
                                    .fuse();

                                    pin_mut!(forward_from_redis_to_ws_channel);
                                    pin_mut!(process_incoming);
                                    pin_mut!(accept_pings);
                                    pin_mut!(send_pings);
                                    pin_mut!(forward_from_channel_to_ws);

                                    select_biased! {
                                        r = forward_from_channel_to_ws => {
                                            r?;
                                        }
                                        r = accept_pings => {
                                            r?;
                                        }
                                        r = forward_from_redis_to_ws_channel => {
                                            r?;
                                        }
                                        r = send_pings => {
                                            r?;
                                        }
                                        r = process_incoming => {
                                            r?;
                                        }
                                    }

                                    Ok::<_, anyhow::Error>(())
                                }
                                .await
                            };

                            if let Err(e) = r {
                                error!("error forwarding WS: {}", e);
                            }
                        }
                        Err(_e) => {
                            info!("timeout waiting for the first config");
                        }
                        Ok(Err(e)) => {
                            info!("config error: {}", e);
                        }
                    }
                    if let Err(e) = presence_client
                        .set_offline(&instance_id, &authorization)
                        .await
                    {
                        error!("could not unset presence: {}", e);
                    }
                })
            }
        });

    let (_, server) = warp::serve(presence).bind_with_graceful_shutdown(
        listen_addr,
        stop_wait.map({ move |r| info!("public HTTP server stop request received: {}", r) }),
    );

    server.await;

    info!("public HTTP server stopped");
}

#[derive(Debug)]
pub struct BadInstanceId {}

impl warp::reject::Reject for BadInstanceId {}
