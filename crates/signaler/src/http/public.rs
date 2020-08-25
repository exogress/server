use std::net::SocketAddr;

use futures::{pin_mut, select_biased, FutureExt, SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::time::Duration;

use exogress_config_core::Config;
use exogress_entities::{AccountName, InstanceId, ProjectName};
use warp::Filter;

use crate::presence;
use crate::presence::Error;
use crate::termination::StopReason;
use exogress_common_utils::backoff::Backoff;
use shadow_clone::shadow_clone;
use stop_handle::{StopHandle, StopWait};

const CONFIG_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const PING_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Debug, Deserialize)]
struct Workspace {
    project: ProjectName,
    account: AccountName,
}

pub async fn server(
    listen_addr: SocketAddr,
    presence_client: presence::Client,
    redis: redis::Client,
    stop_handle: StopHandle<StopReason>,
    stop_wait: StopWait<stop_handle::StopReason<StopReason>>,
) {
    let presence = warp::path!("api" / "v1" / "instances" / String / "channel")
        .and_then(|instance_id: String| async move {
            match instance_id.parse::<InstanceId>() {
                Err(_e) => Err(warp::reject::custom(BadInstanceId {})),
                Ok(instance_id) => Ok(instance_id),
            }
        })
        .and(warp::query::query::<Workspace>())
        .and(warp::ws())
        .and(warp::header("authorization"))
        .map({
            move |instance_id: InstanceId,
                  workspace: Workspace,
                  ws: warp::ws::Ws,
                  authorization: String| {
                shadow_clone!(redis);
                shadow_clone!(presence_client);
                shadow_clone!(stop_handle);

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
                        Ok(Ok((config, mut websocket))) => {
                            match presence_client
                                .set_online(
                                    &instance_id,
                                    &authorization,
                                    &workspace.project,
                                    &workspace.account,
                                    &config,
                                )
                                .await
                            {
                                Err(Error::Unauthorized) => {
                                    info!("Closing connection with unauthorized message");
                                    let _ = websocket
                                        .send(warp::filters::ws::Message::close_with(
                                            4001u16,
                                            "unauthorized",
                                        ))
                                        .await;
                                    return;
                                }
                                Err(Error::Forbidden) => {
                                    info!("Closing connection with forbidden message");
                                    let _ = websocket
                                        .send(warp::filters::ws::Message::close_with(
                                            4003u16,
                                            "forbidden",
                                        ))
                                        .await;
                                    return;
                                }
                                Err(Error::Conflict) => {
                                    info!("Closing connection with conflict message");
                                    let _ = websocket
                                        .send(warp::filters::ws::Message::close_with(
                                            4009u16, "conflict",
                                        ))
                                        .await;
                                    return;
                                }
                                Err(Error::BadRequest(maybe_str)) => {
                                    info!("Closing connection with conflict message");
                                    let _ = websocket
                                        .send(warp::filters::ws::Message::close_with(
                                            4000u16,
                                            format!(
                                                "bad request: {}",
                                                maybe_str.unwrap_or("no error specified".into())
                                            ),
                                        ))
                                        .await;
                                    return;
                                }
                                Err(e) => {
                                    info!("could not set presence: {}", e);
                                    let _ = websocket
                                        .send(warp::filters::ws::Message::close_with(
                                            1011u16,
                                            "server error",
                                        ))
                                        .await;
                                    return;
                                }
                                Ok(_) => {}
                            };

                            let r = {
                                shadow_clone!(presence_client);
                                shadow_clone!(authorization);

                                async move {
                                    let mut pubsub =
                                        redis.get_tokio_connection_tokio().await?.into_pubsub();
                                    let redis_subscription = format!(
                                        "signaler.{}.{}.{}",
                                        workspace.account, workspace.project, config.name
                                    );
                                    info!("subscribe to {}", redis_subscription);
                                    pubsub.subscribe(redis_subscription).await?;
                                    let mut from_redis_messages = pubsub.on_message();

                                    let (mut tx, mut rx) = websocket.split();

                                    let (mut to_ws_tx, mut to_ws_rx) = mpsc::channel(4);

                                    let forward_from_channel_to_ws = async move {
                                        while let Some(msg) = to_ws_rx.next().await {
                                            tx.send(msg).await?;
                                        }

                                        let _ = tx
                                            .send(warp::filters::ws::Message::close_with(
                                                1000u16, "finished",
                                            ))
                                            .await;

                                        Ok::<_, anyhow::Error>(())
                                    }
                                    .fuse();

                                    let forward_from_redis_to_ws_channel = {
                                        shadow_clone!(mut to_ws_tx);

                                        async move {
                                            while let Some(msg) = from_redis_messages.next().await {
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
                                        shadow_clone!(mut to_ws_tx);
                                        shadow_clone!(presence_client);
                                        shadow_clone!(authorization);

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

                    let mut set_offline_backoff =
                        Backoff::new(Duration::from_millis(100), Duration::from_secs(1));

                    for _ in 0..10 {
                        if let Err(e) = presence_client
                            .set_offline(&instance_id, &authorization)
                            .await
                        {
                            error!("could not unset presence: {}", e);
                        } else {
                            return;
                        }
                        set_offline_backoff.next().await;
                    }

                    stop_handle.stop(StopReason::SetOfflineError);

                    futures::future::pending::<()>().await;
                })
            }
        });

    let (_, server) = warp::serve(presence).bind_with_graceful_shutdown(
        listen_addr,
        stop_wait.map(move |r| info!("public HTTP server stop request received: {}", r)),
    );

    server.await;

    info!("public HTTP server stopped");
}

#[derive(Debug)]
pub struct BadInstanceId {}

impl warp::reject::Reject for BadInstanceId {}
