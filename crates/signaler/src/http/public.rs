use std::net::SocketAddr;

use futures::{channel::mpsc, pin_mut, select_biased, FutureExt, SinkExt, StreamExt};
use tokio::time::Duration;

use exogress_common::{
    entities::{AccountName, ProfileName, ProjectName},
    signaling::{InstanceConfigMessage, SignalerHandshakeResponse, WsInstanceToCloudMessage},
};
use warp::Filter;

use crate::termination::StopReason;
use exogress_common::common_utils::backoff::Backoff;
use exogress_server_common::{
    presence,
    presence::{Error, InstanceRegistered, UpstreamHealthReport},
};
use shadow_clone::shadow_clone;
use stop_handle::{StopHandle, StopWait};

const CONFIG_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const PING_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Debug, Serialize)]
struct CloseFrameReason {
    error: &'static str,
}

const CONFLICT_CLOSE_REASON: CloseFrameReason = CloseFrameReason { error: "conflict" };
const FORBIDDEN_CLOSE_REASON: CloseFrameReason = CloseFrameReason { error: "forbidden" };
const UNAUTHORIZED_CLOSE_REASON: CloseFrameReason = CloseFrameReason {
    error: "unauthorized",
};
const SERVER_ERROR_CLOSE_REASON: CloseFrameReason = CloseFrameReason {
    error: "internal server error",
};
const CONNECTION_FINISHED_CLOSE_REASON: CloseFrameReason = CloseFrameReason { error: "finished" };

#[derive(Debug, Deserialize)]
struct ChannelConnectParams {
    project: ProjectName,
    account: AccountName,
    labels: String,
    active_profile: Option<ProfileName>,
}

pub async fn server(
    listen_addr: SocketAddr,
    presence_client: presence::Client,
    redis: redis::Client,
    stop_handle: StopHandle<StopReason>,
    stop_wait: StopWait<stop_handle::StopReason<StopReason>>,
) {
    let presence = warp::path!("api" / "v1" / "channel")
        .and(warp::query::query::<ChannelConnectParams>())
        .and(warp::ws())
        .and(warp::header("authorization"))
        .map({
            move |channel_connect_params: ChannelConnectParams,
                  ws: warp::ws::Ws,
                  authorization: String| {
                shadow_clone!(redis);
                shadow_clone!(presence_client);
                shadow_clone!(stop_handle);

                ws.on_upgrade({
                    move |mut websocket| async move {
                        let start_time = crate::statistics::CHANELS_ESTABLISHMENT_TIME.start_timer();

                        let wait_first = async move {
                            loop {
                                let msg = websocket.next().await;
                                match msg {
                                    Some(Ok(m)) if m.is_text() => {
                                        return Ok((
                                            serde_json::from_str::<WsInstanceToCloudMessage>(
                                                m.to_str().unwrap(),
                                            )?,
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
                            Ok(Ok((
                                WsInstanceToCloudMessage::InstanceConfig(InstanceConfigMessage {
                                    config,
                                }),
                                mut websocket,
                            ))) => {
                                let InstanceRegistered {
                                    instance_id,
                                    access_key_id,
                                    account_unique_id,
                                    base_urls: _,
                                } = match presence_client
                                    .set_online(
                                        &authorization,
                                        &channel_connect_params.project,
                                        &channel_connect_params.account,
                                        &channel_connect_params.labels,
                                        &config,
                                        &channel_connect_params.active_profile,
                                    )
                                    .await
                                {
                                    Err(Error::Unauthorized) => {
                                        info!("Closing connection with unauthorized message");
                                        let _ = websocket
                                            .send(warp::filters::ws::Message::close_with(
                                                4001u16,
                                                serde_json::to_string_pretty(&UNAUTHORIZED_CLOSE_REASON).unwrap(),
                                            ))
                                            .await;
                                        crate::statistics::CHANNEL_ESTABLISHMENT_ERRORS.inc();
                                        return;
                                    }
                                    Err(Error::Forbidden) => {
                                        info!("Closing connection with forbidden message");
                                        crate::statistics::CHANNEL_ESTABLISHMENT_ERRORS.inc();
                                        let _ = websocket
                                            .send(warp::filters::ws::Message::close_with(
                                                4003u16,
                                                serde_json::to_string_pretty(&FORBIDDEN_CLOSE_REASON).unwrap()
                                            ))
                                            .await;
                                        return;
                                    }
                                    Err(Error::Conflict) => {
                                        info!("Closing connection with conflict message");
                                        crate::statistics::CHANNEL_ESTABLISHMENT_ERRORS.inc();

                                        let _ = websocket
                                            .send(warp::filters::ws::Message::close_with(
                                                4009u16,
                                                serde_json::to_string_pretty(&CONFLICT_CLOSE_REASON).unwrap()
                                            ))
                                            .await;
                                        return;
                                    }
                                    Err(Error::BadRequest(maybe_str)) => {
                                        info!(
                                            "Closing connection with bad request message: {}",
                                            maybe_str.as_ref().unwrap_or(&"".to_string())
                                        );
                                        crate::statistics::CHANNEL_ESTABLISHMENT_ERRORS.inc();
                                        let _ = websocket
                                            .send(warp::filters::ws::Message::close_with(
                                                4000u16,
                                                serde_json::to_string_pretty(&SERVER_ERROR_CLOSE_REASON).unwrap()
                                            ))
                                            .await;
                                        return;
                                    }
                                    Err(e) => {
                                        info!("could not set presence: {}", e);
                                        crate::statistics::CHANNEL_ESTABLISHMENT_ERRORS.inc();
                                        let _ = websocket
                                            .send(warp::filters::ws::Message::close_with(
                                                1011u16,
                                                serde_json::to_string_pretty(&SERVER_ERROR_CLOSE_REASON).unwrap()
                                            ))
                                            .await;
                                        return;
                                    }
                                    Ok(response) => {
                                        let _ = websocket
                                            .send(warp::filters::ws::Message::text(
                                                serde_json::to_string(
                                                    &SignalerHandshakeResponse::Ok {
                                                        instance_id: response.instance_id,
                                                        base_urls: response.base_urls.clone(),
                                                    },
                                                )
                                                .unwrap(),
                                            ))
                                            .await;
                                        response
                                    }
                                };

                                crate::statistics::ACTIVE_CHANNELS.inc();
                                start_time.observe_duration();

                                let r = {
                                    shadow_clone!(presence_client);
                                    shadow_clone!(authorization);

                                    async move {
                                        let mut messages_pubsub =
                                            redis.get_tokio_connection().await?.into_pubsub();
                                        let redis_subscription = format!(
                                            "signaler.{}.{}.{}",
                                            channel_connect_params.account,
                                            channel_connect_params.project,
                                            config.name
                                        );
                                        info!("subscribe to {}", redis_subscription);
                                        messages_pubsub.subscribe(redis_subscription).await?;

                                        let mut termination_pubsub =
                                            redis.get_tokio_connection().await?.into_pubsub();
                                        termination_pubsub
                                            .subscribe(format!(
                                                "revoke_access_token.{}",
                                                access_key_id
                                            ))
                                            .await?;
                                        termination_pubsub
                                            .subscribe(format!(
                                                "project_deleted.{}.{}",
                                                account_unique_id, channel_connect_params.project
                                            ))
                                            .await?;
                                        termination_pubsub
                                            .subscribe(format!(
                                                "instance_unreachable.{}",
                                                instance_id
                                            ))
                                            .await?;

                                        let mut from_redis_termination_notifications =
                                            termination_pubsub.on_message();
                                        let mut from_redis_messages = messages_pubsub.on_message();

                                        let (mut tx, mut rx) = websocket.split();

                                        let (mut to_ws_tx, mut to_ws_rx) = mpsc::channel(4);

                                        let forward_from_channel_to_ws = async move {
                                            while let Some(msg) = to_ws_rx.next().await {
                                                tx.send(msg).await?;
                                            }

                                            let _ = tx
                                                .send(warp::filters::ws::Message::close_with(
                                                    1000u16,
                                                    serde_json::to_string_pretty(&CONNECTION_FINISHED_CLOSE_REASON).unwrap()
                                                ))
                                                .await;

                                            Ok::<_, anyhow::Error>(())
                                        }
                                        .fuse();

                                        let forward_from_redis_to_ws_channel = {
                                            shadow_clone!(mut to_ws_tx);

                                            async move {
                                                while let Some(msg) =
                                                    from_redis_messages.next().await
                                                {
                                                    let payload: String = msg.get_payload()?;
                                                    to_ws_tx
                                                        .send(warp::filters::ws::Message::text(
                                                            payload,
                                                        ))
                                                        .await?;
                                                }

                                                Ok::<_, anyhow::Error>(())
                                            }
                                        }
                                        .fuse();

                                        let listen_for_termination_requests = {
                                            async move {
                                                if let Some(msg) =
                                                    from_redis_termination_notifications
                                                        .next()
                                                        .await
                                                {
                                                    let payload: String = msg.get_payload()?;
                                                    info!(
                                                        "Terminate by request. Payload = {}",
                                                        payload
                                                    );
                                                }

                                                Ok::<_, anyhow::Error>(())
                                            }
                                        }
                                        .fuse();

                                        let (mut incoming_ping_tx, incoming_ping_rx) =
                                            mpsc::channel(2);

                                        let process_incoming = {
                                            shadow_clone!(mut to_ws_tx);
                                            shadow_clone!(presence_client);
                                            shadow_clone!(authorization);

                                            async move {
                                                while let Some(msg_res) = rx.next().await {
                                                    match msg_res? {
                                                        msg if msg.is_text() => {
                                                            let msg_parsed = serde_json::from_str::<
                                                                WsInstanceToCloudMessage,
                                                            >(
                                                                msg.to_str().unwrap(),
                                                            )?;

                                                            match msg_parsed {
                                                                WsInstanceToCloudMessage::InstanceConfig(InstanceConfigMessage { config }) => {
                                                                    let instance_updated = presence_client
                                                                        .update_presence(
                                                                            &instance_id,
                                                                            &authorization,
                                                                            &config,
                                                                        )
                                                                        .await?;
                                                                    info!(
                                                                        "Base URLs served by the client: {}",
                                                                        itertools::join(
                                                                            instance_updated.base_urls.iter().map(|b| b.to_https_url()),
                                                                            ", "
                                                                        )
                                                                    );
                                                                }

                                                                WsInstanceToCloudMessage::HealthState(health_probes) => {
                                                                    presence_client
                                                                        .report_health(UpstreamHealthReport {
                                                                            instance_id,
                                                                            account_name: channel_connect_params.account.clone(),
                                                                            project_name: channel_connect_params.project.clone(),
                                                                            health_probes,
                                                                        })
                                                                        .await?
                                                                }
                                                            }
                                                        }
                                                        msg if msg.is_ping() => {
                                                            incoming_ping_tx.send(()).await?;
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
                                            let timeout_stream =
                                                tokio_stream::StreamExt::timeout(incoming_ping_rx, PING_INTERVAL * 2);

                                            pin_mut!(timeout_stream);

                                            while let Some(r) =
                                                futures::StreamExt::next(&mut timeout_stream).await
                                            {
                                                r?;
                                            }

                                            Ok::<_, anyhow::Error>(())
                                        }
                                        .fuse();

                                        pin_mut!(forward_from_redis_to_ws_channel);
                                        pin_mut!(listen_for_termination_requests);
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
                                            r = listen_for_termination_requests => {
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

                                let set_offline_backoff = Backoff::new(
                                    Duration::from_millis(100),
                                    Duration::from_secs(1),
                                );

                                pin_mut!(set_offline_backoff);

                                for _ in 0..10 {
                                    if let Err(e) = presence_client
                                        .set_offline(&instance_id, &authorization, false)
                                        .await
                                    {
                                        error!("could not unset presence: {}", e);
                                    } else {
                                        crate::statistics::ACTIVE_CHANNELS.dec();

                                        return;
                                    }
                                    set_offline_backoff.next().await;
                                }

                                crate::statistics::ACTIVE_CHANNELS.dec();

                                stop_handle.stop(StopReason::SetOfflineError);
                            }
                            Err(_e) => {
                                info!("timeout waiting for the first config");
                                crate::statistics::CHANNEL_ESTABLISHMENT_ERRORS.inc();
                            }
                            Ok(Err(e)) => {
                                info!("config error: {}", e);
                                crate::statistics::CHANNEL_ESTABLISHMENT_ERRORS.inc();
                            }
                            Ok(Ok(_)) => {
                                info!("unexpected first message. disconnect");
                                crate::statistics::CHANNEL_ESTABLISHMENT_ERRORS.inc();
                            }
                        }
                    }
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
