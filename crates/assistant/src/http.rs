use crate::{kafka::KafkaProducer, termination::StopReason, HttpsConfig};
use exogress_common::common_utils::backoff::Backoff;
use exogress_server_common::{
    assistant::{
        GatewayConfigMessage, GetValue, Notification, SetValue, WsFromGwMessage, WsToGwMessage,
    },
    dns_rules,
    kafka::GwStatisticsReport,
    logging::LogMessage,
};
use futures::{channel::mpsc, pin_mut, FutureExt, SinkExt, StreamExt};
use hashbrown::HashMap;
use redis::AsyncCommands;
use std::{convert::TryInto, io, net::SocketAddr, path::PathBuf};
use stop_handle::{StopHandle, StopWait};
use tokio::{
    io::AsyncReadExt,
    time::{sleep, Duration},
};
use tracing_futures::Instrument;
use warp::Filter;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayCommonTlsConfig {
    pub hostname: String,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
}

impl GatewayCommonTlsConfig {
    pub async fn ws_message(&self) -> io::Result<GatewayConfigMessage> {
        let mut certificate = String::new();
        tokio::fs::File::open(self.tls_cert_path.as_path())
            .await?
            .read_to_string(&mut certificate)
            .await?;

        let mut private_key = String::new();
        tokio::fs::File::open(self.tls_key_path.as_path())
            .await?
            .read_to_string(&mut private_key)
            .await?;

        Ok(GatewayConfigMessage {
            common_gw_hostname: self.hostname.clone(),
            common_gw_host_certificate: certificate,
            common_gw_host_private_key: private_key,
        })
    }
}

pub async fn server(
    listen_addr: SocketAddr,
    common_gw_tls_config: GatewayCommonTlsConfig,
    https_config: Option<HttpsConfig>,
    dns_rules_path: PathBuf,
    redis: redis::Client,
    presence_client: crate::presence::Client,
    kafka_producer: KafkaProducer,
    stop_handle: StopHandle<StopReason>,
    stop_wait: StopWait<StopReason>,
) {
    info!("Will spawn HTTP server on {}", listen_addr);

    let notifications = warp::path!("int_api" / "v1" / "gateways" / String / "notifications")
        .and(warp::filters::query::query::<HashMap<String, String>>())
        .and(warp::filters::ws::ws())
        .map({
            shadow_clone!(redis, presence_client, kafka_producer);

            move |gw_hostname: String, query: HashMap<String, String>, ws: warp::ws::Ws| {
                shadow_clone!(mut redis, common_gw_tls_config, presence_client, stop_handle, kafka_producer);

                let gw_location = query.get("location").unwrap().clone();

                let start_time = crate::statistics::CHANELS_ESTABLISHMENT_TIME.start_timer();
                ws.on_upgrade(move |websocket| {
                    {
                        shadow_clone!(gw_hostname,stop_handle,kafka_producer);

                        async move {
                            match presence_client.set_online(&gw_hostname).await {
                                Ok(_) => {
                                    info!("set gw presence successfully");
                                    let (mut ws_tx, mut ws_rx) = websocket.split();
                                    let (mut ch_ws_tx, mut ch_ws_rx) = mpsc::channel(16);
                                    let (mut pong_tx, pong_rx) = mpsc::channel(16);

                                    let forward_to_ws = async move {
                                        while let Some(msg) = ch_ws_rx.next().await {
                                            // info!("send to WS: {:?}", msg);
                                            ws_tx.send(msg).await?;
                                        }

                                        Ok::<_, anyhow::Error>(())
                                    };

                                    #[allow(unreachable_code)]
                                        let ensure_pong_received = async move {
                                        let timeout_stream = tokio_stream::StreamExt::timeout(pong_rx, Duration::from_secs(30));

                                        pin_mut!(timeout_stream);

                                        while let Some(r) = timeout_stream.next().await {
                                            // info!("New pong received. Will wait next 30 seconds until the next one");
                                            r?;
                                        }

                                        Ok::<_, anyhow::Error>(())
                                    };

                                    let (mut statistics_saver_tx, mut statistics_saver_rx) = mpsc::channel(128);
                                    let (mut logs_saver_tx, mut logs_saver_rx) = mpsc::channel::<Vec<LogMessage>>(128);

                                    let logs_saver = tokio::spawn({
                                        shadow_clone!(kafka_producer);

                                        async move {
                                            while let Some(messages) = logs_saver_rx.next().await {
                                                let r = kafka_producer.send_log_message(messages).await;

                                                info!("Kafka send Log Messages res = {:?}", r);
                                            }

                                            Ok::<_, anyhow::Error>(())
                                        }
                                    });


                                    let statistics_saver = tokio::spawn({
                                        shadow_clone!(gw_hostname, gw_location);

                                        async move {
                                            while let Some(report) = statistics_saver_rx.next().await {
                                                let r = kafka_producer.send_statistics_report(
                                                    &GwStatisticsReport {
                                                        report,
                                                        gw_hostname: gw_hostname.clone(),
                                                        gw_location: gw_location.clone(),
                                                    },
                                                ).await;

                                                info!("Kafka send statistics res = {:?}", r);
                                            }

                                            Ok::<_, anyhow::Error>(())
                                        }
                                    });

                                    let msg_receiver = {
                                        async move {
                                            while let Some(Ok(msg)) = ws_rx.next().await {
                                                // info!("received from WS: {:?}", msg);

                                                if msg.is_text() {
                                                    let txt = msg.to_str().unwrap().to_string();
                                                    match serde_json::from_str::<WsFromGwMessage>(&txt) {
                                                        Ok(msg) => {
                                                            crate::statistics::GW_MESSAGES_PARSED
                                                                .with_label_values(&[
                                                                    "",
                                                                ])
                                                                .inc();

                                                            match msg {
                                                                WsFromGwMessage::Statistics { report } => {
                                                                    statistics_saver_tx.send(report).await?;
                                                                },
                                                                WsFromGwMessage::Logs { report } => {
                                                                    logs_saver_tx.send(report).await?;
                                                                }
                                                                _ => {},
                                                            }
                                                        }
                                                        Err(e) => {
                                                            crate::statistics::GW_MESSAGES_PARSED
                                                                .with_label_values(&[
                                                                    "1",
                                                                ])
                                                                .inc();
                                                            error!("Error parsing WsFromGwMessage: {}", e);
                                                        }
                                                    }
                                                } else if msg.is_ping() {
                                                    //     pongs are automatic
                                                } else if msg.is_pong() {
                                                    pong_tx.send(()).await?;
                                                } else {
                                                    info!("unexpected message received. exiting: {:?}", msg);
                                                    break;
                                                }
                                            }

                                            Ok::<_, anyhow::Error>(())
                                        }
                                    };

                                    let notifier = async move {
                                        let outgoing_msg = serde_json::to_string(&WsToGwMessage::GwConfig(common_gw_tls_config.ws_message().await?))?;

                                        tokio::time::timeout(Duration::from_secs(5), ch_ws_tx.send(warp::filters::ws::Message::text(outgoing_msg))).await??;

                                        match redis.get_async_connection().await {
                                            Ok(conn) => {
                                                let mut pubsub = conn.into_pubsub();

                                                match pubsub.subscribe("invalidations").await {
                                                    Ok(_) => {
                                                        info!("subscribed to invalidations");
                                                        let mut messages = pubsub.into_on_message();

                                                        let forward_from_redis = {
                                                            shadow_clone!(mut ch_ws_tx);

                                                            async move {
                                                                while let Some(msg) = messages.next().await {
                                                                    match msg.get_payload::<String>() {
                                                                        Ok(p) => {
                                                                            info!("redis -> assistant: {:?}", p);
                                                                            match serde_json::from_str::<Notification>(&p) {
                                                                                Ok(notification) => {
                                                                                    let outgoing_msg = serde_json::to_string(&WsToGwMessage::WebAppNotification(notification))
                                                                                        .expect("could not serialize");
                                                                                    let r = tokio::time::timeout(Duration::from_secs(5), ch_ws_tx
                                                                                        .send(warp::filters::ws::Message::text(
                                                                                            outgoing_msg,
                                                                                        ))).await;
                                                                                    match r {
                                                                                        Err(_) => {
                                                                                            error!(
                                                                                                "timeout sending to websocket",
                                                                                            );
                                                                                            return;
                                                                                        }
                                                                                        Ok(Err(e)) => {
                                                                                            error!(
                                                                                                "error sending to websocket: {}",
                                                                                                e
                                                                                            );
                                                                                            return;
                                                                                        }
                                                                                        Ok(Ok(_)) => {}
                                                                                    }
                                                                                }
                                                                                Err(e) => {
                                                                                    error!("notification format error: {}", e);
                                                                                    return;
                                                                                }
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

                                                        #[allow(unreachable_code)]
                                                            let periodically_send_ping = {
                                                            shadow_clone!(mut ch_ws_tx);

                                                            async move {
                                                                loop {
                                                                    sleep(Duration::from_secs(15)).await;

                                                                    tokio::time::timeout(Duration::from_secs(5), ch_ws_tx
                                                                        .send(warp::filters::ws::Message::ping("")))
                                                                        .await??;
                                                                }

                                                                Ok::<_, anyhow::Error>(())
                                                            }
                                                        };

                                                        tokio::select! {
                                                            r = forward_from_redis => {
                                                                info!("forward_from_redis closed: {:?}", r);
                                                            },
                                                            r = periodically_send_ping => {
                                                                info!("periodically_send_ping closed: {:?}", r);
                                                            },
                                                        }

                                                        info!("WS forwarder closed");
                                                    }
                                                    Err(e) => {
                                                        error!("couldn't subscribe to invalidation_groups: {}", e)
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                error!("redis server connection  error: {}", e);
                                            }
                                        }

                                        let res = tokio::time::timeout(Duration::from_secs(5), ch_ws_tx.send(warp::filters::ws::Message::close()) ).await;
                                        info!("Send close message result = {:?}", res);

                                        Ok::<_, anyhow::Error>(())
                                    };

                                    crate::statistics::ACTIVE_CHANNELS.inc();
                                    start_time.observe_duration();

                                    tokio::select! {
                                        r = notifier => {
                                            warn!("WS connection closed: {:?}", r);
                                        },
                                        r = msg_receiver => {
                                            warn!("WS statistics_saver closed: {:?}", r);
                                        },
                                        r = forward_to_ws => {
                                            warn!("WS forward_to_ws stopped: {:?}", r);
                                        },
                                        r = statistics_saver => {
                                            warn!("statistics_saver stopped: {:?}", r);
                                        },
                                        r = logs_saver => {
                                            warn!("logs_saver stopped: {:?}", r);
                                        },
                                        r = ensure_pong_received => {
                                            warn!("WS ensure_pong_received stopped: {:?}", r);
                                        },
                                    };

                                    let set_offline_backoff =
                                        Backoff::new(Duration::from_millis(100), Duration::from_secs(1));

                                    pin_mut!(set_offline_backoff);

                                    for _ in 0..10 {
                                        if let Err(e) = presence_client
                                            .set_offline(&gw_hostname)
                                            .await
                                        {
                                            error!("could not unset presence: {}", e);
                                        } else {
                                            info!("unset gw presence successfully");
                                            crate::statistics::ACTIVE_CHANNELS.inc();
                                            return;
                                        }
                                        set_offline_backoff.next().await;
                                    }

                                    stop_handle.stop(StopReason::SetOfflineError);
                                }
                                Err(e) => {
                                    warn!("failed to set gateway presence: {:?}", e);
                                }
                            }

                            info!("ws connection closed");
                        }
                    }.instrument(tracing::info_span!("gw", host = gw_hostname.as_str()))
                })
            }
        });

    let save_kv = warp::path!("int_api" / "v1" / "keys" / String)
        .and(warp::filters::method::post())
        .and(warp::filters::body::json::<SetValue>())
        .and_then({
            shadow_clone!(redis);

            move |key: String, body: SetValue| {
                shadow_clone!(redis);

                async move {
                    let res: Result<(), redis::RedisError> = async move {
                        let mut redis_conn = redis.get_async_connection().await?;

                        info!("set key: {} => {:?}", key, body);
                        redis_conn
                            .set_ex(
                                key.as_str(),
                                body.payload,
                                body.ttl.as_secs().try_into().unwrap(),
                            )
                            .await?;

                        Ok(())
                    }
                    .await;

                    match res {
                        Ok(()) => Ok::<_, warp::reject::Rejection>(warp::reply::json(&())),
                        Err(e) => {
                            error!("redis error: {}", e);
                            Err(warp::reject())
                        }
                    }
                }
            }
        });

    let get_kv =
        warp::path!("int_api" / "v1" / "keys" / String)
            .and(warp::filters::method::get())
            .and_then({
                shadow_clone!(redis);

                move |key: String| {
                    shadow_clone!(redis);

                    async move {
                        let res: Result<Option<String>, redis::RedisError> = async move {
                            let mut redis_conn = redis.get_async_connection().await?;

                            let maybe_resp: Option<String> = redis_conn.get(key.as_str()).await?;
                            if let Some(resp) = maybe_resp {
                                redis_conn.del(key.as_str()).await?;
                                Ok(Some(resp))
                            } else {
                                Ok(None)
                            }
                        }
                        .await;

                        match res {
                            Ok(Some(payload)) => Ok::<_, warp::reject::Rejection>(
                                warp::reply::json::<GetValue>(&GetValue { payload }),
                            ),
                            Ok(None) => Err(warp::reject::not_found()),
                            Err(_e) => Err(warp::reject::custom(InternalServerError {})),
                        }
                    }
                }
            });

    let dns_rules = warp::path!("int_api" / "v1" / "dns_rules")
        .and(warp::filters::method::get())
        .and_then({
            shadow_clone!(dns_rules_path);

            move || {
                shadow_clone!(dns_rules_path);

                async move {
                    let res = async move {
                        let mut file = tokio::fs::File::open(dns_rules_path).await?;
                        let mut v = Vec::new();

                        file.read_to_end(&mut v).await?;

                        let rules: dns_rules::Main = serde_yaml::from_slice(&v)?;

                        Ok::<_, anyhow::Error>(rules)
                    }
                    .await;

                    match res {
                        Ok(rules) => {
                            Ok::<_, warp::reject::Rejection>(warp::reply::json::<dns_rules::Main>(
                                &rules,
                            ))
                        }
                        Err(e) => {
                            error!("Error reading DNS rules: {}", e);
                            Err(warp::reject::custom(InternalServerError {}))
                        }
                    }
                }
            }
        });

    let health = warp::path!("int" / "healthcheck")
        .and(warp::filters::method::get())
        .and_then({
            shadow_clone!(redis);

            move || {
                shadow_clone!(redis);

                async move {
                    let res = async move {
                        let mut redis_conn = redis.get_async_connection().await?;
                        let r = redis_conn.set("assistant_healthcheck", "1").await?;
                        Ok::<String, redis::RedisError>(r)
                    }
                    .await;

                    if let Err(e) = res {
                        error!("health check: redis error: {}", e);
                        return Ok::<_, warp::reject::Rejection>(
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        );
                    }

                    Ok::<_, warp::reject::Rejection>(warp::http::StatusCode::OK)
                }
            }
        });

    let metrics = warp::path!("metrics").map(crate::statistics::dump_prometheus);

    info!("Spawning...");

    let combined = warp::serve(
        notifications
            .or(dns_rules)
            .or(save_kv)
            .or(get_kv)
            .or(metrics)
            .or(health),
    );

    match https_config {
        Some(https_config) => {
            combined
                .tls()
                .key(https_config.int_tls_key)
                .cert(https_config.int_tls_cert)
                .client_auth_required(https_config.int_tls_auth_ca)
                .bind_with_graceful_shutdown(
                    listen_addr,
                    stop_wait
                        .map(move |r| info!("private HTTP server stop request received: {}", r)),
                )
                .1
                .await;
        }
        None => {
            combined
                .bind_with_graceful_shutdown(
                    listen_addr,
                    stop_wait
                        .map(move |r| info!("private HTTP server stop request received: {}", r)),
                )
                .1
                .await;
        }
    }

    info!("HTTP server stopped");
}

#[derive(Debug)]
pub struct InternalServerError {}

impl warp::reject::Reject for InternalServerError {}
