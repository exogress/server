use crate::clickhouse::Clickhouse;
use crate::termination::StopReason;
use exogress_server_common::assistant::{
    GatewayConfigMessage, GetValue, Notification, SetValue, StatisticsReport, WsFromGwMessage,
    WsToGwMessage,
};
use futures::{FutureExt, SinkExt, StreamExt};
use hashbrown::HashMap;
use redis::AsyncCommands;
use std::convert::TryInto;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use stop_handle::StopWait;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::time::{delay_for, Duration};
use tracing_futures::Instrument;
use warp::Filter;

// TODO: add pings

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
    redis: redis::Client,
    clickhouse_client: Clickhouse,
    stop_wait: StopWait<StopReason>,
) {
    info!("Will spawn HTTP server on {}", listen_addr);

    let notifications = warp::path!("api" / "v1" / "gateways" / String / "notifications")
        .and(warp::filters::query::query::<HashMap<String, String>>())
        .and(warp::filters::ws::ws())
        .map({
            shadow_clone!(redis);
            shadow_clone!(clickhouse_client);

            move |gw_hostname: String, query: HashMap<String, String>, ws: warp::ws::Ws| {
                shadow_clone!(mut redis);
                shadow_clone!(common_gw_tls_config);
                shadow_clone!(clickhouse_client);

                let gw_location = query.get("location").unwrap().clone();

                ws.on_upgrade(move |websocket| {
                    {
                        shadow_clone!(gw_hostname);

                        async move {
                            let (mut ws_tx, mut ws_rx) = websocket.split();

                            let statistics_saver = {
                                shadow_clone!(gw_hostname);

                                async move {
                                    shadow_clone!(gw_hostname);

                                    while let Some(Ok(msg)) = ws_rx.next().await {
                                        shadow_clone!(gw_hostname);

                                        if msg.is_text() {
                                            let msg = serde_json::from_str::<WsFromGwMessage>(msg.to_str().unwrap()).expect("FIXME");
                                            info!("received statistics notification: {:?}", msg);
                                            match msg {
                                                WsFromGwMessage::Statistics { report: StatisticsReport::Traffic { records } } => {
                                                    clickhouse_client.register_traffic_report(records, &gw_hostname, &gw_location).await?;
                                                }
                                                _ => {},
                                            }
                                        }
                                    }

                                    Ok::<_, anyhow::Error>(())
                                }
                            };

                            let notifier = async move {
                                let outgoing_msg = serde_json::to_string(&WsToGwMessage::GwConfig(common_gw_tls_config.ws_message().await?))?;

                                ws_tx.send(warp::filters::ws::Message::text(outgoing_msg)).await?;

                                match redis.get_async_connection().await {
                                    Ok(conn) => {
                                        let mut pubsub = conn.into_pubsub();

                                        match pubsub.subscribe("invalidations").await {
                                            Ok(_) => {
                                                info!("subscribed to invalidations");
                                                let mut messages = pubsub.into_on_message();

                                                let (mut to_ws_tx, mut to_ws_rx) = mpsc::channel(16);

                                                let forward_channel_to_ws = async {
                                                    while let Some(msg) = to_ws_rx.next().await {
                                                        ws_tx.send(msg).await?;
                                                    }

                                                    Ok::<_, anyhow::Error>(())
                                                };

                                                let forward_from_redis = {
                                                    shadow_clone!(mut to_ws_tx);

                                                    async move {
                                                        while let Some(msg) = messages.next().await {
                                                            match msg.get_payload::<String>() {
                                                                Ok(p) => {
                                                                    info!("redis -> assistant: {:?}", p);
                                                                    match serde_json::from_str::<Notification>(&p) {
                                                                        Ok(notification) => {
                                                                            let outgoing_msg = serde_json::to_string(&WsToGwMessage::WebAppNotification(notification))
                                                                                .expect("could not serialize");
                                                                            if let Err(e) = to_ws_tx
                                                                                .send(warp::filters::ws::Message::text(
                                                                                    outgoing_msg,
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
                                            Err(e) => {
                                                error!("couldn't subscribe to invalidations: {}", e)
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("redis server connection  error: {}", e);
                                    }
                                }

                                let _ = ws_tx.send(warp::filters::ws::Message::close()).await;

                                Ok::<_, anyhow::Error>(())
                            };

                            tokio::select! {
                                r = notifier => {
                                    if let Err(e) = r {
                                        warn!("Error on WS connection: {}", e);
                                    }
                                },
                                r = statistics_saver => {
                                    if let Err(e) = r {
                                        warn!("Error on WS statistics_saver: {}", e);
                                    }
                                },
                            }
                        }
                    }.instrument(tracing::info_span!("gw", host = gw_hostname.as_str()))
                })
            }
        });

    let save_kv = warp::path!("api" / "v1" / "keys" / String)
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

    let get_kv = warp::path!("api" / "v1" / "keys" / String)
        .and(warp::filters::method::get())
        .and_then({
            shadow_clone!(redis);

            move |key: String| {
                shadow_clone!(redis);

                async move {
                    let res: Result<String, redis::RedisError> = async move {
                        let mut redis_conn = redis.get_async_connection().await?;

                        info!("retrieve key: {}", key);
                        let r = redis_conn.get(key.as_str()).await?;
                        redis_conn.del(key.as_str()).await?;
                        info!("result: {}", r);

                        Ok(r)
                    }
                    .await;

                    match res {
                        Ok(payload) => {
                            Ok::<_, warp::reject::Rejection>(warp::reply::json::<GetValue>(
                                &GetValue { payload },
                            ))
                        }
                        Err(e) => {
                            error!("redis error: {}", e);
                            Err(warp::reject::not_found())
                        }
                    }
                }
            }
        });

    info!("Spawning...");
    let (_, server) = warp::serve(
        notifications
            .or(save_kv)
            .or(get_kv)
            .with(warp::trace::request()),
    )
    .bind_with_graceful_shutdown(
        listen_addr,
        stop_wait.map(move |r| info!("private HTTP server stop request received: {}", r)),
    );

    server.await;

    info!("private HTTP server stopped");
}

#[derive(Debug)]
pub struct InternalServerError {}

impl warp::reject::Reject for InternalServerError {}
