use futures::{SinkExt, StreamExt};

use crate::{
    clients::ClientTunnels,
    registry::RequestsProcessorsRegistry,
    stop_reasons::{AppStopHandle, StopReason},
    webapp,
};
use chrono::{TimeZone, Utc};
use core::mem;
use exogress_common::ws_client::{connect_ws_resolved, Error};
use exogress_server_common::assistant::{
    Action, GatewayConfigMessage, WsFromGwMessage, WsToGwMessage,
};
use futures::{channel::mpsc, pin_mut};
use hashbrown::HashSet;
use parking_lot::{Mutex, RwLock};
use rand::{prelude::IteratorRandom, thread_rng, SeedableRng};
use smol_str::SmolStr;
use std::{
    net::IpAddr,
    str::FromStr,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{net::TcpStream, time::sleep};
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::{
    tungstenite,
    tungstenite::{handshake::client::Request, http::Method},
    WebSocketStream,
};
use tokio_util::either::Either;
use tracing::Instrument;
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;

pub struct AssistantClient {
    client_tunnels: ClientTunnels,
    stop_handle: AppStopHandle,
    webapp_client: webapp::Client,
    mappings: RequestsProcessorsRegistry,
    tls_gw_common: Arc<RwLock<Option<GatewayConfigMessage>>>,
    gw_to_assistant_messages_rx: mpsc::Receiver<WsFromGwMessage>,
    concurrency: u8,
    established_ips: Arc<tokio::sync::Mutex<HashSet<IpAddr>>>,
    assistant_base_url: Url,
    individual_hostname: SmolStr,
    gw_location: SmolStr,
    maybe_identity: Option<Vec<u8>>,
    resolver: TokioAsyncResolver,
}

impl AssistantClient {
    pub async fn new(
        assistant_base_url: Url,
        concurrency: u8,
        individual_hostname: &str,
        gw_location: SmolStr,
        mappings: &RequestsProcessorsRegistry,
        client_tunnels: &ClientTunnels,
        tls_gw_common: Arc<RwLock<Option<GatewayConfigMessage>>>,
        gw_to_assistant_messages_rx: mpsc::Receiver<WsFromGwMessage>,
        maybe_identity: Option<Vec<u8>>,
        webapp_client: &webapp::Client,
        resolver: TokioAsyncResolver,
        app_stop_handle: &AppStopHandle,
    ) -> Result<AssistantClient, Error> {
        shadow_clone!(mappings);

        Ok(AssistantClient {
            client_tunnels: client_tunnels.clone(),
            webapp_client: webapp_client.clone(),
            stop_handle: app_stop_handle.clone(),
            mappings,
            tls_gw_common,
            gw_to_assistant_messages_rx,
            concurrency,
            established_ips: Arc::new(Default::default()),
            assistant_base_url,
            individual_hostname: individual_hostname.into(),
            gw_location,
            maybe_identity,
            resolver,
        })
    }

    async fn establish_connection(
        assistant_base_url: Url,
        individual_hostname: SmolStr,
        gw_location: SmolStr,
        maybe_identity: Option<Vec<u8>>,
        ip: IpAddr,
    ) -> Result<WebSocketStream<Either<TlsStream<TcpStream>, TcpStream>>, anyhow::Error> {
        let scheme = assistant_base_url.scheme().to_string();

        let mut url = assistant_base_url.clone();
        {
            let mut segments = url.path_segments_mut().unwrap();
            segments
                .push("int_api")
                .push("v1")
                .push("gateways")
                .push(individual_hostname.as_str())
                .push("notifications");
        }
        url.query_pairs_mut()
            .append_pair("location", gw_location.as_str());

        if scheme == "https" {
            url.set_scheme("wss").unwrap();
        } else if scheme == "http" {
            url.set_scheme("ws").unwrap();
        };

        let notifier_req = Request::builder()
            .method(Method::GET)
            .uri(url.to_string())
            .body(())
            .unwrap();

        info!("connecting to notification listener..");
        let (stream, _resp) = connect_ws_resolved(notifier_req, ip, maybe_identity.clone()).await?;

        Ok(stream)
    }

    pub async fn spawn(self) {
        let tls_gw_common = self.tls_gw_common;
        let client_tunnels = self.client_tunnels;
        let webapp_client = self.webapp_client;
        let mappings = self.mappings;
        let mut gw_to_assistant_messages_rx = self.gw_to_assistant_messages_rx;
        let stop_handle = self.stop_handle.clone();
        let assistant_base_url = self.assistant_base_url.clone();
        let maybe_identity = self.maybe_identity.clone();
        let gw_location = self.gw_location.clone();
        let individual_hostname = self.individual_hostname.clone();

        let resolver = self.resolver.clone();
        let host = self
            .assistant_base_url
            .host_str()
            .expect("no host in assistant base URL")
            .to_string();

        let established_ips = self.established_ips.clone();

        let mut to_assistant_streams = Vec::new();
        let mut from_assistant_streams = Vec::new();
        let num_connections = Arc::new(AtomicU8::new(0));
        let latest_msg_time = Arc::new(Mutex::new(Utc.timestamp(0, 0)));

        for conn_idx in 0..self.concurrency {
            shadow_clone!(
                resolver,
                host,
                established_ips,
                assistant_base_url,
                individual_hostname,
                gw_location,
                maybe_identity,
                stop_handle,
                num_connections,
                latest_msg_time
            );

            let (from_assistant_tx, from_assistant_rx) = mpsc::channel(16);
            let (to_assistant_tx, to_assistant_rx) = mpsc::channel(16);

            from_assistant_streams.push(from_assistant_rx);
            to_assistant_streams.push(to_assistant_tx);

            tokio::spawn(
                #[allow(unreachable_code)]
                    async move {
                    let mut to_assistant_rx = to_assistant_rx;

                    info!("spawning assistant client consumer... host = {}", host);
                    loop {
                        let ip = if let Ok(ip) = IpAddr::from_str(host.as_str()) {
                            ip
                        } else {
                            loop {
                                let mut established_ips = established_ips.lock().await;
                                let resolved_ips: HashSet<IpAddr> = resolver
                                    .lookup_ip(host.as_str())
                                    .await?
                                    .into_iter()
                                    .collect();
                                let may_use_ips = resolved_ips.difference(&*established_ips);

                                let select_result = may_use_ips.choose(&mut thread_rng()).cloned();

                                match select_result {
                                    Some(selected_ip) => {
                                        info!("will connect to assistant IP {:?}", selected_ip);
                                        established_ips.insert(selected_ip);
                                        break selected_ip;
                                    }
                                    None => {
                                        // no IP available
                                        warn!("no assistant IP address is available for exclusive connection");
                                        mem::drop(established_ips);
                                        sleep(Duration::from_secs(1)).await;
                                    }
                                };
                            }
                        };

                        info!("using IP {:?}", ip);

                        match Self::establish_connection(
                            assistant_base_url.clone(),
                            individual_hostname.clone(),
                            gw_location.clone(),
                            maybe_identity.clone(),
                            ip,

                        ).await {
                            Ok(stream) => {
                                let (mut ws_tx, mut ws_rx) = stream.split();
                                let (mut ch_ws_tx, mut ch_ws_rx) = mpsc::channel(16);
                                let (mut pong_tx, pong_rx) = mpsc::channel::<()>(16);

                                let forward_to_ws = async move {
                                    while let Some(msg) = ch_ws_rx.next().await {
                                        ws_tx.send(msg).await?;
                                    }

                                    Ok::<_, anyhow::Error>(())
                                };

                                #[allow(unreachable_code)]
                                    let consume = {
                                    shadow_clone!(stop_handle, mut ch_ws_tx, mut from_assistant_tx, num_connections, latest_msg_time);

                                    async move {
                                        let mut is_first_received = false;
                                        while let Some(msg) = ws_rx.next().await {
                                            match msg {
                                                Err(e) => {
                                                    warn!("Error while receiving from Notifier: {}", e);
                                                    break;
                                                }
                                                Ok(msg) if msg.is_text() => {
                                                    if !is_first_received {
                                                        is_first_received = true;
                                                        num_connections.fetch_add(1, Ordering::Relaxed);
                                                    }

                                                    let text = msg.into_text().unwrap();

                                                    match serde_json::from_str::<WsToGwMessage>(text.as_str()) {
                                                        Ok(ws_message) => {
                                                            if let WsToGwMessage::WebAppNotification(notification) = &ws_message {
                                                                let mut locked = latest_msg_time.lock();
                                                                if notification.generated_at <= *locked {
                                                                    debug!("skip duplicate message {:?}", notification);
                                                                    continue;
                                                                }
                                                                debug!("accept the first message {:?}", notification);
                                                                *locked = notification.generated_at;
                                                            }

                                                            if let Err(_e) = from_assistant_tx.send(ws_message).await {
                                                                error!("error sending packet from websocket to aggregated receiver");
                                                                stop_handle.stop(StopReason::NotificationChannelError);
                                                            }
                                                        }
                                                        Err(e) => {
                                                            error!("error parsing notification from assistant: {}", e);
                                                            break;
                                                        }
                                                    }
                                                }
                                                Ok(msg) if msg.is_ping() => {
                                                    //     pongs are automatic
                                                }
                                                Ok(msg) if msg.is_pong() => {
                                                    pong_tx.send(()).await?;
                                                }
                                                Ok(msg) => {
                                                    error!("received unexpected message from assistant: {:?}", msg);
                                                    break;
                                                }
                                            }
                                        }

                                        Ok::<_, anyhow::Error>(())
                                    }
                                };

                                #[allow(unreachable_code)]
                                    let ensure_pong_received = async move {
                                    let timeout_stream =
                                        tokio_stream::StreamExt::timeout(pong_rx, Duration::from_secs(30));

                                    pin_mut!(timeout_stream);

                                    while let Some(r) = timeout_stream.next().await {
                                        // info!("New pong received. Will wait next 30 seconds until the next one");
                                        r?;
                                    }

                                    Ok::<_, anyhow::Error>(())
                                };

                                #[allow(unreachable_code)]
                                    let periodically_send_ping = {
                                    shadow_clone!(mut ch_ws_tx);

                                    async move {
                                        loop {
                                            sleep(Duration::from_secs(15)).await;

                                            tokio::time::timeout(
                                                Duration::from_secs(5),
                                                ch_ws_tx.send(tungstenite::Message::Ping(vec![])),
                                            )
                                                .await??;
                                        }

                                        Ok::<_, anyhow::Error>(())
                                    }
                                };


                                let produce = {
                                    // shadow_clone!(mut ch_ws_tx, stop_handle);

                                    async {
                                        while let Some(report) = (&mut to_assistant_rx).next().await {
                                            debug!(
                                                "received statistics report. will send to assistant WS: {:?}",
                                                report
                                            );
                                            let report = simd_json::to_string(&report).unwrap();
                                            if let Err(e) = (&mut ch_ws_tx).send(tungstenite::Message::Text(report)).await
                                            {
                                                // TODO: here we miss some statistics report
                                                error!("send statistics error: {:?}", e);
                                                break;
                                            }
                                        }
                                    }
                                };

                                tokio::select! {
                                    _ = consume => {},
                                    _ = produce => {},
                                    r = periodically_send_ping => {
                                        warn!("periodically_send_ping error: {:?}", r);
                                    },
                                    r = forward_to_ws => {
                                        warn!("forward_to_ws error: {:?}", r);
                                    },
                                    r = ensure_pong_received => {
                                        warn!("ensure_pong_received error: {:?}", r);
                                    },
                                };

                                // if it's the last connection - no more active connections
                                if num_connections.fetch_sub(1, Ordering::Relaxed) == 1 {
                                    error!("no more active assistant connections. exiting");
                                    stop_handle.stop(StopReason::NotificationChannelError);
                                };

                            }
                            Err(e) => {
                                error!("Error connecting: {}", e);
                                sleep(Duration::from_secs(1)).await;
                            }
                        }

                        info!("return IP {:?}", ip);
                        let mut locked = established_ips.lock().await;
                        assert!(locked.remove(&ip));
                    }
                    Ok::<_, anyhow::Error>(())
                }
                .instrument(info_span!("assistant connector", conn_idx = conn_idx)),
            );
        }

        let mut merged_from_assistants = futures::stream::select_all(from_assistant_streams);
        let process_notifications = async {
            while let Some(msg) = merged_from_assistants.next().await {
                info!("received msg: {:?}", msg);
                match msg {
                    WsToGwMessage::WebAppNotification(notification) => match notification.action {
                        Action::Invalidate {
                            url_prefixes,
                            config_ids,
                        } => {
                            for url_prefix in url_prefixes.into_iter() {
                                let domain_only = url_prefix.domain_only();
                                mappings.remove_by_notification_if_time_applicable(
                                    &domain_only,
                                    &notification.generated_at,
                                );

                                let host = url_prefix.host().to_string();

                                info!("invalidate certificate for: {}", host);

                                webapp_client.forget_certificate(host);
                            }

                            for config_id in &config_ids {
                                info!("Closing all tunnels with config {}", config_id);
                                client_tunnels.close_all_config_tunnels(config_id);
                            }
                        }
                    },
                    WsToGwMessage::GwConfig(gw_tls) => {
                        info!("Received common gateway TLS config");
                        *tls_gw_common.write() = Some(gw_tls);
                    }
                }
            }
        };

        let forward_statistics_to_channels = async {
            let mut rng = rand::rngs::SmallRng::from_entropy();
            while let Some(msg) = gw_to_assistant_messages_rx.next().await {
                let maybe_tx = to_assistant_streams.iter_mut().choose(&mut rng);
                if let Some(tx) = maybe_tx {
                    let _ = tx.send(msg).await;
                } else {
                    error!("No active assistant channels. Gateway is expected to stop now");
                }
            }
        };

        tokio::select! {
            _ = forward_statistics_to_channels => {}
            _ = process_notifications => {}
        }
    }
}
