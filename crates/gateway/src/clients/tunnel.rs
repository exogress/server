use hashbrown::{hash_map::Entry, HashMap};
use hyper::{
    header::{HeaderValue, UPGRADE},
    service::{make_service_fn, service_fn},
    Body, Request, Response, Server, StatusCode, Version,
};
use pin_utils::pin_mut;
use std::{
    fs::File,
    io::{self, BufReader},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};
use tokio_rustls::{
    rustls::{
        internal::pemfile::{certs, pkcs8_private_keys, rsa_private_keys},
        Certificate, NoClientAuth, PrivateKey, ServerConfig, Session,
    },
    server::TlsStream,
    TlsAcceptor,
};

use exogress_common::tunnel::{
    server_connection, server_framed, ServerPacket, TunnelHello, TunnelHelloResponse, ALPN_PROTOCOL,
};

use crate::{
    clients::{
        registry::{
            ClientTunnels, ConnectedTunnel, InstanceConnections, InstanceConnector,
            TunnelConnectionState,
        },
        traffic_counter::{RecordedTrafficStatistics, TrafficCountedStream, TrafficCounters},
    },
    webapp,
    webapp::AuthorizeTunnelResponse,
};
use exogress_common::entities::{ConfigId, TunnelId};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, Stream,
};
use std::{
    convert::TryInto,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};

fn load_certs(path: &str) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
}

fn load_keys(path: &str) -> io::Result<Vec<PrivateKey>> {
    use std::io::Read;

    let mut content = Vec::new();
    let mut f = File::open(path)?;
    f.read_to_end(&mut content)?;

    match pkcs8_private_keys(&mut content.as_slice()) {
        Ok(pkcs8) if !pkcs8.is_empty() => {
            info!("using PKCS8 tunnel certificate");
            return Ok(pkcs8);
        }
        _ => {}
    }

    let rsa = rsa_private_keys(&mut content.as_slice())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))?;

    info!("using RSA tunnel certificate");

    Ok(rsa)
}

pub const MAX_ALLOWED_TUNNELS: usize = 2;

struct HyperAcceptor<F>
where
    F: Stream<Item = TlsStream<TcpStream>> + Unpin + Send,
{
    acceptor: F,
}

impl<F> hyper::server::accept::Accept for HyperAcceptor<F>
where
    F: Stream<Item = TlsStream<TcpStream>> + Unpin + Send,
{
    type Conn = TlsStream<TcpStream>;
    type Error = io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let res = futures::ready!(Pin::new(&mut self.acceptor).poll_next(cx));
        Poll::Ready(res.map(Ok))
    }
}

pub async fn tunnels_acceptor(
    addr: SocketAddr,
    tls_cert_path: String,
    tls_key_path: String,
    tunnels: ClientTunnels,
    webapp: webapp::Client,
    high_resource_consumption: Arc<AtomicBool>,
    tunnel_counters_tx: tokio::sync::mpsc::Sender<RecordedTrafficStatistics>,
) -> io::Result<()> {
    let mut config = ServerConfig::new(NoClientAuth::new());

    let certs = load_certs(&tls_cert_path).expect("could not load certificate");
    let key = load_keys(&tls_key_path).expect("could not open certificate");

    config
        .set_single_cert(certs, key.get(0).unwrap().clone())
        .expect("error setting certs");

    let mut alpn = vec![ALPN_PROTOCOL.to_vec()];
    alpn.push(AsRef::<[u8]>::as_ref("http/1.1").to_vec());

    config.alpn_protocols = alpn;

    let tls_acceptor = TlsAcceptor::from(Arc::new(config));
    info!("Listening for incoming tunnels on {:?}", addr);
    let listener = TcpListener::bind(addr).await?;

    let (accepted_connection_tx, accepted_connection_rx) = mpsc::channel(4);

    let acceptor = tokio::spawn(async move {
        shadow_clone!(tls_acceptor);

        while let Ok((tcp_stream, _)) = listener.accept().await {
            if !high_resource_consumption.load(Ordering::Relaxed) {
                shadow_clone!(tls_acceptor, mut accepted_connection_tx);
                tokio::spawn(async move {
                    tcp_stream.set_nodelay(true)?;

                    let accept_result = tokio::time::timeout(
                        Duration::from_secs(20),
                        tls_acceptor.accept(tcp_stream),
                    )
                    .await;

                    let mut tls_conn = match accept_result {
                        Err(_) => {
                            return Ok(());
                        }
                        Ok(Err(_e)) => {
                            return Ok(());
                        }
                        Ok(Ok(r)) => r,
                    };

                    let is_alpn_error = tls_conn
                        .get_mut()
                        .1
                        .get_alpn_protocol()
                        .map(|p| {
                            // info!("provided ALPN: {}", std::str::from_utf8(p).unwrap());
                            p != *ALPN_PROTOCOL
                        })
                        // ALPN not provides should lead to Error as well
                        .unwrap_or(true);

                    if is_alpn_error {
                        warn!("not accepting tunnel connection: ALPN mismatch");
                    } else {
                        accepted_connection_tx.send(tls_conn).await.unwrap();
                    }

                    Ok::<_, anyhow::Error>(())
                });
            };
        }
    });

    let make_service = make_service_fn(move |_| {
        shadow_clone!(tunnels, webapp, tunnel_counters_tx);

        async move {
            Ok::<_, hyper::Error>(service_fn({
                move |mut req: Request<Body>| {
                    shadow_clone!(tunnels, webapp, mut tunnel_counters_tx);

                    async move {
                        let query_params = req.uri().query().unwrap_or("").to_string();
                        if req.version() != Version::HTTP_11 {
                            bail!("not HTTP/1.1, abort connection");
                        }

                        let mut res = Response::new(Body::empty());

                        tokio::spawn(async move {
                            let mut upgraded = match hyper::upgrade::on(&mut req).await {
                                Ok(upgraded) => upgraded,
                                Err(e) => {
                                    bail!("upgrade error: {}", e);
                                }
                            };

                            let tunnel_id = TunnelId::new();

                            let accept_tunnel = async {
                                let len = upgraded.read_u16().await?;
                                let mut payload = vec![0u8; len.into()];
                                upgraded.read_exact(&mut payload).await?;
                                let tunnel_hello = serde_cbor::from_slice::<TunnelHello>(&payload)?;

                                let AuthorizeTunnelResponse {
                                    account_unique_id,
                                    project_unique_id,
                                } = webapp.authorize_tunnel(&tunnel_hello).await?;

                                info!(
                                    "Accepted tunnel from instance {}. Params: {}",
                                    tunnel_hello.instance_id, query_params
                                );

                                let resp = TunnelHelloResponse::Ok { tunnel_id };

                                let resp_bytes = serde_cbor::to_vec(&resp)?;
                                upgraded
                                    .write_u16(resp_bytes.len().try_into().unwrap())
                                    .await?;
                                upgraded.write_all(&resp_bytes).await?;

                                Ok::<_, anyhow::Error>((
                                    tunnel_hello,
                                    account_unique_id,
                                    project_unique_id,
                                ))
                            };

                            let (tunnel_hello, account_unique_id, project_unique_id) =
                                match timeout(Duration::from_secs(5), accept_tunnel).await {
                                    Ok(Ok((
                                        tunnel_hello,
                                        account_unique_id,
                                        project_unique_id,
                                    ))) => {
                                        // warn!(
                                        //     "accepted new TLS tunnel with tunnel_hello {:?}",
                                        //     tunnel_hello
                                        // );

                                        (tunnel_hello, account_unique_id, project_unique_id)
                                    }
                                    Ok(Err(e)) => {
                                        warn!("error on TLS tunnel: {}. Closing connection", e);
                                        return Err(e);
                                    }
                                    Err(tokio::time::error::Elapsed { .. }) => {
                                        warn!(
                                        "no initial connection data received. Closing connection"
                                    );
                                        return Err(anyhow::Error::msg("timeout on handshake"));
                                    }
                                };

                            let counters =
                                TrafficCounters::new(account_unique_id, project_unique_id);
                            let metered = TrafficCountedStream::new(
                                upgraded,
                                counters.clone(),
                                crate::statistics::TUNNELS_BYTES_SENT.clone(),
                                crate::statistics::TUNNELS_BYTES_RECV.clone(),
                            );

                            let (stop_tx, stop_rx) = oneshot::channel();
                            let framed = server_framed(metered);

                            let instance_id = tunnel_hello.instance_id;

                            let config_id = ConfigId {
                                config_name: tunnel_hello.config_name,
                                account_name: tunnel_hello.account_name,
                                account_unique_id,
                                project_name: tunnel_hello.project_name,
                            };

                            // info!("new instance connected");

                            let bg = {
                                let mut locked = tunnels.inner.lock().await;

                                match locked.by_config.entry(config_id.clone()) {
                                    Entry::Occupied(mut rec) => {
                                        let (bg, connector) = server_connection(framed);

                                        let new_connected_tunnel = ConnectedTunnel {
                                            connector,
                                            config_id: config_id.clone(),
                                            instance_id,
                                        };

                                        match rec.get_mut() {
                                            TunnelConnectionState::Requested(requested) => {
                                                // tunnels connections for config_name were requested
                                                // and the first instance is connected
                                                // Save and switch to Connected state

                                                let mut c = HashMap::new();
                                                let mut tunnels = HashMap::new();
                                                tunnels.insert(
                                                    tunnel_id,
                                                    (new_connected_tunnel, Some(stop_tx)),
                                                );

                                                let instance_connector = InstanceConnector::new();
                                                instance_connector.sync(&tunnels);

                                                let instance_conections = InstanceConnections {
                                                    storage: tunnels,
                                                    instance_connector: instance_connector.clone(),
                                                    http_client: hyper::Client::builder()
                                                        .set_host(false)
                                                        .http2_only(false)
                                                        .build::<_, Body>(instance_connector),
                                                };

                                                c.insert(instance_id, instance_conections);
                                                requested.reset_event.set();
                                                rec.insert(TunnelConnectionState::Connected(c));
                                            }
                                            TunnelConnectionState::Connected(c) => {
                                                // new tunnel is established, and some other tunnels were already connected

                                                match c.entry(instance_id) {
                                                    Entry::Occupied(mut e) => {
                                                        // tunnels from this instance_id is already exist
                                                        // add tunnel to the list

                                                        let entry = e.get_mut();
                                                        if entry.storage.len()
                                                            >= MAX_ALLOWED_TUNNELS
                                                        {
                                                            warn!("Client tried to connect more than {} tunnels. Reject connection", MAX_ALLOWED_TUNNELS);
                                                            return Err(anyhow::Error::msg(
                                                                "client tunnels limit reached",
                                                            ));
                                                        }
                                                        let storage = &mut entry.storage;

                                                        storage.insert(
                                                            tunnel_id,
                                                            (new_connected_tunnel, Some(stop_tx)),
                                                        );

                                                        entry.instance_connector.sync(storage);
                                                    }
                                                    Entry::Vacant(e) => {
                                                        // this is the first connection from instance

                                                        let mut tunnels = HashMap::new();
                                                        tunnels.insert(
                                                            tunnel_id,
                                                            (new_connected_tunnel, Some(stop_tx)),
                                                        );

                                                        let instance_connector =
                                                            InstanceConnector::new();
                                                        instance_connector.sync(&tunnels);

                                                        let instance_connections =
                                                            InstanceConnections {
                                                                storage: tunnels,
                                                                http_client:
                                                                    hyper::Client::builder()
                                                                        .set_host(false)
                                                                        .http2_only(false)
                                                                        .build::<_, Body>(
                                                                            instance_connector
                                                                                .clone(),
                                                                        ),
                                                                instance_connector,
                                                            };
                                                        e.insert(instance_connections);
                                                    }
                                                }
                                            }
                                        };

                                        bg
                                    }
                                    Entry::Vacant(_) => {
                                        // no instances with the config_name.
                                        // Tunnel established, but was not requested
                                        // This happens when new instance is connected, and the older
                                        // one immediately re-connects. If we accept the tunnel and
                                        // switch to the "Connected" state, new instance will never get request
                                        // for connection. In order to prevent that, we don't accept the tunnel
                                        // and ask to stop re-connection attempts, until the new HTTP request arrives

                                        pin_mut!(framed);

                                        // ask client to disconnect and close the tunnel

                                        framed
                                            .send((ServerPacket::close_no_reconnect(), vec![]))
                                            .await?;

                                        return Ok::<_, anyhow::Error>(());
                                    }
                                }
                            };

                            crate::statistics::TUNNELS_GAUGE.inc();

                            #[allow(unreachable_code)]
                            let flush_counters = async move {
                                loop {
                                    sleep(Duration::from_secs(60)).await;
                                    match counters.flush() {
                                        Ok(Some(stats)) => {
                                            tunnel_counters_tx.send(stats).await?;
                                        }
                                        Err(()) => {
                                            break;
                                        }
                                        Ok(None) => {}
                                    }
                                }

                                Ok::<_, anyhow::Error>(())
                            };

                            tokio::spawn(flush_counters);

                            tokio::select! {
                                res = bg => {
                                    match res {
                                        Ok(()) => {
                                            info!("instance connection closed successfully");
                                        }
                                        Err(e) => {
                                            info!("instance connection closed with error {:?}", e);
                                        }
                                    }
                                },
                                _ = stop_rx => {
                                    info!("tunnel terminated by request");
                                },
                            }

                            // at this point the tunnel is closed

                            crate::statistics::TUNNELS_GAUGE.dec();

                            if let Entry::Occupied(mut client) = tunnels
                                .inner
                                .lock()
                                .await
                                .by_config
                                .entry(config_id.clone())
                            {
                                let should_delete_client = match client.get_mut() {
                                    TunnelConnectionState::Connected(conns) => {
                                        if let Entry::Occupied(mut tunnels_entry) =
                                            conns.entry(instance_id)
                                        {
                                            tunnels_entry.get_mut().storage.remove(&tunnel_id);
                                            if tunnels_entry.get().storage.is_empty() {
                                                tunnels_entry.remove_entry();
                                            }
                                        } else {
                                            unreachable!("should never happen")
                                        };

                                        conns.is_empty()
                                    }
                                    _ => {
                                        warn!(
                                            "Not delete tunnel since it's not in connected state"
                                        );
                                        false
                                    }
                                };

                                if should_delete_client {
                                    client.remove_entry();
                                }
                            }

                            Ok::<_, anyhow::Error>(())
                        });

                        *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                        res.headers_mut()
                            .insert(UPGRADE, HeaderValue::from_static("exotun"));
                        Ok(res)
                    }
                }
            }))
        }
    });

    let https_server = Server::builder(HyperAcceptor {
        acceptor: accepted_connection_rx,
    })
    .http1_only(true)
    .http2_only(false)
    .serve(make_service);

    tokio::select! {
        r = https_server => {
            error!("tunnel https server stopped: {:?}", r);
        },
        r = acceptor => {
            error!("TLS acceptor stopped: {:?}", r);
        },
    }

    Ok(())
}
