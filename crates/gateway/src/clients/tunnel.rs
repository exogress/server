use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hashbrown::hash_map::Entry;
use hashbrown::HashMap;
use hyper::header::{HeaderValue, UPGRADE};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode, Version};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{delay_for, timeout};
use tokio_rustls::rustls::internal::pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio_rustls::rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig, Session};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use exogress_common::tunnel::{
    server_connection, server_framed, TunnelHello, TunnelHelloResponse, ALPN_PROTOCOL,
};

use crate::clients::registry::{
    ClientTunnels, ConnectedTunnel, InstanceConnections, InstanceConnector, TunnelConnectionState,
};
use crate::clients::traffic_counter::{
    RecordedTrafficStatistics, TrafficCountedStream, TrafficCounters,
};
use crate::webapp;
use exogress_common::entities::{ConfigId, TunnelId};
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, Stream, StreamExt};
use std::convert::TryInto;
use std::pin::Pin;
use std::task::{Context, Poll};

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

pub const MAX_ALLOWED_TUNNELS: usize = 8;

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
    tunnel_counters_tx: mpsc::Sender<RecordedTrafficStatistics>,
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
    let mut listener = TcpListener::bind(addr).await?;

    let (accepted_connection_tx, accepted_connection_rx) = mpsc::channel(4);

    let acceptor = tokio::spawn(async move {
        shadow_clone!(tls_acceptor);

        while let Some(res) = listener.next().await {
            shadow_clone!(tls_acceptor);
            shadow_clone!(mut accepted_connection_tx);

            match res {
                Ok(tcp_stream) => {
                    tokio::spawn(async move {
                        tcp_stream.set_nodelay(true)?;

                        let accept_result = tokio::time::timeout(
                            Duration::from_secs(20),
                            tls_acceptor.accept(tcp_stream),
                        )
                        .await;

                        let mut tls_conn = match accept_result {
                            Err(_) => {
                                warn!("Timeout TLS tunnel connection");
                                return Ok(());
                            }
                            Ok(Err(e)) => {
                                warn!("Error accepting TLS connection: {}", e);
                                return Ok(());
                            }
                            Ok(Ok(r)) => r,
                        };

                        if tls_conn
                            .get_mut()
                            .1
                            .get_alpn_protocol()
                            .map(|p| {
                                // info!("provided ALPN: {}", std::str::from_utf8(p).unwrap());
                                p != *ALPN_PROTOCOL
                            })
                            // ALPN not provides should lead to Error as well
                            .unwrap_or(true)
                        {
                            warn!("not accepting tunnel connection: ALPN mismatch");
                        } else {
                            accepted_connection_tx.send(tls_conn).await.unwrap();
                        }

                        Ok::<_, anyhow::Error>(())
                    });
                }
                Err(e) => {
                    warn!("could not accept tunnel TCP connection: {}", e);
                }
            }
        }
    });

    let make_service = make_service_fn(move |_| {
        shadow_clone!(tunnels);
        shadow_clone!(webapp);
        shadow_clone!(tunnel_counters_tx);

        async move {
            Ok::<_, hyper::Error>(service_fn({
                move |req: Request<Body>| {
                    shadow_clone!(tunnels);
                    shadow_clone!(webapp);
                    shadow_clone!(mut tunnel_counters_tx);

                    async move {
                        if req.version() != Version::HTTP_11 {
                            bail!("not HTTP/1.1, abort connection");
                        }

                        let mut res = Response::new(Body::empty());

                        tokio::spawn(async move {
                            let mut upgraded = match req.into_body().on_upgrade().await {
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
                                let tunnel_hello = bincode::deserialize::<TunnelHello>(&payload)?;

                                let account_unique_id = webapp
                                    .authorize_tunnel(
                                        &tunnel_hello.project_name,
                                        &tunnel_hello.instance_id,
                                        &tunnel_hello.access_key_id,
                                        &tunnel_hello.secret_access_key,
                                    )
                                    .await?
                                    .account_unique_id;

                                info!("Accepted tunnel from instance {}", tunnel_hello.instance_id);

                                let resp = TunnelHelloResponse::Ok { tunnel_id };

                                let resp_bytes = bincode::serialize(&resp)?;
                                upgraded
                                    .write_u16(resp_bytes.len().try_into().unwrap())
                                    .await?;
                                upgraded.write_all(&resp_bytes).await?;

                                Ok::<_, anyhow::Error>((tunnel_hello, account_unique_id))
                            };

                            let (tunnel_hello, account_unique_id) =
                                match timeout(Duration::from_secs(5), accept_tunnel).await {
                                    Ok(Ok((tunnel_hello, account_unique_id))) => {
                                        // warn!(
                                        //     "accepted new TLS tunnel with tunnel_hello {:?}",
                                        //     tunnel_hello
                                        // );

                                        (tunnel_hello, account_unique_id)
                                    }
                                    Ok(Err(e)) => {
                                        warn!("error on TLS tunnel: {}. Closing connection", e);
                                        return Err(e.into());
                                    }
                                    Err(tokio::time::Elapsed { .. }) => {
                                        warn!(
                                        "no initial connection data received. Closing connection"
                                    );
                                        return Err(anyhow::Error::msg("timeout on handshake"));
                                    }
                                };

                            let counters = TrafficCounters::new(account_unique_id.clone());
                            let metered = TrafficCountedStream::new(
                                upgraded,
                                counters.clone(),
                                crate::statistics::TUNNELS_BYTES_SENT.clone(),
                                crate::statistics::TUNNELS_BYTES_RECV.clone(),
                            );

                            let (stop_tx, stop_rx) = oneshot::channel();
                            let (bg, connector) = server_connection(server_framed(metered));

                            let instance_id = tunnel_hello.instance_id;

                            let config_id = ConfigId {
                                config_name: tunnel_hello.config_name,
                                account_name: tunnel_hello.account_name,
                                account_unique_id,
                                project_name: tunnel_hello.project_name,
                            };

                            // info!("new instance connected");

                            {
                                let new_connected_tunnel = ConnectedTunnel {
                                    connector: connector.clone(),
                                    config_id: config_id.clone(),
                                    instance_id,
                                };

                                let locked = &mut *tunnels.inner.lock();

                                match locked.by_config.entry(config_id.clone()) {
                                    Entry::Occupied(mut rec) => {
                                        match rec.get_mut() {
                                            TunnelConnectionState::Requested(reset_event) => {
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
                                                        .build::<_, Body>(
                                                            instance_connector.clone(),
                                                        ),
                                                };

                                                c.insert(instance_id, instance_conections);
                                                reset_event.set();
                                                rec.insert(TunnelConnectionState::Connected(c));
                                            }
                                            TunnelConnectionState::Connected(c) => {
                                                match c.entry(instance_id) {
                                                    Entry::Occupied(mut e) => {
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
                                    }
                                    Entry::Vacant(rec) => {
                                        let mut c = HashMap::new();
                                        let mut tunnels = HashMap::new();
                                        tunnels.insert(
                                            tunnel_id,
                                            (new_connected_tunnel, Some(stop_tx)),
                                        );

                                        let instance_connector = InstanceConnector::new();
                                        instance_connector.sync(&tunnels);

                                        let instance_connections = InstanceConnections {
                                            storage: tunnels,
                                            http_client: hyper::Client::builder()
                                                .set_host(false)
                                                .http2_only(false)
                                                .build::<_, Body>(instance_connector.clone()),
                                            instance_connector,
                                        };

                                        c.insert(instance_id, instance_connections);
                                        rec.insert(TunnelConnectionState::Connected(c));
                                    }
                                }
                            }

                            crate::statistics::TUNNELS_GAUGE.inc();

                            #[allow(unreachable_code)]
                            let flush_counters = async move {
                                loop {
                                    delay_for(Duration::from_secs(60)).await;
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
                            crate::statistics::TUNNELS_GAUGE.dec();

                            if let Entry::Occupied(mut client) =
                                tunnels.inner.lock().by_config.entry(config_id.clone())
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
                            } else {
                                error!("should never happen. could not find client config")
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
