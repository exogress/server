use std::fs::File;
use std::io::{self, BufReader, Cursor};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use byteorder::BigEndian;
use hashbrown::hash_map::Entry;
use hashbrown::HashMap;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_rustls::rustls::internal::pemfile::{certs, rsa_private_keys};
use tokio_rustls::rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;

use exogress_entities::{ConfigName, InstanceId};
use exogress_tunnel::{server_connection, server_framed, TunnelHello};
use hyper::Body;

use crate::clients::registry::{ClientTunnels, ConnectedTunnel, TunnelConnectionState};

fn load_certs(path: &str) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
}

fn load_keys(path: &str) -> io::Result<Vec<PrivateKey>> {
    rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}

pub async fn spawn(
    addr: SocketAddr,
    tls_cert_path: String,
    tls_key_path: String,
    tunnels: ClientTunnels,
    log: slog::Logger,
) -> io::Result<()> {
    let mut config = ServerConfig::new(NoClientAuth::new());

    let certs = load_certs(&tls_cert_path).expect("could not load certificate");
    let key = load_keys(&tls_key_path).expect("could not open certificate");

    config
        .set_single_cert(certs, key.get(0).unwrap().clone())
        .expect("error setting certs");

    let acceptor = TlsAcceptor::from(Arc::new(config));

    info!(log, "Listening for incoming tunnels on {:?}", addr);
    let mut listener = TcpListener::bind(addr).await?;

    loop {
        let (tunnel_stream, _peer_addr) = listener.accept().await?;
        let _ = tunnel_stream.set_nodelay(true);

        shadow_clone!(tunnels);
        shadow_clone!(acceptor);

        tokio::spawn({
            shadow_clone!(log);

            async move {
                match acceptor.accept(tunnel_stream).await {
                    Ok(mut tls_conn) => {
                        let read_tunnel_hello = async {
                            let len = tls_conn.read_u16().await?;
                            let mut payload = vec![0u8; len.into()];
                            tls_conn.read_exact(&mut payload).await?;
                            Ok::<_, anyhow::Error>(bincode::deserialize::<TunnelHello>(&payload)?)
                        };

                        let tunnel_hello = match timeout(Duration::from_secs(5), read_tunnel_hello)
                            .await
                        {
                            Ok(Ok(tunnel_hello)) => {
                                warn!(
                                    log,
                                    "accepted new TLS tunnel with tunnel_hello {:?}", tunnel_hello
                                );

                                tunnel_hello
                            }
                            Ok(Err(e)) => {
                                warn!(log, "error on TLS tunnel: {}. Closing connection", e);
                                return;
                            }
                            Err(tokio::time::Elapsed { .. }) => {
                                warn!(
                                    log,
                                    "no initial connection data received. Closing connection"
                                );
                                return;
                            }
                        };

                        let (bg, connector) = server_connection(server_framed(tls_conn), &log);

                        let instance_id = tunnel_hello.instance_id;
                        let config_name = tunnel_hello.config_name;

                        let log = log.new(
                            o!("instance_id" => instance_id, "config_name" => config_name.clone()),
                        );

                        info!(log, "new instance connected");

                        {
                            let locked = &mut *tunnels.inner.lock();

                            if let Entry::Occupied(mut rec) = locked.entry(config_name.clone()) {
                                let new_connected_tunnel = ConnectedTunnel {
                                    hyper: hyper::Client::builder()
                                        .build::<_, Body>(connector.clone()),
                                    connector,
                                    config_name: config_name.clone(),
                                    instance_id,
                                };

                                let c = match rec.get_mut() {
                                    TunnelConnectionState::Requested(reset_event) => {
                                        let mut c = HashMap::new();
                                        c.insert(instance_id, new_connected_tunnel);

                                        reset_event.set();

                                        c
                                    }
                                    TunnelConnectionState::Connected(c) => {
                                        if c.contains_key(&instance_id) {
                                            // TODO: allow multiple connections
                                        } else {
                                            c.insert(instance_id, new_connected_tunnel);
                                        };

                                        return;
                                    }
                                };

                                rec.insert(TunnelConnectionState::Connected(c));
                            }
                        }

                        let res = bg.await;

                        match res {
                            Ok(()) => {
                                info!(log, "instance connection closed successfully");
                            }
                            Err(e) => {
                                info!(log, "instance connection closed with error {:?}", e);
                            }
                        }

                        if let Entry::Occupied(mut client) = tunnels.inner.lock().entry(config_name)
                        {
                            let should_delete_client = match client.get_mut() {
                                TunnelConnectionState::Connected(conns) => {
                                    conns.remove(&instance_id);
                                    conns.is_empty()
                                }
                                _ => false,
                            };

                            if should_delete_client {
                                client.remove_entry();
                            }
                        }
                    }
                    Err(e) => {
                        warn!(log, "could not accept tunnel connnection: {}", e);
                    }
                }
            }
        });
    }
}
