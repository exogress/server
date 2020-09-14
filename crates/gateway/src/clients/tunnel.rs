use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hashbrown::hash_map::Entry;
use hashbrown::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_rustls::rustls::internal::pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio_rustls::rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;

use exogress_tunnel::{server_connection, server_framed, TunnelHello, TunnelHelloResponse};
use hyper::Body;

use crate::clients::registry::{ClientTunnels, ConnectedTunnel, TunnelConnectionState};
use exogress_entities::TunnelId;
use futures::channel::oneshot;
use generational_arena::Arena;
use std::convert::TryInto;

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

pub const MAX_ALLOWED_TUNNELS: usize = 32;

pub async fn spawn(
    addr: SocketAddr,
    tls_cert_path: String,
    tls_key_path: String,
    tunnels: ClientTunnels,
) -> io::Result<()> {
    let mut config = ServerConfig::new(NoClientAuth::new());

    let certs = load_certs(&tls_cert_path).expect("could not load certificate");
    let key = load_keys(&tls_key_path).expect("could not open certificate");

    config
        .set_single_cert(certs, key.get(0).unwrap().clone())
        .expect("error setting certs");

    let acceptor = TlsAcceptor::from(Arc::new(config));

    info!("Listening for incoming tunnels on {:?}", addr);
    let mut listener = TcpListener::bind(addr).await?;

    loop {
        let (tunnel_stream, _peer_addr) = listener.accept().await?;
        let _ = tunnel_stream.set_nodelay(true);

        shadow_clone!(tunnels);
        shadow_clone!(acceptor);

        tokio::spawn({
            async move {
                match acceptor.accept(tunnel_stream).await {
                    Ok(mut tls_conn) => {
                        let tunnel_id = TunnelId::new();

                        let accept_tunnel = async {
                            let len = tls_conn.read_u16().await?;
                            let mut payload = vec![0u8; len.into()];
                            tls_conn.read_exact(&mut payload).await?;
                            let tunnel_hello = bincode::deserialize::<TunnelHello>(&payload)?;

                            // TODO: check instance_id!
                            info!("Accepted tunnel from instance {}", tunnel_hello.instance_id);

                            let resp = TunnelHelloResponse::Ok { tunnel_id };

                            let resp_bytes = bincode::serialize(&resp)?;
                            tls_conn
                                .write_u16(resp_bytes.len().try_into().unwrap())
                                .await?;
                            tls_conn.write_all(&resp_bytes).await?;

                            Ok::<_, anyhow::Error>(tunnel_hello)
                        };

                        let tunnel_hello = match timeout(Duration::from_secs(5), accept_tunnel)
                            .await
                        {
                            Ok(Ok(tunnel_hello)) => {
                                // warn!(
                                //     "accepted new TLS tunnel with tunnel_hello {:?}",
                                //     tunnel_hello
                                // );

                                tunnel_hello
                            }
                            Ok(Err(e)) => {
                                warn!("error on TLS tunnel: {}. Closing connection", e);
                                return;
                            }
                            Err(tokio::time::Elapsed { .. }) => {
                                warn!("no initial connection data received. Closing connection");
                                return;
                            }
                        };

                        let (stop_tx, stop_rx) = oneshot::channel();
                        let (bg, connector) = server_connection(server_framed(tls_conn));

                        let instance_id = tunnel_hello.instance_id;
                        let config_name = tunnel_hello.config_name;

                        let arena_index;

                        // info!("new instance connected");

                        {
                            let new_connected_tunnel = ConnectedTunnel {
                                hyper: hyper::Client::builder().build::<_, Body>(connector.clone()),
                                connector,
                                config_name: config_name.clone(),
                                instance_id,
                                stop_tx: Arc::new(stop_tx),
                            };

                            let locked = &mut *tunnels.inner.lock();

                            match locked.0.entry(config_name.clone()) {
                                Entry::Occupied(mut rec) => {
                                    match rec.get_mut() {
                                        TunnelConnectionState::Requested(reset_event) => {
                                            let mut c = HashMap::new();
                                            let mut arena = Arena::new();
                                            arena_index = arena.insert(new_connected_tunnel);
                                            c.insert(instance_id, arena);
                                            reset_event.set();
                                            rec.insert(TunnelConnectionState::Connected(c));
                                        }
                                        TunnelConnectionState::Connected(c) => {
                                            match c.entry(instance_id) {
                                                Entry::Occupied(mut e) => {
                                                    if e.get().len() >= MAX_ALLOWED_TUNNELS {
                                                        warn!("Client tried to connect more than {} tunnels. Reject connection", MAX_ALLOWED_TUNNELS);
                                                        return;
                                                    }
                                                    arena_index =
                                                        e.get_mut().insert(new_connected_tunnel);
                                                }
                                                Entry::Vacant(e) => {
                                                    let mut arena = Arena::new();
                                                    arena_index =
                                                        arena.insert(new_connected_tunnel);
                                                    e.insert(arena);
                                                }
                                            }
                                        }
                                    };
                                }
                                Entry::Vacant(rec) => {
                                    let mut c = HashMap::new();
                                    let mut arena = Arena::new();
                                    arena_index = arena.insert(new_connected_tunnel);
                                    c.insert(instance_id, arena);
                                    rec.insert(TunnelConnectionState::Connected(c));
                                }
                            }
                        }

                        crate::statistics::TUNNELS_GAUGE.inc();

                        let mut should_cleanup = true;

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
                                should_cleanup = false;
                                info!("tunnel terminated by request");
                            },
                        }
                        crate::statistics::TUNNELS_GAUGE.dec();

                        if let Entry::Occupied(mut client) =
                            tunnels.inner.lock().0.entry(config_name)
                        {
                            let should_delete_client = match client.get_mut() {
                                TunnelConnectionState::Connected(conns) => {
                                    if let Entry::Occupied(mut arena_entry) =
                                        conns.entry(instance_id)
                                    {
                                        arena_entry.get_mut().remove(arena_index);
                                        if arena_entry.get().is_empty() {
                                            arena_entry.remove_entry();
                                        }
                                    } else {
                                        unreachable!("should never happen")
                                    };

                                    conns.is_empty()
                                }
                                _ => false,
                            };

                            if should_delete_client {
                                client.remove_entry();
                            }
                        } else {
                            if should_cleanup {
                                error!("should never happen. could not find client config")
                            }
                        }
                    }
                    Err(e) => {
                        warn!("could not accept tunnel connection: {}", e);
                    }
                }
            }
        });
    }
}
