use crate::{
    balancer::{GwSelectionPolicy, ShardedGateways},
    tls::extract_sni_hostname,
};
use exogress_server_common::director::SourceInfo;
use lru_time_cache::LruCache;
use parking_lot::Mutex;
use std::{convert::TryInto, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io,
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::sleep,
};

#[derive(Builder)]
pub struct Forwarder {
    listen_http: SocketAddr,
    listen_https: SocketAddr,
    forward_to_http_port: u16,
    forward_to_https_port: u16,
    sharded_gateways: Arc<ShardedGateways>,
    #[builder(default = "default_balancers()")]
    balancers: Arc<Mutex<LruCache<u64, Arc<Mutex<GwSelectionPolicy>>>>>,
}

fn default_balancers() -> Arc<Mutex<LruCache<u64, Arc<Mutex<GwSelectionPolicy>>>>> {
    Arc::new(Mutex::new(LruCache::with_expiry_duration(
        Duration::from_secs(300),
    )))
}

async fn forwarder(
    addr: SocketAddr,
    forward_to_port: u16,
    sharded_gateways: Arc<ShardedGateways>,
    balancers: Arc<Mutex<LruCache<u64, Arc<Mutex<GwSelectionPolicy>>>>>,
    is_tls: bool,
    max_retries: usize,
) -> Result<(), io::Error> {
    info!("listen to {}", addr);

    let tcp = TcpListener::bind(addr).await?;
    loop {
        shadow_clone!(sharded_gateways, balancers);

        match tcp.accept().await {
            Ok((mut incoming, incoming_addr)) => {
                tokio::spawn({
                    shadow_clone!(sharded_gateways, balancers);

                    async move {
                        crate::statistics::NUM_ACTIVE_FORWARDERS.inc();

                        let perform_connection = async move {
                            incoming.set_nodelay(true)?;
                            let local_addr = incoming.local_addr()?;

                            let mut consumed_bytes = None;
                            let mut sni_hostname = None;

                            if is_tls {
                                let mut header = vec![0u8; 512];
                                let mut header_bytes_read = 0;
                                sni_hostname = loop {
                                    let bytes_read =
                                        incoming.read(&mut header[header_bytes_read..]).await?;
                                    if bytes_read == 0 {
                                        return Err(anyhow!(
                                            "connection closed while waiting for SNI"
                                        ));
                                    }

                                    header_bytes_read += bytes_read;

                                    let to_parse = header[..header_bytes_read].to_vec();

                                    let client_hello_parse_result =
                                        extract_sni_hostname(&to_parse[..]);

                                    const MAX_CLIENT_HELLO_LEN: usize = 16536;

                                    match client_hello_parse_result? {
                                        None => {
                                            if header_bytes_read < MAX_CLIENT_HELLO_LEN {
                                                header.resize(
                                                    std::cmp::min(
                                                        header.len() * 2,
                                                        MAX_CLIENT_HELLO_LEN,
                                                    ),
                                                    0,
                                                );
                                            } else {
                                                return Err(anyhow!(
                                                    "could not parse ClientHello: too long"
                                                ));
                                            }
                                        }
                                        Some(sni_hostname) => {
                                            break sni_hostname;
                                        }
                                    };
                                };
                                header.truncate(header_bytes_read);
                                consumed_bytes = Some(header);
                            };

                            let balancer_seed = sni_hostname
                                .as_ref()
                                .map(|s| seahash::hash(s.as_ref()))
                                .unwrap_or(1);

                            let policy = match balancers.lock().entry(balancer_seed) {
                                lru_time_cache::Entry::Occupied(occupied) => {
                                    occupied.into_mut().clone()
                                }
                                lru_time_cache::Entry::Vacant(vacant) => {
                                    let policy = Arc::new(Mutex::new(sharded_gateways.policy(
                                        balancer_seed,
                                        2,
                                        2,
                                        Duration::from_secs(10),
                                    )?));
                                    vacant.insert(policy.clone());
                                    policy
                                }
                            };

                            let mut is_any_gw_connected = false;
                            let mut retry = 0;

                            while retry < max_retries {
                                retry += 1;
                                let maybe_dst_addr = policy.lock().next();
                                if let Some(dst_addr) = maybe_dst_addr {
                                    let try_connect = async {
                                        let conn_result = TcpStream::connect(SocketAddr::from((
                                            dst_addr,
                                            forward_to_port,
                                        )))
                                        .await;

                                        match conn_result {
                                            Ok(mut forward_to) => {
                                                forward_to.set_nodelay(true)?;

                                                let source_info = serde_cbor::to_vec(&SourceInfo {
                                                    local_addr,
                                                    remote_addr: incoming_addr,
                                                    alpn_domain: sni_hostname.clone(),
                                                })
                                                .unwrap();

                                                forward_to
                                                    .write_u16(
                                                        source_info.len().try_into().unwrap(),
                                                    )
                                                    .await?;
                                                forward_to.write_all(&source_info).await?;
                                                if let Some(header) = &consumed_bytes {
                                                    forward_to.write_all(header).await?;
                                                }

                                                is_any_gw_connected = true;
                                                crate::statistics::NUM_PROXIED_CONNECTIONS
                                                    .with_label_values(&[
                                                        retry.to_string().as_str(),
                                                        max_retries.to_string().as_str(),
                                                        "1",
                                                    ])
                                                    .inc();

                                                return Ok(copy_bidirectional(
                                                    &mut incoming,
                                                    &mut forward_to,
                                                )
                                                .await?);
                                            }
                                            Err(e) => {
                                                warn!("could not connect to gateway: {}", e);
                                                policy.lock().mark_unhealthy(&dst_addr);
                                            }
                                        }

                                        Err(anyhow!("could not connect to the gateway"))
                                    };

                                    match try_connect.await {
                                        Ok(_) => {
                                            break;
                                        }
                                        Err(_e) => {
                                            // error!("could not serve connection to gateway: {}", e);
                                            sleep(Duration::from_millis(10)).await;
                                        }
                                    };
                                }
                            }

                            if !is_any_gw_connected {
                                crate::statistics::NUM_PROXIED_CONNECTIONS
                                    .with_label_values(&[
                                        "",
                                        max_retries.to_string().as_str(),
                                        retry.to_string().as_str(),
                                    ])
                                    .inc();
                            }

                            Ok(())
                        };

                        if let Err(e) = perform_connection.await {
                            warn!("Error forwarding connection: {}", e);
                        }

                        crate::statistics::NUM_ACTIVE_FORWARDERS.dec();
                    }
                });
            }
            Err(e) => {
                warn!("could not accept incoming connection: {}", e);
            }
        }
    }
}

impl Forwarder {
    pub async fn spawn(self) -> Result<(), io::Error> {
        let http = forwarder(
            self.listen_http,
            self.forward_to_http_port,
            self.sharded_gateways.clone(),
            self.balancers.clone(),
            false,
            3,
        );

        let https = forwarder(
            self.listen_https,
            self.forward_to_https_port,
            self.sharded_gateways.clone(),
            self.balancers.clone(),
            true,
            3,
        );

        tokio::select! {
            r = http => r,
            r = https => r,
        }
    }
}
