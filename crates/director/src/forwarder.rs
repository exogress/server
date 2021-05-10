use crate::{
    balancer::{GwSelectionPolicy, ShardedGateways},
    tls::extract_sni_hostname,
};
use anyhow::Context;
use exogress_server_common::director::SourceInfo;
use lru_time_cache::LruCache;
use object_pool::Pool;
use parking_lot::Mutex;
use std::{convert::TryInto, net::SocketAddr, sync::Arc, time::Duration};
use sys_info::mem_info;
use tokio::{
    io,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
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

async fn forward(
    mut incoming: impl AsyncRead + AsyncWrite + Unpin,
    mut forward_to: impl AsyncRead + AsyncWrite + Unpin,
    buf1: &mut [u8],
    buf2: &mut [u8],
) -> Result<(), anyhow::Error> {
    loop {
        tokio::select! {
            bytes_read_result = incoming.read(buf1) => {
                let bytes_read = bytes_read_result
                    .with_context(|| "error reading from incoming")?;
                if bytes_read == 0 {
                    return Ok(());
                } else {
                    crate::statistics::BUF_FILL_BYTES.observe(bytes_read as f64);

                    forward_to
                        .write_all(&buf1[..bytes_read])
                        .await
                        .with_context(|| "error writing to forwarded")?;
                    forward_to
                        .flush()
                        .await
                        .with_context(|| "error flushing forward_to")?;
                }
            },

            bytes_read_result = forward_to.read(buf2) => {
                let bytes_read = bytes_read_result
                    .with_context(|| "error reading from forwarded")?;
                if bytes_read == 0 {
                    return Ok(());
                } else {
                    incoming
                        .write_all(&buf2[..bytes_read])
                        .await
                        .with_context(|| "error writing to incoming")?;
                    incoming
                        .flush()
                        .await
                        .with_context(|| "error flushing incoming")?;
                }
            }
        }
    }
}

const BUF_SIZE: usize = 1024;

async fn forwarder(
    addr: SocketAddr,
    forward_to_port: u16,
    sharded_gateways: Arc<ShardedGateways>,
    balancers: Arc<Mutex<LruCache<u64, Arc<Mutex<GwSelectionPolicy>>>>>,
    is_tls: bool,
    max_retries: usize,
    initial_buf_pool_size: usize,
) -> Result<(), io::Error> {
    info!("listen to {}", addr);
    let buf_pool = Arc::new(Pool::new(initial_buf_pool_size, || [0u8; BUF_SIZE]));

    let tcp = TcpListener::bind(addr).await?;
    loop {
        shadow_clone!(buf_pool, sharded_gateways, balancers);

        match tcp.accept().await {
            Ok((mut incoming, incoming_addr)) => {
                incoming.set_nodelay(true)?;
                let local_addr = incoming.local_addr()?;

                tokio::spawn({
                    shadow_clone!(sharded_gateways, balancers);

                    async move {
                        let mut consumed_bytes = None;
                        let mut sni_hostname = None;

                        if is_tls {
                            let mut header = vec![0u8; 512];
                            let mut header_bytes_read = 0;
                            sni_hostname = loop {
                                let bytes_read =
                                    incoming.read(&mut header[header_bytes_read..]).await?;
                                if bytes_read == 0 {
                                    return Err(anyhow!("connection closed while waiting for SNI"));
                                }

                                header_bytes_read += bytes_read;

                                let to_parse = header[..header_bytes_read].to_vec();

                                let client_hello_parse_result = extract_sni_hostname(&to_parse[..]);

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
                                                .write_u16(source_info.len().try_into().unwrap())
                                                .await?;
                                            forward_to.write_all(&source_info).await?;
                                            if let Some(header) = &consumed_bytes {
                                                forward_to.write_all(header).await?;
                                            }

                                            let (reusable_buf1, reusable_buf2) = if buf_pool.len()
                                                > 2
                                            {
                                                (
                                                    buf_pool.pull(|| [0; BUF_SIZE]),
                                                    buf_pool.pull(|| [0; BUF_SIZE]),
                                                )
                                            } else {
                                                let mem = mem_info()
                                                    .expect("could not retrieve memory info");
                                                let avail_mem = mem.avail as f32;
                                                let total_mem = mem.total as f32;
                                                let avail_percent = (1.0
                                                    - (total_mem - avail_mem) / total_mem)
                                                    * 100.0;
                                                if avail_percent < 80.0
                                                    && avail_mem < 1.0 * 1024.0 * 1024.0
                                                {
                                                    return Err(anyhow!("not enough free memory for buffer allocation. only {}% of memory is available ({} bytes)", avail_percent, avail_mem));
                                                }

                                                (
                                                    buf_pool.pull(|| [0; BUF_SIZE]),
                                                    buf_pool.pull(|| [0; BUF_SIZE]),
                                                )
                                            };

                                            let (_, mut buf1) = reusable_buf1.detach();
                                            let (_, mut buf2) = reusable_buf2.detach();

                                            is_any_gw_connected = true;
                                            crate::statistics::NUM_PROXIED_CONNECTIONS
                                                .with_label_values(&[
                                                    retry.to_string().as_str(),
                                                    max_retries.to_string().as_str(),
                                                    "1",
                                                ])
                                                .inc();

                                            let r = forward(
                                                &mut incoming,
                                                &mut forward_to,
                                                &mut buf1,
                                                &mut buf2,
                                            )
                                            .await;

                                            buf_pool.attach(buf1);
                                            buf_pool.attach(buf2);

                                            return r;
                                        }
                                        Err(e) => {
                                            warn!("could not connect to gateway: {}", e);
                                            policy.lock().mark_unhealthy(&dst_addr);
                                        }
                                    }

                                    Err(anyhow!("could not connect to the gateway"))
                                };

                                match try_connect.await {
                                    Ok(()) => {
                                        break;
                                    }
                                    Err(_e) => {
                                        // error!("could not serve connection to gateway: {}", e);
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
            1024,
        );

        let https = forwarder(
            self.listen_https,
            self.forward_to_https_port,
            self.sharded_gateways.clone(),
            self.balancers.clone(),
            true,
            3,
            1024,
        );

        tokio::select! {
            r = http => r,
            r = https => r,
        }
    }
}
