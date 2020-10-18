use anyhow::Context;
use exogress_server_common::director::SourceInfo;
use object_pool::Pool;
use parking_lot::Mutex;
use std::convert::TryInto;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use weighted_rs::{SmoothWeight, Weight};

#[derive(Clone)]
pub struct ForwardingRules {
    inner: Arc<Mutex<SmoothWeight<IpAddr>>>,
}

impl fmt::Debug for ForwardingRules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.inner.lock().all())
    }
}

impl ForwardingRules {
    pub fn add(&self, addr: IpAddr, weight: isize) {
        self.inner.lock().add(addr, weight);
    }
}

impl Default for ForwardingRules {
    fn default() -> Self {
        ForwardingRules {
            inner: Arc::new(Mutex::new(SmoothWeight::new())),
        }
    }
}

#[derive(Builder)]
pub struct Forwarder {
    listen_http: SocketAddr,
    listen_https: SocketAddr,
    forward_to_http_port: u16,
    forward_to_https_port: u16,
    rules: ForwardingRules,
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
                    forward_to
                        .write_all(&buf1[..bytes_read])
                        .await
                        .with_context(|| "error writing to forwarded")?;
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
                }
            }
        }
    }
}

const BUF_SIZE: usize = 65536;

async fn forwarder(
    addr: SocketAddr,
    forward_to_port: u16,
    rules: ForwardingRules,
    max_retries: usize,
    initial_buf_pool_size: usize,
    max_buf_pool_size: usize,
) -> Result<(), io::Error> {
    info!("listen to {}", addr);
    let buf_pool = Arc::new(Pool::new(initial_buf_pool_size, || [0u8; BUF_SIZE]));

    let mut tcp = TcpListener::bind(addr).await?;
    loop {
        shadow_clone!(buf_pool);

        match tcp.accept().await {
            Ok((mut incoming, incoming_addr)) => {
                incoming.set_nodelay(true)?;
                let local_addr = incoming.local_addr()?;

                info!("accepted connection from {}", incoming_addr);
                tokio::spawn({
                    shadow_clone!(rules);

                    async move {
                        for _retry in 0..max_retries {
                            let maybe_dst_addr = rules.inner.lock().next();
                            if let Some(dst_addr) = maybe_dst_addr {
                                info!("try proxy to {}", dst_addr);
                                let try_connect = async {
                                    let conn_result = TcpStream::connect(SocketAddr::from((
                                        dst_addr,
                                        forward_to_port,
                                    )))
                                    .await;

                                    match conn_result {
                                        Ok(mut forward_to) => {
                                            forward_to.set_nodelay(true)?;

                                            let header = bincode::serialize(&SourceInfo {
                                                local_addr,
                                                remote_addr: incoming_addr,
                                            })
                                            .unwrap();

                                            forward_to
                                                .write_u16(header.len().try_into().unwrap())
                                                .await?;
                                            forward_to.write_all(&header).await?;

                                            let reusable_buf1 = buf_pool.pull(|| [0; BUF_SIZE]);
                                            let reusable_buf2 = buf_pool.pull(|| [0; BUF_SIZE]);

                                            let (_, mut buf1) = reusable_buf1.detach();
                                            let (_, mut buf2) = reusable_buf2.detach();

                                            let r = forward(
                                                &mut incoming,
                                                &mut forward_to,
                                                &mut buf1,
                                                &mut buf2,
                                            )
                                            .await;

                                            if buf_pool.len() < max_buf_pool_size {
                                                buf_pool.attach(buf1);
                                                buf_pool.attach(buf2);
                                            }

                                            return r;
                                        }
                                        Err(e) => {
                                            warn!("could not connect to gateway: {}", e);
                                        }
                                    }

                                    Err(anyhow!("could not connect to any of gateways"))
                                };

                                match try_connect.await {
                                    Ok(()) => {
                                        info!("connection finished");
                                        break;
                                    }
                                    Err(e) => {
                                        error!("could not connect to gateway: {}", e);
                                    }
                                };
                            }
                        }
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
            self.rules.clone(),
            3,
            1024,
            4096,
        );
        let https = forwarder(
            self.listen_https,
            self.forward_to_https_port,
            self.rules.clone(),
            3,
            1024,
            4096,
        );
        tokio::select! {
            r = http => r,
            r = https => r,
        }
    }
}
