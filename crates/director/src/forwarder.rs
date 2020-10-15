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
    mut tx: impl AsyncRead + Unpin,
    mut rx: impl AsyncWrite + Unpin,
    buf: &mut [u8],
) -> Result<(), io::Error> {
    loop {
        let bytes_read = tx.read(buf).await?;

        if bytes_read == 0 {
            break Ok(());
        }

        rx.write(&buf[..bytes_read]).await?;
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
                let local_addr = incoming.local_addr()?;

                info!("accepted connection from {}", incoming_addr);
                if let Some(dst_addr) = rules.inner.lock().next() {
                    tokio::spawn(async move {
                        for _retry in 0..max_retries {
                            let try_connect = async {
                                let conn_result = TcpStream::connect(SocketAddr::from((
                                    dst_addr,
                                    forward_to_port,
                                )))
                                .await;

                                match conn_result {
                                    Ok(mut forward_to) => {
                                        let (incoming_tx, incoming_rx) = incoming.split();
                                        let (dst_tx, mut dst_rx) = forward_to.split();

                                        let header = bincode::serialize(&SourceInfo {
                                            local_addr,
                                            remote_addr: incoming_addr,
                                        })
                                        .unwrap();

                                        dst_rx.write_u16(header.len().try_into().unwrap()).await?;
                                        dst_rx.write_all(&header).await?;

                                        let buf1 = buf_pool.pull(|| [0; BUF_SIZE]);
                                        let buf2 = buf_pool.pull(|| [0; BUF_SIZE]);

                                        let (_, mut reusable_buff1) = buf1.detach();
                                        let (_, mut reusable_buff2) = buf2.detach();

                                        let forward1 =
                                            forward(incoming_tx, dst_rx, &mut reusable_buff1[..]);
                                        let forward2 =
                                            forward(dst_tx, incoming_rx, &mut reusable_buff2[..]);

                                        let r = tokio::select! {
                                            r = forward1 => r,
                                            r = forward2 => r,
                                        };

                                        if buf_pool.len() < max_buf_pool_size {
                                            buf_pool.attach(reusable_buff1);
                                            buf_pool.attach(reusable_buff2);
                                        }

                                        return r;
                                    }
                                    Err(e) => {
                                        warn!("could not connect to gateway: {}", e);
                                    }
                                }

                                Err(io::Error::new(
                                    io::ErrorKind::ConnectionRefused,
                                    "could not connect to any of gateways",
                                ))
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
                    });
                }
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
