use crate::clients::traffic_counter::{
    RecordedTrafficStatistics, TrafficCountedStream, TrafficCounters,
};
use exogress_common::common_utils::tls::load_native_certs_safe;
use futures::{
    channel::oneshot,
    future::BoxFuture,
    task::{Context, Poll},
};
use http::Uri;
use prometheus::IntCounter;
use rand::{seq::IteratorRandom, thread_rng};
use std::{io::Cursor, pin::Pin, sync::Arc, task};
use tokio::{
    io,
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::{
    client::TlsStream,
    rustls::{internal::pemfile, ClientConfig, Session},
    webpki::{DNSNameRef, InvalidDNSNameError},
    TlsConnector,
};
use tokio_util::either::Either;
use trust_dns_resolver::TokioAsyncResolver;

pub struct HyperUsableConnection {
    inner: RawMeteredConnection,
}

impl HyperUsableConnection {
    pub fn new(conn: RawMeteredConnection) -> Self {
        HyperUsableConnection { inner: conn }
    }
}

impl hyper::client::connect::Connection for HyperUsableConnection {
    fn connected(&self) -> hyper::client::connect::Connected {
        match &self.inner.inner {
            Either::Left(tls) => {
                if tls.get_ref().1.get_alpn_protocol() == Some(b"h2") {
                    tls.get_ref().0.get_ref().connected().negotiated_h2()
                } else {
                    tls.get_ref().0.get_ref().connected()
                }
            }
            Either::Right(_) => hyper::client::connect::Connected::new(),
        }
    }
}

impl AsyncRead for RawMeteredConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RawMeteredConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for HyperUsableConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for HyperUsableConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Clone)]
pub struct MeteredHttpConnector {
    pub public_counters_tx: tokio::sync::mpsc::Sender<RecordedTrafficStatistics>,
    pub resolver: TokioAsyncResolver,
    pub counters: Arc<TrafficCounters>,
    pub sent_counter: IntCounter,
    pub recv_counter: IntCounter,
    pub maybe_identity: Option<Vec<u8>>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("bad scheme")]
    BadScheme,

    #[error("no hostname in URI")]
    NoHost,

    #[error("not resolved")]
    NotResolved,

    #[error("TLS error: {_0}")]
    Tls(#[from] tokio_rustls::rustls::TLSError),

    #[error("lookup error: {_0}")]
    Lookup(#[from] Box<trust_dns_resolver::error::ResolveError>),

    #[error("IO error: {_0}")]
    Io(#[from] std::io::Error),

    #[error("invalid DNS name error: {_0}")]
    InvalidHostname(#[from] InvalidDNSNameError),

    #[error("bad certificate")]
    BadCert,
}

pub struct RawMeteredConnection {
    _stop_public_counter_tx: oneshot::Sender<()>,
    inner: Either<TlsStream<TrafficCountedStream<TcpStream>>, TrafficCountedStream<TcpStream>>,
}

impl RawMeteredConnection {
    pub fn new(
        conn: Either<TlsStream<TrafficCountedStream<TcpStream>>, TrafficCountedStream<TcpStream>>,
        stop_public_counter_tx: oneshot::Sender<()>,
    ) -> Self {
        RawMeteredConnection {
            _stop_public_counter_tx: stop_public_counter_tx,
            inner: conn,
        }
    }
}

pub async fn connect_metered(
    public_counters_tx: tokio::sync::mpsc::Sender<RecordedTrafficStatistics>,
    resolver: TokioAsyncResolver,
    counters: Arc<TrafficCounters>,
    sent_counter: IntCounter,
    recv_counter: IntCounter,
    host: &str,
    dst_port: u16,
    is_tls: bool,
    maybe_identity: Option<Vec<u8>>,
) -> Result<RawMeteredConnection, Error> {
    let ip = resolver
        .lookup_ip(host)
        .await
        .map_err(Box::new)?
        .into_iter()
        .choose(&mut thread_rng())
        .ok_or(Error::NotResolved)?;
    let tcp = TcpStream::connect((ip, dst_port)).await?;
    tcp.set_nodelay(true)?;

    let counted = TrafficCountedStream::new(tcp, counters.clone(), sent_counter, recv_counter);

    let (stop_public_counter_tx, stop_public_counter_rx) = oneshot::channel();

    tokio::spawn(TrafficCounters::spawn_flusher(
        counters,
        public_counters_tx,
        stop_public_counter_rx,
    ));

    let c = if is_tls {
        let mut tls_client_config = ClientConfig::new();
        load_native_certs_safe(&mut tls_client_config);

        if let Some(buf) = &maybe_identity {
            let (key, certs) = {
                let mut pem = Cursor::new(buf);
                let certs = pemfile::certs(&mut pem).map_err(|_| Error::BadCert)?;
                pem.set_position(0);
                let mut sk = pemfile::pkcs8_private_keys(&mut pem)
                    .and_then(|pkcs8_keys| {
                        if pkcs8_keys.is_empty() {
                            Err(())
                        } else {
                            Ok(pkcs8_keys)
                        }
                    })
                    .or_else(|_| {
                        pem.set_position(0);
                        pemfile::rsa_private_keys(&mut pem)
                    })
                    .map_err(|_| Error::BadCert)?;
                if let (Some(sk), false) = (sk.pop(), certs.is_empty()) {
                    (sk, certs)
                } else {
                    return Err(Error::BadCert);
                }
            };
            tls_client_config.set_single_client_cert(certs, key)?;
        }

        Either::Left(
            TlsConnector::from(Arc::new(tls_client_config))
                .connect(DNSNameRef::try_from_ascii_str(host)?, counted)
                .await?,
        )
    } else {
        Either::Right(counted)
    };

    Ok(RawMeteredConnection::new(c, stop_public_counter_tx))
}

impl hyper::service::Service<Uri> for MeteredHttpConnector {
    type Response = HyperUsableConnection;
    type Error = Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let resolver = self.resolver.clone();
        let counters = self.counters.clone();
        let sent_counter = self.sent_counter.clone();
        let recv_counter = self.recv_counter.clone();
        let public_counters_tx = self.public_counters_tx.clone();
        let maybe_identity = self.maybe_identity.clone();

        Box::pin(async move {
            let host = dst.host().ok_or(Error::NoHost)?;

            let is_tls = if dst.scheme_str() == Some("https") {
                true
            } else if dst.scheme_str() == Some("http") {
                false
            } else {
                return Err(Error::BadScheme);
            };
            let conn = connect_metered(
                public_counters_tx,
                resolver,
                counters,
                sent_counter,
                recv_counter,
                host,
                dst.port_u16().unwrap_or(443),
                is_tls,
                maybe_identity,
            )
            .await?;

            Ok(HyperUsableConnection::new(conn))
        })
    }
}
