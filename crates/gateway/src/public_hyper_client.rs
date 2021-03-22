use crate::clients::traffic_counter::{
    RecordedTrafficStatistics, TrafficCountedStream, TrafficCounters,
};
use futures::{
    channel::{mpsc, oneshot},
    future::BoxFuture,
    task::{Context, Poll},
};
use http::Uri;
use prometheus::IntCounter;
use rand::{seq::IteratorRandom, thread_rng};
use std::{pin::Pin, sync::Arc, task};
use tokio::{
    io,
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::{
    client::TlsStream,
    rustls::{ClientConfig, Session},
    webpki::{DNSNameRef, InvalidDNSNameError},
    TlsConnector,
};
use trust_dns_resolver::TokioAsyncResolver;

pub struct HyperUsableConnection {
    _stop_public_counter_tx: oneshot::Sender<()>,
    inner: TlsStream<TrafficCountedStream<TcpStream>>,
}

impl HyperUsableConnection {
    pub fn new(
        conn: TlsStream<TrafficCountedStream<TcpStream>>,
        stop_public_counter_tx: oneshot::Sender<()>,
    ) -> Self {
        HyperUsableConnection {
            _stop_public_counter_tx: stop_public_counter_tx,
            inner: conn,
        }
    }
}

impl hyper::client::connect::Connection for HyperUsableConnection {
    fn connected(&self) -> hyper::client::connect::Connected {
        if self.inner.get_ref().1.get_alpn_protocol() == Some(b"h2") {
            self.inner.get_ref().0.get_ref().connected().negotiated_h2()
        } else {
            self.inner.get_ref().0.get_ref().connected()
        }
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
pub struct MeteredHttpsConnector {
    pub public_counters_tx: mpsc::Sender<RecordedTrafficStatistics>,
    pub resolver: TokioAsyncResolver,
    pub counters: Arc<TrafficCounters>,
    pub sent_counter: IntCounter,
    pub recv_counter: IntCounter,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("not an HTTPS")]
    NotHttps,

    #[error("no hostname in URI")]
    NoHost,

    #[error("not resolved")]
    NotResolved,

    #[error("TLS error: {_0}")]
    Tls(#[from] tokio_rustls::rustls::TLSError),

    #[error("lookup error: {_0}")]
    Lookup(#[from] trust_dns_resolver::error::ResolveError),

    #[error("IO error: {_0}")]
    Io(#[from] std::io::Error),

    #[error("invalid DNS name error: {_0}")]
    InvalidHostname(#[from] InvalidDNSNameError),
}

impl hyper::service::Service<Uri> for MeteredHttpsConnector {
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

        Box::pin(async move {
            if dst.scheme_str() != Some("https") {
                return Err(Error::NotHttps);
            }

            let host = dst.host().ok_or(Error::NoHost)?;

            let ip = resolver
                .lookup_ip(host)
                .await?
                .into_iter()
                .choose(&mut thread_rng())
                .ok_or(Error::NotResolved)?;
            let tcp = TcpStream::connect((ip, dst.port_u16().unwrap_or(443))).await?;
            tcp.set_nodelay(true)?;

            let counted =
                TrafficCountedStream::new(tcp, counters.clone(), sent_counter, recv_counter);

            let (stop_public_counter_tx, stop_public_counter_rx) = oneshot::channel();

            tokio::spawn(TrafficCounters::spawn_flusher(
                counters,
                public_counters_tx,
                stop_public_counter_rx,
            ));

            let mut tls_client_config = ClientConfig::new();
            tls_client_config.root_store =
                rustls_native_certs::load_native_certs().expect("native certs error");

            let c = TlsConnector::from(Arc::new(tls_client_config))
                .connect(DNSNameRef::try_from_ascii_str(host)?, counted)
                .await?;

            Ok(HyperUsableConnection::new(c, stop_public_counter_tx))
        })
    }
}
