use exogress_common::common_utils::uri_ext::UriExt;
use futures::{ready, FutureExt};
use futures_util::{sink::SinkExt, stream::Stream};
use http::{
    header::{CACHE_CONTROL, CONTENT_TYPE, HOST, LOCATION},
    status::StatusCode,
    Request, Response, Version,
};
use hyper::Body;
use std::{convert::TryInto, net::SocketAddr, sync::Arc, time::Duration};
use stop_handle::stop_handle;
use tokio_rustls::{rustls, TlsAcceptor};
use url::Url;

use crate::{
    clients::{
        traffic_counter::{RecordedTrafficStatistics, TrafficCountedStream, TrafficCounters},
        ClientTunnels,
    },
    http_serve::{
        auth,
        auth::{save_assistant_key, AuthFinalizer},
        director,
    },
    stop_reasons::AppStopWait,
    urls::matchable_url::MatchableUrl,
    webapp::Client,
};
use exogress_common::entities::Ulid;
use exogress_server_common::{assistant::GatewayConfigMessage, director::SourceInfo};
use futures::channel::{mpsc, oneshot};
use hyper::service::{make_service_fn, service_fn};
use parking_lot::RwLock;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use smol_str::SmolStr;
use std::{
    io,
    io::{BufReader, Cursor},
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::TcpListener,
    time::timeout,
};
use tokio_rustls::rustls::{NoClientAuth, ServerConfig};
use tokio_util::either::Either;

struct HyperAcceptor<F, I>
where
    F: Stream<Item = Result<(I, SourceInfo), io::Error>> + Unpin + Send,
    I: AsyncRead + AsyncWrite + Send + Unpin,
{
    acceptor: F,
}

pub struct AcceptedIo<I: AsyncRead + AsyncWrite + Send + Unpin> {
    inner: I,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl<I> AcceptedIo<I>
where
    I: AsyncRead + AsyncWrite + Send + Unpin,
{
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

impl<I> AsyncRead for AcceptedIo<I>
where
    I: AsyncRead + AsyncWrite + Send + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<I> AsyncWrite for AcceptedIo<I>
where
    I: AsyncRead + AsyncWrite + Send + Unpin,
{
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

impl<F, I> hyper::server::accept::Accept for HyperAcceptor<F, I>
where
    F: Stream<Item = Result<(I, SourceInfo), io::Error>> + Unpin + Send,
    I: AsyncRead + AsyncWrite + Send + Unpin,
{
    type Conn = AcceptedIo<I>;
    type Error = io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let next_conn = ready!(Pin::new(&mut self.acceptor).poll_next(cx));
        match next_conn {
            Some(Ok((conn, source))) => Poll::Ready(Some(Ok(AcceptedIo {
                inner: conn,
                local_addr: source.local_addr,
                remote_addr: source.remote_addr,
            }))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

pub async fn server(
    tunnels: ClientTunnels,
    listen_http_addr: SocketAddr,
    listen_https_addr: SocketAddr,
    external_https_port: u16,
    webapp_client: Client,
    high_resource_consumption: Arc<AtomicBool>,
    app_stop_wait: AppStopWait,
    tls_gw_common: Arc<RwLock<Option<GatewayConfigMessage>>>,
    public_gw_base_url: Url,
    gw_location: SmolStr,
    individual_hostname: SmolStr,
    google_oauth2_client: auth::google::GoogleOauth2Client,
    github_oauth2_client: auth::github::GithubOauth2Client,
    assistant_base_url: Url,
    maybe_identity: Option<Vec<u8>>,
    https_counters_tx: mpsc::Sender<RecordedTrafficStatistics>,
) {
    let (https_stop_handle, https_stop_wait) = stop_handle();

    let (incoming_http_connections_tx, incoming_http_connections_rx) = mpsc::channel(16);

    let http_acceptor = tokio::spawn(
        #[allow(unreachable_code)]
        async move {
            let listener = TcpListener::bind(listen_http_addr).await?;
            loop {
                let (mut conn, _director_addr) = listener.accept().await?;

                if !high_resource_consumption.load(Ordering::Relaxed) {
                    tokio::spawn({
                        shadow_clone!(mut incoming_http_connections_tx);

                        async move {
                            conn.set_nodelay(true)?;

                            let header_len = conn.read_u16().await?;
                            let mut buf = vec![0u8; header_len.try_into().unwrap()];
                            conn.read_exact(&mut buf).await?;
                            let source_info = serde_cbor::from_slice::<SourceInfo>(&buf)?;
                            let conn = director::Connection::new(conn, source_info.clone());
                            incoming_http_connections_tx
                                .send(Ok::<_, io::Error>((conn, source_info)))
                                .await?;

                            Ok::<_, anyhow::Error>(())
                        }
                    });
                }
            }

            Ok::<_, anyhow::Error>(())
        },
    );

    let (incoming_https_connections_tx, incoming_https_connections_rx) = mpsc::channel(16);
    let https_acceptor = tokio::spawn({
        shadow_clone!(webapp_client, public_gw_base_url);

        #[allow(unreachable_code)]
        async move {
            let listener = TcpListener::bind(listen_https_addr).await?;
            loop {
                shadow_clone!(
                    tls_gw_common,
                    incoming_https_connections_tx,
                    public_gw_base_url,
                    webapp_client,
                    mut https_counters_tx
                );

                let (mut conn, _director_addr) = listener.accept().await?;

                let handle_connection = {
                    shadow_clone!(mut incoming_https_connections_tx);

                    async move {
                        shadow_clone!(tls_gw_common, public_gw_base_url, webapp_client);

                        let handshake = async {
                            conn.set_nodelay(true)?;
                            let header_len = conn.read_u16().await?;
                            let mut buf = vec![0u8; header_len.try_into().unwrap()];
                            conn.read_exact(&mut buf).await?;
                            let source_info = serde_cbor::from_slice::<SourceInfo>(&buf)?;

                            Ok::<_, anyhow::Error>((conn, source_info))
                        };

                        let (conn, source_info) =
                            timeout(Duration::from_secs(10), handshake).await??;

                        let hostname = if let Some(hostname) = &source_info.alpn_domain {
                            hostname.clone()
                        } else {
                            return Err(anyhow!("no hostname in ClientHello"));
                        };

                        let (cert, pkey, maybe_account_info) = if public_gw_base_url
                            .host()
                            .unwrap()
                            .to_string()
                            == hostname
                        {
                            let cfg = (&*tls_gw_common.read()).clone();

                            match &cfg {
                                Some(cert_data)
                                    if cert_data.common_gw_hostname == hostname
                                        || cfg!(debug_assertions) =>
                                {
                                    (
                                        cert_data.common_gw_host_certificate.clone(),
                                        cert_data.common_gw_host_private_key.clone(),
                                        None,
                                    )
                                }
                                Some(cert_data) => {
                                    info!(
                                        "common cert for wrong hostname found. expected {}, found {}",
                                        hostname, cert_data.common_gw_hostname
                                    );
                                    return Err(anyhow!("wrong hostname"));
                                }
                                None => {
                                    info!("certificate haven't been set by assistant channel");
                                    return Err(anyhow!("no certificate set"));
                                }
                            }
                        } else {
                            shadow_clone!(webapp_client);

                            match webapp_client.get_certificate(hostname.clone()).await {
                                Ok(Some(certs)) => (
                                    certs.certificate,
                                    certs.private_key,
                                    Some((certs.account_unique_id, certs.project_unique_id)),
                                ),
                                Ok(None) => {
                                    let locked = tls_gw_common.read();

                                    match &*locked {
                                        Some(cert_data) if cfg!(debug_assertions) => (
                                            cert_data.common_gw_host_certificate.clone(),
                                            cert_data.common_gw_host_private_key.clone(),
                                            Some((
                                                Ulid::nil().to_string().parse().unwrap(),
                                                Ulid::nil().to_string().parse().unwrap(),
                                            )), // FIXME
                                        ),
                                        _ => {
                                            return Err(anyhow!("no certificate found"));
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("error retrieving certificate for {}: {}", hostname, e);
                                    return Err(anyhow!("error retrieving certificates: {}", e));
                                }
                            }
                        };

                        let mut config = ServerConfig::new(NoClientAuth::new());

                        // FIXME: set session memory cache
                        // TODO: migrate to shared session memory cache
                        // config.set_persistence(rustls::ServerSessionMemoryCache::new(1024));
                        config.ticketer = rustls::Ticketer::new();
                        config.ignore_client_order = true;

                        let cert_vec = cert.as_bytes().to_vec();
                        let key_vec = pkey.as_bytes().to_vec();

                        let mut cert_rdr = BufReader::new(Cursor::new(&cert_vec));
                        let certs = tokio_rustls::rustls::internal::pemfile::certs(&mut cert_rdr)
                            .map_err(|_| anyhow!("cert error"))?;

                        let key = match tokio_rustls::rustls::internal::pemfile::pkcs8_private_keys(
                            &mut BufReader::new(Cursor::new(&key_vec)),
                        ) {
                            Ok(pkcs8) if !pkcs8.is_empty() => {
                                info!("using PKCS8 tunnel certificate");
                                pkcs8
                            }
                            _ => tokio_rustls::rustls::internal::pemfile::rsa_private_keys(
                                &mut BufReader::new(Cursor::new(&key_vec)),
                            )
                            .map_err(|_| anyhow!("private key error"))?,
                        };

                        config.set_single_cert(certs, key[0].clone())?;

                        config.set_protocols(&["h2".into(), "http/1.1".into()]);

                        let acceptor = TlsAcceptor::from(Arc::new(config));

                        let metered = if let Some((account_unique_id, project_unique_id)) =
                            maybe_account_info
                        {
                            let counters =
                                TrafficCounters::new(account_unique_id, project_unique_id);
                            let counted_stream = TrafficCountedStream::new(
                                conn,
                                counters.clone(),
                                crate::statistics::HTTPS_BYTES_SENT.clone(),
                                crate::statistics::HTTPS_BYTES_RECV.clone(),
                            );

                            let (stop_flusher_tx, stop_flusher_rx) = oneshot::channel();

                            let flush_counters = TrafficCounters::spawn_flusher(
                                counters,
                                https_counters_tx,
                                stop_flusher_rx,
                            );

                            // we never forcefully stop flusher through the channel,
                            // if will automatically stop when counter flush returns error
                            tokio::spawn(async move {
                                let _stop_flusher_tx = stop_flusher_tx;

                                flush_counters.await
                            });

                            Either::Left(counted_stream)
                        } else {
                            Either::Right(conn)
                        };

                        let tls_conn = acceptor.accept(metered).await?;

                        let conn = director::Connection::new(tls_conn, source_info.clone());
                        incoming_https_connections_tx
                            .send(Ok::<_, io::Error>((conn, source_info)))
                            .await?;

                        Ok::<_, anyhow::Error>(())
                    }
                };

                tokio::spawn(async move {
                    crate::statistics::NUM_OPENED_HTTPS_CONNECTIONS.inc();

                    if let Err(_e) = handle_connection.await {
                        // warn!("connection closed: {}", e);
                    }

                    crate::statistics::NUM_OPENED_HTTPS_CONNECTIONS.dec();
                });
            }

            Ok::<(), anyhow::Error>(())
        }
    });

    let http_make_service = make_service_fn::<_, AcceptedIo<_>, _>({
        shadow_clone!(webapp_client, gw_location);

        move |socket| {
            shadow_clone!(webapp_client, gw_location);

            let _local_addr = socket.local_addr();
            let _remote_addr = socket.remote_addr();

            async move {
                Ok::<_, hyper::Error>(service_fn({
                    shadow_clone!(webapp_client, gw_location);

                    move |req: Request<Body>| {
                        shadow_clone!(webapp_client, gw_location);

                        async move {
                            let mut res = Response::new(Body::empty());
                            res.headers_mut()
                                .insert("server", "exogress".parse().unwrap());
                            res.headers_mut()
                                .insert("x-exg-location", gw_location.parse().unwrap());

                            if req.uri().path() == "/_exg/health" {
                                *res.body_mut() = hyper::Body::from("Healthy");
                                *res.status_mut() = StatusCode::OK;
                                return Ok::<_, anyhow::Error>(res);
                            }

                            let uri = req.uri().to_string();
                            let host = req.headers().get(HOST);

                            let mut url = match uri.parse::<Url>().or_else(|_| {
                                if let Some(host) = host {
                                    Ok(format!("http://{}{}", host.to_str().unwrap(), uri)
                                        .parse()?)
                                } else {
                                    Err::<_, anyhow::Error>(anyhow!("unable to restore url"))
                                }
                            }) {
                                Ok(url) => url,
                                Err(e) => {
                                    error!("failed to build url: {}", e);
                                    *res.status_mut() = StatusCode::BAD_REQUEST;
                                    return Ok(res);
                                }
                            };

                            {
                                if let Some(mut segments) = url.path_segments() {
                                    if segments.next() == Some(".well-known")
                                        && segments.next() == Some("acme-challenge")
                                    {
                                        if let Some(token) = segments.next() {
                                            let hostname = url.host_str().unwrap();

                                            let filename =
                                                format!(".well-known/acme-challenge/{}", token);

                                            info!(
                                                "ACME HTTP challenge verification request: {} on {}",
                                                hostname, filename
                                            );

                                            let webapp_result = webapp_client
                                                .acme_http_challenge_verification(
                                                    hostname,
                                                    filename.as_str(),
                                                )
                                                .await;

                                            match webapp_result {
                                                Ok(info) => {
                                                    info!(
                                                        "validation request succeeded for host {}",
                                                        hostname
                                                    );
                                                    res.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        info.content_type.parse().unwrap(),
                                                    );
                                                    *res.body_mut() = Body::from(info.file_content);
                                                    *res.status_mut() = StatusCode::OK;

                                                    return Ok(res);
                                                }
                                                Err(e) => {
                                                    warn!("error in ACME verification: {}", e);
                                                    *res.status_mut() = StatusCode::NOT_FOUND;

                                                    return Ok(res);
                                                }
                                            }
                                        } else {
                                            *res.status_mut() = StatusCode::NOT_FOUND;
                                            return Ok(res);
                                        }
                                    }
                                }
                            }

                            url.set_scheme("https")
                                .map_err(|_| anyhow!("failed to set https scheme"))?;
                            url.set_port(Some(external_https_port))
                                .map_err(|_| anyhow!("failed to set port"))?;

                            res.headers_mut()
                                .insert(LOCATION, url.to_string().parse().unwrap());
                            *res.status_mut() = StatusCode::PERMANENT_REDIRECT;

                            Ok(res)
                        }
                    }
                }))
            }
        }
    });

    let http_server = hyper::Server::builder(HyperAcceptor {
        acceptor: incoming_http_connections_rx,
    })
    .serve(http_make_service)
    .with_graceful_shutdown(async {
        let reason = https_stop_wait.await;
        info!(
            "Triggering graceful shutdown of HTTP by request: {}",
            reason
        );
    });

    let make_service = make_service_fn::<_, AcceptedIo<_>, _>(move |socket| {
        shadow_clone!(
            webapp_client,
            tunnels,
            individual_hostname,
            public_gw_base_url,
            google_oauth2_client,
            github_oauth2_client,
            assistant_base_url,
            maybe_identity
        );

        let local_addr = socket.local_addr();
        let remote_addr = socket.remote_addr();

        async move {
            Ok::<_, hyper::Error>(service_fn(move |mut req: Request<Body>| {
                shadow_clone!(
                    webapp_client,
                    tunnels,
                    individual_hostname,
                    public_gw_base_url,
                    google_oauth2_client,
                    github_oauth2_client,
                    assistant_base_url,
                    maybe_identity
                );

                async move {
                    let handle = AssertUnwindSafe(async move {
                        crate::statistics::HTTPS_REQUESTS
                            .with_label_values(&[match req.version() {
                                Version::HTTP_09 => "HTTP_09",
                                Version::HTTP_10 => "HTTP_10",
                                Version::HTTP_11 => "HTTP_11",
                                Version::HTTP_2 => "HTTP_2",
                                Version::HTTP_3 => "HTTP_3",
                                _ => "unknown",
                            }])
                            .inc();

                        let mut requested_url = req.uri().clone();

                        if requested_url.host().is_none() {
                            if let Some(host) = req.headers_mut().remove(HOST) {
                                requested_url =
                                    format!("https://{}{}", host.to_str().unwrap(), req.uri())
                                        .parse()
                                        .expect("FIXME");
                            } else {
                                panic!("fixme")
                            }
                        }
                        let mut res = Response::new(Body::empty());

                        let host_without_port = requested_url.host().expect("FIXME");

                        if req.uri().host() == public_gw_base_url.host_str() {
                            if let Err(e) = handle_public_gw_request(
                                requested_url,
                                &req,
                                &mut res,
                                google_oauth2_client,
                                github_oauth2_client,
                                assistant_base_url.clone(),
                                maybe_identity.clone(),
                            )
                            .await
                            {
                                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                *res.body_mut() = Body::from("internal server error");
                                error!("error handling public URL: {}", e);
                            }
                            return Ok(res);
                        }

                        let matchable_url = MatchableUrl::from_components(
                            host_without_port,
                            requested_url.path().as_ref(),
                            requested_url.query().unwrap_or(""),
                        )
                        .expect("FIXME");

                        let handle_result = tokio::time::timeout(
                            Duration::from_secs(30),
                            webapp_client.resolve_url(
                                matchable_url,
                                tunnels.clone(),
                                individual_hostname.clone(),
                            ),
                        )
                        .await;

                        match handle_result {
                            Ok(Ok(Some(requests_processor))) => {
                                let result = tokio::time::timeout(Duration::from_secs(20), async {
                                    requests_processor
                                        .process(
                                            &mut req,
                                            &mut res,
                                            &requested_url,
                                            &local_addr,
                                            &remote_addr,
                                        )
                                        .await;
                                })
                                .await;
                                if result.is_err() {
                                    res = Response::new(Body::from(
                                        "timeout while processing request",
                                    ));
                                    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                }
                            }
                            Ok(Ok(None)) => {
                                *res.status_mut() = StatusCode::NOT_FOUND;
                            }
                            Ok(Err(e)) => {
                                error!("Error resolving URL: {:?}", e);
                                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                            }
                            Err(e) => {
                                error!("Error in config: {}", e);
                                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                *res.body_mut() =
                                    Body::from(format!("error receiving config: `{}`", e));
                            }
                        }

                        Ok::<_, anyhow::Error>(res)
                    });

                    match handle.catch_unwind().await {
                        Err(e) => {
                            let cause = e
                                .downcast_ref::<String>()
                                .map(|e| &**e)
                                .or_else(|| e.downcast_ref::<&'static str>().copied())
                                .unwrap_or("unknown panic error");

                            error!("server error, panic: {}", cause);
                            sentry::capture_message(&cause, sentry::Level::Error);

                            let mut res = Response::new(Body::from("Error processing request"));
                            *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                            Ok(res)
                        }
                        Ok(r) => r,
                    }
                }
            }))
        }
    });

    let https_server = hyper::Server::builder(HyperAcceptor {
        acceptor: incoming_https_connections_rx,
    })
    .serve(make_service)
    .with_graceful_shutdown(async {
        let reason = app_stop_wait.await;
        https_stop_handle.stop(reason.clone());
        info!("Triggering graceful shutdown by request: {}", reason);
    });

    tokio::select! {
        r = http_server => {
            info!("http_server stopped: {:?}", r);
        },
        r = https_server => {
            info!("https_server stopped: {:?}", r);
        },
        r = http_acceptor => {
            info!("http_acceptor stopped: {:?}", r);
        },
        r = https_acceptor => {
            info!("https_acceptor stopped: {:?}", r);
        },
    }
}

async fn handle_public_gw_request(
    url: http::Uri,
    _req: &Request<Body>,
    res: &mut Response<Body>,
    google_oauth2_client: auth::google::GoogleOauth2Client,
    github_oauth2_client: auth::github::GithubOauth2Client,
    assistant_base_url: Url,
    maybe_identity: Option<Vec<u8>>,
) -> anyhow::Result<()> {
    let path_segments = url.path_segments();

    if path_segments.len() == 3 && path_segments[0] == "_exg" && path_segments[2] == "callback" {
        let query_pairs = url.query_pairs();
        let provider = path_segments[1];

        let oauth2_result = match provider {
            "google" => google_oauth2_client.process_callback(query_pairs).await,
            "github" => github_oauth2_client.process_callback(query_pairs).await,
            _ => {
                *res.status_mut() = StatusCode::NOT_FOUND;
                *res.body_mut() = Body::from("not found");

                return Ok(());
            }
        };

        match oauth2_result {
            Ok(callback_result) => {
                info!("oauth2 callback result: {:?}", callback_result);
                let secret: String =
                    String::from_utf8(thread_rng().sample_iter(&Alphanumeric).take(30).collect())
                        .unwrap();

                save_assistant_key(
                    &assistant_base_url,
                    &secret,
                    &AuthFinalizer {
                        identities: callback_result.identities,
                        oauth2_flow_data: callback_result.oauth2_flow_data.clone(),
                    },
                    Duration::from_secs(15),
                    maybe_identity.clone(),
                )
                .await?;

                let mut redirect_to: Url =
                    format!("https://{}/", callback_result.oauth2_flow_data.fqdn).parse()?;

                // FIXME: Broken logic here!
                redirect_to
                    .set_port(callback_result.oauth2_flow_data.requested_url.port())
                    .unwrap();

                redirect_to
                    .path_segments_mut()
                    .unwrap()
                    .push("_exg")
                    .push("check_auth");

                redirect_to.set_query(None);
                redirect_to
                    .query_pairs_mut()
                    .append_pair("secret", secret.as_str());

                redirect_to.set_fragment(None);
                redirect_to.set_scheme("https").unwrap();

                res.headers_mut()
                    .insert(CACHE_CONTROL, "no-cache".try_into().unwrap());

                res.headers_mut()
                    .insert(LOCATION, redirect_to.to_string().try_into().unwrap());

                *res.status_mut() = StatusCode::TEMPORARY_REDIRECT;
            }
            Err(e) => {
                warn!("Error from Identity Provider: {:?}", e);

                *res.status_mut() = StatusCode::FORBIDDEN;
                *res.body_mut() = Body::from("Forbidden");
            }
        }
    } else {
        *res.status_mut() = StatusCode::NOT_FOUND;
        *res.body_mut() = Body::from("not found");
    };

    Ok(())
}
