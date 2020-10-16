use crate::config::handler::HandlerExt;
use crate::http_serve::auth::{retrieve_assistant_key, save_assistant_key, AuthFinalizer};
use bytes::{Buf, Bytes};
use exogress_tunnel::{Compression, Conn, ConnectTarget, Connector};
use futures::TryFutureExt;
use futures_util::future::Either;
use futures_util::sink::SinkExt;
use futures_util::stream::{Stream, StreamExt};
use futures_util::TryStreamExt;
use globset::Glob;
use hashbrown::HashMap;
use http::header::{
    ACCEPT_ENCODING, CACHE_CONTROL, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
    COOKIE, HOST, LOCATION, SET_COOKIE, UPGRADE,
};
use http::status::StatusCode;
use http::{Response, Uri};
use hyper::header::{HeaderName, HeaderValue};
use hyper::Body;
use memmap::Mmap;
use reqwest::header::Entry;
use std::convert::{Infallible, TryInto};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use stop_handle::stop_handle;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite;
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;
use warp::reject::Reject;
use warp::{filters, Filter, Rejection, Reply};

use crate::clients::{ClientTunnels, ConnectedTunnel};
// use crate::http_serve::auth;
use crate::config::static_response::StaticResponseExt;
use crate::dbip::LocationAndIsp;
use crate::http_serve::compression::{maybe_compress_body, SupportedContentEncoding};
use crate::http_serve::request::RequestBody;
use crate::http_serve::templates::respond_with_login;
use crate::http_serve::{auth, director};
use crate::joined_io::JoinedIo;
use crate::rules_counter::AccountRulesCounters;
use crate::stop_reasons::AppStopWait;
use crate::url_mapping::mapping::{
    JwtEcdsa, MappingAction, Oauth2Provider, Protocol, UrlForRewriting,
};
use crate::url_mapping::rate_limiter::RateLimiters;
use crate::webapp::Client;
use chrono::{DateTime, Utc};
use cookie::Cookie;
use exogress_config_core::{AclEntry, Action, Auth, AuthProvider, ClientHandlerVariant};
use exogress_entities::{ConfigId, ExceptionName, HandlerName, RateLimiterName};
use exogress_server_common::assistant::GatewayConfigMessage;
use exogress_server_common::director::SourceInfo;
use exogress_server_common::health::HealthState;
use exogress_server_common::url_prefix::UrlPrefix;
use http::uri::Authority;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use parking_lot::RwLock;
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
use rand::distributions::Alphanumeric;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use std::collections::BTreeMap;
use std::io;
use std::io::{BufReader, Cursor};
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::rustls::{NoClientAuth, ServerConfig};
use typed_headers::{Accept, ContentCoding, ContentEncoding, HeaderMapExt};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    idp: String,
    exp: usize,
}

fn extract_sni_hostname(buf: &[u8]) -> Result<Option<Option<String>>, anyhow::Error> {
    match tls_parser::parse_tls_plaintext(buf) {
        Ok((_rem, record)) => Ok(Some(
            record
                .msg
                .into_iter()
                .filter_map(|msg| match msg {
                    tls_parser::tls::TlsMessage::Handshake(handshake) => match handshake {
                        tls_parser::tls::TlsMessageHandshake::ClientHello(hello) => {
                            if let Some(ext) = hello.ext {
                                tls_parser::tls_extensions::parse_tls_extensions(ext)
                                    .ok()
                                    .and_then(|(_, ext)| {
                                        ext
                                            .into_iter()
                                            .filter_map(|ext| match ext {
                                                tls_parser::tls_extensions::TlsExtension::SNI(snis) => snis
                                                    .into_iter()
                                                    .filter_map(|(sni_type, value)| {
                                                        if tls_parser::tls_extensions::SNIType::HostName
                                                            == sni_type
                                                        {
                                                            Some(value)
                                                        } else {
                                                            None
                                                        }
                                                    })
                                                    .next(),
                                                _ => None,
                                            })
                                            .next()
                                    })
                            } else {
                                None
                            }
                        }
                        _ => None,
                    },
                    _ => None,
                })
                .next()
                .and_then(|m| String::from_utf8(m.to_vec()).ok()),
        )),
        Err(nom::Err::Incomplete(_needed)) => {
            Ok(None)
        }
        Err(e) => Err(anyhow!("parse error: {}", e)),
    }
}

pub async fn server(
    tunnels: ClientTunnels,
    listen_http_addr: SocketAddr,
    listen_https_addr: SocketAddr,
    external_https_port: u16,
    webapp_client: Client,
    app_stop_wait: AppStopWait,
    tls_gw_common: Arc<RwLock<Option<GatewayConfigMessage>>>,
    public_base_url: Url,
    individual_hostname: String,
    webroot: PathBuf,
    google_oauth2_client: auth::google::GoogleOauth2Client,
    github_oauth2_client: auth::github::GithubOauth2Client,
    assistant_base_url: Url,
    account_rules_counters: &AccountRulesCounters,
    dbip: Option<Arc<maxminddb::Reader<Mmap>>>,
    resolver: TokioAsyncResolver,
) {
    let (https_stop_handle, https_stop_wait) = stop_handle();

    let redirect_http_server = warp::any()
        .and(filters::path::full())
        // take query part
        .and(
            filters::query::raw()
                .or_else(|_| futures::future::ready(Ok::<(_,), Rejection>(("".to_string(),)))),
        )
        .and(filters::host::optional())
        .map(
            move |path: warp::filters::path::FullPath, query: String, host: Option<Authority>| {
                let mut path_and_query = path.as_str().to_string();

                if !query.is_empty() {
                    path_and_query.push_str("?");
                    path_and_query.push_str(&query);
                }

                let redirect_to_uri = Uri::builder()
                    .scheme("https")
                    .authority(host.unwrap().as_str())
                    .path_and_query(path_and_query.as_str())
                    .build()
                    .unwrap();

                let mut redirect_to = Url::parse(redirect_to_uri.to_string().as_str()).unwrap();

                redirect_to.set_port(Some(external_https_port)).unwrap();

                warp::redirect(redirect_to.as_str().parse::<Uri>().unwrap())
            },
        );

    let acme = warp::path!(".well-known" / "acme-challenge" / String)
        .and(filters::host::optional())
        .and_then({
            shadow_clone!(webapp_client);
            shadow_clone!(webroot);

            move |token: String, host: Option<Authority>| {
                shadow_clone!(webapp_client);
                shadow_clone!(webroot);

                async move {
                    let filename = format!(".well-known/acme-challenge/{}", token);

                    let read_local_file = async {
                        let full_path = webroot.clone().join(&filename);

                        info!("check ACME challenges in {}", full_path.display());
                        let mut file = File::open(full_path).await?;
                        let mut content = String::new();
                        file.read_to_string(&mut content).await?;

                        Ok::<_, io::Error>(content)
                    };

                    match read_local_file.await {
                        Ok(content) => {
                            info!("validation request successfully served from local filder");
                            Ok(Response::builder()
                                .header(CONTENT_TYPE, "text/plain")
                                .body(content)
                                .unwrap())
                        }
                        Err(_e) => {
                            let hostname = host.expect("no host in request");

                            info!(
                                "ACME HTTP challenge verification request: {} on {}",
                                filename, hostname
                            );

                            let res = webapp_client
                                .acme_http_challenge_verification(
                                    hostname.as_str(),
                                    filename.as_str(),
                                )
                                .await;

                            match res {
                                Ok(info) => {
                                    info!("validation request succeeded for host {}", hostname);
                                    Ok(Response::builder()
                                        .header(CONTENT_TYPE, info.content_type.as_str())
                                        .body(info.file_content)
                                        .unwrap())
                                }
                                Err(e) => {
                                    warn!("error in ACME verification: {}", e);
                                    Err(warp::reject::not_found())
                                }
                            }
                        }
                    }
                }
            }
        });

    let health = warp::path!("_exg" / "health")
        .and_then(move || async move { Ok::<_, warp::Rejection>("Healthy") });

    let (mut incoming_http_connections_tx, incoming_http_connections_rx) = mpsc::channel(16);

    let http_acceptor = tokio::spawn(
        #[allow(unreachable_code)]
        async move {
            let mut listener = TcpListener::bind(listen_http_addr).await?;
            loop {
                let (mut conn, _director_addr) = listener.accept().await?;
                let _ = conn.set_nodelay(true);

                let header_len = conn.read_u16().await?;
                let mut buf = vec![0u8; header_len.try_into().unwrap()];
                conn.read_exact(&mut buf).await?;
                let source_info = bincode::deserialize::<SourceInfo>(&buf)?;
                let conn = director::Connection::new(conn, source_info);
                incoming_http_connections_tx
                    .send(Ok::<_, io::Error>(conn))
                    .await?;
            }

            Ok::<_, anyhow::Error>(())
        },
    );

    let (incoming_https_connections_tx, incoming_https_connections_rx) = mpsc::channel(16);
    let https_acceptor = tokio::spawn({
        shadow_clone!(webapp_client);

        #[allow(unreachable_code)]
        async move {
            let mut listener = TcpListener::bind(listen_https_addr).await?;
            loop {
                shadow_clone!(tls_gw_common);
                shadow_clone!(incoming_https_connections_tx);
                shadow_clone!(public_base_url);
                shadow_clone!(webapp_client);

                let (mut conn, _director_addr) = listener.accept().await?;
                let _ = conn.set_nodelay(true);

                let handle_connection = {
                    shadow_clone!(mut incoming_https_connections_tx);

                    async move {
                        shadow_clone!(tls_gw_common);
                        shadow_clone!(public_base_url);
                        shadow_clone!(webapp_client);

                        let handshake = async {
                            let header_len = conn.read_u16().await?;
                            let mut buf = vec![0u8; header_len.try_into().unwrap()];
                            conn.read_exact(&mut buf).await?;
                            let source_info = bincode::deserialize::<SourceInfo>(&buf)?;

                            let mut header = vec![0u8; 512];
                            let mut header_bytes_read = 0;
                            let sni_hostname = loop {
                                let bytes_read =
                                    conn.read(&mut header[header_bytes_read..]).await?;
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

                            let (read, write) = conn.into_split();

                            header.truncate(header_bytes_read);

                            Ok::<_, anyhow::Error>((
                                JoinedIo::new(Cursor::new(header).chain(read), write),
                                sni_hostname,
                                source_info,
                            ))
                        };

                        let (conn, sni_hostname, source_info) =
                            timeout(Duration::from_secs(10), handshake).await??;

                        let hostname = if let Some(hostname) = sni_hostname {
                            hostname
                        } else {
                            return Err(anyhow!("no hostname in ClientHello"));
                        };

                        info!("SNI hostname = {}", hostname);

                        // let builder = warp::TlsConfigBuilder::new();

                        let (cert, pkey) = if public_base_url.host().unwrap().to_string()
                            == hostname
                        {
                            let locked = tls_gw_common.read();

                            let cfg = (&*tls_gw_common.read()).clone();

                            match &cfg {
                                Some(cert_data)
                                    if cert_data.common_gw_hostname == hostname
                                        || cfg!(debug_assertions) =>
                                {
                                    (
                                        cert_data.common_gw_host_certificate.clone(),
                                        cert_data.common_gw_host_private_key.clone(),
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
                                Ok(Some(certs)) => (certs.certificate, certs.private_key),
                                Ok(None) => {
                                    let locked = tls_gw_common.read();

                                    match &*locked {
                                        Some(cert_data) if cfg!(debug_assertions) => (
                                            cert_data.common_gw_host_certificate.clone(),
                                            cert_data.common_gw_host_private_key.clone(),
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

                        let tls_conn = acceptor.accept(conn).await?;

                        let conn = director::Connection::new(tls_conn, source_info);
                        incoming_https_connections_tx
                            .send(Ok::<_, io::Error>(conn))
                            .await?;

                        Ok::<_, anyhow::Error>(())
                    }
                };

                tokio::spawn(handle_connection.map_err(|e| {
                    warn!("connection closed: {}", e);
                }));
            }

            Ok::<(), anyhow::Error>(())
        }
    });

    let http_server = tokio::spawn(
        warp::serve(
            acme.or(health)
                .or(redirect_http_server)
                .with(warp::trace::request()),
        )
        .serve_incoming_with_graceful_shutdown2(incoming_http_connections_rx, {
            async move {
                let reason = https_stop_wait.await;
                info!(
                    "Triggering graceful shutdown of HTTP by request: {}",
                    reason
                );
            }
        }),
    );

    let client = reqwest::ClientBuilder::new()
        .gzip(true)
        .brotli(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(5)
        .use_native_tls()
        .trust_dns(true)
        .build()
        .unwrap();

    let oauth2_callback = warp::path!("_exg" / String / "callback")
        .and(filters::query::query::<HashMap<String, String>>())
        .and_then({
            shadow_clone!(google_oauth2_client);
            shadow_clone!(github_oauth2_client);
            shadow_clone!(assistant_base_url);

            move |provider: String, params| {
                shadow_clone!(google_oauth2_client);
                shadow_clone!(github_oauth2_client);
                shadow_clone!(assistant_base_url);

                async move {
                    let oauth2_result = match provider.as_str() {
                        "google" => google_oauth2_client.process_callback(params).await,
                        "github" => github_oauth2_client.process_callback(params).await,
                        _ => panic!("unsupported provider"),
                    };

                    let mut resp = Response::new("");

                    match oauth2_result {
                        Ok(callback_result) => {
                            info!("oauth2 callback result: {:?}", callback_result);
                            let secret: String =
                                thread_rng().sample_iter(&Alphanumeric).take(30).collect();

                            save_assistant_key(
                                &assistant_base_url,
                                &secret,
                                &AuthFinalizer {
                                    identities: callback_result.identities,
                                    oauth2_flow_data: callback_result.oauth2_flow_data.clone(),
                                },
                                Duration::from_secs(15),
                            )
                            .await
                            .expect("FIXME");

                            let mut redirect_to = callback_result.oauth2_flow_data.base_url.clone();

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

                            resp.headers_mut()
                                .insert(CACHE_CONTROL, "no-cache".try_into().unwrap());

                            resp.headers_mut()
                                .insert(LOCATION, redirect_to.to_string().try_into().unwrap());

                            *resp.status_mut() = StatusCode::TEMPORARY_REDIRECT;
                        }
                        Err(e) => {
                            warn!("Error from Identity Provider: {:?}", e);

                            *resp.status_mut() = StatusCode::FORBIDDEN;
                            *resp.body_mut() = "Forbidden";
                        }
                    }

                    Ok::<_, Rejection>(resp)
                }
            }
        });

    let server = warp::any()
        .and(filters::path::full())
        // take query part
        .and(
            filters::query::raw()
                .or_else(|_| futures::future::ready(Ok::<(String, ), Rejection>(("".into(), )))),
        )
        .map(move |path: warp::filters::path::FullPath, query: String| {
            // info!("check injections in path {:?}", path.as_str());
            // let decoded_path = percent_decode_str(path.as_str()).decode_utf8_lossy();
            // let decoded_query = percent_decode_str(query.as_str()).decode_utf8_lossy();
            //
            // if let Some(true) = libinjection::xss(decoded_path.as_ref()) {
            //     warn!("found XSS in path");
            //     return Err::<_, _>(warp::reject::custom(InjectionFound {}));
            // }
            // if let Some((true, fingerprint)) = libinjection::sqli(decoded_path.as_ref()) {
            //     warn!("found SQL injection in path: {}", fingerprint);
            //     return Err::<_, _>(warp::reject::custom(InjectionFound {}));
            // }
            // if let Some(true) = libinjection::xss(decoded_query.as_ref()) {
            //     warn!("found XSS in query params");
            //     return Err::<_, _>(warp::reject::custom(InjectionFound {}));
            // }
            // if let Some((true, fingerprint)) = libinjection::sqli(decoded_query.as_ref()) {
            //     warn!("found SQL injection in query params: {}", fingerprint);
            //     return Err::<_, _>(warp::reject::custom(InjectionFound {}));
            // }

            (path, query)
        })
        .and(warp::ws().or(filters::body::stream()))
        .and(filters::header::headers_cloned())
        .and(filters::host::optional())
        .and(filters::query::query::<HashMap<String, String>>())
        // find mapping
        .and_then({
            shadow_clone!(webapp_client);
            shadow_clone!(tunnels);
            shadow_clone!(individual_hostname);

            move |(path, query): (warp::filters::path::FullPath, String),
                  ws_or_body,
                  headers: http::HeaderMap,
                  authority: Option<Authority>,
                  params: HashMap<String, String>| {
                shadow_clone!(webapp_client);
                shadow_clone!(individual_hostname);
                shadow_clone!(tunnels);

                async move {
                    let authority = authority.expect("unknown host");

                    let host_without_port = authority.host();

                    let mut requested_url: Url = format!("https://{}{}", authority, path.as_str())
                        .parse()
                        .expect("FIXME: bad URL");

                    if !query.is_empty() {
                        requested_url.set_query(Some(query.as_str()));
                    }

                    info!("path = {:?}", path);

                    let url_for_rewriting = UrlForRewriting::from_components(
                        host_without_port,
                        path.as_str(),
                        query.as_str(),
                    )
                        .unwrap();

                    let proto = match &ws_or_body {
                        warp::Either::A(_) => Protocol::WebSockets,
                        warp::Either::B(_) => Protocol::Http,
                    };

                    let handle_result = webapp_client
                        .resolve_url(
                            url_for_rewriting.clone(),
                            external_https_port,
                            proto,
                            tunnels,
                            individual_hostname.clone(),
                        )
                        .await;

                    match handle_result {
                        Ok(Some((mapping_action, maybe_rate_limiter, mount_point_base_url))) => {
                            if path.as_str().ends_with("/_exg/auth") {
                                let res = (|| {
                                    let redirect_to = params.get("url")?;
                                    let handler_name = params.get("handler")?;
                                    let (found_handler_name, auth_handler) = mapping_action
                                        .handler
                                        .handlers_processor
                                        .handlers
                                        .iter()
                                        .filter_map(|handler| {
                                            if let ClientHandlerVariant::Auth(auth) = &handler.config_handler.variant {
                                                Some((handler.name.clone(), auth.clone()))
                                            } else {
                                                None
                                            }
                                        })
                                        .find(|(found_handler_name, _)| found_handler_name.as_str() == handler_name.as_str())?;

                                    let maybe_provider: Option<AuthProvider> = params
                                        .get("provider")
                                        .cloned()
                                        .or_else(|| {
                                            if auth_handler.providers.len() == 1 {
                                                Some(auth_handler.providers.iter().next().unwrap().name.to_string())
                                            } else {
                                                None
                                            }
                                        })
                                        .map(|p| p.parse().unwrap());

                                    Some((redirect_to, found_handler_name, auth_handler, maybe_provider))
                                })();

                                match res {
                                    Some((redirect_to, found_handler_name, auth_handler, maybe_provider)) => {
                                        Err(warp::reject::custom(ShowAuth {
                                            redirect_to: redirect_to.parse().unwrap(),
                                            base_url: mapping_action.external_base_url,
                                            handler_name: found_handler_name,
                                            auth: auth_handler,
                                            maybe_provider,
                                            jwt_ecdsa: mapping_action.jwt_ecdsa,
                                        }))
                                    }
                                    None => {
                                        Err(warp::reject::not_found())
                                    }
                                }
                            } else if path.as_str().ends_with("/_exg/check_auth") {
                                let secret = params.get("secret").expect("FIXME").clone();

                                Err(warp::reject::custom(Authenticate {
                                    secret,
                                    mapping_action,
                                }))
                            } else {
                                Ok((
                                    ws_or_body,
                                    headers,
                                    path,
                                    maybe_rate_limiter,
                                    mapping_action,
                                    requested_url,
                                    mount_point_base_url,
                                    params,
                                ))
                            }
                        }
                        Ok(None) => Err(warp::reject::not_found()),
                        Err(e) => {
                            error!("Error resolving URL: {:?}", e);
                            Err(warp::reject::not_found())
                        }
                    }
                }
            }
        })
        // check rate limits
        .and_then({
            move |(
                      ws_or_body,
                      headers,
                      path,
                      rate_limiters,
                      action,
                      requested_url,
                      mount_point_base_url,
                      params
                  ): (
                _,
                http::HeaderMap,
                warp::filters::path::FullPath,
                RateLimiters,
                MappingAction,
                _,
                _,
                _,
            )| {
                async move {
                    // let delayed_for = match rate_limiters.process().await {
                    //     RateLimiterResponse::DelayedBy(limiters) => {
                    //         info!("Request delayed: {:?}", limiters);
                    //         Some(limiters.iter().map(|(_, delay)| delay).sum::<Duration>())
                    //     }
                    //     RateLimiterResponse::LimitedError {
                    //         rate_limiter_name,
                    //         not_until,
                    //     } => {
                    //         info!(
                    //             "rate limited by {} at least upto {:?}",
                    //             rate_limiter_name, not_until
                    //         );
                    //         return Err::<_, _>(warp::reject::custom(RateLimited {
                    //             not_until,
                    //             rate_limiter_name,
                    //         }));
                    //     }
                    //     RateLimiterResponse::Passthrough => None,
                    // };

                    Ok::<_, warp::Rejection>((
                        ws_or_body,
                        headers,
                        None, //delayed_for,
                        path,
                        action,
                        requested_url,
                        mount_point_base_url,
                        params
                    ))
                }
            }
        })
        .and(warp::method())
        .and(filters::addr::remote())
        .and(filters::addr::local())
        .and_then({
            shadow_clone!(client);
            shadow_clone!(resolver);
            shadow_clone!(dbip);
            shadow_clone!(individual_hostname);
            shadow_clone!(tunnels);
            shadow_clone!(account_rules_counters);

            move |(
                      ws_or_body,
                      headers,
                      delayed_for,
                      path,
                      mapping_action,
                      requested_url,
                      mount_point_base_url,
                      params
                  ): (
                _,
                http::HeaderMap,
                Option<Duration>,
                _,
                MappingAction,
                Url,
                UrlPrefix,
                _,
            ),
                  method: http::Method,
                  remote_addr: Option<SocketAddr>,
                  local_addr: Option<SocketAddr>| {
                shadow_clone!(client);
                shadow_clone!(resolver);
                shadow_clone!(dbip);
                shadow_clone!(tunnels);
                shadow_clone!(individual_hostname);
                shadow_clone!(mut tunnels);
                shadow_clone!(account_rules_counters);

                let accept = headers.typed_get::<Accept>().expect("FIXME").expect("FIXME");

                let remote_addr = remote_addr.unwrap().ip();
                let local_addr = local_addr.unwrap().ip();

                if let Some(dbip) = dbip {
                    let resolved = dbip.lookup::<LocationAndIsp>(remote_addr);
                    info!("GEO IP: {:?}", resolved);
                }

                async move {
                    let account_name = mapping_action.handler.account_name.clone();
                    let project_name = mapping_action.handler.project_name.clone();
                    // let url = mapping_action.handler.url.clone();

                    let mut req = match ws_or_body {
                        warp::Either::A((ws, )) => {
                            RequestBody::new_ws(ws)
                        }
                        warp::Either::B((body, )) => {
                            RequestBody::new_http(hyper::Body::wrap_stream(
                                tokio::stream::StreamExt::timeout(
                                    to_bytes_stream_and_check_injections(body),
                                    HTTP_BYTES_TIMEOUT,
                                )
                                    .map(|r| {
                                        debug!("streaming data {:?}", r);
                                        match r {
                                            Err(e) => Err(anyhow::Error::new(e)),
                                            Ok(Err(e)) => Err(anyhow::Error::new(e)),
                                            Ok(Ok(r)) => Ok(r),
                                        }
                                    }), //Timeout on data
                            )).await
                        }
                    };

                    info!("!handlers = {:?}", mapping_action.handler);

                    'handlers: for handler in &mapping_action.handler.handlers_processor.handlers {
                        info!("HANDLER: {:?}", handler);
                        info!("requested_url: {:?}", requested_url);

                        let mut replaced_url = requested_url.clone();
                        {
                            let mut requested_segments = requested_url.path_segments().unwrap();
                            info!("handle base_path = {:?}", handler.base_path);
                            info!("requested_segments = {:?}",requested_segments);

                            let matched_segments_count = handler
                                .base_path
                                .iter()
                                .zip(&mut requested_segments)
                                .take_while(|(a,b)| &a.as_ref() == b)
                                .count();
                            info!("matched_segments_count = {} <=> {}", matched_segments_count, handler.base_path.len());
                            if matched_segments_count == handler.base_path.len() {
                                {
                                    let mut replaced_segments = replaced_url.path_segments_mut().unwrap();
                                    replaced_segments.clear();
                                    for segment in &handler.rewrite_base_path {
                                        replaced_segments.push(segment.as_str());
                                    }

                                    // add rest part
                                    for segment in requested_segments {
                                        replaced_segments.push(segment);
                                    }
                                }
                                info!("replaced_url = {:?}", replaced_url);

                            } else {
                                continue 'handlers;
                            }
                        }

                        let matching_actions = handler.config_handler.find_filter_rule(replaced_url.clone());

                        let mut should_try_next_handler = None;

                        'actions: for action in matching_actions {
                            // TODO: handle modifications

                            info!("action = {:?}", action);
                            account_rules_counters.register(&account_name);

                            match action {
                                Action::Respond { static_response_name } => {
                                    if let Some(static_response) = mapping_action
                                        .static_responses
                                        .get(static_response_name) {

                                        let mut resp = Response::new(Body::from(""));

                                        match static_response.try_respond(&accept, &mut resp) {
                                            Ok(()) => {
                                                return Ok(resp);
                                            }
                                            Err(e) => {
                                                return Err(warp::reject::custom(Exception {
                                                    exception_name: "static-response-error".parse().unwrap(),
                                                    delayed_for,
                                                    data: btreemap! {
                                                        "static-response".to_string() => static_response_name.to_string(),
                                                        "error".to_string() => e.to_string(),
                                                    }
                                                }));
                                            }
                                        }
                                    } else {
                                        return Err(warp::reject::custom(Exception {
                                            exception_name: "static-response-not-found".parse().unwrap(),
                                            delayed_for,
                                            data: btreemap! {
                                                "static-response".to_string() => static_response_name.to_string(),
                                            }
                                        }));
                                    }
                                }
                                Action::Throw { exception, data } => {
                                    return Err(warp::reject::custom(Exception {
                                        exception_name: exception.clone(),
                                        delayed_for,
                                        data: data.clone(),
                                    }));
                                }
                                Action::NextHandler => {
                                    info!("skip");
                                    continue 'handlers;
                                }
                                Action::None => {}
                                Action::Invoke { .. } => {
                                    info!("try");
                                    // FIXME
                                    should_try_next_handler = Some(true);
                                    break 'actions;
                                }
                            }
                        };

                        if let Some(should_try_next_handler) = should_try_next_handler {
                            if let Some(auth) = handler.auth() {
                                let cookies = headers.get_all(COOKIE);

                                let proto = if req.is_ws_body() {
                                    Protocol::WebSockets
                                } else {
                                    Protocol::Http
                                };


                                let auth_cookie_name =
                                    format!("exg-auth-{}", handler.name);

                                let jwt_token = cookies
                                    .iter()
                                    .map(|header| {
                                        header
                                            .to_str()
                                            .unwrap()
                                            .split(';')
                                            .map(|s| s.trim_start().trim_end().to_string())
                                    })
                                    .flatten()
                                    .filter_map(move |s| Cookie::parse(s).ok())
                                    .find(|cookie| cookie.name() == auth_cookie_name);

                                info!(
                                    "replaced_url = {:?} mount_point_base_url = {:?}",
                                    replaced_url, mount_point_base_url
                                );

                                if let Some(token) = jwt_token {
                                    match jsonwebtoken::decode::<Claims>(
                                        &token.value(),
                                        &DecodingKey::from_ec_pem(&mapping_action.jwt_ecdsa.public_key)
                                            .expect("FIXME"),
                                        &Validation {
                                            algorithms: vec![jsonwebtoken::Algorithm::ES256],
                                            ..Default::default()
                                        },
                                    ) {
                                        Ok(token) => {
                                            info!("jwt-token parse and verified. go ahead. provider = {}", token.claims.idp);
                                        }
                                        Err(e) => {
                                            if let jsonwebtoken::errors::ErrorKind::InvalidSignature =
                                            e.kind()
                                            {
                                                info!("jwt-token parsed but not verified");
                                            } else {
                                                info!(
                                                    "JWT token error: {:?}. Token: {}",
                                                    e,
                                                    token.value()
                                                );
                                            };
                                            return Err::<_, _>(warp::reject::custom(NotAuthorized {
                                                handler_name: handler.name.clone(),
                                                auth,
                                                requested_url: requested_url.clone(),
                                                base_url: mount_point_base_url.clone(),
                                                proto,
                                                is_jwt_token_included: true,
                                                jwt_ecdsa: mapping_action.jwt_ecdsa.clone(),
                                            }));
                                        }
                                    }
                                } else {
                                    info!("jwt-token not found");

                                    return Err::<_, _>(warp::reject::custom(NotAuthorized {
                                        handler_name: handler.name.clone(),
                                        auth,
                                        requested_url: requested_url.clone(),
                                        base_url: mount_point_base_url.clone(),
                                        proto,
                                        is_jwt_token_included: false,
                                        jwt_ecdsa: mapping_action.jwt_ecdsa,
                                    }));
                                }
                            } else if let Some((config_name, instances_ids)) = &handler.client_config_data {
                                let config_id = ConfigId {
                                    account_name: account_name.clone(),
                                    project_name: project_name.clone(),
                                    config_name: config_name.clone(),
                                };
                                let mut ordered_instances = instances_ids.clone();
                                {
                                    let mut rng = thread_rng();
                                    ordered_instances.shuffle(&mut rng);
                                }

                                if let Some(connect_target) = handler.connect_target("") {
                                    'instances: for instance_id in &ordered_instances {
                                        if let ConnectTarget::Upstream(upstream) = &connect_target {
                                            let state = mapping_action.health.get_health(instance_id, upstream);

                                            match state {
                                                Some(HealthState::NotYetKnown) => {
                                                    info!("Unknown health state. Try to proxy anyway {} {}", instance_id, upstream);
                                                }
                                                Some(HealthState::Unhealthy { probe, reason }) => {
                                                    info!("Skip {} {}. probe {:?} failed with reason {:?}", instance_id, upstream, probe, reason);
                                                    continue 'instances;
                                                }
                                                Some(HealthState::Healthy) | None => {}
                                            }
                                        };

                                        info!("try proxy to {}", instance_id);
                                        let (connector, hyper, proxy_to) =
                                            if let Some(ConnectedTunnel {
                                                            connector, hyper, ..
                                                        }) = tunnels
                                                .retrieve_client_tunnel(
                                                    config_id.clone(),
                                                    instance_id.clone(),
                                                    individual_hostname.clone().into(),
                                                )
                                                .await
                                            {
                                                (connector, hyper, replaced_url.clone())
                                            } else {
                                                info!("No connected tunnels. Try again..");
                                                continue;
                                            };

                                        info!("HTTP: proxy to {}. req = {:?}", proxy_to, req);

                                        if req.is_ws_body() {
                                            let res = proxy_ws(
                                                &mut req,
                                                remote_addr,
                                                headers.clone(),
                                                proxy_to,
                                                local_addr,
                                                mount_point_base_url.host().as_str(),
                                                connector,
                                                connect_target.clone(),
                                            )
                                                .await;

                                            match res {
                                                Ok(mut r) => {
                                                    if r.status() == StatusCode::NOT_FOUND {
                                                        info!("WS not found. try other handlers");
                                                        break 'instances; //continue through handlers
                                                    } else if r.status() == StatusCode::BAD_GATEWAY {
                                                        info!("WS bad gateway. try another instance");
                                                        continue 'instances;
                                                    };
                                                    if let Some(delay) = delayed_for {
                                                        r.headers_mut().insert(
                                                            "x-exg-delayed-for-ms",
                                                            delay
                                                                .as_millis()
                                                                .to_string()
                                                                .try_into()
                                                                .unwrap(),
                                                        );
                                                    }

                                                    return Ok(r);
                                                }
                                                Err(Error::AlreadyUsed) => {
                                                    error!("Give Up retrying WS");
                                                    return Err::<_, _>(warp::reject::custom(
                                                        BadGateway { delayed_for },
                                                    ));
                                                }
                                                Err(e) => {
                                                    error!("WS error: {:?}", e);
                                                }
                                            }
                                        } else if req.is_http() {
                                            let res = proxy_http_request(
                                                &mut req,
                                                remote_addr,
                                                headers.clone(),
                                                proxy_to,
                                                method.clone(),
                                                local_addr,
                                                mount_point_base_url.host().as_str(),
                                                hyper,
                                                connect_target.clone(),
                                            )
                                                .await;

                                            match res {
                                                Ok(mut r) => {
                                                    if r.status() == StatusCode::NOT_FOUND {
                                                        let body = hyper::body::to_bytes(r.body_mut()).await.unwrap();
                                                        info!("HTTP not found. try other handlers. body = {:?}", body);
                                                        break 'instances; //continue through handlers
                                                    } else if r.status() == StatusCode::BAD_GATEWAY {
                                                        let body = r.into_body();
                                                        info!("HTTP bad gateway. try another instance: {:?}", body);
                                                        continue 'instances;
                                                    }

                                                    if let Some(delay) = delayed_for {
                                                        r.headers_mut().insert(
                                                            "x-exg-delayed-for-ms",
                                                            delay
                                                                .as_millis()
                                                                .to_string()
                                                                .try_into()
                                                                .unwrap(),
                                                        );
                                                    }

                                                    return Ok(r);
                                                }
                                                Err(Error::AlreadyUsed) => {
                                                    error!("Give Up retrying HTTP");
                                                    return Err::<_, _>(warp::reject::custom(
                                                        BadGateway { delayed_for },
                                                    ));
                                                }
                                                Err(e) => {
                                                    error!("HTTP error: {:?}", e);
                                                }
                                            }
                                        } else {
                                            info!("no longer retry: req = {:?}", req);
                                            return Err::<_, _>(warp::reject::custom(
                                                BadGateway { delayed_for },
                                            ));
                                        }
                                    }
                                }
                            }
                            if !should_try_next_handler {
                                break 'handlers;
                            }
                        } else {
                            continue 'handlers;
                        }
                    }

                    // no handler processed at this point. Raise Exception

                    return Err::<_, _>(warp::reject::custom(Exception {
                        exception_name: "not-handled".parse().unwrap(),
                        delayed_for,
                        data: Default::default(),
                    }));
                }
            }
        })
        .recover({
            shadow_clone!(google_oauth2_client);
            shadow_clone!(github_oauth2_client);
            shadow_clone!(assistant_base_url);

            move |r| {
                shadow_clone!(google_oauth2_client);
                shadow_clone!(github_oauth2_client);
                shadow_clone!(assistant_base_url);

                warn!("Error: {:?}", r);

                handle_rejection(r, google_oauth2_client, github_oauth2_client, assistant_base_url)
            }
        });

    let https_server = tokio::spawn(
        warp::serve(
            health
                .or(oauth2_callback)
                .or(server)
                .with(warp::trace::request()),
        )
        .serve_incoming_with_graceful_shutdown2(incoming_https_connections_rx, {
            async move {
                let reason = app_stop_wait.await;

                https_stop_handle.stop(reason.clone());

                info!("Triggering graceful shutdown by request: {}", reason);
            }
        }),
    );

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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("loop detected")]
    LoopDetected,

    #[error("request error")]
    RequestError(#[from] hyper::Error),

    #[error("request timeout")]
    Timeout,

    #[error("websocket connect error")]
    WebSocketError(#[from] tungstenite::Error),

    #[error("request is already used")]
    AlreadyUsed,
}

async fn handle_rejection(
    err: Rejection,
    google_oauth2_client: auth::google::GoogleOauth2Client,
    github_oauth2_client: auth::github::GithubOauth2Client,
    assistant_base_url: Url,
) -> Result<impl Reply, Infallible> {
    let mut resp = Response::new(Body::empty());

    resp.headers_mut()
        .insert(CACHE_CONTROL, "no-cache".try_into().unwrap());
    if err.is_not_found() {
        *resp.status_mut() = StatusCode::NOT_FOUND;
        *resp.body_mut() = Body::from("404 Not Found");
    } else if let Some(BadGateway { delayed_for }) = err.find() {
        if let Some(delay) = delayed_for {
            resp.headers_mut().insert(
                "x-exg-delayed-for-ms",
                delay.as_millis().to_string().try_into().unwrap(),
            );
        }

        *resp.status_mut() = StatusCode::BAD_GATEWAY;
        *resp.body_mut() = Body::from("Bad Gateway")
    } else if let Some(RateLimited {
        not_until,
        rate_limiter_name,
    }) = err.find()
    {
        resp.headers_mut()
            .insert("x-exg-rate-limited", "1".try_into().unwrap());
        resp.headers_mut().insert(
            "x-exg-rate-limited-by",
            rate_limiter_name.to_string().try_into().unwrap(),
        );
        resp.headers_mut()
            .insert("x-exg-retry-at", not_until.to_rfc3339().try_into().unwrap());

        *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        *resp.body_mut() = Body::from("Rate Limited");
    } else if let Some(NotAuthorized {
        auth,
        handler_name,
        requested_url,
        jwt_ecdsa,
        base_url,
        proto,
        is_jwt_token_included,
    }) = err.find::<NotAuthorized>()
    {
        match proto {
            Protocol::Http => {
                let mut url = base_url.to_url();
                url.path_segments_mut().unwrap().push("_exg").push("auth");
                url.set_query(Some(
                    format!(
                        "url={}&handler={}",
                        percent_encode(requested_url.as_str().as_ref(), NON_ALPHANUMERIC),
                        percent_encode(handler_name.as_ref(), NON_ALPHANUMERIC),
                    )
                    .as_str(),
                ));
                url.set_host(Some("strip")).unwrap();
                url.set_scheme("http").unwrap();
                let redirect_to = url
                    .to_string()
                    .strip_prefix("http://strip")
                    .unwrap()
                    .to_string();

                resp.headers_mut()
                    .insert(LOCATION, redirect_to.try_into().unwrap());
                *resp.status_mut() = StatusCode::TEMPORARY_REDIRECT;
            }
            Protocol::WebSockets if *is_jwt_token_included => {
                *resp.status_mut() = StatusCode::UNAUTHORIZED;
            }
            Protocol::WebSockets => {
                *resp.status_mut() = StatusCode::FORBIDDEN;
            }
        }
    } else if let Some(ShowAuth {
        base_url,
        redirect_to,
        handler_name,
        auth,
        maybe_provider,
        jwt_ecdsa,
    }) = err.find()
    {
        respond_with_login(
            base_url,
            maybe_provider,
            redirect_to,
            handler_name,
            auth,
            jwt_ecdsa,
            &mut resp,
            google_oauth2_client.clone(),
            github_oauth2_client.clone(),
        )
        .await;
    } else if let Some(Authenticate {
        secret,
        mapping_action,
    }) = err.find::<Authenticate>()
    {
        match retrieve_assistant_key::<AuthFinalizer>(&assistant_base_url, &secret).await {
            Ok(res) => {
                let handler_name = res.oauth2_flow_data.handler_name.clone();
                let used_provider = res.oauth2_flow_data.provider.clone();

                let (_, auth) = mapping_action
                    .handler
                    .handlers_processor
                    .handlers
                    .iter()
                    .filter_map(|handler| {
                        if let ClientHandlerVariant::Auth(auth) = &handler.config_handler.variant {
                            Some((handler.name.clone(), auth.clone()))
                        } else {
                            None
                        }
                    })
                    .find(|(found_handler_name, _)| {
                        found_handler_name.as_str() == handler_name.as_str()
                    })
                    .expect("FIXME");

                info!("auth = {:?}", auth);

                let maybe_auth_definition =
                    auth.providers
                        .iter()
                        .find(|provider| match (&provider.name, &used_provider) {
                            (&AuthProvider::Google, &Oauth2Provider::Google) => true,
                            (&AuthProvider::Github, &Oauth2Provider::Github) => true,
                            _ => false,
                        });
                info!("maybe_auth_definition = {:?}", maybe_auth_definition);

                match maybe_auth_definition {
                    Some(auth_definition) => {
                        let mut acl_allow = false;

                        'acl: for acl_entry in &auth_definition.acl {
                            for identity in &res.identities {
                                match acl_entry {
                                    AclEntry::Allow { identity: pass } => {
                                        let is_match = match Glob::new(pass) {
                                            Ok(glob) => glob.compile_matcher().is_match(identity),
                                            Err(_) => pass == identity,
                                        };
                                        if is_match {
                                            info!("Pass {} ", identity);
                                            acl_allow = true;
                                            break 'acl;
                                        }
                                    }
                                    AclEntry::Deny { identity: deny } => {
                                        let is_match = match Glob::new(deny) {
                                            Ok(glob) => glob.compile_matcher().is_match(identity),
                                            Err(_) => deny == identity,
                                        };
                                        if is_match {
                                            info!("Deny {} ", identity);
                                            acl_allow = false;
                                            break 'acl;
                                        }
                                    }
                                }
                            }
                        }

                        info!("acl_allow = {}", acl_allow);

                        if acl_allow {
                            resp.headers_mut()
                                .insert(CACHE_CONTROL, "no-cache".try_into().unwrap());

                            resp.headers_mut().insert(
                                LOCATION,
                                res.oauth2_flow_data
                                    .requested_url
                                    .to_string()
                                    .try_into()
                                    .unwrap(),
                            );

                            *resp.status_mut() = StatusCode::TEMPORARY_REDIRECT;

                            let claims = Claims {
                                idp: serde_json::to_value(res.oauth2_flow_data.provider)
                                    .unwrap()
                                    .to_string(),
                                exp: (Utc::now() + chrono::Duration::hours(24))
                                    .timestamp()
                                    .try_into()
                                    .unwrap(),
                            };

                            let token = jsonwebtoken::encode(
                                &Header {
                                    alg: jsonwebtoken::Algorithm::ES256,
                                    ..Default::default()
                                },
                                &claims,
                                &EncodingKey::from_ec_pem(
                                    res.oauth2_flow_data.jwt_ecdsa.private_key.as_ref(),
                                )
                                .expect("FIXME"),
                            )
                            .expect("FIXME");

                            let auth_cookie_name =
                                format!("exg-auth-{}", res.oauth2_flow_data.handler_name);

                            let set_cookie = Cookie::build(auth_cookie_name, token)
                                .path(res.oauth2_flow_data.base_url.path())
                                .max_age(time::Duration::hours(24))
                                .http_only(true)
                                .secure(true)
                                .finish();

                            resp.headers_mut()
                                .insert(SET_COOKIE, set_cookie.to_string().try_into().unwrap());
                        } else {
                            *resp.status_mut() = StatusCode::FORBIDDEN;
                            *resp.body_mut() = Body::from("Access Denied");
                        }
                    }
                    None => {
                        info!("could not find provider");
                        *resp.status_mut() = StatusCode::BAD_REQUEST;
                        *resp.body_mut() = Body::from("bad request");
                    }
                }
            }
            Err(e) => {
                info!("could not retrieve assistant oauth2 key: {}", e);
                *resp.status_mut() = StatusCode::UNAUTHORIZED;
                *resp.body_mut() = Body::from("error");
            }
        }
    } else if err.find::<NotSupported>().is_some() {
        *resp.status_mut() = StatusCode::NOT_IMPLEMENTED;
    } else if err.find::<InjectionFound>().is_some() {
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        *resp.body_mut() = Body::from("Injection detected");
    } else if err.find::<AuthError>().is_some() {
        *resp.status_mut() = StatusCode::FORBIDDEN;
        *resp.body_mut() = Body::from("Forbidden");
    } else if let Some(ex) = err.find::<Exception>() {
        *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        let data = serde_json::to_string_pretty(&ex.data).unwrap();
        let msg = format!("Error {}: {}", ex.exception_name, data);
        *resp.body_mut() = Body::from(msg);
    } else {
        *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    }
    Ok(resp)
}

async fn proxy_ws(
    req: &mut RequestBody,
    client_ip_addr: IpAddr,
    headers: http::HeaderMap,
    mut proxy_to: Url,
    local_ip: IpAddr,
    external_host: &str,
    connector: Connector,
    connect_target: ConnectTarget,
) -> Result<Response<hyper::Body>, Error> {
    connect_target.update_url(&mut proxy_to);

    let should_use_tls = if proxy_to.scheme() == "http" {
        proxy_to.set_scheme("ws").unwrap();
        false
    } else if proxy_to.scheme() == "https" {
        proxy_to.set_scheme("wss").unwrap();
        true
    } else if proxy_to.scheme() == "ws" {
        false
    } else if proxy_to.scheme() == "wss" {
        true
    } else {
        error!("bad protocol {:?}", proxy_to);
        panic!("bad protocol {:?}", proxy_to)
    };

    info!("handle WS connection. handler = {:?}", connect_target);

    let mut proxy_req = http::Request::new(());

    *proxy_req.uri_mut() = proxy_to.to_string().try_into().unwrap();

    let proxy_headers = proxy_request_headers(local_ip, external_host, client_ip_addr, headers);

    for (header, value) in proxy_headers.into_iter() {
        match proxy_req
            .headers_mut()
            .entry(HeaderName::from_bytes(header.as_bytes()).unwrap())
        {
            Entry::Occupied(mut e) => {
                e.append(value.try_into().unwrap());
            }
            Entry::Vacant(e) => {
                e.insert(value.try_into().unwrap());
            }
        }
    }

    let transport: Box<dyn Conn> = Box::new(
        connector
            .retrieve_connection(connect_target, Compression::Zstd)
            .await
            .expect("FIXME"),
    );

    info!("connected");

    let (proxied_ws, proxied_response) = if should_use_tls {
        let (s, resp) = tokio_tungstenite::client_async_tls(proxy_req, transport).await?;

        (Either::Left(s), resp)
    } else {
        info!("PLAIN");
        let (s, resp) = tokio_tungstenite::client_async(proxy_req, transport).await?;

        (Either::Right(s), resp)
    };

    // Take WS stream at this point. If error occurred before actual upgrade, the request may be retried with

    let ws = req
        .take()
        .ok_or(Error::AlreadyUsed)?
        .take_ws()
        .expect("bad request type");

    let mut resp = ws
        .on_upgrade({
            move |ws| async move {
                let (server_sink, server_stream) = ws.split();
                let (proxied_sink, proxied_stream) = proxied_ws.split();

                let forward1 = server_stream
                    .map({
                        move |warp_msg| {
                            warp_msg.map(move |r| {
                                let m = if r.is_text() {
                                    tungstenite::Message::Text(r.to_str().unwrap().into())
                                } else if r.is_binary() {
                                    tungstenite::Message::Binary(r.into_bytes())
                                } else if r.is_ping() {
                                    tungstenite::Message::Ping(r.into_bytes())
                                } else if r.is_pong() {
                                    tungstenite::Message::Pong(r.into_bytes())
                                } else if r.is_close() {
                                    //TODO: fix passing close frame
                                    tungstenite::Message::Close(None)
                                } else {
                                    unreachable!()
                                };

                                trace!("Send warp message to handler: {:?}", m);

                                m
                            })
                        }
                    })
                    .map_err({
                        move |e| {
                            error!("Warp WS stream error: {:?}", e);
                        }
                    })
                    .forward(proxied_sink.sink_map_err({
                        move |e| {
                            error!("Tungstenite WS sink error: {:?}", e);
                        }
                    }));

                let forward2 = proxied_stream
                    .map({
                        move |tungstenite_msg| {
                            tungstenite_msg.map(move |r| {
                                let m = match r {
                                    tungstenite::Message::Text(s) => warp::ws::Message::text(s),
                                    tungstenite::Message::Binary(v) => warp::ws::Message::binary(v),
                                    tungstenite::Message::Ping(v) => warp::ws::Message::ping(v),
                                    tungstenite::Message::Pong(v) => warp::ws::Message::pong(v),
                                    tungstenite::Message::Close(v) => {
                                        trace!("Proxied host asked to close connection");
                                        if let Some(close_frame) = v {
                                            warp::ws::Message::close_with(
                                                close_frame.code,
                                                close_frame.reason,
                                            )
                                        } else {
                                            warp::ws::Message::close()
                                        }
                                    }
                                };

                                trace!("Send from host to warp: {:?}", m);

                                m
                            })
                        }
                    })
                    .map_err({
                        move |e| {
                            error!("Tungstenite WS stream error: {:?}", e);
                        }
                    })
                    .forward(server_sink.sink_map_err({
                        move |e| {
                            error!("Warp WS sink error: {:?}", e);
                        }
                    }));

                tokio::select! {
                    _ = forward1 => {},
                    _ = forward2 => {},
                }

                info!("WS connection closed");
            }
        })
        .into_response();

    *resp.status_mut() = proxied_response.status();

    for (header, value) in proxied_response.headers().into_iter() {
        if header.as_str().to_lowercase().starts_with("x-exg") {
            info!("Trying to proxy already proxied request (prevent loops)");
            return Err(Error::LoopDetected);
        }

        if !header.as_str().to_lowercase().starts_with("sec-")
            && header != CONNECTION
            && header != UPGRADE
        {
            match resp.headers_mut().entry(header) {
                Entry::Occupied(mut e) => {
                    e.append(value.try_into().unwrap());
                }
                Entry::Vacant(e) => {
                    e.insert(value.try_into().unwrap());
                }
            }
        }
    }

    resp.headers_mut()
        .insert("x-exg-proxied", HeaderValue::from_str("1").unwrap());

    Ok(resp)
}

static ACCEPT_ENCODING_HEADER: HeaderName = ACCEPT_ENCODING;
static CONNECTION_HEADER: HeaderName = CONNECTION;
static HOST_HEADER: HeaderName = HOST;
static UPGRADE_HEADER: HeaderName = UPGRADE;

fn proxy_request_headers(
    local_ip: IpAddr,
    external_host: &str,
    client_ip: IpAddr,
    mut headers: http::HeaderMap,
) -> Vec<(String, String)> {
    let mut res = vec![];

    res.push(("x-forwarded-host".to_string(), external_host.to_string()));
    res.push(("x-forwarded-proto".to_string(), "https".to_string()));

    //X-Forwarded-Host and X-Forwarded-Proto
    let mut x_forwarded_for = headers
        .remove("x-forwarded-for")
        .map(|h| h.to_str().unwrap().to_string())
        .unwrap_or_else(|| client_ip.to_string());

    x_forwarded_for.push_str(&format!(", {}", local_ip));

    res.push(("x-forwarded-for".into(), x_forwarded_for));
    if !headers.contains_key("x-real-ip") {
        res.push(("x-real-ip".into(), client_ip.to_string()));
    }

    let mut previous = None;
    for (initial_name, value) in headers.into_iter() {
        let name = initial_name.clone().or_else(|| previous.clone()).unwrap();

        if initial_name.is_some() {
            previous = initial_name.clone();
        }

        if name != ACCEPT_ENCODING_HEADER
            && name != CONNECTION_HEADER
            && name != HOST_HEADER
            && !name.as_str().to_lowercase().starts_with("sec-")
            && name != UPGRADE_HEADER
        {
            res.push((name.to_string(), value.to_str().unwrap().to_string()));
        }
    }

    res.push(("x-exg".into(), "1".into()));

    res
}

const HTTP_REQ_TIMEOUT: Duration = Duration::from_secs(60 * 5);
const HTTP_BYTES_TIMEOUT: Duration = Duration::from_secs(60);

async fn proxy_http_request(
    req: &mut RequestBody,
    client_ip_addr: IpAddr,
    headers: http::HeaderMap,
    mut proxy_to: Url,
    method: http::Method,
    local_ip: IpAddr,
    external_host: &str,
    hyper: hyper::client::Client<Connector>,
    connect_target: ConnectTarget,
) -> Result<Response<hyper::Body>, Error> {
    connect_target.update_url(&mut proxy_to);

    let accept_encoding = headers
        .typed_get::<typed_headers::AcceptEncoding>()
        .ok()
        .and_then(|r| r);

    let proxy_headers = proxy_request_headers(local_ip, external_host, client_ip_addr, headers);

    info!("Proxy request to {}", proxy_to);

    let mut proxy_req = hyper::Request::builder()
        .uri(proxy_to.to_string())
        .method(method);

    debug!("Request built");

    for (header, value) in proxy_headers.into_iter() {
        debug!("copy header {:?}: {:?}", header, value);
        proxy_req.headers_mut().unwrap().append(
            HeaderName::from_bytes(header.as_bytes()).unwrap(),
            HeaderValue::from_str(&value).unwrap(),
        );
    }

    let body_stream = req
        .take()
        .ok_or(Error::AlreadyUsed)?
        .take_http()
        .expect("bad request type");

    let r = tokio::time::timeout(
        HTTP_REQ_TIMEOUT,
        hyper.request(proxy_req.body(body_stream).expect("FIXME")),
    )
    .await;

    debug!("finished request {:?}", r);

    match r {
        Err(_) => {
            info!("timeout processing request");

            Err(Error::Timeout)
        }
        Ok(Err(e)) => {
            info!("error requesting client connection: {}", e);

            Err(Error::RequestError(e))
        }
        Ok(Ok(hyper_response)) => {
            debug!("building response");
            let mut resp = Response::builder().status(match hyper_response.status() {
                StatusCode::PERMANENT_REDIRECT => StatusCode::TEMPORARY_REDIRECT,
                code => code,
            });

            let content_type = hyper_response
                .headers()
                .typed_get::<typed_headers::ContentType>()
                .ok()
                .and_then(|r| r);
            let upstream_resp_headers = hyper_response
                .headers()
                .into_iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>();
            let upstream_response_body = hyper_response.into_body();
            let (body_processing, compression) =
                maybe_compress_body(upstream_response_body, accept_encoding, content_type);

            let resp_stream = hyper::Body::wrap_stream(
                tokio::stream::StreamExt::timeout(body_processing, HTTP_BYTES_TIMEOUT).map(|r| {
                    debug!("streaming data {:?}", r);
                    match r {
                        Err(e) => Err(anyhow::Error::new(e)),
                        Ok(Err(e)) => Err(anyhow::Error::new(e)),
                        Ok(Ok(r)) => Ok(r),
                    }
                }), //Timeout on data
            );

            {
                let resp_headers = resp.headers_mut().unwrap();

                debug!("copy headers to response");
                for (header, value) in &upstream_resp_headers {
                    if header == CONNECTION || header == CONTENT_ENCODING {
                        continue;
                    }

                    if compression.is_some() && header == CONTENT_LENGTH {
                        continue;
                    }

                    if header.as_str().to_lowercase().starts_with("x-exg") {
                        info!("Trying to proxy already proxied request (prevent loops)");
                        return Err(Error::LoopDetected);
                    }

                    match resp_headers.entry(header) {
                        Entry::Occupied(mut e) => {
                            e.append(value.try_into().unwrap());
                        }
                        Entry::Vacant(e) => {
                            e.insert(value.try_into().unwrap());
                        }
                    }
                }

                info!("copied resp_headers = {:?}", resp_headers);

                resp_headers.insert("x-exg-proxied", HeaderValue::from_str("1").unwrap());
                resp_headers.insert("vary", HeaderValue::from_str("Accept-Encoding").unwrap());

                info!("compression = {:?}", compression);

                match compression {
                    // Some(SupportedContentEncoding::Brotli) => {
                    //     resp_headers.typed_insert(&ContentEncoding::from(ContentCoding::BROTLI));
                    // }
                    Some(SupportedContentEncoding::Gzip) => {
                        resp_headers.typed_insert(&ContentEncoding::from(ContentCoding::GZIP));
                    }
                    // Some(SupportedContentEncoding::Deflate) => {
                    //     resp_headers.typed_insert(&ContentEncoding::from(ContentCoding::DEFLATE));
                    // }
                    None => {
                        let _ = resp_headers.typed_remove::<ContentEncoding>();
                    }
                }

                info!("updated resp_headers = {:?}", resp_headers);
            }

            Ok(resp.body(resp_stream).expect("FIXME"))
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum StreamingError {
    #[error("streaming with upstream error: `{0}`")]
    UpstreamStreaming(#[from] warp::Error),

    #[error("streaming to user error: `{0}`")]
    OutgoingStreaming(#[from] io::Error),
    //
    // #[error("XSS detected")]
    // XssDetected,
    //
    // #[error("XSS detected")]
    // SqlInjectionDetected { fingerprint: String },
}

#[inline]
fn to_bytes_stream_and_check_injections(
    s: impl Stream<Item = Result<impl Buf + 'static, warp::Error>>,
) -> impl Stream<Item = Result<Bytes, StreamingError>> {
    s.map(move |s| match s {
        Ok(r) => {
            let bytes = r.bytes();
            // if let Ok(str) = std::str::from_utf8(bytes) {
            //     let decoded = percent_decode_str(str).decode_utf8_lossy();
            //     if let Some(true) = libinjection::xss(decoded.as_ref()) {
            //         warn!("found XSS in body");
            //         return Err(StreamingError::XssDetected);
            //     }
            //     if let Some((true, fingerprint)) = libinjection::sqli(decoded.as_ref()) {
            //         warn!("found sql injection in body: `{:?}`", fingerprint);
            //         return Err(StreamingError::SqlInjectionDetected { fingerprint });
            //     }
            // }

            Ok(Bytes::copy_from_slice(bytes))
        }
        Err(e) => {
            info!("Error sending data: {:?}", e);
            Err(e.into())
        }
    })
}

#[derive(Debug)]
struct Authenticate {
    secret: String,
    mapping_action: MappingAction,
}

impl Reject for Authenticate {}

#[derive(Debug)]
struct ShowAuth {
    redirect_to: Url,
    base_url: Url,
    auth: Auth,
    handler_name: HandlerName,
    maybe_provider: Option<AuthProvider>,
    jwt_ecdsa: JwtEcdsa,
}

impl Reject for ShowAuth {}

#[derive(Debug)]
struct AuthError {}

impl Reject for AuthError {}

#[derive(Debug)]
struct RateLimited {
    not_until: DateTime<Utc>,
    rate_limiter_name: RateLimiterName,
}

impl Reject for RateLimited {}

#[derive(Debug)]
struct NotAuthorized {
    handler_name: HandlerName,
    auth: Auth,
    base_url: UrlPrefix,
    requested_url: Url,
    jwt_ecdsa: JwtEcdsa,
    proto: Protocol,
    is_jwt_token_included: bool,
}

impl Reject for NotAuthorized {}

#[derive(Debug)]
struct NotSupported {}

impl Reject for NotSupported {}

#[derive(Debug)]
struct AlreadyProxied {}

impl Reject for AlreadyProxied {}

#[derive(Debug)]
struct InjectionFound {}

impl Reject for InjectionFound {}

#[derive(Debug)]
struct BadGateway {
    delayed_for: Option<Duration>,
}

impl Reject for BadGateway {}

#[derive(Debug)]
struct Exception {
    pub exception_name: ExceptionName,
    pub delayed_for: Option<Duration>,
    pub data: BTreeMap<String, String>,
}

impl Reject for Exception {}
