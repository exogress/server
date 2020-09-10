use std::convert::{Infallible, TryInto};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use futures_util::future::Either;
use futures_util::sink::SinkExt;
use futures_util::stream::{Stream, StreamExt};
use futures_util::TryStreamExt;
use hashbrown::HashMap;
use http::header::{
    ACCEPT_ENCODING, CACHE_CONTROL, CONNECTION, CONTENT_TYPE, COOKIE, HOST, LOCATION, SET_COOKIE,
    UPGRADE,
};
use http::status::StatusCode;
use http::{Response, Uri};
use memmap::Mmap;
use reqwest::header::Entry;
use stop_handle::stop_handle;
use tokio_tungstenite::tungstenite;
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;
use warp::reject::Reject;
use warp::{filters, Filter, Rejection, Reply};

use exogress_tunnel::{Conn, ConnectTarget, Connector};
use hyper::header::{HeaderName, HeaderValue};
use hyper::Body;

use crate::clients::{ClientTunnels, ConnectedTunnel};
// use crate::http_serve::auth;
use crate::dbip::LocationAndIsp;
use crate::http_serve::auth;
use crate::stop_reasons::AppStopWait;
use crate::url_mapping::mapping::{
    AuthProviderConfig, JwtEcdsa, MappingAction, Oauth2Provider, Oauth2SsoClient, Protocol,
    UrlForRewriting,
};
use crate::url_mapping::rate_limiter::{RateLimiterResponse, RateLimiters};
use crate::webapp::Client;
use chrono::{DateTime, Utc};
use cookie::Cookie;
use exogress_entities::RateLimiterName;
use exogress_server_common::assistant::GatewayCommonTlsConfigMessage;
use exogress_server_common::url_prefix::UrlPrefix;
use http::uri::Authority;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use lru_time_cache::LruCache;
use parking_lot::{Mutex, RwLock};
use rand::distributions::Alphanumeric;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use std::io;
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

pub const AUTH_COOKIE_NAME: &str = "exg_auth";

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    idp: String,
    exp: usize,
}

pub async fn server(
    tunnels: ClientTunnels,
    listen_http_addr: SocketAddr,
    listen_https_addr: SocketAddr,
    external_https_port: u16,
    webapp_client: Client,
    app_stop_wait: AppStopWait,
    tls_gw_common: Arc<RwLock<Option<GatewayCommonTlsConfigMessage>>>,
    public_base_url: Url,
    individual_hostname: String,
    webroot: PathBuf,
    google_oauth2_client: auth::google::GoogleOauth2Client,
    github_oauth2_client: auth::github::GithubOauth2Client,
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

    let (_, http_server) = warp::serve(
        acme.or(health)
            .or(redirect_http_server)
            .with(warp::trace::request()),
    )
    .bind_with_graceful_shutdown(listen_http_addr, {
        async move {
            let reason = https_stop_wait.await;
            info!(
                "Triggering graceful shutdown of HTTP by request: {}",
                reason
            );
        }
    });

    tokio::spawn(http_server);

    let auth_finalizers = Arc::new(Mutex::new(LruCache::with_expiry_duration(
        Duration::from_secs(10),
    )));

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
            shadow_clone!(auth_finalizers);

            move |provider: String, params| {
                shadow_clone!(google_oauth2_client);
                shadow_clone!(github_oauth2_client);

                shadow_clone!(auth_finalizers);

                async move {
                    let oauth2_result = match provider.as_str() {
                        "google" => google_oauth2_client.process_callback(params).await,
                        "github" => github_oauth2_client.process_callback(params).await,
                        _ => todo!("unsupported provider"),
                    };

                    let mut resp = Response::new("");

                    match oauth2_result {
                        Ok(res) => {
                            info!("oauth2 result: {:?}", res);
                            let secret: String =
                                thread_rng().sample_iter(&Alphanumeric).take(30).collect();

                            let mut redirect_to = res.oauth2_flow_data.requested_url.clone();

                            {
                                let mut segments = redirect_to.path_segments_mut().unwrap();
                                segments.clear();
                                segments.push("_exg").push("authorized").push(&secret);
                            }

                            redirect_to.set_query(None);
                            redirect_to.set_fragment(None);
                            redirect_to.set_scheme("https").unwrap();

                            auth_finalizers.lock().insert(secret, res.oauth2_flow_data);

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

    let authorized_callback = warp::path!("_exg" / "authorized" / String).and_then({
        shadow_clone!(auth_finalizers);

        move |secret| {
            shadow_clone!(auth_finalizers);

            let mut resp = Response::new("");

            async move {
                match auth_finalizers.lock().remove(&secret) {
                    Some(res) => {
                        resp.headers_mut()
                            .insert(CACHE_CONTROL, "no-cache".try_into().unwrap());

                        resp.headers_mut()
                            .insert(LOCATION, res.requested_url.to_string().try_into().unwrap());

                        *resp.status_mut() = StatusCode::TEMPORARY_REDIRECT;

                        let claims = Claims {
                            idp: serde_json::to_value(res.provider).unwrap().to_string(),
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
                            &EncodingKey::from_ec_pem(res.jwt_ecdsa.private_key.as_ref())
                                .expect("FIXME"),
                        )
                        .expect("FIXME");

                        let set_cookie = Cookie::build(AUTH_COOKIE_NAME, token)
                            .path(res.base_url.path())
                            .max_age(time::Duration::hours(24))
                            .http_only(true)
                            .secure(true)
                            .finish();

                        resp.headers_mut()
                            .insert(SET_COOKIE, set_cookie.to_string().try_into().unwrap());
                    }
                    None => {
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
                .or_else(|_| futures::future::ready(Ok::<(String,), Rejection>(("".into(),)))),
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
        // find mapping
        .and_then({
            shadow_clone!(webapp_client);
            shadow_clone!(tunnels);
            shadow_clone!(individual_hostname);

            move |(path, query): (warp::filters::path::FullPath, String),
                  ws_or_body,
                  headers: http::HeaderMap,
                  authority: Option<Authority>| {
                shadow_clone!(webapp_client);
                shadow_clone!(individual_hostname);
                shadow_clone!(tunnels);

                async move {
                    let authority = authority.expect("unknown host");

                    let host_without_port = authority.host();

                    let requested_url = format!("https://{}{}?{}", authority, path.as_str(), query)
                        .parse()
                        .expect("FIXME: bad URL");

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
                            Ok((
                                ws_or_body,
                                headers,
                                path,
                                maybe_rate_limiter,
                                mapping_action,
                                requested_url,
                                mount_point_base_url,
                            ))
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
            ): (
                _,
                http::HeaderMap,
                warp::filters::path::FullPath,
                RateLimiters,
                MappingAction,
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
                    ))
                }
            }
        })
        .and(filters::query::query::<HashMap<String, String>>())
        .and(warp::method())
        .and(filters::addr::remote())
        .and(filters::addr::local())
        .and_then({
            shadow_clone!(client);
            shadow_clone!(resolver);
            shadow_clone!(dbip);
            shadow_clone!(individual_hostname);
            shadow_clone!(tunnels);

            move |(
                ws_or_body,
                headers,
                delayed_for,
                _path,
                mapping_action,
                requested_url,
                mount_point_base_url,
            ): (
                _,
                http::HeaderMap,
                Option<Duration>,
                _,
                MappingAction,
                Url,
                UrlPrefix,
            ),
                  _params,
                  method,
                  remote_addr: Option<SocketAddr>,
                  local_addr: Option<SocketAddr>| {
                shadow_clone!(client);
                shadow_clone!(resolver);
                shadow_clone!(dbip);
                shadow_clone!(tunnels);
                shadow_clone!(individual_hostname);
                shadow_clone!(mut tunnels);

                let remote_addr = remote_addr.unwrap().ip();
                let local_addr = local_addr.unwrap().ip();

                if let Some(dbip) = dbip {
                    let resolved = dbip.lookup::<LocationAndIsp>(remote_addr);
                    info!("GEO IP: {:?}", resolved);
                }

                async move {
                    let account_name = mapping_action.handler.account_name;
                    let project_name = mapping_action.handler.project_name;
                    let url = mapping_action.handler.url;
                    let handlers_processor = mapping_action.handler.handlers_processor;

                    for handler in &handlers_processor.handlers {
                        info!("HANDLER: {:?}", handler);

                        let mut ordered_instances = handler.instances_ids.clone();
                        {
                            let mut rng = thread_rng();
                            ordered_instances.shuffle(&mut rng);
                        }

                        if let Some(connect_target) = handler.connect_target("") {
                            for instance_id in ordered_instances.iter() {
                                info!("try proxy to {}", instance_id);
                                let (connector, hyper, proxy_to) =
                                    if let Some(ConnectedTunnel {
                                        connector, hyper, ..
                                    }) = tunnels
                                        .retrieve_client_tunnel(
                                            account_name.clone(),
                                            project_name.clone(),
                                            handler.config_name.clone(),
                                            instance_id.clone(),
                                            individual_hostname.clone().into(),
                                        )
                                        .await
                                    {
                                        (connector, hyper, url.clone())
                                    } else {
                                        info!("No connected tunnels. Try again..");
                                        continue;
                                    };

                                info!("HTTP: proxy to {}", proxy_to);

                                match ws_or_body {
                                    warp::Either::A((ws,)) => {
                                        let res = proxy_ws(
                                            ws,
                                            remote_addr,
                                            headers.clone(),
                                            proxy_to,
                                            local_addr,
                                            connector,
                                            connect_target.clone(),
                                        )
                                        .await;

                                        match res {
                                            Ok(mut r) => {
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
                                            Err(e) => {
                                                error!("Give Up retrying WS. Error: {:?}", e); //FIXME
                                                return Err::<_, _>(warp::reject::custom(
                                                    BadGateway { delayed_for },
                                                ));
                                            }
                                        }
                                    }
                                    warp::Either::B((body,)) => {
                                        let res = proxy_http_request(
                                            body,
                                            remote_addr,
                                            headers.clone(),
                                            proxy_to,
                                            method,
                                            local_addr,
                                            hyper,
                                            connect_target.clone(),
                                        )
                                        .await;

                                        match res {
                                            Ok(mut r) => {
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
                                            Err(e) => {
                                                error!("Give Up retrying HTTP. error: {:?}", e); //FIXME
                                                return Err::<_, _>(warp::reject::custom(
                                                    BadGateway { delayed_for },
                                                ));
                                            }
                                        }
                                    }
                                };
                            }
                        } else if let Some(auth) = handler.auth() {
                            let cookies = headers.get_all(COOKIE);

                            let proto = match &ws_or_body {
                                warp::Either::A(_) => Protocol::WebSockets,
                                warp::Either::B(_) => Protocol::Http,
                            };

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
                                .find(|cookie| cookie.name() == AUTH_COOKIE_NAME);

                            let auth_type = Some(auth.provider.into());

                            info!(
                                "requested_url = {:?} mount_point_base_url = {:?}",
                                requested_url, mount_point_base_url
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
                                    Ok(_token) => {
                                        info!("jwt-token parse and verified. go ahead");
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
                                            auth_type,
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
                                    auth_type,
                                    requested_url: requested_url.clone(),
                                    base_url: mount_point_base_url.clone(),
                                    proto,
                                    is_jwt_token_included: false,
                                    jwt_ecdsa: mapping_action.jwt_ecdsa,
                                }));
                            }
                        }
                    }

                    return Err::<_, _>(warp::reject::custom(BadGateway { delayed_for }));
                }
            }
        })
        .recover({
            shadow_clone!(google_oauth2_client);
            shadow_clone!(github_oauth2_client);

            move |r| {
                shadow_clone!(google_oauth2_client);
                shadow_clone!(github_oauth2_client);

                warn!("Error: {:?}", r);

                handle_rejection(r, google_oauth2_client, github_oauth2_client)
            }
        });

    let (_, https_server) = warp::serve(
        health
            .or(oauth2_callback)
            .or(authorized_callback)
            .or(server)
            .with(warp::trace::request()),
    )
    .tls({
        shadow_clone!(webapp_client);

        move |maybe_hostname| {
            shadow_clone!(webapp_client);
            shadow_clone!(public_base_url);
            shadow_clone!(tls_gw_common);

            info!("Serve hostname (from SNI) `{:?}`", maybe_hostname);

            Box::pin(async move {
                if let Some(hostname) = maybe_hostname {
                    let mut builder = warp::TlsConfigBuilder::new();

                    info!(
                        "compare {:?} with {:?}",
                        public_base_url.host().unwrap().to_string(),
                        hostname
                    );

                    if public_base_url.host().unwrap().to_string() == hostname {
                        let locked = tls_gw_common.read();

                        match &*locked {
                            Some(cert_data) if cert_data.hostname == hostname => {
                                info!("successfully set cert and key");
                                builder = builder
                                    .cert(cert_data.certificate.as_ref())
                                    .key(cert_data.private_key.as_ref());
                            }
                            Some(cert_data) => {
                                info!(
                                    "common cert for wrong hostname found. expected {}, found {}",
                                    hostname, cert_data.hostname
                                );
                                return None;
                            }
                            None => {
                                info!("certificate haven't been set by assistant channel");
                                return None;
                            }
                        }
                    } else {
                        shadow_clone!(webapp_client);

                        match webapp_client.get_certificate(hostname.clone()).await {
                            Ok(Some(certs)) => {
                                builder = builder
                                    .cert(certs.certificate.as_bytes())
                                    .key(certs.private_key.as_bytes());
                            }
                            Ok(None) => {
                                info!("certificate not found");
                                return None;
                            }
                            Err(e) => {
                                warn!("error retrieving certificate for {}: {}", hostname, e);
                                return None;
                            }
                        }
                    }

                    match builder.build() {
                        Err(e) => {
                            error!("Error in TLS certificate: {}", e);
                            None
                        }
                        Ok(r) => Some(Arc::new(r)),
                    }
                } else {
                    None
                }
            })
        }
    })
    .bind_with_graceful_shutdown(listen_https_addr, {
        async move {
            let reason = app_stop_wait.await;

            https_stop_handle.stop(reason.clone());

            info!("Triggering graceful shutdown by request: {}", reason);
        }
    });

    https_server.await;
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
}

async fn handle_rejection(
    err: Rejection,
    google_oauth2_client: auth::google::GoogleOauth2Client,
    github_oauth2_client: auth::github::GithubOauth2Client,
) -> Result<impl Reply, Infallible> {
    let mut resp = Response::new("");

    resp.headers_mut()
        .insert(CACHE_CONTROL, "no-cache".try_into().unwrap());
    if err.is_not_found() {
        *resp.status_mut() = StatusCode::NOT_FOUND;
        *resp.body_mut() = "404 Not Found";
    } else if let Some(BadGateway { delayed_for }) = err.find() {
        if let Some(delay) = delayed_for {
            resp.headers_mut().insert(
                "x-exg-delayed-for-ms",
                delay.as_millis().to_string().try_into().unwrap(),
            );
        }

        *resp.status_mut() = StatusCode::BAD_GATEWAY;
        *resp.body_mut() = "Bad Gateway"
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
        *resp.body_mut() = "Rate Limited"
    } else if let Some(NotAuthorized {
        auth_type: Some(AuthProviderConfig::Oauth2(Oauth2SsoClient { provider })),
        requested_url,
        jwt_ecdsa,
        base_url,
        proto,
        is_jwt_token_included,
    }) = err.find::<NotAuthorized>()
    {
        let redirect_to = match provider {
            Oauth2Provider::Google => google_oauth2_client
                .save_state_and_retrieve_authorization_url(base_url, jwt_ecdsa, requested_url)
                .await
                .expect("FIXME"),
            Oauth2Provider::Github => github_oauth2_client
                .save_state_and_retrieve_authorization_url(base_url, jwt_ecdsa, requested_url)
                .await
                .expect("FIXME"),
        };

        let delete_cookie = Cookie::build(AUTH_COOKIE_NAME, "deleted")
            .http_only(true)
            .secure(true)
            .path(base_url.path())
            .expires(time::OffsetDateTime::unix_epoch())
            .finish();

        resp.headers_mut()
            .insert(SET_COOKIE, delete_cookie.to_string().try_into().unwrap());

        match proto {
            Protocol::Http => {
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
    } else if err.find::<NotSupported>().is_some() {
        *resp.status_mut() = StatusCode::NOT_IMPLEMENTED;
    } else if err.find::<InjectionFound>().is_some() {
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        *resp.body_mut() = "Injection detected";
    } else if err.find::<AuthError>().is_some() {
        *resp.status_mut() = StatusCode::FORBIDDEN;
        *resp.body_mut() = "Forbidden";
    } else {
        *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    }
    Ok(resp)
}

async fn proxy_ws(
    ws: warp::ws::Ws,
    client_ip_addr: IpAddr,
    headers: http::HeaderMap,
    mut proxy_to: Url,
    local_ip: IpAddr,
    connector: Connector,
    connect_target: ConnectTarget,
) -> Result<Response<Body>, Error> {
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

    let proxy_headers = proxy_request_headers(local_ip, client_ip_addr, headers);

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
            .retrieve_connection(connect_target)
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
    client_ip: IpAddr,
    mut headers: http::HeaderMap,
) -> Vec<(String, String)> {
    let mut res = vec![];

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

async fn proxy_http_request<
    T: Stream<Item = Result<impl Buf + 'static, warp::Error>> + Send + Sync + 'static,
>(
    body_stream: T,
    client_ip_addr: IpAddr,
    headers: http::HeaderMap,
    mut proxy_to: Url,
    method: http::Method,
    local_ip: IpAddr,
    hyper: hyper::client::Client<Connector>,
    connect_target: ConnectTarget,
) -> Result<Response<Body>, Error> {
    connect_target.update_url(&mut proxy_to);

    let proxy_headers = proxy_request_headers(local_ip, client_ip_addr, headers);

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

    let r = tokio::time::timeout(
        HTTP_REQ_TIMEOUT,
        hyper.request(
            proxy_req
                .body(hyper::Body::wrap_stream(
                    tokio::stream::StreamExt::timeout(
                        to_bytes_stream_and_check_injections(body_stream),
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
                ))
                .expect("FIXME"),
        ),
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

            debug!("copy headers to response");
            for (header, value) in hyper_response.headers().into_iter() {
                if header.as_str().to_lowercase().starts_with("x-exg") {
                    info!("Trying to proxy already proxied request (prevent loops)");
                    return Err(Error::LoopDetected);
                }

                match resp.headers_mut().unwrap().entry(header) {
                    Entry::Occupied(mut e) => {
                        e.append(value.try_into().unwrap());
                    }
                    Entry::Vacant(e) => {
                        e.insert(value.try_into().unwrap());
                    }
                }
            }

            resp.headers_mut()
                .unwrap()
                .insert("x-exg-proxied", HeaderValue::from_str("1").unwrap());

            debug!("set exg-proxy. sending body");

            Ok(resp.body(hyper_response.into_body()).expect("FIXME"))
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum StreamingError {
    #[error("warp error: `{0}`")]
    Warp(#[from] warp::Error),
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
    auth_type: Option<AuthProviderConfig>,
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
