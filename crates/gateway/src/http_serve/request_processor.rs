use crate::clients::ClientTunnels;
use crate::http_serve::auth;
use crate::http_serve::auth::github::GithubOauth2Client;
use crate::http_serve::auth::google::GoogleOauth2Client;
use crate::http_serve::auth::{
    retrieve_assistant_key, save_assistant_key, AuthFinalizer, JwtEcdsa, Oauth2Provider,
};
use crate::http_serve::health_checks::HealthStorage;
use crate::http_serve::templates::respond_with_login;
use crate::mime_helpers::{is_mime_match, ordered_by_quality};
use crate::webapp::{ConfigData, ConfigsResponse};
use anyhow::Context;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use cookie::Cookie;
use core::mem;
use exogress_config_core::{
    AclEntry, Action, Auth, AuthProvider, Catch, CatchAction, CatchActions, ClientConfig,
    ClientHandler, ClientHandlerVariant, Filter, MatchingPath, Proxy, ResponseBody, Rule,
    StaticDir, StaticResponse, StatusCodeRange, StatusCodeRangeHandler, TemplateEngine,
    UpstreamDefinition, UrlPathSegmentOrQueryPart,
};
use exogress_entities::{
    ConfigId, ConfigName, ExceptionName, HandlerName, InstanceId, MountPointName,
    StaticResponseName, Upstream,
};
use exogress_server_common::url_prefix::MountPointBaseUrl;
use exogress_tunnel::ConnectTarget;
use futures::{SinkExt, StreamExt, TryFutureExt, TryStreamExt};
use globset::Glob;
use handlebars::Handlebars;
use hashbrown::{HashMap, HashSet};
use http::header::{
    ACCEPT_ENCODING, CACHE_CONTROL, CONNECTION, COOKIE, HOST, LOCATION, SET_COOKIE,
    TRANSFER_ENCODING,
};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use hyper::upgrade::Upgraded;
use hyper::{Body, Error};
use itertools::Itertools;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use parking_lot::Mutex;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use smallvec::SmallVec;
use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_either::Either;
use typed_headers::{Accept, ContentCoding, ContentLength, ContentType, HeaderMapExt};
use url::{PathSegmentsMut, Url};
use weighted_rs::{SmoothWeight, Weight};

pub struct RequestsProcessor {
    ordered_handlers: Vec<ResolvedHandler>,
    pub generated_at: DateTime<Utc>,
    // pub health: HealthStorage,
    pub google_oauth2_client: auth::google::GoogleOauth2Client,
    pub github_oauth2_client: auth::github::GithubOauth2Client,
    pub assistant_base_url: Url,
    pub maybe_identity: Option<Vec<u8>>,
    public_gw_base_url: Url,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    idp: String,
    exp: usize,
}

pub enum StepProcessingResult {
    Handled,
    Skipped,
}

impl RequestsProcessor {
    pub async fn process(
        &self,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        requested_url: &Url,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
    ) {
        for handler in &self.ordered_handlers {
            let mut replaced_url = requested_url.clone();
            {
                let mut requested_segments = requested_url.path_segments().unwrap();

                let matched_segments_count = handler
                    .base_path
                    .iter()
                    .zip(&mut requested_segments)
                    .take_while(|(a, b)| &a.as_ref() == b)
                    .count();
                if matched_segments_count == handler.base_path.len() {
                    let mut replaced_segments = replaced_url.path_segments_mut().unwrap();
                    replaced_segments.clear();
                    for segment in &handler.replace_base_path {
                        replaced_segments.push(segment.as_str());
                    }

                    // add rest part
                    for segment in requested_segments {
                        replaced_segments.push(segment);
                    }
                } else {
                    // path don't match the base path. move on to the next handler
                    continue;
                }
            }

            *req.uri_mut() = replaced_url.as_str().parse().unwrap();

            if handler
                .handle_request(req, res, requested_url, local_addr, remote_addr)
                .await
                .is_some()
            {
                break;
            };
        }

        self.compress(req, res);
    }

    fn compress(&self, req: &Request<Body>, res: &mut Response<Body>) {
        let maybe_accept_encoding = req
            .headers()
            .typed_get::<typed_headers::AcceptEncoding>()
            .ok()
            .flatten();
        let maybe_content_type = res
            .headers()
            .typed_get::<typed_headers::ContentType>()
            .ok()
            .flatten();

        let maybe_compression = if maybe_content_type.is_none() {
            None
        } else if !COMPRESSABLE_MIME_TYPES.contains(maybe_content_type.unwrap().essence_str()) {
            None
        } else if let Some(accept_encoding) = maybe_accept_encoding {
            accept_encoding
                .iter()
                .map(|qi| &qi.item)
                .filter_map(|a| SupportedContentEncoding::try_from(a).ok())
                .sorted_by(|&a, &b| a.weight().cmp(&b.weight()).reverse())
                .next()
        } else {
            None
        };

        let compression = match maybe_compression {
            None => return,
            Some(compression) => compression,
        };

        let mut uncompressed_body = mem::replace(res.body_mut(), Body::empty())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()));

        res.headers_mut()
            .insert("vary", HeaderValue::from_str("Accept-Encoding").unwrap());
        let _ = res
            .headers_mut()
            .typed_remove::<typed_headers::ContentLength>();
        let processed_stream = match compression {
            // SupportedContentEncoding::Brotli => {
            //     res.headers_mut()
            //         .typed_insert(&typed_headers::ContentEncoding::from(
            //             typed_headers::ContentCoding::BROTLI,
            //         ));
            //
            //     Either::Left(async_compression::stream::BrotliEncoder::new(
            //         uncompressed_body,
            //     ))
            // }
            SupportedContentEncoding::Gzip => {
                res.headers_mut()
                    .typed_insert(&typed_headers::ContentEncoding::from(
                        typed_headers::ContentCoding::GZIP,
                    ));

                // Either::Right(Either::Left(
                async_compression::stream::GzipEncoder::new(uncompressed_body)
                // ))
            } // SupportedContentEncoding::Deflate => {
              //     res.headers_mut()
              //         .typed_insert(&typed_headers::ContentEncoding::from(
              //             typed_headers::ContentCoding::DEFLATE,
              //         ));
              //
              //     Either::Right(Either::Right(
              //         async_compression::stream::DeflateEncoder::new(uncompressed_body),
              //     ))
              // }
        };

        *res.body_mut() = Body::wrap_stream(processed_stream);
    }
}

struct ResolvedProxy {
    name: Upstream,
    upstream: UpstreamDefinition,
    instance_ids: Mutex<SmoothWeight<InstanceId>>,
    client_tunnels: ClientTunnels,
    config_id: ConfigId,
    individual_hostname: SmolStr,
    public_hostname: SmolStr,
}

impl ResolvedProxy {
    const EXCEPTION_LOOP_DETECTED: ExceptionName = ExceptionName::from_static("loop-detected");

    async fn invoke(
        &self,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        requested_url: &Url,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
    ) -> HandlerInvocationResult {
        if req.headers().contains_key("x-exg-proxied") {
            return HandlerInvocationResult::Exception {
                name: ResolvedProxy::EXCEPTION_LOOP_DETECTED,
                data: Default::default(),
            };
        }

        let mut proxy_to = requested_url.clone();

        let connect_target = ConnectTarget::Upstream(self.name.clone());
        connect_target.update_url(&mut proxy_to);

        proxy_to.set_port(None).unwrap();
        if proxy_to.scheme() == "https" {
            proxy_to.set_scheme("http").unwrap();
        } else if proxy_to.scheme() == "wss" {
            proxy_to.set_scheme("ws").unwrap();
        } else {
            panic!("FIXME");
        }

        let mut proxy_req = Request::<Body>::new(Body::empty());
        *proxy_req.method_mut() = req.method().clone();
        *proxy_req.uri_mut() = proxy_to.as_str().parse().unwrap();

        for (incoming_header_name, incoming_header_value) in req.headers() {
            if incoming_header_name == ACCEPT_ENCODING
                || (incoming_header_name == CONNECTION
                    && incoming_header_value.to_str().unwrap().to_lowercase() != "upgrade")
                || incoming_header_name == HOST
            {
                continue;
            }

            proxy_req
                .headers_mut()
                .append(incoming_header_name, incoming_header_value.clone());
        }

        proxy_req
            .headers_mut()
            .append("x-forwarded-host", self.public_hostname.parse().unwrap());

        proxy_req
            .headers_mut()
            .append("x-forwarded-proto", "https".parse().unwrap());

        //X-Forwarded-Host and X-Forwarded-Proto
        let mut x_forwarded_for = proxy_req
            .headers_mut()
            .remove("x-forwarded-for")
            .map(|h| h.to_str().unwrap().to_string())
            .unwrap_or_else(|| remote_addr.ip().to_string());

        x_forwarded_for.push_str(&format!(", {}", local_addr.ip()));

        proxy_req
            .headers_mut()
            .insert("x-forwarded-for", x_forwarded_for.parse().unwrap());

        if !proxy_req.headers().contains_key("x-real-ip") {
            proxy_req
                .headers_mut()
                .append("x-real-ip", remote_addr.ip().to_string().parse().unwrap());
        }

        proxy_req
            .headers_mut()
            .append("x-exg", "1".parse().unwrap());

        if req.method() != &Method::GET
            && req.headers().get(CONNECTION).map(|h| h.to_str().unwrap()) != Some("upgrade")
        {
            *proxy_req.body_mut() = mem::replace(req.body_mut(), Body::empty());
        }

        let instance_id = Weight::next(&mut *self.instance_ids.lock()).expect("FIXME");

        let http_client = self
            .client_tunnels
            .retrieve_http_connector(
                &self.config_id,
                &instance_id,
                self.individual_hostname.clone(),
            )
            .await
            .expect("FIXME");

        let mut proxy_resp = http_client.request(proxy_req).await.expect("FIXME");

        for (incoming_header_name, incoming_header_value) in proxy_resp.headers() {
            if incoming_header_name == ACCEPT_ENCODING
                || (incoming_header_name == CONNECTION
                    && incoming_header_value.to_str().unwrap().to_lowercase() != "upgrade")
            {
                continue;
            }

            res.headers_mut()
                .append(incoming_header_name, incoming_header_value.clone());
        }

        res.headers_mut()
            .append("x-exg-proxied", "1".parse().unwrap());

        *res.status_mut() = proxy_resp.status();

        if res.status_mut() == &StatusCode::SWITCHING_PROTOCOLS {
            let req_body = mem::replace(req.body_mut(), Body::empty());

            tokio::spawn(async move {
                match proxy_resp.into_body().on_upgrade().await {
                    Ok(mut proxy_upgraded) => {
                        let mut req_upgraded = req_body.on_upgrade().await.expect("FIXME");

                        let mut buf1 = vec![0u8; 65536];
                        let mut buf2 = vec![0u8; 65536];

                        loop {
                            tokio::select! {
                                bytes_read_result = proxy_upgraded.read(&mut buf1) => {
                                    let bytes_read = bytes_read_result
                                        .with_context(|| "error reading from incoming")?;
                                    if bytes_read == 0 {
                                        return Ok(());
                                    } else {
                                        req_upgraded
                                            .write_all(&buf1[..bytes_read])
                                            .await
                                            .with_context(|| "error writing to forwarded")?;
                                    }
                                },

                                bytes_read_result = req_upgraded.read(&mut buf2) => {
                                    let bytes_read = bytes_read_result
                                        .with_context(|| "error reading from forwarded")?;
                                    if bytes_read == 0 {
                                        return Ok(());
                                    } else {
                                        proxy_upgraded
                                            .write_all(&buf2[..bytes_read])
                                            .await
                                            .with_context(|| "error writing to incoming")?;
                                    }
                                }
                            }
                        }

                        Ok::<_, anyhow::Error>(())
                    }
                    Err(_) => {
                        // raise exception
                        panic!("FIXME");
                    }
                }
            });
        } else {
            *res.body_mut() = proxy_resp.into_body();
        }

        HandlerInvocationResult::Responded
    }
}

struct ResolvedStaticDir {
    config: StaticDir,
    handler_name: HandlerName,
    instance_ids: Mutex<SmoothWeight<InstanceId>>,
    client_tunnels: ClientTunnels,
    config_id: ConfigId,
    individual_hostname: SmolStr,
    public_hostname: SmolStr,
}

impl ResolvedStaticDir {
    const EXCEPTION_LOOP_DETECTED: ExceptionName = ResolvedProxy::EXCEPTION_LOOP_DETECTED;

    async fn invoke(
        &self,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        requested_url: &Url,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
    ) -> HandlerInvocationResult {
        if req.headers().contains_key("x-exg-proxied") {
            return HandlerInvocationResult::Exception {
                name: ResolvedProxy::EXCEPTION_LOOP_DETECTED,
                data: Default::default(),
            };
        }

        if req.method() != &Method::GET {
            return HandlerInvocationResult::ToNextHandler;
        }

        let mut proxy_to = requested_url.clone();

        let connect_target = ConnectTarget::Internal(self.handler_name.clone());
        connect_target.update_url(&mut proxy_to);

        proxy_to.set_port(None).unwrap();
        if proxy_to.scheme() == "https" {
            proxy_to.set_scheme("http").unwrap();
        } else {
            panic!("FIXME");
        }

        let mut proxy_req = Request::<Body>::new(Body::empty());
        *proxy_req.method_mut() = req.method().clone();
        *proxy_req.uri_mut() = proxy_to.as_str().parse().unwrap();

        for (incoming_header_name, incoming_header_value) in req.headers() {
            if incoming_header_name == ACCEPT_ENCODING
                || incoming_header_name == CONNECTION
                || incoming_header_name == HOST
            {
                continue;
            }

            proxy_req
                .headers_mut()
                .append(incoming_header_name, incoming_header_value.clone());
        }

        proxy_req
            .headers_mut()
            .append("x-forwarded-host", self.public_hostname.parse().unwrap());

        proxy_req
            .headers_mut()
            .append("x-forwarded-proto", "https".parse().unwrap());

        //X-Forwarded-Host and X-Forwarded-Proto
        let mut x_forwarded_for = proxy_req
            .headers_mut()
            .remove("x-forwarded-for")
            .map(|h| h.to_str().unwrap().to_string())
            .unwrap_or_else(|| remote_addr.ip().to_string());

        x_forwarded_for.push_str(&format!(", {}", local_addr.ip()));

        proxy_req
            .headers_mut()
            .insert("x-forwarded-for", x_forwarded_for.parse().unwrap());

        if !proxy_req.headers().contains_key("x-real-ip") {
            proxy_req
                .headers_mut()
                .append("x-real-ip", remote_addr.ip().to_string().parse().unwrap());
        }

        proxy_req
            .headers_mut()
            .append("x-exg", "1".parse().unwrap());

        *proxy_req.body_mut() = mem::replace(req.body_mut(), Body::empty());

        let instance_id = Weight::next(&mut *self.instance_ids.lock()).expect("FIXME");

        let http_client = self
            .client_tunnels
            .retrieve_http_connector(
                &self.config_id,
                &instance_id,
                self.individual_hostname.clone(),
            )
            .await
            .expect("FIXME");

        let mut proxy_resp = http_client.request(proxy_req).await.expect("FIXME");

        for (incoming_header_name, incoming_header_value) in proxy_resp.headers() {
            if incoming_header_name == ACCEPT_ENCODING || incoming_header_name == CONNECTION {
                continue;
            }

            res.headers_mut()
                .append(incoming_header_name, incoming_header_value.clone());
        }

        res.headers_mut()
            .append("x-exg-proxied", "1".parse().unwrap());
        *res.status_mut() = proxy_resp.status();
        *res.body_mut() = proxy_resp.into_body();

        HandlerInvocationResult::Responded
    }
}

#[derive(Debug)]
struct ResolvedAuth {
    config: Auth,
    handler_name: HandlerName,
    mount_point_base_url: MountPointBaseUrl,
    jwt_ecdsa: JwtEcdsa,
    google_oauth2_client: GoogleOauth2Client,
    github_oauth2_client: GithubOauth2Client,
    assistant_base_url: Url,
    maybe_identity: Option<Vec<u8>>,
}

impl ResolvedAuth {
    fn cookie_name(&self) -> String {
        format!("exg-auth-{}", self.handler_name)
    }

    fn respond_not_authorized(&self, req: &Request<Body>, res: &mut Response<Body>) {
        *res.status_mut() = StatusCode::TEMPORARY_REDIRECT;
        let mut redirect_to = self.mount_point_base_url.to_url();
        redirect_to
            .path_segments_mut()
            .unwrap()
            .push("_exg")
            .push("auth");

        redirect_to
            .query_pairs_mut()
            .append_pair("url", req.uri().to_string().as_str())
            .append_pair("handler", self.handler_name.as_str());

        redirect_to.set_host(Some("strip")).unwrap();
        redirect_to.set_port(None).unwrap();
        redirect_to.set_scheme("https").unwrap();

        let auth_redirect_relative_url =
            redirect_to.as_str().strip_prefix("https://strip").unwrap();

        res.headers_mut()
            .insert(LOCATION, auth_redirect_relative_url.try_into().unwrap());
    }

    async fn invoke(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        requested_url: &Url,
    ) -> HandlerInvocationResult {
        let path_segments: Vec<_> = requested_url.path_segments().unwrap().collect();
        let query = requested_url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<HashMap<String, String>>();

        let path_segments_len = path_segments.len();

        if path_segments_len >= 2 {
            if path_segments[path_segments_len - 2] == "_exg" {
                if path_segments[path_segments_len - 1] == "auth" {
                    let result = (|| {
                        let requested_url: Url = query.get("url")?.parse().ok()?;
                        let handler_name: HandlerName =
                            query.get("handler")?.as_str().parse().expect("FIXME");

                        let maybe_default_provider: Option<AuthProvider> = query
                            .get("provider")
                            .cloned()
                            .or_else(|| {
                                if self.config.providers.len() == 1 {
                                    Some(
                                        self.config
                                            .providers
                                            .iter()
                                            .next()
                                            .unwrap()
                                            .name
                                            .to_string(),
                                    )
                                } else {
                                    None
                                }
                            })
                            .map(|p| p.parse().unwrap());

                        Some((requested_url, handler_name, maybe_default_provider))
                    })();

                    match result {
                        Some((requested_url, handler_name, maybe_provider)) => {
                            if handler_name != self.handler_name {
                                return HandlerInvocationResult::ToNextHandler;
                            }

                            respond_with_login(
                                res,
                                &self.mount_point_base_url,
                                &maybe_provider,
                                &requested_url,
                                &handler_name,
                                &self.config,
                                &self.jwt_ecdsa,
                                &self.google_oauth2_client,
                                &self.github_oauth2_client,
                            )
                            .await;

                            return HandlerInvocationResult::Responded;
                        }
                        None => {
                            *res.status_mut() = StatusCode::NOT_FOUND;

                            return HandlerInvocationResult::Responded;
                        }
                    }
                } else if path_segments[path_segments_len - 1] == "check_auth" {
                    let secret = query.get("secret").expect("FIXME").clone();

                    match retrieve_assistant_key::<AuthFinalizer>(
                        &self.assistant_base_url,
                        &secret,
                        self.maybe_identity.clone(),
                    )
                    .await
                    {
                        Ok(retrieved_flow_data) => {
                            let handler_name =
                                retrieved_flow_data.oauth2_flow_data.handler_name.clone();
                            let used_provider =
                                retrieved_flow_data.oauth2_flow_data.provider.clone();

                            if handler_name != self.handler_name {
                                return HandlerInvocationResult::ToNextHandler;
                            }

                            let maybe_auth_definition =
                                self.config.providers.iter().find(|provider| {
                                    match (&provider.name, &used_provider) {
                                        (&AuthProvider::Google, &Oauth2Provider::Google) => true,
                                        (&AuthProvider::Github, &Oauth2Provider::Github) => true,
                                        _ => false,
                                    }
                                });

                            match maybe_auth_definition {
                                Some(auth_definition) => {
                                    let mut acl_allow = false;

                                    'acl: for acl_entry in &auth_definition.acl {
                                        for identity in &retrieved_flow_data.identities {
                                            match acl_entry {
                                                AclEntry::Allow { identity: pass } => {
                                                    let is_match = match Glob::new(pass) {
                                                        Ok(glob) => glob
                                                            .compile_matcher()
                                                            .is_match(identity),
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
                                                        Ok(glob) => glob
                                                            .compile_matcher()
                                                            .is_match(identity),
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

                                    if acl_allow {
                                        res.headers_mut()
                                            .insert(CACHE_CONTROL, "no-cache".try_into().unwrap());

                                        res.headers_mut().insert(
                                            LOCATION,
                                            retrieved_flow_data
                                                .oauth2_flow_data
                                                .requested_url
                                                .to_string()
                                                .try_into()
                                                .unwrap(),
                                        );

                                        *res.status_mut() = StatusCode::TEMPORARY_REDIRECT;

                                        let claims = Claims {
                                            idp: serde_json::to_value(
                                                retrieved_flow_data.oauth2_flow_data.provider,
                                            )
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
                                                retrieved_flow_data
                                                    .oauth2_flow_data
                                                    .jwt_ecdsa
                                                    .private_key
                                                    .as_ref(),
                                            )
                                            .expect("FIXME"),
                                        )
                                        .expect("FIXME");

                                        let auth_cookie_name = self.cookie_name();

                                        let set_cookie = Cookie::build(auth_cookie_name, token)
                                            .path(
                                                retrieved_flow_data
                                                    .oauth2_flow_data
                                                    .base_url
                                                    .path(),
                                            )
                                            .max_age(time::Duration::hours(24))
                                            .http_only(true)
                                            .secure(true)
                                            .finish();

                                        res.headers_mut().insert(
                                            SET_COOKIE,
                                            set_cookie.to_string().try_into().unwrap(),
                                        );
                                    } else {
                                        *res.status_mut() = StatusCode::FORBIDDEN;
                                        *res.body_mut() = Body::from("Access Denied");
                                    }
                                }
                                None => {
                                    info!("could not find provider");
                                    *res.status_mut() = StatusCode::BAD_REQUEST;
                                    *res.body_mut() = Body::from("bad request");
                                }
                            }
                        }
                        Err(e) => {
                            info!("could not retrieve assistant oauth2 key: {}", e);
                            *res.status_mut() = StatusCode::UNAUTHORIZED;
                            *res.body_mut() = Body::from("error");
                        }
                    }

                    return HandlerInvocationResult::Responded;
                }
            }
        }

        // otherwise, check authorization cookie

        let auth_cookie_name = self.cookie_name();

        let jwt_token = req
            .headers()
            .get_all(COOKIE)
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

        if let Some(token) = jwt_token {
            match jsonwebtoken::decode::<Claims>(
                &token.value(),
                &DecodingKey::from_ec_pem(&self.jwt_ecdsa.public_key).expect("FIXME"),
                &Validation {
                    algorithms: vec![jsonwebtoken::Algorithm::ES256],
                    ..Default::default()
                },
            ) {
                Ok(token) => {
                    info!(
                        "jwt-token parse and verified. go ahead. provider = {}",
                        token.claims.idp
                    );
                }
                Err(e) => {
                    if let jsonwebtoken::errors::ErrorKind::InvalidSignature = e.kind() {
                        info!("jwt-token parsed but not verified");
                    } else {
                        info!("JWT token error: {:?}. Token: {}", e, token.value());
                    };

                    self.respond_not_authorized(req, res);
                    return HandlerInvocationResult::Responded;
                }
            }
        } else {
            info!("jwt-token not found");

            self.respond_not_authorized(req, res);
            return HandlerInvocationResult::Responded;
        }

        HandlerInvocationResult::ToNextHandler
    }
}

enum ResolvedHandlerVariant {
    Proxy(ResolvedProxy),
    StaticDir(ResolvedStaticDir),
    Auth(ResolvedAuth),
}

#[derive(Debug)]
enum HandlerInvocationResult {
    Responded,
    ToNextHandler,
    Exception {
        name: ExceptionName,
        data: HashMap<SmolStr, SmolStr>,
    },
}

lazy_static! {
    pub static ref COMPRESSABLE_MIME_TYPES: HashSet<&'static str> = vec![
        mime::TEXT_CSS.essence_str(),
        mime::TEXT_CSV.essence_str(),
        mime::TEXT_HTML.essence_str(),
        mime::TEXT_JAVASCRIPT.essence_str(),
        mime::TEXT_PLAIN.essence_str(),
        mime::TEXT_STAR.essence_str(),
        mime::TEXT_TAB_SEPARATED_VALUES.essence_str(),
        mime::TEXT_VCARD.essence_str(),
        mime::TEXT_XML.essence_str(),
        mime::IMAGE_BMP.essence_str(),
        mime::IMAGE_SVG.essence_str(),
        mime::APPLICATION_JAVASCRIPT.essence_str(),
        mime::APPLICATION_JSON.essence_str(),
        "application/atom+xml",
        "application/geo+json",
        "application/x-javascript",
        "application/ld+json",
        "application/manifest+json",
        "application/rdf+xml",
        "application/rss+xml",
        "application/vnd.ms-fontobject",
        "application/wasm",
        "application/x-web-app-manifest+json",
        "application/xhtml+xml",
        "application/xml",
        "font/eot",
        "font/otf",
        "font/ttf",
        "text/cache-manifest",
        "text/calendar",
        "text/markdown",
        "text/vnd.rim.location.xloc",
        "text/vtt",
        "text/x-component",
        "text/x-cross-domain-policy",
    ]
    .into_iter()
    .collect();
}

#[derive(Debug, Clone, Copy)]
pub enum SupportedContentEncoding {
    // Brotli,
    Gzip,
    // Deflate,
}

impl SupportedContentEncoding {
    pub fn weight(&self) -> u8 {
        match self {
            // SupportedContentEncoding::Brotli => 1,
            SupportedContentEncoding::Gzip => 150,
            // SupportedContentEncoding::Deflate => 10,
        }
    }
}

impl<'a> TryFrom<&'a ContentCoding> for SupportedContentEncoding {
    type Error = ();

    fn try_from(value: &'a ContentCoding) -> Result<Self, Self::Error> {
        match value {
            // &ContentCoding::BROTLI => Ok(SupportedContentEncoding::Brotli),
            &ContentCoding::GZIP | &ContentCoding::STAR => Ok(SupportedContentEncoding::Gzip),
            // &ContentCoding::DEFLATE => Ok(SupportedContentEncoding::Deflate),
            _ => Err(()),
        }
    }
}

impl ResolvedHandlerVariant {
    async fn invoke(
        &self,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        requested_url: &Url,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
    ) -> HandlerInvocationResult {
        match self {
            ResolvedHandlerVariant::Proxy(proxy) => {
                proxy
                    .invoke(req, res, requested_url, local_addr, remote_addr)
                    .await
            }
            ResolvedHandlerVariant::StaticDir(static_dir) => {
                static_dir
                    .invoke(req, res, requested_url, local_addr, remote_addr)
                    .await
            }
            ResolvedHandlerVariant::Auth(auth) => auth.invoke(req, res, requested_url).await,
        }
    }
}

#[derive(Debug)]
enum ResolvedFinalizingRuleAction {
    Invoke {
        catch: ResolvedCatchActions,
    },
    NextHandler,
    Throw {
        exception: ExceptionName,
        data: HashMap<SmolStr, SmolStr>,
    },
    Respond {
        static_response: ResolvedStaticResponse,
    },
}

#[derive(Debug)]
enum ResolvedRuleAction {
    Finalizing(ResolvedFinalizingRuleAction),
    None,
}

impl ResolvedRuleAction {
    fn is_finalizing(&self) -> bool {
        match self {
            ResolvedRuleAction::None => false,
            ResolvedRuleAction::Finalizing(_) => true,
        }
    }
}

#[derive(Debug)]
enum ResolvedCatchAction {
    StaticResponse {
        static_response: ResolvedStaticResponse,
    },
    Throw {
        exception_name: ExceptionName,
        data: HashMap<SmolStr, SmolStr>,
    },
    NextHandler,
}

#[derive(Debug)]
pub struct ResolvedFilter {
    pub path: MatchingPath,
    pub base_path: Vec<UrlPathSegmentOrQueryPart>,
}

impl ResolvedFilter {
    fn is_matches(&self, url: &Url) -> bool {
        let mut segments = vec![];
        {
            let mut path_segments = url.path_segments().unwrap();
            let mut base_segments = self.base_path.iter();

            while let Some(expected_base_segment) = base_segments.next() {
                if let Some(segment) = path_segments.next() {
                    if segment != expected_base_segment.as_str() {
                        return false;
                    }
                } else {
                    return false;
                }
            }

            while let Some(segment) = path_segments.next() {
                segments.push(segment.to_string());
            }
        }

        match &self.path {
            MatchingPath::Root
                if segments.len() == 0 || (segments.len() == 1 && segments[0].is_empty()) =>
            {
                return true;
            }
            MatchingPath::Wildcard => {
                return true;
            }
            MatchingPath::Strict(match_segments) => {
                if match_segments.len() != segments.len() {
                    return false;
                }
                for (match_segment, segment) in match_segments.iter().zip(&segments) {
                    if !match_segment.is_match(segment) {
                        return false;
                    }
                }
                return true;
            }
            MatchingPath::LeftWildcardRight(left_match_segments, right_match_segments) => {
                if left_match_segments.len() + right_match_segments.len() > segments.len() {
                    return false;
                }
                for (match_segment, segment) in left_match_segments.iter().zip(&segments) {
                    if !match_segment.is_match(segment) {
                        return false;
                    }
                }
                for (match_segment, segment) in
                    right_match_segments.iter().rev().zip(segments.iter().rev())
                {
                    if !match_segment.is_match(segment) {
                        return false;
                    }
                }
                return true;
            }
            MatchingPath::LeftWildcard(left_match_segments) => {
                if left_match_segments.len() > segments.len() {
                    return false;
                }
                for (match_segment, segment) in left_match_segments.iter().zip(&segments) {
                    if !match_segment.is_match(segment) {
                        return false;
                    }
                }
                return true;
            }
            MatchingPath::WildcardRight(right_match_segments) => {
                if right_match_segments.len() > segments.len() {
                    return false;
                }
                for (match_segment, segment) in
                    right_match_segments.iter().rev().zip(segments.iter().rev())
                {
                    if !match_segment.is_match(segment) {
                        return false;
                    }
                }
                return true;
            }
            _ => return false,
        }
    }
}

#[derive(Debug)]
struct ResolvedRule {
    filter: ResolvedFilter,
    action: ResolvedRuleAction,
}

impl ResolvedRule {
    fn get_action(&self, url: &Url) -> Option<&ResolvedRuleAction> {
        if !self.filter.is_matches(url) {
            return None;
        } else {
            info!("{} matches {:?} action {:?}", url, self.filter, self.action);
        }

        Some(&self.action)
    }
}

struct ResolvedHandler {
    config_name: Option<ConfigName>,

    resolved_variant: ResolvedHandlerVariant,

    base_path: Vec<UrlPathSegmentOrQueryPart>,
    replace_base_path: Vec<UrlPathSegmentOrQueryPart>,
    priority: u16,
    handler_catch: ResolvedCatchActions,
    name: HandlerName,

    mount_point_catch: ResolvedCatchActions,
    project_catch: ResolvedCatchActions,

    resolved_rules: Vec<ResolvedRule>,
}

impl ResolvedHandler {
    /// Handle exception in the right order
    fn handle_exception(
        &self,
        exception_name: &ExceptionName,
        exception_data: &HashMap<SmolStr, SmolStr>,
        maybe_rule_invoke_catch: Option<&ResolvedCatchActions>,
    ) -> ExceptionHandleResult {
        let maybe_resolved_exception = maybe_rule_invoke_catch
            .and_then(|r| r.handle_exception(exception_name))
            .or_else(|| self.handler_catch.handle_exception(exception_name))
            .or_else(|| self.mount_point_catch.handle_exception(exception_name))
            .or_else(|| self.project_catch.handle_exception(exception_name));

        match maybe_resolved_exception {
            None => ExceptionHandleResult::UnhandledException {
                exception_name: exception_name.clone(),
                data: exception_data.clone(),
            },
            Some(ResolvedCatchAction::Throw {
                exception_name,
                data,
            }) => ExceptionHandleResult::UnhandledException {
                exception_name: exception_name.clone(),
                data: data.clone(),
            },
            Some(ResolvedCatchAction::StaticResponse { static_response }) => {
                ExceptionHandleResult::StaticResponse {
                    static_response: static_response.clone(),
                }
            }
            Some(ResolvedCatchAction::NextHandler) => ExceptionHandleResult::NextHandler,
        }
    }

    /// Find appropriate final action, which should be executed
    fn find_action(&self, url: &Url) -> Option<&ResolvedRuleAction> {
        self.resolved_rules
            .iter()
            .filter_map(|resolved_rule| resolved_rule.get_action(url))
            // TODO: apply modifications
            .filter(|maybe_resolved_action| maybe_resolved_action.is_finalizing())
            .next()
    }

    // Handle whole request
    async fn handle_request(
        &self,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        requested_url: &Url,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
    ) -> Option<()> {
        let mut url: Url = req.uri().to_string().parse().unwrap();

        let action = self.find_action(&url)?;

        match action {
            ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Invoke { catch }) => {
                let invocation_result = self
                    .resolved_variant
                    .invoke(req, res, requested_url, local_addr, remote_addr)
                    .await;

                info!("invocation_result = {:?}", invocation_result);

                match invocation_result {
                    HandlerInvocationResult::Responded => {
                        // TODO: handle status-code catch block!
                        return Some(());
                    }
                    HandlerInvocationResult::ToNextHandler => {
                        return None;
                    }
                    HandlerInvocationResult::Exception { name, data } => {
                        let handle_exception = self.handle_exception(&name, &data, Some(catch));
                        error!("handle_exception = {:?}", handle_exception);
                    }
                }
            }
            ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::NextHandler) => {
                return None
            }
            ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Throw {
                exception,
                data,
            }) => {
                self.handle_exception(exception, data, None);
            }
            ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Respond {
                static_response,
            }) => static_response.invoke(req, res),
            ResolvedRuleAction::None => {
                unreachable!("None action should never be called for execution")
            }
        }

        None
    }
}

impl ResolvedCatchActions {
    fn handle_exception(&self, name: &ExceptionName) -> Option<&ResolvedCatchAction> {
        if let Some(catch) = self.exceptions.get(name) {
            return Some(catch);
        }
        if let Some(unhandled_catch) = &self.unhandled_exception {
            return Some(unhandled_catch);
        }
        None
    }
}

#[derive(Debug)]
enum ExceptionHandleResult {
    StaticResponse {
        static_response: ResolvedStaticResponse,
    },
    NextHandler,
    UnhandledException {
        exception_name: ExceptionName,
        data: HashMap<SmolStr, SmolStr>,
    },
}

struct ResolvedMountPoint {
    handlers: Vec<ResolvedHandler>,
}

fn resolve_static_response(
    static_response_name: &StaticResponseName,
    status_code: &Option<exogress_config_core::StatusCode>,
    data: &BTreeMap<SmolStr, SmolStr>,
    static_responses: &HashMap<StaticResponseName, StaticResponse>,
) -> Option<ResolvedStaticResponse> {
    let static_response: StaticResponse = static_responses.get(&static_response_name)?.clone();

    let static_response_status_code = match &static_response {
        StaticResponse::Redirect(redirect) => redirect.redirect_type.status_code(),
        StaticResponse::Raw(raw) => raw.status_code,
    };

    let resolved = ResolvedStaticResponse {
        status_code: status_code
            .as_ref()
            .map(|s| s.0)
            .unwrap_or(static_response_status_code),
        body: match &static_response {
            StaticResponse::Raw(raw) => (&raw.body).clone(),
            StaticResponse::Redirect(_) => {
                vec![]
            }
        },
        headers: match &static_response {
            StaticResponse::Raw(raw) => raw.common.headers.clone(),
            StaticResponse::Redirect(redirect) => {
                let mut headers = redirect.common.headers.clone();
                headers.insert(
                    "Location",
                    redirect.destination.as_str().parse().expect("bad URL"),
                );
                headers
            }
        },
        data: data
            .iter()
            .map(|(k, v)| (k.as_str().into(), v.as_str().into()))
            .collect(),
    };

    Some(resolved)
}

fn resolve_cache_action(
    catch_action: &CatchAction,
    static_responses: &HashMap<StaticResponseName, StaticResponse>,
) -> Option<ResolvedCatchAction> {
    Some(match catch_action {
        CatchAction::StaticResponse {
            static_response_name,
            status_code,
            data,
        } => ResolvedCatchAction::StaticResponse {
            static_response: resolve_static_response(
                static_response_name,
                status_code,
                data,
                static_responses,
            )?,
        },
        CatchAction::Throw {
            exception_name,
            data,
        } => ResolvedCatchAction::Throw {
            exception_name: exception_name.clone(),
            data: data.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        },
        CatchAction::NextHandler => ResolvedCatchAction::NextHandler,
    })
}

fn resolve_catch_actions(
    catch_actions: &CatchActions,
    static_responses: &HashMap<StaticResponseName, StaticResponse>,
) -> Option<ResolvedCatchActions> {
    Some(ResolvedCatchActions {
        exceptions: catch_actions
            .exceptions
            .iter()
            .map(|(exception_name, catch_action)| {
                let resolved_action = resolve_cache_action(catch_action, &static_responses)?;

                Some((exception_name.clone(), resolved_action))
            })
            .into_iter()
            .collect::<Option<HashMap<ExceptionName, ResolvedCatchAction>>>()?,
        unhandled_exception: catch_actions
            .unhandled_exception
            .as_ref()
            .and_then(|r| resolve_cache_action(r, &static_responses)),
        status_codes: catch_actions
            .status_codes
            .iter()
            .map(|range_handler| {
                Some(ResolvedStatusCodeRangeHandler {
                    status_codes_range: range_handler.status_codes_range.clone(),
                    catch: resolve_cache_action(&range_handler.catch, &static_responses)?,
                })
            })
            .collect::<Option<_>>()?,
    })
}
impl RequestsProcessor {
    pub fn new(
        resp: ConfigsResponse,
        google_oauth2_client: auth::google::GoogleOauth2Client,
        github_oauth2_client: auth::github::GithubOauth2Client,
        assistant_base_url: Url,
        public_gw_base_url: &Url,
        client_tunnels: ClientTunnels,
        individual_hostname: SmolStr,
        maybe_identity: Option<Vec<u8>>,
    ) -> Result<RequestsProcessor, ()> {
        let grouped = resp.configs.iter().group_by(|item| &item.config_name);

        let project_catch = resp.project_config.catch;
        let jwt_ecdsa = JwtEcdsa {
            private_key: resp.jwt_ecdsa.private_key.into(),
            public_key: resp.jwt_ecdsa.public_key.into(),
        };

        let mount_point_base_url = resp.url_prefix;
        let account_unique_id = resp.account_unique_id;
        let account_name = resp.account;
        let project_name = resp.project;

        let project_mount_points = resp
            .project_config
            .mount_points
            .into_iter()
            .map(|(k, v)| (k, (None, None, None, v.into())));

        // static responses are shared accross different config names
        let mut static_responses = HashMap::new();

        let grouped_mount_points = grouped
            .into_iter()
            .map(move |(config_name, configs)| {
                let entry: &ConfigData = &configs
                    .into_iter()
                    .map(|entry| (entry.instance_ids.len(), entry))
                    .sorted_by(|(left, _), (right, _)| left.cmp(&right).reverse())
                    .into_iter()
                    .next() //keep only revision with largest number of instances
                    .unwrap()
                    .1;

                let config = &entry.config;
                let instance_ids: &SmallVec<[InstanceId; 4]> = &entry.instance_ids;

                let upstreams = &config.upstreams;

                config
                    .mount_points
                    .clone()
                    .into_iter()
                    .map(move |(mp_name, mp)| {
                        (
                            mp_name,
                            (
                                Some(config_name.clone()),
                                Some(upstreams.clone()),
                                Some(instance_ids.clone()),
                                mp,
                            ),
                        )
                    })
            })
            .flatten()
            .chain(project_mount_points)
            .group_by(|a| a.0.clone())
            .into_iter()
            .map(|a| a.1)
            .flatten()
            .collect::<Vec<_>>();

        for (_, (_, _, _, mp)) in &grouped_mount_points {
            for (name, static_response) in &mp.static_responses {
                static_responses.insert(name.clone(), static_response.clone());
            }
        }

        let mut merged_resolved_handlers = vec![];

        for (_, (config_name, upstreams, instance_ids, mp)) in grouped_mount_points.into_iter() {
            let mp_catch = mp.catch.clone();

            shadow_clone!(instance_ids);
            shadow_clone!(project_catch);
            shadow_clone!(static_responses);
            shadow_clone!(jwt_ecdsa);
            shadow_clone!(mount_point_base_url);
            shadow_clone!(google_oauth2_client);
            shadow_clone!(github_oauth2_client);
            shadow_clone!(assistant_base_url);
            shadow_clone!(maybe_identity);
            shadow_clone!(client_tunnels);
            shadow_clone!(individual_hostname);
            shadow_clone!(account_name);
            shadow_clone!(account_unique_id);
            shadow_clone!(project_name);

            let mut r = mp.handlers
                .into_iter()
                .map(move |(handler_name, handler)| {
                    let replace_base_path = handler.replace_base_path.clone();

                    Some(ResolvedHandler {
                        config_name: config_name.clone(),

                        resolved_variant: match handler.variant {
                            ClientHandlerVariant::Auth(auth) => {
                                ResolvedHandlerVariant::Auth(ResolvedAuth {
                                    config: auth,
                                    handler_name: handler_name.clone(),
                                    mount_point_base_url: mount_point_base_url.clone(),
                                    jwt_ecdsa: jwt_ecdsa.clone(),
                                    google_oauth2_client: google_oauth2_client.clone(),
                                    github_oauth2_client: github_oauth2_client.clone(),
                                    assistant_base_url: assistant_base_url.clone(),
                                    maybe_identity: maybe_identity.clone(),
                                })
                            }
                            ClientHandlerVariant::StaticDir(static_dir) => {
                                ResolvedHandlerVariant::StaticDir(ResolvedStaticDir {
                                    config: static_dir,
                                    handler_name: handler_name.clone(),
                                    instance_ids: {
                                        let mut balancer = SmoothWeight::<InstanceId>::new();
                                        let instance_ids = instance_ids
                                            .as_ref()
                                            .expect("[BUG] try to access instance_ids on project-level config")
                                            .iter();
                                        for instance_id in instance_ids {
                                            balancer.add(instance_id.clone(), 1);
                                        }

                                        Mutex::new(balancer)
                                    },
                                    client_tunnels: client_tunnels.clone(),
                                    config_id: ConfigId {
                                        account_name: account_name.clone(),
                                        account_unique_id: account_unique_id.clone(),
                                        project_name: project_name.clone(),
                                        config_name: config_name.as_ref().expect("[BUG] try to access config_name on project-level config").clone(),
                                    },
                                    individual_hostname: individual_hostname.clone(),
                                    public_hostname: mount_point_base_url.host().into(),
                                })
                            }
                            ClientHandlerVariant::Proxy(proxy) => {
                                ResolvedHandlerVariant::Proxy(ResolvedProxy {
                                    name: proxy.upstream.clone(),
                                    upstream: upstreams
                                        .as_ref()
                                        .expect(
                                            "[BUG]: try to access upstream for project-level config",
                                        )
                                        .get(&proxy.upstream)
                                        .cloned()?,
                                    instance_ids: {
                                        let mut balancer = SmoothWeight::<InstanceId>::new();
                                        let instance_ids = instance_ids
                                            .as_ref()
                                            .expect("[BUG] try to access instance_ids on project-level config")
                                            .iter();
                                        for instance_id in instance_ids {
                                            balancer.add(instance_id.clone(), 1);
                                        }

                                        Mutex::new(balancer)
                                    },
                                    client_tunnels: client_tunnels.clone(),
                                    config_id: ConfigId {
                                        account_name: account_name.clone(),
                                        account_unique_id: account_unique_id.clone(),
                                        project_name: project_name.clone(),
                                        config_name: config_name.as_ref().expect("[BUG] try to access config_name on project-level config").clone(),
                                    },
                                    individual_hostname: individual_hostname.clone(),
                                    public_hostname: mount_point_base_url.host().into(),
                                })
                            }
                        },
                        priority: handler.priority,
                        handler_catch: resolve_catch_actions(
                            &handler.catch.actions,
                            &static_responses,
                        )?,
                        name: handler_name,
                        mount_point_catch: resolve_catch_actions(
                            &mp_catch.actions,
                            &static_responses,
                        )?,
                        project_catch: resolve_catch_actions(
                            &project_catch.actions,
                            &static_responses,
                        )?,
                        resolved_rules: handler
                            .rules
                            .into_iter()
                            .map(|rule| {
                                    Some(ResolvedRule {
                                        filter: ResolvedFilter {
                                            path: rule.filter.path,
                                            base_path: replace_base_path.clone(),
                                        },
                                        action: match rule.action {
                                            Action::Invoke { catch } => ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Invoke {
                                                catch: resolve_catch_actions(
                                                    &catch.actions,
                                                    &static_responses,
                                                )?,
                                            }),
                                            Action::NextHandler => ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::NextHandler),
                                            Action::None => ResolvedRuleAction::None,
                                            Action::Throw { exception, data } => ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Throw {
                                                exception,
                                                data: data.iter().map(|(k,v)| (k.as_str().into(), v.as_str().into())).collect(),
                                            }),
                                            Action::Respond {
                                                static_response_name,
                                                status_code,
                                                data,
                                            } => ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Respond {
                                                static_response: resolve_static_response(
                                                    &static_response_name,
                                                    &status_code,
                                                    &data,
                                                    &static_responses,
                                                )?,
                                            }),
                                        },
                                    })
                                })
                            .collect::<Option<_>>()?,
                        base_path: handler.base_path,
                        replace_base_path: handler.replace_base_path,
                    })
                })
                .collect::<Option<Vec<_>>>()
                .ok_or(())?;

            merged_resolved_handlers.append(&mut r);
        }

        merged_resolved_handlers.sort_by(|left, right| left.priority.cmp(&right.priority));

        Ok(RequestsProcessor {
            ordered_handlers: merged_resolved_handlers,
            generated_at: resp.generated_at,
            google_oauth2_client,
            github_oauth2_client,
            assistant_base_url,
            maybe_identity,
            public_gw_base_url: public_gw_base_url.clone(),
        })
    }
}

#[derive(Clone, Debug)]
struct ResolvedStaticResponse {
    status_code: StatusCode,
    body: Vec<ResponseBody>,
    headers: HeaderMap,
    data: HashMap<SmolStr, SmolStr>,
}

impl ResolvedStaticResponse {
    fn invoke(&self, req: &Request<Body>, res: &mut Response<Body>) {
        for (k, v) in &self.headers {
            res.headers_mut().append(k, v.clone());
        }

        *res.status_mut() = self.status_code.clone();

        if self.body.is_empty() {
            // no body defined, just respond with the status code
            return;
        }

        let accept = req
            .headers()
            .typed_get::<Accept>()
            .expect("FIXME")
            .expect("FIXME");

        let best_content_type = ordered_by_quality(&accept)
            .filter_map(|mime_pattern| {
                self.body
                    .iter()
                    .filter_map(|resp_candidate| {
                        Some((
                            resp_candidate.content_type.as_str().parse().ok()?,
                            resp_candidate,
                        ))
                    })
                    .find(|(content_type, _resp_candidate)| {
                        is_mime_match(mime_pattern, &content_type)
                    })
            })
            .next();

        match best_content_type {
            Some((resp_content_type, resp)) => {
                res.headers_mut()
                    .typed_insert::<ContentType>(&ContentType(resp_content_type.clone()));
                let body = match &resp.engine {
                    None => resp.content.to_string(),

                    Some(TemplateEngine::Handlebars) => {
                        let handlebars = Handlebars::new();
                        let data = hashmap! {
                            "time" => Utc::now()
                        };
                        // TODO: add data bash-map
                        handlebars
                            .render_template(&resp.content, &data)
                            .expect("FIXME")
                    }
                };
                *res.body_mut() = Body::from(body);
            }
            None => {
                *res.status_mut() = StatusCode::NOT_ACCEPTABLE;
            }
        }
    }
}

#[derive(Debug)]
struct ResolvedCatchActions {
    exceptions: HashMap<ExceptionName, ResolvedCatchAction>,
    unhandled_exception: Option<ResolvedCatchAction>,
    status_codes: Vec<ResolvedStatusCodeRangeHandler>,
}

#[derive(Debug)]
struct ResolvedStatusCodeRangeHandler {
    status_codes_range: StatusCodeRange,
    catch: ResolvedCatchAction,
}

#[cfg(test)]
mod test {
    use super::*;

    //     #[test]
    //     fn test_parsing_config_response_no_instances() {
    //         const JSON: &str = r#"{
    //   "generated_at": 1606467323711,
    //   "account": "gleb",
    //   "account_unique_id": "01ENZAGRCYQ5WEVB0DT890RXTK",
    //   "project": "home",
    //   "project_config": {
    //     "version": "1.0.0",
    //     "mount-points": {
    //       "backend": {
    //         "handlers": {
    //           "authorize": {
    //             "type": "auth",
    //             "providers": [
    //               {
    //                 "name": "github",
    //                 "acl": [
    //                   {
    //                     "allow": "user"
    //                   }
    //                 ]
    //               }
    //             ],
    //             "priority": 1
    //           }
    //         }
    //       }
    //     }
    //   },
    //   "configs": [],
    //   "url_prefix": "local.sexg.link/",
    //   "mount_point": "backend",
    //   "jwt_ecdsa": {
    //     "private_key": "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgf8NRJLvkKcASfP74\nWGvgwENSH8Uf8wOyVcpJHSPvwTOhRANCAASoP0aITZ7/1VqE70muWc0AWE9y7OXl\n42wDOcGqx0kqJQL7CB3Rqb0piojbg99Ea9WD7s37a9De9FkfsdHMd3LL\n-----END PRIVATE KEY-----\n",
    //     "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqD9GiE2e/9VahO9JrlnNAFhPcuzl\n5eNsAznBqsdJKiUC+wgd0am9KYqI24PfRGvVg+7N+2vQ3vRZH7HRzHdyyw==\n-----END PUBLIC KEY-----\n"
    //   }
    // }
    // "#;
    //         let configs_response: ConfigsResponse = serde_json::from_str(JSON).unwrap();
    //         let _ = MountPointConfig::new(configs_response).unwrap();
    //     }
    //
    //     #[test]
    //     fn test_parsing_config() {
    //         const JSON: &str = r#"{
    //   "generated_at": 1606469115249,
    //   "account": "gleb",
    //   "account_unique_id": "01ENZAGRCYQ5WEVB0DT890RXTK",
    //   "project": "home",
    //   "project_config": {
    //     "version": "1.0.0",
    //     "mount-points": {
    //       "backend": {
    //         "handlers": {
    //           "authorize": {
    //             "type": "auth",
    //             "providers": [
    //               {
    //                 "name": "github",
    //                 "acl": [
    //                   {
    //                     "allow": "user"
    //                   }
    //                 ]
    //               }
    //             ],
    //             "priority": 1
    //           }
    //         }
    //       }
    //     }
    //   },
    //   "configs": [
    //     {
    //       "config": {
    //         "version": "1.0.0",
    //         "revision": 1,
    //         "name": "config1",
    //         "mount-points": {
    //           "backend": {
    //             "handlers": {
    //               "my-target": {
    //                 "type": "proxy",
    //                 "upstream": "my-upstream",
    //                 "base-path": [],
    //                 "replace-base-path": [],
    //                 "priority": 10
    //               }
    //             },
    //             "static-responses": {
    //               "bad-gateway": {
    //                 "kind": "raw",
    //                 "status-code": 200,
    //                 "body": [
    //                   {
    //                     "content-type": "text/html",
    //                     "content": "<html>\n  <body>\n    Not found at {{ this.time }}\n  </body>\n</html>\n",
    //                     "engine": "handlebars"
    //                   },
    //                   {
    //                     "content-type": "application/json",
    //                     "content": "{\"status\": \"not-found\"}\n",
    //                     "engine": null
    //                   }
    //                 ],
    //                 "headers": {
    //                   "x-error-detected": "1"
    //                 }
    //               },
    //               "redirect-to-google1": {
    //                 "kind": "redirect",
    //                 "redirect-type": "see-other",
    //                 "destination": "https://google.com/",
    //                 "headers": {
    //                   "x-my-header": "true"
    //                 }
    //               },
    //               "redirect-to-google2": {
    //                 "kind": "raw",
    //                 "status-code": 307,
    //                 "body": [],
    //                 "headers": {
    //                   "location": "https://google.com"
    //                 }
    //               },
    //               "static": {
    //                 "kind": "raw",
    //                 "status-code": 200,
    //                 "body": [
    //                   {
    //                     "content-type": "text/html",
    //                     "content": "<html>\n  <body>\n    Static {{ this.time }}\n  </body>\n</html>\n",
    //                     "engine": "handlebars"
    //                   },
    //                   {
    //                     "content-type": "application/json",
    //                     "content": "{\"status\": \"static\"}\n",
    //                     "engine": null
    //                   }
    //                 ],
    //                 "headers": {
    //                   "x-static": "true"
    //                 }
    //               }
    //             }
    //           }
    //         },
    //         "upstreams": {
    //           "my-upstream": {
    //             "port": 2368,
    //             "host": "127.0.0.1"
    //           }
    //         }
    //       },
    //       "config_name": "config1",
    //       "instance_ids": [
    //         "01ER4GAMQXFVSP87KMGANKNE26"
    //       ],
    //       "revision": 1
    //     }
    //   ],
    //   "url_prefix": "local.sexg.link/",
    //   "mount_point": "backend",
    //   "jwt_ecdsa": {
    //     "private_key": "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgf8NRJLvkKcASfP74\nWGvgwENSH8Uf8wOyVcpJHSPvwTOhRANCAASoP0aITZ7/1VqE70muWc0AWE9y7OXl\n42wDOcGqx0kqJQL7CB3Rqb0piojbg99Ea9WD7s37a9De9FkfsdHMd3LL\n-----END PRIVATE KEY-----\n",
    //     "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqD9GiE2e/9VahO9JrlnNAFhPcuzl\n5eNsAznBqsdJKiUC+wgd0am9KYqI24PfRGvVg+7N+2vQ3vRZH7HRzHdyyw==\n-----END PUBLIC KEY-----\n"
    //   }
    // }
    // "#;
    //         let configs_response: ConfigsResponse = serde_json::from_str(JSON).unwrap();
    //         let _ = MountPointConfig::new(configs_response).unwrap();
    //     }
    //
    #[test]
    fn test_revisions_filtering() {
        const JSON: &str = r#"{
  "generated_at": 1606490346283,
  "account": "account-name",
  "account_unique_id": "01ENZAGRCYQ5WEVB0DT890RXTK",
  "project": "my-prj",
  "project_config": {
    "version": "1.0.0",
    "mount-points": {
      "backend": {
        "handlers": {
          "authorize": {
            "type": "auth",
            "providers": [
              {
                "name": "github",
                "acl": [
                  {
                    "allow": "username"
                  }
                ]
              }
            ],
            "priority": 1
          }
        }
      }
    }
  },
  "configs": [
    {
      "config": {
        "version": "1.0.0",
        "revision": 1,
        "name": "config1",
        "mount-points": {
          "backend": {
            "handlers": {
              "my-target": {
                "type": "proxy",
                "upstream": "my-upstream",
                "priority": 10
              }
            }
          }
        },
        "upstreams": {
          "my-upstream": {
            "port": 2368,
            "host": "127.0.0.1"
          }
        }
      },
      "config_name": "config1",
      "instance_ids": [
        "01ER54CWZD747V2369RD36Y9MF"
      ],
      "revision": 1
    },
    {
      "config": {
        "version": "1.0.0",
        "revision": 2,
        "name": "config1",
        "mount-points": {
          "backend": {
            "handlers": {
              "my-target": {
                "type": "proxy",
                "upstream": "my-upstream",
                "priority": 20
              }
            }
          }
        },
        "upstreams": {
          "my-upstream": {
            "port": 2368,
            "host": "127.0.0.1"
          }
        }
      },
      "config_name": "config1",
      "instance_ids": [
        "01ER54J5N5VHV99AZETBFCSB5P", "01ER55M7DCGC4K0M533ASKG0E1"
      ],
      "revision": 2
    }
  ],
  "url_prefix": "local.sexg.link/",
  "mount_point": "backend",
  "jwt_ecdsa": {
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgf8NRJLvkKcASfP74\nWGvgwENSH8Uf8wOyVcpJHSPvwTOhRANCAASoP0aITZ7/1VqE70muWc0AWE9y7OXl\n42wDOcGqx0kqJQL7CB3Rqb0piojbg99Ea9WD7s37a9De9FkfsdHMd3LL\n-----END PRIVATE KEY-----\n",
    "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqD9GiE2e/9VahO9JrlnNAFhPcuzl\n5eNsAznBqsdJKiUC+wgd0am9KYqI24PfRGvVg+7N+2vQ3vRZH7HRzHdyyw==\n-----END PUBLIC KEY-----\n"
  }
}"#;
        let configs_response: ConfigsResponse = serde_json::from_str(JSON).unwrap();
        let _ = RequestsProcessor::new(configs_response).unwrap();
    }
}
