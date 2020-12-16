use crate::clients::ClientTunnels;
use crate::http_serve::auth;
use crate::http_serve::auth::github::GithubOauth2Client;
use crate::http_serve::auth::google::GoogleOauth2Client;
use crate::http_serve::auth::{retrieve_assistant_key, AuthFinalizer, JwtEcdsa, Oauth2Provider};
use crate::http_serve::templates::respond_with_login;
use crate::mime_helpers::{is_mime_match, ordered_by_quality};
use crate::rules_counter::AccountRulesCounters;
use crate::webapp::{ConfigData, ConfigsResponse};
use anyhow::Context;
use chrono::{DateTime, Utc};
use cookie::Cookie;
use core::{fmt, mem};
use exogress_common::config_core::{
    AclEntry, Action, Auth, AuthProvider, CatchAction, CatchMatcher, ClientHandlerVariant,
    Exception, MatchingPath, RescueItem, ResponseBody, StaticDir, StaticResponse, StatusCodeRange,
    TemplateEngine, UpstreamDefinition, UrlPathSegmentOrQueryPart,
};
use exogress_common::entities::{
    AccountUniqueId, ConfigId, HandlerName, InstanceId, MountPointName, StaticResponseName,
    Upstream,
};
use exogress_common::tunnel::ConnectTarget;
use exogress_server_common::url_prefix::MountPointBaseUrl;
use futures::TryStreamExt;
use globset::Glob;
use handlebars::Handlebars;
use hashbrown::{HashMap, HashSet};
use http::header::{
    ACCEPT_ENCODING, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST,
    LOCATION, SET_COOKIE,
};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use hyper::Body;
use itertools::Itertools;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use magick_rust::{magick_wand_genesis, MagickWand};
use parking_lot::Mutex;
use smol_str::SmolStr;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::{Arc, Once};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task;
use tokio_either::Either;
use typed_headers::{Accept, ContentCoding, ContentType, HeaderMapExt};
use url::Url;
use weighted_rs::{SmoothWeight, Weight};

static IMAGE_MAGIC: Once = Once::new();

pub struct RequestsProcessor {
    ordered_handlers: Vec<ResolvedHandler>,
    pub generated_at: DateTime<Utc>,
    // pub health: HealthStorage,
    pub google_oauth2_client: auth::google::GoogleOauth2Client,
    pub github_oauth2_client: auth::github::GithubOauth2Client,
    pub assistant_base_url: Url,
    pub maybe_identity: Option<Vec<u8>>,
    rules_counter: AccountRulesCounters,
    account_unique_id: AccountUniqueId,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    idp: String,
    exp: usize,
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
        self.rules_counter.register_request(&self.account_unique_id);
        let mut is_processed = false;
        for handler in &self.ordered_handlers {
            // create new response for each handler, avoid using dirty data from the previous handler
            *res = Response::new(Body::empty());

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

            let result = handler
                .handle_request(
                    req,
                    res,
                    requested_url,
                    &replaced_url,
                    local_addr,
                    remote_addr,
                )
                .await;

            match result {
                ResolvedHandlerProcessingResult::Processed => {
                    info!("handle successfully finished. exit from handlers loop");
                    is_processed = true;
                    break;
                }
                ResolvedHandlerProcessingResult::FiltersNotMatched => {}
                ResolvedHandlerProcessingResult::NextHandler => {}
            };
        }

        if !is_processed {
            *res = Response::new(Body::from("Not found"));
            *res.status_mut() = StatusCode::NOT_FOUND;
        }

        let optimize_result = self.optimize_image(req, res).await;
        if let Err(e) = optimize_result {
            warn!("Skipped image optimization due to the error: {}", e);
        }

        self.compress(req, res);

        res.headers_mut()
            .insert("server", HeaderValue::from_static("exogress"));
    }

    async fn optimize_image(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
    ) -> Result<(), anyhow::Error> {
        // return Ok(());
        let is_webp_supported = req
            .headers()
            .typed_get::<typed_headers::Accept>()?
            .ok_or_else(|| anyhow!("no accept header"))?
            .iter()
            .find(|&item| item.item == mime::Mime::from_str("image/webp").unwrap())
            .is_some();
        if !is_webp_supported {
            return Ok(());
        }
        let content_type: mime::Mime = res
            .headers()
            .get(CONTENT_TYPE)
            .ok_or_else(|| anyhow!("no content-type"))?
            .to_str()?
            .parse()?;
        if content_type == mime::IMAGE_JPEG || content_type == mime::IMAGE_PNG {
            IMAGE_MAGIC.call_once(|| {
                magick_wand_genesis();
            });

            let image_body = Arc::new(
                mem::replace(res.body_mut(), Body::empty())
                    .try_fold(Vec::new(), |mut data, chunk| async move {
                        data.extend_from_slice(&chunk);
                        Ok(data)
                    })
                    .await?,
            );

            let converted_image_result = task::spawn_blocking({
                shadow_clone!(image_body);

                move || {
                    let wand = MagickWand::new();
                    wand.read_image_blob(image_body.as_ref())
                        .map_err(|e| anyhow!("imagemagick read error: {}", e))?;
                    let converted_image = wand
                        .write_image_blob("webp")
                        .map_err(|e| anyhow!("imagemagick write error: {}", e))?;
                    Ok::<_, anyhow::Error>(converted_image)
                }
            })
            .await?;

            match converted_image_result {
                Ok(buf) => {
                    let buf_len = buf.len();
                    *res.body_mut() = Body::from(buf);
                    res.headers_mut().typed_insert::<ContentType>(&ContentType(
                        mime::Mime::from_str("image/webp").unwrap(),
                    ));
                    res.headers_mut()
                        .insert(CONTENT_LENGTH, HeaderValue::from(buf_len));
                }
                Err(e) => {
                    warn!("error converting image to WebP: {}", e);
                    assert_eq!(Arc::strong_count(&image_body), 1);
                    // restore original image body
                    *res.body_mut() = Body::from(Arc::try_unwrap(image_body).unwrap());
                }
            }

            Ok(())
        } else {
            Ok(())
        }
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

        let uncompressed_body = mem::replace(res.body_mut(), Body::empty())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()));

        res.headers_mut()
            .insert("vary", HeaderValue::from_str("Accept-Encoding").unwrap());
        let _ = res
            .headers_mut()
            .typed_remove::<typed_headers::ContentLength>();
        let processed_stream = match compression {
            SupportedContentEncoding::Brotli => {
                res.headers_mut()
                    .typed_insert(&typed_headers::ContentEncoding::from(
                        typed_headers::ContentCoding::BROTLI,
                    ));

                Either::Left(async_compression::stream::BrotliEncoder::with_quality(
                    uncompressed_body,
                    async_compression::Level::Precise(6),
                ))
            }
            SupportedContentEncoding::Gzip => {
                res.headers_mut()
                    .typed_insert(&typed_headers::ContentEncoding::from(
                        typed_headers::ContentCoding::GZIP,
                    ));

                Either::Right(Either::Left(async_compression::stream::GzipEncoder::new(
                    uncompressed_body,
                )))
            }
            SupportedContentEncoding::Deflate => {
                res.headers_mut()
                    .typed_insert(&typed_headers::ContentEncoding::from(
                        typed_headers::ContentCoding::DEFLATE,
                    ));

                Either::Right(Either::Right(
                    async_compression::stream::DeflateEncoder::new(uncompressed_body),
                ))
            }
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

impl fmt::Debug for ResolvedProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedProxy")
            .field("name", &self.name)
            .field("upstream", &self.upstream)
            .field("config_id", &self.config_id)
            .finish()
    }
}

fn copy_headers_from_proxy_res_to_res(
    proxy_res: &Response<Body>,
    res: &mut Response<Body>,
    is_upgrade_allowed: bool,
) {
    for (incoming_header_name, incoming_header_value) in proxy_res.headers() {
        if incoming_header_name == ACCEPT_ENCODING {
            continue;
        }

        if incoming_header_name == CONNECTION {
            if is_upgrade_allowed {
                if !incoming_header_value
                    .to_str()
                    .unwrap()
                    .to_lowercase()
                    .contains("upgrade")
                {
                    continue;
                }
            } else {
                continue;
            }
        }

        res.headers_mut()
            .append(incoming_header_name, incoming_header_value.clone());
    }
}

fn copy_headers_to_proxy_req(
    req: &Request<Body>,
    proxy_req: &mut Request<Body>,
    is_upgrade_allowed: bool,
) {
    for (incoming_header_name, incoming_header_value) in req.headers() {
        if incoming_header_name == ACCEPT_ENCODING || incoming_header_name == HOST {
            continue;
        }

        if incoming_header_name == CONNECTION {
            if is_upgrade_allowed {
                if !incoming_header_value
                    .to_str()
                    .unwrap()
                    .to_lowercase()
                    .contains("upgrade")
                {
                    continue;
                }
            } else {
                continue;
            }
        }

        proxy_req
            .headers_mut()
            .append(incoming_header_name, incoming_header_value.clone());
    }
}

fn add_forwarded_headers(
    req: &mut Request<Body>,
    local_addr: &SocketAddr,
    remote_addr: &SocketAddr,
    public_hostname: &str,
) {
    req.headers_mut()
        .append("x-forwarded-host", public_hostname.parse().unwrap());

    req.headers_mut()
        .append("x-forwarded-proto", "https".parse().unwrap());

    //X-Forwarded-Host and X-Forwarded-Proto
    let mut x_forwarded_for = req
        .headers_mut()
        .remove("x-forwarded-for")
        .map(|h| h.to_str().unwrap().to_string())
        .unwrap_or_else(|| remote_addr.ip().to_string());

    x_forwarded_for.push_str(&format!(", {}", local_addr.ip()));

    req.headers_mut()
        .insert("x-forwarded-for", x_forwarded_for.parse().unwrap());

    if !req.headers().contains_key("x-real-ip") {
        req.headers_mut()
            .append("x-real-ip", remote_addr.ip().to_string().parse().unwrap());
    }
}

impl ResolvedProxy {
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
                name: "proxy-error:loop-detected".parse().unwrap(),
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

        copy_headers_to_proxy_req(req, &mut proxy_req, true);

        add_forwarded_headers(
            &mut proxy_req,
            local_addr,
            remote_addr,
            &self.public_hostname,
        );

        proxy_req
            .headers_mut()
            .append("x-exg", "1".parse().unwrap());

        if req.method() != &Method::GET
            && req
                .headers()
                .get(CONNECTION)
                .map(|h| h.to_str().unwrap().to_lowercase())
                .map(|s| s.contains("upgrade"))
                != Some(true)
        {
            *proxy_req.body_mut() = mem::replace(req.body_mut(), Body::empty());
        }

        let selected_instance_id = Weight::next(&mut *self.instance_ids.lock());

        match selected_instance_id {
            Some(instance_id) => {
                let http_client = self
                    .client_tunnels
                    .retrieve_http_connector(
                        &self.config_id,
                        &instance_id,
                        self.individual_hostname.clone(),
                    )
                    .await
                    .expect("FIXME");

                let proxy_res = http_client.request(proxy_req).await.expect("FIXME");

                copy_headers_from_proxy_res_to_res(&proxy_res, res, true);

                res.headers_mut()
                    .append("x-exg-proxied", "1".parse().unwrap());

                *res.status_mut() = proxy_res.status();

                if res.status_mut() == &StatusCode::SWITCHING_PROTOCOLS {
                    let req_body = mem::replace(req.body_mut(), Body::empty());

                    tokio::spawn(
                        #[allow(unreachable_code)]
                        async move {
                            match proxy_res.into_body().on_upgrade().await {
                                Ok(mut proxy_upgraded) => {
                                    let mut req_upgraded =
                                        req_body.on_upgrade().await.expect("FIXME");

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
                                                    req_upgraded.flush().await.with_context(|| "error flushing data to cliet")?;
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
                                                    proxy_upgraded
                                                        .flush()
                                                        .await
                                                        .with_context(|| "error flushing data to proxy")?;
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
                        },
                    );
                } else {
                    *res.body_mut() = proxy_res.into_body();
                }

                HandlerInvocationResult::Responded
            }
            None => HandlerInvocationResult::Exception {
                name: "proxy-error:bad-gateway:no-healthy-upstreams"
                    .parse()
                    .unwrap(),
                data: Default::default(),
            },
        }
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

impl fmt::Debug for ResolvedStaticDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedStaticDir")
            .field("config", &self.config)
            .field("handler_name", &self.handler_name)
            .field("config_id", &self.config_id)
            .finish()
    }
}

impl ResolvedStaticDir {
    async fn invoke(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        requested_url: &Url,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
    ) -> HandlerInvocationResult {
        if req.headers().contains_key("x-exg-proxied") {
            return HandlerInvocationResult::Exception {
                name: "proxy-error:loop-detected".parse().unwrap(),
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

        copy_headers_to_proxy_req(req, &mut proxy_req, false);

        add_forwarded_headers(
            &mut proxy_req,
            local_addr,
            remote_addr,
            &self.public_hostname,
        );

        proxy_req
            .headers_mut()
            .append("x-exg", "1".parse().unwrap());

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

        let proxy_res = http_client.request(proxy_req).await.expect("FIXME");

        copy_headers_from_proxy_res_to_res(&proxy_res, res, false);

        res.headers_mut()
            .append("x-exg-proxied", "1".parse().unwrap());
        *res.status_mut() = proxy_res.status();
        *res.body_mut() = proxy_res.into_body();

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

#[derive(Debug)]
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
        name: Exception,
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
    Brotli,
    Gzip,
    Deflate,
}

impl SupportedContentEncoding {
    pub fn weight(&self) -> u8 {
        match self {
            SupportedContentEncoding::Brotli => 200,
            SupportedContentEncoding::Gzip => 150,
            SupportedContentEncoding::Deflate => 10,
        }
    }
}

impl<'a> TryFrom<&'a ContentCoding> for SupportedContentEncoding {
    type Error = ();

    fn try_from(value: &'a ContentCoding) -> Result<Self, Self::Error> {
        match value {
            &ContentCoding::BROTLI | &ContentCoding::STAR => Ok(SupportedContentEncoding::Brotli),
            &ContentCoding::GZIP => Ok(SupportedContentEncoding::Gzip),
            &ContentCoding::DEFLATE => Ok(SupportedContentEncoding::Deflate),
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
        rescue: Vec<ResolvedRescueItem>,
    },
    NextHandler,
    Throw {
        exception: Exception,
        data: HashMap<SmolStr, SmolStr>,
    },
    Respond {
        static_response: Option<ResolvedStaticResponse>,
        data: HashMap<SmolStr, SmolStr>,
        rescue: Vec<ResolvedRescueItem>,
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

#[derive(Debug, Clone)]
enum ResolvedCatchAction {
    StaticResponse {
        static_response: Option<ResolvedStaticResponse>,
        data: HashMap<SmolStr, SmolStr>,
    },
    Throw {
        exception: Exception,
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
    resolved_variant: ResolvedHandlerVariant,

    base_path: Vec<UrlPathSegmentOrQueryPart>,
    replace_base_path: Vec<UrlPathSegmentOrQueryPart>,
    priority: u16,
    handler_rescue: Vec<ResolvedRescueItem>,

    mount_point_rescue: Vec<ResolvedRescueItem>,
    config_rescue: Vec<ResolvedRescueItem>,
    project_rescue: Vec<ResolvedRescueItem>,

    resolved_rules: Vec<ResolvedRule>,

    account_unique_id: AccountUniqueId,
    rules_counter: AccountRulesCounters,
}

#[derive(Debug)]
enum Rescueable<'a> {
    Exception {
        exception: &'a Exception,
        data: &'a HashMap<SmolStr, SmolStr>,
    },
    StatusCode(StatusCode),
}

impl<'a> Rescueable<'a> {
    fn is_exception(&'a self) -> bool {
        match self {
            Rescueable::Exception { .. } => true,
            Rescueable::StatusCode(_) => false,
        }
    }

    fn data(&'a self) -> Option<&'a HashMap<SmolStr, SmolStr>> {
        match self {
            Rescueable::Exception { data, .. } => Some(data),
            Rescueable::StatusCode(_) => None,
        }
    }
}

#[must_use]
enum ResolvedHandlerProcessingResult {
    Processed,
    FiltersNotMatched,
    NextHandler,
}

impl ResolvedHandler {
    fn is_exception_matches(matcher: &Exception, exception: &Exception) -> bool {
        if matcher.0.len() > exception.0.len() {
            return false;
        }

        let zipped = matcher.0.iter().zip(exception.0.iter());

        for (matcher_segment, exception_segment) in zipped {
            if matcher_segment != exception_segment {
                return false;
            }
        }

        true
    }

    fn is_status_code_matches(matcher: &StatusCodeRange, status_code: &StatusCode) -> bool {
        match matcher {
            StatusCodeRange::Single(single) => single == status_code,
            StatusCodeRange::Range(from, to) => {
                (from.as_u16()..=to.as_u16()).contains(&status_code.as_u16())
            }
            StatusCodeRange::List(codes) => codes
                .iter()
                .find(|code| code.as_u16() == status_code.as_u16())
                .is_some(),
        }
    }

    fn find_exception_handler(
        rescue: &Vec<ResolvedRescueItem>,
        rescueable: &Rescueable<'_>,
    ) -> Option<ResolvedCatchAction> {
        for rescue_item in rescue.iter() {
            match (rescueable, &rescue_item.catch) {
                (
                    Rescueable::Exception { exception, .. },
                    ResolvedCatchMatcher::Exception(exception_matcher),
                ) if Self::is_exception_matches(exception_matcher, exception) => {
                    return Some(rescue_item.handle.clone())
                }
                (
                    Rescueable::StatusCode(status_code),
                    ResolvedCatchMatcher::StatusCode(status_code_rande),
                ) if Self::is_status_code_matches(status_code_rande, status_code) => {
                    return Some(rescue_item.handle.clone())
                }
                _ => {}
            }
        }

        None
    }

    /// Handle exception in the right order
    fn handle_rescueable(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        rescueable: &Rescueable<'_>,
        is_in_exception: bool,
        maybe_rule_invoke_catch: Option<&Vec<ResolvedRescueItem>>,
    ) -> ResolvedHandlerProcessingResult {
        info!("handle rescueable: {:?}", rescueable);

        let maybe_resolved_exception = maybe_rule_invoke_catch
            .and_then(|r| Self::find_exception_handler(r, &rescueable))
            .or_else(|| Self::find_exception_handler(&self.handler_rescue, &rescueable))
            .or_else(|| Self::find_exception_handler(&self.mount_point_rescue, &rescueable))
            .or_else(|| Self::find_exception_handler(&self.config_rescue, &rescueable))
            .or_else(|| Self::find_exception_handler(&self.project_rescue, &rescueable));

        let result = match maybe_resolved_exception {
            None => match rescueable {
                &Rescueable::Exception { exception, data } => {
                    RescueableHandleResult::UnhandledException {
                        exception_name: exception.clone(),
                        data: data.clone(),
                    }
                }
                Rescueable::StatusCode(_) => RescueableHandleResult::FinishProcessing,
            },
            Some(ResolvedCatchAction::Throw { exception, data }) => match rescueable {
                &Rescueable::Exception { .. } => RescueableHandleResult::UnhandledException {
                    exception_name: exception.clone(),
                    data: data.clone(),
                },
                Rescueable::StatusCode(_) => RescueableHandleResult::FinishProcessing,
            },
            Some(ResolvedCatchAction::StaticResponse {
                static_response,
                data,
            }) => RescueableHandleResult::StaticResponse {
                static_response: static_response.clone(),
                data: data.clone(),
            },
            Some(ResolvedCatchAction::NextHandler) => RescueableHandleResult::NextHandler,
        };

        match result {
            RescueableHandleResult::StaticResponse {
                static_response,
                mut data,
            } => {
                if let Some(additional_data) = rescueable.data() {
                    data.extend(additional_data.iter().map(|(k, v)| (k.clone(), v.clone())));
                }
                return self.handle_static_response(
                    req,
                    res,
                    &static_response,
                    data,
                    rescueable.is_exception() || is_in_exception,
                    maybe_rule_invoke_catch,
                );
            }
            RescueableHandleResult::NextHandler => {
                info!("move on to next handler");
                return ResolvedHandlerProcessingResult::NextHandler;
            }
            RescueableHandleResult::UnhandledException { exception_name, .. } => {
                warn!("unhandled exception: {}", exception_name);
                self.respond_server_error(res);
                return ResolvedHandlerProcessingResult::Processed;
            }
            RescueableHandleResult::FinishProcessing => {
                info!("processing finished");
                return ResolvedHandlerProcessingResult::Processed;
            }
        }
    }

    /// Find appropriate final action, which should be executed
    fn find_action(&self, url: &Url) -> Option<&ResolvedRuleAction> {
        self.resolved_rules
            .iter()
            .filter_map(|resolved_rule| resolved_rule.get_action(url))
            .inspect(|_| {
                self.rules_counter.register_rule(&self.account_unique_id);
            })
            // TODO: apply modifications
            .filter(|maybe_resolved_action| maybe_resolved_action.is_finalizing())
            .next()
    }

    fn respond_server_error(&self, res: &mut Response<Body>) {
        *res = Response::new(Body::from("Internal server error"));
        *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    }

    // Handle whole request
    async fn handle_request(
        &self,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        _requested_url: &Url,
        replaced_url: &Url,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
    ) -> ResolvedHandlerProcessingResult {
        let action = match self.find_action(replaced_url) {
            None => return ResolvedHandlerProcessingResult::FiltersNotMatched,
            Some(action) => action,
        };
        match action {
            ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Invoke {
                rescue: catch,
            }) => {
                let invocation_result = self
                    .resolved_variant
                    .invoke(req, res, replaced_url, local_addr, remote_addr)
                    .await;

                match invocation_result {
                    HandlerInvocationResult::Responded => {
                        let rescueable = Rescueable::StatusCode(res.status());
                        return self.handle_rescueable(req, res, &rescueable, false, Some(catch));
                    }
                    HandlerInvocationResult::ToNextHandler => {
                        return ResolvedHandlerProcessingResult::NextHandler;
                    }
                    HandlerInvocationResult::Exception { name, data } => {
                        let rescueable = Rescueable::Exception {
                            exception: &name,
                            data: &data,
                        };
                        return self.handle_rescueable(req, res, &rescueable, false, Some(catch));
                    }
                }
            }
            ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::NextHandler) => {
                return ResolvedHandlerProcessingResult::NextHandler;
            }
            ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Throw {
                exception,
                data,
            }) => {
                let rescueable = Rescueable::Exception { exception, data };
                return self.handle_rescueable(req, res, &rescueable, false, None);
            }
            ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Respond {
                static_response,
                data,
                rescue,
            }) => {
                return self.handle_static_response(
                    req,
                    res,
                    static_response,
                    data.clone(),
                    false,
                    Some(rescue),
                );
            }
            ResolvedRuleAction::None => {
                unreachable!("None action should never be called for execution")
            }
        }
    }

    fn handle_static_response(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        maybe_static_response: &Option<ResolvedStaticResponse>,
        additional_data: HashMap<SmolStr, SmolStr>,
        is_in_exception: bool,
        maybe_rule_invoke_catch: Option<&Vec<ResolvedRescueItem>>,
    ) -> ResolvedHandlerProcessingResult {
        *res = Response::new(Body::empty());

        match maybe_static_response {
            None => {
                let rescueable = Rescueable::Exception {
                    exception: &"static-response-error:not-defined".parse().unwrap(),
                    data: &additional_data,
                };
                return self.handle_rescueable(
                    req,
                    res,
                    &rescueable,
                    true,
                    maybe_rule_invoke_catch,
                );
            }
            Some(static_response) => match static_response.invoke(req, res, additional_data) {
                Ok(()) => ResolvedHandlerProcessingResult::Processed,
                Err((exception, data)) => {
                    *res = Response::new(Body::empty());
                    if !is_in_exception {
                        let rescueable = Rescueable::Exception {
                            exception: &exception,
                            data: &data,
                        };
                        return self.handle_rescueable(
                            req,
                            res,
                            &rescueable,
                            false,
                            maybe_rule_invoke_catch,
                        );
                    } else {
                        error!(
                                "error evaluating static response while in exception handling: {:?}. {:?}",
                                exception, data
                            );
                        *res.body_mut() = Body::from("Internal server error");
                        *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

                        return ResolvedHandlerProcessingResult::Processed;
                    }
                }
            },
        }
    }
}

#[derive(Debug)]
#[must_use]
enum RescueableHandleResult {
    /// Respond with static response
    StaticResponse {
        static_response: Option<ResolvedStaticResponse>,
        data: HashMap<SmolStr, SmolStr>,
    },
    /// Move on to next handler
    NextHandler,
    /// Exception hasn't been handled by ant of handlers
    UnhandledException {
        exception_name: Exception,
        data: HashMap<SmolStr, SmolStr>,
    },
    /// Finish processing normally, respond with prepared response
    FinishProcessing,
}

fn resolve_static_response(
    static_response_name: &StaticResponseName,
    status_code: &Option<exogress_common::config_core::StatusCode>,
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
                    LOCATION,
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
            name,
            status_code,
            data,
        } => ResolvedCatchAction::StaticResponse {
            static_response: resolve_static_response(name, status_code, data, static_responses),
            data: data.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        },
        CatchAction::Throw { exception, data } => ResolvedCatchAction::Throw {
            exception: exception.clone(),
            data: data.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        },
        CatchAction::NextHandler => ResolvedCatchAction::NextHandler,
    })
}

fn resolve_rescue_items(
    rescue: &[RescueItem],
    static_responses: &HashMap<StaticResponseName, StaticResponse>,
) -> Option<Vec<ResolvedRescueItem>> {
    rescue
        .iter()
        .map(|rescue_item| {
            Some(ResolvedRescueItem {
                catch: match &rescue_item.catch {
                    CatchMatcher::StatusCode(status_code) => {
                        ResolvedCatchMatcher::StatusCode(status_code.clone())
                    }
                    CatchMatcher::Exception(exception) => {
                        ResolvedCatchMatcher::Exception(exception.clone())
                    }
                },
                handle: resolve_cache_action(&rescue_item.handle, &static_responses)?,
            })
        })
        .collect::<Option<_>>()
}
impl RequestsProcessor {
    pub fn new(
        resp: ConfigsResponse,
        google_oauth2_client: auth::google::GoogleOauth2Client,
        github_oauth2_client: auth::github::GithubOauth2Client,
        assistant_base_url: Url,
        client_tunnels: ClientTunnels,
        rules_counter: AccountRulesCounters,
        individual_hostname: SmolStr,
        maybe_identity: Option<Vec<u8>>,
    ) -> Result<RequestsProcessor, ()> {
        let grouped = resp.configs.iter().group_by(|item| &item.config_name);

        let project_rescue = resp.project_config.rescue;
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
            .map(|(k, v)| (k, (None, None, None, None, v.into())));

        // static responses are shared across different config names
        let static_responses: Rc<RefCell<HashMap<MountPointName, HashMap<_, _>>>> =
            Rc::new(RefCell::new(HashMap::new()));

        let grouped_mount_points = grouped
            .into_iter()
            .map({
                shadow_clone!(static_responses);

                move |(config_name, configs)| {
                    let entry: &ConfigData = &configs
                        .into_iter()
                        .map(|entry| (entry.instance_ids.len(), entry))
                        .sorted_by(|(left, _), (right, _)| left.cmp(&right).reverse())
                        .into_iter()
                        .next() //keep only revision with largest number of instances
                        .unwrap()
                        .1;

                    let config = &entry.config;
                    let instance_ids = entry.instance_ids.clone();

                    let upstreams = &config.upstreams;

                    for (static_response_name, static_response) in &config.static_responses {
                        for mp in config.mount_points.keys() {
                            static_responses
                                .borrow_mut()
                                .entry(mp.clone())
                                .or_default()
                                .insert(static_response_name.clone(), static_response.clone());
                        }
                    }

                    let client_rescue = config.rescue.clone();

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
                                    Some(client_rescue.clone()),
                                    mp,
                                ),
                            )
                        })
                }
            })
            .flatten()
            .chain(project_mount_points)
            .group_by(|a| a.0.clone())
            .into_iter()
            .map(|a| a.1)
            .flatten()
            .collect::<Vec<_>>();

        for (mp_name, (_, _, _, _, mp)) in &grouped_mount_points {
            for (static_response_name, static_response) in &mp.static_responses {
                static_responses
                    .borrow_mut()
                    .entry(mp_name.clone())
                    .or_default()
                    .insert(static_response_name.clone(), static_response.clone());
            }
        }

        for (static_response_name, static_response) in &resp.project_config.static_responses {
            for (_, mp_static_responses) in static_responses.borrow_mut().iter_mut() {
                mp_static_responses.insert(static_response_name.clone(), static_response.clone());
            }
        }

        let mut merged_resolved_handlers = vec![];

        for (mp_name, (config_name, upstreams, instance_ids, client_config_rescue, mp)) in
            grouped_mount_points.into_iter()
        {
            let mp_rescue = mp.rescue.clone();

            shadow_clone!(instance_ids);
            shadow_clone!(project_rescue);
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
            shadow_clone!(rules_counter);

            let mut r = mp.handlers
                .into_iter()
                .map(move |(handler_name, handler)| {
                    let replace_base_path = handler.replace_base_path.clone();

                    let mp_static_responses = &static_responses.borrow().get(&mp_name).cloned().unwrap_or_default();

                    Some(ResolvedHandler {
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
                                            .keys();
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
                                        for (instance_id, health_status) in instance_ids {
                                            if health_status.get(&proxy.upstream) == Some(&true) {
                                                balancer.add(instance_id.clone(), 1);
                                            }
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
                        handler_rescue: resolve_rescue_items(
                            &handler.rescue,
                            mp_static_responses,
                        )?,
                        mount_point_rescue: resolve_rescue_items(
                            &mp_rescue,
                            mp_static_responses,
                        )?,
                        config_rescue: resolve_rescue_items(
                            &client_config_rescue.as_ref().expect("[BUG] try to access client_config_rescue on project-level config").clone(),
                            mp_static_responses,
                        )?,
                        project_rescue: resolve_rescue_items(
                            &project_rescue,
                            mp_static_responses,
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
                                            Action::Invoke { rescue } => ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Invoke {
                                                rescue: resolve_rescue_items(
                                                    &rescue,
                                                    mp_static_responses,
                                                )?,
                                            }),
                                            Action::NextHandler => ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::NextHandler),
                                            Action::None => ResolvedRuleAction::None,
                                            Action::Throw { exception, data } => ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Throw {
                                                exception,
                                                data: data.iter().map(|(k,v)| (k.as_str().into(), v.as_str().into())).collect(),
                                            }),
                                            Action::Respond {
                                                name: static_response_name, status_code, data, rescue
                                            } => ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Respond {
                                                static_response: resolve_static_response(
                                                    &static_response_name,
                                                    &status_code,
                                                    &data,
                                                    mp_static_responses,
                                                ),
                                                data: Default::default(), // TODO: what data should be here? argh, need integrateion test suite
                                                rescue: resolve_rescue_items(
                                                    &rescue,
                                                    mp_static_responses,
                                                )?,
                                            }),
                                        },
                                    })
                                })
                            .collect::<Option<_>>()?,
                        account_unique_id,
                        base_path: handler.base_path,
                        replace_base_path: handler.replace_base_path,
                        rules_counter: rules_counter.clone(),
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
            rules_counter,
            account_unique_id,
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
    fn invoke(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        additional_data: HashMap<SmolStr, SmolStr>,
    ) -> Result<(), (Exception, HashMap<SmolStr, SmolStr>)> {
        let mut merged_data = self.data.clone();
        merged_data.extend(additional_data.into_iter());

        merged_data.insert("time".into(), Utc::now().to_string().into());

        for (k, v) in &self.headers {
            res.headers_mut().append(k, v.clone());
        }

        *res.status_mut() = self.status_code.clone();

        if self.body.is_empty() {
            // no body defined, just respond with the status code
            return Ok(());
        }

        let accept = req
            .headers()
            .typed_get::<Accept>()
            .map_err(|_| {
                (
                    Exception::from_str("static-response-error:bad-accept-header").unwrap(),
                    merged_data.clone(),
                )
            })?
            .ok_or_else(|| {
                (
                    Exception::from_str("static-response-error:no-accept-header").unwrap(),
                    merged_data.clone(),
                )
            })?;

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
                        handlebars
                            .render_template(&resp.content, &merged_data)
                            .map_err(|e| {
                                merged_data.insert("error".into(), e.to_string().into());
                                (
                                    Exception::from_str("static-response-error:render-error")
                                        .unwrap(),
                                    merged_data.into_iter().collect(),
                                )
                            })?
                    }
                };
                *res.body_mut() = Body::from(body);
            }
            None => {
                *res.status_mut() = StatusCode::NOT_ACCEPTABLE;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum ResolvedCatchMatcher {
    StatusCode(StatusCodeRange),
    Exception(Exception),
}

#[derive(Debug)]
pub struct ResolvedRescueItem {
    catch: ResolvedCatchMatcher,
    handle: ResolvedCatchAction,
}

#[derive(Debug)]
struct ResolvedStatusCodeRangeHandler {
    status_codes_range: StatusCodeRange,
    catch: ResolvedCatchAction,
}
