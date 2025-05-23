use crate::http_serve::{
    auth::{
        github::GithubOauth2Client, google::GoogleOauth2Client, retrieve_assistant_key,
        AuthFinalizer, JwtEcdsa, Oauth2Provider,
    },
    logging::LogMessageSendOnDrop,
    requests_processor::HandlerInvocationResult,
    templates::{render_access_denied, respond_with_login},
};
use chrono::Utc;
use cookie::Cookie;
use exogress_common::{
    common_utils::uri_ext::UriExt,
    config_core::{
        referenced,
        referenced::acl::{Acl, AclEntry},
    },
    entities::{exceptions, HandlerName},
};
use exogress_server_common::logging::{AclAction, AuthHandlerLogMessage};
use globset::Glob;
use http::{
    header::{CACHE_CONTROL, COOKIE, LOCATION, SET_COOKIE},
    Request, Response, StatusCode,
};
use hyper::Body;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use language_tags::LanguageTag;
use smol_str::SmolStr;
use std::{convert::TryInto, sync::Arc};
use typed_headers::HeaderMapExt;
use url::Url;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    pub idp: String,
    pub sub: String,
    pub exp: usize,
}

#[derive(Debug)]
pub struct ResolvedGithubAuthDefinition {
    pub acl: Result<Acl, referenced::Error>,
}

#[derive(Debug)]
pub struct ResolvedGoogleAuthDefinition {
    pub acl: Result<Acl, referenced::Error>,
}

#[derive(Debug)]
pub struct ResolvedAuth {
    pub github: Option<ResolvedGithubAuthDefinition>,
    pub google: Option<ResolvedGoogleAuthDefinition>,
    pub handler_name: HandlerName,
    pub mount_point_fqdn: String,
    pub jwt_ecdsa: JwtEcdsa,
    pub google_oauth2_client: GoogleOauth2Client,
    pub github_oauth2_client: GithubOauth2Client,
    pub assistant_base_url: Url,
    pub maybe_identity: Option<Vec<u8>>,
}

impl ResolvedAuth {
    fn cookie_name(&self) -> String {
        format!("exg-auth-{}", self.handler_name)
    }

    fn respond_not_authorized(&self, req: &Request<Body>, res: &mut Response<Body>) {
        *res.status_mut() = StatusCode::TEMPORARY_REDIRECT;
        let mut redirect_to: Url = format!("https://{}/", self.mount_point_fqdn)
            .parse()
            .unwrap();

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
        res.headers_mut()
            .typed_insert::<typed_headers::ContentType>(&typed_headers::ContentType(
                mime::TEXT_HTML_UTF_8,
            ));

        *res.body_mut() =
            Body::from("<HTML><BODY>Redirecting to authorization page...</BODY></HTML>");
    }

    fn acl_allowed_to<'a, 'b, 'c>(
        &'c self,
        identities: &'a [String],
        acl_entries: &'b [AclEntry],
    ) -> (Option<&'a String>, Option<&'b SmolStr>) {
        let mut acl_allow_to = (None, None);
        'acl: for acl_entry in acl_entries {
            for identity in identities {
                match acl_entry {
                    AclEntry::Allow { identity: pass } => {
                        let is_match = match Glob::new(pass) {
                            Ok(glob) => glob.compile_matcher().is_match(identity),
                            Err(_) => pass == identity,
                        };
                        if is_match {
                            acl_allow_to = (Some(identity), Some(pass));
                            break 'acl;
                        }
                    }
                    AclEntry::Deny { identity: deny } => {
                        let is_match = match Glob::new(deny) {
                            Ok(glob) => glob.compile_matcher().is_match(identity),
                            Err(_) => deny == identity,
                        };
                        if is_match {
                            acl_allow_to = (None, Some(deny));
                            break 'acl;
                        }
                    }
                }
            }
        }

        acl_allow_to
    }

    fn auth_definition(
        &self,
        used_provider: &Oauth2Provider,
    ) -> Option<&Result<Acl, referenced::Error>> {
        match used_provider {
            Oauth2Provider::Google => self.google.as_ref().map(|google| &google.acl),
            Oauth2Provider::Github => self.github.as_ref().map(|github| &github.acl),
        }
    }

    pub async fn try_handle_service_paths(
        &self,
        _req: &Request<Body>,
        res: &mut Response<Body>,
        requested_url: &http::uri::Uri,
        _language: &Option<LanguageTag>,
        _log_message_container: &Arc<parking_lot::Mutex<LogMessageSendOnDrop>>,
    ) -> Option<HandlerInvocationResult> {
        let path_segments: Vec<_> = requested_url.path_segments();
        let query = requested_url.query_pairs();

        let path_segments_len = path_segments.len();

        if path_segments_len >= 2 && path_segments[path_segments_len - 2] == "_exg" {
            if path_segments[path_segments_len - 1] == "auth" {
                let result = (|| {
                    let requested_url: Url =
                        percent_encoding::percent_decode_str(query.get("url")?)
                            .decode_utf8()
                            .ok()?
                            .parse()
                            .ok()?;
                    let handler_name: HandlerName = query.get("handler")?.as_str().parse().ok()?;

                    let provided_oauth2_provider: Option<Oauth2Provider> =
                        query.get("provider").cloned().map(|p| p.parse().unwrap());

                    Some((requested_url, handler_name, provided_oauth2_provider))
                })();

                match result {
                    Some((requested_url, handler_name, provided_oauth2_provider)) => {
                        if handler_name != self.handler_name {
                            return Some(HandlerInvocationResult::ToNextHandler);
                        }

                        respond_with_login(
                            res,
                            &self.mount_point_fqdn,
                            &provided_oauth2_provider,
                            &requested_url,
                            &handler_name,
                            &self.enabled_providers(),
                            &self.jwt_ecdsa,
                            &self.google_oauth2_client,
                            &self.github_oauth2_client,
                        )
                        .await;

                        return Some(HandlerInvocationResult::Responded);
                    }
                    None => {
                        *res.status_mut() = StatusCode::NOT_FOUND;

                        return Some(HandlerInvocationResult::Responded);
                    }
                }
            } else if path_segments[path_segments_len - 1] == "check_auth" {
                match query.get("secret") {
                    Some(secret) => {
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
                                let used_provider = retrieved_flow_data.oauth2_flow_data.provider;

                                if handler_name != self.handler_name {
                                    return Some(HandlerInvocationResult::ToNextHandler);
                                }

                                let maybe_auth_definition = self.auth_definition(&used_provider);

                                match maybe_auth_definition {
                                    Some(acl_result) => {
                                        let acl = match &acl_result {
                                            Ok(val) => val,
                                            Err(err) => {
                                                let (exception, data) = err.to_exception();
                                                return Some(HandlerInvocationResult::Exception {
                                                    name: exception,
                                                    data,
                                                });
                                            }
                                        };

                                        let acl_allow_to = self.acl_allowed_to(
                                            &retrieved_flow_data.identities,
                                            &acl.0,
                                        );

                                        let redirect_to = retrieved_flow_data
                                            .oauth2_flow_data
                                            .requested_url
                                            .to_string();

                                        if let (Some(allowed_identity), _) = acl_allow_to {
                                            res.headers_mut().insert(
                                                CACHE_CONTROL,
                                                "no-cache".try_into().unwrap(),
                                            );

                                            res.headers_mut()
                                                .insert(LOCATION, redirect_to.try_into().unwrap());

                                            *res.status_mut() = StatusCode::TEMPORARY_REDIRECT;

                                            let claims = Claims {
                                                idp: retrieved_flow_data
                                                    .oauth2_flow_data
                                                    .provider
                                                    .to_string(),
                                                sub: allowed_identity.to_string(),
                                                exp: (Utc::now() + chrono::Duration::hours(24))
                                                    .timestamp()
                                                    .try_into()
                                                    .unwrap(),
                                            };

                                            let token = try_or_exception!(
                                                jsonwebtoken::encode(
                                                    &Header {
                                                        alg: jsonwebtoken::Algorithm::ES256,
                                                        ..Default::default()
                                                    },
                                                    &claims,
                                                    &try_or_exception!(
                                                        EncodingKey::from_ec_pem(
                                                            retrieved_flow_data
                                                                .oauth2_flow_data
                                                                .jwt_ecdsa
                                                                .private_key
                                                                .as_ref(),
                                                        ),
                                                        exceptions::AUTH_INTERNAL_ERROR
                                                    ),
                                                ),
                                                exceptions::AUTH_INTERNAL_ERROR
                                            );

                                            let auth_cookie_name = self.cookie_name();

                                            let set_cookie = Cookie::build(auth_cookie_name, token)
                                                .path("/")
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
                                            *res.body_mut() =
                                                Body::from(render_access_denied(redirect_to));
                                        }
                                    }
                                    None => {
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
                    }
                    None => {
                        *res.status_mut() = StatusCode::NOT_FOUND;
                    }
                };

                return Some(HandlerInvocationResult::Responded);
            }
        }

        None
    }

    pub async fn invoke(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        _requested_url: &http::uri::Uri,
        language: &Option<LanguageTag>,
        handler_log: &mut Option<AuthHandlerLogMessage>,
    ) -> HandlerInvocationResult {
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
            let decoding_key = try_or_exception!(
                DecodingKey::from_ec_pem(&self.jwt_ecdsa.public_key),
                exceptions::AUTH_INTERNAL_ERROR
            );
            match jsonwebtoken::decode::<Claims>(
                &token.value(),
                &decoding_key,
                &Validation {
                    algorithms: vec![jsonwebtoken::Algorithm::ES256],
                    ..Default::default()
                },
            ) {
                Ok(token) => {
                    let granted_identity = token.claims.sub;
                    let granted_provider: Oauth2Provider = try_or_exception!(
                        token.claims.idp.parse(),
                        exceptions::AUTH_UNKNOWN_PROVIDER
                    );

                    let maybe_auth_definition = self.auth_definition(&granted_provider);

                    match maybe_auth_definition {
                        Some(acl_result) => {
                            let acl = try_or_to_exception!(acl_result.as_ref());

                            let identities = [granted_identity.clone()];

                            let (acl_allowed_to, acl_entry) =
                                self.acl_allowed_to(&identities, &acl.0);

                            if let Some(allow_to) = acl_allowed_to {
                                *handler_log = Some(AuthHandlerLogMessage {
                                    handler_name: self.handler_name.clone(),
                                    provider: Some(granted_provider.to_string().into()),
                                    identity: Some(allow_to.into()),
                                    acl_entry: acl_entry.cloned(),
                                    acl_action: AclAction::Allowed,
                                    language: language.clone(),
                                });
                            } else {
                                self.respond_not_authorized(req, res);

                                *handler_log = Some(AuthHandlerLogMessage {
                                    handler_name: self.handler_name.clone(),
                                    provider: Some(granted_provider.to_string().into()),
                                    identity: Some(granted_identity.into()),
                                    acl_entry: acl_entry.cloned(),
                                    acl_action: AclAction::Denied,
                                    language: language.clone(),
                                });

                                return HandlerInvocationResult::Responded;
                            }
                        }
                        None => {
                            self.respond_not_authorized(req, res);

                            *handler_log = Some(AuthHandlerLogMessage {
                                handler_name: self.handler_name.clone(),
                                provider: Some(granted_provider.to_string().into()),
                                identity: Some(granted_identity.into()),
                                acl_entry: None,
                                acl_action: AclAction::Denied,
                                language: language.clone(),
                            });

                            return HandlerInvocationResult::Responded;
                        }
                    }
                }
                Err(_e) => {
                    self.respond_not_authorized(req, res);

                    *handler_log = Some(AuthHandlerLogMessage {
                        handler_name: self.handler_name.clone(),
                        provider: None,
                        identity: None,
                        acl_entry: None,
                        acl_action: AclAction::Denied,
                        language: language.clone(),
                    });

                    return HandlerInvocationResult::Responded;
                }
            }
        } else {
            *handler_log = Some(AuthHandlerLogMessage {
                handler_name: self.handler_name.clone(),
                provider: None,
                identity: None,
                acl_entry: None,
                acl_action: AclAction::Denied,
                language: language.clone(),
            });

            self.respond_not_authorized(req, res);
            return HandlerInvocationResult::Responded;
        }

        HandlerInvocationResult::ToNextHandler
    }

    fn enabled_providers(&self) -> Vec<Oauth2Provider> {
        let mut providers = vec![];
        if self.github.is_some() {
            providers.push(Oauth2Provider::Github);
        }
        if self.google.is_some() {
            providers.push(Oauth2Provider::Google);
        }
        providers
    }
}
