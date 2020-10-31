use std::fmt;
use std::str::FromStr;

use chrono::serde::ts_milliseconds;
use chrono::{DateTime, Utc};

use exogress_config_core::{AuthProvider, ClientConfig, StaticResponse};
use exogress_entities::{
    AccountName, AccountUniqueId, ConfigId, ConfigName, InstanceId, ProjectName,
    StaticResponseName, Upstream,
};
use http::Uri;
use smallvec::SmallVec;
use url::Url;

use crate::clients::ClientTunnels;
use crate::url_mapping::handlers::HandlersProcessor;
use crate::url_mapping::rate_limiter::RateLimiters;
use crate::webapp::ConfigsResponse;
use core::mem;
use exogress_server_common::assistant::UpstreamReport;
use exogress_server_common::health::{HealthEndpoint, HealthState, UnhealthyReason};
use exogress_server_common::url_prefix::UrlPrefix;
use exogress_tunnel::ConnectTarget;
use futures::channel::{mpsc, oneshot};
use futures::stream::FuturesUnordered;
use futures::{SinkExt, StreamExt};
use hashbrown::hash_map::Entry;
use hashbrown::HashMap;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::time::delay_for;

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    cn: String,
    certificate: String,
    private_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InstanceSchema {
    config: ClientConfig,
    instance_id: InstanceId,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SchemaConfigs {
    #[serde(with = "ts_milliseconds")]
    generated_at: DateTime<Utc>,
    url_prefix: String,
    tls: TlsConfig,
    instances: SmallVec<[InstanceSchema; 8]>,
}

/// UrlForRewriting
/// MatchPattern
/// RewriteTemplate
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UrlForRewriting {
    inner: String,
    host: String,
    path: String,
    username: String,
    password: Option<String>,
}

impl UrlForRewriting {
    pub fn to_url_prefix(&self) -> UrlPrefix {
        let s = format!("{}{}", self.host, self.path);
        UrlPrefix::from_str(s.as_ref()).expect("unexpected bad data in UrlForRewriting")
    }
}

impl fmt::Display for UrlForRewriting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum UrlForRewritingError {
    #[error("port should not exist")]
    PortFound,

    #[error("path should start from '/'")]
    NoRootPath,
}

impl UrlForRewriting {
    #[allow(dead_code)]
    pub fn from_url(mut url: Url) -> Self {
        url.set_port(None).unwrap();
        url.set_scheme("https").unwrap();

        let host = url.host_str().unwrap().into();
        let path = url.path().into();

        UrlForRewriting {
            host,
            password: url.password().map(|s| s.into()),
            username: url.username().into(),
            inner: url.to_string().trim_start_matches("https://").into(),
            path,
        }
    }

    pub fn from_components(
        host_without_port: &str,
        path: &str,
        query: &str,
    ) -> Result<Self, UrlForRewritingError> {
        if host_without_port.contains(":") {
            return Err(UrlForRewritingError::PortFound);
        }

        let host = host_without_port.into();

        let mut s = host_without_port.to_string();

        if !path.starts_with('/') {
            return Err(UrlForRewritingError::NoRootPath);
        }

        s.push_str(path);

        if !query.is_empty() {
            s.push_str("?");
            s.push_str(query);
        }

        Ok(UrlForRewriting {
            inner: s.into(),
            password: None,
            username: "".into(),
            host,
            path: path.into(),
        })
    }

    pub fn matches(self, pattern: MatchPattern) -> Option<Matched> {
        if self
            .inner
            .as_str()
            .starts_with(pattern.matchable_prefix.as_str())
        {
            if pattern.matchable_prefix.len() < self.inner.len() {
                let pattern_last_idx = pattern.matchable_prefix.len() - 1;
                let next_idx = pattern.matchable_prefix.len();
                let pattern_last_char = pattern
                    .matchable_prefix
                    .get(pattern_last_idx..=pattern_last_idx)
                    .unwrap();
                let next_char = self.inner.get(next_idx..=next_idx).unwrap();

                if pattern_last_char != "/" && next_char != "/" && next_char != "?" {
                    return None;
                }
            }
            Some(Matched {
                url: self,
                pattern,
                config_name: None,
            })
        } else {
            None
        }
    }

    pub fn host(&self) -> String {
        self.host.clone()
    }
}

impl AsRef<[u8]> for UrlForRewriting {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

#[derive(Debug)]
pub struct Matched {
    url: UrlForRewriting,
    pattern: MatchPattern,
    config_name: Option<ConfigName>,
}

impl Matched {
    pub fn resolve_handler(
        self,
        rewrite_to: &ProxyMatchedTo,
        protocol: Protocol,
    ) -> Result<ClientHandler, url::ParseError> {
        let mut rewritten_str = self.url.inner.clone();

        rewritten_str.replace_range(0..self.pattern.matchable_prefix.len() - 1, "localhost");

        let parsable = format!("http://{}", rewritten_str);

        let mut url = Url::parse(&parsable)?;

        let scheme = match (protocol, rewrite_to) {
            (Protocol::Http, _) => "http",
            (Protocol::WebSockets, _) => "ws",
        };

        url.set_scheme(scheme).unwrap();

        url.set_username(self.url.username.as_str()).unwrap();
        url.set_password(self.url.password.as_deref()).unwrap();

        match rewrite_to {
            ProxyMatchedTo::Client {
                handlers_processor,
                account_name,
                project_name,
                account_unique_id,
            } => Ok(ClientHandler {
                account_name: account_name.clone(),
                handlers_processor: handlers_processor.clone(),
                url,
                project_name: project_name.clone(),
                account_unique_id: account_unique_id.clone(),
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MatchPattern {
    matchable_prefix: String,
}

#[derive(thiserror::Error, Debug)]
pub enum MatchPatternError {
    #[error("URL parse error: `{0}`")]
    Url(#[from] url::ParseError),

    #[error("URI build error: `{0}`")]
    Uri(#[from] http::Error),

    #[error("fragment (hash) should not exist")]
    FragmentFound,

    #[error("query should not exist")]
    QueryFound,

    #[error("port should not exist")]
    PortFound,

    #[error("username/password shoud not exist")]
    AuthFound,
}

impl MatchPattern {
    #[allow(dead_code)]
    pub fn new(host: &str, path: &str) -> Result<MatchPattern, MatchPatternError> {
        let uri = Uri::builder()
            .scheme("http")
            .authority(host)
            .path_and_query(path)
            .build()?;

        if uri.path_and_query().unwrap().query().is_some() {
            return Err(MatchPatternError::QueryFound);
        }
        if uri.authority().unwrap().port().is_some() {
            return Err(MatchPatternError::PortFound);
        }
        if uri.authority().unwrap().as_str().contains('@') {
            return Err(MatchPatternError::AuthFound);
        }

        Ok(MatchPattern {
            matchable_prefix: uri.to_string().trim_start_matches("http://").into(),
        })
    }

    pub fn generate_url(
        &self,
        proto: Protocol,
        maybe_port: Option<u16>,
        relative_url: &str,
    ) -> Url {
        let scheme = match proto {
            Protocol::Http => "https",
            Protocol::WebSockets => "wss",
        };

        let mut url =
            Url::parse(format!("{}://{}", scheme, self.matchable_prefix).as_str()).unwrap();

        url.set_port(maybe_port).unwrap();

        url.path_segments_mut().unwrap().extend(
            relative_url.split('/').filter(|s| !s.is_empty()), //remove first empty
        );

        url
    }
}

impl fmt::Display for MatchPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.matchable_prefix)
    }
}

impl FromStr for MatchPattern {
    type Err = MatchPatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(format!("http://{}", s).as_str())?;

        if url.fragment().is_some() {
            return Err(MatchPatternError::FragmentFound);
        }

        if url.query().is_some() {
            return Err(MatchPatternError::QueryFound);
        }
        if url.port().is_some() {
            return Err(MatchPatternError::PortFound);
        }
        if url.password().is_some() || !url.username().is_empty() {
            return Err(MatchPatternError::AuthFound);
        }

        Ok(MatchPattern {
            matchable_prefix: url.to_string().trim_start_matches("http://").into(),
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RewriteMatchedToError {
    #[error("URL parse error: `{0}`")]
    Url(#[from] url::ParseError),

    #[error("URI build error: `{0}`")]
    Uri(#[from] http::Error),
    // #[error("query should not exist")]
    // QueryFound,

    // #[error("fragment (hash) should not exist")]
    // FragmentFound,
}

#[derive(Clone)]
pub enum ProxyMatchedTo {
    Client {
        handlers_processor: HandlersProcessor,
        account_name: AccountName,
        account_unique_id: AccountUniqueId,
        project_name: ProjectName,
    },
}

impl ProxyMatchedTo {
    pub fn new(
        account_name: AccountName,
        account_unique_id: AccountUniqueId,
        project_name: ProjectName,
        handlers_processor: &HandlersProcessor,
    ) -> Result<Self, RewriteMatchedToError> {
        Ok(ProxyMatchedTo::Client {
            handlers_processor: handlers_processor.clone(),
            account_name,
            account_unique_id,
            project_name,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Oauth2SsoClient {
    pub provider: Oauth2Provider,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy)]
pub enum Oauth2Provider {
    #[serde(rename = "google")]
    Google,
    #[serde(rename = "github")]
    Github,
}

impl ToString for Oauth2Provider {
    fn to_string(&self) -> std::string::String {
        match self {
            Oauth2Provider::Google => "google",
            Oauth2Provider::Github => "github",
        }
        .to_string()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AuthProviderConfig {
    Oauth2(Oauth2SsoClient),
}

impl From<AuthProvider> for AuthProviderConfig {
    fn from(provider: AuthProvider) -> Self {
        match provider {
            AuthProvider::Google => AuthProviderConfig::Oauth2(Oauth2SsoClient {
                provider: Oauth2Provider::Google,
            }),
            AuthProvider::Github => AuthProviderConfig::Oauth2(Oauth2SsoClient {
                provider: Oauth2Provider::Github,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtEcdsa {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug)]
pub struct Mapping {
    match_pattern: MatchPattern,
    pub generated_at: DateTime<Utc>,
    pub config_names: SmallVec<[ConfigName; 8]>,
    handlers_processor: HandlersProcessor,
    pub account: AccountName,
    pub account_unique_id: AccountUniqueId,
    pub project: ProjectName,
    jwt_ecdsa: JwtEcdsa,
    rate_limiters: RateLimiters,
    healthcheck_stop_tx: oneshot::Sender<()>,
    pub health: HealthStorage,
    static_responses: BTreeMap<StaticResponseName, StaticResponse>,
}

#[derive(Clone, Debug)]
pub struct HealthStorage {
    inner: Arc<Mutex<HashMap<HealthEndpoint, HealthState>>>,
    notify_on_change_tx: mpsc::Sender<UpstreamReport>,
    account_name: AccountName,
    project_name: ProjectName,
}

impl HealthStorage {
    pub fn new(
        account_name: &AccountName,
        project_name: &ProjectName,
        notify_on_change_tx: mpsc::Sender<UpstreamReport>,
    ) -> Self {
        HealthStorage {
            inner: Arc::new(Default::default()),
            notify_on_change_tx,
            account_name: account_name.clone(),
            project_name: project_name.clone(),
        }
    }
}

impl HealthStorage {
    async fn set_health(
        &mut self,
        instance_id: &InstanceId,
        upstream: &Upstream,
        state: HealthState,
    ) -> Result<(), mpsc::SendError> {
        let endpoint = HealthEndpoint {
            instance_id: instance_id.clone(),
            upstream: upstream.clone(),
        };

        match self.inner.lock().entry(endpoint.clone()) {
            Entry::Vacant(vacant) => {
                vacant.insert(state.clone());
            }
            Entry::Occupied(mut occupied) => {
                if occupied.get() == &state {
                    return Ok(());
                };
                occupied.insert(state.clone());
            }
        }

        self.notify_on_change_tx
            .send(UpstreamReport {
                account_name: self.account_name.clone(),
                project_name: self.project_name.clone(),
                health_endpoint: endpoint,
                health: Some(state),
                datetime: Utc::now(),
            })
            .await?;

        Ok(())
    }

    pub(crate) fn get_health(
        &self,
        instance_id: &InstanceId,
        upstream: &Upstream,
    ) -> Option<HealthState> {
        let endpoint = HealthEndpoint {
            instance_id: instance_id.clone(),
            upstream: upstream.clone(),
        };

        self.inner.lock().get(&endpoint).cloned()
    }

    pub async fn health_deleted(&self) -> Result<(), mpsc::SendError> {
        let old = mem::replace(&mut *self.inner.lock(), Default::default());

        let mut notify_on_change_tx = self.notify_on_change_tx.clone();

        for (endpoint, _) in old.into_iter() {
            notify_on_change_tx
                .send(UpstreamReport {
                    account_name: self.account_name.clone(),
                    project_name: self.project_name.clone(),
                    health_endpoint: endpoint,
                    health: None,
                    datetime: Utc::now(),
                })
                .await?;
        }

        Ok(())
    }
}

impl Mapping {
    pub fn new(
        config_response: ConfigsResponse,
        handlers_processor: HandlersProcessor,
        health: HealthStorage,
        static_responses: BTreeMap<StaticResponseName, StaticResponse>,
        rate_limiters: RateLimiters,
        client_tunnels: ClientTunnels,
        individual_hostname: String,
    ) -> Mapping {
        let config_names = config_response
            .configs
            .iter()
            .map(|config| config.config_name.clone())
            .collect();
        let match_pattern = config_response.url_prefix.as_str().parse().expect("FIXME");

        let account = config_response.account.clone();
        let account_unique_id = config_response.account_unique_id.clone();
        let project = config_response.project.clone();
        let generated_at = config_response.generated_at.clone();

        let jwt_ecdsa = JwtEcdsa {
            private_key: config_response.jwt_ecdsa.private_key.clone().into(),
            public_key: config_response.jwt_ecdsa.public_key.clone().into(),
        };

        let (healthcheck_stop_tx, healthcheck_stop_rx) = oneshot::channel();

        info!("spawn healthcheck");

        let healthcheck = {
            shadow_clone!(individual_hostname);
            shadow_clone!(handlers_processor);
            shadow_clone!(client_tunnels);

            shadow_clone!(account);
            shadow_clone!(project);
            shadow_clone!(health);

            async move {
                shadow_clone!(project);
                shadow_clone!(mut health);

                {
                    for config in &config_response.configs {
                        for instance_id in &config.instance_ids {
                            for (upstream, upstream_definition) in &config.config.upstreams {
                                if !upstream_definition.health.is_empty() {
                                    health
                                        .set_health(instance_id, upstream, HealthState::NotYetKnown)
                                        .await
                                        .expect("FIXME");
                                }
                            }
                        }
                    }
                }

                loop {
                    shadow_clone!(client_tunnels);
                    shadow_clone!(project);
                    shadow_clone!(health);

                    let futures = FuturesUnordered::new();

                    // info!("Current health status: {:#?}", instances_health.lock());

                    for config in &config_response.configs {
                        let config_id = ConfigId {
                            account_name: account.clone(),
                            account_unique_id: account_unique_id.clone(),
                            project_name: project.clone(),
                            config_name: config.config_name.clone(),
                        };

                        for instance_id in &config.instance_ids {
                            for (upstream, upstream_definition) in &config.config.upstreams {
                                if upstream_definition.health.is_empty() {
                                    break;
                                }

                                shadow_clone!(individual_hostname);
                                shadow_clone!(health);
                                shadow_clone!(handlers_processor);
                                shadow_clone!(client_tunnels);

                                shadow_clone!(account);
                                shadow_clone!(project);

                                let maybe_client_tunnel = client_tunnels
                                    .retrieve_client_tunnel(
                                        config_id.clone(),
                                        instance_id.clone(),
                                        individual_hostname.clone().into(),
                                    )
                                    .await;

                                if let Some(client_tunnel) = maybe_client_tunnel {
                                    let connect_target = ConnectTarget::Upstream(upstream.clone());

                                    for probe in &upstream_definition.health {
                                        let hyper = client_tunnel.hyper.clone();

                                        futures.push({
                                            shadow_clone!(connect_target);
                                            shadow_clone!(health);

                                            async move {
                                                shadow_clone!(connect_target);
                                                shadow_clone!(mut health);

                                                let url = connect_target
                                                    .with_path(probe.target.path.as_str())
                                                    .expect("FIXME: URL error");

                                                debug!(
                                                    "healthcheck connect target {:?} to instance {}. probe: {:?}. URL = {}",
                                                    connect_target, instance_id, probe, url
                                                );

                                                let r = tokio::time::timeout(
                                                    probe.target.timeout,
                                                    hyper.get(
                                                        url.to_string().parse().expect("FIXME"),
                                                    ),
                                                )
                                                    .await;

                                                match r {
                                                    Ok(Ok(resp)) if resp.status().is_success() => {
                                                        health
                                                            .set_health(instance_id, upstream,HealthState::Healthy)
                                                            .await
                                                            .expect("FIXME");
                                                        debug!(
                                                            "healthcheck ok instance_id={}, upstream={}",
                                                            instance_id, upstream
                                                        )
                                                    }
                                                    Ok(Ok(resp)) => {
                                                        info!(
                                                            "healthcheck bad status {:?} instance_id={}, upstream={}",
                                                            resp.status(),
                                                            instance_id,
                                                            upstream
                                                        );
                                                        health
                                                            .set_health(instance_id, upstream,
                                                                HealthState::Unhealthy {
                                                                    probe: probe.clone(),
                                                                    reason: UnhealthyReason::BadStatus(resp.status()),
                                                                }
                                                            )
                                                            .await
                                                            .expect("FIXME");
                                                    }
                                                    Ok(Err(e)) => {
                                                        info!(
                                                            "healthcheck error {:?} instance_id={}, upstream={}",
                                                            e, instance_id, upstream
                                                        );
                                                        health
                                                            .set_health(
                                                                instance_id,
                                                                upstream,
                                                                HealthState::Unhealthy {
                                                                    probe: probe.clone(),
                                                                    reason: UnhealthyReason::Unreachable,
                                                                }
                                                            )
                                                            .await
                                                            .expect("FIXME");

                                                    }
                                                    Err(_e) => {
                                                        error!(
                                                            "healthcheck timeout instance_id={}, upstream={}",
                                                            instance_id, upstream
                                                        );
                                                        health
                                                            .set_health(
                                                                instance_id,
                                                                upstream,
                                                                HealthState::Unhealthy {
                                                                    probe: probe.clone(),
                                                                    reason: UnhealthyReason::Timeout,
                                                                }
                                                            )
                                                            .await
                                                            .expect("FIXME");

                                                    }
                                                }

                                                delay_for(probe.target.period).await;
                                            }
                                        });
                                    }
                                }
                            }
                        }
                    }

                    let probes_performed = futures.collect::<Vec<_>>().await;
                    if probes_performed.len() == 0 {
                        info!("no healthchecks defined");
                        return;
                    }
                }
            }
        };

        tokio::spawn(async move {
            tokio::select! {
              _ = healthcheck => {},
              _ = healthcheck_stop_rx => {},
            }
        });

        let mapping = Mapping {
            match_pattern,
            generated_at,
            config_names,
            handlers_processor,
            account,
            account_unique_id,
            project,
            jwt_ecdsa,
            rate_limiters,
            healthcheck_stop_tx,
            health: health.clone(),
            static_responses,
        };

        mapping
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UrlMappingError {
    #[error("URL parse error: `{0}`")]
    Url(#[from] url::ParseError),

    #[error("The URL `{url}` doesn't belong to match pattern `{pattern}`")]
    DoesNotBelongToPrefix {
        pattern: MatchPattern,
        url: UrlForRewriting,
    },
}

#[derive(Clone, Debug)]
pub struct ClientHandler {
    pub account_name: AccountName,
    pub account_unique_id: AccountUniqueId,
    pub project_name: ProjectName,
    pub handlers_processor: HandlersProcessor,
    pub url: Url,
}

#[derive(Clone, Debug)]
pub struct MappingAction {
    pub handler: ClientHandler,
    pub jwt_ecdsa: JwtEcdsa,
    pub external_base_url: Url,
    pub health: HealthStorage,
    pub static_responses: BTreeMap<StaticResponseName, StaticResponse>,
}

#[derive(Debug, Clone)]
pub struct RenderedResponse {
    pub body: String,
    pub content_type: mime::Mime,
}

impl MappingAction {
    #[allow(dead_code)]
    pub fn rewrite_to_url(&self) -> Url {
        self.handler.url.clone()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    Http,
    WebSockets,
}

impl Mapping {
    pub fn handle(
        &self,
        url: UrlForRewriting,
        external_port: u16,
        proto: Protocol,
    ) -> Result<(MappingAction, RateLimiters), UrlMappingError> {
        if let Some(m) = url.clone().matches(self.match_pattern.clone()) {
            let base_url = self
                .match_pattern
                .generate_url(proto, Some(external_port), "");

            let handler = m
                .resolve_handler(
                    &ProxyMatchedTo::new(
                        self.account.clone(),
                        self.account_unique_id.clone(),
                        self.project.clone(),
                        &self.handlers_processor,
                    )
                    .expect("FIXME"),
                    proto,
                )
                .expect("FIXME");

            Ok((
                MappingAction {
                    handler,
                    jwt_ecdsa: self.jwt_ecdsa.clone(),
                    external_base_url: base_url,
                    health: self.health.clone(),
                    static_responses: self.static_responses.clone(),
                },
                self.rate_limiters.clone(),
            ))
        } else {
            Err(UrlMappingError::DoesNotBelongToPrefix {
                pattern: self.match_pattern.clone(),
                url,
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::static_response::StaticResponseExt;
    use exogress_config_core::{CommonResponse, RawResponse, ResponseBody, TemplateEngine};
    use http::header::CONTENT_TYPE;
    use http::Response;
    use hyper::Body;
    use typed_headers::{Accept, Quality, QualityItem};

    #[tokio::test]
    pub async fn test_client() {
        let plain = StaticResponse::Raw(RawResponse {
            status_code: http::StatusCode::OK,
            body: vec![
                ResponseBody {
                    content_type: "text/html".to_string(),
                    content: "<html><body><h1>plain resp</h1></body>/html>".to_string(),
                    engine: None,
                },
                ResponseBody {
                    content_type: "application/json".to_string(),
                    content: "{\"status\": \"not-found\"}".to_string(),
                    engine: None,
                },
            ],
            common: CommonResponse {
                ..Default::default()
            },
        });

        let mut resp = Response::new(Body::empty());

        plain
            .try_respond(
                &Accept(vec![QualityItem::new(
                    "text/html".parse().unwrap(),
                    Quality::from_u16(200),
                )]),
                &mut resp,
            )
            .unwrap();

        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            mime::TEXT_HTML.to_string().as_str()
        );
        assert!(
            std::str::from_utf8(resp.into_body().next().await.unwrap().unwrap().as_ref())
                .unwrap()
                .contains("html")
        );

        let mut resp = Response::new(Body::empty());
        plain
            .try_respond(
                &Accept(vec![
                    QualityItem::new("text/html".parse().unwrap(), Quality::from_u16(200)),
                    QualityItem::new("application/json".parse().unwrap(), Quality::from_u16(1000)),
                ]),
                &mut resp,
            )
            .unwrap();

        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            mime::APPLICATION_JSON.to_string().as_str()
        );
        assert!(
            std::str::from_utf8(resp.into_body().next().await.unwrap().unwrap().as_ref())
                .unwrap()
                .contains("not-found")
        );

        let handlebars = StaticResponse::Raw(RawResponse {
            status_code: http::StatusCode::OK,
            body: vec![ResponseBody {
                content_type: "text/html".to_string(),
                content: "<html><body><h1>Generated at {{ this.time }}</h1></body>/html>"
                    .to_string(),
                engine: Some(TemplateEngine::Handlebars),
            }],
            common: CommonResponse {
                ..Default::default()
            },
        });

        let mut resp = Response::new(Body::empty());
        plain
            .try_respond(
                &Accept(vec![QualityItem::new(
                    "text/html".parse().unwrap(),
                    Quality::from_u16(200),
                )]),
                &mut resp,
            )
            .unwrap();

        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            mime::TEXT_HTML.to_string().as_str()
        );
        assert!(
            std::str::from_utf8(resp.into_body().next().await.unwrap().unwrap().as_ref())
                .unwrap()
                .contains("html")
        );

        let mut resp = Response::new(Body::empty());
        plain
            .try_respond(
                &Accept(vec![QualityItem::new(
                    "text/*".parse().unwrap(),
                    Quality::from_u16(200),
                )]),
                &mut resp,
            )
            .unwrap();

        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            mime::TEXT_HTML.to_string().as_str()
        );
        assert!(
            std::str::from_utf8(resp.into_body().next().await.unwrap().unwrap().as_ref())
                .unwrap()
                .contains("html")
        );

        let mut resp = Response::new(Body::empty());
        plain
            .try_respond(
                &Accept(vec![QualityItem::new(
                    "*/*".parse().unwrap(),
                    Quality::from_u16(200),
                )]),
                &mut resp,
            )
            .unwrap();

        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            mime::TEXT_HTML.to_string().as_str()
        );
        assert!(
            std::str::from_utf8(resp.into_body().next().await.unwrap().unwrap().as_ref())
                .unwrap()
                .contains("html")
        );
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     pub fn schema() {
//         static JSON: &'static str = r#"{
//     "generated_at": 1594736221163,
//     "mount_point": "01ED925W8DK8W7G0Q6TP5MS6SD",
//     "path_prefixes": [],
//     "destination_path_prefix": "asd",
//     "revisions": [
//         {
//             "revision": 12345,
//             "version": "0.0.1",
//             "handlers": [
//                 {
//                     "definition": {
//                         "type": "static_app",
//                         "app": "swagger-ui",
//                         "version": "3.28.0",
//                         "base_path": ["a", "b"],
//                         "priority": 10
//                     },
//                     "config_name": "01ED9C7EJV2BK4Z24WW26TZAVP",
//                     "instance_ids": ["01ED9C74GHBAECTRYZD3D8X6B5", "01ED9C794H75XKT27683ME02V6"],
//                     "name": "static-assets"
//                 }
//             ]
//         }
//     ]
// }
// "#;
//
//         let _n: SchemaMapping = serde_json::from_str(JSON).unwrap();
//         // assert_eq!("2020-07-14T14:17:01.163Z".parse::<DateTime<Utc>>().unwrap(), n.generated_at);
//         // assert!(
//         //     matches!(
//         //         n.action,
//         //         Action::Invalidate { mount_points } if mount_points.as_slice() == [String::from("mpid")]
//         //     )
//         // );
//     }
//
//     #[test]
//     pub fn check_matching() {
//         let pattern = MatchPattern::new("example.exg.co", "/asd").unwrap();
//
//         let url1 = UrlForRewriting::from_components("example.exg.co", "/asdfgh", "").unwrap();
//         assert!(url1.matches(pattern.clone()).is_none());
//
//         let url2 = UrlForRewriting::from_components("example.exg.co", "/asd/fgh", "").unwrap();
//         assert!(url2.matches(pattern.clone()).is_some());
//
//         let url3 = UrlForRewriting::from_components("example.exg.co", "/asd?a=2", "").unwrap();
//         assert!(url3.matches(pattern.clone()).is_some());
//
//         let url4 = UrlForRewriting::from_components("example.exg.co", "/asd", "").unwrap();
//         assert!(url4.matches(pattern.clone()).is_some());
//
//         let url5 = UrlForRewriting::from_components("example.exg.co", "/asd/", "").unwrap();
//         assert!(url5.matches(pattern.clone()).is_some());
//
//         let pattern2 = MatchPattern::new("example.exg.co", "/").unwrap();
//         let url6 = UrlForRewriting::from_components("example.exg.co", "/", "").unwrap();
//         assert!(url6.matches(pattern2.clone()).is_some());
//
//         let url7 = UrlForRewriting::from_components("example.exg.co", "/admin", "").unwrap();
//         assert!(url7.matches(pattern2.clone()).is_some());
//
//         let pattern3 = MatchPattern::new("example.exg.co", "").unwrap();
//         let url8 = UrlForRewriting::from_components("example.exg.co", "/", "").unwrap();
//         assert!(url8.matches(pattern3.clone()).is_some());
//     }
//
//     #[test]
//     pub fn incorrect() {
//         let mapping = Mapping {
//             match_pattern: MatchPattern::new("example.exg.co", "/").unwrap(),
//             proxy_matched_to: ProxyMatchedTo::new("lancastr.com/", "test-config".parse().unwrap())
//                 .unwrap(),
//             generated_at: Utc::now(),
//             // jwt_secret: vec![],
//             // auth_type: AuthProviderConfig::Oauth2(Oauth2SsoClient {
//             //     provider: Oauth2Provider::Google,
//             // }),
//             // rate_limiter: None,
//         };
//
//         assert!(mapping
//             .handle(
//                 UrlForRewriting::from_components("bad.com", "/", "").unwrap(),
//                 ClientTunnels::new(),
//                 443,
//                 Protocol::Http,
//             )
//             .is_err())
//     }
//
//     // #[test]
//     // pub fn domain_rewrite() {
//     //     let mapping = Mapping {
//     //         match_pattern: MatchPattern::new("example.exg.co", "/").unwrap(),
//     //         proxy_matched_to: ProxyMatchedTo::new("lancastr.com/", Default::default()).unwrap(),
//     //         generated_at: Utc::now(),
//     //         jwt_secret: vec![],
//     //         auth_type: AuthProviderConfig::Oauth2(Oauth2SsoClient {
//     //             provider: Oauth2Provider::Google,
//     //         }),
//     //         rate_limiter: None,
//     //     };
//     //
//     //     assert_eq!(
//     //         Url::parse("https://lancastr.com/").unwrap(),
//     //         mapping
//     //             .handle(
//     //                 UrlForRewriting::from_components("example.exg.co", "/", "").unwrap(),
//     //                 ClientTunnels::new(),
//     //                 443,
//     //                 Protocol::Http,
//     //             )
//     //             .unwrap()
//     //             .0
//     //             .rewrite_to_url()
//     //     )
//     // }
//
//     // #[test]
//     // pub fn domain_and_path_rewrite() {
//     //     let mapping = Mapping {
//     //         match_pattern: MatchPattern::new("example.exg.co", "/from/url").unwrap(),
//     //         proxy_matched_to: ProxyMatchedTo::new("lancastr.com/to/newurl", Default::default()).unwrap(),
//     //         generated_at: Utc::now(),
//     //         jwt_secret: vec![],
//     //         auth_type: AuthProviderConfig::Oauth2(Oauth2SsoClient {
//     //             provider: Oauth2Provider::Google,
//     //         }),
//     //         rate_limiter: None,
//     //     };
//     //
//     //     assert_eq!(
//     //         Url::parse("https://lancastr.com/to/newurl/path?a=2").unwrap(),
//     //         mapping
//     //             .handle(
//     //                 UrlForRewriting::from_components("example.exg.co", "/from/url/path", "a=2")
//     //                     .unwrap(),
//     //                 ClientTunnels::new(),
//     //                 443,
//     //                 Protocol::Http,
//     //             )
//     //             .unwrap()
//     //             .0
//     //             .rewrite_to_url()
//     //     )
//     // }
//
//     // #[test]
//     // pub fn port_rewrite() {
//     //     let mapping = Mapping {
//     //         match_pattern: MatchPattern::new("example.exg.co", "/from/url").unwrap(),
//     //         proxy_matched_to: ProxyMatchedTo::new("lancastr.com/", Default::default()).unwrap(),
//     //         generated_at: Utc::now(),
//     //         jwt_secret: vec![],
//     //         auth_type: AuthProviderConfig::Oauth2(Oauth2SsoClient {
//     //             provider: Oauth2Provider::Google,
//     //         }),
//     //         rate_limiter: None,
//     //     };
//     //
//     //     assert_eq!(
//     //         Url::parse("https://lancastr.com:5567/to/newurl/path").unwrap(),
//     //         mapping
//     //             .handle(
//     //                 UrlForRewriting::from_components("example.exg.co", "/from/url/path", "")
//     //                     .unwrap(),
//     //                 ClientTunnels::new(),
//     //                 443,
//     //                 Protocol::Http,
//     //             )
//     //             .unwrap()
//     //             .0
//     //             .rewrite_to_url()
//     //     )
//     // }
//
//     // #[test]
//     // pub fn websockets_rewrite() {
//     //     let mapping = Mapping {
//     //         match_pattern: MatchPattern::new("example.exg.co", "/from").unwrap(),
//     //         proxy_matched_to: ProxyMatchedTo::new("lancastr.com/to", Default::default()).unwrap(),
//     //         generated_at: Utc::now(),
//     //         jwt_secret: vec![],
//     //         auth_type: AuthProviderConfig::Oauth2(Oauth2SsoClient {
//     //             provider: Oauth2Provider::Google,
//     //         }),
//     //         rate_limiter: None,
//     //     };
//     //
//     //     assert_eq!(
//     //         Url::parse("wss://lancastr.com/to/path").unwrap(),
//     //         mapping
//     //             .handle(
//     //                 UrlForRewriting::from_components("example.exg.co", "/from/path", "").unwrap(),
//     //                 ClientTunnels::new(),
//     //                 443,
//     //                 Protocol::WebSockets,
//     //             )
//     //             .unwrap()
//     //             .0
//     //             .rewrite_to_url()
//     //     )
//     // }
//
//     // #[test]
//     // pub fn rewrite_tls_to_plain() {
//     //     let mapping = Mapping {
//     //         match_pattern: MatchPattern::new("example.exg.co", "/from").unwrap(),
//     //         proxy_matched_to: ProxyMatchedTo::new("lancastr.com/to", Default::default()).unwrap(),
//     //         generated_at: Utc::now(),
//     //         jwt_secret: vec![],
//     //         auth_type: AuthProviderConfig::Oauth2(Oauth2SsoClient {
//     //             provider: Oauth2Provider::Google,
//     //         }),
//     //         rate_limiter: None,
//     //     };
//     //
//     //     assert_eq!(
//     //         Url::parse("http://lancastr.com/to/path").unwrap(),
//     //         mapping
//     //             .handle(
//     //                 UrlForRewriting::from_components("example.exg.co", "/from/path", "").unwrap(),
//     //                 ClientTunnels::new(),
//     //                 443,
//     //                 Protocol::Http,
//     //             )
//     //             .unwrap()
//     //             .0
//     //             .rewrite_to_url()
//     //     );
//     //
//     //     assert_eq!(
//     //         Url::parse("ws://lancastr.com/to/path").unwrap(),
//     //         mapping
//     //             .handle(
//     //                 UrlForRewriting::from_components("example.exg.co", "/from/path", "").unwrap(),
//     //                 ClientTunnels::new(),
//     //                 443,
//     //                 Protocol::WebSockets,
//     //             )
//     //             .unwrap()
//     //             .0
//     //             .rewrite_to_url()
//     //     );
//     // }
//
//     // #[test]
//     // pub fn rewrite_plain_to_tls() {
//     //     let mapping = Mapping {
//     //         match_pattern: MatchPattern::new("example.exg.co", "/from").unwrap(),
//     //         proxy_matched_to: ProxyMatchedTo::new("lancastr.com/to", Default::default()).unwrap(),
//     //         generated_at: Utc::now(),
//     //         jwt_secret: vec![],
//     //         auth_type: AuthProviderConfig::Oauth2(Oauth2SsoClient {
//     //             provider: Oauth2Provider::Google,
//     //         }),
//     //         rate_limiter: None,
//     //     };
//     //
//     //     assert_eq!(
//     //         Url::parse("https://lancastr.com/to/path").unwrap(),
//     //         mapping
//     //             .handle(
//     //                 UrlForRewriting::from_components("example.exg.co", "/from/path", "").unwrap(),
//     //                 ClientTunnels::new(),
//     //                 443,
//     //                 Protocol::Http,
//     //             )
//     //             .unwrap()
//     //             .0
//     //             .rewrite_to_url()
//     //     );
//     //
//     //     assert_eq!(
//     //         Url::parse("wss://lancastr.com/to/path").unwrap(),
//     //         mapping
//     //             .handle(
//     //                 UrlForRewriting::from_components("example.exg.co", "/from/path", "").unwrap(),
//     //                 ClientTunnels::new(),
//     //                 443,
//     //                 Protocol::WebSockets,
//     //             )
//     //             .unwrap()
//     //             .0
//     //             .rewrite_to_url()
//     //     );
//     // }
// }
