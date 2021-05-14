use crate::{
    clients::{traffic_counter::RecordedTrafficStatistics, ClientTunnels},
    http_serve::{auth, cache::Cache, RequestsProcessor},
    registry::RequestsProcessorsRegistry,
    rules_counter::AccountCounters,
    urls::matchable_url::MatchableUrl,
};
use byte_unit::Byte;
use chrono::{serde::ts_milliseconds, DateTime, Utc};
use dashmap::DashMap;
use exogress_common::{
    access_tokens::JwtError,
    config_core::{
        referenced::Parameter,
        refinable::{Refinable, RefinableSet},
        ClientConfig, ClientConfigRevision, ProjectConfig, Scope,
    },
    entities::{
        AccountName, AccountUniqueId, ConfigName, InstanceId, LabelName, LabelValue,
        MountPointName, ParameterName, ProfileName, ProjectName, ProjectUniqueId, Upstream,
    },
    tunnel::TunnelHello,
};
use exogress_server_common::{geoip::GeoipReader, logging::LogMessage, presence};
use futures::channel::mpsc;
use futures_intrusive::sync::ManualResetEvent;
use hashbrown::HashMap;
use http::StatusCode;
use lru_time_cache::LruCache;
use parking_lot::Mutex;
use percent_encoding::NON_ALPHANUMERIC;
use reqwest::Identity;
use smallvec::SmallVec;
use smol_str::SmolStr;
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;

#[derive(Clone)]
pub enum CertificateRetrievalState {
    NotExist,
    Found(CertificateResponse),
    InFlight(Arc<ManualResetEvent>),
}

#[derive(Clone)]
pub struct Client {
    reqwest: reqwest::Client,
    retrieve_configs: Arc<DashMap<String, Arc<ManualResetEvent>>>,
    certificates: Arc<parking_lot::Mutex<LruCache<String, CertificateRetrievalState>>>,
    requests_processors_registry: RequestsProcessorsRegistry,
    webapp_base_url: Url,

    google_oauth2_client: auth::google::GoogleOauth2Client,
    github_oauth2_client: auth::github::GithubOauth2Client,
    assistant_base_url: Url,
    transformer_base_url: Url,
    maybe_identity: Option<Vec<u8>>,

    gw_location: SmolStr,

    public_gw_base_url: Url,
    log_messages_tx: mpsc::UnboundedSender<LogMessage>,

    rules_counters: AccountCounters,

    tunnels_counters_tx: mpsc::Sender<RecordedTrafficStatistics>,
    public_counters_tx: mpsc::Sender<RecordedTrafficStatistics>,

    presence_client: presence::Client,

    dbip: Option<GeoipReader>,

    cache: Cache,
    resolver: TokioAsyncResolver,

    gcs_credentials_file: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct AcmeHttpChallengeVerificationResponse {
    pub content_type: String,
    pub file_content: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct CertificateResponse {
    pub certificate: String,
    pub private_key: String,
    pub account_name: AccountName,
    pub project_unique_id: ProjectUniqueId,
    pub account_unique_id: AccountUniqueId,
}

#[derive(Deserialize, Clone, Debug)]
pub struct AuthorizeTunnelResponse {
    pub account_unique_id: AccountUniqueId,
    pub project_unique_id: ProjectUniqueId,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("request error: `{0}`")]
    Reqwest(#[from] reqwest::Error),

    #[error("bad response: `{_0}`")]
    BadResponse(StatusCode),

    #[error("not found")]
    NotFound,

    #[error("forbidden")]
    Forbidden,

    #[error("JWT token Error: `{0}`")]
    JwtError(#[from] JwtError),

    #[error("URL prefix error: `{0}`")]
    Url(#[from] url::ParseError),

    #[error("could not retrieve URL")]
    CouldNotRetrieve,

    #[error("config error")]
    ConfigError,
}

#[derive(thiserror::Error, Debug)]
pub enum CertificateRetrievalError {
    #[error("request error: `{0}`")]
    Reqwest(#[from] reqwest::Error),

    #[error("bad response: `{_0}`")]
    BadResponse(StatusCode),

    #[error("not found")]
    NotFound,
}

#[derive(Debug, Serialize)]
pub struct AcmeHttpChallengeVerificationQueryParams {
    domain: String,
    filename: String,
}

// #[derive(thiserror::Error, Debug)]
// pub enum MappingConversionError {
//     #[error("url prefix parse error")]
//     UrlForRewritingParse(#[from] url::ParseError),
//
//     // #[error("no JWT Secret")]
//     // NoJwtSecret,
//     //
//     // #[error("unsupported JWT kind {0}")]
//     // UnsupportedJwtKind(i32),
//     #[error("timestamp conversion error")]
//     TimestampError,
//
//     #[error("generated_at field not provided")]
//     GeneratedAtNotProvided,
//
//     #[error("replenish_one_per is empty in rate limiter")]
//     RateLimiterReplenishIntervalEmpty,
//
//     #[error("replenish_one_per can't convert duration")]
//     RateLimiterReplenishIntervalConversionError,
//
//     #[error("bad auth config")]
//     BadAuthConfig,
//
//     #[error("unknown oauth2 provider: `{0}`")]
//     UnknownOauth2Provider(i32),
//
//     #[error("bad auth providers count: `{0}`")]
//     BadProvidersCount(usize),
//
//     #[error("match pattern error: `{0}`")]
//     MatchPatter(#[from] MatchPatternError),
//
//     #[error("rewrite_matched_to error: `{0}`")]
//     RewriteMatchedTo(#[from] RewriteMatchedToError),
// }

#[derive(Deserialize, Clone, Debug)]
pub struct InstanceInfo {
    pub upstreams: HashMap<Upstream, bool>,
    pub labels: HashMap<LabelName, LabelValue>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ConfigData {
    pub instances: HashMap<InstanceId, InstanceInfo>,
    pub config: ClientConfig,
    pub revision: ClientConfigRevision,
    pub config_name: ConfigName,
    pub active_profile: Option<ProfileName>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct JwtEcdsaResponse {
    pub private_key: String,
    pub public_key: String,
}

fn default_as_true() -> bool {
    true
}

#[derive(Deserialize, Clone, Debug)]
pub struct ConfigsResponse {
    pub strict_transport_security: Option<u64>,
    #[serde(default = "default_as_true")]
    pub is_active: bool,
    #[serde(with = "ts_milliseconds")]
    pub generated_at: DateTime<Utc>,
    pub fqdn: String,
    pub account: AccountName,
    pub account_unique_id: AccountUniqueId,
    pub project_unique_id: ProjectUniqueId,
    pub project: ProjectName,
    pub mount_point: MountPointName,
    pub project_config: ProjectConfig,
    pub configs: SmallVec<[ConfigData; 8]>,
    pub jwt_ecdsa: JwtEcdsaResponse,
    pub xchacha20poly1305_secret_key: String,
    pub max_pop_cache_size_bytes: Byte,
    pub params: HashMap<ParameterName, Parameter>,
    pub is_transformations_limited: bool,
}

impl ConfigsResponse {
    pub(crate) fn refinable(&self) -> RefinableSet {
        let mut refinable_set = RefinableSet::new();

        refinable_set
            .add(Scope::ProjectConfig, &self.project_config.refinable)
            .unwrap();
        for (mount_point_name, mount) in &self.project_config.mount_points {
            refinable_set
                .add(
                    Scope::ProjectMount {
                        mount_point: mount_point_name.clone(),
                    },
                    &mount.refinable,
                )
                .unwrap();
            for (handler_name, handler) in &mount.handlers {
                refinable_set
                    .add(
                        Scope::ProjectHandler {
                            mount_point: mount_point_name.clone(),
                            handler: handler_name.clone(),
                        },
                        &handler.refinable,
                    )
                    .unwrap();
                for (rule_num, rule) in handler.rules.iter().enumerate() {
                    if let Some(rescue) = rule.action.rescue() {
                        refinable_set
                            .add(
                                Scope::ProjectRule {
                                    mount_point: mount_point_name.clone(),
                                    handler: handler_name.clone(),
                                    rule_num,
                                },
                                &Refinable {
                                    static_responses: Default::default(),
                                    rescue: rescue.clone(),
                                },
                            )
                            .unwrap();
                    }
                }
            }
        }

        for config_data in &self.configs {
            refinable_set
                .add(
                    Scope::ClientConfig {
                        config: config_data.config_name.clone(),
                        revision: config_data.config.revision,
                    },
                    &config_data.config.refinable,
                )
                .unwrap();
            for (mount_point_name, mount) in &config_data.config.mount_points {
                refinable_set
                    .add(
                        Scope::ClientMount {
                            config: config_data.config_name.clone(),
                            revision: config_data.config.revision,
                            mount_point: mount_point_name.clone(),
                        },
                        &mount.refinable,
                    )
                    .unwrap();
                for (handler_name, handler) in &mount.handlers {
                    refinable_set
                        .add(
                            Scope::ClientHandler {
                                config: config_data.config_name.clone(),
                                revision: config_data.config.revision,
                                mount_point: mount_point_name.clone(),
                                handler: handler_name.clone(),
                            },
                            &handler.refinable,
                        )
                        .unwrap();
                    for (rule_num, rule) in handler.rules.iter().enumerate() {
                        if let Some(rescue) = rule.action.rescue() {
                            refinable_set
                                .add(
                                    Scope::ClientRule {
                                        config: config_data.config_name.clone(),
                                        revision: config_data.config.revision,
                                        mount_point: mount_point_name.clone(),
                                        handler: handler_name.clone(),
                                        rule_num,
                                    },
                                    &Refinable {
                                        static_responses: Default::default(),
                                        rescue: rescue.clone(),
                                    },
                                )
                                .unwrap();
                        }
                    }
                }
            }
        }

        refinable_set
    }
}

impl Client {
    pub fn new(
        ttl: Duration,
        rules_counters: AccountCounters,
        tunnels_counters_tx: mpsc::Sender<RecordedTrafficStatistics>,
        public_counters_tx: mpsc::Sender<RecordedTrafficStatistics>,
        base_url: Url,
        google_oauth2_client: auth::google::GoogleOauth2Client,
        github_oauth2_client: auth::github::GithubOauth2Client,
        assistant_base_url: Url,
        transformer_base_url: Url,
        public_gw_base_url: &Url,
        gw_location: SmolStr,
        gcs_credentials_file: String,
        log_messages_tx: mpsc::UnboundedSender<LogMessage>,
        maybe_identity: Option<Vec<u8>>,
        cache: Cache,
        dbip: Option<GeoipReader>,
        resolver: TokioAsyncResolver,
    ) -> Self {
        let presence_client = presence::Client::new(
            base_url.clone(),
            "FIXME: not provided".to_string(),
            maybe_identity.clone(),
        );

        let mut builder = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .use_rustls_tls()
            .trust_dns(true);

        if let Some(identity) = &maybe_identity {
            builder = builder.identity(Identity::from_pem(identity).unwrap());
        }

        Client {
            requests_processors_registry: RequestsProcessorsRegistry::new(ttl),
            reqwest: builder.build().unwrap(),
            retrieve_configs: Arc::new(Default::default()),
            webapp_base_url: base_url,
            certificates: Arc::new(parking_lot::Mutex::new(
                LruCache::with_expiry_duration_and_capacity(ttl, 65536),
            )),
            google_oauth2_client,
            github_oauth2_client,
            assistant_base_url,
            transformer_base_url,
            maybe_identity,
            gw_location,
            public_gw_base_url: public_gw_base_url.clone(),
            log_messages_tx,
            rules_counters,
            tunnels_counters_tx,
            public_counters_tx,
            presence_client,
            cache,
            dbip,
            resolver,
            gcs_credentials_file,
        }
    }

    pub fn mappings(&self) -> RequestsProcessorsRegistry {
        self.requests_processors_registry.clone()
    }

    pub async fn acme_http_challenge_verification(
        &self,
        domain: &str,
        path: &str,
    ) -> Result<AcmeHttpChallengeVerificationResponse, Error> {
        let mut url = self.webapp_base_url.clone();
        url.path_segments_mut()
            .unwrap()
            .push("int_api")
            .push("v1")
            .push("acme_http_challenge_verification");

        let rec_params = serde_qs::to_string(&AcmeHttpChallengeVerificationQueryParams {
            domain: domain.into(),
            filename: path.into(),
        })
        .unwrap();

        url.set_query(Some(rec_params.as_str()));

        let res = self.reqwest.get(url).send().await?;

        if res.status().is_success() {
            Ok(res.json().await?)
        } else if res.status() == http::StatusCode::NOT_FOUND {
            Err(Error::NotFound)
        } else {
            Err(Error::BadResponse(res.status()))
        }
    }

    pub async fn resolve_url(
        &self,
        matchable_url: MatchableUrl,
        tunnels: ClientTunnels,
        individual_hostname: SmolStr,
    ) -> Result<Option<Arc<RequestsProcessor>>, Error> {
        let cache = self.cache.clone();
        let resolver = self.resolver.clone();
        let public_counters_tx = self.public_counters_tx.clone();

        // Try to read from cache
        if let Some(maybe_cached) = self
            .requests_processors_registry
            .resolve(matchable_url.host().as_str())
        {
            crate::statistics::CONFIGS_CACHE_HIT.inc();

            match maybe_cached {
                Some(data) => {
                    // mapping exist
                    return Ok(Some(data));
                }
                None => {
                    return Ok(None);
                }
            }
        }

        // no info in cache
        info!("No data in cache for {}", matchable_url);
        crate::statistics::CONFIGS_CACHE_MISS.inc();

        let host = matchable_url.host();
        let config_error = Arc::new(Mutex::new(None));
        let gw_location = self.gw_location.clone();

        // take lock and deal with in_flight queries
        let in_flight_request = self
            .retrieve_configs
            .entry(host.clone())
            .or_insert_with({
                shadow_clone!(matchable_url, config_error, gw_location);

                let base_url = self.webapp_base_url.clone();
                let reqwest = self.reqwest.clone();
                let google_oauth2_client = self.google_oauth2_client.clone();
                let github_oauth2_client = self.github_oauth2_client.clone();
                let assistant_base_url = self.assistant_base_url.clone();
                let transformer_base_url = self.transformer_base_url.clone();
                let maybe_identity = self.maybe_identity.clone();
                let rules_counters = self.rules_counters.clone();
                let presence_client = self.presence_client.clone();
                let log_messages_tx = self.log_messages_tx.clone();
                let dbip = self.dbip.clone();
                let gcs_credentials_file = self.gcs_credentials_file.clone();

                let requests_processors_registry = self.requests_processors_registry.clone();

                move || {
                    let ready_event = Arc::new(ManualResetEvent::new(false));

                    // initiate query
                    tokio::spawn({
                        shadow_clone!(gcs_credentials_file, ready_event, reqwest, base_url, google_oauth2_client, github_oauth2_client, assistant_base_url, transformer_base_url, maybe_identity, rules_counters, config_error, cache, presence_client, dbip);

                        async move {
                            let retrieval_started_at = crate::statistics::CONFIGS_RETRIEVAL_TIME.start_timer();

                            info!(
                                "Initiating new request to retrieve mapping for {}",
                                matchable_url
                            );

                            let mut url = base_url.clone();
                            url.path_segments_mut()
                                .unwrap()
                                .push("int_api")
                                .push("v1")
                                .push("configs");

                            url.set_query(Some(
                                format!(
                                    "fqdn={}",
                                    percent_encoding::utf8_percent_encode(
                                        matchable_url.host().as_str(),
                                        NON_ALPHANUMERIC,
                                    )
                                )
                                .as_str(),
                            ));

                            match reqwest.get(url).send().await {
                                Ok(res) => {
                                    let status = res.status();
                                    if status.is_success() {
                                        match res.json::<ConfigsResponse>().await {
                                            Ok(configs_response) => {
                                                info!(
                                                    "Configs retrieved successfully: `{:?}`",
                                                    configs_response
                                                );

                                                crate::statistics::CONFIGS_RETRIEVAL_SUCCESS.inc();

                                                let fqdn =
                                                    configs_response.fqdn.clone();
                                                let generated_at =
                                                    configs_response.generated_at;

                                                let requests_processor =
                                                    match RequestsProcessor::new(
                                                        configs_response,
                                                        google_oauth2_client,
                                                        github_oauth2_client,
                                                        gcs_credentials_file,
                                                        assistant_base_url,
                                                        transformer_base_url,
                                                        tunnels,
                                                        rules_counters.clone(),
                                                        individual_hostname,
                                                        maybe_identity,
                                                        public_counters_tx.clone(),
                                                        log_messages_tx,
                                                        &gw_location,
                                                        cache,
                                                        presence_client.clone(),
                                                        dbip.clone(),
                                                        resolver,
                                                    ) {
                                                        Ok(rp) => rp,
                                                        Err(e) => {
                                                            error!("Error creating RequestsProcessor: {}", e);
                                                            crate::statistics::CONFIGS_PROCESSING_ERRORS.inc();
                                                            *config_error.lock() = Some(e);
                                                            return;
                                                        }
                                                    };

                                                requests_processors_registry.upsert(
                                                    &fqdn,
                                                    Some(requests_processor),
                                                    &generated_at,
                                                );
                                            }
                                            Err(e) => {
                                                crate::statistics::CONFIGS_RETRIEVAL_ERROR
                                                    .with_label_values(&[
                                                        crate::statistics::HTTP_ERROR_BAD_RESPONSE,
                                                        &status.as_u16().to_string(),
                                                    ])
                                                    .inc();
                                                error!(
                                                    "Could not parse retrieved config body: {}",
                                                    e
                                                );
                                            }
                                        }
                                    } else if status == StatusCode::NOT_FOUND {
                                        crate::statistics::CONFIGS_RETRIEVAL_SUCCESS.inc();
                                        requests_processors_registry.upsert(
                                            &matchable_url.host(),
                                            None,
                                            &Utc::now(), //FIXME: return generated_at in 404 resp
                                        );
                                    } else {
                                        crate::statistics::CONFIGS_RETRIEVAL_ERROR
                                            .with_label_values(&[
                                                crate::statistics::HTTP_ERROR_BAD_STATUS,
                                                &res.status().as_u16().to_string(),
                                            ])
                                            .inc();
                                        error!(
                                            "Bad status on configs retrieving: {}",
                                            res.status()
                                        );
                                    }
                                }
                                Err(e) => {
                                    crate::statistics::CONFIGS_RETRIEVAL_ERROR
                                        .with_label_values(&[
                                            crate::statistics::HTTP_ERROR_REQUEST_ERROR,
                                            "",
                                        ])
                                        .inc();
                                    error!("Error retrieving configs: {}", e);
                                }
                            }

                            retrieval_started_at.observe_duration();

                            ready_event.set();
                        }
                    });
                    ready_event
                }
            })
            .clone();

        let _ = timeout(Duration::from_secs(20), in_flight_request.wait()).await;

        if config_error.lock().is_some() {
            error!("Error in received config");
            return Err(Error::ConfigError);
        }

        if let dashmap::mapref::entry::Entry::Occupied(entry) = self.retrieve_configs.entry(host) {
            if Arc::ptr_eq(entry.get(), &in_flight_request) {
                // we are now sure that it's the same request
                entry.remove_entry();
            }
        }

        if let Some(cached) = self
            .requests_processors_registry
            .resolve(matchable_url.host().as_str())
        {
            Ok(cached)
        } else {
            error!("Still can't resolve after successful reset event happened");
            Err(Error::CouldNotRetrieve)
        }
    }

    pub fn forget_certificate(&self, domain: String) {
        crate::statistics::CERTIFICATES_FORGOTTEN.inc();
        self.certificates.lock().remove(&domain);
    }

    pub async fn get_certificate(
        &self,
        domain: String,
    ) -> Result<Option<CertificateResponse>, Error> {
        let cached_cert = self.certificates.lock().get(&domain).cloned();

        let reset_event = match cached_cert {
            Some(CertificateRetrievalState::Found(resp)) => {
                crate::statistics::CERTIFICATES_CACHE_HIT.inc();
                return Ok(Some(resp));
            }
            Some(CertificateRetrievalState::NotExist) => {
                crate::statistics::CERTIFICATES_CACHE_HIT.inc();
                return Ok(None);
            }
            Some(CertificateRetrievalState::InFlight(evt)) => evt,
            None => {
                crate::statistics::CERTIFICATES_CACHE_MISS.inc();
                let evt = Arc::new(ManualResetEvent::new(false));

                self.certificates.lock().insert(
                    domain.clone(),
                    CertificateRetrievalState::InFlight(evt.clone()),
                );

                tokio::spawn({
                    shadow_clone!(evt);
                    let certificates = self.certificates.clone();
                    let client = self.clone();
                    let domain = domain.clone();

                    async move {
                        let start_retrieval =
                            crate::statistics::CERTIFICATES_RETRIEVAL_TIME.start_timer();

                        match client.retrieve_certificate(&domain).await {
                            Ok(certs) => {
                                crate::statistics::CERTIFICATES_RETRIEVAL_SUCCESS.inc();

                                certificates
                                    .lock()
                                    .insert(domain, CertificateRetrievalState::Found(certs));
                            }
                            Err(e) => {
                                match e {
                                    CertificateRetrievalError::NotFound => {
                                        crate::statistics::CERTIFICATES_RETRIEVAL_SUCCESS.inc();
                                    }
                                    CertificateRetrievalError::Reqwest(_) => {
                                        crate::statistics::CERTIFICATES_RETRIEVAL_ERROR
                                            .with_label_values(&[
                                                crate::statistics::HTTP_ERROR_BAD_RESPONSE,
                                                "",
                                            ])
                                            .inc();
                                    }
                                    CertificateRetrievalError::BadResponse(status) => {
                                        crate::statistics::CERTIFICATES_RETRIEVAL_ERROR
                                            .with_label_values(&[
                                                crate::statistics::HTTP_ERROR_BAD_STATUS,
                                                &status.as_u16().to_string(),
                                            ])
                                            .inc();
                                    }
                                }
                                certificates
                                    .lock()
                                    .insert(domain, CertificateRetrievalState::NotExist);
                            }
                        }

                        start_retrieval.observe_duration();

                        evt.set();
                    }
                });

                evt
            }
        };

        let _ = timeout(Duration::from_secs(20), reset_event.wait()).await;

        match self.certificates.lock().get(&domain).cloned() {
            Some(CertificateRetrievalState::Found(resp)) => Ok(Some(resp)),
            _ => Ok(None),
        }
    }

    async fn retrieve_certificate(
        &self,
        domain: &str,
    ) -> Result<CertificateResponse, CertificateRetrievalError> {
        let mut url = self.webapp_base_url.clone();
        url.path_segments_mut()
            .unwrap()
            .push("int_api")
            .push("v1")
            .push("domains")
            .push(domain)
            .push("certificate");

        let res = self.reqwest.get(url).send().await?;

        if res.status().is_success() {
            Ok(res.json().await?)
        } else if res.status() == http::StatusCode::NOT_FOUND {
            Err(CertificateRetrievalError::NotFound)
        } else {
            Err(CertificateRetrievalError::BadResponse(res.status()))
        }
    }

    pub async fn authorize_tunnel(
        &self,
        tunnel_hello: &TunnelHello,
    ) -> Result<AuthorizeTunnelResponse, Error> {
        let mut url = self.webapp_base_url.clone();
        url.path_segments_mut()
            .unwrap()
            .push("int_api")
            .push("v1")
            .push("tunnels")
            .push("auth");

        url.query_pairs_mut()
            .append_pair("project", tunnel_hello.project_name.as_str())
            .append_pair("instance_id", &tunnel_hello.instance_id.to_string());

        let res = self
            .reqwest
            .post(url)
            .header(
                "Authorization",
                format!("Bearer {}", tunnel_hello.jwt_token),
            )
            .send()
            .await?;

        if res.status().is_success() {
            Ok(res.json().await?)
        } else if res.status() == http::StatusCode::FORBIDDEN {
            Err(Error::Forbidden)
        } else {
            Err(Error::BadResponse(res.status()))
        }
    }
}
