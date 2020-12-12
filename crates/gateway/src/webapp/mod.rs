use std::time::Duration;

use crate::clients::ClientTunnels;
use crate::http_serve::{auth, RequestsProcessor};
use crate::registry::RequestsProcessorsRegistry;
use crate::rules_counter::AccountRulesCounters;
use crate::urls::matchable_url::MatchableUrl;
use chrono::serde::ts_milliseconds;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use exogress_common_utils::jwt::{jwt_token, JwtError};
use exogress_config_core::{ClientConfig, ClientConfigRevision, ProjectConfig};
use exogress_entities::{
    AccessKeyId, AccountName, AccountUniqueId, ConfigName, InstanceId, MountPointName, ProjectName,
    Upstream,
};
use exogress_server_common::url_prefix::MountPointBaseUrl;
use futures_intrusive::sync::ManualResetEvent;
use hashbrown::HashMap;
use http::StatusCode;
use lru_time_cache::LruCache;
use percent_encoding::NON_ALPHANUMERIC;
use reqwest::Identity;
use smallvec::SmallVec;
use smol_str::SmolStr;
use std::sync::Arc;
use tokio::time::timeout;
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
    maybe_identity: Option<Vec<u8>>,

    public_gw_base_url: Url,

    rules_counters: AccountRulesCounters,
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
    pub account_unique_id: AccountUniqueId,
}

#[derive(Deserialize, Clone, Debug)]
pub struct AuthorizeTunnelResponse {
    pub account_unique_id: AccountUniqueId,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("request error: `{0}`")]
    Reqwest(#[from] reqwest::Error),

    #[error("bad response")]
    BadResponse,

    #[error("not found")]
    NotFound,

    #[error("forbidden")]
    Forbidden,

    #[error("JWT token Error: `{0}`")]
    JwtError(#[from] JwtError),

    #[error("URL prefix error: `{0}`")]
    Url(#[from] url::ParseError),

    #[error("Could not retrieve URL")]
    CouldNotRetrieve,
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
pub struct ConfigData {
    pub instance_ids: HashMap<InstanceId, HashMap<Upstream, bool>>,
    pub config: ClientConfig,
    pub revision: ClientConfigRevision,
    pub config_name: ConfigName,
}

#[derive(Deserialize, Clone, Debug)]
pub struct JwtEcdsaResponse {
    pub private_key: String,
    pub public_key: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ConfigsResponse {
    #[serde(with = "ts_milliseconds")]
    pub generated_at: DateTime<Utc>,
    pub url_prefix: MountPointBaseUrl,
    pub account: AccountName,
    pub account_unique_id: AccountUniqueId,
    pub project: ProjectName,
    pub mount_point: MountPointName,
    pub project_config: ProjectConfig,
    pub configs: SmallVec<[ConfigData; 8]>,
    pub jwt_ecdsa: JwtEcdsaResponse,
}

impl Client {
    pub fn new(
        ttl: Duration,
        rules_counters: AccountRulesCounters,
        base_url: Url,
        google_oauth2_client: auth::google::GoogleOauth2Client,
        github_oauth2_client: auth::github::GithubOauth2Client,
        assistant_base_url: Url,
        public_gw_base_url: &Url,
        maybe_identity: Option<Vec<u8>>,
    ) -> Self {
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
                LruCache::with_expiry_duration_and_capacity(ttl, 1024),
            )),
            google_oauth2_client,
            github_oauth2_client,
            assistant_base_url,
            maybe_identity,
            public_gw_base_url: public_gw_base_url.clone(),
            rules_counters,
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
            Err(Error::BadResponse)
        }
    }

    pub async fn resolve_url(
        &self,
        matchable_url: MatchableUrl,
        tunnels: ClientTunnels,
        individual_hostname: SmolStr,
    ) -> Result<
        Option<(
            Arc<RequestsProcessor>,
            // RateLimiters,
            MountPointBaseUrl,
        )>,
        Error,
    > {
        // Try to read from cache
        if let Some((cached, mount_point_base_path)) =
            self.requests_processors_registry.resolve(&matchable_url)
        //, tunnels.clone(), external_port, proto)
        {
            match cached {
                Some(data) => {
                    // mapping exist
                    return Ok(Some((data, mount_point_base_path)));
                }
                None => {
                    return Ok(None);
                }
            }
        }

        // no info in cache
        info!("No data in cache for {}", matchable_url);

        let host = matchable_url.host();

        // take lock and deal with in_flight queries
        let in_flight_request = self
            .retrieve_configs
            .entry(host.clone().into())
            .or_insert_with({
                shadow_clone!(matchable_url);

                let base_url = self.webapp_base_url.clone();
                let reqwest = self.reqwest.clone();
                let google_oauth2_client = self.google_oauth2_client.clone();
                let github_oauth2_client = self.github_oauth2_client.clone();
                let assistant_base_url = self.assistant_base_url.clone();
                let maybe_identity = self.maybe_identity.clone();
                let public_gw_base_url = self.public_gw_base_url.clone();
                let rules_counters = self.rules_counters.clone();

                let requests_processors_registry = self.requests_processors_registry.clone();

                move || {
                    let ready_event = Arc::new(ManualResetEvent::new(false));

                    // initiate query
                    tokio::spawn({
                        shadow_clone!(ready_event);
                        shadow_clone!(reqwest);
                        shadow_clone!(base_url);
                        shadow_clone!(google_oauth2_client);
                        shadow_clone!(github_oauth2_client);
                        shadow_clone!(assistant_base_url);
                        shadow_clone!(maybe_identity);
                        shadow_clone!(public_gw_base_url);
                        shadow_clone!(rules_counters);

                        async move {
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
                                    "url={}",
                                    percent_encoding::utf8_percent_encode(
                                        format!("{}", matchable_url).as_str(),
                                        NON_ALPHANUMERIC,
                                    )
                                )
                                .as_str(),
                            ));

                            match reqwest.get(url).send().await {
                                Ok(res) => {
                                    if res.status().is_success() {
                                        match res.json::<ConfigsResponse>().await {
                                            Ok(configs_response) => {
                                                info!(
                                                    "Configs retrieved successfully: `{:?}`",
                                                    configs_response
                                                );

                                                let url_prefix =
                                                    configs_response.url_prefix.clone();
                                                let generated_at =
                                                    configs_response.generated_at.clone();

                                                let requests_processor = RequestsProcessor::new(
                                                    configs_response,
                                                    google_oauth2_client,
                                                    github_oauth2_client,
                                                    assistant_base_url,
                                                    tunnels,
                                                    rules_counters.clone(),
                                                    individual_hostname,
                                                    maybe_identity,
                                                )
                                                .expect("FIXME");

                                                requests_processors_registry.upsert(
                                                    &url_prefix,
                                                    Some(requests_processor),
                                                    &generated_at,
                                                );
                                            }
                                            Err(e) => {
                                                error!(
                                                    "Could not parse retrieved config body: {}",
                                                    e
                                                );
                                            }
                                        }
                                    } else if res.status() == StatusCode::NOT_FOUND {
                                        requests_processors_registry.upsert(
                                            &matchable_url.to_url_prefix(),
                                            None,
                                            &Utc::now(), //FIXME: return generated_at in 404 resp
                                        );
                                    } else {
                                        error!(
                                            "Bad status on configs retrieving: {}",
                                            res.status()
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!("Error retrieving configs: {}", e);
                                }
                            }

                            ready_event.set();
                        }
                    });
                    ready_event
                }
            })
            .clone();

        let _ = timeout(Duration::from_secs(20), in_flight_request.wait()).await;

        if let dashmap::mapref::entry::Entry::Occupied(entry) =
            self.retrieve_configs.entry(host.into())
        {
            if Arc::ptr_eq(entry.get(), &in_flight_request) {
                // we are now sure that it's the same request
                entry.remove_entry();
            }
        }

        if let Some((cached, url_prefix)) =
            self.requests_processors_registry.resolve(&matchable_url)
        {
            Ok(cached.map(|a| (a, url_prefix)))
        } else {
            error!("Still can't resolve after successful reset event happened");
            Err(Error::CouldNotRetrieve)
        }
    }

    pub fn forget_certificate(&self, domain: String) {
        self.certificates.lock().remove(&domain);
    }

    pub async fn get_certificate(
        &self,
        domain: String,
    ) -> Result<Option<CertificateResponse>, Error> {
        let cached_cert = self.certificates.lock().get(&domain).cloned();

        let reset_event = match cached_cert {
            Some(CertificateRetrievalState::Found(resp)) => {
                return Ok(Some(resp));
            }
            Some(CertificateRetrievalState::NotExist) => {
                return Ok(None);
            }
            Some(CertificateRetrievalState::InFlight(evt)) => evt,
            None => {
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
                        match client.retrieve_certificate(&domain).await {
                            Ok(certs) => {
                                certificates.lock().insert(
                                    domain,
                                    CertificateRetrievalState::Found(certs.clone()),
                                );
                            }
                            Err(_e) => {
                                certificates
                                    .lock()
                                    .insert(domain, CertificateRetrievalState::NotExist);
                            }
                        }

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

    async fn retrieve_certificate(&self, domain: &str) -> Result<CertificateResponse, Error> {
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
            Err(Error::NotFound)
        } else {
            Err(Error::BadResponse)
        }
    }

    pub async fn authorize_tunnel(
        &self,
        project_name: &ProjectName,
        instance_id: &InstanceId,
        access_key_id: &AccessKeyId,
        secret_access_key: &str,
    ) -> Result<AuthorizeTunnelResponse, Error> {
        let mut url = self.webapp_base_url.clone();
        url.path_segments_mut()
            .unwrap()
            .push("int_api")
            .push("v1")
            .push("tunnels")
            .push("auth");

        url.query_pairs_mut()
            .append_pair("project", project_name.as_str())
            .append_pair("instance_id", &instance_id.to_string());

        let token = jwt_token(access_key_id, secret_access_key)?;

        let res = self
            .reqwest
            .post(url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if res.status().is_success() {
            Ok(res.json().await?)
        } else if res.status() == http::StatusCode::FORBIDDEN {
            Err(Error::Forbidden)
        } else {
            Err(Error::BadResponse)
        }
    }
}
