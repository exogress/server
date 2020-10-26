use std::time::Duration;

use crate::clients::ClientTunnels;
use crate::url_mapping::handlers::HandlersProcessor;
use crate::url_mapping::mapping::{
    HealthStorage, Mapping, MappingAction, Protocol, UrlForRewriting,
};
use crate::url_mapping::rate_limiter::RateLimiters;
use crate::url_mapping::registry::Configs;
use chrono::serde::ts_milliseconds;
use chrono::{DateTime, Utc};
use exogress_config_core::{ClientConfig, ClientConfigRevision, ProjectConfig};
use exogress_entities::{AccountName, ConfigName, InstanceId, MountPointName, ProjectName};
use exogress_server_common::assistant::UpstreamReport;
use exogress_server_common::url_prefix::UrlPrefix;
use futures::channel::mpsc;
use futures_intrusive::sync::ManualResetEvent;
use hashbrown::hash_map::Entry;
use hashbrown::HashMap;
use http::StatusCode;
use itertools::Itertools;
use lru_time_cache::LruCache;
use parking_lot::Mutex;
use percent_encoding::NON_ALPHANUMERIC;
use smallvec::SmallVec;
use std::sync::Arc;
use url::Url;

#[derive(Clone)]
pub struct Client {
    reqwest: reqwest::Client,
    retrieve_configs: Arc<Mutex<HashMap<String, Arc<ManualResetEvent>>>>,
    certificates: Arc<parking_lot::Mutex<LruCache<String, Option<CertificateResponse>>>>,
    configs: Configs,
    base_url: Url,
    health_state_change_tx: mpsc::Sender<UpstreamReport>,
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
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("request error: `{0}`")]
    Reqwest(#[from] reqwest::Error),

    #[error("bad response")]
    BadResponse,

    #[error("not found")]
    NotFound,

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
    pub instance_ids: SmallVec<[InstanceId; 4]>,
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
    pub url_prefix: UrlPrefix,
    pub account: AccountName,
    pub project: ProjectName,
    pub mount_point: MountPointName,
    pub project_config: ProjectConfig,
    pub configs: SmallVec<[ConfigData; 8]>,
    pub jwt_ecdsa: JwtEcdsaResponse,
}

impl Client {
    pub fn new(
        ttl: Duration,
        health_state_change_tx: mpsc::Sender<UpstreamReport>,
        base_url: Url,
    ) -> Self {
        Client {
            configs: Configs::new(ttl),
            reqwest: reqwest::ClientBuilder::new()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(10))
                .use_rustls_tls()
                .trust_dns(true)
                .build()
                .unwrap(),
            retrieve_configs: Arc::new(Default::default()),
            base_url,
            certificates: Arc::new(parking_lot::Mutex::new(
                LruCache::with_expiry_duration_and_capacity(ttl, 1024),
            )),
            health_state_change_tx,
        }
    }

    pub fn mappings(&self) -> Configs {
        self.configs.clone()
    }

    pub async fn acme_http_challenge_verification(
        &self,
        domain: &str,
        path: &str,
    ) -> Result<AcmeHttpChallengeVerificationResponse, Error> {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .unwrap()
            .push("int")
            .push("api")
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
        url_for_rewriting: UrlForRewriting,
        external_port: u16,
        proto: Protocol,
        tunnels: ClientTunnels,
        individual_hostname: String,
    ) -> Result<Option<(MappingAction, RateLimiters, UrlPrefix)>, Error> {
        // Try to read from cache
        if let Some((cached, url_prefix)) = self
            .configs
            .resolve(
                url_for_rewriting.clone(),
                tunnels.clone(),
                external_port,
                proto,
            )
            .await
        {
            match cached {
                Some((data, rate_limiters)) => {
                    // mapping exist
                    return Ok(Some((data, rate_limiters, url_prefix)));
                }
                None => {
                    return Ok(None);
                }
            }
        }

        // no info in cache
        info!("No data in cache for {}", url_for_rewriting);

        let host = url_for_rewriting.host();

        let health_state_change_tx = self.health_state_change_tx.clone();

        // take lock and deal with in_flight queries
        let in_flight_request = self
            .retrieve_configs
            .lock()
            .entry(host.clone().into())
            .or_insert_with({
                shadow_clone!(url_for_rewriting);
                shadow_clone!(tunnels);

                let base_url = self.base_url.clone();
                let reqwest = self.reqwest.clone();
                let configs = self.configs.clone();

                move || {
                    let ready_event = Arc::new(ManualResetEvent::new(false));

                    // initiate query
                    tokio::spawn({
                        shadow_clone!(ready_event);
                        shadow_clone!(tunnels);
                        shadow_clone!(reqwest);
                        shadow_clone!(base_url);

                        async move {
                            info!(
                                "Initiating new request to retrieve mapping for {}",
                                url_for_rewriting
                            );

                            let mut url = base_url.clone();
                            url.path_segments_mut()
                                .unwrap()
                                .push("int")
                                .push("api")
                                .push("v1")
                                .push("configs");

                            url.set_query(Some(
                                format!(
                                    "url={}",
                                    percent_encoding::utf8_percent_encode(
                                        format!("{}", url_for_rewriting).as_str(),
                                        NON_ALPHANUMERIC,
                                    )
                                )
                                    .as_str(),
                            ));

                            match reqwest.get(url).send().await {
                                Ok(res) => {
                                    if res.status().is_success() {
                                        match res.json::<ConfigsResponse>().await {
                                            Ok(config_response) => {
                                                info!(
                                                    "Configs retrieved successfully: `{:?}`",
                                                    config_response
                                                );

                                                let project = config_response.project.clone();
                                                let account = config_response.account.clone();

                                                let grouped = config_response
                                                    .configs
                                                    .iter()
                                                    .group_by(|elt| elt.config_name.clone());

                                                let static_responses = grouped
                                                    .into_iter()
                                                    .map(|(config_name, config_entries)| {
                                                        let config_entry = config_entries
                                                            .into_iter()
                                                            .sorted_by(|left, right| {
                                                                left.revision
                                                                    .cmp(&right.revision)
                                                                    .reverse()
                                                            })
                                                            .next() // Take last revision only
                                                            .expect("FIXME");

                                                        let prj_static_responses = config_response
                                                            .project_config
                                                            .mount_points
                                                            .values()
                                                            .next()
                                                            .map(|mp| {
                                                                mp
                                                                    .static_responses
                                                                    .iter()
                                                                    .map({
                                                                        move |(static_response_name, static_response_data)| {
                                                                            (
                                                                                static_response_name.clone(),
                                                                                static_response_data.clone().into(),
                                                                                // None,
                                                                            )
                                                                        }
                                                                    })
                                                            })
                                                            .into_iter()
                                                            .flatten();

                                                        config_entry
                                                            .config
                                                            .mount_points
                                                            .values()
                                                            .next()
                                                            .map(|mp| {
                                                                mp.static_responses
                                                                    .iter()
                                                                    .map(move |(static_response_name, static_response_data)| {
                                                                        (
                                                                            static_response_name.clone(),
                                                                            static_response_data.clone(),
                                                                            // Some((
                                                                            //     config_name.clone(),
                                                                            //     instances_ids.clone(),
                                                                            // )),
                                                                        )
                                                                    })
                                                            })
                                                            .into_iter()
                                                            .flatten()
                                                            .chain(prj_static_responses)
                                                    })
                                                    .flatten()
                                                    .collect();

                                                info!("static resps = {:#?}", static_responses);

                                                let grouped = config_response
                                                    .configs
                                                    .iter()
                                                    .group_by(|elt| elt.config_name.clone());
                                                let handlers = grouped
                                                    .into_iter()
                                                    .map(|(config_name, config_entries)| {
                                                        let config_entry = config_entries
                                                            .into_iter()
                                                            .sorted_by(|left, right| {
                                                                left.revision
                                                                    .cmp(&right.revision)
                                                                    .reverse()
                                                            })
                                                            .next() // Take last revision only
                                                            .expect("FIXME");

                                                        let instances_ids =
                                                            config_entry.instance_ids.clone();

                                                        let prj_handlers = config_response
                                                            .project_config
                                                            .mount_points
                                                            .values()
                                                            .next()
                                                            .map(|mp| {
                                                                mp
                                                                    .handlers
                                                                    .iter()
                                                                    .map({
                                                                        move |(handler_name, handler)| {
                                                                            (
                                                                                handler_name.clone(),
                                                                                handler.clone().into(),
                                                                                None,
                                                                            )
                                                                        }
                                                                    })
                                                            })
                                                            .into_iter()
                                                            .flatten();

                                                        config_entry
                                                            .config
                                                            .mount_points
                                                            .values()
                                                            .next()
                                                            .map(|mp| {
                                                                mp.handlers
                                                                    .iter()
                                                                    .map(move |(handler_name, handler)| {
                                                                        (
                                                                            handler_name.clone(),
                                                                            handler.clone(),
                                                                            Some((
                                                                                config_name.clone(),
                                                                                instances_ids.clone(),
                                                                            )),
                                                                        )
                                                                    })
                                                            })
                                                            .into_iter()
                                                            .flatten()
                                                            .chain(prj_handlers)
                                                    })
                                                    .flatten()
                                                    .collect::<Vec<_>>();

                                                let handlers_processor =
                                                    HandlersProcessor::new(handlers);
                                                info!("handlers = {:#?}", handlers_processor);

                                                let instances_health = HealthStorage::new(
                                                    &account,
                                                    &project,
                                                    health_state_change_tx
                                                );

                                                let mapping = Mapping::new(
                                                    config_response.clone(),
                                                    handlers_processor,
                                                    instances_health,
                                                    static_responses,
                                                RateLimiters::new(vec![
                                                        // RateLimiter::new(
                                                        //     "free_plan".parse().unwrap(),
                                                        //     RateLimiterKind::FailResponse,
                                                        //     governor::Quota::with_period(
                                                        //         Duration::from_millis(1),
                                                        //     )
                                                        //     .unwrap()
                                                        //     .allow_burst(
                                                        //         NonZeroU32::new(2500).unwrap(),
                                                        //     ),
                                                        // )
                                                    ]),
                                                    tunnels.clone(),
                                                    individual_hostname.clone().into(),
                                                );

                                                info!("mapping = {:?}", mapping);

                                                configs.upsert(
                                                    &config_response.url_prefix,
                                                    Some(mapping),
                                                    config_response.generated_at,
                                                ).await;
                                            }
                                            Err(e) => {
                                                error!(
                                                    "Could not parse retrieved config body: {}",
                                                    e
                                                );
                                            }
                                        }
                                    } else if res.status() == StatusCode::NOT_FOUND {
                                        configs.upsert(
                                            &url_for_rewriting.to_url_prefix(),
                                            None,
                                            Utc::now(), //FIXME: return generated_at in 404 resp
                                        ).await;
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

        in_flight_request.wait().await;

        {
            let mut cfg = self.retrieve_configs.lock();
            if let Entry::Occupied(entry) = cfg.entry(host.into()) {
                if Arc::ptr_eq(entry.get(), &in_flight_request) {
                    // we are now sure that it's the same request
                    entry.remove_entry();
                }
            }
        }

        if let Some((cached, url_prefix)) = self
            .configs
            .resolve(url_for_rewriting, tunnels, external_port, proto)
            .await
        {
            Ok(cached.map(|(a, b)| (a, b, url_prefix)))
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

        if let Some(certs) = cached_cert {
            info!("serve cert from cache");
            Ok(certs)
        } else {
            match self.retrieve_certificate(&domain).await {
                Ok(certs) => {
                    self.certificates.lock().insert(domain, Some(certs.clone()));
                    Ok(Some(certs))
                }
                Err(e) => {
                    warn!("error retrieving certificate for {}: {}", domain, e);
                    self.certificates.lock().insert(domain, None);
                    Ok(None)
                }
            }
        }
    }

    async fn retrieve_certificate(&self, domain: &str) -> Result<CertificateResponse, Error> {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .unwrap()
            .push("int")
            .push("api")
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
}
