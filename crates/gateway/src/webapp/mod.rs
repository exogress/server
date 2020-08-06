use std::time::Duration;

use crate::clients::ClientTunnels;
use crate::url_mapping;
use crate::url_mapping::mapping::{Mapping, MappingAction, Protocol, UrlForRewriting};
use crate::url_mapping::registry::Configs;
use crate::url_mapping::url_prefix::UrlPrefix;
use chrono::serde::ts_milliseconds;
use chrono::{DateTime, Utc};
use exogress_config_core::Config;
use exogress_entities::InstanceId;
use futures_intrusive::sync::ManualResetEvent;
use hashbrown::hash_map::Entry;
use hashbrown::HashMap;
use http::StatusCode;
use percent_encoding::NON_ALPHANUMERIC;
use smallvec::SmallVec;
use std::sync::Arc;
use url::Url;

#[derive(Clone)]
pub struct Client {
    reqwest: reqwest::Client,
    retrieve_configs: Arc<parking_lot::Mutex<HashMap<String, Arc<ManualResetEvent>>>>,
    retrieving_certs: Arc<parking_lot::Mutex<HashMap<String, Arc<ManualResetEvent>>>>,
    configs: Configs,
    base_url: String,
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
pub struct InstanceData {
    pub instance_id: InstanceId,
    pub config: Config,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ConfigsResponse {
    #[serde(with = "ts_milliseconds")]
    generated_at: DateTime<Utc>,
    instances: SmallVec<[InstanceData; 8]>,
    url_prefix: UrlPrefix,
}

impl url_mapping::mapping::Mapping {
    // pub fn try_from_message(mapping_schema: SchemaMapping) -> Result<Self, MappingConversionError> {
    //     let jwt_secret_message = mapping_schema
    //         .jwt_secret
    //         .ok_or(MappingConversionError::NoJwtSecret)?;
    //
    //     let rate_limiter = if let Some(rate_limiter) = mapping_schema.rate_limiter {
    //         let replenish_one_per = rate_limiter
    //             .replenish_one_per
    //             .ok_or(MappingConversionError::RateLimiterReplenishIntervalEmpty)?;
    //
    //         let mut quota = Quota::with_period(replenish_one_per.try_into().map_err(|_| {
    //             MappingConversionError::RateLimiterReplenishIntervalConversionError
    //         })?)
    //         .unwrap();
    //
    //         if rate_limiter.allow_max_burst > 0 {
    //             quota = quota.allow_burst(NonZeroU32::new(rate_limiter.allow_max_burst).unwrap());
    //         }
    //
    //         Some(Arc::new(Mutex::new(RateLimiter::direct_with_clock(
    //             quota,
    //             &MonotonicClock::default(),
    //         ))))
    //     } else {
    //         None
    //     };
    //
    //     match jwt_secret::Digest::from_i32(jwt_secret_message.kind) {
    //         Some(jwt_secret::Digest::Sha256) => {}
    //         _ => {
    //             return Err(MappingConversionError::UnsupportedJwtKind(
    //                 jwt_secret_message.kind,
    //             ));
    //         }
    //     }
    //
    //     let generated_at: DateTime<Utc> = SystemTime::try_from(
    //         mapping_schema
    //             .generated_at
    //             .ok_or(MappingConversionError::GeneratedAtNotProvided)?,
    //     )
    //     .map_err(|_| MappingConversionError::TimestampError)?
    //     .into();
    //
    //     let from_url_prefix: MatchPattern = mapping_schema.from_url_prefix.parse()?;
    //
    //     let auth_providers: Vec<_> = mapping_schema
    //         .auth_providers
    //         .into_iter()
    //         .map(|auth_provider| match auth_provider.config {
    //             Some(auth_provider_config::Config::Oauth2(auth_provider_config::Oauth2Sso {
    //                 provider,
    //             })) => match auth_provider_config::Oauth2Provider::from_i32(provider) {
    //                 Some(auth_provider_config::Oauth2Provider::Google) => {
    //                     Ok(AuthProviderConfig::Oauth2(Oauth2SsoClient {
    //                         provider: Oauth2Provider::Google,
    //                     }))
    //                 }
    //                 Some(auth_provider_config::Oauth2Provider::Github) => {
    //                     Ok(AuthProviderConfig::Oauth2(Oauth2SsoClient {
    //                         provider: Oauth2Provider::Github,
    //                     }))
    //                 }
    //                 _ => Err(MappingConversionError::UnknownOauth2Provider(provider)),
    //             },
    //             _ => Err(MappingConversionError::BadAuthConfig),
    //         })
    //         .collect::<Result<Vec<_>, _>>()?;
    //
    //     if auth_providers.len() != 1 {
    //         return Err(MappingConversionError::BadProvidersCount(
    //             auth_providers.len(),
    //         ));
    //     }
    //
    //     let auth_provider = auth_providers.into_iter().next();
    //
    //     Ok(url_mapping::mapping::Mapping {
    //         match_pattern: from_url_prefix,
    //         // proxy_matched_to: ProxyMatchedTo::new_exteral(
    //         //     &mapping_schema.to_url_prefix,
    //         //     mapping_schema.target_is_tls,
    //         // )?,
    //         proxy_matched_to: ProxyMatchedTo::new(
    //             &mapping_schema.to_url_prefix,
    //             ConfigName::zero(),
    //         )?,
    //         generated_at,
    //         jwt_secret: jwt_secret_message.secret_key,
    //         auth_type: auth_provider.unwrap(),
    //         rate_limiter,
    //     })
    // }
}

impl Client {
    pub fn new(ttl: Duration, base_url: String) -> Self {
        Client {
            configs: Configs::new(ttl),
            reqwest: reqwest::ClientBuilder::new()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(10))
                .use_rustls_tls()
                .trust_dns(true)
                .build()
                .unwrap(),
            retrieve_configs: Arc::new(parking_lot::Mutex::new(Default::default())),
            retrieving_certs: Arc::new(parking_lot::Mutex::new(Default::default())),
            base_url,
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
        let mut url = Url::parse(self.base_url.as_str()).unwrap();
        url.path_segments_mut()
            .unwrap()
            .push("int")
            .push("api")
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
        url_prefix: UrlForRewriting,
        external_port: u16,
        proto: Protocol,
        tunnels: ClientTunnels,
    ) -> Result<
        Option<(
            MappingAction,
            // Option<Arc<Mutex<RateLimiter<NotKeyed, InMemoryState, MonotonicClock>>>>,
        )>,
        Error,
    > {
        // Try to read from cache
        if let Some((cached, matched_prefix)) =
            self.configs
                .resolve(url_prefix.clone(), tunnels.clone(), external_port, proto)
        {
            match cached {
                Some(data) => {
                    // mapping exist
                    return Ok(Some(data));
                }
                None if matched_prefix == url_prefix.to_string() => {
                    return Ok(None);
                }
                None => {
                    info!(
                        "Found in cache, but for higher-level prefix: {}. Query was: {}",
                        matched_prefix, url_prefix
                    );
                    // go ahead, and ask again on subpath, since it may be another oath
                }
            }
        }

        // no info in cache
        info!("No data in cache for {}", url_prefix);

        let host = url_prefix.host();

        // take lock and deal with in_flight queries
        let in_flight_request = self
            .retrieve_configs
            .lock()
            .entry(host.clone().into())
            .or_insert_with({
                shadow_clone!(url_prefix);
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
                                url_prefix
                            );

                            let mut url = Url::parse(base_url.as_str()).unwrap();
                            url.path_segments_mut()
                                .unwrap()
                                .push("int")
                                .push("api")
                                .push("configs");

                            url.set_query(Some(
                                format!(
                                    "url={}",
                                    percent_encoding::utf8_percent_encode(
                                        format!("{}", url_prefix).as_str(),
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

                                                configs.upsert(
                                                    &url_prefix,
                                                    Some(Mapping {
                                                        match_pattern: config_response
                                                            .url_prefix
                                                            .as_str()
                                                            .parse()
                                                            .expect("FIXME"),
                                                        generated_at: config_response.generated_at,
                                                        instances: config_response.instances,
                                                    }),
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
                                        configs.upsert(&url_prefix, None);
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
            let locked = &mut *self.retrieve_configs.lock();

            if let Entry::Occupied(entry) = locked.entry(host.into()) {
                if Arc::ptr_eq(entry.get(), &in_flight_request) {
                    // we are now sure that it's the same request
                    entry.remove_entry();
                }
            }
        }

        if let Some((cached, _)) = self
            .configs
            .resolve(url_prefix, tunnels, external_port, proto)
        {
            Ok(cached)
        } else {
            error!("Still can't resolve after successful reset event happened");
            Err(Error::CouldNotRetrieve)
        }
    }

    pub async fn retrieve_certificate(&self, domain: &str) -> Result<CertificateResponse, Error> {
        let mut url = Url::parse(self.base_url.as_str()).unwrap();
        url.path_segments_mut()
            .unwrap()
            .push("int")
            .push("api")
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
