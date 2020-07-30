

use std::sync::Arc;
use std::time::Duration;



use futures_intrusive::sync::ManualResetEvent;
use governor::clock::MonotonicClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{RateLimiter};
use hashbrown::hash_map::Entry;
use hashbrown::HashMap;
use parking_lot::Mutex;
use url::Url;

use smartstring::alias::*;



use crate::clients::ClientTunnels;
use crate::url_mapping;
use crate::url_mapping::mapping::{
    AuthProviderConfig, Mapping, MappingAction, MatchPattern, MatchPatternError, Oauth2Provider,
    Oauth2SsoClient, Protocol, ProxyMatchedTo, RewriteMatchedToError, UrlForRewriting,
};
use crate::url_mapping::registry::Mappings;

struct Inner {
    in_flight: parking_lot::Mutex<HashMap<String, Arc<ManualResetEvent>>>,
    int_api_access_secret: String,
}

#[derive(Clone)]
pub struct Client {
    retrieval: Arc<Inner>,
    mappings: Mappings,
}

#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("URL prefix error: `{0}`")]
    Url(#[from] url::ParseError),

    #[error("Could not retrieve URL")]
    CouldNotRetrieve,
}

impl Client {
    pub async fn new(ttl: Duration, _url: Url, int_api_access_secret: String) -> Result<Client, ()> {
        Ok(Client {
            mappings: Mappings::new(ttl),
            retrieval: Arc::new(Inner {
                int_api_access_secret,
                in_flight: parking_lot::Mutex::new(Default::default()),
            }),
        })
    }

    pub fn mappings(&self) -> Mappings {
        self.mappings.clone()
    }

    pub async fn resolve(
        &self,
        _individual_hostname: String,
        url_prefix: UrlForRewriting,
        external_port: u16,
        proto: Protocol,
        tunnels: ClientTunnels,
    ) -> Result<
        Option<(
            MappingAction,
            Option<Arc<Mutex<RateLimiter<NotKeyed, InMemoryState, MonotonicClock>>>>,
        )>,
        ClientError,
    > {
        // Try to read from cache
        if let Some((cached, matched_prefix)) =
            self.mappings
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
            .retrieval
            .in_flight
            .lock()
            .entry(host.clone())
            .or_insert_with({
                shadow_clone!(url_prefix);

                let _mappings = self.mappings.clone();
                let _int_api_access_secret = self.retrieval.int_api_access_secret.clone();

                move || {
                    let ready_event = Arc::new(ManualResetEvent::new(false));

                    // initiate query
                    tokio::spawn({
                        shadow_clone!(ready_event);

                        async move {
                            info!(
                                "Initiating new request to retrieve mapping for {}",
                                url_prefix
                            );

                            // FIXME

                            // let request = tonic::Request::new(MapRequest {
                            //     url_prefix: url_prefix.into(),
                            //     access_secret: int_api_access_secret.clone(),
                            // });

                            // match server_client.resolve(request).await {
                            //     Ok(response) => {
                            //         let mapping_response = response.into_inner();
                            //
                            //         debug!(
                            //             "Mapping retrieved successfully: `{:?}`", mapping_response
                            //         );
                            //
                            //         match mapping_response.response {
                            //             Some(
                            //                 resolve_url_mapping_response::Response::FoundMapping(
                            //                     mapping,
                            //                 ),
                            //             ) => {
                            //                 info!("Mapping found: {:?}", mapping);
                            //
                            //                 let mapping = Mapping::try_from_message(
                            //                     mapping,
                            //                 );
                            //
                            //                 match mapping {
                            //                     Ok(mapping) => {
                            //                         mappings.
                            //                             upsert(
                            //                                 &url_prefix,
                            //                                 Some(mapping))
                            //                     }
                            //                     Err(e) => {
                            //                         error!("Could not parse incoming mapping: {}. Save None to prevent queries on each request", e);
                            //                         mappings.upsert(&url_prefix, None);
                            //                     }
                            //                 }
                            //             }
                            //             Some(
                            //                 resolve_url_mapping_response::Response::MappingNotFound(
                            //                     _,
                            //                 ),
                            //             ) => {
                            //                 info!("Mapping not found");
                            //                 mappings.upsert(&url_prefix, None);
                            //             }
                            //             None => {
                            //                 error!(
                            //                     "unexpected empty response from gRPC mapping api"
                            //                 );
                            //             }
                            //         }
                            //     }
                            //     Err(e) => {
                            //         error!("Error retrieving mapping: {}", e);
                            //     }
                            // }

                            ready_event.set();
                        }
                    });
                    ready_event
                }
            })
            .clone();

        in_flight_request.wait().await;

        {
            let locked = &mut *self.retrieval.in_flight.lock();

            if let Entry::Occupied(entry) = locked.entry(host) {
                if Arc::ptr_eq(entry.get(), &in_flight_request) {
                    // we are now sure that it's the same request
                    entry.remove_entry();
                }
            }
        }

        if let Some((cached, _)) = self
            .mappings
            .resolve(url_prefix, tunnels, external_port, proto)
        {
            Ok(cached)
        } else {
            error!("Still can't resolve after successful reset event happened");
            Err(ClientError::CouldNotRetrieve)
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MappingConversionError {
    #[error("url prefix parse error")]
    UrlPrefixParse(#[from] url::ParseError),

    #[error("no JWT Secret")]
    NoJwtSecret,

    #[error("unsupported JWT kind {0}")]
    UnsupportedJwtKind(i32),

    #[error("timestamp conversion error")]
    TimestampError,

    #[error("generated_at field not provided")]
    GeneratedAtNotProvided,

    #[error("replenish_one_per is empty in rate limiter")]
    RateLimiterReplenishIntervalEmpty,

    #[error("replenish_one_per can't convert duration")]
    RateLimiterReplenishIntervalConversionError,

    #[error("bad auth config")]
    BadAuthConfig,

    #[error("unknown oauth2 provider: `{0}`")]
    UnknownOauth2Provider(i32),

    #[error("bad auth providers count: `{0}`")]
    BadProvidersCount(usize),

    #[error("match pattern error: `{0}`")]
    MatchPatter(#[from] MatchPatternError),

    #[error("rewrite_matched_to error: `{0}`")]
    RewriteMatchedTo(#[from] RewriteMatchedToError),
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
