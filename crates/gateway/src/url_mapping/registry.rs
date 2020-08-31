use std::sync::{Arc, Weak};
use std::time::Duration;

use chrono::{DateTime, Utc};
use lru_time_cache::LruCache;
use parking_lot::Mutex;
use patricia_tree::PatriciaMap;
use smartstring::alias::*;

use crate::clients::ClientTunnels;
use crate::url_mapping::mapping::{Mapping, MappingAction, Protocol, UrlForRewriting};
use crate::url_mapping::rate_limiter::RateLimiters;
use crate::url_mapping::url_prefix::UrlPrefix;

struct Inner {
    // List of prefix with expiration according to policies
    lru_storage: LruCache<String, Option<Arc<Mapping>>>,

    // Radix (Patricia) tree to search for longest prefix
    from_prefix_lookup_tree: PatriciaMap<Option<Weak<Mapping>>>,
}

impl Inner {
    fn process_evicted(&mut self, evicted: Vec<(String, Option<Arc<Mapping>>)>) {
        for (k, _mapping) in evicted.into_iter() {
            self.from_prefix_lookup_tree.remove(k);
        }
    }

    fn upsert(
        &mut self,
        url_prefix: &UrlPrefix,
        mapping: Option<Mapping>,
        generated_at: DateTime<Utc>,
    ) {
        //cleanup all Mappings overlapping with this one
        self.remove_by_notification_if_time_applicable(url_prefix, generated_at);

        let from_key: String = url_prefix.to_string().into();

        let for_lru = mapping.map(Arc::new);
        let for_trie = for_lru.as_ref().map(|arc| Arc::downgrade(arc));

        let (_, evicted) = self.lru_storage.notify_insert(from_key.clone(), for_lru);

        self.process_evicted(evicted);

        self.from_prefix_lookup_tree.insert(from_key, for_trie);
    }

    fn remove_by_notification_if_time_applicable(
        &mut self,
        url_prefix: &UrlPrefix,
        generated_at: DateTime<Utc>,
    ) {
        let s: String = url_prefix.to_string().into();

        info!("Cleanup all mappings with prefix: {}", s);

        let items_for_invalidation = self
            .from_prefix_lookup_tree
            .iter_prefix(s.as_ref())
            .map(|(k, _)| k)
            .collect::<Vec<_>>();
        for k in items_for_invalidation {
            let found_url_prefix: UrlPrefix = std::str::from_utf8(k.as_ref())
                .expect("corrupted data in patricia tree")
                .parse()
                .expect("Corrupted data in patricia tree");

            if !url_prefix.is_subpath_of_or_equal(&found_url_prefix) {
                info!("{} is not a subpath of {}", url_prefix, found_url_prefix);
                continue;
            }

            info!("Remove data with key {}", found_url_prefix);

            let found_url_prefix_string: String = found_url_prefix.to_string().into();

            let (maybe_mapping, evicted) = self.lru_storage.notify_get(&found_url_prefix_string);

            if let Some(Some(mapping)) = maybe_mapping {
                if generated_at <= mapping.generated_at {
                    // ignore if stale. process evicted before returning
                    self.process_evicted(evicted);
                    continue;
                }
            }

            self.process_evicted(evicted);

            self.lru_storage.remove(&found_url_prefix_string);
            self.from_prefix_lookup_tree
                .remove(&found_url_prefix_string);
        }
    }

    fn find_mapping(
        &mut self,
        url_prefix: &UrlForRewriting,
    ) -> Option<(Option<Arc<Mapping>>, String)> {
        self.from_prefix_lookup_tree
            .get_longest_common_prefix(url_prefix.to_string().as_str())
            .map(|(prefix, v)| {
                (
                    v.as_ref().map(|weak| {
                        if let Some(r) = weak.upgrade() {
                            r
                        } else {
                            panic!("Unexpected dangling weak pointer in from- PatriciaTree")
                        }
                    }),
                    std::str::from_utf8(prefix).expect("FIXME").into(),
                )
            })
    }
}

#[derive(Clone)]
pub struct Configs {
    inner: Arc<Mutex<Inner>>,
}

impl Configs {
    pub fn new(ttl: Duration) -> Self {
        Configs {
            inner: Arc::new(Mutex::new(Inner {
                lru_storage: LruCache::with_expiry_duration(ttl),
                from_prefix_lookup_tree: Default::default(),
            })),
        }
    }

    pub fn resolve(
        &self,
        url_prefix: UrlForRewriting,
        tunnels: ClientTunnels,
        external_port: u16,
        proto: Protocol,
    ) -> Option<
        //first option indicate, if the data exist in registry
        (
            Option<(
                //second option indicate if there is an actual mapping, or 404 should be returned
                MappingAction,
                RateLimiters,
            )>,
            String,
        ),
    > {
        self.inner
            .lock()
            .find_mapping(&url_prefix)
            .map(move |(maybe_mapping, matched_prefix)| {
                (
                    maybe_mapping.and_then(|r| {
                        match r.handle(url_prefix, tunnels, external_port, proto) {
                            Ok(r) => Some(r),
                            Err(e) => {
                                error!("error handling URL: {:?}", e);
                                None
                            }
                        }
                    }),
                    matched_prefix,
                )
            })
    }

    pub fn remove_by_notification_if_time_applicable(
        &self,
        url_prefix: &UrlPrefix,
        generated_at: DateTime<Utc>,
    ) {
        self.inner
            .lock()
            .remove_by_notification_if_time_applicable(url_prefix, generated_at)
    }

    pub fn upsert(
        &self,
        url_prefix: &UrlPrefix,
        mapping: Option<Mapping>,
        generated_at: DateTime<Utc>,
    ) {
        self.inner.lock().upsert(url_prefix, mapping, generated_at)
    }
}

// #[cfg(test)]
// mod tests {
//     use std::thread;
//
//     use crate::url_mapping::mapping::MatchPattern;
//
//     use super::*;
//
//     #[test]
//     pub fn lifetime_tests() {
//         let mappings = Mappings::new(Duration::from_secs(2));
//
//         assert!(mappings
//             .resolve(
//                 UrlForRewriting::from_components("example.exg.co", "/from/url/test", "").unwrap(),
//                 ClientTunnels::new(),
//                 443,
//                 Protocol::Http,
//             )
//             .is_none());
//
//         let request_url =
//             UrlForRewriting::from_components("example.exg.co", "/from/url", "").unwrap();
//         let match_pattern = MatchPattern::new("example.exg.co", "/from/url").unwrap();
//
//         let mapping = Mapping {
//             match_pattern: match_pattern.clone(),
//             proxy_matched_to: ProxyMatchedTo::new(
//                 "lancastr.com/to/newurl",
//                 "test-config".parse().unwrap(),
//             )
//             .unwrap(),
//             generated_at: Utc::now(),
//             // jwt_secret: vec![],
//             // auth_type: AuthProviderConfig::Oauth2(Oauth2SsoClient {
//             //     provider: Oauth2Provider::Google,
//             // }),
//             // rate_limiter: None,
//         };
//
//         mappings.upsert(&request_url, Some(mapping.clone()));
//         assert!(mappings
//             .resolve(
//                 UrlForRewriting::from_components("example.exg.co", "/from/url/test", "").unwrap(),
//                 ClientTunnels::new(),
//                 443,
//                 Protocol::Http,
//             )
//             .is_some());
//         mappings.upsert(&request_url, None);
//         assert!(mappings
//             .resolve(
//                 UrlForRewriting::from_components("example.exg.co", "/from/url/test", "").unwrap(),
//                 ClientTunnels::new(),
//                 443,
//                 Protocol::Http,
//             )
//             .unwrap()
//             .0
//             .is_none());
//         mappings.upsert(&request_url, Some(mapping.clone()));
//         thread::sleep(Duration::from_secs(3));
//
//         // Stale data may be returned. No need to do additional check through LRU on removing the data
//         // Just return
//         assert!(mappings
//             .resolve(
//                 UrlForRewriting::from_components("example.exg.co", "/from/url/test", "").unwrap(),
//                 ClientTunnels::new(),
//                 443,
//                 Protocol::Http,
//             )
//             .is_some());
//
//         // Trigger cleanup by sending stale notification
//         let request_url2 =
//             UrlForRewriting::from_components("example2.exg.co", "/from/url", "").unwrap();
//         let match_pattern2 = MatchPattern::new("example2.exg.co", "/from/url").unwrap();
//
//         let mapping2 = Mapping {
//             match_pattern: match_pattern2.clone(),
//             proxy_matched_to: ProxyMatchedTo::new("example.com/", "test-config".parse().unwrap())
//                 .unwrap(),
//             generated_at: Utc::now(),
//             // jwt_secret: vec![],
//             // auth_type: AuthProviderConfig::Oauth2(Oauth2SsoClient {
//             //     provider: Oauth2Provider::Google,
//             // }),
//             // rate_limiter: None,
//         };
//
//         mappings.upsert(&request_url2.clone(), Some(mapping2.clone()));
//
//         // now the first mapping should be evicted
//         assert!(mappings
//             .resolve(
//                 UrlForRewriting::from_components("example.exg.co", "/from/url/test", "").unwrap(),
//                 ClientTunnels::new(),
//                 443,
//                 Protocol::Http,
//             )
//             .is_none());
//
//         // send stale notification on the second mapping
//         mappings.remove_by_notification_if_time_applicable(
//             request_url2.to_string().into(),
//             Utc::now() - chrono::Duration::seconds(100000),
//         );
//
//         // should not be deleted
//         assert!(mappings
//             .resolve(
//                 UrlForRewriting::from_components("example2.exg.co", "/from/url/asd", "").unwrap(),
//                 ClientTunnels::new(),
//                 443,
//                 Protocol::Http,
//             )
//             .is_some());
//
//         // send notification on the second mapping with correct time
//         mappings
//             .remove_by_notification_if_time_applicable(request_url2.to_string().into(), Utc::now());
//
//         // should not be deleted
//         assert!(mappings
//             .resolve(
//                 UrlForRewriting::from_components("example2.exg.co", "/from/url/asd", "").unwrap(),
//                 ClientTunnels::new(),
//                 443,
//                 Protocol::Http,
//             )
//             .is_none());
//     }
// }
