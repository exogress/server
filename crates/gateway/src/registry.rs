use std::sync::{Arc, Weak};
use std::time::Duration;

use crate::http_serve::RequestsProcessor;
use chrono::{DateTime, Utc};
use lru_time_cache::LruCache;
use patricia_tree::PatriciaMap;

use crate::clients::ClientTunnels;
use crate::urls::matchable_url::MatchableUrl;
use crate::urls::Protocol;
use exogress_server_common::url_prefix::MountPointBaseUrl;

struct Inner {
    // List of prefix with expiration according to policies
    lru_storage: LruCache<String, Option<Arc<RequestsProcessor>>>,

    // Radix (Patricia) tree to search for longest prefix
    from_prefix_lookup_tree: PatriciaMap<Option<Weak<RequestsProcessor>>>,
}

impl Inner {
    fn process_evicted(&mut self, evicted: Vec<(String, Option<Arc<RequestsProcessor>>)>) {
        for (k, maybe_requests_processors) in evicted.into_iter() {
            self.from_prefix_lookup_tree.remove(k);
            if let Some(requests_processors) = maybe_requests_processors {
                // requests_processors
                //     .health
                //     .health_deleted()
                //     .await
                //     .expect("FIXME");
            }
        }
    }

    fn upsert(
        &mut self,
        url_prefix: &MountPointBaseUrl,
        requests_processors: Option<RequestsProcessor>,
        generated_at: &DateTime<Utc>,
    ) {
        //cleanup all RequestsProcessors overlapping with this one
        self.remove_by_notification_if_time_applicable(url_prefix, generated_at);

        let from_key: String = url_prefix.to_string().into();

        let for_lru = requests_processors.map(Arc::new);
        let for_trie = for_lru.as_ref().map(|arc| Arc::downgrade(arc));

        let (_, evicted) = self.lru_storage.notify_insert(from_key.clone(), for_lru);

        self.process_evicted(evicted);

        self.from_prefix_lookup_tree.insert(from_key, for_trie);
    }

    fn remove_by_notification_if_time_applicable(
        &mut self,
        url_prefix: &MountPointBaseUrl,
        generated_at: &DateTime<Utc>,
    ) {
        let s: String = url_prefix.to_string().into();

        info!("Cleanup all requests_processorss with prefix: {}", s);

        let items_for_invalidation = self
            .from_prefix_lookup_tree
            .iter_prefix(s.as_ref())
            .map(|(k, _)| k)
            .collect::<Vec<_>>();

        for k in items_for_invalidation {
            let found_url_prefix: MountPointBaseUrl = std::str::from_utf8(k.as_ref())
                .expect("corrupted data in patricia tree")
                .parse()
                .expect("Corrupted data in patricia tree");

            if !url_prefix.is_subpath_of_or_equal(&found_url_prefix) {
                info!("{} is not a subpath of {}", url_prefix, found_url_prefix);
                continue;
            }

            info!("Remove data with key {}", found_url_prefix);

            let found_url_prefix_string: String = found_url_prefix.to_string().into();

            let (maybe_requests_processors, evicted) =
                self.lru_storage.notify_get(&found_url_prefix_string);

            if let Some(Some(requests_processors)) = maybe_requests_processors {
                if generated_at <= &requests_processors.generated_at {
                    // ignore if stale. process evicted before returning
                    self.process_evicted(evicted);
                    continue;
                }
            }

            self.process_evicted(evicted);

            let maybe_requests_processors = self.lru_storage.remove(&found_url_prefix_string);
            self.from_prefix_lookup_tree
                .remove(&found_url_prefix_string);

            if let Some(Some(requests_processors)) = maybe_requests_processors {
                // requests_processors
                //     .health
                //     .health_deleted()
                //     .expect("FIXME");
            }
        }
    }

    fn find_requests_processors(
        &mut self,
        matchable_url: &MatchableUrl,
    ) -> Option<(Option<Arc<RequestsProcessor>>, MountPointBaseUrl)> {
        self.from_prefix_lookup_tree
            .get_longest_common_prefix(matchable_url.as_str())
            .map(|(prefix, v)| {
                (
                    v.as_ref().map(|weak| {
                        if let Some(r) = weak.upgrade() {
                            r
                        } else {
                            panic!("Unexpected dangling weak pointer in from- PatriciaTree")
                        }
                    }),
                    std::str::from_utf8(prefix)
                        .expect("FIXME")
                        .parse()
                        .expect("FIXME"),
                )
            })
    }
}

#[derive(Clone)]
pub struct RequestsProcessorsRegistry {
    inner: Arc<parking_lot::Mutex<Inner>>,
}

impl RequestsProcessorsRegistry {
    pub fn new(ttl: Duration) -> Self {
        RequestsProcessorsRegistry {
            inner: Arc::new(parking_lot::Mutex::new(Inner {
                lru_storage: LruCache::with_expiry_duration(ttl),
                from_prefix_lookup_tree: Default::default(),
            })),
        }
    }

    /// Find proper RequestProcessor
    pub fn resolve(
        &self,
        matchable_url: &MatchableUrl,
        // external_port: u16,
        // proto: Protocol,
    ) -> Option<(Option<Arc<RequestsProcessor>>, MountPointBaseUrl)> {
        self.inner.lock().find_requests_processors(matchable_url)
        // .map(move |(maybe_mapping, matched_prefix)| {
        //     (
        //         maybe_mapping.and_then(|r| match r.handle(url_prefix, external_port, proto) {
        //             Ok(r) => Some(r),
        //             Err(e) => {
        //                 error!("error handling URL: {:?}", e);
        //                 None
        //             }
        //         }),
        //         matched_prefix,
        //     )
        // })
    }

    pub fn remove_by_notification_if_time_applicable(
        &self,
        url_prefix: &MountPointBaseUrl,
        generated_at: &DateTime<Utc>,
    ) {
        self.inner
            .lock()
            .remove_by_notification_if_time_applicable(url_prefix, generated_at)
    }

    pub fn upsert(
        &self,
        url_prefix: &MountPointBaseUrl,
        requests_processors: Option<RequestsProcessor>,
        generated_at: &DateTime<Utc>,
    ) {
        self.inner
            .lock()
            .upsert(url_prefix, requests_processors, generated_at)
    }
}

// #[cfg(test)]
// mod tests {
//     use std::thread;
//
//     use crate::url_requests_processors::requests_processors::MatchPattern;
//
//     use super::*;
//
//     #[test]
//     pub fn lifetime_tests() {
//         let requests_processorss = RequestsProcessors::new(Duration::from_secs(2));
//
//         assert!(requests_processorss
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
//         let requests_processors = RequestsProcessor {
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
//         requests_processorss.upsert(&request_url, Some(requests_processors.clone()));
//         assert!(requests_processorss
//             .resolve(
//                 UrlForRewriting::from_components("example.exg.co", "/from/url/test", "").unwrap(),
//                 ClientTunnels::new(),
//                 443,
//                 Protocol::Http,
//             )
//             .is_some());
//         requests_processorss.upsert(&request_url, None);
//         assert!(requests_processorss
//             .resolve(
//                 UrlForRewriting::from_components("example.exg.co", "/from/url/test", "").unwrap(),
//                 ClientTunnels::new(),
//                 443,
//                 Protocol::Http,
//             )
//             .unwrap()
//             .0
//             .is_none());
//         requests_processorss.upsert(&request_url, Some(requests_processors.clone()));
//         thread::sleep(Duration::from_secs(3));
//
//         // Stale data may be returned. No need to do additional check through LRU on removing the data
//         // Just return
//         assert!(requests_processorss
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
//         let requests_processors2 = RequestsProcessor {
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
//         requests_processorss.upsert(&request_url2.clone(), Some(requests_processors2.clone()));
//
//         // now the first requests_processors should be evicted
//         assert!(requests_processorss
//             .resolve(
//                 UrlForRewriting::from_components("example.exg.co", "/from/url/test", "").unwrap(),
//                 ClientTunnels::new(),
//                 443,
//                 Protocol::Http,
//             )
//             .is_none());
//
//         // send stale notification on the second requests_processors
//         requests_processorss.remove_by_notification_if_time_applicable(
//             request_url2.to_string().into(),
//             Utc::now() - chrono::Duration::seconds(100000),
//         );
//
//         // should not be deleted
//         assert!(requests_processorss
//             .resolve(
//                 UrlForRewriting::from_components("example2.exg.co", "/from/url/asd", "").unwrap(),
//                 ClientTunnels::new(),
//                 443,
//                 Protocol::Http,
//             )
//             .is_some());
//
//         // send notification on the second requests_processors with correct time
//         requests_processorss
//             .remove_by_notification_if_time_applicable(request_url2.to_string().into(), Utc::now());
//
//         // should not be deleted
//         assert!(requests_processorss
//             .resolve(
//                 UrlForRewriting::from_components("example2.exg.co", "/from/url/asd", "").unwrap(),
//                 ClientTunnels::new(),
//                 443,
//                 Protocol::Http,
//             )
//             .is_none());
//     }
// }
