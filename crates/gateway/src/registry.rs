use std::{sync::Arc, time::Duration};

use crate::http_serve::RequestsProcessor;
use chrono::{DateTime, Utc};
use lru_time_cache::LruCache;

struct Inner {
    // List of domain with expiration according to policies
    lru_storage: LruCache<String, Option<Arc<RequestsProcessor>>>,
}

impl Inner {
    fn upsert(
        &mut self,
        fqdn: &str,
        requests_processors: Option<RequestsProcessor>,
        generated_at: &DateTime<Utc>,
    ) {
        if let Some(Some(requests_processors)) = self.lru_storage.get(fqdn) {
            if generated_at < &requests_processors.generated_at {
                return;
            }
        }

        self.lru_storage
            .insert(fqdn.to_string(), requests_processors.map(Arc::new));
    }

    fn remove_by_notification_if_time_applicable(
        &mut self,
        fqdn: &str,
        generated_at: &DateTime<Utc>,
    ) {
        if let Some(Some(requests_processors)) = self.lru_storage.get(fqdn) {
            if generated_at > &requests_processors.generated_at {
                self.lru_storage.remove(fqdn);
                crate::statistics::CONFIGS_FORGOTTEN.inc();
            }
        }
    }

    fn find_requests_processors(&mut self, fqdn: &str) -> Option<Option<Arc<RequestsProcessor>>> {
        self.lru_storage.get(fqdn).cloned()
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
            })),
        }
    }

    /// Find proper RequestProcessor
    pub fn resolve(&self, fqdn: &str) -> Option<Option<Arc<RequestsProcessor>>> {
        self.inner.lock().find_requests_processors(fqdn)
    }

    pub fn remove_by_notification_if_time_applicable(
        &self,
        fqdn: &str,
        generated_at: &DateTime<Utc>,
    ) {
        self.inner
            .lock()
            .remove_by_notification_if_time_applicable(fqdn, generated_at)
    }

    pub fn upsert(
        &self,
        fqdn: &str,
        requests_processors: Option<RequestsProcessor>,
        generated_at: &DateTime<Utc>,
    ) {
        self.inner
            .lock()
            .upsert(fqdn, requests_processors, generated_at)
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
