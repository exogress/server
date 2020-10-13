use std::sync::Arc;
use std::time::Duration;

use futures_intrusive::sync::ManualResetEvent;
use governor::clock::MonotonicClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::RateLimiter;
use hashbrown::hash_map::Entry;
use hashbrown::HashMap;
use parking_lot::Mutex;
use url::Url;

use crate::clients::ClientTunnels;
use crate::url_mapping;
use crate::url_mapping::mapping::{
    Mapping, MappingAction, MatchPattern, MatchPatternError, Protocol, ProxyMatchedTo,
    RewriteMatchedToError, UrlForRewriting,
};
use crate::url_mapping::registry::Mappings;

struct Inner {
    in_flight: Mutex<HashMap<String, Arc<ManualResetEvent>>,
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
    pub async fn new(
        ttl: Duration,
        _url: Url,
        int_api_access_secret: String,
    ) -> Result<Client, ()> {
        Ok(Client {
            mappings: Mappings::new(ttl),
            retrieval: Arc::new(Inner {
                int_api_access_secret,
                in_flight: parking_lot::Mutex::new(Default::default()),
            }),
        })
    }
}
