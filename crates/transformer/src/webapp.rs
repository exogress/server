use exogress_common::entities::AccountUniqueId;
use lru_time_cache::LruCache;
use parking_lot::Mutex;
use reqwest::{Identity, Method};
use serde::{Deserialize, Serialize};
use sodiumoxide::{crypto::secretstream::xchacha20poly1305, hex};
use std::{sync::Arc, time::Duration};
use url::Url;

#[derive(Clone)]
pub struct Client {
    reqwest: reqwest::Client,
    base_url: Url,
    secret_keys: Arc<Mutex<LruCache<AccountUniqueId, xchacha20poly1305::Key>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseStatus {
    #[serde(rename = "ok")]
    Ok,

    #[serde(rename = "error")]
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    xchacha20poly1305_secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountResponse {
    status: ResponseStatus,
    account: AccountInfo,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("request error: `{0}`")]
    Reqwest(#[from] reqwest::Error),

    #[error("URL prefix error: `{0}`")]
    Url(#[from] url::ParseError),
}

impl Client {
    pub fn new(base_url: Url, maybe_identity: Option<Vec<u8>>) -> Self {
        let mut reqwest = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .use_rustls_tls()
            .trust_dns(true);

        if let Some(identity) = maybe_identity {
            reqwest =
                reqwest.identity(Identity::from_pem(identity.as_ref()).expect("Bad int api cert"));
        }

        Client {
            reqwest: reqwest.build().unwrap(),
            base_url,
            secret_keys: Arc::new(Mutex::new(LruCache::with_capacity(65536))),
        }
    }

    pub async fn get_secret_key(
        &self,
        account_id: &AccountUniqueId,
    ) -> anyhow::Result<xchacha20poly1305::Key> {
        if let Some(secret_key) = self.secret_keys.lock().get_mut(account_id) {
            return Ok(secret_key.clone());
        }

        let mut url = self.base_url.clone();

        url.path_segments_mut()
            .unwrap()
            .push("int_api")
            .push("v1")
            .push("accounts")
            .push(account_id.to_string().as_str());

        let req = reqwest::Request::new(Method::GET, url);

        let resp = self
            .reqwest
            .execute(req)
            .await?
            .error_for_status()?
            .json::<AccountResponse>()
            .await?;

        let secret_key = xchacha20poly1305::Key::from_slice(
            &hex::decode(resp.account.xchacha20poly1305_secret_key)
                .map_err(|_| anyhow!("malformed secret key"))?,
        )
        .ok_or_else(|| anyhow!("bad secret key"))?;

        self.secret_keys
            .lock()
            .insert(*account_id, secret_key.clone());

        Ok(secret_key)
    }
}
