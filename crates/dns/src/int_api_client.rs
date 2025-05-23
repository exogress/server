use reqwest::Identity;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;
use warp::http;

#[derive(Clone)]
pub struct IntApiClient {
    reqwest: reqwest::Client,
    webapp_base_url: Url,
}

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    record_content: String,
}

impl IntApiClient {
    pub fn new(webapp_base_url: Url, maybe_identity: Option<Vec<u8>>) -> IntApiClient {
        let mut builder = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .use_rustls_tls()
            .trust_dns(true);

        if let Some(identity) = maybe_identity {
            builder = builder.identity(Identity::from_pem(&identity).unwrap());
        }

        IntApiClient {
            reqwest: builder.build().unwrap(),
            webapp_base_url,
        }
    }

    pub async fn acme_dns_challenge_verification(
        &self,
        record_name: &str,
        record_type: &str,
        domain: &str,
    ) -> anyhow::Result<Option<String>> {
        let mut url = self.webapp_base_url.clone();
        url.path_segments_mut()
            .unwrap()
            .push("int_api")
            .push("v1")
            .push("acme_dns_challenge_verification");

        url.query_pairs_mut()
            .append_pair("domain", domain)
            .append_pair("record_type", record_type)
            .append_pair("record_name", record_name);

        let res = self.reqwest.get(url).send().await?;

        if res.status().is_success() {
            Ok(Some(res.json::<Response>().await?.record_content))
        } else if res.status() == http::StatusCode::NOT_FOUND {
            Ok(None)
        } else {
            bail!("bad response: {}", res.status());
        }
    }
}
