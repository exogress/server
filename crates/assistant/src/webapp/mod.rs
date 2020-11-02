use exogress_server_common::assistant::UpstreamReport;
use reqwest::Identity;
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamReportWithGwInfo {
    pub gw_hostname: String,
    pub gw_location: String,

    #[serde(flatten)]
    pub inner: UpstreamReport,
}

#[derive(Clone)]
pub struct Client {
    reqwest: reqwest::Client,
    base_url: Url,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("request error: `{0}`")]
    Reqwest(#[from] reqwest::Error),

    #[error("bad response")]
    BadResponse,

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
        }
    }

    pub async fn report_health(&self, report: Vec<UpstreamReportWithGwInfo>) -> Result<(), Error> {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .unwrap()
            .push("int_api")
            .push("v1")
            .push("healths");

        let res = self.reqwest.post(url).json(&report).send().await?;

        if res.status().is_success() {
            Ok(())
        } else {
            Err(Error::BadResponse)
        }
    }
}
