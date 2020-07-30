use std::time::Duration;

use url::Url;

#[derive(Clone, Debug)]
pub struct Client {
    reqwest: reqwest::Client,
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
}

#[derive(Debug, Serialize)]
pub struct AcmeHttpChallengeVerificationQueryParams {
    domain: String,
    filename: String,
}

impl Client {
    pub fn new() -> Self {
        Client {
            reqwest: reqwest::ClientBuilder::new()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(10))
                .use_rustls_tls()
                .trust_dns(true)
                .build()
                .unwrap(),
        }
    }

    pub async fn acme_http_challenge_verification(
        &self,
        domain: &str,
        path: &str,
    ) -> Result<AcmeHttpChallengeVerificationResponse, Error> {
        let mut url = Url::parse("https://int-api2.stage.exogress.com/").unwrap();
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

    pub async fn retrieve_certificate(&self, domain: &str) -> Result<CertificateResponse, Error> {
        let mut url = Url::parse("https://int-api2.stage.exogress.com/").unwrap();
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
