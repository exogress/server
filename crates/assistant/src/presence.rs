use reqwest::{Identity, Method, StatusCode, Url};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nothing {}

#[derive(Clone, Debug)]
pub struct Client {
    client: reqwest::Client,
    base_url: Url,
    assistant_name: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reqwest error: `{0}`")]
    ReqwestError(#[from] reqwest::Error),

    #[error("bad response `{0}`")]
    BadResponse(StatusCode),

    #[error("conflict")]
    Conflict,

    #[error("not found")]
    NotFound,

    #[error("forbidden")]
    Forbidden,

    #[error("unauthorized")]
    Unauthorized,

    #[error("bad request: {:?}", _0)]
    BadRequest(Option<String>),
}

impl Client {
    pub fn new(
        mut webapp_base_url: Url,
        assistant_name: String,
        maybe_identity: Option<Vec<u8>>,
    ) -> Self {
        {
            let mut segments = webapp_base_url.path_segments_mut().unwrap();
            segments.push("int_api");
            segments.push("v1");
            segments.push("assistants");
            segments.push(assistant_name.as_str());
        }

        let mut builder = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .use_rustls_tls()
            .trust_dns(true);

        if let Some(identity) = maybe_identity {
            builder = builder.identity(Identity::from_pem(&identity).unwrap());
        }

        Client {
            client: builder.build().unwrap(),
            base_url: webapp_base_url,
            assistant_name,
        }
    }

    async fn execute_url<R: Serialize + DeserializeOwned + Sized>(
        &self,
        url: Url,
        method: Method,
    ) -> Result<R, Error> {
        let req = self.client.request(method, url);

        let res = req.send().await?;

        match res.status() {
            code if code.is_success() => Ok(res.json().await?),
            StatusCode::CONFLICT => Err(Error::Conflict),
            StatusCode::NOT_FOUND => Err(Error::NotFound),
            StatusCode::FORBIDDEN => Err(Error::Forbidden),
            StatusCode::UNAUTHORIZED => Err(Error::Unauthorized),
            StatusCode::BAD_REQUEST => {
                Err(Error::BadRequest(res.text().await.ok().map(|s| s.into())))
            }
            code => Err(Error::BadResponse(code)),
        }
    }

    async fn execute_assistant(&self, method: Method) -> Result<Nothing, Error> {
        let url = self.base_url.clone();

        self.execute_url(url, method).await
    }

    async fn execute_presence<R: Serialize + DeserializeOwned + Sized>(
        &self,
        method: Method,
        hostname: &str,
    ) -> Result<R, Error> {
        let mut url: Url = self.base_url.clone();

        url.path_segments_mut()
            .unwrap()
            .push("gateways")
            .push(hostname);

        self.execute_url(url, method).await
    }

    pub async fn register_assistant(&self) -> Result<Nothing, Error> {
        self.execute_assistant(Method::POST).await
    }

    pub async fn unregister_assistant(&self) -> Result<Nothing, Error> {
        self.execute_assistant(Method::DELETE).await
    }

    pub async fn set_online(&self, hostname: &str) -> Result<Nothing, Error> {
        self.execute_presence(Method::POST, hostname).await
    }

    pub async fn assistant_alive(&self) -> Result<Nothing, Error> {
        let mut url = self.base_url.clone();
        {
            let mut segments = url.path_segments_mut().unwrap();
            segments.push("alive");
        }

        self.execute_url(url, Method::POST).await
    }

    pub async fn set_offline(&self, hostname: &str) -> Result<Nothing, Error> {
        self.execute_presence(Method::DELETE, hostname).await
    }
}
