//! Presence API
use exogress_config_core::ClientConfig;
use exogress_entities::{AccountName, InstanceId, ProjectName};
use reqwest::{Method, StatusCode, Url};
use serde::Serialize;
use smartstring::alias::String;

#[derive(Clone, Debug)]
pub struct Client {
    client: reqwest::Client,
    base_url: Url,
    name: String,
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
    pub fn new(mut webapp_base_url: Url, name: String) -> Self {
        {
            let mut segments = webapp_base_url.path_segments_mut().unwrap();
            segments.push("int");
            segments.push("api");
            segments.push("v1");
            segments.push("signalers");
            segments.push(name.as_str());
        }

        Client {
            client: reqwest::Client::default(),
            base_url: webapp_base_url,
            name,
        }
    }

    async fn execute_url<T: Serialize + ?Sized>(
        &self,
        url: Url,
        method: Method,
        authorization: Option<&str>,
        body: &T,
    ) -> Result<(), Error> {
        let mut req = self.client.request(method, url).json(body);

        if let Some(auth) = authorization {
            req = req.header("Authorization", auth.to_string());
        }

        let res = req.send().await?;

        match res.status() {
            code if code.is_success() => Ok(()),
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

    async fn execute_signaler(&self, method: Method) -> Result<(), Error> {
        let url = self.base_url.clone();

        self.execute_url(url, method, None, &()).await
    }

    async fn execute_presence<T: Serialize + ?Sized>(
        &self,
        method: Method,
        instance_id: &InstanceId,
        authorization: &str,
        params: Option<&str>,
        config: &T,
    ) -> Result<(), Error> {
        let mut url: Url = self.base_url.clone();
        {
            let mut segments = url.path_segments_mut().unwrap();
            segments.push("instances");
            segments.push(instance_id.to_string().as_str());
        }

        url.set_query(params);

        self.execute_url(url, method, Some(authorization), config)
            .await
    }

    pub async fn register_signaler(&self) -> Result<(), Error> {
        self.execute_signaler(Method::POST).await
    }

    pub async fn unregister_signaler(&self) -> Result<(), Error> {
        self.execute_signaler(Method::DELETE).await
    }

    pub async fn set_online(
        &self,
        instance_id: &InstanceId,
        authorization: &str,
        project: &ProjectName,
        account: &AccountName,
        labels_json: &String,
        config: &ClientConfig,
    ) -> Result<(), Error> {
        let args = format!(
            "project={}&account={}&labels_json={}",
            project,
            account,
            urlencoding::encode(&labels_json)
        );

        self.execute_presence(
            Method::POST,
            instance_id,
            authorization,
            Some(args.as_str()),
            config,
        )
        .await
    }

    pub async fn signaler_alive(&self) -> Result<(), Error> {
        let mut url = self.base_url.clone();
        {
            let mut segments = url.path_segments_mut().unwrap();
            segments.push("alive");
        }

        self.execute_url(url, Method::POST, None, &()).await
    }

    pub async fn set_offline(
        &self,
        instance_id: &InstanceId,
        authorization: &str,
    ) -> Result<(), Error> {
        self.execute_presence(Method::DELETE, instance_id, authorization, None, &())
            .await
    }

    pub async fn update_presence(
        &self,
        instance_id: &InstanceId,
        authorization: &str,
        config: &ClientConfig,
    ) -> Result<(), Error> {
        self.execute_presence(Method::PUT, instance_id, authorization, None, config)
            .await
    }
}
