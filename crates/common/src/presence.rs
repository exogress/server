//! Presence API
use exogress_common::config_core::ClientConfig;
use exogress_common::entities::{
    AccessKeyId, AccountName, AccountUniqueId, HealthCheckProbeName, InstanceId, ProjectName,
    SmolStr, Upstream,
};
use exogress_common::signaling::ProbeHealthStatus;
use hashbrown::HashMap;
use reqwest::{Identity, Method, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nothing {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstanceRegistered {
    pub instance_id: InstanceId,
    pub account_unique_id: AccountUniqueId,
    pub access_key_id: AccessKeyId,
}

#[derive(Clone, Debug)]
pub struct Client {
    pub client: reqwest::Client,
    pub base_url: Arc<Url>,
    // TODO: signaler_id rework, so that signaler_id may not be provided
    pub signaler_id: SmolStr,
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
    pub fn new(webapp_base_url: Url, name: String, maybe_identity: Option<Vec<u8>>) -> Self {
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
            base_url: Arc::new(webapp_base_url),
            signaler_id: name.into(),
        }
    }

    async fn execute_url<T: Serialize + ?Sized, R: Serialize + DeserializeOwned + Sized>(
        &self,
        url: Url,
        method: Method,
        authorization: Option<&str>,
        body: &T,
    ) -> Result<R, Error> {
        let mut req = self.client.request(method, url.clone()).json(body);

        if let Some(auth) = authorization {
            req = req.header("Authorization", auth.to_string());
        }

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

    async fn execute_signaler(&self, method: Method) -> Result<Nothing, Error> {
        let mut url = (&*self.base_url).clone();

        {
            let mut segments = url.path_segments_mut().unwrap();
            segments.push("int_api");
            segments.push("v1");
            segments.push("signalers");
            segments.push(self.signaler_id.as_str());
        }

        self.execute_url(url, method, None, &()).await
    }

    async fn execute_presence<T: Serialize + ?Sized, R: Serialize + DeserializeOwned + Sized>(
        &self,
        with_signaler_id: bool,
        method: Method,
        instance_id: Option<&InstanceId>,
        authorization: &str,
        params: Option<&str>,
        config: &T,
    ) -> Result<R, Error> {
        let mut url: Url = (&*self.base_url).clone();

        {
            let mut segments = url.path_segments_mut().unwrap();
            segments.push("int_api").push("v1");
            if with_signaler_id {
                segments.push("signalers").push(self.signaler_id.as_str());
            }
            segments.push("instances");
            if let Some(instance_id) = instance_id {
                segments.push(instance_id.to_string().as_str());
            }
        }

        url.set_query(params);

        self.execute_url(url, method, Some(authorization), config)
            .await
    }

    pub async fn register_signaler(&self) -> Result<Nothing, Error> {
        self.execute_signaler(Method::POST).await
    }

    pub async fn unregister_signaler(&self) -> Result<Nothing, Error> {
        self.execute_signaler(Method::DELETE).await
    }

    pub async fn set_online(
        &self,
        authorization: &str,
        project: &ProjectName,
        account: &AccountName,
        labels_json: &String,
        config: &ClientConfig,
    ) -> Result<InstanceRegistered, Error> {
        let args = format!(
            "project={}&account={}&labels_json={}",
            urlencoding::encode(project),
            urlencoding::encode(account),
            urlencoding::encode(&labels_json)
        );

        self.execute_presence(
            true,
            Method::POST,
            None,
            authorization,
            Some(args.as_str()),
            config,
        )
        .await
    }

    pub async fn signaler_alive(&self) -> Result<Nothing, Error> {
        let mut url = (&*self.base_url).clone();
        {
            let mut segments = url.path_segments_mut().unwrap();
            segments
                .push("int_api")
                .push("v1")
                .push("signalers")
                .push(self.signaler_id.as_str())
                .push("alive");
        }

        self.execute_url(url, Method::POST, None, &()).await
    }

    pub async fn set_offline(
        &self,
        instance_id: &InstanceId,
        authorization: &str,
        is_unreachable: bool,
    ) -> Result<Nothing, Error> {
        self.execute_presence(
            false,
            Method::DELETE,
            Some(instance_id),
            authorization,
            if is_unreachable {
                Some("unreachable=1")
            } else {
                None
            },
            &(),
        )
        .await
    }

    pub async fn update_presence(
        &self,
        instance_id: &InstanceId,
        authorization: &str,
        config: &ClientConfig,
    ) -> Result<Nothing, Error> {
        self.execute_presence(
            false,
            Method::PUT,
            Some(instance_id),
            authorization,
            None,
            config,
        )
        .await
    }

    pub async fn report_health(&self, report: UpstreamHealthReport) -> Result<(), Error> {
        let mut url = (&*self.base_url).clone();
        url.path_segments_mut()
            .unwrap()
            .push("int_api")
            .push("v1")
            .push("healths");

        let res = self.client.post(url).json(&report).send().await?;

        if res.status().is_success() {
            Ok(())
        } else {
            Err(Error::BadResponse(res.status()))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamHealthReport {
    pub instance_id: InstanceId,
    pub account_name: AccountName,
    pub project_name: ProjectName,
    pub health_probes: HashMap<Upstream, HashMap<HealthCheckProbeName, ProbeHealthStatus>>,
}
