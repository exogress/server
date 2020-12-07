use exogress_config_core::AuthProvider;
use exogress_entities::HandlerName;
use exogress_server_common::assistant::{GetValue, SetValue};
use exogress_server_common::url_prefix::MountPointBaseUrl;
use http::StatusCode;
use oauth2::basic::BasicTokenResponse;
use reqwest::Identity;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

pub mod github;
pub mod google;

#[derive(Debug, Clone, Copy)]
pub struct Oauth2SsoClient {
    pub provider: Oauth2Provider,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy)]
pub enum Oauth2Provider {
    #[serde(rename = "google")]
    Google,
    #[serde(rename = "github")]
    Github,
}

impl ToString for Oauth2Provider {
    fn to_string(&self) -> std::string::String {
        match self {
            Oauth2Provider::Google => "google",
            Oauth2Provider::Github => "github",
        }
        .to_string()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AuthProviderConfig {
    Oauth2(Oauth2SsoClient),
}

impl From<AuthProvider> for AuthProviderConfig {
    fn from(provider: AuthProvider) -> Self {
        match provider {
            AuthProvider::Google => AuthProviderConfig::Oauth2(Oauth2SsoClient {
                provider: Oauth2Provider::Google,
            }),
            AuthProvider::Github => AuthProviderConfig::Oauth2(Oauth2SsoClient {
                provider: Oauth2Provider::Github,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtEcdsa {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowData {
    pub requested_url: Url,
    pub base_url: MountPointBaseUrl,
    pub jwt_ecdsa: JwtEcdsa,
    pub provider: Oauth2Provider,
    pub handler_name: HandlerName,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthFinalizer {
    pub identities: Vec<String>,
    pub oauth2_flow_data: FlowData,
}

#[derive(Clone, Debug)]
pub struct CallbackResult {
    pub identities: Vec<String>,
    pub token_response: BasicTokenResponse,
    pub oauth2_flow_data: FlowData,
}

#[derive(Debug, thiserror::Error)]
pub enum Oauth2FlowError {
    #[error("error retrieving user info: {_0}")]
    RetrieveUserInfoError(reqwest::Error),

    #[error("retrieving user info bad status: {_0}")]
    RetrieveUserInfoBadStatus(reqwest::StatusCode),

    #[error("retrieving user info bad response: {_0}")]
    RetrieveUserInfoBadResponse(reqwest::Error),

    #[error("error in persisting state: {_0}")]
    PersistentStateError(#[from] AssistantError),

    #[error("no `code` param in google oauth2 callback")]
    NoCodeInCallback,

    #[error("state (CSRF) not found")]
    StateNotFound,

    #[error("no `state` param in google oauth2 callback")]
    NoStateInCallback,

    #[error("error requesting oauth2 token: `{0}`")]
    // RequestTokenError is not Error, no conversion allowed
    RequestTokenError(
        oauth2::RequestTokenError<
            oauth2::reqwest::Error<reqwest::Error>,
            oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
        >,
    ),
}

#[derive(Debug, thiserror::Error)]
pub enum AssistantError {
    #[error("reqwest error: {_0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("parse error: {_0}")]
    ParseError(#[from] serde_json::Error),

    #[error("bad status: {_0}")]
    BadStatus(StatusCode),
}

pub async fn retrieve_assistant_key<T: DeserializeOwned>(
    assistant_url: &Url,
    key: &str,
    maybe_identity: Option<Vec<u8>>,
) -> Result<T, AssistantError> {
    let mut url = assistant_url.clone();
    if url.scheme() == "wss" {
        url.set_scheme("https").unwrap();
    } else if url.scheme() == "ws" {
        url.set_scheme("http").unwrap();
    };

    url.path_segments_mut()
        .unwrap()
        .push("int_api")
        .push("v1")
        .push("keys")
        .push(key);

    let mut builder = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .use_rustls_tls()
        .trust_dns(true);

    if let Some(identity) = maybe_identity {
        builder = builder.identity(Identity::from_pem(&identity).unwrap());
    }

    info!("request url {}", url);
    let resp = builder.build().unwrap().get(url).send().await?;
    info!("request status {:?}", resp.status());

    if resp.status().is_success() {
        let value: GetValue = resp.json().await?;
        Ok(serde_json::from_str::<T>(value.payload.as_str())?)
    } else {
        Err(AssistantError::BadStatus(resp.status()))
    }
}

pub async fn save_assistant_key<T: Serialize>(
    assistant_url: &Url,
    key: &str,
    value: &T,
    ttl: Duration,
    maybe_identity: Option<Vec<u8>>,
) -> Result<(), AssistantError> {
    let mut url = assistant_url.clone();
    if url.scheme() == "wss" {
        url.set_scheme("https").unwrap();
    } else if url.scheme() == "ws" {
        url.set_scheme("http").unwrap();
    };

    url.path_segments_mut()
        .unwrap()
        .push("int_api")
        .push("v1")
        .push("keys")
        .push(key);

    let payload = serde_json::to_string(value)?;

    let mut builder = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .use_rustls_tls()
        .trust_dns(true);

    if let Some(identity) = maybe_identity {
        builder = builder.identity(Identity::from_pem(&identity).unwrap());
    }

    info!("request url {}", url);

    let resp = builder
        .build()
        .unwrap()
        .post(url)
        .json(&SetValue { payload, ttl })
        .send()
        .await?;
    info!("request status {:?}", resp.status());

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(AssistantError::BadStatus(resp.status()))
    }
}
