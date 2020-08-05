use std::sync::Arc;
use std::time::Duration;

use crate::http_serve::auth::FlowData;
// use crate::url_mapping::mapping::Oauth2Provider;
use hashbrown::HashMap;
use lru_time_cache::LruCache;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AsyncCodeTokenRequest, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    RedirectUrl, Scope, TokenUrl,
};
use parking_lot::Mutex;
use url::Url;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct GithubClientCreds {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

impl GithubClientCreds {
    fn client(&self) -> BasicClient {
        let client_id = ClientId::new(self.client_id.clone());
        let client_secret = ClientSecret::new(self.client_secret.clone());

        let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".into())
            .expect("Invalid authorization endpoint URL");
        let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".into())
            .expect("Invalid token endpoint URL");

        // Set up the config for the Github OAuth2 process.
        BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
            .set_redirect_url(
                RedirectUrl::new(self.redirect_url.to_string()).expect("Invalid redirect URL"),
            )
    }
}

pub struct Oauth2FlowData {
    data: FlowData,
}

pub struct Inner {
    // verifiers: LruCache<String, Oauth2FlowData>,
}

#[derive(Clone)]
pub struct GithubOauth2Client {
    inner: Arc<Mutex<Inner>>,
    creds: GithubClientCreds,
}

impl GithubOauth2Client {
    pub fn new(
        ttl: Duration,
        client_id: String,
        client_secret: String,
        public_base_url: Url,
    ) -> Self {
        let mut redirect_url = public_base_url;

        redirect_url
            .path_segments_mut()
            .unwrap()
            .push("_exg")
            .push("github")
            .push("callback");

        GithubOauth2Client {
            inner: Arc::new(Mutex::new(Inner {
                verifiers: LruCache::with_expiry_duration(ttl),
            })),
            creds: GithubClientCreds {
                client_id,
                client_secret,
                redirect_url: redirect_url.to_string(),
            },
        }
    }

    pub fn authorization_url(
        &self,
        base_url: &Url,
        jwt_secret: &[u8],
        requested_url: &Url,
    ) -> String {
        let client = self.creds.client();

        let (authorize_url, csrf_state) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("user:email".into()))
            .url();

        // self.inner.lock().verifiers.insert(
        //     csrf_state.secret().clone(),
        //     Oauth2FlowData {
        //         data: FlowData {
        //             requested_url: requested_url.clone(),
        //             jwt_secret: jwt_secret.to_vec(),
        //             base_url: base_url.clone(),
        //             provider: Oauth2Provider::Github,
        //         },
        //     },
        // );

        authorize_url.to_string()
    }

    pub async fn process_callback(
        &self,
        mut params: HashMap<String, String>,
    ) -> Result<CallbackResult, Oauth2FlowError> {
        let received_state = CsrfToken::new(
            params
                .remove("state")
                .ok_or(Oauth2FlowError::NoStateInCallback)?,
        );

        let oauth2_flow_data = self
            .inner
            .lock()
            .verifiers
            .remove(received_state.secret())
            .ok_or(Oauth2FlowError::StateNotFound)?;

        let code = AuthorizationCode::new(
            params
                .remove("code")
                .ok_or(Oauth2FlowError::NoCodeInCallback)?,
        );

        let token = self
            .creds
            .client()
            .exchange_code(code)
            .request_async(async_http_client)
            .await
            .map_err(Oauth2FlowError::RequestTokenError)?;

        Ok(CallbackResult {
            token_response: token,
            oauth2_flow_data: oauth2_flow_data.data,
        })
    }
}
