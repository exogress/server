use std::time::Duration;

use crate::http_serve::auth::{
    retrieve_assistant_key, save_assistant_key, AssistantError, CallbackResult, FlowData, JwtEcdsa,
    Oauth2FlowError, Oauth2Provider,
};
use exogress_common::entities::HandlerName;
use linked_hash_map::LinkedHashMap;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use url::Url;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct GithubClientCreds {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubUserResponse {
    login: String,
    email: Option<String>,
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
            .set_redirect_uri(
                RedirectUrl::new(self.redirect_url.to_string()).expect("Invalid redirect URL"),
            )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Oauth2FlowData {
    data: FlowData,
}

#[derive(Clone, Debug)]
pub struct GithubOauth2Client {
    assistant_base_url: Url,
    creds: GithubClientCreds,
    ttl: Duration,
    maybe_identity: Option<Vec<u8>>,
}

impl GithubOauth2Client {
    pub fn new(
        ttl: Duration,
        client_id: String,
        client_secret: String,
        public_base_url: Url,
        assistant_base_url: Url,
        maybe_identity: Option<Vec<u8>>,
    ) -> Self {
        let mut redirect_url = public_base_url;

        redirect_url
            .path_segments_mut()
            .unwrap()
            .push("_exg")
            .push("github")
            .push("callback");

        GithubOauth2Client {
            assistant_base_url,
            creds: GithubClientCreds {
                client_id,
                client_secret,
                redirect_url: redirect_url.to_string(),
            },
            ttl,
            maybe_identity,
        }
    }

    pub async fn save_state_and_retrieve_authorization_url(
        &self,
        fqdn: &str,
        jwt_ecdsa: &JwtEcdsa,
        requested_url: &Url,
        handler_name: &HandlerName,
    ) -> Result<String, AssistantError> {
        let client = self.creds.client();

        let (authorize_url, csrf_state) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("user:email".into()))
            .url();

        save_assistant_key(
            &self.assistant_base_url,
            csrf_state.secret().as_str(),
            &Oauth2FlowData {
                data: FlowData {
                    requested_url: requested_url.clone(),
                    jwt_ecdsa: jwt_ecdsa.clone(),
                    fqdn: fqdn.to_string(),
                    provider: Oauth2Provider::Github,
                    handler_name: handler_name.clone(),
                },
            },
            self.ttl,
            self.maybe_identity.clone(),
        )
        .await?;

        Ok(authorize_url.to_string())
    }

    pub async fn process_callback(
        &self,
        mut params: LinkedHashMap<String, String>,
    ) -> Result<CallbackResult, Oauth2FlowError> {
        let received_state = CsrfToken::new(
            params
                .remove("state")
                .ok_or(Oauth2FlowError::NoStateInCallback)?,
        );

        let oauth2_flow_data = retrieve_assistant_key::<Oauth2FlowData>(
            &self.assistant_base_url,
            received_state.secret(),
            self.maybe_identity.clone(),
        )
        .await?;

        let code_param = params
            .remove("code")
            .ok_or(Oauth2FlowError::NoCodeInCallback)?;
        let code_param_decoded = percent_encoding::percent_decode_str(&code_param).decode_utf8()?;
        let code = AuthorizationCode::new(code_param_decoded.to_string());

        let token = self
            .creds
            .client()
            .exchange_code(code)
            .request_async(async_http_client)
            .await
            .map_err(Oauth2FlowError::RequestTokenError)?;

        let user_resp = reqwest::Client::new()
            .get("https://api.github.com/user")
            .header(
                "Authorization",
                format!("token {}", token.access_token().secret()),
            )
            .header(
                "User-Agent",
                format!("Exogress Gateway/{}", clap::crate_version!()),
            )
            .send()
            .await
            .map_err(Oauth2FlowError::RetrieveUserInfoError)?;

        let status = user_resp.status();

        if !status.is_success() {
            let text = user_resp.text().await;
            info!("Error retrieving user data: {:?}", text);

            Err(Oauth2FlowError::RetrieveUserInfoBadStatus(status))
        } else {
            let user_info = user_resp
                .json::<GithubUserResponse>()
                .await
                .map_err(Oauth2FlowError::RetrieveUserInfoBadResponse)?;

            let mut identities = vec![user_info.login];
            if let Some(email) = user_info.email {
                identities.push(email);
            }

            Ok(CallbackResult {
                identities,
                token_response: token,
                oauth2_flow_data: oauth2_flow_data.data,
            })
        }
    }
}
