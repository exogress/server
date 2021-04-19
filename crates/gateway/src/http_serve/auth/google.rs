use std::time::Duration;

use crate::http_serve::auth::{
    retrieve_assistant_key, save_assistant_key, AssistantError, CallbackResult, FlowData, JwtEcdsa,
    Oauth2FlowError, Oauth2Provider,
};
use exogress_common::entities::HandlerName;
use linked_hash_map::LinkedHashMap;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use url::Url;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct GoogleClientCreds {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GoogleUserResponse {
    email: String,
}

impl GoogleClientCreds {
    fn client(&self) -> BasicClient {
        let google_client_id = ClientId::new(self.client_id.clone());
        let google_client_secret = ClientSecret::new(self.client_secret.clone());
        let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".into())
            .expect("Invalid authorization endpoint URL");
        let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".into())
            .expect("Invalid token endpoint URL");

        // Set up the config for the Google OAuth2 process.
        BasicClient::new(
            google_client_id,
            Some(google_client_secret),
            auth_url,
            Some(token_url),
        )
        .set_redirect_uri(
            RedirectUrl::new(self.redirect_url.to_string()).expect("Invalid redirect URL"),
        )
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Oauth2FlowData {
    pkce_code_verifier: PkceCodeVerifier,
    data: FlowData,
}

#[derive(Clone, Debug)]
pub struct GoogleOauth2Client {
    assistant_base_url: Url,
    creds: GoogleClientCreds,
    ttl: Duration,
    maybe_identity: Option<Vec<u8>>,
}

impl GoogleOauth2Client {
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
            .push("google")
            .push("callback");

        GoogleOauth2Client {
            assistant_base_url,
            creds: GoogleClientCreds {
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

        let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

        let (authorize_url, csrf_state) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("https://www.googleapis.com/auth/plus.me".into()))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.email".into(),
            ))
            .set_pkce_challenge(pkce_code_challenge)
            .url();

        save_assistant_key(
            &self.assistant_base_url,
            csrf_state.secret().as_str(),
            &Oauth2FlowData {
                pkce_code_verifier,
                data: FlowData {
                    requested_url: requested_url.clone(),
                    jwt_ecdsa: jwt_ecdsa.clone(),
                    fqdn: fqdn.to_string(),
                    provider: Oauth2Provider::Google,
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
            .set_pkce_verifier(oauth2_flow_data.pkce_code_verifier)
            .request_async(async_http_client)
            .await
            .map_err(Oauth2FlowError::RequestTokenError)?;

        let user_resp = reqwest::Client::new()
            .get("https://www.googleapis.com/oauth2/v3/userinfo")
            .header(
                "Authorization",
                format!("Bearer {}", token.access_token().secret()),
            )
            .send()
            .await
            .map_err(Oauth2FlowError::RetrieveUserInfoError)?;

        let status = user_resp.status();

        if !status.is_success() {
            Err(Oauth2FlowError::RetrieveUserInfoBadStatus(status))
        } else {
            let user_info = user_resp
                .json::<GoogleUserResponse>()
                .await
                .map_err(Oauth2FlowError::RetrieveUserInfoBadResponse)?;

            Ok(CallbackResult {
                identities: vec![user_info.email],
                token_response: token,
                oauth2_flow_data: oauth2_flow_data.data,
            })
        }
    }
}
