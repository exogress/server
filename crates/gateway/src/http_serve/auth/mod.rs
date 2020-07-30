use crate::url_mapping::mapping::Oauth2Provider;
use oauth2::basic::BasicTokenResponse;
use url::Url;

pub mod github;
pub mod google;

#[derive(Debug, Clone)]
pub struct FlowData {
    pub requested_url: Url,
    pub base_url: Url,
    pub jwt_secret: Vec<u8>,
    pub provider: Oauth2Provider,
}

#[derive(Clone, Debug)]
pub struct CallbackResult {
    pub token_response: BasicTokenResponse,
    pub oauth2_flow_data: FlowData,
}

#[derive(Debug, thiserror::Error)]
pub enum Oauth2FlowError {
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
