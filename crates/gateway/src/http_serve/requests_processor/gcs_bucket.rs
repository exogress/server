use crate::{
    http_serve::requests_processor::{
        helpers::copy_headers_from_proxy_res_to_res, post_processing::ResolvedPostProcessing,
        HandlerInvocationResult,
    },
    public_hyper_client::MeteredHttpsConnector,
};
use core::{fmt, mem};
use exogress_common::{
    config_core::{referenced, referenced::google::bucket::GcsBucket},
    entities::{exceptions, Exception},
};
use exogress_server_common::logging::{
    GcsBucketHandlerLogMessage, HandlerProcessingStep, LogMessage, ProcessingStep,
};
use futures::TryStreamExt;
use hashbrown::HashMap;
use http::{header::CONTENT_DISPOSITION, HeaderValue, Method, Request, Response};
use hyper::Body;
use langtag::LanguageTagBuf;
use smol_str::SmolStr;
use std::convert::{TryFrom, TryInto};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("oAuth2 error: {_0}")]
    TameOauth2Error(#[from] tame_oauth::Error),

    #[error("referenced error: {_0}")]
    ReferencedError(#[from] referenced::Error),
}

impl AuthError {
    pub fn to_exception(&self) -> (Exception, HashMap<SmolStr, SmolStr>) {
        let mut data = HashMap::new();
        match self {
            AuthError::TameOauth2Error(err) => {
                data.insert("error".into(), err.to_string().into());
                (exceptions::GCS_BAD_CONFIGURATION.clone(), data)
            }
            AuthError::ReferencedError(e) => e.to_exception(),
        }
    }
}

pub struct ResolvedGcsBucket {
    pub client: hyper::Client<MeteredHttpsConnector, hyper::Body>,
    pub bucket_name: Result<GcsBucket, referenced::Error>,
    pub auth: Result<tame_oauth::gcp::ServiceAccountAccess, AuthError>,
    pub token: tokio::sync::Mutex<Option<tame_oauth::Token>>,
    pub is_cache_enabled: bool,
    pub post_processing: ResolvedPostProcessing,
}

impl fmt::Debug for ResolvedGcsBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedGcsBucket")
            .field("bucket_name", &self.bucket_name)
            .finish()
    }
}

impl ResolvedGcsBucket {
    pub async fn invoke(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        _requested_url: &http::uri::Uri,
        rebased_url: &http::uri::Uri,
        language: &Option<LanguageTagBuf>,
        log_message: &mut LogMessage,
    ) -> HandlerInvocationResult {
        if req.method() != &Method::GET && req.method() != &Method::HEAD {
            return HandlerInvocationResult::ToNextHandler;
        }

        let auth = try_or_to_exception!(self.auth.as_ref());
        let bucket_name = try_or_to_exception!(self.bucket_name.as_ref());

        log_message
            .steps
            .push(ProcessingStep::Invoked(HandlerProcessingStep::GcsBucket(
                GcsBucketHandlerLogMessage {
                    bucket: bucket_name.name.clone(),
                    language: language.clone(),
                },
            )));

        let token_or_req = try_or_exception!(
            auth.get_token(&[tame_gcs::Scopes::ReadOnly]),
            exceptions::GCS_AUTH_ERROR_BUILD_REQUEST_EROR
        );

        let token = match self.token.lock().await.clone() {
            Some(token) if !token.has_expired() => token,
            _ => {
                let new_token = match token_or_req {
                    tame_oauth::gcp::TokenOrRequest::Token(token) => token,
                    tame_oauth::gcp::TokenOrRequest::Request {
                        request,
                        scope_hash,
                        ..
                    } => {
                        let (parts, body) = request.into_parts();
                        let read_body = Body::from(body);
                        let auth_req = http::Request::from_parts(parts, read_body);

                        let mut auth_res = try_or_exception!(
                            self.client.request(auth_req).await,
                            exceptions::PROXY_BAD_GATEWAY
                        );

                        let resp_bytes = try_or_exception!(
                            mem::replace(auth_res.body_mut(), Body::empty())
                                .try_fold(Vec::new(), |mut data, chunk| async move {
                                    data.extend_from_slice(&chunk);
                                    Ok(data)
                                })
                                .await,
                            exceptions::PROXY_BAD_GATEWAY
                        );

                        let mut converted_res = Response::new(resp_bytes);

                        *converted_res.headers_mut() = auth_res.headers().clone();
                        *converted_res.status_mut() = auth_res.status();

                        try_or_exception!(
                            auth.parse_token_response(scope_hash, converted_res),
                            exceptions::GCS_AUTH_ERROR_BAD_RESPONSE
                        )
                    }
                };

                *self.token.lock().await = Some(new_token.clone());

                new_token
            }
        };

        let bucket_name = try_or_exception!(
            tame_gcs::BucketName::try_from(bucket_name.name.as_str().to_string()),
            exceptions::GCS_BAD_BUCKET_NAME
        );
        let object_name = try_or_exception!(
            tame_gcs::ObjectName::try_from(rebased_url.path()[1..].to_string()),
            exceptions::GCS_BAD_OBJECT_NAME
        );
        let download_req_empty = try_or_exception!(
            tame_gcs::objects::Object::download(&(&bucket_name, &object_name), None),
            exceptions::PROXY_BAD_GATEWAY
        );

        let mut req = Request::new(Body::empty());
        *req.headers_mut() = download_req_empty.headers().clone();
        req.headers_mut()
            .insert(http::header::AUTHORIZATION, token.try_into().unwrap());
        *req.uri_mut() = download_req_empty.uri().clone();
        *req.method_mut() = download_req_empty.method().clone();

        let mut proxy_resp = try_or_exception!(
            self.client.request(req).await,
            exceptions::PROXY_BAD_GATEWAY
        );

        copy_headers_from_proxy_res_to_res(proxy_resp.headers(), res);

        *res.status_mut() = proxy_resp.status();
        res.headers_mut().insert(
            CONTENT_DISPOSITION,
            HeaderValue::try_from("inline").unwrap(),
        );

        *res.body_mut() = mem::replace(proxy_resp.body_mut(), Body::empty());

        HandlerInvocationResult::Responded
    }
}
