use crate::http_serve::requests_processor::helpers::copy_headers_from_proxy_res_to_res;
use crate::http_serve::requests_processor::HandlerInvocationResult;
use crate::public_hyper_client::MeteredHttpsConnector;
use anyhow::Context;
use core::{fmt, mem};
use exogress_common::config_core::parametrized;
use exogress_common::config_core::parametrized::google::bucket::GcsBucket;
use exogress_server_common::logging::{
    GcsBucketHandlerLogMessage, HandlerProcessingStep, LogMessage, ProcessingStep,
};
use futures::TryStreamExt;
use http::header::CONTENT_DISPOSITION;
use http::HeaderValue;
use http::{Method, Request, Response};
use hyper::Body;
use langtag::LanguageTagBuf;
use parking_lot::Mutex;
use std::convert::{TryFrom, TryInto};

pub struct ResolvedGcsBucket {
    pub client: hyper::Client<MeteredHttpsConnector, hyper::Body>,
    pub bucket_name: Result<GcsBucket, parametrized::Error>,
    pub auth: Result<tame_oauth::gcp::ServiceAccountAccess, parametrized::Error>,
    pub token: Mutex<Option<tame_oauth::Token>>,
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

        let token_or_req = auth
            .get_token(&[tame_gcs::Scopes::ReadOnly])
            .expect("FIXME");

        let token = async {
            if let Some(token) = self.token.lock().clone() {
                if !token.has_expired() {
                    return token;
                }
            }

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

                    let mut auth_res = self
                        .client
                        .request(auth_req)
                        .await
                        .context("failed to send token request")
                        .expect("FIXME");

                    let mut converted_res = Response::new(
                        mem::replace(auth_res.body_mut(), Body::empty())
                            .try_fold(Vec::new(), |mut data, chunk| async move {
                                data.extend_from_slice(&chunk);
                                Ok(data)
                            })
                            .await
                            .expect("FIXME"),
                    );

                    *converted_res.headers_mut() = auth_res.headers().clone();
                    *converted_res.status_mut() = auth_res.status();

                    auth.parse_token_response(scope_hash, converted_res)
                        .expect("FIXME")
                }
            };

            *self.token.lock() = Some(new_token.clone());

            new_token
        }
        .await;

        let download_req_empty = tame_gcs::objects::Object::download(
            &(
                &tame_gcs::BucketName::try_from(bucket_name.name.as_str().to_string())
                    .expect("FIXME"),
                &tame_gcs::ObjectName::try_from(rebased_url.path()[1..].to_string())
                    .expect("FIXME"),
            ),
            None,
        )
        .expect("FIXME");

        let mut req = Request::new(Body::empty());
        *req.headers_mut() = download_req_empty.headers().clone();
        req.headers_mut().insert(
            http::header::AUTHORIZATION,
            token.try_into().expect("FIXME"),
        );
        *req.uri_mut() = download_req_empty.uri().clone();
        *req.method_mut() = download_req_empty.method().clone();

        let mut proxy_resp = self.client.request(req).await.expect("FIXME");

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
