use crate::{
    http_serve::{
        logging::{save_body_state, LogMessageSendOnDrop},
        requests_processor::{
            helpers::copy_headers_from_proxy_res_to_res, post_processing::ResolvedPostProcessing,
            s3_bucket, HandlerInvocationResult,
        },
    },
    public_hyper_client::MeteredHttpConnector,
};
use core::mem;
use exogress_common::{
    config_core::referenced,
    entities::{exceptions, Exception},
};
use exogress_server_common::logging::{
    HandlerProcessingStep, HttpBodyLog, ProcessingStep, S3BucketHandlerLogMessage,
};
use hashbrown::HashMap;
use http::{Method, Request, Response};
use hyper::Body;
use langtag::LanguageTagBuf;
use rusty_s3::S3Action;
use smol_str::SmolStr;
use std::{sync::Arc, time::Duration};

#[derive(Debug, thiserror::Error, Clone)]
pub enum BucketError {
    #[error("bad S3 config")]
    BadConfig,

    #[error("referenced error: {_0}")]
    ReferencedError(#[from] referenced::Error),
}

impl BucketError {
    pub fn to_exception(&self) -> (Exception, HashMap<SmolStr, SmolStr>) {
        let data = HashMap::new();
        match self {
            BucketError::BadConfig => (exceptions::S3_BAD_CONFIGURATION.clone(), data),
            BucketError::ReferencedError(e) => e.to_exception(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedS3Bucket {
    pub client: hyper::Client<MeteredHttpConnector, hyper::Body>,
    pub credentials: Option<Result<rusty_s3::Credentials, referenced::Error>>,
    pub bucket: Result<rusty_s3::Bucket, s3_bucket::BucketError>,
    pub is_cache_enabled: bool,
    pub post_processing: ResolvedPostProcessing,
}

impl ResolvedS3Bucket {
    pub async fn invoke(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        _requested_url: &http::uri::Uri,
        rebased_url: &http::uri::Uri,
        language: &Option<LanguageTagBuf>,
        log_message_container: &Arc<parking_lot::Mutex<LogMessageSendOnDrop>>,
    ) -> HandlerInvocationResult {
        if req.method() != &Method::GET && req.method() != &Method::HEAD {
            return HandlerInvocationResult::ToNextHandler;
        }

        let bucket = try_or_to_exception!(self.bucket.as_ref());

        let proxy_response_body = HttpBodyLog::default();

        log_message_container
            .lock()
            .as_mut()
            .steps
            .push(ProcessingStep::Invoked(HandlerProcessingStep::S3Bucket(
                S3BucketHandlerLogMessage {
                    region: bucket.region().into(),
                    language: language.clone(),
                    proxy_response_body: proxy_response_body.clone(),
                },
            )));

        let credentials = if let Some(creds) = &self.credentials {
            Some(try_or_to_exception!(creds))
        } else {
            None
        };

        let action = rusty_s3::actions::GetObject::new(&bucket, credentials, rebased_url.path());
        let signed_url = action.sign(Duration::from_secs(60));

        let mut proxy_resp = try_or_exception!(
            self.client.get(signed_url.as_str().parse().unwrap()).await,
            exceptions::PROXY_BAD_GATEWAY
        );

        copy_headers_from_proxy_res_to_res(proxy_resp.headers(), res);

        *res.status_mut() = proxy_resp.status();

        let instrumented_response = save_body_state(
            mem::replace(proxy_resp.body_mut(), Body::empty()),
            log_message_container.clone(),
            proxy_response_body,
        );

        *res.body_mut() = instrumented_response;

        HandlerInvocationResult::Responded
    }
}
