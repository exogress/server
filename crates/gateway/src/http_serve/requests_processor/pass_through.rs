use crate::http_serve::{
    logging::LogMessageSendOnDrop, requests_processor::HandlerInvocationResult,
};
use http::{Request, Response};
use hyper::Body;
use std::sync::Arc;

#[derive(Debug)]
pub struct ResolvedPassThrough {}

impl ResolvedPassThrough {
    pub async fn invoke(
        &self,
        _req: &Request<Body>,
        _res: &mut Response<Body>,
        _requested_url: &http::uri::Uri,
        _rebased_url: &http::uri::Uri,
        _log_message_container: &Arc<parking_lot::Mutex<LogMessageSendOnDrop>>,
    ) -> HandlerInvocationResult {
        HandlerInvocationResult::ToNextHandler
    }
}
