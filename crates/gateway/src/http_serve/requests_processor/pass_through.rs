use crate::http_serve::requests_processor::HandlerInvocationResult;
use exogress_server_common::logging::LogMessage;
use http::{Request, Response};
use hyper::Body;
use url::Url;

#[derive(Debug)]
pub struct ResolvedPassThrough {}

impl ResolvedPassThrough {
    pub async fn invoke(
        &self,
        _req: &Request<Body>,
        _res: &mut Response<Body>,
        _requested_url: &Url,
        _rebased_url: &Url,
        _log_message: &mut LogMessage,
    ) -> HandlerInvocationResult {
        HandlerInvocationResult::ToNextHandler
    }
}
