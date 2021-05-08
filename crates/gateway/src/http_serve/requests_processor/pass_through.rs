use crate::http_serve::requests_processor::HandlerInvocationResult;
use http::{Request, Response};
use hyper::Body;

#[derive(Debug)]
pub struct ResolvedPassThrough {}

impl ResolvedPassThrough {
    pub async fn invoke(
        &self,
        _req: &Request<Body>,
        _res: &mut Response<Body>,
        _requested_url: &http::uri::Uri,
        _rebased_url: &http::uri::Uri,
    ) -> HandlerInvocationResult {
        HandlerInvocationResult::ToNextHandler
    }
}
