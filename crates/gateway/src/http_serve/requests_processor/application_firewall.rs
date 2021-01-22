use crate::http_serve::requests_processor::HandlerInvocationResult;
use exogress_server_common::logging::{
    ApplicationFirewallLogMessage, HandlerProcessingStep, LogMessage, ProcessingStep,
};
use hashbrown::HashMap;
use http::{Request, Response};
use hyper::Body;
use url::Url;

#[derive(Debug)]
pub struct ResolvedApplicationFirewall {
    pub uri_xss: bool,
    pub uri_sqli: bool,
}

impl ResolvedApplicationFirewall {
    pub async fn invoke(
        &self,
        req: &Request<Body>,
        _res: &mut Response<Body>,
        _requested_url: &Url,
        _rebased_url: &Url,
        log_message: &mut LogMessage,
    ) -> HandlerInvocationResult {
        let raw_path_and_query = req.uri().path_and_query().unwrap().to_string();
        let decoded_path_and_query =
            percent_encoding::percent_decode_str(raw_path_and_query.as_str())
                .decode_utf8()
                .expect("FIXME");

        info!("check {} for injection", decoded_path_and_query);

        let mut sqli_result = None;
        let mut xss_result = false;

        if self.uri_sqli {
            let result = libinjection::sqli(decoded_path_and_query.as_ref());

            sqli_result = if let Some((is_sqli, fingerprint)) = result {
                if is_sqli {
                    Some(fingerprint)
                } else {
                    None
                }
            } else {
                None
            }
        }

        if self.uri_xss {
            xss_result = libinjection::xss(decoded_path_and_query.as_ref()).unwrap_or(false);
        }

        info!("result: XSS = {:?}, SQLi = {:?}", xss_result, sqli_result);

        let is_detected = sqli_result.is_some() || xss_result;

        log_message.steps.push(ProcessingStep::Invoked(
            HandlerProcessingStep::ApplicationFirewall(ApplicationFirewallLogMessage {
                sqli_detected: sqli_result.clone(),
                xss_detected: xss_result,
                is_passed: !is_detected,
            }),
        ));

        if is_detected {
            let mut data = HashMap::new();
            data.insert(
                "sqli".into(),
                sqli_result.unwrap_or_else(|| "none".into()).into(),
            );
            data.insert("xss".into(), xss_result.to_string().into());
            HandlerInvocationResult::Exception {
                name: "application-firewall-error:injection-detected"
                    .parse()
                    .unwrap(),
                data,
            }
        } else {
            HandlerInvocationResult::ToNextHandler
        }
    }
}
