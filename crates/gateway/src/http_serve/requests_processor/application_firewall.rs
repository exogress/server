use crate::http_serve::requests_processor::HandlerInvocationResult;
use exogress_common::entities::exceptions;
use exogress_server_common::logging::{
    ApplicationFirewallAction, ApplicationFirewallLogMessage, HandlerProcessingStep, LogMessage,
    ProcessingStep,
};
use hashbrown::HashMap;
use http::{Request, Response};
use hyper::Body;
use langtag::LanguageTagBuf;

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
        _requested_url: &http::uri::Uri,
        _rebased_url: &http::uri::Uri,
        language: &Option<LanguageTagBuf>,
        log_message: &mut LogMessage,
    ) -> HandlerInvocationResult {
        let raw_path_and_query = req.uri().path_and_query().unwrap().to_string();
        let decoded_path_and_query =
            percent_encoding::percent_decode_str(raw_path_and_query.as_str())
                .decode_utf8()
                .expect("FIXME");

        let mut detected = vec![];

        if self.uri_sqli {
            let result = libinjection::sqli(decoded_path_and_query.as_ref());

            if let Some((is_sqli, fingerprint)) = result {
                if is_sqli {
                    detected.push(format!("libinjection:sqli:{}", fingerprint));
                }
            }
        }

        if self.uri_xss {
            if libinjection::xss(decoded_path_and_query.as_ref()).unwrap_or(false) {
                detected.push("libinjection:xss".to_string());
            }
        }

        let is_detected = !detected.is_empty();

        log_message.steps.push(ProcessingStep::Invoked(
            HandlerProcessingStep::ApplicationFirewall(ApplicationFirewallLogMessage {
                detected: detected.clone(),
                action: if is_detected {
                    ApplicationFirewallAction::Prohibited
                } else {
                    ApplicationFirewallAction::Permitted
                },
                language: language.clone(),
            }),
        ));

        if is_detected {
            let mut data = HashMap::new();
            data.insert("detected".into(), detected.join(", ").into());
            HandlerInvocationResult::Exception {
                name: exceptions::APPLICATION_FIREWALL_INJECTION_DETECTED.clone(),
                data,
            }
        } else {
            HandlerInvocationResult::ToNextHandler
        }
    }
}
