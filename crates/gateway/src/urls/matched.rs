use crate::urls::matchable_url::MatchableUrl;
use crate::urls::{MatchPattern, Protocol};
use exogress_config_core::ClientHandler;
use exogress_entities::ConfigName;
use url::Url;

#[derive(Debug)]
pub struct Matched {
    pub url: MatchableUrl,
    pub pattern: MatchPattern,
    pub config_name: Option<ConfigName>,
}

impl Matched {
    // pub fn resolve_handler(
    //     self,
    //     rewrite_to: &ProxyMatchedTo,
    //     protocol: Protocol,
    // ) -> Result<ClientHandler, url::ParseError> {
    //     let mut rewritten_str = self.url.inner.clone();
    //
    //     rewritten_str.replace_range(0..self.pattern.matchable_prefix.len() - 1, "localhost");
    //
    //     let parsable = format!("http://{}", rewritten_str);
    //
    //     let mut url = Url::parse(&parsable)?;
    //
    //     let scheme = match (protocol, rewrite_to) {
    //         (Protocol::Http, _) => "http",
    //         (Protocol::WebSockets, _) => "ws",
    //     };
    //
    //     url.set_scheme(scheme).unwrap();
    //
    //     url.set_username(self.url.username.as_str()).unwrap();
    //     url.set_password(self.url.password.as_deref()).unwrap();
    //
    //     match rewrite_to {
    //         ProxyMatchedTo::Client {
    //             handlers_processor,
    //             account_name,
    //             project_name,
    //             account_unique_id,
    //         } => Ok(ClientHandler {
    //             account_name: account_name.clone(),
    //             handlers_processor: handlers_processor.clone(),
    //             url,
    //             project_name: project_name.clone(),
    //             account_unique_id: account_unique_id.clone(),
    //         }),
    //     }
    // }
}
