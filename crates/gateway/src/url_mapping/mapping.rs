use std::fmt;
use std::str::FromStr;

use chrono::serde::ts_milliseconds;
use chrono::{DateTime, Utc};

use http::Uri;
use smallvec::SmallVec;
use smartstring::alias::String;
use url::Url;

use exogress_config_core::{AuthProvider, Config};
use exogress_entities::{AccountName, ConfigName, InstanceId, ProjectName};

use crate::clients::ClientTunnels;
use crate::url_mapping::handlers::HandlersProcessor;
use crate::url_mapping::rate_limiter::RateLimiters;
use crate::url_mapping::url_prefix::UrlPrefix;

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    cn: String,
    certificate: String,
    private_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InstanceSchema {
    config: Config,
    instance_id: InstanceId,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SchemaConfigs {
    #[serde(with = "ts_milliseconds")]
    generated_at: DateTime<Utc>,
    url_prefix: String,
    tls: TlsConfig,
    instances: SmallVec<[InstanceSchema; 8]>,
}

/// UrlForRewriting
/// MatchPattern
/// RewriteTemplate
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UrlForRewriting {
    inner: String,
    host: String,
    path: String,
    username: String,
    password: Option<String>,
}

impl UrlForRewriting {
    pub fn to_url_prefix(&self) -> UrlPrefix {
        let s = format!("{}{}", self.host, self.path);
        UrlPrefix::from_str(s.as_ref()).expect("unexpected bad data in UrlForRewriting")
    }
}

impl fmt::Display for UrlForRewriting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum UrlForRewritingError {
    #[error("port should not exist")]
    PortFound,

    #[error("path should start from '/'")]
    NoRootPath,
}

impl UrlForRewriting {
    #[allow(dead_code)]
    pub fn from_url(mut url: Url) -> Self {
        url.set_port(None).unwrap();
        url.set_scheme("https").unwrap();

        let host = url.host_str().unwrap().into();
        let path = url.path().into();

        UrlForRewriting {
            host,
            password: url.password().map(|s| s.into()),
            username: url.username().into(),
            inner: url.to_string().trim_start_matches("https://").into(),
            path,
        }
    }

    pub fn from_components(
        host_without_port: &str,
        path: &str,
        query: &str,
    ) -> Result<Self, UrlForRewritingError> {
        if host_without_port.contains(":") {
            return Err(UrlForRewritingError::PortFound);
        }

        let host = host_without_port.into();

        let mut s = host_without_port.to_string();

        if !path.starts_with('/') {
            return Err(UrlForRewritingError::NoRootPath);
        }

        s.push_str(path);

        if !query.is_empty() {
            s.push_str("?");
            s.push_str(query);
        }

        Ok(UrlForRewriting {
            inner: s.into(),
            password: None,
            username: "".into(),
            host,
            path: path.into(),
        })
    }

    pub fn matches(self, pattern: MatchPattern) -> Option<Matched> {
        if self
            .inner
            .as_str()
            .starts_with(pattern.matchable_prefix.as_str())
        {
            if pattern.matchable_prefix.len() < self.inner.len() {
                let pattern_last_idx = pattern.matchable_prefix.len() - 1;
                let next_idx = pattern.matchable_prefix.len();
                let pattern_last_char = pattern
                    .matchable_prefix
                    .get(pattern_last_idx..=pattern_last_idx)
                    .unwrap();
                let next_char = self.inner.get(next_idx..=next_idx).unwrap();

                if pattern_last_char != "/" && next_char != "/" && next_char != "?" {
                    return None;
                }
            }
            Some(Matched {
                url: self,
                pattern,
                config_name: None,
            })
        } else {
            None
        }
    }

    pub fn host(&self) -> String {
        self.host.clone()
    }
}

impl AsRef<[u8]> for UrlForRewriting {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

#[derive(Debug)]
pub struct Matched {
    url: UrlForRewriting,
    pattern: MatchPattern,
    config_name: Option<ConfigName>,
}

impl Matched {
    pub fn resolve_handler(
        self,
        rewrite_to: &ProxyMatchedTo,
        protocol: Protocol,
    ) -> Result<ClientHandler, url::ParseError> {
        let mut rewritten_str = self.url.inner.clone();

        rewritten_str.replace_range(0..self.pattern.matchable_prefix.len() - 1, "localhost");

        let parsable = format!("http://{}", rewritten_str);

        let mut url = Url::parse(&parsable)?;

        let scheme = match (protocol, rewrite_to) {
            (Protocol::Http, _) => "http",
            (Protocol::WebSockets, _) => "ws",
        };

        url.set_scheme(scheme).unwrap();

        url.set_username(self.url.username.as_str()).unwrap();
        url.set_password(self.url.password.as_deref()).unwrap();

        match rewrite_to {
            ProxyMatchedTo::Client {
                handlers_processor,
                config_name,
                account_name,
                project_name,
                ..
            } => Ok(ClientHandler {
                account_name: account_name.clone(),
                handlers_processor: handlers_processor.clone(),
                config_name: config_name.clone(),
                url,
                project_name: project_name.clone(),
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MatchPattern {
    matchable_prefix: String,
}

#[derive(thiserror::Error, Debug)]
pub enum MatchPatternError {
    #[error("URL parse error: `{0}`")]
    Url(#[from] url::ParseError),

    #[error("URI build error: `{0}`")]
    Uri(#[from] http::Error),

    #[error("fragment (hash) should not exist")]
    FragmentFound,

    #[error("query should not exist")]
    QueryFound,

    #[error("port should not exist")]
    PortFound,

    #[error("username/password shoud not exist")]
    AuthFound,
}

impl MatchPattern {
    #[allow(dead_code)]
    pub fn new(host: &str, path: &str) -> Result<MatchPattern, MatchPatternError> {
        let uri = Uri::builder()
            .scheme("http")
            .authority(host)
            .path_and_query(path)
            .build()?;

        if uri.path_and_query().unwrap().query().is_some() {
            return Err(MatchPatternError::QueryFound);
        }
        if uri.authority().unwrap().port().is_some() {
            return Err(MatchPatternError::PortFound);
        }
        if uri.authority().unwrap().as_str().contains('@') {
            return Err(MatchPatternError::AuthFound);
        }

        Ok(MatchPattern {
            matchable_prefix: uri.to_string().trim_start_matches("http://").into(),
        })
    }

    pub fn generate_url(
        &self,
        proto: Protocol,
        maybe_port: Option<u16>,
        relative_url: &str,
    ) -> Url {
        let scheme = match proto {
            Protocol::Http => "https",
            Protocol::WebSockets => "wss",
        };

        let mut url =
            Url::parse(format!("{}://{}", scheme, self.matchable_prefix).as_str()).unwrap();

        url.set_port(maybe_port).unwrap();

        url.path_segments_mut().unwrap().extend(
            relative_url.split('/').filter(|s| !s.is_empty()), //remove first empty
        );

        url
    }
}

impl fmt::Display for MatchPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.matchable_prefix)
    }
}

impl FromStr for MatchPattern {
    type Err = MatchPatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(format!("http://{}", s).as_str())?;

        if url.fragment().is_some() {
            return Err(MatchPatternError::FragmentFound);
        }

        if url.query().is_some() {
            return Err(MatchPatternError::QueryFound);
        }
        if url.port().is_some() {
            return Err(MatchPatternError::PortFound);
        }
        if url.password().is_some() || !url.username().is_empty() {
            return Err(MatchPatternError::AuthFound);
        }

        Ok(MatchPattern {
            matchable_prefix: url.to_string().trim_start_matches("http://").into(),
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RewriteMatchedToError {
    #[error("URL parse error: `{0}`")]
    Url(#[from] url::ParseError),

    #[error("URI build error: `{0}`")]
    Uri(#[from] http::Error),
    // #[error("query should not exist")]
    // QueryFound,

    // #[error("fragment (hash) should not exist")]
    // FragmentFound,
}

#[derive(Clone)]
pub enum ProxyMatchedTo {
    Client {
        handlers_processor: HandlersProcessor,
        account_name: AccountName,
        project_name: ProjectName,
        config_name: ConfigName,
    },
}

impl ProxyMatchedTo {
    pub fn new(
        account_name: AccountName,
        project_name: ProjectName,
        config_name: ConfigName,
        handlers_processor: &HandlersProcessor,
    ) -> Result<Self, RewriteMatchedToError> {
        Ok(ProxyMatchedTo::Client {
            handlers_processor: handlers_processor.clone(),
            account_name,
            project_name,
            config_name,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Oauth2SsoClient {
    pub provider: Oauth2Provider,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy)]
pub enum Oauth2Provider {
    #[serde(rename = "google")]
    Google,
    #[serde(rename = "github")]
    Github,
}

#[derive(Debug, Clone, Copy)]
pub enum AuthProviderConfig {
    Oauth2(Oauth2SsoClient),
}

impl From<AuthProvider> for AuthProviderConfig {
    fn from(provider: AuthProvider) -> Self {
        match provider {
            AuthProvider::Google => AuthProviderConfig::Oauth2(Oauth2SsoClient {
                provider: Oauth2Provider::Google,
            }),
            AuthProvider::Github => AuthProviderConfig::Oauth2(Oauth2SsoClient {
                provider: Oauth2Provider::Github,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtEcdsa {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Mapping {
    pub match_pattern: MatchPattern,
    pub generated_at: DateTime<Utc>,
    pub handlers_processor: HandlersProcessor,
    pub account: AccountName,
    pub project: ProjectName,
    pub config_name: ConfigName,
    pub jwt_ecdsa: JwtEcdsa,
    pub rate_limiters: RateLimiters,
}

#[derive(Debug, thiserror::Error)]
pub enum UrlMappingError {
    #[error("URL parse error: `{0}`")]
    Url(#[from] url::ParseError),

    #[error("The URL `{url}` doesn't belong to match pattern `{pattern}`")]
    DoesNotBelongToPrefix {
        pattern: MatchPattern,
        url: UrlForRewriting,
    },
}

#[derive(Clone, Debug)]
pub struct ClientHandler {
    pub account_name: AccountName,
    pub project_name: ProjectName,
    pub config_name: ConfigName,
    pub handlers_processor: HandlersProcessor,
    pub url: Url,
}

#[derive(Clone)]
pub struct MappingAction {
    pub handler: ClientHandler,
    pub jwt_ecdsa: JwtEcdsa,
    pub external_base_url: Url,
}

impl MappingAction {
    #[allow(dead_code)]
    pub fn rewrite_to_url(&self) -> Url {
        self.handler.url.clone()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    Http,
    WebSockets,
}

impl Mapping {
    pub fn handle(
        &self,
        url: UrlForRewriting,
        _tunnels: ClientTunnels,
        external_port: u16,
        proto: Protocol,
    ) -> Result<(MappingAction, RateLimiters), UrlMappingError> {
        if let Some(m) = url.clone().matches(self.match_pattern.clone()) {
            info!("matched = {:?}", m);
            info!("self = {:?}", self);
            let base_url = self
                .match_pattern
                .generate_url(proto, Some(external_port), "");
            info!("base_url = {:?}", base_url);

            let handler = m
                .resolve_handler(
                    &ProxyMatchedTo::new(
                        self.account.clone(),
                        self.project.clone(),
                        self.config_name.clone(),
                        &self.handlers_processor,
                    )
                    .expect("FIXME"),
                    proto,
                )
                .expect("FIXME");

            info!("proxy_handler = {:?}", handler);

            Ok((
                MappingAction {
                    handler,
                    jwt_ecdsa: self.jwt_ecdsa.clone(),
                    external_base_url: base_url,
                },
                self.rate_limiters.clone(),
            ))
        } else {
            Err(UrlMappingError::DoesNotBelongToPrefix {
                pattern: self.match_pattern.clone(),
                url,
            })
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     pub fn schema() {
//         static JSON: &'static str = r#"{
//     "generated_at": 1594736221163,
//     "mount_point": "01ED925W8DK8W7G0Q6TP5MS6SD",
//     "path_prefixes": [],
//     "destination_path_prefix": "asd",
//     "revisions": [
//         {
//             "revision": 12345,
//             "version": "0.0.1",
//             "handlers": [
//                 {
//                     "definition": {
//                         "type": "static_app",
//                         "app": "swagger-ui",
//                         "version": "3.28.0",
//                         "base_path": ["a", "b"],
//                         "priority": 10
//                     },
//                     "config_name": "01ED9C7EJV2BK4Z24WW26TZAVP",
//                     "instance_ids": ["01ED9C74GHBAECTRYZD3D8X6B5", "01ED9C794H75XKT27683ME02V6"],
//                     "name": "static-assets"
//                 }
//             ]
//         }
//     ]
// }
// "#;
//
//         let _n: SchemaMapping = serde_json::from_str(JSON).unwrap();
//         // assert_eq!("2020-07-14T14:17:01.163Z".parse::<DateTime<Utc>>().unwrap(), n.generated_at);
//         // assert!(
//         //     matches!(
//         //         n.action,
//         //         Action::Invalidate { mount_points } if mount_points.as_slice() == [String::from("mpid")]
//         //     )
//         // );
//     }
//
//     #[test]
//     pub fn check_matching() {
//         let pattern = MatchPattern::new("example.exg.co", "/asd").unwrap();
//
//         let url1 = UrlForRewriting::from_components("example.exg.co", "/asdfgh", "").unwrap();
//         assert!(url1.matches(pattern.clone()).is_none());
//
//         let url2 = UrlForRewriting::from_components("example.exg.co", "/asd/fgh", "").unwrap();
//         assert!(url2.matches(pattern.clone()).is_some());
//
//         let url3 = UrlForRewriting::from_components("example.exg.co", "/asd?a=2", "").unwrap();
//         assert!(url3.matches(pattern.clone()).is_some());
//
//         let url4 = UrlForRewriting::from_components("example.exg.co", "/asd", "").unwrap();
//         assert!(url4.matches(pattern.clone()).is_some());
//
//         let url5 = UrlForRewriting::from_components("example.exg.co", "/asd/", "").unwrap();
//         assert!(url5.matches(pattern.clone()).is_some());
//
//         let pattern2 = MatchPattern::new("example.exg.co", "/").unwrap();
//         let url6 = UrlForRewriting::from_components("example.exg.co", "/", "").unwrap();
//         assert!(url6.matches(pattern2.clone()).is_some());
//
//         let url7 = UrlForRewriting::from_components("example.exg.co", "/admin", "").unwrap();
//         assert!(url7.matches(pattern2.clone()).is_some());
//
//         let pattern3 = MatchPattern::new("example.exg.co", "").unwrap();
//         let url8 = UrlForRewriting::from_components("example.exg.co", "/", "").unwrap();
//         assert!(url8.matches(pattern3.clone()).is_some());
//     }
//
//     #[test]
//     pub fn incorrect() {
//         let mapping = Mapping {
//             match_pattern: MatchPattern::new("example.exg.co", "/").unwrap(),
//             proxy_matched_to: ProxyMatchedTo::new("lancastr.com/", "test-config".parse().unwrap())
//                 .unwrap(),
//             generated_at: Utc::now(),
//             // jwt_secret: vec![],
//             // auth_type: AuthProviderConfig::Oauth2(Oauth2SsoClient {
//             //     provider: Oauth2Provider::Google,
//             // }),
//             // rate_limiter: None,
//         };
//
//         assert!(mapping
//             .handle(
//                 UrlForRewriting::from_components("bad.com", "/", "").unwrap(),
//                 ClientTunnels::new(),
//                 443,
//                 Protocol::Http,
//             )
//             .is_err())
//     }
//
//     // #[test]
//     // pub fn domain_rewrite() {
//     //     let mapping = Mapping {
//     //         match_pattern: MatchPattern::new("example.exg.co", "/").unwrap(),
//     //         proxy_matched_to: ProxyMatchedTo::new("lancastr.com/", Default::default()).unwrap(),
//     //         generated_at: Utc::now(),
//     //         jwt_secret: vec![],
//     //         auth_type: AuthProviderConfig::Oauth2(Oauth2SsoClient {
//     //             provider: Oauth2Provider::Google,
//     //         }),
//     //         rate_limiter: None,
//     //     };
//     //
//     //     assert_eq!(
//     //         Url::parse("https://lancastr.com/").unwrap(),
//     //         mapping
//     //             .handle(
//     //                 UrlForRewriting::from_components("example.exg.co", "/", "").unwrap(),
//     //                 ClientTunnels::new(),
//     //                 443,
//     //                 Protocol::Http,
//     //             )
//     //             .unwrap()
//     //             .0
//     //             .rewrite_to_url()
//     //     )
//     // }
//
//     // #[test]
//     // pub fn domain_and_path_rewrite() {
//     //     let mapping = Mapping {
//     //         match_pattern: MatchPattern::new("example.exg.co", "/from/url").unwrap(),
//     //         proxy_matched_to: ProxyMatchedTo::new("lancastr.com/to/newurl", Default::default()).unwrap(),
//     //         generated_at: Utc::now(),
//     //         jwt_secret: vec![],
//     //         auth_type: AuthProviderConfig::Oauth2(Oauth2SsoClient {
//     //             provider: Oauth2Provider::Google,
//     //         }),
//     //         rate_limiter: None,
//     //     };
//     //
//     //     assert_eq!(
//     //         Url::parse("https://lancastr.com/to/newurl/path?a=2").unwrap(),
//     //         mapping
//     //             .handle(
//     //                 UrlForRewriting::from_components("example.exg.co", "/from/url/path", "a=2")
//     //                     .unwrap(),
//     //                 ClientTunnels::new(),
//     //                 443,
//     //                 Protocol::Http,
//     //             )
//     //             .unwrap()
//     //             .0
//     //             .rewrite_to_url()
//     //     )
//     // }
//
//     // #[test]
//     // pub fn port_rewrite() {
//     //     let mapping = Mapping {
//     //         match_pattern: MatchPattern::new("example.exg.co", "/from/url").unwrap(),
//     //         proxy_matched_to: ProxyMatchedTo::new("lancastr.com/", Default::default()).unwrap(),
//     //         generated_at: Utc::now(),
//     //         jwt_secret: vec![],
//     //         auth_type: AuthProviderConfig::Oauth2(Oauth2SsoClient {
//     //             provider: Oauth2Provider::Google,
//     //         }),
//     //         rate_limiter: None,
//     //     };
//     //
//     //     assert_eq!(
//     //         Url::parse("https://lancastr.com:5567/to/newurl/path").unwrap(),
//     //         mapping
//     //             .handle(
//     //                 UrlForRewriting::from_components("example.exg.co", "/from/url/path", "")
//     //                     .unwrap(),
//     //                 ClientTunnels::new(),
//     //                 443,
//     //                 Protocol::Http,
//     //             )
//     //             .unwrap()
//     //             .0
//     //             .rewrite_to_url()
//     //     )
//     // }
//
//     // #[test]
//     // pub fn websockets_rewrite() {
//     //     let mapping = Mapping {
//     //         match_pattern: MatchPattern::new("example.exg.co", "/from").unwrap(),
//     //         proxy_matched_to: ProxyMatchedTo::new("lancastr.com/to", Default::default()).unwrap(),
//     //         generated_at: Utc::now(),
//     //         jwt_secret: vec![],
//     //         auth_type: AuthProviderConfig::Oauth2(Oauth2SsoClient {
//     //             provider: Oauth2Provider::Google,
//     //         }),
//     //         rate_limiter: None,
//     //     };
//     //
//     //     assert_eq!(
//     //         Url::parse("wss://lancastr.com/to/path").unwrap(),
//     //         mapping
//     //             .handle(
//     //                 UrlForRewriting::from_components("example.exg.co", "/from/path", "").unwrap(),
//     //                 ClientTunnels::new(),
//     //                 443,
//     //                 Protocol::WebSockets,
//     //             )
//     //             .unwrap()
//     //             .0
//     //             .rewrite_to_url()
//     //     )
//     // }
//
//     // #[test]
//     // pub fn rewrite_tls_to_plain() {
//     //     let mapping = Mapping {
//     //         match_pattern: MatchPattern::new("example.exg.co", "/from").unwrap(),
//     //         proxy_matched_to: ProxyMatchedTo::new("lancastr.com/to", Default::default()).unwrap(),
//     //         generated_at: Utc::now(),
//     //         jwt_secret: vec![],
//     //         auth_type: AuthProviderConfig::Oauth2(Oauth2SsoClient {
//     //             provider: Oauth2Provider::Google,
//     //         }),
//     //         rate_limiter: None,
//     //     };
//     //
//     //     assert_eq!(
//     //         Url::parse("http://lancastr.com/to/path").unwrap(),
//     //         mapping
//     //             .handle(
//     //                 UrlForRewriting::from_components("example.exg.co", "/from/path", "").unwrap(),
//     //                 ClientTunnels::new(),
//     //                 443,
//     //                 Protocol::Http,
//     //             )
//     //             .unwrap()
//     //             .0
//     //             .rewrite_to_url()
//     //     );
//     //
//     //     assert_eq!(
//     //         Url::parse("ws://lancastr.com/to/path").unwrap(),
//     //         mapping
//     //             .handle(
//     //                 UrlForRewriting::from_components("example.exg.co", "/from/path", "").unwrap(),
//     //                 ClientTunnels::new(),
//     //                 443,
//     //                 Protocol::WebSockets,
//     //             )
//     //             .unwrap()
//     //             .0
//     //             .rewrite_to_url()
//     //     );
//     // }
//
//     // #[test]
//     // pub fn rewrite_plain_to_tls() {
//     //     let mapping = Mapping {
//     //         match_pattern: MatchPattern::new("example.exg.co", "/from").unwrap(),
//     //         proxy_matched_to: ProxyMatchedTo::new("lancastr.com/to", Default::default()).unwrap(),
//     //         generated_at: Utc::now(),
//     //         jwt_secret: vec![],
//     //         auth_type: AuthProviderConfig::Oauth2(Oauth2SsoClient {
//     //             provider: Oauth2Provider::Google,
//     //         }),
//     //         rate_limiter: None,
//     //     };
//     //
//     //     assert_eq!(
//     //         Url::parse("https://lancastr.com/to/path").unwrap(),
//     //         mapping
//     //             .handle(
//     //                 UrlForRewriting::from_components("example.exg.co", "/from/path", "").unwrap(),
//     //                 ClientTunnels::new(),
//     //                 443,
//     //                 Protocol::Http,
//     //             )
//     //             .unwrap()
//     //             .0
//     //             .rewrite_to_url()
//     //     );
//     //
//     //     assert_eq!(
//     //         Url::parse("wss://lancastr.com/to/path").unwrap(),
//     //         mapping
//     //             .handle(
//     //                 UrlForRewriting::from_components("example.exg.co", "/from/path", "").unwrap(),
//     //                 ClientTunnels::new(),
//     //                 443,
//     //                 Protocol::WebSockets,
//     //             )
//     //             .unwrap()
//     //             .0
//     //             .rewrite_to_url()
//     //     );
//     // }
// }
