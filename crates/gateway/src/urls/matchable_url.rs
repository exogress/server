use std::fmt;
use url::Url;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MatchableUrl {
    inner: String,
    host: String,
    path: String,
    username: String,
    password: Option<String>,
}

impl fmt::Display for MatchableUrl {
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

impl MatchableUrl {
    #[allow(dead_code)]
    pub fn from_url(mut url: Url) -> Self {
        url.set_port(None).unwrap();
        url.set_scheme("https").unwrap();

        let host = url.host_str().unwrap().into();
        let path = url.path().into();

        MatchableUrl {
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
        if host_without_port.contains(':') {
            return Err(UrlForRewritingError::PortFound);
        }

        let host = host_without_port.into();

        let mut s = host_without_port.to_string();

        if !path.starts_with('/') {
            return Err(UrlForRewritingError::NoRootPath);
        }

        s.push_str(path);

        if !query.is_empty() {
            s.push('?');
            s.push_str(query);
        }

        Ok(MatchableUrl {
            inner: s,
            password: None,
            username: "".into(),
            host,
            path: path.into(),
        })
    }

    pub fn host(&self) -> String {
        self.host.clone()
    }
}

impl AsRef<[u8]> for MatchableUrl {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}
