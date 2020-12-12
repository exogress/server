use core::fmt;
use http::Uri;
use std::str::FromStr;
use url::Url;

#[derive(Clone, Debug)]
pub struct MatchPattern {
    pub matchable_prefix: String,
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
