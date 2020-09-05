use core::fmt;
use futures_util::core_reexport::str::FromStr;
use url::Url;

use serde::de::Visitor;
use serde::{de, Deserialize, Deserializer};
use smartstring::alias::*;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, PartialOrd, Ord)]
#[serde(transparent)]
pub struct UrlPrefix {
    inner: String,
}

impl fmt::Display for UrlPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum UrlPrefixError {
    #[error("port should not exist")]
    PortFound,

    #[error("fragment should not exist")]
    FragmentFound,

    #[error("auth should not be present")]
    AuthFound,

    #[error("qurty should not be present")]
    QueryFound,

    #[error("host not found")]
    HostNotFound,

    #[error("path root not set")]
    PathRootNotSet,

    #[error("parse error {0}")]
    ParseError(#[from] url::ParseError),

    #[error("malformed")]
    Malformed,
}

impl UrlPrefix {
    pub fn domain_only(&self) -> UrlPrefix {
        let url = Url::parse(format!("http://{}", self.inner).as_str()).expect("FIXME");
        UrlPrefix::from_str(format!("{}/", url.host_str().expect("FIXME")).as_str()).expect("FIXME")
    }

    pub fn host(&self) -> String {
        let url = Url::parse(format!("http://{}", self.inner).as_str()).expect("FIXME");
        url.host_str().expect("FIXME").to_string().into()
    }

    pub fn path(&self) -> std::string::String {
        let url = Url::parse(format!("http://{}", self.inner).as_str()).expect("FIXME");
        url.path().to_string()
    }

    pub fn is_subpath_of_or_equal(&self, other: &UrlPrefix) -> bool {
        if self.inner.len() > other.inner.len() {
            return false;
        }
        if !other.inner.starts_with(self.inner.as_str()) {
            return false;
        }

        //last symbol
        if other.inner.len() == self.inner.len() {
            return true;
        }

        let cur_char = other.inner.chars().nth(self.inner.len() - 1).unwrap();
        if self.inner.ends_with('/') && cur_char == '/' {
            return true;
        }

        //is next symbol == '\'
        let next_char = other.inner.chars().nth(self.inner.len()).unwrap();
        next_char == '/'
    }
}

impl FromStr for UrlPrefix {
    type Err = UrlPrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(format!("http://{}", s).as_str())?;

        if url.port().is_some() {
            return Err(UrlPrefixError::PortFound);
        }

        if url.fragment().is_some() {
            return Err(UrlPrefixError::FragmentFound);
        }

        if url.query().is_some() {
            return Err(UrlPrefixError::QueryFound);
        }

        if !url.has_host() {
            return Err(UrlPrefixError::HostNotFound);
        }

        if url.password().is_some() || !url.username().is_empty() {
            return Err(UrlPrefixError::AuthFound);
        }

        if url.path() == "/" && s.chars().last() != Some('/') {
            return Err(UrlPrefixError::PathRootNotSet);
        }

        let restored = url.to_string()[7..].to_string();
        if restored != s {
            return Err(UrlPrefixError::Malformed);
        }

        let mut inner: String = restored.into();

        if url.path().is_empty() {
            inner.push('/');
        } else if url.path() != "/" {
            inner = inner.trim_end_matches('/').into();
        }

        Ok(UrlPrefix { inner })
    }
}

impl UrlPrefix {
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }
}

struct UrlPrefixVisitor;

impl<'de> Visitor<'de> for UrlPrefixVisitor {
    type Value = UrlPrefix;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("URL prefix")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match UrlPrefix::from_str(value) {
            Ok(segment) => Ok(segment),
            Err(e) => Err(de::Error::custom(e)),
        }
    }
}

impl<'de> Deserialize<'de> for UrlPrefix {
    fn deserialize<D>(deserializer: D) -> Result<UrlPrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(UrlPrefixVisitor)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_parse() {
        UrlPrefix::from_str("asd").err().unwrap();
        UrlPrefix::from_str("link/path").unwrap();
        UrlPrefix::from_str("link.com/").unwrap();
        UrlPrefix::from_str("localhost/").unwrap();
        UrlPrefix::from_str("http://").err().unwrap();
    }

    #[test]
    fn test_deserialize() {
        serde_json::from_str::<UrlPrefix>("\"asd\"").err().unwrap();
        serde_json::from_str::<UrlPrefix>("\"link.com/\"").unwrap();
    }

    #[test]
    fn test_subpath() {
        assert!(UrlPrefix::from_str("host/")
            .unwrap()
            .is_subpath_of_or_equal(&UrlPrefix::from_str("host/d").unwrap()));

        assert!(!UrlPrefix::from_str("host/d")
            .unwrap()
            .is_subpath_of_or_equal(&UrlPrefix::from_str("host/").unwrap()));

        assert!(UrlPrefix::from_str("host/a/b")
            .unwrap()
            .is_subpath_of_or_equal(&UrlPrefix::from_str("host/a/b").unwrap()));

        assert!(UrlPrefix::from_str("host/a/b/")
            .unwrap()
            .is_subpath_of_or_equal(&UrlPrefix::from_str("host/a/b").unwrap()));
        assert!(UrlPrefix::from_str("host/a/b")
            .unwrap()
            .is_subpath_of_or_equal(&UrlPrefix::from_str("host/a/b/").unwrap()));
        assert!(UrlPrefix::from_str("host/a/b")
            .unwrap()
            .is_subpath_of_or_equal(&UrlPrefix::from_str("host/a/b/c").unwrap()));

        assert!(!UrlPrefix::from_str("host/a/b")
            .unwrap()
            .is_subpath_of_or_equal(&UrlPrefix::from_str("host/a/bb/c").unwrap()));

        assert!(!UrlPrefix::from_str("host/a/b")
            .unwrap()
            .is_subpath_of_or_equal(&UrlPrefix::from_str("host/a").unwrap()));
    }
}
