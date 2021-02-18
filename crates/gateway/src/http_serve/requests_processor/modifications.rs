use crate::http_serve::requests_processor::Matched;
use exogress_common::common_utils::uri_ext::UriExt;
use hashbrown::HashMap;
use itertools::Itertools;
use regex::{Captures, RegexBuilder};
use smol_str::SmolStr;
use std::{borrow::Cow, num::ParseIntError};

#[derive(Debug, Hash, Clone, Eq, PartialEq)]
pub struct ResolvedPathSegmentModify(pub SmolStr);

#[derive(thiserror::Error, Debug)]
pub enum MatchPathModificationError {
    #[error("parse error")]
    ParseIntError(#[from] ParseIntError),

    #[error("non-existing reference")]
    NotExistingReference { main: SmolStr, second: Option<u8> },

    #[error("multiple segments matched")]
    MultipleSegments,

    #[error("not segments tried to being accessed")]
    NotSegments,

    #[error("not matched tried to being accessed")]
    NotMatches,

    #[error("nothings matched")]
    NothingMatched,

    #[error("malformed")]
    Malformed,

    #[error("single match is not indexable")]
    SingleNotIndexable,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Replaced {
    Multiple(Vec<SmolStr>),
    Single(SmolStr),
}

impl Replaced {
    pub fn push_to_url(self, url: &mut http::Uri) {
        match self {
            Replaced::Multiple(multiple) => {
                for seg in multiple {
                    url.push_segment(seg.as_ref());
                }
            }
            Replaced::Single(single) => {
                url.push_segment(single.as_ref());
            }
        }
    }
}

impl ToString for Replaced {
    fn to_string(&self) -> String {
        match self {
            Replaced::Multiple(multiple) => multiple.join("/").into(),
            Replaced::Single(single) => single.as_str().into(),
        }
    }
}

fn replace_single_substitution(
    s: &str,
    filter_matches: &HashMap<SmolStr, Matched>,
) -> Result<Replaced, MatchPathModificationError> {
    let s = s.trim();

    let mut split_positions = s.chars().enumerate().tuple_windows().filter_map(
        |((_first_idx, first), (second_idx, second))| {
            if first != '\\' && second == '.' {
                Some(second_idx)
            } else {
                None
            }
        },
    );

    let maybe_split_at = split_positions.next();
    if split_positions.next().is_some() {
        return Err(MatchPathModificationError::Malformed);
    }

    let mut first = s;
    let mut second = None;

    if let Some(split_at) = maybe_split_at {
        let (a, b) = s.split_at(split_at);
        first = a;
        second = Some(&b[1..]);
    }

    let first_string = first.replace("\\.", ".");
    let first = first_string.as_str();

    let m = filter_matches.get(first).ok_or_else(|| {
        MatchPathModificationError::NotExistingReference {
            main: first.into(),
            second: None,
        }
    })?;

    match second {
        None => match m {
            Matched::Multiple(_multiple) => {
                return Err(MatchPathModificationError::NotSegments);
            }
            Matched::Single(single) => {
                return Ok(Replaced::Single(single.clone()));
            }
            Matched::None => {
                return Err(MatchPathModificationError::NothingMatched);
            }
            Matched::Segments(segments) => {
                return Ok(Replaced::Multiple(segments.clone()));
            }
        },
        Some(s) => {
            let ref_num = s.parse::<u8>()?;

            match m {
                Matched::Multiple(multiple) => match multiple.get(&ref_num) {
                    Some(matched) => {
                        return Ok(Replaced::Single(matched.clone()));
                    }
                    None => {
                        return Err(MatchPathModificationError::NothingMatched);
                    }
                },
                Matched::Single(_) => {
                    return Err(MatchPathModificationError::SingleNotIndexable);
                }
                Matched::None => {
                    return Err(MatchPathModificationError::NothingMatched);
                }
                Matched::Segments(_segments) => {
                    return Err(MatchPathModificationError::NotMatches);
                }
            }
        }
    }
}

pub fn substitute_str_with_filter_matches(
    s: &str,
    filter_matches: &HashMap<SmolStr, Matched>,
) -> Result<Replaced, MatchPathModificationError> {
    if let Some(right) = s.strip_prefix("{{") {
        if let Some(middle) = right.strip_suffix("}}") {
            if middle.contains("{{") || middle.contains("}}") {
                return Err(MatchPathModificationError::MultipleSegments);
            }

            return replace_single_substitution(middle, filter_matches);
        }
    }

    let re = RegexBuilder::new(r"\{\{(.+?)\}\}").build().unwrap();
    let mut error = None;

    let replaced = re.replace_all(s, |captures: &Captures<'_>| {
        let substitution = captures.get(1).unwrap().as_str();

        match replace_single_substitution(substitution, filter_matches) {
            Ok(replace) => match replace {
                Replaced::Multiple(_) => {
                    if error.is_none() {
                        error = Some(MatchPathModificationError::MultipleSegments);
                    };
                    return Cow::Borrowed("");
                }
                Replaced::Single(single) => {
                    return Cow::Owned(single.to_string());
                }
            },
            Err(e) => {
                if error.is_none() {
                    error = Some(e);
                };
                return Cow::Borrowed("");
            }
        }
    });

    if let Some(e) = error {
        return Err(e);
    }

    Ok(Replaced::Single(replaced.into()))
}

impl ResolvedPathSegmentModify {
    pub fn substitute(
        &self,
        groups: &HashMap<SmolStr, Matched>,
    ) -> Result<Replaced, MatchPathModificationError> {
        substitute_str_with_filter_matches(&self.0, groups)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_modification_multiple() {
        let modify = ResolvedPathSegmentModify(SmolStr::from("{{ 3 }}"));
        let mut data = HashMap::new();
        data.insert(
            "3".into(),
            Matched::Segments(vec!["zero".into(), "one".into()]),
        );

        let res = modify.substitute(&data).unwrap();
        assert_eq!(res, Replaced::Multiple(vec!["zero".into(), "one".into()]));

        assert!(modify.substitute(&HashMap::new()).is_err());

        let mut data = HashMap::new();
        data.insert("3".into(), Matched::None);
        assert!(modify.substitute(&data).is_err());

        let mut data = HashMap::new();
        let mut map = BTreeMap::new();
        map.insert(0, "zero".into());
        data.insert("3".into(), Matched::Multiple(map));
        assert!(modify.substitute(&data).is_err());

        let mut data = HashMap::new();
        data.insert("3".into(), Matched::Single(SmolStr::from("single")));
        let res = modify.substitute(&data).unwrap();
        assert_eq!(res, Replaced::Single(SmolStr::from("single")));
    }

    #[test]
    fn test_modification_single() {
        let modify = ResolvedPathSegmentModify(SmolStr::from(
            "before-{{ 3.0 }}-middle-{{ param\\.a }}-after",
        ));
        let mut data = HashMap::new();
        data.insert("param.a".into(), Matched::Single(SmolStr::from("two")));
        data.insert("3".into(), {
            let mut inner = BTreeMap::new();
            inner.insert(0, "zero".into());
            Matched::Multiple(inner)
        });
        let res = modify.substitute(&data).unwrap();
        assert_eq!(res, Replaced::Single("before-zero-middle-two-after".into()));
    }

    #[test]
    fn test_modification_single_error() {
        let modify = ResolvedPathSegmentModify(SmolStr::from("before-{{ 1 }}-after"));
        let mut data = HashMap::new();
        data.insert("1".into(), {
            Matched::Segments(vec!["seg1".into(), "seg2".into()])
        });
        assert!(modify.substitute(&data).is_err());

        let mut data = HashMap::new();
        data.insert("1".into(), Matched::None);
        assert!(modify.substitute(&data).is_err());

        let data = HashMap::new();
        assert!(modify.substitute(&data).is_err());

        let mut data = HashMap::new();
        data.insert("1".into(), Matched::Multiple(Default::default()));
        assert!(modify.substitute(&data).is_err());
    }
}
