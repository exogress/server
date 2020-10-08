use exogress_config_core::{Action, ClientHandler, MatchingPath, ProjectHandler, Rule};
use url::Url;

pub trait HandlerExt<'a> {
    fn find_filter_rule(&'a self, url: Url) -> Box<dyn Iterator<Item = &'a Action> + Send + 'a>;
}

fn common_find_filter_rule<'a>(
    rules: &'a Vec<Rule>,
    url: Url,
) -> Box<dyn Iterator<Item = &'a Action> + Send + 'a> {
    let mut segments = vec![];
    {
        let mut path_segments = url.path_segments().unwrap();
        while let Some(segment) = path_segments.next() {
            segments.push(segment.to_string());
        }
    }

    let iter = rules.iter().filter_map(move |rule| {
        let matching_path = &rule.filter.path;
        info!(
            "processed rule = {:?}. matching_path = {:?}",
            rule, matching_path
        );
        match matching_path {
            MatchingPath::Root
                if segments.len() == 0 || (segments.len() == 1 && segments[0].is_empty()) =>
            {
                return Some(&rule.action);
            }
            MatchingPath::Wildcard => {
                return Some(&rule.action);
            }
            MatchingPath::Strict(match_segments) => {
                if match_segments.len() != segments.len() {
                    info!("length missmatch");
                    return None;
                }
                for (match_segment, segment) in match_segments.iter().zip(&segments) {
                    if !match_segment.is_match(segment) {
                        info!("!match {:?} <=> {:?}", match_segment, segment);
                        return None;
                    }
                }
                info!("matched! action");
                return Some(&rule.action);
            }
            MatchingPath::LeftWildcardRight(left_match_segments, right_match_segments) => {
                if left_match_segments.len() + right_match_segments.len() > segments.len() {
                    return None;
                }
                for (match_segment, segment) in left_match_segments.iter().zip(&segments) {
                    if !match_segment.is_match(segment) {
                        return None;
                    }
                }
                for (match_segment, segment) in
                    right_match_segments.iter().rev().zip(segments.iter().rev())
                {
                    if !match_segment.is_match(segment) {
                        return None;
                    }
                }
                return Some(&rule.action);
            }
            MatchingPath::LeftWildcard(left_match_segments) => {
                if left_match_segments.len() > segments.len() {
                    return None;
                }
                for (match_segment, segment) in left_match_segments.iter().zip(&segments) {
                    if !match_segment.is_match(segment) {
                        return None;
                    }
                }
                return Some(&rule.action);
            }
            MatchingPath::WildcardRight(right_match_segments) => {
                if right_match_segments.len() > segments.len() {
                    return None;
                }
                for (match_segment, segment) in
                    right_match_segments.iter().rev().zip(segments.iter().rev())
                {
                    if !match_segment.is_match(segment) {
                        return None;
                    }
                }
                return Some(&rule.action);
            }
            _ => return None,
        }
    });

    Box::new(iter)
}

impl<'a> HandlerExt<'a> for ClientHandler {
    fn find_filter_rule(&'a self, url: Url) -> Box<dyn Iterator<Item = &'a Action> + Send + 'a> {
        common_find_filter_rule(&self.rules, url)
    }
}

impl<'a> HandlerExt<'a> for ProjectHandler {
    fn find_filter_rule(&'a self, url: Url) -> Box<dyn Iterator<Item = &'a Action> + Send + 'a> {
        common_find_filter_rule(&self.rules, url)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use exogress_config_core::{Action, ClientHandlerVariant, Filter, MatchPathSegment, StaticDir};

    #[test]
    fn test_matching() {
        let handler = ClientHandler {
            variant: ClientHandlerVariant::StaticDir(StaticDir {
                dir: "./dir".parse().unwrap(),
            }),
            base_path: vec![],
            replace_base_path: vec![],
            rules: vec![
                Rule {
                    filter: Filter {
                        path: MatchingPath::Root,
                    },
                    action: Action::Throw {
                        exception: "exception".parse().unwrap(),
                        data: Default::default(),
                    },
                },
                Rule {
                    filter: Filter {
                        path: MatchingPath::LeftWildcard(vec![MatchPathSegment::Exact(
                            "a".parse().unwrap(),
                        )]),
                    },
                    action: Action::Throw {
                        exception: "exception2".parse().unwrap(),
                        data: Default::default(),
                    },
                },
                Rule {
                    filter: Filter {
                        path: MatchingPath::WildcardRight(vec![MatchPathSegment::Exact(
                            "z".parse().unwrap(),
                        )]),
                    },
                    action: Action::Throw {
                        exception: "exception3".parse().unwrap(),
                        data: Default::default(),
                    },
                },
                Rule {
                    filter: Filter {
                        path: MatchingPath::LeftWildcardRight(
                            vec![MatchPathSegment::Exact("b".parse().unwrap())],
                            vec![MatchPathSegment::Exact("y".parse().unwrap())],
                        ),
                    },
                    action: Action::Throw {
                        exception: "exception4".parse().unwrap(),
                        data: Default::default(),
                    },
                },
                Rule {
                    filter: Filter {
                        path: MatchingPath::Strict(vec![
                            MatchPathSegment::Exact("c".parse().unwrap()),
                            MatchPathSegment::Exact("d".parse().unwrap()),
                        ]),
                    },
                    action: Action::Throw {
                        exception: "exception5".parse().unwrap(),
                        data: Default::default(),
                    },
                },
                Rule {
                    filter: Filter {
                        path: MatchingPath::Strict(vec![
                            MatchPathSegment::Any,
                            MatchPathSegment::Exact("e".parse().unwrap()),
                        ]),
                    },
                    action: Action::Throw {
                        exception: "exception6".parse().unwrap(),
                        data: Default::default(),
                    },
                },
                Rule {
                    filter: Filter {
                        path: MatchingPath::Strict(vec![
                            MatchPathSegment::Any,
                            MatchPathSegment::Regex("[0-9]{1}.{2}a".parse().unwrap()),
                        ]),
                    },
                    action: Action::Throw {
                        exception: "exception7".parse().unwrap(),
                        data: Default::default(),
                    },
                },
            ],
            priority: 1,
            catch: Default::default(),
        };

        let found = handler
            .find_filter_rule("http://asd/".parse().unwrap())
            .next();
        assert!(
            matches!(found, Some(Action::Throw { exception, .. }) if exception.as_str() == "exception")
        );

        let found = handler
            .find_filter_rule("http://asd/a".parse().unwrap())
            .next();
        assert!(
            matches!(found, Some(Action::Throw { exception, .. }) if exception.as_str() == "exception2")
        );
        let found = handler
            .find_filter_rule("http://asd/a/b/c".parse().unwrap())
            .next();
        assert!(
            matches!(found, Some(Action::Throw { exception, .. }) if exception.as_str() == "exception2")
        );
        let found = handler
            .find_filter_rule("http://asd/1/2/z".parse().unwrap())
            .next();
        assert!(
            matches!(found, Some(Action::Throw { exception, .. }) if exception.as_str() == "exception3")
        );
        let found = handler
            .find_filter_rule("http://asd/z".parse().unwrap())
            .next();
        assert!(
            matches!(found, Some(Action::Throw { exception, .. }) if exception.as_str() == "exception3")
        );
        let found = handler
            .find_filter_rule("http://asd/b/1/2/3/y".parse().unwrap())
            .next();
        assert!(
            matches!(found, Some(Action::Throw { exception, .. }) if exception.as_str() == "exception4")
        );
        let found = handler
            .find_filter_rule("http://asd/b/y".parse().unwrap())
            .next();
        assert!(
            matches!(found, Some(Action::Throw { exception, .. }) if exception.as_str() == "exception4")
        );
        let not_found = handler
            .find_filter_rule("http://asd/b".parse().unwrap())
            .next();
        assert!(matches!(not_found, None));

        let found = handler
            .find_filter_rule("http://asd/c/d".parse().unwrap())
            .next();
        assert!(
            matches!(found, Some(Action::Throw { exception, .. }) if exception.as_str() == "exception5")
        );
        let found = handler
            .find_filter_rule("http://asd/aasd/e".parse().unwrap())
            .next();
        assert!(
            matches!(found, Some(Action::Throw { exception, .. }) if exception.as_str() == "exception6")
        );
        let found = handler
            .find_filter_rule("http://asd/asdfsfdg/1hra".parse().unwrap())
            .next();
        assert!(
            matches!(found, Some(Action::Throw { exception, .. }) if exception.as_str() == "exception7")
        );
        let not_found = handler
            .find_filter_rule("http://asd/asdfsfdg/1hsra".parse().unwrap())
            .next();
        assert!(matches!(not_found, None));
    }
}
