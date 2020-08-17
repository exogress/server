use exogress_config_core::{Proxy, StaticDir, Target, TargetVariant};
use exogress_entities::TargetName;
use itertools::Itertools;
use smallvec::SmallVec;
use smartstring::alias::String;
use std::str::FromStr;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServerTarget {
    base_path_matcher: String,
    name: TargetName,
    variant: TargetVariant,
}

pub struct TargetsProcessor {
    inner: SmallVec<[ServerTarget; 4]>,
}

impl TargetsProcessor {
    pub fn new<'a>(f: impl Iterator<Item = (&'a TargetName, &'a Target)>) -> TargetsProcessor {
        let inner = f
            .map(|(target_name, t)| {
                let base_path = t
                    .base_path
                    .clone()
                    .into_iter()
                    .map(|bp| bp.as_str().into())
                    .collect::<Vec<String>>()
                    .join("/")
                    .into();
                (
                    ServerTarget {
                        base_path_matcher: base_path,
                        name: target_name.clone(),
                        variant: t.variant.clone().into(),
                    },
                    t.priority,
                )
            })
            .sorted_by(|a, b| a.1.cmp(&b.1))
            .map(|(s, _)| s)
            .collect();

        TargetsProcessor { inner }
    }

    pub fn seq_for_rest_path<'a>(
        &'a self,
        path: &'a str,
    ) -> impl Iterator<Item = &'a ServerTarget> {
        self.inner
            .iter()
            .filter(move |item| path.starts_with(item.base_path_matcher.as_str()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use exogress_config_core::Config;
    use exogress_entities::MountPointName;

    #[test]
    pub fn test_targets() {
        const YAML: &str = r#"---
version: 0.0.1
revision: 10
name: repository-1
upstreams:
  backend2:
    port: 3000
exposes:
  mount_point:
    targets:
      directory1:
        type: static_dir
        priority: 1000
        dir: ./dir1
        base_path: []
      directory2:
        type: static_dir
        priority: 10
        dir: ./dir2
        base_path: ["asd", "ads"]
      main:
        type: proxy
        priority: 30
        upstream: backend
        base_path: []
"#;
        let cfg = serde_yaml::from_str::<Config>(YAML).unwrap();

        let targets = TargetsProcessor::new(
            cfg.exposes
                .get(&MountPointName::from_str("mount_point").unwrap())
                .unwrap()
                .targets
                .iter(),
        );

        assert_eq!(
            targets.seq_for_rest_path("").cloned().collect::<Vec<_>>(),
            vec![
                ServerTarget {
                    base_path_matcher: "".into(),
                    name: "main".parse().unwrap(),
                    variant: TargetVariant::Proxy(Proxy {
                        upstream: "backend".parse().unwrap(),
                    }),
                },
                ServerTarget {
                    base_path_matcher: "".into(),
                    name: "directory1".parse().unwrap(),
                    variant: TargetVariant::StaticDir(StaticDir {
                        dir: "./dir1".parse().unwrap(),
                    }),
                },
            ]
        );

        assert_eq!(
            targets
                .seq_for_rest_path("asd/ads/hello")
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                ServerTarget {
                    base_path_matcher: "asd/ads".into(),
                    name: "directory2".parse().unwrap(),
                    variant: TargetVariant::StaticDir(StaticDir {
                        dir: "./dir2".parse().unwrap(),
                    }),
                },
                ServerTarget {
                    base_path_matcher: "".into(),
                    name: "main".parse().unwrap(),
                    variant: TargetVariant::Proxy(Proxy {
                        upstream: "backend".parse().unwrap(),
                    }),
                },
                ServerTarget {
                    base_path_matcher: "".into(),
                    name: "directory1".parse().unwrap(),
                    variant: TargetVariant::StaticDir(StaticDir {
                        dir: "./dir1".parse().unwrap(),
                    }),
                },
            ]
        )
    }
}
