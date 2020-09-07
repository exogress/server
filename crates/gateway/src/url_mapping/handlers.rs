use exogress_config_core::{Auth, Handler as HandlerConfig, HandlerVariant};
use exogress_entities::{ConfigName, HandlerName, InstanceId, Upstream};
use exogress_tunnel::ConnectTarget;
use hashbrown::HashMap;
use itertools::Itertools;
use smallvec::SmallVec;
use smartstring::alias::String;
use std::path::Path;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Handler {
    pub base_path_matcher: String,
    pub name: HandlerName,
    pub variant: HandlerVariant,
    pub config_name: ConfigName,
    pub instances_ids: SmallVec<[InstanceId; 4]>,
}

impl Handler {
    pub fn connect_target(&self, _path: impl AsRef<Path>) -> Option<ConnectTarget> {
        match &self.variant {
            HandlerVariant::Proxy(proxy) => Some(ConnectTarget::Upstream(proxy.upstream.clone())),
            HandlerVariant::StaticDir(_) => Some(ConnectTarget::Internal(self.name.clone())),
            _ => None,
        }
    }

    pub fn auth(&self) -> Option<Auth> {
        match &self.variant {
            HandlerVariant::Auth(auth) => Some(auth.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HandlersProcessor {
    pub handlers: SmallVec<[Handler; 4]>,
}

impl HandlersProcessor {
    pub fn new<'a>(
        handlers: impl Iterator<
            Item = (
                HandlerName,
                HandlerConfig,
                ConfigName,
                SmallVec<[InstanceId; 4]>,
            ),
        >,
    ) -> HandlersProcessor {
        let inner = handlers
            .map(
                |(handler_name, handler_config, config_name, instances_ids)| {
                    let base_path = handler_config
                        .base_path
                        .clone()
                        .into_iter()
                        .map(|bp| bp.as_str().into())
                        .collect::<Vec<String>>()
                        .join("/")
                        .into();
                    (
                        Handler {
                            base_path_matcher: base_path,
                            name: handler_name.clone(),
                            variant: handler_config.variant.clone().into(),
                            config_name,
                            instances_ids,
                        },
                        handler_config.priority,
                    )
                },
            )
            .sorted_by(|a, b| a.1.cmp(&b.1))
            .map(|(s, _)| s)
            .collect();

        HandlersProcessor { handlers: inner }
    }

    // fn seq_for_rest_path<'a>(&'a self, path: &'a str) -> impl Iterator<Item = &'a ServerHandler> {
    //     self.handlers
    //         .iter()
    //         .filter(move |item| path.starts_with(item.base_path_matcher.as_str()))
    // }
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use exogress_config_core::{Config, Proxy, StaticDir};
//     use exogress_entities::MountPointName;
//     use std::str::FromStr;
//
//     #[test]
//     pub fn test_handlers() {
//         const YAML: &str = r#"---
// version: 0.0.1
// revision: 10
// name: repository-1
// upstreams:
//   backend2:
//     port: 3000
// mount_points:
//   mount_point:
//     handlers:
//       directory1:
//         type: static_dir
//         priority: 1000
//         dir: ./dir1
//         base_path: []
//       directory2:
//         type: static_dir
//         priority: 10
//         dir: ./dir2
//         base_path: ["asd", "ads"]
//       main:
//         type: proxy
//         priority: 30
//         upstream: backend
//         base_path: []
// "#;
//         let cfg = serde_yaml::from_str::<Config>(YAML).unwrap();
//
//         let handlers = HandlersProcessor::new(
//             cfg.exposes
//                 .get(&MountPointName::from_str("mount_point").unwrap())
//                 .unwrap()
//                 .handlers
//                 .iter(),
//             vec![].iter(),
//         );
//
//         assert_eq!(
//             handlers.seq_for_rest_path("").cloned().collect::<Vec<_>>(),
//             vec![
//                 ServerHandler {
//                     base_path_matcher: "".into(),
//                     name: "main".parse().unwrap(),
//                     variant: HandlerVariant::Proxy(Proxy {
//                         upstream: "backend".parse().unwrap(),
//                     }),
//                 },
//                 ServerHandler {
//                     base_path_matcher: "".into(),
//                     name: "directory1".parse().unwrap(),
//                     variant: HandlerVariant::StaticDir(StaticDir {
//                         dir: "./dir1".parse().unwrap(),
//                     }),
//                 },
//             ]
//         );
//
//         assert_eq!(
//             handlers
//                 .seq_for_rest_path("asd/ads/hello")
//                 .cloned()
//                 .collect::<Vec<_>>(),
//             vec![
//                 ServerHandler {
//                     base_path_matcher: "asd/ads".into(),
//                     name: "directory2".parse().unwrap(),
//                     variant: HandlerVariant::StaticDir(StaticDir {
//                         dir: "./dir2".parse().unwrap(),
//                     }),
//                 },
//                 ServerHandler {
//                     base_path_matcher: "".into(),
//                     name: "main".parse().unwrap(),
//                     variant: HandlerVariant::Proxy(Proxy {
//                         upstream: "backend".parse().unwrap(),
//                     }),
//                 },
//                 ServerHandler {
//                     base_path_matcher: "".into(),
//                     name: "directory1".parse().unwrap(),
//                     variant: HandlerVariant::StaticDir(StaticDir {
//                         dir: "./dir1".parse().unwrap(),
//                     }),
//                 },
//             ]
//         )
//     }
// }
