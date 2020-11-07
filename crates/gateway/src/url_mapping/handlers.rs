use exogress_config_core::{
    Auth, ClientHandler as ClientHandlerConfig, ClientHandler, ClientHandlerVariant,
    UrlPathSegmentOrQueryPart,
};
use exogress_entities::{ConfigName, HandlerName, InstanceId};
use exogress_tunnel::ConnectTarget;
use itertools::Itertools;
use smallvec::SmallVec;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Handler {
    pub base_path: Vec<UrlPathSegmentOrQueryPart>,
    pub rewrite_base_path: Vec<UrlPathSegmentOrQueryPart>,
    pub name: HandlerName,
    pub config_handler: ClientHandler,
    pub client_config_data: Option<(ConfigName, SmallVec<[InstanceId; 4]>)>,
}

impl Handler {
    pub fn connect_target(&self, _path: impl AsRef<Path>) -> Option<ConnectTarget> {
        match &self.config_handler.variant {
            ClientHandlerVariant::Proxy(proxy) => {
                Some(ConnectTarget::Upstream(proxy.upstream.clone()))
            }
            ClientHandlerVariant::StaticDir(_) => Some(ConnectTarget::Internal(self.name.clone())),
            _ => None,
        }
    }

    pub fn auth(&self) -> Option<Auth> {
        match &self.config_handler.variant {
            ClientHandlerVariant::Auth(auth) => Some(auth.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HandlersProcessor {
    pub handlers: SmallVec<[Handler; 4]>,
}

impl HandlersProcessor {
    // TODO: accept iterator instead of Vec
    pub fn new(
        handlers: Vec<(
            HandlerName,
            ClientHandlerConfig,
            Option<(ConfigName, SmallVec<[InstanceId; 4]>)>,
        )>,
    ) -> HandlersProcessor {
        let inner = handlers
            .into_iter()
            .map(|(handler_name, handler_config, client_config_data)| {
                (
                    Handler {
                        base_path: handler_config.base_path.clone(),
                        rewrite_base_path: handler_config.replace_base_path.clone(),
                        name: handler_name.clone(),
                        config_handler: handler_config.clone(),
                        client_config_data,
                    },
                    handler_config.priority,
                )
            })
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
