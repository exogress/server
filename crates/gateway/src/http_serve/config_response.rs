use crate::url_mapping::handlers::HandlersProcessor;
use crate::webapp::ConfigsResponse;
use exogress_config_core::{
    Action, Auth, Catch, CatchAction, CatchActions, ClientConfig, ClientHandler,
    ClientHandlerVariant, Filter, MatchingPath, Proxy, ResponseBody, Rule, StaticDir,
    StaticResponse, StatusCodeRange, StatusCodeRangeHandler, UpstreamDefinition,
    UrlPathSegmentOrQueryPart,
};
use exogress_entities::{
    ConfigName, ExceptionName, HandlerName, MountPointName, StaticResponseName, Upstream,
};
use hashbrown::HashMap;
use http::{HeaderMap, StatusCode};
use itertools::Itertools;
use smol_str::SmolStr;
use std::collections::BTreeMap;
use url::PathSegmentsMut;

pub struct MountPointConfig {
    ordered_handlers: Vec<ResolvedHandler>,
}

#[derive(Debug, Clone)]
struct ResolvedProxy {
    upstream: UpstreamDefinition,
    //TODO: weighted connector with all involved instance_ids
}

#[derive(Debug, Clone)]
struct ResolvedStaticDir {
    config: StaticDir,
}

#[derive(Debug, Clone)]
struct ResolvedAuth {
    config: Auth,
}

#[derive(Debug, Clone)]
enum ResolvedHandlerVariant {
    Proxy(ResolvedProxy),
    StaticDir(ResolvedStaticDir),
    Auth(ResolvedAuth),
}

enum HandlerInvocationResult {
    Ok,
    Exception {
        name: ExceptionName,
        data: HashMap<SmolStr, SmolStr>,
    },
}

impl ResolvedHandlerVariant {
    fn invoke(&self) -> HandlerInvocationResult {
        todo!("delegate to particular handlers")
    }
}

#[derive(Debug, Clone)]
enum ResolvedFinalizingRuleAction {
    Invoke {
        catch: ResolvedCatchActions,
    },
    NextHandler,
    Throw {
        exception: ExceptionName,
        data: HashMap<SmolStr, SmolStr>,
    },
    Respond {
        static_response: ResolvedStaticResponse,
    },
}

#[derive(Debug, Clone)]
enum ResolvedRuleAction {
    Finalizing(ResolvedFinalizingRuleAction),
    None,
}

impl ResolvedRuleAction {
    fn is_finalizing(&self) -> bool {
        match self {
            ResolvedRuleAction::None => false,
            ResolvedRuleAction::Finalizing(_) => true,
        }
    }
}

#[derive(Debug, Clone)]
enum ResolvedCatchAction {
    StaticResponse {
        static_response: ResolvedStaticResponse,
    },
    Throw {
        exception_name: ExceptionName,
        data: HashMap<SmolStr, SmolStr>,
    },
    NextHandler,
}

#[derive(Debug, Clone)]
pub struct ResolvedFilter {
    pub path: MatchingPath,
}

impl ResolvedFilter {
    fn is_matches(&self, path: &PathSegmentsMut) -> bool {
        todo!("return true if rule matches the path segment")
    }
}

#[derive(Debug, Clone)]
struct ResolvedRule {
    filter: ResolvedFilter,
    action: ResolvedRuleAction,
}

impl ResolvedRule {
    fn get_action(&self, path: &PathSegmentsMut) -> Option<&ResolvedRuleAction> {
        if !self.filter.is_matches(path) {
            return None;
        }

        Some(&self.action)
    }
}

#[derive(Debug, Clone)]
struct ResolvedHandler {
    config_name: Option<ConfigName>,

    resolved_variant: ResolvedHandlerVariant,

    base_path: Vec<UrlPathSegmentOrQueryPart>,
    replace_base_path: Vec<UrlPathSegmentOrQueryPart>,
    priority: u16,
    handler_catch: ResolvedCatchActions,
    name: HandlerName,

    mount_point_catch: ResolvedCatchActions,
    project_catch: ResolvedCatchActions,

    resolved_rules: Vec<ResolvedRule>,
}

impl ResolvedHandler {
    /// Handle exception in the right order
    fn handle_exception(
        &self,
        exception_name: &ExceptionName,
        exception_data: &HashMap<SmolStr, SmolStr>,
        maybe_rule_invoke_catch: Option<&ResolvedCatchActions>,
    ) -> ExceptionHandleResult {
        let maybe_resolved_exception = maybe_rule_invoke_catch
            .and_then(|r| r.handle_exception(exception_name))
            .or_else(|| self.handler_catch.handle_exception(exception_name))
            .or_else(|| self.mount_point_catch.handle_exception(exception_name))
            .or_else(|| self.project_catch.handle_exception(exception_name));

        match maybe_resolved_exception {
            None => ExceptionHandleResult::UnhandledException {
                exception_name: exception_name.clone(),
                data: exception_data.clone(),
            },
            Some(ResolvedCatchAction::Throw {
                exception_name,
                data,
            }) => ExceptionHandleResult::UnhandledException {
                exception_name: exception_name.clone(),
                data: data.clone(),
            },
            Some(ResolvedCatchAction::StaticResponse { static_response }) => {
                ExceptionHandleResult::StaticResponse {
                    static_response: static_response.clone(),
                }
            }
            Some(ResolvedCatchAction::NextHandler) => ExceptionHandleResult::NextHandler,
        }
    }

    /// Find appropriate final action, which should be executed
    fn find_action(&self, path: &PathSegmentsMut) -> Option<&ResolvedRuleAction> {
        self.resolved_rules
            .iter()
            .filter_map(|resolved_rule| resolved_rule.get_action(path))
            // TODO: apply modifications
            .filter(|maybe_resolved_action| maybe_resolved_action.is_finalizing())
            .next()
    }

    // Handle whole request
    fn handle_request(&self, path: &PathSegmentsMut) -> Option<()> {
        todo!("1. correct base path");
        let action = self.find_action(path)?;

        match action {
            ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Invoke { catch }) => {
                let invocation_result = self.resolved_variant.invoke();
                match invocation_result {
                    HandlerInvocationResult::Ok => {
                        return todo!("all good, executed successfully");
                    }
                    HandlerInvocationResult::Exception { name, data } => {
                        self.handle_exception(&name, &data, Some(catch));
                    }
                }
            }
            ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::NextHandler) => {
                return None
            }
            ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Throw {
                exception,
                data,
            }) => {
                self.handle_exception(exception, data, None);
            }
            ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Respond {
                static_response,
            }) => static_response.invoke(),
            ResolvedRuleAction::None => {
                unreachable!("None axtion should never be called for execution")
            }
        }

        None
    }
}

impl ResolvedCatchActions {
    fn handle_exception(&self, name: &ExceptionName) -> Option<&ResolvedCatchAction> {
        if let Some(catch) = self.exceptions.get(name) {
            return Some(catch);
        }
        if let Some(unhandled_catch) = &self.unhandled_exception {
            return Some(unhandled_catch);
        }
        None
    }
}

#[derive(Debug, Clone)]
enum ExceptionHandleResult {
    StaticResponse {
        static_response: ResolvedStaticResponse,
    },
    NextHandler,
    UnhandledException {
        exception_name: ExceptionName,
        data: HashMap<SmolStr, SmolStr>,
    },
}

#[derive(Debug, Clone)]
struct ResolvedMountPoint {
    handlers: Vec<ResolvedHandler>,
}

fn resolve_static_response(
    static_response_name: &StaticResponseName,
    status_code: &Option<exogress_config_core::StatusCode>,
    data: &BTreeMap<SmolStr, SmolStr>,
    static_responses: &HashMap<StaticResponseName, StaticResponse>,
) -> Option<ResolvedStaticResponse> {
    let static_response: StaticResponse = static_responses.get(&static_response_name)?.clone();

    let static_response_status_code = match &static_response {
        StaticResponse::Redirect(redirect) => redirect.redirect_type.status_code(),
        StaticResponse::Raw(raw) => raw.status_code,
    };

    let resolved = ResolvedStaticResponse {
        status_code: status_code
            .as_ref()
            .map(|s| s.0)
            .unwrap_or(static_response_status_code),
        body: match &static_response {
            StaticResponse::Raw(raw) => (&raw.body).clone(),
            StaticResponse::Redirect(_) => {
                vec![]
            }
        },
        headers: match &static_response {
            StaticResponse::Raw(raw) => raw.common.headers.clone(),
            StaticResponse::Redirect(redirect) => {
                let mut headers = redirect.common.headers.clone();
                headers.insert(
                    "Location",
                    redirect.destination.as_str().parse().expect("bad URL"),
                );
                headers
            }
        },
        data: data
            .iter()
            .map(|(k, v)| (k.as_str().into(), v.as_str().into()))
            .collect(),
    };

    Some(resolved)
}

fn resolve_cache_action(
    catch_action: &CatchAction,
    static_responses: &HashMap<StaticResponseName, StaticResponse>,
) -> Option<ResolvedCatchAction> {
    Some(match catch_action {
        CatchAction::StaticResponse {
            static_response_name,
            status_code,
            data,
        } => ResolvedCatchAction::StaticResponse {
            static_response: resolve_static_response(
                static_response_name,
                status_code,
                data,
                static_responses,
            )?,
        },
        CatchAction::Throw {
            exception_name,
            data,
        } => ResolvedCatchAction::Throw {
            exception_name: exception_name.clone(),
            data: data.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        },
        CatchAction::NextHandler => ResolvedCatchAction::NextHandler,
    })
}

fn resolve_catch_actions(
    catch_actions: &CatchActions,
    static_responses: &HashMap<StaticResponseName, StaticResponse>,
) -> Option<ResolvedCatchActions> {
    Some(ResolvedCatchActions {
        exceptions: catch_actions
            .exceptions
            .iter()
            .map(|(exception_name, catch_action)| {
                let resolved_action = resolve_cache_action(catch_action, &static_responses)?;

                Some((exception_name.clone(), resolved_action))
            })
            .into_iter()
            .collect::<Option<HashMap<ExceptionName, ResolvedCatchAction>>>()?,
        unhandled_exception: catch_actions
            .unhandled_exception
            .as_ref()
            .and_then(|r| resolve_cache_action(r, &static_responses)),
        status_codes: catch_actions
            .status_codes
            .iter()
            .map(|range_handler| {
                Some(ResolvedStatusCodeRangeHandler {
                    status_codes_range: range_handler.status_codes_range.clone(),
                    catch: resolve_cache_action(&range_handler.catch, &static_responses)?,
                })
            })
            .collect::<Option<_>>()?,
    })
}
impl MountPointConfig {
    fn new(resp: ConfigsResponse) -> Result<MountPointConfig, ()> {
        let grouped = resp.configs.iter().group_by(|item| &item.config_name);

        let project_catch = resp.project_config.catch;

        let project_mount_points = resp
            .project_config
            .mount_points
            .into_iter()
            .map(|(k, v)| (k, (None, None, v.into())));

        // static responses are shared accross different config names
        let mut static_responses = HashMap::new();

        let grouped_mount_points = grouped
            .into_iter()
            .map(move |(config_name, configs)| {
                let config = &configs
                    .into_iter()
                    .map(|entry| (entry.instance_ids.len(), entry))
                    .sorted_by(|(left, _), (right, _)| left.cmp(&right).reverse())
                    .into_iter()
                    .next() //keep only
                    .unwrap()
                    .1
                    .config;

                let upstreams = &config.upstreams;

                config
                    .mount_points
                    .clone()
                    .into_iter()
                    .map(move |(mp_name, mp)| {
                        (
                            mp_name,
                            (Some(config_name.clone()), Some(upstreams.clone()), mp),
                        )
                    })
            })
            .flatten()
            .chain(project_mount_points)
            .group_by(|a| a.0.clone())
            .into_iter()
            .map(|a| a.1)
            .flatten()
            .collect::<Vec<_>>();

        for (_, (_, _, mp)) in &grouped_mount_points {
            for (name, static_response) in &mp.static_responses {
                static_responses.insert(name.clone(), static_response.clone());
            }
        }

        let mut merged_resolved_handlers = vec![];

        for (_, (config_name, upstreams, mp)) in grouped_mount_points.into_iter() {
            let mp_catch = mp.catch.clone();
            shadow_clone!(project_catch);
            shadow_clone!(static_responses);

            let mut r = mp.handlers
                .into_iter()
                .map(move |(handler_name, handler)| {
                    Some(ResolvedHandler {
                        config_name: config_name.clone(),

                        resolved_variant: match handler.variant {
                            ClientHandlerVariant::Auth(auth) => {
                                ResolvedHandlerVariant::Auth(ResolvedAuth { config: auth })
                            }
                            ClientHandlerVariant::StaticDir(static_dir) => {
                                ResolvedHandlerVariant::StaticDir(ResolvedStaticDir {
                                    config: static_dir,
                                })
                            }
                            ClientHandlerVariant::Proxy(proxy) => {
                                ResolvedHandlerVariant::Proxy(ResolvedProxy {
                                    upstream: upstreams
                                        .as_ref()
                                        .expect(
                                            "[BUG]: try to access upstream for project-level config",
                                        )
                                        .get(&proxy.upstream)
                                        .cloned()?,
                                })
                            }
                        },
                        base_path: handler.base_path,
                        replace_base_path: handler.replace_base_path,
                        priority: handler.priority,
                        handler_catch: resolve_catch_actions(
                            &handler.catch.actions,
                            &static_responses,
                        )?,
                        name: handler_name,
                        mount_point_catch: resolve_catch_actions(
                            &mp_catch.actions,
                            &static_responses,
                        )?,
                        project_catch: resolve_catch_actions(
                            &project_catch.actions,
                            &static_responses,
                        )?,
                        resolved_rules: handler
                            .rules
                            .into_iter()
                            .map(|rule| {
                                Some(ResolvedRule {
                                    filter: ResolvedFilter {
                                        path: rule.filter.path,
                                    },
                                    action: match rule.action {
                                        Action::Invoke { catch } => ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Invoke {
                                            catch: resolve_catch_actions(
                                                &catch.actions,
                                                &static_responses,
                                            )?,
                                        }),
                                        Action::NextHandler => ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::NextHandler),
                                        Action::None => ResolvedRuleAction::None,
                                        Action::Throw { exception, data } => ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Throw {
                                            exception,
                                            data: data.iter().map(|(k,v)| (k.as_str().into(), v.as_str().into())).collect(),
                                        }),
                                        Action::Respond {
                                            static_response_name,
                                            status_code,
                                            data,
                                        } => ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Respond {
                                            static_response: resolve_static_response(
                                                &static_response_name,
                                                &status_code,
                                                &data,
                                                &static_responses,
                                            )?,
                                        }),
                                    },
                                })
                            })
                            .collect::<Option<_>>()?,
                    })
                })
                .collect::<Option<Vec<_>>>()
                .ok_or(())?;

            merged_resolved_handlers.append(&mut r);
        }

        merged_resolved_handlers.sort_by(|left, right| left.priority.cmp(&right.priority));

        Ok(MountPointConfig {
            ordered_handlers: merged_resolved_handlers,
        })
    }
}

#[derive(Debug, Clone)]
struct ResolvedStaticResponse {
    status_code: StatusCode,
    body: Vec<ResponseBody>,
    headers: HeaderMap,
    data: HashMap<SmolStr, SmolStr>,
}

impl ResolvedStaticResponse {
    fn invoke(&self) {
        todo!("perform static response!");
    }
}

#[derive(Debug, Clone)]
struct ResolvedCatchActions {
    exceptions: HashMap<ExceptionName, ResolvedCatchAction>,
    unhandled_exception: Option<ResolvedCatchAction>,
    status_codes: Vec<ResolvedStatusCodeRangeHandler>,
}

#[derive(Debug, Clone)]
struct ResolvedStatusCodeRangeHandler {
    status_codes_range: StatusCodeRange,
    catch: ResolvedCatchAction,
}

#[cfg(test)]
mod test {
    use super::*;

    //     #[test]
    //     fn test_parsing_config_response_no_instances() {
    //         const JSON: &str = r#"{
    //   "generated_at": 1606467323711,
    //   "account": "gleb",
    //   "account_unique_id": "01ENZAGRCYQ5WEVB0DT890RXTK",
    //   "project": "home",
    //   "project_config": {
    //     "version": "1.0.0",
    //     "mount-points": {
    //       "backend": {
    //         "handlers": {
    //           "authorize": {
    //             "type": "auth",
    //             "providers": [
    //               {
    //                 "name": "github",
    //                 "acl": [
    //                   {
    //                     "allow": "user"
    //                   }
    //                 ]
    //               }
    //             ],
    //             "priority": 1
    //           }
    //         }
    //       }
    //     }
    //   },
    //   "configs": [],
    //   "url_prefix": "local.sexg.link/",
    //   "mount_point": "backend",
    //   "jwt_ecdsa": {
    //     "private_key": "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgf8NRJLvkKcASfP74\nWGvgwENSH8Uf8wOyVcpJHSPvwTOhRANCAASoP0aITZ7/1VqE70muWc0AWE9y7OXl\n42wDOcGqx0kqJQL7CB3Rqb0piojbg99Ea9WD7s37a9De9FkfsdHMd3LL\n-----END PRIVATE KEY-----\n",
    //     "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqD9GiE2e/9VahO9JrlnNAFhPcuzl\n5eNsAznBqsdJKiUC+wgd0am9KYqI24PfRGvVg+7N+2vQ3vRZH7HRzHdyyw==\n-----END PUBLIC KEY-----\n"
    //   }
    // }
    // "#;
    //         let configs_response: ConfigsResponse = serde_json::from_str(JSON).unwrap();
    //         let _ = MountPointConfig::new(configs_response).unwrap();
    //     }
    //
    //     #[test]
    //     fn test_parsing_config() {
    //         const JSON: &str = r#"{
    //   "generated_at": 1606469115249,
    //   "account": "gleb",
    //   "account_unique_id": "01ENZAGRCYQ5WEVB0DT890RXTK",
    //   "project": "home",
    //   "project_config": {
    //     "version": "1.0.0",
    //     "mount-points": {
    //       "backend": {
    //         "handlers": {
    //           "authorize": {
    //             "type": "auth",
    //             "providers": [
    //               {
    //                 "name": "github",
    //                 "acl": [
    //                   {
    //                     "allow": "user"
    //                   }
    //                 ]
    //               }
    //             ],
    //             "priority": 1
    //           }
    //         }
    //       }
    //     }
    //   },
    //   "configs": [
    //     {
    //       "config": {
    //         "version": "1.0.0",
    //         "revision": 1,
    //         "name": "config1",
    //         "mount-points": {
    //           "backend": {
    //             "handlers": {
    //               "my-target": {
    //                 "type": "proxy",
    //                 "upstream": "my-upstream",
    //                 "base-path": [],
    //                 "replace-base-path": [],
    //                 "priority": 10
    //               }
    //             },
    //             "static-responses": {
    //               "bad-gateway": {
    //                 "kind": "raw",
    //                 "status-code": 200,
    //                 "body": [
    //                   {
    //                     "content-type": "text/html",
    //                     "content": "<html>\n  <body>\n    Not found at {{ this.time }}\n  </body>\n</html>\n",
    //                     "engine": "handlebars"
    //                   },
    //                   {
    //                     "content-type": "application/json",
    //                     "content": "{\"status\": \"not-found\"}\n",
    //                     "engine": null
    //                   }
    //                 ],
    //                 "headers": {
    //                   "x-error-detected": "1"
    //                 }
    //               },
    //               "redirect-to-google1": {
    //                 "kind": "redirect",
    //                 "redirect-type": "see-other",
    //                 "destination": "https://google.com/",
    //                 "headers": {
    //                   "x-my-header": "true"
    //                 }
    //               },
    //               "redirect-to-google2": {
    //                 "kind": "raw",
    //                 "status-code": 307,
    //                 "body": [],
    //                 "headers": {
    //                   "location": "https://google.com"
    //                 }
    //               },
    //               "static": {
    //                 "kind": "raw",
    //                 "status-code": 200,
    //                 "body": [
    //                   {
    //                     "content-type": "text/html",
    //                     "content": "<html>\n  <body>\n    Static {{ this.time }}\n  </body>\n</html>\n",
    //                     "engine": "handlebars"
    //                   },
    //                   {
    //                     "content-type": "application/json",
    //                     "content": "{\"status\": \"static\"}\n",
    //                     "engine": null
    //                   }
    //                 ],
    //                 "headers": {
    //                   "x-static": "true"
    //                 }
    //               }
    //             }
    //           }
    //         },
    //         "upstreams": {
    //           "my-upstream": {
    //             "port": 2368,
    //             "host": "127.0.0.1"
    //           }
    //         }
    //       },
    //       "config_name": "config1",
    //       "instance_ids": [
    //         "01ER4GAMQXFVSP87KMGANKNE26"
    //       ],
    //       "revision": 1
    //     }
    //   ],
    //   "url_prefix": "local.sexg.link/",
    //   "mount_point": "backend",
    //   "jwt_ecdsa": {
    //     "private_key": "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgf8NRJLvkKcASfP74\nWGvgwENSH8Uf8wOyVcpJHSPvwTOhRANCAASoP0aITZ7/1VqE70muWc0AWE9y7OXl\n42wDOcGqx0kqJQL7CB3Rqb0piojbg99Ea9WD7s37a9De9FkfsdHMd3LL\n-----END PRIVATE KEY-----\n",
    //     "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqD9GiE2e/9VahO9JrlnNAFhPcuzl\n5eNsAznBqsdJKiUC+wgd0am9KYqI24PfRGvVg+7N+2vQ3vRZH7HRzHdyyw==\n-----END PUBLIC KEY-----\n"
    //   }
    // }
    // "#;
    //         let configs_response: ConfigsResponse = serde_json::from_str(JSON).unwrap();
    //         let _ = MountPointConfig::new(configs_response).unwrap();
    //     }
    //
    #[test]
    fn test_revisions_filtering() {
        const JSON: &str = r#"{
  "generated_at": 1606490346283,
  "account": "account-name",
  "account_unique_id": "01ENZAGRCYQ5WEVB0DT890RXTK",
  "project": "my-prj",
  "project_config": {
    "version": "1.0.0",
    "mount-points": {
      "backend": {
        "handlers": {
          "authorize": {
            "type": "auth",
            "providers": [
              {
                "name": "github",
                "acl": [
                  {
                    "allow": "username"
                  }
                ]
              }
            ],
            "priority": 1
          }
        }
      }
    }
  },
  "configs": [
    {
      "config": {
        "version": "1.0.0",
        "revision": 1,
        "name": "config1",
        "mount-points": {
          "backend": {
            "handlers": {
              "my-target": {
                "type": "proxy",
                "upstream": "my-upstream",
                "priority": 10
              }
            }
          }
        },
        "upstreams": {
          "my-upstream": {
            "port": 2368,
            "host": "127.0.0.1"
          }
        }
      },
      "config_name": "config1",
      "instance_ids": [
        "01ER54CWZD747V2369RD36Y9MF"
      ],
      "revision": 1
    },
    {
      "config": {
        "version": "1.0.0",
        "revision": 2,
        "name": "config1",
        "mount-points": {
          "backend": {
            "handlers": {
              "my-target": {
                "type": "proxy",
                "upstream": "my-upstream",
                "priority": 20
              }
            }
          }
        },
        "upstreams": {
          "my-upstream": {
            "port": 2368,
            "host": "127.0.0.1"
          }
        }
      },
      "config_name": "config1",
      "instance_ids": [
        "01ER54J5N5VHV99AZETBFCSB5P", "01ER55M7DCGC4K0M533ASKG0E1"
      ],
      "revision": 2
    }
  ],
  "url_prefix": "local.sexg.link/",
  "mount_point": "backend",
  "jwt_ecdsa": {
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgf8NRJLvkKcASfP74\nWGvgwENSH8Uf8wOyVcpJHSPvwTOhRANCAASoP0aITZ7/1VqE70muWc0AWE9y7OXl\n42wDOcGqx0kqJQL7CB3Rqb0piojbg99Ea9WD7s37a9De9FkfsdHMd3LL\n-----END PRIVATE KEY-----\n",
    "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqD9GiE2e/9VahO9JrlnNAFhPcuzl\n5eNsAznBqsdJKiUC+wgd0am9KYqI24PfRGvVg+7N+2vQ3vRZH7HRzHdyyw==\n-----END PUBLIC KEY-----\n"
  }
}"#;
        let configs_response: ConfigsResponse = serde_json::from_str(JSON).unwrap();
        let _ = MountPointConfig::new(configs_response).unwrap();
    }
}
