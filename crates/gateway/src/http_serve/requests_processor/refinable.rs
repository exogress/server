use exogress_common::{
    config_core::{
        referenced::Container, refinable::Refinable, ClientConfig, ClientConfigRevision,
        RescueItem, StaticResponse,
    },
    entities::{ConfigName, HandlerName, MountPointName, StaticResponseName},
};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, VecDeque},
};

#[derive(Clone, Debug, Hash)]
pub enum Scope {
    ProjectConfig,
    ClientConfig {
        config: ConfigName,
        revision: ClientConfigRevision,
    },
    ProjectMount {
        mount_point: MountPointName,
    },
    ClientMount {
        config: ConfigName,
        revision: ClientConfigRevision,
        mount_point: MountPointName,
    },
    ProjectHandler {
        mount_point: MountPointName,
        handler: HandlerName,
    },
    ClientHandler {
        config: ConfigName,
        revision: ClientConfigRevision,
        mount_point: MountPointName,
        handler: HandlerName,
    },
    ProjectRule {
        mount_point: MountPointName,
        handler: HandlerName,
        rule_num: usize,
    },
    ClientRule {
        config: ConfigName,
        revision: ClientConfigRevision,
        mount_point: MountPointName,
        handler: HandlerName,
        rule_num: usize,
    },
}

impl Scope {
    fn order(&self) -> u8 {
        match self {
            Scope::ProjectConfig => 1,
            Scope::ClientConfig { .. } => 2,
            Scope::ProjectMount { .. } => 3,
            Scope::ClientMount { .. } => 4,
            Scope::ProjectHandler { .. } => 5,
            Scope::ClientHandler { .. } => 6,
            Scope::ProjectRule { .. } => 7,
            Scope::ClientRule { .. } => 8,
        }
    }

    fn client_config(&self) -> Option<(&ConfigName, &ClientConfigRevision)> {
        match self {
            Scope::ClientConfig { config, revision }
            | Scope::ClientMount {
                config, revision, ..
            }
            | Scope::ClientHandler {
                config, revision, ..
            }
            | Scope::ClientRule {
                config, revision, ..
            } => Some((config, revision)),
            _ => None,
        }
    }

    fn mount_point_name(&self) -> Option<&MountPointName> {
        match self {
            Scope::ClientMount { mount_point, .. }
            | Scope::ClientHandler { mount_point, .. }
            | Scope::ClientRule { mount_point, .. } => Some(mount_point),
            _ => None,
        }
    }

    fn handler_name(&self) -> Option<&HandlerName> {
        match self {
            Scope::ClientHandler { handler, .. } | Scope::ClientRule { handler, .. } => {
                Some(handler)
            }
            _ => None,
        }
    }

    fn rule_num(&self) -> Option<&usize> {
        match self {
            Scope::ClientRule { rule_num, .. } => Some(rule_num),
            _ => None,
        }
    }

    fn matches_by_same_entity(&self, match_to: &Scope) -> bool {
        (self.mount_point_name() == match_to.mount_point_name()
            || self.mount_point_name().is_none())
            && (self.handler_name() == match_to.handler_name() || self.handler_name().is_none())
            && (self.rule_num() == match_to.rule_num() || self.rule_num().is_none())
    }
}

impl PartialEq for Scope {
    fn eq(&self, other: &Self) -> bool {
        self.order().eq(&other.order())
    }
}

impl PartialOrd for Scope {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Scope {
    fn cmp(&self, other: &Self) -> Ordering {
        self.order().cmp(&other.order())
    }
}

impl Eq for Scope {}

pub struct RefinableSet {
    inner: BTreeMap<Scope, Refinable>,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct Refined {
    pub static_responses: BTreeMap<StaticResponseName, (StaticResponse, Scope)>,
    pub rescue: VecDeque<(RescueItem, Scope)>,
}

impl RefinableSet {
    pub fn new() -> Self {
        RefinableSet {
            inner: Default::default(),
        }
    }

    pub fn add(&mut self, scope: Scope, refinable: &Refinable) -> anyhow::Result<()> {
        if self
            .inner
            .insert(scope.clone(), refinable.clone())
            .is_some()
        {
            bail!("refinable scope already added");
        }

        Ok(())
    }

    pub fn joined_for_scope(&self, current_scope: Scope) -> Refined {
        self.inner
            .range(&Scope::ProjectConfig..=&current_scope)
            .filter(|(existing_scope, _)| existing_scope.matches_by_same_entity(&current_scope))
            .fold(
                Refined {
                    static_responses: Default::default(),
                    rescue: Default::default(),
                },
                |mut acc, (scope, refinable)| {
                    for (static_resp_name, static_resp) in refinable.static_responses.iter() {
                        acc.static_responses.insert(
                            static_resp_name.clone(),
                            (static_resp.clone(), scope.clone()),
                        );
                    }
                    for rescue_item in refinable.rescue.iter().rev() {
                        acc.rescue.push_front((rescue_item.clone(), scope.clone()));
                    }
                    acc
                },
            )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use exogress_common::config_core::{CatchAction, CatchMatcher, RescueItem};

    #[test]
    fn test_lookup() {
        let mut set = RefinableSet::new();

        set.add(
            Scope::ProjectConfig,
            &Refinable {
                static_responses: Default::default(),
                rescue: vec![RescueItem {
                    catch: CatchMatcher::Exception("exception_project".parse().unwrap()),
                    handle: CatchAction::NextHandler,
                }],
            },
        )
        .unwrap();

        set.add(
            Scope::ClientConfig {
                config: "config1".parse().unwrap(),
                revision: ClientConfigRevision(1),
            },
            &Refinable {
                static_responses: Default::default(),
                rescue: vec![RescueItem {
                    catch: CatchMatcher::Exception("client-config1".parse().unwrap()),
                    handle: CatchAction::NextHandler,
                }],
            },
        )
        .unwrap();

        set.add(
            Scope::ProjectMount {
                mount_point: "mp1".parse().unwrap(),
            },
            &Refinable {
                static_responses: Default::default(),
                rescue: vec![
                    RescueItem {
                        catch: CatchMatcher::Exception("project-mp1".parse().unwrap()),
                        handle: CatchAction::NextHandler,
                    },
                    RescueItem {
                        catch: CatchMatcher::Exception("project-mp1:ex2".parse().unwrap()),
                        handle: CatchAction::NextHandler,
                    },
                ],
            },
        )
        .unwrap();

        assert_eq!(
            set.joined_for_scope(Scope::ClientMount {
                config: "config1".parse().unwrap(),
                revision: ClientConfigRevision(1),
                mount_point: "mp1".parse().unwrap(),
            }),
            Refined {
                static_responses: Default::default(),
                rescue: vec![
                    (
                        RescueItem {
                            catch: CatchMatcher::Exception("project-mp1".parse().unwrap()),
                            handle: CatchAction::NextHandler,
                        },
                        Scope::ProjectMount {
                            mount_point: "mp1".parse().unwrap()
                        }
                    ),
                    (
                        RescueItem {
                            catch: CatchMatcher::Exception("project-mp1:ex2".parse().unwrap()),
                            handle: CatchAction::NextHandler,
                        },
                        Scope::ProjectMount {
                            mount_point: "mp1".parse().unwrap()
                        }
                    ),
                    (
                        RescueItem {
                            catch: CatchMatcher::Exception("client-config1".parse().unwrap()),
                            handle: CatchAction::NextHandler,
                        },
                        Scope::ClientConfig {
                            config: "config1".parse().unwrap(),
                            revision: ClientConfigRevision(1),
                        }
                    ),
                    (
                        RescueItem {
                            catch: CatchMatcher::Exception("exception_project".parse().unwrap()),
                            handle: CatchAction::NextHandler,
                        },
                        Scope::ProjectConfig
                    ),
                ]
                .into()
            }
        );

        assert_eq!(
            set.joined_for_scope(Scope::ProjectConfig),
            Refined {
                static_responses: Default::default(),
                rescue: vec![(
                    RescueItem {
                        catch: CatchMatcher::Exception("exception_project".parse().unwrap()),
                        handle: CatchAction::NextHandler,
                    },
                    Scope::ProjectConfig
                )]
                .into()
            }
        );

        assert_eq!(
            set.joined_for_scope(Scope::ClientConfig {
                config: "config1".parse().unwrap(),
                revision: ClientConfigRevision(1),
            }),
            Refined {
                static_responses: Default::default(),
                rescue: vec![
                    (
                        RescueItem {
                            catch: CatchMatcher::Exception("client-config1".parse().unwrap()),
                            handle: CatchAction::NextHandler,
                        },
                        Scope::ClientConfig {
                            config: "config1".parse().unwrap(),
                            revision: ClientConfigRevision(1),
                        }
                    ),
                    (
                        RescueItem {
                            catch: CatchMatcher::Exception("exception_project".parse().unwrap()),
                            handle: CatchAction::NextHandler,
                        },
                        Scope::ProjectConfig
                    ),
                ]
                .into()
            }
        );
    }
}
