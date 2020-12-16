use exogress_common::config_core::Catch;
use exogress_common::entities::ConfigName;
use hashbrown::HashMap;

#[derive(Debug, Hash, Eq, PartialEq)]
pub enum CatcherScope {
    Project,
    Config(ConfigName),
}

pub struct Catcher {
    inner: HashMap<CatcherScope, Catch>,
}
