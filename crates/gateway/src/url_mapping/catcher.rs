use exogress_config_core::Catch;
use exogress_entities::ConfigName;
use hashbrown::HashMap;

#[derive(Debug, Hash, Eq, PartialEq)]
pub enum CatcherScope {
    Project,
    Config(ConfigName),
}

pub struct Catcher {
    inner: HashMap<CatcherScope, Catch>,
}
