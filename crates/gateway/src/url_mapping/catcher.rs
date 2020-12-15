use exogress::config_core::Catch;
use exogress::entities::ConfigName;
use hashbrown::HashMap;

#[derive(Debug, Hash, Eq, PartialEq)]
pub enum CatcherScope {
    Project,
    Config(ConfigName),
}

pub struct Catcher {
    inner: HashMap<CatcherScope, Catch>,
}
