use maxminddb::Reader;
use memmap2::Mmap;
use std::sync::Arc;

pub mod clap;
pub mod model;

pub type GeoipReader = Arc<Reader<Mmap>>;

pub use maxminddb::MaxMindDBError;
