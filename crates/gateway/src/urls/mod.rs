mod match_pattern;
pub mod matchable_url;
pub mod matched;

#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    Http,
    WebSockets,
}

pub use match_pattern::{MatchPattern, MatchPatternError};
