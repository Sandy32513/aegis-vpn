pub mod path_selector;
pub mod features;
pub mod adaptive_kill_switch;

pub use path_selector::PathSelector;
pub use features::{NetworkFeatures, FeatureExtractor};
pub use adaptive_kill_switch::{AdaptiveKillSwitch, KillSwitchLevel};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("feature error: {0}")]
    FeatureError(String),
    #[error("prediction error: {0}")]
    PredictionError(String),
    #[error("model error: {0}")]
    ModelError(String),
}