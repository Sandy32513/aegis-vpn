pub mod metrics;
pub mod events;
pub mod export;

pub use metrics::{ConnectionMetrics, MetricsRecorder};
pub use events::{ConnectionEvent, EventRecorder};
pub use export::{PrometheusExporter, ExportFormat};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("metric error: {0}")]
    MetricError(String),
    #[error("export error: {0}")]
    ExportError(String),
    #[error("storage error: {0}")]
    StorageError(String),
}