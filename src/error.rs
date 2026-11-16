use std::{io, time::Duration};
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("invalid target: {0}")]
    Target(String),
    #[error("{0} must be greater than zero")]
    ZeroDuration(&'static str),
    #[error("duration is too large for the monotonic clock")]
    DurationOverflow,
    #[error("probe count must be greater than zero")]
    ZeroCount,
    #[error("collecting results requires a finite probe count")]
    ContinuousCollection,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SessionError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("DNS resolution failed: {0}")]
    Resolve(#[source] io::Error),
    #[error("DNS resolution timed out after {0:?}")]
    ResolveTimeout(Duration),
    #[error("no address matches the requested IP family")]
    NoAddress,
}

#[derive(Debug, Error)]
pub enum RunError<E> {
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error("event handler failed: {0}")]
    Handler(E),
}
