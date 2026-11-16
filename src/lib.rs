//! TCP connection probes with explicit outcomes, deadlines, and cancellation.
//!
//! The async engine owns no runtime and performs no terminal I/O. Network
//! adapters can be replaced for deterministic tests or application integration.
//!
//! ```no_run
//! use std::{convert::Infallible, ops::ControlFlow, time::Duration};
//! use tcping::{Engine, Event, SessionConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = SessionConfig::new("example.com:443".parse()?)
//!     .with_count(4)?
//!     .with_connect_timeout(Duration::from_secs(2))?;
//! let engine = Engine::default();
//! let session = engine.collect(&config).await?;
//! assert_eq!(session.probes().len(), 4);
//!
//! let continuous = config.continuous();
//! engine.run_until(&continuous, tokio::time::sleep(Duration::from_secs(10)), |event| {
//!     if let Event::Probe(probe) = event {
//!         let _outcome = probe.outcome();
//!     }
//!     Ok::<_, Infallible>(ControlFlow::Continue(()))
//! }).await?;
//! # Ok(())
//! # }
//! ```
mod config;
mod engine;
mod error;
mod model;
mod network;
mod stats;
mod target;

#[cfg(feature = "report")]
pub mod report;

pub use config::{AddressFamily, ProbeCount, SessionConfig};
pub use engine::Engine;
pub use error::{ConfigError, RunError, SessionError};
pub use model::{
    Counts, Event, Failure, FailureKind, LatencyStats, Outcome, Probe, Resolution,
    ResolutionSource, Session, StopReason, Summary,
};
pub use network::{Connector, DnsResolver, Lookup, Resolver, TcpConnector};
pub use target::Target;
