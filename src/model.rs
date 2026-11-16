use crate::Target;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailureKind {
    Refused,
    HostUnreachable,
    NetworkUnreachable,
    PermissionDenied,
    Reset,
    Aborted,
    AddressUnavailable,
    Other,
}
impl FailureKind {
    pub fn code(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::HostUnreachable => "host_unreachable",
            Self::NetworkUnreachable => "network_unreachable",
            Self::PermissionDenied => "permission_denied",
            Self::Reset => "reset",
            Self::Aborted => "aborted",
            Self::AddressUnavailable => "address_unavailable",
            Self::Other => "error",
        }
    }
    pub fn description(self) -> &'static str {
        match self {
            Self::Refused => "connection refused (port closed)",
            Self::HostUnreachable => "host unreachable",
            Self::NetworkUnreachable => "network unreachable",
            Self::PermissionDenied => "permission denied",
            Self::Reset => "connection reset",
            Self::Aborted => "connection aborted",
            Self::AddressUnavailable => "local address unavailable",
            Self::Other => "connection failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    kind: FailureKind,
    os_code: Option<i32>,
    message: String,
}
impl Failure {
    pub fn kind(&self) -> FailureKind {
        self.kind
    }
    pub fn os_code(&self) -> Option<i32> {
        self.os_code
    }
    pub fn message(&self) -> &str {
        &self.message
    }
    pub(crate) fn from_io(error: io::Error) -> Self {
        use io::ErrorKind as K;
        let kind = match error.kind() {
            K::ConnectionRefused => FailureKind::Refused,
            K::HostUnreachable => FailureKind::HostUnreachable,
            K::NetworkUnreachable => FailureKind::NetworkUnreachable,
            K::PermissionDenied => FailureKind::PermissionDenied,
            K::ConnectionReset => FailureKind::Reset,
            K::ConnectionAborted => FailureKind::Aborted,
            K::AddrNotAvailable => FailureKind::AddressUnavailable,
            _ => FailureKind::Other,
        };
        Self {
            kind,
            os_code: error.raw_os_error(),
            message: error.to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    Open { rtt: Duration },
    Failed(Failure),
    TimedOut,
    Cancelled,
}
impl Outcome {
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Open { .. })
    }
    pub fn code(&self) -> &'static str {
        match self {
            Self::Open { .. } => "open",
            Self::Failed(failure) => failure.kind.code(),
            Self::TimedOut => "timeout",
            Self::Cancelled => "cancelled",
        }
    }
    pub fn description(&self) -> &'static str {
        match self {
            Self::Open { .. } => "open",
            Self::Failed(failure) => failure.kind.description(),
            Self::TimedOut => "request timed out",
            Self::Cancelled => "probe cancelled",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Probe {
    pub(crate) mode: crate::ProbeMode,
    pub(crate) sequence: u64,
    pub(crate) address: SocketAddr,
    pub(crate) started_at: SystemTime,
    pub(crate) elapsed: Duration,
    pub(crate) timeout: Duration,
    pub(crate) outcome: Outcome,
    pub(crate) jitter: Option<Duration>,
}
impl Probe {
    pub fn mode(&self) -> crate::ProbeMode {
        self.mode
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn started_at(&self) -> SystemTime {
        self.started_at
    }
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }
    pub fn rtt(&self) -> Option<Duration> {
        match self.outcome {
            Outcome::Open { rtt } => Some(rtt),
            _ => None,
        }
    }
    pub fn jitter(&self) -> Option<Duration> {
        self.jitter
    }
}

/// The source of the address used by this lookup, not configured DNS candidates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolutionSource {
    Dns(IpAddr),
    Cache,
    Hosts,
    Literal,
    Unknown,
}
impl ResolutionSource {
    pub fn code(self) -> &'static str {
        match self {
            Self::Dns(_) => "dns",
            Self::Cache => "cache",
            Self::Hosts => "hosts",
            Self::Literal => "literal",
            Self::Unknown => "unknown",
        }
    }
    /// The directly queried server that supplied this result; absent for local results.
    pub fn dns_server(self) -> Option<IpAddr> {
        match self {
            Self::Dns(server) => Some(server),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Resolution {
    pub(crate) mode: crate::ProbeMode,
    pub(crate) target: Target,
    pub(crate) candidates: Vec<SocketAddr>,
    pub(crate) source: ResolutionSource,
    pub(crate) selected: SocketAddr,
    pub(crate) started_at: SystemTime,
    pub(crate) elapsed: Duration,
}
impl Resolution {
    pub fn mode(&self) -> crate::ProbeMode {
        self.mode
    }
    pub fn target(&self) -> &Target {
        &self.target
    }
    pub fn candidates(&self) -> &[SocketAddr] {
        &self.candidates
    }
    pub fn source(&self) -> ResolutionSource {
        self.source
    }
    pub fn selected(&self) -> SocketAddr {
        self.selected
    }
    pub fn started_at(&self) -> SystemTime {
        self.started_at
    }
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StopReason {
    CountReached,
    FirstSuccess,
    Cancelled,
    HandlerStopped,
}
impl StopReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::CountReached => "count_reached",
            Self::FirstSuccess => "first_success",
            Self::Cancelled => "cancelled",
            Self::HandlerStopped => "handler_stopped",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub(crate) attempted: u64,
    pub(crate) open: u64,
    pub(crate) failed: u64,
    pub(crate) timed_out: u64,
    pub(crate) cancelled: u64,
}
impl Counts {
    pub fn attempted(self) -> u64 {
        self.attempted
    }
    pub fn open(self) -> u64 {
        self.open
    }
    pub fn failed(self) -> u64 {
        self.failed
    }
    pub fn timed_out(self) -> u64 {
        self.timed_out
    }
    pub fn cancelled(self) -> u64 {
        self.cancelled
    }
    pub fn completed(self) -> u64 {
        self.open + self.failed + self.timed_out
    }
    pub fn failure_ratio(self) -> Option<f64> {
        let completed = self.completed();
        (completed != 0).then(|| (self.failed + self.timed_out) as f64 / completed as f64)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LatencyStats {
    pub(crate) min: Duration,
    pub(crate) average: Duration,
    pub(crate) max: Duration,
}
impl LatencyStats {
    pub fn min(self) -> Duration {
        self.min
    }
    pub fn average(self) -> Duration {
        self.average
    }
    pub fn max(self) -> Duration {
        self.max
    }
}

#[derive(Clone, Debug)]
pub struct Summary {
    pub(crate) mode: crate::ProbeMode,
    pub(crate) target: Target,
    pub(crate) address: Option<SocketAddr>,
    pub(crate) started_at: SystemTime,
    pub(crate) finished_at: SystemTime,
    pub(crate) elapsed: Duration,
    pub(crate) resolution_elapsed: Option<Duration>,
    pub(crate) reason: StopReason,
    pub(crate) counts: Counts,
    pub(crate) latency: Option<LatencyStats>,
    pub(crate) jitter_samples: u64,
    pub(crate) jitter_p95: Option<Duration>,
}
impl Summary {
    pub fn mode(&self) -> crate::ProbeMode {
        self.mode
    }
    pub fn target(&self) -> &Target {
        &self.target
    }
    pub fn address(&self) -> Option<SocketAddr> {
        self.address
    }
    pub fn started_at(&self) -> SystemTime {
        self.started_at
    }
    pub fn finished_at(&self) -> SystemTime {
        self.finished_at
    }
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }
    pub fn resolution_elapsed(&self) -> Option<Duration> {
        self.resolution_elapsed
    }
    pub fn reason(&self) -> StopReason {
        self.reason
    }
    pub fn counts(&self) -> Counts {
        self.counts
    }
    pub fn latency(&self) -> Option<LatencyStats> {
        self.latency
    }
    pub fn jitter_samples(&self) -> u64 {
        self.jitter_samples
    }
    pub fn jitter_p95(&self) -> Option<Duration> {
        self.jitter_p95
    }
}

#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Event<'a> {
    Resolved(&'a Resolution),
    Probe(&'a Probe),
    Summary(&'a Summary),
}

#[derive(Clone, Debug)]
pub struct Session {
    pub(crate) resolution: Option<Resolution>,
    pub(crate) probes: Vec<Probe>,
    pub(crate) summary: Summary,
}
impl Session {
    pub fn resolution(&self) -> Option<&Resolution> {
        self.resolution.as_ref()
    }
    pub fn probes(&self) -> &[Probe] {
        &self.probes
    }
    pub fn summary(&self) -> &Summary {
        &self.summary
    }
}
