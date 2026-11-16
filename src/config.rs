use crate::{ConfigError, Target};
use std::{net::SocketAddr, num::NonZeroUsize, time::Duration};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AddressFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}
impl AddressFamily {
    pub(crate) fn accepts(self, address: &SocketAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Ipv4 => address.is_ipv4(),
            Self::Ipv6 => address.is_ipv6(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeCount {
    Finite(NonZeroUsize),
    Continuous,
}
impl ProbeCount {
    pub fn finite(count: usize) -> Result<Self, ConfigError> {
        NonZeroUsize::new(count)
            .map(Self::Finite)
            .ok_or(ConfigError::ZeroCount)
    }
}

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub(crate) target: Target,
    pub(crate) count: ProbeCount,
    pub(crate) interval: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) resolve_timeout: Duration,
    pub(crate) family: AddressFamily,
    pub(crate) exit_on_success: bool,
    pub(crate) jitter: bool,
}

impl SessionConfig {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            count: ProbeCount::Finite(NonZeroUsize::MIN.saturating_add(3)),
            interval: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(2),
            resolve_timeout: Duration::from_secs(5),
            family: AddressFamily::Any,
            exit_on_success: false,
            jitter: false,
        }
    }
    pub fn with_count(mut self, count: usize) -> Result<Self, ConfigError> {
        self.count = ProbeCount::finite(count)?;
        Ok(self)
    }
    pub fn continuous(mut self) -> Self {
        self.count = ProbeCount::Continuous;
        self
    }
    pub fn with_interval(mut self, interval: Duration) -> Result<Self, ConfigError> {
        validate_duration(interval, "probe interval")?;
        self.interval = interval;
        Ok(self)
    }
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Result<Self, ConfigError> {
        validate_duration(timeout, "connection timeout")?;
        self.connect_timeout = timeout;
        Ok(self)
    }
    pub fn with_resolve_timeout(mut self, timeout: Duration) -> Result<Self, ConfigError> {
        validate_duration(timeout, "DNS timeout")?;
        self.resolve_timeout = timeout;
        Ok(self)
    }
    pub fn with_family(mut self, family: AddressFamily) -> Self {
        self.family = family;
        self
    }
    pub fn exit_on_success(mut self, enabled: bool) -> Self {
        self.exit_on_success = enabled;
        self
    }
    pub fn jitter(mut self, enabled: bool) -> Self {
        self.jitter = enabled;
        self
    }
    pub fn target(&self) -> &Target {
        &self.target
    }
    pub fn count(&self) -> ProbeCount {
        self.count
    }
    pub fn interval(&self) -> Duration {
        self.interval
    }
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }
    pub fn resolve_timeout(&self) -> Duration {
        self.resolve_timeout
    }
    pub fn family(&self) -> AddressFamily {
        self.family
    }
}

fn validate_duration(duration: Duration, name: &'static str) -> Result<(), ConfigError> {
    if duration.is_zero() {
        return Err(ConfigError::ZeroDuration(name));
    }
    if std::time::Instant::now().checked_add(duration).is_none() {
        return Err(ConfigError::DurationOverflow);
    }
    Ok(())
}
