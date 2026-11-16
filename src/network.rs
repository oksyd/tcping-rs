mod dns;
#[cfg(target_os = "linux")]
mod syn;
pub use dns::DnsResolver;

use crate::{AddressFamily, ConfigError, ResolutionSource, Target};
use std::{fmt, future::Future, io, net::SocketAddr, str::FromStr, time::Duration};
use tokio::net::TcpStream;
use tokio::time::Instant;

/// Addresses and their observed resolution source, returned by a network adapter.
#[derive(Clone, Debug)]
pub struct Lookup {
    pub addresses: Vec<SocketAddr>,
    pub source: ResolutionSource,
}

/// Resolves the requested address family. Implementations must yield while waiting
/// and support dropping pending lookups.
pub trait Resolver: Send + Sync {
    fn resolve(
        &self,
        target: &Target,
        family: AddressFamily,
    ) -> impl Future<Output = io::Result<Lookup>> + Send;
}

/// The protocol operation whose response is measured.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProbeMode {
    #[default]
    Connect,
    Syn,
}
impl ProbeMode {
    pub fn code(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Syn => "syn",
        }
    }
}
impl fmt::Display for ProbeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl FromStr for ProbeMode {
    type Err = ConfigError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "connect" => Ok(Self::Connect),
            "syn" => Ok(Self::Syn),
            _ => Err(ConfigError::ProbeMode),
        }
    }
}

/// Prepares resources for one resolved endpoint. Setup errors stop the session.
/// Preparation must not block on network I/O. Each run owns its prepared session.
pub trait ProbeBackend: Send + Sync {
    fn mode(&self) -> ProbeMode;
    fn prepare(&self, address: SocketAddr) -> io::Result<impl ProbeSession>;
}

/// A sequence of probes to one endpoint. Dropping a pending probe must stop its I/O.
/// Successful probes return the measured RTT, excluding session setup and cleanup work.
pub trait ProbeSession: Send {
    fn probe(&mut self) -> impl Future<Output = io::Result<Duration>> + Send;
}

impl ProbeBackend for ProbeMode {
    fn mode(&self) -> ProbeMode {
        *self
    }
    fn prepare(&self, address: SocketAddr) -> io::Result<impl ProbeSession> {
        match self {
            Self::Connect => Ok(PreparedProbe::Connect(TcpProbe(address))),
            #[cfg(target_os = "linux")]
            Self::Syn => syn::SynProbe::new(address).map(PreparedProbe::Syn),
            #[cfg(not(target_os = "linux"))]
            Self::Syn => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SYN mode is only supported on Linux",
            )),
        }
    }
}
enum PreparedProbe {
    Connect(TcpProbe),
    #[cfg(target_os = "linux")]
    Syn(syn::SynProbe),
}
impl ProbeSession for PreparedProbe {
    async fn probe(&mut self) -> io::Result<Duration> {
        match self {
            Self::Connect(probe) => probe.probe().await,
            #[cfg(target_os = "linux")]
            Self::Syn(probe) => probe.probe().await,
        }
    }
}

struct TcpProbe(SocketAddr);
impl ProbeSession for TcpProbe {
    async fn probe(&mut self) -> io::Result<Duration> {
        let started = Instant::now();
        let stream = TcpStream::connect(self.0).await?;
        let rtt = started.elapsed();
        drop(stream);
        Ok(rtt)
    }
}
