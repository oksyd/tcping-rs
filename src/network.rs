mod dns;
pub use dns::DnsResolver;

use crate::{ResolutionSource, Target};
use std::{future::Future, io, net::SocketAddr};
use tokio::net::TcpStream;

/// Addresses and their observed resolution source, returned by a network adapter.
#[derive(Clone, Debug)]
pub struct Lookup {
    pub addresses: Vec<SocketAddr>,
    pub source: ResolutionSource,
}

/// Implementations must yield while waiting and support dropping pending lookups.
pub trait Resolver: Send + Sync {
    fn resolve(&self, target: &Target) -> impl Future<Output = io::Result<Lookup>> + Send;
}

/// A connection future owns its socket; dropping the future cancels the attempt.
pub trait Connector: Send + Sync {
    fn connect(&self, address: SocketAddr) -> impl Future<Output = io::Result<()>> + Send;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TcpConnector;
impl Connector for TcpConnector {
    async fn connect(&self, address: SocketAddr) -> io::Result<()> {
        TcpStream::connect(address).await.map(drop)
    }
}
