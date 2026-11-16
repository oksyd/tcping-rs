use super::{Lookup, Resolver};
use crate::{ResolutionSource, Target};
use futures_util::{StreamExt, stream};
use hickory_resolver::{
    Hosts, TokioResolver,
    config::{LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
    proto::{
        op::Query,
        rr::{IntoName, Name, RecordType},
    },
    system_conf::read_system_conf,
};
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    time::Instant,
};
use tokio::sync::{Mutex, OnceCell};

const CACHE_CAPACITY: usize = 64;

/// Resolves against system DNS servers and retains the successful responder's address.
/// Hosts and TTL-valid local cache entries are explicitly distinguished from DNS replies.
#[derive(Debug, Default)]
pub struct DnsResolver {
    hosts: OnceCell<Hosts>,
    configuration: OnceCell<Configuration>,
    cache: Mutex<VecDeque<CachedLookup>>,
}
#[derive(Debug)]
struct Configuration {
    config: ResolverConfig,
    options: ResolverOpts,
}
#[derive(Debug)]
struct CachedLookup {
    name: Name,
    ips: Vec<IpAddr>,
    valid_until: Instant,
}
struct Answer {
    ips: Vec<IpAddr>,
    server: IpAddr,
    valid_until: Instant,
}

impl Resolver for DnsResolver {
    async fn resolve(&self, target: &Target) -> io::Result<Lookup> {
        if let Some(address) = target.literal_address() {
            return Ok(Lookup {
                addresses: vec![address],
                source: ResolutionSource::Literal,
            });
        }
        let name = target.host().into_name().map_err(io::Error::other)?;
        let hosts = self
            .hosts
            .get_or_try_init(|| async {
                match Hosts::from_system() {
                    Ok(hosts) => Ok(hosts),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Hosts::default()),
                    Err(error) => Err(error),
                }
            })
            .await?;
        let ips: Vec<_> = [RecordType::A, RecordType::AAAA]
            .into_iter()
            .filter_map(|kind| hosts.lookup_static_host(&Query::query(name.clone(), kind)))
            .flat_map(|lookup| {
                lookup
                    .answers()
                    .iter()
                    .filter_map(|record| record.data.ip_addr())
                    .collect::<Vec<_>>()
            })
            .collect();
        if !ips.is_empty() {
            return Ok(result(ips, target.port(), ResolutionSource::Hosts));
        }

        if let Some(ips) = self.cached(&name).await {
            return Ok(result(ips, target.port(), ResolutionSource::Cache));
        }
        let configuration = self
            .configuration
            .get_or_try_init(|| async {
                let (config, options) = read_system_conf().map_err(io::Error::other)?;
                Ok::<_, io::Error>(Configuration { config, options })
            })
            .await?;
        let answer = configuration.lookup(&name).await?;
        let lookup = result(
            answer.ips.clone(),
            target.port(),
            ResolutionSource::Dns(answer.server),
        );
        if answer.valid_until > Instant::now() {
            let mut cache = self.cache.lock().await;
            cache.retain(|entry| entry.valid_until > Instant::now() && entry.name != name);
            if cache.len() >= CACHE_CAPACITY {
                cache.pop_back();
            }
            cache.push_front(CachedLookup {
                name,
                ips: answer.ips,
                valid_until: answer.valid_until,
            });
        }
        Ok(lookup)
    }
}

impl DnsResolver {
    async fn cached(&self, name: &Name) -> Option<Vec<IpAddr>> {
        let mut cache = self.cache.lock().await;
        cache.retain(|entry| entry.valid_until > Instant::now());
        let index = cache.iter().position(|entry| &entry.name == name)?;
        let entry = cache.remove(index)?;
        let ips = entry.ips.clone();
        cache.push_front(entry);
        Some(ips)
    }
}

impl Configuration {
    async fn lookup(&self, name: &Name) -> io::Result<Answer> {
        // Each attempt owns one upstream, so replies and CNAME follow-ups retain an
        // unambiguous source. Select the first successful complete address lookup.
        let mut lookups = stream::iter(self.config.name_servers.clone())
            .map(|server| async move { self.lookup_at(name, &server).await })
            .buffer_unordered(self.options.num_concurrent_reqs.max(1));
        let mut error = io::Error::new(io::ErrorKind::NotFound, "no DNS servers configured");
        while let Some(result) = lookups.next().await {
            match result {
                Ok(answer) => return Ok(answer),
                Err(failure) => error = failure,
            }
        }
        Err(error)
    }

    async fn lookup_at(&self, name: &Name, server: &NameServerConfig) -> io::Result<Answer> {
        let mut config = self.config.clone();
        config.name_servers = vec![server.clone()];
        let mut options = self.options.clone();
        options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        options.use_hosts_file = ResolveHosts::Never;
        // Cache final address sets above, together with their explicit local origin.
        options.cache_size = 0;
        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(options)
            .build()
            .map_err(io::Error::other)?;
        let lookup = resolver
            .lookup_ip(name.clone())
            .await
            .map_err(io::Error::other)?;
        let ips: Vec<_> = lookup.iter().collect();
        if ips.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "DNS response contains no addresses",
            ));
        }
        Ok(Answer {
            ips,
            server: server.ip,
            valid_until: lookup.valid_until(),
        })
    }
}

fn result(ips: Vec<IpAddr>, port: u16, source: ResolutionSource) -> Lookup {
    Lookup {
        addresses: ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::{
        op::{Message, OpCode, ResponseCode},
        rr::{
            RData, Record,
            rdata::{A, CNAME},
        },
    };
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::{net::UdpSocket, task::JoinHandle};

    #[derive(Clone, Copy)]
    enum Reply {
        Address(u32),
        Alias,
        Refused,
        Silent,
    }
    struct Server {
        config: NameServerConfig,
        requests: Arc<AtomicUsize>,
        task: JoinHandle<()>,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    impl Server {
        async fn start(ip: Ipv4Addr, reply: Reply, delay: Duration) -> Self {
            let socket = UdpSocket::bind((ip, 0)).await.unwrap();
            let mut config = NameServerConfig::udp(ip.into());
            config.connections[0].port = socket.local_addr().unwrap().port();
            let requests = Arc::new(AtomicUsize::new(0));
            let counter = requests.clone();
            let task = tokio::spawn(async move {
                let mut buffer = [0; 4096];
                loop {
                    let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                    counter.fetch_add(1, Ordering::SeqCst);
                    let request = Message::from_vec(&buffer[..length]).unwrap();
                    if matches!(reply, Reply::Silent) {
                        continue;
                    }
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let query = request.queries[0].clone();
                    let mut response = Message::response(request.metadata.id, OpCode::Query);
                    response.metadata.recursion_available = true;
                    response.add_query(query.clone());
                    match reply {
                        Reply::Refused => response.metadata.response_code = ResponseCode::ServFail,
                        Reply::Alias if query.name().to_ascii() == "alias.test." => {
                            response.add_answer(Record::from_rdata(
                                query.name().clone(),
                                30,
                                RData::CNAME(CNAME("answer.test.".parse().unwrap())),
                            ));
                        }
                        Reply::Address(_) | Reply::Alias if query.query_type() == RecordType::A => {
                            let ttl = match reply {
                                Reply::Address(ttl) => ttl,
                                _ => 30,
                            };
                            response.add_answer(Record::from_rdata(
                                query.name().clone(),
                                ttl,
                                RData::A(A::new(192, 0, 2, 42)),
                            ));
                        }
                        _ => {}
                    }
                    socket
                        .send_to(&response.to_vec().unwrap(), peer)
                        .await
                        .unwrap();
                }
            });
            Self {
                config,
                requests,
                task,
            }
        }
        fn requests(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }
    }
    fn resolver(servers: &[&Server], hosts: Hosts) -> DnsResolver {
        let mut options = ResolverOpts::default();
        options.timeout = Duration::from_millis(100);
        options.attempts = 1;
        let configuration = Configuration {
            config: ResolverConfig::from_name_servers(
                servers.iter().map(|server| server.config.clone()).collect(),
            ),
            options,
        };
        DnsResolver {
            configuration: OnceCell::new_with(Some(configuration)),
            hosts: OnceCell::new_with(Some(hosts)),
            ..DnsResolver::default()
        }
    }
    fn target() -> Target {
        "answer.test.:443".parse().unwrap()
    }

    #[tokio::test]
    async fn caches_positive_answers_without_claiming_a_fresh_dns_response() {
        let server = Server::start(Ipv4Addr::LOCALHOST, Reply::Address(30), Duration::ZERO).await;
        let resolver = resolver(&[&server], Hosts::default());
        let first = resolver.resolve(&target()).await.unwrap();
        assert_eq!(first.source, ResolutionSource::Dns(server.config.ip));
        assert_eq!(first.addresses[0], "192.0.2.42:443".parse().unwrap());
        let queries = server.requests();
        let cached = resolver
            .resolve(&"answer.test.:8443".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(cached.source, ResolutionSource::Cache);
        assert_eq!(cached.addresses[0].port(), 8443);
        assert_eq!(server.requests(), queries);
        assert!(queries >= 2);
    }

    #[tokio::test]
    async fn zero_ttl_and_expired_answers_are_queried_again() {
        let server = Server::start(Ipv4Addr::LOCALHOST, Reply::Address(0), Duration::ZERO).await;
        let resolver = resolver(&[&server], Hosts::default());
        for _ in 0..2 {
            assert!(matches!(
                resolver.resolve(&target()).await.unwrap().source,
                ResolutionSource::Dns(_)
            ));
        }
        assert!(server.requests() >= 4);
        assert!(resolver.cache.lock().await.is_empty());
        resolver.cache.lock().await.push_back(CachedLookup {
            name: target().host().into_name().unwrap(),
            ips: vec!["192.0.2.99".parse().unwrap()],
            valid_until: Instant::now() - Duration::from_secs(1),
        });
        let lookup = resolver.resolve(&target()).await.unwrap();
        assert_eq!(
            lookup.addresses[0].ip(),
            "192.0.2.42".parse::<IpAddr>().unwrap()
        );
        assert!(matches!(lookup.source, ResolutionSource::Dns(_)));
    }

    #[tokio::test]
    async fn hosts_and_literals_do_not_query_dns() {
        let mut hosts = Hosts::default();
        hosts
            .read_hosts_conf("192.0.2.9 local.test\n2001:db8::9 local.test\n".as_bytes())
            .unwrap();
        let resolver = resolver(&[], hosts);
        let lookup = resolver
            .resolve(&"local.test:443".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(lookup.source, ResolutionSource::Hosts);
        assert_eq!(lookup.addresses.len(), 2);
        let lookup = resolver
            .resolve(&"[::1]:443".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(lookup.source, ResolutionSource::Literal);
        assert_eq!(lookup.addresses, vec!["[::1]:443".parse().unwrap()]);
    }

    #[tokio::test]
    async fn cname_follow_up_keeps_the_actual_upstream() {
        let server = Server::start(Ipv4Addr::LOCALHOST, Reply::Alias, Duration::ZERO).await;
        let resolver = resolver(&[&server], Hosts::default());
        let lookup = resolver
            .resolve(&"alias.test.:443".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(lookup.source, ResolutionSource::Dns(server.config.ip));
        assert_eq!(lookup.addresses[0], "192.0.2.42:443".parse().unwrap());
        assert!(server.requests() >= 3);
    }

    #[tokio::test]
    async fn cancelled_lookup_does_not_populate_cache() {
        let server = Server::start(Ipv4Addr::LOCALHOST, Reply::Silent, Duration::ZERO).await;
        let resolver = resolver(&[&server], Hosts::default());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), resolver.resolve(&target()))
                .await
                .is_err()
        );
        assert!(server.requests() > 0);
        assert!(resolver.cache.lock().await.is_empty());
    }

    #[tokio::test]
    async fn failed_responder_does_not_hide_a_successful_backup() {
        let first = Server::start(Ipv4Addr::LOCALHOST, Reply::Refused, Duration::ZERO).await;
        let second = Server::start(Ipv4Addr::LOCALHOST, Reply::Address(30), Duration::ZERO).await;
        let mut resolver = resolver(&[&first, &second], Hosts::default());
        resolver
            .configuration
            .get_mut()
            .unwrap()
            .options
            .num_concurrent_reqs = 1;
        let lookup = resolver.resolve(&target()).await.unwrap();
        assert_eq!(lookup.addresses[0], "192.0.2.42:443".parse().unwrap());
        assert!(matches!(lookup.source, ResolutionSource::Dns(_)));
        assert!(first.requests() > 0 && second.requests() > 0);
    }

    #[tokio::test]
    async fn hostname_cache_is_bounded_and_evicted_entries_are_resolved_again() {
        let server = Server::start(Ipv4Addr::LOCALHOST, Reply::Address(30), Duration::ZERO).await;
        let resolver = resolver(&[&server], Hosts::default());
        for index in 0..=CACHE_CAPACITY {
            let target = format!("host{index}.test.:443").parse().unwrap();
            resolver.resolve(&target).await.unwrap();
        }
        assert_eq!(resolver.cache.lock().await.len(), CACHE_CAPACITY);
        let recent = format!("host{CACHE_CAPACITY}.test.:443").parse().unwrap();
        assert_eq!(
            resolver.resolve(&recent).await.unwrap().source,
            ResolutionSource::Cache
        );
        let queries = server.requests();
        assert!(matches!(
            resolver
                .resolve(&"host0.test.:443".parse().unwrap())
                .await
                .unwrap()
                .source,
            ResolutionSource::Dns(_)
        ));
        assert!(server.requests() > queries);
    }

    // Linux permits distinct loopback addresses without changing interface configuration.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn records_the_successful_responder_instead_of_the_first_configured_server() {
        for reply in [Reply::Refused, Reply::Silent, Reply::Address(30)] {
            let first = Server::start(
                Ipv4Addr::new(127, 0, 0, 2),
                reply,
                Duration::from_millis(50),
            )
            .await;
            let second =
                Server::start(Ipv4Addr::LOCALHOST, Reply::Address(30), Duration::ZERO).await;
            let resolver = resolver(&[&first, &second], Hosts::default());
            let lookup = resolver.resolve(&target()).await.unwrap();
            assert_eq!(lookup.source, ResolutionSource::Dns(second.config.ip));
            assert_ne!(lookup.source.dns_server(), Some(first.config.ip));
            assert!(second.requests() >= 2);
        }
    }
}
