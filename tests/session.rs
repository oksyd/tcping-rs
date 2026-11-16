use std::{
    collections::VecDeque,
    convert::Infallible,
    future::pending,
    io,
    net::SocketAddr,
    ops::ControlFlow,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tcping::{
    AddressFamily, ConfigError, Engine, Event, FailureKind, Lookup, Outcome, ProbeBackend,
    ProbeMode, ProbeSession, ResolutionSource, Resolver, RunError, SessionConfig, SessionError,
    StopReason, Target,
};
use tokio::{
    sync::Notify,
    time::{Instant, sleep},
};
const ADDRESS: &str = "127.0.0.1:443";

#[derive(Default)]
struct Activity {
    calls: AtomicUsize,
    dropped: AtomicUsize,
    started: Notify,
    connections: Mutex<Vec<(SocketAddr, Instant)>>,
}
struct Guard(Arc<Activity>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
impl Activity {
    fn enter(self: &Arc<Self>) -> Guard {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        Guard(self.clone())
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
    fn dropped(&self) -> usize {
        self.dropped.load(Ordering::SeqCst)
    }
}
struct FakeResolver {
    addresses: Vec<SocketAddr>,
    delay: Option<Duration>,
    activity: Arc<Activity>,
}
impl Default for FakeResolver {
    fn default() -> Self {
        Self {
            addresses: vec![ADDRESS.parse().unwrap()],
            delay: Some(Duration::ZERO),
            activity: Arc::default(),
        }
    }
}
impl Resolver for FakeResolver {
    async fn resolve(&self, _: &Target, _: AddressFamily) -> io::Result<Lookup> {
        let _guard = self.activity.enter();
        wait(self.delay).await;
        Ok(Lookup {
            addresses: self.addresses.clone(),
            source: ResolutionSource::Dns("1.1.1.1".parse().unwrap()),
        })
    }
}
struct Step {
    delay: Option<Duration>,
    error: Option<io::ErrorKind>,
}
impl Step {
    fn open(ms: u64) -> Self {
        Self {
            delay: Some(Duration::from_millis(ms)),
            error: None,
        }
    }
    fn refused(ms: u64) -> Self {
        Self {
            error: Some(io::ErrorKind::ConnectionRefused),
            ..Self::open(ms)
        }
    }
    fn stalled() -> Self {
        Self {
            delay: None,
            error: None,
        }
    }
}
struct FakeBackend {
    steps: Mutex<VecDeque<Step>>,
    activity: Arc<Activity>,
}
impl FakeBackend {
    fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            steps: Mutex::new(steps.into_iter().collect()),
            activity: Arc::default(),
        }
    }
}
impl ProbeBackend for FakeBackend {
    fn mode(&self) -> ProbeMode {
        ProbeMode::Connect
    }
    fn prepare(&self, address: SocketAddr) -> io::Result<impl ProbeSession> {
        Ok(FakeProbe {
            backend: self,
            address,
        })
    }
}
struct FakeProbe<'a> {
    backend: &'a FakeBackend,
    address: SocketAddr,
}
impl ProbeSession for FakeProbe<'_> {
    async fn probe(&mut self) -> io::Result<Duration> {
        let address = self.address;
        let started = Instant::now();
        let _guard = self.backend.activity.enter();
        self.backend
            .activity
            .connections
            .lock()
            .unwrap()
            .push((address, Instant::now()));
        let step = self
            .backend
            .steps
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected extra connection");
        wait(step.delay).await;
        match step.error {
            Some(error) => Err(error.into()),
            None => Ok(started.elapsed()),
        }
    }
}
async fn wait(delay: Option<Duration>) {
    match delay {
        Some(delay) if delay.is_zero() => {}
        Some(delay) => sleep(delay).await,
        None => pending().await,
    }
}
fn config(count: usize) -> SessionConfig {
    SessionConfig::new("probe.test:443".parse().unwrap())
        .with_count(count)
        .unwrap()
        .with_interval(Duration::from_millis(100))
        .unwrap()
        .with_probe_timeout(Duration::from_millis(200))
        .unwrap()
        .with_resolve_timeout(Duration::from_millis(300))
        .unwrap()
}
fn keep_going(_: Event<'_>) -> Result<ControlFlow<()>, Infallible> {
    Ok(ControlFlow::Continue(()))
}

#[tokio::test(start_paused = true)]
async fn separates_outcomes_and_only_successes_contribute_to_latency_and_jitter() {
    let engine = Engine::new(
        FakeResolver::default(),
        FakeBackend::new([
            Step::open(10),
            Step::refused(1),
            Step::stalled(),
            Step::open(30),
        ]),
    );
    let session = engine.collect(&config(4).jitter(true)).await.unwrap();
    let probes = session.probes();
    assert_eq!(
        probes
            .iter()
            .map(|p| p.outcome().code())
            .collect::<Vec<_>>(),
        ["open", "refused", "timeout", "open"]
    );
    assert!(matches!(probes[1].outcome(), Outcome::Failed(f) if f.kind() == FailureKind::Refused));
    assert_eq!(probes[1].rtt(), None);
    assert_eq!(probes[2].rtt(), None);
    assert_eq!(probes[2].elapsed(), Duration::from_millis(200));
    assert_eq!(probes[3].jitter(), Some(Duration::from_millis(20)));
    let summary = session.summary();
    assert_eq!(summary.counts().attempted(), 4);
    assert_eq!(summary.counts().open(), 2);
    assert_eq!(summary.counts().failed(), 1);
    assert_eq!(summary.counts().timed_out(), 1);
    assert_eq!(summary.counts().failure_ratio(), Some(0.5));
    assert_eq!(
        summary.latency().unwrap().average(),
        Duration::from_millis(20)
    );
    assert_eq!(summary.jitter_samples(), 1);
    assert_eq!(summary.jitter_p95(), Some(Duration::from_millis(20)));
}
#[tokio::test(start_paused = true)]
async fn ready_cancellation_does_not_start_dns_or_connections() {
    let resolver = FakeResolver::default();
    let activity = resolver.activity.clone();
    let session = Engine::new(resolver, FakeBackend::new([]))
        .collect_until(&config(1), async {})
        .await
        .unwrap();
    assert_eq!(activity.calls(), 0);
    assert!(session.resolution().is_none());
    assert!(session.probes().is_empty());
    assert_eq!(session.summary().reason(), StopReason::Cancelled);
    assert_eq!(session.summary().counts().failure_ratio(), None);
}
#[tokio::test(start_paused = true)]
async fn cancellation_drops_dns_future() {
    let resolver = FakeResolver {
        delay: None,
        ..FakeResolver::default()
    };
    let activity = resolver.activity.clone();
    let session = Engine::new(resolver, FakeBackend::new([]))
        .collect_until(&config(1), sleep(Duration::from_millis(50)))
        .await
        .unwrap();
    assert_eq!((activity.calls(), activity.dropped()), (1, 1));
    assert_eq!(session.summary().elapsed(), Duration::from_millis(50));
    assert!(session.probes().is_empty());
}
#[tokio::test(start_paused = true)]
async fn dns_deadline_drops_future_and_returns_setup_error() {
    let resolver = FakeResolver {
        delay: None,
        ..FakeResolver::default()
    };
    let activity = resolver.activity.clone();
    let result = Engine::new(resolver, FakeBackend::new([]))
        .collect(&config(1))
        .await;
    assert!(
        matches!(result, Err(SessionError::ResolveTimeout(duration)) if duration == Duration::from_millis(300))
    );
    assert_eq!((activity.calls(), activity.dropped()), (1, 1));
}
#[tokio::test(start_paused = true)]
async fn cancellation_drops_connection_and_does_not_count_as_target_failure() {
    let backend = FakeBackend::new([Step::stalled()]);
    let activity = backend.activity.clone();
    let session = Engine::new(FakeResolver::default(), backend)
        .collect_until(&config(2), sleep(Duration::from_millis(50)))
        .await
        .unwrap();
    assert_eq!((activity.calls(), activity.dropped()), (1, 1));
    assert_eq!(session.probes()[0].outcome(), &Outcome::Cancelled);
    assert_eq!(session.probes()[0].rtt(), None);
    assert_eq!(session.summary().counts().cancelled(), 1);
    assert_eq!(session.summary().counts().completed(), 0);
    assert_eq!(session.summary().counts().failure_ratio(), None);
}
#[tokio::test(start_paused = true)]
async fn cancellation_during_interval_adds_no_probe() {
    let engine = Engine::new(FakeResolver::default(), FakeBackend::new([Step::open(10)]));
    let session = engine
        .collect_until(&config(3), sleep(Duration::from_millis(50)))
        .await
        .unwrap();
    assert_eq!(session.probes().len(), 1);
    assert_eq!(session.summary().reason(), StopReason::Cancelled);
    assert_eq!(session.summary().counts().cancelled(), 0);
}
#[tokio::test(start_paused = true)]
async fn deadline_wins_over_simultaneous_connection_success() {
    let engine = Engine::new(FakeResolver::default(), FakeBackend::new([Step::open(200)]));
    let session = engine.collect(&config(1)).await.unwrap();
    assert_eq!(session.probes()[0].outcome(), &Outcome::TimedOut);
}
#[tokio::test(start_paused = true)]
async fn cancellation_wins_over_simultaneous_deadline() {
    let engine = Engine::new(FakeResolver::default(), FakeBackend::new([Step::stalled()]));
    let session = engine
        .collect_until(&config(1), sleep(Duration::from_millis(200)))
        .await
        .unwrap();
    assert_eq!(session.probes()[0].outcome(), &Outcome::Cancelled);
}
#[tokio::test(start_paused = true)]
async fn scheduler_delay_is_reported_instead_of_clamped_to_deadline() {
    let backend = FakeBackend::new([Step::stalled()]);
    let activity = backend.activity.clone();
    let engine = Engine::new(FakeResolver::default(), backend);
    let task = tokio::spawn(async move { engine.collect(&config(1)).await.unwrap() });
    activity.started.notified().await;
    tokio::time::advance(Duration::from_millis(215)).await;
    let session = task.await.unwrap();
    let probe = &session.probes()[0];
    assert_eq!(probe.outcome(), &Outcome::TimedOut);
    assert_eq!(probe.timeout(), Duration::from_millis(200));
    assert!(probe.elapsed() >= Duration::from_millis(215));
    assert_eq!(activity.dropped(), 1);
}
#[tokio::test(start_paused = true)]
async fn probe_schedule_uses_start_intervals_without_catch_up_bursts() {
    let backend = FakeBackend::new([Step::stalled(), Step::open(10), Step::open(10)]);
    let activity = backend.activity.clone();
    Engine::new(FakeResolver::default(), backend)
        .collect(&config(3))
        .await
        .unwrap();
    let starts = activity.connections.lock().unwrap();
    assert_eq!(starts[1].1 - starts[0].1, Duration::from_millis(200));
    assert_eq!(starts[2].1 - starts[1].1, Duration::from_millis(100));
}
#[tokio::test(start_paused = true)]
async fn first_success_stops_after_prior_failure() {
    let engine = Engine::new(
        FakeResolver::default(),
        FakeBackend::new([Step::refused(1), Step::open(10)]),
    );
    let session = engine
        .collect(&config(5).exit_on_success(true))
        .await
        .unwrap();
    assert_eq!(session.probes().len(), 2);
    assert_eq!(session.summary().reason(), StopReason::FirstSuccess);
}
#[tokio::test(start_paused = true)]
async fn filters_and_deduplicates_addresses_then_keeps_one_for_the_session() {
    let resolver = FakeResolver {
        addresses: ["[::1]:443", ADDRESS, ADDRESS, "127.0.0.2:443"]
            .map(|value| value.parse().unwrap())
            .to_vec(),
        ..FakeResolver::default()
    };
    let backend = FakeBackend::new([Step::refused(1), Step::open(1)]);
    let activity = backend.activity.clone();
    let session = Engine::new(resolver, backend)
        .collect(&config(2).with_family(AddressFamily::Ipv4))
        .await
        .unwrap();
    let resolution = session.resolution().unwrap();
    assert_eq!(resolution.candidates().len(), 2);
    assert_eq!(
        resolution.source().dns_server().unwrap().to_string(),
        "1.1.1.1"
    );
    assert_eq!(resolution.selected(), ADDRESS.parse().unwrap());
    assert!(
        activity
            .connections
            .lock()
            .unwrap()
            .iter()
            .all(|(address, _)| *address == resolution.selected())
    );
}
#[tokio::test(start_paused = true)]
async fn literal_address_bypasses_resolver_and_honors_family() {
    let resolver = FakeResolver::default();
    let activity = resolver.activity.clone();
    let engine = Engine::new(resolver, FakeBackend::new([Step::open(0)]));
    let config = SessionConfig::new(ADDRESS.parse().unwrap())
        .with_count(1)
        .unwrap();
    engine.collect(&config).await.unwrap();
    assert_eq!(activity.calls(), 0);
    assert!(matches!(
        engine
            .collect(&config.with_family(AddressFamily::Ipv6))
            .await,
        Err(SessionError::NoAddress)
    ));
}
#[tokio::test(start_paused = true)]
async fn emits_one_summary_and_stops_when_handler_requests_it() {
    let engine = Engine::new(FakeResolver::default(), FakeBackend::new([Step::open(1)]));
    let mut events = Vec::new();
    let summary = engine
        .run(&config(3), |event| {
            Ok::<_, Infallible>(match event {
                Event::Resolved(_) => {
                    events.push("resolved");
                    ControlFlow::Continue(())
                }
                Event::Probe(_) => {
                    events.push("probe");
                    ControlFlow::Break(())
                }
                Event::Summary(_) => {
                    events.push("summary");
                    ControlFlow::Continue(())
                }
                _ => unreachable!(),
            })
        })
        .await
        .unwrap();
    assert_eq!(events, ["resolved", "probe", "summary"]);
    assert_eq!(summary.reason(), StopReason::HandlerStopped);
}
#[tokio::test(start_paused = true)]
async fn output_error_propagates_without_further_events() {
    let engine = Engine::new(FakeResolver::default(), FakeBackend::new([]));
    let mut events = 0;
    let result = engine
        .run(&config(3), |_| {
            events += 1;
            Err::<ControlFlow<()>, _>(io::Error::from(io::ErrorKind::BrokenPipe))
        })
        .await;
    assert!(
        matches!(result, Err(RunError::Handler(error)) if error.kind() == io::ErrorKind::BrokenPipe)
    );
    assert_eq!(events, 1);
}
#[tokio::test(start_paused = true)]
async fn terminal_output_error_is_not_discarded() {
    let engine = Engine::new(FakeResolver::default(), FakeBackend::new([Step::open(1)]));
    let result = engine
        .run(&config(1), |event| {
            if matches!(event, Event::Summary(_)) {
                Err("summary write failed")
            } else {
                Ok(ControlFlow::Continue(()))
            }
        })
        .await;
    assert!(matches!(
        result,
        Err(RunError::Handler("summary write failed"))
    ));
}
#[tokio::test(start_paused = true)]
async fn continuous_sessions_require_streaming() {
    let engine = Engine::new(FakeResolver::default(), FakeBackend::new([Step::open(1)]));
    let config = config(1).continuous();
    assert!(matches!(
        engine.collect(&config).await,
        Err(SessionError::Config(ConfigError::ContinuousCollection))
    ));
    let summary = engine
        .run_until(&config, sleep(Duration::from_millis(50)), keep_going)
        .await
        .unwrap();
    assert_eq!(summary.counts().open(), 1);
    assert_eq!(summary.reason(), StopReason::Cancelled);
}
#[tokio::test]
async fn real_tcp_connection_and_refusal() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = SessionConfig::new(address.to_string().parse().unwrap())
        .with_count(1)
        .unwrap();
    let engine = Engine::default();
    let session = engine.collect(&config).await.unwrap();
    assert!(session.probes()[0].outcome().is_open());
    drop(listener);
    let session = engine.collect(&config).await.unwrap();
    assert!(
        matches!(session.probes()[0].outcome(), Outcome::Failed(f) if f.kind() == FailureKind::Refused)
    );
}
#[cfg(feature = "report")]
#[tokio::test(start_paused = true)]
async fn wire_records_keep_failures_separate_from_rtt_and_use_one_schema() {
    use tcping::report::Record;
    let engine = Engine::new(
        FakeResolver::default(),
        FakeBackend::new([Step::refused(10)]),
    );
    let mut records = Vec::new();
    engine
        .run(&config(1), |event| {
            records.push(serde_json::to_value(Record::from_event(event, true).unwrap()).unwrap());
            keep_going(event)
        })
        .await
        .unwrap();
    assert_eq!(records.len(), 3);
    for record in &records {
        assert_eq!(record["schema"], "tcping.v3");
        assert!(record["timestamp"]["utc"].is_string());
        assert!(record["timestamp"]["unix_ms"].is_number());
    }
    assert_eq!(records[0]["dns_server"], "1.1.1.1");
    assert_eq!(records[0]["source"], "dns");
    assert_eq!(records[1]["status"], "refused");
    assert_eq!(records[1]["elapsed_ms"], 10.0);
    assert!(records[1]["rtt_ms"].is_null());
    assert!(records[2]["rtt"].is_null());
    assert_eq!(records[2]["counts"]["failed"], 1);
}

struct MeasuredBackend;
struct MeasuredProbe;
impl ProbeBackend for MeasuredBackend {
    fn mode(&self) -> ProbeMode {
        ProbeMode::Syn
    }
    fn prepare(&self, _: SocketAddr) -> io::Result<impl ProbeSession> {
        Ok(MeasuredProbe)
    }
}
impl ProbeSession for MeasuredProbe {
    async fn probe(&mut self) -> io::Result<Duration> {
        sleep(Duration::from_millis(40)).await;
        Ok(Duration::from_millis(5))
    }
}

#[tokio::test(start_paused = true)]
async fn measured_rtt_excludes_cleanup_and_mode_follows_every_event() {
    let session = Engine::new(FakeResolver::default(), MeasuredBackend)
        .collect(&config(1))
        .await
        .unwrap();
    let probe = &session.probes()[0];
    assert_eq!(probe.elapsed(), Duration::from_millis(40));
    assert_eq!(probe.rtt(), Some(Duration::from_millis(5)));
    assert_eq!(
        session.summary().latency().unwrap().average(),
        Duration::from_millis(5)
    );
    assert_eq!(probe.mode(), ProbeMode::Syn);
    assert_eq!(session.resolution().unwrap().mode(), ProbeMode::Syn);
    assert_eq!(session.summary().mode(), ProbeMode::Syn);
    #[cfg(feature = "report")]
    for event in [
        Event::Resolved(session.resolution().unwrap()),
        Event::Probe(probe),
        Event::Summary(session.summary()),
    ] {
        let record = tcping::report::Record::from_event(event, false).unwrap();
        assert_eq!(record.mode, "syn");
    }
}

struct DeniedBackend;
impl ProbeBackend for DeniedBackend {
    fn mode(&self) -> ProbeMode {
        ProbeMode::Syn
    }
    fn prepare(&self, _: SocketAddr) -> io::Result<impl ProbeSession> {
        Err::<MeasuredProbe, _>(io::ErrorKind::PermissionDenied.into())
    }
}
#[tokio::test(start_paused = true)]
async fn setup_failure_stops_even_continuous_sessions_without_emitting_probe_results() {
    let mut events = 0;
    let error = Engine::new(FakeResolver::default(), DeniedBackend)
        .run(&config(1).continuous(), |_| {
            events += 1;
            Ok::<_, Infallible>(ControlFlow::Continue(()))
        })
        .await
        .unwrap_err();
    assert!(
        matches!(error, RunError::Session(SessionError::ProbeSetup { mode: ProbeMode::Syn, source }) if source.kind() == io::ErrorKind::PermissionDenied)
    );
    assert_eq!(events, 0);
}
