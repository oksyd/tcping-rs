use crate::{
    ConfigError, Connector, DnsResolver, Event, Failure, Lookup, Outcome, Probe, ProbeCount,
    Resolution, ResolutionSource, Resolver, RunError, Session, SessionConfig, SessionError,
    StopReason, Summary, TcpConnector, stats::Statistics,
};
use std::{
    convert::Infallible,
    future::{Future, pending},
    io,
    ops::ControlFlow,
    time::SystemTime,
};
use tokio::time::{Instant, sleep_until};

#[derive(Debug)]
pub struct Engine<R = DnsResolver, C = TcpConnector> {
    resolver: R,
    connector: C,
}
impl Default for Engine {
    fn default() -> Self {
        Self::new(DnsResolver::default(), TcpConnector)
    }
}
impl<R, C> Engine<R, C> {
    pub fn new(resolver: R, connector: C) -> Self {
        Self {
            resolver,
            connector,
        }
    }
}

impl<R: Resolver, C: Connector> Engine<R, C> {
    /// Streams borrowed events. The handler may stop the session or return its own error.
    /// Handlers run inline and must return promptly. The caller provides a Tokio runtime
    /// with I/O and time enabled; the engine never creates a runtime.
    pub async fn run<H, E>(
        &self,
        config: &SessionConfig,
        handler: H,
    ) -> Result<Summary, RunError<E>>
    where
        H: FnMut(Event<'_>) -> Result<ControlFlow<()>, E>,
    {
        self.run_until(config, pending(), handler).await
    }

    /// Cancellation has priority over deadlines, which have priority over network results.
    /// A cancelled in-flight connection is recorded separately from failed attempts.
    pub async fn run_until<H, E, F>(
        &self,
        config: &SessionConfig,
        cancel: F,
        mut handler: H,
    ) -> Result<Summary, RunError<E>>
    where
        H: FnMut(Event<'_>) -> Result<ControlFlow<()>, E>,
        F: Future<Output = ()>,
    {
        let mut state = RunState::new(config);
        tokio::pin!(cancel);
        let resolve_started = Instant::now();
        let resolve_wall = SystemTime::now();
        let resolve_deadline = deadline(resolve_started, config.resolve_timeout)?;
        let resolve = async {
            match config.target.literal_address() {
                Some(address) => Ok(Lookup {
                    addresses: vec![address],
                    source: ResolutionSource::Literal,
                }),
                None => self.resolver.resolve(&config.target).await,
            }
        };
        let lookup = tokio::select! {
            biased;
            _ = &mut cancel => return state.finish(StopReason::Cancelled, &mut handler),
            _ = sleep_until(resolve_deadline) => return Err(SessionError::ResolveTimeout(config.resolve_timeout).into()),
            result = resolve => {
                if Instant::now() >= resolve_deadline {
                    return Err(SessionError::ResolveTimeout(config.resolve_timeout).into());
                }
                result.map_err(SessionError::Resolve)?
            }
        };
        let mut candidates = Vec::new();
        for address in lookup.addresses {
            if config.family.accepts(&address) && !candidates.contains(&address) {
                candidates.push(address);
            }
        }
        let selected = *candidates.first().ok_or(SessionError::NoAddress)?;
        let resolution = Resolution {
            target: config.target.clone(),
            candidates,
            source: lookup.source,
            selected,
            started_at: resolve_wall,
            elapsed: resolve_started.elapsed(),
        };
        state.resolution = Some(resolution);
        if let Some(resolution) = &state.resolution
            && handler(Event::Resolved(resolution))
                .map_err(RunError::Handler)?
                .is_break()
        {
            return state.finish(StopReason::HandlerStopped, &mut handler);
        }

        let mut next_start = Instant::now();
        loop {
            tokio::select! {
                biased;
                _ = &mut cancel => return state.finish(StopReason::Cancelled, &mut handler),
                _ = sleep_until(next_start) => {},
            }
            let started = Instant::now();
            let started_at = SystemTime::now();
            let connect_deadline = deadline(started, config.connect_timeout)?;
            let outcome = tokio::select! {
                biased;
                _ = &mut cancel => Outcome::Cancelled,
                _ = sleep_until(connect_deadline) => Outcome::TimedOut,
                result = self.connector.connect(selected) => {
                    if Instant::now() >= connect_deadline { Outcome::TimedOut }
                    else {
                        match result {
                            Ok(()) => Outcome::Open,
                            Err(error) if error.kind() == io::ErrorKind::TimedOut => Outcome::TimedOut,
                            Err(error) => Outcome::Failed(Failure::from_io(error)),
                        }
                    }
                }
            };
            let mut probe = Probe {
                sequence: state.stats.counts().attempted() + 1,
                address: selected,
                started_at,
                elapsed: started.elapsed(),
                timeout: config.connect_timeout,
                outcome,
                jitter: None,
            };
            probe.jitter = state.stats.observe(&probe);
            let stopped = handler(Event::Probe(&probe))
                .map_err(RunError::Handler)?
                .is_break();
            let reason = if matches!(probe.outcome(), Outcome::Cancelled) {
                Some(StopReason::Cancelled)
            } else if stopped {
                Some(StopReason::HandlerStopped)
            } else if config.exit_on_success && probe.outcome().is_open() {
                Some(StopReason::FirstSuccess)
            } else if matches!(config.count, ProbeCount::Finite(count) if state.stats.counts().attempted() >= count.get() as u64)
            {
                Some(StopReason::CountReached)
            } else {
                None
            };
            if let Some(reason) = reason {
                return state.finish(reason, &mut handler);
            }
            next_start = deadline(started, config.interval)?;
        }
    }

    /// Collects a finite session. Use streaming events for continuous sessions.
    pub async fn collect(&self, config: &SessionConfig) -> Result<Session, SessionError> {
        self.collect_until(config, pending()).await
    }

    pub async fn collect_until<F: Future<Output = ()>>(
        &self,
        config: &SessionConfig,
        cancel: F,
    ) -> Result<Session, SessionError> {
        if matches!(config.count, ProbeCount::Continuous) {
            return Err(ConfigError::ContinuousCollection.into());
        }
        let mut resolution = None;
        let mut probes = Vec::new();
        let result = self
            .run_until(config, cancel, |event| {
                match event {
                    Event::Resolved(value) => resolution = Some(value.clone()),
                    Event::Probe(value) => probes.push(value.clone()),
                    Event::Summary(_) => {}
                }
                Ok::<_, Infallible>(ControlFlow::Continue(()))
            })
            .await;
        let summary = match result {
            Ok(summary) => summary,
            Err(RunError::Session(error)) => return Err(error),
            Err(RunError::Handler(never)) => match never {},
        };
        Ok(Session {
            resolution,
            probes,
            summary,
        })
    }
}

fn deadline(start: Instant, duration: std::time::Duration) -> Result<Instant, SessionError> {
    start
        .checked_add(duration)
        .ok_or_else(|| ConfigError::DurationOverflow.into())
}

struct RunState<'a> {
    config: &'a SessionConfig,
    started: Instant,
    started_at: SystemTime,
    stats: Statistics,
    resolution: Option<Resolution>,
}
impl<'a> RunState<'a> {
    fn new(config: &'a SessionConfig) -> Self {
        Self {
            config,
            started: Instant::now(),
            started_at: SystemTime::now(),
            stats: Statistics::new(config.jitter),
            resolution: None,
        }
    }
    fn finish<H, E>(&self, reason: StopReason, handler: &mut H) -> Result<Summary, RunError<E>>
    where
        H: FnMut(Event<'_>) -> Result<ControlFlow<()>, E>,
    {
        let summary = Summary {
            target: self.config.target.clone(),
            address: self.resolution.as_ref().map(Resolution::selected),
            started_at: self.started_at,
            finished_at: SystemTime::now(),
            elapsed: self.started.elapsed(),
            resolution_elapsed: self.resolution.as_ref().map(Resolution::elapsed),
            reason,
            counts: self.stats.counts(),
            latency: self.stats.latency(),
            jitter_samples: self.stats.jitter_samples(),
            jitter_p95: self.stats.jitter_p95(),
        };
        let _ = handler(Event::Summary(&summary)).map_err(RunError::Handler)?;
        Ok(summary)
    }
}
