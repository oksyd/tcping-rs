//! Versioned wire records. Domain types never serialize themselves.
use crate::{Event, Outcome};
use serde::Serialize;
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const SCHEMA: &str = "tcping.v3";

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReportError {
    #[error("timestamp is outside the supported RFC 3339 range")]
    TimestampRange,
    #[error("cannot format timestamp: {0}")]
    TimestampFormat(#[from] time::error::Format),
}

#[derive(Clone, Debug, Serialize)]
pub struct Timestamp {
    pub unix_ms: i128,
    pub utc: String,
}
impl Timestamp {
    pub fn from_system_time(value: SystemTime) -> Result<Self, ReportError> {
        let nanos = match value.duration_since(UNIX_EPOCH) {
            Ok(duration) => {
                i128::try_from(duration.as_nanos()).map_err(|_| ReportError::TimestampRange)?
            }
            Err(error) => -i128::try_from(error.duration().as_nanos())
                .map_err(|_| ReportError::TimestampRange)?,
        };
        let datetime = OffsetDateTime::from_unix_timestamp_nanos(nanos)
            .map_err(|_| ReportError::TimestampRange)?;
        Ok(Self {
            unix_ms: nanos.div_euclid(1_000_000),
            utc: datetime.format(&Rfc3339)?,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct Record {
    pub schema: &'static str,
    pub mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,
    #[serde(flatten)]
    pub data: RecordData,
}

#[derive(Debug, Serialize)]
#[serde(tag = "record", rename_all = "snake_case")]
pub enum RecordData {
    Resolved(ResolvedRecord),
    Probe(ProbeRecord),
    Summary(SummaryRecord),
}

#[derive(Debug, Serialize)]
pub struct ResolvedRecord {
    pub target: String,
    pub address: SocketAddr,
    pub candidates: Vec<SocketAddr>,
    pub source: &'static str,
    pub dns_server: Option<IpAddr>,
    pub elapsed_ms: f64,
}
#[derive(Debug, Serialize)]
pub struct FailureRecord {
    pub kind: &'static str,
    pub os_code: Option<i32>,
    pub message: String,
}
#[derive(Debug, Serialize)]
pub struct ProbeRecord {
    pub sequence: u64,
    pub address: SocketAddr,
    pub status: &'static str,
    pub elapsed_ms: f64,
    pub timeout_ms: f64,
    pub rtt_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub failure: Option<FailureRecord>,
}
#[derive(Debug, Serialize)]
pub struct CountsRecord {
    pub attempted: u64,
    pub open: u64,
    pub failed: u64,
    pub timed_out: u64,
    pub cancelled: u64,
}
#[derive(Debug, Serialize)]
pub struct LatencyRecord {
    pub min_ms: f64,
    pub average_ms: f64,
    pub max_ms: f64,
}
#[derive(Debug, Serialize)]
pub struct SummaryRecord {
    pub target: String,
    pub address: Option<SocketAddr>,
    pub stop_reason: &'static str,
    pub elapsed_ms: f64,
    pub resolution_ms: Option<f64>,
    pub counts: CountsRecord,
    pub failure_rate_pct: Option<f64>,
    pub rtt: Option<LatencyRecord>,
    pub jitter_samples: u64,
    pub jitter_p95_ms: Option<f64>,
}

pub fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

impl Record {
    pub fn from_event(event: Event<'_>, timestamps: bool) -> Result<Self, ReportError> {
        let mode = match event {
            Event::Resolved(value) => value.mode(),
            Event::Probe(value) => value.mode(),
            Event::Summary(value) => value.mode(),
        };
        let (at, data) = match event {
            Event::Resolved(value) => (
                value.started_at(),
                RecordData::Resolved(ResolvedRecord {
                    target: value.target().to_string(),
                    address: value.selected(),
                    candidates: value.candidates().to_vec(),
                    source: value.source().code(),
                    dns_server: value.source().dns_server(),
                    elapsed_ms: milliseconds(value.elapsed()),
                }),
            ),
            Event::Probe(value) => (
                value.started_at(),
                RecordData::Probe(ProbeRecord {
                    sequence: value.sequence(),
                    address: value.address(),
                    status: value.outcome().code(),
                    elapsed_ms: milliseconds(value.elapsed()),
                    timeout_ms: milliseconds(value.timeout()),
                    rtt_ms: value.rtt().map(milliseconds),
                    jitter_ms: value.jitter().map(milliseconds),
                    failure: match value.outcome() {
                        Outcome::Failed(failure) => Some(FailureRecord {
                            kind: failure.kind().code(),
                            os_code: failure.os_code(),
                            message: failure.message().to_owned(),
                        }),
                        _ => None,
                    },
                }),
            ),
            Event::Summary(value) => {
                let counts = value.counts();
                (
                    value.finished_at(),
                    RecordData::Summary(SummaryRecord {
                        target: value.target().to_string(),
                        address: value.address(),
                        stop_reason: value.reason().code(),
                        elapsed_ms: milliseconds(value.elapsed()),
                        resolution_ms: value.resolution_elapsed().map(milliseconds),
                        counts: CountsRecord {
                            attempted: counts.attempted(),
                            open: counts.open(),
                            failed: counts.failed(),
                            timed_out: counts.timed_out(),
                            cancelled: counts.cancelled(),
                        },
                        failure_rate_pct: counts.failure_ratio().map(|ratio| ratio * 100.0),
                        rtt: value.latency().map(|latency| LatencyRecord {
                            min_ms: milliseconds(latency.min()),
                            average_ms: milliseconds(latency.average()),
                            max_ms: milliseconds(latency.max()),
                        }),
                        jitter_samples: value.jitter_samples(),
                        jitter_p95_ms: value.jitter_p95().map(milliseconds),
                    }),
                )
            }
        };
        Ok(Self {
            schema: SCHEMA,
            mode: mode.code(),
            timestamp: timestamps
                .then(|| Timestamp::from_system_time(at))
                .transpose()?,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negative_and_large_timestamps_are_fallible() {
        let before_epoch = UNIX_EPOCH - Duration::from_millis(1);
        let timestamp = Timestamp::from_system_time(before_epoch).unwrap();
        assert_eq!(timestamp.unix_ms, -1);
        assert_eq!(timestamp.utc, "1969-12-31T23:59:59.999Z");
        if let Some(large) = UNIX_EPOCH.checked_add(Duration::from_millis(i64::MAX as u64)) {
            assert!(Timestamp::from_system_time(large).is_err());
        }
    }
}
