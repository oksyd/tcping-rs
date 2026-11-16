use super::color;
use crate::cli::TimestampFormat;
use std::{
    io::{self, Write},
    num::NonZeroU8,
    time::SystemTime,
};
use tcping::{
    Event, FailureKind, Outcome, ProbeMode, ResolutionSource, StopReason,
    report::{Timestamp, milliseconds},
};
use time::{
    OffsetDateTime,
    format_description::well_known::{
        Iso8601,
        iso8601::{Config, TimePrecision},
    },
};

fn timestamp(at: SystemTime, format: TimestampFormat) -> io::Result<String> {
    let value = Timestamp::from_system_time(at).map_err(io::Error::other)?;
    Ok(match format {
        TimestampFormat::Iso8601 => {
            const FORMAT: Iso8601<
                {
                    Config::DEFAULT
                        .set_time_precision(TimePrecision::Second {
                            decimal_digits: NonZeroU8::new(3),
                        })
                        .encode()
                },
            > = Iso8601;
            OffsetDateTime::from_unix_timestamp_nanos(value.unix_ms * 1_000_000)
                .map_err(io::Error::other)?
                .format(&FORMAT)
                .map_err(io::Error::other)?
        }
        TimestampFormat::Unix => {
            let magnitude = value.unix_ms.unsigned_abs();
            let sign = if value.unix_ms < 0 { "-" } else { "" };
            format!("{sign}{}.{:03}", magnitude / 1000, magnitude % 1000)
        }
    })
}
fn prefix(at: SystemTime, format: Option<TimestampFormat>) -> io::Result<String> {
    format
        .map(|format| timestamp(at, format).map(|value| format!("[{value}] ")))
        .unwrap_or_else(|| Ok(String::new()))
}
fn status(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Open { .. } => "open".to_owned(),
        Outcome::Cancelled => "CANCELLED".to_owned(),
        outcome => {
            let mut text = format!("FAILED: {}", outcome.description());
            if let Outcome::Failed(failure) = outcome
                && failure.kind() == FailureKind::Other
                && !failure.message().is_empty()
            {
                text.push_str(": ");
                for character in failure.message().chars() {
                    if character.is_control() {
                        text.extend(character.escape_default());
                    } else {
                        text.push(character);
                    }
                }
            }
            text
        }
    }
}

fn plural_suffix(count: u64) -> &'static str {
    if count == 1 { "" } else { "s" }
}

pub(super) fn write_text(
    writer: &mut impl Write,
    event: Event<'_>,
    format: Option<TimestampFormat>,
    color: bool,
) -> io::Result<()> {
    match event {
        Event::Resolved(value) if value.target().literal_address().is_none() => {
            writeln!(
                writer,
                "{}Resolved {} -> {}  ({})  in {:.4} ms",
                prefix(value.started_at(), format)?,
                value.target().host(),
                value.selected().ip(),
                match value.source() {
                    ResolutionSource::Dns(server) => format!("DNS {server}"),
                    ResolutionSource::Cache => "DNS cache".to_owned(),
                    ResolutionSource::Hosts => "hosts".to_owned(),
                    ResolutionSource::Literal => "IP literal".to_owned(),
                    _ => "source unknown".to_owned(),
                },
                milliseconds(value.elapsed())
            )?;
        }
        Event::Probe(value) => {
            let mut prefix = prefix(value.started_at(), format)?;
            if value.mode() == ProbeMode::Syn {
                prefix.push_str("[syn] ");
            }
            match value.outcome() {
                Outcome::Open { rtt } => {
                    write!(
                        writer,
                        "{prefix}Probing {}/tcp - {} - {:.4} ms",
                        value.address(),
                        color::status(value.outcome(), &status(value.outcome()), color),
                        milliseconds(*rtt)
                    )?;
                    if let Some(jitter) = value.jitter() {
                        write!(writer, " jitter={:.4} ms", milliseconds(jitter))?;
                    }
                    writeln!(writer)?;
                }
                outcome => writeln!(
                    writer,
                    "{prefix}Probing {}/tcp - {}",
                    value.address(),
                    color::status(outcome, &status(outcome), color)
                )?,
            }
        }
        Event::Summary(value) => {
            let counts = value.counts();
            let (mode, failure_label) = match value.mode() {
                ProbeMode::Connect => ("", "Connection"),
                ProbeMode::Syn => (" (syn)", "Probe"),
            };
            writeln!(
                writer,
                "\n{}--- {} tcping statistics{mode} ---",
                prefix(value.finished_at(), format)?,
                value.target()
            )?;
            writeln!(
                writer,
                "{} attempt{}, {} open, {} failed, {} timed out, {} cancelled",
                counts.attempted(),
                plural_suffix(counts.attempted()),
                counts.open(),
                counts.failed(),
                counts.timed_out(),
                counts.cancelled()
            )?;
            if let Some(ratio) = counts.failure_ratio() {
                writeln!(
                    writer,
                    "{failure_label} failure rate: {:.2}%",
                    ratio * 100.0
                )?;
            }
            if let Some(latency) = value.latency() {
                writeln!(
                    writer,
                    "Round-trip min/avg/max = {:.4}/{:.4}/{:.4} ms",
                    milliseconds(latency.min()),
                    milliseconds(latency.average()),
                    milliseconds(latency.max())
                )?;
            }
            if let Some(p95) = value.jitter_p95() {
                writeln!(
                    writer,
                    "Jitter p95 = {:.4} ms ({} sample{})",
                    milliseconds(p95),
                    value.jitter_samples(),
                    plural_suffix(value.jitter_samples())
                )?;
            }
            if value.reason() == StopReason::Cancelled {
                writeln!(
                    writer,
                    "Stopped: {}",
                    color::status(&Outcome::Cancelled, "cancelled", color)
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn write_markdown(
    writer: &mut impl Write,
    event: Event<'_>,
    format: Option<TimestampFormat>,
    header_written: &mut bool,
) -> io::Result<()> {
    match event {
        Event::Probe(value) => {
            let show_mode = value.mode() == ProbeMode::Syn;
            if !*header_written {
                writeln!(
                    writer,
                    "| {}{}address | status | rtt_ms | jitter_ms |\n|{}{}---|---|---|---|",
                    if format.is_some() { "timestamp | " } else { "" },
                    if show_mode { "mode | " } else { "" },
                    if format.is_some() { "---|" } else { "" },
                    if show_mode { "---|" } else { "" },
                )?;
                *header_written = true;
            }
            write!(writer, "| ")?;
            if let Some(format) = format {
                write!(writer, "{} | ", timestamp(value.started_at(), format)?)?;
            }
            if show_mode {
                write!(writer, "{} | ", value.mode())?;
            }
            let status = escape_markdown(&status(value.outcome()));
            let rtt = value
                .rtt()
                .map(|duration| format!("{:.4}", milliseconds(duration)))
                .unwrap_or_else(|| "-".into());
            let jitter = value
                .jitter()
                .map(|duration| format!("{:.4}", milliseconds(duration)))
                .unwrap_or_else(|| "-".into());
            writeln!(
                writer,
                "{} | {status} | {rtt} | {jitter} |",
                value.address()
            )?;
        }
        Event::Summary(value) => {
            let counts = value.counts();
            writeln!(writer, "\n### Summary\n\n| field | value |\n|---|---|")?;
            writeln!(
                writer,
                "| target | {} |",
                escape_markdown(&value.target().to_string())
            )?;
            if let Some(format) = format {
                writeln!(
                    writer,
                    "| timestamp | {} |",
                    timestamp(value.finished_at(), format)?
                )?;
            }
            if value.mode() == ProbeMode::Syn {
                writeln!(writer, "| mode | {} |", value.mode())?;
            }
            writeln!(writer, "| stop reason | {} |", value.reason().code())?;
            writeln!(
                writer,
                "| attempts | {} |\n| open | {} |\n| failed | {} |\n| timed out | {} |\n| cancelled | {} |",
                counts.attempted(),
                counts.open(),
                counts.failed(),
                counts.timed_out(),
                counts.cancelled()
            )?;
            if let Some(ratio) = counts.failure_ratio() {
                writeln!(writer, "| failure rate (%) | {:.2} |", ratio * 100.0)?;
            }
            if let Some(latency) = value.latency() {
                writeln!(
                    writer,
                    "| min / avg / max (ms) | {:.4} / {:.4} / {:.4} |",
                    milliseconds(latency.min()),
                    milliseconds(latency.average()),
                    milliseconds(latency.max())
                )?;
            } else {
                writeln!(writer, "| min / avg / max (ms) | - |")?;
            }
            if let Some(p95) = value.jitter_p95() {
                writeln!(writer, "| jitter p95 (ms) | {:.4} |", milliseconds(p95))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn escape_markdown(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "&#124;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};
    #[test]
    fn iso_timestamp_uses_fixed_milliseconds_without_rounding() {
        for (at, expected) in [
            (UNIX_EPOCH, "1970-01-01T00:00:00.000Z"),
            (
                UNIX_EPOCH + Duration::from_millis(100),
                "1970-01-01T00:00:00.100Z",
            ),
            (
                UNIX_EPOCH + Duration::from_nanos(123_456_789),
                "1970-01-01T00:00:00.123Z",
            ),
            (
                UNIX_EPOCH + Duration::from_nanos(999_999_999),
                "1970-01-01T00:00:00.999Z",
            ),
            (
                UNIX_EPOCH + Duration::from_secs(86_400),
                "1970-01-02T00:00:00.000Z",
            ),
            (
                UNIX_EPOCH - Duration::from_nanos(1),
                "1969-12-31T23:59:59.999Z",
            ),
        ] {
            assert_eq!(timestamp(at, TimestampFormat::Iso8601).unwrap(), expected);
        }
        assert_eq!(
            Timestamp::from_system_time(UNIX_EPOCH + Duration::from_nanos(123_456_789))
                .unwrap()
                .utc,
            "1970-01-01T00:00:00.123456789Z"
        );
    }

    #[test]
    fn unix_timestamp_handles_both_sides_of_epoch() {
        assert_eq!(
            timestamp(UNIX_EPOCH - Duration::from_millis(1), TimestampFormat::Unix).unwrap(),
            "-0.001"
        );
        assert_eq!(
            timestamp(
                UNIX_EPOCH + Duration::from_millis(1001),
                TimestampFormat::Unix
            )
            .unwrap(),
            "1.001"
        );
    }
}
