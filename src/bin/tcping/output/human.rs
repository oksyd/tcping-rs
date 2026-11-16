use super::color;
use crate::cli::TimestampFormat;
use std::{
    io::{self, Write},
    time::SystemTime,
};
use tcping::{
    Event, Outcome, ResolutionSource, StopReason,
    report::{Timestamp, milliseconds},
};

fn timestamp(at: SystemTime, format: TimestampFormat) -> io::Result<String> {
    let value = Timestamp::from_system_time(at).map_err(io::Error::other)?;
    Ok(match format {
        TimestampFormat::Iso8601 => value.utc,
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
            let prefix = prefix(value.started_at(), format)?;
            match value.outcome() {
                Outcome::Open => {
                    write!(
                        writer,
                        "{prefix}Probing {}/tcp - {} - {:.4} ms",
                        value.address(),
                        color::status(value.outcome(), "open", color),
                        milliseconds(value.elapsed())
                    )?;
                    if let Some(jitter) = value.jitter() {
                        write!(writer, " jitter={:.4} ms", milliseconds(jitter))?;
                    }
                    writeln!(writer)?;
                }
                Outcome::Cancelled => writeln!(
                    writer,
                    "{prefix}Probing {}/tcp - {}",
                    value.address(),
                    color::status(value.outcome(), "CANCELLED", color)
                )?,
                outcome => writeln!(
                    writer,
                    "{prefix}Probing {}/tcp - {}",
                    value.address(),
                    color::status(
                        outcome,
                        &format!("FAILED: {}", outcome.description()),
                        color
                    )
                )?,
            }
        }
        Event::Summary(value) => {
            let counts = value.counts();
            writeln!(
                writer,
                "\n{}--- {} tcping statistics ---",
                prefix(value.finished_at(), format)?,
                value.target()
            )?;
            writeln!(
                writer,
                "{} attempts, {} open, {} failed, {} timed out, {} cancelled",
                counts.attempted(),
                counts.open(),
                counts.failed(),
                counts.timed_out(),
                counts.cancelled()
            )?;
            if let Some(ratio) = counts.failure_ratio() {
                writeln!(writer, "Connection failure rate: {:.2}%", ratio * 100.0)?;
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
                    "Jitter p95 = {:.4} ms ({} samples)",
                    milliseconds(p95),
                    value.jitter_samples()
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
            if !*header_written {
                if format.is_some() {
                    writeln!(
                        writer,
                        "| timestamp | address | status | rtt_ms | jitter_ms |\n|---|---|---|---|---|"
                    )?;
                } else {
                    writeln!(
                        writer,
                        "| address | status | rtt_ms | jitter_ms |\n|---|---|---|---|"
                    )?;
                }
                *header_written = true;
            }
            write!(writer, "| ")?;
            if let Some(format) = format {
                write!(writer, "{} | ", timestamp(value.started_at(), format)?)?;
            }
            let status = match value.outcome() {
                Outcome::Open => "open".to_owned(),
                Outcome::Cancelled => "CANCELLED".to_owned(),
                outcome => format!("FAILED: {}", outcome.description()),
            };
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
