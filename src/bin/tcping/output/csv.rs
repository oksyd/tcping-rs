use std::io::{self, Write};
use tcping::report::{Record, RecordData};

// The column declaration controls both the header and the row layout.
macro_rules! columns {
    ($($name:ident),+ $(,)?) => {
        #[derive(Default)]
        struct Row { $($name: String),+ }
        impl Row {
            fn write(&self, writer: &mut impl Write, header: &mut bool) -> io::Result<()> {
                if !*header {
                    write_fields(writer, &[$(stringify!($name)),+])?;
                    *header = true;
                }
                write_fields(writer, &[$(&self.$name),+])
            }
        }
    };
}
columns!(
    record,
    schema,
    mode,
    timestamp,
    unix_ms,
    target,
    address,
    candidates,
    source,
    dns_server,
    sequence,
    status,
    elapsed_ms,
    timeout_ms,
    rtt_ms,
    jitter_ms,
    failure_kind,
    os_error,
    error,
    stop_reason,
    attempted,
    open,
    failed,
    timed_out,
    cancelled,
    failure_rate_pct,
    min_rtt_ms,
    avg_rtt_ms,
    max_rtt_ms,
    resolve_ms,
    jitter_samples,
    jitter_p95_ms,
);

fn optional(value: Option<impl ToString>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}

pub(super) fn write_record(
    writer: &mut impl Write,
    record: &Record,
    header: &mut bool,
) -> io::Result<()> {
    let mut row = Row {
        schema: record.schema.into(),
        mode: record.mode.into(),
        ..Row::default()
    };
    if let Some(timestamp) = &record.timestamp {
        row.timestamp = timestamp.utc.clone();
        row.unix_ms = timestamp.unix_ms.to_string();
    }
    match &record.data {
        RecordData::Resolved(value) => {
            row.record = "resolved".into();
            row.target = value.target.clone();
            row.address = value.address.to_string();
            row.candidates = value
                .candidates
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            row.source = value.source.into();
            row.dns_server = optional(value.dns_server);
            row.elapsed_ms = value.elapsed_ms.to_string();
        }
        RecordData::Probe(value) => {
            row.record = "probe".into();
            row.sequence = value.sequence.to_string();
            row.address = value.address.to_string();
            row.status = value.status.into();
            row.elapsed_ms = value.elapsed_ms.to_string();
            row.timeout_ms = value.timeout_ms.to_string();
            row.rtt_ms = optional(value.rtt_ms);
            row.jitter_ms = optional(value.jitter_ms);
            if let Some(failure) = &value.failure {
                row.failure_kind = failure.kind.into();
                row.os_error = optional(failure.os_code);
                row.error = failure.message.clone();
            }
        }
        RecordData::Summary(value) => {
            row.record = "summary".into();
            row.target = value.target.clone();
            row.address = optional(value.address);
            row.stop_reason = value.stop_reason.into();
            row.elapsed_ms = value.elapsed_ms.to_string();
            row.resolve_ms = optional(value.resolution_ms);
            row.attempted = value.counts.attempted.to_string();
            row.open = value.counts.open.to_string();
            row.failed = value.counts.failed.to_string();
            row.timed_out = value.counts.timed_out.to_string();
            row.cancelled = value.counts.cancelled.to_string();
            row.failure_rate_pct = optional(value.failure_rate_pct);
            if let Some(rtt) = &value.rtt {
                row.min_rtt_ms = rtt.min_ms.to_string();
                row.avg_rtt_ms = rtt.average_ms.to_string();
                row.max_rtt_ms = rtt.max_ms.to_string();
            }
            row.jitter_samples = value.jitter_samples.to_string();
            row.jitter_p95_ms = optional(value.jitter_p95_ms);
        }
    }
    row.write(writer, header)
}

fn write_fields(writer: &mut impl Write, fields: &[&str]) -> io::Result<()> {
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            writer.write_all(b",")?;
        }
        if field.contains([',', '"', '\r', '\n']) {
            writer.write_all(b"\"")?;
            for (index, part) in field.split('"').enumerate() {
                if index != 0 {
                    writer.write_all(b"\"\"")?;
                }
                writer.write_all(part.as_bytes())?;
            }
            writer.write_all(b"\"")?;
        } else {
            writer.write_all(field.as_bytes())?;
        }
    }
    writer.write_all(b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quotes_delimiters_and_multiline_errors() {
        let mut output = Vec::new();
        write_fields(&mut output, &["plain", "a,b", "a\"b", "a\r\nb", ""]).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "plain,\"a,b\",\"a\"\"b\",\"a\r\nb\",\r\n"
        );
    }
}
