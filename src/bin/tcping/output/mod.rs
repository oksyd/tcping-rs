pub(crate) mod color;
mod csv;
mod human;

use crate::cli::{OutputMode, TimestampFormat};
use std::io::{self, Write};
use tcping::{Event, report::Record};

pub(crate) struct Renderer<W> {
    writer: W,
    mode: OutputMode,
    timestamp: Option<TimestampFormat>,
    color: bool,
    header_written: bool,
}
impl<W: Write> Renderer<W> {
    pub(crate) fn new(
        writer: W,
        mode: OutputMode,
        timestamp: Option<TimestampFormat>,
        color: bool,
    ) -> Self {
        Self {
            writer,
            mode,
            timestamp,
            color,
            header_written: false,
        }
    }
    pub(crate) fn write_event(&mut self, event: Event<'_>) -> io::Result<()> {
        match self.mode {
            OutputMode::Normal => {
                human::write_text(&mut self.writer, event, self.timestamp, self.color)?
            }
            OutputMode::Md => human::write_markdown(
                &mut self.writer,
                event,
                self.timestamp,
                &mut self.header_written,
            )?,
            OutputMode::Json | OutputMode::Csv => {
                let record = Record::from_event(event, self.timestamp.is_some())
                    .map_err(io::Error::other)?;
                if self.mode == OutputMode::Json {
                    serde_json::to_writer(&mut self.writer, &record).map_err(|error| {
                        io::Error::new(error.io_error_kind().unwrap_or(io::ErrorKind::Other), error)
                    })?;
                    writeln!(self.writer)?;
                } else {
                    csv::write_record(&mut self.writer, &record, &mut self.header_written)?;
                }
            }
        }
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{convert::Infallible, net::SocketAddr, ops::ControlFlow};
    use tcping::{
        Engine, Lookup, ProbeBackend, ProbeMode, ProbeSession, ResolutionSource, Resolver,
        SessionConfig, Target,
    };

    struct Network(ResolutionSource, ProbeMode);
    impl Default for Network {
        fn default() -> Self {
            Self(
                ResolutionSource::Dns("1.1.1.1".parse().unwrap()),
                ProbeMode::Connect,
            )
        }
    }
    impl Resolver for Network {
        async fn resolve(&self, _: &Target, _: tcping::AddressFamily) -> io::Result<Lookup> {
            Ok(Lookup {
                addresses: vec!["104.16.132.229:443".parse().unwrap()],
                source: self.0,
            })
        }
    }
    impl ProbeBackend for Network {
        fn mode(&self) -> ProbeMode {
            self.1
        }
        fn prepare(&self, _: SocketAddr) -> io::Result<impl ProbeSession> {
            Ok(Ready)
        }
    }
    struct Ready;
    impl ProbeSession for Ready {
        async fn probe(&mut self) -> io::Result<std::time::Duration> {
            Ok(std::time::Duration::ZERO)
        }
    }

    struct FailedProbe(&'static str);
    impl ProbeBackend for FailedProbe {
        fn mode(&self) -> ProbeMode {
            ProbeMode::Connect
        }
        fn prepare(&self, _: SocketAddr) -> io::Result<impl ProbeSession> {
            Ok(Self(self.0))
        }
    }
    impl ProbeSession for FailedProbe {
        async fn probe(&mut self) -> io::Result<std::time::Duration> {
            Err(io::Error::other(self.0))
        }
    }

    #[tokio::test]
    async fn unknown_errors_keep_their_details_without_breaking_output() {
        let config = SessionConfig::new("127.0.0.1:443".parse().unwrap())
            .with_count(1)
            .unwrap();
        let message = "RST cleanup failed: <device>|link\\path\nretry\tblocked\u{1b}[31m";
        for (format, expected) in [
            (
                OutputMode::Normal,
                "FAILED: connection failed: RST cleanup failed: <device>|link\\path\\nretry\\tblocked\\u{1b}[31m",
            ),
            (
                OutputMode::Md,
                "FAILED: connection failed: RST cleanup failed: &lt;device&gt;&#124;link\\\\path\\\\nretry\\\\tblocked\\\\u{1b}\\[31m",
            ),
        ] {
            let mut writer = Renderer::new(Vec::new(), format, None, false);
            Engine::new(Network::default(), FailedProbe(message))
                .run(&config, |event| {
                    writer.write_event(event)?;
                    Ok::<_, io::Error>(ControlFlow::Continue(()))
                })
                .await
                .unwrap();
            let text = String::from_utf8(writer.writer).unwrap();
            let probe = text.lines().find(|line| line.contains("FAILED:")).unwrap();
            assert!(probe.contains(expected), "{text}");
            assert!(!text.contains('\x1b'));
            if format == OutputMode::Md {
                assert_eq!(probe.matches('|').count(), 5, "{text}");
                assert!(probe.ends_with("| - | - |"), "{text}");
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn summary_uses_singular_and_plural_counts() {
        for count in [1, 2, 3] {
            let config = SessionConfig::new("127.0.0.1:443".parse().unwrap())
                .with_count(count)
                .unwrap()
                .jitter(true);
            let mut writer = Renderer::new(Vec::new(), OutputMode::Normal, None, false);
            Engine::new(Network::default(), Network::default())
                .run(&config, |event| {
                    writer.write_event(event)?;
                    Ok::<_, io::Error>(ControlFlow::Continue(()))
                })
                .await
                .unwrap();
            let text = String::from_utf8(writer.writer).unwrap();
            let expected = match count {
                1 => "1 attempt, 1 open",
                2 => "2 attempts, 2 open",
                _ => "3 attempts, 3 open",
            };
            assert!(text.contains(expected), "{text}");
            match count {
                1 => assert!(!text.contains("Jitter p95"), "{text}"),
                2 => assert!(text.contains("Jitter p95 = 0.0000 ms (1 sample)"), "{text}"),
                _ => assert!(
                    text.contains("Jitter p95 = 0.0000 ms (2 samples)"),
                    "{text}"
                ),
            }
        }
    }

    #[tokio::test]
    async fn syn_mode_is_explicit_in_every_output_format() {
        let config = SessionConfig::new("127.0.0.1:443".parse().unwrap())
            .with_count(1)
            .unwrap();
        for format in [
            OutputMode::Normal,
            OutputMode::Md,
            OutputMode::Json,
            OutputMode::Csv,
        ] {
            let mut writer = Renderer::new(Vec::new(), format, None, false);
            Engine::new(
                Network::default(),
                Network(ResolutionSource::Literal, ProbeMode::Syn),
            )
            .run(&config, |event| {
                writer.write_event(event)?;
                Ok::<_, io::Error>(ControlFlow::Continue(()))
            })
            .await
            .unwrap();
            let text = String::from_utf8(writer.writer).unwrap();
            match format {
                OutputMode::Normal => {
                    assert!(text.contains("[syn] Probing") && text.contains("statistics (syn)"))
                }
                OutputMode::Md => {
                    assert!(text.contains("| mode | address |") && text.contains("| syn |"))
                }
                OutputMode::Json => {
                    for line in text.lines() {
                        let value: serde_json::Value = serde_json::from_str(line).unwrap();
                        assert_eq!(value["mode"], "syn");
                    }
                }
                OutputMode::Csv => {
                    let mut lines = text.lines();
                    let index = lines
                        .next()
                        .unwrap()
                        .split(',')
                        .position(|column| column == "mode")
                        .unwrap();
                    assert!(lines.all(|line| line.split(',').nth(index) == Some("syn")));
                }
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn resolved_line_preserves_the_dns_server_display() {
        let config = SessionConfig::new("cloudflare.com:443".parse().unwrap())
            .with_count(1)
            .unwrap();
        for color in [false, true] {
            let mut writer = Renderer::new(Vec::new(), OutputMode::Normal, None, color);
            Engine::new(Network::default(), Network::default())
                .run(&config, |event| {
                    writer.write_event(event).unwrap();
                    Ok::<_, Infallible>(ControlFlow::Continue(()))
                })
                .await
                .unwrap();
            let text = String::from_utf8(writer.writer).unwrap();
            assert!(
                text.starts_with(
                    "Resolved cloudflare.com -> 104.16.132.229  (DNS 1.1.1.1)  in 0.0000 ms\n"
                ),
                "{text}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn local_results_are_not_labelled_as_dns_replies() {
        let config = SessionConfig::new("example.com:443".parse().unwrap())
            .with_count(1)
            .unwrap();
        for (source, label) in [
            (ResolutionSource::Hosts, "(hosts)"),
            (ResolutionSource::Cache, "(DNS cache)"),
            (ResolutionSource::Unknown, "(source unknown)"),
        ] {
            for mode in [OutputMode::Normal, OutputMode::Json, OutputMode::Csv] {
                let mut writer = Renderer::new(Vec::new(), mode, None, true);
                Engine::new(Network(source, ProbeMode::Connect), Network::default())
                    .run(&config, |event| {
                        writer.write_event(event).unwrap();
                        Ok::<_, Infallible>(ControlFlow::Continue(()))
                    })
                    .await
                    .unwrap();
                let text = String::from_utf8(writer.writer).unwrap();
                assert!(!text.contains("1.1.1.1"));
                if mode == OutputMode::Normal {
                    assert!(text.contains(label));
                } else if mode == OutputMode::Json {
                    let record: serde_json::Value =
                        serde_json::from_str(text.lines().next().unwrap()).unwrap();
                    assert_eq!(record["source"], source.code());
                    assert!(record["dns_server"].is_null());
                } else {
                    let mut lines = text.lines();
                    let columns: Vec<_> = lines.next().unwrap().split(',').collect();
                    let row: Vec<_> = lines.next().unwrap().split(',').collect();
                    assert_eq!(
                        row[columns.iter().position(|c| *c == "source").unwrap()],
                        source.code()
                    );
                    assert_eq!(
                        row[columns.iter().position(|c| *c == "dns_server").unwrap()],
                        ""
                    );
                }
            }
        }
    }

    struct FailingWriter(io::ErrorKind);
    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(self.0.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(self.0.into())
        }
    }
    #[tokio::test(start_paused = true)]
    async fn all_renderers_preserve_output_error_kinds() {
        let config = SessionConfig::new("cloudflare.com:443".parse().unwrap())
            .with_count(1)
            .unwrap();
        for mode in [
            OutputMode::Normal,
            OutputMode::Json,
            OutputMode::Csv,
            OutputMode::Md,
        ] {
            for kind in [io::ErrorKind::BrokenPipe, io::ErrorKind::StorageFull] {
                let mut writer = Renderer::new(FailingWriter(kind), mode, None, true);
                let error = Engine::new(Network::default(), Network::default())
                    .run(&config, |event| {
                        writer.write_event(event)?;
                        Ok::<_, io::Error>(ControlFlow::Continue(()))
                    })
                    .await
                    .unwrap_err();
                assert!(matches!(error, tcping::RunError::Handler(error) if error.kind() == kind));
            }
        }
    }
}
