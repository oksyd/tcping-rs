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
    use tcping::{Connector, Engine, Lookup, ResolutionSource, Resolver, SessionConfig, Target};

    struct Network(ResolutionSource);
    impl Default for Network {
        fn default() -> Self {
            Self(ResolutionSource::Dns("1.1.1.1".parse().unwrap()))
        }
    }
    impl Resolver for Network {
        async fn resolve(&self, _: &Target) -> io::Result<Lookup> {
            Ok(Lookup {
                addresses: vec!["104.16.132.229:443".parse().unwrap()],
                source: self.0,
            })
        }
    }
    impl Connector for Network {
        async fn connect(&self, _: SocketAddr) -> io::Result<()> {
            Ok(())
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
                Engine::new(Network(source), Network::default())
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
