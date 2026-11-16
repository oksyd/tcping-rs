use clap::{ArgGroup, ColorChoice, Parser, ValueEnum};
use std::{
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};
use tcping::{AddressFamily, ConfigError, ProbeMode, SessionConfig, Target};

#[derive(Parser, Debug)]
#[command(version, about)]
#[command(group(ArgGroup::new("timestamp_style").args(["timestamp", "unix_timestamp"])))]
#[command(group(ArgGroup::new("ip_family").args(["ipv4", "ipv6"])))]
pub(crate) struct Args {
    #[arg(value_name = "HOST:PORT")]
    pub target: Target,
    #[arg(long, default_value_t = ProbeMode::default(), help = "Probe mode: connect or syn (Linux, requires CAP_NET_RAW)")]
    pub mode: ProbeMode,
    #[arg(short, long, default_value_t = SessionConfig::DEFAULT_COUNT, help = "Total probes to send")]
    pub count: NonZeroUsize,
    #[arg(
        short = 't',
        long,
        conflicts_with = "count",
        help = "Probe until interrupted"
    )]
    pub continuous: bool,
    #[arg(short = 'o', long, value_enum, default_value = "normal")]
    pub output_mode: OutputMode,
    #[arg(
        long,
        value_enum,
        default_value = "auto",
        help = "Color status text in normal output"
    )]
    pub color: ColorChoice,
    #[arg(
        short = 'e',
        long,
        help = "Stop successfully after the first open result"
    )]
    pub exit_on_success: bool,
    #[arg(short = 'j', long, help = "Report jitter between successful probes")]
    pub jitter: bool,
    #[arg(long, visible_alias = "date", value_enum, num_args = 0..=1,
        require_equals = true, default_missing_value = "iso8601", help = "Include timestamps")]
    pub timestamp: Option<TimestampFormat>,
    #[arg(
        short = 'D',
        help = "Use Unix timestamps (equivalent to --timestamp=unix)"
    )]
    pub unix_timestamp: bool,
    #[arg(
        long,
        default_value_t = SessionConfig::DEFAULT_PROBE_TIMEOUT_MS,
        help = "Deadline per probe in milliseconds"
    )]
    pub timeout_ms: NonZeroU64,
    #[arg(
        long,
        default_value_t = SessionConfig::DEFAULT_RESOLVE_TIMEOUT_MS,
        help = "DNS resolution deadline in milliseconds"
    )]
    pub resolve_timeout_ms: NonZeroU64,
    #[arg(
        long,
        default_value_t = SessionConfig::DEFAULT_INTERVAL_MS,
        help = "Minimum interval between probe starts in milliseconds"
    )]
    pub interval_ms: NonZeroU64,
    #[arg(short = '4', long, help = "Select an IPv4 address")]
    pub ipv4: bool,
    #[arg(short = '6', long, help = "Select an IPv6 address")]
    pub ipv6: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutputMode {
    Normal,
    Json,
    Csv,
    Md,
}
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TimestampFormat {
    Unix,
    Iso8601,
}

impl Args {
    pub(crate) fn timestamp_format(&self) -> Option<TimestampFormat> {
        if self.unix_timestamp {
            Some(TimestampFormat::Unix)
        } else {
            self.timestamp
        }
    }
    pub(crate) fn config(&self) -> Result<SessionConfig, ConfigError> {
        let family = if self.ipv4 {
            AddressFamily::Ipv4
        } else if self.ipv6 {
            AddressFamily::Ipv6
        } else {
            AddressFamily::Any
        };
        let config = SessionConfig::new(self.target.clone())
            .with_count(self.count.get())?
            .with_probe_timeout(Duration::from_millis(self.timeout_ms.get()))?
            .with_resolve_timeout(Duration::from_millis(self.resolve_timeout_ms.get()))?
            .with_interval(Duration::from_millis(self.interval_ms.get()))?
            .with_family(family)
            .exit_on_success(self.exit_on_success)
            .jitter(self.jitter);
        Ok(if self.continuous {
            config.continuous()
        } else {
            config
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_library_configuration_and_overrides_are_preserved() {
        let defaults = SessionConfig::new("localhost:80".parse().unwrap());
        let parsed = Args::try_parse_from(["tcping", "localhost:80"])
            .unwrap()
            .config()
            .unwrap();
        assert_eq!(parsed.count(), defaults.count());
        assert_eq!(parsed.interval(), defaults.interval());
        assert_eq!(parsed.probe_timeout(), defaults.probe_timeout());
        assert_eq!(parsed.resolve_timeout(), defaults.resolve_timeout());
        let parsed = Args::try_parse_from([
            "tcping",
            "localhost:80",
            "-c",
            "7",
            "--interval-ms",
            "123",
            "--timeout-ms",
            "456",
            "--resolve-timeout-ms",
            "789",
        ])
        .unwrap()
        .config()
        .unwrap();
        assert_eq!(parsed.count(), tcping::ProbeCount::finite(7).unwrap());
        assert_eq!(parsed.interval(), Duration::from_millis(123));
        assert_eq!(parsed.probe_timeout(), Duration::from_millis(456));
        assert_eq!(parsed.resolve_timeout(), Duration::from_millis(789));
    }
    #[test]
    fn validates_values_and_conflicts() {
        for args in [
            vec!["-c", "0"],
            vec!["--timeout-ms", "0"],
            vec!["--interval-ms", "0"],
            vec!["--resolve-timeout-ms", "0"],
            vec!["-4", "-6"],
            vec!["-t", "-c", "2"],
            vec!["--timestamp", "-D"],
            vec!["-o", "unknown"],
            vec!["-o", "color"],
            vec!["--color", "unknown"],
            vec!["--mode", "unknown"],
        ] {
            assert!(
                Args::try_parse_from(["tcping", "localhost:80"].into_iter().chain(args)).is_err()
            );
        }
    }
    #[test]
    fn optional_timestamp_does_not_consume_the_target() {
        let args = Args::try_parse_from(["tcping", "--timestamp", "localhost:80"]).unwrap();
        assert_eq!(args.timestamp_format(), Some(TimestampFormat::Iso8601));
        let args = Args::try_parse_from(["tcping", "localhost:80", "--date=unix", "-4"]).unwrap();
        assert_eq!(args.timestamp_format(), Some(TimestampFormat::Unix));
        assert_eq!(args.config().unwrap().family(), AddressFamily::Ipv4);
    }
}
