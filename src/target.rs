use crate::ConfigError;
use hickory_resolver::proto::rr::Name;
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
    str::FromStr,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    host: String,
    parsed_host: Host,
    port: NonZeroU16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Host {
    Ip(IpAddr),
    Name(Name),
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, ConfigError> {
        let host = host.into();
        let host = host.trim();
        if host.is_empty()
            || host.chars().any(|c| c.is_whitespace() || c.is_control())
            || host.contains(['[', ']', '/', '\\'])
        {
            return Err(ConfigError::Target(
                "expected a hostname or IP literal".into(),
            ));
        }
        let parsed_host = match host.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) if host.contains(':') => {
                return Err(ConfigError::Target("invalid IP literal".into()));
            }
            Err(_) => Host::Name(
                Name::from_utf8(host)
                    .map_err(|error| ConfigError::Target(format!("invalid DNS name: {error}")))?,
            ),
        };
        let port = NonZeroU16::new(port)
            .ok_or_else(|| ConfigError::Target("port must be between 1 and 65535".into()))?;
        Ok(Self {
            host: host.to_owned(),
            parsed_host,
            port,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port.get()
    }
    pub fn literal_address(&self) -> Option<SocketAddr> {
        match self.parsed_host {
            Host::Ip(ip) => Some(SocketAddr::new(ip, self.port())),
            Host::Name(_) => None,
        }
    }
    pub(crate) fn parsed_host(&self) -> &Host {
        &self.parsed_host
    }
}

impl FromStr for Target {
    type Err = ConfigError;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.trim();
        let bracketed = input.starts_with('[');
        let (host, port) = if let Some(rest) = input.strip_prefix('[') {
            let (host, port) = rest
                .split_once("]:")
                .ok_or_else(|| ConfigError::Target("IPv6 targets require [address]:port".into()))?;
            (host, port)
        } else {
            let (host, port) = input
                .split_once(':')
                .ok_or_else(|| ConfigError::Target("expected host:port".into()))?;
            if port.contains(':') {
                return Err(ConfigError::Target(
                    "IPv6 targets require [address]:port".into(),
                ));
            }
            (host, port)
        };
        let port = port
            .parse::<u16>()
            .map_err(|_| ConfigError::Target("port must be between 1 and 65535".into()))?;
        let target = Self::new(host, port)?;
        if bracketed && !matches!(target.parsed_host, Host::Ip(IpAddr::V6(_))) {
            return Err(ConfigError::Target(
                "brackets require an IPv6 address".into(),
            ));
        }
        Ok(target)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if matches!(self.parsed_host, Host::Ip(IpAddr::V6(_))) {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_round_trips() {
        for input in ["localhost:80", "127.0.0.1:443", "[::1]:443"] {
            let target: Target = input.parse().unwrap();
            assert_eq!(target.to_string(), input);
        }
    }
    #[test]
    fn rejects_ambiguous_or_invalid_targets() {
        for input in [
            "localhost",
            "localhost:0",
            "localhost:65536",
            "::1:80",
            "[localhost]:80",
            "[::1]80",
            "a b:80",
            "https://example.com:443",
            ":80",
        ] {
            assert!(input.parse::<Target>().is_err(), "{input}");
        }
    }

    #[test]
    fn rejects_invalid_dns_names_at_construction() {
        for host in [
            "bad..example".to_owned(),
            format!("{}.example", "a".repeat(64)),
            vec!["a".repeat(63); 4].join("."),
            "bad\0example".to_owned(),
            "bad\u{1b}example".to_owned(),
        ] {
            assert!(Target::new(&host, 443).is_err(), "accepted {host:?}");
            assert!(format!("{host}:443").parse::<Target>().is_err());
        }
    }

    #[test]
    fn preserves_valid_host_spelling_and_literal_addresses() {
        for host in [
            "localhost",
            "Example.COM.",
            "bücher.example",
            "_service.example",
        ] {
            let target = Target::new(host, 443).unwrap();
            assert_eq!(target.host(), host);
            assert_eq!(target.to_string().parse::<Target>().unwrap(), target);
            assert!(target.literal_address().is_none());
        }
        let target: Target = "[2001:0db8:0:0::1]:443".parse().unwrap();
        assert_eq!(target.to_string(), "[2001:0db8:0:0::1]:443");
        assert_eq!(
            target.literal_address(),
            Some("[2001:db8::1]:443".parse().unwrap())
        );
    }
}
