use crate::ConfigError;
use std::{
    fmt,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    host: String,
    port: u16,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, ConfigError> {
        let host = host.into();
        let host = host.trim();
        if host.is_empty()
            || host.chars().any(char::is_whitespace)
            || host.contains(['[', ']', '/', '\\'])
            || (host.contains(':') && host.parse::<Ipv6Addr>().is_err())
        {
            return Err(ConfigError::Target(
                "expected a hostname or IP literal".into(),
            ));
        }
        if port == 0 {
            return Err(ConfigError::Target(
                "port must be between 1 and 65535".into(),
            ));
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn literal_address(&self) -> Option<SocketAddr> {
        self.host
            .parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, self.port))
    }
}

impl FromStr for Target {
    type Err = ConfigError;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.trim();
        let (host, port) = if let Some(rest) = input.strip_prefix('[') {
            let (host, port) = rest
                .split_once("]:")
                .ok_or_else(|| ConfigError::Target("IPv6 targets require [address]:port".into()))?;
            host.parse::<Ipv6Addr>()
                .map_err(|_| ConfigError::Target("brackets require an IPv6 address".into()))?;
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
        Self::new(host, port)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
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
}
