# tcping-rs

TCP connection probes for Linux, macOS, and Windows. Measure connection latency without ICMP, distinguish closed ports from timeouts, and consume results as a CLI or an async Rust library.

[![Crates.io](https://img.shields.io/crates/v/tcping.svg)](https://crates.io/crates/tcping)
[![CI](https://github.com/oksyd/tcping-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/oksyd/tcping-rs/actions/workflows/ci.yaml)

## Installation

Download a binary from [GitHub Releases](https://github.com/oksyd/tcping-rs/releases), or build the checkout with Rust 1.100 or later:

```sh
cargo install --path . --locked
```

The container image is published to GHCR for `linux/amd64` and `linux/arm64`:

```sh
docker run --rm ghcr.io/oksyd/tcping:latest example.com:443 -c 4
```

## CLI

```sh
tcping example.com:443
tcping 127.0.0.1:8080 -c 10 --interval-ms 500
tcping '[::1]:443' -t -j
tcping example.com:443 -4 -e --timeout-ms 2000
tcping example.com:443 -o json --timestamp
tcping example.com:443 -o csv -D
```

| Option | Meaning |
|---|---|
| `-c`, `--count` | Number of attempts; default `4`, must be positive |
| `-t`, `--continuous` | Run until interrupted; conflicts with an explicit count |
| `-e`, `--exit-on-success` | Stop successfully at the first open connection |
| `-j`, `--jitter` | Jitter between successive successful connections and p95 |
| `-o`, `--output-mode` | `normal`, `json`, `csv`, or `md` |
| `--color` | `auto` (default), `always`, or `never`; colors status text in normal output |
| `--timeout-ms` | Connection deadline per attempt; default `2000` |
| `--resolve-timeout-ms` | Separate DNS resolution deadline; default `5000` |
| `--interval-ms` | Minimum interval between attempt starts; default `1000` |
| `-4`, `--ipv4` / `-6`, `--ipv6` | Select an address family |
| `--timestamp[=iso8601\|unix]` | Include timestamps; bare flag uses UTC RFC 3339 |
| `--date` | Alias for `--timestamp` |
| `-D` | Shorthand for `--timestamp=unix` |
| `-h` / `-V` | Help / version |

All durations must be positive. IPv6 literals require brackets. An optional timestamp value uses `=` so that `--timestamp example.com:443` unambiguously treats the address as the target.

### Colors

Normal output colors only the status text: green for `open`, red for refused connections and other connection errors, yellow for timeouts or unreachable hosts/networks, and gray for cancellation. Addresses, RTT values, and statistics retain the terminal's default color. Basic terminal palette colors adapt to the selected terminal theme.

`--color auto` enables color on a terminal and disables it for pipes, files, `TERM=dumb`, or a nonempty [`NO_COLOR`](https://no-color.org/) environment variable. `--color always` explicitly forces status colors, including in pipes and when `NO_COLOR` is set. `--color never` disables them. JSON, CSV, and Markdown never receive ANSI color codes, including with `--color always`.

```sh
tcping example.com:443                      # automatic terminal colors
tcping example.com:443 --color never       # plain text
tcping example.com:443 --color always | less -R
NO_COLOR=1 tcping example.com:443
```

The previous `-o color` format is removed; use `--color always` with normal output instead.

### Outcomes and timing

```text
Resolved cloudflare.com -> 104.16.132.229  (DNS 1.1.1.1)  in 77.5638 ms
Probing 127.0.0.1:8080/tcp - open - 0.2531 ms
Probing 127.0.0.1:8081/tcp - FAILED: connection refused (port closed)
Probing 192.0.2.1:443/tcp - FAILED: request timed out
```

Only successful TCP connections have an RTT. A refused connection fails immediately; it does not wait for the timeout. Other failures distinguish host/network unreachable, permission denied, connection reset/aborted, and an unavailable local address. Cancellation is a separate outcome.

The deadline is a scheduling boundary, not a real-time guarantee. OS and executor scheduling can make the observed duration exceed `2000 ms`, including fractional milliseconds. Elapsed time is measured with a monotonic clock and never clamped to the configured timeout. A connection observed at or after its deadline is classified as timed out. When cancellation and a deadline are both ready, cancellation takes priority.

Attempts run sequentially. Their starts are spaced by at least `--interval-ms`; a slow attempt allows the next to start immediately after it finishes, without a burst of missed attempts. DNS time is excluded from connection RTT. The session duration includes DNS, probing, and intervening waits.

DNS uses Hickory's async resolver with system DNS configuration and the hosts file. It does not reproduce every OS name-service extension, such as NSS plugins or mDNS. IP literals bypass DNS. Resolution occurs once per session: after family filtering and deduplication, the first address is used for every attempt. There is no connection failover that could silently change the endpoint being measured.

`(DNS 1.1.1.1)` identifies the directly queried DNS server whose address result was accepted. Each upstream lookup keeps its A/AAAA and CNAME queries on one server; configured upstreams are queried with bounded concurrency, and the first successful address result wins. Unsuccessful or unused servers are not listed. This identifies the directly contacted resolver, including a local forwarder such as `127.0.0.53`; it cannot reveal that forwarder's own upstreams or whether its answer came from its cache.

Local hosts-file results display `(hosts)`. Repeated library lookups can use a TTL-aware local cache and display `(DNS cache)` without naming a server as if it had just answered. The cache retains up to 64 hostnames per resolver; zero-TTL answers are not cached. JSON and CSV expose `source` (`dns`, `cache`, `hosts`, `literal`, or `unknown`) and `dns_server` (the responder IP for fresh DNS results; JSON `null` or an empty CSV field otherwise), alongside the candidates and selected address. Use an IP literal to choose an exact endpoint.

Statistics count open, failed, timed-out, and cancelled attempts separately. The connection failure rate is `(failed + timed_out) / (open + failed + timed_out)`, excluding cancellation. It is absent when no attempt completed. RTT statistics include successful connections only. Jitter is the absolute difference between successive successful RTTs, even if failures occur between them. The first success has no jitter. The p95 is interpolated exactly for the first 100 jitter samples, then estimated using the constant-memory P² algorithm.

### Exit status

| Code | Meaning |
|---|---|
| `0` | All completed attempts succeeded, or `-e` found an open connection |
| `1` | At least one connection failed/timed out |
| `2` | Invalid arguments, DNS/setup failure, or an output error |
| `130` | Cancelled by Ctrl-C, SIGTERM on Unix, or Ctrl-Break on Windows |

A closed downstream pipe exits quietly with `0`. Interruption stops DNS, a pending connection, or the interval wait and emits a final summary when stdout is available.

## Output contract: `tcping.v3`

Version 1.3 includes breaking API changes. Machine output always uses `schema: "tcping.v3"`, with or without timestamps. There are no legacy v1/v2 serializers.

JSON is NDJSON: one object per event, with `record` equal to `resolved`, `probe`, or `summary`. CSV uses the same event model, a single fixed header, and empty fields for missing values. It quotes commas, quotes, and line breaks. Markdown and normal text show explicit failure reasons and omit RTT for failed attempts.

A failed JSON probe looks like this:

```json
{"schema":"tcping.v3","record":"probe","sequence":1,"address":"127.0.0.1:8081","status":"refused","elapsed_ms":0.15,"timeout_ms":2000.0,"rtt_ms":null,"jitter_ms":null,"failure":{"kind":"refused","os_code":111,"message":"Connection refused (os error 111)"}}
```

`elapsed_ms` measures the attempt regardless of outcome; `rtt_ms` exists only for `open`. Status codes are `open`, `refused`, `host_unreachable`, `network_unreachable`, `permission_denied`, `reset`, `aborted`, `address_unavailable`, `error`, `timeout`, and `cancelled`. OS error codes and messages are platform dependent.

When requested, all JSON events include a `timestamp` object with `utc` (RFC 3339) and `unix_ms` (integer milliseconds). CSV flattens these to `timestamp` and `unix_ms`. The requested timestamp style affects human-readable output; machine fields remain stable. Resolution/probe timestamps mark their start; summary timestamps mark completion.

Summary fields include `stop_reason`, `counts`, `failure_rate_pct`, optional `rtt` min/average/max, `jitter_samples`, and optional `jitter_p95_ms`. CSV flattens the counters and RTT fields. Stop reasons are `count_reached`, `first_success`, `cancelled`, and `handler_stopped`.

## Rust library

Disable default features when embedding the engine:

```toml
[dependencies]
tcping = { version = "1.3", default-features = false }
tokio = { version = "1", features = ["rt", "macros", "net", "time"] }
```

```rust
use std::time::Duration;
use tcping::{Engine, SessionConfig, SessionError};

async fn example() -> Result<(), SessionError> {
    let config = SessionConfig::new("example.com:443".parse()?)
        .with_count(4)?
        .with_connect_timeout(Duration::from_secs(2))?
        .jitter(true);
    let session = Engine::default().collect(&config).await?;
    for probe in session.probes() {
        println!("{}: {:?}", probe.address(), probe.outcome());
    }
    Ok(())
}
```

The caller supplies a Tokio runtime with I/O and time enabled. The library does not create a runtime, install signal handlers, or write to stdout. Domain values use `Duration`, `SystemTime`, and typed outcomes; CLI exit codes and serialization belong to adapters.

`Engine::run` streams borrowed `Event` values to a handler. `run_until` also accepts a cancellation future. Handlers return `Result<ControlFlow<()>, E>`: `Continue` keeps probing, `Break` ends the session with `HandlerStopped`, and `Err` stops immediately and is returned as `RunError::Handler(E)`. Handlers should return promptly. A successful run emits one terminal summary; setup or handler errors return an error without attempting further events. Cancellation before resolution produces a summary without an address or probes.

`collect` and `collect_until` store results for finite sessions only. Continuous sessions require streaming, whose internal memory use is bounded. Dropping the engine's run future drops the active network future; it does not emit a summary. `Resolver` and `Connector` are replaceable async adapters, allowing deterministic tests without external DNS or network access.

| Feature | Purpose |
|---|---|
| No default features | Async engine, typed domain model, DNS/TCP adapters |
| `report` | Versioned `report::Record` DTOs and fallible timestamps; no CLI |
| `cli` (default) | CLI parsing, process signals, and output writers; enables `report` |

Use `report::Record::from_event` for the same wire contract as the CLI. Domain types deliberately do not implement serialization. The old `PingOptions`, implicit-runtime helpers, public mutable result fields, and v1/v2 schemas have been removed.

## Development

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo test --no-default-features --locked
cargo test --no-default-features --features report --locked
cargo doc --no-deps --all-features --locked
docker build -t tcping:local .
docker run --rm tcping:local --version
```

The core is separated into validated configuration/targets (`config`, `target`), domain values (`model`), network adapters (`network`), orchestration (`engine`), and online statistics (`stats`). The optional `report` module owns the wire schema. The binary owns argument parsing, signal registration, rendering, and exit codes. Tests exercise virtual-time deadlines and cancellation, network-future disposal, output failures, protocol records, statistics, and real loopback connections.

[MIT license](LICENSE).
