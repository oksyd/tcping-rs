# tcping-rs: TCP Ping in Rust

[![Release](https://img.shields.io/github/v/release/oksyd/tcping-rs?style=flat&label=release&color=blue)](https://github.com/oksyd/tcping-rs/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/oksyd/tcping-rs/ci.yaml?branch=main&style=flat&label=CI)](https://github.com/oksyd/tcping-rs/actions/workflows/ci.yaml?query=branch%3Amain)
[![Apache-2.0 License](https://img.shields.io/badge/license-Apache--2.0-gray?style=flat)](LICENSE)

**tcping-rs** is a TCP ping tool for Linux, macOS, and Windows. Check TCP port reachability and measure connection latency without ICMP. Use it from the command line, in scripts, or as an async Rust library.

Supports IPv4, IPv6, jitter measurement, JSON/CSV output, and optional TCP SYN half-open probes on Linux.

## Installation

### Release binaries

Download the latest release for your platform, extract the archive, and put `tcping` (`tcping.exe` on Windows) on your `PATH`:

| Platform | Direct download |
|---|---|
| Linux x86_64 | [tar.gz](https://github.com/oksyd/tcping-rs/releases/latest/download/tcping-x86_64-unknown-linux-musl.tar.gz) |
| Linux ARM64 | [tar.gz](https://github.com/oksyd/tcping-rs/releases/latest/download/tcping-aarch64-unknown-linux-musl.tar.gz) |
| macOS Apple Silicon | [tar.gz](https://github.com/oksyd/tcping-rs/releases/latest/download/tcping-aarch64-apple-darwin.tar.gz) |
| Windows x86_64 | [zip](https://github.com/oksyd/tcping-rs/releases/latest/download/tcping-x86_64-pc-windows-msvc.zip) |

See the [latest release](https://github.com/oksyd/tcping-rs/releases/latest) for all builds and checksums.

### Docker

The GHCR image supports `linux/amd64` and `linux/arm64`:

```sh
docker run --rm ghcr.io/oksyd/tcping:latest example.com:443
```

### Nix

Install [tcping-rs from Nixpkgs](https://github.com/NixOS/nixpkgs/blob/master/pkgs/by-name/tc/tcping-rs/package.nix) with `nix-command` and `flakes` enabled:

```sh
nix profile add nixpkgs#tcping-rs
```

The package version depends on your Nixpkgs revision.

## Usage

```sh
tcping cloudflare.com:443 -c 1                        # Probe once
tcping example.com:443 -t -j                          # Continuous probes with jitter
tcping 127.0.0.1:8080 -c 10 --interval-ms 500          # Ten probes, at least 500 ms apart
tcping example.com:443 -4 -e --timeout-ms 2000         # IPv4, stop on first success
tcping '[::1]:443'                                   # IPv6 literal
```

Defaults: **4 probes**, a **2-second timeout** per probe, and at least **1 second between probe starts**. DNS has a separate 5-second timeout. Press Ctrl-C to stop and print a summary. Run `tcping --help` for all options.

Example output for a single probe:

```text
Resolved cloudflare.com -> 104.16.133.229  (DNS 1.1.1.1)  in 77.0911 ms
Probing 104.16.133.229:443/tcp - open - 183.4491 ms

--- cloudflare.com:443 tcping statistics ---
1 attempt, 1 open, 0 failed, 0 timed out, 0 cancelled
Connection failure rate: 0.00%
Round-trip min/avg/max = 183.4491/183.4491/183.4491 ms
```

## Understanding results

| Result | Meaning |
|---|---|
| `open` | The TCP connection succeeded, or a SYN probe received SYN-ACK and sent RST. |
| `FAILED: connection refused (port closed)` | The target rejected the connection immediately. |
| `FAILED: request timed out` | The probe did not complete before its deadline. |
| `CANCELLED` | The probe was interrupted. |

Only successful probes contribute RTT and latency statistics. RTT excludes DNS and cleanup; `open` confirms TCP reachability, not application health. Scheduling may delay a timeout beyond the configured deadline. Jitter measures the absolute difference between successive successful RTTs.

Each run resolves the target once and probes the same selected IP. The DNS label identifies the directly contacted resolver; local results use `(hosts)` or `(DNS cache)`. Use an IP literal to select an exact endpoint.

Status colors adapt to the terminal and respect `NO_COLOR`. Use `--color never` to disable them or `--color always` to force them. Structured output has no color codes.

## Linux SYN mode

SYN mode measures the time from SYN to SYN-ACK, then sends RST without completing the TCP handshake. It supports IPv4 and IPv6 and can reduce application processing caused by repeated full connections. Each attempt sends one SYN without retransmission.

It requires Linux and `CAP_NET_RAW`, normally available to root:

```sh
sudo tcping example.com:443 --mode syn
```

For Docker, run with the required capability:

```sh
docker run --rm --user 0:0 --cap-drop=ALL --cap-add=NET_RAW ghcr.io/oksyd/tcping:latest example.com:443 --mode syn
```

SYN output is marked `[syn]`. Unsupported platforms or missing permissions produce an error; the default mode is `connect`.

## JSON, CSV, and Markdown output

```sh
tcping example.com:443 -o json --timestamp
tcping example.com:443 -o csv > probes.csv
tcping example.com:443 -o md
```

JSON uses one object per line (NDJSON), with `resolved`, `probe`, and `summary` records. CSV uses the same events with a fixed header. Both include `schema` (`tcping.v3`) and `mode` (`connect` or `syn`). Read CSV columns by name.

`rtt_ms` contains a value only for successful probes; missing values are JSON `null` or empty CSV fields. `elapsed_ms` measures the whole attempt, including cleanup. `--timestamp` adds UTC timestamps and integer Unix milliseconds to JSON/CSV; human output uses fixed milliseconds, with `-D` selecting Unix time.

Exit codes: **0** for success, **1** for failed or timed-out probes, **2** for argument/setup/output errors, and **130** for interruption. With `-e`, the first success exits **0** even after earlier failures. A closed downstream pipe exits quietly with **0**.

## Rust library

Add [tcping from crates.io](https://crates.io/crates/tcping) with CLI features disabled:

```toml
[dependencies]
tcping = { version = "1.3", default-features = false }
tokio = { version = "1", features = ["rt", "macros", "net", "time"] }
```

```rust
use tcping::{Engine, SessionConfig, SessionError};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), SessionError> {
    let config = SessionConfig::new("example.com:443".parse()?).with_count(4)?;
    let session = Engine::default().collect(&config).await?;
    for probe in session.probes() {
        println!("{}: {:?}", probe.address(), probe.outcome());
    }
    Ok(())
}
```

Use `collect` for finite runs and `run`/`run_until` for streaming or cancellation. The library uses the caller's Tokio runtime and does not install signal handlers or write output. Enable the `report` feature for the CLI's structured records.

## License

[Apache License 2.0](LICENSE).
