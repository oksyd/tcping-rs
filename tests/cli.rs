#![cfg(feature = "cli")]
#[cfg(unix)]
use std::io::Read;
use std::{
    io::{BufRead, BufReader},
    net::TcpListener,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tcping"));
    command.env_remove("NO_COLOR").env("TERM", "xterm-256color");
    command
}
fn run(address: &str, args: &[&str]) -> Output {
    command()
        .args([address, "-c", "1"])
        .args(args)
        .output()
        .unwrap()
}
fn finish(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!("CLI failed to exit promptly: {output:?}");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn open_connections_work_in_every_output_mode() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    for mode in ["normal", "md", "json", "csv"] {
        let output = run(&address, &["-o", mode, "--timestamp"]);
        assert!(output.status.success(), "{mode}: {output:?}");
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            !text.contains('\x1b'),
            "auto color must be disabled in a pipe: {text}"
        );
        assert!(text.contains("open"), "{mode}: {text}");
        if mode == "json" {
            let records = text
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(records.len(), 3);
            assert_eq!(records[0]["record"], "resolved");
            assert_eq!(records[1]["record"], "probe");
            assert_eq!(records[2]["record"], "summary");
            assert!(
                records
                    .iter()
                    .all(|r| r["schema"] == "tcping.v3" && r["timestamp"]["utc"].is_string())
            );
            assert!(records[1]["rtt_ms"].is_number());
        }
        if mode == "csv" {
            let lines = text.lines().collect::<Vec<_>>();
            assert_eq!(lines.len(), 4);
            let width = lines[0].split(',').count();
            assert!(lines.iter().all(|line| line.split(',').count() == width));
            assert!(lines[0].contains("elapsed_ms,timeout_ms,rtt_ms"));
        }
        if mode == "md" {
            let rows = text
                .lines()
                .filter(|line| line.starts_with('|'))
                .take(3)
                .collect::<Vec<_>>();
            assert_eq!(rows.len(), 3);
            let width = rows[0].split('|').count();
            assert!(
                rows.iter().all(|row| row.split('|').count() == width),
                "{text}"
            );
        }
    }
}

#[test]
fn connect_mode_preserves_human_output_and_reports_machine_mode() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    for explicit in [false, true] {
        for format in ["normal", "md", "json", "csv"] {
            let mut args = vec!["-o", format];
            if explicit {
                args.extend(["--mode", "connect"]);
            }
            let output = run(&address, &args);
            assert!(output.status.success(), "{format}: {output:?}");
            let text = String::from_utf8(output.stdout).unwrap();
            match format {
                "normal" => {
                    assert!(
                        text.starts_with(&format!("Probing {address}/tcp - open - ")),
                        "{text}"
                    );
                    assert!(text.contains(&format!("--- {address} tcping statistics ---")));
                    assert!(text.contains("Connection failure rate: 0.00%"));
                }
                "md" => {
                    assert!(
                        text.starts_with(
                            "| address | status | rtt_ms | jitter_ms |\n|---|---|---|---|\n"
                        ),
                        "{text}"
                    );
                    assert!(!text.contains("| mode |"));
                }
                "json" => {
                    for line in text.lines() {
                        let record: serde_json::Value = serde_json::from_str(line).unwrap();
                        assert_eq!(record["mode"], "connect");
                    }
                }
                "csv" => {
                    let mut lines = text.lines();
                    let index = lines
                        .next()
                        .unwrap()
                        .split(',')
                        .position(|column| column == "mode")
                        .unwrap();
                    assert!(lines.all(|line| line.split(',').nth(index) == Some("connect")));
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn explicit_colors_apply_only_to_normal_output() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    for (mode, choice, colored) in [
        ("normal", "always", true),
        ("normal", "never", false),
        ("normal", "auto", false),
        ("json", "always", false),
        ("csv", "always", false),
        ("md", "always", false),
    ] {
        let output = command()
            .args([&address, "-c", "1", "-o", mode, "--color", choice])
            .env("NO_COLOR", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{mode}/{choice}: {output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert_eq!(text.contains('\x1b'), colored, "{mode}/{choice}: {text}");
        if colored {
            assert!(text.contains("\x1b[32mopen\x1b[0m - "));
            assert_eq!(
                text.matches('\x1b').count(),
                2,
                "only the status is colored"
            );
        }
    }
}

#[test]
fn refused_connections_are_explicit_failures_without_rtt() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    drop(listener);
    for mode in ["normal", "md", "json", "csv"] {
        let output = run(&address, &["-o", mode]);
        assert_eq!(output.status.code(), Some(1), "{mode}: {output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        if mode == "json" {
            let records = text
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(records[1]["status"], "refused");
            assert!(records[1]["rtt_ms"].is_null());
            assert!(records[1]["elapsed_ms"].is_number());
            assert!(records.iter().all(|r| r.get("timestamp").is_none()));
        } else if mode == "csv" {
            let lines = text.lines().collect::<Vec<_>>();
            let columns = lines[0].split(',').collect::<Vec<_>>();
            let row = lines[2].split(',').collect::<Vec<_>>();
            assert_eq!(
                row[columns.iter().position(|v| *v == "status").unwrap()],
                "refused"
            );
            assert_eq!(
                row[columns.iter().position(|v| *v == "rtt_ms").unwrap()],
                ""
            );
        } else {
            assert!(text.contains("FAILED: connection refused (port closed)"));
            assert!(!text.contains("Round-trip"));
        }
    }
}

#[test]
fn invalid_arguments_and_incompatible_family_exit_with_code_two() {
    for args in [
        vec!["missing-port"],
        vec!["127.0.0.1:80", "-c", "0"],
        vec!["127.0.0.1:80", "-6"],
    ] {
        let output = command().args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn closed_stdout_is_a_quiet_success_in_every_mode() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    for mode in ["normal", "md", "json", "csv"] {
        let mut child = command()
            .args([&address, "-t", "--interval-ms", "1", "-o", mode])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        drop(reader);
        let output = finish(child);
        assert_eq!(output.status.code(), Some(0), "{mode}: {output:?}");
        assert!(output.stderr.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn unix_signals_interrupt_interval_and_emit_a_final_summary() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    for signal in ["-INT", "-TERM"] {
        let mut child = command()
            .args([&address, "-t", "--interval-ms", "60000", "-o", "json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("\"record\":\"probe\""));
        assert!(
            Command::new("kill")
                .args([signal, &child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let output = finish(child);
        assert_eq!(output.status.code(), Some(130));
        assert!(output.stderr.is_empty());
        let mut remainder = String::new();
        reader.read_to_string(&mut remainder).unwrap();
        let summary: serde_json::Value = serde_json::from_str(remainder.trim()).unwrap();
        assert_eq!(summary["stop_reason"], "cancelled");
        assert_eq!(summary["counts"]["attempted"], 1);
        assert_eq!(summary["counts"]["cancelled"], 0);
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn syn_mode_is_explicitly_unsupported_outside_linux() {
    let output = run("127.0.0.1:443", &["--mode", "syn"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("only supported on Linux")
    );
}
