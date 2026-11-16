#![cfg(target_os = "linux")]

use socket2::{Domain, Protocol, Socket, Type};
use std::{io, net::SocketAddr, time::Duration};
use tcping::{DnsResolver, Engine, FailureKind, Outcome, ProbeMode, SessionConfig};
use tokio::{
    net::{TcpListener, UdpSocket},
    time::timeout,
};

fn config(address: SocketAddr, count: usize) -> SessionConfig {
    SessionConfig::new(address.to_string().parse().unwrap())
        .with_count(count)
        .unwrap()
        .with_interval(Duration::from_millis(1))
        .unwrap()
        .with_probe_timeout(Duration::from_secs(1))
        .unwrap()
}

async fn verify_half_open(bind: &str) {
    let listener = TcpListener::bind(bind).await.unwrap();
    let address = listener.local_addr().unwrap();
    let capture =
        Socket::new(Domain::for_address(address), Type::RAW, Some(Protocol::TCP)).unwrap();
    let mut peer = address;
    peer.set_port(0);
    capture.connect(&peer.into()).unwrap();
    capture.set_nonblocking(true).unwrap();
    let capture = UdpSocket::from_std(capture.into()).unwrap();
    let engine = Engine::new(DnsResolver::default(), ProbeMode::Syn);
    let session = engine.collect(&config(address, 3)).await.unwrap();
    assert_eq!(session.summary().counts().open(), 3, "{session:?}");
    assert!(
        session
            .probes()
            .iter()
            .all(|probe| probe.mode() == ProbeMode::Syn && probe.rtt().is_some())
    );
    assert!(
        timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err(),
        "SYN probing must not establish an application connection"
    );

    let mut buffer = [0; 65535];
    let mut syns = Vec::new();
    let mut resets = Vec::new();
    while let Ok(result) = timeout(Duration::from_millis(20), capture.recv(&mut buffer)).await {
        let length = result.unwrap();
        let offset = if address.is_ipv4() {
            usize::from(buffer[0] & 15) * 4
        } else {
            0
        };
        let tcp = &buffer[offset..length];
        if tcp.len() < 20 || tcp[2..4] != address.port().to_be_bytes() {
            continue;
        }
        let local_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let sequence = u32::from_be_bytes(tcp[4..8].try_into().unwrap());
        match tcp[13] {
            0x02 => syns.push((local_port, sequence)),
            flags if flags & 0x04 != 0 => resets.push((local_port, sequence)),
            flags => panic!("unexpected client flags {flags:#x}: handshake completed"),
        }
    }
    assert_eq!(syns.len(), 3);
    for &(port, sequence) in &syns {
        assert!(
            resets.contains(&(port, sequence.wrapping_add(1))),
            "missing reset for SYN {sequence:#x}"
        );
    }
    assert!(syns.windows(2).all(|pair| pair[0].1 != pair[1].1));
}

#[tokio::test]
#[ignore = "requires Linux CAP_NET_RAW; run by CI on the compiled test binary"]
async fn ipv4_syn_ack_is_reset_without_completing_handshake() {
    verify_half_open("127.0.0.1:0").await;
}

#[tokio::test]
#[ignore = "requires Linux CAP_NET_RAW; run by CI on the compiled test binary"]
async fn ipv6_syn_ack_is_reset_without_completing_handshake() {
    verify_half_open("[::1]:0").await;
}

#[tokio::test]
#[ignore = "requires Linux CAP_NET_RAW; run by CI on the compiled test binary"]
async fn closed_ports_are_refused_for_both_families() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let address: SocketAddr = bind.parse().unwrap();
        let reserved = Socket::new(
            Domain::for_address(address),
            Type::STREAM,
            Some(Protocol::TCP),
        )
        .unwrap();
        reserved.bind(&address.into()).unwrap();
        let address = reserved.local_addr().unwrap().as_socket().unwrap();
        let session = Engine::new(DnsResolver::default(), ProbeMode::Syn)
            .collect(&config(address, 1))
            .await
            .unwrap();
        assert!(
            matches!(session.probes()[0].outcome(), Outcome::Failed(failure) if failure.kind() == FailureKind::Refused),
            "{session:?}"
        );
        assert_eq!(session.probes()[0].rtt(), None);
    }
}

#[tokio::test]
#[ignore = "requires Linux CAP_NET_RAW; run by CI on the compiled test binary"]
async fn simultaneous_sessions_have_independent_ports_and_replies() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = config(listener.local_addr().unwrap(), 3);
    let engine = Engine::new(DnsResolver::default(), ProbeMode::Syn);
    let (first, second) = tokio::join!(engine.collect(&config), engine.collect(&config));
    assert_eq!(first.unwrap().summary().counts().open(), 3);
    assert_eq!(second.unwrap().summary().counts().open(), 3);
    assert!(
        timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn missing_raw_socket_permission_is_a_setup_error() {
    let result = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP));
    if let Err(error) = result {
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let error = Engine::new(DnsResolver::default(), ProbeMode::Syn)
            .collect(&config("127.0.0.1:443".parse().unwrap(), 1))
            .await
            .unwrap_err();
        assert!(
            matches!(error, tcping::SessionError::ProbeSetup { mode: ProbeMode::Syn, source } if source.kind() == io::ErrorKind::PermissionDenied && source.to_string().contains("CAP_NET_RAW"))
        );
    }
}
