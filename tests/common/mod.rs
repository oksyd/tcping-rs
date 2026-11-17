use std::{net::SocketAddr, time::Duration};
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream},
    time::timeout,
};

// Windows may retry SYN packets before reporting connection refused.
pub(super) const REFUSAL_TIMEOUT: Duration = Duration::from_secs(10);

// Bind explicitly to reserve the port, then connect so unrelated SYNs cannot
// match it. A merely bound socket silently drops them on macOS. Keep both
// peers and the listener alive so neither port can be reused by a probe.
pub(super) struct RefusedEndpoint {
    client: TcpStream,
    _peer: TcpStream,
    _listener: TcpListener,
}

impl RefusedEndpoint {
    pub(super) async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let client = timeout(
            REFUSAL_TIMEOUT,
            socket.connect(listener.local_addr().unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        Self {
            client,
            _peer: peer,
            _listener: listener,
        }
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.client.local_addr().unwrap()
    }
}
