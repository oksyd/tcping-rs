mod packet;

use super::ProbeSession;
use packet::{Exchange, Reply};
use socket2::{Domain, Protocol, Socket, Type};
use std::{io, net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::Instant};

pub(super) struct SynProbe {
    socket: PacketSocket,
    // Binding without listening reserves the TCP port without accepting connections.
    // Linux's TCP stack resets unsolicited SYN-ACKs, including ones arriving after cancellation.
    _port: Socket,
    exchange: Exchange,
    buffer: Box<[u8]>,
}
impl SynProbe {
    pub(super) fn new(remote: SocketAddr) -> io::Result<Self> {
        let domain = Domain::for_address(remote);
        let socket = Socket::new(domain, Type::RAW, Some(Protocol::TCP)).map_err(|error| {
            if error.kind() == io::ErrorKind::PermissionDenied {
                io::Error::new(error.kind(), "SYN mode requires CAP_NET_RAW (or root)")
            } else {
                error
            }
        })?;
        let mut route = remote;
        route.set_port(0);
        // Raw connect selects a route/source and filters the peer; it sends no TCP handshake.
        socket.connect(&route.into())?;
        let mut local = socket
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("missing local IP address"))?;
        local.set_port(0);
        let port = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        if remote.is_ipv6() {
            port.set_only_v6(true)?;
        }
        port.bind(&local.into())?;
        let local = port
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("missing local TCP port"))?;
        Ok(Self {
            socket: PacketSocket::new(socket)?,
            _port: port,
            exchange: Exchange {
                local,
                remote,
                sequence: 0,
            },
            buffer: vec![0; 65535].into_boxed_slice(),
        })
    }
}
impl ProbeSession for SynProbe {
    async fn probe(&mut self) -> io::Result<Duration> {
        self.exchange.sequence = getrandom::u32().map_err(io::Error::other)?;
        exchange(&self.socket, self.exchange, &mut self.buffer).await
    }
}

async fn exchange(socket: &PacketSocket, key: Exchange, buffer: &mut [u8]) -> io::Result<Duration> {
    let syn = key.syn();
    let started = loop {
        socket.0.writable().await?;
        let started = Instant::now();
        match socket.send(&syn) {
            Ok(()) => break started,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    };
    loop {
        let length = socket.0.recv(buffer).await?;
        let rtt = started.elapsed();
        match key.reply(&buffer[..length]) {
            Some(Reply::Open) => {
                // Record the reply before cleanup. Never report success if our reset fails.
                socket.send(&key.reset()).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("SYN-ACK received but RST cleanup failed: {error}"),
                    )
                })?;
                return Ok(rtt);
            }
            Some(Reply::Refused) => return Err(io::ErrorKind::ConnectionRefused.into()),
            None => tokio::task::yield_now().await,
        }
    }
}

// Tokio's owned datagram adapter provides readiness and cancellation without unsafe
// descriptor registration. Converting the socket does not change IPPROTO_TCP or SOCK_RAW.
struct PacketSocket(UdpSocket);
impl PacketSocket {
    fn new(socket: Socket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into()).map(Self)
    }
    fn send(&self, packet: &[u8]) -> io::Result<()> {
        if self.0.try_send(packet)? != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "incomplete TCP packet send",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, timeout};

    async fn pair() -> (PacketSocket, UdpSocket) {
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(peer.local_addr().unwrap()).unwrap();
        peer.connect(client.local_addr().unwrap()).await.unwrap();
        (PacketSocket::new(client.into()).unwrap(), peer)
    }
    fn key() -> Exchange {
        Exchange {
            local: "[2001:db8::1]:40000".parse().unwrap(),
            remote: "[2001:db8::2]:443".parse().unwrap(),
            sequence: 0x12345678,
        }
    }
    fn response(key: Exchange, flags: u8) -> [u8; 20] {
        let mut packet = [0; 20];
        packet[..2].copy_from_slice(&key.remote.port().to_be_bytes());
        packet[2..4].copy_from_slice(&key.local.port().to_be_bytes());
        packet[8..12].copy_from_slice(&key.sequence.wrapping_add(1).to_be_bytes());
        packet[12] = 0x50;
        packet[13] = flags;
        packet
    }

    #[tokio::test]
    async fn syn_ack_produces_reset_without_a_handshake_ack() {
        let (client, peer) = pair().await;
        let key = key();
        let server = async {
            let mut packet = [0; 40];
            let length = peer.recv(&mut packet).await.unwrap();
            assert_eq!(&packet[..length], &key.syn());
            peer.send(&[0; 3]).await.unwrap();
            let stale = Exchange {
                sequence: key.sequence.wrapping_sub(1),
                ..key
            };
            peer.send(&response(stale, 0x12)).await.unwrap();
            sleep(Duration::from_millis(10)).await;
            peer.send(&response(key, 0x12)).await.unwrap();
            let length = peer.recv(&mut packet).await.unwrap();
            assert_eq!(&packet[..length], &key.reset());
            assert_eq!(packet[13], 0x04);
        };
        let probe = async {
            let mut buffer = [0; 128];
            exchange(&client, key, &mut buffer).await.unwrap()
        };
        let (rtt, ()) = timeout(Duration::from_secs(1), async {
            tokio::join!(probe, server)
        })
        .await
        .unwrap();
        assert!(rtt >= Duration::from_millis(10));
    }

    #[tokio::test]
    async fn rst_is_refused_without_an_extra_packet() {
        let (client, peer) = pair().await;
        let server = async {
            let mut packet = [0; 40];
            peer.recv(&mut packet).await.unwrap();
            peer.send(&response(key(), 0x14)).await.unwrap();
        };
        let probe = async {
            let mut buffer = [0; 128];
            exchange(&client, key(), &mut buffer).await.unwrap_err()
        };
        let (error, ()) = timeout(Duration::from_secs(1), async {
            tokio::join!(probe, server)
        })
        .await
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        let mut packet = [0; 40];
        assert!(
            timeout(Duration::from_millis(10), peer.recv(&mut packet))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn cancelled_exchange_does_not_consume_a_late_reply() {
        let (client, peer) = pair().await;
        let mut buffer = [0; 128];
        assert!(
            timeout(
                Duration::from_millis(10),
                exchange(&client, key(), &mut buffer)
            )
            .await
            .is_err()
        );
        let mut packet = [0; 40];
        peer.recv(&mut packet).await.unwrap();
        peer.send(&response(key(), 0x12)).await.unwrap();
        let next = Exchange {
            sequence: key().sequence.wrapping_add(1),
            ..key()
        };
        let server = async {
            let length = peer.recv(&mut packet).await.unwrap();
            assert_eq!(&packet[..length], &next.syn());
            peer.send(&response(next, 0x12)).await.unwrap();
            let length = peer.recv(&mut packet).await.unwrap();
            assert_eq!(&packet[..length], &next.reset());
        };
        let (result, ()) = timeout(Duration::from_secs(1), async {
            tokio::join!(exchange(&client, next, &mut buffer), server)
        })
        .await
        .unwrap();
        result.unwrap();
    }

    #[tokio::test]
    async fn unrelated_traffic_does_not_starve_deadlines() {
        let (client, peer) = pair().await;
        let sender = tokio::spawn(async move {
            loop {
                peer.send(&response(key(), 0x10)).await.unwrap();
            }
        });
        let mut buffer = [0; 128];
        let result = timeout(
            Duration::from_millis(20),
            exchange(&client, key(), &mut buffer),
        )
        .await;
        sender.abort();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn reset_send_failure_is_not_reported_as_open() {
        let (client, peer) = pair().await;
        let server = async {
            let mut packet = [0; 40];
            peer.recv(&mut packet).await.unwrap();
            socket2::SockRef::from(&client.0)
                .shutdown(std::net::Shutdown::Write)
                .unwrap();
            peer.send(&response(key(), 0x12)).await.unwrap();
        };
        let probe = async {
            let mut buffer = [0; 128];
            exchange(&client, key(), &mut buffer).await.unwrap_err()
        };
        let (error, ()) = timeout(Duration::from_secs(1), async {
            tokio::join!(probe, server)
        })
        .await
        .unwrap();
        assert!(error.to_string().contains("RST cleanup failed"), "{error}");
    }
}
