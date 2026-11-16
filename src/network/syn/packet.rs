use std::net::SocketAddr;

#[derive(Clone, Copy, Debug)]
pub(super) struct Exchange {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub sequence: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Reply {
    Open,
    Refused,
}
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

impl Exchange {
    pub(super) fn syn(self) -> [u8; 20] {
        self.segment(self.sequence, SYN)
    }
    pub(super) fn reset(self) -> [u8; 20] {
        // RFC 9293: a reset responding to an ACK uses SEG.ACK as its sequence.
        self.segment(self.sequence.wrapping_add(1), RST)
    }
    fn segment(self, sequence: u32, flags: u8) -> [u8; 20] {
        let mut segment = [0; 20];
        segment[..2].copy_from_slice(&self.local.port().to_be_bytes());
        segment[2..4].copy_from_slice(&self.remote.port().to_be_bytes());
        segment[4..8].copy_from_slice(&sequence.to_be_bytes());
        segment[12] = 5 << 4;
        segment[13] = flags;
        if flags == SYN {
            segment[14..16].copy_from_slice(&64240u16.to_be_bytes());
        }
        let checksum = self.checksum(&segment);
        segment[16..18].copy_from_slice(&checksum.to_be_bytes());
        segment
    }
    pub(super) fn reply(self, packet: &[u8]) -> Option<Reply> {
        let tcp = match (self.remote.ip(), self.local.ip()) {
            (std::net::IpAddr::V4(remote), std::net::IpAddr::V4(local)) => {
                if packet.len() < 20
                    || packet[0] >> 4 != 4
                    || packet[9] != 6
                    || packet[12..16] != remote.octets()
                    || packet[16..20] != local.octets()
                    || u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0
                {
                    return None;
                }
                let header = usize::from(packet[0] & 15) * 4;
                let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
                if header < 20 {
                    return None;
                }
                packet.get(header..total)?
            }
            (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_)) => packet,
            _ => return None,
        };
        if tcp.len() < 20 {
            return None;
        }
        let header = usize::from(tcp[12] >> 4) * 4;
        if header < 20
            || header > tcp.len()
            || tcp[..2] != self.remote.port().to_be_bytes()
            || tcp[2..4] != self.local.port().to_be_bytes()
            || tcp[8..12] != self.sequence.wrapping_add(1).to_be_bytes()
        {
            return None;
        }
        // Linux raw receive can expose partial checksums (e.g. loopback/offload).
        // Match identity and control flags; do not reject replies using their checksum.
        // ECN flags may accompany SYN-ACK; FIN and conflicting control flags may not.
        match tcp[13] & (SYN | RST | ACK | 0x01) {
            flags if flags == SYN | ACK => Some(Reply::Open),
            flags if flags == RST | ACK => Some(Reply::Refused),
            _ => None,
        }
    }
    fn checksum(self, tcp: &[u8]) -> u16 {
        let mut sum = words(tcp) + tcp.len() as u32 + 6;
        match (self.local.ip(), self.remote.ip()) {
            (std::net::IpAddr::V4(local), std::net::IpAddr::V4(remote)) => {
                sum += words(&local.octets()) + words(&remote.octets());
            }
            (std::net::IpAddr::V6(local), std::net::IpAddr::V6(remote)) => {
                sum += words(&local.octets()) + words(&remote.octets());
            }
            _ => unreachable!("an exchange uses one address family"),
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}
fn words(bytes: &[u8]) -> u32 {
    bytes
        .chunks(2)
        .map(|pair| u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0)))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    fn exchanges() -> [Exchange; 2] {
        [
            Exchange {
                local: "192.0.2.1:40000".parse().unwrap(),
                remote: "192.0.2.2:443".parse().unwrap(),
                sequence: 0x12345678,
            },
            Exchange {
                local: "[2001:db8::1]:40000".parse().unwrap(),
                remote: "[2001:db8::2]:443".parse().unwrap(),
                sequence: 0x12345678,
            },
        ]
    }
    const OPEN: [&str; 2] = [
        "450000280000400040060000c0000202c000020101bb9c4098765432123456795012faf03d8c0000",
        "01bb9c4098765432123456795012faf0661b0000",
    ];
    const CLOSED: [&str; 2] = [
        "450000280000400040060000c0000202c000020101bb9c4000000000123456795014faf02a330000",
        "01bb9c4000000000123456795014faf052c20000",
    ];
    #[test]
    fn encodes_syn_and_reset_with_independent_wire_fixtures() {
        let syn = [
            "9c4001bb12345678000000005002faf02a460000",
            "9c4001bb12345678000000005002faf052d50000",
        ];
        let reset = [
            "9c4001bb12345679000000005004000025340000",
            "9c4001bb1234567900000000500400004dc30000",
        ];
        for (i, exchange) in exchanges().into_iter().enumerate() {
            assert_eq!(exchange.syn().as_slice(), bytes(syn[i]));
            assert_eq!(exchange.reset().as_slice(), bytes(reset[i]));
        }
    }
    #[test]
    fn recognizes_open_and_closed_but_rejects_unrelated_or_malformed_packets() {
        for (i, exchange) in exchanges().into_iter().enumerate() {
            let packet = bytes(OPEN[i]);
            assert_eq!(exchange.reply(&packet), Some(Reply::Open));
            assert_eq!(exchange.reply(&bytes(CLOSED[i])), Some(Reply::Refused));
            let stale = Exchange {
                sequence: exchange.sequence.wrapping_add(1),
                ..exchange
            };
            assert_eq!(stale.reply(&packet), None);
            let wrong_port = Exchange {
                local: SocketAddr::new(exchange.local.ip(), 40001),
                ..exchange
            };
            assert_eq!(wrong_port.reply(&packet), None);
            for size in 0..packet.len() {
                assert_eq!(exchange.reply(&packet[..size]), None);
            }
            let offset = if i == 0 { 20 } else { 0 };
            for index in [offset, offset + 2, offset + 8, offset + 12, offset + 13] {
                let mut corrupt = packet.clone();
                corrupt[index] ^= if index == offset + 12 { 0x40 } else { 1 };
                assert_eq!(exchange.reply(&corrupt), None, "byte {index}");
            }
        }
    }

    #[test]
    fn accepts_responses_with_kernel_checksum_offload() {
        for (i, exchange) in exchanges().into_iter().enumerate() {
            let mut packet = bytes(OPEN[i]);
            let offset = if i == 0 { 20 } else { 0 };
            // Raw sockets can receive a checksum that has not been completed in software.
            packet[offset + 16..offset + 18].copy_from_slice(&[0, 0]);
            assert_eq!(exchange.reply(&packet), Some(Reply::Open));
        }
    }

    #[test]
    fn sequence_wrap_and_packet_options_preserve_matching() {
        for (i, mut exchange) in exchanges().into_iter().enumerate() {
            let offset = if i == 0 { 20 } else { 0 };
            let mut packet = bytes(OPEN[i]);
            exchange.sequence = u32::MAX;
            packet[offset + 8..offset + 12].fill(0);
            assert_eq!(exchange.reply(&packet), Some(Reply::Open));
            assert_eq!(&exchange.reset()[4..8], &[0; 4]);
            packet[offset + 12] = 0x60;
            packet.extend_from_slice(&[1, 1, 1, 1]);
            if i == 0 {
                packet[3] = 44;
            }
            assert_eq!(exchange.reply(&packet), Some(Reply::Open));
            if i == 0 {
                packet[0] = 0x46;
                packet[3] = 48;
                packet.splice(20..20, [1, 1, 1, 1]);
                assert_eq!(exchange.reply(&packet), Some(Reply::Open));
                packet[6] |= 0x20;
                assert_eq!(exchange.reply(&packet), None);
                packet[6] &= !0x20;
                packet[12] ^= 1;
                assert_eq!(exchange.reply(&packet), None);
            }
        }
    }
}
