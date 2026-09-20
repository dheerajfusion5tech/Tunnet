//! Transparent TCP port NAT for Tunnet SSH (22 ↔ internal listen port).
//!
//! Only unfragmented (or first-fragment) TCP packets identified by the shared
//! parser are rewritten. Checksums are recomputed with etherparse.

use tunnet_common::packet::{self, Packet, Transport, set_tcp_ipv4_checksum};

pub const SSH_EXTERNAL_PORT: u16 = 22;
pub const SSH_INTERNAL_PORT: u16 = 30022;

pub fn needs_inbound_rewrite(packet: &[u8]) -> bool {
    let Ok(pkt) = packet::parse(packet) else {
        return false;
    };
    eligible(&pkt, true).is_some()
}

pub fn rewrite_inbound(packet: &mut [u8]) -> bool {
    rewrite(packet, true)
}

pub fn rewrite_outbound(packet: &mut [u8]) -> bool {
    rewrite(packet, false)
}

fn eligible(pkt: &Packet<'_>, inbound: bool) -> Option<(usize, usize)> {
    if pkt.fragmentation.is_later() {
        return None;
    }
    let Transport::Tcp {
        src_port,
        dst_port,
        header_len,
        ..
    } = pkt.transport
    else {
        return None;
    };
    if header_len < 18 {
        return None;
    }
    let ip_len = pkt.ip.header_len();
    if inbound {
        if dst_port != SSH_EXTERNAL_PORT {
            return None;
        }
        Some((ip_len + 2, SSH_INTERNAL_PORT as usize))
    } else {
        if src_port != SSH_INTERNAL_PORT {
            return None;
        }
        Some((ip_len, SSH_EXTERNAL_PORT as usize))
    }
}

fn rewrite(packet: &mut [u8], inbound: bool) -> bool {
    let Ok(pkt) = packet::parse(packet) else {
        return false;
    };
    let Some((offset, new_port)) = eligible(&pkt, inbound) else {
        return false;
    };
    let ip_len = pkt.ip.header_len();
    let new = new_port as u16;
    packet[offset] = (new >> 8) as u8;
    packet[offset + 1] = (new & 0xff) as u8;
    set_tcp_ipv4_checksum(packet, ip_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::net::Ipv4Addr;
    use tunnet_common::packet::{parse, tcp_ipv4_checksum_of};

    fn sample_tcp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let b = PacketBuilder::ipv4(src.octets(), dst.octets(), 64).tcp(sport, dport, 1, 1000);
        let mut out = Vec::new();
        b.write(&mut out, payload).unwrap();
        out
    }

    #[test]
    fn inbound_rewrites_22_to_internal() {
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer = Ipv4Addr::new(100, 64, 0, 2);
        let mut p = sample_tcp(peer, self_ip, 45678, 22, b"hello");
        let before_payload = p[40..].to_vec();
        assert!(rewrite_inbound(&mut p));
        let pkt = parse(&p).unwrap();
        assert_eq!(pkt.transport.dst_port(), Some(SSH_INTERNAL_PORT));
        assert_eq!(&p[40..], before_payload.as_slice());
        assert_eq!(
            u16::from_be_bytes([p[36], p[37]]),
            tcp_ipv4_checksum_of(&p).unwrap()
        );
    }

    #[test]
    fn inbound_rewrites_every_mesh_destination_address() {
        let peer = Ipv4Addr::new(100, 64, 0, 9);
        for local in [Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(100, 65, 0, 1)] {
            let mut packet = sample_tcp(peer, local, 45678, SSH_EXTERNAL_PORT, &[]);
            assert!(rewrite_inbound(&mut packet));
            assert_eq!(
                parse(&packet).unwrap().transport.dst_port(),
                Some(SSH_INTERNAL_PORT)
            );
        }
    }

    #[test]
    fn outbound_rewrites_internal_to_22() {
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer = Ipv4Addr::new(100, 64, 0, 2);
        let mut p = sample_tcp(self_ip, peer, SSH_INTERNAL_PORT, 45678, &[]);
        assert!(rewrite_outbound(&mut p));
        let pkt = parse(&p).unwrap();
        assert_eq!(pkt.transport.src_port(), Some(22));
        assert_eq!(
            u16::from_be_bytes([p[36], p[37]]),
            tcp_ipv4_checksum_of(&p).unwrap()
        );
    }

    #[test]
    fn ignores_other_ports_and_fragments() {
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer = Ipv4Addr::new(100, 64, 0, 2);
        let mut p = sample_tcp(peer, self_ip, 45678, 443, &[]);
        assert!(!rewrite_inbound(&mut p));

        let mut later = sample_tcp(peer, self_ip, 45678, 22, &[]);
        later[6] = 0;
        later[7] = 8;
        assert!(!needs_inbound_rewrite(&later));
        assert!(!rewrite_inbound(&mut later));
    }
}
