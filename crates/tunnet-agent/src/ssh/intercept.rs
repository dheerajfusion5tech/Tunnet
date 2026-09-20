//! Mesh-local TCP/22 interception for the embedded SSH listener.
//!
//! Only packets whose IPv4 address is an active embedded-SSH binding are
//! rewritten. Routed/subnet destinations and networks with SSH disabled are
//! left alone so native sshd can own ordinary TCP/22.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tunnet_common::packet::{self, Packet, Transport, set_tcp_ipv4_checksum};

pub const SSH_EXTERNAL_PORT: u16 = 22;
pub const SSH_INTERNAL_PORT: u16 = 30022;

#[derive(Clone)]
pub struct SshIntercept {
    addrs: Arc<ArcSwap<HashSet<Ipv4Addr>>>,
}

impl SshIntercept {
    pub fn new() -> Self {
        Self {
            addrs: Arc::new(ArcSwap::from_pointee(HashSet::new())),
        }
    }

    pub fn set(&self, addrs: HashSet<Ipv4Addr>) {
        self.addrs.store(Arc::new(addrs));
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        self.addrs.load().contains(&ip)
    }
}

impl Default for SshIntercept {
    fn default() -> Self {
        Self::new()
    }
}

pub fn rewrite_inbound(packet: &mut [u8], intercept: &SshIntercept) -> bool {
    rewrite(packet, true, intercept)
}

pub fn rewrite_inbound_needed(packet: &[u8], intercept: &SshIntercept) -> bool {
    let Ok(pkt) = packet::parse(packet) else {
        return false;
    };
    eligible(&pkt, true, intercept).is_some()
}

pub fn rewrite_outbound(packet: &mut [u8], intercept: &SshIntercept) -> bool {
    rewrite(packet, false, intercept)
}

fn rewrite(packet: &mut [u8], inbound: bool, intercept: &SshIntercept) -> bool {
    let Ok(pkt) = packet::parse(packet) else {
        return false;
    };
    let Some((offset, new_port)) = eligible(&pkt, inbound, intercept) else {
        return false;
    };
    let ip_len = pkt.ip.header_len();
    let new = new_port as u16;
    packet[offset] = (new >> 8) as u8;
    packet[offset + 1] = (new & 0xff) as u8;
    set_tcp_ipv4_checksum(packet, ip_len)
}

fn eligible(pkt: &Packet<'_>, inbound: bool, intercept: &SshIntercept) -> Option<(usize, usize)> {
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
        let dst = pkt.ip.v4_dst()?;
        if !intercept.contains(dst) || dst_port != SSH_EXTERNAL_PORT {
            return None;
        }
        Some((ip_len + 2, SSH_INTERNAL_PORT as usize))
    } else {
        let src = pkt.ip.v4_src()?;
        if !intercept.contains(src) || src_port != SSH_INTERNAL_PORT {
            return None;
        }
        Some((ip_len, SSH_EXTERNAL_PORT as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use tunnet_common::packet::{parse, tcp_ipv4_checksum_of};

    fn sample_tcp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        let b = PacketBuilder::ipv4(src.octets(), dst.octets(), 64).tcp(sport, dport, 1, 1000);
        let mut out = Vec::new();
        b.write(&mut out, &[]).unwrap();
        out
    }

    fn intercept(addrs: &[Ipv4Addr]) -> SshIntercept {
        let table = SshIntercept::new();
        table.set(addrs.iter().copied().collect());
        table
    }

    #[test]
    fn inbound_rewrites_enabled_local_address() {
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer = Ipv4Addr::new(100, 64, 0, 2);
        let table = intercept(&[self_ip]);
        let mut p = sample_tcp(peer, self_ip, 45678, 22);
        assert!(rewrite_inbound(&mut p, &table));
        assert_eq!(
            parse(&p).unwrap().transport.dst_port(),
            Some(SSH_INTERNAL_PORT)
        );
        assert_eq!(
            u16::from_be_bytes([p[36], p[37]]),
            tcp_ipv4_checksum_of(&p).unwrap()
        );
    }

    #[test]
    fn inbound_skips_disabled_local_address() {
        let local = Ipv4Addr::new(10, 110, 66, 150);
        let other = Ipv4Addr::new(10, 110, 67, 1);
        let peer = Ipv4Addr::new(10, 110, 66, 95);
        let table = intercept(&[other]);
        let mut p = sample_tcp(peer, local, 45678, 22);
        assert!(!rewrite_inbound(&mut p, &table));
        assert_eq!(parse(&p).unwrap().transport.dst_port(), Some(22));
    }

    #[test]
    fn inbound_never_rewrites_routed_subnet_destination() {
        let local = Ipv4Addr::new(10, 110, 66, 150);
        let routed = Ipv4Addr::new(192, 168, 1, 10);
        let peer = Ipv4Addr::new(10, 110, 66, 95);
        let table = intercept(&[local]);
        let mut p = sample_tcp(peer, routed, 45678, 22);
        assert!(!rewrite_inbound(&mut p, &table));
    }

    #[test]
    fn outbound_rewrites_only_embedded_listener_replies() {
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer = Ipv4Addr::new(100, 64, 0, 2);
        let table = intercept(&[self_ip]);
        let mut p = sample_tcp(self_ip, peer, SSH_INTERNAL_PORT, 45678);
        assert!(rewrite_outbound(&mut p, &table));
        assert_eq!(parse(&p).unwrap().transport.src_port(), Some(22));

        let mut unrelated = sample_tcp(Ipv4Addr::new(10, 0, 0, 9), peer, SSH_INTERNAL_PORT, 45678);
        assert!(!rewrite_outbound(&mut unrelated, &table));
    }

    #[test]
    fn contains_tracks_enabled_addresses() {
        let ip = Ipv4Addr::new(10, 110, 66, 1);
        let table = intercept(&[ip]);
        assert!(table.contains(ip));
    }
}
