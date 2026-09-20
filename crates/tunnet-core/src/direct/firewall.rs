//! Userspace stateful firewall for Direct mode.
//!
//! Defaults (authenticated mesh peers):
//! - Outbound: allow all (opens flow)
//! - Inbound from a known mesh peer: allow all (QUIC already gated by PSK/AuthCache)
//! - Inbound without a peer identity: ICMP echo only; TCP/UDP deny
//!
//! Restrict further with local ACL rules (`tunnet firewall`).

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tunnet_common::packet::{FragmentTable, Packet, ResolvedL4, TcpFlags, synthesize_reject};
use tunnet_common::policy::{PortRange, Protocol};
use uuid::Uuid;

use crate::state::StatePaths;

const TCP_ACTIVE_TTL: Duration = Duration::from_secs(300);
const TCP_TIME_WAIT_TTL: Duration = Duration::from_secs(10);
const UDP_TTL: Duration = Duration::from_secs(30);
const ICMP_TTL: Duration = Duration::from_secs(10);
const GC_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallDirection {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallAction {
    Allow,
    Deny,
    /// Silent drop vs. send TCP RST / ICMP unreachable back to the local stack.
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PeerFilter {
    #[default]
    #[serde(alias = "*")]
    Any,
    Endpoint(String),
    Hostname(String),
    NetworkId(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub direction: FirewallDirection,
    pub action: FirewallAction,
    pub protocol: Protocol,
    /// Empty = any port.
    #[serde(default)]
    pub ports: Vec<PortRange>,
    #[serde(default)]
    pub peer: PeerFilter,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
    #[serde(default)]
    pub version: u64,
}

fn default_true() -> bool {
    true
}

/// Empty config: engine applies built-in default policy.
pub fn default_firewall() -> FirewallConfig {
    FirewallConfig {
        enabled: true,
        rules: vec![],
        version: 1,
    }
}

impl FirewallConfig {
    pub fn load(paths: &StatePaths) -> anyhow::Result<Self> {
        Ok(crate::agent_config::load_firewall(paths))
    }

    pub fn save(&self, paths: &StatePaths, network_name: &str) -> anyhow::Result<()> {
        crate::agent_config::save_firewall(paths, network_name, self)
    }

    pub fn add_rule(&mut self, rule: FirewallRule) {
        self.rules.push(rule);
        self.version += 1;
    }

    pub fn remove_at(&mut self, index: usize) -> anyhow::Result<()> {
        if index >= self.rules.len() {
            anyhow::bail!("rule index out of range");
        }
        self.rules.remove(index);
        self.version += 1;
        Ok(())
    }

    pub fn reset(&mut self) {
        *self = default_firewall();
    }
}

pub fn parse_port_spec(s: &str) -> anyhow::Result<Vec<PortRange>> {
    if s.is_empty() || s == "*" {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some((a, b)) = part.split_once('-') {
            let start: u16 = a.parse().context("port range start")?;
            let end: u16 = b.parse().context("port range end")?;
            out.push(PortRange { start, end });
        } else {
            let p: u16 = part.parse().context("port")?;
            out.push(PortRange { start: p, end: p });
        }
    }
    Ok(out)
}

/// Parse peer filter from CLI/IPC: `*`, bare hostname, `endpoint:<hex>`, `host:<name>`, or hex endpoint.
pub fn parse_peer_filter(s: Option<&str>) -> anyhow::Result<PeerFilter> {
    let Some(s) = s.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(PeerFilter::Any);
    };
    if s == "*" || s.eq_ignore_ascii_case("any") {
        return Ok(PeerFilter::Any);
    }
    if let Some(rest) = s.strip_prefix("endpoint:") {
        return Ok(PeerFilter::Endpoint(rest.to_string()));
    }
    if let Some(rest) = s.strip_prefix("host:") {
        return Ok(PeerFilter::Hostname(rest.to_string()));
    }
    if let Some(rest) = s.strip_prefix("hostname:") {
        return Ok(PeerFilter::Hostname(rest.to_string()));
    }
    if let Some(rest) = s.strip_prefix("network:") {
        return Ok(PeerFilter::NetworkId(rest.to_string()));
    }
    // 64-char hex → endpoint id; otherwise treat as hostname.
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(PeerFilter::Endpoint(s.to_string()));
    }
    Ok(PeerFilter::Hostname(s.to_string()))
}

pub fn peer_filter_display(peer: &PeerFilter) -> Option<String> {
    match peer {
        PeerFilter::Any => None,
        PeerFilter::Endpoint(e) => Some(format!("endpoint:{e}")),
        PeerFilter::Hostname(h) => Some(format!("host:{h}")),
        PeerFilter::NetworkId(n) => Some(format!("network:{n}")),
    }
}

pub fn action_display(action: FirewallAction) -> &'static str {
    match action {
        FirewallAction::Allow => "allow",
        FirewallAction::Deny => "deny",
        FirewallAction::Reject => "reject",
    }
}

pub fn direction_display(d: FirewallDirection) -> &'static str {
    match d {
        FirewallDirection::In => "in",
        FirewallDirection::Out => "out",
    }
}

pub const TCP_FIN: u8 = TcpFlags::FIN;
pub const TCP_SYN: u8 = TcpFlags::SYN;
pub const TCP_RST: u8 = TcpFlags::RST;
pub const TCP_ACK: u8 = TcpFlags::ACK;

// ── Conntrack ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    proto: u8,
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
}

impl FlowKey {
    fn forward(src: Ipv4Addr, dst: Ipv4Addr, l4: ResolvedL4) -> Option<Self> {
        let proto = l4.protocol.ip_number()?;
        if l4.protocol.is_icmp() {
            Some(Self {
                proto,
                src: src.min(dst),
                sport: l4.icmp_id.unwrap_or(0),
                dst: src.max(dst),
                dport: 0,
            })
        } else {
            Some(Self {
                proto,
                src,
                sport: l4.src_port.unwrap_or(0),
                dst,
                dport: l4.dst_port.unwrap_or(0),
            })
        }
    }

    fn reverse(src: Ipv4Addr, dst: Ipv4Addr, l4: ResolvedL4) -> Option<Self> {
        if l4.protocol.is_icmp() {
            Self::forward(src, dst, l4)
        } else {
            Some(Self {
                proto: l4.protocol.ip_number()?,
                src: dst,
                sport: l4.dst_port.unwrap_or(0),
                dst: src,
                dport: l4.src_port.unwrap_or(0),
            })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpPhase {
    SynSent,
    Established,
    TimeWait,
}

#[derive(Debug, Clone, Copy)]
enum FlowPhase {
    Tcp(TcpPhase),
    Udp,
    Icmp,
}

#[derive(Debug, Clone)]
struct FlowState {
    phase: FlowPhase,
    last_seen: Instant,
}

// ── Evaluation ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    Inbound,
    Outbound,
}

#[derive(Debug)]
pub enum EvalResult {
    Allow,
    Deny,
    /// Synthesized RST / ICMP unreachable for the local TUN.
    Reject {
        reply: Bytes,
    },
}

pub struct FirewallStats {
    pub conntrack_entries: usize,
    pub local_rules: usize,
    pub suggested_rules: usize,
    pub enabled: bool,
    pub version: u64,
    pub packets_allowed: u64,
    pub packets_denied: u64,
    pub packets_rejected: u64,
}

// ── Engine ────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct FirewallEngine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    enabled: ArcSwap<bool>,
    local_rules: ArcSwap<Vec<FirewallRule>>,
    suggested_rules: ArcSwap<Vec<FirewallRule>>,
    version: AtomicU64,
    conntrack: DashMap<FlowKey, FlowState>,
    fragments: Mutex<FragmentTable>,
    allowed: AtomicU64,
    denied: AtomicU64,
    rejected: AtomicU64,
    /// Self mesh IP for default policy and reject synthesis.
    self_ip: ArcSwap<Ipv4Addr>,
}

impl FirewallEngine {
    pub fn from_config(
        cfg: &FirewallConfig,
        self_ip: Ipv4Addr,
        _self_endpoint_hex: String,
    ) -> Self {
        let engine = Self {
            inner: Arc::new(EngineInner {
                enabled: ArcSwap::from_pointee(cfg.enabled),
                local_rules: ArcSwap::from_pointee(cfg.rules.clone()),
                suggested_rules: ArcSwap::from_pointee(Vec::new()),
                version: AtomicU64::new(cfg.version),
                conntrack: DashMap::new(),
                fragments: Mutex::new(FragmentTable::default()),
                allowed: AtomicU64::new(0),
                denied: AtomicU64::new(0),
                rejected: AtomicU64::new(0),
                self_ip: ArcSwap::from_pointee(self_ip),
            }),
        };
        engine.spawn_gc();
        engine
    }

    fn spawn_gc(&self) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(GC_INTERVAL);
            loop {
                tick.tick().await;
                let now = Instant::now();
                inner.conntrack.retain(|_, st| !is_expired(st, now));
            }
        });
    }

    pub fn reload_local(&self, cfg: &FirewallConfig) {
        self.inner.enabled.store(Arc::new(cfg.enabled));
        self.inner.local_rules.store(Arc::new(cfg.rules.clone()));
        self.inner.version.store(cfg.version, Ordering::Relaxed);
    }

    pub fn set_suggested(&self, rules: Vec<FirewallRule>) {
        self.inner.suggested_rules.store(Arc::new(rules));
    }

    pub fn clear_suggested(&self) {
        self.inner.suggested_rules.store(Arc::new(Vec::new()));
    }

    pub fn flush_conntrack(&self) {
        self.inner.conntrack.clear();
        self.inner.fragments.lock().clear();
    }

    pub fn set_self_ip(&self, ip: Ipv4Addr) {
        self.inner.self_ip.store(Arc::new(ip));
    }

    pub fn stats(&self) -> FirewallStats {
        FirewallStats {
            conntrack_entries: self.inner.conntrack.len(),
            local_rules: self.inner.local_rules.load().len(),
            suggested_rules: self.inner.suggested_rules.load().len(),
            enabled: **self.inner.enabled.load(),
            version: self.inner.version.load(Ordering::Relaxed),
            packets_allowed: self.inner.allowed.load(Ordering::Relaxed),
            packets_denied: self.inner.denied.load(Ordering::Relaxed),
            packets_rejected: self.inner.rejected.load(Ordering::Relaxed),
        }
    }

    pub fn local_rules_snapshot(&self) -> Vec<FirewallRule> {
        self.inner.local_rules.load().as_ref().clone()
    }

    pub fn suggested_rules_snapshot(&self) -> Vec<FirewallRule> {
        self.inner.suggested_rules.load().as_ref().clone()
    }

    /// Evaluate a packet. `peer_endpoint_hex` is the remote mesh peer (if known).
    /// `network_id` is the peer's Direct network (for `PeerFilter::NetworkId`).
    pub fn evaluate(
        &self,
        direction: PacketDirection,
        packet: &Packet<'_>,
        peer_endpoint_hex: Option<&str>,
        peer_hostname: Option<&str>,
        network_id: Option<Uuid>,
    ) -> EvalResult {
        if !**self.inner.enabled.load() {
            self.inner.allowed.fetch_add(1, Ordering::Relaxed);
            return EvalResult::Allow;
        }

        let Some(src) = packet.ip.v4_src() else {
            self.inner.denied.fetch_add(1, Ordering::Relaxed);
            return EvalResult::Deny;
        };
        let Some(dst) = packet.ip.v4_dst() else {
            self.inner.denied.fetch_add(1, Ordering::Relaxed);
            return EvalResult::Deny;
        };
        let Some(l4) = self.inner.fragments.lock().resolve(packet) else {
            self.inner.denied.fetch_add(1, Ordering::Relaxed);
            return EvalResult::Deny;
        };

        if self.conntrack_allows(direction, src, dst, l4) {
            self.inner.allowed.fetch_add(1, Ordering::Relaxed);
            return EvalResult::Allow;
        }

        if let Some(action) = self.match_rules(
            &self.inner.local_rules.load(),
            direction,
            l4,
            peer_endpoint_hex,
            peer_hostname,
            network_id,
        ) {
            return self.apply_action(action, direction, packet, src, dst, l4);
        }
        if let Some(action) = self.match_rules(
            &self.inner.suggested_rules.load(),
            direction,
            l4,
            peer_endpoint_hex,
            peer_hostname,
            network_id,
        ) {
            return self.apply_action(action, direction, packet, src, dst, l4);
        }

        let default = default_policy(direction, l4, peer_endpoint_hex);
        self.apply_action(default, direction, packet, src, dst, l4)
    }

    fn apply_action(
        &self,
        action: FirewallAction,
        direction: PacketDirection,
        packet: &Packet<'_>,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        l4: ResolvedL4,
    ) -> EvalResult {
        match action {
            FirewallAction::Allow => {
                self.open_or_refresh_flow(direction, src, dst, l4);
                self.inner.allowed.fetch_add(1, Ordering::Relaxed);
                EvalResult::Allow
            }
            FirewallAction::Deny => {
                self.inner.denied.fetch_add(1, Ordering::Relaxed);
                EvalResult::Deny
            }
            FirewallAction::Reject => {
                self.inner.rejected.fetch_add(1, Ordering::Relaxed);
                let reply = synthesize_reject(packet).unwrap_or_default();
                EvalResult::Reject { reply }
            }
        }
    }

    fn match_rules(
        &self,
        rules: &[FirewallRule],
        direction: PacketDirection,
        l4: ResolvedL4,
        peer_hex: Option<&str>,
        peer_hostname: Option<&str>,
        network_id: Option<Uuid>,
    ) -> Option<FirewallAction> {
        let want_dir = match direction {
            PacketDirection::Inbound => FirewallDirection::In,
            PacketDirection::Outbound => FirewallDirection::Out,
        };
        for rule in rules {
            if rule.direction != want_dir {
                continue;
            }
            if !l4.protocol.matches_rule(Some(rule.protocol)) {
                continue;
            }
            if !rule.ports.is_empty() && !l4.protocol.is_icmp() {
                let Some(port) = l4.dst_port else {
                    continue;
                };
                if !rule.ports.iter().any(|p| p.contains(port)) {
                    continue;
                }
            }
            if !peer_matches(&rule.peer, peer_hex, peer_hostname, network_id) {
                continue;
            }
            return Some(rule.action);
        }
        None
    }

    fn conntrack_allows(
        &self,
        direction: PacketDirection,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        l4: ResolvedL4,
    ) -> bool {
        let now = Instant::now();
        let Some(fwd) = FlowKey::forward(src, dst, l4) else {
            return false;
        };
        let Some(rev) = FlowKey::reverse(src, dst, l4) else {
            return false;
        };
        let tcp_flags = l4.tcp_flags.map(|f| f.0).unwrap_or(0);

        let key = if self.inner.conntrack.contains_key(&fwd) {
            fwd
        } else if self.inner.conntrack.contains_key(&rev) {
            rev
        } else {
            return false;
        };

        let mut entry = match self.inner.conntrack.get_mut(&key) {
            Some(e) => e,
            None => return false,
        };
        if is_expired(&entry, now) {
            drop(entry);
            self.inner.conntrack.remove(&key);
            return false;
        }

        match entry.phase {
            FlowPhase::Tcp(phase) => match phase {
                TcpPhase::SynSent => {
                    if direction == PacketDirection::Inbound
                        || (tcp_flags & TCP_ACK) != 0
                        || (tcp_flags & TCP_RST) != 0
                    {
                        if (tcp_flags & TCP_RST) != 0 || (tcp_flags & TCP_FIN) != 0 {
                            entry.phase = FlowPhase::Tcp(TcpPhase::TimeWait);
                        } else {
                            entry.phase = FlowPhase::Tcp(TcpPhase::Established);
                        }
                        entry.last_seen = now;
                        return true;
                    }
                    if direction == PacketDirection::Outbound {
                        entry.last_seen = now;
                        return true;
                    }
                    false
                }
                TcpPhase::Established => {
                    if (tcp_flags & TCP_RST) != 0 || (tcp_flags & TCP_FIN) != 0 {
                        entry.phase = FlowPhase::Tcp(TcpPhase::TimeWait);
                    }
                    entry.last_seen = now;
                    true
                }
                TcpPhase::TimeWait => {
                    entry.last_seen = now;
                    true
                }
            },
            FlowPhase::Udp | FlowPhase::Icmp => {
                entry.last_seen = now;
                true
            }
        }
    }

    fn open_or_refresh_flow(
        &self,
        _direction: PacketDirection,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        l4: ResolvedL4,
    ) {
        let now = Instant::now();
        let Some(key) = FlowKey::forward(src, dst, l4) else {
            return;
        };
        let tcp_flags = l4.tcp_flags.map(|f| f.0).unwrap_or(0);

        let phase = match l4.protocol {
            Protocol::Tcp => {
                if (tcp_flags & TCP_SYN) != 0 && (tcp_flags & TCP_ACK) == 0 {
                    FlowPhase::Tcp(TcpPhase::SynSent)
                } else if (tcp_flags & TCP_FIN) != 0 || (tcp_flags & TCP_RST) != 0 {
                    FlowPhase::Tcp(TcpPhase::TimeWait)
                } else {
                    FlowPhase::Tcp(TcpPhase::Established)
                }
            }
            Protocol::Udp => FlowPhase::Udp,
            Protocol::Icmp | Protocol::Icmpv6 => FlowPhase::Icmp,
            Protocol::Any | Protocol::Other(_) => return,
        };

        self.inner
            .conntrack
            .entry(key)
            .and_modify(|st| {
                st.last_seen = now;
                if matches!(st.phase, FlowPhase::Tcp(TcpPhase::SynSent))
                    && matches!(phase, FlowPhase::Tcp(TcpPhase::Established))
                {
                    st.phase = phase;
                }
                if matches!(phase, FlowPhase::Tcp(TcpPhase::TimeWait)) {
                    st.phase = phase;
                }
            })
            .or_insert(FlowState {
                phase,
                last_seen: now,
            });
    }
}
fn peer_matches(
    filter: &PeerFilter,
    peer_hex: Option<&str>,
    peer_hostname: Option<&str>,
    network_id: Option<Uuid>,
) -> bool {
    match filter {
        PeerFilter::Any => true,
        PeerFilter::Endpoint(id) => peer_hex.is_some_and(|h| h.eq_ignore_ascii_case(id)),
        PeerFilter::Hostname(h) => peer_hostname.is_some_and(|n| n.eq_ignore_ascii_case(h)),
        PeerFilter::NetworkId(n) => {
            let Some(id) = network_id else {
                return false;
            };
            id.to_string().eq_ignore_ascii_case(n)
                || n.parse::<Uuid>().ok().is_some_and(|parsed| parsed == id)
        }
    }
}

fn default_policy(
    direction: PacketDirection,
    l4: ResolvedL4,
    peer_endpoint_hex: Option<&str>,
) -> FirewallAction {
    match direction {
        PacketDirection::Outbound => FirewallAction::Allow,
        PacketDirection::Inbound => {
            if peer_endpoint_hex.is_some() {
                return FirewallAction::Allow;
            }
            if l4.protocol == Protocol::Icmp && matches!(l4.icmp_type, Some(0) | Some(8)) {
                FirewallAction::Allow
            } else {
                FirewallAction::Deny
            }
        }
    }
}

fn is_expired(st: &FlowState, now: Instant) -> bool {
    let ttl = match st.phase {
        FlowPhase::Tcp(TcpPhase::TimeWait) => TCP_TIME_WAIT_TTL,
        FlowPhase::Tcp(_) => TCP_ACTIVE_TTL,
        FlowPhase::Udp => UDP_TTL,
        FlowPhase::Icmp => ICMP_TTL,
    };
    now.duration_since(st.last_seen) > ttl
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> FirewallEngine {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.enter();
        FirewallEngine::from_config(
            &default_firewall(),
            Ipv4Addr::new(100, 64, 0, 1),
            "aa".repeat(32),
        )
    }

    fn tcp_syn(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ipv4(src.octets(), dst.octets(), 64)
            .tcp(sport, dport, 1, 1000)
            .syn();
        let mut out = Vec::new();
        b.write(&mut out, &[]).unwrap();
        out
    }

    fn tcp_ack(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ipv4(src.octets(), dst.octets(), 64)
            .tcp(sport, dport, 1, 1000)
            .ack(1);
        let mut out = Vec::new();
        b.write(&mut out, &[]).unwrap();
        out
    }

    fn eval(
        e: &FirewallEngine,
        dir: PacketDirection,
        raw: &[u8],
        peer: Option<&str>,
    ) -> EvalResult {
        let pkt = tunnet_common::packet::parse(raw).unwrap();
        e.evaluate(dir, &pkt, peer, None, None)
    }

    #[test]
    fn parse_tcp() {
        let src = Ipv4Addr::new(100, 64, 0, 1);
        let dst = Ipv4Addr::new(100, 64, 0, 2);
        let p = tcp_syn(src, dst, 12345, 80);
        let v = tunnet_common::packet::parse(&p).unwrap();
        assert_eq!(v.policy_protocol(), Protocol::Tcp);
        assert_eq!(v.transport.src_port(), Some(12345));
        assert_eq!(v.transport.dst_port(), Some(80));
        assert!(v.transport.tcp_flags().unwrap().syn());
    }

    #[test]
    fn outbound_allowed_by_default() {
        let e = engine();
        let p = tcp_syn(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            12345,
            443,
        );
        assert!(matches!(
            eval(&e, PacketDirection::Outbound, &p, Some("peer")),
            EvalResult::Allow
        ));
    }

    #[test]
    fn inbound_tcp_allowed_from_authenticated_peer() {
        let e = engine();
        let p = tcp_syn(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            443,
            12345,
        );
        assert!(matches!(
            eval(&e, PacketDirection::Inbound, &p, Some("peer")),
            EvalResult::Allow
        ));
    }

    #[test]
    fn inbound_tcp_denied_without_peer_identity() {
        let e = engine();
        let p = tcp_syn(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            443,
            12345,
        );
        assert!(matches!(
            eval(&e, PacketDirection::Inbound, &p, None),
            EvalResult::Deny
        ));
    }

    #[test]
    fn return_traffic_allowed_via_conntrack() {
        let e = engine();
        let out = tcp_syn(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            12345,
            443,
        );
        assert!(matches!(
            eval(&e, PacketDirection::Outbound, &out, Some("peer")),
            EvalResult::Allow
        ));
        let ret = tcp_ack(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            443,
            12345,
        );
        assert!(matches!(
            eval(&e, PacketDirection::Inbound, &ret, Some("peer")),
            EvalResult::Allow
        ));
    }

    #[test]
    fn local_deny_outbound() {
        let e = engine();
        e.reload_local(&FirewallConfig {
            enabled: true,
            version: 2,
            rules: vec![FirewallRule {
                direction: FirewallDirection::Out,
                action: FirewallAction::Deny,
                protocol: Protocol::Tcp,
                ports: vec![PortRange {
                    start: 443,
                    end: 443,
                }],
                peer: PeerFilter::Any,
            }],
        });
        let p = tcp_syn(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            12345,
            443,
        );
        assert!(matches!(
            eval(&e, PacketDirection::Outbound, &p, Some("peer")),
            EvalResult::Deny
        ));
    }

    #[test]
    fn later_fragment_cannot_bypass_port_deny() {
        let e = engine();
        e.reload_local(&FirewallConfig {
            enabled: true,
            version: 2,
            rules: vec![FirewallRule {
                direction: FirewallDirection::Out,
                action: FirewallAction::Deny,
                protocol: Protocol::Tcp,
                ports: vec![PortRange {
                    start: 443,
                    end: 443,
                }],
                peer: PeerFilter::Any,
            }],
        });
        let mut later = tcp_syn(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            12345,
            443,
        );
        later[6] = 0;
        later[7] = 8;
        assert!(matches!(
            eval(&e, PacketDirection::Outbound, &later, Some("peer")),
            EvalResult::Deny
        ));
    }

    #[test]
    fn reject_synthesizes_rst() {
        let src = Ipv4Addr::new(100, 64, 0, 2);
        let dst = Ipv4Addr::new(100, 64, 0, 1);
        let p = tcp_syn(src, dst, 9999, 22);
        let v = tunnet_common::packet::parse(&p).unwrap();
        let reply = synthesize_reject(&v).unwrap();
        assert!(reply.len() >= 40);
        assert_eq!(reply[9], 6);
        let parsed = tunnet_common::packet::parse(&reply).unwrap();
        assert!(parsed.transport.tcp_flags().unwrap().rst());
    }
}
