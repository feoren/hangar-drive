//! The client address, for rate limits and logs only, never for an access decision.
//!
//! `X-Forwarded-For` counts only when the connection comes from a proxy the operator listed in
//! `HANGAR_DRIVE_TRUSTED_PROXIES` (ADR 0001, section 6). The header is read from the right:
//! every entry a trusted proxy appended is skipped, and the first address that is not a trusted
//! proxy is the client. Entries further left were written by the client itself and are ignored,
//! so a client cannot pick its own rate limit key. With several header lines the lines are read
//! as one list in order.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;

use crate::config::IpNet;

pub fn client_ip(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trusted: &[IpNet],
) -> Option<IpAddr> {
    let peer = peer.map(|p| p.ip())?;
    let is_trusted = |ip: IpAddr| trusted.iter().any(|net| net.contains(ip));
    if !is_trusted(peer) {
        return Some(peer);
    }
    let mut entries: Vec<&str> = Vec::new();
    for line in headers.get_all("x-forwarded-for") {
        let Ok(line) = line.to_str() else {
            return Some(peer);
        };
        entries.extend(line.split(','));
    }
    let mut client = peer;
    for entry in entries.iter().rev() {
        let Ok(ip) = entry.trim().parse::<IpAddr>() else {
            // An entry that is not an address: stop at the last address we could trust.
            break;
        };
        client = ip;
        if !is_trusted(ip) {
            break;
        }
    }
    Some(client)
}

/// The rate limit key of an address: IPv6 per /64, since one connection usually gets a whole
/// /64 and single addresses from it cost nothing.
pub fn rate_key(ip: Option<IpAddr>) -> Vec<u8> {
    match ip {
        Some(IpAddr::V4(v4)) => v4.octets().to_vec(),
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.octets().to_vec(),
            None => v6.octets()[..8].to_vec(),
        },
        None => b"unknown".to_vec(),
    }
}

/// The rate limit key of the client's network: IPv4 per /16, IPv6 per /48 (the usual
/// allocation of one site). Its limit is higher than an address's (finding M1).
pub fn net_key(ip: Option<IpAddr>) -> Vec<u8> {
    let mut key = match ip {
        Some(IpAddr::V4(v4)) => v4.octets()[..2].to_vec(),
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.octets()[..2].to_vec(),
            None => v6.octets()[..6].to_vec(),
        },
        None => b"unknown".to_vec(),
    };
    // Never equal to an address key of the same bytes.
    key.insert(0, b'n');
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(lines: &[&str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for line in lines {
            map.append("x-forwarded-for", line.parse().unwrap());
        }
        map
    }

    fn peer(ip: &str) -> Option<SocketAddr> {
        Some(SocketAddr::new(ip.parse().unwrap(), 1234))
    }

    fn ip(text: &str) -> Option<IpAddr> {
        Some(text.parse().unwrap())
    }

    #[test]
    fn untrusted_peers_cannot_set_their_address() {
        let trusted = vec![IpNet::parse("10.0.0.1").unwrap()];
        let h = headers(&["198.51.100.1"]);
        assert_eq!(
            client_ip(&h, peer("203.0.113.9"), &trusted),
            ip("203.0.113.9")
        );
        assert_eq!(client_ip(&h, peer("203.0.113.9"), &[]), ip("203.0.113.9"));
    }

    #[test]
    fn a_trusted_proxy_names_the_client_and_spoofed_entries_are_ignored() {
        let trusted = vec![IpNet::parse("10.0.0.0/8").unwrap()];
        // The client sent "1.1.1.1" itself; the proxy appended the real address.
        let h = headers(&["1.1.1.1, 198.51.100.7"]);
        assert_eq!(
            client_ip(&h, peer("10.0.0.1"), &trusted),
            ip("198.51.100.7")
        );
        let lines = headers(&["1.1.1.1", "198.51.100.8"]);
        assert_eq!(
            client_ip(&lines, peer("10.0.0.1"), &trusted),
            ip("198.51.100.8")
        );
        // Two proxies in a row.
        let chain = headers(&["1.1.1.1, 198.51.100.9, 10.0.0.2"]);
        assert_eq!(
            client_ip(&chain, peer("10.0.0.1"), &trusted),
            ip("198.51.100.9")
        );
        // No header: the proxy itself.
        assert_eq!(
            client_ip(&HeaderMap::new(), peer("10.0.0.1"), &trusted),
            ip("10.0.0.1")
        );
        // Garbage stops the walk at the last trusted hop.
        let junk = headers(&["198.51.100.1, junk"]);
        assert_eq!(client_ip(&junk, peer("10.0.0.1"), &trusted), ip("10.0.0.1"));
    }

    #[test]
    fn network_keys_group_per_16_and_48() {
        assert_eq!(net_key(ip("203.0.113.7")), net_key(ip("203.0.1.1")));
        assert_ne!(net_key(ip("203.0.113.7")), net_key(ip("203.1.113.7")));
        assert_eq!(
            net_key(ip("2001:db8:1::1")),
            net_key(ip("2001:db8:1:ffff::9"))
        );
        assert_ne!(net_key(ip("2001:db8:1::1")), net_key(ip("2001:db8:2::1")));
        assert_eq!(net_key(ip("::ffff:203.0.113.7")), net_key(ip("203.0.9.9")));
    }

    #[test]
    fn ipv6_keys_group_per_64() {
        assert_eq!(
            rate_key(ip("2001:db8:1:2::1")),
            rate_key(ip("2001:db8:1:2:ffff::9"))
        );
        assert_ne!(
            rate_key(ip("2001:db8:1:2::1")),
            rate_key(ip("2001:db8:1:3::1"))
        );
        assert_eq!(
            rate_key(ip("::ffff:203.0.113.7")),
            rate_key(ip("203.0.113.7"))
        );
    }
}
