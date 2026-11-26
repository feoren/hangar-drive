//! In-memory rate limiting (one process): fixed windows per key, after the sister relay
//! server's limiter. Keys are hashed with a random secret of this process, so no client address
//! sits in memory in plain text. A restart resets the counters, which is acceptable for one
//! process.
//!
//! The limits are checked in the authorization layer, before a handler reads the body
//! ([`check_address`], [`check_account`], finding M6), so a flood of requests costs no body reads. Each public
//! endpoint is limited twice by address: per address (IPv4, IPv6 /64) and, with a higher limit,
//! per network (IPv4 /16, IPv6 /48), so one network cannot spread its requests over many
//! addresses (finding M1). Sign-in is limited per account only by failed proofs, keyed by
//! account and device and only for devices the account's log lists ([`Scope::ProofFailures`]):
//! nobody can fill that table with invented accounts, and a valid proof never counts.
//!
//! Each scope has its own table with its own size limit, so flooding one scope with random keys
//! cannot lock out another. When a table is full, entries whose window ended are evicted, oldest
//! window first, on every new key (a queue in window order keeps this cheap); if the table is
//! still full, only new keys of that scope are refused, and known keys keep counting. Evicting
//! keys whose window still runs would let an attacker reset their own counter.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use hangar_drive_crypto::{Entropy, OsEntropy};
use sha2::{Digest, Sha256};

use crate::http::access::Handler;

/// Keys remembered per scope.
const MAX_KEYS: usize = 100_000;

/// A limit: `limit` hits per `window_s` seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub limit: u32,
    pub window_s: u64,
}

/// The rate limited endpoints (ADR 0001, section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    ChallengeIp,
    ChallengeNet,
    ProofIp,
    ProofNet,
    /// Failed proofs per account and listed device.
    ProofFailures,
    InviteIp,
    InviteNet,
    PairingIp,
    PairingNet,
    PairingAccount,
    UploadIp,
    UploadAccount,
    /// Every call with a bearer token, per address and network, counted before the token is
    /// looked up (overall review, info).
    CallIp,
    CallNet,
}

impl Scope {
    /// The limits. Sign-in needs a challenge and a proof about once an hour per device, so a
    /// few dozen per minute leaves room for many devices behind one address while making an
    /// online search pointless (the proof is an Ed25519 signature, the invite 128 random bits).
    /// A network gets four times the limit of one address.
    pub const fn rule(self) -> Rule {
        match self {
            Scope::ChallengeIp | Scope::ProofIp => Rule {
                limit: 60,
                window_s: 60,
            },
            Scope::ChallengeNet | Scope::ProofNet => Rule {
                limit: 240,
                window_s: 60,
            },
            // A device whose proofs keep failing is misconfigured or attacked; ten tries in ten
            // minutes are plenty for the first and stop nothing an honest device does.
            Scope::ProofFailures => Rule {
                limit: 10,
                window_s: 600,
            },
            Scope::InviteIp => Rule {
                limit: 10,
                window_s: 3600,
            },
            Scope::InviteNet => Rule {
                limit: 40,
                window_s: 3600,
            },
            Scope::PairingIp => Rule {
                limit: 30,
                window_s: 600,
            },
            Scope::PairingNet => Rule {
                limit: 120,
                window_s: 600,
            },
            Scope::PairingAccount => Rule {
                limit: 240,
                window_s: 60,
            },
            // A first upload of many small files: 20 objects a second, sustained.
            Scope::UploadIp | Scope::UploadAccount => Rule {
                limit: 1200,
                window_s: 60,
            },
            // Above the upload limit with room for the calls around the uploads (missing,
            // commits, feed, records) of several devices behind one address; it only bounds
            // how many token lookups a flood of made-up tokens costs.
            Scope::CallIp => Rule {
                limit: 3000,
                window_s: 60,
            },
            Scope::CallNet => Rule {
                limit: 12000,
                window_s: 60,
            },
        }
    }
}

/// Window start, count and window length of one key.
type Bucket = (u64, u32, u64);

#[derive(Default)]
struct Table {
    buckets: HashMap<[u8; 32], Bucket>,
    /// Window ends in the order the windows started (one rule per scope, so this is also the
    /// order in which they end). Entries of a key whose window was reset since are skipped.
    ends: VecDeque<(u64, [u8; 32])>,
}

impl Table {
    /// Evicts entries whose window ended, oldest first, until there is room or none is left.
    fn evict_ended(&mut self, now_s: u64, max_keys: usize) {
        while self.buckets.len() >= max_keys {
            let Some(&(end, id)) = self.ends.front() else {
                return;
            };
            if end > now_s {
                return;
            }
            self.ends.pop_front();
            if let Some((start, _, window)) = self.buckets.get(&id) {
                if start.saturating_add(*window) == end {
                    self.buckets.remove(&id);
                }
            }
        }
    }

    /// Keeps the queue bounded when keys are reset more often than they are evicted.
    fn compact(&mut self, max_keys: usize) {
        if self.ends.len() > max_keys.saturating_mul(4).max(64) {
            let mut ends: Vec<(u64, [u8; 32])> = self
                .buckets
                .iter()
                .map(|(id, (start, _, window))| (start.saturating_add(*window), *id))
                .collect();
            ends.sort_unstable();
            self.ends = ends.into();
        }
    }
}

pub struct RateLimiter {
    secret: [u8; 32],
    max_keys: usize,
    scopes: Mutex<HashMap<Scope, Table>>,
    /// Factor on every limit (tests lower it).
    scale_down: u32,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::with(MAX_KEYS, 1)
    }

    /// Limits divided by `scale_down` (at least 1), for tests that hit them quickly.
    pub fn scaled(scale_down: u32) -> Self {
        Self::with(MAX_KEYS, scale_down.max(1))
    }

    /// A limiter with `max_keys` keys per scope (tests).
    pub fn with(max_keys: usize, scale_down: u32) -> Self {
        let mut secret = [0u8; 32];
        // Without randomness the hash still hides nothing worse than the address itself.
        let _ = OsEntropy.fill(&mut secret);
        Self {
            secret,
            max_keys,
            scopes: Mutex::new(HashMap::new()),
            scale_down,
        }
    }

    fn rule(&self, scope: Scope) -> Rule {
        let mut rule = scope.rule();
        rule.limit = (rule.limit / self.scale_down).max(1);
        rule
    }

    fn id(&self, key: &[u8]) -> [u8; 32] {
        Sha256::new()
            .chain_update(self.secret)
            .chain_update(key)
            .finalize()
            .into()
    }

    /// Counts one attempt. `false`: the limit is reached.
    pub fn hit(&self, scope: Scope, key: &[u8], now_s: u64) -> bool {
        let rule = self.rule(scope);
        let id = self.id(key);
        let Ok(mut scopes) = self.scopes.lock() else {
            return false;
        };
        let table = scopes.entry(scope).or_default();
        if !table.buckets.contains_key(&id) {
            table.evict_ended(now_s, self.max_keys);
            if table.buckets.len() >= self.max_keys {
                return false;
            }
        }
        let mut fresh = false;
        let entry = table.buckets.entry(id).or_insert_with(|| {
            fresh = true;
            (now_s, 0, rule.window_s)
        });
        if !fresh && now_s.saturating_sub(entry.0) >= rule.window_s {
            *entry = (now_s, 0, rule.window_s);
            fresh = true;
        }
        if entry.1 >= rule.limit {
            return false;
        }
        entry.1 += 1;
        if fresh {
            table
                .ends
                .push_back((now_s.saturating_add(rule.window_s), id));
            table.compact(self.max_keys);
        }
        true
    }

    /// Whether the key has used up its limit, without counting anything.
    pub fn exceeded(&self, scope: Scope, key: &[u8], now_s: u64) -> bool {
        let rule = self.rule(scope);
        let id = self.id(key);
        let Ok(scopes) = self.scopes.lock() else {
            return true;
        };
        scopes
            .get(&scope)
            .and_then(|t| t.buckets.get(&id))
            .is_some_and(|(start, count, window)| {
                now_s.saturating_sub(*start) < *window && *count >= rule.limit
            })
    }

    /// Keys a scope remembers (tests).
    pub fn keys(&self, scope: Scope) -> usize {
        self.scopes
            .lock()
            .ok()
            .and_then(|s| s.get(&scope).map(|t| t.buckets.len()))
            .unwrap_or(0)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Who sent a request, as the limits key it.
pub struct RateKeys<'a> {
    /// The client address key (IPv4, IPv6 /64).
    pub ip: &'a [u8],
    /// The client network key (IPv4 /16, IPv6 /48).
    pub net: &'a [u8],
    /// The session's account, for calls.
    pub account: Option<&'a [u8]>,
}

/// The address limits of a route, checked first, before its handler reads the body and, for a
/// call with a bearer token (`session_call`), before the token is looked up in the database
/// (overall review, info): a flood of made-up tokens costs no database read beyond the limit.
/// The network is counted first, so a network over its limit does not add address keys either.
pub fn check_address(
    limiter: &RateLimiter,
    handler: Handler,
    keys: &RateKeys<'_>,
    session_call: bool,
    now_s: u64,
) -> bool {
    let route: &[(Scope, &[u8])] = match handler {
        Handler::CreateAccount => &[(Scope::InviteNet, keys.net), (Scope::InviteIp, keys.ip)],
        Handler::Challenge => &[
            (Scope::ChallengeNet, keys.net),
            (Scope::ChallengeIp, keys.ip),
        ],
        Handler::Proof => &[(Scope::ProofNet, keys.net), (Scope::ProofIp, keys.ip)],
        Handler::PostPairing => &[(Scope::PairingNet, keys.net), (Scope::PairingIp, keys.ip)],
        Handler::PutObject => &[(Scope::UploadIp, keys.ip)],
        _ => &[],
    };
    let calls: &[(Scope, &[u8])] = if session_call {
        &[(Scope::CallNet, keys.net), (Scope::CallIp, keys.ip)]
    } else {
        &[]
    };
    calls
        .iter()
        .chain(route)
        .all(|(scope, key)| limiter.hit(*scope, key, now_s))
}

/// The account limits of a call, checked once its session is known.
pub fn check_account(limiter: &RateLimiter, handler: Handler, account: &[u8], now_s: u64) -> bool {
    match handler {
        // With a session the account is the key; the address limit is for the public post.
        Handler::GetPairing | Handler::ReservePairing => {
            limiter.hit(Scope::PairingAccount, account, now_s)
        }
        Handler::PutObject => limiter.hit(Scope::UploadAccount, account, now_s),
        _ => true,
    }
}

/// Every limit of a route at once: the address limits ([`check_address`]) and, with
/// `keys.account`, the account limits ([`check_account`]). A route with account limits but no
/// account is refused rather than skipped.
pub fn check_route(
    limiter: &RateLimiter,
    handler: Handler,
    keys: &RateKeys<'_>,
    now_s: u64,
) -> bool {
    if !check_address(limiter, handler, keys, keys.account.is_some(), now_s) {
        return false;
    }
    match keys.account {
        Some(account) => check_account(limiter, handler, account, now_s),
        None => !matches!(
            handler,
            Handler::GetPairing | Handler::ReservePairing | Handler::PutObject
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_window_per_scope_and_key() {
        let rl = RateLimiter::new();
        let limit = Scope::InviteIp.rule().limit;
        for _ in 0..limit {
            assert!(rl.hit(Scope::InviteIp, b"x", 0));
        }
        assert!(!rl.hit(Scope::InviteIp, b"x", 1));
        assert!(rl.exceeded(Scope::InviteIp, b"x", 1));
        assert!(!rl.exceeded(Scope::InviteIp, b"y", 1));
        assert!(rl.hit(Scope::InviteIp, b"y", 1), "another key");
        assert!(rl.hit(Scope::PairingIp, b"x", 1), "another scope");
        assert!(rl.hit(Scope::InviteIp, b"x", 3600), "a new window");
    }

    #[test]
    fn a_full_scope_refuses_only_new_keys() {
        let rl = RateLimiter::with(3, 1);
        assert!(rl.hit(Scope::ProofIp, b"me", 0));
        for i in 0..10u8 {
            rl.hit(Scope::ProofIp, &[i], 1);
        }
        assert!(
            rl.hit(Scope::ProofIp, b"me", 2),
            "a known key keeps counting"
        );
        assert!(!rl.hit(Scope::ProofIp, b"new", 2));
        assert!(
            rl.hit(Scope::ChallengeIp, b"new", 2),
            "other scopes are not affected"
        );
        assert!(
            rl.hit(Scope::ProofIp, b"new", 61),
            "room once windows have ended"
        );
    }

    #[test]
    fn a_full_table_evicts_ended_windows_at_once_and_oldest_first() {
        // Finding M1: the old table swept at most once per second, so within that second every
        // new key was refused although windows had ended. Now each new key evicts what ended.
        let rl = RateLimiter::with(2, 1);
        assert!(rl.hit(Scope::ProofIp, b"a", 0));
        assert!(rl.hit(Scope::ProofIp, b"b", 30));
        assert!(rl.hit(Scope::ProofIp, b"c", 60), "a's window ended at 60");
        assert_eq!(rl.keys(Scope::ProofIp), 2);
        assert!(rl.hit(Scope::ProofIp, b"d", 90), "b's window ended at 90");
        assert!(!rl.hit(Scope::ProofIp, b"e", 91), "c and d still run");
        // A reset window moves its key to the back of the queue.
        assert!(rl.hit(Scope::ProofIp, b"c", 125));
        assert!(
            rl.hit(Scope::ProofIp, b"f", 150),
            "d ended at 150, c runs to 185"
        );
        assert!(rl.hit(Scope::ProofIp, b"c", 151), "c was kept");
    }

    #[test]
    fn many_resets_keep_the_queue_bounded() {
        let rl = RateLimiter::with(4, 1);
        for t in 0..1000u64 {
            assert!(rl.hit(Scope::ProofIp, b"k", t * 60));
        }
        let scopes = rl.scopes.lock().unwrap();
        assert!(scopes[&Scope::ProofIp].ends.len() <= 64);
    }

    #[test]
    fn routes_count_the_network_before_the_address() {
        let rl = RateLimiter::new();
        let net_limit = Scope::ChallengeNet.rule().limit;
        let ip_limit = Scope::ChallengeIp.rule().limit;
        let mut ok = 0;
        for i in 0..net_limit + 10 {
            let ip = i.to_be_bytes();
            let keys = RateKeys {
                ip: &ip,
                net: b"net",
                account: None,
            };
            if check_route(&rl, Handler::Challenge, &keys, 0) {
                ok += 1;
            }
        }
        assert_eq!(
            ok, net_limit,
            "many addresses of one network share its limit"
        );
        assert!(ip_limit < net_limit);
        let keys = RateKeys {
            ip: b"x",
            net: b"other",
            account: None,
        };
        assert!(check_route(&rl, Handler::Health, &keys, 0));
        assert!(
            !check_route(&rl, Handler::PutObject, &keys, 0),
            "an upload without a session account is refused"
        );
    }

    #[test]
    fn scaled_limits_are_at_least_one() {
        let rl = RateLimiter::scaled(u32::MAX);
        assert!(rl.hit(Scope::UploadAccount, b"a", 0));
        assert!(!rl.hit(Scope::UploadAccount, b"a", 0));
    }
}
