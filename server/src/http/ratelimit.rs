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
//! cannot lock out another. Entries whose window ended are evicted, oldest window first, on
//! every new key (a queue in window order keeps this cheap); if the table is still full, only
//! new keys of that scope are refused, and known keys keep counting. Evicting keys whose window
//! still runs would let an attacker reset their own counter.
//!
//! **Address keys per network** (server security review, MEDIUM 1): an address scope keeps at
//! most [`MAX_ADDRESSES_PER_NET`] address keys of one network at a time. Beyond that, a new
//! address of that network is not tracked, and only the network's limit, which every address
//! route counts first, applies to it. Without the cap one IPv6 /48 could add a new /64 key with
//! every request its network limit allows, a few such networks filled a table of [`MAX_KEYS`]
//! within a minute, and from then on every new honest key was refused. The token lookup scope
//! [`Scope::CallIp`] also fails open when its table is full anyway (many networks at once): it
//! only bounds database reads of made-up tokens, which the network limit still bounds, and
//! refusing there locked out every client whose address was new.
//!
//! **Sessions are not limited by address** (follow-up review M2): a call with a token this
//! server issued (its tag checks out, `sessions::issued_here`) counts per token before the
//! lookup and per device after it ([`check_issued_token`], [`check_session`]); only other tokens
//! count against [`Scope::CallIp`] and [`Scope::CallNet`]. Commits count per device and, with a
//! higher cap, per account (follow-up review L2).
//!
//! **Limits outside the authorization layer:** refused commits ([`commit_refused`]) and device
//! log appends ([`Scope::LogAppendAccount`], [`Scope::LogRotateAccount`]) are counted by their
//! services, which know the outcome or the shape of the call.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use hangar_drive_crypto::{Entropy, OsEntropy};
use sha2::{Digest, Sha256};

use crate::http::access::Handler;

/// Keys remembered per scope.
const MAX_KEYS: usize = 100_000;

/// Address keys one network may have in an address scope at a time (module docs). Far above
/// the addresses of one site that talk to one sync server within a window, far below
/// [`MAX_KEYS`]: a full table needs about 400 networks at once.
pub const MAX_ADDRESSES_PER_NET: u32 = 256;

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
    UploadAccount,
    /// Every call with a bearer token this server did not issue, per address and network,
    /// counted before the token is looked up (overall review, info).
    CallIp,
    CallNet,
    /// Calls with one token this server issued, before it is looked up (follow-up review M2).
    CallToken,
    /// Calls of one device of an account, once its session is known (follow-up review M2).
    CallDevice,
    /// Commit calls per device, before the body is read (server security review, MEDIUM 2;
    /// per device since follow-up review L2).
    CommitDevice,
    /// Commit calls per account, a higher cap over all its devices.
    CommitAccount,
    /// Refused commit calls per device, other than `head_moved`; once used up, every commit
    /// call of the device is refused before its body is read until the window ends.
    CommitRefusedDevice,
    /// Refused commit calls per account, a higher cap over all its devices.
    CommitRefusedAccount,
    /// Device log appends per account that add a device or rotate without a removal. Removals
    /// with their rotation, the rotation a recovery left due and the one append of a recovery
    /// session are never counted, so a stolen device always stays removable.
    LogAppendAccount,
    /// Rotations without a removal per account (a flood of them would fill the log).
    LogRotateAccount,
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
            Scope::UploadAccount => Rule {
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
            // One token of an honest device stays below its device's limit.
            Scope::CallToken | Scope::CallDevice => Rule {
                limit: 3000,
                window_s: 60,
            },
            // A device commits after a batch of changes, a few times a minute at most.
            Scope::CommitDevice => Rule {
                limit: 30,
                window_s: 60,
            },
            // Four devices' worth: one device alone never uses up the account's cap.
            Scope::CommitAccount => Rule {
                limit: 120,
                window_s: 60,
            },
            // An honest device is refused about once per commit it retries (missing objects,
            // one delta mismatch before its full delta); twenty in ten minutes is a device that
            // keeps sending what cannot pass.
            Scope::CommitRefusedDevice => Rule {
                limit: 20,
                window_s: 600,
            },
            // Three such devices before the whole account waits.
            Scope::CommitRefusedAccount => Rule {
                limit: 60,
                window_s: 600,
            },
            // Pairing a new device is one append; thirty an hour is a household's worth.
            Scope::LogAppendAccount => Rule {
                limit: 30,
                window_s: 3600,
            },
            // A rotation without a removal is a manual "rotate now"; one an hour is plenty, and
            // filling the log's reserve with them takes the better part of a year.
            Scope::LogRotateAccount => Rule {
                limit: 1,
                window_s: 3600,
            },
        }
    }

    /// Whether a full table lets new keys through untracked instead of refusing them (module
    /// docs): only the token lookup scope, whose network scope still counts every call.
    const fn fails_open(self) -> bool {
        matches!(self, Scope::CallIp)
    }
}

/// One key's window.
struct Bucket {
    start: u64,
    count: u32,
    window: u64,
    /// The network of an address key, whose count of keys [`Table::groups`] keeps.
    group: Option<[u8; 32]>,
}

#[derive(Default)]
struct Table {
    buckets: HashMap<[u8; 32], Bucket>,
    /// Window ends in the order the windows started (one rule per scope, so this is also the
    /// order in which they end). Entries of a key whose window was reset since are skipped.
    ends: VecDeque<(u64, [u8; 32])>,
    /// Keys per network in `buckets`.
    groups: HashMap<[u8; 32], u32>,
}

impl Table {
    /// Evicts every entry whose window ended, oldest first. Each entry is queued once per
    /// window, so this costs O(1) per hit on average; evicting at once (not only when the
    /// table is full) keeps the per network counts free of keys that no longer limit anything.
    fn evict_ended(&mut self, now_s: u64) {
        while let Some(&(end, id)) = self.ends.front() {
            if end > now_s {
                return;
            }
            self.ends.pop_front();
            let ended = self
                .buckets
                .get(&id)
                .is_some_and(|b| b.start.saturating_add(b.window) == end);
            if ended {
                self.remove(&id);
            }
        }
    }

    fn remove(&mut self, id: &[u8; 32]) {
        let Some(bucket) = self.buckets.remove(id) else {
            return;
        };
        if let Some(group) = bucket.group {
            if let Some(count) = self.groups.get_mut(&group) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.groups.remove(&group);
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
                .map(|(id, b)| (b.start.saturating_add(b.window), *id))
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
        self.hit_in(scope, key, None, now_s)
    }

    /// [`RateLimiter::hit`] for an address `key` of the network `net` (module docs): a network
    /// with [`MAX_ADDRESSES_PER_NET`] keys in the scope adds no further ones, and the call
    /// passes on the network's limit alone.
    pub fn hit_in(&self, scope: Scope, key: &[u8], net: Option<&[u8]>, now_s: u64) -> bool {
        let rule = self.rule(scope);
        let id = self.id(key);
        let group = net.map(|n| self.id(n));
        let Ok(mut scopes) = self.scopes.lock() else {
            return false;
        };
        let table = scopes.entry(scope).or_default();
        if !table.buckets.contains_key(&id) {
            table.evict_ended(now_s);
            if group.is_some_and(|g| {
                table.groups.get(&g).copied().unwrap_or(0) >= MAX_ADDRESSES_PER_NET
            }) {
                return true;
            }
            if table.buckets.len() >= self.max_keys {
                return scope.fails_open();
            }
            if let Some(g) = group {
                *table.groups.entry(g).or_insert(0) += 1;
            }
        }
        let mut fresh = false;
        let entry = table.buckets.entry(id).or_insert_with(|| {
            fresh = true;
            Bucket {
                start: now_s,
                count: 0,
                window: rule.window_s,
                group,
            }
        });
        if !fresh && now_s.saturating_sub(entry.start) >= rule.window_s {
            entry.start = now_s;
            entry.count = 0;
            entry.window = rule.window_s;
            fresh = true;
        }
        if entry.count >= rule.limit {
            return false;
        }
        entry.count += 1;
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
            .is_some_and(|b| now_s.saturating_sub(b.start) < b.window && b.count >= rule.limit)
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
}

/// The address limits of a route, checked first, before its handler reads the body and, for a
/// call with a bearer token this server did not issue (`unknown_token`), before the token is
/// looked up in the database (overall review, info): a flood of made-up tokens costs no
/// database read beyond the limit. The network is counted first, so a network over its limit
/// does not add address keys either; every address scope keeps at most
/// [`MAX_ADDRESSES_PER_NET`] keys per network (module docs).
///
/// A call with a token this server issued (`sessions::issued_here`) skips these limits and is
/// counted per token ([`check_issued_token`]) and per device ([`check_session`]) instead
/// (follow-up review M2): a device behind the same public address as another, honest one could
/// otherwise use up the address's limits with made-up tokens or its own calls, and the honest
/// device could not even remove it.
pub fn check_address(
    limiter: &RateLimiter,
    handler: Handler,
    keys: &RateKeys<'_>,
    unknown_token: bool,
    now_s: u64,
) -> bool {
    // `true`: an address scope, whose keys are grouped by the network key.
    let route: &[(Scope, bool)] = match handler {
        Handler::CreateAccount => &[(Scope::InviteNet, false), (Scope::InviteIp, true)],
        Handler::Challenge => &[(Scope::ChallengeNet, false), (Scope::ChallengeIp, true)],
        Handler::Proof => &[(Scope::ProofNet, false), (Scope::ProofIp, true)],
        Handler::PostPairing => &[(Scope::PairingNet, false), (Scope::PairingIp, true)],
        _ => &[],
    };
    let calls: &[(Scope, bool)] = if unknown_token {
        &[(Scope::CallNet, false), (Scope::CallIp, true)]
    } else {
        &[]
    };
    calls.iter().chain(route).all(|&(scope, address)| {
        if address {
            limiter.hit_in(scope, keys.ip, Some(keys.net), now_s)
        } else {
            limiter.hit(scope, keys.net, now_s)
        }
    })
}

/// The limit of one issued token before it is looked up: it bounds the database reads an
/// expired or revoked token can still cause, without touching anyone else's limits.
pub fn check_issued_token(limiter: &RateLimiter, token: &[u8], now_s: u64) -> bool {
    limiter.hit(Scope::CallToken, token, now_s)
}

/// The key of one device of one account.
fn device_key(account: &[u8], device: &[u8]) -> Vec<u8> {
    [account, device].concat()
}

/// The limits of a call once its session is known: every call per device, and the route's own
/// limits. Commits count per device and, with a higher cap, per account (follow-up review L2):
/// one device can use up only its own share, while the account as a whole still cannot keep the
/// global write lock busy.
pub fn check_session(
    limiter: &RateLimiter,
    handler: Handler,
    account: &[u8],
    device: &[u8],
    now_s: u64,
) -> bool {
    let both = device_key(account, device);
    if !limiter.hit(Scope::CallDevice, &both, now_s) {
        return false;
    }
    match handler {
        // With a session the account is the key; the address limit is for the public post.
        Handler::GetPairing | Handler::ReservePairing => {
            limiter.hit(Scope::PairingAccount, account, now_s)
        }
        Handler::PutObject => limiter.hit(Scope::UploadAccount, account, now_s),
        // A device, or an account, whose commits keep failing waits before it may send the
        // next large body.
        Handler::Commit => {
            !limiter.exceeded(Scope::CommitRefusedDevice, &both, now_s)
                && !limiter.exceeded(Scope::CommitRefusedAccount, account, now_s)
                && !limiter.exceeded(Scope::CommitAccount, account, now_s)
                && limiter.hit(Scope::CommitDevice, &both, now_s)
                && limiter.hit(Scope::CommitAccount, account, now_s)
        }
        _ => true,
    }
}

/// Counts a refused commit of `device` (`service::commits`): per device, and per account with a
/// higher cap.
pub fn commit_refused(limiter: &RateLimiter, account: &[u8], device: &[u8], now_s: u64) {
    limiter.hit(
        Scope::CommitRefusedDevice,
        &device_key(account, device),
        now_s,
    );
    limiter.hit(Scope::CommitRefusedAccount, account, now_s);
}

/// The limits of a public route ([`check_address`]). A route that needs a session is refused
/// here rather than skipped.
pub fn check_route(
    limiter: &RateLimiter,
    handler: Handler,
    keys: &RateKeys<'_>,
    now_s: u64,
) -> bool {
    check_address(limiter, handler, keys, false, now_s)
        && !matches!(
            handler,
            Handler::GetPairing | Handler::ReservePairing | Handler::PutObject | Handler::Commit
        )
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
        };
        assert!(check_route(&rl, Handler::Health, &keys, 0));
        assert!(
            !check_route(&rl, Handler::PutObject, &keys, 0),
            "an upload without a session account is refused"
        );
    }

    /// A session call from address `ip` of network `net`, through the authorization layer's
    /// address check.
    fn call(rl: &RateLimiter, ip: &[u8], net: &[u8], now_s: u64) -> bool {
        let keys = RateKeys { ip, net };
        check_address(rl, Handler::Feed, &keys, true, now_s)
    }

    #[test]
    fn one_network_cannot_flood_an_address_table() {
        // MEDIUM 1: every request of one /48 with a new /64 key used to add a key until the
        // table was full.
        let rl = RateLimiter::new();
        let net_limit = Scope::CallNet.rule().limit;
        let mut passed = 0;
        for i in 0..net_limit + 100 {
            if call(&rl, &i.to_be_bytes(), b"n-attacker", 0) {
                passed += 1;
            }
        }
        assert_eq!(passed, net_limit, "the network limit still holds");
        assert_eq!(
            rl.keys(Scope::CallIp),
            MAX_ADDRESSES_PER_NET as usize,
            "one network keeps at most its share of address keys"
        );
        // Every address scope caps the keys per network, also the public ones (whose network
        // limits are below the cap today, so this is checked on the scope itself).
        for scope in [
            Scope::ChallengeIp,
            Scope::ProofIp,
            Scope::InviteIp,
            Scope::PairingIp,
        ] {
            for i in 0..1000u32 {
                assert!(rl.hit_in(scope, &i.to_be_bytes(), Some(b"n-attacker"), 0));
            }
            assert_eq!(rl.keys(scope), MAX_ADDRESSES_PER_NET as usize, "{scope:?}");
        }
    }

    #[test]
    fn a_tracked_address_keeps_its_own_limit() {
        let rl = RateLimiter::new();
        let limit = Scope::CallIp.rule().limit;
        let passed = (0..limit + 10)
            .filter(|_| call(&rl, b"one", b"n-home", 0))
            .count();
        assert_eq!(passed, limit as usize);
    }

    #[test]
    fn after_a_flood_a_key_of_another_network_gets_through() {
        // Many networks together fill the table; the token lookup scope then fails open for new
        // keys instead of locking every new client out, and the network limit still counts.
        let max = 2 * MAX_ADDRESSES_PER_NET as usize;
        let rl = RateLimiter::with(max, 1);
        for net in 0..4u8 {
            for i in 0..MAX_ADDRESSES_PER_NET + 50 {
                call(
                    &rl,
                    &[&[net][..], &i.to_be_bytes()].concat(),
                    &[b'n', net],
                    0,
                );
            }
        }
        assert_eq!(rl.keys(Scope::CallIp), max, "the table is full");
        assert!(
            call(&rl, b"honest", b"n-honest", 1),
            "a new key of another network passes"
        );
        assert!(
            rl.hit_in(Scope::ProofIp, b"x", Some(b"n"), 1),
            "other scopes are unaffected"
        );
        // Only the token lookup scope fails open; a full sign-in table still refuses new keys.
        let rl = RateLimiter::with(1, 1);
        assert!(rl.hit_in(Scope::ProofIp, b"a", Some(b"n1"), 0));
        assert!(!rl.hit_in(Scope::ProofIp, b"b", Some(b"n2"), 0));
        assert!(rl.hit_in(Scope::CallIp, b"a", Some(b"n1"), 0));
        assert!(rl.hit_in(Scope::CallIp, b"b", Some(b"n2"), 0));
    }

    #[test]
    fn ended_windows_free_a_networks_share() {
        let rl = RateLimiter::new();
        for i in 0..MAX_ADDRESSES_PER_NET {
            assert!(rl.hit_in(Scope::CallIp, &i.to_be_bytes(), Some(b"n"), 0));
        }
        assert_eq!(rl.keys(Scope::CallIp), MAX_ADDRESSES_PER_NET as usize);
        // A new address after the windows ended is tracked again.
        let limit = Scope::CallIp.rule().limit;
        let passed = (0..limit + 1)
            .filter(|_| rl.hit_in(Scope::CallIp, b"late", Some(b"n"), 60))
            .count();
        assert_eq!(passed, limit as usize, "the new address has its own limit");
        assert_eq!(rl.keys(Scope::CallIp), 1);
    }

    fn commit(rl: &RateLimiter, account: &[u8], device: &[u8], now_s: u64) -> bool {
        check_session(rl, Handler::Commit, account, device, now_s)
    }

    #[test]
    fn one_device_uses_up_only_its_own_commits() {
        // Follow-up review L2: the commit limits were per account, so one device blocked the
        // others.
        let rl = RateLimiter::new();
        let per_device = Scope::CommitDevice.rule().limit;
        let passed = (0..per_device + 5)
            .filter(|_| commit(&rl, b"acct", b"dev-a", 0))
            .count();
        assert_eq!(passed, per_device as usize, "commits per device and minute");
        assert!(commit(&rl, b"acct", b"dev-b", 0), "another device commits");
        // The account's cap holds over all its devices.
        let per_account = Scope::CommitAccount.rule().limit;
        let mut passed = per_device + 1;
        for d in 0..20u8 {
            passed += (0..per_device)
                .filter(|_| commit(&rl, b"acct", &[b'x', d], 0))
                .count() as u32;
        }
        assert_eq!(passed, per_account, "the account's cap");
    }

    #[test]
    fn refused_commits_brake_the_device_and_then_the_account() {
        let rl = RateLimiter::new();
        for _ in 0..Scope::CommitRefusedDevice.rule().limit {
            commit_refused(&rl, b"acct", b"bad", 0);
        }
        assert!(!commit(&rl, b"acct", b"bad", 1), "the refused device waits");
        assert!(
            commit(&rl, b"acct", b"good", 1),
            "the other device does not"
        );
        let window = Scope::CommitRefusedDevice.rule().window_s;
        assert!(commit(&rl, b"acct", b"bad", window), "after the window");
        // Several bad devices together brake the account.
        let rl = RateLimiter::new();
        let per_account = Scope::CommitRefusedAccount.rule().limit;
        for i in 0..per_account {
            commit_refused(&rl, b"acct", &i.to_be_bytes(), 0);
        }
        assert!(!commit(&rl, b"acct", b"good", 1));
        assert!(
            commit(&rl, b"other", b"good", 1),
            "another account does not"
        );
    }

    #[test]
    fn issued_tokens_and_sessions_never_touch_the_address_limits() {
        // Follow-up review M2: made-up tokens from one address use up its limits; a session
        // behind that address keeps its own.
        let rl = RateLimiter::new();
        let limit = Scope::CallIp.rule().limit;
        for _ in 0..limit + 10 {
            call(&rl, b"home", b"n-home", 0);
        }
        assert!(
            !call(&rl, b"home", b"n-home", 0),
            "unknown tokens are limited"
        );
        assert!(check_issued_token(&rl, b"token-of-the-honest-device", 0));
        assert!(check_session(&rl, Handler::Feed, b"acct", b"honest", 0));
        // A flooding device with a valid session uses up only its own limits.
        let device_limit = Scope::CallDevice.rule().limit;
        let passed = (0..device_limit + 10)
            .filter(|_| check_session(&rl, Handler::Feed, b"acct", b"thief", 0))
            .count();
        assert_eq!(passed, device_limit as usize);
        assert!(check_session(
            &rl,
            Handler::AppendLog,
            b"acct",
            b"honest",
            0
        ));
    }

    #[test]
    fn scaled_limits_are_at_least_one() {
        let rl = RateLimiter::scaled(u32::MAX);
        assert!(rl.hit(Scope::UploadAccount, b"a", 0));
        assert!(!rl.hit(Scope::UploadAccount, b"a", 0));
    }
}
