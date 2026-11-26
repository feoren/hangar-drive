//! Configuration from environment variables (ADR 0001, section 5: only the operator sets
//! retention, quotas and budgets). An invalid value stops the server at startup with a message
//! naming the variable, instead of running with a value nobody chose.
//!
//! Sizes take a number of bytes or a number with a binary suffix (`KiB`, `MiB`, `GiB`, `TiB`),
//! for example `50GiB`.

use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

/// TCP port the server listens on.
pub const PORT_VAR: &str = "HANGAR_DRIVE_PORT";
/// Folder for the database and the objects.
pub const DATA_DIR_VAR: &str = "HANGAR_DRIVE_DATA_DIR";
/// Days a superseded commit's tree is kept.
pub const RETENTION_DAYS_VAR: &str = "HANGAR_DRIVE_RETENTION_DAYS";
/// Newest heads per folder kept regardless of age, within the minimum count cap.
pub const RETENTION_MIN_COMMITS_VAR: &str = "HANGAR_DRIVE_RETENTION_MIN_COMMITS";
/// Account quota: live bytes per account.
pub const QUOTA_VAR: &str = "HANGAR_DRIVE_QUOTA";
/// Headroom above the quota for directory nodes.
pub const HEADROOM_VAR: &str = "HANGAR_DRIVE_HEADROOM";
/// Cap of the bytes only the minimum commit count retains, per account.
pub const MIN_COUNT_CAP_VAR: &str = "HANGAR_DRIVE_MIN_COUNT_CAP";
/// Bytes an account may make live per rolling 24 hours.
pub const ACCOUNT_BUDGET_VAR: &str = "HANGAR_DRIVE_ACCOUNT_BUDGET";
/// Bytes one device may make live per rolling 24 hours.
pub const DEVICE_BUDGET_VAR: &str = "HANGAR_DRIVE_DEVICE_BUDGET";
/// Free disk space below which every upload is refused.
pub const DISK_RESERVE_VAR: &str = "HANGAR_DRIVE_DISK_RESERVE";
/// Comma-separated addresses or CIDR ranges of reverse proxies whose `X-Forwarded-For` counts.
pub const TRUSTED_PROXIES_VAR: &str = "HANGAR_DRIVE_TRUSTED_PROXIES";
/// PEM certificate chain for TLS in the server (optional; default is a reverse proxy).
pub const TLS_CERT_VAR: &str = "HANGAR_DRIVE_TLS_CERT";
/// PEM private key for TLS in the server.
pub const TLS_KEY_VAR: &str = "HANGAR_DRIVE_TLS_KEY";
/// Minutes between two garbage collection steps.
pub const GC_INTERVAL_VAR: &str = "HANGAR_DRIVE_GC_INTERVAL_MINUTES";
/// Seconds a shutdown waits for open requests and streams.
pub const SHUTDOWN_GRACE_VAR: &str = "HANGAR_DRIVE_SHUTDOWN_GRACE_SECS";
/// Replaced or dropped file objects within an hour that count as a burst.
pub const ANOMALY_MIN_OBJECTS_VAR: &str = "HANGAR_DRIVE_ANOMALY_MIN_OBJECTS";
/// Share of a folder's live file data, in percent, that a burst replaces or drops.
pub const ANOMALY_PERCENT_VAR: &str = "HANGAR_DRIVE_ANOMALY_PERCENT";
/// Bytes of sealed account records one account may store.
pub const RECORD_CAP_VAR: &str = "HANGAR_DRIVE_RECORD_CAP";
/// Requests with large bodies (commits, records) the server works on at once.
pub const HEAVY_REQUESTS_VAR: &str = "HANGAR_DRIVE_HEAVY_REQUESTS";
/// Uploads one account may have in flight at once.
pub const UPLOADS_PER_ACCOUNT_VAR: &str = "HANGAR_DRIVE_UPLOADS_PER_ACCOUNT";
/// Open connections per client address (not counted for trusted proxies).
pub const CONNECTIONS_PER_IP_VAR: &str = "HANGAR_DRIVE_CONNECTIONS_PER_IP";

pub const DEFAULT_PORT: u16 = 8080;
/// Relative to the working directory; the container image sets `/data`, its volume.
pub const DEFAULT_DATA_DIR: &str = "data";
pub const DEFAULT_RETENTION_DAYS: u32 = 30;
pub const DEFAULT_RETENTION_MIN_COMMITS: u32 = 10;
const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;
pub const DEFAULT_QUOTA: u64 = 100 * GIB;
/// The headroom is at least this (ADR 0001, section 5).
pub const MIN_HEADROOM: u64 = 64 * MIB;
pub const DEFAULT_DISK_RESERVE: u64 = GIB;
pub const DEFAULT_GC_INTERVAL_MINUTES: u32 = 60;
pub const DEFAULT_SHUTDOWN_GRACE_SECS: u32 = 10;
pub const DEFAULT_ANOMALY_MIN_OBJECTS: u32 = 500;
pub const DEFAULT_ANOMALY_PERCENT: u32 = 30;
/// The burst threshold never goes below this many file objects (finding L4).
pub const MIN_BURST_OBJECTS: u64 = 20;
pub const DEFAULT_RECORD_CAP: u64 = 64 * MIB;
pub const DEFAULT_HEAVY_REQUESTS: u32 = 4;
pub const DEFAULT_UPLOADS_PER_ACCOUNT: u32 = 8;
pub const DEFAULT_CONNECTIONS_PER_IP: u32 = 64;
/// How long an anomaly pin holds its tree (ADR 0001, section 5).
pub const PIN_DAYS: u64 = 90;
const DAY_MS: u64 = 86_400_000;

/// What the operator decides about storage (ADR 0001, section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// W: how long a superseded tree is kept, in milliseconds.
    pub retention_ms: u64,
    /// The minimum count of heads per folder.
    pub min_commits: u32,
    /// Q.
    pub quota: u64,
    /// H.
    pub headroom: u64,
    /// C.
    pub min_count_cap: u64,
    /// B per account.
    pub account_budget: u64,
    /// Per device.
    pub device_budget: u64,
    /// Free bytes the disk keeps.
    pub disk_reserve: u64,
    /// Burst signal: objects.
    pub anomaly_min_objects: u32,
    /// Burst signal: percent of the folder's live file data and file objects.
    pub anomaly_percent: u32,
    /// R: bytes of sealed records per account.
    pub record_cap: u64,
}

impl Limits {
    /// P = Q + H.
    pub fn pin_cap(&self) -> u64 {
        self.quota.saturating_add(self.headroom)
    }

    /// The defaults for a quota (ADR 0001, section 5): headroom 1% and at least 64 MiB, the
    /// minimum count cap and the account budget equal to the quota, the device budget equal to
    /// the account budget.
    pub fn for_quota(quota: u64) -> Self {
        Self {
            retention_ms: u64::from(DEFAULT_RETENTION_DAYS) * DAY_MS,
            min_commits: DEFAULT_RETENTION_MIN_COMMITS,
            quota,
            headroom: default_headroom(quota),
            min_count_cap: quota,
            account_budget: quota,
            device_budget: quota,
            disk_reserve: DEFAULT_DISK_RESERVE,
            anomaly_min_objects: DEFAULT_ANOMALY_MIN_OBJECTS,
            anomaly_percent: DEFAULT_ANOMALY_PERCENT,
            record_cap: DEFAULT_RECORD_CAP,
        }
    }

    /// How long a pin holds.
    pub fn pin_ms(&self) -> u64 {
        PIN_DAYS * DAY_MS
    }

    /// File objects a burst must replace or drop within the hour (finding L4): the configured
    /// share of the folder's file objects, at least [`MIN_BURST_OBJECTS`], and at most the
    /// configured count. With the defaults that is `min(500, 30 % of the folder)`, at least 20.
    /// Without the share, a folder with fewer files than the count could never set off a pin;
    /// an operator who sets a count below 20 gets that count.
    pub fn burst_objects(&self, folder_file_objects: u64) -> u64 {
        let share = folder_file_objects
            .saturating_mul(u64::from(self.anomaly_percent))
            .div_ceil(100);
        share
            .max(MIN_BURST_OBJECTS)
            .min(u64::from(self.anomaly_min_objects))
    }
}

fn default_headroom(quota: u64) -> u64 {
    (quota / 100).max(MIN_HEADROOM)
}

/// An address or a CIDR range of trusted proxies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// Parses `10.0.0.0/8`, `::1` or `fd00::/8`.
    pub fn parse(text: &str) -> Option<Self> {
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let addr: IpAddr = addr.trim().parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) => p.trim().parse::<u8>().ok().filter(|p| *p <= max)?,
        };
        Some(Self { addr, prefix })
    }

    /// Whether `ip` lies in this range. An IPv4-mapped IPv6 address counts as IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

fn prefix_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = usize::from(prefix / 8);
    let rest = prefix % 8;
    if a[..full] != b[..full] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    (a[full] & mask) == (b[full] & mask)
}

/// Certificate and key files for TLS in the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub port: u16,
    pub data_dir: PathBuf,
    pub limits: Limits,
    pub trusted_proxies: Vec<IpNet>,
    pub tls: Option<TlsFiles>,
    pub gc_interval: Duration,
    pub shutdown_grace: Duration,
    /// Concurrency limits of the HTTP layer (findings M4, M5, M6).
    pub concurrency: Concurrency,
}

/// How much the server works on at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Concurrency {
    /// Commits and record writes at once, whose JSON bodies are held in memory.
    pub heavy_requests: u32,
    /// Uploads in flight per account.
    pub uploads_per_account: u32,
    /// Connections per client address; trusted proxies are exempt.
    pub connections_per_ip: u32,
}

impl Default for Concurrency {
    fn default() -> Self {
        Self {
            heavy_requests: DEFAULT_HEAVY_REQUESTS,
            uploads_per_account: DEFAULT_UPLOADS_PER_ACCOUNT,
            connections_per_ip: DEFAULT_CONNECTIONS_PER_IP,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{PORT_VAR} must be a port number from 1 to 65535, not {0:?}")]
    InvalidPort(String),
    #[error("{DATA_DIR_VAR} must not be empty")]
    EmptyDataDir,
    #[error("{0} must be a whole number in its range, not {1:?}")]
    InvalidNumber(&'static str, String),
    #[error("{0} must be a size such as 1073741824, 512MiB or 50GiB, not {1:?}")]
    InvalidSize(&'static str, String),
    #[error("{TRUSTED_PROXIES_VAR} must list addresses or CIDR ranges, not {0:?}")]
    InvalidProxy(String),
    #[error("{TLS_CERT_VAR} and {TLS_KEY_VAR} must be set together")]
    TlsIncomplete,
    #[error("{DEVICE_BUDGET_VAR} must not exceed {ACCOUNT_BUDGET_VAR}")]
    DeviceBudgetAboveAccount,
}

impl Config {
    /// Reads the configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var_os(name))
    }

    /// Reads the configuration through `lookup`, which returns a variable's value if it is set.
    /// Unset (or empty, except the data folder) variables take their default.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        let text = |name: &str| {
            lookup(name)
                .map(|v| v.to_string_lossy().trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        let port = match text(PORT_VAR) {
            None => DEFAULT_PORT,
            Some(value) => match value.parse::<u16>() {
                Ok(port) if port != 0 => port,
                _ => return Err(ConfigError::InvalidPort(value)),
            },
        };
        let data_dir = match lookup(DATA_DIR_VAR) {
            None => PathBuf::from(DEFAULT_DATA_DIR),
            Some(value) if value.is_empty() => return Err(ConfigError::EmptyDataDir),
            Some(value) => PathBuf::from(value),
        };
        let number = |name: &'static str, default: u32, min: u32, max: u32| match text(name) {
            None => Ok(default),
            Some(value) => value
                .parse::<u32>()
                .ok()
                .filter(|n| (min..=max).contains(n))
                .ok_or(ConfigError::InvalidNumber(name, value)),
        };
        let size = |name: &'static str| -> Result<Option<u64>, ConfigError> {
            text(name)
                .map(|value| parse_size(&value).ok_or(ConfigError::InvalidSize(name, value)))
                .transpose()
        };
        let retention_days = number(RETENTION_DAYS_VAR, DEFAULT_RETENTION_DAYS, 1, 3650)?;
        let min_commits = number(
            RETENTION_MIN_COMMITS_VAR,
            DEFAULT_RETENTION_MIN_COMMITS,
            1,
            10_000,
        )?;
        let quota = size(QUOTA_VAR)?.unwrap_or(DEFAULT_QUOTA);
        let mut limits = Limits::for_quota(quota);
        limits.retention_ms = u64::from(retention_days) * DAY_MS;
        limits.min_commits = min_commits;
        if let Some(headroom) = size(HEADROOM_VAR)? {
            limits.headroom = headroom;
        }
        if let Some(cap) = size(MIN_COUNT_CAP_VAR)? {
            limits.min_count_cap = cap;
        }
        if let Some(budget) = size(ACCOUNT_BUDGET_VAR)? {
            limits.account_budget = budget;
        }
        limits.device_budget = size(DEVICE_BUDGET_VAR)?.unwrap_or(limits.account_budget);
        if limits.device_budget > limits.account_budget {
            return Err(ConfigError::DeviceBudgetAboveAccount);
        }
        if let Some(reserve) = size(DISK_RESERVE_VAR)? {
            limits.disk_reserve = reserve;
        }
        limits.anomaly_min_objects = number(
            ANOMALY_MIN_OBJECTS_VAR,
            DEFAULT_ANOMALY_MIN_OBJECTS,
            1,
            u32::MAX,
        )?;
        limits.anomaly_percent = number(ANOMALY_PERCENT_VAR, DEFAULT_ANOMALY_PERCENT, 1, 100)?;
        if let Some(cap) = size(RECORD_CAP_VAR)? {
            limits.record_cap = cap;
        }
        let concurrency = Concurrency {
            heavy_requests: number(HEAVY_REQUESTS_VAR, DEFAULT_HEAVY_REQUESTS, 1, 1024)?,
            uploads_per_account: number(
                UPLOADS_PER_ACCOUNT_VAR,
                DEFAULT_UPLOADS_PER_ACCOUNT,
                1,
                1024,
            )?,
            connections_per_ip: number(
                CONNECTIONS_PER_IP_VAR,
                DEFAULT_CONNECTIONS_PER_IP,
                1,
                65_536,
            )?,
        };
        let trusted_proxies = match text(TRUSTED_PROXIES_VAR) {
            None => Vec::new(),
            Some(list) => list
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(|p| IpNet::parse(p).ok_or_else(|| ConfigError::InvalidProxy(p.to_owned())))
                .collect::<Result<_, _>>()?,
        };
        let tls = match (text(TLS_CERT_VAR), text(TLS_KEY_VAR)) {
            (None, None) => None,
            (Some(cert), Some(key)) => Some(TlsFiles {
                cert: cert.into(),
                key: key.into(),
            }),
            _ => return Err(ConfigError::TlsIncomplete),
        };
        let gc_minutes = number(GC_INTERVAL_VAR, DEFAULT_GC_INTERVAL_MINUTES, 1, 7 * 24 * 60)?;
        let grace = number(SHUTDOWN_GRACE_VAR, DEFAULT_SHUTDOWN_GRACE_SECS, 1, 600)?;
        Ok(Self {
            port,
            data_dir,
            limits,
            trusted_proxies,
            tls,
            gc_interval: Duration::from_secs(u64::from(gc_minutes) * 60),
            shutdown_grace: Duration::from_secs(u64::from(grace)),
            concurrency,
        })
    }

    /// Address to listen on: every IPv4 interface, as a container needs it. On a host, a reverse
    /// proxy or the port mapping decides who can reach it.
    pub fn bind_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, self.port))
    }

    /// The SQLite file.
    pub fn database_path(&self) -> PathBuf {
        self.data_dir.join("drive.sqlite3")
    }

    /// The object store's root.
    pub fn objects_dir(&self) -> PathBuf {
        self.data_dir.join("objects")
    }
}

/// `123`, `64MiB`, `50 GiB`; also `K`, `M`, `G`, `T` with the same binary meaning.
pub fn parse_size(text: &str) -> Option<u64> {
    let text = text.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (digits, unit) = text.split_at(split);
    let value: u64 = digits.parse().ok()?;
    let factor: u64 = match unit.trim() {
        "" | "B" => 1,
        "K" | "KiB" => 1 << 10,
        "M" | "MiB" => 1 << 20,
        "G" | "GiB" => 1 << 30,
        "T" | "TiB" => 1 << 40,
        _ => return None,
    };
    value.checked_mul(factor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
        Config::from_lookup(|name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        })
    }

    #[test]
    fn uses_the_defaults_without_variables() {
        let config = config(&[]).unwrap();
        assert_eq!(config.port, DEFAULT_PORT);
        assert_eq!(config.data_dir, PathBuf::from(DEFAULT_DATA_DIR));
        let l = config.limits;
        assert_eq!(l.retention_ms, 30 * DAY_MS);
        assert_eq!(l.min_commits, 10);
        assert_eq!(l.quota, DEFAULT_QUOTA);
        assert_eq!(l.headroom, DEFAULT_QUOTA / 100);
        assert_eq!(l.min_count_cap, l.quota);
        assert_eq!(l.account_budget, l.quota);
        assert_eq!(l.device_budget, l.account_budget);
        assert_eq!(l.pin_cap(), l.quota + l.headroom);
        assert!(config.trusted_proxies.is_empty() && config.tls.is_none());
    }

    #[test]
    fn the_burst_threshold_is_a_share_of_the_folder_with_a_floor() {
        let l = Limits::for_quota(GIB);
        // min(500, 30 % of the folder's file objects), at least 20.
        assert_eq!(l.burst_objects(10), 20);
        assert_eq!(l.burst_objects(100), 30);
        assert_eq!(l.burst_objects(1001), 301);
        assert_eq!(l.burst_objects(10_000), 500);
        assert_eq!(l.burst_objects(0), 20);
        let mut low = l;
        low.anomaly_min_objects = 5;
        assert_eq!(
            low.burst_objects(1000),
            5,
            "a lower count set by the operator holds"
        );
        let c = config(&[]).unwrap().concurrency;
        assert_eq!(c, Concurrency::default());
        assert_eq!(c.heavy_requests, 4);
        let c = config(&[(HEAVY_REQUESTS_VAR, "2"), (UPLOADS_PER_ACCOUNT_VAR, "3")])
            .unwrap()
            .concurrency;
        assert_eq!((c.heavy_requests, c.uploads_per_account), (2, 3));
        assert!(matches!(
            config(&[(HEAVY_REQUESTS_VAR, "0")]),
            Err(ConfigError::InvalidNumber(HEAVY_REQUESTS_VAR, _))
        ));
        assert_eq!(config(&[]).unwrap().limits.record_cap, 64 * MIB);
    }

    #[test]
    fn headroom_is_at_least_64_mib() {
        let config = config(&[(QUOTA_VAR, "1GiB")]).unwrap();
        assert_eq!(config.limits.headroom, MIN_HEADROOM);
    }

    #[test]
    fn reads_every_variable() {
        let config = config(&[
            (PORT_VAR, " 9000\n"),
            (DATA_DIR_VAR, "/srv/drive data"),
            (RETENTION_DAYS_VAR, "7"),
            (RETENTION_MIN_COMMITS_VAR, "3"),
            (QUOTA_VAR, "10GiB"),
            (HEADROOM_VAR, "100MiB"),
            (MIN_COUNT_CAP_VAR, "1GiB"),
            (ACCOUNT_BUDGET_VAR, "5GiB"),
            (DEVICE_BUDGET_VAR, "2GiB"),
            (DISK_RESERVE_VAR, "2G"),
            (TRUSTED_PROXIES_VAR, "127.0.0.1, 10.0.0.0/8,fd00::/8"),
            (TLS_CERT_VAR, "/certs/c.pem"),
            (TLS_KEY_VAR, "/certs/k.pem"),
            (GC_INTERVAL_VAR, "5"),
            (SHUTDOWN_GRACE_VAR, "3"),
        ])
        .unwrap();
        assert_eq!(config.port, 9000);
        assert_eq!(config.data_dir, PathBuf::from("/srv/drive data"));
        let l = config.limits;
        assert_eq!(l.retention_ms, 7 * DAY_MS);
        assert_eq!(l.min_commits, 3);
        assert_eq!(l.quota, 10 * GIB);
        assert_eq!(l.headroom, 100 * MIB);
        assert_eq!(l.min_count_cap, GIB);
        assert_eq!(l.account_budget, 5 * GIB);
        assert_eq!(l.device_budget, 2 * GIB);
        assert_eq!(l.disk_reserve, 2 * GIB);
        assert_eq!(config.trusted_proxies.len(), 3);
        assert!(config.tls.is_some());
        assert_eq!(config.gc_interval, Duration::from_secs(300));
        assert_eq!(config.shutdown_grace, Duration::from_secs(3));
    }

    #[test]
    fn device_budget_defaults_to_the_account_budget() {
        let config = config(&[(ACCOUNT_BUDGET_VAR, "3GiB")]).unwrap();
        assert_eq!(config.limits.device_budget, 3 * GIB);
        assert_eq!(
            super::Config::from_lookup(|n| match n {
                ACCOUNT_BUDGET_VAR => Some("1GiB".into()),
                DEVICE_BUDGET_VAR => Some("2GiB".into()),
                _ => None,
            }),
            Err(ConfigError::DeviceBudgetAboveAccount)
        );
    }

    #[test]
    fn rejects_invalid_values() {
        for value in ["0", "65536", "-1", "http"] {
            assert_eq!(
                config(&[(PORT_VAR, value)]),
                Err(ConfigError::InvalidPort(value.to_owned()))
            );
        }
        assert_eq!(
            config(&[(DATA_DIR_VAR, "")]),
            Err(ConfigError::EmptyDataDir)
        );
        assert!(matches!(
            config(&[(QUOTA_VAR, "10 PB")]),
            Err(ConfigError::InvalidSize(QUOTA_VAR, _))
        ));
        assert!(matches!(
            config(&[(RETENTION_DAYS_VAR, "0")]),
            Err(ConfigError::InvalidNumber(RETENTION_DAYS_VAR, _))
        ));
        assert!(matches!(
            config(&[(TRUSTED_PROXIES_VAR, "10.0.0.0/33")]),
            Err(ConfigError::InvalidProxy(_))
        ));
        assert_eq!(
            config(&[(TLS_CERT_VAR, "/c.pem")]),
            Err(ConfigError::TlsIncomplete)
        );
        let message = ConfigError::InvalidPort("x".into()).to_string();
        assert!(message.contains(PORT_VAR), "{message}");
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("123"), Some(123));
        assert_eq!(parse_size("64MiB"), Some(64 << 20));
        assert_eq!(parse_size("2 GiB"), Some(2 << 30));
        assert_eq!(parse_size("1T"), Some(1 << 40));
        assert_eq!(parse_size("GiB"), None);
        assert_eq!(parse_size("1.5GiB"), None);
        assert_eq!(parse_size("99999999999TiB"), None);
    }

    #[test]
    fn proxy_ranges() {
        let net = IpNet::parse("10.0.0.0/8").unwrap();
        assert!(net.contains("10.200.0.1".parse().unwrap()));
        assert!(net.contains("::ffff:10.1.2.3".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));
        let one = IpNet::parse("192.168.1.7").unwrap();
        assert!(one.contains("192.168.1.7".parse().unwrap()));
        assert!(!one.contains("192.168.1.8".parse().unwrap()));
        let v6 = IpNet::parse("fd00::/12").unwrap();
        assert!(v6.contains("fd0f::1".parse().unwrap()));
        assert!(!v6.contains("fd10::1".parse().unwrap()));
        assert!(IpNet::parse("not an ip").is_none());
    }

    #[test]
    fn listens_on_every_ipv4_interface() {
        let config = config(&[(PORT_VAR, "8123")]).unwrap();
        assert_eq!(config.bind_addr(), "0.0.0.0:8123".parse().unwrap());
    }
}
