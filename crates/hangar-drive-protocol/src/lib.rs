//! The Hangar Drive protocol: the wire types the desktop app and the sync server exchange, and
//! the version of that protocol.
//!
//! No I/O, no async runtime, no network: the app and the server both depend on this crate and
//! bring those themselves.
//!
//! - [`ids`]: account, device, folder and item IDs (16 bytes), object and commit IDs and log
//!   hashes (32 bytes), keys, signatures and tokens, with one canonical text form each.
//! - [`object`]: object types, directory entry kinds and flags, chunk size and limits.
//! - [`name`]: the cross-platform name policy: NFC comparison keys, case and normalization
//!   collisions, names Windows cannot hold, the built-in ignore list.
//! - [`format`](mod@format): the plaintext formats of directory nodes and file manifests.
//! - [`framing`]: the `field(x)` byte framing all formats, hashes and signatures share.
//! - [`api`]: the wire types of the server API and the closed list of error codes.
//!
//! Design: ADR 0001 in `docs/wiki/pages/decisions/0001-foundation.md`.

#![warn(missing_docs)]

pub mod api;
pub mod format;
pub mod framing;
pub mod ids;
pub mod name;
pub mod object;

use serde::{Deserialize, Serialize};

/// The protocol version this crate speaks. A change to the shape of any message or to the
/// meaning of a field needs a new version, so an app can tell whether it understands a server.
pub const PROTOCOL_VERSION: u16 = 1;

/// Path of the health endpoint, answered with [`ServerInfo`] as JSON.
pub const HEALTH_PATH: &str = "/api/v1/health";

/// What a server reports about itself at [`HEALTH_PATH`].
///
/// Unknown fields are ignored when reading, so a newer server can add fields without breaking an
/// older app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    /// Version of the server program (`X.Y.Z`), for display and support only.
    pub version: String,
    /// The [`PROTOCOL_VERSION`] the server speaks.
    pub protocol_version: u16,
}

impl ServerInfo {
    /// Server info for a server of the given program version that speaks this crate's
    /// [`PROTOCOL_VERSION`].
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            protocol_version: PROTOCOL_VERSION,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_carries_this_crates_protocol_version() {
        let info = ServerInfo::new("1.2.3");
        assert_eq!(info.version, "1.2.3");
        assert_eq!(info.protocol_version, PROTOCOL_VERSION);
    }

    #[test]
    fn serializes_to_the_documented_field_names() {
        let json = serde_json::to_value(ServerInfo::new("0.1.0")).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "version": "0.1.0", "protocol_version": PROTOCOL_VERSION })
        );
    }

    #[test]
    fn round_trips_through_json() {
        let info = ServerInfo::new("0.1.0");
        let text = serde_json::to_string(&info).unwrap();
        let back: ServerInfo = serde_json::from_str(&text).unwrap();
        assert_eq!(back, info);
    }

    #[test]
    fn ignores_fields_a_newer_server_adds() {
        let info: ServerInfo = serde_json::from_str(
            r#"{ "version": "9.0.0", "protocol_version": 7, "features": ["later"] }"#,
        )
        .unwrap();
        assert_eq!(info.version, "9.0.0");
        assert_eq!(info.protocol_version, 7);
    }

    #[test]
    fn rejects_a_reply_without_protocol_version() {
        let result = serde_json::from_str::<ServerInfo>(r#"{ "version": "0.1.0" }"#);
        assert!(result.is_err());
    }

    #[test]
    fn health_path_is_versioned() {
        assert_eq!(HEALTH_PATH, "/api/v1/health");
    }
}
