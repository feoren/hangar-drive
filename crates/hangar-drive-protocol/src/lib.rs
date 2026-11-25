//! The Hangar Drive protocol: the wire types the desktop app and the sync server exchange, and
//! the version of that protocol.
//!
//! No I/O, no async runtime, no network: the app and the server both depend on this crate and
//! bring those themselves. For now it only describes the server's health endpoint.

#![warn(missing_docs)]

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
