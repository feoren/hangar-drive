//! In-app updates through `tauri-plugin-updater`, which installs an update only when its
//! minisign signature verifies against the public key in tauri.conf.json
//! (`plugins.updater.pubkey`). Until the owner puts a key and an endpoint there, the plugin is not
//! even registered and `install_update` refuses with a clear error: no update ever runs
//! unsigned. How the key is made and kept: docs/wiki/pages/decisions/0002-version-scheme.md,
//! section "Signed updates".

use serde::Serialize;
use serde_json::Value;

/// Whether updates are set up: a public key and at least one endpoint in the updater's
/// plugin configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Updates {
    pub enabled: bool,
}

/// The error `install_update` gives while updates are off.
pub const OFF: &str =
    "updates are off: tauri.conf.json carries no updater public key (plugins.updater.pubkey) and endpoint";

/// Whether the updater configuration `plugins.updater` names a public key and an endpoint.
pub fn configured(plugin_config: Option<&Value>) -> bool {
    let Some(config) = plugin_config else {
        return false;
    };
    let key = config
        .get("pubkey")
        .and_then(Value::as_str)
        .is_some_and(|k| !k.trim().is_empty());
    let endpoints = config
        .get("endpoints")
        .and_then(Value::as_array)
        .is_some_and(|e| !e.is_empty());
    key && endpoints
}

/// What `install_update` did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum UpdateOutcome {
    /// No newer version.
    UpToDate,
    /// The signed update was installed; on Windows the installer ends the app.
    Installed { version: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn updates_stay_off_without_a_key_and_an_endpoint() {
        assert!(!configured(None));
        assert!(!configured(Some(&json!({}))));
        assert!(!configured(Some(
            &json!({ "pubkey": " ", "endpoints": ["https://x/latest.json"] })
        )));
        assert!(!configured(Some(
            &json!({ "pubkey": "RWQ...", "endpoints": [] })
        )));
        assert!(configured(Some(
            &json!({ "pubkey": "RWQ...", "endpoints": ["https://x/latest.json"] })
        )));
        assert_eq!(
            serde_json::to_value(UpdateOutcome::Installed {
                version: "0.2.0".into()
            })
            .unwrap(),
            json!({ "kind": "installed", "version": "0.2.0" })
        );
    }
}
