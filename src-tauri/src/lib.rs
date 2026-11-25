//! Hangar Drive backend: owns all file and network access, the frontend only renders.

/// Starts the app and returns once its last window has closed.
pub fn run() -> tauri::Result<()> {
    tauri::Builder::default().run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    fn version_in(json: &str) -> String {
        let value: Value = serde_json::from_str(json).unwrap();
        value["version"].as_str().unwrap().to_owned()
    }

    // The code always carries the upcoming version, in all three places at once: the crate, the
    // Tauri config (installer and window) and package.json (frontend).
    #[test]
    fn crate_tauri_config_and_package_json_carry_the_same_version() {
        let crate_version = env!("CARGO_PKG_VERSION");
        assert_eq!(
            version_in(include_str!("../tauri.conf.json")),
            crate_version,
            "tauri.conf.json"
        );
        assert_eq!(
            version_in(include_str!("../../package.json")),
            crate_version,
            "package.json"
        );
    }
}
