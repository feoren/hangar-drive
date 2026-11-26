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

    /// X.Y.Z of `X.Y.Z` or `X.Y.Z+B` (ADR 0002); `None` for anything else, such as `X.Y.Z-B`.
    fn base_version(version: &str) -> Option<[u64; 3]> {
        let (base, build) = match version.split_once('+') {
            Some((base, build)) => (base, Some(build)),
            None => (version, None),
        };
        if build.is_some_and(|build| build.is_empty() || !build.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        let mut parts = base.split('.').map(|part| {
            (!part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
                .then(|| part.parse::<u64>().ok())
                .flatten()
        });
        let parsed = [parts.next()??, parts.next()??, parts.next()??];
        parts.next().is_none().then_some(parsed)
    }

    #[test]
    fn base_version_reads_only_the_internal_forms() {
        assert_eq!(base_version("0.12.224+1548"), Some([0, 12, 224]));
        assert_eq!(base_version("0.10.0"), Some([0, 10, 0]));
        assert_eq!(base_version("0.1.0-12"), None);
        assert_eq!(base_version("0.1.0+"), None);
        assert_eq!(base_version("0.1"), None);
        assert_eq!(base_version("0.1.0.4"), None);
    }

    // The internal form is X.Y.Z or X.Y.Z+B: NSIS takes the Windows file version X.Y.Z.B only from
    // the build metadata after "+", and "-B" would make it a pre-release.
    #[test]
    fn the_crate_version_follows_the_scheme() {
        let version = env!("CARGO_PKG_VERSION");
        assert!(base_version(version).is_some(), "{version}");
    }

    // The code carries the upcoming version, so its X.Y.Z is the highest entry in the changelog.
    #[test]
    fn the_crate_version_is_the_highest_changelog_entry() {
        let changelog: Value =
            serde_json::from_str(include_str!("../../src/changelog.json")).unwrap();
        let highest = changelog
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| base_version(entry["version"].as_str().unwrap()).unwrap())
            .max()
            .unwrap();
        assert_eq!(
            base_version(env!("CARGO_PKG_VERSION")).unwrap(),
            highest,
            "changelog.json"
        );
    }
}
