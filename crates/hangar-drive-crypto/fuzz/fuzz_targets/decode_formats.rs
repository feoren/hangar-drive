//! The protocol crate's plaintext formats: directory nodes and file manifests re-encode to the
//! same bytes; the name policy never panics on any name.
#![no_main]

use hangar_drive_protocol::format::{DirectoryNode, FileManifest};
use hangar_drive_protocol::name::{check_display_name, collision, windows_problem, CaseKeys};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(node) = DirectoryNode::decode(data) {
        assert_eq!(node.encode().expect("a decoded node encodes"), data);
    }
    if let Ok(manifest) = FileManifest::decode(data) {
        assert_eq!(manifest.encode().expect("a decoded manifest encodes"), data);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let (a, b) = text.split_at(
            text.char_indices()
                .nth(text.chars().count() / 2)
                .map_or(0, |(i, _)| i),
        );
        assert_eq!(collision(a, b), collision(b, a));
        let _ = CaseKeys::of(text);
        let _ = windows_problem(text);
        let _ = check_display_name(text, 255);
    }
});
