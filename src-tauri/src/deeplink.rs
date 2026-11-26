//! `hangar-drive://join`, `pair` and `recover` links (ux-concept 4.2 to 4.4). The OS hands an
//! opened link to the running app (the deep link plugin, through the single instance plugin on
//! a second start); this module only recognises the kind and keeps the latest link until the
//! window takes it. Nothing is acted on here: the window fills the matching field, and the
//! engine's strict parsers read the link when the person continues.

use std::sync::Mutex;

use serde::Serialize;

/// The longest link taken (the engine's parsers read at most this, `links::MAX_LINK_LEN`).
pub const MAX_LEN: usize = hangar_drive_sync::links::MAX_LINK_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LinkKind {
    Join,
    Pair,
    Recover,
}

/// A link for the window: its kind, so the right screen opens, and the link itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeepLink {
    pub kind: LinkKind,
    pub link: String,
}

/// The kind of a `hangar-drive://` link; `None` for anything else, a link that is too long or
/// carries white space or control characters.
pub fn classify(text: &str) -> Option<DeepLink> {
    let text = text.trim();
    if text.len() > MAX_LEN || text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let lower = text.get(..24)?.to_ascii_lowercase();
    let kind = [
        ("hangar-drive://join#", LinkKind::Join),
        ("hangar-drive://pair#", LinkKind::Pair),
        ("hangar-drive://recover#", LinkKind::Recover),
    ]
    .into_iter()
    .find(|(prefix, _)| lower.starts_with(prefix))
    .map(|(_, kind)| kind)?;
    Some(DeepLink {
        kind,
        link: text.to_owned(),
    })
}

/// The latest link, until the window takes it.
#[derive(Debug, Default)]
pub struct Pending(Mutex<Option<DeepLink>>);

impl Pending {
    pub fn put(&self, link: DeepLink) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(link);
        }
    }

    pub fn take(&self) -> Option<DeepLink> {
        self.0.lock().ok().and_then(|mut slot| slot.take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_are_recognised_by_kind_and_nothing_else() {
        let join = classify("hangar-drive://join#abc@https://drive.example/").unwrap();
        assert_eq!(join.kind, LinkKind::Join);
        assert_eq!(
            classify(" HANGAR-DRIVE://pair#AQID ").unwrap().kind,
            LinkKind::Pair
        );
        assert_eq!(
            classify("hangar-drive://recover#AQID").unwrap().kind,
            LinkKind::Recover
        );
        for bad in [
            "hangar-drive://other#x",
            "https://drive.example/join#x",
            "hangar-drive://join",
            "hangar-drive://join#a b",
            "",
        ] {
            assert_eq!(classify(bad), None, "{bad:?}");
        }
        assert_eq!(
            classify(&format!("hangar-drive://pair#{}", "A".repeat(MAX_LEN))),
            None
        );
    }

    #[test]
    fn a_pending_link_is_taken_once() {
        let link = classify("hangar-drive://pair#AQID").unwrap();
        let pending = Pending::default();
        pending.put(link.clone());
        assert_eq!(pending.take(), Some(link));
        assert_eq!(pending.take(), None);
    }
}
