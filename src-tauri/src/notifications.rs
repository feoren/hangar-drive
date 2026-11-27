//! Desktop notifications (ux-concept 6.4): only for causes that must interrupt, each at most once
//! while it lasts, conflicts batched to one notification per ten minutes. The policy is pure
//! ([`Policy::on_snapshot`]) and works on the engine's snapshot; [`render`] picks the text from
//! the window's catalog (`texts`), and a cause without a text in the catalog is not shown.
//!
//! Never: "sync finished", "file uploaded", "back online".

use std::collections::{BTreeMap, BTreeSet};

use hangar_drive_sync::api::{Millis, Snapshot, Warning};

/// Conflicts are told at most this often.
pub const CONFLICT_INTERVAL_MS: Millis = 10 * 60 * 1000;

/// What to tell, before it is put into words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// The text key; for a plural text its base.
    pub key: &'static str,
    /// The number for a plural text.
    pub count: Option<u64>,
    /// Placeholders.
    pub params: BTreeMap<&'static str, String>,
    /// The banner it belongs to, for a click.
    pub warning_id: String,
}

/// What was told already.
#[derive(Debug, Default, Clone)]
pub struct Policy {
    told: BTreeSet<String>,
    conflicts_told: u64,
    conflicts_at: Option<Millis>,
}

impl Policy {
    /// The notices a new snapshot calls for. A warning is told once while it lasts; when it is
    /// gone and comes back, it is a new cause.
    pub fn on_snapshot(&mut self, snapshot: &Snapshot, now: Millis) -> Vec<Notice> {
        let mut out = Vec::new();
        let mut present = BTreeSet::new();
        let mut conflicts = 0;
        for warning in &snapshot.warnings {
            if let Warning::Conflicts { count, .. } = warning {
                conflicts = *count;
                continue;
            }
            let Some(notice) = notice_of(warning) else {
                continue;
            };
            present.insert(notice.warning_id.clone());
            if self.told.insert(notice.warning_id.clone()) {
                out.push(notice);
            }
        }
        self.told.retain(|id| present.contains(id));
        // Conflicts: the number of groups that came since the last notice, batched.
        if conflicts < self.conflicts_told {
            self.conflicts_told = conflicts;
        }
        let new = conflicts.saturating_sub(self.conflicts_told);
        let due = self
            .conflicts_at
            .is_none_or(|at| now - at >= CONFLICT_INTERVAL_MS);
        if new > 0 && due {
            out.push(Notice {
                key: "conflict.noticeMany",
                count: Some(new),
                params: BTreeMap::new(),
                warning_id: "conflicts".into(),
            });
            self.conflicts_told = conflicts;
            self.conflicts_at = Some(now);
        }
        out
    }
}

fn notice_of(warning: &Warning) -> Option<Notice> {
    let notice = |key: &'static str, id: &str, params: &[(&'static str, &str)]| Notice {
        key,
        count: None,
        params: params.iter().map(|(k, v)| (*k, (*v).to_owned())).collect(),
        warning_id: id.to_owned(),
    };
    Some(match warning {
        Warning::MassDelete {
            id,
            count,
            folder_name,
            ..
        } => Notice {
            count: Some(*count),
            ..notice("deletes.title", id, &[("folder", folder_name)])
        },
        // The device only when the engine could name exactly one, as in the window's question.
        Warning::IncomingDelete {
            id,
            count,
            folder_name,
            device: Some(device),
            ..
        } => Notice {
            count: Some(*count),
            ..notice(
                "incoming.title",
                id,
                &[("folder", folder_name), ("device", device)],
            )
        },
        Warning::IncomingDelete {
            id,
            count,
            folder_name,
            device: None,
            ..
        } => Notice {
            count: Some(*count),
            ..notice("incoming.titleUnknown", id, &[("folder", folder_name)])
        },
        Warning::MissingFolder {
            id, folder_name, ..
        } => notice("missing.title", id, &[("folder", folder_name)]),
        Warning::OlderState {
            id, folder_name, ..
        } => notice("older.title", id, &[("folder", folder_name)]),
        Warning::RemovedHeads {
            id,
            folder_name,
            devices,
            ..
        } => {
            // A device whose name this device never could read has an empty name; without any
            // name left the text without placeholders is used.
            let named: Vec<&str> = devices
                .iter()
                .map(|d| d.trim())
                .filter(|d| !d.is_empty())
                .collect();
            if named.is_empty() {
                notice("heads.title", id, &[])
            } else {
                notice(
                    "removedHeads.title",
                    id,
                    &[("folder", folder_name), ("device", &named.join(", "))],
                )
            }
        }
        // Without the device (the folder is not synced here, or its newest changes have not
        // arrived) the folder is named, as in the window's banner.
        Warning::Suspect {
            id,
            device_name,
            folder_name,
            ..
        } if device_name.trim().is_empty() => {
            notice("suspect.titleFolder", id, &[("folder", folder_name)])
        }
        Warning::Suspect {
            id,
            device_name,
            folder_name,
            ..
        } => notice(
            "suspect.title",
            id,
            &[("device", device_name), ("folder", folder_name)],
        ),
        Warning::QuotaFull { id } => notice("quotaFull.title", id, &[]),
        Warning::ServerDisk { id } => notice("serverDisk.title", id, &[]),
        Warning::DiskFull { id, .. } => notice("disk.title", id, &[]),
        _ => return None,
    })
}

/// The title and body of a notice in `language`; `None` when the catalog has no text for it.
pub fn render(language: &str, notice: &Notice) -> Option<(String, String)> {
    let text = match notice.count {
        Some(n) => crate::texts::plural(language, notice.key, n),
        None => crate::texts::text(language, notice.key),
    }?;
    let mut params = notice.params.clone();
    if let Some(n) = notice.count {
        params.insert("count", n.to_string());
    }
    let title = crate::texts::text(language, "app.name").unwrap_or("Hangar Drive");
    Some((
        title.to_owned(),
        crate::texts::fill(language, text, &params),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_drive_sync::api::*;

    fn snapshot(warnings: Vec<Warning>) -> Snapshot {
        Snapshot {
            setup: SetupState::Done,
            sync: SyncSummary {
                connection: Connection::Online,
                pause: None,
                pending_files: 0,
                bytes_left: 0,
                last_sync: None,
                last_file: None,
                waiting_metered: 0,
                waiting_budget: 0,
            },
            folders: Vec::new(),
            activity: Vec::new(),
            warnings,
            notices: Vec::new(),
            storage: None,
            account: None,
            remote_folders: Vec::new(),
            deleted_folders: Vec::new(),
            env: Environment { camera: false },
        }
    }

    fn missing() -> Warning {
        Warning::MissingFolder {
            id: "missing-1".into(),
            folder_id: "1".into(),
            folder_name: "Docs".into(),
        }
    }

    fn conflicts(count: u64) -> Warning {
        Warning::Conflicts {
            id: "conflicts".into(),
            count,
        }
    }

    #[test]
    fn a_cause_is_told_once_while_it_lasts() {
        let mut policy = Policy::default();
        let first = policy.on_snapshot(&snapshot(vec![missing()]), 0);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].key, "missing.title");
        assert!(policy.on_snapshot(&snapshot(vec![missing()]), 1).is_empty());
        // Gone, then back: a new cause.
        assert!(policy.on_snapshot(&snapshot(vec![]), 2).is_empty());
        assert_eq!(policy.on_snapshot(&snapshot(vec![missing()]), 3).len(), 1);
        // Quiet banners never interrupt.
        let quiet = Warning::Names {
            id: "names".into(),
            count: 2,
        };
        assert!(policy
            .on_snapshot(&snapshot(vec![missing(), quiet]), 4)
            .is_empty());
    }

    // A missing recovery code is not urgent (the tray shows "needs you" and the window's banner
    // offers a new code), and a pending recovery and folders unreadable after a recovery resolve
    // by themselves: none of them interrupts.
    #[test]
    fn the_recovery_warnings_raise_no_notice() {
        let mut policy = Policy::default();
        let warnings = vec![
            Warning::NoRecoveryCode {
                id: "noRecoveryCode".into(),
            },
            Warning::RecoveryPending {
                id: "recoveryPending".into(),
            },
            Warning::FoldersUnreadable {
                id: "foldersUnreadable".into(),
                folders: vec!["Docs".into()],
                folder_list: true,
            },
        ];
        assert!(policy.on_snapshot(&snapshot(warnings), 0).is_empty());
    }

    #[test]
    fn conflicts_are_batched_to_one_notice_per_ten_minutes() {
        let mut policy = Policy::default();
        let told = policy.on_snapshot(&snapshot(vec![conflicts(2)]), 0);
        assert_eq!(told.len(), 1);
        assert_eq!(told[0].count, Some(2));
        // Three more within ten minutes: nothing yet.
        assert!(policy
            .on_snapshot(&snapshot(vec![conflicts(5)]), 60_000)
            .is_empty());
        // After the interval, only the new ones.
        let later = policy.on_snapshot(&snapshot(vec![conflicts(5)]), CONFLICT_INTERVAL_MS);
        assert_eq!(later[0].count, Some(3));
        // Resolved ones lower the count; a new one after that is told again.
        assert!(policy
            .on_snapshot(&snapshot(vec![conflicts(1)]), 2 * CONFLICT_INTERVAL_MS)
            .is_empty());
        let again = policy.on_snapshot(&snapshot(vec![conflicts(2)]), 3 * CONFLICT_INTERVAL_MS);
        assert_eq!(again[0].count, Some(1));
    }

    #[test]
    fn removed_heads_without_a_name_use_the_plain_title() {
        let heads = |devices: Vec<String>| Warning::RemovedHeads {
            id: "heads-1".into(),
            folder_id: "1".into(),
            folder_name: "Docs".into(),
            devices,
            count: 1,
        };
        let mut policy = Policy::default();
        let told = policy.on_snapshot(&snapshot(vec![heads(vec![String::new(), " ".into()])]), 0);
        assert_eq!(told[0].key, "heads.title");
        let (_, body) = render("en", &told[0]).unwrap();
        assert!(!body.contains('{') && !body.contains(", "), "{body}");
        let mut policy = Policy::default();
        let told = policy.on_snapshot(
            &snapshot(vec![heads(vec![String::new(), "Old Laptop".into()])]),
            0,
        );
        assert_eq!(told[0].key, "removedHeads.title");
        let (_, body) = render("en", &told[0]).unwrap();
        assert!(
            body.contains("Old Laptop") && body.contains("Docs"),
            "{body}"
        );
        assert!(
            !body.contains(", Old") && !body.contains("Laptop, "),
            "{body}"
        );
    }

    // ADR 0001, section 5: every device is told of a suspected attack, also one that cannot
    // name the device (the folder is not synced there); it names the folder then.
    #[test]
    fn a_suspect_warning_without_a_device_names_the_folder() {
        let suspect = |device: &str| Warning::Suspect {
            id: format!("suspect-{device}"),
            device_id: String::new(),
            device_name: device.into(),
            folder_id: "1".into(),
            folder_name: "Photos".into(),
            entry_id: "e".into(),
            days: 30,
            until: 0,
            lapsed: false,
        };
        let mut policy = Policy::default();
        let told = policy.on_snapshot(&snapshot(vec![suspect(""), suspect("Old Laptop")]), 0);
        assert_eq!(told[0].key, "suspect.titleFolder");
        let (_, body) = render("en", &told[0]).unwrap();
        assert!(body.contains("Photos") && !body.contains('{'), "{body}");
        assert_eq!(told[1].key, "suspect.title");
        let (_, body) = render("en", &told[1]).unwrap();
        assert!(body.contains("Old Laptop"), "{body}");
    }

    // ADR 0001, amendment "incoming mass deletes": the person is told once, with the device
    // when the engine knows exactly one, else without a name.
    #[test]
    fn held_incoming_deletes_are_told_with_or_without_the_device() {
        let incoming = |device: Option<&str>| Warning::IncomingDelete {
            id: "incomingDelete-1".into(),
            folder_id: "1".into(),
            folder_name: "Fotos".into(),
            device: device.map(str::to_owned),
            device_added: device.map(|_| 0),
            count: 342,
            sample: Vec::new(),
        };
        let mut policy = Policy::default();
        let told = policy.on_snapshot(&snapshot(vec![incoming(Some("Laptop"))]), 0);
        assert_eq!(told.len(), 1);
        assert_eq!(told[0].key, "incoming.title");
        let (_, body) = render("de", &told[0]).unwrap();
        assert_eq!(body, "Laptop hat 342 Dateien in „Fotos“ gelöscht");
        assert!(policy
            .on_snapshot(&snapshot(vec![incoming(Some("Laptop"))]), 1)
            .is_empty());
        let mut policy = Policy::default();
        let told = policy.on_snapshot(&snapshot(vec![incoming(None)]), 0);
        assert_eq!(told[0].key, "incoming.titleUnknown");
        let (_, body) = render("de", &told[0]).unwrap();
        assert_eq!(
            body,
            "Ein anderes Gerät hat 342 Dateien in „Fotos“ gelöscht"
        );
        for lang in crate::texts::LANGUAGES {
            let (_, body) = render(lang, &told[0]).unwrap();
            assert!(
                !body.contains('{') && body.contains("342"),
                "{lang}: {body}"
            );
        }
    }

    #[test]
    fn notices_are_put_into_the_catalog_words() {
        let mut policy = Policy::default();
        let told = policy.on_snapshot(&snapshot(vec![missing(), conflicts(1)]), 0);
        let (title, body) = render("en", &told[0]).unwrap();
        assert_eq!(title, "Hangar Drive");
        assert!(body.contains("Docs"), "{body}");
        let (_, body) = render("de", &told[1]).unwrap();
        assert!(body.starts_with("1 Datei"), "{body}");
        let unknown = Notice {
            key: "no.such.key",
            count: None,
            params: BTreeMap::new(),
            warning_id: "x".into(),
        };
        assert_eq!(render("en", &unknown), None);
    }
}
