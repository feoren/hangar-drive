//! The two documents the app hands the person: the recovery sheet (ux-concept 4.2, step 2),
//! printed or saved as a text file, and the error report (ux-concept 11: versions, states and
//! error codes, never file names, folder or device names, IDs or keys). The window puts the
//! sheet into words in the person's language (`RecoverySheetDocument`); this module only
//! checks it and lays it out, as plain text or as a page to print with the QR code of its link.

use hangar_drive_sync::api::{FolderStatus, Snapshot};
use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroizing;

/// The recovery code on screen, kept until the check group is confirmed, for "copy".
pub struct ShownCode {
    /// The code, groups joined by `-`.
    pub code: Zeroizing<String>,
    /// The group the person types back, counted from 1.
    pub check_group: u32,
    /// A renewed code of a set-up account: confirming it ends the old code, so the shell asks
    /// natively first (security review M4).
    pub renewal: bool,
}

impl ShownCode {
    /// Whether `typed` is the check group, compared as the engine compares it.
    pub fn group_matches(&self, typed: &str) -> bool {
        let index = usize::try_from(self.check_group.saturating_sub(1)).unwrap_or(usize::MAX);
        self.code
            .split('-')
            .nth(index)
            .is_some_and(|group| !group.is_empty() && typed.trim().to_ascii_uppercase() == group)
    }
}

impl std::fmt::Debug for ShownCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShownCode").finish_non_exhaustive()
    }
}

const MAX_FIELDS: usize = 32;
const MAX_NOTES: usize = 16;
const MAX_TEXT_CHARS: usize = 2048;
const MAX_NAME_CHARS: usize = 120;

/// One labelled line of the sheet.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SheetField {
    pub label: String,
    pub value: String,
}

/// The window's `RecoverySheetDocument`: the sheet in words.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SheetDocument {
    pub language: String,
    pub title: String,
    pub fields: Vec<SheetField>,
    pub notes: Vec<String>,
    pub qr_link: String,
    pub file_name: String,
}

impl std::fmt::Debug for SheetDocument {
    // The fields carry the recovery code.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SheetDocument").finish_non_exhaustive()
    }
}

impl Drop for SheetDocument {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        for field in &mut self.fields {
            field.value.zeroize();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SheetError {
    #[error("the recovery sheet has too many or too long parts")]
    TooLarge,
    #[error("the recovery sheet's link is not a recovery link")]
    NotARecoveryLink,
}

fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_TEXT_CHARS)
        .collect::<String>()
        .trim()
        .to_owned()
}

impl SheetDocument {
    /// Checks the bounds and cleans every text to one line; the QR link must be the sheet's
    /// recovery link, so nothing but that link becomes a code on paper.
    pub fn checked(mut self) -> Result<Self, SheetError> {
        let long = |t: &str| t.chars().count() > MAX_TEXT_CHARS;
        if self.fields.len() > MAX_FIELDS
            || self.notes.len() > MAX_NOTES
            || long(&self.title)
            || self.notes.iter().any(|n| long(n))
            || self.fields.iter().any(|f| long(&f.label) || long(&f.value))
        {
            return Err(SheetError::TooLarge);
        }
        if hangar_drive_sync::links::parse_recovery_link(&self.qr_link).is_err() {
            return Err(SheetError::NotARecoveryLink);
        }
        self.title = one_line(&self.title);
        for field in &mut self.fields {
            field.label = one_line(&field.label);
            field.value = one_line(&field.value);
        }
        for note in &mut self.notes {
            *note = one_line(note);
        }
        self.language = self
            .language
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(35)
            .collect();
        self.file_name = file_name(&self.file_name);
        // The link is printed in groups, so it can be typed from paper; the app removes the
        // spaces when it reads a pasted or typed link.
        let grouped = grouped_link(&self.qr_link);
        for field in &mut self.fields {
            if field.value == self.qr_link {
                field.value = grouped.clone();
            }
        }
        Ok(self)
    }

    /// The sheet as a text file.
    pub fn text(&self) -> Zeroizing<String> {
        let newline = if cfg!(windows) { "\r\n" } else { "\n" };
        let mut out = Zeroizing::new(String::new());
        out.push_str(&self.title);
        out.push_str(newline);
        out.push_str(newline);
        for field in &self.fields {
            out.push_str(&field.label);
            out.push_str(": ");
            out.push_str(&field.value);
            out.push_str(newline);
        }
        out.push_str(newline);
        for note in &self.notes {
            out.push_str(note);
            out.push_str(newline);
        }
        out
    }

    /// The sheet as a page to print: every text escaped, the QR code of the link as inline SVG
    /// (made by the `qrcode` crate here, not by the window), no script, and a policy that
    /// allows nothing but the page's own style.
    pub fn html(&self, qr_svg: &str) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::new());
        out.push_str("<!doctype html><html lang=\"");
        out.push_str(&escape(&self.language));
        out.push_str("\"><head><meta charset=\"utf-8\">");
        out.push_str(
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; \
             style-src 'unsafe-inline'; img-src data:\">",
        );
        out.push_str("<title>");
        out.push_str(&escape(&self.title));
        out.push_str("</title><style>");
        out.push_str(
            "body{font:12pt/1.45 system-ui,sans-serif;margin:2cm;color:#000;background:#fff}\
             h1{font-size:18pt;margin:0 0 1em}dl{display:grid;grid-template-columns:auto 1fr;\
             gap:.35em 1.2em;margin:0 0 1.5em}dt{font-weight:600}dd{margin:0;\
             font-family:ui-monospace,Consolas,monospace;overflow-wrap:anywhere}\
             .qr{width:5cm;height:5cm;margin:0 0 1.5em}.qr svg{width:100%;height:100%}\
             p{margin:.4em 0}.link{font-family:ui-monospace,Consolas,monospace;             word-spacing:.3em;margin:0 0 1.5em}",
        );
        out.push_str("</style></head><body><h1>");
        out.push_str(&escape(&self.title));
        out.push_str("</h1><dl>");
        for field in &self.fields {
            out.push_str("<dt>");
            out.push_str(&escape(&field.label));
            out.push_str("</dt><dd>");
            out.push_str(&escape(&field.value));
            out.push_str("</dd>");
        }
        out.push_str("</dl><div class=\"qr\">");
        out.push_str(strip_xml_declaration(qr_svg));
        out.push_str("</div><p class=\"link\">");
        out.push_str(&escape(&grouped_link(&self.qr_link)));
        out.push_str("</p>");
        for note in &self.notes {
            out.push_str("<p>");
            out.push_str(&escape(note));
            out.push_str("</p>");
        }
        out.push_str("</body></html>");
        out
    }
}

/// A link with its fragment in groups of four characters (`hangar-drive://recover# AQID ...`),
/// for reading and typing from paper.
pub fn grouped_link(link: &str) -> String {
    let Some((head, fragment)) = link.split_once('#') else {
        return link.to_owned();
    };
    let chars: Vec<char> = fragment.chars().collect();
    let groups: Vec<String> = chars.chunks(4).map(|c| c.iter().collect()).collect();
    format!("{head}# {}", groups.join(" "))
}

fn strip_xml_declaration(svg: &str) -> &str {
    match svg.find("<svg") {
        Some(start) => &svg[start..],
        None => "",
    }
}

/// Text for HTML content and attribute values.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// A file name from the window's proposal: no folder, none of the characters a platform
/// refuses, at most 120 characters, ending in `.txt`.
pub fn file_name(proposal: &str) -> String {
    let cleaned: String = proposal
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*') || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .take(MAX_NAME_CHARS)
        .collect();
    let cleaned = cleaned.trim().trim_matches('.').trim().to_owned();
    let base = if cleaned.is_empty() {
        "Hangar Drive".to_owned()
    } else {
        cleaned
    };
    if base.to_ascii_lowercase().ends_with(".txt") {
        base
    } else {
        format!("{base}.txt")
    }
}

/// The kind of a tagged union value (`kind` or `type`), for the report.
fn kind_of(value: &Value) -> String {
    value
        .get("kind")
        .or_else(|| value.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_owned()
}

/// The error report (ux-concept 11): states and codes only.
pub fn error_report(
    version: &str,
    snapshot: Option<&Snapshot>,
    engine_error: Option<&str>,
) -> String {
    let mut out = String::new();
    let mut push = |s: String| {
        out.push_str(&s);
        out.push('\n');
    };
    push(format!("Hangar Drive {version}"));
    push(format!(
        "System: {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    push(format!(
        "Sync engine: {}, protocol {}",
        hangar_drive_sync::engine::EngineCore::version(),
        hangar_drive_protocol::PROTOCOL_VERSION
    ));
    if let Some(error) = engine_error {
        let home = dirs::home_dir();
        let user = std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .ok();
        push(format!(
            "Engine: not started ({})",
            scrub(error, home.as_deref(), user.as_deref())
        ));
    }
    let Some(s) = snapshot else {
        push("Snapshot: none".into());
        return out;
    };
    let json = serde_json::to_value(s).unwrap_or(Value::Null);
    push(format!("Setup: {}", json["setup"].as_str().unwrap_or("?")));
    push(format!(
        "Connection: {}",
        kind_of(&json["sync"]["connection"])
    ));
    push(format!("Paused: {}", s.sync.pause.is_some()));
    push(format!(
        "Pending files: {}, waiting metered: {}, waiting budget: {}",
        s.sync.pending_files, s.sync.waiting_metered, s.sync.waiting_budget
    ));
    push(format!("Folders: {}", s.folders.len()));
    for (i, folder) in s.folders.iter().enumerate() {
        let status = match folder.status {
            FolderStatus::Stopped { .. } => format!(
                "stopped ({})",
                serde_json::to_value(folder.status)
                    .ok()
                    .and_then(|v| v["reason"].as_str().map(str::to_owned))
                    .unwrap_or_default()
            ),
            other => kind_of(&serde_json::to_value(other).unwrap_or(Value::Null)),
        };
        push(format!(
            "  folder {}: {status}, not synced {}",
            i + 1,
            folder.not_synced_count
        ));
    }
    let warnings: Vec<String> = json["warnings"]
        .as_array()
        .map(|a| a.iter().map(kind_of).collect())
        .unwrap_or_default();
    push(format!("Warnings: {}", warnings.join(", ")));
    let notices: Vec<String> = json["notices"]
        .as_array()
        .map(|a| a.iter().map(kind_of).collect())
        .unwrap_or_default();
    push(format!("Notices: {}", notices.join(", ")));
    push(format!(
        "Other devices: {}",
        s.account.as_ref().is_some_and(|a| a.has_other_devices)
    ));
    out
}

/// `text` without the user's name (security review I3): the home folder becomes `~`, the
/// folder after `Users` or `home` in any other path becomes `<user>`, and the account name
/// itself `<user>` wherever it stands. An engine error can name the index path, which lies in
/// the user's profile.
pub fn scrub(text: &str, home: Option<&std::path::Path>, user: Option<&str>) -> String {
    let mut out = text.to_owned();
    if let Some(home) = home {
        let home = home.to_string_lossy();
        if home.len() > 3 {
            for form in [
                home.to_string(),
                home.replace('\\', "/"),
                home.replace('/', "\\"),
            ] {
                out = replace_ignore_case(&out, &form, "~");
            }
        }
    }
    for marker in ["\\Users\\", "/Users/", "/home/", "\\home\\"] {
        out = mask_after(&out, marker);
    }
    if let Some(user) = user.map(str::trim).filter(|u| u.chars().count() >= 3) {
        out = replace_ignore_case(&out, user, "<user>");
    }
    out
}

/// `text` with every ASCII-case-insensitive occurrence of `needle` replaced.
fn replace_ignore_case(text: &str, needle: &str, with: &str) -> String {
    if needle.is_empty() {
        return text.to_owned();
    }
    let lower = text.to_lowercase();
    let wanted = needle.to_lowercase();
    // Lowercasing can change byte lengths outside ASCII; then only exact matches are replaced.
    if lower.len() != text.len() || wanted.len() != needle.len() {
        return text.replace(needle, with);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = 0;
    while let Some(found) = lower[rest..].find(&wanted) {
        let start = rest + found;
        out.push_str(&text[rest..start]);
        out.push_str(with);
        rest = start + needle.len();
    }
    out.push_str(&text[rest..]);
    out
}

/// The path segment after every `marker` (case ignored) replaced by `<user>`.
fn mask_after(text: &str, marker: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let wanted = marker.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut rest = 0;
    while let Some(found) = lower[rest..].find(&wanted) {
        let start = rest + found + marker.len();
        out.push_str(&text[rest..start]);
        let tail = &text[start..];
        let end = tail
            .find(['\\', '/', ' ', '"', '\'', ')', ':'])
            .unwrap_or(tail.len());
        if end > 0 {
            out.push_str("<user>");
        }
        rest = start + end;
    }
    out.push_str(&text[rest..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_drive_sync::api::*;
    use serde_json::json;

    fn sheet_link() -> String {
        use hangar_drive_protocol::ids::{AccountId, LogHash, ServerId};
        hangar_drive_sync::links::recovery_link(&hangar_drive_sync::links::RecoverySheet {
            server_url: hangar_drive_crypto::pairing::parse_server_url("https://drive.example/")
                .unwrap(),
            server: ServerId::from_bytes([0x5e; 16]),
            account: AccountId::from_bytes([0xac; 16]),
            genesis: LogHash::from_bytes([0x61; 32]),
            pin: None,
        })
    }

    fn document(qr_link: &str) -> SheetDocument {
        serde_json::from_value(json!({
            "language": "de",
            "title": "Hangar Drive: Wiederherstellungsblatt",
            "fields": [
                { "label": "Wiederherstellungscode", "value": "D7KQ-M2XP-9H4T-RW8C-ZB3N-F6JA-Q1VE-K5SY" },
                { "label": "Server", "value": "https://drive.example/" },
                { "label": "Gerät", "value": "<b>Laptop</b> & Co" }
            ],
            "notes": ["Bewahre das Blatt auf wie einen Haustürschlüssel.\nZeile"],
            "qrLink": qr_link,
            "fileName": "../Hangar Drive Wiederherstellungsblatt"
        }))
        .unwrap()
    }

    #[test]
    fn the_sheet_is_laid_out_from_the_window_words() {
        let link = sheet_link();
        let mut doc = document(&link);
        doc.fields.push(SheetField {
            label: "Link".into(),
            value: link.clone(),
        });
        let doc = doc.checked().unwrap();
        let grouped = grouped_link(&link);
        assert!(grouped.starts_with("hangar-drive://recover# "));
        assert_eq!(grouped.replace(' ', ""), link);
        assert!(grouped
            .split_once("# ")
            .unwrap()
            .1
            .split(' ')
            .all(|g| (1..=4).contains(&g.len())));
        assert_eq!(doc.fields.last().unwrap().value, grouped);
        assert!(hangar_drive_sync::links::parse_recovery_link(&grouped.replace(' ', "")).is_ok());
        let text = doc.text();
        assert!(text.contains("Wiederherstellungscode: D7KQ-M2XP-9H4T-RW8C-ZB3N-F6JA-Q1VE-K5SY"));
        assert!(
            text.contains("Haustürschlüssel. Zeile"),
            "notes are one line"
        );
        assert_eq!(doc.file_name, "_Hangar Drive Wiederherstellungsblatt.txt");
        let (_, svg) = crate::qr::encode(&doc.qr_link).unwrap();
        let html = doc.html(&svg);
        assert!(html.contains("&lt;b&gt;Laptop&lt;/b&gt; &amp; Co"));
        assert!(!html.contains("<b>Laptop"));
        assert!(html.contains("<svg"));
        assert!(html.contains(&escape(&grouped)));
        assert!(!html.contains("<script"));
        assert!(html.contains("default-src 'none'"));
        assert!(!format!("{doc:?}").contains("D7KQ"));
    }

    #[test]
    fn odd_sheets_are_refused() {
        assert_eq!(
            document("hangar-drive://pair#AQID").checked().unwrap_err(),
            SheetError::NotARecoveryLink
        );
        let mut big = document(&sheet_link());
        big.notes = vec!["x".into(); MAX_NOTES + 1];
        assert_eq!(big.checked().unwrap_err(), SheetError::TooLarge);
        assert_eq!(file_name(""), "Hangar Drive.txt");
        assert_eq!(file_name("a.TXT"), "a.TXT");
        assert_eq!(file_name("C:\\x\\y.txt"), "C__x_y.txt");
    }

    #[test]
    fn the_error_report_names_no_folder_device_or_file() {
        let snapshot = Snapshot {
            setup: SetupState::Done,
            sync: SyncSummary {
                connection: Connection::ServerSilent { since: 5 },
                pause: None,
                pending_files: 3,
                bytes_left: 0,
                last_sync: None,
                last_file: Some(LastFile {
                    name: "secret-plan.docx".into(),
                    at: 1,
                }),
                waiting_metered: 0,
                waiting_budget: 0,
            },
            folders: vec![Folder {
                id: "f0f0".into(),
                name: "Private Docs".into(),
                path: "C:\\Users\\someone\\Private Docs".into(),
                status: FolderStatus::Stopped {
                    reason: StopReasonApi::OlderState,
                },
                freeze_days: None,
                not_synced_count: 2,
            }],
            activity: Vec::new(),
            warnings: vec![Warning::Suspect {
                id: "s".into(),
                device_id: "d1".into(),
                device_name: "Old Laptop".into(),
                folder_id: "f0f0".into(),
                folder_name: "Private Docs".into(),
                entry_id: "e".into(),
                days: 30,
            }],
            notices: vec![ServerNotice::Retained],
            storage: None,
            account: None,
            remote_folders: Vec::new(),
            deleted_folders: Vec::new(),
            env: Environment { camera: false },
        };
        let report = error_report("0.1.0", Some(&snapshot), None);
        for leak in [
            "secret-plan",
            "Private Docs",
            "someone",
            "Old Laptop",
            "f0f0",
            "d1",
        ] {
            assert!(!report.contains(leak), "{leak} in {report}");
        }
        assert!(report.contains("serverSilent"));
        assert!(report.contains("stopped (olderState)"));
        assert!(report.contains("Warnings: suspect"));
        assert!(error_report("0.1.0", None, Some("index locked")).contains("not started"));
    }

    // Security review I3: a path in an engine error keeps no user name.
    #[test]
    fn the_report_drops_user_names_from_paths() {
        let home = std::path::Path::new("C:\\Users\\Jane Doe");
        let error =
            "index: cannot open C:\\Users\\Jane Doe\\AppData\\Local\\Hangar Drive\\index.sqlite3 \
                     (also /home/jdoe/.config and c:\\users\\other\\x, user Jane Doe)";
        let clean = scrub(error, Some(home), Some("Jane Doe"));
        for leak in ["Jane", "jdoe", "other"] {
            assert!(!clean.contains(leak), "{leak} in {clean}");
        }
        assert!(
            clean.contains("~\\AppData\\Local\\Hangar Drive\\index.sqlite3"),
            "{clean}"
        );
        assert!(clean.contains("/home/<user>/.config"), "{clean}");
        assert!(clean.contains("c:\\users\\<user>\\x"), "{clean}");
        // The report applies it to the engine error.
        let report = error_report(
            "0.1.0",
            None,
            Some(&format!("{}\\Hangar Drive locked", home.display())),
        );
        let report_home = dirs::home_dir().map(|h| h.display().to_string());
        if let Some(own) = report_home {
            let report = error_report("0.1.0", None, Some(&format!("{own}/x")));
            assert!(!report.contains(&own), "{report}");
        }
        assert!(!report.contains("Jane"), "{report}");
        assert_eq!(scrub("no path here", None, None), "no path here");
    }
}
