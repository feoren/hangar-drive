//! The window's commands: one per method of the `Backend` interface (src/backend/types.ts), in
//! snake case, with the window's camelCase arguments. Each is a thin layer: it reads its input,
//! calls one engine method on the engine thread (`Shell::engine`) or one OS service of the
//! shell (dialogs, clipboard, file manager, tray, autostart), and shapes the answer as the
//! window's decoders read it (src/backend/tauri/decoders.ts). The logic stays in the engine.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hangar_drive_sync::api::{
    AcceptedHeads, ApiResult, BeginError, ConflictGroup, Device, DeviceList, DeviceNameError,
    FixServerError, FolderRefusal, FolderRefusalView, InspectedLink, InviteCheck, InviteError,
    LinkProblem, NameError, NameIssue, NotSyncedEntry, NumberRows, PairError, PauseDuration,
    QrMatrix, RecoverError, RecoveryCodeView, RenameError, RestoreOutcome, ServerNumberView,
    Snapshot, Timeline, TrashItem, VersionTree, Warning,
};
use hangar_drive_sync::error::SyncError;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager as _, State};
use tauri_plugin_autostart::ManagerExt as _;
use tauri_plugin_clipboard_manager::ClipboardExt as _;
use tauri_plugin_dialog::DialogExt as _;
use zeroize::Zeroizing;

use crate::clipboard::{Clipboard, ClipboardError};
use crate::documents::{SheetDocument, ShownCode};
use crate::error::CommandError;
use crate::state::{lock, DialogGuard, Shell};

type Answer<T> = Result<T, CommandError>;
/// Counting local files stops here (ux-concept 6.5 shows "at least").
const COUNT_LIMIT: u64 = 1_000_000;
const TIMELINE_LIMIT: usize = 500;
const TRASH_DEPTH: usize = 200;

// ---------------------------------------------------------------------------------------------
// Shapes the window reads

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum PickResult {
    /// `token` names the place in every later command (security review L2); `path` is for
    /// display only.
    Picked {
        path: String,
        name: String,
        token: String,
    },
    Cancelled,
    Refused {
        reason: FolderRefusal,
        folder: Option<String>,
    },
}

impl From<FolderRefusalView> for PickResult {
    fn from(view: FolderRefusalView) -> Self {
        PickResult::Refused {
            reason: view.reason,
            folder: view.folder,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SaveResult {
    Saved {
        path: String,
    },
    Cancelled,
    InSyncFolder,
    /// The chosen place lies in another sync client's or a cloud folder (OneDrive, Dropbox,
    /// Google Drive, iCloud Drive; security review M2); recovery file only.
    InCloudFolder,
}

#[derive(Debug, Serialize)]
pub struct FolderPlace {
    path: String,
    name: String,
    token: String,
}

#[derive(Debug, Serialize)]
pub struct PairWaiting {
    path: &'static str,
    safety: NumberRows,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountFolder {
    id: String,
    name: String,
    size: u64,
    proposed_path: String,
    proposed_token: String,
}

#[derive(Debug, Serialize)]
pub struct AccountFolders {
    folders: Vec<AccountFolder>,
    free: u64,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum FolderNumber {
    Number { number: NumberRows },
    Offline,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UndoToken {
    undo_token: String,
}

/// The engine's offer with the QR code the shell draws: `qr` as the window's type names it, and
/// `qrSvg`, the same code as an SVG document.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingOffer {
    id: String,
    link: String,
    code: Vec<String>,
    host: String,
    account: String,
    qr: QrMatrix,
    qr_svg: String,
    expires_at: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsView {
    autostart: bool,
    language: String,
    folder_view: String,
}

#[derive(Debug, Serialize)]
pub struct About {
    version: String,
    build: Option<u64>,
    /// Updates are set up (`updater::Updates::enabled`), so the window offers them.
    updates: bool,
}

/// How `deleteFolderEverywhere` ended, after the native confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DeleteOutcome {
    /// The person confirmed; the folder is deleted on every device.
    Deleted,
    /// The person said no in the native dialog; nothing changed.
    Kept,
}

/// How `confirmServerNumber` ended, after the native confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ServerConfirm {
    /// The person confirmed; the key whose number was shown is the pin now.
    Confirmed,
    /// The person said no in the native dialog; nothing changed.
    Declined,
}

/// How an action behind a native confirmation ended (security review M4): removing a device,
/// resetting or disconnecting this device, re-anchoring a folder, turning autostart off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Confirmation {
    /// The person confirmed; the action ran.
    Confirmed,
    /// The person said no in the native dialog; nothing changed.
    Declined,
}

/// How `resetDevice` ended. `RecoveryPending`: a recovery sent its change and this device has
/// not joined yet, so its key may be the account's only one (follow-up review LOW 7); nothing
/// was asked and nothing changed, and the window explains before it offers
/// `resetDeviceDiscardingRecovery`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ResetOutcome {
    /// The person confirmed; this device was reset.
    Confirmed,
    /// The person said no in the native dialog; nothing changed.
    Declined,
    /// Refused while a recovery is pending; nothing changed.
    RecoveryPending,
}

impl From<bool> for Confirmation {
    fn from(yes: bool) -> Self {
        if yes {
            Self::Confirmed
        } else {
            Self::Declined
        }
    }
}

/// How `confirmRecoveryGroup` ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RecoveryCheck {
    /// The group matched: the account came into being, or the renewed code replaced the old one.
    Confirmed,
    /// The typed group is not the asked one.
    Wrong,
    /// The group matched a renewed code, but the person said no in the native dialog; the old
    /// code stays valid.
    Declined,
}

/// Why the last step of a recovery (`finishRecoveryCleanup`) did not add this device, where the
/// window has something to say beyond a general error. `ListChanged`: nothing was written, the
/// person chooses again from the new list. `Unreachable`: the same step is tried again. The
/// others: the step cannot succeed with this sheet, so the window offers to start the recovery
/// again. Any other engine error stays an error. The engine keeps the choice (or, after the
/// append, the pending recovery) in every case but a new start, so trying again is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RecoveryCleanupError {
    /// The account's devices changed since they were shown; nothing was written.
    ListChanged,
    /// The server could not be reached; the step can be tried again.
    Unreachable,
    /// The code stopped working between the steps (another device removed its recovery device).
    Used,
    /// The code does not belong to the account (any more).
    Unknown,
    /// The server's identity does not match the sheet, or the connection is not secure.
    Insecure,
}

impl RecoveryCleanupError {
    /// Only the engine's typed refusals name a reason; a message text never does, so a reworded
    /// error falls back to a plain (repeatable) error instead of a wrong reason.
    fn of(error: &SyncError) -> Option<Self> {
        use hangar_drive_sync::ports::NetError;
        match error {
            SyncError::RecoveryListChanged => Some(Self::ListChanged),
            SyncError::RecoveryCodeUsed => Some(Self::Used),
            SyncError::RecoveryCodeUnknown => Some(Self::Unknown),
            SyncError::Net(NetError::PinMismatch | NetError::Tls(_)) => Some(Self::Insecure),
            SyncError::Net(net) if net.is_transient() => Some(Self::Unreachable),
            _ => None,
        }
    }
}

/// How `resolveMassDelete` ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum MassDeleteOutcome {
    /// Restored or deleted, `count` files.
    Resolved { count: u64 },
    /// "Delete" was declined in the native dialog; the deletions still wait.
    Declined,
}

/// How `acceptRemovedHeads` ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum HeadsAnswer {
    /// The changes are taken in.
    Accepted(AcceptedHeads),
    /// The person said no in the native dialog; the folder stays stopped.
    Declined,
}

/// How joining an account folder at a place ended (`addAccountFolder`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum JoinOutcome {
    /// The folder syncs at the place.
    Joined,
    /// The place holds files and the person chose another folder in the native dialog
    /// (security review H1); nothing was joined.
    Declined,
}

/// Who answers a native confirmation: the operating system's dialog ([`Native`]), or in tests a
/// fixed answer. Generic rather than an enum, so a test never instantiates the native dialog:
/// its Windows API (`TaskDialogIndirect`) needs the Common Controls 6 manifest, which only the
/// app's binary carries, not the test binary.
pub trait Ask: Sync {
    fn ask(
        &self,
        shell: &Shell,
        confirm: crate::confirm::Confirm,
    ) -> impl std::future::Future<Output = Answer<bool>> + Send;
}

/// The operating system's dialog, one at a time, off the async runtime.
pub struct Native<'a>(pub &'a AppHandle);

impl Ask for Native<'_> {
    async fn ask(&self, shell: &Shell, confirm: crate::confirm::Confirm) -> Answer<bool> {
        native_confirm(self.0, shell, confirm).await
    }
}

/// A fixed answer that keeps the questions it was asked.
#[cfg(test)]
pub struct Fixed<'a>(
    pub bool,
    pub &'a std::sync::Mutex<Vec<crate::confirm::Confirm>>,
);

#[cfg(test)]
impl Ask for Fixed<'_> {
    async fn ask(&self, _shell: &Shell, confirm: crate::confirm::Confirm) -> Answer<bool> {
        lock(self.1).push(confirm);
        Ok(self.0)
    }
}

/// How `answerPairRequest` ended, after the native confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PairAnswer {
    /// The device was added.
    Added,
    /// The window or the native dialog declined it.
    Declined,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum PickPurpose {
    New,
    /// A place for an account folder; which folder does not change the check.
    Account {
        #[serde(rename = "folderId")]
        #[allow(dead_code)]
        folder_id: String,
    },
    Find {
        #[serde(rename = "folderId")]
        folder_id: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum PairInput {
    Link {
        link: String,
    },
    /// Read so the window's shape is accepted, then refused (see `start_pairing`).
    #[allow(dead_code)]
    Typed {
        server: String,
        code: String,
    },
}

/// An account folder and the place for it, as a token of `pickFolder` or `listAccountFolders`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderChoice {
    folder_id: String,
    token: String,
}

/// Why `startPairing` failed: the pairing's own reasons and the device name rule (N5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PairStartError {
    NotALink,
    Expired,
    Typo,
    Declined,
    TooMany,
    OtherAccount,
    Unreachable,
    Insecure,
    Blank,
    EdgeWhitespace,
}

impl From<PairError> for PairStartError {
    fn from(error: PairError) -> Self {
        match error {
            PairError::NotALink => Self::NotALink,
            PairError::Expired => Self::Expired,
            PairError::Typo => Self::Typo,
            PairError::Declined => Self::Declined,
            PairError::TooMany => Self::TooMany,
            PairError::OtherAccount => Self::OtherAccount,
            PairError::Unreachable => Self::Unreachable,
            PairError::Insecure => Self::Insecure,
        }
    }
}

impl From<NameError> for PairStartError {
    fn from(error: NameError) -> Self {
        match error {
            NameError::Blank => Self::Blank,
            NameError::EdgeWhitespace => Self::EdgeWhitespace,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum MassDeleteDecision {
    Restore,
    Delete,
}

// ---------------------------------------------------------------------------------------------
// Helpers

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// The last name of a path, the folder's name in the account.
fn folder_name_of(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "Hangar Drive".to_owned())
}

/// A folder name as a directory name: the characters no platform allows become `_`, a leading
/// dot becomes `_` too, so the folder is never hidden and never named like the dot folders of
/// other programs (security review N8), and the result never names a parent.
pub fn safe_dir_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*') || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim().trim_end_matches(['.', ' ']);
    if cleaned.is_empty() {
        return "Hangar Drive".to_owned();
    }
    match cleaned.strip_prefix('.') {
        Some(rest) => format!("_{rest}"),
        None => cleaned.to_owned(),
    }
}

/// The longest root name in UTF-16 units, so that `Name (99)` still fits Windows' 255.
pub const ROOT_NAME_UNITS: usize = 200;

/// A folder name from the account as the name of a new sync root (security review MEDIUM 1).
/// The name was chosen on another device, so after [`safe_dir_name`] it loses everything the
/// Windows shell or the macOS Finder would read as more than a folder: a `.{GUID}` ending,
/// which makes Explorer treat the folder as a namespace junction whose "open" shows another
/// place, loses its dot; a reserved device name gets a leading `_`; the shape of an 8.3 short
/// name, which can address another entry of the same directory, loses its `~`; an overlong name
/// is cut; and a bundle ending (`.app` and the like, [`crate::platform::is_bundle_name`]), which
/// `open` would run instead of showing, loses its dot. Every platform applies every rule, so a
/// folder gets the same name on each device of the account.
pub fn root_dir_name(name: &str) -> String {
    use hangar_drive_protocol::name::{windows_problem, WindowsNameProblem};
    let cut: String = name
        .chars()
        .scan(0usize, |units, c| {
            *units += c.len_utf16();
            (*units <= ROOT_NAME_UNITS).then_some(c)
        })
        .collect();
    let mut dir = safe_dir_name(&cut);
    // Each step removes its own problem and cannot bring back an earlier one; the bound only
    // keeps a rule this function does not know from looping.
    for _ in 0..4 {
        dir = match windows_problem(&dir) {
            None if crate::platform::is_bundle_name(&dir) => without_last_dot(&dir),
            None => return dir,
            // The ending is `.{GUID}`: the last dot is the one before the brace.
            Some(WindowsNameProblem::ShellJunction) => without_last_dot(&dir),
            Some(WindowsNameProblem::Reserved) => format!("_{dir}"),
            Some(WindowsNameProblem::ShortNameAlias) => dir.replace('~', "_"),
            // `safe_dir_name` already replaced forbidden and control characters and trimmed
            // trailing dots and spaces, and the name was cut above.
            Some(_) => break,
        };
    }
    "Hangar Drive".to_owned()
}

/// `name` with its last dot replaced by `_`.
fn without_last_dot(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) => format!("{stem}_{ext}"),
        None => name.to_owned(),
    }
}

/// How many places `proposed_place` tries for one folder: `Name`, `Name (2)` ... `Name (99)`.
const PROPOSAL_TRIES: u32 = 99;

/// The place proposed for an account folder: always a new folder below `base` (`~/Hangar
/// Drive`), never an existing one and never a direct child of the home folder, where folders
/// like Documents live that a stranger's account must not be offered (security review H1, N8).
/// `taken` says whether a candidate is out (it exists, the engine refuses it, or another folder
/// of the same list got it). The name is the account's, so it goes through [`root_dir_name`].
pub fn proposed_place(base: &Path, name: &str, taken: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    let dir = root_dir_name(name);
    (1..=PROPOSAL_TRIES)
        .map(|n| {
            if n == 1 {
                base.join(&dir)
            } else {
                base.join(format!("{dir} ({n})"))
            }
        })
        .find(|candidate| !taken(candidate))
}

/// `inside`, a `/` separated path in a synced folder, below `root`; `None` for anything that
/// could leave it.
pub fn path_inside(root: &Path, inside: &str) -> Option<PathBuf> {
    let mut out = root.to_path_buf();
    for part in inside.split('/').filter(|p| !p.is_empty()) {
        let mut components = Path::new(part).components();
        let ok = matches!(components.next(), Some(Component::Normal(_)))
            && components.next().is_none()
            && !part.contains('\\')
            && !part.contains(':');
        if !ok {
            return None;
        }
        out.push(part);
    }
    Some(out)
}

fn device_name(shell: &Shell) -> String {
    lock(&shell.device_name)
        .clone()
        .unwrap_or_else(crate::platform::device_name)
}

/// The window's name rule (rule N5) before the device belongs to an account.
fn name_error(name: &str) -> Option<NameError> {
    use hangar_drive_protocol::name::{check_display_name, DisplayNameError};
    match check_display_name(name, hangar_drive_protocol::api::MAX_DEVICE_NAME_LEN) {
        Ok(()) => None,
        Err(DisplayNameError::EdgeWhitespace) => Some(NameError::EdgeWhitespace),
        Err(_) => Some(NameError::Blank),
    }
}

fn remember_code(shell: &Shell, view: &RecoveryCodeView, renewal: bool) {
    *lock(&shell.shown) = Some(ShownCode {
        code: Zeroizing::new(view.groups.join("-")),
        check_group: view.check_group,
        renewal,
    });
}

/// The system clipboard through the clipboard plugin.
struct AppClipboard(AppHandle);

impl Clipboard for AppClipboard {
    fn write_secret(&self, text: &str) -> Result<(), ClipboardError> {
        self.0
            .clipboard()
            .write_secret(text)
            .map_err(|_| ClipboardError)
    }
    fn write_text(&self, text: &str) -> Result<(), ClipboardError> {
        self.0
            .clipboard()
            .write_text(text)
            .map_err(|_| ClipboardError)
    }
    fn read_text(&self) -> Option<String> {
        self.0.clipboard().read_text().ok()
    }
}

/// Copies a code or link as a secret and clears it after a minute (security review M1).
fn copy_and_clear(app: &AppHandle, shell: &Shell, text: Zeroizing<String>) -> Answer<()> {
    crate::clipboard::copy_and_clear(
        Arc::new(AppClipboard(app.clone())),
        Arc::clone(&shell.clipboard_writes),
        Arc::clone(&shell.clipboard_secret),
        text,
        crate::clipboard::CLEAR_AFTER,
    )
    .map_err(|e| CommandError::unexpected(e.to_string()))
}

/// Takes a code or link the app copied off the clipboard now, if it is still there, before the
/// app ends: on exit (lib.rs, `RunEvent::Exit`) and before an update installs, which on Windows
/// ends the process without that event (security review LOW 2).
pub fn clear_copied_secret(app: &AppHandle) {
    if let Some(shell) = app.try_state::<Shell>() {
        crate::clipboard::clear_now(&AppClipboard(app.clone()), &shell.clipboard_secret);
    }
}

/// The canonical form of `inside` (a `/` separated path in the synced folder `root`), which must
/// still lie in the folder once links and `..` are resolved (security review L5).
fn checked_inside(root: &Path, inside: &str) -> Answer<PathBuf> {
    use hangar_drive_sync::roots::{key, within};
    let target = path_inside(root, inside)
        .ok_or_else(|| CommandError::invalid("path outside the folder"))?;
    let root = std::fs::canonicalize(root)?;
    let target = std::fs::canonicalize(target)?;
    if !within(&key(&target), &key(&root)) {
        return Err(CommandError::invalid("path outside the folder"));
    }
    Ok(target)
}

/// Checks a place as a new sync root before anything is created there (security review L4),
/// then creates it.
async fn check_then_create(
    shell: &Shell,
    path: &Path,
    except: Option<String>,
) -> Answer<Result<(), FolderRefusalView>> {
    let probe = path_text(path);
    let refusal = shell
        .engine(move |core| Ok(core.check_folder(&probe, except.as_deref())))
        .await?;
    if let Some(refusal) = refusal {
        return Ok(Err(refusal));
    }
    let path = path.to_path_buf();
    blocking(move || std::fs::create_dir_all(path).map_err(CommandError::from)).await?;
    Ok(Ok(()))
}

fn refused(view: FolderRefusalView) -> CommandError {
    CommandError::invalid(format!("the folder is refused: {:?}", view.reason))
}

/// A file dialog owned by the main window: without an owner Windows may open it behind the app,
/// where the person waits for a dialog they cannot see.
fn with_main_parent(
    app: &AppHandle,
    dialog: tauri_plugin_dialog::FileDialogBuilder<tauri::Wry>,
) -> tauri_plugin_dialog::FileDialogBuilder<tauri::Wry> {
    match app.get_webview_window(crate::tray::MAIN_WINDOW) {
        Some(window) => dialog.set_parent(&window),
        None => dialog,
    }
}

async fn pick_directory(app: &AppHandle, shell: &Shell) -> Answer<Option<PathBuf>> {
    let _dialog = DialogGuard::enter(&shell.dialog_open)?;
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut dialog = with_main_parent(&app, app.dialog().file());
        if let Some(home) = dirs::home_dir() {
            dialog = dialog.set_directory(home);
        }
        dialog
            .blocking_pick_folder()
            .and_then(|p| p.into_path().ok())
    })
    .await
    .map_err(|e| CommandError::unexpected(e.to_string()))
}

async fn save_dialog(
    app: &AppHandle,
    shell: &Shell,
    directory: Option<PathBuf>,
    name: String,
) -> Answer<Option<PathBuf>> {
    let _dialog = DialogGuard::enter(&shell.dialog_open)?;
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut dialog = with_main_parent(&app, app.dialog().file()).set_file_name(name);
        if let Some(dir) = directory {
            dialog = dialog.set_directory(dir);
        }
        dialog
            .add_filter("Text", &["txt"])
            .blocking_save_file()
            .and_then(|p| p.into_path().ok())
    })
    .await
    .map_err(|e| CommandError::unexpected(e.to_string()))
}

/// Whether `path` lies inside one of the synced folders (the recovery file must not travel to
/// the server next to the data it opens).
fn inside_synced_folder(path: &Path, snapshot: &Snapshot) -> bool {
    let target = path
        .parent()
        .and_then(|dir| std::fs::canonicalize(dir).ok())
        .map(|dir| hangar_drive_sync::roots::key(&dir));
    let Some(target) = target else {
        return false;
    };
    snapshot.folders.iter().any(|f| {
        std::fs::canonicalize(&f.path)
            .map(|p| hangar_drive_sync::roots::within(&target, &hangar_drive_sync::roots::key(&p)))
            .unwrap_or(false)
    })
}

/// Writes a file only this user may read: on Unix it is created with mode 0600, and a file the
/// save dialog lets the person replace is narrowed to 0600 before its new content goes in
/// (security review N11). On Windows the file inherits the ACL of its folder, which for the
/// user's own folders admits only the user, the system and administrators.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, PRIVATE_MODE);
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(PRIVATE_MODE))?;
    }
    file.write_all(bytes)?;
    file.sync_all()
}

/// Owner read and write, nothing for anyone else.
#[cfg(unix)]
const PRIVATE_MODE: u32 = 0o600;

async fn fresh_snapshot(shell: &Shell) -> Answer<Snapshot> {
    shell.engine(|core| Ok(core.snapshot())).await
}

fn folder_of_warning(snapshot: &Snapshot, warning_id: &str) -> Option<String> {
    snapshot.warnings.iter().find_map(|w| match w {
        Warning::MassDelete { id, folder_id, .. } if id == warning_id => Some(folder_id.clone()),
        _ => None,
    })
}

/// The folder of a shown `incomingDelete` warning; an ID of any other kind is refused.
fn folder_of_incoming(snapshot: &Snapshot, warning_id: &str) -> Option<String> {
    snapshot.warnings.iter().find_map(|w| match w {
        Warning::IncomingDelete { id, folder_id, .. } if id == warning_id => {
            Some(folder_id.clone())
        }
        _ => None,
    })
}

fn folder_path(snapshot: &Snapshot, folder_id: Option<&str>) -> Option<PathBuf> {
    let folder = match folder_id {
        Some(id) => snapshot.folders.iter().find(|f| f.id == id),
        None => snapshot.folders.first(),
    }?;
    Some(PathBuf::from(&folder.path))
}

// ---------------------------------------------------------------------------------------------
// Snapshot and clipboard

/// The window asks for the first snapshot right after it subscribed, so a link the app was
/// started with (`openLink`) is sent a moment later, once the window listens.
#[tauri::command]
pub async fn get_snapshot(
    app: AppHandle,
    shell: State<'_, Shell>,
    links: State<'_, crate::deeplink::Pending>,
) -> Answer<Snapshot> {
    if let Some(link) = links.take() {
        let app = app.clone();
        std::thread::spawn(move || {
            std::thread::sleep(LINK_DELAY);
            crate::events::emit_open_link(&app, &link.link);
        });
    }
    // The window asks for its first snapshot when it opens. While the engine works through a
    // long round it answers commands only between slices of work, so the newest snapshot the
    // engine already sent is the answer here; later ones arrive as events anyway. Only before
    // the first one is the engine asked (a blank window waited minutes on a large first
    // upload, 2026-11-28).
    window_snapshot(&shell).await
}

/// The snapshot for a window that opens: the newest one the engine sent, kept by the event
/// thread (`events::forward`), and the engine's own answer only before the first one.
async fn window_snapshot(shell: &Shell) -> Answer<Snapshot> {
    let cached = lock(&shell.snapshot).clone();
    match cached {
        Some(snapshot) => Ok(snapshot),
        None => fresh_snapshot(shell).await,
    }
}

/// The last minute of network traffic, for a traffic line that missed readings (it opened, or
/// traffic started again after a quiet minute). Read from the sampler's meter, never from the
/// engine thread.
#[tauri::command]
pub async fn get_traffic(
    traffic: State<'_, crate::traffic::Traffic>,
) -> Answer<hangar_drive_sync::traffic::TrafficHistory> {
    Ok(traffic.history())
}

/// How long after the first snapshot a start link is sent.
const LINK_DELAY: Duration = Duration::from_millis(400);

/// Only text that looks like a Hangar Drive link or code, else `""` (security review L2).
#[tauri::command]
pub async fn read_clipboard_text(app: AppHandle) -> Answer<String> {
    let text = Zeroizing::new(app.clipboard().read_text().unwrap_or_default());
    Ok(crate::clipboard::readable(&text))
}

// ---------------------------------------------------------------------------------------------
// Setup, new account

#[tauri::command]
pub async fn check_invite(
    shell: State<'_, Shell>,
    link: String,
) -> Answer<ApiResult<InviteCheck, InviteError>> {
    shell.engine(move |core| Ok(core.check_invite(&link))).await
}

#[tauri::command]
pub async fn default_device_name(shell: State<'_, Shell>) -> Answer<String> {
    Ok(device_name(&shell))
}

#[tauri::command]
pub async fn begin_account(
    shell: State<'_, Shell>,
    link: String,
    device_name: String,
) -> Answer<ApiResult<RecoveryCodeView, BeginError>> {
    let name = device_name.clone();
    let result = shell
        .engine(move |core| core.begin_account(&link, &device_name))
        .await?;
    if let ApiResult::Ok(view) = &result {
        *lock(&shell.device_name) = Some(name);
        remember_code(&shell, view, false);
    }
    Ok(result)
}

/// Prints the sheet the window put into words: a window of its own shows it laid out with the
/// QR code of its link, and opens the system's print dialog. The page has no script and no
/// access to the backend (the window has no capability); it is served once from memory over the
/// `hangar-print` scheme in an incognito WebView and dropped after that, and nothing of it is
/// written to disk (security review M3, [`crate::print`]).
#[tauri::command]
pub async fn print_recovery_sheet(app: AppHandle, document: SheetDocument) -> Answer<()> {
    let document = document
        .checked()
        .map_err(|e| CommandError::invalid(e.to_string()))?;
    let (_, svg) = crate::qr::encode(&document.qr_link)
        .map_err(|e| CommandError::unexpected(e.to_string()))?;
    // The SVG carries the link, which names the account; it is wiped with the page.
    let svg = Zeroizing::new(svg);
    let html = document.html(&svg);
    let mut token = [0u8; 16];
    {
        use hangar_drive_crypto::Entropy as _;
        hangar_drive_crypto::OsEntropy
            .fill(&mut token)
            .map_err(|_| CommandError::unexpected("no randomness for the print page"))?;
    }
    let token = hangar_drive_protocol::ids::base64url(&token);
    let url = crate::print::page_url(&token)
        .ok_or_else(|| CommandError::unexpected("no print page URL"))?;
    if let Some(old) = app.get_webview_window(crate::print::WINDOW) {
        let _ = old.destroy();
    }
    app.state::<crate::print::PrintPage>().put(token, html);
    tauri::WebviewWindowBuilder::new(
        &app,
        crate::print::WINDOW,
        tauri::WebviewUrl::CustomProtocol(url),
    )
    .title(&document.title)
    .inner_size(720.0, 900.0)
    .incognito(true)
    .on_navigation(crate::print::may_navigate)
    .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
    .on_page_load(|window, payload| {
        // The callback runs inside the WebView's event handling; the print dialog is opened
        // after it returned, so the window finishes its load and paints first.
        if payload.event() == tauri::webview::PageLoadEvent::Finished {
            drop(tauri::async_runtime::spawn_blocking(move || {
                if let Err(error) = window.print() {
                    eprintln!("hangar-drive: print dialog not opened: {error}");
                }
            }));
        }
    })
    .build()?;
    Ok(())
}

#[tauri::command]
pub async fn save_recovery_file(
    app: AppHandle,
    shell: State<'_, Shell>,
    document: SheetDocument,
) -> Answer<SaveResult> {
    let document = document
        .checked()
        .map_err(|e| CommandError::invalid(e.to_string()))?;
    let name = document.file_name.clone();
    // Downloads, not Documents: Windows often redirects Documents into OneDrive (M2).
    let Some(path) = save_dialog(&app, &shell, dirs::download_dir(), name).await? else {
        return Ok(SaveResult::Cancelled);
    };
    let snapshot = fresh_snapshot(&shell).await?;
    let text = document.text();
    blocking(move || {
        if inside_synced_folder(&path, &snapshot) {
            return Ok(SaveResult::InSyncFolder);
        }
        if path.parent().is_some_and(|dir| {
            crate::platform::in_cloud_folder(dir, &crate::platform::cloud_roots())
        }) {
            return Ok(SaveResult::InCloudFolder);
        }
        write_private(&path, text.as_bytes())?;
        Ok(SaveResult::Saved {
            path: path_text(&path),
        })
    })
    .await
}

#[tauri::command]
pub async fn copy_recovery_code(app: AppHandle, shell: State<'_, Shell>) -> Answer<()> {
    let code = lock(&shell.shown)
        .as_ref()
        .map(|s| s.code.clone())
        .ok_or_else(|| CommandError::invalid("no recovery code is shown"))?;
    copy_and_clear(&app, &shell, code)
}

/// Checks the typed group. For a renewed code the old one stops working on success, so a
/// matching group is confirmed once more in a native dialog first (security review M4); "no"
/// there keeps the old code and is not an error.
#[tauri::command]
pub async fn confirm_recovery_group(
    app: AppHandle,
    shell: State<'_, Shell>,
    group: String,
) -> Answer<RecoveryCheck> {
    check_recovery_group(&shell, &Native(&app), group).await
}

async fn check_recovery_group(
    shell: &Shell,
    asker: &impl Ask,
    group: String,
) -> Answer<RecoveryCheck> {
    let renewal_matches = lock(&shell.shown)
        .as_ref()
        .is_some_and(|shown| shown.renewal && shown.group_matches(&group));
    if renewal_matches {
        // Without a valid code (warning `noRecoveryCode`) there is no old one to replace, and
        // the question must not say so.
        let has_code = !fresh_snapshot(shell)
            .await?
            .warnings
            .iter()
            .any(|w| matches!(w, Warning::NoRecoveryCode { .. }));
        let confirm = crate::confirm::renew_code(shell.language(), has_code);
        if !asker.ask(shell, confirm).await? {
            return Ok(RecoveryCheck::Declined);
        }
    }
    let ok = shell
        .engine(move |core| core.confirm_recovery_group(&group))
        .await?;
    if !ok {
        return Ok(RecoveryCheck::Wrong);
    }
    *lock(&shell.shown) = None;
    Ok(RecoveryCheck::Confirmed)
}

#[tauri::command]
pub async fn default_folder_place(shell: State<'_, Shell>) -> Answer<FolderPlace> {
    let path = crate::platform::default_folder()
        .ok_or_else(|| CommandError::unexpected("no home folder"))?;
    Ok(FolderPlace {
        name: folder_name_of(&path_text(&path)),
        path: path_text(&path),
        token: shell.places.issue(path)?,
    })
}

#[tauri::command]
pub async fn pick_folder(
    app: AppHandle,
    shell: State<'_, Shell>,
    purpose: PickPurpose,
) -> Answer<PickResult> {
    let Some(path) = pick_directory(&app, &shell).await? else {
        return Ok(PickResult::Cancelled);
    };
    let text = path_text(&path);
    let except = match purpose {
        PickPurpose::Find { folder_id } => Some(folder_id),
        PickPurpose::New | PickPurpose::Account { .. } => None,
    };
    let probe = text.clone();
    let refusal = shell
        .engine(move |core| Ok(core.check_folder(&probe, except.as_deref())))
        .await?;
    Ok(match refusal {
        Some(view) => view.into(),
        None => PickResult::Picked {
            name: folder_name_of(&text),
            path: text,
            token: shell.places.issue(path)?,
        },
    })
}

/// `token` of `pickFolder`, `defaultFolderPlace` or `listAccountFolders` (security review L2).
#[tauri::command]
pub async fn count_local_files(shell: State<'_, Shell>, token: String) -> Answer<u64> {
    let path = shell.places.path(&token)?;
    tauri::async_runtime::spawn_blocking(move || {
        hangar_drive_sync::roots::count_files(&path, COUNT_LIMIT)
    })
    .await
    .map_err(|e| CommandError::unexpected(e.to_string()))
}

#[tauri::command]
pub async fn finish_setup(shell: State<'_, Shell>, token: String) -> Answer<()> {
    add_folder(shell, token).await
}

// ---------------------------------------------------------------------------------------------
// Setup, additional device and recovery

/// No camera support in version 1 (`env.camera` is false, so the window never offers it).
#[tauri::command]
pub async fn scan_with_camera() -> Answer<Option<String>> {
    Ok(None)
}

/// N2: what a link names (invite, pairing offer, recovery sheet), read offline and shown
/// before anything is sent.
#[tauri::command]
pub async fn inspect_link(
    shell: State<'_, Shell>,
    link: String,
) -> Answer<ApiResult<InspectedLink, LinkProblem>> {
    shell.engine(move |core| Ok(core.inspect_link(&link))).await
}

/// `device_name` is this new device's name (trimmed by the window), which the other device shows
/// in its question; it follows the device name rule (N5) like every device name.
#[tauri::command]
pub async fn start_pairing(
    shell: State<'_, Shell>,
    input: PairInput,
    device_name: String,
) -> Answer<ApiResult<PairWaiting, PairStartError>> {
    pair(&shell, input, device_name).await
}

async fn pair(
    shell: &Shell,
    input: PairInput,
    device_name: String,
) -> Answer<ApiResult<PairWaiting, PairStartError>> {
    // Only a device without an account pairs (security review H1): a set-up device that joined
    // another account would hand that account the folders the person adds next. The engine
    // refuses as well; the shell does not even pass the link on.
    if fresh_snapshot(shell).await?.account.is_some() {
        return Err(SyncError::AlreadySetUp.into());
    }
    let PairInput::Link { link } = input else {
        // The typed path needs the offer's log head, which a typed code does not carry; the
        // engine of version 1 pairs through the link or QR code only.
        return Ok(ApiResult::Err(PairStartError::NotALink));
    };
    if let Some(error) = name_error(&device_name) {
        return Ok(ApiResult::Err(error.into()));
    }
    let name = device_name.clone();
    let result = shell
        .engine(move |core| core.start_pairing(&link, &name))
        .await?;
    Ok(match result {
        ApiResult::Ok(safety) => {
            *lock(&shell.device_name) = Some(device_name);
            ApiResult::Ok(PairWaiting {
                path: "link",
                safety,
            })
        }
        ApiResult::Err(e) => ApiResult::Err(e.into()),
    })
}

#[tauri::command]
pub async fn cancel_pairing(shell: State<'_, Shell>) -> Answer<()> {
    shell
        .engine(|core| {
            core.cancel_pairing();
            Ok(())
        })
        .await
}

#[tauri::command]
pub async fn list_account_folders(shell: State<'_, Shell>) -> Answer<AccountFolders> {
    account_folders(&shell).await
}

async fn account_folders(shell: &Shell) -> Answer<AccountFolders> {
    let base = crate::platform::default_folder()
        .ok_or_else(|| CommandError::unexpected("no home folder"))?;
    let probe = base.clone();
    let proposals = shell
        .engine(move |core| {
            let mut chosen: Vec<PathBuf> = Vec::new();
            let mut out = Vec::new();
            for f in core.snapshot().remote_folders {
                let used = |p: &Path| p.exists() || chosen.iter().any(|c| c == p);
                // A place the engine would refuse (inside a synced folder) only when nothing
                // else is free, so the window shows that refusal instead of no proposal.
                let place = proposed_place(&probe, &f.name, |p| {
                    used(p) || core.check_folder(&path_text(p), None).is_some()
                })
                .or_else(|| proposed_place(&probe, &f.name, used))
                .ok_or(SyncError::Invalid("no free place for an account folder"))?;
                chosen.push(place.clone());
                out.push((f, place));
            }
            Ok(out)
        })
        .await?;
    let mut folders = Vec::with_capacity(proposals.len());
    for (f, place) in proposals {
        folders.push(AccountFolder {
            id: f.id,
            name: f.name,
            size: f.size,
            proposed_path: path_text(&place),
            proposed_token: shell.places.issue(place)?,
        });
    }
    let home = base.parent().map(Path::to_path_buf).unwrap_or(base);
    Ok(AccountFolders {
        folders,
        free: crate::platform::free_bytes(&home).unwrap_or(0),
    })
}

/// Joins every chosen folder; answers the IDs of those whose place holds files and for which
/// the person chose another folder in the native dialog (security review H1).
#[tauri::command]
pub async fn join_folders(
    app: AppHandle,
    shell: State<'_, Shell>,
    choices: Vec<FolderChoice>,
) -> Answer<Vec<String>> {
    let mut declined = Vec::new();
    for choice in choices {
        let outcome =
            join_account_folder(&shell, &Native(&app), &choice.folder_id, &choice.token).await?;
        if outcome == JoinOutcome::Declined {
            declined.push(choice.folder_id);
        }
    }
    Ok(declined)
}

/// `sheet` is the sheet's link `hangar-drive://recover#...`: only the link carries the genesis
/// anchor and the pin a recovery is checked against (N1).
#[tauri::command]
pub async fn recover_account(
    shell: State<'_, Shell>,
    sheet: String,
    code: String,
    device_name: String,
) -> Answer<ApiResult<(), RecoverError>> {
    let code = Zeroizing::new(code);
    let name = device_name.clone();
    let result = shell
        .engine(move |core| core.recover_account(&sheet, &code, &device_name))
        .await?;
    if result == ApiResult::Ok(()) {
        *lock(&shell.device_name) = Some(name);
    }
    Ok(result)
}

/// With an account, a name that looks like another device's is taken only after a native
/// question that names that device (skeleton check of device names).
#[tauri::command]
pub async fn set_device_name(
    app: AppHandle,
    shell: State<'_, Shell>,
    name: String,
) -> Answer<ApiResult<(), DeviceNameError>> {
    let snapshot = fresh_snapshot(&shell).await?;
    if snapshot.account.is_none() {
        if let Some(error) = name_error(&name) {
            return Ok(ApiResult::Err(error.into()));
        }
        *lock(&shell.device_name) = Some(name);
        return Ok(ApiResult::Ok(()));
    }
    let this = shell
        .engine(|core| {
            core.list_devices()?
                .devices
                .into_iter()
                .find(|d| d.is_this)
                .map(|d| d.id)
                .ok_or(SyncError::NotSetUp("this device is not in the list"))
        })
        .await?;
    rename_checked(&shell, &Native(&app), this, name).await
}

#[tauri::command]
pub async fn recovery_devices(shell: State<'_, Shell>) -> Answer<Vec<Device>> {
    shell.engine(|core| core.recovery_devices()).await
}

/// Removing regular devices asks natively first and names them (follow-up check N-2); the
/// window asks nothing before it. `Ok(None)`: the person said no and nothing was removed. Only
/// devices the engine offered for removal are passed on, so nothing is removed that the
/// question did not name. `Err`: this device was not added, for a reason the window explains
/// (see [`RecoveryCleanupError`]); any other failure is an error, and the same call is tried
/// again.
#[tauri::command]
pub async fn finish_recovery_cleanup(
    app: AppHandle,
    shell: State<'_, Shell>,
    remove: Vec<String>,
) -> Answer<ApiResult<Option<RecoveryCodeView>, RecoveryCleanupError>> {
    cleanup_after_recovery(&shell, &Native(&app), remove).await
}

async fn cleanup_after_recovery(
    shell: &Shell,
    asker: &impl Ask,
    remove: Vec<String>,
) -> Answer<ApiResult<Option<RecoveryCodeView>, RecoveryCleanupError>> {
    let offered = shell.engine(|core| core.recovery_devices()).await?;
    let chosen: Vec<&Device> = offered.iter().filter(|d| remove.contains(&d.id)).collect();
    if !chosen.is_empty() {
        let language = shell.language();
        // Before the join the recovery session cannot open the sealed names: such a device is
        // named by the day it was added, as the window lists it.
        let labels: Vec<String> = chosen
            .iter()
            .map(|d| {
                crate::confirm::recovery_device_label(
                    language,
                    &d.name,
                    d.added,
                    shell.tz_offset_minutes,
                )
            })
            .collect();
        let confirm = crate::confirm::recovery_cleanup(language, &labels);
        if !asker.ask(shell, confirm).await? {
            return Ok(ApiResult::Ok(None));
        }
    }
    let remove: Vec<String> = chosen.into_iter().map(|d| d.id.clone()).collect();
    let finished = shell
        .engine(move |core| match core.finish_recovery_cleanup(&remove) {
            Ok(view) => Ok(ApiResult::Ok(view)),
            Err(error) => match RecoveryCleanupError::of(&error) {
                Some(reason) => Ok(ApiResult::Err(reason)),
                None => Err(error),
            },
        })
        .await?;
    Ok(match finished {
        ApiResult::Ok(view) => {
            remember_code(shell, &view, false);
            ApiResult::Ok(Some(view))
        }
        ApiResult::Err(reason) => ApiResult::Err(reason),
    })
}

// ---------------------------------------------------------------------------------------------
// Everyday

#[tauri::command]
pub async fn open_folder(
    shell: State<'_, Shell>,
    folder_id: Option<String>,
    path: Option<String>,
) -> Answer<()> {
    // The folder's place is in the snapshot the window shows; asking the engine would wait for
    // the end of its current slice of work, which in a long round is many seconds.
    let snapshot = window_snapshot(&shell).await?;
    let root = folder_path(&snapshot, folder_id.as_deref())
        .ok_or_else(|| CommandError::invalid("unknown folder"))?;
    blocking(move || {
        match path.filter(|p| !p.is_empty()) {
            Some(inside) => {
                let target = checked_inside(&root, &inside)?;
                crate::platform::reveal(&target, true)?;
            }
            None => crate::platform::reveal(&std::fs::canonicalize(&root)?, false)?,
        }
        Ok(())
    })
    .await
}

/// Runs file system and shell work (canonicalizing, the file manager, writing a file) on a
/// blocking thread, so it never holds an async worker that other commands need.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Answer<T> + Send + 'static,
) -> Answer<T> {
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|e| CommandError::unexpected(e.to_string()))?
}

#[tauri::command]
pub async fn pause(shell: State<'_, Shell>, duration: PauseDuration) -> Answer<()> {
    let until = (duration == PauseDuration::Tomorrow)
        .then(|| crate::platform::next_morning(crate::events::now_ms(), shell.tz_offset_minutes));
    shell.engine(move |core| core.pause(duration, until)).await
}

#[tauri::command]
pub async fn resume(shell: State<'_, Shell>) -> Answer<()> {
    shell.engine(|core| core.resume()).await
}

/// Runs a round now: every command is followed by one pass of the control loop. Version 1
/// holds no files back for a metered network, so there is nothing else to let go. Returns at
/// once; the outcome arrives as snapshots ([`Shell::nudge`]).
#[tauri::command]
pub async fn sync_now(shell: State<'_, Shell>) -> Answer<()> {
    shell.nudge()
}

#[tauri::command]
pub async fn retry_connection(shell: State<'_, Shell>) -> Answer<()> {
    shell.nudge()
}

#[tauri::command]
pub async fn pause_folder(shell: State<'_, Shell>, folder_id: String) -> Answer<()> {
    shell
        .engine(move |core| core.set_folder_paused(&folder_id, true))
        .await
}

#[tauri::command]
pub async fn resume_folder(shell: State<'_, Shell>, folder_id: String) -> Answer<()> {
    shell
        .engine(move |core| core.set_folder_paused(&folder_id, false))
        .await
}

/// `token` names a place the backend chose (security review L2); the place is checked before
/// it is created (L4).
#[tauri::command]
pub async fn add_folder(shell: State<'_, Shell>, token: String) -> Answer<()> {
    let place = shell.places.path(&token)?;
    check_then_create(&shell, &place, None)
        .await?
        .map_err(refused)?;
    shell.places.take(&token)?;
    let path = path_text(&place);
    let name = folder_name_of(&path);
    shell
        .engine(move |core| core.add_folder(&path, &name).map(drop))
        .await
}

#[tauri::command]
pub async fn add_account_folder(
    app: AppHandle,
    shell: State<'_, Shell>,
    folder_id: String,
    token: String,
) -> Answer<JoinOutcome> {
    join_account_folder(&shell, &Native(&app), &folder_id, &token).await
}

/// Joins the account folder `folder_id` at the place behind `token`. A place that already holds
/// files is merged with the folder and uploaded to the server, so the device joins it only after
/// a native question that names the place, the folder and the server (security review H1); the
/// window asks nothing before it (ux-concept 6.5).
async fn join_account_folder(
    shell: &Shell,
    asker: &impl Ask,
    folder_id: &str,
    token: &str,
) -> Answer<JoinOutcome> {
    let place = shell.places.path(token)?;
    let files = files_at(&place).await?;
    if files > 0 {
        let snapshot = fresh_snapshot(shell).await?;
        let name = snapshot
            .remote_folders
            .iter()
            .find(|f| f.id == folder_id)
            .map_or_else(|| folder_id.to_owned(), |f| f.name.clone());
        let host = snapshot
            .account
            .as_ref()
            .map(|a| a.host.clone())
            .unwrap_or_default();
        let confirm =
            crate::confirm::join_folder(shell.language(), &path_text(&place), &name, files, &host);
        if !asker.ask(shell, confirm).await? {
            return Ok(JoinOutcome::Declined);
        }
    }
    check_then_create(shell, &place, None)
        .await?
        .map_err(refused)?;
    shell.places.take(token)?;
    let path = path_text(&place);
    let folder = folder_id.to_owned();
    shell
        .engine(move |core| core.add_account_folder(&folder, &path))
        .await?;
    Ok(JoinOutcome::Joined)
}

/// The files at `place` as the sync would see them (the built-in ignore list skips the rest);
/// 0 for a place that does not exist yet.
async fn files_at(place: &Path) -> Answer<u64> {
    let place = place.to_path_buf();
    tauri::async_runtime::spawn_blocking(move || {
        if !place.exists() {
            return 0;
        }
        hangar_drive_sync::roots::count_files(&place, COUNT_LIMIT)
    })
    .await
    .map_err(|e| CommandError::unexpected(e.to_string()))
}

#[tauri::command]
pub async fn stop_folder(shell: State<'_, Shell>, folder_id: String) -> Answer<()> {
    shell.engine(move |core| core.stop_folder(&folder_id)).await
}

/// Asks once more in a native dialog that names the folder (security review L2); "no" changes
/// nothing and is not an error.
#[tauri::command]
pub async fn delete_folder_everywhere(
    app: AppHandle,
    shell: State<'_, Shell>,
    folder_id: String,
) -> Answer<DeleteOutcome> {
    let snapshot = fresh_snapshot(&shell).await?;
    let name = snapshot
        .folders
        .iter()
        .find(|f| f.id == folder_id)
        .map(|f| f.name.clone())
        .or_else(|| {
            snapshot
                .remote_folders
                .iter()
                .find(|f| f.id == folder_id)
                .map(|f| f.name.clone())
        })
        .ok_or_else(|| CommandError::invalid("unknown folder"))?;
    let days = snapshot
        .account
        .as_ref()
        .map_or(DEFAULT_RETENTION_DAYS, |a| a.retention_days);
    let confirm = crate::confirm::delete_everywhere(shell.language(), &name, days);
    if !native_confirm(&app, &shell, confirm).await? {
        return Ok(DeleteOutcome::Kept);
    }
    shell
        .engine(move |core| core.delete_folder_everywhere(&folder_id))
        .await?;
    Ok(DeleteOutcome::Deleted)
}

/// Brings a folder deleted everywhere back within the retention window (ADR 0001, section 3).
#[tauri::command]
pub async fn restore_deleted_folder(shell: State<'_, Shell>, folder_id: String) -> Answer<()> {
    shell
        .engine(move |core| core.restore_deleted_folder(&folder_id))
        .await
}

/// Brings back the files another device deleted, from their activity entry (UX 8.1); answers
/// how many came back.
#[tauri::command]
pub async fn restore_remote_deleted(shell: State<'_, Shell>, activity_id: String) -> Answer<u64> {
    shell
        .engine(move |core| core.restore_remote_deleted(&activity_id))
        .await
}

/// The retention window the server keeps a deleted folder for, when no account says (ADR 0001,
/// section 5: 30 days by default).
const DEFAULT_RETENTION_DAYS: u32 = 30;

/// Shows a native confirmation off the async runtime, one dialog at a time.
async fn native_confirm(
    app: &AppHandle,
    shell: &Shell,
    confirm: crate::confirm::Confirm,
) -> Answer<bool> {
    let _dialog = DialogGuard::enter(&shell.dialog_open)?;
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || crate::confirm::ask(&app, confirm))
        .await
        .map_err(|e| CommandError::unexpected(e.to_string()))
}

#[tauri::command]
pub async fn list_not_synced(
    shell: State<'_, Shell>,
    folder_id: String,
) -> Answer<Vec<NotSyncedEntry>> {
    shell
        .engine(move |core| core.list_not_synced(&folder_id))
        .await
}

#[tauri::command]
pub async fn get_folder_number(shell: State<'_, Shell>, folder_id: String) -> Answer<FolderNumber> {
    let number = shell
        .engine(move |core| core.get_folder_number(&folder_id))
        .await?;
    Ok(match number {
        Some(number) => FolderNumber::Number { number },
        None => FolderNumber::Offline,
    })
}

// ---------------------------------------------------------------------------------------------
// Problems

#[tauri::command]
pub async fn list_mass_delete(shell: State<'_, Shell>, warning_id: String) -> Answer<Vec<String>> {
    shell
        .engine(move |core| {
            let folder = folder_of_warning(&core.snapshot(), &warning_id)
                .ok_or(SyncError::Invalid("unknown warning"))?;
            core.list_mass_delete(&folder)
        })
        .await
}

/// "Restore" runs at once; "delete" asks once more in a native dialog with the folder and the
/// number of files (security review M4), and "no" there leaves the deletions waiting.
#[tauri::command]
pub async fn resolve_mass_delete(
    app: AppHandle,
    shell: State<'_, Shell>,
    warning_id: String,
    decision: MassDeleteDecision,
) -> Answer<MassDeleteOutcome> {
    resolve_deletes(&shell, &Native(&app), warning_id, decision).await
}

async fn resolve_deletes(
    shell: &Shell,
    asker: &impl Ask,
    warning_id: String,
    decision: MassDeleteDecision,
) -> Answer<MassDeleteOutcome> {
    if decision == MassDeleteDecision::Delete {
        let snapshot = fresh_snapshot(shell).await?;
        let (folder, count) = snapshot
            .warnings
            .iter()
            .find_map(|w| match w {
                Warning::MassDelete {
                    id,
                    folder_name,
                    count,
                    ..
                } if *id == warning_id => Some((folder_name.clone(), *count)),
                _ => None,
            })
            .ok_or_else(|| CommandError::invalid("unknown warning"))?;
        let confirm = crate::confirm::mass_delete(shell.language(), &folder, count);
        if !asker.ask(shell, confirm).await? {
            return Ok(MassDeleteOutcome::Declined);
        }
    }
    let count = shell
        .engine(move |core| {
            let folder = folder_of_warning(&core.snapshot(), &warning_id)
                .ok_or(SyncError::Invalid("unknown warning"))?;
            core.resolve_mass_delete(&folder, decision == MassDeleteDecision::Restore)
        })
        .await?;
    Ok(MassDeleteOutcome::Resolved { count })
}

/// The paths of the files another device deleted that wait here (`listIncomingDelete`).
#[tauri::command]
pub async fn list_incoming_delete(
    shell: State<'_, Shell>,
    warning_id: String,
) -> Answer<Vec<String>> {
    shell
        .engine(move |core| {
            let folder = folder_of_incoming(&core.snapshot(), &warning_id)
                .ok_or(SyncError::Invalid("unknown warning"))?;
            core.list_incoming_delete(&folder)
        })
        .await
}

/// "Restore" brings the files back on every device at once; "delete here" asks once more in a
/// native dialog with the folder and the number of files, and approves exactly the state that
/// number was read from: deletes that arrived since ask again (ADR 0001, amendment "incoming
/// mass deletes").
#[tauri::command]
pub async fn resolve_incoming_delete(
    app: AppHandle,
    shell: State<'_, Shell>,
    warning_id: String,
    decision: MassDeleteDecision,
) -> Answer<MassDeleteOutcome> {
    resolve_incoming(&shell, &Native(&app), warning_id, decision).await
}

async fn resolve_incoming(
    shell: &Shell,
    asker: &impl Ask,
    warning_id: String,
    decision: MassDeleteDecision,
) -> Answer<MassDeleteOutcome> {
    let probe = warning_id.clone();
    let (folder, folder_name, count, revision) = shell
        .engine(move |core| {
            let snapshot = core.snapshot();
            let (folder, name, count) = snapshot
                .warnings
                .iter()
                .find_map(|w| match w {
                    Warning::IncomingDelete {
                        id,
                        folder_id,
                        folder_name,
                        count,
                        ..
                    } if *id == probe => Some((folder_id.clone(), folder_name.clone(), *count)),
                    _ => None,
                })
                .ok_or(SyncError::Invalid("unknown warning"))?;
            let revision = core.incoming_delete_revision(&folder)?;
            Ok((folder, name, count, revision))
        })
        .await?;
    let restore = decision == MassDeleteDecision::Restore;
    if !restore {
        let confirm = crate::confirm::incoming_delete(shell.language(), &folder_name, count);
        if !asker.ask(shell, confirm).await? {
            return Ok(MassDeleteOutcome::Declined);
        }
    }
    let count = shell
        .engine(move |core| core.resolve_incoming_delete(&folder, restore, revision))
        .await?;
    Ok(MassDeleteOutcome::Resolved { count })
}

#[tauri::command]
pub async fn find_missing_folder(
    app: AppHandle,
    shell: State<'_, Shell>,
    folder_id: String,
) -> Answer<PickResult> {
    let Some(path) = pick_directory(&app, &shell).await? else {
        return Ok(PickResult::Cancelled);
    };
    let text = path_text(&path);
    let probe = text.clone();
    shell
        .engine(move |core| {
            if let Some(refusal) = core.check_folder(&probe, Some(&folder_id)) {
                return Ok(refusal.into());
            }
            Ok(if core.relocate_folder(&folder_id, &probe)? {
                PickResult::Picked {
                    name: folder_name_of(&text),
                    path: text,
                    // The folder is relocated already; the token names nothing to do.
                    token: String::new(),
                }
            } else {
                PickResult::Refused {
                    reason: FolderRefusal::WrongFolder,
                    folder: None,
                }
            })
        })
        .await
}

/// "Download again" (UX 8.2): the folder's old place is checked as a sync root and created
/// again (security review L4), then the engine fills it from the server.
#[tauri::command]
pub async fn redownload_folder(shell: State<'_, Shell>, folder_id: String) -> Answer<()> {
    let probe = folder_id.clone();
    let path = shell.engine(move |core| core.folder_path(&probe)).await?;
    check_then_create(&shell, Path::new(&path), Some(folder_id.clone()))
        .await?
        .map_err(refused)?;
    shell
        .engine(move |core| core.redownload_folder(&folder_id))
        .await
}

/// The server number of the key the server presents now, and the server CLI command to compare
/// it with (ADR 0001, section 6, "Pin rotation").
#[tauri::command]
pub async fn get_server_number(shell: State<'_, Shell>) -> Answer<ServerNumberView> {
    shell.engine(|core| core.server_number()).await
}

/// Trusts the key whose server number the window showed, after one more question in a native
/// dialog that shows the number (security review L2); "no" there changes nothing.
#[tauri::command]
pub async fn confirm_server_number(
    app: AppHandle,
    shell: State<'_, Shell>,
) -> Answer<ServerConfirm> {
    trust_server_number(&shell, &Native(&app)).await
}

/// The pin of the number in the dialog is taken before the dialog opens and handed back as it
/// is (security review N7): should another number be shown meanwhile, the engine refuses
/// instead of trusting a key the person never compared.
async fn trust_server_number(shell: &Shell, asker: &impl Ask) -> Answer<ServerConfirm> {
    let shown = shell.engine(|core| core.server_number()).await?;
    let pin = shown.pin;
    let confirm = crate::confirm::server_number(shell.language(), &shown.number.groups);
    if !asker.ask(shell, confirm).await? {
        return Ok(ServerConfirm::Declined);
    }
    shell
        .engine(move |core| core.confirm_server_number(&pin))
        .await?;
    Ok(ServerConfirm::Confirmed)
}

/// The server's new address and pin from a pairing offer of a device that still connects
/// (ADR 0001, section 6); this device does not pair again.
#[tauri::command]
pub async fn fix_server_with_offer(
    shell: State<'_, Shell>,
    link: String,
) -> Answer<ApiResult<(), FixServerError>> {
    shell
        .engine(move |core| core.fix_server_with_offer(&link))
        .await
}

#[tauri::command]
pub async fn check_older_state(shell: State<'_, Shell>, folder_id: String) -> Answer<&'static str> {
    let older = shell
        .engine(move |core| core.check_older_state(&folder_id))
        .await?;
    Ok(if older { "stillOlder" } else { "resolved" })
}

/// Continues a folder with the server's older state after a native question that names the
/// folder and what is lost (security review M4); `compared` picks the words of the path with or
/// without the folder number comparison. The engine's re-anchor is the same either way.
#[tauri::command]
pub async fn reanchor(
    app: AppHandle,
    shell: State<'_, Shell>,
    folder_id: String,
    compared: bool,
) -> Answer<Confirmation> {
    continue_older(&shell, &Native(&app), folder_id, compared).await
}

async fn continue_older(
    shell: &Shell,
    asker: &impl Ask,
    folder_id: String,
    compared: bool,
) -> Answer<Confirmation> {
    let snapshot = fresh_snapshot(shell).await?;
    let name = snapshot
        .folders
        .iter()
        .find(|f| f.id == folder_id)
        .map(|f| f.name.clone())
        .ok_or_else(|| CommandError::invalid("unknown folder"))?;
    let confirm = crate::confirm::reanchor(shell.language(), &name, compared);
    if !asker.ask(shell, confirm).await? {
        return Ok(Confirmation::Declined);
    }
    shell.engine(move |core| core.reanchor(&folder_id)).await?;
    Ok(Confirmation::Confirmed)
}

#[tauri::command]
pub async fn dismiss_suspect(shell: State<'_, Shell>, warning_id: String) -> Answer<()> {
    shell
        .engine(move |core| core.dismiss_warning(&warning_id))
        .await
}

/// Security review H1: the person takes the heads of a removed device in; the window then
/// offers "Undo a device" from the entry before them.
///
/// Asks once more in a native dialog that names the folder and the removed devices (security
/// review M4); "no" there leaves the folder stopped.
#[tauri::command]
pub async fn accept_removed_heads(
    app: AppHandle,
    shell: State<'_, Shell>,
    folder_id: String,
) -> Answer<HeadsAnswer> {
    take_removed_heads(&shell, &Native(&app), folder_id).await
}

async fn take_removed_heads(
    shell: &Shell,
    asker: &impl Ask,
    folder_id: String,
) -> Answer<HeadsAnswer> {
    let snapshot = fresh_snapshot(shell).await?;
    let (folder, devices) = snapshot
        .warnings
        .iter()
        .find_map(|w| match w {
            Warning::RemovedHeads {
                folder_id: id,
                folder_name,
                devices,
                ..
            } if *id == folder_id => Some((folder_name.clone(), devices.clone())),
            _ => None,
        })
        .ok_or_else(|| CommandError::invalid("no changes of a removed device wait here"))?;
    let confirm = crate::confirm::accept_heads(shell.language(), &folder, &devices);
    if !asker.ask(shell, confirm).await? {
        return Ok(HeadsAnswer::Declined);
    }
    let accepted = shell
        .engine(move |core| core.accept_removed_heads(&folder_id))
        .await?;
    Ok(HeadsAnswer::Accepted(accepted))
}

#[tauri::command]
pub async fn open_storage_settings() -> Answer<()> {
    crate::platform::open_storage_settings().map_err(CommandError::from)
}

/// The report reads the snapshot the window shows: a report is wanted most when the engine is
/// stuck in a long round, and asking it would wait for that round.
async fn report(shell: &Shell) -> String {
    let snapshot = window_snapshot(shell).await.ok();
    crate::documents::error_report(
        env!("CARGO_PKG_VERSION"),
        snapshot.as_ref(),
        shell.engine_error().as_deref(),
    )
}

#[tauri::command]
pub async fn copy_error_report(app: AppHandle, shell: State<'_, Shell>) -> Answer<()> {
    let text = report(&shell).await;
    app.clipboard()
        .write_text(text)
        .map_err(|e| CommandError::unexpected(e.to_string()))
}

#[tauri::command]
pub async fn preview_error_report(shell: State<'_, Shell>) -> Answer<String> {
    Ok(report(&shell).await)
}

#[tauri::command]
pub async fn save_error_report(app: AppHandle, shell: State<'_, Shell>) -> Answer<SaveResult> {
    let text = report(&shell).await;
    let Some(path) = save_dialog(
        &app,
        &shell,
        dirs::document_dir(),
        "Hangar Drive report.txt".to_owned(),
    )
    .await?
    else {
        return Ok(SaveResult::Cancelled);
    };
    let shown = path_text(&path);
    blocking(move || std::fs::write(&path, text).map_err(CommandError::from)).await?;
    Ok(SaveResult::Saved { path: shown })
}

// ---------------------------------------------------------------------------------------------
// Conflicts and names

#[tauri::command]
pub async fn list_conflicts(shell: State<'_, Shell>) -> Answer<Vec<ConflictGroup>> {
    shell.engine(|core| Ok(core.list_conflicts())).await
}

/// Shows the original of a conflict group selected in the file manager, its copies next to it.
#[tauri::command]
pub async fn open_conflict(shell: State<'_, Shell>, group_id: String) -> Answer<()> {
    let snapshot = window_snapshot(&shell).await?;
    let groups = shell.engine(|core| Ok(core.list_conflicts())).await?;
    let group = groups
        .into_iter()
        .find(|g| g.id == group_id)
        .ok_or_else(|| CommandError::invalid("unknown conflict"))?;
    let root = folder_path(&snapshot, Some(&group.folder_id))
        .ok_or_else(|| CommandError::invalid("unknown folder"))?;
    blocking(move || {
        let target = checked_inside(&root, &group.path)?;
        crate::platform::reveal(&target, true).map_err(CommandError::from)
    })
    .await
}

#[tauri::command]
pub async fn keep_conflict_version(
    shell: State<'_, Shell>,
    group_id: String,
    version_id: String,
) -> Answer<UndoToken> {
    let token = shell
        .engine(move |core| core.keep_conflict_version(&group_id, &version_id))
        .await?;
    Ok(UndoToken { undo_token: token })
}

#[tauri::command]
pub async fn keep_both_conflict(shell: State<'_, Shell>, group_id: String) -> Answer<()> {
    shell
        .engine(move |core| core.keep_both_conflict(&group_id))
        .await
}

/// Undoes a restore, a folder reset or a "keep this" by its token: a new commit with the state
/// before the action.
#[tauri::command]
pub async fn undo(shell: State<'_, Shell>, token: String) -> Answer<()> {
    shell.engine(move |core| core.undo(&token)).await
}

#[tauri::command]
pub async fn list_name_issues(shell: State<'_, Shell>) -> Answer<Vec<NameIssue>> {
    shell.engine(|core| Ok(core.list_name_issues())).await
}

#[tauri::command]
pub async fn rename_name_issue(
    shell: State<'_, Shell>,
    issue_id: String,
    name: String,
) -> Answer<ApiResult<(), RenameError>> {
    shell
        .engine(move |core| core.rename_name_issue(&issue_id, &name))
        .await
}

#[tauri::command]
pub async fn ignore_name_issue(shell: State<'_, Shell>, issue_id: String) -> Answer<()> {
    shell
        .engine(move |core| core.ignore_name_issue(&issue_id))
        .await
}

// ---------------------------------------------------------------------------------------------
// Restore

/// The folder's history; `path` (the history of one file) is not narrowed yet, the window
/// filters the tree of each entry itself.
#[tauri::command]
pub async fn get_timeline(
    shell: State<'_, Shell>,
    folder_id: String,
    path: Option<String>,
) -> Answer<Timeline> {
    let _ = path;
    shell
        .engine(move |core| core.get_timeline(&folder_id, TIMELINE_LIMIT))
        .await
}

#[tauri::command]
pub async fn get_tree_at(
    shell: State<'_, Shell>,
    folder_id: String,
    entry_id: String,
) -> Answer<VersionTree> {
    shell
        .engine(move |core| core.get_tree_at(&folder_id, &entry_id))
        .await
}

/// The engine restores in place, and under another name when the name is taken; `mode` is
/// read once the engine offers "as a copy" (see the report).
#[tauri::command]
pub async fn restore_file(
    shell: State<'_, Shell>,
    folder_id: String,
    entry_id: String,
    path: String,
    mode: String,
) -> Answer<RestoreOutcome> {
    let _ = mode;
    shell
        .engine(move |core| core.restore_file(&folder_id, &entry_id, &path))
        .await
}

/// Resetting a folder changes it on every device, so it asks natively every time, with the
/// folder's name and the number of files that disappear, which the engine counts first
/// (follow-up check N-1); the window asks nothing before it. `None`: the person said no.
#[tauri::command]
pub async fn reset_folder(
    app: AppHandle,
    shell: State<'_, Shell>,
    folder_id: String,
    entry_id: String,
) -> Answer<Option<RestoreOutcome>> {
    reset_to_entry(&shell, &Native(&app), folder_id, entry_id).await
}

async fn reset_to_entry(
    shell: &Shell,
    asker: &impl Ask,
    folder_id: String,
    entry_id: String,
) -> Answer<Option<RestoreOutcome>> {
    let (folder, entry) = (folder_id.clone(), entry_id.clone());
    let preview = shell
        .engine(move |core| core.reset_folder_preview(&folder, &entry))
        .await?;
    let confirm =
        crate::confirm::reset_folder(shell.language(), &preview.folder_name, preview.vanishing);
    if !asker.ask(shell, confirm).await? {
        return Ok(None);
    }
    let outcome = shell
        .engine(move |core| core.reset_folder(&folder_id, &entry_id))
        .await?;
    Ok(Some(outcome))
}

/// Stops a restore that waits for the upload budget (UX 9.1).
#[tauri::command]
pub async fn cancel_restore(shell: State<'_, Shell>, job_id: String) -> Answer<()> {
    shell.engine(move |core| core.cancel_restore(&job_id)).await
}

#[tauri::command]
pub async fn find_before_device(
    shell: State<'_, Shell>,
    folder_id: String,
    device_id: String,
    from: i64,
) -> Answer<Option<String>> {
    shell
        .engine(move |core| core.find_before_device(&folder_id, &device_id, from))
        .await
}

#[tauri::command]
pub async fn get_trash(shell: State<'_, Shell>, folder_id: String) -> Answer<Vec<TrashItem>> {
    shell
        .engine(move |core| core.get_trash(&folder_id, TRASH_DEPTH))
        .await
}

#[tauri::command]
pub async fn restore_trash(
    shell: State<'_, Shell>,
    folder_id: String,
    item_ids: Vec<String>,
) -> Answer<RestoreOutcome> {
    shell
        .engine(move |core| core.restore_trash(&folder_id, &item_ids))
        .await
}

// ---------------------------------------------------------------------------------------------
// Devices

#[tauri::command]
pub async fn list_devices(shell: State<'_, Shell>) -> Answer<DeviceList> {
    shell.engine(|core| core.list_devices()).await
}

/// A name that looks like another device's is taken only after a native question that names
/// that device (skeleton check of device names); "no" answers `looksLike`.
#[tauri::command]
pub async fn rename_device(
    app: AppHandle,
    shell: State<'_, Shell>,
    device_id: String,
    name: String,
) -> Answer<ApiResult<(), DeviceNameError>> {
    rename_checked(&shell, &Native(&app), device_id, name).await
}

async fn rename_checked(
    shell: &Shell,
    asker: &impl Ask,
    device_id: String,
    name: String,
) -> Answer<ApiResult<(), DeviceNameError>> {
    let (device, probe) = (device_id.clone(), name.clone());
    let first = shell
        .engine(move |core| core.rename_device(&device, &probe, false))
        .await?;
    if first != ApiResult::Err(DeviceNameError::LooksLike) {
        return Ok(first);
    }
    let (device, probe) = (device_id.clone(), name.clone());
    let other = shell
        .engine(move |core| Ok(core.similar_device_name(&probe, Some(&device))))
        .await?
        .unwrap_or_default();
    let confirm = crate::confirm::look_alike_name(shell.language(), &name, &other);
    if !asker.ask(shell, confirm).await? {
        return Ok(first);
    }
    shell
        .engine(move |core| core.rename_device(&device_id, &name, true))
        .await
}

#[tauri::command]
pub async fn get_safety_number(shell: State<'_, Shell>, device_id: String) -> Answer<NumberRows> {
    shell
        .engine(move |core| core.get_safety_number(&device_id))
        .await
}

/// Asks in a native dialog that names the device (security review M4); the window asks nothing
/// before it. "No" there keeps the device.
#[tauri::command]
pub async fn remove_device(
    app: AppHandle,
    shell: State<'_, Shell>,
    device_id: String,
) -> Answer<Confirmation> {
    remove_one_device(&shell, &Native(&app), device_id).await
}

async fn remove_one_device(
    shell: &Shell,
    asker: &impl Ask,
    device_id: String,
) -> Answer<Confirmation> {
    let devices = shell.engine(|core| core.list_devices()).await?;
    let name = devices
        .devices
        .iter()
        .find(|d| d.id == device_id && !d.is_this)
        .map(|d| d.name.clone())
        .ok_or_else(|| CommandError::invalid("unknown device"))?;
    let confirm = crate::confirm::remove_device(shell.language(), &name);
    if !asker.ask(shell, confirm).await? {
        return Ok(Confirmation::Declined);
    }
    shell
        .engine(move |core| core.remove_device(&device_id).map(drop))
        .await?;
    Ok(Confirmation::Confirmed)
}

#[tauri::command]
pub async fn create_pairing_offer(shell: State<'_, Shell>) -> Answer<PairingOffer> {
    let offer = shell.engine(|core| core.create_pairing_offer()).await?;
    let (qr, qr_svg) =
        crate::qr::encode(&offer.link).map_err(|e| CommandError::unexpected(e.to_string()))?;
    shell.remember_offer(offer.id.clone(), offer.link.clone());
    Ok(PairingOffer {
        id: offer.id,
        link: offer.link,
        code: offer.code,
        host: offer.host,
        account: offer.account,
        qr,
        qr_svg,
        expires_at: offer.expires_at,
    })
}

#[tauri::command]
pub async fn copy_pairing_link(
    app: AppHandle,
    shell: State<'_, Shell>,
    offer_id: String,
) -> Answer<()> {
    let link = shell
        .offer_link(&offer_id)
        .ok_or_else(|| CommandError::invalid("unknown offer"))?;
    copy_and_clear(&app, &shell, Zeroizing::new(link))
}

/// Accepting asks once more in a native dialog that names the new device and its safety number
/// (security review L2); "no" there declines the request.
#[tauri::command]
pub async fn answer_pair_request(
    app: AppHandle,
    shell: State<'_, Shell>,
    offer_id: String,
    accept: bool,
) -> Answer<PairAnswer> {
    let mut accept = accept;
    if accept {
        let probe = offer_id.clone();
        let request = shell
            .engine(move |core| Ok(core.pair_request(&probe)))
            .await?
            .ok_or_else(|| CommandError::invalid("no device is waiting for this offer"))?;
        let confirm = crate::confirm::pairing(
            shell.language(),
            &request.device_name,
            &request.safety.groups,
            request.similar_to.as_deref(),
        );
        accept = native_confirm(&app, &shell, confirm).await?;
    }
    shell
        .engine(move |core| core.answer_pair_request(&offer_id, accept))
        .await?;
    Ok(if accept {
        PairAnswer::Added
    } else {
        PairAnswer::Declined
    })
}

/// The server reported this device as removed, which this device cannot check (security review
/// H2): the account is forgotten here only after a native question; "no" keeps it, and the
/// engine keeps sync stopped while the server says so.
#[tauri::command]
pub async fn confirm_device_removed(
    app: AppHandle,
    shell: State<'_, Shell>,
) -> Answer<Confirmation> {
    forget_removed(&shell, &Native(&app)).await
}

async fn forget_removed(shell: &Shell, asker: &impl Ask) -> Answer<Confirmation> {
    let reported = fresh_snapshot(shell)
        .await?
        .warnings
        .iter()
        .any(|w| matches!(w, Warning::RemovalReported { .. }));
    if !reported {
        return Err(CommandError::invalid("the server did not report a removal"));
    }
    let confirm = crate::confirm::removal_reported(shell.language());
    if !asker.ask(shell, confirm).await? {
        return Ok(Confirmation::Declined);
    }
    shell.engine(|core| core.confirm_device_removed()).await?;
    *lock(&shell.shown) = None;
    *lock(&shell.device_name) = None;
    Ok(Confirmation::Confirmed)
}

/// Forgets the account on this device (security review L1): secrets, stored account and the
/// folders' sync state; the files stay. For "pair again" after a removal and for starting over.
///
/// Asks in a native dialog first (security review M4); the window asks nothing before it. While
/// a recovery is pending it asks nothing and answers [`ResetOutcome::RecoveryPending`]; the
/// engine refuses the plain reset then as well.
#[tauri::command]
pub async fn reset_device(app: AppHandle, shell: State<'_, Shell>) -> Answer<ResetOutcome> {
    reset(&shell, &Native(&app)).await
}

async fn reset(shell: &Shell, asker: &impl Ask) -> Answer<ResetOutcome> {
    if recovery_pending(&fresh_snapshot(shell).await?) {
        return Ok(ResetOutcome::RecoveryPending);
    }
    if !asker
        .ask(shell, crate::confirm::reset(shell.language()))
        .await?
    {
        return Ok(ResetOutcome::Declined);
    }
    let reset = shell.engine(|core| Ok(core.reset_device())).await?;
    let outcome = reset_outcome(reset)?;
    if outcome == ResetOutcome::Confirmed {
        forget_shown(shell);
    }
    Ok(outcome)
}

/// Whether the snapshot shows a recovery that is not finished (warning `recoveryPending`).
fn recovery_pending(snapshot: &Snapshot) -> bool {
    snapshot
        .warnings
        .iter()
        .any(|w| matches!(w, Warning::RecoveryPending { .. }))
}

/// The engine's answer to a plain reset: its refusal during a pending recovery is an outcome the
/// window explains (a recovery can become pending between the check and the reset), every other
/// error stays an error.
fn reset_outcome(result: Result<(), SyncError>) -> Answer<ResetOutcome> {
    match result {
        Ok(()) => Ok(ResetOutcome::Confirmed),
        Err(SyncError::RecoveryPending) => Ok(ResetOutcome::RecoveryPending),
        Err(error) => Err(error.into()),
    }
}

fn forget_shown(shell: &Shell) {
    *lock(&shell.shown) = None;
    *lock(&shell.device_name) = None;
}

/// Resets this device although a recovery is pending (follow-up review LOW 7): the pending
/// recovery's key leaves with every other secret, so the account may be lost for good. Only
/// after a native question that says so, "no" as its default; the window explains first.
#[tauri::command]
pub async fn reset_device_discarding_recovery(
    app: AppHandle,
    shell: State<'_, Shell>,
) -> Answer<Confirmation> {
    reset_discarding(&shell, &Native(&app)).await
}

async fn reset_discarding(shell: &Shell, asker: &impl Ask) -> Answer<Confirmation> {
    if !asker
        .ask(
            shell,
            crate::confirm::reset_discarding_recovery(shell.language()),
        )
        .await?
    {
        return Ok(Confirmation::Declined);
    }
    shell
        .engine(|core| core.reset_device_discarding_recovery())
        .await?;
    forget_shown(shell);
    Ok(Confirmation::Confirmed)
}

/// Disconnects this device from its account (N2 "these are not my devices", and the device
/// list): the engine forgets the account here at once, as a reset does. The device stays in the
/// account's log until a device of that account removes it; it has no keys left to use it.
/// Asks in a native dialog first, with the warning for the account's last device (security
/// review M4, ux-concept 10.2); the window asks nothing before it.
#[tauri::command]
pub async fn disconnect_this_device(
    app: AppHandle,
    shell: State<'_, Shell>,
) -> Answer<Confirmation> {
    disconnect(&shell, &Native(&app)).await
}

async fn disconnect(shell: &Shell, asker: &impl Ask) -> Answer<Confirmation> {
    // The last device unless the list names another regular one; a list that cannot be read
    // (no connection) asks the plain question.
    let last_one = shell
        .engine(|core| core.list_devices())
        .await
        .is_ok_and(|list| list.devices.iter().all(|d| d.is_this));
    let confirm = crate::confirm::disconnect(shell.language(), last_one);
    if !asker.ask(shell, confirm).await? {
        return Ok(Confirmation::Declined);
    }
    shell.engine(|core| core.disconnect_this_device()).await?;
    *lock(&shell.shown) = None;
    *lock(&shell.device_name) = None;
    Ok(Confirmation::Confirmed)
}

/// Installs a signed update (`tauri-plugin-updater`, [`crate::updater`]); a clear error while
/// tauri.conf.json carries no updater public key.
///
/// A found update is installed only after a native question that names its version (security
/// review, information finding); "no" there installs nothing.
#[tauri::command]
pub async fn install_update(
    app: AppHandle,
    shell: State<'_, Shell>,
    updates: State<'_, crate::updater::Updates>,
) -> Answer<crate::updater::UpdateOutcome> {
    use tauri_plugin_updater::UpdaterExt as _;
    if !updates.enabled {
        return Err(CommandError::unexpected(crate::updater::OFF));
    }
    let updater = app
        .updater()
        .map_err(|e| CommandError::unexpected(e.to_string()))?;
    let Some(update) = updater
        .check()
        .await
        .map_err(|e| CommandError::unexpected(e.to_string()))?
    else {
        return Ok(crate::updater::UpdateOutcome::UpToDate);
    };
    let version = update.version.clone();
    let confirm = crate::confirm::install_update(shell.language(), &version);
    if !Native(&app).ask(&shell, confirm).await? {
        return Ok(crate::updater::UpdateOutcome::Declined);
    }
    clear_copied_secret(&app);
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|e| CommandError::unexpected(e.to_string()))?;
    Ok(crate::updater::UpdateOutcome::Installed { version })
}

#[tauri::command]
pub async fn renew_recovery_code(shell: State<'_, Shell>) -> Answer<RecoveryCodeView> {
    let view = shell.engine(|core| core.renew_recovery_code()).await?;
    remember_code(&shell, &view, true);
    Ok(view)
}

// ---------------------------------------------------------------------------------------------
// Settings

#[tauri::command]
pub async fn get_settings(app: AppHandle, shell: State<'_, Shell>) -> Answer<SettingsView> {
    Ok(SettingsView {
        autostart: app.autolaunch().is_enabled().unwrap_or(false),
        language: lock(&shell.settings).language.clone(),
        folder_view: lock(&shell.settings).folder_view.clone(),
    })
}

/// Turning autostart off asks in a native dialog first (security review M4): a page that was
/// taken over must not stop the sync from starting unnoticed. Turning it on asks nothing.
#[tauri::command]
pub async fn set_autostart(
    app: AppHandle,
    shell: State<'_, Shell>,
    on: bool,
) -> Answer<Confirmation> {
    let launcher = app.autolaunch();
    if on {
        launcher
            .enable()
            .map_err(|e| CommandError::unexpected(e.to_string()))?;
        return Ok(Confirmation::Confirmed);
    }
    let confirm = crate::confirm::autostart_off(shell.language());
    if !Native(&app).ask(&shell, confirm).await? {
        return Ok(Confirmation::Declined);
    }
    launcher
        .disable()
        .map_err(|e| CommandError::unexpected(e.to_string()))?;
    Ok(Confirmation::Confirmed)
}

/// The backend's texts (notifications, the recovery file) follow at once; the engine's
/// conflict and restore words with the next start.
#[tauri::command]
pub async fn set_language(shell: State<'_, Shell>, language: String) -> Answer<()> {
    if !crate::settings::is_language_choice(&language) {
        return Err(CommandError::invalid("unknown language"));
    }
    lock(&shell.settings).language = language;
    shell.save_settings_off_thread().await
}

/// How the main window lists the folders, kept across restarts.
#[tauri::command]
pub async fn set_folder_view(shell: State<'_, Shell>, view: String) -> Answer<()> {
    if !crate::settings::is_folder_view(&view) {
        return Err(CommandError::invalid("unknown folder view"));
    }
    lock(&shell.settings).folder_view = view;
    shell.save_settings_off_thread().await
}

/// Version and build: the build is the `+B` of the version (ADR 0002), absent in a plain
/// `X.Y.Z`.
#[tauri::command]
pub async fn get_about(updates: State<'_, crate::updater::Updates>) -> Answer<About> {
    Ok(about(env!("CARGO_PKG_VERSION"), *updates))
}

pub fn about(version: &str, updates: crate::updater::Updates) -> About {
    let (base, build) = match version.split_once('+') {
        Some((base, build)) => (base, build.parse::<u64>().ok()),
        None => (version, None),
    };
    About {
        version: base.to_owned(),
        build,
        updates: updates.enabled,
    }
}

// ---------------------------------------------------------------------------------------------
// Tray, window, links

#[tauri::command]
pub async fn update_tray(app: AppHandle, model: crate::tray::TrayModel) -> Answer<()> {
    let (model, ids) = model
        .checked()
        .map_err(|e| CommandError::invalid(e.to_string()))?;
    let Some(seq) = app.state::<crate::tray::TrayState>().changes(&model) else {
        return Ok(());
    };
    crate::tray::apply(&app, seq, model, ids).map_err(CommandError::from)
}

#[tauri::command]
pub async fn show_window(app: AppHandle) -> Answer<()> {
    crate::tray::show_main_window(&app);
    Ok(())
}

#[tauri::command]
pub async fn quit(app: AppHandle) -> Answer<()> {
    app.exit(0);
    Ok(())
}

/// Every command, for the invoke handler (the same list as build.rs `COMMANDS`).
#[macro_export]
macro_rules! command_handler {
    () => {
        tauri::generate_handler![
            $crate::commands::get_snapshot,
            $crate::commands::get_traffic,
            $crate::commands::read_clipboard_text,
            $crate::commands::check_invite,
            $crate::commands::inspect_link,
            $crate::commands::default_device_name,
            $crate::commands::begin_account,
            $crate::commands::print_recovery_sheet,
            $crate::commands::save_recovery_file,
            $crate::commands::copy_recovery_code,
            $crate::commands::confirm_recovery_group,
            $crate::commands::default_folder_place,
            $crate::commands::pick_folder,
            $crate::commands::count_local_files,
            $crate::commands::finish_setup,
            $crate::commands::scan_with_camera,
            $crate::commands::start_pairing,
            $crate::commands::cancel_pairing,
            $crate::commands::list_account_folders,
            $crate::commands::join_folders,
            $crate::commands::recover_account,
            $crate::commands::set_device_name,
            $crate::commands::recovery_devices,
            $crate::commands::finish_recovery_cleanup,
            $crate::commands::open_folder,
            $crate::commands::pause,
            $crate::commands::resume,
            $crate::commands::sync_now,
            $crate::commands::retry_connection,
            $crate::commands::pause_folder,
            $crate::commands::resume_folder,
            $crate::commands::add_folder,
            $crate::commands::add_account_folder,
            $crate::commands::stop_folder,
            $crate::commands::delete_folder_everywhere,
            $crate::commands::list_not_synced,
            $crate::commands::get_folder_number,
            $crate::commands::list_mass_delete,
            $crate::commands::resolve_mass_delete,
            $crate::commands::list_incoming_delete,
            $crate::commands::resolve_incoming_delete,
            $crate::commands::find_missing_folder,
            $crate::commands::check_older_state,
            $crate::commands::reanchor,
            $crate::commands::dismiss_suspect,
            $crate::commands::accept_removed_heads,
            $crate::commands::open_storage_settings,
            $crate::commands::copy_error_report,
            $crate::commands::preview_error_report,
            $crate::commands::save_error_report,
            $crate::commands::list_conflicts,
            $crate::commands::open_conflict,
            $crate::commands::keep_conflict_version,
            $crate::commands::keep_both_conflict,
            $crate::commands::list_name_issues,
            $crate::commands::rename_name_issue,
            $crate::commands::ignore_name_issue,
            $crate::commands::get_timeline,
            $crate::commands::get_tree_at,
            $crate::commands::restore_file,
            $crate::commands::reset_folder,
            $crate::commands::find_before_device,
            $crate::commands::get_trash,
            $crate::commands::restore_trash,
            $crate::commands::list_devices,
            $crate::commands::rename_device,
            $crate::commands::get_safety_number,
            $crate::commands::remove_device,
            $crate::commands::create_pairing_offer,
            $crate::commands::copy_pairing_link,
            $crate::commands::answer_pair_request,
            $crate::commands::renew_recovery_code,
            $crate::commands::reset_device,
            $crate::commands::reset_device_discarding_recovery,
            $crate::commands::disconnect_this_device,
            $crate::commands::undo,
            $crate::commands::restore_deleted_folder,
            $crate::commands::cancel_restore,
            $crate::commands::redownload_folder,
            $crate::commands::get_server_number,
            $crate::commands::confirm_server_number,
            $crate::commands::fix_server_with_offer,
            $crate::commands::restore_remote_deleted,
            $crate::commands::confirm_device_removed,
            $crate::commands::install_update,
            $crate::commands::get_settings,
            $crate::commands::set_autostart,
            $crate::commands::set_language,
            $crate::commands::set_folder_view,
            $crate::commands::get_about,
            $crate::commands::update_tray,
            $crate::commands::show_window,
            $crate::commands::quit,
        ]
    };
}

/// The command names of the handler, for the test against build.rs and the capability file.
#[cfg(test)]
pub const COMMAND_NAMES: &[&str] = &[
    "get_snapshot",
    "get_traffic",
    "read_clipboard_text",
    "check_invite",
    "inspect_link",
    "default_device_name",
    "begin_account",
    "print_recovery_sheet",
    "save_recovery_file",
    "copy_recovery_code",
    "confirm_recovery_group",
    "default_folder_place",
    "pick_folder",
    "count_local_files",
    "finish_setup",
    "scan_with_camera",
    "start_pairing",
    "cancel_pairing",
    "list_account_folders",
    "join_folders",
    "recover_account",
    "set_device_name",
    "recovery_devices",
    "finish_recovery_cleanup",
    "open_folder",
    "pause",
    "resume",
    "sync_now",
    "retry_connection",
    "pause_folder",
    "resume_folder",
    "add_folder",
    "add_account_folder",
    "stop_folder",
    "delete_folder_everywhere",
    "list_not_synced",
    "get_folder_number",
    "list_mass_delete",
    "resolve_mass_delete",
    "list_incoming_delete",
    "resolve_incoming_delete",
    "find_missing_folder",
    "check_older_state",
    "reanchor",
    "dismiss_suspect",
    "accept_removed_heads",
    "open_storage_settings",
    "copy_error_report",
    "preview_error_report",
    "save_error_report",
    "list_conflicts",
    "open_conflict",
    "keep_conflict_version",
    "keep_both_conflict",
    "list_name_issues",
    "rename_name_issue",
    "ignore_name_issue",
    "get_timeline",
    "get_tree_at",
    "restore_file",
    "reset_folder",
    "find_before_device",
    "get_trash",
    "restore_trash",
    "list_devices",
    "rename_device",
    "get_safety_number",
    "remove_device",
    "create_pairing_offer",
    "copy_pairing_link",
    "answer_pair_request",
    "renew_recovery_code",
    "reset_device",
    "reset_device_discarding_recovery",
    "disconnect_this_device",
    "undo",
    "restore_deleted_folder",
    "cancel_restore",
    "redownload_folder",
    "get_server_number",
    "confirm_server_number",
    "fix_server_with_offer",
    "restore_remote_deleted",
    "confirm_device_removed",
    "install_update",
    "get_settings",
    "set_autostart",
    "set_language",
    "set_folder_view",
    "get_about",
    "update_tray",
    "show_window",
    "quit",
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn arguments_read_as_the_window_sends_them() {
        let p: PickPurpose =
            serde_json::from_value(json!({ "kind": "find", "folderId": "ab" })).unwrap();
        assert!(matches!(p, PickPurpose::Find { folder_id } if folder_id == "ab"));
        let p: PickPurpose = serde_json::from_value(json!({ "kind": "new" })).unwrap();
        assert!(matches!(p, PickPurpose::New));
        let i: PairInput =
            serde_json::from_value(json!({ "kind": "typed", "server": "s", "code": "c" })).unwrap();
        assert!(matches!(i, PairInput::Typed { .. }));
        let c: FolderChoice =
            serde_json::from_value(json!({ "folderId": "f", "token": "t0k" })).unwrap();
        assert_eq!((c.folder_id.as_str(), c.token.as_str()), ("f", "t0k"));
        // A path where a token belongs is refused.
        assert!(serde_json::from_value::<FolderChoice>(
            json!({ "folderId": "f", "path": "C:\\x" })
        )
        .is_err());
        let d: MassDeleteDecision = serde_json::from_value(json!("restore")).unwrap();
        assert_eq!(d, MassDeleteDecision::Restore);
        let d: PauseDuration = serde_json::from_value(json!("manual")).unwrap();
        assert_eq!(d, PauseDuration::Manual);
    }

    #[test]
    fn answers_have_the_shape_the_decoders_read() {
        assert_eq!(
            serde_json::to_value(PickResult::Refused {
                reason: FolderRefusal::Nested,
                folder: Some("Docs".into())
            })
            .unwrap(),
            json!({ "kind": "refused", "reason": "nested", "folder": "Docs" })
        );
        assert_eq!(
            serde_json::to_value(SaveResult::InSyncFolder).unwrap(),
            json!({ "kind": "inSyncFolder" })
        );
        assert_eq!(
            serde_json::to_value(SaveResult::InCloudFolder).unwrap(),
            json!({ "kind": "inCloudFolder" })
        );
        assert_eq!(
            serde_json::to_value(PickResult::Picked {
                path: "C:\\Docs".into(),
                name: "Docs".into(),
                token: "t".into()
            })
            .unwrap(),
            json!({ "kind": "picked", "path": "C:\\Docs", "name": "Docs", "token": "t" })
        );
        let r: ApiResult<(), PairStartError> = ApiResult::Err(NameError::EdgeWhitespace.into());
        assert_eq!(
            serde_json::to_value(r).unwrap(),
            json!({ "ok": false, "error": "edgeWhitespace" })
        );
        for (error, code) in [
            (PairError::NotALink, "notALink"),
            (PairError::OtherAccount, "otherAccount"),
            (PairError::TooMany, "tooMany"),
        ] {
            assert_eq!(
                serde_json::to_value(PairStartError::from(error)).unwrap(),
                json!(code)
            );
        }
        assert_eq!(
            serde_json::to_value(FolderNumber::Offline).unwrap(),
            json!({ "kind": "offline" })
        );
        assert_eq!(
            serde_json::to_value(UndoToken {
                undo_token: "t".into()
            })
            .unwrap(),
            json!({ "undoToken": "t" })
        );
        let r: ApiResult<(), NameError> = ApiResult::Ok(());
        assert_eq!(
            serde_json::to_value(r).unwrap(),
            json!({ "ok": true, "value": null })
        );
        let on = crate::updater::Updates { enabled: true };
        let off = crate::updater::Updates { enabled: false };
        assert_eq!(
            serde_json::to_value(about("0.2.0+48", on)).unwrap(),
            json!({ "version": "0.2.0", "build": 48, "updates": true })
        );
        assert_eq!(
            serde_json::to_value(about("0.1.0", off)).unwrap(),
            json!({ "version": "0.1.0", "build": null, "updates": false })
        );
        // A folder row with its size and its number of files, null before the first scan.
        let folder = |bytes: Option<u64>| hangar_drive_sync::api::Folder {
            id: "f".into(),
            name: "Docs".into(),
            path: "C:\\Docs".into(),
            status: hangar_drive_sync::api::FolderStatus::UpToDate,
            freeze_days: None,
            not_synced_count: 0,
            bytes,
            file_count: bytes.map(|_| 12),
        };
        assert_eq!(
            serde_json::to_value(folder(Some(2_400))).unwrap(),
            json!({
                "id": "f",
                "name": "Docs",
                "path": "C:\\Docs",
                "status": { "kind": "upToDate" },
                "freezeDays": null,
                "notSyncedCount": 0,
                "bytes": 2400,
                "fileCount": 12
            })
        );
        let unscanned = serde_json::to_value(folder(None)).unwrap();
        assert_eq!(unscanned["bytes"], json!(null));
        assert_eq!(unscanned["fileCount"], json!(null));
        // The suspect warning and the server notices, as src/backend/tauri/decoders.ts reads
        // them (ADR 0001, section 5).
        let suspect = hangar_drive_sync::api::Warning::Suspect {
            id: "s".into(),
            device_id: "d".into(),
            device_name: "Laptop".into(),
            folder_id: "f".into(),
            folder_name: "Docs".into(),
            entry_id: "e".into(),
            days: 30,
            until: 5,
            lapsed: true,
        };
        assert_eq!(
            serde_json::to_value(suspect).unwrap(),
            json!({ "kind": "suspect", "id": "s", "deviceId": "d", "deviceName": "Laptop",
                "folderId": "f", "folderName": "Docs", "entryId": "e", "days": 30, "until": 5,
                "lapsed": true })
        );
        use hangar_drive_sync::api::ServerNotice;
        for (notice, kind) in [
            (ServerNotice::Quota, "quota"),
            (ServerNotice::BudgetAccount, "budgetAccount"),
            (ServerNotice::ServerDisk, "serverDisk"),
        ] {
            assert_eq!(
                serde_json::to_value(notice).unwrap(),
                json!({ "kind": kind })
            );
        }
        // The outcomes of the two native confirmations, as the window's decoder reads them.
        assert_eq!(
            serde_json::to_value(DeleteOutcome::Deleted).unwrap(),
            json!("deleted")
        );
        assert_eq!(
            serde_json::to_value(DeleteOutcome::Kept).unwrap(),
            json!("kept")
        );
        assert_eq!(
            serde_json::to_value(PairAnswer::Added).unwrap(),
            json!("added")
        );
        assert_eq!(
            serde_json::to_value(PairAnswer::Declined).unwrap(),
            json!("declined")
        );
        let w = PairWaiting {
            path: "link",
            safety: NumberRows {
                groups: vec!["00001".into()],
            },
        };
        assert_eq!(
            serde_json::to_value(w).unwrap(),
            json!({ "path": "link", "safety": { "groups": ["00001"] } })
        );
    }

    /// A shell over a real engine thread with the in-memory ports of the sync crate, and the
    /// engine's event receiver, which keeps the thread running while it lives.
    fn engine_shell() -> (
        Shell,
        std::sync::mpsc::Receiver<hangar_drive_sync::api::BackendEvent>,
    ) {
        engine_shell_on(None)
    }

    /// [`engine_shell`] whose every sync root is `disk` when one is given, so a test can put
    /// files into a folder.
    fn engine_shell_on(
        disk: Option<std::sync::Arc<hangar_drive_sync::memory::MemFs>>,
    ) -> (
        Shell,
        std::sync::mpsc::Receiver<hangar_drive_sync::api::BackendEvent>,
    ) {
        use hangar_drive_sync::engine::{Engine, EngineCore, EnginePorts, EngineSettings};
        use hangar_drive_sync::memory::{
            ManualClock, MemFs, MemKeychain, MemServer, MemStore, SeededRandom,
        };
        let (handle, events) = Engine::spawn(
            || {
                let shared = MemServer::new_shared();
                let ports = EnginePorts {
                    store: Box::new(MemStore::new()),
                    keychain: Box::new(MemKeychain::default()),
                    clock: Box::new(ManualClock::at(1_795_651_200_000)),
                    entropy: Box::new(SeededRandom::new(5)),
                    fs: Box::new(move |_path: &Path| {
                        let fs = disk
                            .clone()
                            .unwrap_or_else(|| std::sync::Arc::new(MemFs::new(true)));
                        Ok((
                            Box::new(fs) as Box<dyn hangar_drive_sync::ports::FileSystem>,
                            None,
                        ))
                    }),
                    server: Box::new(move |_config, identity| {
                        let device = identity.map_or(
                            hangar_drive_protocol::ids::DeviceId::from_bytes([0; 16]),
                            |i| i.device,
                        );
                        Ok(Box::new(MemServer::connect(&shared, device)) as Box<_>)
                    }),
                    roots: Box::new(|path: &Path, _existing: &[PathBuf]| Ok(path.to_path_buf())),
                };
                EngineCore::open(ports, EngineSettings::default())
            },
            Duration::from_millis(5),
        )
        .unwrap();
        (
            Shell::new(Ok(handle), 0, None, crate::settings::Stored::default()),
            events,
        )
    }

    // A blank window waited minutes for its first snapshot while the engine uploaded
    // (2026-11-28): with a snapshot already sent, opening the window never waits on the engine.
    #[test]
    fn an_open_window_gets_the_sent_snapshot_while_the_engine_is_busy() {
        let (shell, _events) = engine_shell();
        let sent = tauri::async_runtime::block_on(fresh_snapshot(&shell)).unwrap();
        *lock(&shell.snapshot) = Some(sent.clone());
        std::thread::scope(|scope| {
            scope.spawn(|| {
                tauri::async_runtime::block_on(shell.engine(|_| {
                    std::thread::sleep(Duration::from_secs(2));
                    Ok(())
                }))
            });
            std::thread::sleep(Duration::from_millis(100));
            let started = std::time::Instant::now();
            let shown = tauri::async_runtime::block_on(window_snapshot(&shell)).unwrap();
            assert!(started.elapsed() < Duration::from_millis(500));
            assert_eq!(shown, sent);
        });
    }

    #[test]
    fn the_command_layer_carries_a_setup_through_the_engine_thread() {
        let (shell, _events) = engine_shell();
        let link = format!(
            "http://localhost:8080/join#{}",
            hangar_drive_protocol::ids::base64url(&[9; 16])
        );
        let probe = link.clone();
        let check =
            tauri::async_runtime::block_on(shell.engine(move |core| Ok(core.check_invite(&probe))))
                .unwrap();
        assert_eq!(
            serde_json::to_value(check).unwrap(),
            json!({ "ok": true, "value": { "host": "localhost:8080", "pinned": false, "punycode": false } })
        );
        let begun = tauri::async_runtime::block_on(
            shell.engine(move |core| core.begin_account(&link, "Laptop")),
        )
        .unwrap();
        let ApiResult::Ok(view) = begun else {
            panic!("begin");
        };
        remember_code(&shell, &view, false);
        assert!(lock(&shell.shown).is_some());
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["groups"].as_array().unwrap().len(), 8);
        assert_eq!(json["sheet"]["genesisAnchor"].as_str().unwrap().len(), 64);
        assert_eq!(json["sheet"]["pin"], serde_json::Value::Null);
        assert!(json["sheet"]["link"]
            .as_str()
            .unwrap()
            .starts_with("hangar-drive://recover#"));
        let group = view.groups[view.check_group as usize - 1].clone();
        assert!(tauri::async_runtime::block_on(
            shell.engine(move |core| core.confirm_recovery_group(&group))
        )
        .unwrap());
        // A warning the window names by its ID leads to its folder; an unknown one is refused.
        let error = tauri::async_runtime::block_on(shell.engine(|core| {
            folder_of_warning(&core.snapshot(), "massDelete-x")
                .ok_or(SyncError::Invalid("unknown warning"))
        }))
        .unwrap_err();
        assert_eq!(error.kind, hangar_drive_sync::error::ErrorKind::Invalid);
        // The incoming question takes only its own warnings: a made-up ID and one of the local
        // question are refused, before anything is asked.
        for id in ["incomingDelete-x", "massDelete-x"] {
            let asked = std::sync::Mutex::new(Vec::new());
            let error = tauri::async_runtime::block_on(resolve_incoming(
                &shell,
                &Fixed(true, &asked),
                id.to_owned(),
                MassDeleteDecision::Delete,
            ))
            .unwrap_err();
            assert_eq!(error.kind, hangar_drive_sync::error::ErrorKind::Invalid);
            assert!(lock(&asked).is_empty(), "{id}");
        }
        let snapshot = tauri::async_runtime::block_on(fresh_snapshot(&shell)).unwrap();
        assert_eq!(
            serde_json::to_value(&snapshot).unwrap()["setup"],
            json!("done")
        );
        // An engine error reaches the window as a code, not as a panic.
        let error =
            tauri::async_runtime::block_on(shell.engine(|core| core.stop_folder("not hex")))
                .unwrap_err();
        assert_eq!(error.code, "unexpected");
    }

    // N2: "these are not my devices" disconnects for real: the engine forgets the account, and
    // the shell the code it showed and the name it kept.
    #[test]
    fn disconnecting_this_device_forgets_the_account() {
        let (shell, _events) = engine_shell();
        let link = format!(
            "http://localhost:8080/join#{}",
            hangar_drive_protocol::ids::base64url(&[9; 16])
        );
        let ApiResult::Ok(view) = tauri::async_runtime::block_on(
            shell.engine(move |core| core.begin_account(&link, "Laptop")),
        )
        .unwrap() else {
            panic!("begin");
        };
        let group = view.groups[view.check_group as usize - 1].clone();
        assert!(tauri::async_runtime::block_on(
            shell.engine(move |core| core.confirm_recovery_group(&group))
        )
        .unwrap());
        remember_code(&shell, &view, false);
        *lock(&shell.device_name) = Some("Laptop".into());
        let snapshot = tauri::async_runtime::block_on(fresh_snapshot(&shell)).unwrap();
        assert_eq!(
            serde_json::to_value(&snapshot).unwrap()["setup"],
            json!("done")
        );

        let asked = std::sync::Mutex::new(Vec::new());
        assert_eq!(
            tauri::async_runtime::block_on(disconnect(&shell, &Fixed(true, &asked))).unwrap(),
            Confirmation::Confirmed
        );

        let snapshot = tauri::async_runtime::block_on(fresh_snapshot(&shell)).unwrap();
        assert_eq!(
            serde_json::to_value(&snapshot).unwrap()["setup"],
            json!("needed")
        );
        assert!(snapshot.warnings.is_empty(), "{:?}", snapshot.warnings);
        assert!(lock(&shell.shown).is_none());
        assert!(lock(&shell.device_name).is_none());
        // Nothing of the account answers any more.
        let devices = tauri::async_runtime::block_on(shell.engine(|core| core.list_devices()));
        assert!(devices.is_err());
    }

    // Security review L5: a path inside a folder is canonicalized and must stay inside.
    #[test]
    fn a_revealed_path_stays_in_its_folder() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(".tmp")
            .join("reveal");
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("Docs");
        std::fs::create_dir_all(root.join("a b")).unwrap();
        std::fs::create_dir_all(base.join("outside")).unwrap();
        std::fs::write(root.join("a b").join("plan, final.txt"), b"x").unwrap();
        let target = checked_inside(&root, "a b/plan, final.txt").unwrap();
        assert!(target.ends_with(Path::new("a b").join("plan, final.txt")));
        assert!(checked_inside(&root, "../outside").is_err());
        assert!(checked_inside(&root, "missing.txt").is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A shell whose device has an account, its recovery code confirmed.
    fn set_up_shell() -> (
        Shell,
        std::sync::mpsc::Receiver<hangar_drive_sync::api::BackendEvent>,
    ) {
        set_up_shell_on(None)
    }

    fn set_up_shell_on(
        disk: Option<std::sync::Arc<hangar_drive_sync::memory::MemFs>>,
    ) -> (
        Shell,
        std::sync::mpsc::Receiver<hangar_drive_sync::api::BackendEvent>,
    ) {
        let (shell, events) = engine_shell_on(disk);
        let link = format!(
            "http://localhost:8080/join#{}",
            hangar_drive_protocol::ids::base64url(&[9; 16])
        );
        let ApiResult::Ok(view) = tauri::async_runtime::block_on(
            shell.engine(move |core| core.begin_account(&link, "Laptop")),
        )
        .unwrap() else {
            panic!("begin");
        };
        let group = view.groups[view.check_group as usize - 1].clone();
        assert!(tauri::async_runtime::block_on(
            shell.engine(move |core| core.confirm_recovery_group(&group))
        )
        .unwrap());
        (shell, events)
    }

    fn setup_state(shell: &Shell) -> serde_json::Value {
        let snapshot = tauri::async_runtime::block_on(fresh_snapshot(shell)).unwrap();
        serde_json::to_value(&snapshot).unwrap()["setup"].clone()
    }

    // Security review M4: resetting and disconnecting ask natively; "no" changes nothing and is
    // not an error, and the question carries the warning for the last device.
    #[test]
    fn reset_and_disconnect_run_only_after_a_yes() {
        let (shell, _events) = set_up_shell();
        let asked = std::sync::Mutex::new(Vec::new());
        let no = Fixed(false, &asked);
        assert_eq!(
            tauri::async_runtime::block_on(reset(&shell, &no)).unwrap(),
            ResetOutcome::Declined
        );
        assert_eq!(
            tauri::async_runtime::block_on(disconnect(&shell, &no)).unwrap(),
            Confirmation::Declined
        );
        assert_eq!(setup_state(&shell), json!("done"));
        {
            let asked = lock(&asked);
            assert_eq!(asked.len(), 2);
            assert_eq!(asked[0], crate::confirm::reset(shell.language()));
            // The only device of the account: the question warns about it.
            assert_eq!(asked[1], crate::confirm::disconnect(shell.language(), true));
        }
        let yes = Fixed(true, &asked);
        assert_eq!(
            tauri::async_runtime::block_on(reset(&shell, &yes)).unwrap(),
            ResetOutcome::Confirmed
        );
        assert_eq!(setup_state(&shell), json!("needed"));
    }

    // Follow-up review LOW 7: during a pending recovery the plain reset asks nothing and tells
    // the window; the engine's own refusal (a recovery that became pending in between) is the
    // same outcome, and every other error stays an error.
    #[test]
    fn a_reset_during_a_pending_recovery_is_an_outcome() {
        let pending = |warnings: Vec<Warning>| {
            let (shell, _events) = engine_shell();
            let mut snapshot = tauri::async_runtime::block_on(fresh_snapshot(&shell)).unwrap();
            snapshot.warnings = warnings;
            recovery_pending(&snapshot)
        };
        assert!(pending(vec![Warning::RecoveryPending {
            id: "recoveryPending".into()
        }]));
        assert!(!pending(vec![Warning::NoRecoveryCode {
            id: "noRecoveryCode".into()
        }]));
        assert!(!pending(vec![]));
        assert_eq!(reset_outcome(Ok(())).unwrap(), ResetOutcome::Confirmed);
        assert_eq!(
            reset_outcome(Err(SyncError::RecoveryPending)).unwrap(),
            ResetOutcome::RecoveryPending
        );
        assert_eq!(
            reset_outcome(Err(SyncError::Invalid("device")))
                .unwrap_err()
                .kind,
            hangar_drive_sync::error::ErrorKind::Invalid
        );
        assert_eq!(
            serde_json::to_value(ResetOutcome::RecoveryPending).unwrap(),
            json!("recoveryPending")
        );
    }

    // Follow-up review LOW 7: the forced reset runs only after its own native question, which
    // says the account may be lost; "no" changes nothing.
    #[test]
    fn the_forced_reset_runs_only_after_its_own_yes() {
        let (shell, _events) = set_up_shell();
        let asked = std::sync::Mutex::new(Vec::new());
        assert_eq!(
            tauri::async_runtime::block_on(reset_discarding(&shell, &Fixed(false, &asked)))
                .unwrap(),
            Confirmation::Declined
        );
        assert_eq!(setup_state(&shell), json!("done"));
        assert_eq!(
            lock(&asked).as_slice(),
            &[crate::confirm::reset_discarding_recovery(shell.language())]
        );
        assert_eq!(
            tauri::async_runtime::block_on(reset_discarding(&shell, &Fixed(true, &asked))).unwrap(),
            Confirmation::Confirmed
        );
        assert_eq!(setup_state(&shell), json!("needed"));
    }

    // Security review M4: a renewed code replaces the old one only after a native yes, asked
    // once the typed group matched; a wrong group asks nothing.
    #[test]
    fn a_renewed_code_takes_over_only_after_a_yes() {
        let (shell, _events) = set_up_shell();
        let view = tauri::async_runtime::block_on(shell.engine(|core| core.renew_recovery_code()))
            .unwrap();
        remember_code(&shell, &view, true);
        let group = view.groups[view.check_group as usize - 1].clone();
        let asked = std::sync::Mutex::new(Vec::new());
        let no = Fixed(false, &asked);
        let check = |asker: &Fixed<'_>, typed: &str| {
            tauri::async_runtime::block_on(check_recovery_group(&shell, asker, typed.to_owned()))
                .unwrap()
        };
        assert_eq!(check(&no, "ZZZZ"), RecoveryCheck::Wrong);
        assert!(lock(&asked).is_empty());
        assert_eq!(
            check(&no, &group.to_ascii_lowercase()),
            RecoveryCheck::Declined
        );
        assert_eq!(lock(&asked).len(), 1);
        // The renewal still waits: the same group confirms it after a yes.
        assert!(lock(&shell.shown).is_some());
        let yes = Fixed(true, &asked);
        assert_eq!(check(&yes, &group), RecoveryCheck::Confirmed);
        assert!(lock(&shell.shown).is_none());
        assert_eq!(
            serde_json::to_value(RecoveryCheck::Declined).unwrap(),
            json!("declined")
        );
    }

    // Security review H1: a device that belongs to an account does not pair, so a window call
    // cannot move it into a stranger's account. The shell refuses before the engine.
    // Security review H2: the account is forgotten on a server's "removed" only after it said
    // so and the person confirmed; without a report nothing is asked and nothing forgotten.
    #[test]
    fn a_removal_nobody_reported_forgets_nothing() {
        let (shell, _events) = set_up_shell();
        let asked = std::sync::Mutex::new(Vec::new());
        let error = tauri::async_runtime::block_on(forget_removed(&shell, &Fixed(true, &asked)))
            .unwrap_err();
        assert_eq!(error.kind, hangar_drive_sync::error::ErrorKind::Invalid);
        assert!(lock(&asked).is_empty());
        assert_eq!(setup_state(&shell), json!("done"));
    }

    // Follow-up check N-1: a folder reset asks every time, with the folder and the number of
    // files that disappear; "no" resets nothing and is no error.
    #[test]
    fn a_folder_reset_runs_only_after_a_yes() {
        let disk = std::sync::Arc::new(hangar_drive_sync::memory::MemFs::new(true));
        let (shell, _events) = set_up_shell_on(Some(std::sync::Arc::clone(&disk)));
        // Before the folder is added, so its first scan sees the file whenever it runs.
        disk.user_write(&["first.txt".to_owned()], b"1");
        let folder = tauri::async_runtime::block_on(
            shell.engine(|core| core.add_folder("mem:/Docs", "Docs")),
        )
        .unwrap();
        let probe = folder.clone();
        let entry = tauri::async_runtime::block_on(shell.engine(move |core| {
            core.tick();
            core.get_timeline(&probe, 10)
        }))
        .unwrap()
        .entries
        .last()
        .map(|e| e.id.clone())
        .expect("a first entry");
        // Two files the folder's first entry does not hold; the clock of the test
        // engine stands still, so the same place again asks for the full scan.
        disk.user_write(&["new.txt".to_owned()], b"n");
        disk.user_write(&["more.txt".to_owned()], b"m");
        let probe = folder.clone();
        tauri::async_runtime::block_on(shell.engine(move |core| {
            assert!(core.relocate_folder(&probe, "mem:/Docs")?);
            core.tick();
            Ok(())
        }))
        .unwrap();
        let asked = std::sync::Mutex::new(Vec::new());
        let outcome = tauri::async_runtime::block_on(reset_to_entry(
            &shell,
            &Fixed(false, &asked),
            folder.clone(),
            entry.clone(),
        ))
        .unwrap();
        assert_eq!(outcome, None);
        {
            let asked = lock(&asked);
            assert_eq!(asked.len(), 1);
            assert_eq!(
                asked[0],
                crate::confirm::reset_folder(shell.language(), "Docs", 2)
            );
        }
        assert!(
            disk.read_all(&["new.txt".to_owned()]).is_some(),
            "nothing was reset"
        );
        let outcome = tauri::async_runtime::block_on(reset_to_entry(
            &shell,
            &Fixed(true, &asked),
            folder,
            entry,
        ))
        .unwrap();
        assert!(
            matches!(outcome, Some(RestoreOutcome::Done { .. })),
            "{outcome:?}"
        );
        assert_eq!(lock(&asked).len(), 2);
    }

    // Follow-up check N-2: without a regular device to remove nothing is asked, and a device ID
    // the engine did not offer is never passed on.
    #[test]
    fn the_recovery_cleanup_passes_on_only_offered_devices() {
        let (shell, _events) = set_up_shell();
        let asked = std::sync::Mutex::new(Vec::new());
        let error = tauri::async_runtime::block_on(cleanup_after_recovery(
            &shell,
            &Fixed(true, &asked),
            vec!["00112233445566778899aabbccddeeff".to_owned()],
        ))
        .unwrap_err();
        // No recovery runs on this device; the engine refuses, and nothing was asked.
        assert_eq!(error.kind, hangar_drive_sync::error::ErrorKind::Invalid);
        assert!(lock(&asked).is_empty());
        assert_eq!(setup_state(&shell), json!("done"));
    }

    // ADR 0001, "the engine on the recovery in one piece": the devices come without names
    // before the join, the native question names them by the day they were added, a "no" there
    // changes nothing, and the account comes into being only with the cleanup.
    #[test]
    fn a_recovery_joins_only_with_the_cleanup() {
        let (shell, _events) = engine_shell();
        let link = format!(
            "http://localhost:8080/join#{}",
            hangar_drive_protocol::ids::base64url(&[9; 16])
        );
        let ApiResult::Ok(view) = tauri::async_runtime::block_on(
            shell.engine(move |core| core.begin_account(&link, "Laptop")),
        )
        .unwrap() else {
            panic!("begin");
        };
        let group = view.groups[view.check_group as usize - 1].clone();
        assert!(tauri::async_runtime::block_on(
            shell.engine(move |core| core.confirm_recovery_group(&group))
        )
        .unwrap());
        let asked = std::sync::Mutex::new(Vec::new());
        assert_eq!(
            tauri::async_runtime::block_on(reset(&shell, &Fixed(true, &asked))).unwrap(),
            ResetOutcome::Confirmed
        );
        lock(&asked).clear();

        // The lost laptop's sheet, on a fresh installation (the same server).
        let sheet = view.sheet.link.clone();
        let code = view.groups.join("-");
        let recovered = tauri::async_runtime::block_on(
            shell.engine(move |core| core.recover_account(&sheet, &code, "Neu")),
        )
        .unwrap();
        assert_eq!(recovered, ApiResult::Ok(()));
        assert_eq!(setup_state(&shell), json!("needed"));
        let devices =
            tauri::async_runtime::block_on(shell.engine(|core| core.recovery_devices())).unwrap();
        assert_eq!(devices.len(), 1);
        assert!(devices[0].name.is_empty());
        let label = crate::confirm::recovery_device_label(
            shell.language(),
            "",
            devices[0].added,
            shell.tz_offset_minutes,
        );
        let lost = vec![devices[0].id.clone()];

        let declined = tauri::async_runtime::block_on(cleanup_after_recovery(
            &shell,
            &Fixed(false, &asked),
            lost.clone(),
        ))
        .unwrap();
        assert_eq!(declined, ApiResult::Ok(None));
        assert_eq!(setup_state(&shell), json!("needed"));
        assert_eq!(
            lock(&asked).as_slice(),
            &[crate::confirm::recovery_cleanup(
                shell.language(),
                std::slice::from_ref(&label)
            )]
        );

        let done = tauri::async_runtime::block_on(cleanup_after_recovery(
            &shell,
            &Fixed(true, &asked),
            lost,
        ))
        .unwrap();
        let ApiResult::Ok(Some(renewed)) = done else {
            panic!("the cleanup did not finish: {done:?}");
        };
        assert_ne!(renewed.groups, view.groups);
        assert_eq!(setup_state(&shell), json!("done"));
        assert!(lock(&shell.shown).is_some());
        let list =
            tauri::async_runtime::block_on(shell.engine(|core| core.list_devices())).unwrap();
        assert_eq!(list.devices.len(), 1);
        assert!(list.devices[0].is_this);
        // Once joined, an error is no end of the recovery: the window may try again.
        let again = tauri::async_runtime::block_on(cleanup_after_recovery(
            &shell,
            &Fixed(true, &asked),
            vec![],
        ))
        .unwrap_err();
        assert_eq!(again.kind, hangar_drive_sync::error::ErrorKind::Invalid);
    }

    #[test]
    fn a_recovery_cleanup_names_the_engine_refusal() {
        use hangar_drive_protocol::api::{ErrorBody, ErrorCode};
        use hangar_drive_sync::ports::NetError;
        let named = [
            (
                SyncError::RecoveryListChanged,
                RecoveryCleanupError::ListChanged,
            ),
            (SyncError::RecoveryCodeUsed, RecoveryCleanupError::Used),
            (
                SyncError::RecoveryCodeUnknown,
                RecoveryCleanupError::Unknown,
            ),
            (
                SyncError::Net(NetError::PinMismatch),
                RecoveryCleanupError::Insecure,
            ),
            (
                SyncError::Net(NetError::Unreachable),
                RecoveryCleanupError::Unreachable,
            ),
            (
                SyncError::Net(NetError::Server(ErrorBody::new(ErrorCode::RateLimited))),
                RecoveryCleanupError::Unreachable,
            ),
            (
                SyncError::Net(NetError::Tls("certificate".into())),
                RecoveryCleanupError::Insecure,
            ),
        ];
        for (error, reason) in named {
            assert_eq!(RecoveryCleanupError::of(&error), Some(reason), "{error}");
        }
        // A general error: the engine keeps the choice or the pending recovery.
        for error in [
            SyncError::Net(NetError::Server(ErrorBody::new(ErrorCode::LogEntryRefused))),
            SyncError::Invalid("device"),
            SyncError::Invalid("no recovery in progress"),
            // The engine's former texts of the two refusals: a text never names a reason.
            SyncError::Invalid("the recovery code was used before"),
            SyncError::Invalid("the code does not belong to this account"),
        ] {
            assert_eq!(RecoveryCleanupError::of(&error), None, "{error}");
        }
        for (reason, wire) in [
            (RecoveryCleanupError::ListChanged, "listChanged"),
            (RecoveryCleanupError::Used, "used"),
            (RecoveryCleanupError::Unknown, "unknown"),
            (RecoveryCleanupError::Unreachable, "unreachable"),
            (RecoveryCleanupError::Insecure, "insecure"),
        ] {
            assert_eq!(
                serde_json::to_value(ApiResult::<(), _>::Err(reason)).unwrap(),
                json!({ "ok": false, "error": wire })
            );
        }
    }

    #[test]
    fn a_set_up_device_does_not_pair() {
        let (shell, _events) = set_up_shell();
        let input = PairInput::Link {
            link: "hangar-drive://pair#AQID".to_owned(),
        };
        let error =
            tauri::async_runtime::block_on(pair(&shell, input, "Laptop".to_owned())).unwrap_err();
        assert_eq!(error.kind, hangar_drive_sync::error::ErrorKind::Invalid);
        assert_eq!(error.message, SyncError::AlreadySetUp.to_string());
        assert_eq!(setup_state(&shell), json!("done"));
    }

    // Security review H1: a place that holds files is joined only after a native question that
    // names the place, the number of files and the server; "no" joins nothing and keeps the
    // place's token for another try.
    #[test]
    fn a_folder_with_files_is_joined_only_after_a_yes() {
        let (shell, _events) = set_up_shell();
        let place = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(".tmp")
            .join("join")
            .join("Documents");
        let _ = std::fs::remove_dir_all(&place);
        std::fs::create_dir_all(&place).unwrap();
        std::fs::write(place.join("letter.txt"), b"x").unwrap();
        std::fs::write(place.join("notes.txt"), b"y").unwrap();
        let token = shell.places.issue(place.clone()).unwrap();
        let asked = std::sync::Mutex::new(Vec::new());
        let outcome = tauri::async_runtime::block_on(join_account_folder(
            &shell,
            &Fixed(false, &asked),
            "00112233445566778899aabbccddeeff",
            &token,
        ))
        .unwrap();
        assert_eq!(outcome, JoinOutcome::Declined);
        let asked = lock(&asked);
        assert_eq!(asked.len(), 1);
        assert!(
            asked[0].message.contains(&path_text(&place)),
            "{}",
            asked[0].message
        );
        assert!(asked[0].message.contains('2'), "{}", asked[0].message);
        assert!(
            asked[0].message.contains("localhost:8080"),
            "{}",
            asked[0].message
        );
        assert!(shell.places.path(&token).is_ok(), "the token stays");
        assert!(place.join("letter.txt").exists());
        let _ = std::fs::remove_dir_all(place.parent().unwrap());
    }

    // Security review H1, N8: proposals are new folders below ~/Hangar Drive, never an existing
    // place and never a direct child of the home folder; a leading dot is replaced.
    #[test]
    fn proposed_places_are_new_folders_below_the_app_folder() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(".tmp")
            .join("proposals")
            .join("Hangar Drive");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("Documents")).unwrap();
        std::fs::create_dir_all(base.join("Documents (2)")).unwrap();
        let place = proposed_place(&base, "Documents", |p| p.exists()).unwrap();
        assert_eq!(place, base.join("Documents (3)"));
        assert_eq!(
            proposed_place(&base, ".ssh", |p| p.exists()).unwrap(),
            base.join("_ssh")
        );
        assert_eq!(
            proposed_place(&base, "..", |p| p.exists()).unwrap(),
            base.join("Hangar Drive")
        );
        assert_eq!(proposed_place(&base, "x", |_| true), None);
        // The app folder itself is the default place, not the home folder.
        let default = crate::platform::default_folder().unwrap();
        assert!(default.ends_with("Hangar Drive"));
        assert!(proposed_place(&default, "Documents", |_| false)
            .unwrap()
            .starts_with(&default));
        let source = include_str!("commands.rs");
        let at = source.find("async fn account_folders").unwrap();
        let body = &source[at..at + source[at..].find("\n}\n").unwrap()];
        assert!(body.contains("default_folder()"), "{body}");
        assert!(!body.contains("home_dir()"), "{body}");
        let _ = std::fs::remove_dir_all(base.parent().unwrap());
    }

    // Security review MEDIUM 1: a folder name from the account (chosen on another device) never
    // becomes a root name the Windows shell reads as a namespace junction, a reserved or short
    // name, or a macOS bundle that `open` would run, on any platform.
    #[test]
    fn account_folder_names_become_plain_root_names() {
        let base = PathBuf::from("base");
        let place = |name: &str| proposed_place(&base, name, |_| false).unwrap();
        assert_eq!(
            place("Photos.{0AFACED1-E828-11D1-9187-B532F1E9575D}"),
            base.join("Photos_{0AFACED1-E828-11D1-9187-B532F1E9575D}")
        );
        assert_eq!(place("Photos.app"), base.join("Photos_app"));
        assert_eq!(place("Notes.APP"), base.join("Notes_APP"));
        for bundle in [
            "a.bundle",
            "a.plugin",
            "a.prefPane",
            "a.saver",
            "a.workflow",
            "a.framework",
            "a.kext",
            "a.appex",
        ] {
            assert_eq!(root_dir_name(bundle), bundle.replace('.', "_"), "{bundle}");
        }
        assert_eq!(root_dir_name("CON"), "_CON");
        assert_eq!(root_dir_name("nul.txt"), "_nul.txt");
        assert_eq!(root_dir_name("HANGAR~1"), "HANGAR_1");
        assert_eq!(root_dir_name("AB~1"), "AB_1");
        assert_eq!(root_dir_name(".config"), "_config");
        assert_eq!(root_dir_name("a/b:c"), "a_b_c");
        // Ordinary names stay as they are, a dot inside included.
        for plain in ["Photos", "Report 2026.final", "app", "x.apps", "Taxes.2026"] {
            assert_eq!(root_dir_name(plain), plain);
        }
        let long = "x".repeat(300);
        let cut = root_dir_name(&long);
        assert!(
            cut.encode_utf16().count() <= ROOT_NAME_UNITS,
            "{}",
            cut.len()
        );
        assert_eq!(
            hangar_drive_protocol::name::windows_problem(&format!("{cut} (99)")),
            None
        );
        for name in [
            "Photos.{0AFACED1-E828-11D1-9187-B532F1E9575D}",
            "CON",
            "a~1.b",
            "Photos.app",
        ] {
            let dir = root_dir_name(name);
            assert_eq!(
                hangar_drive_protocol::name::windows_problem(&dir),
                None,
                "{dir}"
            );
            assert!(!crate::platform::is_bundle_name(&dir), "{dir}");
        }
    }

    // Security review N8: a leading dot never reaches the file system.
    #[test]
    fn folder_names_lose_a_leading_dot() {
        assert_eq!(safe_dir_name(".config"), "_config");
        assert_eq!(safe_dir_name("..hidden"), "_.hidden");
        assert_eq!(safe_dir_name(" .x "), "_x");
        assert_eq!(safe_dir_name("a.b"), "a.b");
    }

    // Security review N11: the recovery file is readable by its owner only.
    #[test]
    fn the_recovery_file_is_private() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(".tmp")
            .join("private");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Recovery sheet.txt");
        std::fs::write(&path, b"old and longer").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        write_private(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let fresh = dir.join("fresh.txt");
            write_private(&fresh, b"x").unwrap();
            let mode = std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let source = include_str!("commands.rs");
        let at = source.find("pub async fn save_recovery_file").unwrap();
        let body = &source[at..at + source[at..].find("\n}\n").unwrap()];
        assert!(body.contains("write_private(&path"), "{body}");
        assert!(!body.contains("std::fs::write"), "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The body of `pub async fn {name}(` or `async fn {name}(` up to its closing line.
    fn body_of<'a>(source: &'a str, name: &str) -> &'a str {
        let at = source
            .find(&format!("pub async fn {name}("))
            .or_else(|| source.find(&format!("async fn {name}(")))
            .unwrap_or_else(|| panic!("no function {name}"));
        let end = source[at..].find("\n}\n").unwrap();
        &source[at..at + end]
    }

    // Security review M4 and N7: every destructive command asks natively before the engine
    // acts, and the server number confirms exactly the pin taken before the dialog.
    #[test]
    fn destructive_commands_ask_natively_first() {
        let source = include_str!("commands.rs");
        for (command, helper, acts) in [
            ("remove_device", "remove_one_device", "core.remove_device("),
            ("reset_device", "reset", "core.reset_device()"),
            (
                "reset_device_discarding_recovery",
                "reset_discarding",
                "core.reset_device_discarding_recovery()",
            ),
            (
                "disconnect_this_device",
                "disconnect",
                "core.disconnect_this_device()",
            ),
            (
                "confirm_recovery_group",
                "check_recovery_group",
                "core.confirm_recovery_group(",
            ),
            ("reanchor", "continue_older", "core.reanchor("),
            (
                "accept_removed_heads",
                "take_removed_heads",
                "core.accept_removed_heads(",
            ),
            (
                "resolve_mass_delete",
                "resolve_deletes",
                "core.resolve_mass_delete(",
            ),
            (
                "resolve_incoming_delete",
                "resolve_incoming",
                "core.resolve_incoming_delete(",
            ),
            (
                "add_account_folder",
                "join_account_folder",
                "core.add_account_folder(",
            ),
            (
                "join_folders",
                "join_account_folder",
                "core.add_account_folder(",
            ),
            (
                "confirm_server_number",
                "trust_server_number",
                "core.confirm_server_number(",
            ),
            ("set_autostart", "set_autostart", ".disable()"),
            ("install_update", "install_update", ".download_and_install("),
            (
                "confirm_device_removed",
                "forget_removed",
                "core.confirm_device_removed()",
            ),
            // Follow-up check N-1 and N-2.
            ("reset_folder", "reset_to_entry", "core.reset_folder("),
            (
                "finish_recovery_cleanup",
                "cleanup_after_recovery",
                "core.finish_recovery_cleanup(",
            ),
        ] {
            let outer = body_of(source, command);
            assert!(outer.contains("Native(&app)"), "{command}");
            let inner = body_of(source, helper);
            let asks = inner
                .find(".ask(")
                .unwrap_or_else(|| panic!("{helper} asks nothing"));
            let acts = inner
                .find(acts)
                .unwrap_or_else(|| panic!("{helper} does not act"));
            assert!(asks < acts, "{helper} acts before it asks");
        }
        // Skeleton check: a look-alike name is taken (`true`) only after the question.
        for command in ["rename_device", "set_device_name"] {
            assert!(
                body_of(source, command).contains("Native(&app)"),
                "{command}"
            );
        }
        let rename = body_of(source, "rename_checked");
        let asks = rename.find(".ask(").unwrap();
        let takes = rename
            .find("core.rename_device(&device_id, &name, true)")
            .unwrap();
        assert!(asks < takes);
        assert!(!rename[..asks].contains(", true)"));
        let trust = body_of(source, "trust_server_number");
        let pin = trust.find("let pin = shown.pin;").unwrap();
        let asks = trust.find(".ask(").unwrap();
        assert!(pin < asks);
        assert!(trust.contains("core.confirm_server_number(&pin)"));
        // "No" is an answer, not an error.
        assert_eq!(
            serde_json::to_value(Confirmation::Declined).unwrap(),
            json!("declined")
        );
        assert_eq!(
            serde_json::to_value(MassDeleteOutcome::Resolved { count: 3 }).unwrap(),
            json!({ "kind": "resolved", "count": 3 })
        );
        assert_eq!(
            serde_json::to_value(HeadsAnswer::Accepted(AcceptedHeads {
                count: 2,
                before_entry_id: None
            }))
            .unwrap(),
            json!({ "kind": "accepted", "count": 2, "beforeEntryId": null })
        );
        assert_eq!(
            serde_json::to_value(JoinOutcome::Declined).unwrap(),
            json!("declined")
        );
        assert_eq!(
            serde_json::to_value(crate::updater::UpdateOutcome::Declined).unwrap(),
            json!({ "kind": "declined" })
        );
    }

    #[test]
    fn paths_never_leave_their_folder() {
        let root = PathBuf::from("root");
        assert_eq!(
            path_inside(&root, "a/b.txt"),
            Some(root.join("a").join("b.txt"))
        );
        for bad in ["../x", "a/../../x", "C:/x", "a\\..\\x", "./x"] {
            assert_eq!(path_inside(&root, bad), None, "{bad}");
        }
        assert_eq!(safe_dir_name("Fotos"), "Fotos");
        assert_eq!(safe_dir_name("a/b:c"), "a_b_c");
        assert_eq!(safe_dir_name(".."), "Hangar Drive");
        assert_eq!(safe_dir_name("  "), "Hangar Drive");
        assert_eq!(folder_name_of("C:\\Users\\x\\Hangar Drive"), "Hangar Drive");
    }

    #[test]
    fn the_command_list_matches_the_build_script_and_the_capability() {
        let build = include_str!("../build.rs");
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let granted: Vec<&str> = capability["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p.as_str())
            .collect();
        for name in COMMAND_NAMES {
            assert!(
                build.contains(&format!("\"{name}\",")),
                "build.rs lacks {name}"
            );
            let permission = format!("allow-{}", name.replace('_', "-"));
            assert!(
                granted.contains(&permission.as_str()),
                "capability lacks {permission}"
            );
        }
        let own = granted.iter().filter(|p| p.starts_with("allow-")).count();
        assert_eq!(
            own,
            COMMAND_NAMES.len(),
            "the capability grants exactly the commands"
        );
        // Nothing of a plugin is granted to the window: dialogs, clipboard, notifications,
        // autostart and links run in the backend only.
        for p in &granted {
            assert!(
                p.starts_with("allow-") || p.starts_with("core:event:"),
                "unexpected permission {p}"
            );
        }
        let handler = include_str!("commands.rs");
        for name in COMMAND_NAMES {
            assert!(
                handler.contains(&format!("$crate::commands::{name},")),
                "handler lacks {name}"
            );
        }
    }

    /// `getSnapshot` -> `get_snapshot`, as the bridge names commands (`commandName`).
    fn snake_case(name: &str) -> String {
        let mut out = String::new();
        for c in name.chars() {
            if c.is_ascii_uppercase() {
                out.push('_');
                out.push(c.to_ascii_lowercase());
            } else {
                out.push(c);
            }
        }
        out
    }

    /// `folder_id` -> `folderId`, as Tauri reads a command's arguments.
    fn camel_case(name: &str) -> String {
        let mut out = String::new();
        let mut upper = false;
        for c in name.chars() {
            if c == '_' {
                upper = true;
            } else if upper {
                out.push(c.to_ascii_uppercase());
                upper = false;
            } else {
                out.push(c);
            }
        }
        out
    }

    /// `text` from its start up to the bracket that closes the one before it, at depth zero.
    fn until_closed(text: &str, open: char, close: char) -> &str {
        let mut depth = 0usize;
        for (i, c) in text.char_indices() {
            if c == open {
                depth += 1;
            } else if c == close {
                if depth == 0 {
                    return &text[..i];
                }
                depth -= 1;
            }
        }
        panic!("unclosed {open} in {text:.80}");
    }

    /// `text` split at the commas outside of any bracket.
    fn top_level_items(text: &str) -> Vec<&str> {
        let mut items = Vec::new();
        let (mut depth, mut start) = (0i32, 0usize);
        for (i, c) in text.char_indices() {
            match c {
                '(' | '{' | '[' | '<' => depth += 1,
                ')' | '}' | ']' | '>' => depth -= 1,
                ',' if depth == 0 => {
                    items.push(text[start..i].trim());
                    start = i + 1;
                }
                _ => {}
            }
        }
        items.push(text[start..].trim());
        items.into_iter().filter(|i| !i.is_empty()).collect()
    }

    /// Every `this.call("method", { args })` and `this.run("method", { args })` of the bridge,
    /// with the argument names it sends.
    fn bridge_calls(bridge: &str) -> Vec<(String, Vec<String>)> {
        let mut calls = Vec::new();
        for start in ["this.call(", "this.run("] {
            for (at, _) in bridge.match_indices(start) {
                let rest = bridge[at + start.len()..].trim_start();
                let Some(rest) = rest.strip_prefix('"') else {
                    // `run` passing its own `method` on.
                    continue;
                };
                let end = rest.find('"').expect("closing quote");
                let method = rest[..end].to_owned();
                let after = rest[end + 1..].trim_start();
                let args = match after.strip_prefix(',').map(str::trim_start) {
                    Some(object) if object.starts_with('{') => {
                        top_level_items(until_closed(&object[1..], '{', '}'))
                            .into_iter()
                            .map(|item| item.split(':').next().unwrap_or(item).trim().to_owned())
                            .collect()
                    }
                    _ => Vec::new(),
                };
                calls.push((method, args));
            }
        }
        calls
    }

    /// The parameters the window fills of a command of this file (not the app handle and the
    /// managed state Tauri passes).
    fn command_params(source: &str, command: &str) -> Option<Vec<String>> {
        let head = format!("pub async fn {command}(");
        let at = source.find(&head)?;
        let list = until_closed(&source[at + head.len()..], '(', ')');
        Some(
            top_level_items(list)
                .into_iter()
                .filter_map(|param| {
                    let (name, ty) = param.split_once(':')?;
                    let ty = ty.trim();
                    let passed_by_tauri = ty.starts_with("AppHandle")
                        || ty.starts_with("State<")
                        || ty.starts_with("tauri::");
                    (!passed_by_tauri).then(|| name.trim().to_owned())
                })
                .collect(),
        )
    }

    /// The window's bridge calls only commands the shell has, with the argument names their
    /// Rust parameters read (camelCase against snake_case), so no button of the window ends in
    /// "this version cannot do that yet".
    #[test]
    fn every_command_the_window_calls_exists_with_its_arguments() {
        let bridge = include_str!("../../src/backend/tauri/tauriBackend.ts");
        let source = include_str!("commands.rs");
        let calls = bridge_calls(bridge);
        assert!(calls.len() > 80, "the bridge's calls were not found");
        for (method, args) in &calls {
            let command = snake_case(method);
            assert!(
                COMMAND_NAMES.contains(&command.as_str()),
                "the window calls {command}, which the shell does not have"
            );
            let params = command_params(source, &command)
                .unwrap_or_else(|| panic!("no command function {command}"));
            let mut want: Vec<String> = params.iter().map(|p| camel_case(p)).collect();
            want.sort();
            let mut sent = args.clone();
            sent.sort();
            assert_eq!(sent, want, "the arguments of {command}");
        }
        // The parser itself: a command the shell lacks and a wrong argument name are caught.
        let fake = r#"this.run("notThere", { folderId }); this.call("undo", { tokn: t }, d.x)"#;
        let calls = bridge_calls(fake);
        let sent = |name: &str| calls.iter().find(|(m, _)| m == name).unwrap().1.clone();
        assert_eq!(sent("notThere"), vec!["folderId".to_owned()]);
        assert!(!COMMAND_NAMES.contains(&snake_case("notThere").as_str()));
        let undo = command_params(source, "undo").unwrap();
        assert_eq!(undo, vec!["token".to_owned()]);
        assert_ne!(sent("undo"), vec![camel_case(&undo[0])]);
    }
}
