//! The window's commands: one per method of the `Backend` interface (src/backend/types.ts), in
//! snake case, with the window's camelCase arguments. Each is a thin layer: it reads its input,
//! calls one engine method on the engine thread (`Shell::engine`) or one OS service of the
//! shell (dialogs, clipboard, file manager, tray, autostart), and shapes the answer as the
//! window's decoders read it (src/backend/tauri/decoders.ts). The logic stays in the engine.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hangar_drive_sync::api::{
    AcceptedHeads, ApiResult, BeginError, ConflictGroup, Device, DeviceList, FixServerError,
    FolderRefusal, FolderRefusalView, InspectedLink, InviteCheck, InviteError, LinkProblem,
    NameError, NameIssue, NotSyncedEntry, NumberRows, PairError, PauseDuration, QrMatrix,
    RecoverError, RecoveryCodeView, RenameError, RestoreOutcome, ServerNumberView, Snapshot,
    Timeline, TrashItem, VersionTree, Warning,
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
pub struct SettingsView {
    autostart: bool,
    language: String,
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

/// A folder name as a directory name in the home folder: the characters no platform allows
/// become `_`, and the result never names a parent.
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
    let cleaned = cleaned.trim().trim_end_matches(['.', ' ']).to_owned();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "Hangar Drive".to_owned()
    } else {
        cleaned
    }
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

fn remember_code(shell: &Shell, view: &RecoveryCodeView) {
    *lock(&shell.shown) = Some(ShownCode {
        code: Zeroizing::new(view.groups.join("-")),
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
        text,
        crate::clipboard::CLEAR_AFTER,
    )
    .map_err(|e| CommandError::unexpected(e.to_string()))
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
    std::fs::create_dir_all(path)?;
    Ok(Ok(()))
}

fn refused(view: FolderRefusalView) -> CommandError {
    CommandError::invalid(format!("the folder is refused: {:?}", view.reason))
}

async fn pick_directory(app: &AppHandle, shell: &Shell) -> Answer<Option<PathBuf>> {
    let _dialog = DialogGuard::enter(&shell.dialog_open)?;
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut dialog = app.dialog().file();
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
        let mut dialog = app.dialog().file().set_file_name(name);
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

async fn fresh_snapshot(shell: &Shell) -> Answer<Snapshot> {
    shell.engine(|core| Ok(core.snapshot())).await
}

fn folder_of_warning(snapshot: &Snapshot, warning_id: &str) -> Option<String> {
    snapshot.warnings.iter().find_map(|w| match w {
        Warning::MassDelete { id, folder_id, .. } if id == warning_id => Some(folder_id.clone()),
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
    fresh_snapshot(&shell).await
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
        remember_code(&shell, view);
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
    .on_page_load(|window, payload| {
        if payload.event() == tauri::webview::PageLoadEvent::Finished {
            if let Err(error) = window.print() {
                eprintln!("hangar-drive: print dialog not opened: {error}");
            }
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
    if inside_synced_folder(&path, &snapshot) {
        return Ok(SaveResult::InSyncFolder);
    }
    if path
        .parent()
        .is_some_and(|dir| crate::platform::in_cloud_folder(dir, &crate::platform::cloud_roots()))
    {
        return Ok(SaveResult::InCloudFolder);
    }
    std::fs::write(&path, document.text().as_bytes())?;
    Ok(SaveResult::Saved {
        path: path_text(&path),
    })
}

#[tauri::command]
pub async fn copy_recovery_code(app: AppHandle, shell: State<'_, Shell>) -> Answer<()> {
    let code = lock(&shell.shown)
        .as_ref()
        .map(|s| s.code.clone())
        .ok_or_else(|| CommandError::invalid("no recovery code is shown"))?;
    copy_and_clear(&app, &shell, code)
}

#[tauri::command]
pub async fn confirm_recovery_group(shell: State<'_, Shell>, group: String) -> Answer<bool> {
    let ok = shell
        .engine(move |core| core.confirm_recovery_group(&group))
        .await?;
    if ok {
        *lock(&shell.shown) = None;
    }
    Ok(ok)
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
    let snapshot = fresh_snapshot(&shell).await?;
    let home = dirs::home_dir().ok_or_else(|| CommandError::unexpected("no home folder"))?;
    let mut folders = Vec::with_capacity(snapshot.remote_folders.len());
    for f in &snapshot.remote_folders {
        let place = home.join(safe_dir_name(&f.name));
        folders.push(AccountFolder {
            id: f.id.clone(),
            name: f.name.clone(),
            size: f.size,
            proposed_path: path_text(&place),
            proposed_token: shell.places.issue(place)?,
        });
    }
    Ok(AccountFolders {
        folders,
        free: crate::platform::free_bytes(&home).unwrap_or(0),
    })
}

#[tauri::command]
pub async fn join_folders(shell: State<'_, Shell>, choices: Vec<FolderChoice>) -> Answer<()> {
    for choice in choices {
        add_account_folder(shell.clone(), choice.folder_id, choice.token).await?;
    }
    Ok(())
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

#[tauri::command]
pub async fn set_device_name(
    shell: State<'_, Shell>,
    name: String,
) -> Answer<ApiResult<(), NameError>> {
    let snapshot = fresh_snapshot(&shell).await?;
    if snapshot.account.is_none() {
        if let Some(error) = name_error(&name) {
            return Ok(ApiResult::Err(error));
        }
        *lock(&shell.device_name) = Some(name);
        return Ok(ApiResult::Ok(()));
    }
    shell
        .engine(move |core| {
            let this = core
                .list_devices()?
                .devices
                .into_iter()
                .find(|d| d.is_this)
                .ok_or(SyncError::NotSetUp("this device is not in the list"))?;
            core.rename_device(&this.id, &name)
        })
        .await
}

#[tauri::command]
pub async fn recovery_devices(shell: State<'_, Shell>) -> Answer<Vec<Device>> {
    shell.engine(|core| core.recovery_devices()).await
}

#[tauri::command]
pub async fn finish_recovery_cleanup(
    shell: State<'_, Shell>,
    remove: Vec<String>,
) -> Answer<RecoveryCodeView> {
    let view = shell
        .engine(move |core| core.finish_recovery_cleanup(&remove))
        .await?;
    remember_code(&shell, &view);
    Ok(view)
}

// ---------------------------------------------------------------------------------------------
// Everyday

#[tauri::command]
pub async fn open_folder(
    shell: State<'_, Shell>,
    folder_id: Option<String>,
    path: Option<String>,
) -> Answer<()> {
    let snapshot = fresh_snapshot(&shell).await?;
    let root = folder_path(&snapshot, folder_id.as_deref())
        .ok_or_else(|| CommandError::invalid("unknown folder"))?;
    match path.filter(|p| !p.is_empty()) {
        Some(inside) => {
            let target = checked_inside(&root, &inside)?;
            crate::platform::reveal(&target, true)?;
        }
        None => crate::platform::reveal(&std::fs::canonicalize(&root)?, false)?,
    }
    Ok(())
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
/// holds no files back for a metered network, so there is nothing else to let go.
#[tauri::command]
pub async fn sync_now(shell: State<'_, Shell>) -> Answer<()> {
    shell.engine(|_| Ok(())).await
}

#[tauri::command]
pub async fn retry_connection(shell: State<'_, Shell>) -> Answer<()> {
    shell.engine(|_| Ok(())).await
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
    shell: State<'_, Shell>,
    folder_id: String,
    token: String,
) -> Answer<()> {
    let place = shell.places.path(&token)?;
    check_then_create(&shell, &place, None)
        .await?
        .map_err(refused)?;
    shell.places.take(&token)?;
    let path = path_text(&place);
    shell
        .engine(move |core| core.add_account_folder(&folder_id, &path))
        .await
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

#[tauri::command]
pub async fn resolve_mass_delete(
    shell: State<'_, Shell>,
    warning_id: String,
    decision: MassDeleteDecision,
) -> Answer<u64> {
    shell
        .engine(move |core| {
            let folder = folder_of_warning(&core.snapshot(), &warning_id)
                .ok_or(SyncError::Invalid("unknown warning"))?;
            core.resolve_mass_delete(&folder, decision == MassDeleteDecision::Restore)
        })
        .await
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
    let shown = shell.engine(|core| core.server_number()).await?;
    let confirm = crate::confirm::server_number(shell.language(), &shown.number.groups);
    if !native_confirm(&app, &shell, confirm).await? {
        return Ok(ServerConfirm::Declined);
    }
    shell.engine(|core| core.confirm_server_number()).await?;
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

#[tauri::command]
pub async fn reanchor(shell: State<'_, Shell>, folder_id: String, compared: bool) -> Answer<()> {
    // Whether the person compared is the window's business (its texts differ); the engine's
    // re-anchor is the same either way.
    let _ = compared;
    shell.engine(move |core| core.reanchor(&folder_id)).await
}

#[tauri::command]
pub async fn dismiss_suspect(shell: State<'_, Shell>, warning_id: String) -> Answer<()> {
    shell
        .engine(move |core| core.dismiss_warning(&warning_id))
        .await
}

/// Security review H1: the person takes the heads of a removed device in; the window then
/// offers "Undo a device" from the entry before them.
#[tauri::command]
pub async fn accept_removed_heads(
    shell: State<'_, Shell>,
    folder_id: String,
) -> Answer<AcceptedHeads> {
    shell
        .engine(move |core| core.accept_removed_heads(&folder_id))
        .await
}

#[tauri::command]
pub async fn open_storage_settings() -> Answer<()> {
    crate::platform::open_storage_settings().map_err(CommandError::from)
}

async fn report(shell: &Shell) -> String {
    let snapshot = fresh_snapshot(shell).await.ok();
    crate::documents::error_report(
        env!("CARGO_PKG_VERSION"),
        snapshot.as_ref(),
        shell.engine_error(),
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
    std::fs::write(&path, text)?;
    Ok(SaveResult::Saved {
        path: path_text(&path),
    })
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
    let snapshot = fresh_snapshot(&shell).await?;
    let groups = shell.engine(|core| Ok(core.list_conflicts())).await?;
    let group = groups
        .iter()
        .find(|g| g.id == group_id)
        .ok_or_else(|| CommandError::invalid("unknown conflict"))?;
    let root = folder_path(&snapshot, Some(&group.folder_id))
        .ok_or_else(|| CommandError::invalid("unknown folder"))?;
    let target = checked_inside(&root, &group.path)?;
    crate::platform::reveal(&target, true).map_err(CommandError::from)
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

#[tauri::command]
pub async fn reset_folder(
    shell: State<'_, Shell>,
    folder_id: String,
    entry_id: String,
) -> Answer<RestoreOutcome> {
    shell
        .engine(move |core| core.reset_folder(&folder_id, &entry_id))
        .await
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

#[tauri::command]
pub async fn rename_device(
    shell: State<'_, Shell>,
    device_id: String,
    name: String,
) -> Answer<ApiResult<(), NameError>> {
    shell
        .engine(move |core| core.rename_device(&device_id, &name))
        .await
}

#[tauri::command]
pub async fn get_safety_number(shell: State<'_, Shell>, device_id: String) -> Answer<NumberRows> {
    shell
        .engine(move |core| core.get_safety_number(&device_id))
        .await
}

#[tauri::command]
pub async fn remove_device(shell: State<'_, Shell>, device_id: String) -> Answer<()> {
    shell
        .engine(move |core| core.remove_device(&device_id).map(drop))
        .await
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

/// Forgets the account on this device (security review L1): secrets, stored account and the
/// folders' sync state; the files stay. For "pair again" after a removal and for starting over.
#[tauri::command]
pub async fn reset_device(shell: State<'_, Shell>) -> Answer<()> {
    shell.engine(|core| core.reset_device()).await?;
    *lock(&shell.shown) = None;
    *lock(&shell.device_name) = None;
    Ok(())
}

/// Disconnects this device from its account (N2 "these are not my devices", and the device
/// list): the engine forgets the account here at once, as a reset does. The device stays in the
/// account's log until a device of that account removes it; it has no keys left to use it.
#[tauri::command]
pub async fn disconnect_this_device(shell: State<'_, Shell>) -> Answer<()> {
    disconnect(&shell).await
}

async fn disconnect(shell: &Shell) -> Answer<()> {
    shell.engine(|core| core.disconnect_this_device()).await?;
    *lock(&shell.shown) = None;
    *lock(&shell.device_name) = None;
    Ok(())
}

/// Installs a signed update (`tauri-plugin-updater`, [`crate::updater`]); a clear error while
/// tauri.conf.json carries no updater public key.
#[tauri::command]
pub async fn install_update(
    app: AppHandle,
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
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|e| CommandError::unexpected(e.to_string()))?;
    Ok(crate::updater::UpdateOutcome::Installed { version })
}

#[tauri::command]
pub async fn renew_recovery_code(shell: State<'_, Shell>) -> Answer<RecoveryCodeView> {
    let view = shell.engine(|core| core.renew_recovery_code()).await?;
    remember_code(&shell, &view);
    Ok(view)
}

// ---------------------------------------------------------------------------------------------
// Settings

#[tauri::command]
pub async fn get_settings(app: AppHandle, shell: State<'_, Shell>) -> Answer<SettingsView> {
    Ok(SettingsView {
        autostart: app.autolaunch().is_enabled().unwrap_or(false),
        language: lock(&shell.settings).language.clone(),
    })
}

#[tauri::command]
pub async fn set_autostart(app: AppHandle, on: bool) -> Answer<()> {
    let launcher = app.autolaunch();
    let result = if on {
        launcher.enable()
    } else {
        launcher.disable()
    };
    result.map_err(|e| CommandError::unexpected(e.to_string()))
}

/// The backend's texts (notifications, the recovery file) follow at once; the engine's
/// conflict and restore words with the next start.
#[tauri::command]
pub async fn set_language(shell: State<'_, Shell>, language: String) -> Answer<()> {
    if !crate::settings::is_language_choice(&language) {
        return Err(CommandError::invalid("unknown language"));
    }
    lock(&shell.settings).language = language;
    shell.save_settings()
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
    crate::tray::apply(&app, model, ids).map_err(CommandError::from)
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
            $crate::commands::disconnect_this_device,
            $crate::commands::undo,
            $crate::commands::restore_deleted_folder,
            $crate::commands::cancel_restore,
            $crate::commands::redownload_folder,
            $crate::commands::get_server_number,
            $crate::commands::confirm_server_number,
            $crate::commands::fix_server_with_offer,
            $crate::commands::restore_remote_deleted,
            $crate::commands::install_update,
            $crate::commands::get_settings,
            $crate::commands::set_autostart,
            $crate::commands::set_language,
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
    "disconnect_this_device",
    "undo",
    "restore_deleted_folder",
    "cancel_restore",
    "redownload_folder",
    "get_server_number",
    "confirm_server_number",
    "fix_server_with_offer",
    "restore_remote_deleted",
    "install_update",
    "get_settings",
    "set_autostart",
    "set_language",
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
                    fs: Box::new(|_path: &Path| {
                        let fs = std::sync::Arc::new(MemFs::new(true));
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
        remember_code(&shell, &view);
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
        remember_code(&shell, &view);
        *lock(&shell.device_name) = Some("Laptop".into());
        let snapshot = tauri::async_runtime::block_on(fresh_snapshot(&shell)).unwrap();
        assert_eq!(
            serde_json::to_value(&snapshot).unwrap()["setup"],
            json!("done")
        );

        tauri::async_runtime::block_on(disconnect(&shell)).unwrap();

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
