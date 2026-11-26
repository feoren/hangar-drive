//! The types of the app's window contract, one to one with `src/backend/types.ts`.
//!
//! Every type serializes to the JSON shape the TypeScript decoders read: camelCase fields,
//! unions tagged with `kind` (events with `type`), times in milliseconds since the epoch (UTC),
//! sizes in bytes, IDs in their canonical hex. Expected outcomes the person has to see are part
//! of the return types ([`ApiResult`]); only unexpected failures are errors.

use serde::{Serialize, Serializer};

/// Milliseconds since the Unix epoch (UTC).
pub type Millis = i64;
/// Bytes.
pub type Bytes = u64;

/// `Result<T, E>` of the TypeScript side: `{ ok: true, value }` or `{ ok: false, error }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiResult<T, E> {
    /// Success.
    Ok(T),
    /// An expected failure the window shows in words.
    Err(E),
}

impl<T: Serialize, E: Serialize> Serialize for ApiResult<T, E> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("Result", 2)?;
        match self {
            ApiResult::Ok(v) => {
                st.serialize_field("ok", &true)?;
                st.serialize_field("value", v)?;
            }
            ApiResult::Err(e) => {
                st.serialize_field("ok", &false)?;
                st.serialize_field("error", e)?;
            }
        }
        st.end()
    }
}

/// Six groups of five digits (safety number, folder number, server number).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NumberRows {
    /// The groups, zero padded.
    pub groups: Vec<String>,
}

impl NumberRows {
    /// The rows of a safety number.
    pub fn of(number: &hangar_drive_crypto::identity::SafetyNumber) -> Self {
        Self {
            groups: number.groups().iter().map(|g| format!("{g:05}")).collect(),
        }
    }
}

/// The server key number of the key the server presents now (`getServerNumber`, ADR 0001,
/// section 6, "Pin rotation"), and the server CLI command that prints the server's own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServerNumberView {
    /// The number to compare.
    pub number: NumberRows,
    /// The command the operator runs on the server.
    pub command: String,
    /// The pin (SHA-256 of the SPKI) of the key whose number this is. The shell hands it back to
    /// `confirm_server_number`, so only the key whose number the person compared is taken
    /// (security review N7); the window never sees it.
    #[serde(skip)]
    pub pin: [u8; 32],
}

/// Why an offer could not bring the server's new identity (`fixServerWithOffer`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FixServerError {
    /// Not a pairing link.
    NotALink,
    /// The offer is of another account or server, or no trusted device of this account signed
    /// it.
    OtherAccount,
    /// The offer's time is over.
    Expired,
}

/// A QR code as a square of modules, row by row, "1" dark and "0" light.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QrMatrix {
    /// Modules per side.
    pub size: u32,
    /// `size * size` characters.
    pub modules: String,
}

/// The connection to the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Connection {
    /// Online.
    Online,
    /// The OS reports no network.
    NoNetwork,
    /// The server has not answered for at least two minutes.
    ServerSilent {
        /// Since when.
        since: Millis,
    },
}

/// A pause of all syncing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Pause {
    /// `None`: until the person resumes.
    pub until: Option<Millis>,
}

/// The last file that changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LastFile {
    /// Its name.
    pub name: String,
    /// When.
    pub at: Millis,
}

/// The summary line of the main window and the tray.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncSummary {
    /// The connection.
    pub connection: Connection,
    /// Set while paused.
    pub pause: Option<Pause>,
    /// Files with work left.
    pub pending_files: u64,
    /// Bytes left to transfer.
    pub bytes_left: Bytes,
    /// The last full sync.
    pub last_sync: Option<Millis>,
    /// The last file.
    pub last_file: Option<LastFile>,
    /// Files held back by a metered network.
    pub waiting_metered: u64,
    /// Files held back by the server's upload budget.
    pub waiting_budget: u64,
}

/// Why a folder stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StopReasonApi {
    /// The folder (its root marker) is missing.
    Missing,
    /// The server shows an older state.
    OlderState,
    /// Heads of a removed device wait for the person's decision (security review H1).
    RemovedHeads,
    /// The server's tree of the folder is beyond the limits of a folder (security review M3);
    /// a restore ("Undo a device") replaces it.
    TreeLimit,
    /// The folder on this disk is too large for a folder (follow-up check N-4): more items or
    /// deeper than a device takes in. Nothing is published until it is within the limits.
    TooLarge,
}

/// A folder's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum FolderStatus {
    /// Up to date.
    UpToDate,
    /// Uploading.
    Uploading {
        /// Files.
        count: u64,
    },
    /// Downloading.
    Downloading {
        /// Files.
        count: u64,
    },
    /// Paused.
    Paused,
    /// Stopped.
    Stopped {
        /// Why.
        reason: StopReasonApi,
    },
}

/// One synced folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    /// The folder ID.
    pub id: String,
    /// Its name.
    pub name: String,
    /// Its local path.
    pub path: String,
    /// Its status.
    pub status: FolderStatus,
    /// Days without news from the other devices, above the threshold.
    pub freeze_days: Option<u32>,
    /// Entries never synced.
    pub not_synced_count: u64,
}

/// What happened to a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FileAction {
    /// Changed here.
    Changed,
    /// Added here.
    Added,
    /// Deleted here.
    Deleted,
    /// Renamed or moved.
    Renamed,
    /// Came from another device.
    FromDevice,
    /// Restored.
    Restored,
    /// Two versions (a conflict copy was made).
    TwoVersions,
}

/// One line of the activity list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ActivityEntry {
    /// One file.
    #[serde(rename_all = "camelCase")]
    File {
        /// Entry ID.
        id: String,
        /// The folder.
        folder_id: String,
        /// Its name.
        folder_name: String,
        /// The file's name.
        name: String,
        /// Its path in the folder.
        path: String,
        /// What happened.
        action: FileAction,
        /// The other device for "fromDevice".
        device: Option<String>,
        /// When.
        at: Millis,
    },
    /// Many files at once.
    #[serde(rename_all = "camelCase")]
    Group {
        /// Entry ID.
        id: String,
        /// The folder.
        folder_id: String,
        /// Its name.
        folder_name: String,
        /// Files.
        count: u64,
        /// When.
        at: Millis,
    },
    /// Another device deleted files.
    #[serde(rename_all = "camelCase")]
    RemoteDeleted {
        /// Entry ID.
        id: String,
        /// The folder.
        folder_id: String,
        /// Its name.
        folder_name: String,
        /// Files.
        count: u64,
        /// The device.
        device: String,
        /// When.
        at: Millis,
    },
    /// A file another device deleted came back here (a change beat the delete).
    #[serde(rename_all = "camelCase")]
    CameBack {
        /// Entry ID.
        id: String,
        /// The folder.
        folder_id: String,
        /// Its name.
        folder_name: String,
        /// The file's name.
        name: String,
        /// Its path.
        path: String,
        /// The device.
        device: String,
        /// When.
        at: Millis,
    },
}

/// A banner of the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Warning {
    /// Many deletes wait for the person's decision.
    #[serde(rename_all = "camelCase")]
    MassDelete {
        /// Warning ID.
        id: String,
        /// The folder.
        folder_id: String,
        /// Its name.
        folder_name: String,
        /// Deletes.
        count: u64,
        /// The first few names.
        sample: Vec<String>,
    },
    /// The folder is missing.
    #[serde(rename_all = "camelCase")]
    MissingFolder {
        /// Warning ID.
        id: String,
        /// The folder.
        folder_id: String,
        /// Its name.
        folder_name: String,
    },
    /// The server identifies itself differently than usual (pin mismatch).
    #[serde(rename_all = "camelCase")]
    ServerIdentity {
        /// Warning ID.
        id: String,
        /// Another device of the account exists.
        has_other_device: bool,
    },
    /// The quota is nearly used up.
    Quota {
        /// Warning ID.
        id: String,
    },
    /// The quota is used up.
    QuotaFull {
        /// Warning ID.
        id: String,
    },
    /// The server's disk is full.
    ServerDisk {
        /// Warning ID.
        id: String,
    },
    /// This disk is full.
    DiskFull {
        /// Warning ID.
        id: String,
        /// Bytes needed.
        needed: Bytes,
    },
    /// The server shows an older state of a folder.
    #[serde(rename_all = "camelCase")]
    OlderState {
        /// Warning ID.
        id: String,
        /// The folder.
        folder_id: String,
        /// Its name.
        folder_name: String,
    },
    /// The folder's newest version on the server is too deep or too large to be a folder
    /// (security review M3): it was not taken in, and the folder waits for "Undo a device".
    #[serde(rename_all = "camelCase")]
    TreeLimit {
        /// Warning ID.
        id: String,
        /// The folder.
        folder_id: String,
        /// Its name.
        folder_name: String,
    },
    /// A removed device's changes arrived without the barrier of the device that removed it;
    /// the folder waits until the person takes them in (then "Undo a device" is offered) or
    /// leaves the folder stopped (security review H1).
    #[serde(rename_all = "camelCase")]
    RemovedHeads {
        /// Warning ID.
        id: String,
        /// The folder.
        folder_id: String,
        /// Its name.
        folder_name: String,
        /// The removed devices' names, as far as this device still knows them.
        devices: Vec<String>,
        /// Their commits.
        count: u64,
    },
    /// This device was removed.
    Removed {
        /// Warning ID.
        id: String,
        /// By which device.
        by: String,
    },
    /// The server answered this device's own sign-in with "removed" without device log entries
    /// that show a valid removal from this device's own verified head (security review H2).
    /// Sync stops; the account is forgotten only once the person confirms
    /// (`confirmDeviceRemoved`). A verified removal forgets at once and shows [`Self::Removed`]
    /// instead. This warning cannot be dismissed, only confirmed.
    RemovalReported {
        /// Warning ID.
        id: String,
        /// When the server said it first (Unix ms).
        since: i64,
    },
    /// The server needs a newer app.
    UpdateRequired {
        /// Warning ID.
        id: String,
    },
    /// The server refused something.
    Refused {
        /// Warning ID.
        id: String,
    },
    /// A device may be compromised (anomaly pin).
    #[serde(rename_all = "camelCase")]
    Suspect {
        /// Warning ID.
        id: String,
        /// The device.
        device_id: String,
        /// Its name.
        device_name: String,
        /// The folder.
        folder_id: String,
        /// Its name.
        folder_name: String,
        /// The timeline entry before the device's first commit in the burst.
        entry_id: String,
        /// Retention days.
        days: u32,
    },
    /// Conflict copies exist.
    Conflicts {
        /// Warning ID.
        id: String,
        /// Groups.
        count: u64,
    },
    /// Names this device cannot hold.
    Names {
        /// Warning ID.
        id: String,
        /// Items.
        count: u64,
    },
}

/// A quiet notice from the server's change feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ServerNotice {
    /// Retained bytes exceed the quota.
    Retained,
    /// A device reached its upload budget.
    BudgetDevice {
        /// Its name.
        device: String,
    },
    /// The minimum count cap was reached.
    MinCount {
        /// Days.
        days: u32,
    },
    /// The server's change feed was behind this device's cursor (an older backup of the server,
    /// or a sequence a server had pushed too far): the device read the whole account again
    /// (security review M2).
    OlderAccountState,
}

/// The account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    /// The server's host.
    pub host: String,
    /// Retention days the server guarantees.
    pub retention_days: u32,
    /// Other devices exist.
    pub has_other_devices: bool,
}

/// The quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Storage {
    /// Used.
    pub used: Bytes,
    /// The quota.
    pub quota: Bytes,
}

/// A folder of the account not on this device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteFolder {
    /// The folder ID.
    pub id: String,
    /// Its name.
    pub name: String,
    /// Its size.
    pub size: Bytes,
}

/// A folder deleted on all devices that can still come back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedFolder {
    /// The folder ID.
    pub id: String,
    /// Its name.
    pub name: String,
    /// Days left.
    pub days_left: u32,
}

/// What the device offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Environment {
    /// A camera for QR codes.
    pub camera: bool,
}

/// Set up or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SetupState {
    /// No account yet.
    Needed,
    /// Set up.
    Done,
}

/// Everything the main window and the tray show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    /// Setup.
    pub setup: SetupState,
    /// The summary.
    pub sync: SyncSummary,
    /// The folders.
    pub folders: Vec<Folder>,
    /// Newest first, at most 50.
    pub activity: Vec<ActivityEntry>,
    /// Banners.
    pub warnings: Vec<Warning>,
    /// Notices.
    pub notices: Vec<ServerNotice>,
    /// The quota, if the server reports one.
    pub storage: Option<Storage>,
    /// The account.
    pub account: Option<AccountInfo>,
    /// Account folders not on this device.
    pub remote_folders: Vec<RemoteFolder>,
    /// Folders that can come back.
    pub deleted_folders: Vec<DeletedFolder>,
    /// The environment.
    pub env: Environment,
}

/// A recovery code to write down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCodeView {
    /// Eight groups of four characters.
    pub groups: Vec<String>,
    /// One-based group the person types back; never 1.
    pub check_group: u32,
    /// What the recovery sheet prints next to the code (ADR 0001, section 2.3).
    pub sheet: RecoverySheetView,
}

/// The public part of the recovery sheet: printed in the clear, and as the link
/// `hangar-drive://recover#...`, which never carries the code (open point A). The link is
/// what a recovery reads: it also carries the genesis anchor and the optional pin (N1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverySheetView {
    /// The server address.
    pub server_url: String,
    /// The server ID.
    pub server_id: String,
    /// The account ID.
    pub account_id: String,
    /// The hash of the account's first log entry, in hex (the genesis anchor).
    pub genesis_anchor: String,
    /// The SPKI pin of a self-signed server in base64url (as in an invite link), if any.
    pub pin: Option<String>,
    /// The recovery link.
    pub link: String,
}

/// Why a recovery with the sheet failed (the window's `RecoverError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RecoverError {
    /// The code has a typo.
    Typo,
    /// The sheet or the code does not belong to an account on this server.
    Unknown,
    /// The code was used before.
    Used,
    /// A code of another app.
    OtherApp,
    /// The server cannot be reached.
    Unreachable,
    /// Not secure.
    Insecure,
    /// The new device's name is blank.
    Blank,
    /// The new device's name has white space at an edge.
    EdgeWhitespace,
}

/// One version of a conflict group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConflictVersion {
    /// The item ID.
    pub id: String,
    /// Its name.
    pub name: String,
    /// The writing device, if known.
    pub device: String,
    /// Modification time.
    pub modified: Millis,
    /// Size.
    pub size: Bytes,
    /// The version that kept the name.
    pub original: bool,
}

/// The kind of a conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ConflictKind {
    /// Two contents.
    Content,
    /// Names that differ only in case or normalization.
    CaseOnly,
}

/// An original and its conflict copies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictGroup {
    /// The group ID (the original's item ID).
    pub id: String,
    /// The folder.
    pub folder_id: String,
    /// Its name.
    pub folder_name: String,
    /// The original's path.
    pub path: String,
    /// The kind.
    pub kind: ConflictKind,
    /// Original first.
    pub versions: Vec<ConflictVersion>,
}

/// Why a name cannot be held here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum NameReason {
    /// A forbidden character.
    Char {
        /// The character.
        char: String,
    },
    /// A reserved name.
    Reserved {
        /// The name.
        name: String,
    },
    /// A trailing dot or space.
    Trailing,
    /// A control character.
    Control,
    /// The file system refused to create it.
    CannotCreate,
}

/// An item this device cannot hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NameIssue {
    /// Issue ID (folder and item).
    pub id: String,
    /// The folder.
    pub folder_id: String,
    /// Its name.
    pub folder_name: String,
    /// The parent path, empty at the root.
    pub dir: String,
    /// The name.
    pub name: String,
    /// Why.
    pub reason: NameReason,
    /// The device that wrote it, if known.
    pub device: String,
}

/// Why a rename was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RenameError {
    /// Not a valid name.
    Invalid,
    /// Taken.
    Exists,
}

/// An entry that is never synced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotSyncedEntry {
    /// Path in the folder.
    pub path: String,
    /// `link` or `system`.
    pub reason: String,
}

/// One entry of the timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimelineEntry {
    /// The commit ID.
    pub id: String,
    /// When this device saw it (the protocol carries no server time in the delta).
    pub at: Millis,
    /// The writing device.
    pub device: String,
    /// Files changed.
    pub changed: u64,
    /// Files added.
    pub added: u64,
    /// Files deleted.
    pub deleted: u64,
    /// A re-anchor.
    pub reanchored: bool,
}

/// A folder's history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Timeline {
    /// Newest first.
    pub entries: Vec<TimelineEntry>,
    /// Entries whose tree has expired.
    pub expired_count: u64,
    /// Retention days.
    pub retention_days: u32,
}

/// How a file of an old version compares with now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FileDiff {
    /// Same.
    Same,
    /// Different.
    Different,
    /// Missing now.
    Missing,
    /// Newer now.
    Newer,
}

/// The kind of a tree node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TreeNodeKind {
    /// A file.
    File,
    /// A directory.
    Dir,
}

/// One node of an old version's tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TreeNode {
    /// Path in the folder, "/" separated.
    pub path: String,
    /// Its name.
    pub name: String,
    /// Depth from 1.
    pub depth: u32,
    /// File or directory.
    pub kind: TreeNodeKind,
    /// Compared with now.
    pub diff: FileDiff,
}

/// An old version's tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionTree {
    /// Nodes, parents first.
    pub nodes: Vec<TreeNode>,
    /// Files that differ now.
    pub changed: u64,
    /// Files missing now.
    pub missing: u64,
}

/// What a restore did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum RestoreOutcome {
    /// Done.
    #[serde(rename_all = "camelCase")]
    Done {
        /// Items restored.
        count: u64,
        /// The name it came back under, if it was taken.
        renamed_to: Option<String>,
        /// Undo.
        undo_token: Option<String>,
    },
    /// Waits for the upload budget.
    #[serde(rename_all = "camelCase")]
    WaitBudget {
        /// The waiting job.
        job_id: String,
    },
    /// No room (quota).
    NoSpace,
    /// The version is no longer retained.
    Expired,
    /// Failed.
    Failed,
}

/// A deleted item that can come back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashItem {
    /// The item ID.
    pub id: String,
    /// Its name.
    pub name: String,
    /// Its last parent path.
    pub dir: String,
    /// When it was deleted (as seen).
    pub deleted_at: Millis,
    /// The device that deleted it.
    pub device: String,
}

/// The kind of device, for the icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DeviceKind {
    /// A laptop.
    Laptop,
    /// A desktop.
    Desktop,
}

/// A device of the account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    /// The device ID.
    pub id: String,
    /// Its name.
    pub name: String,
    /// The icon.
    pub kind: DeviceKind,
    /// This device.
    pub is_this: bool,
    /// Last seen, if known.
    pub last_seen: Option<Millis>,
    /// When it was added (the issuer's clock in the log).
    pub added: Millis,
}

/// The devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceList {
    /// The devices.
    pub devices: Vec<Device>,
    /// When the recovery code was made.
    pub recovery_created: Millis,
}

/// A pairing offer of this device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingOfferView {
    /// The offer ID.
    pub id: String,
    /// The link.
    pub link: String,
    /// The code to type, grouped.
    pub code: Vec<String>,
    /// The server's host.
    pub host: String,
    /// The account ID in hex, so the new device's question can be compared (N2).
    pub account: String,
    /// The QR code of the link, drawn by the app shell (`None` here).
    pub qr: Option<QrMatrix>,
    /// When it expires.
    pub expires_at: Millis,
}

/// How the new device answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PairPath {
    /// The link or QR code.
    Link,
    /// The typed code.
    Typed,
}

/// A new device asks to join.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairRequestView {
    /// The offer.
    pub offer_id: String,
    /// The new device's name.
    pub device_name: String,
    /// How it answered.
    pub path: PairPath,
    /// Its safety number.
    pub safety: NumberRows,
    /// The name of a device of the account that looks the same as the new one's
    /// (`hangar_drive_protocol::name::looks_alike`): the window says so, and the native question
    /// names it, so a stranger's device cannot pass for one of the person's own.
    pub similar_to: Option<String>,
}

/// Why pairing failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PairError {
    /// Not a link.
    NotALink,
    /// Expired.
    Expired,
    /// A typo in the code.
    Typo,
    /// The other device declined.
    Declined,
    /// Too many devices.
    TooMany,
    /// Another account.
    OtherAccount,
    /// The server cannot be reached.
    Unreachable,
    /// Not secure.
    Insecure,
}

/// The outcome of pairing on the new device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum PairResult {
    /// Joined: the devices of the account the new device joined, for the person to confirm
    /// that these are their own (N2).
    Joined {
        /// The account's devices, this one included.
        devices: Vec<Device>,
    },
    /// Failed.
    Failed {
        /// Why.
        error: PairError,
    },
}

/// An event for the window, on the channel `hangar-drive://event`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum BackendEvent {
    /// The snapshot changed.
    Snapshot {
        /// It.
        snapshot: Box<Snapshot>,
    },
    /// A new device answered an offer of this device.
    PairRequest {
        /// The request.
        request: PairRequestView,
    },
    /// The new device gave up or the offer expired.
    #[serde(rename_all = "camelCase")]
    PairRequestGone {
        /// The offer.
        offer_id: String,
    },
    /// The outcome of pairing on this (new) device.
    PairResult {
        /// It.
        result: PairResult,
    },
    /// Heads of a removed device arrived without a barrier: the folder stopped, and the window
    /// asks the person and then offers "Undo a device" (security review H1, N2).
    #[serde(rename_all = "camelCase")]
    RemovedHeads {
        /// The folder.
        folder_id: String,
        /// The heads.
        heads: Vec<RemovedHeadView>,
    },
}

/// One head of a removed device for "Undo a device".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovedHeadView {
    /// The commit (timeline entry ID once taken in).
    pub commit: String,
    /// The removed device.
    pub device_id: String,
    /// Its name, if this device still knows it.
    pub device_name: String,
    /// The folder sequence.
    pub sequence: u64,
}

/// A checked invite link (`checkInvite`, N3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteCheck {
    /// The server's host (and port) as the client connects to it: internationalized names in
    /// their ASCII (punycode) form, so a look-alike name shows as `xn--`.
    pub host: String,
    /// The link carries an SPKI pin (a self-signed server): the window can say that this link
    /// trusts that one key and no certificate authority.
    pub pinned: bool,
    /// A label of the host is punycode (`xn--`), which can hide a look-alike name.
    pub punycode: bool,
}

/// What a link names, read offline before anything is sent (`inspectLink`, N2): the window
/// shows host and account and asks before it connects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum InspectedLink {
    /// An operator's invite.
    Invite {
        /// The server's host, as in [`InviteCheck::host`].
        host: String,
        /// The link carries an SPKI pin.
        pinned: bool,
        /// A label of the host is punycode, which can hide a look-alike name (N3).
        punycode: bool,
    },
    /// A pairing offer of another device.
    Pair {
        /// The server's host.
        host: String,
        /// The account ID in hex.
        account: String,
        /// The offer carries an SPKI pin.
        pinned: bool,
        /// A label of the host is punycode (security review, info: as for an invite).
        punycode: bool,
    },
    /// A recovery sheet.
    Recover {
        /// The server's host.
        host: String,
        /// The account ID in hex.
        account: String,
        /// The sheet carries an SPKI pin.
        pinned: bool,
        /// A label of the host is punycode (security review, info: as for an invite).
        punycode: bool,
    },
}

/// Why `inspectLink` read nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LinkProblem {
    /// Not a link of the app.
    NotALink,
    /// A link of the app, but a part of it does not decode.
    Damaged,
    /// The server address is not allowed.
    Insecure,
}

/// What taking in a removed device's heads did (`acceptRemovedHeads`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptedHeads {
    /// The heads the barrier covers.
    pub count: u64,
    /// The timeline entry right before the first of them, for "Undo a device"; `None` when
    /// the folder has no earlier version.
    pub before_entry_id: Option<String>,
}

/// Why a new account could not be started (`beginAccount`): an invite or a device name error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BeginError {
    /// Not an invite link.
    NotALink,
    /// The invite was used.
    Used,
    /// The invite expired.
    Expired,
    /// The server cannot be reached.
    Unreachable,
    /// Not secure.
    Insecure,
    /// The device name is blank.
    Blank,
    /// The device name has white space at an edge.
    EdgeWhitespace,
}

/// Why a folder cannot be synced (the window's `FolderRefusal`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FolderRefusal {
    /// A network drive.
    Network,
    /// A whole drive.
    Root,
    /// A system folder, the home folder, application data, the app's own data or another
    /// sync client's folder.
    System,
    /// Inside or around a synced folder.
    Nested,
    /// The folder cannot be read or resolved.
    NoAccess,
    /// The folder's marker names another folder (`findMissingFolder`).
    WrongFolder,
}

/// A refused folder and, for [`FolderRefusal::Nested`], the synced folder it collides with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FolderRefusalView {
    /// Why.
    pub reason: FolderRefusal,
    /// The colliding synced folder's name.
    pub folder: Option<String>,
}

/// Why an invite link was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum InviteError {
    /// Not a link.
    NotALink,
    /// Used.
    Used,
    /// Expired.
    Expired,
    /// The server cannot be reached.
    Unreachable,
    /// Not secure.
    Insecure,
}

/// Why a device name was refused (rule N5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NameError {
    /// Blank.
    Blank,
    /// White space at an edge.
    EdgeWhitespace,
}

/// Why a device name was refused when a device is named or renamed: the name rule (N5), or a
/// name that looks the same as another device's of the account and was not confirmed in the
/// native question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DeviceNameError {
    /// Blank.
    Blank,
    /// White space at an edge.
    EdgeWhitespace,
    /// Looks the same as the name of another device of the account.
    LooksLike,
}

impl From<NameError> for DeviceNameError {
    fn from(error: NameError) -> Self {
        match error {
            NameError::Blank => Self::Blank,
            NameError::EdgeWhitespace => Self::EdgeWhitespace,
        }
    }
}

/// What resetting a folder to a timeline entry changes, computed before the native question
/// (follow-up check N-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetPreview {
    /// The folder's name.
    pub folder_name: String,
    /// Files of the folder's current state that the entry does not hold: they disappear on
    /// every device (they stay in the history).
    pub vanishing: u64,
}

/// How long to pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PauseDuration {
    /// One hour.
    Hour,
    /// Until tomorrow (the app passes the local midnight in `until`).
    Tomorrow,
    /// Until resumed.
    Manual,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shapes_match_the_typescript_contract() {
        let r: ApiResult<u8, InviteError> = ApiResult::Err(InviteError::NotALink);
        assert_eq!(
            serde_json::to_value(r).unwrap(),
            json!({"ok": false, "error": "notALink"})
        );
        let r: ApiResult<Option<u8>, NameError> = ApiResult::Ok(None);
        assert_eq!(
            serde_json::to_value(r).unwrap(),
            json!({"ok": true, "value": null})
        );
        assert_eq!(
            serde_json::to_value(FolderStatus::Stopped {
                reason: StopReasonApi::OlderState
            })
            .unwrap(),
            json!({"kind": "stopped", "reason": "olderState"})
        );
        assert_eq!(
            serde_json::to_value(Connection::ServerSilent { since: 5 }).unwrap(),
            json!({"kind": "serverSilent", "since": 5})
        );
        let w = Warning::MassDelete {
            id: "w".into(),
            folder_id: "f".into(),
            folder_name: "Docs".into(),
            count: 3,
            sample: vec!["a".into()],
        };
        assert_eq!(
            serde_json::to_value(w).unwrap(),
            json!({"kind": "massDelete", "id": "w", "folderId": "f", "folderName": "Docs", "count": 3, "sample": ["a"]})
        );
        let e = BackendEvent::PairRequestGone {
            offer_id: "o".into(),
        };
        assert_eq!(
            serde_json::to_value(e).unwrap(),
            json!({"type": "pairRequestGone", "offerId": "o"})
        );
        let o = RestoreOutcome::Done {
            count: 1,
            renamed_to: None,
            undo_token: Some("t".into()),
        };
        assert_eq!(
            serde_json::to_value(o).unwrap(),
            json!({"kind": "done", "count": 1, "renamedTo": null, "undoToken": "t"})
        );
        assert_eq!(
            serde_json::to_value(NameReason::Char { char: ":".into() }).unwrap(),
            json!({"kind": "char", "char": ":"})
        );
        let p: PauseDuration = serde_json::from_value(json!("tomorrow")).unwrap();
        assert_eq!(p, PauseDuration::Tomorrow);
    }
}
