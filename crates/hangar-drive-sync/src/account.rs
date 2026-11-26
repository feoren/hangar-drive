//! The account as this device verified it: the device log, the epoch secrets, the folder key
//! rings, the folder list and the device names, the record replay guard and the commit counter.
//!
//! Everything comes from the server and is verified before it is used (ADR 0001, section 3,
//! "Change feed": the feed is only an index). [`Account::refresh`] pulls the feed from the
//! account cursor and applies log, epochs and records before it reports folder heads, so keys
//! are present before the commits that need them.
//!
//! Secrets live only in the [`Keychain`]: the device identity and one entry per epoch secret.
//! The local index holds the verified log entries, the sealed records, the guard marks, the
//! counter and the feed cursor, none of which is secret.

use std::collections::BTreeMap;

use hangar_drive_crypto::commit::{Commit, CommitCounter, SignedCommit};
use hangar_drive_crypto::device_names::{
    device_names_key, open_device_names, seal_device_names, DeviceName, DeviceNameList,
};
use hangar_drive_crypto::devicelog::{AccountState, EntryKind, LogDevice};
use hangar_drive_crypto::epoch::{self, AccountSecret};
use hangar_drive_crypto::folder_keys::{
    open_folder_list, open_ring, seal_folder_list, seal_ring, writable_generation, FolderEntry,
    FolderKeyRing, FolderList, OpenedRing,
};
use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_crypto::record::{record_header, RecordCipher, RecordGuard};
use hangar_drive_crypto::Entropy;
use hangar_drive_protocol::api::{
    CreateAccountRequest, FeedChange, LogAppendRequest, Notice, RecordKey, RecordKind, RecordPut,
    WrappedKeyEntry,
};
use hangar_drive_protocol::ids::{
    AccountId, Blob, DeviceId, Epoch, FolderId, Generation, InviteToken, LogHash, LogHead, ServerId,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::chunker::DynEntropy;
use crate::codec::FolderCrypto;
use crate::error::SyncError;
use crate::ports::{Keychain, ServerApi, Store};

const KEY_IDENTITY: &str = "device-identity";
const STORE_KEY: &str = "account";

fn epoch_key_name(epoch: Epoch) -> String {
    format!("epoch-{}", epoch.0)
}

/// Epoch secrets past the newest one the stored log names that [`forget`] deletes as well: a
/// refresh stores a new epoch's secret before it saves the log that names it, so a crash in
/// between leaves a secret the stored log does not know of.
const FORGET_MARGIN: u32 = 8;

/// Deletes this device's secrets from the keychain (security review L1): the device identity
/// and the epoch secrets 1 to `newest`. Every key is tried, so one failure does not keep the
/// others; the first failure is returned.
pub fn forget_secrets(keychain: &mut dyn Keychain, newest: u32) -> Result<(), SyncError> {
    let mut first = keychain.delete(KEY_IDENTITY).err();
    for epoch in 1..=newest {
        if let Err(e) = keychain.delete(&epoch_key_name(Epoch(epoch))) {
            first.get_or_insert(e);
        }
    }
    first.map_or(Ok(()), |e| Err(e.into()))
}

/// The newest epoch the stored account's log names; 0 without a stored account or with one
/// that does not read.
fn stored_newest_epoch(store: &dyn Store) -> u32 {
    let Ok(Some(bytes)) = store.account_value(STORE_KEY) else {
        return 0;
    };
    let Ok(p) = serde_json::from_slice::<Persisted>(&bytes) else {
        return 0;
    };
    AccountState::from_entries(p.account, p.log.iter().map(|b| b.0.as_slice()))
        .ok()
        .and_then(|state| state.current_epoch().map(|e| e.epoch.0))
        .unwrap_or(0)
}

/// Forgets the account on this device (security review L1: the device was removed, the person
/// resets it, or the app is uninstalled): every secret of the keychain, then the stored account.
/// The local files and the folders' sync state are the caller's.
pub fn forget(store: &mut dyn Store, keychain: &mut dyn Keychain) -> Result<(), SyncError> {
    let newest = stored_newest_epoch(store).saturating_add(FORGET_MARGIN);
    let secrets = forget_secrets(keychain, newest);
    store.delete_account_value(STORE_KEY)?;
    secrets
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRecord {
    key: RecordKey,
    version: u64,
    data: Blob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Persisted {
    account: AccountId,
    device: DeviceId,
    device_name: String,
    server: Option<ServerId>,
    log: Vec<Blob>,
    counter: u64,
    feed_cursor: u64,
    records: Vec<StoredRecord>,
    guard: Vec<(RecordKey, u64, [u8; 32])>,
    /// The account exists on the server, but its first epoch or its device names may not yet
    /// ([`Account::finish_setup`]).
    #[serde(default)]
    setup_pending: bool,
}

/// What a refresh found besides the account state itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Refresh {
    /// Folders whose server sequence is now this.
    pub folder_heads: BTreeMap<FolderId, u64>,
    /// Notices of the server, from the closed list.
    pub notices: Vec<Notice>,
    /// The device log grew.
    pub log_changed: bool,
    /// The folder list changed.
    pub folders_changed: bool,
    /// This device was removed from the account.
    pub removed: bool,
    /// The server's feed sequence was below this device's cursor, so the whole account was read
    /// again from cursor 0 (security review M2).
    pub feed_reset: bool,
}

/// Entry 1 of a new account, made and verified before the invite is redeemed: the recovery
/// sheet names its hash as the genesis anchor (N1), so it must exist before the code is shown.
/// Nothing of it is on the server until [`Account::create_from`].
pub struct Genesis {
    identity: DeviceIdentity,
    account: AccountId,
    device: DeviceId,
    entry: Vec<u8>,
    state: AccountState,
}

impl std::fmt::Debug for Genesis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Genesis")
            .field("account", &self.account)
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

impl Genesis {
    /// A new device identity and the create entry listing it (and the recovery device, if
    /// given), applied to a fresh log.
    pub fn new(
        entropy: &mut dyn Entropy,
        now_ms: u64,
        account: AccountId,
        device: DeviceId,
        recovery: Option<(&DeviceIdentity, DeviceId)>,
    ) -> Result<Self, SyncError> {
        let identity = DeviceIdentity::generate(&mut DynEntropy(entropy))
            .map_err(|_| SyncError::Entropy(hangar_drive_crypto::EntropyError))?;
        let mut devices = vec![LogDevice::of(&identity, &account, device, false)];
        if let Some((recovery_identity, recovery_id)) = recovery {
            devices.push(LogDevice::of(
                recovery_identity,
                &account,
                recovery_id,
                true,
            ));
        }
        let mut state = AccountState::new(account);
        let entry = state.next_entry(&identity, device, now_ms, EntryKind::Create { devices })?;
        state.apply(&entry)?;
        Ok(Self {
            identity,
            account,
            device,
            entry,
            state,
        })
    }

    /// The account.
    pub fn account(&self) -> &AccountId {
        &self.account
    }

    /// The hash of entry 1, the recovery sheet's genesis anchor.
    pub fn hash(&self) -> Result<LogHash, SyncError> {
        self.state
            .hash_at(1)
            .copied()
            .ok_or(SyncError::Invalid("the genesis entry"))
    }
}

/// The verified account (module docs).
pub struct Account {
    account: AccountId,
    device: DeviceId,
    device_name: String,
    server: Option<ServerId>,
    identity: DeviceIdentity,
    state: AccountState,
    log: Vec<Vec<u8>>,
    secrets: BTreeMap<u32, AccountSecret>,
    rings: BTreeMap<FolderId, OpenedRing>,
    folders: Option<(FolderList, u64)>,
    device_names: Option<(DeviceNameList, u64)>,
    records: BTreeMap<RecordKey, (u64, Vec<u8>)>,
    guard: RecordGuard,
    counter: CommitCounter,
    feed_cursor: u64,
    setup_pending: bool,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("account", &self.account)
            .field("device", &self.device)
            .field("log_len", &self.state.len())
            .field("folders", &self.rings.len())
            .finish_non_exhaustive()
    }
}

impl Account {
    // -- Creation ---------------------------------------------------------------------------

    /// Creates a new account on the server: entry 1 lists this device (and the recovery device
    /// derived from the recovery code, if given), then the first epoch, then the device names.
    /// `server` is used without a session for the creation and must sign in as this device
    /// for the rest (a client of one session identity cannot; the engine uses
    /// [`Account::create_from`] and [`Account::finish_setup`] with two clients).
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        server: &mut dyn ServerApi,
        keychain: &mut dyn Keychain,
        store: &mut dyn Store,
        entropy: &mut dyn Entropy,
        now_ms: u64,
        invite: InviteToken,
        account: AccountId,
        device: DeviceId,
        device_name: &str,
        recovery: Option<(&DeviceIdentity, DeviceId)>,
    ) -> Result<Self, SyncError> {
        let genesis = Genesis::new(entropy, now_ms, account, device, recovery)?;
        let mut me = Self::create_from(server, keychain, store, invite, &genesis, device_name)?;
        me.finish_setup(server, keychain, store, entropy, now_ms)?;
        Ok(me)
    }

    /// The first step of [`Account::create`] with entry 1 made beforehand ([`Genesis::new`]),
    /// so the recovery sheet shown before the invite is redeemed can name the hash of that
    /// entry (N1). Redeems the invite with entry 1 through `server`, which needs no session,
    /// and stores the device identity and the account at once, marked as not set up yet: the
    /// rest ([`Account::finish_setup`]) needs a session of this device, and a failure after the
    /// invite was used must leave an account this device can carry on with, not a half one it
    /// forgot (finding E2E-1). Nothing is stored when the server refuses.
    pub fn create_from(
        server: &mut dyn ServerApi,
        keychain: &mut dyn Keychain,
        store: &mut dyn Store,
        invite: InviteToken,
        genesis: &Genesis,
        device_name: &str,
    ) -> Result<Self, SyncError> {
        let created = server.create_account(&CreateAccountRequest {
            invite,
            account: genesis.account,
            genesis: Blob(genesis.entry.clone()),
        })?;
        let identity = DeviceIdentity::import(&genesis.identity.export())
            .map_err(|_| SyncError::Corrupt("device identity".into()))?;
        keychain.store(KEY_IDENTITY, &identity.export())?;
        let me = Self {
            account: genesis.account,
            device: genesis.device,
            device_name: device_name.to_owned(),
            server: Some(created.server),
            identity,
            state: genesis.state.clone(),
            log: vec![genesis.entry.clone()],
            secrets: BTreeMap::new(),
            rings: BTreeMap::new(),
            folders: None,
            device_names: None,
            records: BTreeMap::new(),
            guard: RecordGuard::new(),
            counter: CommitCounter::resume(0),
            feed_cursor: 0,
            setup_pending: true,
        };
        me.save(store)?;
        Ok(me)
    }

    /// Whether the account exists on the server but [`Account::finish_setup`] has not
    /// completed yet.
    pub fn setup_pending(&self) -> bool {
        self.setup_pending
    }

    /// The second step of a new account, through `server` signed in as this device: the first
    /// epoch and the device names. It reads first what an earlier attempt got through (the log
    /// and the device names record), so it can be repeated after any failure, also after a
    /// restart of the app. Does nothing once the setup is complete.
    pub fn finish_setup(
        &mut self,
        server: &mut dyn ServerApi,
        keychain: &mut dyn Keychain,
        store: &mut dyn Store,
        entropy: &mut dyn Entropy,
        now_ms: u64,
    ) -> Result<(), SyncError> {
        if !self.setup_pending {
            return Ok(());
        }
        self.refresh(server, keychain, store)?;
        if self.state.current_epoch().is_none() {
            self.rotate(server, keychain, &[], now_ms, entropy)?;
        }
        if self.device_names.is_none() {
            self.fetch_record(server, keychain, &device_names_key())?;
        }
        if self.device_names.is_none() {
            let names = DeviceNameList::new(vec![DeviceName {
                device: self.device,
                name: self.device_name.clone(),
            }])?;
            self.put_device_names(server, &names, entropy)?;
        }
        self.setup_pending = false;
        self.save(store)
    }

    /// A device that was just added to the log by another device (pairing, recovery): reads the
    /// log from the server, checks that it lists this device, and fetches its epoch secret.
    ///
    /// Refused with [`SyncError::AlreadySetUp`] before anything is written when this device
    /// already holds an identity or a stored account (security review H1): the join stores its
    /// identity and epoch secrets under the same keychain names, so joining over a set-up device
    /// would replace its identity, and the clean-up of a failed join would delete its secrets.
    /// A failed join removes exactly what it wrote: its identity, the epoch secrets it fetched
    /// and the account it stored.
    #[allow(clippy::too_many_arguments)]
    pub fn join(
        server: &mut dyn ServerApi,
        keychain: &mut dyn Keychain,
        store: &mut dyn Store,
        identity: DeviceIdentity,
        account: AccountId,
        device: DeviceId,
        device_name: &str,
        anchors: &[LogHead],
    ) -> Result<Self, SyncError> {
        if keychain.load(KEY_IDENTITY)?.is_some() || store.account_value(STORE_KEY)?.is_some() {
            return Err(SyncError::AlreadySetUp);
        }
        keychain.store(KEY_IDENTITY, &identity.export())?;
        let mut me = Self {
            account,
            device,
            device_name: device_name.to_owned(),
            server: None,
            identity,
            state: AccountState::new(account),
            log: Vec::new(),
            secrets: BTreeMap::new(),
            rings: BTreeMap::new(),
            folders: None,
            device_names: None,
            records: BTreeMap::new(),
            guard: RecordGuard::new(),
            counter: CommitCounter::resume(0),
            feed_cursor: 0,
            setup_pending: false,
        };
        match me.finish_join(server, keychain, store, anchors) {
            Ok(()) => Ok(me),
            Err(error) => {
                // An aborted join leaves no secret behind (security review L1), and it removes
                // only what it wrote itself (H1): the identity stored above, the epoch secrets
                // its refresh fetched (each is stored before it enters `secrets`) and the
                // account its refresh saved. Nothing of it existed before, as checked above.
                let _ = keychain.delete(KEY_IDENTITY);
                for epoch in me.secrets.keys() {
                    let _ = keychain.delete(&epoch_key_name(Epoch(*epoch)));
                }
                let _ = store.delete_account_value(STORE_KEY);
                Err(error)
            }
        }
    }

    fn finish_join(
        &mut self,
        server: &mut dyn ServerApi,
        keychain: &mut dyn Keychain,
        store: &mut dyn Store,
        anchors: &[LogHead],
    ) -> Result<(), SyncError> {
        self.sync_log(server)?;
        for anchor in anchors {
            self.state.check_anchor(anchor)?;
        }
        let device = self.device;
        if !self
            .state
            .device(&device)
            .is_some_and(|d| d.is_current() && !d.recovery)
        {
            return Err(SyncError::NotSetUp("this device is not in the account log"));
        }
        self.refresh(server, keychain, store)?;
        self.save(store)
    }

    /// The stored account, with its secrets from the keychain; `None` if none is set up.
    pub fn load(store: &dyn Store, keychain: &dyn Keychain) -> Result<Option<Self>, SyncError> {
        let Some(bytes) = store.account_value(STORE_KEY)? else {
            return Ok(None);
        };
        let p: Persisted =
            serde_json::from_slice(&bytes).map_err(|e| SyncError::Corrupt(e.to_string()))?;
        let identity_bytes = keychain
            .load(KEY_IDENTITY)?
            .ok_or(SyncError::NotSetUp("the device identity is missing"))?;
        let identity = DeviceIdentity::import(&identity_bytes)
            .map_err(|_| SyncError::Corrupt("device identity".into()))?;
        let log: Vec<Vec<u8>> = p.log.into_iter().map(|b| b.0).collect();
        let state = AccountState::from_entries(p.account, log.iter().map(Vec::as_slice))?;
        let mut secrets = BTreeMap::new();
        let newest = state.current_epoch().map_or(0, |e| e.epoch.0);
        for epoch in 1..=newest {
            if let Some(secret) = keychain.load(&epoch_key_name(Epoch(epoch)))? {
                if secret.len() == 32 {
                    let mut bytes = Zeroizing::new([0u8; 32]);
                    bytes.copy_from_slice(&secret);
                    secrets.insert(epoch, AccountSecret::from_bytes(bytes));
                }
            }
        }
        let mut me = Self {
            account: p.account,
            device: p.device,
            device_name: p.device_name,
            server: p.server,
            identity,
            state,
            log,
            secrets,
            rings: BTreeMap::new(),
            folders: None,
            device_names: None,
            records: BTreeMap::new(),
            guard: RecordGuard::resume(p.guard.into_iter().map(|(k, v, d)| (k, (v, d))).collect()),
            counter: CommitCounter::resume(p.counter),
            feed_cursor: p.feed_cursor,
            setup_pending: p.setup_pending,
        };
        for record in p.records {
            // Records were verified when they were accepted; a record that no longer opens (its
            // sender was removed since) is dropped and fetched again by the next refresh.
            let _ = me.open_record(&record.key, record.version, &record.data.0, false);
        }
        Ok(Some(me))
    }

    /// Stores the non-secret state.
    pub fn save(&self, store: &mut dyn Store) -> Result<(), SyncError> {
        let p = Persisted {
            account: self.account,
            device: self.device,
            device_name: self.device_name.clone(),
            server: self.server,
            log: self.log.iter().map(|e| Blob(e.clone())).collect(),
            counter: self.counter.last(),
            feed_cursor: self.feed_cursor,
            records: self
                .records
                .iter()
                .map(|(key, (version, data))| StoredRecord {
                    key: *key,
                    version: *version,
                    data: Blob(data.clone()),
                })
                .collect(),
            guard: self
                .guard
                .marks()
                .iter()
                .map(|(k, (v, d))| (*k, *v, *d))
                .collect(),
            setup_pending: self.setup_pending,
        };
        let bytes = serde_json::to_vec(&p).map_err(|e| SyncError::Corrupt(e.to_string()))?;
        store.put_account_value(STORE_KEY, &bytes)?;
        Ok(())
    }

    // -- Accessors --------------------------------------------------------------------------

    /// The account ID.
    pub fn id(&self) -> &AccountId {
        &self.account
    }

    /// This device's ID.
    pub fn device(&self) -> &DeviceId {
        &self.device
    }

    /// The server's ID, once known (account creation, or the pairing offer).
    pub fn server_id(&self) -> Option<ServerId> {
        self.server
    }

    /// Records the server's ID from a verified pairing offer.
    pub fn set_server_id(&mut self, server: ServerId) {
        self.server = Some(server);
    }

    /// This device's name.
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    /// The device identity.
    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    /// The verified device log.
    pub fn state(&self) -> &AccountState {
        &self.state
    }

    /// The newest verified log head.
    pub fn log_head(&self) -> Result<LogHead, SyncError> {
        self.state
            .head()
            .ok_or(SyncError::NotSetUp("the account log is empty"))
    }

    /// The account's folders with their names.
    pub fn folders(&self) -> Vec<FolderEntry> {
        self.folders
            .as_ref()
            .map(|(list, _)| list.folders().to_vec())
            .unwrap_or_default()
    }

    /// Whether this device holds the account's folder list record yet; until then
    /// [`Self::folders`] is empty without meaning that the account has no folders.
    pub fn has_folder_list(&self) -> bool {
        self.folders.is_some()
    }

    /// A device's name from the sealed list.
    pub fn device_display_name(&self, device: &DeviceId) -> Option<String> {
        self.device_names
            .as_ref()
            .and_then(|(list, _)| list.get(device).map(str::to_owned))
    }

    /// The device names list and its version.
    pub fn device_names(&self) -> Option<(&DeviceNameList, u64)> {
        self.device_names.as_ref().map(|(l, v)| (l, *v))
    }

    /// The secret of the current epoch.
    pub fn current_secret(&self) -> Option<&AccountSecret> {
        let epoch = self.state.current_epoch()?.epoch;
        self.secrets.get(&epoch.0)
    }

    /// A folder's opened ring.
    pub fn ring(&self, folder: &FolderId) -> Option<&OpenedRing> {
        self.rings.get(folder)
    }

    /// Every ring with the version this device accepted.
    pub fn rings(&self) -> impl Iterator<Item = (&FolderId, &OpenedRing)> {
        self.rings.iter()
    }

    /// The folder list and its version.
    pub fn folder_list(&self) -> Option<(&FolderList, u64)> {
        self.folders.as_ref().map(|(l, v)| (l, *v))
    }

    /// The newest generation of a folder's ring.
    pub fn newest_generation(&self, folder: &FolderId) -> Option<Generation> {
        self.rings.get(folder).map(|r| r.ring.newest_generation())
    }

    /// The keys to write to `folder`, or why this device may not commit there yet
    /// (`hangar_drive_crypto::folder_keys::writable_generation`).
    pub fn folder_crypto(
        &self,
        folder: &FolderId,
        chain_generation: Option<Generation>,
    ) -> Result<FolderCrypto, SyncError> {
        let ring = self
            .rings
            .get(folder)
            .ok_or(SyncError::NotSetUp("no key ring for the folder"))?;
        let writable = writable_generation(&self.state, ring, chain_generation)?;
        Ok(FolderCrypto::new(&self.account, &ring.ring, writable)?)
    }

    /// The keys to read `folder` (every generation), whatever the freshness rule says.
    pub fn folder_reader(&self, folder: &FolderId) -> Result<FolderCrypto, SyncError> {
        let ring = self
            .rings
            .get(folder)
            .ok_or(SyncError::NotSetUp("no key ring for the folder"))?;
        Ok(FolderCrypto::new(
            &self.account,
            &ring.ring,
            ring.ring.newest_generation(),
        )?)
    }

    /// The next commit counter, stored before the commit is uploaded so a restart never reuses
    /// it.
    pub fn next_counter(&mut self, store: &mut dyn Store) -> Result<u64, SyncError> {
        let n = self
            .counter
            .take()
            .ok_or(SyncError::Invalid("commit counter exhausted"))?;
        self.save(store)?;
        Ok(n)
    }

    /// Signs a commit as this device.
    pub fn sign(&self, commit: Commit) -> Result<SignedCommit, SyncError> {
        Ok(commit.sign(&self.identity)?)
    }

    // -- Refresh ----------------------------------------------------------------------------

    fn sync_log(&mut self, server: &mut dyn ServerApi) -> Result<bool, SyncError> {
        let mut changed = false;
        loop {
            let page = server.log(self.state.len())?;
            // No log is longer than this; a server that claims more is refused before its
            // entries are read (N4, as in `recovery::fetch_log`).
            if page.length > hangar_drive_crypto::devicelog::MAX_LOG_ENTRIES {
                return Err(SyncError::Net(crate::ports::NetError::Protocol(
                    "the log is longer than any log can be".into(),
                )));
            }
            if page.length < self.state.len() {
                // The server's log is behind ours: an older state of the account (re-anchor,
                // step 2, republishes it; ADR 0001, section 4).
                return Ok(changed);
            }
            if page.entries.is_empty() {
                return Ok(changed);
            }
            if page.first_index != self.state.len() + 1 {
                return Err(SyncError::Net(crate::ports::NetError::Protocol(
                    "log page out of order".into(),
                )));
            }
            for entry in &page.entries {
                self.state.apply(entry.as_bytes())?;
                self.log.push(entry.0.clone());
                changed = true;
            }
            if self.state.len() >= page.length {
                return Ok(changed);
            }
        }
    }

    fn ensure_secret(
        &mut self,
        server: &mut dyn ServerApi,
        keychain: &mut dyn Keychain,
        epoch: Epoch,
    ) -> Result<(), SyncError> {
        if self.secrets.contains_key(&epoch.0) {
            return Ok(());
        }
        let record = *self
            .state
            .epoch(epoch)
            .ok_or(SyncError::Invalid("unknown epoch"))?;
        let wrapped = server.epoch_key(epoch)?;
        let secret = epoch::unwrap(
            &self.identity,
            &self.account,
            epoch,
            &self.device,
            wrapped.data.as_bytes(),
            &record.commitment,
        )?;
        keychain.store(&epoch_key_name(epoch), secret.export().as_ref())?;
        self.secrets.insert(epoch.0, secret);
        Ok(())
    }

    /// Opens a record and takes it if the guard accepts it.
    fn open_record(
        &mut self,
        key: &RecordKey,
        version: u64,
        data: &[u8],
        check_guard: bool,
    ) -> Result<bool, SyncError> {
        let header = record_header(data).ok_or(SyncError::Corrupt("record header".into()))?;
        let secret = self
            .secrets
            .get(&header.epoch.0)
            .ok_or(SyncError::NotSetUp("the record's epoch secret is missing"))?;
        let cipher = RecordCipher::for_epoch(&self.state, secret, header.epoch)?;
        let opened = match key.kind {
            RecordKind::FolderKeys => {
                let folder = key
                    .folder
                    .ok_or(SyncError::Invalid("ring without folder"))?;
                let ring = open_ring(&cipher, &self.state, &folder, version, data)?;
                if check_guard {
                    self.guard.accept(&ring.record)?;
                }
                if let Some(old) = self.rings.get(&folder) {
                    if !ring.ring.extends(&old.ring) {
                        return Ok(false);
                    }
                }
                self.rings.insert(folder, ring);
                true
            }
            RecordKind::Folders => {
                let (list, record) = open_folder_list(&cipher, &self.state, version, data)?;
                if check_guard {
                    self.guard.accept(&record)?;
                }
                self.folders = Some((list, version));
                true
            }
            RecordKind::DeviceNames => {
                let (list, record) = open_device_names(&cipher, &self.state, version, data)?;
                if check_guard {
                    self.guard.accept(&record)?;
                }
                self.device_names = Some((list, version));
                true
            }
        };
        if opened {
            self.records.insert(*key, (version, data.to_vec()));
        }
        Ok(opened)
    }

    fn fetch_record(
        &mut self,
        server: &mut dyn ServerApi,
        keychain: &mut dyn Keychain,
        key: &RecordKey,
    ) -> Result<bool, SyncError> {
        let Some(response) = server.record(key)? else {
            return Ok(false);
        };
        if self.guard.accepted(key) == Some(response.version)
            && self.records.get(key).map(|(v, _)| *v) == Some(response.version)
        {
            return Ok(false);
        }
        if let Some(header) = record_header(response.data.as_bytes()) {
            self.ensure_secret(server, keychain, header.epoch)?;
        }
        self.open_record(key, response.version, response.data.as_bytes(), true)
    }

    /// Pulls the change feed and applies it (module docs).
    pub fn refresh(
        &mut self,
        server: &mut dyn ServerApi,
        keychain: &mut dyn Keychain,
        store: &mut dyn Store,
    ) -> Result<Refresh, SyncError> {
        let mut out = Refresh::default();
        let mut records = Vec::new();
        let mut log = self.state.is_empty() || self.feed_cursor == 0;
        let (entries, server_sequence) =
            crate::paging::collect_feed(self.feed_cursor, |after| server.feed(after))?;
        if server_sequence < self.feed_cursor {
            // An older state of the account's feed (security review M2): an older backup of the
            // server, or a cursor a server pushed far ahead (up to `u64::MAX`) to hide every
            // later entry from this device. Taking the larger value would freeze the device for
            // good, so it starts over from 0 and reads the whole account again, verified as
            // always; at cursor 0 this branch cannot be taken again.
            self.feed_cursor = 0;
            let mut again = self.refresh(server, keychain, store)?;
            again.feed_reset = true;
            return Ok(again);
        }
        let mut cursor = self.feed_cursor;
        {
            for entry in &entries {
                match &entry.change {
                    FeedChange::DeviceLog { .. } | FeedChange::Epoch { .. } => log = true,
                    FeedChange::Record { key, .. } => records.push(*key),
                    FeedChange::FolderHead { folder, sequence } => {
                        out.folder_heads.insert(*folder, *sequence);
                    }
                    FeedChange::FolderCreated { .. } | FeedChange::FolderRetired { .. } => {
                        records.push(RecordKey {
                            kind: RecordKind::Folders,
                            folder: None,
                        });
                    }
                    FeedChange::Notice { notice } => out.notices.push(notice.clone()),
                    FeedChange::Unknown => {}
                }
                cursor = cursor.max(entry.sequence);
            }
            // The feed may coalesce entries; its sequence is where this device now stands.
            cursor = cursor.max(server_sequence);
        }
        if log {
            out.log_changed = self.sync_log(server)?;
        }
        if !self
            .state
            .device(&self.device)
            .is_some_and(|d| d.is_current())
        {
            out.removed = true;
            self.feed_cursor = cursor;
            self.save(store)?;
            return Ok(out);
        }
        if let Some(epoch) = self.state.current_epoch().map(|e| e.epoch) {
            self.ensure_secret(server, keychain, epoch)?;
        }
        // At the first refresh every record the account has is fetched.
        if self.feed_cursor == 0 || out.log_changed {
            records.push(RecordKey {
                kind: RecordKind::Folders,
                folder: None,
            });
            records.push(device_names_key());
        }
        records.sort();
        records.dedup();
        for key in &records {
            let changed = self.fetch_record(server, keychain, key)?;
            if changed && key.kind == RecordKind::Folders {
                out.folders_changed = true;
            }
        }
        // Rings of folders the list names but this device has not opened yet.
        let missing: Vec<FolderId> = self
            .folders()
            .iter()
            .map(|f| f.folder)
            .filter(|f| !self.rings.contains_key(f) || out.log_changed)
            .collect();
        for folder in missing {
            let key = RecordKey {
                kind: RecordKind::FolderKeys,
                folder: Some(folder),
            };
            self.fetch_record(server, keychain, &key)?;
        }
        self.feed_cursor = cursor;
        self.save(store)?;
        Ok(out)
    }

    // -- Changes ----------------------------------------------------------------------------

    fn put_record(
        &mut self,
        server: &mut dyn ServerApi,
        key: RecordKey,
        version: u64,
        data: Vec<u8>,
    ) -> Result<(), SyncError> {
        server.put_record(
            &key,
            &RecordPut {
                version,
                data: Blob(data.clone()),
            },
        )?;
        self.open_record(&key, version, &data, true)?;
        Ok(())
    }

    fn cipher(&self) -> Result<RecordCipher, SyncError> {
        let epoch = self
            .state
            .current_epoch()
            .ok_or(SyncError::NotSetUp("no epoch"))?
            .epoch;
        let secret = self
            .secrets
            .get(&epoch.0)
            .ok_or(SyncError::NotSetUp("the epoch secret is missing"))?;
        Ok(RecordCipher::for_epoch(&self.state, secret, epoch)?)
    }

    fn put_device_names(
        &mut self,
        server: &mut dyn ServerApi,
        names: &DeviceNameList,
        entropy: &mut dyn Entropy,
    ) -> Result<(), SyncError> {
        let version = self.device_names.as_ref().map_or(0, |(_, v)| *v) + 1;
        let head = self.log_head()?;
        let data = seal_device_names(
            &self.cipher()?,
            names,
            version,
            &self.identity,
            &self.device,
            &head,
            &mut DynEntropy(entropy),
        )?;
        self.put_record(server, device_names_key(), version, data)
    }

    /// Rotates the epoch, removing `targets` in the same batch (ADR 0001, section 4,
    /// "Atomic"); returns the new secret's epoch.
    pub fn rotate(
        &mut self,
        server: &mut dyn ServerApi,
        keychain: &mut dyn Keychain,
        targets: &[DeviceId],
        now_ms: u64,
        entropy: &mut dyn Entropy,
    ) -> Result<epoch::Removal, SyncError> {
        let removal = epoch::remove_devices(
            &self.state,
            &self.identity,
            self.device,
            now_ms,
            targets,
            &mut DynEntropy(entropy),
        )?;
        server.append_log(&LogAppendRequest {
            entries: removal.entries.iter().map(|e| Blob(e.clone())).collect(),
            wraps: removal
                .rotation
                .wraps
                .iter()
                .map(|(device, data)| WrappedKeyEntry {
                    device: *device,
                    data: Blob(data.clone()),
                })
                .collect(),
            device_wrap: None,
        })?;
        self.state = removal.state.clone();
        self.log.extend(removal.entries.iter().cloned());
        keychain.store(
            &epoch_key_name(removal.rotation.epoch),
            removal.rotation.secret.export().as_ref(),
        )?;
        self.secrets.insert(
            removal.rotation.epoch.0,
            AccountSecret::from_bytes(removal.rotation.secret.export()),
        );
        Ok(removal)
    }

    /// Adds the offline recovery device of a new recovery code, with its wrapped key of the
    /// current epoch; it gets no name (open point A: after a recovery, and for a renewed code).
    pub fn add_recovery_device(
        &mut self,
        server: &mut dyn ServerApi,
        store: &mut dyn Store,
        device: LogDevice,
        now_ms: u64,
        entropy: &mut dyn Entropy,
    ) -> Result<(), SyncError> {
        if !device.recovery {
            return Err(SyncError::Invalid("not a recovery device"));
        }
        self.append_device(server, device, now_ms, entropy)?;
        self.save(store)
    }

    fn append_device(
        &mut self,
        server: &mut dyn ServerApi,
        device: LogDevice,
        now_ms: u64,
        entropy: &mut dyn Entropy,
    ) -> Result<(), SyncError> {
        let addition = epoch::add_device(
            &self.state,
            &self.identity,
            self.device,
            now_ms,
            device,
            self.current_secret(),
            &mut DynEntropy(entropy),
        )?;
        server.append_log(&LogAppendRequest {
            entries: vec![Blob(addition.entry.clone())],
            wraps: Vec::new(),
            device_wrap: addition.wrap.map(|data| WrappedKeyEntry {
                device: device.id,
                data: Blob(data),
            }),
        })?;
        self.state.apply(&addition.entry)?;
        self.log.push(addition.entry);
        Ok(())
    }

    /// Adds a device to the log (the inviting side of pairing), with its wrapped key of the
    /// current epoch, and its name to the device names.
    pub fn add_device(
        &mut self,
        server: &mut dyn ServerApi,
        store: &mut dyn Store,
        device: LogDevice,
        name: &str,
        now_ms: u64,
        entropy: &mut dyn Entropy,
    ) -> Result<(), SyncError> {
        self.append_device(server, device, now_ms, entropy)?;
        let mut names: Vec<DeviceName> = self
            .device_names
            .as_ref()
            .map(|(l, _)| l.names().to_vec())
            .unwrap_or_default();
        names.retain(|n| n.device != device.id);
        names.push(DeviceName {
            device: device.id,
            name: name.to_owned(),
        });
        let list = DeviceNameList::new(names)?;
        self.put_device_names(server, &list, entropy)?;
        self.save(store)
    }

    /// Creates a folder: its key ring with generation 1 and the folder list with it.
    pub fn create_folder(
        &mut self,
        server: &mut dyn ServerApi,
        store: &mut dyn Store,
        folder: FolderId,
        name: &str,
        entropy: &mut dyn Entropy,
    ) -> Result<(), SyncError> {
        let head = self.log_head()?;
        let ring = FolderKeyRing::new(folder, head.index, &mut DynEntropy(entropy))?;
        let cipher = self.cipher()?;
        let data = seal_ring(
            &cipher,
            &ring,
            1,
            &self.identity,
            &self.device,
            &head,
            &mut DynEntropy(entropy),
        )?;
        let key = RecordKey {
            kind: RecordKind::FolderKeys,
            folder: Some(folder),
        };
        self.put_record(server, key, 1, data)?;
        let mut entries = self.folders();
        entries.retain(|f| f.folder != folder);
        entries.push(FolderEntry {
            folder,
            name: name.to_owned(),
        });
        self.put_folder_list(server, FolderList::new(entries)?, entropy)?;
        self.save(store)
    }

    /// Stores a new version of the folder list.
    pub fn put_folder_list(
        &mut self,
        server: &mut dyn ServerApi,
        list: FolderList,
        entropy: &mut dyn Entropy,
    ) -> Result<(), SyncError> {
        let version = self.folders.as_ref().map_or(0, |(_, v)| *v) + 1;
        let head = self.log_head()?;
        let data = seal_folder_list(
            &self.cipher()?,
            &list,
            version,
            &self.identity,
            &self.device,
            &head,
            &mut DynEntropy(entropy),
        )?;
        let key = RecordKey {
            kind: RecordKind::Folders,
            folder: None,
        };
        self.put_record(server, key, version, data)
    }

    /// Re-seals after a removal (N1 step 2): every ring with a new generation, the folder list
    /// and the device names (without the removed devices). Returns whether anything was
    /// written; a record another device re-sealed first ([`RecordVersion`]) is fetched instead.
    ///
    /// [`RecordVersion`]: hangar_drive_protocol::api::ErrorCode::RecordVersion
    pub fn reseal_after_removal(
        &mut self,
        server: &mut dyn ServerApi,
        keychain: &mut dyn Keychain,
        entropy: &mut dyn Entropy,
    ) -> Result<bool, SyncError> {
        let secret = self
            .current_secret()
            .ok_or(SyncError::NotSetUp("the epoch secret is missing"))?;
        let secret = AccountSecret::from_bytes(secret.export());
        let mut rings: Vec<(FolderKeyRing, u64)> = self
            .rings
            .values()
            .map(|r| (r.ring.clone(), r.version))
            .collect();
        let folders = self.folders.clone();
        let names = self.device_names.as_ref().map(|(list, version)| {
            let kept: Vec<DeviceName> = list
                .names()
                .iter()
                .filter(|n| self.state.device(&n.device).is_some_and(|d| d.is_current()))
                .cloned()
                .collect();
            (DeviceNameList::new(kept).unwrap_or_default(), *version)
        });
        let resealed = hangar_drive_crypto::folder_keys::reseal_after_removal(
            &self.state,
            &secret,
            &self.identity,
            &self.device,
            hangar_drive_crypto::folder_keys::AccountRecords {
                rings: &mut rings,
                folders: folders.as_ref().map(|(l, v)| (l, *v)),
                device_names: names.as_ref().map(|(l, v)| (l, *v)),
            },
            &mut DynEntropy(entropy),
        )?;
        let mut wrote = false;
        for record in resealed {
            match self.put_record(server, record.key, record.version, record.data) {
                Ok(()) => wrote = true,
                Err(SyncError::Net(e))
                    if e.code() == Some(hangar_drive_protocol::api::ErrorCode::RecordVersion) =>
                {
                    // Another device of the account completed this step first (N1).
                    self.fetch_record(server, keychain, &record.key)?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(wrote)
    }

    /// Renames a device in the sealed device names.
    pub fn set_device_name(
        &mut self,
        server: &mut dyn ServerApi,
        store: &mut dyn Store,
        device: &DeviceId,
        name: &str,
        entropy: &mut dyn Entropy,
    ) -> Result<(), SyncError> {
        let mut names: Vec<DeviceName> = self
            .device_names
            .as_ref()
            .map(|(l, _)| l.names().to_vec())
            .unwrap_or_default();
        names.retain(|n| n.device != *device);
        names.push(DeviceName {
            device: *device,
            name: name.to_owned(),
        });
        let list = DeviceNameList::new(names)?;
        self.put_device_names(server, &list, entropy)?;
        if *device == self.device {
            self.device_name = name.to_owned();
        }
        self.save(store)
    }

    /// When the entry that added `device` was issued (the issuer's clock), milliseconds.
    pub fn device_added_ms(&self, device: &DeviceId) -> Option<u64> {
        let record = self.state.device(device)?;
        let index = usize::try_from(record.added_at.checked_sub(1)?).ok()?;
        let entry = hangar_drive_crypto::devicelog::LogEntry::decode(self.log.get(index)?).ok()?;
        Some(entry.issued_at_ms)
    }

    /// Whether a removal is not yet followed by the re-seal: some ring's newest generation was
    /// made before the log's last removal (N1: any current device then completes the step).
    pub fn reseal_due(&self) -> bool {
        let removal = self.state.last_removal_index();
        removal > 0
            && !self.state.rotation_due()
            && (self
                .rings
                .values()
                .any(|r| r.ring.newest_created_at() < removal)
                // An account without folders has no ring, yet its device names (and folder
                // list) were sealed before the removal and must move to the new epoch too:
                // otherwise a device added later finds a record under an epoch it never got.
                || self.records.values().any(|(_, data)| {
                    record_header(data).is_some_and(|h| h.head.index < removal)
                }))
    }
}
