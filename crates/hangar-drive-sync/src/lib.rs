//! The sync engine of Hangar Drive (ADR 0001, sections 3 to 5 and 7), after Dropbox Nucleus:
//! three trees with stable item IDs, moves as their own operations, one deterministic control
//! loop with every effect behind a trait, and a seeded simulation of several devices and a
//! server (`tests/simulation.rs`).
//!
//! # Layers
//!
//! | Layer | Modules |
//! | --- | --- |
//! | Pure core | [`tree`] (the three trees), [`merge`] (ADR 3 merge and the join), [`names`] (conflict and restore labels, N6), [`planner`] (one round), [`apply`] (the disk in a working order) |
//! | Folder loop | [`folder`] (scan, pull and verify, merge, publish with compare-and-swap and side commit, apply, re-anchor, restore, barrier) |
//! | Account | [`account`] (log, epochs, rings, records, counter), [`removal`] (removal as a resumable job, N1, N2 and H1), [`recovery`] (the recovery device's one append) |
//! | Rules | [`paging`] (every paged list, M1), [`roots`] (which folders may be sync roots, M4), [`links`] (invite, pairing and recovery links) |
//! | Objects | [`codec`] (trees to objects and back), [`chunker`] (4 MiB chunks, parallel hashing with backpressure) |
//! | Ports | [`ports`] (file system, server API, store, clock, randomness, keychain) |
//! | Real ports | [`localfs`] (`\\?\` paths, name checks, directories on the way, atomic writes without replacing, locked files, 8.3), [`trash`] (recycle bin and quarantine for incoming deletes), [`watch`] (`notify` 9), [`index`] (SQLite), [`http`] (reqwest, rustls, SPKI pin, SSE) |
//! | Test ports | [`memory`] |
//! | App API | [`engine`] (thread, commands, events), [`api`] (the window's types), [`error`] |
//!
//! # The app's contract
//!
//! The window's `Backend` (`src/backend/types.ts`) calls Tauri commands in snake case; each
//! maps onto one [`engine::EngineCore`] method run through [`engine::EngineHandle::call`], and
//! every event is an [`api::BackendEvent`].
//!
//! | `Backend` method | Engine |
//! | --- | --- |
//! | `getSnapshot`, `subscribe` | `snapshot`, the event receiver of `Engine::spawn` |
//! | `checkInvite`, `beginAccount`, `confirmRecoveryGroup` | same names |
//! | `startPairing`, `cancelPairing` | same names; the outcome arrives as `pairResult` |
//! | `listAccountFolders`, `joinFolders`, `addAccountFolder` | `snapshot().remote_folders`, `add_account_folder` |
//! | `finishSetup`, `addFolder` | `add_folder` |
//! | `recoverAccount`, `recoveryDevices`, `finishRecoveryCleanup` | same names; `recover_account` takes the sheet's link (`hangar-drive://recover#...`), the code and the device name |
//! | `acceptRemovedHeads` | `accept_removed_heads`, after the `removedHeads` event or warning |
//! | `pause`, `resume`, `pauseFolder`, `resumeFolder` | `pause`, `resume`, `set_folder_paused` |
//! | `stopFolder`, `deleteFolderEverywhere` | same names |
//! | `listNotSynced`, `getFolderNumber` | same names |
//! | `listMassDelete`, `resolveMassDelete` | same names (folder ID from the warning) |
//! | `findMissingFolder` | the app's folder picker, then `relocate_folder` |
//! | `checkOlderState`, `reanchor` | same names |
//! | `dismissSuspect` | `dismiss_warning` |
//! | `listConflicts`, `keepConflictVersion`, `keepBothConflict` | same names |
//! | `listNameIssues`, `renameNameIssue`, `ignoreNameIssue` | same names |
//! | `getTimeline`, `getTreeAt`, `restoreFile`, `resetFolder`, `findBeforeDevice`, `getTrash`, `restoreTrash` | same names |
//! | `listDevices`, `renameDevice`, `setDeviceName`, `getSafetyNumber`, `removeDevice` | `list_devices`, `rename_device`, `get_safety_number`, `remove_device` |
//! | `createPairingOffer`, `answerPairRequest` | same names; requests arrive as `pairRequest` |
//! | clipboard, camera, printing, saving files, file dialogs, tray, window, autostart, language, updates, error report, QR drawing | the app shell, not the engine |

#![warn(missing_docs)]

pub mod account;
pub mod api;
pub mod apply;
pub mod chunker;
pub mod codec;
pub mod engine;
pub mod error;
pub mod folder;
pub mod http;
pub mod index;
pub mod links;
pub mod localfs;
// Test doubles for the tests and the seeded simulation; never part of a release build.
#[cfg(any(test, feature = "test-support"))]
pub mod memory;
pub mod merge;
pub mod names;
pub mod paging;
pub mod planner;
pub mod ports;
pub mod recovery;
pub mod removal;
pub mod roots;
pub mod trash;
pub mod tree;
pub mod watch;
