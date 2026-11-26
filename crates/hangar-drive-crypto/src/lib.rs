//! End-to-end cryptography of Hangar Drive (ADR 0001, section 4), on top of the IDs, framing
//! and plaintext formats of `hangar-drive-protocol`.
//!
//! - [`identity`]: a device's Ed25519 and X25519 keys, their keychain format, proofs of
//!   possession, safety numbers (device, log, folder) and the server key number.
//! - [`devicelog`]: the account's signed, hash-chained device log with one member and its
//!   verifier [`devicelog::AccountState`], which clients and the server share.
//! - [`epoch`]: the random secret per epoch, its commitment in the log, HPKE wrapping to every
//!   device, the account seal key and the rotation after every removal.
//! - [`record`]: sealed, signed account records with a version per record and the replay
//!   guard.
//! - [`folder_keys`]: folder key rings with generations bound to the log, the freshness rule
//!   before committing, the re-seal after a removal,
//!   and the folder list.
//! - [`device_names`]: the sealed list of device names.
//! - [`object`]: chunks, file manifests and directory nodes: keyed IDs, Padmé, XChaCha20-Poly1305
//!   and the recomputed ID as key commitment.
//! - [`commit`]: signed commits, the verified first-parent chain with the frontier check (fail
//!   closed), side commit rules, nothing going back, per-device counters, the empty seen vector,
//!   the re-anchor mark and the re-anchor itself.
//! - [`recovery`]: the 128-bit recovery code and the offline recovery device it derives.
//! - [`pairing`]: the pairing offer, the request tag (HMAC) and the new device's log check.
//! - [`session`]: the device sign-in proof the server checks.
//!
//! Pure: no I/O, no clock, no keychain, no network. Randomness comes in through [`Entropy`]
//! ([`OsEntropy`] in the app). Secrets are wiped on drop and never shown by `Debug`; secret
//! comparisons run in constant time. Every label starts with `hangar-drive/v1/`, so no key or
//! signature of the sister product is valid here.
//!
//! The primitives and crate versions are those of the sister project's `hangar-team-crypto`;
//! several modules are built after its code (noted per module). This is a hand-built protocol
//! from standard parts: an external cryptographic review is a release blocker (ADR 0001,
//! Consequences). Fixed test vectors are in `testdata/vectors.json`, recomputed independently
//! by `test_vectors.py`.

#![warn(missing_docs)]

pub mod commit;
pub mod device_names;
pub mod devicelog;
mod encoding;
pub mod entropy;
pub mod epoch;
pub mod folder_keys;
pub mod identity;
pub mod object;
pub mod pairing;
pub mod record;
pub mod recovery;
pub mod session;

#[cfg(test)]
mod vectors;

pub use entropy::{Entropy, EntropyError, OsEntropy};
