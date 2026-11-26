//! Identifiers and fixed-size byte values of the protocol.
//!
//! | Type | Bytes | Chosen by | JSON |
//! | --- | --- | --- | --- |
//! | [`AccountId`], [`DeviceId`], [`FolderId`] | 16 | the client, at random; the server refuses duplicates | lowercase hex |
//! | [`ItemId`] | 16 | the device that first adds a file or directory, at random | lowercase hex |
//! | [`ServerId`] | 16 | the server at its first start | lowercase hex |
//! | [`PairingId`] | 16 | derived from the pairing secret | lowercase hex |
//! | [`ObjectId`] | 32 | keyed hash of the object's plaintext | lowercase hex |
//! | [`CommitId`], [`LogHash`] | 32 | SHA-256 of the signed body or log entry | lowercase hex |
//! | [`PublicKey`], [`Challenge`] | 32 | | base64url without padding |
//! | [`Signature`] | 64 | | base64url without padding |
//! | [`SessionToken`] | 32 | the server | base64url without padding |
//! | [`InviteToken`] | 16 | the server CLI | base64url without padding |
//!
//! Every text form has exactly one spelling: hex is lowercase only, base64url has no padding
//! and no set unused bits, so a value can be compared by its text.

use std::fmt;
use std::str::FromStr;

use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// A text that is not the canonical spelling of the expected value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("not a valid {what}")]
pub struct InvalidValue {
    /// What was expected.
    pub what: &'static str,
}

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    HEXLOWER.encode(bytes)
}

/// Bytes of canonical (lowercase) hex.
pub(crate) fn from_hex(text: &str) -> Option<Vec<u8>> {
    HEXLOWER.decode(text.as_bytes()).ok()
}

/// Base64url without padding.
pub fn base64url(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

/// Bytes of canonical base64url without padding; `None` for any other spelling.
pub fn from_base64url(text: &str) -> Option<Vec<u8>> {
    BASE64URL_NOPAD.decode(text.as_bytes()).ok()
}

macro_rules! hex_id {
    ($(#[$meta:meta])* $name:ident, $len:expr, $what:expr) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Bytes of this identifier.
            pub const LEN: usize = $len;

            /// The identifier with these bytes.
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// The identifier's bytes.
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// The identifier of a slice of exactly [`Self::LEN`] bytes.
            pub fn from_slice(bytes: &[u8]) -> Option<Self> {
                Some(Self(bytes.try_into().ok()?))
            }

            /// Lowercase hex, the spelling on the wire and in paths.
            pub fn to_hex(&self) -> String {
                hex(&self.0)
            }

            /// Reads lowercase hex of exactly [`Self::LEN`] bytes.
            pub fn from_hex(text: &str) -> Result<Self, InvalidValue> {
                from_hex(text)
                    .and_then(|bytes| Self::from_slice(&bytes))
                    .ok_or(InvalidValue { what: $what })
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl FromStr for $name {
            type Err = InvalidValue;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::from_hex(text)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
                Self::from_hex(&text).map_err(serde::de::Error::custom)
            }
        }
    };
}

hex_id!(
    /// An account: one person's devices and folders on one server.
    AccountId,
    16,
    "account id"
);
hex_id!(
    /// A device of an account (also the offline recovery device).
    DeviceId,
    16,
    "device id"
);
hex_id!(
    /// A synced folder of an account.
    FolderId,
    16,
    "folder id"
);
hex_id!(
    /// A file or directory inside a folder, stable across renames and moves; the merge matches
    /// items by it.
    ItemId,
    16,
    "item id"
);
hex_id!(
    /// A server, made at its first start; a session proof is valid for one server only.
    ServerId,
    16,
    "server id"
);
hex_id!(
    /// Where the server routes a pairing request, derived from the pairing secret.
    PairingId,
    16,
    "pairing id"
);
hex_id!(
    /// An encrypted object (chunk, file manifest, directory node): the keyed hash of its
    /// plaintext, so equal content in one folder and key generation has one ID.
    ObjectId,
    32,
    "object id"
);
hex_id!(
    /// A signed commit: SHA-256 of its body.
    CommitId,
    32,
    "commit id"
);
hex_id!(
    /// The hash of a device log entry, chained over its predecessor.
    LogHash,
    32,
    "log hash"
);

macro_rules! b64_value {
    ($(#[$meta:meta])* $name:ident, $len:expr, $what:expr) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Bytes of this value.
            pub const LEN: usize = $len;

            /// The value with these bytes.
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// The value's bytes.
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// The value of a slice of exactly [`Self::LEN`] bytes.
            pub fn from_slice(bytes: &[u8]) -> Option<Self> {
                Some(Self(bytes.try_into().ok()?))
            }

            /// Base64url without padding.
            pub fn to_base64url(&self) -> String {
                base64url(&self.0)
            }

            /// Reads canonical base64url of exactly [`Self::LEN`] bytes.
            pub fn from_base64url(text: &str) -> Result<Self, InvalidValue> {
                from_base64url(text)
                    .and_then(|bytes| Self::from_slice(&bytes))
                    .ok_or(InvalidValue { what: $what })
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_base64url())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_base64url())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
                Self::from_base64url(&text).map_err(serde::de::Error::custom)
            }
        }
    };
}

b64_value!(
    /// An Ed25519 or X25519 public key.
    PublicKey,
    32,
    "public key"
);
b64_value!(
    /// An Ed25519 signature.
    Signature,
    64,
    "signature"
);
b64_value!(
    /// A fresh random value the server hands out for one session proof.
    Challenge,
    32,
    "challenge"
);

macro_rules! secret_token {
    ($(#[$meta:meta])* $name:ident, $len:expr, $what:expr) => {
        $(#[$meta])*
        ///
        /// `Debug` never shows the value, and there is no `Display` or `PartialEq`: the server
        /// compares only the SHA-256 of a token, in its storage. The value is wiped on drop, and
        /// so are the text form [`Self::expose_base64url`] returns and the bytes decoded in
        /// between. What serde reads from or writes to (the HTTP body, the JSON buffer of the
        /// app or the server) lies outside this type: the caller keeps that buffer short-lived
        /// and wipes it where it can.
        #[derive(Clone)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Bytes of a token.
            pub const LEN: usize = $len;

            /// The token with these bytes.
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// The token's bytes, for hashing or the `Authorization` header only.
            pub fn expose(&self) -> &[u8; $len] {
                &self.0
            }

            /// Base64url without padding, for the `Authorization` header or the CLI output.
            pub fn expose_base64url(&self) -> Zeroizing<String> {
                Zeroizing::new(base64url(&self.0))
            }

            /// Reads canonical base64url of exactly [`Self::LEN`] bytes.
            pub fn from_base64url(text: &str) -> Result<Self, InvalidValue> {
                let bytes = Zeroizing::new(from_base64url(text).ok_or(InvalidValue { what: $what })?);
                <[u8; $len]>::try_from(bytes.as_slice())
                    .map(Self)
                    .map_err(|_| InvalidValue { what: $what })
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.expose_base64url().as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
                Self::from_base64url(&text).map_err(serde::de::Error::custom)
            }
        }
    };
}

secret_token!(
    /// A session's bearer token (256 random bits), sent only in the `Authorization` header.
    SessionToken,
    32,
    "session token"
);
secret_token!(
    /// A single-use, expiring account invite (128 random bits) the operator creates.
    InviteToken,
    16,
    "invite token"
);

/// An account key epoch, counted from 1 without gaps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Epoch(pub u32);

/// A folder key generation, counted from 1 without gaps per folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Generation(pub u32);

/// A position in the account's device log: the number of entries (index of the last one,
/// counted from 1) and the hash of that entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LogHead {
    /// Index of the entry, from 1.
    pub index: u64,
    /// Hash of the entry.
    pub hash: LogHash,
}

/// Bytes of variable length on the wire (log entries, commits, records, wrapped keys), as
/// base64url without padding. The server's request body limit bounds them before decoding;
/// each format checks its own limits after.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Blob(pub Vec<u8>);

impl Blob {
    /// The bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Characters of the base64url form of `len` bytes.
    pub fn encoded_len(len: usize) -> usize {
        BASE64URL_NOPAD.encode_len(len)
    }
}

impl From<Vec<u8>> for Blob {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blob({} bytes)", self.0.len())
    }
}

impl Serialize for Blob {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64url(&self.0))
    }
}

impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        from_base64url(&text)
            .map(Blob)
            .ok_or_else(|| serde::de::Error::custom(InvalidValue { what: "base64url" }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_ids_have_one_spelling() {
        let id = FolderId::from_bytes([0xab; 16]);
        assert_eq!(id.to_hex(), "ab".repeat(16));
        assert_eq!(FolderId::from_hex(&"ab".repeat(16)), Ok(id));
        assert!(FolderId::from_hex(&"AB".repeat(16)).is_err());
        assert!(FolderId::from_hex(&"ab".repeat(15)).is_err());
        assert!(FolderId::from_hex(&"ab".repeat(17)).is_err());
        assert!(FolderId::from_hex("zz").is_err());
        assert_eq!(format!("{id:?}"), format!("FolderId({})", "ab".repeat(16)));
        assert_eq!(id.to_string().parse::<FolderId>(), Ok(id));
    }

    #[test]
    fn ids_serialize_as_hex_strings() {
        let id = ObjectId::from_bytes([1; 32]);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", "01".repeat(32)));
        assert_eq!(serde_json::from_str::<ObjectId>(&json).unwrap(), id);
        assert!(serde_json::from_str::<ObjectId>("\"01\"").is_err());
        assert!(serde_json::from_str::<ObjectId>("5").is_err());
    }

    #[test]
    fn base64_values_are_canonical() {
        let key = PublicKey::from_bytes([0xff; 32]);
        let text = key.to_base64url();
        assert_eq!(PublicKey::from_base64url(&text), Ok(key));
        assert!(PublicKey::from_base64url(&format!("{text}=")).is_err());
        // Non-zero unused trailing bits: a second spelling of the same bytes.
        assert_eq!(from_base64url("_w"), Some(vec![0xff]));
        assert_eq!(from_base64url("_x"), None);
        assert!(Signature::from_base64url(&text).is_err());
    }

    #[test]
    fn tokens_never_show_their_value() {
        let token = SessionToken::from_bytes([7; 32]);
        assert_eq!(format!("{token:?}"), "SessionToken(..)");
        let invite = InviteToken::from_bytes([7; 16]);
        assert_eq!(format!("{invite:?}"), "InviteToken(..)");
        let json = serde_json::to_string(&token).unwrap();
        let back: SessionToken = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expose(), token.expose());
        let text: Zeroizing<String> = token.expose_base64url();
        assert_eq!(
            SessionToken::from_base64url(&text).unwrap().expose(),
            &[7; 32]
        );
        assert!(
            SessionToken::from_base64url("AQID").is_err(),
            "wrong length"
        );
        assert!(SessionToken::from_base64url("not base64!").is_err());
    }

    #[test]
    fn blobs_round_trip_and_hide_content() {
        let blob = Blob(vec![1, 2, 3]);
        let json = serde_json::to_string(&blob).unwrap();
        assert_eq!(json, "\"AQID\"");
        assert_eq!(serde_json::from_str::<Blob>(&json).unwrap(), blob);
        assert_eq!(format!("{blob:?}"), "Blob(3 bytes)");
        assert!(serde_json::from_str::<Blob>("\"AQID=\"").is_err());
        assert_eq!(Blob::encoded_len(3), 4);
    }

    #[test]
    fn log_head_and_counters_serialize_plainly() {
        let head = LogHead {
            index: 3,
            hash: LogHash::from_bytes([0; 32]),
        };
        let json = serde_json::to_value(head).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "index": 3, "hash": "00".repeat(32) })
        );
        assert_eq!(serde_json::to_string(&Epoch(4)).unwrap(), "4");
        assert_eq!(serde_json::to_string(&Generation(2)).unwrap(), "2");
    }
}
