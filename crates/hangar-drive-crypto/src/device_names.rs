//! The names of the account's devices (record kind `device-names`), sealed like every account
//! record, so the server sees only device IDs.
//!
//! # Format (version 1)
//!
//! ```text
//! list = 0x01 || count (u32) || count x ( device id (16) || field(name, UTF-8) ), sorted by device id
//! ```
//!
//! A name is 1 to [`MAX_DEVICE_NAME_LEN`] bytes and passes
//! [`hangar_drive_protocol::name::check_display_name`], the rule of the pairing request's name,
//! so the name a person confirmed in `Add device <name>?` can be stored unchanged. Decoding is
//! strict: re-encoding gives the same bytes. The list may keep names of removed devices, which
//! the history still shows; at most [`MAX_DEVICE_NAMES`] entries.

use hangar_drive_protocol::api::{RecordKey, RecordKind, MAX_DEVICE_NAME_LEN};
use hangar_drive_protocol::ids::{DeviceId, LogHead};
use hangar_drive_protocol::name::check_display_name;

use crate::devicelog::AccountState;
use crate::encoding::{Reader, Writer};
use crate::entropy::Entropy;
use crate::folder_keys::FolderKeysError;
use crate::identity::DeviceIdentity;
use crate::record::{OpenedRecord, RecordCipher};

const LIST_VERSION: u8 = 1;
/// Names one list may hold.
pub const MAX_DEVICE_NAMES: usize = 1024;

/// One device's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceName {
    /// The device.
    pub device: DeviceId,
    /// Its name, shown in the app.
    pub name: String,
}

/// The account's device names (module docs).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceNameList {
    names: Vec<DeviceName>,
}

impl DeviceNameList {
    /// A list of these names in any order.
    pub fn new(mut names: Vec<DeviceName>) -> Result<Self, FolderKeysError> {
        names.sort_by_key(|n| n.device);
        let list = Self { names };
        list.check()?;
        Ok(list)
    }

    fn check(&self) -> Result<(), FolderKeysError> {
        if self.names.len() > MAX_DEVICE_NAMES {
            return Err(FolderKeysError::TooLarge);
        }
        if self.names.windows(2).any(|w| w[0].device >= w[1].device) {
            return Err(FolderKeysError::Unsorted);
        }
        if self
            .names
            .iter()
            .any(|n| check_display_name(&n.name, MAX_DEVICE_NAME_LEN).is_err())
        {
            return Err(FolderKeysError::Name);
        }
        Ok(())
    }

    /// The names, sorted by device ID.
    pub fn names(&self) -> &[DeviceName] {
        &self.names
    }

    /// The name of `device`.
    pub fn get(&self, device: &DeviceId) -> Option<&str> {
        self.names
            .binary_search_by(|n| n.device.cmp(device))
            .ok()
            .and_then(|at| self.names.get(at))
            .map(|n| n.name.as_str())
    }

    /// The list's plaintext.
    pub fn encode(&self) -> Result<Vec<u8>, FolderKeysError> {
        self.check()?;
        let mut w = Writer::new();
        w.u8(LIST_VERSION)
            .u32(u32::try_from(self.names.len()).map_err(|_| FolderKeysError::TooLarge)?);
        for entry in &self.names {
            w.raw(entry.device.as_bytes()).field(entry.name.as_bytes());
        }
        Ok(w.into_bytes())
    }

    /// Reads a list strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self, FolderKeysError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().ok_or(FolderKeysError::Malformed)?;
        if version != LIST_VERSION {
            return Err(FolderKeysError::Version(version));
        }
        let count = usize::try_from(r.u32().ok_or(FolderKeysError::Malformed)?)
            .map_err(|_| FolderKeysError::TooLarge)?;
        if count > MAX_DEVICE_NAMES {
            return Err(FolderKeysError::TooLarge);
        }
        let mut names = Vec::with_capacity(count);
        for _ in 0..count {
            let device = DeviceId::from_bytes(r.raw().ok_or(FolderKeysError::Malformed)?);
            let name = r.field().ok_or(FolderKeysError::Malformed)?;
            let name = std::str::from_utf8(name).map_err(|_| FolderKeysError::Name)?;
            names.push(DeviceName {
                device,
                name: name.to_owned(),
            });
        }
        r.finish().ok_or(FolderKeysError::Malformed)?;
        let list = Self { names };
        list.check()?;
        Ok(list)
    }
}

/// The key of the account's `device-names` record.
pub fn device_names_key() -> RecordKey {
    RecordKey {
        kind: RecordKind::DeviceNames,
        folder: None,
    }
}

/// Seals `list` as `version` of the account's `device-names` record.
#[allow(clippy::too_many_arguments)]
pub fn seal_device_names(
    cipher: &RecordCipher,
    list: &DeviceNameList,
    version: u64,
    identity: &DeviceIdentity,
    sender: &DeviceId,
    head: &LogHead,
    entropy: &mut impl Entropy,
) -> Result<Vec<u8>, FolderKeysError> {
    Ok(cipher.seal(
        &device_names_key(),
        version,
        identity,
        sender,
        head,
        &list.encode()?,
        entropy,
    )?)
}

/// Opens the `device-names` record served as `version`; the record is for the
/// [`crate::record::RecordGuard`].
pub fn open_device_names(
    cipher: &RecordCipher,
    state: &AccountState,
    version: u64,
    data: &[u8],
) -> Result<(DeviceNameList, OpenedRecord), FolderKeysError> {
    let record = cipher.open(state, &device_names_key(), version, data)?;
    let list = DeviceNameList::decode(&record.plaintext)?;
    Ok((list, record))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::OsEntropy;
    use crate::record::tests::setup;
    use hangar_drive_protocol::ids::Epoch;

    fn name(byte: u8, name: &str) -> DeviceName {
        DeviceName {
            device: DeviceId::from_bytes([byte; 16]),
            name: name.into(),
        }
    }

    #[test]
    fn round_trip_rules_and_record() {
        let list = DeviceNameList::new(vec![name(2, "Laptop"), name(1, "Desktop")]).unwrap();
        assert_eq!(list.names()[0], name(1, "Desktop"));
        assert_eq!(list.get(&DeviceId::from_bytes([2; 16])), Some("Laptop"));
        assert_eq!(list.get(&DeviceId::from_bytes([3; 16])), None);
        let bytes = list.encode().unwrap();
        assert_eq!(DeviceNameList::decode(&bytes).unwrap(), list);
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(
            DeviceNameList::decode(&longer),
            Err(FolderKeysError::Malformed)
        );
        assert_eq!(
            DeviceNameList::new(vec![name(1, "a"), name(1, "b")]),
            Err(FolderKeysError::Unsorted)
        );
        for bad in ["", "a\nb", "Lap\u{202e}pot", "a\u{200b}b"] {
            assert_eq!(
                DeviceNameList::new(vec![name(1, bad)]),
                Err(FolderKeysError::Name),
                "{bad:?}"
            );
        }
        let s = setup();
        let cipher = RecordCipher::for_epoch(&s.state, &s.secret, Epoch(1)).unwrap();
        let head = s.state.head().unwrap();
        let data = seal_device_names(
            &cipher,
            &list,
            3,
            &s.a.identity,
            &s.a.id,
            &head,
            &mut OsEntropy,
        )
        .unwrap();
        let (opened, record) = open_device_names(&cipher, &s.state, 3, &data).unwrap();
        assert_eq!(opened, list);
        assert_eq!(record.key, device_names_key());
        assert!(open_device_names(&cipher, &s.state, 2, &data).is_err());
    }
}
