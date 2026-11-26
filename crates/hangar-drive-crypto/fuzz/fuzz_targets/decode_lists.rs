//! The folder list and the device names: a decoded list re-encodes to the same bytes.
#![no_main]

use hangar_drive_crypto::device_names::DeviceNameList;
use hangar_drive_crypto::folder_keys::FolderList;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(list) = FolderList::decode(data) {
        assert_eq!(list.encode().expect("a decoded list encodes"), data);
    }
    if let Ok(list) = DeviceNameList::decode(data) {
        assert_eq!(list.encode().expect("a decoded list encodes"), data);
    }
});
