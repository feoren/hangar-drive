//! A fixed account for the targets that need one: a device with epoch 1, built once.

#![allow(dead_code)]

use std::sync::OnceLock;

use hangar_drive_crypto::devicelog::{AccountState, EntryKind, LogDevice};
use hangar_drive_crypto::epoch::{rotate, AccountSecret};
use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_crypto::OsEntropy;
use hangar_drive_protocol::ids::{AccountId, DeviceId, FolderId};

pub const ACCOUNT: AccountId = AccountId::from_bytes([0xac; 16]);
pub const DEVICE: DeviceId = DeviceId::from_bytes([1; 16]);
pub const FOLDER: FolderId = FolderId::from_bytes([3; 16]);

pub struct Fixture {
    pub identity: DeviceIdentity,
    pub state: AccountState,
    pub secret: AccountSecret,
}

pub fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let identity = DeviceIdentity::generate(&mut OsEntropy).expect("os randomness");
        let mut state = AccountState::new(ACCOUNT);
        let create = state
            .next_entry(
                &identity,
                DEVICE,
                0,
                EntryKind::Create {
                    devices: vec![LogDevice::of(&identity, &ACCOUNT, DEVICE, false)],
                },
            )
            .expect("create");
        state.apply(&create).expect("apply");
        let rotation = rotate(&state, &identity, DEVICE, 0, &mut OsEntropy).expect("rotate");
        state.apply(&rotation.entry).expect("apply");
        Fixture {
            identity,
            state,
            secret: rotation.secret,
        }
    })
}
