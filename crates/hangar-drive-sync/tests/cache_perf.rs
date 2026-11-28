//! The plaintext cache knows what this device uploaded itself: after a large first upload, the
//! next publish works out the parent's reachable set from the cache and downloads none of its
//! own directory nodes and manifests again.

use hangar_drive_protocol::ids::{AccountId, DeviceId, FolderId, InviteToken};
use hangar_drive_sync::account::Account;
use hangar_drive_sync::folder::{Ctx, FolderSettings, FolderSync, RoundReport};
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemKeychain, MemServer, MemStore, SeededRandom,
};

const ACCOUNT: AccountId = AccountId::from_bytes([0xac; 16]);
const FOLDER: FolderId = FolderId::from_bytes([0xf0; 16]);

struct Dev {
    fs: MemFs,
    store: MemStore,
    keys: MemKeychain,
    server: MemServer,
    rng: SeededRandom,
    account: Account,
    folder: FolderSync,
}

fn p(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

fn device() -> Dev {
    let shared = MemServer::new_shared();
    let id = DeviceId::from_bytes([1; 16]);
    let mut server = MemServer::connect(&shared, id);
    let (mut store, mut keys, mut rng) = (
        MemStore::new(),
        MemKeychain::default(),
        SeededRandom::new(1),
    );
    let mut account = Account::create(
        &mut server,
        &mut keys,
        &mut store,
        &mut rng,
        0,
        InviteToken::from_bytes([9; 16]),
        ACCOUNT,
        id,
        "A",
        None,
    )
    .unwrap();
    account
        .create_folder(&mut server, &mut store, FOLDER, "Docs", &mut rng)
        .unwrap();
    account.refresh(&mut server, &mut keys, &mut store).unwrap();
    let folder = FolderSync::new(&account, FOLDER, "Docs");
    let fs = MemFs::new(true);
    folder.write_marker(&fs).unwrap();
    Dev {
        fs,
        store,
        keys,
        server,
        rng,
        account,
        folder,
    }
}

fn round(d: &mut Dev, clock: &ManualClock, settings: &FolderSettings) -> RoundReport {
    d.folder.request_full_scan();
    d.account
        .refresh(&mut d.server, &mut d.keys, &mut d.store)
        .unwrap();
    let mut cx = Ctx {
        account: &mut d.account,
        server: &mut d.server,
        keychain: &mut d.keys,
        fs: &d.fs,
        store: &mut d.store,
        clock,
        entropy: &mut d.rng,
        settings,
    };
    d.folder.round(&mut cx).unwrap()
}

#[test]
fn own_uploads_are_never_downloaded_again() {
    let mut d = device();
    let clock = ManualClock::at(1_795_651_200_000);
    let settings = FolderSettings::default();
    round(&mut d, &clock, &settings);
    for n in 0..40 {
        d.fs.user_mkdir(&p(&[&format!("d{n}")]));
        for f in 0..3 {
            d.fs.user_write(
                &p(&[&format!("d{n}"), &format!("f{f}.txt")]),
                format!("first {n} {f}").as_bytes(),
            );
        }
    }
    assert!(round(&mut d, &clock, &settings).published);
    d.server.state().object_gets.clear();
    for v in 0..3 {
        d.fs.user_write(&p(&["d7", "f1.txt"]), format!("version {v}").as_bytes());
        clock.advance(60_000);
        assert!(round(&mut d, &clock, &settings).published);
    }
    let gets: u64 = d.server.state().object_gets.values().sum();
    assert_eq!(gets, 0, "downloads of objects this device uploaded itself");
}
