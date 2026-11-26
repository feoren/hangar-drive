//! The push channel (ADR 0001, section 3): one watch per account that carries only the
//! account's newest feed sequence. SSE streams subscribe to it; services notify it after their
//! transaction committed, so a device never pulls a feed that does not hold the change yet.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hangar_drive_protocol::ids::DeviceId;
use tokio::sync::watch;

/// Open SSE streams per device at most (security review LOW 2). A device needs one; the second
/// covers a reconnect while the server has not yet noticed that the old connection died. A
/// further stream of the same device closes that device's oldest one instead of being refused:
/// the newest connection is the one most likely alive, so a half-open connection never keeps an
/// honest device from reconnecting, and a device can only ever close its own streams.
pub const MAX_STREAMS_PER_DEVICE: usize = 2;
/// Open SSE streams per account at most. Still needed beside the device limit, since a
/// compromised device can add devices to the account log, each with its own two streams.
pub const MAX_STREAMS_PER_ACCOUNT: usize = 32;
/// Open SSE streams on the server at most.
pub const MAX_STREAMS: usize = 2048;

/// One registered stream: its ID and the sender whose drop closes it.
type Registered = (u64, watch::Sender<()>);

struct AccountStreams {
    sender: watch::Sender<u64>,
    devices: HashMap<DeviceId, VecDeque<Registered>>,
    count: usize,
}

#[derive(Default)]
pub struct EventHub {
    accounts: Mutex<HashMap<i64, AccountStreams>>,
    open: AtomicUsize,
    next_id: AtomicU64,
}

/// One open stream; dropping it frees its slot. A slot is counted while it is registered: a
/// slot that a newer stream of its device closed no longer counts, even before its stream has
/// noticed.
pub struct StreamSlot {
    hub: Arc<EventHub>,
    account_pk: i64,
    device: DeviceId,
    id: u64,
    pub receiver: watch::Receiver<u64>,
    /// Never sends; its `changed()` fails once the hub closed this stream.
    pub closed: watch::Receiver<()>,
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        let Ok(mut accounts) = self.hub.accounts.lock() else {
            return;
        };
        let Some(entry) = accounts.get_mut(&self.account_pk) else {
            return;
        };
        let Some(streams) = entry.devices.get_mut(&self.device) else {
            return;
        };
        let Some(at) = streams.iter().position(|(id, _)| *id == self.id) else {
            // Closed by a newer stream of the device; already uncounted.
            return;
        };
        streams.remove(at);
        if streams.is_empty() {
            entry.devices.remove(&self.device);
        }
        entry.count = entry.count.saturating_sub(1);
        self.hub.open.fetch_sub(1, Ordering::SeqCst);
        if entry.count == 0 {
            accounts.remove(&self.account_pk);
        }
    }
}

impl EventHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A stream slot for the device, starting at `current`. A device at its limit gets the slot
    /// and its oldest stream is closed; `None` if the account or server limit is reached.
    pub fn subscribe(
        self: &Arc<Self>,
        account_pk: i64,
        device: DeviceId,
        current: u64,
    ) -> Option<StreamSlot> {
        let mut accounts = self.accounts.lock().ok()?;
        let replaces = accounts
            .get(&account_pk)
            .and_then(|entry| entry.devices.get(&device))
            .is_some_and(|streams| streams.len() >= MAX_STREAMS_PER_DEVICE);
        if !replaces {
            if self.open.load(Ordering::SeqCst) >= MAX_STREAMS {
                return None;
            }
            if accounts
                .get(&account_pk)
                .is_some_and(|entry| entry.count >= MAX_STREAMS_PER_ACCOUNT)
            {
                return None;
            }
        }
        let entry = accounts
            .entry(account_pk)
            .or_insert_with(|| AccountStreams {
                sender: watch::channel(current).0,
                devices: HashMap::new(),
                count: 0,
            });
        let streams = entry.devices.entry(device).or_default();
        if replaces {
            // Dropping the sender ends the oldest stream; the new one takes its count.
            streams.pop_front();
        } else {
            entry.count += 1;
            self.open.fetch_add(1, Ordering::SeqCst);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (close, closed) = watch::channel(());
        streams.push_back((id, close));
        entry.sender.send_if_modified(|seq| {
            if current > *seq {
                *seq = current;
                true
            } else {
                false
            }
        });
        let receiver = entry.sender.subscribe();
        Some(StreamSlot {
            hub: self.clone(),
            account_pk,
            device,
            id,
            receiver,
            closed,
        })
    }

    /// The account's feed reached `seq`. Never lowers the value.
    pub fn notify(&self, account_pk: i64, seq: u64) {
        if let Ok(accounts) = self.accounts.lock() {
            if let Some(entry) = accounts.get(&account_pk) {
                entry.sender.send_if_modified(|current| {
                    if seq > *current {
                        *current = seq;
                        true
                    } else {
                        false
                    }
                });
            }
        }
    }

    /// Open streams.
    pub fn open_streams(&self) -> usize {
        self.open.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(n: u8) -> DeviceId {
        DeviceId::from_bytes([n; 16])
    }

    #[tokio::test]
    async fn streams_see_only_rising_sequences_and_free_their_slots() {
        let hub = EventHub::new();
        let mut slot = hub.subscribe(1, device(1), 3).unwrap();
        assert_eq!(*slot.receiver.borrow_and_update(), 3);
        hub.notify(1, 2);
        assert!(!slot.receiver.has_changed().unwrap());
        hub.notify(1, 5);
        slot.receiver.changed().await.unwrap();
        assert_eq!(*slot.receiver.borrow(), 5);
        hub.notify(2, 9);
        assert_eq!(hub.open_streams(), 1);
        drop(slot);
        assert_eq!(hub.open_streams(), 0);
        // The account limit, reached by many devices of one account.
        let slots: Vec<_> = (0..MAX_STREAMS_PER_ACCOUNT)
            .map(|n| hub.subscribe(7, device(n as u8), 0).unwrap())
            .collect();
        assert!(hub.subscribe(7, device(200), 0).is_none());
        assert!(hub.subscribe(8, device(200), 0).is_some());
        drop(slots);
        assert!(hub.subscribe(7, device(200), 0).is_some());
    }

    #[tokio::test]
    async fn a_device_holds_at_most_two_streams_and_a_third_closes_its_oldest() {
        let hub = EventHub::new();
        let mut first = hub.subscribe(1, device(1), 0).unwrap();
        let second = hub.subscribe(1, device(1), 0).unwrap();
        let other = hub.subscribe(1, device(2), 0).unwrap();
        assert_eq!(hub.open_streams(), 3);

        let third = hub.subscribe(1, device(1), 0).unwrap();
        // The oldest stream of the device is told to close, the others stay open.
        assert!(first.closed.changed().await.is_err());
        assert!(second.closed.has_changed().is_ok());
        assert!(third.closed.has_changed().is_ok());
        assert_eq!(hub.open_streams(), 3, "the closed slot no longer counts");
        drop(first);
        assert_eq!(
            hub.open_streams(),
            3,
            "dropping a closed slot frees nothing twice"
        );

        // Hammering never takes more than the device's two slots of the account.
        let mut held = Vec::new();
        for _ in 0..(MAX_STREAMS_PER_ACCOUNT * 2) {
            held.push(hub.subscribe(1, device(1), 0).unwrap());
        }
        assert_eq!(hub.open_streams(), 3);
        assert!(second.closed.has_changed().is_err());
        assert!(third.closed.has_changed().is_err());
        let live = held
            .iter()
            .filter(|s| s.closed.has_changed().is_ok())
            .count();
        assert_eq!(live, MAX_STREAMS_PER_DEVICE);
        // Other devices of the account still get their streams.
        assert!(hub.subscribe(1, device(3), 0).is_some());
        drop(held);
        drop(second);
        drop(third);
        drop(other);
        assert_eq!(hub.open_streams(), 0);
    }
}
