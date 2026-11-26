//! The push channel (ADR 0001, section 3): one watch per account that carries only the
//! account's newest feed sequence. SSE streams subscribe to it; services notify it after their
//! transaction committed, so a device never pulls a feed that does not hold the change yet.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

/// Open SSE streams per account at most (devices of one person; a few each).
pub const MAX_STREAMS_PER_ACCOUNT: usize = 32;
/// Open SSE streams on the server at most.
pub const MAX_STREAMS: usize = 2048;

#[derive(Default)]
pub struct EventHub {
    accounts: Mutex<HashMap<i64, (watch::Sender<u64>, usize)>>,
    open: Arc<AtomicUsize>,
}

/// One open stream; dropping it frees its slot.
pub struct StreamSlot {
    hub_open: Arc<AtomicUsize>,
    hub: Arc<EventHub>,
    account_pk: i64,
    pub receiver: watch::Receiver<u64>,
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        self.hub_open.fetch_sub(1, Ordering::SeqCst);
        if let Ok(mut accounts) = self.hub.accounts.lock() {
            if let Some(entry) = accounts.get_mut(&self.account_pk) {
                entry.1 = entry.1.saturating_sub(1);
                if entry.1 == 0 {
                    accounts.remove(&self.account_pk);
                }
            }
        }
    }
}

impl EventHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A stream slot for the account, starting at `current`; `None` if a limit is reached.
    pub fn subscribe(self: &Arc<Self>, account_pk: i64, current: u64) -> Option<StreamSlot> {
        let mut accounts = self.accounts.lock().ok()?;
        if self.open.load(Ordering::SeqCst) >= MAX_STREAMS {
            return None;
        }
        let entry = accounts
            .entry(account_pk)
            .or_insert_with(|| (watch::channel(current).0, 0));
        if entry.1 >= MAX_STREAMS_PER_ACCOUNT {
            return None;
        }
        entry.1 += 1;
        entry.0.send_if_modified(|seq| {
            if current > *seq {
                *seq = current;
                true
            } else {
                false
            }
        });
        let receiver = entry.0.subscribe();
        self.open.fetch_add(1, Ordering::SeqCst);
        Some(StreamSlot {
            hub_open: self.open.clone(),
            hub: self.clone(),
            account_pk,
            receiver,
        })
    }

    /// The account's feed reached `seq`. Never lowers the value.
    pub fn notify(&self, account_pk: i64, seq: u64) {
        if let Ok(accounts) = self.accounts.lock() {
            if let Some((sender, _)) = accounts.get(&account_pk) {
                sender.send_if_modified(|current| {
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

    #[tokio::test]
    async fn streams_see_only_rising_sequences_and_free_their_slots() {
        let hub = EventHub::new();
        let mut slot = hub.subscribe(1, 3).unwrap();
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
        let slots: Vec<_> = (0..MAX_STREAMS_PER_ACCOUNT)
            .map(|_| hub.subscribe(7, 0).unwrap())
            .collect();
        assert!(hub.subscribe(7, 0).is_none());
        assert!(hub.subscribe(8, 0).is_some());
        drop(slots);
        assert!(hub.subscribe(7, 0).is_some());
    }
}
