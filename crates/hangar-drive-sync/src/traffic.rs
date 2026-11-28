//! Network traffic of the server connection, for the window's traffic line.
//!
//! [`crate::http::HttpServer`] adds the payload bytes it sends (request bodies) and reads
//! (response bodies, also of the event stream) to a shared [`TrafficCounter`]: two atomics, so
//! the app shell reads them from its own thread at any time, without asking the engine thread,
//! which may be in the middle of a long round. Only numbers are kept, never contents or paths.
//!
//! [`TrafficMeter`] turns the running totals into rates once per second and keeps the last
//! minute of them for the sparklines.

use std::collections::VecDeque;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;

/// Samples a meter keeps: one minute at one sample per second.
pub const TRAFFIC_HISTORY: usize = 60;
/// Below this rate in bytes per second a direction counts as quiet. The event stream's
/// keep-alive and the feed poll stay below it, so an idle connection never shows a line
/// (`QUIET_RATE` in src/main/traffic.ts).
pub const QUIET_RATE: u64 = 1000;

/// Payload bytes sent to and received from the server since the counter was made.
#[derive(Debug, Default)]
pub struct TrafficCounter {
    sent: AtomicU64,
    received: AtomicU64,
}

impl TrafficCounter {
    /// Counts `bytes` sent.
    pub fn add_sent(&self, bytes: u64) {
        // Relaxed: the totals are independent counters with no ordering to other memory.
        self.sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Counts `bytes` received.
    pub fn add_received(&self, bytes: u64) {
        self.received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Both totals as they are now.
    pub fn totals(&self) -> TrafficTotals {
        TrafficTotals {
            sent: self.sent.load(Ordering::Relaxed),
            received: self.received.load(Ordering::Relaxed),
        }
    }
}

/// Running totals in bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrafficTotals {
    /// Bytes sent.
    pub sent: u64,
    /// Bytes received.
    pub received: u64,
}

/// A reader that counts every byte it reads as received.
pub struct CountingReader<'a, R> {
    inner: R,
    counter: &'a TrafficCounter,
}

impl<'a, R> CountingReader<'a, R> {
    /// Counts what is read from `inner` on `counter`.
    pub fn new(inner: R, counter: &'a TrafficCounter) -> Self {
        Self { inner, counter }
    }
}

impl<R: Read> Read for CountingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.counter.add_received(n as u64);
        Ok(n)
    }
}

/// Bytes per second between two readings of the totals; 0 for no elapsed time. A total that
/// went down (a new counter) counts as no traffic, not as a huge jump.
pub fn rate(before: TrafficTotals, after: TrafficTotals, elapsed: Duration) -> (u64, u64) {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        return (0, 0);
    }
    let per_second = |from: u64, to: u64| (to.saturating_sub(from) as f64 / seconds).round() as u64;
    (
        per_second(before.sent, after.sent),
        per_second(before.received, after.received),
    )
}

/// One reading for the window: the rates of the last second and the totals so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficSample {
    /// Readings taken so far; a gap tells the window that it missed some.
    pub tick: u64,
    /// Bytes per second sent.
    pub up: u64,
    /// Bytes per second received.
    pub down: u64,
    /// Bytes sent since the start.
    pub sent: u64,
    /// Bytes received since the start.
    pub received: u64,
}

/// The last minute for a window that (re)opens: the rates oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficHistory {
    /// The tick of the newest reading (0 before the first).
    pub tick: u64,
    /// Bytes per second sent, oldest first, at most [`TRAFFIC_HISTORY`].
    pub up: Vec<u64>,
    /// Bytes per second received, oldest first, at most [`TRAFFIC_HISTORY`].
    pub down: Vec<u64>,
    /// Bytes sent since the start.
    pub sent: u64,
    /// Bytes received since the start.
    pub received: u64,
}

/// Rates from the running totals, with the last minute of them.
#[derive(Debug)]
pub struct TrafficMeter {
    last: Option<(TrafficTotals, Instant)>,
    rates: VecDeque<(u64, u64)>,
    tick: u64,
}

impl Default for TrafficMeter {
    fn default() -> Self {
        Self {
            last: None,
            rates: VecDeque::with_capacity(TRAFFIC_HISTORY),
            tick: 0,
        }
    }
}

impl TrafficMeter {
    /// Takes a reading of `totals` at `now`. The first reading only sets the baseline and
    /// reports no rate, since a rate needs two readings.
    pub fn sample(&mut self, totals: TrafficTotals, now: Instant) -> TrafficSample {
        let (up, down) = match self.last {
            Some((before, at)) => rate(before, totals, now.saturating_duration_since(at)),
            None => (0, 0),
        };
        self.last = Some((totals, now));
        if self.rates.len() == TRAFFIC_HISTORY {
            self.rates.pop_front();
        }
        self.rates.push_back((up, down));
        self.tick += 1;
        TrafficSample {
            tick: self.tick,
            up,
            down,
            sent: totals.sent,
            received: totals.received,
        }
    }

    /// Whether the last minute had traffic above [`QUIET_RATE`] in either direction; the window
    /// shows its line only then.
    pub fn active(&self) -> bool {
        self.rates
            .iter()
            .any(|&(up, down)| up >= QUIET_RATE || down >= QUIET_RATE)
    }

    /// The last minute, for a window that missed readings.
    pub fn history(&self) -> TrafficHistory {
        let totals = self.last.map(|(totals, _)| totals).unwrap_or_default();
        TrafficHistory {
            tick: self.tick,
            up: self.rates.iter().map(|&(up, _)| up).collect(),
            down: self.rates.iter().map(|&(_, down)| down).collect(),
            sent: totals.sent,
            received: totals.received,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counter_adds_up_from_several_threads() {
        let counter = std::sync::Arc::new(TrafficCounter::default());
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let counter = std::sync::Arc::clone(&counter);
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        counter.add_sent(3);
                        counter.add_received(5);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(
            counter.totals(),
            TrafficTotals {
                sent: 12_000,
                received: 20_000
            }
        );
    }

    #[test]
    fn the_counting_reader_counts_what_it_reads() {
        let counter = TrafficCounter::default();
        let mut out = Vec::new();
        CountingReader::new(&b"hello world"[..], &counter)
            .take(5)
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"hello");
        assert_eq!(counter.totals().received, 5);
        assert_eq!(counter.totals().sent, 0);
    }

    #[test]
    fn rates_are_bytes_per_second_of_the_elapsed_time() {
        let before = TrafficTotals {
            sent: 1000,
            received: 0,
        };
        let after = TrafficTotals {
            sent: 6000,
            received: 3000,
        };
        assert_eq!(rate(before, after, Duration::from_secs(1)), (5000, 3000));
        assert_eq!(
            rate(before, after, Duration::from_millis(500)),
            (10_000, 6000)
        );
        assert_eq!(rate(before, after, Duration::ZERO), (0, 0));
        // A counter that went back is no traffic.
        assert_eq!(rate(after, before, Duration::from_secs(1)), (0, 0));
    }

    #[test]
    fn the_meter_keeps_one_minute_and_knows_when_it_is_quiet() {
        let counter = TrafficCounter::default();
        let mut meter = TrafficMeter::default();
        let start = Instant::now();
        let first = meter.sample(counter.totals(), start);
        assert_eq!((first.tick, first.up, first.down), (1, 0, 0));
        assert!(!meter.active());

        counter.add_sent(2_000_000);
        counter.add_received(500);
        let second = meter.sample(counter.totals(), start + Duration::from_secs(1));
        assert_eq!(
            second,
            TrafficSample {
                tick: 2,
                up: 2_000_000,
                down: 500,
                sent: 2_000_000,
                received: 500
            }
        );
        assert!(meter.active());

        // A minute of silence pushes the burst out of the history.
        for second in 2..=61 {
            meter.sample(counter.totals(), start + Duration::from_secs(second));
        }
        let history = meter.history();
        assert_eq!(history.tick, 62);
        assert_eq!(history.up.len(), TRAFFIC_HISTORY);
        assert!(history.up.iter().all(|&up| up == 0));
        assert_eq!((history.sent, history.received), (2_000_000, 500));
        assert!(!meter.active());

        // Keep-alive sized traffic stays quiet.
        counter.add_received(QUIET_RATE - 1);
        meter.sample(counter.totals(), start + Duration::from_secs(62));
        assert!(!meter.active());
    }
}
