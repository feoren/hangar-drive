//! Reading a paged list from the server (security review M1): the folder delta of a pull, a
//! re-anchor and the removal job, and the account's change feed all go through
//! [`collect_pages`], so a server cannot keep a device in a loop or make it hold an unbounded
//! list.
//!
//! The rules, checked on every page before it is kept:
//!
//! - every item's sequence is above the cursor the page was asked for, and the sequences rise
//!   within the page (strictly; a delta page may repeat a sequence for the side commit and the
//!   head of one call, [`Order::CallPairs`]);
//! - a page holds at most [`Limits::per_page`] items, and all pages together at most
//!   [`Limits::total`];
//! - a page that says `more` must hold at least one item, so every further request moves the
//!   cursor; `more` with an empty page is a protocol error;
//! - the server's sequence is not below the last item's.
//!
//! Every violation is [`NetError::Protocol`]: the answer does not follow the protocol, nothing
//! of it is used.

use hangar_drive_protocol::api::{DeltaCommit, DeltaPage, FeedEntry, FeedPage};

use crate::ports::NetError;

/// How sequences may follow each other within a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// Every item has its own, higher sequence (the feed).
    Strict,
    /// Items rise, and one call's side commit and head share a sequence (the folder delta).
    CallPairs,
}

/// Size limits of a paged list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Items one page may hold.
    pub per_page: usize,
    /// Items all pages together may hold.
    pub total: usize,
}

/// Most commits of one folder delta read as a whole list ([`collect_delta`]), about 1 KiB each
/// in memory. Only the re-anchor still reads its delta so (ADR 0001, amendment "delta pages
/// in the engine"); a pull and the removal job check the delta page by page and are bounded by
/// `folder::MAX_PULL_COMMITS` instead.
pub const MAX_DELTA_TOTAL: usize = 200_000;
/// Most feed entries one refresh reads.
pub const MAX_FEED_TOTAL: usize = 200_000;

/// The limits of a folder delta: a page holds at most [`hangar_drive_protocol::api::MAX_DELTA_PAGE`]
/// calls, each a head and at most one side commit.
pub const DELTA_LIMITS: Limits = Limits {
    per_page: 2 * hangar_drive_protocol::api::MAX_DELTA_PAGE,
    total: MAX_DELTA_TOTAL,
};

/// The limits of the change feed.
pub const FEED_LIMITS: Limits = Limits {
    per_page: hangar_drive_protocol::api::MAX_FEED_PAGE,
    total: MAX_FEED_TOTAL,
};

/// One page as the helper sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    /// The items.
    pub items: Vec<T>,
    /// The server has more after the last item.
    pub more: bool,
    /// The server's sequence when it answered.
    pub sequence: u64,
}

impl From<DeltaPage> for Page<DeltaCommit> {
    fn from(p: DeltaPage) -> Self {
        Self {
            items: p.commits,
            more: p.more,
            sequence: p.sequence,
        }
    }
}

impl From<FeedPage> for Page<FeedEntry> {
    fn from(p: FeedPage) -> Self {
        Self {
            items: p.entries,
            more: p.more,
            sequence: p.sequence,
        }
    }
}

fn protocol(what: &str) -> NetError {
    NetError::Protocol(format!("paging: {what}"))
}

/// Reads every page after `after` (module docs). `fetch` asks for the page after a cursor;
/// `sequence` reads an item's sequence. Returns the items in order and the server's sequence of
/// the last page.
pub fn collect_pages<T>(
    after: u64,
    limits: Limits,
    order: Order,
    sequence: impl Fn(&T) -> u64,
    mut fetch: impl FnMut(u64) -> Result<Page<T>, NetError>,
) -> Result<(Vec<T>, u64), NetError> {
    let mut out: Vec<T> = Vec::new();
    let mut cursor = after;
    loop {
        let page = fetch(cursor)?;
        if out.len().saturating_add(page.items.len()) > limits.total {
            return Err(protocol("the list is longer than this device reads"));
        }
        let last = check_page(cursor, &page, limits.per_page, order, &sequence)?;
        out.extend(page.items);
        if !page.more {
            return Ok((out, page.sequence));
        }
        cursor = last;
    }
}

/// Checks one page asked for after `cursor` by the rules of the module docs (all but the total,
/// which a caller that keeps no list bounds itself) and returns the cursor for the next page:
/// the last item's sequence. A page that says `more` holds at least one item, so every further
/// request moves the cursor, and the items rise above it: a server can only page forward, over
/// items it really has.
pub fn check_page<T>(
    cursor: u64,
    page: &Page<T>,
    per_page: usize,
    order: Order,
    sequence: impl Fn(&T) -> u64,
) -> Result<u64, NetError> {
    if page.items.len() > per_page {
        return Err(protocol("a page is larger than the protocol allows"));
    }
    let mut last = cursor;
    for (index, item) in page.items.iter().enumerate() {
        let s = sequence(item);
        let fine = if index == 0 {
            s > cursor
        } else {
            match order {
                Order::Strict => s > last,
                Order::CallPairs => s >= last,
            }
        };
        if !fine {
            return Err(protocol("sequences do not rise above the cursor"));
        }
        last = s;
    }
    // Only the items bind the server's sequence: a server below the cursor is an older state,
    // which the caller detects (`FolderView::check_server_sequence`).
    if !page.items.is_empty() && page.sequence < last {
        return Err(protocol("the server sequence is below its own items"));
    }
    if page.more && page.items.is_empty() {
        return Err(protocol("more pages announced without an item"));
    }
    Ok(last)
}

/// Every page of a folder delta after `after`.
pub fn collect_delta(
    after: u64,
    mut fetch: impl FnMut(u64) -> Result<DeltaPage, NetError>,
) -> Result<(Vec<DeltaCommit>, u64), NetError> {
    collect_pages(
        after,
        DELTA_LIMITS,
        Order::CallPairs,
        |c: &DeltaCommit| c.sequence,
        |cursor| fetch(cursor).map(Page::from),
    )
}

/// Every page of the change feed after `after`.
pub fn collect_feed(
    after: u64,
    mut fetch: impl FnMut(u64) -> Result<FeedPage, NetError>,
) -> Result<(Vec<FeedEntry>, u64), NetError> {
    collect_pages(
        after,
        FEED_LIMITS,
        Order::Strict,
        |e: &FeedEntry| e.sequence,
        |cursor| fetch(cursor).map(Page::from),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: Limits = Limits {
        per_page: 3,
        total: 10,
    };

    fn page(items: &[u64], more: bool, sequence: u64) -> Page<u64> {
        Page {
            items: items.to_vec(),
            more,
            sequence,
        }
    }

    type Run = (Result<(Vec<u64>, u64), NetError>, Vec<u64>);

    fn run(order: Order, pages: Vec<Page<u64>>) -> Run {
        let mut asked = Vec::new();
        let mut pages = pages.into_iter();
        let result = collect_pages(
            0,
            SMALL,
            order,
            |s| *s,
            |cursor| {
                asked.push(cursor);
                pages.next().ok_or(NetError::Unreachable)
            },
        );
        (result, asked)
    }

    #[test]
    fn pages_are_followed_from_cursor_to_cursor() {
        let (result, asked) = run(
            Order::Strict,
            vec![page(&[1, 2, 3], true, 7), page(&[4, 7], false, 7)],
        );
        assert_eq!(result.unwrap(), (vec![1, 2, 3, 4, 7], 7));
        assert_eq!(asked, vec![0, 3]);
    }

    #[test]
    fn an_endlessly_repeated_page_is_refused() {
        // The same page again and again: its items are not above the new cursor.
        let mut calls = 0;
        let result = collect_pages(
            0,
            SMALL,
            Order::Strict,
            |s: &u64| *s,
            |_| {
                calls += 1;
                Ok(page(&[1, 2], true, 9))
            },
        );
        assert!(matches!(result, Err(NetError::Protocol(_))));
        assert_eq!(calls, 2, "refused at the first repetition");
        // A server that pages forward forever is stopped by the total limit.
        let mut next = 0u64;
        let result = collect_pages(
            0,
            SMALL,
            Order::Strict,
            |s: &u64| *s,
            |_| {
                next += 1;
                Ok(page(&[next], true, u64::MAX))
            },
        );
        assert!(matches!(result, Err(NetError::Protocol(_))));
        assert_eq!(next, 11);
    }

    #[test]
    fn more_with_an_empty_page_is_a_protocol_error() {
        let (result, _) = run(Order::Strict, vec![page(&[], true, 5)]);
        assert!(matches!(result, Err(NetError::Protocol(_))));
        // An empty last page is the normal end.
        let (result, _) = run(Order::Strict, vec![page(&[], false, 5)]);
        assert_eq!(result.unwrap(), (vec![], 5));
    }

    #[test]
    fn sequences_must_rise_above_the_cursor() {
        let (result, _) = run(Order::Strict, vec![page(&[0], false, 5)]);
        assert!(result.is_err(), "at the cursor");
        let (result, _) = run(Order::Strict, vec![page(&[2, 1], false, 5)]);
        assert!(result.is_err(), "falling");
        let (result, _) = run(Order::Strict, vec![page(&[2, 2], false, 5)]);
        assert!(result.is_err(), "repeated in the feed");
        let (result, _) = run(Order::CallPairs, vec![page(&[2, 2], false, 5)]);
        assert_eq!(result.unwrap().0, vec![2, 2], "a side commit and its head");
        let (result, _) = run(Order::Strict, vec![page(&[1, 9], false, 5)]);
        assert!(result.is_err(), "the server sequence below its items");
    }

    #[test]
    fn pages_and_lists_have_a_size_limit() {
        let (result, _) = run(Order::Strict, vec![page(&[1, 2, 3, 4], false, 9)]);
        assert!(result.is_err());
    }
}
