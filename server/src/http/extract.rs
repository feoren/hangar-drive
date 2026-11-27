//! Request parsing that answers every failure with an `ErrorCode`, never with axum's own text
//! rejections: JSON bodies with a size limit and a time limit, path IDs, the `after` cursor
//! and the bearer token. The client address for rate limits is read in the authorization
//! layer (`http::mod`).

use std::time::Duration;

use axum::body::Body;
use axum::extract::{FromRequest, FromRequestParts, RawPathParams, Request};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, StatusCode};
use futures_util::StreamExt;
use hangar_drive_protocol::api::ErrorCode;
use hangar_drive_protocol::ids::SessionToken;
use serde::de::DeserializeOwned;
use tokio::time::Instant;

use crate::app::AppState;
use crate::error::ApiError;

/// Time a client has to send a whole JSON body of a call (with a session).
pub const BODY_TIMEOUT: Duration = Duration::from_secs(120);
/// Time anyone has to send the small body of a public route (finding M6): no session stands
/// behind it, so it must not hold a connection and a request slot for two minutes.
pub const PUBLIC_BODY_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest pause between two parts of a body.
pub const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Limits of JSON bodies per route.
pub const SMALL_JSON: usize = 64 * 1024;
/// A sealed record (1 MiB plaintext) in base64url, with room.
pub const RECORD_JSON: usize = 2 * 1024 * 1024;
/// A commit call: two reference deltas of up to 2^20 IDs in hex (about 70 MB at the limit).
pub const COMMIT_JSON: usize = 80 * 1024 * 1024;
/// `objects/missing`: 4096 IDs in hex, with room.
pub const MISSING_JSON: usize = 1024 * 1024;

fn timeout_error() -> ApiError {
    ApiError {
        status: Some(StatusCode::REQUEST_TIMEOUT),
        ..ApiError::new(ErrorCode::BadRequest)
    }
}

/// The least data rate of a body after a grace period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pace {
    /// Time before the rate counts (connection set-up, a slow start).
    pub grace: Duration,
    /// Bytes per second on average since the body began, from the end of the grace period.
    pub bytes_per_s: u64,
}

/// The pace of a body read while holding a heavy slot (server security review, LOW 2): two
/// accounts that trickled their bodies held every heavy slot for the whole [`BODY_TIMEOUT`],
/// and nobody else could commit. It is enforced only while another call waits for a heavy
/// slot (follow-up review L3): then a body that fell behind 64 KiB/s on average frees its slot;
/// without contention a slow honest uplink keeps only the idle and the total timeout.
pub const HEAVY_PACE: Pace = Pace {
    grace: Duration::from_secs(5),
    bytes_per_s: 64 * 1024,
};

impl Pace {
    /// How long after the start a body of `received` bytes may wait for its next part.
    fn due(&self, received: usize) -> Duration {
        let received = u64::try_from(received).unwrap_or(u64::MAX);
        let ms = received.saturating_mul(1000) / self.bytes_per_s.max(1);
        self.grace.saturating_add(Duration::from_millis(ms))
    }
}

/// Reads a whole body of at most `limit` bytes within `total`, with no pause longer than
/// [`BODY_IDLE_TIMEOUT`].
pub async fn read_limited(
    headers: &HeaderMap,
    body: Body,
    limit: usize,
    total: Duration,
) -> Result<Vec<u8>, ApiError> {
    read_paced(headers, body, limit, total, None).await
}

/// [`read_limited`], and with `pace` a body that falls behind that rate after its grace
/// period is cut off like one that pauses too long.
pub async fn read_paced(
    headers: &HeaderMap,
    body: Body,
    limit: usize,
    total: Duration,
    pace: Option<(Pace, &(dyn Fn() -> bool + Send + Sync))>,
) -> Result<Vec<u8>, ApiError> {
    let announced = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if announced.is_some_and(|len| len > limit as u64) {
        return Err(ErrorCode::TooLarge.into());
    }
    // The announced length, which is within the limit, is reserved at once (overall review
    // N4): grown by doubling, a 67 MiB commit body took a 128 MiB buffer, and the copy from
    // the 64 MiB one into it held both at once.
    let reserve = announced
        .and_then(|len| usize::try_from(len).ok())
        .unwrap_or(0)
        .min(limit);
    let started = Instant::now();
    let read = async {
        let mut stream = body.into_data_stream();
        let mut bytes = Vec::with_capacity(reserve);
        let mut last_part = started;
        loop {
            let idle_deadline = last_part + BODY_IDLE_TIMEOUT.min(total);
            let mut deadline = idle_deadline;
            let mut paced = false;
            if let Some((pace, contended)) = pace {
                if contended() {
                    paced = true;
                    deadline = deadline.min(started + pace.due(bytes.len()));
                } else {
                    // Look again soon whether someone started to wait.
                    deadline = deadline.min(Instant::now() + PACE_RECHECK);
                }
            }
            // A part that is already there is still taken: the timeout polls first.
            let Ok(next) = tokio::time::timeout_at(deadline, stream.next()).await else {
                if paced || Instant::now() >= idle_deadline {
                    return Err(timeout_error());
                }
                continue;
            };
            last_part = Instant::now();
            match next {
                None => return Ok(bytes),
                Some(Err(_)) => return Err(ApiError::new(ErrorCode::BadRequest)),
                Some(Ok(chunk)) => {
                    if bytes.len() + chunk.len() > limit {
                        return Err(ApiError::new(ErrorCode::TooLarge));
                    }
                    bytes.extend_from_slice(&chunk);
                }
            }
        }
    };
    tokio::time::timeout(total, read)
        .await
        .map_err(|_| timeout_error())?
}

/// How often a paced read without contention checks whether a call started to wait.
const PACE_RECHECK: Duration = Duration::from_millis(500);

/// A JSON body of at most `LIMIT` bytes.
pub struct JsonBody<T, const LIMIT: usize>(pub T);

impl<T: DeserializeOwned, const LIMIT: usize> FromRequest<AppState> for JsonBody<T, LIMIT> {
    type Rejection = ApiError;

    async fn from_request(request: Request, _state: &AppState) -> Result<Self, Self::Rejection> {
        let (parts, body) = request.into_parts();
        let bytes = read_limited(&parts.headers, body, LIMIT, BODY_TIMEOUT).await?;
        serde_json::from_slice(&bytes)
            .map(JsonBody)
            .map_err(|_| ApiError::new(ErrorCode::BadRequest))
    }
}

/// A JSON body of a public route: at most `LIMIT` bytes within [`PUBLIC_BODY_TIMEOUT`].
pub struct PublicJsonBody<T, const LIMIT: usize>(pub T);

impl<T: DeserializeOwned, const LIMIT: usize> FromRequest<AppState> for PublicJsonBody<T, LIMIT> {
    type Rejection = ApiError;

    async fn from_request(request: Request, _state: &AppState) -> Result<Self, Self::Rejection> {
        let (parts, body) = request.into_parts();
        let bytes = read_limited(&parts.headers, body, LIMIT, PUBLIC_BODY_TIMEOUT).await?;
        serde_json::from_slice(&bytes)
            .map(PublicJsonBody)
            .map_err(|_| ApiError::new(ErrorCode::BadRequest))
    }
}

/// The path parameters by name.
pub struct PathParams(Vec<(String, String)>);

impl PathParams {
    /// Parses the parameter `name` with `parse`; anything unparsable is `bad_request`.
    pub fn get<T>(&self, name: &str, parse: impl FnOnce(&str) -> Option<T>) -> Result<T, ApiError> {
        self.0
            .iter()
            .find(|(key, _)| key == name)
            .and_then(|(_, value)| parse(value))
            .ok_or_else(|| ApiError::new(ErrorCode::BadRequest))
    }
}

impl<S: Send + Sync> FromRequestParts<S> for PathParams {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let raw = RawPathParams::from_request_parts(parts, state)
            .await
            .map_err(|_| ApiError::new(ErrorCode::BadRequest))?;
        Ok(Self(
            raw.iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        ))
    }
}

/// `?after=N` (absent: 0). Other query parameters are refused.
pub struct After(pub u64);

impl<S: Send + Sync> FromRequestParts<S> for After {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some(query) = parts.uri.query() else {
            return Ok(Self(0));
        };
        let mut after = None;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            match pair.split_once('=') {
                Some(("after", value)) if after.is_none() => {
                    after = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| ApiError::new(ErrorCode::BadRequest))?,
                    );
                }
                _ => return Err(ErrorCode::BadRequest.into()),
            }
        }
        Ok(Self(after.unwrap_or(0)))
    }
}

/// The bearer token of the `Authorization` header.
pub fn bearer(headers: &HeaderMap) -> Option<SessionToken> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    SessionToken::from_base64url(token.trim()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body of `parts` parts of `size` bytes, one every `every`.
    fn trickle(parts: usize, size: usize, every: Duration) -> Body {
        let stream = futures_util::stream::unfold(0usize, move |sent| async move {
            if sent == parts {
                return None;
            }
            tokio::time::sleep(every).await;
            Some((
                Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![b'x'; size])),
                sent + 1,
            ))
        });
        Body::from_stream(stream)
    }

    const TEST_PACE: Pace = Pace {
        grace: Duration::from_millis(300),
        bytes_per_s: 10_000,
    };

    #[tokio::test]
    async fn a_heavy_body_below_the_pace_is_cut_off_after_the_grace() {
        // LOW 2: 100 bytes every 50 ms is 2000 B/s, below the pace of 10 000 B/s, and never
        // pauses for the idle timeout; before the pace it held its slot for the whole time.
        let started = std::time::Instant::now();
        let read = read_paced(
            &HeaderMap::new(),
            trickle(1000, 100, Duration::from_millis(50)),
            1 << 20,
            Duration::from_secs(20),
            Some((TEST_PACE, &|| true)),
        )
        .await;
        let error = read.expect_err("a trickling body is cut off");
        assert_eq!(error.status, Some(StatusCode::REQUEST_TIMEOUT));
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_slow_body_passes_while_nobody_waits_and_is_cut_off_once_someone_does() {
        // Follow-up review L3: a slow honest uplink below the pace must pass while the heavy
        // slots are not contended. 100 bytes every 50 ms is 2000 B/s, a fifth of the pace.
        let waiting = std::sync::atomic::AtomicBool::new(false);
        let contended = || waiting.load(std::sync::atomic::Ordering::SeqCst);
        let read = read_paced(
            &HeaderMap::new(),
            trickle(30, 100, Duration::from_millis(50)),
            1 << 20,
            Duration::from_secs(20),
            Some((TEST_PACE, &contended)),
        )
        .await;
        assert_eq!(read.map(|b| b.len()), Ok(3000), "without contention");
        // The same body, and after a second another call starts to wait for a slot.
        let started = std::time::Instant::now();
        let read = async {
            read_paced(
                &HeaderMap::new(),
                trickle(1000, 100, Duration::from_millis(50)),
                1 << 20,
                Duration::from_secs(20),
                Some((TEST_PACE, &contended)),
            )
            .await
        };
        let someone_waits = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            waiting.store(true, std::sync::atomic::Ordering::SeqCst);
        };
        let (read, ()) = tokio::join!(read, someone_waits);
        let error = read.expect_err("cut off once a call waits");
        assert_eq!(error.status, Some(StatusCode::REQUEST_TIMEOUT));
        let took = started.elapsed();
        assert!(
            took >= Duration::from_secs(1) && took < Duration::from_secs(3),
            "{took:?}"
        );
    }

    #[tokio::test]
    async fn a_body_at_the_pace_and_a_small_one_pass() {
        // 2000 bytes every 50 ms is 40 000 B/s.
        let read = read_paced(
            &HeaderMap::new(),
            trickle(30, 2000, Duration::from_millis(50)),
            1 << 20,
            Duration::from_secs(20),
            Some((TEST_PACE, &|| true)),
        )
        .await;
        assert_eq!(read.map(|b| b.len()), Ok(60_000));
        // A small body slower than the pace that ends within the grace period.
        let read = read_paced(
            &HeaderMap::new(),
            trickle(2, 10, Duration::from_millis(100)),
            1 << 20,
            Duration::from_secs(20),
            Some((TEST_PACE, &|| true)),
        )
        .await;
        assert_eq!(read.map(|b| b.len()), Ok(20));
        // Without a pace only the idle timeout counts.
        let read = read_paced(
            &HeaderMap::new(),
            trickle(20, 100, Duration::from_millis(50)),
            1 << 20,
            Duration::from_secs(20),
            None,
        )
        .await;
        assert_eq!(read.map(|b| b.len()), Ok(2000));
    }

    #[test]
    fn bearer_tokens_only_from_the_authorization_header() {
        let mut headers = HeaderMap::new();
        assert!(bearer(&headers).is_none());
        let token = "A".repeat(43);
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        assert!(bearer(&headers).is_some());
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {token}").parse().unwrap(),
        );
        assert!(bearer(&headers).is_none());
        headers.insert(header::AUTHORIZATION, "Bearer short".parse().unwrap());
        assert!(bearer(&headers).is_none());
    }
}
