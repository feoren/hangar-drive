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

/// Reads a whole body of at most `limit` bytes within `total`, with no pause longer than
/// [`BODY_IDLE_TIMEOUT`].
pub async fn read_limited(
    headers: &HeaderMap,
    body: Body,
    limit: usize,
    total: Duration,
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
    let read = async {
        let mut stream = body.into_data_stream();
        let mut bytes = Vec::with_capacity(reserve);
        loop {
            let next = tokio::time::timeout(BODY_IDLE_TIMEOUT.min(total), stream.next())
                .await
                .map_err(|_| timeout_error())?;
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
