//! The handlers: parse, call one service function, answer. No rule of the protocol lives here;
//! rate limits run in the authorization layer before any handler (`http::ratelimit`).

use std::time::Duration;

use axum::body::Body;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::StreamExt;
use hangar_drive_crypto::object::OBJECT_HEADER_LEN;
use hangar_drive_protocol::api::{
    ChallengeRequest, CommitRequest, CreateAccountRequest, ErrorCode, LogAppendRequest,
    MissingObjectsRequest, PairingRequest, ProofRequest, RecordKey, RecordKind, RecordPut,
    SequenceEvent, UploadResponse,
};
use hangar_drive_protocol::ids::{FolderId, ObjectId, PairingId};
use hangar_drive_protocol::ServerInfo;
use tokio::io::AsyncWriteExt;

use crate::app::AppState;
use crate::error::{ApiError, ApiResult};
use crate::http::extract::{
    read_limited, After, JsonBody, PathParams, PublicJsonBody, BODY_IDLE_TIMEOUT, BODY_TIMEOUT,
    COMMIT_JSON, MISSING_JSON, RECORD_JSON, SMALL_JSON,
};
use crate::service::objects::{self, Precheck, Staged};
use crate::service::sessions::{self, Session};
use crate::service::{accounts, commits, devicelog, feed, folders, pairing, records};

/// The session the authorization layer put on the request.
pub struct Authed(pub Session);

impl<S: Send + Sync> FromRequestParts<S> for Authed {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Session>()
            .cloned()
            .map(Authed)
            .ok_or_else(|| ApiError::internal(&"handler without a session"))
    }
}

/// How long a commit or record write waits for a free slot before it is refused.
const HEAVY_WAIT: Duration = Duration::from_secs(30);

/// Reads the JSON body of a commit or record write while holding a slot of [`App::heavy`]
/// (finding M4): these bodies are held in memory, up to [`COMMIT_JSON`] each, so only a few are
/// read and worked on at once. The slot is taken before the first body byte is read and held
/// until the service call returns.
///
/// [`App::heavy`]: crate::app::App::heavy
///
/// An account holds at most [`heavy_share`] of the slots; a call beyond its share is refused
/// at once, before it waits, so the share is never used to queue.
async fn heavy_json<'a, T: serde::de::DeserializeOwned>(
    app: &'a AppState,
    request: Request,
    limit: usize,
) -> ApiResult<(T, HeavySlot<'a>)> {
    let account_pk = request
        .extensions()
        .get::<Session>()
        .map(|s| s.account_pk)
        .ok_or_else(|| ApiError::internal(&"heavy call without a session"))?;
    let share = app
        .heavy_accounts
        .take(account_pk, heavy_share(app.concurrency.heavy_requests))
        .ok_or_else(|| ApiError::new(ErrorCode::RateLimited))?;
    let permit = tokio::time::timeout(HEAVY_WAIT, app.heavy.clone().acquire_owned())
        .await
        .map_err(|_| ApiError::new(ErrorCode::RateLimited))?
        .map_err(|_| ApiError::new(ErrorCode::RateLimited))?;
    let (parts, body) = request.into_parts();
    let bytes = read_limited(&parts.headers, body, limit, BODY_TIMEOUT).await?;
    let value = serde_json::from_slice(&bytes).map_err(|_| ApiError::new(ErrorCode::BadRequest))?;
    Ok((
        value,
        HeavySlot {
            _share: share,
            _permit: permit,
        },
    ))
}

/// Heavy slots one account may hold: half of all, at least one.
fn heavy_share(heavy_requests: u32) -> u32 {
    (heavy_requests / 2).max(1)
}

/// A heavy slot and the account's share of it, both freed on drop.
struct HeavySlot<'a> {
    _share: crate::app::UploadSlot<'a>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

fn folder_of(params: &PathParams) -> ApiResult<FolderId> {
    params.get("folder", |v| FolderId::from_hex(v).ok())
}

pub async fn health() -> Json<ServerInfo> {
    Json(ServerInfo::new(crate::VERSION))
}

pub async fn create_account(
    State(app): State<AppState>,
    PublicJsonBody(request): PublicJsonBody<CreateAccountRequest, SMALL_JSON>,
) -> ApiResult<Response> {
    let reply = accounts::create_account(&app, request).await?;
    Ok((StatusCode::CREATED, Json(reply)).into_response())
}

pub async fn challenge(
    State(app): State<AppState>,
    PublicJsonBody(request): PublicJsonBody<ChallengeRequest, SMALL_JSON>,
) -> ApiResult<Response> {
    Ok(Json(sessions::challenge(&app, &request)?).into_response())
}

pub async fn proof(
    State(app): State<AppState>,
    PublicJsonBody(request): PublicJsonBody<ProofRequest, SMALL_JSON>,
) -> ApiResult<Response> {
    Ok(Json(sessions::proof(&app, &request).await?).into_response())
}

pub async fn get_log(
    State(app): State<AppState>,
    Authed(s): Authed,
    After(after): After,
) -> ApiResult<Response> {
    Ok(Json(devicelog::page(&app, &s, after).await?).into_response())
}

pub async fn append_log(
    State(app): State<AppState>,
    Authed(s): Authed,
    JsonBody(request): JsonBody<LogAppendRequest, SMALL_JSON>,
) -> ApiResult<Response> {
    Ok(Json(devicelog::append(&app, &s, request).await?).into_response())
}

pub async fn epoch_key(
    State(app): State<AppState>,
    Authed(s): Authed,
    params: PathParams,
) -> ApiResult<Response> {
    let epoch = params.get("epoch", |v| v.parse::<u32>().ok().filter(|e| *e >= 1))?;
    Ok(Json(devicelog::epoch_key(&app, &s, epoch).await?).into_response())
}

fn record_key(params: &PathParams, with_folder: bool) -> ApiResult<RecordKey> {
    let kind = params.get("kind", |v| match v {
        "folder-keys" => Some(RecordKind::FolderKeys),
        "folders" => Some(RecordKind::Folders),
        "device-names" => Some(RecordKind::DeviceNames),
        _ => None,
    })?;
    let folder = if with_folder {
        Some(folder_of(params)?)
    } else {
        None
    };
    RecordKey::new(kind, folder).ok_or_else(|| ApiError::new(ErrorCode::NotFound))
}

pub async fn get_record(
    State(app): State<AppState>,
    Authed(s): Authed,
    params: PathParams,
) -> ApiResult<Response> {
    let key = record_key(&params, false)?;
    Ok(Json(records::get(&app, &s, key).await?).into_response())
}

pub async fn get_folder_record(
    State(app): State<AppState>,
    Authed(s): Authed,
    params: PathParams,
) -> ApiResult<Response> {
    let key = record_key(&params, true)?;
    Ok(Json(records::get(&app, &s, key).await?).into_response())
}

pub async fn put_record(
    State(app): State<AppState>,
    Authed(s): Authed,
    params: PathParams,
    request: Request,
) -> ApiResult<Response> {
    let key = record_key(&params, false)?;
    let (put, _slot) = heavy_json::<RecordPut>(&app, request, RECORD_JSON).await?;
    Ok(Json(records::put(&app, &s, key, put).await?).into_response())
}

pub async fn put_folder_record(
    State(app): State<AppState>,
    Authed(s): Authed,
    params: PathParams,
    request: Request,
) -> ApiResult<Response> {
    let key = record_key(&params, true)?;
    let (put, _slot) = heavy_json::<RecordPut>(&app, request, RECORD_JSON).await?;
    Ok(Json(records::put(&app, &s, key, put).await?).into_response())
}

pub async fn feed_page(
    State(app): State<AppState>,
    Authed(s): Authed,
    After(after): After,
) -> ApiResult<Response> {
    Ok(Json(feed::page(&app, s.account_pk, after).await?).into_response())
}

/// SSE keepalive comments; below the 60 s read timeouts of common proxies.
pub const KEEPALIVE: Duration = Duration::from_secs(25);
/// How often a stream checks that its session still exists (removed device, expiry).
const SESSION_CHECK: Duration = Duration::from_secs(30);

/// `GET /account/events`: one event with the current sequence, then one per change. Ends when
/// the session ends (expiry or removal of the device) or the server shuts down; the client
/// reconnects with a fresh token and pulls the feed meanwhile.
pub async fn events(State(app): State<AppState>, Authed(s): Authed) -> ApiResult<Response> {
    let current = feed::current(&app, s.account_pk).await?;
    let slot = app
        .events
        .subscribe(s.account_pk, current)
        .ok_or(ErrorCode::RateLimited)?;
    struct StreamState {
        app: AppState,
        slot: crate::events::StreamSlot,
        session: Session,
        first: bool,
        shutdown: tokio::sync::watch::Receiver<bool>,
    }
    let state = StreamState {
        shutdown: app.shutdown.clone(),
        app,
        slot,
        session: s,
        first: true,
    };
    let stream = futures_util::stream::unfold(state, |mut st| async move {
        let event = |seq: u64| {
            Event::default()
                .event("sequence")
                .json_data(SequenceEvent { sequence: seq })
        };
        if st.first {
            st.first = false;
            let seq = *st.slot.receiver.borrow_and_update();
            return event(seq)
                .ok()
                .map(|e| (Ok::<_, std::convert::Infallible>(e), st));
        }
        loop {
            if *st.shutdown.borrow() || st.session.expires_ms <= st.app.now_ms() {
                return None;
            }
            tokio::select! {
                changed = st.slot.receiver.changed() => {
                    changed.ok()?;
                    let seq = *st.slot.receiver.borrow_and_update();
                    return event(seq).ok().map(|e| (Ok(e), st));
                }
                _ = st.shutdown.changed() => return None,
                _ = tokio::time::sleep(SESSION_CHECK) => {
                    if !sessions::still_valid(&st.app, &st.session.token_hash).await.unwrap_or(false) {
                        return None;
                    }
                }
            }
        }
    });
    let mut response = Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(KEEPALIVE))
        .into_response();
    // Tells nginx not to buffer the stream.
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    Ok(response)
}

fn pairing_id(params: &PathParams) -> ApiResult<PairingId> {
    params.get("pairing", |v| PairingId::from_hex(v).ok())
}

pub async fn reserve_pairing(
    State(app): State<AppState>,
    Authed(s): Authed,
    params: PathParams,
) -> ApiResult<Response> {
    let id = pairing_id(&params)?;
    Ok(Json(pairing::reserve(&app, &s, id).await?).into_response())
}

pub async fn post_pairing(
    State(app): State<AppState>,
    params: PathParams,
    PublicJsonBody(request): PublicJsonBody<PairingRequest, SMALL_JSON>,
) -> ApiResult<Response> {
    let id = pairing_id(&params)?;
    pairing::post(&app, id, request).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn get_pairing(
    State(app): State<AppState>,
    Authed(s): Authed,
    params: PathParams,
) -> ApiResult<Response> {
    let id = pairing_id(&params)?;
    Ok(Json(pairing::get(&app, &s, id).await?).into_response())
}

pub async fn close_pairing(
    State(app): State<AppState>,
    Authed(s): Authed,
    params: PathParams,
) -> ApiResult<Response> {
    let id = pairing_id(&params)?;
    pairing::close(&app, &s, id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn missing(
    State(app): State<AppState>,
    Authed(s): Authed,
    params: PathParams,
    JsonBody(request): JsonBody<MissingObjectsRequest, MISSING_JSON>,
) -> ApiResult<Response> {
    let folder = folder_of(&params)?;
    Ok(Json(objects::missing(&app, &s, folder, request).await?).into_response())
}

/// `PUT /folders/{folder}/objects/{id}`: checks what needs no body first, then streams the body
/// to a staging file with a size limit and an idle timeout.
/// Bytes of an upload kept for the header check: header, tag and the length prefix.
const HEAD_KEEP: usize = OBJECT_HEADER_LEN + 16 + 8;

pub async fn put_object(
    State(app): State<AppState>,
    Authed(s): Authed,
    params: PathParams,
    request: Request,
) -> ApiResult<Response> {
    let folder = folder_of(&params)?;
    let id = params.get("id", |v| ObjectId::from_hex(v).ok())?;
    // At most a few uploads per account at once (finding M5), taken before the body is read.
    let _slot = app
        .uploads
        .take(s.account_pk, app.concurrency.uploads_per_account)
        .ok_or(ErrorCode::RateLimited)?;
    let max = objects::max_blob_len();
    let (parts, body) = request.into_parts();
    let announced = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if announced.is_some_and(|len| len > max as u64) {
        return Err(ErrorCode::TooLarge.into());
    }
    // Without a length the upload may still write up to the largest blob.
    let expected = announced.unwrap_or(max as u64);
    if let Precheck::Held = objects::precheck(&app, &s, &folder, &id, expected).await? {
        return Ok(Json(UploadResponse { stored: false }).into_response());
    }
    let mut claim = app.staging.claim(expected);
    let path = app.store.staging_path()?;
    let mut staged = Staged::new(path.clone(), 0, Vec::new());
    let receive = async {
        let mut file = tokio::fs::File::create(&path).await?;
        let mut stream = body.into_data_stream();
        loop {
            let next = tokio::time::timeout(BODY_IDLE_TIMEOUT, stream.next())
                .await
                .map_err(|_| ApiError {
                    status: Some(StatusCode::REQUEST_TIMEOUT),
                    ..ApiError::new(ErrorCode::BadRequest)
                })?;
            let chunk = match next {
                None => break,
                Some(Err(_)) => return Err(ApiError::new(ErrorCode::BadRequest)),
                Some(Ok(chunk)) => chunk,
            };
            if staged.len + chunk.len() > max {
                return Err(ApiError::new(ErrorCode::TooLarge));
            }
            // The clear header plus what `object_header` needs to see of the smallest blob.
            if staged.head.len() < HEAD_KEEP {
                let take = (HEAD_KEEP - staged.head.len()).min(chunk.len());
                staged.head.extend_from_slice(&chunk[..take]);
            }
            file.write_all(&chunk).await?;
            staged.len += chunk.len();
            claim.wrote(chunk.len() as u64);
        }
        file.flush().await?;
        // On disk before the write transaction starts (finding M4): the flush must not run
        // while the database's write lock is held.
        file.sync_all().await?;
        Ok::<(), ApiError>(())
    };
    tokio::time::timeout(Duration::from_secs(600), receive)
        .await
        .map_err(|_| ApiError {
            status: Some(StatusCode::REQUEST_TIMEOUT),
            ..ApiError::new(ErrorCode::BadRequest)
        })??;
    drop(claim);
    let reply = objects::store(&app, &s, folder, id, staged).await?;
    let status = if reply.stored {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(reply)).into_response())
}

pub async fn get_object(
    State(app): State<AppState>,
    Authed(s): Authed,
    params: PathParams,
) -> ApiResult<Response> {
    let folder = folder_of(&params)?;
    let id = params.get("id", |v| ObjectId::from_hex(v).ok())?;
    let (file, size) = objects::open(&app, &s, folder, id).await?;
    let file = tokio::fs::File::from_std(file);
    let stream = futures_util::stream::unfold(file, |mut file| async move {
        use tokio::io::AsyncReadExt;
        let mut buffer = vec![0u8; 64 * 1024];
        match file.read(&mut buffer).await {
            Ok(0) => None,
            Ok(n) => {
                buffer.truncate(n);
                Some((
                    Ok::<_, std::io::Error>(axum::body::Bytes::from(buffer)),
                    file,
                ))
            }
            Err(e) => Some((Err(e), file)),
        }
    });
    let mut response = Body::from_stream(stream).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    // Objects never change under their ID.
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=31536000, immutable"),
    );
    Ok(response)
}

pub async fn commit(
    State(app): State<AppState>,
    Authed(s): Authed,
    params: PathParams,
    request: Request,
) -> ApiResult<Response> {
    let folder = folder_of(&params)?;
    let (request, _slot) = heavy_json::<CommitRequest>(&app, request, COMMIT_JSON).await?;
    Ok(Json(commits::commit(&app, &s, folder, request).await?).into_response())
}

pub async fn delta(
    State(app): State<AppState>,
    Authed(s): Authed,
    params: PathParams,
    After(after): After,
) -> ApiResult<Response> {
    let folder = folder_of(&params)?;
    Ok(Json(commits::delta(&app, &s, folder, after).await?).into_response())
}

pub async fn retire(
    State(app): State<AppState>,
    Authed(s): Authed,
    params: PathParams,
) -> ApiResult<Response> {
    let folder = folder_of(&params)?;
    folders::retire(&app, &s, folder).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn bring_back(
    State(app): State<AppState>,
    Authed(s): Authed,
    params: PathParams,
) -> ApiResult<Response> {
    let folder = folder_of(&params)?;
    folders::bring_back(&app, &s, folder).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
