//! The one error type of the API: a code from the protocol's closed list and, for two codes,
//! the fields the protocol defines. Internal causes go to the server log only, never into the
//! reply.

use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use hangar_drive_protocol::api::{ErrorBody, ErrorCode};
use hangar_drive_protocol::ids::{CommitId, ObjectId};

/// Missing object IDs one error reply lists at most.
pub const MAX_MISSING_LISTED: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code:?}")]
pub struct ApiError {
    pub code: ErrorCode,
    pub current_head: Option<CommitId>,
    pub missing: Vec<ObjectId>,
    /// HTTP status other than the code's own (only 405 for a known path with another method).
    pub status: Option<StatusCode>,
}

impl ApiError {
    pub const fn new(code: ErrorCode) -> Self {
        Self {
            code,
            current_head: None,
            missing: Vec::new(),
            status: None,
        }
    }

    pub fn head_moved(current: Option<CommitId>) -> Self {
        Self {
            current_head: current,
            ..Self::new(ErrorCode::HeadMoved)
        }
    }

    pub fn missing(mut ids: Vec<ObjectId>) -> Self {
        ids.truncate(MAX_MISSING_LISTED);
        Self {
            missing: ids,
            ..Self::new(ErrorCode::MissingObjects)
        }
    }

    /// Logs `cause` (without request content) and answers `internal`.
    pub fn internal(cause: &dyn std::fmt::Display) -> Self {
        tracing::error!(error = %cause, "internal error");
        Self::new(ErrorCode::Internal)
    }
}

impl From<ErrorCode> for ApiError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::internal(&error)
    }
}

impl From<std::io::Error> for ApiError {
    fn from(error: std::io::Error) -> Self {
        Self::internal(&error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status.unwrap_or_else(|| {
            StatusCode::from_u16(self.code.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
        });
        let body = ErrorBody {
            code: self.code,
            current_head: self.current_head,
            missing: self.missing,
        };
        let mut response = (status, Json(body)).into_response();
        if self.code == ErrorCode::RateLimited {
            response
                .headers_mut()
                .insert("retry-after", HeaderValue::from_static("60"));
        }
        response
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
