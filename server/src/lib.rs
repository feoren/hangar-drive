//! The Hangar Drive sync server: it will distribute every client's changes to the others and keep
//! versions as a backup. For now it only answers [`HEALTH_PATH`].

pub mod config;
pub mod probe;

use std::future::Future;

use axum::routing::get;
use axum::{Json, Router};
use hangar_drive_protocol::{ServerInfo, HEALTH_PATH};
use tokio::net::TcpListener;

/// Version of this server program, as reported at [`HEALTH_PATH`].
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// All routes of the server. Unknown paths answer 404, known paths with the wrong method 405.
pub fn router() -> Router {
    Router::new().route(HEALTH_PATH, get(health))
}

/// Serves [`router`] on `listener` until `shutdown` completes, then stops accepting connections
/// and returns once the requests in flight are answered.
pub async fn serve<F>(listener: TcpListener, shutdown: F) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(listener, router())
        .with_graceful_shutdown(shutdown)
        .await
}

async fn health() -> Json<ServerInfo> {
    Json(ServerInfo::new(VERSION))
}
