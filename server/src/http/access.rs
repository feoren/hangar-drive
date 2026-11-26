//! The access table (ADR 0001, section 6, "Scope"): every route of the router is listed here,
//! either as public (no session: health, account creation, sign-in, a new device's pairing
//! request into a slot the inviting device reserved) or mapped to exactly one `ApiCall`, which the session's `SessionScope` must allow.
//! The router is built from this table, and the authorization layer looks every request up in
//! it again: a route that is not in the table, or a method the table does not name, is refused
//! (default deny), so adding a route without deciding its access cannot open it.

use axum::http::Method;
use hangar_drive_protocol::api::ApiCall;

/// How a route is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// No session.
    Public,
    /// A session whose scope allows the call.
    Call(ApiCall),
}

/// Which handler serves a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handler {
    Health,
    CreateAccount,
    Challenge,
    Proof,
    GetLog,
    AppendLog,
    EpochKey,
    GetRecord,
    PutRecord,
    GetFolderRecord,
    PutFolderRecord,
    Feed,
    Events,
    ReservePairing,
    PostPairing,
    GetPairing,
    Missing,
    PutObject,
    GetObject,
    Commit,
    Delta,
    Retire,
    BringBack,
}

pub struct Route {
    pub method: Method,
    pub path: &'static str,
    pub access: Access,
    pub handler: Handler,
}

const fn route(method: Method, path: &'static str, access: Access, handler: Handler) -> Route {
    Route {
        method,
        path,
        access,
        handler,
    }
}

/// Every route of the server.
pub fn routes() -> Vec<Route> {
    use Access::{Call, Public};
    vec![
        route(Method::GET, "/api/v1/health", Public, Handler::Health),
        route(
            Method::POST,
            "/api/v1/accounts",
            Public,
            Handler::CreateAccount,
        ),
        route(
            Method::POST,
            "/api/v1/session/challenge",
            Public,
            Handler::Challenge,
        ),
        route(
            Method::POST,
            "/api/v1/session/proof",
            Public,
            Handler::Proof,
        ),
        route(
            Method::GET,
            "/api/v1/account/log",
            Call(ApiCall::GetLog),
            Handler::GetLog,
        ),
        route(
            Method::POST,
            "/api/v1/account/log",
            Call(ApiCall::AppendLog),
            Handler::AppendLog,
        ),
        route(
            Method::GET,
            "/api/v1/account/epochs/{epoch}/key",
            Call(ApiCall::GetOwnEpochKey),
            Handler::EpochKey,
        ),
        route(
            Method::GET,
            "/api/v1/account/records/{kind}",
            Call(ApiCall::GetRecord),
            Handler::GetRecord,
        ),
        route(
            Method::PUT,
            "/api/v1/account/records/{kind}",
            Call(ApiCall::PutRecord),
            Handler::PutRecord,
        ),
        route(
            Method::GET,
            "/api/v1/account/records/{kind}/{folder}",
            Call(ApiCall::GetRecord),
            Handler::GetFolderRecord,
        ),
        route(
            Method::PUT,
            "/api/v1/account/records/{kind}/{folder}",
            Call(ApiCall::PutRecord),
            Handler::PutFolderRecord,
        ),
        route(
            Method::GET,
            "/api/v1/account/feed",
            Call(ApiCall::GetFeed),
            Handler::Feed,
        ),
        route(
            Method::GET,
            "/api/v1/account/events",
            Call(ApiCall::Events),
            Handler::Events,
        ),
        route(
            Method::PUT,
            "/api/v1/pairing/{pairing}",
            Call(ApiCall::ReservePairing),
            Handler::ReservePairing,
        ),
        route(
            Method::POST,
            "/api/v1/pairing/{pairing}",
            Public,
            Handler::PostPairing,
        ),
        route(
            Method::GET,
            "/api/v1/pairing/{pairing}",
            Call(ApiCall::GetPairing),
            Handler::GetPairing,
        ),
        route(
            Method::POST,
            "/api/v1/folders/{folder}/objects/missing",
            Call(ApiCall::MissingObjects),
            Handler::Missing,
        ),
        route(
            Method::PUT,
            "/api/v1/folders/{folder}/objects/{id}",
            Call(ApiCall::PutObject),
            Handler::PutObject,
        ),
        route(
            Method::GET,
            "/api/v1/folders/{folder}/objects/{id}",
            Call(ApiCall::GetObject),
            Handler::GetObject,
        ),
        route(
            Method::POST,
            "/api/v1/folders/{folder}/commit",
            Call(ApiCall::Commit),
            Handler::Commit,
        ),
        route(
            Method::GET,
            "/api/v1/folders/{folder}/commits",
            Call(ApiCall::GetCommits),
            Handler::Delta,
        ),
        route(
            Method::POST,
            "/api/v1/folders/{folder}/retire",
            Call(ApiCall::Retire),
            Handler::Retire,
        ),
        // Bringing a retired folder back is the same folder lifecycle call as retiring it.
        route(
            Method::DELETE,
            "/api/v1/folders/{folder}/retire",
            Call(ApiCall::Retire),
            Handler::BringBack,
        ),
    ]
}

/// Whether some route of the table has this pattern.
pub fn is_known_path(pattern: &str) -> bool {
    routes().iter().any(|r| r.path == pattern)
}

/// The access of a matched route pattern and method; `None`: not in the table (refused).
pub fn lookup(method: &Method, pattern: &str) -> Option<Access> {
    route_of(method, pattern).map(|(access, _)| access)
}

/// The access and the handler of a matched route pattern and method.
pub fn route_of(method: &Method, pattern: &str) -> Option<(Access, Handler)> {
    // HEAD is answered like GET by the router; it needs the same access.
    let method = if method == Method::HEAD {
        &Method::GET
    } else {
        method
    };
    routes()
        .into_iter()
        .find(|r| r.method == *method && r.path == pattern)
        .map(|r| (r.access, r.handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_drive_protocol::api::*;

    #[test]
    fn every_protocol_path_is_in_the_table() {
        let f = hangar_drive_protocol::ids::FolderId::from_bytes([1; 16]);
        let patterns: Vec<&str> = routes().iter().map(|r| r.path).collect();
        for (path, pattern) in [
            (ACCOUNTS_PATH.to_owned(), "/api/v1/accounts"),
            (CHALLENGE_PATH.to_owned(), "/api/v1/session/challenge"),
            (PROOF_PATH.to_owned(), "/api/v1/session/proof"),
            (LOG_PATH.to_owned(), "/api/v1/account/log"),
            (FEED_PATH.to_owned(), "/api/v1/account/feed"),
            (EVENTS_PATH.to_owned(), "/api/v1/account/events"),
            (commit_path(&f), "/api/v1/folders/{folder}/commit"),
            (commits_path(&f), "/api/v1/folders/{folder}/commits"),
            (retire_path(&f), "/api/v1/folders/{folder}/retire"),
            (
                missing_objects_path(&f),
                "/api/v1/folders/{folder}/objects/missing",
            ),
        ] {
            assert!(patterns.contains(&pattern), "{path}");
        }
        assert_eq!(hangar_drive_protocol::HEALTH_PATH, "/api/v1/health");
    }

    #[test]
    fn the_recovery_scope_reaches_only_its_three_calls() {
        let recovery = SessionScope::for_device(true);
        let allowed: Vec<&str> = routes()
            .iter()
            .filter_map(|r| match r.access {
                Access::Call(call) if recovery.allows(call) => Some(r.path),
                _ => None,
            })
            .collect();
        assert_eq!(
            allowed,
            [
                "/api/v1/account/log",
                "/api/v1/account/log",
                "/api/v1/account/epochs/{epoch}/key"
            ]
        );
    }

    #[test]
    fn unknown_routes_and_methods_are_not_in_the_table() {
        assert_eq!(lookup(&Method::DELETE, "/api/v1/account/log"), None);
        assert_eq!(lookup(&Method::GET, "/api/v1/admin"), None);
        assert_eq!(lookup(&Method::GET, "/api/v1/health"), Some(Access::Public));
        assert_eq!(
            lookup(&Method::HEAD, "/api/v1/account/feed"),
            Some(Access::Call(ApiCall::GetFeed))
        );
        // Only the health check and the four calls without a session are public; reserving a
        // pairing slot needs a session (finding M2).
        assert_eq!(
            lookup(&Method::PUT, "/api/v1/pairing/{pairing}"),
            Some(Access::Call(ApiCall::ReservePairing))
        );
        let public: Vec<&str> = routes()
            .iter()
            .filter(|r| r.access == Access::Public)
            .map(|r| r.path)
            .collect();
        assert_eq!(
            public,
            [
                "/api/v1/health",
                "/api/v1/accounts",
                "/api/v1/session/challenge",
                "/api/v1/session/proof",
                "/api/v1/pairing/{pairing}"
            ]
        );
    }
}
