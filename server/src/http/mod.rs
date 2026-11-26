//! The HTTP surface: the router built from the access table, the authorization layer, security
//! headers and request logs. Logs name the route pattern, never the path (it carries IDs) and
//! never a header (the token).

pub mod access;
pub mod client_ip;
pub mod extract;
pub mod handlers;
pub mod ratelimit;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{on, MethodFilter, MethodRouter};
use axum::Router;
use hangar_drive_protocol::api::ErrorCode;

use crate::app::AppState;
use crate::error::ApiError;
use crate::service::sessions;
use access::{Access, Handler};

fn method_router(handler: Handler, filter: MethodFilter) -> MethodRouter<AppState> {
    use handlers as h;
    match handler {
        Handler::Health => on(filter, h::health),
        Handler::CreateAccount => on(filter, h::create_account),
        Handler::Challenge => on(filter, h::challenge),
        Handler::Proof => on(filter, h::proof),
        Handler::GetLog => on(filter, h::get_log),
        Handler::AppendLog => on(filter, h::append_log),
        Handler::EpochKey => on(filter, h::epoch_key),
        Handler::GetRecord => on(filter, h::get_record),
        Handler::PutRecord => on(filter, h::put_record),
        Handler::GetFolderRecord => on(filter, h::get_folder_record),
        Handler::PutFolderRecord => on(filter, h::put_folder_record),
        Handler::Feed => on(filter, h::feed_page),
        Handler::Events => on(filter, h::events),
        Handler::ReservePairing => on(filter, h::reserve_pairing),
        Handler::PostPairing => on(filter, h::post_pairing),
        Handler::GetPairing => on(filter, h::get_pairing),
        Handler::Missing => on(filter, h::missing),
        Handler::PutObject => on(filter, h::put_object),
        Handler::GetObject => on(filter, h::get_object),
        Handler::Commit => on(filter, h::commit),
        Handler::Delta => on(filter, h::delta),
        Handler::Retire => on(filter, h::retire),
        Handler::BringBack => on(filter, h::bring_back),
    }
}

fn filter_of(method: &axum::http::Method) -> MethodFilter {
    match *method {
        axum::http::Method::POST => MethodFilter::POST,
        axum::http::Method::PUT => MethodFilter::PUT,
        axum::http::Method::DELETE => MethodFilter::DELETE,
        _ => MethodFilter::GET,
    }
}

/// Every route of [`access::routes`], behind the authorization layer.
pub fn router(app: AppState) -> Router {
    let mut by_path: Vec<(&'static str, MethodRouter<AppState>)> = Vec::new();
    for route in access::routes() {
        let added = method_router(route.handler, filter_of(&route.method));
        match by_path.iter_mut().find(|(p, _)| *p == route.path) {
            Some((_, existing)) => *existing = std::mem::take(existing).merge(added),
            None => by_path.push((route.path, added)),
        }
    }
    let mut router = Router::new();
    for (path, methods) in by_path {
        router = router.route(
            path,
            methods.fallback(|| async {
                ApiError {
                    status: Some(StatusCode::METHOD_NOT_ALLOWED),
                    ..ApiError::new(ErrorCode::BadRequest)
                }
            }),
        );
    }
    router
        .route_layer(middleware::from_fn_with_state(app.clone(), authorize))
        .fallback(|| async { ApiError::new(ErrorCode::NotFound) })
        .layer(middleware::from_fn(guard))
        .with_state(app)
}

/// Looks the matched route up in the access table (default deny), for calls checks the session
/// and its scope, and applies the route's rate limits, all before the handler runs and so before
/// any body is read (finding M6).
async fn authorize(State(app): State<AppState>, request: Request, next: Next) -> Response {
    let pattern = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned());
    let mut response = authorize_inner(app, pattern.clone(), request, next).await;
    if let Some(pattern) = pattern {
        response.extensions_mut().insert(RoutePattern(pattern));
    }
    response
}

/// The matched route pattern, handed from the authorization layer to the log line.
#[derive(Clone)]
struct RoutePattern(String);

async fn authorize_inner(
    app: AppState,
    pattern: Option<String>,
    mut request: Request,
    next: Next,
) -> Response {
    let access = pattern
        .as_deref()
        .and_then(|p| access::route_of(request.method(), p));
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0);
    let ip = client_ip::client_ip(request.headers(), peer, &app.trusted_proxies);
    let (ip_key, net_key) = (client_ip::rate_key(ip), client_ip::net_key(ip));
    let limited = |handler: access::Handler, account: Option<&[u8]>| {
        let keys = ratelimit::RateKeys {
            ip: &ip_key,
            net: &net_key,
            account,
        };
        !ratelimit::check_route(&app.limiter, handler, &keys, app.now_ms() / 1000)
    };
    match access {
        // A known path with a method the table does not name has no handler but the 405
        // fallback; everything else outside the table is refused.
        None if pattern.as_deref().is_some_and(access::is_known_path) => ApiError {
            status: Some(StatusCode::METHOD_NOT_ALLOWED),
            ..ApiError::new(ErrorCode::BadRequest)
        }
        .into_response(),
        None => ApiError::new(ErrorCode::Forbidden).into_response(),
        Some((Access::Public, handler)) => {
            if limited(handler, None) {
                return ApiError::new(ErrorCode::RateLimited).into_response();
            }
            next.run(request).await
        }
        Some((Access::Call(call), handler)) => {
            let Some(token) = extract::bearer(request.headers()) else {
                return ApiError::new(ErrorCode::Unauthorized).into_response();
            };
            let session = match sessions::authenticate(&app, &token).await {
                Ok(session) => session,
                Err(error) => return error.into_response(),
            };
            if session.scope.require(call).is_err() {
                return ApiError::new(ErrorCode::Forbidden).into_response();
            }
            if limited(handler, Some(session.account.as_bytes().as_slice())) {
                return ApiError::new(ErrorCode::RateLimited).into_response();
            }
            request.extensions_mut().insert(session);
            next.run(request).await
        }
    }
}

/// Security headers on every reply and one log line per request.
async fn guard(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let started = std::time::Instant::now();
    let mut response = next.run(request).await;
    let status = response.status().as_u16();
    let route = response
        .extensions()
        .get::<RoutePattern>()
        .map(|p| p.0.clone());
    if route.as_deref() != Some(hangar_drive_protocol::HEALTH_PATH) {
        tracing::info!(
            %method,
            route = route.as_deref().unwrap_or("unmatched"),
            status,
            ms = started.elapsed().as_millis() as u64,
            "request"
        );
    }
    set_headers(response.headers_mut());
    response
}

fn set_headers(headers: &mut HeaderMap) {
    let set = |headers: &mut HeaderMap, name: &'static str, value: &'static str| {
        headers.insert(name, HeaderValue::from_static(value));
    };
    set(headers, "x-content-type-options", "nosniff");
    set(headers, "x-frame-options", "DENY");
    set(headers, "referrer-policy", "no-referrer");
    set(headers, "cross-origin-resource-policy", "same-origin");
    set(
        headers,
        "content-security-policy",
        "default-src 'none'; frame-ancestors 'none'",
    );
    if !headers.contains_key("cache-control") {
        set(headers, "cache-control", "no-store");
    }
}
