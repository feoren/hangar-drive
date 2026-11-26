//! The print window of the recovery sheet (security review M3). The page never travels as a
//! `data:` URL, which the WebView could keep in its history or session state: it is served once
//! from memory over the app's own scheme `hangar-print` under a random path, and dropped (its
//! text wiped) the moment it is served. The window runs in an incognito WebView (no profile data
//! on disk), may navigate nowhere but that one page, and has no capability, so its page cannot
//! reach a command.
//!
//! The response body is a copy of the page that the WebView owns afterwards; this module cannot
//! wipe that copy, only its own.

use std::sync::Mutex;

use tauri::http::{header, Response, StatusCode};
use tauri::{Manager as _, Runtime, Url};
use zeroize::Zeroizing;

/// The scheme of the print page.
pub const SCHEME: &str = "hangar-print";
/// The label of the print window.
pub const WINDOW: &str = "recovery-sheet";
/// The page's own policy: nothing but its inline style and the QR code's inline SVG.
const CSP: &str =
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'";

/// The one page waiting to be served: its random path and its text.
#[derive(Default)]
pub struct PrintPage(Mutex<Option<(String, Zeroizing<String>)>>);

impl PrintPage {
    /// Keeps `html` for one request of `/<token>`; a page that was never fetched is dropped.
    pub fn put(&self, token: String, html: Zeroizing<String>) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some((token, html));
        }
    }

    /// The page for `path`, once: the slot is emptied whether or not the path matches, so a
    /// guess costs the page instead of revealing it twice.
    pub fn take(&self, path: &str) -> Option<Zeroizing<String>> {
        let mut slot = self.0.lock().ok()?;
        let (token, html) = slot.take()?;
        (path.strip_prefix('/') == Some(token.as_str())).then_some(html)
    }
}

/// The URL of the page `token` on this platform: `http://hangar-print.localhost/<token>` on
/// Windows (WebView2 maps custom schemes to that form), `hangar-print://localhost/<token>`
/// elsewhere (Tauri's `register_uri_scheme_protocol` documentation).
pub fn page_url(token: &str) -> Option<Url> {
    let text = if cfg!(windows) {
        format!("http://{SCHEME}.localhost/{token}")
    } else {
        format!("{SCHEME}://localhost/{token}")
    };
    Url::parse(&text).ok()
}

/// Whether the print window may load `url`: only a page of its own scheme.
pub fn may_navigate(url: &Url) -> bool {
    if cfg!(windows) {
        url.scheme() == "http" && url.host_str() == Some(&format!("{SCHEME}.localhost"))
    } else {
        url.scheme() == SCHEME && url.host_str() == Some("localhost")
    }
}

/// The scheme's handler: the waiting page for the print window, once; 404 for everything else.
pub fn respond<R: Runtime>(
    ctx: tauri::UriSchemeContext<'_, R>,
    request: tauri::http::Request<Vec<u8>>,
) -> Response<Vec<u8>> {
    let page = (ctx.webview_label() == WINDOW)
        .then(|| {
            ctx.app_handle()
                .state::<PrintPage>()
                .take(request.uri().path())
        })
        .flatten();
    let built = match page {
        Some(html) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CONTENT_SECURITY_POLICY, CSP)
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::REFERRER_POLICY, "no-referrer")
            .body(html.as_bytes().to_vec()),
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Vec::new()),
    };
    built.unwrap_or_else(|_| Response::new(Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_is_served_once_and_only_under_its_path() {
        let page = PrintPage::default();
        page.put("abc".into(), Zeroizing::new("<p>sheet</p>".into()));
        assert_eq!(
            page.take("/abc").as_deref().map(String::as_str),
            Some("<p>sheet</p>")
        );
        assert_eq!(page.take("/abc"), None, "served once");
        page.put("abc".into(), Zeroizing::new("x".into()));
        assert_eq!(page.take("/guess"), None);
        assert_eq!(page.take("/abc"), None, "a wrong guess drops it");
    }

    #[test]
    fn the_window_may_only_load_its_own_scheme() {
        let own = page_url("t0k3n").unwrap();
        assert!(may_navigate(&own));
        for other in [
            "https://drive.example/",
            "http://tauri.localhost/",
            "data:text/html,x",
            "file:///C:/x.html",
            "http://hangar-print.localhost.evil/",
        ] {
            assert!(!may_navigate(&Url::parse(other).unwrap()), "{other}");
        }
    }
}
