//! The invite link the admin CLI prints and the static `/join` page a browser shows for it.
//!
//! The link is `<public URL>join#<token>.<server ID>[.<pin>]`, the form the app's link parser
//! reads (`crates/hangar-drive-sync/src/links.rs`): the 16 byte token in base64url (22
//! characters), the server ID in lowercase hex (32), and for a self-signed setup the SHA-256 of
//! the server's SubjectPublicKeyInfo in base64url (43). Everything after `#` stays in the
//! browser: a fragment is never sent to a server or a proxy, so the token lands in no access
//! log, and the `/join` page reads it with its own script only to build the app's deep link
//! `hangar-drive://join#<invite>@<public URL>`.

use hangar_drive_protocol::ids::{base64url, InviteToken, ServerId};

/// The full invite link; it carries the token, so the caller prints it once and keeps no copy.
/// `public_url` is [`crate::config::Config::public_url`] (the client's
/// serialization, ending in `/`).
pub fn invite_link(
    public_url: &str,
    token: &InviteToken,
    server: &ServerId,
    pin: Option<&[u8; 32]>,
) -> String {
    let base = public_url.trim_end_matches('/');
    let mut link = format!(
        "{base}/join#{}.{}",
        token.expose_base64url().as_str(),
        server.to_hex()
    );
    if let Some(pin) = pin {
        link.push('.');
        link.push_str(&base64url(pin));
    }
    link
}

/// The page under `/join`: plain English, no inline script or style, no third-party resource.
pub const JOIN_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Join Hangar Drive</title>
<link rel="stylesheet" href="join.css">
<script src="join.js" defer></script>
</head>
<body>
<main>
<h1>Open this invite in Hangar Drive</h1>
<p>This is an invite to a Hangar Drive server. Your files are synced by the Hangar Drive app on your computer, not in the browser.</p>
<p><a id="open" class="button" href="hangar-drive://join" hidden>Open in Hangar Drive</a></p>
<p id="missing" hidden>This link has no invite in it. Ask the operator of your server for the full link.</p>
<p>If the button does nothing, install Hangar Drive, choose "Start with an invite link" and paste the whole link from your browser's address bar.</p>
<noscript><p>Without JavaScript, copy the whole link from the address bar and paste it into Hangar Drive.</p></noscript>
</main>
</body>
</html>
"#;

/// The page's script: builds the deep link from the fragment in the browser. It only reads
/// `location`, checks the fragment's characters and length, and sets `href` and `hidden`;
/// nothing is written as markup.
pub const JOIN_JS: &str = r#""use strict";
document.addEventListener("DOMContentLoaded", function () {
  var fragment = location.hash.slice(1);
  var open = document.getElementById("open");
  var missing = document.getElementById("missing");
  // <token>[.<server ID>[.<pin>]]: base64url, hex and dots only, a few hundred characters.
  var valid = /^[A-Za-z0-9_-]{22}(\.[0-9a-f]{32}(\.[A-Za-z0-9_-]{43})?)?$/.test(fragment);
  if (!valid || !open || !missing) {
    if (missing) missing.hidden = false;
    return;
  }
  var path = location.pathname.replace(/\/join\/?$/, "/");
  var base = location.origin + path;
  open.href = "hangar-drive://join#" + fragment + "@" + base;
  open.hidden = false;
});
"#;

/// The page's style sheet.
pub const JOIN_CSS: &str =
    "body{font-family:system-ui,sans-serif;max-width:36rem;margin:3rem auto;\
padding:0 1rem;line-height:1.5;color:#1f2328;background:#fff}\
@media (prefers-color-scheme:dark){body{color:#d6dde6;background:#0e1116}}\
.button{display:inline-block;padding:.6rem 1.2rem;border-radius:.4rem;background:#2f6feb;\
color:#fff;text-decoration:none;font-weight:600}\n";

/// The CSP of the three `/join` replies: the page's own script and style, nothing else.
pub const JOIN_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_link_has_the_form_the_app_reads() {
        let token = InviteToken::from_bytes([9; 16]);
        let server = ServerId::from_bytes([0x5e; 16]);
        let plain = invite_link("https://drive.example.org/", &token, &server, None);
        assert_eq!(
            plain.as_str(),
            "https://drive.example.org/join#CQkJCQkJCQkJCQkJCQkJCQ.5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"
        );
        let pinned = invite_link(
            "https://example.org/drive/",
            &token,
            &server,
            Some(&[7; 32]),
        );
        assert_eq!(
            pinned.as_str(),
            "https://example.org/drive/join#CQkJCQkJCQkJCQkJCQkJCQ.5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e\
             .BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
        );
        let fragment = pinned.split_once('#').map(|(_, f)| f).unwrap_or("");
        let parts: Vec<&str> = fragment.split('.').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            [22, 32, 43]
        );
    }

    #[test]
    fn the_page_has_no_inline_script_or_style() {
        assert!(!JOIN_HTML.contains("<script>") && !JOIN_HTML.contains("<style"));
        assert!(!JOIN_HTML.contains(" style=") && !JOIN_HTML.contains("onclick"));
        assert!(!JOIN_JS.contains("innerHTML") && !JOIN_JS.contains("document.write"));
        assert!(!JOIN_HTML.contains("http://") && !JOIN_HTML.contains("https://"));
    }
}
