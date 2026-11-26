//! The links of the UX concept (open point C; [ux-concept, 4.2 to 4.4]):
//!
//! | Link | Form | Carries |
//! | --- | --- | --- |
//! | Invite | `https://<server>[/<base>]/join#<invite>` | the server address, the invite token, optionally the server ID and the SPKI pin |
//! | Invite, deep link | `hangar-drive://join#<invite>@<server URL>` | the same; the server's `/join` page opens it |
//! | Pairing | `hangar-drive://pair#<offer>` | the signed pairing offer, base64url |
//! | Recovery | `hangar-drive://recover#<sheet>` | the recovery sheet's server address, server ID, account ID, genesis anchor and anchor tag, never the code |
//!
//! `<invite>` is `<token>[.<server ID>[.<pin>]]`: the 16 byte token in base64url (22
//! characters), the server ID in lowercase hex (32), the SHA-256 of the server's
//! SubjectPublicKeyInfo in base64url (43). `<sheet>` is base64url of the recovery sheet's bytes,
//! version 3 (`hangar_drive_crypto::recovery::RecoverySheet`: account ID, server ID, the genesis
//! anchor, the code's anchor tag over both, the optional SPKI pin and the server URL).
//!
//! Every parser is strict: surrounding white space is trimmed and nothing else is forgiven.
//! No query, no user info, no white space or second `#` inside, canonical base64url and hex
//! only, the server URL passes the same check as every server address
//! (`hangar_drive_crypto::pairing::parse_server_url`: `https`, or `http` to `localhost`), and a
//! link is at most [`MAX_LINK_LEN`] characters. Anything else is [`LinkError`], never a
//! partly read link.

pub use hangar_drive_crypto::recovery::RecoverySheet;
use hangar_drive_crypto::recovery::SheetError;
use hangar_drive_protocol::ids::{base64url, from_base64url, InviteToken, ServerId};
use reqwest::Url;

/// The longest link the parsers read.
pub const MAX_LINK_LEN: usize = 8192;
/// The deep link scheme.
pub const SCHEME: &str = "hangar-drive";

/// Why a text is not a link of the expected kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    /// Not this kind of link at all.
    #[error("not a link of this kind")]
    NotALink,
    /// The right kind, but a part does not decode or is not allowed.
    #[error("the link is damaged")]
    Malformed,
    /// The server address is not allowed (not `https`, or `http` to another host).
    #[error("the server address is not allowed")]
    Insecure,
}

/// An operator's invite.
#[derive(Debug, Clone)]
pub struct InviteLink {
    /// The server's base URL.
    pub server_url: Url,
    /// The single-use invite.
    pub token: InviteToken,
    /// The server ID, if the link names it.
    pub server: Option<ServerId>,
    /// The SPKI pin of a self-signed server, if the link names it.
    pub pin: Option<[u8; 32]>,
}

impl PartialEq for InviteLink {
    fn eq(&self, other: &Self) -> bool {
        // The token has no `PartialEq` of its own (it is a secret); comparing two links is only
        // needed by tests and the app's "same invite" check.
        self.server_url == other.server_url
            && self.server == other.server
            && self.pin == other.pin
            && self.token.expose_base64url().as_str() == other.token.expose_base64url().as_str()
    }
}

fn clean(text: &str) -> Result<&str, LinkError> {
    let text = text.trim();
    if text.len() > MAX_LINK_LEN {
        return Err(LinkError::Malformed);
    }
    if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(LinkError::Malformed);
    }
    Ok(text)
}

fn server_url(text: &str) -> Result<Url, LinkError> {
    hangar_drive_crypto::pairing::parse_server_url(text).map_err(|_| LinkError::Insecure)
}

/// The fragment of a deep link `hangar-drive://<kind>#<fragment>`.
fn deep_fragment<'a>(text: &'a str, kind: &str) -> Result<&'a str, LinkError> {
    let prefix = format!("{SCHEME}://{kind}#");
    let rest = text
        .get(..prefix.len())
        .filter(|p| p.eq_ignore_ascii_case(&prefix))
        .map(|_| &text[prefix.len()..])
        .ok_or(LinkError::NotALink)?;
    if rest.is_empty() || rest.contains('#') {
        return Err(LinkError::Malformed);
    }
    Ok(rest)
}

/// The token, server ID and pin of an invite fragment.
type InviteParts = (InviteToken, Option<ServerId>, Option<[u8; 32]>);

fn parse_invite_part(text: &str) -> Result<InviteParts, LinkError> {
    let mut parts = text.split('.');
    let token = parts
        .next()
        .and_then(|t| InviteToken::from_base64url(t).ok())
        .ok_or(LinkError::Malformed)?;
    let server = match parts.next() {
        None => None,
        Some(s) => Some(ServerId::from_hex(s).map_err(|_| LinkError::Malformed)?),
    };
    let pin = match parts.next() {
        None => None,
        Some(p) => Some(
            from_base64url(p)
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .ok_or(LinkError::Malformed)?,
        ),
    };
    if parts.next().is_some() {
        return Err(LinkError::Malformed);
    }
    Ok((token, server, pin))
}

fn invite_part(invite: &InviteLink) -> String {
    let mut out = invite.token.expose_base64url().as_str().to_owned();
    if let Some(server) = invite.server {
        out.push('.');
        out.push_str(&server.to_hex());
        if let Some(pin) = invite.pin {
            out.push('.');
            out.push_str(&base64url(&pin));
        }
    }
    out
}

/// Reads an invite in either form (module docs).
pub fn parse_invite(text: &str) -> Result<InviteLink, LinkError> {
    let text = clean(text)?;
    if let Ok(fragment) = deep_fragment(text, "join") {
        let (invite, url) = fragment
            .split_once('@')
            .filter(|(_, url)| !url.is_empty())
            .ok_or(LinkError::Malformed)?;
        let (token, server, pin) = parse_invite_part(invite)?;
        return Ok(InviteLink {
            server_url: server_url(url)?,
            token,
            server,
            pin,
        });
    }
    let (address, fragment) = text.split_once('#').ok_or(LinkError::NotALink)?;
    if fragment.is_empty() || fragment.contains('#') {
        return Err(LinkError::Malformed);
    }
    let url = Url::parse(address).map_err(|_| LinkError::NotALink)?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(LinkError::NotALink);
    }
    if url.query().is_some() || !url.username().is_empty() || url.password().is_some() {
        return Err(LinkError::Malformed);
    }
    let base_path = url
        .path()
        .strip_suffix("/join")
        .ok_or(LinkError::NotALink)?
        .to_owned();
    let mut base = url.clone();
    // The base URL always ends with a slash, as `Url` writes a bare host.
    base.set_path(&format!("{base_path}/"));
    let (token, server, pin) = parse_invite_part(fragment)?;
    Ok(InviteLink {
        server_url: server_url(base.as_str())?,
        token,
        server,
        pin,
    })
}

/// The `https` form of an invite: `<server URL>/join#<invite>`.
pub fn invite_link(invite: &InviteLink) -> String {
    format!(
        "{}/join#{}",
        invite.server_url.as_str().trim_end_matches('/'),
        invite_part(invite)
    )
}

/// The deep link form of an invite: `hangar-drive://join#<invite>@<server URL>`.
pub fn invite_deep_link(invite: &InviteLink) -> String {
    format!(
        "{SCHEME}://join#{}@{}",
        invite_part(invite),
        invite.server_url.as_str()
    )
}

/// The pairing link of an offer's bytes.
pub fn pairing_link(offer: &[u8]) -> String {
    format!("{SCHEME}://pair#{}", base64url(offer))
}

/// The offer bytes of a pairing link (the offer itself is decoded and verified by the crypto
/// crate).
pub fn parse_pairing_link(text: &str) -> Result<Vec<u8>, LinkError> {
    let text = clean(text)?;
    from_base64url(deep_fragment(text, "pair")?).ok_or(LinkError::Malformed)
}

/// The recovery link of a sheet; the code is never part of it.
pub fn recovery_link(sheet: &RecoverySheet) -> String {
    format!("{SCHEME}://recover#{}", base64url(&sheet.encode()))
}

/// The sheet of a recovery link.
pub fn parse_recovery_link(text: &str) -> Result<RecoverySheet, LinkError> {
    let text = clean(text)?;
    let bytes = from_base64url(deep_fragment(text, "recover")?).ok_or(LinkError::Malformed)?;
    RecoverySheet::decode(&bytes).map_err(|e| match e {
        SheetError::Insecure => LinkError::Insecure,
        SheetError::Malformed | SheetError::Version(_) => LinkError::Malformed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> InviteToken {
        InviteToken::from_bytes([9; 16])
    }

    fn server() -> ServerId {
        ServerId::from_bytes([0x5e; 16])
    }

    #[test]
    fn invites_round_trip_in_both_forms() {
        for (url, server, pin) in [
            ("https://drive.example.org/", None, None),
            ("https://example.org/drive/", Some(server()), None),
            ("http://localhost:8080/", Some(server()), Some([7u8; 32])),
        ] {
            let invite = InviteLink {
                server_url: Url::parse(url).unwrap(),
                token: token(),
                server,
                pin,
            };
            assert_eq!(parse_invite(&invite_link(&invite)).unwrap(), invite);
            assert_eq!(parse_invite(&invite_deep_link(&invite)).unwrap(), invite);
        }
        let plain = parse_invite(&format!(
            "  https://drive.example.org/join#{}\n",
            base64url(&[9; 16])
        ))
        .unwrap();
        assert_eq!(plain.server_url.as_str(), "https://drive.example.org/");
        assert_eq!(plain.server, None);
    }

    #[test]
    fn invites_are_parsed_strictly() {
        let t = base64url(&[9; 16]);
        let s = server().to_hex();
        for bad in [
            format!("https://drive.example.org/invite#{t}"),
            "https://drive.example.org/join".to_owned(),
            format!("ftp://drive.example.org/join#{t}"),
            "nonsense".to_owned(),
        ] {
            assert_eq!(parse_invite(&bad), Err(LinkError::NotALink), "{bad}");
        }
        for bad in [
            "https://drive.example.org/join#".to_owned(),
            format!("https://drive.example.org/join#{t}#x"),
            format!("https://drive.example.org/join?x=1#{t}"),
            format!("https://user@drive.example.org/join#{t}"),
            format!("https://drive.example.org/join#{t}="),
            format!("https://drive.example.org/join#{t}.{}", s.to_uppercase()),
            format!("https://drive.example.org/join#{t}.{s}.short"),
            format!(
                "https://drive.example.org/join#{t}.{s}.{}.x",
                base64url(&[1; 32])
            ),
            format!("https://drive.example.org/join# {t}"),
            format!("hangar-drive://join#{t}"),
            format!("hangar-drive://join#{t}@"),
            "x".repeat(MAX_LINK_LEN + 1),
        ] {
            assert_eq!(parse_invite(&bad), Err(LinkError::Malformed), "{bad}");
        }
        assert_eq!(
            parse_invite(&format!("http://drive.example.org/join#{t}")),
            Err(LinkError::Insecure)
        );
        assert_eq!(
            parse_invite(&format!("hangar-drive://join#{t}@http://evil.example/")),
            Err(LinkError::Insecure)
        );
    }

    #[test]
    fn pairing_links_round_trip_and_refuse_other_forms() {
        let offer = vec![1u8, 2, 3, 250];
        let link = pairing_link(&offer);
        assert!(link.starts_with("hangar-drive://pair#"));
        assert_eq!(parse_pairing_link(&link).unwrap(), offer);
        assert_eq!(
            parse_pairing_link(&format!(" {link} ")).unwrap(),
            offer,
            "trimmed"
        );
        assert_eq!(
            parse_pairing_link("hangar-drive:pair#AQID"),
            Err(LinkError::NotALink)
        );
        assert_eq!(
            parse_pairing_link("hangar-drive://join#AQID"),
            Err(LinkError::NotALink)
        );
        for bad in [
            "hangar-drive://pair#",
            "hangar-drive://pair#AQID#",
            "hangar-drive://pair#AQI=",
            "hangar-drive://pair#AQ ID",
        ] {
            assert_eq!(parse_pairing_link(bad), Err(LinkError::Malformed), "{bad}");
        }
    }

    #[test]
    fn recovery_links_carry_the_sheet_without_the_code() {
        use hangar_drive_protocol::ids::{AccountId, LogHash};
        for pin in [None, Some([3u8; 32])] {
            let sheet = RecoverySheet {
                server_url: Url::parse("https://drive.example.org/").unwrap(),
                server: server(),
                account: AccountId::from_bytes([0xac; 16]),
                genesis: LogHash::from_bytes([0x61; 32]),
                pin,
                anchor_tag: [0x7a; 16],
            };
            let link = recovery_link(&sheet);
            assert!(link.starts_with("hangar-drive://recover#"));
            assert_eq!(parse_recovery_link(&link).unwrap(), sheet);
        }
        let mut bytes = vec![3u8];
        bytes.extend_from_slice(&[0xac; 16]);
        bytes.extend_from_slice(&[0x5e; 16]);
        bytes.extend_from_slice(&[0x61; 32]);
        bytes.extend_from_slice(&[0x7a; 16]);
        bytes.push(0);
        let link = |b: &[u8]| format!("hangar-drive://recover#{}", base64url(b));
        let mut insecure = bytes.clone();
        insecure.extend_from_slice(b"http://drive.example.org/");
        assert_eq!(
            parse_recovery_link(&link(&insecure)),
            Err(LinkError::Insecure)
        );
        // Version 1, without the genesis anchor, version 2, without the anchor tag, and a short
        // payload.
        for version in [1, 2] {
            let mut old = bytes.clone();
            old[0] = version;
            old.extend_from_slice(b"https://drive.example.org/");
            assert_eq!(parse_recovery_link(&link(&old)), Err(LinkError::Malformed));
        }
        assert_eq!(
            parse_recovery_link(&link(&bytes[..33])),
            Err(LinkError::Malformed)
        );
        assert_eq!(
            parse_recovery_link("hangar-drive://pair#AQID"),
            Err(LinkError::NotALink)
        );
    }
}
