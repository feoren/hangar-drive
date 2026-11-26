//! Helpers every module shares: the protocol's `field(x)` framing, constant-time comparison,
//! HKDF-SHA256, HMAC-SHA-256 and SHA-256 over framed input.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub(crate) use hangar_drive_protocol::framing::{framed, length_prefix, Reader, Writer};

pub(crate) type HmacSha256 = Hmac<Sha256>;

/// Equality of secret bytes in constant time (`subtle`), so the time taken does not reveal how
/// many leading bytes match. Only the length, which is public here, may end it early.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(a.ct_eq(b))
}

/// HKDF-SHA256 without salt: `N` bytes of `ikm` under `info` (RFC 5869). The pseudorandom key
/// is wiped after use. Fails only for outputs longer than 8160 bytes, which no caller asks for.
pub(crate) fn hkdf<const N: usize>(ikm: &[u8], info: &[u8]) -> Option<Zeroizing<[u8; N]>> {
    let (mut prk, hkdf) = Hkdf::<Sha256>::extract(None, ikm);
    prk.as_mut_slice().zeroize();
    let mut okm = Zeroizing::new([0u8; N]);
    hkdf.expand(info, okm.as_mut()).ok()?;
    Some(okm)
}

/// A keyed HMAC-SHA-256 state. Any key length is valid for HMAC.
pub(crate) fn hmac(key: &[u8]) -> Option<HmacSha256> {
    <HmacSha256 as KeyInit>::new_from_slice(key).ok()
}

/// SHA-256 of `field(p1) || field(p2) || ...`.
pub(crate) fn sha256_framed(parts: &[&[u8]]) -> [u8; 32] {
    let mut sha = Sha256::new();
    for part in parts {
        sha.update(length_prefix(part.len()));
        sha.update(part);
    }
    sha.finalize().into()
}

/// SHA-256 of raw bytes.
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Updates a MAC with `field(part)` without copying `part`.
pub(crate) fn mac_field(mac: &mut HmacSha256, part: &[u8]) {
    mac.update(&length_prefix(part.len()));
    mac.update(part);
}

/// The MAC's 32-byte tag.
pub(crate) fn mac_finish(mac: HmacSha256) -> [u8; 32] {
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn hkdf_matches_rfc_5869_test_3() {
        // RFC 5869, test case 3: no salt, no info.
        let okm = hkdf::<42>(&[0x0b; 22], &[]).unwrap();
        assert_eq!(
            okm.to_vec(),
            hex(concat!(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d",
                "9d201395faa4b61a96c8"
            ))
        );
    }

    #[test]
    fn hmac_matches_rfc_4231_test_2() {
        let mut mac = hmac(b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        assert_eq!(
            mac_finish(mac).to_vec(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn framed_hash_and_mac_agree_with_the_framing() {
        let parts: [&[u8]; 2] = [b"ab", b""];
        assert_eq!(sha256_framed(&parts), sha256(&framed(&parts)));
        let mut a = hmac(b"k").unwrap();
        mac_field(&mut a, b"ab");
        let mut b = hmac(b"k").unwrap();
        b.update(&framed(&[b"ab"]));
        assert_eq!(mac_finish(a), mac_finish(b));
    }

    #[test]
    fn constant_time_eq_compares() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
