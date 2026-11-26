//! Optional TLS in the server (ADR 0001, section 6): TLS 1.3 only, rustls with ring, a PEM
//! certificate chain and key from files. The default deployment terminates TLS at a reverse
//! proxy instead.
//!
//! Also the server key number: the CLI reads the SubjectPublicKeyInfo of a certificate and
//! prints `hangar_drive_crypto::identity::server_key_number` of its SHA-256, so the operator
//! can compare it with the number a device shows.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("certificate file {0}: {1}")]
    Cert(String, String),
    #[error("key file {0}: {1}")]
    Key(String, String),
    #[error("the certificate file holds no certificate")]
    NoCert,
    #[error("TLS setup: {0}")]
    Config(String),
    #[error("the certificate is not valid DER X.509")]
    NotX509,
}

/// Reads every certificate of a PEM file, leaf first.
pub fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certs: Vec<_> = CertificateDer::pem_file_iter(path)
        .map_err(|e| TlsError::Cert(path.display().to_string(), e.to_string()))?
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Cert(path.display().to_string(), e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsError::NoCert);
    }
    Ok(certs)
}

/// The rustls server configuration for `cert` and `key` (PEM), TLS 1.3 only, HTTP/1.1.
pub fn server_config(cert: &Path, key: &Path) -> Result<Arc<rustls::ServerConfig>, TlsError> {
    let certs = read_certs(cert)?;
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| TlsError::Key(key.display().to_string(), e.to_string()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::Config(e.to_string()))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Reads one DER element at the start of `input`: (tag, whole element, contents, rest).
/// Tag, whole element, contents and what follows.
type Element<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

fn der_element(input: &[u8]) -> Option<Element<'_>> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (len, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | usize::from(*input.get(2 + i)?);
        }
        (len, 2 + count)
    };
    let end = header.checked_add(len)?;
    if end > input.len() {
        return None;
    }
    Some((tag, &input[..end], &input[header..end], &input[end..]))
}

const SEQUENCE: u8 = 0x30;

/// The DER of the SubjectPublicKeyInfo of an X.509 certificate (RFC 5280, section 4.1):
/// Certificate is a SEQUENCE of tbsCertificate, ...; tbsCertificate is a SEQUENCE of an
/// optional explicit version [0], serialNumber, signature, issuer, validity, subject and then
/// subjectPublicKeyInfo.
pub fn spki_of_cert(der: &[u8]) -> Result<&[u8], TlsError> {
    let (tag, _, cert, _) = der_element(der).ok_or(TlsError::NotX509)?;
    if tag != SEQUENCE {
        return Err(TlsError::NotX509);
    }
    let (tag, _, tbs, _) = der_element(cert).ok_or(TlsError::NotX509)?;
    if tag != SEQUENCE {
        return Err(TlsError::NotX509);
    }
    let mut rest = tbs;
    let (tag, _, _, after) = der_element(rest).ok_or(TlsError::NotX509)?;
    if tag == 0xa0 {
        rest = after;
    }
    // serialNumber, signature, issuer, validity, subject.
    for _ in 0..5 {
        let (_, _, _, after) = der_element(rest).ok_or(TlsError::NotX509)?;
        rest = after;
    }
    let (tag, spki, _, _) = der_element(rest).ok_or(TlsError::NotX509)?;
    if tag != SEQUENCE {
        return Err(TlsError::NotX509);
    }
    Ok(spki)
}

/// The SPKI pin (SHA-256 of the SPKI) of the leaf certificate of a PEM file.
pub fn spki_pin_of_file(path: &Path) -> Result<[u8; 32], TlsError> {
    let certs = read_certs(path)?;
    let leaf = certs.first().ok_or(TlsError::NoCert)?;
    Ok(hangar_drive_crypto::identity::spki_pin(spki_of_cert(
        leaf.as_ref(),
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_lengths() {
        assert_eq!(der_element(&[0x30, 0x00]).map(|e| e.2.len()), Some(0));
        let long: Vec<u8> = [vec![0x04, 0x81, 0x80], vec![7; 0x80]].concat();
        assert_eq!(der_element(&long).map(|e| e.2.len()), Some(0x80));
        assert!(der_element(&[0x04, 0x05, 1]).is_none());
        assert!(der_element(&[0x04, 0x80]).is_none());
        assert!(spki_of_cert(b"not a certificate").is_err());
    }
}
