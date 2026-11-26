//! TLS in the server and the admin CLI of the same binary. The certificate under
//! `tests/testdata` is a self-signed test certificate for `localhost`, made only for these tests.

mod common;

use std::process::Command;
use std::sync::Arc;

use common::*;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn testdata(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/testdata")
        .join(name)
}

#[test]
fn the_spki_pin_of_a_certificate_matches_openssl() {
    let expected = std::fs::read_to_string(testdata("spki-sha256.txt")).unwrap();
    let pin = hangar_drive_server::tls::spki_pin_of_file(&testdata("cert.pem")).unwrap();
    let hex: String = pin.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, expected.trim());
    assert!(hangar_drive_server::tls::spki_pin_of_file(&testdata("key.pem")).is_err());
}

/// Accepts the test certificate whatever it is, but still checks the handshake signatures.
#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[tokio::test]
async fn the_server_terminates_tls_1_3_itself_when_configured() {
    let mut server = TestServer::with(
        "tls",
        Options {
            tls: true,
            ..Options::default()
        },
    )
    .await;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(server.addr).await.unwrap();
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut reply = Vec::new();
    let _ = tls.read_to_end(&mut reply).await;
    assert!(
        String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&reply)
    );
    // A server that terminates TLS itself tells browsers to stay on https (overall review,
    // info); behind a proxy the proxy sets it, so a plain server does not (`overall_review.rs`).
    assert!(
        String::from_utf8_lossy(&reply)
            .to_ascii_lowercase()
            .contains("strict-transport-security: max-age=31536000\r\n"),
        "{}",
        String::from_utf8_lossy(&reply)
    );
    // Plain HTTP on the TLS port gets no HTTP answer.
    let plain = raw_plain(server.addr).await;
    assert!(!plain.starts_with("HTTP/1.1 200"));
    server.stop().await.unwrap();
}

async fn raw_plain(addr: std::net::SocketAddr) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let _ = stream
        .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await;
    let mut reply = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut reply),
    )
    .await;
    String::from_utf8_lossy(&reply).into_owned()
}

fn cli(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    cli_with(dir, args, None)
}

fn cli_with(
    dir: &std::path::Path,
    args: &[&str],
    public_url: Option<&str>,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hangar-drive-server"));
    command
        .args(args)
        .env("HANGAR_DRIVE_DATA_DIR", dir)
        .env_remove("HANGAR_DRIVE_TLS_CERT")
        .env_remove("HANGAR_DRIVE_TLS_KEY")
        .env_remove("HANGAR_DRIVE_PUBLIC_URL")
        .stdin(std::process::Stdio::null());
    if let Some(url) = public_url {
        command.env("HANGAR_DRIVE_PUBLIC_URL", url);
    }
    command.output().unwrap()
}

/// Token, server ID and pin of an invite link `<base>join#<token>.<server>[.<pin>]`.
fn invite_parts(link: &str, base: &str) -> Vec<String> {
    let fragment = link
        .strip_prefix(&format!("{base}join#"))
        .unwrap_or_else(|| panic!("{link}"));
    fragment.split('.').map(str::to_owned).collect()
}

#[test]
fn the_admin_cli_creates_invites_prints_key_numbers_and_refuses_unconfirmed_purges() {
    let dir = data_dir("cli");
    // Without the public address the server does not start and no invite is made at all.
    let refused = cli(&dir, &["serve"]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("HANGAR_DRIVE_PUBLIC_URL=https://"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let refused = cli(&dir, &["invite"]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("HANGAR_DRIVE_PUBLIC_URL"));
    let base = "https://drive.example.org/";
    let out = cli_with(
        &dir,
        &["invite", "--days", "3"],
        Some("https://DRIVE.example.org"),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let link = String::from_utf8(out.stdout).unwrap();
    let parts = invite_parts(link.trim(), base);
    assert_eq!(parts.len(), 2, "no pin without --pin: {link}");
    assert!(
        hangar_drive_protocol::ids::InviteToken::from_base64url(&parts[0]).is_ok(),
        "{link}"
    );
    assert!(hangar_drive_protocol::ids::ServerId::from_hex(&parts[1]).is_ok());
    assert!(String::from_utf8_lossy(&out.stderr).contains("valid for 3 days"));
    assert!(!cli_with(&dir, &["invite", "--days", "0"], Some(base))
        .status
        .success());
    assert!(
        !cli_with(&dir, &["invite"], Some("http://drive.example.org/"))
            .status
            .success()
    );
    let cert = testdata("cert.pem");
    let pinned = cli_with(
        &dir,
        &["invite", "--pin", "--cert", cert.to_str().unwrap()],
        Some("https://example.org/drive"),
    );
    assert!(
        pinned.status.success(),
        "{}",
        String::from_utf8_lossy(&pinned.stderr)
    );
    let link = String::from_utf8(pinned.stdout).unwrap();
    let parts = invite_parts(link.trim(), "https://example.org/drive/");
    let pin = hangar_drive_server::tls::spki_pin_of_file(&cert).unwrap();
    assert_eq!(parts.len(), 3, "{link}");
    assert_eq!(parts[2], hangar_drive_protocol::ids::base64url(&pin));
    assert!(!cli_with(
        &dir,
        &["invite", "--cert", cert.to_str().unwrap()],
        Some(base)
    )
    .status
    .success());

    let spki = std::fs::read_to_string(testdata("spki-sha256.txt")).unwrap();
    let by_hash = cli(&dir, &["server-key-number", "--spki", spki.trim()]);
    assert!(
        by_hash.status.success(),
        "{}",
        String::from_utf8_lossy(&by_hash.stderr)
    );
    let number = String::from_utf8(by_hash.stdout).unwrap();
    let groups: Vec<&str> = number.split_whitespace().collect();
    assert_eq!(groups.len(), 6, "{number}");
    assert!(groups
        .iter()
        .all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())));
    let cert = testdata("cert.pem");
    let by_cert = cli(
        &dir,
        &["server-key-number", "--cert", cert.to_str().unwrap()],
    );
    assert_eq!(
        String::from_utf8(by_cert.stdout).unwrap(),
        number,
        "the same key, the same number"
    );
    assert!(!cli(&dir, &["server-key-number", "--spki", "abc"])
        .status
        .success());

    let status = cli(&dir, &["status"]);
    assert!(status.status.success());
    let text = String::from_utf8(status.stdout).unwrap();
    assert!(
        text.contains("open invites: 2") && text.contains("accounts: 0"),
        "{text}"
    );

    let account = "11".repeat(16);
    let purge = cli(&dir, &["purge", "account", &account]);
    assert!(!purge.status.success());
    let pins = cli(&dir, &["pin", "list"]);
    assert!(pins.status.success());
    assert!(!cli(&dir, &["frobnicate"]).status.success());
    let gc = cli(&dir, &["gc"]);
    assert!(
        gc.status.success(),
        "{}",
        String::from_utf8_lossy(&gc.stderr)
    );
}
