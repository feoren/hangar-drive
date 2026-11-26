//! The HTTP client of the server API (ADR 0001, section 6) over `reqwest` with rustls.
//!
//! - **TLS 1.3 only.** Plain HTTP only to `localhost` (the URL check of
//!   `hangar_drive_crypto::pairing::parse_server_url`). No switch accepts invalid certificates.
//! - **SPKI pin:** with a pin from a pairing offer, the verifier compares SHA-256 of the server
//!   certificate's SubjectPublicKeyInfo inside the TLS handshake and aborts on a mismatch, so no
//!   request, proof or token is ever sent to a server that identifies itself differently
//!   ([`NetError::PinMismatch`]). The handshake signature is still checked with the pinned key.
//!   Without a pin the platform verifier checks the certificate.
//! - **Sessions:** the client signs in with the device's challenge proof when it has no token
//!   or the server answers `401`, and sends the token only in the `Authorization` header.
//! - **Endpoints** are built by appending the API path to the base URL's path, never with
//!   `Url::join`, which drops a base path (security review N6).
//! - **Retries:** transient failures (no connection, `429`, `5xx`) are retried with exponential
//!   backoff, honouring `Retry-After`; redirects are never followed.
//! - **Limits:** every response body is read with a size limit, so a server cannot make the
//!   app hold an unbounded answer in memory.
//! - **SSE:** [`HttpServer::listen_events`] reads the account's event stream and reports each
//!   new account sequence; the engine polls the feed every 60 s when the stream is down. A line
//!   is read with a limit of 4096 bytes plus its line end and an event's `data` with 4 KiB
//!   (security review M3), so a stream without line ends cannot grow memory. Every read waits
//!   at most three keepalive intervals of the server (25 s each, [`EVENT_READ_TIMEOUT`]); a
//!   silent stream ends with [`NetError::Unreachable`], and [`HttpServer::follow_events`]
//!   connects again with backoff.
//! - **Pin state:** the SPKI pin itself is stored in the local index with the engine's settings
//!   (`engine::Persisted`, key `engine`), not in this client; the client only reports a
//!   mismatch, and the flag is cleared by the next request that succeeds, so a mismatch seen
//!   once (a captive portal, a proxy) does not stick to a healthy connection. With the flag the
//!   client keeps the pin of the key it was shown ([`ServerApi::seen_pin`]), for the server key
//!   number the person compares with the server CLI; it never connects with that key on its
//!   own (ADR 0001, section 6, "Pin rotation").

use std::io::{BufRead, BufReader, Read};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use hangar_drive_protocol::api::{
    self, ChallengeRequest, ChallengeResponse, CommitRequest, CommitResponse, CreateAccountRequest,
    CreateAccountResponse, DeltaPage, ErrorBody, FeedPage, LogAppendRequest, LogAppendResponse,
    LogPage, MissingObjectsRequest, MissingObjectsResponse, PairingRequest, ProofRequest,
    RecordKey, RecordPut, RecordResponse, SequenceEvent, SessionResponse, UploadResponse,
    WrappedKeyResponse,
};
use hangar_drive_protocol::ids::{
    AccountId, Challenge, DeviceId, Epoch, FolderId, ObjectId, PairingId, ServerId, SessionToken,
    Signature,
};
use hangar_drive_protocol::{ServerInfo, HEALTH_PATH, PROTOCOL_VERSION};
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::{Method, StatusCode, Url};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::ports::{NetError, ServerApi};

/// Largest JSON answer the client reads.
const MAX_JSON: u64 = 16 * 1024 * 1024;
/// Longest line of the event stream, without its line end.
pub const MAX_SSE_LINE: usize = 4096;
/// Longest `data` of one event.
pub const MAX_SSE_DATA: usize = 4096;
/// The keepalive interval of the server's event stream
/// (`server/src/http/handlers.rs`, `KEEPALIVE`).
pub const EVENT_KEEPALIVE: Duration = Duration::from_secs(25);
/// How long one read of the event stream may wait: three keepalive intervals.
pub const EVENT_READ_TIMEOUT: Duration = Duration::from_secs(3 * 25);
/// Largest object blob: a manifest of the maximum number of chunks, sealed and padded.
fn max_object() -> u64 {
    hangar_drive_crypto::object::blob_len(hangar_drive_protocol::object::MAX_OBJECT_PLAINTEXT_LEN)
        .map_or(u64::MAX, |n| n as u64)
}

/// When to retry.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Attempts in total (at least 1).
    pub attempts: u32,
    /// The first wait.
    pub base: Duration,
    /// The longest wait.
    pub max: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 4,
            base: Duration::from_millis(250),
            max: Duration::from_secs(8),
        }
    }
}

impl RetryPolicy {
    /// The wait before attempt `attempt` (from 1), doubling from `base` up to `max`.
    pub fn delay(&self, attempt: u32) -> Duration {
        let factor = 1u32
            .checked_shl(attempt.saturating_sub(1))
            .unwrap_or(u32::MAX);
        self.base.saturating_mul(factor).min(self.max)
    }
}

/// Where and how to reach the server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// The base URL, checked by `parse_server_url`.
    pub url: Url,
    /// SHA-256 of the server's SPKI for a self-signed server (from the pairing offer).
    pub pin: Option<[u8; 32]>,
    /// The server ID this device pinned, checked at every sign-in.
    pub server: Option<ServerId>,
    /// Retries of transient failures.
    pub retry: RetryPolicy,
    /// Time limit of one request (not the event stream).
    pub timeout: Duration,
    /// Time limit of one read of the event stream ([`EVENT_READ_TIMEOUT`]).
    pub event_read_timeout: Duration,
}

impl ServerConfig {
    /// A configuration for `url` (refused unless `https`, or `http` to `localhost`).
    pub fn new(url: &str, pin: Option<[u8; 32]>) -> Result<Self, NetError> {
        let url = hangar_drive_crypto::pairing::parse_server_url(url)
            .map_err(|_| NetError::Tls("the server address is not allowed".into()))?;
        Ok(Self {
            url,
            pin,
            server: None,
            retry: RetryPolicy::default(),
            timeout: Duration::from_secs(60),
            event_read_timeout: EVENT_READ_TIMEOUT,
        })
    }
}

/// The URL of API `path` on `base`, keeping a base path (security review N6), with an optional
/// `after` query.
pub fn endpoint(base: &Url, path: &str, after: Option<u64>) -> Url {
    let mut url = base.clone();
    let prefix = base.path().trim_end_matches('/');
    url.set_path(&format!("{prefix}{path}"));
    match after {
        Some(n) => url.set_query(Some(&format!("after={n}"))),
        None => url.set_query(None),
    }
    url.set_fragment(None);
    url
}

/// The pin of a key a server presented instead of the pinned one, shared by the verifier and
/// the client (module docs, "Pin state").
#[derive(Debug, Default)]
pub struct Mismatch(Mutex<Option<[u8; 32]>>);

impl Mismatch {
    fn lock(&self) -> MutexGuard<'_, Option<[u8; 32]>> {
        // The value is a plain pin; one written by a thread that panicked is still whole.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set(&self, pin: Option<[u8; 32]>) {
        *self.lock() = pin;
    }

    /// The presented key's pin while the last handshake failed on the pin.
    pub fn seen(&self) -> Option<[u8; 32]> {
        *self.lock()
    }
}

/// Verifies the server certificate only by its SPKI pin (module docs).
#[derive(Debug)]
pub struct PinVerifier {
    pin: [u8; 32],
    mismatch: Arc<Mismatch>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinVerifier {
    /// A verifier for `pin`; `mismatch` takes the pin of another key a server presents.
    pub fn new(pin: [u8; 32], mismatch: Arc<Mismatch>) -> Self {
        Self {
            pin,
            mismatch,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }

    /// The pin of a certificate (SHA-256 of its DER SubjectPublicKeyInfo).
    pub fn pin_of(cert: &CertificateDer<'_>) -> Result<[u8; 32], rustls::Error> {
        let parsed = webpki::EndEntityCert::try_from(cert)
            .map_err(|_| rustls::Error::General("the server certificate does not parse".into()))?;
        let spki = parsed.subject_public_key_info();
        Ok(hangar_drive_crypto::identity::spki_pin(spki.as_ref()))
    }
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let pin = Self::pin_of(end_entity)?;
        if constant_time_eq(&pin, &self.pin) {
            Ok(ServerCertVerified::assertion())
        } else {
            self.mismatch.set(Some(pin));
            Err(rustls::Error::General(
                "the server key does not match the pin".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.2 is not offered; a server that negotiates it anyway is refused.
        Err(rustls::Error::General("TLS 1.2 is not allowed".into()))
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
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The TLS configuration: TLS 1.3 with the pin verifier, or with the platform verifier.
pub fn tls_config(
    pin: Option<[u8; 32]>,
    mismatch: Arc<Mismatch>,
) -> Result<rustls::ClientConfig, NetError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| NetError::Tls(e.to_string()))?;
    let config = match pin {
        Some(pin) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier::new(pin, mismatch)))
            .with_no_client_auth(),
        None => {
            use rustls_platform_verifier::BuilderVerifierExt;
            builder
                .with_platform_verifier()
                .map_err(|e| NetError::Tls(e.to_string()))?
                .with_no_client_auth()
        }
    };
    Ok(config)
}

/// Signs the session challenge with the device key (the app passes
/// `DeviceIdentity::prove_session`); the second argument is the base URL the client connects to.
pub type Prover =
    Box<dyn Fn(&ServerId, &str, &AccountId, &DeviceId, &Challenge) -> Signature + Send>;

/// Who signs in.
pub struct SessionIdentity {
    /// The account.
    pub account: AccountId,
    /// This device.
    pub device: DeviceId,
    /// The proof.
    pub prover: Prover,
}

/// The server API over HTTPS (module docs).
pub struct HttpServer {
    config: ServerConfig,
    client: Client,
    events: Client,
    mismatch: Arc<Mismatch>,
    identity: Option<SessionIdentity>,
    token: Option<SessionToken>,
}

impl std::fmt::Debug for HttpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpServer")
            .field("url", &self.config.url.as_str())
            .field("pinned", &self.config.pin.is_some())
            .field("signed_in", &self.token.is_some())
            .finish_non_exhaustive()
    }
}

enum Body {
    None,
    Json(Vec<u8>),
    Bytes(Vec<u8>),
}

impl HttpServer {
    /// A client for `config`; `identity` signs in (none before an account exists).
    pub fn new(config: ServerConfig, identity: Option<SessionIdentity>) -> Result<Self, NetError> {
        let mismatch = Arc::new(Mismatch::default());
        // The blocking client applies its timeout to the answer's head and to every single read
        // of the body (reqwest 0.13.5, `blocking/client.rs` `execute_request` and
        // `blocking/response.rs` `Read::read`), so for the event stream it is a read timeout.
        let build = |timeout: Option<Duration>| -> Result<Client, NetError> {
            let tls = tls_config(config.pin, Arc::clone(&mismatch))?;
            let mut builder = Client::builder()
                .tls_backend_preconfigured(tls)
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(15))
                .user_agent(concat!("hangar-drive/", env!("CARGO_PKG_VERSION")));
            builder = match timeout {
                Some(t) => builder.timeout(t),
                None => builder.timeout(None),
            };
            if config.url.scheme() == "https" {
                builder = builder.https_only(true);
            }
            builder.build().map_err(|e| NetError::Tls(e.to_string()))
        };
        Ok(Self {
            client: build(Some(config.timeout))?,
            events: build(Some(config.event_read_timeout))?,
            config,
            mismatch,
            identity,
            token: None,
        })
    }

    /// The server ID learnt at the last sign-in or account creation.
    pub fn server_id(&self) -> Option<ServerId> {
        self.config.server
    }

    /// Checks the server's protocol version (`/api/v1/health`).
    pub fn check_health(&mut self) -> Result<ServerInfo, NetError> {
        let info: ServerInfo = self.call(Method::GET, HEALTH_PATH, None, Body::None, false)?;
        if info.protocol_version != PROTOCOL_VERSION {
            return Err(NetError::Version);
        }
        Ok(info)
    }

    fn send_error(&self, e: &reqwest::Error) -> NetError {
        if self.mismatch.seen().is_some() {
            return NetError::PinMismatch;
        }
        let text = format!("{e:?}").to_ascii_lowercase();
        if text.contains("certificate")
            || text.contains("invalidcertificate")
            || text.contains("tls")
        {
            return NetError::Tls(e.to_string());
        }
        NetError::Unreachable
    }

    fn request(&self, method: &Method, url: Url, body: &Body, auth: bool) -> RequestBuilder {
        let mut req = self.client.request(method.clone(), url);
        req = match body {
            Body::None => req,
            Body::Json(bytes) => req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes.clone()),
            Body::Bytes(bytes) => req
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(bytes.clone()),
        };
        if auth {
            if let Some(token) = &self.token {
                req = req.bearer_auth(token.expose_base64url().as_str());
            }
        }
        req
    }

    /// Sends with retries; returns the response of a 2xx answer or the server's error.
    fn send(
        &mut self,
        method: Method,
        path: &str,
        after: Option<u64>,
        body: Body,
        auth: bool,
    ) -> Result<Response, NetError> {
        if auth && self.token.is_none() {
            self.sign_in()?;
        }
        let url = endpoint(&self.config.url, path, after);
        let retry = self.config.retry;
        let mut signed_in_again = false;
        let mut attempt = 1;
        loop {
            let result = self.request(&method, url.clone(), &body, auth).send();
            let error = match result {
                Ok(resp) if resp.status().is_success() => {
                    // A connection that passed the handshake ends an earlier mismatch.
                    self.mismatch.set(None);
                    return Ok(resp);
                }
                Ok(resp)
                    if resp.status() == StatusCode::UNAUTHORIZED && auth && !signed_in_again =>
                {
                    // The token ran out: one new proof, then the same request again.
                    self.token = None;
                    self.sign_in()?;
                    signed_in_again = true;
                    continue;
                }
                Ok(resp) => {
                    let wait = retry_after(&resp);
                    let error = error_of(resp);
                    if !error.is_transient() || attempt >= retry.attempts.max(1) {
                        return Err(error);
                    }
                    std::thread::sleep(wait.unwrap_or_else(|| retry.delay(attempt)).min(retry.max));
                    attempt += 1;
                    continue;
                }
                Err(e) => self.send_error(&e),
            };
            if !error.is_transient() || attempt >= retry.attempts.max(1) {
                return Err(error);
            }
            std::thread::sleep(retry.delay(attempt));
            attempt += 1;
        }
    }

    fn call<T: DeserializeOwned>(
        &mut self,
        method: Method,
        path: &str,
        after: Option<u64>,
        body: Body,
        auth: bool,
    ) -> Result<T, NetError> {
        let resp = self.send(method, path, after, body, auth)?;
        let bytes = read_limited(resp, MAX_JSON)?;
        serde_json::from_slice(&bytes).map_err(|e| NetError::Protocol(e.to_string()))
    }

    fn call_empty(
        &mut self,
        method: Method,
        path: &str,
        body: Body,
        auth: bool,
    ) -> Result<(), NetError> {
        self.send(method, path, None, body, auth).map(|_| ())
    }

    /// Signs in with a fresh challenge. The server's challenges are stateless and a proof is
    /// accepted once: a proof repeated after a lost answer (the retry of a transient failure)
    /// is answered with `ChallengeInvalid`, so the sign-in starts once more with a new
    /// challenge instead of failing.
    fn sign_in(&mut self) -> Result<(), NetError> {
        match self.sign_in_once() {
            Err(e) if e.code() == Some(api::ErrorCode::ChallengeInvalid) => self.sign_in_once(),
            other => other,
        }
    }

    fn sign_in_once(&mut self) -> Result<(), NetError> {
        let Some(identity) = &self.identity else {
            return Err(NetError::Server(ErrorBody::new(
                api::ErrorCode::Unauthorized,
            )));
        };
        let (account, device) = (identity.account, identity.device);
        let challenge: ChallengeResponse = self.call(
            Method::POST,
            api::CHALLENGE_PATH,
            None,
            json(&ChallengeRequest { account, device })?,
            false,
        )?;
        if let Some(expected) = self.config.server {
            if expected != challenge.server {
                return Err(NetError::Protocol("the server ID changed".into()));
            }
        }
        let Some(identity) = &self.identity else {
            return Err(NetError::Server(ErrorBody::new(
                api::ErrorCode::Unauthorized,
            )));
        };
        let server_url = hangar_drive_crypto::session::base_url(&self.config.url);
        let signature = (identity.prover)(
            &challenge.server,
            &server_url,
            &account,
            &device,
            &challenge.challenge,
        );
        let session: SessionResponse = self.call(
            Method::POST,
            api::PROOF_PATH,
            None,
            json(&ProofRequest {
                account,
                device,
                challenge: challenge.challenge,
                server_url,
                signature,
            })?,
            false,
        )?;
        self.config.server = Some(challenge.server);
        self.token = Some(session.token);
        Ok(())
    }

    /// Reads the account's SSE stream and calls `on_sequence` with every new account sequence
    /// until the stream ends, fails, or `on_sequence` returns false.
    pub fn listen_events(
        &mut self,
        mut on_sequence: impl FnMut(u64) -> bool,
    ) -> Result<(), NetError> {
        if self.token.is_none() {
            self.sign_in()?;
        }
        let url = endpoint(&self.config.url, api::EVENTS_PATH, None);
        let mut req = self
            .events
            .get(url)
            .header(reqwest::header::ACCEPT, "text/event-stream");
        if let Some(token) = &self.token {
            req = req.bearer_auth(token.expose_base64url().as_str());
        }
        let resp = req.send().map_err(|e| self.send_error(&e))?;
        if !resp.status().is_success() {
            if resp.status() == StatusCode::UNAUTHORIZED {
                self.token = None;
            }
            return Err(error_of(resp));
        }
        self.mismatch.set(None);
        parse_sse(BufReader::new(resp), &mut on_sequence)
    }

    /// [`HttpServer::listen_events`] for as long as `keep_going` says: a stream that ends, stays
    /// silent beyond [`EVENT_READ_TIMEOUT`] or breaks is opened again after the retry backoff.
    /// Returns when `on_sequence` or `keep_going` returns false, or on an error a new connection
    /// cannot fix (pin mismatch, TLS, protocol, a refusal).
    pub fn follow_events(
        &mut self,
        mut on_sequence: impl FnMut(u64) -> bool,
        mut keep_going: impl FnMut() -> bool,
    ) -> Result<(), NetError> {
        let mut failures = 0u32;
        while keep_going() {
            let mut stopped = false;
            let result = self.listen_events(|s| {
                let go_on = on_sequence(s);
                stopped = !go_on;
                go_on
            });
            if stopped {
                return Ok(());
            }
            match result {
                Ok(()) => failures = 0,
                Err(e)
                    if e.is_transient()
                        || e == NetError::Server(ErrorBody::new(api::ErrorCode::Unauthorized)) =>
                {
                    failures = failures.saturating_add(1);
                }
                Err(e) => return Err(e),
            }
            if failures > 0 && keep_going() {
                std::thread::sleep(self.config.retry.delay(failures).min(self.config.retry.max));
            }
        }
        Ok(())
    }
}

fn json<T: Serialize>(value: &T) -> Result<Body, NetError> {
    serde_json::to_vec(value)
        .map(Body::Json)
        .map_err(|e| NetError::Protocol(e.to_string()))
}

fn retry_after(resp: &Response) -> Option<Duration> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

fn error_of(resp: Response) -> NetError {
    let status = resp.status();
    match read_limited(resp, 64 * 1024)
        .ok()
        .and_then(|b| serde_json::from_slice::<ErrorBody>(&b).ok())
    {
        Some(body) => NetError::Server(body),
        None if status.is_server_error() => {
            NetError::Server(ErrorBody::new(api::ErrorCode::Internal))
        }
        None if status == StatusCode::TOO_MANY_REQUESTS => {
            NetError::Server(ErrorBody::new(api::ErrorCode::RateLimited))
        }
        None => NetError::Protocol(format!("HTTP {status}")),
    }
}

fn read_limited(resp: Response, limit: u64) -> Result<Vec<u8>, NetError> {
    if resp.content_length().is_some_and(|n| n > limit) {
        return Err(NetError::Protocol("the answer is too large".into()));
    }
    let mut out = Vec::new();
    resp.take(limit + 1)
        .read_to_end(&mut out)
        .map_err(|_| NetError::Unreachable)?;
    if out.len() as u64 > limit {
        return Err(NetError::Protocol("the answer is too large".into()));
    }
    Ok(out)
}

/// Parses an SSE stream: every `data:` line of an event is a [`SequenceEvent`]; comments
/// (keep-alives) and other fields are skipped. Stops when `on_sequence` returns false. A line
/// longer than [`MAX_SSE_LINE`] bytes, a line that is not UTF-8 and an event whose `data` is
/// longer than [`MAX_SSE_DATA`] are protocol errors; no more than one line is ever held.
pub fn parse_sse(
    mut reader: impl BufRead,
    on_sequence: &mut dyn FnMut(u64) -> bool,
) -> Result<(), NetError> {
    let mut data = String::new();
    let mut raw = Vec::with_capacity(256);
    loop {
        raw.clear();
        let n = (&mut reader)
            .take(MAX_SSE_LINE as u64 + 1)
            .read_until(b'\n', &mut raw)
            .map_err(|_| NetError::Unreachable)?;
        if n == 0 {
            return Ok(());
        }
        if raw.last() == Some(&b'\n') {
            raw.pop();
            if raw.last() == Some(&b'\r') {
                raw.pop();
            }
        } else if n > MAX_SSE_LINE {
            return Err(NetError::Protocol("an event line is too long".into()));
        }
        let line = std::str::from_utf8(&raw)
            .map_err(|_| NetError::Protocol("an event line is not UTF-8".into()))?;
        if line.is_empty() {
            if !data.is_empty() {
                let event: SequenceEvent =
                    serde_json::from_str(&data).map_err(|e| NetError::Protocol(e.to_string()))?;
                data.clear();
                if !on_sequence(event.sequence) {
                    return Ok(());
                }
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            let rest = rest.strip_prefix(' ').unwrap_or(rest);
            if data.len() + rest.len() > MAX_SSE_DATA {
                return Err(NetError::Protocol("an event's data is too long".into()));
            }
            data.push_str(rest);
        }
    }
}

impl ServerApi for HttpServer {
    fn create_account(
        &mut self,
        request: &CreateAccountRequest,
    ) -> Result<CreateAccountResponse, NetError> {
        let response: CreateAccountResponse = self.call(
            Method::POST,
            api::ACCOUNTS_PATH,
            None,
            json(request)?,
            false,
        )?;
        self.config.server = Some(response.server);
        Ok(response)
    }

    fn challenge(
        &mut self,
        account: &AccountId,
        device: &DeviceId,
    ) -> Result<ChallengeResponse, NetError> {
        self.call(
            Method::POST,
            api::CHALLENGE_PATH,
            None,
            json(&ChallengeRequest {
                account: *account,
                device: *device,
            })?,
            false,
        )
    }

    fn proof(
        &mut self,
        account: &AccountId,
        device: &DeviceId,
        challenge: &Challenge,
        signature: &Signature,
    ) -> Result<SessionResponse, NetError> {
        self.call(
            Method::POST,
            api::PROOF_PATH,
            None,
            json(&ProofRequest {
                account: *account,
                device: *device,
                challenge: *challenge,
                server_url: hangar_drive_crypto::session::base_url(&self.config.url),
                signature: *signature,
            })?,
            false,
        )
    }

    fn log(&mut self, after: u64) -> Result<LogPage, NetError> {
        self.call(Method::GET, api::LOG_PATH, Some(after), Body::None, true)
    }

    fn append_log(&mut self, request: &LogAppendRequest) -> Result<LogAppendResponse, NetError> {
        self.call(Method::POST, api::LOG_PATH, None, json(request)?, true)
    }

    fn epoch_key(&mut self, epoch: Epoch) -> Result<WrappedKeyResponse, NetError> {
        self.call(
            Method::GET,
            &api::epoch_key_path(epoch),
            None,
            Body::None,
            true,
        )
    }

    fn record(&mut self, key: &RecordKey) -> Result<Option<RecordResponse>, NetError> {
        match self.call(Method::GET, &api::record_path(key), None, Body::None, true) {
            Ok(r) => Ok(Some(r)),
            Err(e) if e.code() == Some(api::ErrorCode::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn put_record(&mut self, key: &RecordKey, put: &RecordPut) -> Result<(), NetError> {
        self.call_empty(Method::PUT, &api::record_path(key), json(put)?, true)
    }

    fn feed(&mut self, after: u64) -> Result<FeedPage, NetError> {
        self.call(Method::GET, api::FEED_PATH, Some(after), Body::None, true)
    }

    fn reserve_pairing(&mut self, id: &PairingId) -> Result<api::PairingReservation, NetError> {
        self.call(Method::PUT, &api::pairing_path(id), None, Body::None, true)
    }

    fn post_pairing(&mut self, id: &PairingId, request: &PairingRequest) -> Result<(), NetError> {
        self.call_empty(Method::POST, &api::pairing_path(id), json(request)?, false)
    }

    fn get_pairing(&mut self, id: &PairingId) -> Result<Option<PairingRequest>, NetError> {
        match self.call(Method::GET, &api::pairing_path(id), None, Body::None, true) {
            Ok(r) => Ok(Some(r)),
            Err(e) if e.code() == Some(api::ErrorCode::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn close_pairing(&mut self, id: &PairingId) -> Result<(), NetError> {
        self.call_empty(Method::DELETE, &api::pairing_path(id), Body::None, true)
    }

    fn missing_objects(
        &mut self,
        folder: &FolderId,
        ids: &[ObjectId],
    ) -> Result<Vec<ObjectId>, NetError> {
        let response: MissingObjectsResponse = self.call(
            Method::POST,
            &api::missing_objects_path(folder),
            None,
            json(&MissingObjectsRequest { ids: ids.to_vec() })?,
            true,
        )?;
        Ok(response.missing)
    }

    fn put_object(
        &mut self,
        folder: &FolderId,
        id: &ObjectId,
        blob: &[u8],
    ) -> Result<UploadResponse, NetError> {
        self.call(
            Method::PUT,
            &api::object_path(folder, id),
            None,
            Body::Bytes(blob.to_vec()),
            true,
        )
    }

    fn get_object(&mut self, folder: &FolderId, id: &ObjectId) -> Result<Vec<u8>, NetError> {
        let resp = self.send(
            Method::GET,
            &api::object_path(folder, id),
            None,
            Body::None,
            true,
        )?;
        read_limited(resp, max_object())
    }

    fn commit(
        &mut self,
        folder: &FolderId,
        request: &CommitRequest,
    ) -> Result<CommitResponse, NetError> {
        self.call(
            Method::POST,
            &api::commit_path(folder),
            None,
            json(request)?,
            true,
        )
    }

    fn commits(&mut self, folder: &FolderId, after: u64) -> Result<DeltaPage, NetError> {
        self.call(
            Method::GET,
            &api::commits_path(folder),
            Some(after),
            Body::None,
            true,
        )
    }

    fn retire(&mut self, folder: &FolderId) -> Result<(), NetError> {
        self.call_empty(Method::POST, &api::retire_path(folder), Body::None, true)
    }

    fn bring_back(&mut self, folder: &FolderId) -> Result<(), NetError> {
        self.call_empty(Method::DELETE, &api::retire_path(folder), Body::None, true)
    }

    fn seen_pin(&self) -> Option<[u8; 32]> {
        self.mismatch.seen()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_keep_a_base_path() {
        let base = Url::parse("https://drive.example/").unwrap();
        assert_eq!(
            endpoint(&base, "/api/v1/account/feed", Some(7)).as_str(),
            "https://drive.example/api/v1/account/feed?after=7"
        );
        // Url::join would drop "/drive" here (N6).
        let base = Url::parse("https://example.org/drive/").unwrap();
        assert_eq!(
            endpoint(&base, "/api/v1/health", None).as_str(),
            "https://example.org/drive/api/v1/health"
        );
        assert_eq!(
            base.join("/api/v1/health").unwrap().as_str(),
            "https://example.org/api/v1/health"
        );
    }

    #[test]
    fn retry_delays_double_up_to_the_maximum() {
        let r = RetryPolicy::default();
        assert_eq!(r.delay(1), Duration::from_millis(250));
        assert_eq!(r.delay(2), Duration::from_millis(500));
        assert_eq!(r.delay(30), r.max);
    }

    #[test]
    fn sse_events_and_keep_alives() {
        let stream =
            ": keep-alive\n\ndata: {\"sequence\":3}\n\nevent: x\ndata: {\"sequence\": 9}\n\n";
        let mut seen = Vec::new();
        parse_sse(stream.as_bytes(), &mut |s| {
            seen.push(s);
            true
        })
        .unwrap();
        assert_eq!(seen, vec![3, 9]);
        assert!(parse_sse("data: nonsense\n\n".as_bytes(), &mut |_| true).is_err());
        // CRLF line ends.
        let mut seen = Vec::new();
        parse_sse("data: {\"sequence\":4}\r\n\r\n".as_bytes(), &mut |s| {
            seen.push(s);
            true
        })
        .unwrap();
        assert_eq!(seen, vec![4]);
    }

    #[test]
    fn a_stream_without_line_ends_is_refused_without_growing() {
        // An endless stream of one byte: the parser reads one bounded line and refuses it.
        let endless = BufReader::new(std::io::repeat(b'a'));
        assert_eq!(
            parse_sse(endless, &mut |_| true),
            Err(NetError::Protocol("an event line is too long".into()))
        );
        // A line of exactly the limit is fine, one byte more is not.
        let fine = format!(": {}\n", "k".repeat(MAX_SSE_LINE - 2));
        assert!(parse_sse(fine.as_bytes(), &mut |_| true).is_ok());
        let long = format!(": {}\n", "k".repeat(MAX_SSE_LINE - 1));
        assert!(parse_sse(long.as_bytes(), &mut |_| true).is_err());
        // Many short data lines of one event add up to the data limit.
        let many = "data: 1234567890\n".repeat(MAX_SSE_DATA / 10 + 1);
        assert!(parse_sse(many.as_bytes(), &mut |_| true).is_err());
        assert_eq!(EVENT_READ_TIMEOUT, 3 * EVENT_KEEPALIVE);
    }

    #[test]
    fn plain_http_only_to_localhost() {
        assert!(ServerConfig::new("http://localhost:8080", None).is_ok());
        assert!(ServerConfig::new("http://drive.example", None).is_err());
        assert!(ServerConfig::new("http://localhost:80@evil.example/", None).is_err());
        assert!(ServerConfig::new("https://drive.example", None).is_ok());
    }
}
