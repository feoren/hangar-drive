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
//! - **Proxies:** never for the plain HTTP of a loopback server; for https the environment's
//!   proxy only tunnels the end-to-end checked TLS connection (security review N5).
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
//! - **Parallel uploads:** [`ServerApi::uploader`] hands out an [`HttpUploader`] that shares
//!   this client's connection pool, session token and traffic counter, so worker threads can
//!   send objects beside the engine thread. Every uploader of one client takes one of its
//!   [`UploadSlots`] per request ([`crate::upload::UPLOAD_WORKERS`] by default), so uploads of
//!   several folders together stay within the cap. An uploader never signs in: a `401` comes
//!   back as `unauthorized`, and the engine thread sends that object again through
//!   [`ServerApi::put_object`], which signs in and renews the shared token.
//! - **Traffic:** the payload bytes of every request body that was sent and of every response
//!   body read (also the event stream's) are added to a shared [`TrafficCounter`]
//!   ([`HttpServer::with_traffic`]), which the app shell reads without the engine thread. Headers
//!   are not counted; contents and paths never reach the counter.

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

use bytes::Bytes;

use crate::interrupt::Interrupt;
use crate::ports::{NetError, ObjectFetcher, ObjectUploader, ServerApi};
use crate::traffic::{CountingReader, TrafficCounter};
use crate::upload::{UploadSlots, UPLOAD_WORKERS};

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

/// How long a connection may take to open. A reachable server answers a TCP and TLS handshake
/// in well under a second even on a slow line; a dead address is noticed after this long
/// instead of the operating system's own limit (about 21 s on Windows).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an idle connection stays in the client's pool: well below the server's own idle
/// limit (10 s) and the reverse proxy's (90 s), so a request never goes out on a connection the
/// other side closed meanwhile (reqwest keeps one 90 s by default).
pub const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// How long an idle connection stays in the pool ([`POOL_IDLE_TIMEOUT`]).
    pub idle_timeout: Duration,
    /// Object uploads of this client at once, across every folder
    /// ([`crate::upload::UPLOAD_WORKERS`]; clamped to [`crate::upload::MAX_UPLOAD_WORKERS`]).
    pub upload_slots: usize,
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
            idle_timeout: POOL_IDLE_TIMEOUT,
            upload_slots: UPLOAD_WORKERS,
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
    /// The session token, shared with the uploaders this client handed out.
    token: Arc<SharedToken>,
    /// Uploads in flight across every uploader of this client (module docs).
    slots: Arc<UploadSlots>,
    /// Downloads in flight across every fetcher of this client
    /// ([`crate::download::DOWNLOAD_WORKERS`]).
    fetch_slots: Arc<UploadSlots>,
    /// The device log length this device verified, sent with the proof (security review H2).
    log_length: Option<u64>,
    /// Payload bytes sent and received (module docs, "Traffic").
    traffic: Arc<TrafficCounter>,
    /// Commands waiting for the engine thread, whose calls go through this client
    /// ([`ServerApi::set_interrupt`]).
    interrupt: Option<Interrupt>,
}

impl std::fmt::Debug for HttpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpServer")
            .field("url", &self.config.url.as_str())
            .field("pinned", &self.config.pin.is_some())
            .field("signed_in", &self.token.get().is_some())
            .finish_non_exhaustive()
    }
}

/// The session token of one client and its uploaders.
#[derive(Default)]
struct SharedToken(Mutex<Option<SessionToken>>);

impl SharedToken {
    fn lock(&self) -> MutexGuard<'_, Option<SessionToken>> {
        // A plain value; one written by a thread that panicked is still whole.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn get(&self) -> Option<SessionToken> {
        self.lock().clone()
    }

    fn set(&self, token: Option<SessionToken>) {
        *self.lock() = token;
    }
}

/// A request body. Reference counted, so a retry sends the same buffer again without a copy.
enum Body {
    None,
    Json(Bytes),
    Bytes(Bytes),
}

impl Body {
    fn len(&self) -> u64 {
        match self {
            Body::None => 0,
            Body::Json(bytes) | Body::Bytes(bytes) => bytes.len() as u64,
        }
    }
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
                .connect_timeout(CONNECT_TIMEOUT)
                .pool_idle_timeout(config.idle_timeout)
                .user_agent(concat!("hangar-drive/", env!("CARGO_PKG_VERSION")));
            builder = match timeout {
                Some(t) => builder.timeout(t),
                None => builder.timeout(None),
            };
            // Proxies (security review N5). Plain HTTP is allowed only to the loopback address
            // (`parse_server_url`), and a proxy from the environment would see such a request,
            // the proof and the session token in the clear, so it never goes through one. For
            // https the client keeps the proxy of the environment (`HTTPS_PROXY`, `ALL_PROXY`):
            // a proxy then only tunnels the TLS connection (`CONNECT`) and learns the host name,
            // while the certificate or the SPKI pin is checked end to end with the server, so it
            // can neither read nor change a request. Networks that allow https only through a
            // proxy keep working that way.
            if config.url.scheme() == "https" {
                builder = builder.https_only(true);
            } else {
                builder = builder.no_proxy();
            }
            builder.build().map_err(|e| NetError::Tls(e.to_string()))
        };
        Ok(Self {
            client: build(Some(config.timeout))?,
            events: build(Some(config.event_read_timeout))?,
            slots: Arc::new(UploadSlots::new(
                config
                    .upload_slots
                    .clamp(1, crate::upload::MAX_UPLOAD_WORKERS),
            )),
            fetch_slots: Arc::new(UploadSlots::new(crate::download::DOWNLOAD_WORKERS)),
            config,
            mismatch,
            identity,
            token: Arc::default(),
            log_length: None,
            traffic: Arc::default(),
            interrupt: None,
        })
    }

    /// Counts this client's traffic on `traffic`, shared with whoever shows it.
    pub fn with_traffic(mut self, traffic: Arc<TrafficCounter>) -> Self {
        self.traffic = traffic;
        self
    }

    /// The counter of this client's traffic.
    pub fn traffic(&self) -> Arc<TrafficCounter> {
        Arc::clone(&self.traffic)
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
        send_error(&self.mismatch, e)
    }

    /// The parts of this client one request needs, borrowed.
    fn wire(&self) -> Wire<'_> {
        Wire {
            client: &self.client,
            mismatch: &self.mismatch,
            traffic: &self.traffic,
            token: &self.token,
            retry: self.config.retry,
            interrupt: self.interrupt.as_ref(),
        }
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
        if auth && self.token.get().is_none() {
            self.sign_in()?;
        }
        let url = endpoint(&self.config.url, path, after);
        match self.wire().send(&method, &url, path, &body, auth, true) {
            Ok(resp) => Ok(resp),
            Err(Failure::Net(e)) => Err(e),
            Err(Failure::Unauthorized(_)) => {
                // The token ran out: one new proof, then the same request again. A waiting
                // command goes first; the next pass signs in.
                if self.interrupt.as_ref().is_some_and(Interrupt::pending) {
                    return Err(NetError::Interrupted);
                }
                self.token.set(None);
                self.sign_in()?;
                self.wire()
                    .send(&method, &url, path, &body, auth, false)
                    .map_err(|f| f.into_net(&self.traffic))
            }
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
        let bytes = read_limited(resp, MAX_JSON, &self.traffic)?;
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
                log_length: self.log_length,
            })?,
            false,
        )?;
        self.config.server = Some(challenge.server);
        self.token.set(Some(session.token));
        Ok(())
    }

    /// Reads the account's SSE stream and calls `on_sequence` with every new account sequence
    /// until the stream ends, fails, or `on_sequence` returns false.
    pub fn listen_events(
        &mut self,
        mut on_sequence: impl FnMut(u64) -> bool,
    ) -> Result<(), NetError> {
        if self.token.get().is_none() {
            self.sign_in()?;
        }
        let url = endpoint(&self.config.url, api::EVENTS_PATH, None);
        let mut req = self
            .events
            .get(url)
            .header(reqwest::header::ACCEPT, "text/event-stream");
        if let Some(token) = self.token.get() {
            req = req.bearer_auth(token.expose_base64url().as_str());
        }
        let resp = req.send().map_err(|e| self.send_error(&e))?;
        if !resp.status().is_success() {
            if resp.status() == StatusCode::UNAUTHORIZED {
                self.token.set(None);
            }
            return Err(removed_only_on_proof(
                api::EVENTS_PATH,
                error_of(resp, &self.traffic),
            ));
        }
        self.mismatch.set(None);
        parse_sse(
            BufReader::new(CountingReader::new(resp, &self.traffic)),
            &mut on_sequence,
        )
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

/// What a failed request of [`Wire::send`] ended with.
enum Failure {
    /// `401` on an authenticated request whose caller renews the session itself.
    Unauthorized(Box<Response>),
    /// Any other failure, after the retries.
    Net(NetError),
}

impl Failure {
    /// The error for the caller; the body of a `401` is read and counted like any other.
    fn into_net(self, traffic: &TrafficCounter) -> NetError {
        match self {
            Failure::Net(e) => e,
            Failure::Unauthorized(resp) => {
                let _ = read_limited(*resp, MAX_ERROR_BODY, traffic);
                NetError::Server(ErrorBody::new(api::ErrorCode::Unauthorized))
            }
        }
    }
}

/// The parts one request needs: shared by [`HttpServer`] and its [`HttpUploader`]s.
struct Wire<'a> {
    client: &'a Client,
    mismatch: &'a Mismatch,
    traffic: &'a Arc<TrafficCounter>,
    token: &'a SharedToken,
    retry: RetryPolicy,
    /// The engine thread's waiting commands, for a call on that thread; `None` for a worker.
    interrupt: Option<&'a Interrupt>,
}

/// How long one slice of a wait between attempts is: a waiting command ends the wait within
/// about this long.
const WAIT_SLICE: Duration = Duration::from_millis(50);

/// Waits `wait` in slices of [`WAIT_SLICE`]; false when a command started waiting meanwhile.
fn wait_unless_interrupted(wait: Duration, interrupt: Option<&Interrupt>) -> bool {
    let Some(interrupt) = interrupt else {
        std::thread::sleep(wait);
        return true;
    };
    let until = std::time::Instant::now() + wait;
    loop {
        if interrupt.pending() {
            return false;
        }
        let left = until.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return true;
        }
        std::thread::sleep(left.min(WAIT_SLICE));
    }
}

/// An upload body that counts its bytes as sent while the client reads it for the line, so
/// the traffic line moves during a long upload instead of jumping once the answer came.
struct SentBody {
    bytes: Bytes,
    at: usize,
    traffic: Arc<TrafficCounter>,
}

impl Read for SentBody {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let rest = self.bytes.get(self.at..).unwrap_or_default();
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.at += n;
        self.traffic.add_sent(n as u64);
        Ok(n)
    }
}

impl Wire<'_> {
    fn request(&self, method: &Method, url: Url, body: &Body, auth: bool) -> RequestBuilder {
        let mut req = self.client.request(method.clone(), url);
        req = match body {
            Body::None => req,
            Body::Json(bytes) => req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes.clone()),
            // Streamed from the shared buffer, so each attempt counts what it sent, as it goes.
            Body::Bytes(bytes) => req
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(reqwest::blocking::Body::sized(
                    SentBody {
                        bytes: bytes.clone(),
                        at: 0,
                        traffic: Arc::clone(self.traffic),
                    },
                    bytes.len() as u64,
                )),
        };
        if auth {
            if let Some(token) = self.token.get() {
                req = req.bearer_auth(token.expose_base64url().as_str());
            }
        }
        req
    }

    /// Sends with retries of transient failures, honouring `Retry-After` (at most
    /// [`RetryPolicy::max`]); with `renew`, a `401` of an authenticated request ends at once
    /// with [`Failure::Unauthorized`], so the caller can sign in again.
    fn send(
        &self,
        method: &Method,
        url: &Url,
        path: &str,
        body: &Body,
        auth: bool,
        renew: bool,
    ) -> Result<Response, Failure> {
        let retry = self.retry;
        let mut attempt = 1;
        loop {
            let result = self.request(method, url.clone(), body, auth).send();
            // An answer means a JSON body went out; a failed attempt counts as nothing sent. An
            // upload body counts itself while it is read ([`SentBody`]).
            if result.is_ok() && matches!(body, Body::Json(_)) {
                self.traffic.add_sent(body.len());
            }
            let error = match result {
                Ok(resp) if resp.status().is_success() => {
                    // A connection that passed the handshake ends an earlier mismatch.
                    self.mismatch.set(None);
                    return Ok(resp);
                }
                Ok(resp) if resp.status() == StatusCode::UNAUTHORIZED && auth && renew => {
                    return Err(Failure::Unauthorized(Box::new(resp)));
                }
                Ok(resp) => {
                    let wait = retry_after(&resp);
                    let error = removed_only_on_proof(path, error_of(resp, self.traffic));
                    if !error.is_transient() || attempt >= retry.attempts.max(1) {
                        return Err(Failure::Net(error));
                    }
                    let wait = wait.unwrap_or_else(|| retry.delay(attempt)).min(retry.max);
                    if !wait_unless_interrupted(wait, self.interrupt) {
                        return Err(Failure::Net(NetError::Interrupted));
                    }
                    attempt += 1;
                    continue;
                }
                // A request that got no answer within the time limit is not sent again: the
                // server hangs or the line is dead, and every retry would hold the calling
                // thread (the engine's, for every call but an upload) for another full limit.
                // The next pass of the loop tries again.
                Err(e) if e.is_timeout() => {
                    return Err(Failure::Net(send_error(self.mismatch, &e)))
                }
                Err(e) => send_error(self.mismatch, &e),
            };
            if !error.is_transient() || attempt >= retry.attempts.max(1) {
                return Err(Failure::Net(error));
            }
            if !wait_unless_interrupted(retry.delay(attempt), self.interrupt) {
                return Err(Failure::Net(NetError::Interrupted));
            }
            attempt += 1;
        }
    }
}

/// The error of a request that got no answer.
fn send_error(mismatch: &Mismatch, e: &reqwest::Error) -> NetError {
    // The mismatch flag stays set until a request succeeds, so the server key number can
    // still be shown after a later failure; it explains only a failure of the TLS handshake
    // itself (security review, info). A timeout or a refused connection after a mismatch is
    // "unreachable", not another "the server identifies itself differently".
    if !is_tls_failure(e) {
        return NetError::Unreachable;
    }
    if mismatch.seen().is_some() {
        return NetError::PinMismatch;
    }
    NetError::Tls(e.to_string())
}

/// Object uploads from worker threads beside an [`HttpServer`] (module docs, "Parallel
/// uploads"): the same connection pool, TLS verifier, session token, traffic counter and upload
/// slots.
pub struct HttpUploader {
    client: Client,
    base: Url,
    mismatch: Arc<Mismatch>,
    traffic: Arc<TrafficCounter>,
    token: Arc<SharedToken>,
    slots: Arc<UploadSlots>,
    retry: RetryPolicy,
}

impl std::fmt::Debug for HttpUploader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpUploader")
            .field("url", &self.base.as_str())
            .finish_non_exhaustive()
    }
}

impl ObjectUploader for HttpUploader {
    fn put_object(
        &self,
        folder: &FolderId,
        id: &ObjectId,
        blob: Bytes,
    ) -> Result<UploadResponse, NetError> {
        // Held until the answer is read, so the slots count uploads the server still works on.
        let _slot = self.slots.acquire();
        let path = api::object_path(folder, id);
        let url = endpoint(&self.base, &path, None);
        let wire = Wire {
            client: &self.client,
            mismatch: &self.mismatch,
            traffic: &self.traffic,
            token: &self.token,
            retry: self.retry,
            interrupt: None,
        };
        let resp = wire
            .send(&Method::PUT, &url, &path, &Body::Bytes(blob), true, true)
            .map_err(|f| f.into_net(&self.traffic))?;
        let bytes = read_limited(resp, MAX_JSON, &self.traffic)?;
        serde_json::from_slice(&bytes).map_err(|e| NetError::Protocol(e.to_string()))
    }
}

/// Object downloads from worker threads beside an [`HttpServer`] ([`crate::download`]): the
/// same connection pool, TLS verifier, session token and traffic counter, and slots of their
/// own per account connection.
pub struct HttpFetcher {
    client: Client,
    base: Url,
    mismatch: Arc<Mismatch>,
    traffic: Arc<TrafficCounter>,
    token: Arc<SharedToken>,
    slots: Arc<UploadSlots>,
    retry: RetryPolicy,
}

impl std::fmt::Debug for HttpFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpFetcher")
            .field("url", &self.base.as_str())
            .finish_non_exhaustive()
    }
}

impl ObjectFetcher for HttpFetcher {
    fn get_object(&self, folder: &FolderId, id: &ObjectId) -> Result<Vec<u8>, NetError> {
        // Held until the body is read, so the slots count downloads still under way.
        let _slot = self.slots.acquire();
        let path = api::object_path(folder, id);
        let url = endpoint(&self.base, &path, None);
        let wire = Wire {
            client: &self.client,
            mismatch: &self.mismatch,
            traffic: &self.traffic,
            token: &self.token,
            retry: self.retry,
            interrupt: None,
        };
        let resp = wire
            .send(&Method::GET, &url, &path, &Body::None, true, true)
            .map_err(|f| f.into_net(&self.traffic))?;
        read_limited(resp, max_object(), &self.traffic)
    }
}

/// Whether a failed request failed in TLS: a `rustls` error in its source chain (also inside
/// nested I/O errors), or a message that names a certificate or TLS. A timeout never is one.
fn is_tls_failure(e: &reqwest::Error) -> bool {
    if e.is_timeout() {
        return false;
    }
    if std::error::Error::source(e).is_some_and(holds_rustls_error) {
        return true;
    }
    let text = format!("{e:?}").to_ascii_lowercase();
    text.contains("certificate") || text.contains("tls") || text.contains("rustls")
}

/// Whether `error` or anything below it is a `rustls` error. An I/O error's `source` skips the
/// error it wraps, so that one is reached through `get_ref`.
fn holds_rustls_error(error: &(dyn std::error::Error + 'static)) -> bool {
    if error.downcast_ref::<rustls::Error>().is_some() {
        return true;
    }
    if let Some(inner) = error
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::get_ref)
    {
        if holds_rustls_error(inner) {
            return true;
        }
    }
    error.source().is_some_and(holds_rustls_error)
}

fn json<T: Serialize>(value: &T) -> Result<Body, NetError> {
    serde_json::to_vec(value)
        .map(|v| Body::Json(Bytes::from(v)))
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

/// `device_removed` counts only as the answer to this device's own proof (security review H2):
/// [`NetError::DeviceRemoved`] on [`api::PROOF_PATH`], a protocol error on every other route.
/// A token says nothing about which key made it, so "removed" on a call with a token, or on a
/// call without any, is no statement about this device's key and must not make it forget.
fn removed_only_on_proof(path: &str, error: NetError) -> NetError {
    match error {
        NetError::Server(body) if body.code == api::ErrorCode::DeviceRemoved => {
            if path == api::PROOF_PATH {
                NetError::DeviceRemoved(body.removal_log)
            } else {
                NetError::Protocol(format!("device_removed is no answer of {path}"))
            }
        }
        other => other,
    }
}

/// The largest error body read: a `device_removed` answer carries up to `MAX_LOG_PAGE` device
/// log entries (a few hundred bytes each, in base64url), far more than any other error body.
const MAX_ERROR_BODY: u64 = 1024 * 1024;

fn error_of(resp: Response, traffic: &TrafficCounter) -> NetError {
    let status = resp.status();
    match read_limited(resp, MAX_ERROR_BODY, traffic)
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

fn read_limited(resp: Response, limit: u64, traffic: &TrafficCounter) -> Result<Vec<u8>, NetError> {
    if resp.content_length().is_some_and(|n| n > limit) {
        return Err(NetError::Protocol("the answer is too large".into()));
    }
    let mut out = Vec::new();
    CountingReader::new(resp, traffic)
        .take(limit + 1)
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
                log_length: None,
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
            Body::Bytes(Bytes::copy_from_slice(blob)),
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
        read_limited(resp, max_object(), &self.traffic)
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

    fn set_known_log_length(&mut self, length: u64) {
        self.log_length = Some(length);
    }

    fn set_interrupt(&mut self, interrupt: Interrupt) {
        self.interrupt = Some(interrupt);
    }

    fn fetcher(&mut self) -> Result<Option<Arc<dyn ObjectFetcher>>, NetError> {
        // The workers never sign in themselves, so the session is there before they start.
        if self.token.get().is_none() {
            self.sign_in()?;
        }
        Ok(Some(Arc::new(HttpFetcher {
            client: self.client.clone(),
            base: self.config.url.clone(),
            mismatch: Arc::clone(&self.mismatch),
            traffic: Arc::clone(&self.traffic),
            token: Arc::clone(&self.token),
            slots: Arc::clone(&self.fetch_slots),
            retry: self.config.retry,
        })))
    }

    fn uploader(&mut self) -> Result<Option<Arc<dyn ObjectUploader>>, NetError> {
        // The workers never sign in themselves, so the session is there before they start.
        if self.token.get().is_none() {
            self.sign_in()?;
        }
        Ok(Some(Arc::new(HttpUploader {
            client: self.client.clone(),
            base: self.config.url.clone(),
            mismatch: Arc::clone(&self.mismatch),
            traffic: Arc::clone(&self.traffic),
            token: Arc::clone(&self.token),
            slots: Arc::clone(&self.slots),
            retry: self.config.retry,
        })))
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

    /// The traffic line moves while an upload body goes out, not once its answer came.
    #[test]
    fn an_upload_body_counts_its_bytes_as_they_are_read() {
        let traffic = Arc::new(TrafficCounter::default());
        let mut body = SentBody {
            bytes: Bytes::from(vec![7u8; 100_000]),
            at: 0,
            traffic: Arc::clone(&traffic),
        };
        let mut buf = vec![0u8; 30_000];
        assert_eq!(body.read(&mut buf).unwrap(), 30_000);
        assert_eq!(traffic.totals().sent, 30_000, "counted as it is read");
        let mut rest = Vec::new();
        body.read_to_end(&mut rest).unwrap();
        assert_eq!(rest.len(), 70_000);
        assert_eq!(traffic.totals().sent, 100_000);
        assert_eq!(body.read(&mut buf).unwrap(), 0);
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
