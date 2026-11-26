//! Entry point and admin CLI: `hangar-drive-server <command>`, without a command it serves.
//! Configuration: environment variables (`config.rs`, `docs/self-hosting.md`).
//!
//! In Docker the commands run in the running container, for example
//! `docker compose exec server hangar-drive-server invite`. `gc` and `purge` delete data and
//! refuse while the server runs on the same data folder (finding L5); they run with the server
//! stopped: `docker compose run --rm server purge ...`.

use std::io::{BufRead, IsTerminal, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use hangar_drive_crypto::identity::server_key_number;
use hangar_drive_protocol::ids::{AccountId, CommitId, FolderId};
use hangar_drive_server::config::Config;
use hangar_drive_server::service::{accounts, admin, retention};
use hangar_drive_server::{DataDirLock, Deps, StartError};
use tracing_subscriber::EnvFilter;

const USAGE: &str = "usage: hangar-drive-server [command]

  serve                              run the server (default)
  healthcheck                        exit 0 if the local server answers its health check
  invite [--days N]                  create a single-use invite (default 7 days)
  server-key-number [--cert FILE | --spki SHA256-HEX]
                                     print the server key number devices compare
  status                             accounts, usage, pins and warnings
  pin list                           list anomaly pins
  pin lift ACCOUNT COMMIT            lift the pins on a commit
  purge account ACCOUNT [--yes]      delete an account and everything it holds
  purge folder ACCOUNT FOLDER [--yes]
                                     delete one folder with all its versions
  purge retained ACCOUNT [--yes]     delete every version that is not live now
  gc                                 run one garbage collection step now

gc and purge need the server stopped (they refuse while it runs on the data folder).";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration: {error}");
            return ExitCode::from(2);
        }
    };
    let command = args.first().map(String::as_str).unwrap_or("serve");
    if command == "healthcheck" {
        return healthcheck(&config);
    }
    if matches!(command, "-h" | "--help" | "help") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    init_logging(command == "serve");
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("could not start the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(config, &args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(config: Config, args: &[String]) -> Result<()> {
    let command = args.first().map(String::as_str).unwrap_or("serve");
    let rest = args.get(1..).unwrap_or(&[]);
    match command {
        "serve" => serve(config).await,
        "invite" => invite(&config, rest).await,
        "server-key-number" => key_number(&config, rest).await,
        "status" => status(&config).await,
        "pin" => pin(&config, rest).await,
        "purge" => purge(&config, rest).await,
        "gc" => {
            let _lock = DataDirLock::acquire(&config.data_dir)?;
            let (app, _shutdown) = open(&config).await?;
            let outcome = retention::run_step(&app)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            println!("{outcome:?}");
            Ok(())
        }
        other => bail!("unknown command {other:?}\n\n{USAGE}"),
    }
}

async fn open(
    config: &Config,
) -> Result<(
    hangar_drive_server::app::AppState,
    tokio::sync::watch::Sender<bool>,
)> {
    hangar_drive_server::open_app(
        config,
        Deps {
            gc_job: false,
            ..Deps::default()
        },
    )
    .await
    .map_err(|e: StartError| anyhow!("{e}"))
}

async fn serve(config: Config) -> Result<()> {
    let addr = config.bind_addr();
    let server = hangar_drive_server::build(&config, Deps::default())
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("listening on {addr}"))?;
    let l = config.limits;
    tracing::info!(
        %addr,
        tls = server.is_tls(),
        data_dir = %config.data_dir.display(),
        version = hangar_drive_server::VERSION,
        protocol = hangar_drive_protocol::PROTOCOL_VERSION,
        retention_days = l.retention_ms / 86_400_000,
        min_commits = l.min_commits,
        quota = l.quota,
        headroom = l.headroom,
        account_budget = l.account_budget,
        device_budget = l.device_budget,
        trusted_proxies = config.trusted_proxies.len(),
        "server ready"
    );
    hangar_drive_server::serve(server, listener, shutdown_signal()).await?;
    tracing::info!("stopped");
    Ok(())
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

async fn invite(config: &Config, args: &[String]) -> Result<()> {
    let days = match flag(args, "--days") {
        None => 7,
        Some(d) => d
            .parse::<u32>()
            .ok()
            .filter(|d| (1..=accounts::MAX_INVITE_DAYS).contains(d))
            .ok_or_else(|| anyhow!("--days must be 1 to {}", accounts::MAX_INVITE_DAYS))?,
    };
    let (app, _shutdown) = open(config).await?;
    let (token, expires_ms) = accounts::create_invite(&app.db, app.now_ms(), days).await?;
    eprintln!(
        "Single-use invite, valid for {days} days (until {} UTC). It is shown only now.",
        format_ms(expires_ms)
    );
    println!("{}", token.expose_base64url().as_str());
    Ok(())
}

async fn key_number(config: &Config, args: &[String]) -> Result<()> {
    let pin: [u8; 32] = if let Some(hex) = flag(args, "--spki") {
        let bytes = decode_hex(hex).ok_or_else(|| {
            anyhow!("--spki takes the SHA-256 of the SubjectPublicKeyInfo as 64 hex digits")
        })?;
        bytes
            .try_into()
            .map_err(|_| anyhow!("--spki takes 32 bytes (64 hex digits)"))?
    } else {
        let path = match flag(args, "--cert") {
            Some(p) => std::path::PathBuf::from(p),
            None => config.tls.as_ref().map(|t| t.cert.clone()).ok_or_else(|| {
                anyhow!("give --cert FILE or --spki HEX, or set HANGAR_DRIVE_TLS_CERT")
            })?,
        };
        hangar_drive_server::tls::spki_pin_of_file(&path)?
    };
    let (app, _shutdown) = open(config).await?;
    let number = server_key_number(&app.server_id, &pin);
    eprintln!(
        "Server key number of server {} (compare it with the number the device shows):",
        app.server_id
    );
    println!("{number}");
    Ok(())
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

fn format_ms(ms: u64) -> String {
    let secs = ms / 1000;
    let days = secs / 86_400;
    let (y, m, d) = civil_from_days(i64::try_from(days).unwrap_or(0));
    let rem = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        rem / 3600,
        (rem % 3600) / 60
    )
}

/// Days since 1970-01-01 to a calendar date (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1u64 << 20) as f64)
}

async fn status(config: &Config) -> Result<()> {
    let (app, _shutdown) = open(config).await?;
    let status = admin::status(&app).await.map_err(|e| anyhow!("{e}"))?;
    println!(
        "server {}  version {}",
        app.server_id,
        hangar_drive_server::VERSION
    );
    match status.disk_available {
        Some(free) => println!(
            "disk: {} free, reserve {}",
            mib(free),
            mib(status.disk_reserve)
        ),
        None => println!("disk: free space unknown on this platform"),
    }
    println!("open invites: {}", status.open_invites);
    println!("accounts: {}", status.accounts.len());
    for a in &status.accounts {
        println!(
            "{}\tdevices {}\tfolders {} ({} retired)\tlive {}\tstored {}\tpins {}\t{}",
            a.id,
            a.devices,
            a.folders,
            a.retired_folders,
            mib(a.live_bytes),
            mib(a.stored_bytes),
            a.pins,
            if a.warnings.is_empty() {
                "ok".to_owned()
            } else {
                a.warnings.join(", ")
            }
        );
    }
    Ok(())
}

async fn pin(config: &Config, args: &[String]) -> Result<()> {
    let (app, _shutdown) = open(config).await?;
    match args.first().map(String::as_str) {
        Some("list") => {
            for p in admin::pins(&app).await.map_err(|e| anyhow!("{e}"))? {
                println!(
                    "{}\t{}\t{}\tcreated {}\tuntil {}{}",
                    p.account,
                    p.folder,
                    p.commit,
                    format_ms(p.created_ms),
                    format_ms(p.until_ms),
                    if p.lapsed { "\tlapsed" } else { "" }
                );
            }
            Ok(())
        }
        Some("lift") => {
            let account = parse_account(args.get(1))?;
            let commit = args
                .get(2)
                .and_then(|c| CommitId::from_hex(c).ok())
                .ok_or_else(|| anyhow!("usage: pin lift ACCOUNT COMMIT"))?;
            let lifted = admin::lift_pin(&app, &account, &commit)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            if lifted == 0 {
                bail!("no pin on that commit");
            }
            eprintln!("lifted {lifted} pin(s); the next garbage collection step frees what only they held");
            Ok(())
        }
        _ => bail!("usage: pin list | pin lift ACCOUNT COMMIT"),
    }
}

fn parse_account(arg: Option<&String>) -> Result<AccountId> {
    arg.and_then(|a| AccountId::from_hex(a).ok())
        .ok_or_else(|| anyhow!("ACCOUNT is the account ID in hex (see status)"))
}

/// What the operator types to confirm a purge: the ID of what goes. A folder purge asks for
/// the folder ID (finding L6), so an account ID copied from `status` cannot confirm the
/// deletion of a folder the operator did not look at.
fn confirmation_for(
    kind: &str,
    account: &AccountId,
    folder: Option<&FolderId>,
) -> (&'static str, String) {
    match (kind, folder) {
        ("folder", Some(folder)) => ("folder ID", folder.to_hex()),
        _ => ("account ID", account.to_hex()),
    }
}

/// Asks the operator to type `expected` (named `label`), unless `--yes` was given.
fn confirm(args: &[String], what: &str, label: &str, expected: &str) -> Result<()> {
    if args.iter().any(|a| a == "--yes") {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        bail!("refusing to {what} without a terminal; add --yes to confirm");
    }
    eprint!("This will {what} at once and cannot be undone. Type the {label} to confirm: ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    confirmed(&line, expected)
}

fn confirmed(line: &str, expected: &str) -> Result<()> {
    if line.trim() != expected {
        bail!("not confirmed");
    }
    Ok(())
}

async fn purge(config: &Config, args: &[String]) -> Result<()> {
    let kind = args.first().map(String::as_str);
    let account = parse_account(args.get(1))?;
    let _lock = DataDirLock::acquire(&config.data_dir)?;
    let (app, _shutdown) = open(config).await?;
    match kind {
        Some("account") => {
            let (label, expected) = confirmation_for("account", &account, None);
            confirm(
                args,
                "delete the account and everything it holds",
                label,
                &expected,
            )?;
            admin::purge_account(&app, &account)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            eprintln!("account deleted");
        }
        Some("folder") => {
            let folder = args
                .get(2)
                .and_then(|f| FolderId::from_hex(f).ok())
                .ok_or_else(|| anyhow!("usage: purge folder ACCOUNT FOLDER"))?;
            let (label, expected) = confirmation_for("folder", &account, Some(&folder));
            confirm(
                args,
                "delete the folder with all its versions",
                label,
                &expected,
            )?;
            admin::purge_folder(&app, &account, &folder)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            eprintln!("folder deleted");
        }
        Some("retained") => {
            let (label, expected) = confirmation_for("retained", &account, None);
            confirm(
                args,
                "delete every version that is not live",
                label,
                &expected,
            )?;
            let outcome = admin::purge_retained(&app, &account)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            eprintln!(
                "deleted {} objects ({}) and {} commit bodies",
                outcome.deleted_objects,
                mib(outcome.deleted_bytes),
                outcome.deleted_side_commits
            );
        }
        _ => bail!("usage: purge account|folder|retained ACCOUNT [FOLDER] [--yes]"),
    }
    Ok(())
}

/// Completes on Ctrl+C or, on Unix, on SIGTERM (what `docker stop` sends).
async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => tracing::info!("Ctrl+C received, shutting down"),
        () = terminate => tracing::info!("SIGTERM received, shutting down"),
    }
}

/// With TLS in the server the probe cannot speak plain HTTP to it; then an accepted TCP
/// connection counts as healthy.
fn healthcheck(config: &Config) -> ExitCode {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, config.port));
    let timeout = Duration::from_secs(3);
    let ok = if config.tls.is_some() {
        std::net::TcpStream::connect_timeout(&addr, timeout).is_ok()
    } else {
        matches!(
            hangar_drive_server::probe::health_ok(addr, timeout),
            Ok(true)
        )
    };
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Log level from `RUST_LOG`; `info` for the server, `warn` for CLI commands, whose output is
/// for the operator.
fn init_logging(serving: bool) {
    let default = if serving { "info,sqlx=warn" } else { "warn" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_hex() {
        assert_eq!(format_ms(0), "1970-01-01 00:00");
        assert_eq!(format_ms(1_767_225_600_000), "2026-01-01 00:00");
        assert_eq!(decode_hex("00ff"), Some(vec![0, 255]));
        assert_eq!(decode_hex("0"), None);
    }

    #[test]
    fn a_folder_purge_is_confirmed_with_the_folder_id() {
        let account = AccountId::from_bytes([1; 16]);
        let folder = FolderId::from_bytes([2; 16]);
        let (label, expected) = confirmation_for("folder", &account, Some(&folder));
        assert_eq!(
            (label, expected.as_str()),
            ("folder ID", folder.to_hex().as_str())
        );
        assert!(confirmed(&format!("{}\n", folder.to_hex()), &expected).is_ok());
        assert!(
            confirmed(&account.to_hex(), &expected).is_err(),
            "the account ID does not confirm a folder purge"
        );
        let (label, expected) = confirmation_for("account", &account, None);
        assert_eq!((label, expected), ("account ID", account.to_hex()));
    }
}
