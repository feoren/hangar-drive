//! Entry point: `hangar-drive-server [serve|healthcheck]`. Without a command it serves.
//! Configuration: environment variables, see `config.rs`.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use hangar_drive_server::config::Config;
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    let command = std::env::args().nth(1);
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration: {error}");
            return ExitCode::from(2);
        }
    };
    match command.as_deref() {
        None | Some("serve") => serve(config),
        Some("healthcheck") => healthcheck(&config),
        Some(other) => {
            eprintln!("unknown command {other:?}; usage: hangar-drive-server [serve|healthcheck]");
            ExitCode::from(2)
        }
    }
}

fn serve(config: Config) -> ExitCode {
    init_logging();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "could not start the async runtime");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "server stopped with an error");
            ExitCode::FAILURE
        }
    }
}

async fn run(config: Config) -> Result<(), String> {
    // Created up front, so a volume without write access fails at startup and not on the first
    // upload.
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|e| format!("data folder {}: {e}", config.data_dir.display()))?;
    let addr = config.bind_addr();
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("{addr}: {e}"))?;
    tracing::info!(
        %addr,
        data_dir = %config.data_dir.display(),
        version = hangar_drive_server::VERSION,
        protocol = hangar_drive_protocol::PROTOCOL_VERSION,
        "server ready"
    );
    hangar_drive_server::serve(listener, shutdown_signal())
        .await
        .map_err(|e| e.to_string())?;
    tracing::info!("stopped");
    Ok(())
}

/// Completes on Ctrl+C or, on Unix, on SIGTERM (what `docker stop` sends).
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "Ctrl+C handler unavailable");
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
            Err(error) => {
                tracing::warn!(%error, "SIGTERM handler unavailable");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => tracing::info!("Ctrl+C received, shutting down"),
        () = terminate => tracing::info!("SIGTERM received, shutting down"),
    }
}

fn healthcheck(config: &Config) -> ExitCode {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, config.port));
    match hangar_drive_server::probe::health_ok(addr, Duration::from_secs(3)) {
        Ok(true) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

/// Log level from `RUST_LOG` (for example `debug`), `info` without it.
fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
