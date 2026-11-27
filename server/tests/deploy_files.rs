//! The deployment files the operator copies (findings M4, M6, L1, L7 of the server security
//! review): `docker-compose.yml` and the proxy examples in `docs/self-hosting.md`. They are
//! configuration, not code, so these tests read them as text and check the settings the review
//! asked for.

use std::path::PathBuf;

fn repo_file(path: &str) -> String {
    let full = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(path);
    std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("{}: {e}", full.display()))
}

/// The lines of `text` that are not YAML comments.
fn active_lines(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect()
}

/// The fenced block of `doc` that starts with "```<lang>".
fn block<'a>(doc: &'a str, lang: &str) -> &'a str {
    let start = doc
        .find(&format!("```{lang}\n"))
        .unwrap_or_else(|| panic!("no {lang} block"));
    let rest = &doc[start + lang.len() + 4..];
    &rest[..rest.find("```").unwrap_or(rest.len())]
}

#[test]
fn compose_trusts_no_proxy_by_default() {
    // L1: the old default trusted 172.16.0.0/12, so every container on any Docker network of
    // the host could set its own X-Forwarded-For and pick its rate limit key.
    let compose = repo_file("docker-compose.yml");
    let active = active_lines(&compose);
    assert!(
        !active
            .iter()
            .any(|l| l.contains("HANGAR_DRIVE_TRUSTED_PROXIES")),
        "the server trusts a proxy only once the operator enables one"
    );
    assert!(!compose.contains("172.16.0.0/12"));
    assert!(compose.contains("# HANGAR_DRIVE_TRUSTED_PROXIES: 172.30.250.10"));
    assert!(compose.contains("ipv4_address: 172.30.250.10"));
}

#[test]
fn compose_limits_memory_and_processes() {
    // M4, L7.
    let compose = repo_file("docker-compose.yml");
    let active = active_lines(&compose);
    assert!(active.iter().any(|l| l.trim() == "mem_limit: 1g"));
    assert!(active.iter().any(|l| l.trim() == "pids_limit: 256"));
}

#[test]
fn the_nginx_example_limits_connections_and_slow_clients() {
    // M6, L7.
    let doc = repo_file("docs/self-hosting.md");
    let nginx = block(&doc, "nginx");
    for setting in [
        "limit_conn_zone $binary_remote_addr",
        "limit_conn drive_conn",
        "client_body_timeout",
        "client_header_timeout",
        "add_header Strict-Transport-Security",
    ] {
        assert!(nginx.contains(setting), "{setting}");
    }
    let sse = &nginx[nginx
        .find("location /api/v1/account/events")
        .expect("the SSE location")..];
    assert!(
        sse.contains("proxy_set_header Host $host;"),
        "the event stream gets the Host header too"
    );
}

#[test]
fn the_caddy_example_sends_hsts_and_times_out_slow_headers() {
    let doc = repo_file("docs/self-hosting.md");
    let caddy = block(&doc, "caddyfile");
    assert!(caddy.contains("Strict-Transport-Security"));
    assert!(caddy.contains("read_header"));
    assert!(!doc.contains("172.16.0.0/12"));
}

#[test]
fn the_image_gives_sqlite_a_writable_temporary_folder() {
    // MEDIUM 3: the container's root file system is read-only (`read_only: true`) and has no
    // writable temporary folder, so SQLite could not spill a large temporary table (the IDs of
    // a large commit) or a sort to disk. The image points it into the data volume, at the
    // folder the server creates and empties at start (`Config::SQLITE_TMP_DIR`).
    let dockerfile = repo_file("server/Dockerfile");
    let env = &dockerfile[dockerfile
        .rfind("ENV HANGAR_DRIVE_DATA_DIR=/data")
        .expect("ENV")..];
    let env = &env[..env.find("\nVOLUME").unwrap_or(env.len())];
    assert!(env.contains("SQLITE_TMPDIR=/data/tmp"), "{env}");
    assert_eq!(hangar_drive_server::config::Config::SQLITE_TMP_DIR, "tmp");
    assert!(dockerfile.contains("VOLUME [\"/data\"]"));
    let compose = repo_file("docker-compose.yml");
    let active = active_lines(&compose);
    assert!(active.iter().any(|l| l.trim() == "read_only: true"));
    assert!(
        active.iter().any(|l| l.trim() == "- drive-data:/data"),
        "the data folder is the volume, so the temporary folder is writable"
    );
    assert!(
        !active
            .iter()
            .any(|l| l.contains("HANGAR_DRIVE_DATA_DIR") && !l.contains("/data")),
        "the data folder stays /data, where SQLITE_TMPDIR points"
    );
}

#[test]
fn the_image_listens_on_every_interface_and_the_binary_on_loopback() {
    // Info 2: outside the image the server listens on loopback unless told otherwise.
    let dockerfile = repo_file("server/Dockerfile");
    assert!(dockerfile.contains("HANGAR_DRIVE_BIND=0.0.0.0"));
    let config = hangar_drive_server::config::Config::from_lookup(|_| None).unwrap();
    assert!(config.bind_addr().ip().is_loopback());
}

#[test]
fn the_backup_command_keeps_the_archive_private_and_pins_its_image() {
    // LOW 4: the archive holds `server.secret`.
    let doc = repo_file("docs/self-hosting.md");
    let backup = &doc[doc.find("## Backups").expect("backups")..];
    let command = block(backup, "sh");
    assert!(command.contains("umask 077"), "{command}");
    assert!(!command.contains(" alpine "), "no unpinned image");
    let compose = repo_file("docker-compose.yml");
    let pinned = compose
        .lines()
        .find_map(|l| l.trim().strip_prefix("#   image: "))
        .expect("the pinned proxy image");
    assert!(pinned.contains("@sha256:"));
    assert!(
        command.contains(pinned),
        "the command uses an image pinned elsewhere in the repository"
    );
}

#[test]
fn the_proxy_examples_send_hsts_like_the_server() {
    // Info 3: the server sends no `includeSubDomains`; the examples match it. Info 4: the
    // nginx example gives large commits and downloads time.
    let doc = repo_file("docs/self-hosting.md");
    assert!(
        !doc.contains("includeSubDomains\""),
        "no includeSubDomains in the examples"
    );
    let nginx = block(&doc, "nginx");
    let folders = &nginx[nginx
        .find("location /api/v1/folders/")
        .expect("the folders location")..];
    assert!(folders.contains("proxy_read_timeout 300s"));
}
