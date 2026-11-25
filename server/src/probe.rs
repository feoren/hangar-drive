//! The container's health check. The runtime image has no shell and no curl, so the server binary
//! checks itself: `hangar-drive-server healthcheck` asks its own port for [`HEALTH_PATH`].

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use hangar_drive_protocol::HEALTH_PATH;

/// Whether the server at `addr` answers [`HEALTH_PATH`] with `200 OK`, each step (connecting,
/// writing, reading) within `timeout`.
pub fn health_ok(addr: SocketAddr, timeout: Duration) -> std::io::Result<bool> {
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let request =
        format!("GET {HEALTH_PATH} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    // The status line is all that counts: "HTTP/1.1 200" is 12 bytes.
    let mut head = [0u8; 12];
    stream.read_exact(&mut head)?;
    Ok(&head == b"HTTP/1.1 200")
}
