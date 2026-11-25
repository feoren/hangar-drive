//! Configuration from environment variables. An invalid value stops the server at startup with a
//! message naming the variable, instead of running with a value nobody chose.

use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use thiserror::Error;

/// TCP port the server listens on.
pub const PORT_VAR: &str = "HANGAR_DRIVE_PORT";
/// Folder for the server's data (file versions, later the database).
pub const DATA_DIR_VAR: &str = "HANGAR_DRIVE_DATA_DIR";

pub const DEFAULT_PORT: u16 = 8080;
/// Relative to the working directory; the container image sets `/data`, its volume.
pub const DEFAULT_DATA_DIR: &str = "data";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub port: u16,
    pub data_dir: PathBuf,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{PORT_VAR} must be a port number from 1 to 65535, not {0:?}")]
    InvalidPort(String),
    #[error("{DATA_DIR_VAR} must not be empty")]
    EmptyDataDir,
}

impl Config {
    /// Reads the configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var_os(name))
    }

    /// Reads the configuration through `lookup`, which returns a variable's value if it is set.
    /// Unset variables take their default.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        let port = match lookup(PORT_VAR) {
            None => DEFAULT_PORT,
            Some(value) => parse_port(&value)?,
        };
        let data_dir = match lookup(DATA_DIR_VAR) {
            None => PathBuf::from(DEFAULT_DATA_DIR),
            Some(value) if value.is_empty() => return Err(ConfigError::EmptyDataDir),
            Some(value) => PathBuf::from(value),
        };
        Ok(Self { port, data_dir })
    }

    /// Address to listen on: every IPv4 interface, as a container needs it. On a host, a reverse
    /// proxy or the port mapping decides who can reach it.
    pub fn bind_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, self.port))
    }
}

fn parse_port(value: &OsString) -> Result<u16, ConfigError> {
    let text = value.to_string_lossy();
    match text.trim().parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(ConfigError::InvalidPort(text.into_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
        Config::from_lookup(|name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        })
    }

    #[test]
    fn uses_the_defaults_without_variables() {
        let config = config(&[]).unwrap();
        assert_eq!(config.port, DEFAULT_PORT);
        assert_eq!(config.data_dir, PathBuf::from(DEFAULT_DATA_DIR));
    }

    #[test]
    fn reads_port_and_data_dir() {
        let config = config(&[(PORT_VAR, "9000"), (DATA_DIR_VAR, "/srv/drive data")]).unwrap();
        assert_eq!(config.port, 9000);
        assert_eq!(config.data_dir, PathBuf::from("/srv/drive data"));
    }

    #[test]
    fn tolerates_spaces_around_the_port() {
        assert_eq!(config(&[(PORT_VAR, " 8081\n")]).unwrap().port, 8081);
    }

    #[test]
    fn rejects_invalid_ports() {
        for value in ["", "0", "65536", "-1", "http", "80a"] {
            assert_eq!(
                config(&[(PORT_VAR, value)]),
                Err(ConfigError::InvalidPort(value.to_owned())),
                "{value:?}"
            );
        }
    }

    #[test]
    fn rejects_an_empty_data_dir() {
        assert_eq!(
            config(&[(DATA_DIR_VAR, "")]),
            Err(ConfigError::EmptyDataDir)
        );
    }

    #[test]
    fn names_the_variable_in_the_error() {
        let message = ConfigError::InvalidPort("x".into()).to_string();
        assert!(message.contains(PORT_VAR), "{message}");
    }

    #[test]
    fn listens_on_every_ipv4_interface() {
        let config = config(&[(PORT_VAR, "8123")]).unwrap();
        assert_eq!(config.bind_addr(), "0.0.0.0:8123".parse().unwrap());
    }
}
