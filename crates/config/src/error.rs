use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
  #[error("failed to read config file {path}: {source}")]
  Read {
    path: PathBuf,
    #[source]
    source: std::io::Error,
  },

  #[error("failed to parse config file {path}: {source}")]
  Parse {
    path: PathBuf,
    #[source]
    source: toml::de::Error,
  },

  #[error("invalid server bind address {value:?}: {source}")]
  InvalidBind {
    value: String,
    #[source]
    source: std::net::AddrParseError,
  },

  #[error("MCP TCP bind address must be loopback: {value:?}")]
  NonLoopbackMcpBind { value: String },

  #[error("unsupported MCP transport {value:?}")]
  UnsupportedMcpTransport { value: String },

  #[error("state.dir must not be empty")]
  EmptyStateDir,

  #[error("database.url must not be empty")]
  EmptyDatabaseUrl,

  #[error("unsupported database driver; only sqlite is supported")]
  UnsupportedDatabaseDriver,
}
