use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChannelContractError {
  #[error("{field} must not be empty")]
  EmptyField { field: &'static str },

  #[error("{field} must be greater than zero")]
  InvalidLimit { field: &'static str },

  #[error("connector does not support capability {capability}")]
  UnsupportedCapability { capability: &'static str },

  #[error("connector does not support reply target {target}")]
  UnsupportedReplyTarget { target: &'static str },
}

pub(crate) fn require_non_empty(
  value: &str,
  field: &'static str,
) -> Result<(), ChannelContractError> {
  if value.trim().is_empty() {
    return Err(ChannelContractError::EmptyField { field });
  }

  Ok(())
}
