use crate::{
  ChannelConnectorCapabilities, ChannelContextPage, ChannelContextRequest, ChannelContractError,
  ChannelMessageReceipt, ChannelMessageRequest,
};

pub trait ChannelConnector {
  fn connector_id(&self) -> &str;

  fn capabilities(&self) -> ChannelConnectorCapabilities;

  /// Sends a message through the connector.
  ///
  /// # Errors
  ///
  /// The default implementation returns an unsupported-capability error.
  fn send_message(
    &self,
    _request: ChannelMessageRequest,
  ) -> Result<ChannelMessageReceipt, ChannelContractError> {
    Err(ChannelContractError::UnsupportedCapability {
      capability: "send_messages",
    })
  }

  /// Fetches a bounded page of context through the connector.
  ///
  /// # Errors
  ///
  /// The default implementation returns an unsupported-capability error.
  fn fetch_context(
    &self,
    _request: ChannelContextRequest,
  ) -> Result<ChannelContextPage, ChannelContractError> {
    Err(ChannelContractError::UnsupportedCapability {
      capability: "history_fetch",
    })
  }
}
