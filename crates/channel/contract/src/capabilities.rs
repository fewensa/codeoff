use crate::ChannelReplyTarget;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ChannelConnectorCapabilities {
  pub receive_events: bool,
  pub slash_commands: bool,
  pub interactive_actions: bool,
  pub modal_inputs: bool,
  pub send_messages: bool,
  pub thread_replies: bool,
  pub direct_messages: bool,
  pub ephemeral_messages: bool,
  pub message_updates: bool,
  pub history_fetch: bool,
  pub user_profile_fetch: bool,
  pub socket_transport: bool,
  pub http_transport: bool,
  pub proactive_delivery: bool,
}

impl ChannelConnectorCapabilities {
  #[must_use]
  pub fn supports_reply_target(self, target: &ChannelReplyTarget) -> bool {
    self.send_messages
      && match target {
        ChannelReplyTarget::Channel { .. } => true,
        ChannelReplyTarget::Thread { .. } => self.thread_replies,
        ChannelReplyTarget::DirectMessage { .. } => self.direct_messages,
        ChannelReplyTarget::Ephemeral { .. } => self.ephemeral_messages,
      }
  }
}
