use std::sync::Arc;

use async_trait::async_trait;
use codeoff_runtime::schedule_service::{
  ChannelTargetVerifier, SlackTargetResolutionRequest, TargetVerificationError, VerifiedSlackTarget,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{SlackChannelAddress, SlackHttpClient, SlackWebApiClient, SlackWebApiError};

const EVIDENCE_VERSION: u32 = 1;

pub struct SlackScheduleTargetVerifier<H> {
  provider: Arc<SlackWebApiClient<H>>,
}

impl<H> SlackScheduleTargetVerifier<H> {
  #[must_use]
  pub const fn new(provider: Arc<SlackWebApiClient<H>>) -> Self {
    Self { provider }
  }
}

#[async_trait]
impl<H: SlackHttpClient + Sync + Send> ChannelTargetVerifier for SlackScheduleTargetVerifier<H> {
  async fn resolve_target(
    &self,
    workspace_id: Option<&str>,
    actor_id: Option<&str>,
    target: &SlackTargetResolutionRequest,
  ) -> Result<VerifiedSlackTarget, TargetVerificationError> {
    let configured_workspace = self.provider.workspace_summary().workspace_id;
    if workspace_id.is_some_and(|workspace_id| workspace_id != configured_workspace) {
      return Err(TargetVerificationError::Unauthorized);
    }
    let capabilities = self.provider.capabilities();
    if !capabilities.send_messages || !capabilities.proactive_delivery {
      return Err(TargetVerificationError::Unavailable);
    }
    let (kind, channel, thread_ts) = match target {
      SlackTargetResolutionRequest::Channel { channel_id } => {
        let channel = self.resolve_conversation(channel_id).await?;
        self.validate_channel(&channel, actor_id, false).await?;
        ("channel", channel, None)
      }
      SlackTargetResolutionRequest::DirectMessageUser { user_id } => {
        if !capabilities.direct_messages {
          return Err(TargetVerificationError::Unavailable);
        }
        let user = self
          .provider
          .get_user(user_id)
          .await
          .map_err(classify_error)?;
        if user.is_bot {
          return Err(TargetVerificationError::Invalid);
        }
        let channel = self
          .provider
          .open_direct_message(&user.user_id)
          .await
          .map_err(classify_error)?;
        Self::validate_direct_message(&channel)?;
        ("direct_message", channel, None)
      }
      SlackTargetResolutionRequest::DirectMessageConversation { channel_id } => {
        if !capabilities.direct_messages {
          return Err(TargetVerificationError::Unavailable);
        }
        let channel = self.resolve_conversation(channel_id).await?;
        Self::validate_direct_message(&channel)?;
        ("direct_message", channel, None)
      }
      SlackTargetResolutionRequest::Thread {
        channel_id,
        thread_ts,
      } => {
        if !capabilities.thread_replies {
          return Err(TargetVerificationError::Unavailable);
        }
        let channel = self.resolve_conversation(channel_id).await?;
        self.validate_channel(&channel, actor_id, false).await?;
        let is_root = self
          .provider
          .thread_parent_is_root(&channel.channel_id, thread_ts)
          .await
          .map_err(classify_error)?;
        if !is_root {
          return Err(TargetVerificationError::Invalid);
        }
        ("thread", channel, Some(thread_ts.clone()))
      }
    };
    let evidence_digest = evidence_digest(
      &configured_workspace,
      kind,
      &channel.channel_id,
      thread_ts.as_deref(),
      actor_id,
    );
    Ok(VerifiedSlackTarget {
      workspace_id: configured_workspace,
      kind: kind.to_owned(),
      channel_id: channel.channel_id,
      thread_ts,
      authorization_evidence_version: EVIDENCE_VERSION,
      authorization_evidence_digest: evidence_digest,
    })
  }
}

impl<H: SlackHttpClient + Sync> SlackScheduleTargetVerifier<H> {
  async fn resolve_conversation(
    &self,
    channel_id: &str,
  ) -> Result<SlackChannelAddress, TargetVerificationError> {
    self
      .provider
      .get_channel(channel_id)
      .await
      .map_err(classify_error)
  }

  async fn validate_channel(
    &self,
    channel: &SlackChannelAddress,
    actor_id: Option<&str>,
    direct_message: bool,
  ) -> Result<(), TargetVerificationError> {
    if channel.is_archived
      || channel.is_mpim
      || channel.is_im != direct_message
      || !channel.is_member
    {
      return Err(TargetVerificationError::Unavailable);
    }
    if let Some(actor_id) = actor_id {
      let actor_is_member = self
        .provider
        .actor_is_channel_member(actor_id, &channel.channel_id)
        .await
        .map_err(classify_error)?;
      if !actor_is_member {
        return Err(TargetVerificationError::Unauthorized);
      }
    }
    Ok(())
  }

  fn validate_direct_message(channel: &SlackChannelAddress) -> Result<(), TargetVerificationError> {
    if channel.is_archived || !channel.is_im || channel.is_mpim {
      return Err(TargetVerificationError::Invalid);
    }
    Ok(())
  }
}

fn classify_error(error: SlackWebApiError) -> TargetVerificationError {
  match error {
    SlackWebApiError::RateLimited { .. }
    | SlackWebApiError::Request { .. }
    | SlackWebApiError::InvalidResponse { .. }
    | SlackWebApiError::Deferred { .. } => TargetVerificationError::Transient,
    SlackWebApiError::Unavailable | SlackWebApiError::UnsupportedTarget => {
      TargetVerificationError::Unavailable
    }
    SlackWebApiError::Provider { message } => {
      if matches!(
        message.as_str(),
        "channel_not_found" | "user_not_found" | "thread_not_found" | "invalid_arguments"
      ) {
        TargetVerificationError::Invalid
      } else if matches!(
        message.as_str(),
        "missing_scope" | "not_in_channel" | "restricted_action" | "not_allowed_token_type"
      ) {
        TargetVerificationError::Unauthorized
      } else {
        TargetVerificationError::Transient
      }
    }
  }
}

fn evidence_digest(
  workspace_id: &str,
  kind: &str,
  channel_id: &str,
  thread_ts: Option<&str>,
  actor_id: Option<&str>,
) -> String {
  let evidence = json!({
    "version": EVIDENCE_VERSION,
    "provider": "slack",
    "workspace_id": workspace_id,
    "kind": kind,
    "channel_id": channel_id,
    "thread_ts": thread_ts,
    "actor_id": actor_id,
    "bot_visibility_verified": true,
    "provider_capability_verified": true,
  });
  let mut digest = Sha256::new();
  digest.update(evidence.to_string().as_bytes());
  format!("{:x}", digest.finalize())
}
