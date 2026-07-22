use std::sync::Arc;

use async_trait::async_trait;
use codeoff_runtime::schedule_service::{
  ChannelTargetVerifier, SlackTargetResolutionRequest, TargetVerificationError, VerifiedSlackTarget,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
  SlackApiErrorClass, SlackAuthIdentity, SlackChannelAddress, SlackHttpClient, SlackUserAddress,
  SlackWebApiClient, SlackWebApiError,
};

const EVIDENCE_VERSION: u32 = 2;

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
  #[allow(clippy::too_many_lines)]
  async fn resolve_target(
    &self,
    workspace_id: Option<&str>,
    actor_id: Option<&str>,
    target: &SlackTargetResolutionRequest,
  ) -> Result<VerifiedSlackTarget, TargetVerificationError> {
    let configured_workspace = self.provider.workspace_summary().workspace_id;
    let authentication = self
      .provider
      .authenticate_bot()
      .await
      .map_err(classify_error)?;
    if configured_workspace != authentication.team_id
      || workspace_id.is_some_and(|workspace_id| workspace_id != authentication.team_id)
    {
      return Err(TargetVerificationError::Unauthorized);
    }
    if let Some(actor_id) = actor_id {
      let actor = self
        .provider
        .get_user(actor_id)
        .await
        .map_err(classify_error)?;
      validate_user(&actor, actor_id, &authentication, false)?;
    }

    let capabilities = self.provider.capabilities();
    if !capabilities.send_messages || !capabilities.proactive_delivery {
      return Err(TargetVerificationError::Unavailable);
    }
    let (kind, channel, thread_ts) = match target {
      SlackTargetResolutionRequest::Channel { channel_id } => {
        let channel = self.resolve_conversation(channel_id).await?;
        validate_conversation_authority(&channel, &authentication)?;
        self.validate_channel(&channel, actor_id).await?;
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
        validate_user(&user, user_id, &authentication, true)?;
        let channel = self
          .provider
          .open_direct_message(&user.user_id)
          .await
          .map_err(classify_error)?;
        validate_conversation_authority(&channel, &authentication)?;
        Self::validate_direct_message(&channel)?;
        ("direct_message", channel, None)
      }
      SlackTargetResolutionRequest::DirectMessageConversation { channel_id } => {
        if !capabilities.direct_messages {
          return Err(TargetVerificationError::Unavailable);
        }
        let channel = self.resolve_conversation(channel_id).await?;
        validate_conversation_authority(&channel, &authentication)?;
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
        validate_conversation_authority(&channel, &authentication)?;
        self.validate_channel(&channel, actor_id).await?;
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
    let host_id = canonical_host_id(&channel, &authentication)?;
    let context_team_id = channel
      .context_team_id
      .clone()
      .ok_or(TargetVerificationError::Unauthorized)?;
    let evidence_digest = evidence_digest(
      &authentication,
      &channel,
      kind,
      thread_ts.as_deref(),
      actor_id,
    );
    Ok(VerifiedSlackTarget {
      workspace_id: authentication.team_id.clone(),
      team_id: authentication.team_id,
      enterprise_id: authentication.enterprise_id,
      context_team_id,
      conversation_host_id: host_id,
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
  ) -> Result<(), TargetVerificationError> {
    if channel.is_archived {
      return Err(TargetVerificationError::Unavailable);
    }
    if channel.is_im || channel.is_mpim {
      return Err(TargetVerificationError::Invalid);
    }
    if !channel.is_member {
      return Err(TargetVerificationError::Unauthorized);
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
    if channel.is_archived {
      return Err(TargetVerificationError::Unavailable);
    }
    if !channel.channel_id.starts_with('D') || !channel.is_im || channel.is_mpim {
      return Err(TargetVerificationError::Invalid);
    }
    Ok(())
  }
}

fn validate_user(
  user: &SlackUserAddress,
  requested_id: &str,
  authentication: &SlackAuthIdentity,
  reject_restricted: bool,
) -> Result<(), TargetVerificationError> {
  if user.user_id != requested_id
    || user.deleted
    || user.is_bot
    || user.is_app_user
    || user.user_id == "USLACKBOT"
    || reject_restricted && (user.is_restricted || user.is_ultra_restricted)
  {
    return Err(TargetVerificationError::Invalid);
  }
  let local_team = user.team_id.as_deref() == Some(authentication.team_id.as_str());
  let enterprise_local = authentication
    .enterprise_id
    .as_deref()
    .is_some_and(|enterprise_id| {
      user.enterprise_id.as_deref() == Some(enterprise_id)
        && user
          .enterprise_team_ids
          .iter()
          .any(|team_id| team_id == &authentication.team_id)
    });
  if !local_team && !enterprise_local {
    return Err(TargetVerificationError::Unauthorized);
  }
  Ok(())
}

fn validate_conversation_authority(
  channel: &SlackChannelAddress,
  authentication: &SlackAuthIdentity,
) -> Result<(), TargetVerificationError> {
  if channel.context_team_id.as_deref() != Some(authentication.team_id.as_str()) {
    return Err(TargetVerificationError::Unauthorized);
  }
  if channel
    .enterprise_id
    .as_deref()
    .is_some_and(|enterprise_id| authentication.enterprise_id.as_deref() != Some(enterprise_id))
  {
    return Err(TargetVerificationError::Unauthorized);
  }
  if channel.is_ext_shared || channel.is_org_shared {
    if !channel.is_shared
      || !channel
        .shared_team_ids
        .iter()
        .any(|team_id| team_id == &authentication.team_id)
    {
      return Err(TargetVerificationError::Unauthorized);
    }
    canonical_host_id(channel, authentication)?;
  } else if channel.is_shared
    || channel
      .shared_team_ids
      .iter()
      .any(|team_id| team_id != &authentication.team_id)
    || !channel.connected_team_ids.is_empty()
  {
    return Err(TargetVerificationError::Unauthorized);
  } else {
    canonical_host_id(channel, authentication)?;
  }
  Ok(())
}

fn canonical_host_id(
  channel: &SlackChannelAddress,
  authentication: &SlackAuthIdentity,
) -> Result<String, TargetVerificationError> {
  let Some(host_id) = channel.conversation_host_id.as_deref() else {
    if channel.is_shared || channel.is_ext_shared || channel.is_org_shared {
      return Err(TargetVerificationError::Unauthorized);
    }
    return Ok(authentication.team_id.clone());
  };
  let valid = if host_id.starts_with('T') {
    host_id == authentication.team_id
      || channel
        .shared_team_ids
        .iter()
        .any(|team_id| team_id == host_id)
      || channel
        .connected_team_ids
        .iter()
        .any(|team_id| team_id == host_id)
  } else if host_id.starts_with('E') {
    authentication.enterprise_id.as_deref() == Some(host_id)
  } else {
    false
  };
  if !valid {
    return Err(TargetVerificationError::Unauthorized);
  }
  Ok(host_id.to_owned())
}

fn classify_error(error: SlackWebApiError) -> TargetVerificationError {
  match error {
    SlackWebApiError::Api { classification, .. } => match classification {
      SlackApiErrorClass::Invalid => TargetVerificationError::Invalid,
      SlackApiErrorClass::Unauthorized => TargetVerificationError::Unauthorized,
      SlackApiErrorClass::TargetUnavailable => TargetVerificationError::Unavailable,
      SlackApiErrorClass::Transient => TargetVerificationError::Transient,
    },
    SlackWebApiError::RateLimited { .. }
    | SlackWebApiError::Request { .. }
    | SlackWebApiError::Deferred { .. } => TargetVerificationError::Transient,
    SlackWebApiError::Unavailable
    | SlackWebApiError::UnsupportedTarget
    | SlackWebApiError::InvalidResponse { .. }
    | SlackWebApiError::Provider { .. } => TargetVerificationError::Unavailable,
  }
}

fn evidence_digest(
  authentication: &SlackAuthIdentity,
  channel: &SlackChannelAddress,
  kind: &str,
  thread_ts: Option<&str>,
  actor_id: Option<&str>,
) -> String {
  let evidence = json!({
    "version": EVIDENCE_VERSION,
    "provider": "slack",
    "team_id": authentication.team_id,
    "enterprise_id": authentication.enterprise_id,
    "bot_user_id": authentication.user_id,
    "bot_id": authentication.bot_id,
    "context_team_id": channel.context_team_id,
    "conversation_host_id": channel.conversation_host_id,
    "kind": kind,
    "channel_id": channel.channel_id,
    "thread_ts": thread_ts,
    "actor_id": actor_id,
    "bot_visibility_verified": true,
    "provider_capability_verified": true,
  });
  let mut digest = Sha256::new();
  digest.update(evidence.to_string().as_bytes());
  format!("{:x}", digest.finalize())
}
