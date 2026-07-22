use async_trait::async_trait;
use codeoff_runtime::scheduled_delivery::{
  DeliveryProvider, DeliveryProviderOutcome, DeliveryProviderReadiness,
  DeliveryProviderReadinessRequest, DeliveryProviderRequest, ProviderMessageIdentity,
};
use serde::Deserialize;

use crate::{SlackApiErrorClass, SlackHttpClient, SlackWebApiClient, SlackWebApiError};

pub struct SlackScheduledDeliveryProvider<H> {
  api: SlackWebApiClient<H>,
  connector_id: String,
  workspace_id: String,
}

impl<H: SlackHttpClient + Sync> SlackScheduledDeliveryProvider<H> {
  #[must_use]
  pub fn new(api: SlackWebApiClient<H>) -> Self {
    let summary = api.workspace_summary();
    Self {
      api,
      connector_id: summary.connector_id,
      workspace_id: summary.workspace_id,
    }
  }

  #[must_use]
  pub const fn http_client(&self) -> &H {
    self.api.http_client()
  }
}

impl<H: SlackHttpClient + Sync> SlackScheduledDeliveryProvider<H> {
  /// Proves that the configured bot credential belongs to the configured delivery workspace.
  ///
  /// # Errors
  /// Returns a redacted Slack error or a typed authority rejection.
  pub async fn verify_authority(&self) -> Result<(), SlackWebApiError> {
    let identity = self.api.authenticate_bot().await?;
    if identity.team_id != self.workspace_id {
      return Err(SlackWebApiError::Api {
        classification: SlackApiErrorClass::Unauthorized,
      });
    }
    Ok(())
  }

  /// Verifies a persisted target against this connector and workspace without provider I/O.
  ///
  /// # Errors
  /// Returns a stable classification when the target is malformed or outside this authority.
  pub fn verify_target_authority(&self, target_json: &str) -> Result<(), &'static str> {
    parse_target(target_json, &self.connector_id, &self.workspace_id).map(|_| ())
  }
}

#[async_trait]
impl<H: SlackHttpClient + Sync + Send> DeliveryProvider for SlackScheduledDeliveryProvider<H> {
  async fn readiness(
    &self,
    request: DeliveryProviderReadinessRequest<'_>,
  ) -> DeliveryProviderReadiness {
    if let Err(error_kind) = self.verify_target_authority(request.target_json) {
      return DeliveryProviderReadiness::Permanent {
        error_kind: error_kind.to_owned(),
      };
    }
    match self.verify_authority().await {
      Ok(()) => DeliveryProviderReadiness::Ready,
      Err(error) => classify_readiness_error(error),
    }
  }

  async fn send(&self, request: DeliveryProviderRequest<'_>) -> DeliveryProviderOutcome {
    let target = match parse_target(request.target_json, &self.connector_id, &self.workspace_id) {
      Ok(target) => target,
      Err(kind) => {
        return DeliveryProviderOutcome::ConfirmedNoWriteTerminal {
          error_kind: kind.to_owned(),
        };
      }
    };
    match self
      .api
      .post_message(
        &target.channel_id,
        target.thread_ts.as_deref(),
        request.payload.body(),
      )
      .await
    {
      Ok(posted) if valid_posted_route(&posted, &target, &self.workspace_id) => {
        DeliveryProviderOutcome::ConfirmedSuccess(ProviderMessageIdentity {
          provider: "slack".to_owned(),
          tenant: self.workspace_id.clone(),
          conversation_id: posted.channel_id,
          thread_id: posted.thread_ts,
          message_id: posted.message_ts,
        })
      }
      Ok(_) => DeliveryProviderOutcome::AmbiguousPostWrite {
        error_kind: "slack_response_route_mismatch".to_owned(),
      },
      Err(error) => classify_error(error),
    }
  }
}

fn classify_readiness_error(error: SlackWebApiError) -> DeliveryProviderReadiness {
  match error {
    SlackWebApiError::RateLimited {
      retry_after_seconds,
    } => DeliveryProviderReadiness::Retryable {
      retry_after_seconds,
      error_kind: "slack_authority_rate_limited".to_owned(),
    },
    SlackWebApiError::Request { .. }
    | SlackWebApiError::InvalidResponse { .. }
    | SlackWebApiError::Provider { .. }
    | SlackWebApiError::Deferred { .. }
    | SlackWebApiError::Api {
      classification: SlackApiErrorClass::Transient,
    } => DeliveryProviderReadiness::Retryable {
      retry_after_seconds: None,
      error_kind: "slack_authority_unavailable".to_owned(),
    },
    SlackWebApiError::Api {
      classification:
        SlackApiErrorClass::Invalid
        | SlackApiErrorClass::Unauthorized
        | SlackApiErrorClass::TargetUnavailable,
    }
    | SlackWebApiError::Unavailable
    | SlackWebApiError::UnsupportedTarget => DeliveryProviderReadiness::Permanent {
      error_kind: "slack_authority_rejected".to_owned(),
    },
  }
}

struct SlackCanonicalTarget {
  channel_id: String,
  thread_ts: Option<String>,
}

fn valid_posted_route(
  posted: &crate::SlackPostedMessage,
  target: &SlackCanonicalTarget,
  workspace_id: &str,
) -> bool {
  posted.channel_id == target.channel_id
    && valid_slack_id(&posted.channel_id)
    && valid_slack_timestamp(&posted.message_ts)
    && posted.response_message_ts.as_deref() == Some(posted.message_ts.as_str())
    && posted.thread_ts == target.thread_ts
    && posted
      .response_team_id
      .as_deref()
      .is_none_or(|team_id| team_id == workspace_id)
}

fn parse_target(
  target_json: &str,
  connector_id: &str,
  workspace_id: &str,
) -> Result<SlackCanonicalTarget, &'static str> {
  let target: TargetSnapshot =
    serde_json::from_str(target_json).map_err(|_| "invalid_slack_target")?;
  if target.provider != "slack"
    || target.connector != connector_id
    || target.tenant != workspace_id
    || target.resolver_version == 0
    || target.resolver_digest.is_empty()
    || !valid_sha256(&target.identity_digest)
    || target.address.schema_version == 0
    || target.address.workspace_id != workspace_id
    || target.address.routing_authority.team != workspace_id
    || target.address.routing_authority.context_team != workspace_id
    || target.address.created_at < 0
    || target.address.authorization_evidence.version == 0
    || !valid_sha256(&target.address.authorization_evidence.digest)
    || !valid_sha256(&target.address.requested_identity_digest)
    || !valid_provider_authority(&target.address.routing_authority)
  {
    return Err("slack_target_authority_mismatch");
  }
  let channel_id = target.address.coordinates.channel_id;
  let thread_ts = target.address.coordinates.thread_ts;
  match target.kind.as_str() {
    "channel"
      if channel_id.starts_with('C') && thread_ts.is_none() && valid_slack_id(&channel_id) => {}
    "direct_message"
      if channel_id.starts_with('D') && thread_ts.is_none() && valid_slack_id(&channel_id) => {}
    "thread"
      if channel_id.starts_with('C')
        && thread_ts.as_deref().is_some_and(valid_slack_timestamp)
        && valid_slack_id(&channel_id) => {}
    _ => return Err("invalid_slack_target_route"),
  }
  Ok(SlackCanonicalTarget {
    channel_id,
    thread_ts,
  })
}

fn classify_error(error: SlackWebApiError) -> DeliveryProviderOutcome {
  match error {
    SlackWebApiError::RateLimited {
      retry_after_seconds,
    } => DeliveryProviderOutcome::ConfirmedNoWriteRetryable {
      retry_after_seconds,
      error_kind: "slack_rate_limited".to_owned(),
    },
    SlackWebApiError::Api {
      classification:
        SlackApiErrorClass::Invalid
        | SlackApiErrorClass::Unauthorized
        | SlackApiErrorClass::TargetUnavailable,
    }
    | SlackWebApiError::Unavailable
    | SlackWebApiError::UnsupportedTarget => DeliveryProviderOutcome::ConfirmedNoWriteTerminal {
      error_kind: "slack_request_rejected".to_owned(),
    },
    SlackWebApiError::Deferred { .. } => DeliveryProviderOutcome::ConfirmedNoWriteRetryable {
      retry_after_seconds: None,
      error_kind: "slack_deferred".to_owned(),
    },
    SlackWebApiError::Request { .. }
    | SlackWebApiError::InvalidResponse { .. }
    | SlackWebApiError::Provider { .. }
    | SlackWebApiError::Api {
      classification: SlackApiErrorClass::Transient,
    } => DeliveryProviderOutcome::AmbiguousPostWrite {
      error_kind: "slack_write_outcome_unknown".to_owned(),
    },
  }
}

fn valid_slack_id(value: &str) -> bool {
  value.len() > 1
    && value
      .bytes()
      .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn valid_slack_timestamp(value: &str) -> bool {
  let Some((seconds, micros)) = value.split_once('.') else {
    return false;
  };
  !seconds.is_empty()
    && seconds.bytes().all(|byte| byte.is_ascii_digit())
    && micros.len() == 6
    && micros.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_sha256(value: &str) -> bool {
  value.len() == 64
    && value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_provider_authority(authority: &RoutingAuthority) -> bool {
  authority
    .enterprise
    .as_deref()
    .is_none_or(|enterprise_id| enterprise_id.starts_with('E'))
    && (authority.conversation_host.starts_with('T')
      || authority.conversation_host.starts_with('E'))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetSnapshot {
  provider: String,
  connector: String,
  tenant: String,
  kind: String,
  address: SlackAddress,
  resolver_version: u32,
  resolver_digest: String,
  identity_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlackAddress {
  schema_version: u32,
  workspace_id: String,
  routing_authority: RoutingAuthority,
  coordinates: SlackCoordinates,
  authorization_evidence: AuthorizationEvidence,
  requested_identity_digest: String,
  created_at: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoutingAuthority {
  #[serde(rename = "team_id")]
  team: String,
  #[serde(rename = "enterprise_id")]
  enterprise: Option<String>,
  #[serde(rename = "context_team_id")]
  context_team: String,
  #[serde(rename = "conversation_host_id")]
  conversation_host: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlackCoordinates {
  channel_id: String,
  #[serde(default)]
  thread_ts: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationEvidence {
  version: u32,
  digest: String,
}
