use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use codeoff_agent_contract::{ChannelTaskContext, ConversationKind, InvocationPrincipalRef};
use codeoff_state::{CapabilityProfileSnapshot, DeliveryTargetSnapshot, PrincipalKey};
use serde_json::{Value, json};

use crate::schedule_authorization::ScheduleInvocation;
use crate::schedule_service::{
  SNAPSHOT_VERSION, ScheduleServiceError, bounded, canonical_json, digest_json,
};

const SLACK_CONNECTOR: &str = "slack-default";
const SLACK_RESOLVER_DIGEST: &str = "slack-web-api-v2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryTargetRequest {
  None,
  Origin,
  Channel {
    channel_id: String,
  },
  DirectMessage {
    user_id: String,
  },
  Thread {
    channel_id: String,
    thread_id: String,
  },
}

#[async_trait]
pub trait TargetResolver: Send + Sync {
  async fn resolve(
    &self,
    invocation: &ScheduleInvocation,
    owner: &PrincipalKey,
    target: &DeliveryTargetRequest,
    now: i64,
  ) -> Result<Vec<DeliveryTargetSnapshot>, ScheduleServiceError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetResolverAuthority {
  provider: String,
  connector: String,
  resolver_version: u32,
  resolver_digest: String,
}

pub struct TargetResolverRegistration {
  authority: TargetResolverAuthority,
  supported_kinds: Vec<&'static str>,
  resolver: Arc<dyn TargetResolver>,
}

impl TargetResolverRegistration {
  /// Binds a resolver implementation to trusted connector and snapshot metadata.
  ///
  /// # Errors
  /// Returns an error when registration metadata or supported target kinds are invalid.
  pub fn new(
    provider: &str,
    connector: &str,
    resolver_version: u32,
    resolver_digest: &str,
    supported_kinds: Vec<&'static str>,
    resolver: Arc<dyn TargetResolver>,
  ) -> Result<Self, ScheduleServiceError> {
    bounded("resolver provider", provider)?;
    bounded("resolver connector", connector)?;
    bounded("resolver digest", resolver_digest)?;
    if resolver_version == 0 || supported_kinds.is_empty() {
      return Err(ScheduleServiceError::InvalidRequest(
        "resolver registration must have a positive version and supported target kind".to_owned(),
      ));
    }
    for kind in &supported_kinds {
      if !matches!(
        *kind,
        "none" | "origin" | "channel" | "direct_message" | "thread"
      ) {
        return Err(ScheduleServiceError::InvalidRequest(
          "resolver registration contains an unsupported target kind".to_owned(),
        ));
      }
    }
    let mut supported_kinds = supported_kinds;
    supported_kinds.sort_unstable();
    supported_kinds.dedup();
    Ok(Self {
      authority: TargetResolverAuthority {
        provider: provider.to_owned(),
        connector: connector.to_owned(),
        resolver_version,
        resolver_digest: resolver_digest.to_owned(),
      },
      supported_kinds,
      resolver,
    })
  }
}

pub(crate) struct ResolvedTargetSet {
  authority: TargetResolverAuthority,
  snapshots: Vec<DeliveryTargetSnapshot>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultTargetResolver;

#[async_trait]
impl TargetResolver for DefaultTargetResolver {
  async fn resolve(
    &self,
    _invocation: &ScheduleInvocation,
    owner: &PrincipalKey,
    target: &DeliveryTargetRequest,
    _now: i64,
  ) -> Result<Vec<DeliveryTargetSnapshot>, ScheduleServiceError> {
    let (provider, connector, tenant, kind, address) = match target {
      DeliveryTargetRequest::None => (
        "none".to_owned(),
        "none".to_owned(),
        owner.tenant().to_owned(),
        "none".to_owned(),
        json!({}),
      ),
      DeliveryTargetRequest::Origin
      | DeliveryTargetRequest::Channel { .. }
      | DeliveryTargetRequest::DirectMessage { .. }
      | DeliveryTargetRequest::Thread { .. } => {
        return Err(ScheduleServiceError::ResolverNotAllowed);
      }
    };
    let address_json = canonical_json(&address)?;
    let identity_digest = digest_json(&json!({
      "provider": provider,
      "connector": connector,
      "tenant": tenant,
      "kind": kind,
      "address": address,
    }))?;
    let target_id = format!("target_{}", &identity_digest[..32]);
    let resolver_digest = "default-none-v1";
    let snapshot = DeliveryTargetSnapshot::new(
      target_id,
      provider,
      connector,
      tenant,
      kind,
      address_json,
      SNAPSHOT_VERSION,
      resolver_digest,
      identity_digest,
    )
    .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))?;
    Ok(vec![snapshot])
  }
}

#[derive(Default)]
pub struct TargetResolverRegistry {
  registrations: Vec<TargetResolverRegistration>,
}

impl TargetResolverRegistry {
  #[must_use]
  pub fn with_defaults() -> Self {
    Self {
      registrations: vec![TargetResolverRegistration {
        authority: TargetResolverAuthority {
          provider: "none".to_owned(),
          connector: "none".to_owned(),
          resolver_version: SNAPSHOT_VERSION,
          resolver_digest: "default-none-v1".to_owned(),
        },
        supported_kinds: vec!["none"],
        resolver: Arc::new(DefaultTargetResolver),
      }],
    }
  }

  pub fn register(&mut self, registration: TargetResolverRegistration) {
    self.registrations.push(registration);
  }

  #[must_use]
  pub fn describe_supported_targets(&self, invocation: &ScheduleInvocation) -> Vec<&'static str> {
    let provider = match invocation.principal.as_ref() {
      InvocationPrincipalRef::ChannelActor { provider, .. } => Some(provider),
      InvocationPrincipalRef::Service { .. } => None,
    };
    let mut kinds = self
      .registrations
      .iter()
      .filter(|registration| {
        registration.authority.provider == "none"
          || provider.is_none_or(|provider| registration.authority.provider == provider)
      })
      .flat_map(|registration| registration.supported_kinds.iter().copied())
      .collect::<Vec<_>>();
    kinds.sort_unstable();
    kinds.dedup();
    kinds
  }

  pub(crate) async fn resolve(
    &self,
    invocation: &ScheduleInvocation,
    owner: &PrincipalKey,
    target: &DeliveryTargetRequest,
    now: i64,
  ) -> Result<ResolvedTargetSet, ScheduleServiceError> {
    let kind = target_kind(target);
    let invocation_provider = match invocation.principal.as_ref() {
      InvocationPrincipalRef::ChannelActor { provider, .. } => Some(provider),
      InvocationPrincipalRef::Service { .. } => None,
    };
    let mut candidates = self.registrations.iter().filter(|registration| {
      registration.supported_kinds.contains(&kind)
        && (registration.authority.provider == "none"
          || invocation_provider.is_none_or(|provider| registration.authority.provider == provider))
    });
    let registration = candidates.next();
    if candidates.next().is_some() {
      return Err(ScheduleServiceError::ResolverNotAllowed);
    }
    let registration = registration.ok_or(ScheduleServiceError::ResolverNotAllowed)?;
    let snapshots = registration
      .resolver
      .resolve(invocation, owner, target, now)
      .await?;
    Ok(ResolvedTargetSet {
      authority: registration.authority.clone(),
      snapshots,
    })
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetVerificationError {
  Invalid,
  Unauthorized,
  Unavailable,
  Transient,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlackTargetResolutionRequest {
  Channel {
    channel_id: String,
  },
  DirectMessageUser {
    user_id: String,
  },
  DirectMessageConversation {
    channel_id: String,
  },
  Thread {
    channel_id: String,
    thread_ts: String,
  },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSlackTarget {
  pub workspace_id: String,
  pub team_id: String,
  pub enterprise_id: Option<String>,
  pub context_team_id: String,
  pub conversation_host_id: String,
  pub kind: String,
  pub channel_id: String,
  pub thread_ts: Option<String>,
  pub authorization_evidence_version: u32,
  pub authorization_evidence_digest: String,
}

#[async_trait]
pub trait ChannelTargetVerifier: Send + Sync {
  async fn resolve_target(
    &self,
    workspace_id: Option<&str>,
    actor_id: Option<&str>,
    target: &SlackTargetResolutionRequest,
  ) -> Result<VerifiedSlackTarget, TargetVerificationError>;
}

pub struct VerifiedSlackTargetResolver {
  verifier: Arc<dyn ChannelTargetVerifier>,
  timeout: Duration,
}

impl VerifiedSlackTargetResolver {
  #[must_use]
  pub const fn new(verifier: Arc<dyn ChannelTargetVerifier>, timeout: Duration) -> Self {
    Self { verifier, timeout }
  }

  #[must_use]
  pub fn registration(
    verifier: Arc<dyn ChannelTargetVerifier>,
    timeout: Duration,
  ) -> TargetResolverRegistration {
    TargetResolverRegistration {
      authority: TargetResolverAuthority {
        provider: "slack".to_owned(),
        connector: SLACK_CONNECTOR.to_owned(),
        resolver_version: SNAPSHOT_VERSION,
        resolver_digest: SLACK_RESOLVER_DIGEST.to_owned(),
      },
      supported_kinds: vec!["origin", "channel", "direct_message", "thread"],
      resolver: Arc::new(Self::new(verifier, timeout)),
    }
  }
}

#[async_trait]
impl TargetResolver for VerifiedSlackTargetResolver {
  async fn resolve(
    &self,
    invocation: &ScheduleInvocation,
    _owner: &PrincipalKey,
    target: &DeliveryTargetRequest,
    now: i64,
  ) -> Result<Vec<DeliveryTargetSnapshot>, ScheduleServiceError> {
    if now < 0 {
      return Err(ScheduleServiceError::InvalidRequest(
        "target resolution time must be nonnegative".to_owned(),
      ));
    }
    let (workspace_id, actor_id) = match invocation.principal.as_ref() {
      InvocationPrincipalRef::ChannelActor {
        provider,
        workspace_id,
        actor_id,
      } => {
        if provider != "slack" {
          return Err(ScheduleServiceError::ResolverNotAllowed);
        }
        (Some(workspace_id), Some(actor_id))
      }
      InvocationPrincipalRef::Service { .. } => (None, None),
    };
    let requested = match target {
      DeliveryTargetRequest::None => return Err(ScheduleServiceError::ResolverNotAllowed),
      DeliveryTargetRequest::Origin => origin_resolution_request(
        invocation
          .channel
          .as_ref()
          .ok_or(ScheduleServiceError::ResolverNotAllowed)?,
      )?,
      DeliveryTargetRequest::Channel { channel_id } => SlackTargetResolutionRequest::Channel {
        channel_id: strict_channel_id(channel_id, false)?,
      },
      DeliveryTargetRequest::DirectMessage { user_id } => {
        SlackTargetResolutionRequest::DirectMessageUser {
          user_id: strict_slack_user_id(user_id)?,
        }
      }
      DeliveryTargetRequest::Thread {
        channel_id,
        thread_id,
      } => SlackTargetResolutionRequest::Thread {
        channel_id: strict_channel_id(channel_id, false)?,
        thread_ts: strict_slack_timestamp("thread_id", thread_id)?,
      },
    };
    let requested_identity_digest = digest_json(&resolution_request_json(&requested))?;
    let verified = match tokio::time::timeout(
      self.timeout,
      self
        .verifier
        .resolve_target(workspace_id, actor_id, &requested),
    )
    .await
    {
      Err(_) => return Err(ScheduleServiceError::ResolverTimeout),
      Ok(Err(TargetVerificationError::Invalid)) => {
        return Err(ScheduleServiceError::InvalidRequest(
          "Slack target is invalid".to_owned(),
        ));
      }
      Ok(Err(TargetVerificationError::Unauthorized)) => {
        return Err(ScheduleServiceError::ResolverNotAllowed);
      }
      Ok(Err(TargetVerificationError::Unavailable)) => {
        return Err(ScheduleServiceError::TargetUnavailable);
      }
      Ok(Err(TargetVerificationError::Transient)) => {
        return Err(ScheduleServiceError::ResolverUnavailable);
      }
      Ok(Ok(verified)) => verified,
    };
    validate_verified_slack_target(&verified, workspace_id)?;
    validate_verified_target_matches_request(&verified, &requested)?;
    let coordinates = match verified.thread_ts.as_deref() {
      Some(thread_ts) => json!({"channel_id": verified.channel_id, "thread_ts": thread_ts}),
      None => json!({"channel_id": verified.channel_id}),
    };
    let address = json!({
      "schema_version": SNAPSHOT_VERSION,
      "workspace_id": verified.workspace_id,
      "routing_authority": {
        "team_id": verified.team_id,
        "enterprise_id": verified.enterprise_id,
        "context_team_id": verified.context_team_id,
        "conversation_host_id": verified.conversation_host_id,
      },
      "coordinates": coordinates,
      "authorization_evidence": {
        "version": verified.authorization_evidence_version,
        "digest": verified.authorization_evidence_digest,
      },
      "requested_identity_digest": requested_identity_digest,
      "created_at": now,
    });
    Ok(vec![build_target_snapshot(
      "slack",
      SLACK_CONNECTOR,
      &verified.workspace_id,
      &verified.kind,
      address,
      SNAPSHOT_VERSION,
      SLACK_RESOLVER_DIGEST,
    )?])
  }
}

pub trait CapabilityRegistry: Send + Sync {
  fn describe_authorized(&self, invocation: &ScheduleInvocation) -> Vec<&'static str>;

  fn resolve(
    &self,
    invocation: &ScheduleInvocation,
    owner: &PrincipalKey,
    capability: &CapabilityRequest,
  ) -> Result<CapabilityProfileSnapshot, ScheduleServiceError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRequest {
  pub name: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultCapabilityRegistry;

impl CapabilityRegistry for DefaultCapabilityRegistry {
  fn describe_authorized(&self, _invocation: &ScheduleInvocation) -> Vec<&'static str> {
    vec!["none"]
  }

  fn resolve(
    &self,
    _invocation: &ScheduleInvocation,
    _owner: &PrincipalKey,
    capability: &CapabilityRequest,
  ) -> Result<CapabilityProfileSnapshot, ScheduleServiceError> {
    if capability.name != "none" {
      return Err(ScheduleServiceError::CapabilityUnavailable);
    }
    let profile = json!({"name": "none", "tools": []});
    let canonical = canonical_json(&profile)?;
    CapabilityProfileSnapshot::new(SNAPSHOT_VERSION, digest_json(&profile)?, canonical)
      .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))
  }
}

pub(crate) fn validate_capability_snapshot(
  requested_name: &str,
  snapshot: CapabilityProfileSnapshot,
) -> Result<CapabilityProfileSnapshot, ScheduleServiceError> {
  if snapshot.schema_version() != SNAPSHOT_VERSION {
    return Err(ScheduleServiceError::CapabilityInvalid);
  }
  let value = serde_json::from_str::<Value>(snapshot.canonical_json())
    .map_err(|_| ScheduleServiceError::CapabilityInvalid)?;
  let object = value
    .as_object()
    .ok_or(ScheduleServiceError::CapabilityInvalid)?;
  if object.len() != 2
    || object.get("name").and_then(Value::as_str) != Some(requested_name)
    || object
      .get("tools")
      .and_then(Value::as_array)
      .is_none_or(|tools| !tools.is_empty())
  {
    return Err(ScheduleServiceError::CapabilityInvalid);
  }
  let digest = digest_json(&value)?;
  if snapshot.digest() != digest {
    return Err(ScheduleServiceError::CapabilityInvalid);
  }
  CapabilityProfileSnapshot::new(SNAPSHOT_VERSION, digest, canonical_json(&value)?)
    .map_err(|_| ScheduleServiceError::CapabilityInvalid)
}

pub(crate) fn scope_targets(
  job_id: &str,
  targets: Vec<DeliveryTargetSnapshot>,
) -> Result<Vec<DeliveryTargetSnapshot>, ScheduleServiceError> {
  targets
    .into_iter()
    .enumerate()
    .map(|(ordinal, target)| {
      let target_id = format!(
        "target_{}",
        &digest_json(&json!({
          "job_id": job_id,
          "ordinal": ordinal,
          "identity_digest": target.identity_digest(),
        }))?[..32]
      );
      target
        .with_target_id(target_id)
        .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))
    })
    .collect()
}

pub(crate) fn validate_resolved_targets(
  invocation: &ScheduleInvocation,
  _owner: &PrincipalKey,
  requested: &DeliveryTargetRequest,
  resolved: ResolvedTargetSet,
) -> Result<Vec<DeliveryTargetSnapshot>, ScheduleServiceError> {
  let ResolvedTargetSet {
    authority,
    snapshots: targets,
  } = resolved;
  if targets.is_empty() || targets.len() > 32 {
    return Err(ScheduleServiceError::InvalidRequest(
      "invalid resolved target count".to_owned(),
    ));
  }
  let mut aggregate = 0_usize;
  for target in &targets {
    target
      .validate()
      .map_err(|_| ScheduleServiceError::ResolverUnavailable)?;
    aggregate = aggregate.saturating_add(target.address_json().len());
    let expected_provider = if matches!(requested, DeliveryTargetRequest::None) {
      "none"
    } else {
      authority.provider.as_str()
    };
    let kind_matches = match requested {
      DeliveryTargetRequest::None => target.kind() == "none",
      DeliveryTargetRequest::Origin => {
        matches!(target.kind(), "channel" | "direct_message" | "thread")
      }
      _ => target.kind() == target_kind(requested),
    };
    let address = serde_json::from_str::<Value>(target.address_json())
      .map_err(|_| ScheduleServiceError::ResolverUnavailable)?;
    let invocation_tenant_matches = match invocation.principal.as_ref() {
      InvocationPrincipalRef::ChannelActor { workspace_id, .. } => target.tenant() == workspace_id,
      InvocationPrincipalRef::Service { .. } => true,
    };
    let none_identity_matches = if matches!(requested, DeliveryTargetRequest::None) {
      let expected_identity = digest_json(&json!({
        "provider": target.provider(), "connector": target.connector(), "tenant": target.tenant(),
        "kind": target.kind(), "address": address,
      }))?;
      target.identity_digest() == expected_identity
    } else {
      true
    };
    if authority.provider != expected_provider
      || target.provider() != authority.provider
      || target.connector() != authority.connector
      || !invocation_tenant_matches
      || !kind_matches
      || target.resolver_version() != authority.resolver_version
      || target.resolver_digest() != authority.resolver_digest
      || !none_identity_matches
    {
      return Err(ScheduleServiceError::ResolverUnavailable);
    }
    validate_address_against_request(invocation, requested, target, &address)?;
  }
  if aggregate > 256 * 1024 {
    return Err(ScheduleServiceError::InvalidRequest(
      "resolved targets exceed aggregate bound".to_owned(),
    ));
  }
  Ok(targets)
}

fn origin_resolution_request(
  context: &ChannelTaskContext,
) -> Result<SlackTargetResolutionRequest, ScheduleServiceError> {
  if context.provider != "slack" {
    return Err(ScheduleServiceError::ResolverNotAllowed);
  }
  match context.conversation_kind {
    ConversationKind::Channel => Ok(SlackTargetResolutionRequest::Channel {
      channel_id: strict_channel_id(
        required("channel_id", context.channel_id.as_deref())?,
        false,
      )?,
    }),
    ConversationKind::DirectMessage => {
      Ok(SlackTargetResolutionRequest::DirectMessageConversation {
        channel_id: strict_channel_id(
          required("channel_id", context.channel_id.as_deref())?,
          true,
        )?,
      })
    }
    ConversationKind::Thread => Ok(SlackTargetResolutionRequest::Thread {
      channel_id: strict_channel_id(
        required("channel_id", context.channel_id.as_deref())?,
        false,
      )?,
      thread_ts: strict_slack_timestamp(
        "thread_id",
        required("thread_id", context.thread_id.as_deref())?,
      )?,
    }),
  }
}

fn required<'a>(field: &str, value: Option<&'a str>) -> Result<&'a str, ScheduleServiceError> {
  bounded(field, value.unwrap_or_default())
}

fn strict_slack_user_id(value: &str) -> Result<String, ScheduleServiceError> {
  let value = bounded("user_id", value)?;
  if !(value.starts_with('U') || value.starts_with('W'))
    || value.len() < 2
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
  {
    return Err(ScheduleServiceError::InvalidRequest(
      "user_id must be a canonical Slack user id".to_owned(),
    ));
  }
  Ok(value.to_owned())
}

fn strict_channel_id(value: &str, direct_message: bool) -> Result<String, ScheduleServiceError> {
  let value = bounded("channel_id", value)?;
  let allowed_prefix = if direct_message {
    value.starts_with('D')
  } else {
    value.starts_with('C') || value.starts_with('G')
  };
  if !allowed_prefix
    || value.len() < 2
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
  {
    return Err(ScheduleServiceError::InvalidRequest(
      "channel_id must be a canonical Slack conversation id".to_owned(),
    ));
  }
  Ok(value.to_owned())
}

fn strict_slack_timestamp(field: &str, value: &str) -> Result<String, ScheduleServiceError> {
  let value = bounded(field, value)?;
  let Some((seconds, fraction)) = value.split_once('.') else {
    return Err(ScheduleServiceError::InvalidRequest(format!(
      "{field} must be a canonical Slack timestamp"
    )));
  };
  if seconds.is_empty()
    || fraction.len() != 6
    || !seconds.bytes().all(|byte| byte.is_ascii_digit())
    || !fraction.bytes().all(|byte| byte.is_ascii_digit())
  {
    return Err(ScheduleServiceError::InvalidRequest(format!(
      "{field} must be a canonical Slack timestamp"
    )));
  }
  Ok(value.to_owned())
}

fn resolution_request_json(request: &SlackTargetResolutionRequest) -> Value {
  match request {
    SlackTargetResolutionRequest::Channel { channel_id } => {
      json!({"kind": "channel", "channel_id": channel_id})
    }
    SlackTargetResolutionRequest::DirectMessageUser { user_id } => {
      json!({"kind": "direct_message_user", "user_id": user_id})
    }
    SlackTargetResolutionRequest::DirectMessageConversation { channel_id } => {
      json!({"kind": "direct_message_conversation", "channel_id": channel_id})
    }
    SlackTargetResolutionRequest::Thread {
      channel_id,
      thread_ts,
    } => json!({"kind": "thread", "channel_id": channel_id, "thread_ts": thread_ts}),
  }
}

fn validate_verified_slack_target(
  target: &VerifiedSlackTarget,
  expected_workspace_id: Option<&str>,
) -> Result<(), ScheduleServiceError> {
  bounded("workspace_id", &target.workspace_id)?;
  bounded("team_id", &target.team_id)?;
  bounded("context_team_id", &target.context_team_id)?;
  bounded("conversation_host_id", &target.conversation_host_id)?;
  strict_channel_id(&target.channel_id, target.kind == "direct_message")?;
  if expected_workspace_id.is_some_and(|workspace_id| workspace_id != target.workspace_id)
    || target.workspace_id != target.team_id
    || target.context_team_id != target.team_id
    || !target.team_id.starts_with('T')
    || !(target.conversation_host_id.starts_with('T')
      || target.conversation_host_id.starts_with('E'))
    || target
      .enterprise_id
      .as_deref()
      .is_some_and(|enterprise_id| !enterprise_id.starts_with('E'))
    || !matches!(
      target.kind.as_str(),
      "channel" | "direct_message" | "thread"
    )
    || (target.kind == "thread") != target.thread_ts.is_some()
    || target.authorization_evidence_version == 0
    || target.authorization_evidence_digest.len() != 64
    || !target
      .authorization_evidence_digest
      .bytes()
      .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
  {
    return Err(ScheduleServiceError::ResolverUnavailable);
  }
  if let Some(thread_ts) = target.thread_ts.as_deref() {
    strict_slack_timestamp("thread_ts", thread_ts)?;
  }
  Ok(())
}

fn validate_verified_target_matches_request(
  target: &VerifiedSlackTarget,
  requested: &SlackTargetResolutionRequest,
) -> Result<(), ScheduleServiceError> {
  let matches = match requested {
    SlackTargetResolutionRequest::Channel { channel_id } => {
      target.kind == "channel"
        && target.channel_id == channel_id.as_str()
        && target.thread_ts.is_none()
    }
    SlackTargetResolutionRequest::DirectMessageUser { .. } => {
      target.kind == "direct_message" && target.thread_ts.is_none()
    }
    SlackTargetResolutionRequest::DirectMessageConversation { channel_id } => {
      target.kind == "direct_message"
        && target.channel_id == channel_id.as_str()
        && target.thread_ts.is_none()
    }
    SlackTargetResolutionRequest::Thread {
      channel_id,
      thread_ts,
    } => {
      target.kind == "thread"
        && target.channel_id == channel_id.as_str()
        && target.thread_ts.as_deref() == Some(thread_ts.as_str())
    }
  };
  matches
    .then_some(())
    .ok_or(ScheduleServiceError::ResolverUnavailable)
}

fn identity_address(address: &Value) -> Result<Value, ScheduleServiceError> {
  if address.get("schema_version").is_some() {
    Ok(json!({
      "workspace_id": address
        .get("workspace_id")
        .cloned()
        .ok_or(ScheduleServiceError::ResolverUnavailable)?,
      "routing_authority": address
        .get("routing_authority")
        .cloned()
        .ok_or(ScheduleServiceError::ResolverUnavailable)?,
      "coordinates": address
        .get("coordinates")
        .cloned()
        .ok_or(ScheduleServiceError::ResolverUnavailable)?,
    }))
  } else {
    Ok(address.clone())
  }
}

fn validate_address_against_request(
  invocation: &ScheduleInvocation,
  requested: &DeliveryTargetRequest,
  target: &DeliveryTargetSnapshot,
  address: &Value,
) -> Result<(), ScheduleServiceError> {
  if matches!(requested, DeliveryTargetRequest::None) {
    return (address == &json!({}))
      .then_some(())
      .ok_or(ScheduleServiceError::ResolverUnavailable);
  }
  let route = target
    .delivery_route()
    .map_err(|_| ScheduleServiceError::ResolverUnavailable)?;
  let resolution_request = match requested {
    DeliveryTargetRequest::Origin => origin_resolution_request(
      invocation
        .channel
        .as_ref()
        .ok_or(ScheduleServiceError::ResolverNotAllowed)?,
    )?,
    DeliveryTargetRequest::Channel { channel_id } => SlackTargetResolutionRequest::Channel {
      channel_id: strict_channel_id(channel_id, false)?,
    },
    DeliveryTargetRequest::DirectMessage { user_id } => {
      SlackTargetResolutionRequest::DirectMessageUser {
        user_id: strict_slack_user_id(user_id)?,
      }
    }
    DeliveryTargetRequest::Thread {
      channel_id,
      thread_id,
    } => SlackTargetResolutionRequest::Thread {
      channel_id: strict_channel_id(channel_id, false)?,
      thread_ts: strict_slack_timestamp("thread_id", thread_id)?,
    },
    DeliveryTargetRequest::None => unreachable!("handled above"),
  };
  let expected_request_digest = digest_json(&resolution_request_json(&resolution_request))?;
  if route.requested_identity_digest() != expected_request_digest {
    return Err(ScheduleServiceError::ResolverUnavailable);
  }
  let route_matches = match resolution_request {
    SlackTargetResolutionRequest::Channel { channel_id } => {
      route.kind() == "channel"
        && route.conversation_id() == channel_id
        && route.thread_id().is_none()
    }
    SlackTargetResolutionRequest::DirectMessageUser { .. } => {
      route.kind() == "direct_message" && route.thread_id().is_none()
    }
    SlackTargetResolutionRequest::DirectMessageConversation { channel_id } => {
      route.kind() == "direct_message"
        && route.conversation_id() == channel_id
        && route.thread_id().is_none()
    }
    SlackTargetResolutionRequest::Thread {
      channel_id,
      thread_ts,
    } => {
      route.kind() == "thread"
        && route.conversation_id() == channel_id
        && route.thread_id() == Some(thread_ts.as_str())
    }
  };
  route_matches
    .then_some(())
    .ok_or(ScheduleServiceError::ResolverUnavailable)
}

fn target_kind(target: &DeliveryTargetRequest) -> &'static str {
  match target {
    DeliveryTargetRequest::None => "none",
    DeliveryTargetRequest::Origin => "origin",
    DeliveryTargetRequest::Channel { .. } => "channel",
    DeliveryTargetRequest::DirectMessage { .. } => "direct_message",
    DeliveryTargetRequest::Thread { .. } => "thread",
  }
}

fn build_target_snapshot(
  provider: &str,
  connector: &str,
  tenant: &str,
  kind: &str,
  address: Value,
  resolver_version: u32,
  resolver_digest: &str,
) -> Result<DeliveryTargetSnapshot, ScheduleServiceError> {
  let address_json = canonical_json(&address)?;
  let identity_address = identity_address(&address)?;
  let identity_digest = digest_json(&json!({
    "provider": provider,
    "connector": connector,
    "tenant": tenant,
    "kind": kind,
    "address": identity_address,
  }))?;
  let snapshot = DeliveryTargetSnapshot::new(
    format!("target_{}", &identity_digest[..32]),
    provider,
    connector,
    tenant,
    kind,
    address_json,
    resolver_version,
    resolver_digest,
    identity_digest,
  )
  .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))?;
  snapshot
    .delivery_route()
    .map_err(|_| ScheduleServiceError::ResolverUnavailable)?;
  Ok(snapshot)
}
