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
  fn provider(&self) -> &'static str;

  fn describe_supported_targets(&self, invocation: &ScheduleInvocation) -> Vec<&'static str>;

  async fn resolve(
    &self,
    invocation: &ScheduleInvocation,
    owner: &PrincipalKey,
    target: &DeliveryTargetRequest,
  ) -> Result<Vec<DeliveryTargetSnapshot>, ScheduleServiceError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultTargetResolver;

#[async_trait]
impl TargetResolver for DefaultTargetResolver {
  fn provider(&self) -> &'static str {
    "none"
  }

  fn describe_supported_targets(&self, _invocation: &ScheduleInvocation) -> Vec<&'static str> {
    vec!["none"]
  }

  async fn resolve(
    &self,
    _invocation: &ScheduleInvocation,
    owner: &PrincipalKey,
    target: &DeliveryTargetRequest,
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
    let resolver_digest = digest_json(&json!({"resolver": "default", "version": 1}))?;
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
  resolvers: Vec<Arc<dyn TargetResolver>>,
}

impl TargetResolverRegistry {
  #[must_use]
  pub fn with_defaults() -> Self {
    Self {
      resolvers: vec![Arc::new(DefaultTargetResolver)],
    }
  }

  pub fn register(&mut self, resolver: Arc<dyn TargetResolver>) {
    self.resolvers.push(resolver);
  }
}

#[async_trait]
impl TargetResolver for TargetResolverRegistry {
  fn provider(&self) -> &'static str {
    "registry"
  }

  fn describe_supported_targets(&self, invocation: &ScheduleInvocation) -> Vec<&'static str> {
    let provider = match invocation.principal.as_ref() {
      InvocationPrincipalRef::ChannelActor { provider, .. } => provider,
      InvocationPrincipalRef::Service { .. } => return Vec::new(),
    };
    let mut kinds = self
      .resolvers
      .iter()
      .filter(|resolver| resolver.provider() == "none" || resolver.provider() == provider)
      .flat_map(|resolver| resolver.describe_supported_targets(invocation))
      .collect::<Vec<_>>();
    kinds.sort_unstable();
    kinds.dedup();
    kinds
  }

  async fn resolve(
    &self,
    invocation: &ScheduleInvocation,
    owner: &PrincipalKey,
    target: &DeliveryTargetRequest,
  ) -> Result<Vec<DeliveryTargetSnapshot>, ScheduleServiceError> {
    let kind = target_kind(target);
    let resolver = self.resolvers.iter().find(|resolver| {
      (resolver.provider() == "none" || resolver.provider() == owner.provider())
        && resolver
          .describe_supported_targets(invocation)
          .contains(&kind)
    });
    resolver
      .ok_or(ScheduleServiceError::ResolverNotAllowed)?
      .resolve(invocation, owner, target)
      .await
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetVerificationError {
  Unavailable,
  NotAllowed,
}

#[async_trait]
pub trait ChannelTargetVerifier: Send + Sync {
  async fn verify_connector(
    &self,
    workspace_id: &str,
    actor_id: &str,
  ) -> Result<(), TargetVerificationError>;
  async fn verify_channel(
    &self,
    workspace_id: &str,
    actor_id: &str,
    channel_id: &str,
  ) -> Result<(), TargetVerificationError>;
  async fn verify_user(
    &self,
    workspace_id: &str,
    actor_id: &str,
    user_id: &str,
  ) -> Result<(), TargetVerificationError>;
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
}

#[async_trait]
impl TargetResolver for VerifiedSlackTargetResolver {
  fn provider(&self) -> &'static str {
    "slack"
  }

  fn describe_supported_targets(&self, invocation: &ScheduleInvocation) -> Vec<&'static str> {
    if matches!(
      invocation.principal.as_ref(),
      InvocationPrincipalRef::ChannelActor {
        provider: "slack",
        ..
      }
    ) && invocation.channel.is_some()
    {
      vec!["origin", "channel", "direct_message", "thread"]
    } else {
      Vec::new()
    }
  }

  async fn resolve(
    &self,
    invocation: &ScheduleInvocation,
    owner: &PrincipalKey,
    target: &DeliveryTargetRequest,
  ) -> Result<Vec<DeliveryTargetSnapshot>, ScheduleServiceError> {
    let context = invocation
      .channel
      .as_ref()
      .ok_or(ScheduleServiceError::ResolverNotAllowed)?;
    ensure_context_matches_owner(context, owner)?;
    let actor = owner.subject();
    let (kind, address) = match target {
      DeliveryTargetRequest::None => return Err(ScheduleServiceError::ResolverNotAllowed),
      DeliveryTargetRequest::Origin => origin_address(context)?,
      DeliveryTargetRequest::Channel { channel_id } => (
        "channel".to_owned(),
        json!({"channel_id": bounded("channel_id", channel_id)?}),
      ),
      DeliveryTargetRequest::DirectMessage { user_id } => (
        "direct_message".to_owned(),
        json!({"user_id": bounded("user_id", user_id)?}),
      ),
      DeliveryTargetRequest::Thread {
        channel_id,
        thread_id,
      } => (
        "thread".to_owned(),
        json!({"channel_id": bounded("channel_id", channel_id)?, "thread_id": bounded("thread_id", thread_id)?}),
      ),
    };
    let verify = async {
      self
        .verifier
        .verify_connector(owner.tenant(), actor)
        .await?;
      match kind.as_str() {
        "channel" | "thread" => {
          self
            .verifier
            .verify_channel(
              owner.tenant(),
              actor,
              address["channel_id"].as_str().unwrap_or_default(),
            )
            .await
        }
        "direct_message" => {
          self
            .verifier
            .verify_user(
              owner.tenant(),
              actor,
              address["user_id"].as_str().unwrap_or_default(),
            )
            .await
        }
        _ => Err(TargetVerificationError::NotAllowed),
      }
    };
    match tokio::time::timeout(self.timeout, verify).await {
      Err(_) => return Err(ScheduleServiceError::ResolverTimeout),
      Ok(Err(TargetVerificationError::Unavailable)) => {
        return Err(ScheduleServiceError::ResolverUnavailable);
      }
      Ok(Err(TargetVerificationError::NotAllowed)) => {
        return Err(ScheduleServiceError::ResolverNotAllowed);
      }
      Ok(Ok(())) => {}
    }
    Ok(vec![build_target_snapshot(
      "slack",
      "channel",
      owner.tenant(),
      &kind,
      address,
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
    return Err(ScheduleServiceError::CapabilityUnavailable);
  }
  let value = serde_json::from_str::<Value>(snapshot.canonical_json())
    .map_err(|_| ScheduleServiceError::CapabilityUnavailable)?;
  let object = value
    .as_object()
    .ok_or(ScheduleServiceError::CapabilityUnavailable)?;
  if object.len() != 2
    || object.get("name").and_then(Value::as_str) != Some(requested_name)
    || object
      .get("tools")
      .and_then(Value::as_array)
      .is_none_or(|tools| !tools.is_empty())
  {
    return Err(ScheduleServiceError::CapabilityUnavailable);
  }
  let digest = digest_json(&value)?;
  if snapshot.digest() != digest {
    return Err(ScheduleServiceError::CapabilityUnavailable);
  }
  CapabilityProfileSnapshot::new(SNAPSHOT_VERSION, digest, canonical_json(&value)?)
    .map_err(|_| ScheduleServiceError::CapabilityUnavailable)
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
  owner: &PrincipalKey,
  requested: &DeliveryTargetRequest,
  targets: Vec<DeliveryTargetSnapshot>,
) -> Result<Vec<DeliveryTargetSnapshot>, ScheduleServiceError> {
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
      owner.provider()
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
    let expected_identity = digest_json(&json!({
      "provider": target.provider(), "connector": target.connector(), "tenant": target.tenant(),
      "kind": target.kind(), "address": address,
    }))?;
    if target.provider() != expected_provider
      || target.tenant() != owner.tenant()
      || !kind_matches
      || target.resolver_version() == 0
      || target.resolver_digest().is_empty()
      || target.identity_digest() != expected_identity
    {
      return Err(ScheduleServiceError::ResolverUnavailable);
    }
  }
  if aggregate > 256 * 1024 {
    return Err(ScheduleServiceError::InvalidRequest(
      "resolved targets exceed aggregate bound".to_owned(),
    ));
  }
  Ok(targets)
}

fn ensure_context_matches_owner(
  context: &ChannelTaskContext,
  owner: &PrincipalKey,
) -> Result<(), ScheduleServiceError> {
  if context.provider != owner.provider() || context.workspace_id != owner.tenant() {
    return Err(ScheduleServiceError::Unauthorized);
  }
  Ok(())
}

fn origin_address(context: &ChannelTaskContext) -> Result<(String, Value), ScheduleServiceError> {
  match context.conversation_kind {
    ConversationKind::Channel => Ok((
      "channel".to_owned(),
      json!({"channel_id": required("channel_id", context.channel_id.as_deref())?}),
    )),
    ConversationKind::DirectMessage => Ok((
      "direct_message".to_owned(),
      json!({"user_id": required("user_id", context.user_id.as_deref())?}),
    )),
    ConversationKind::Thread => Ok((
      "thread".to_owned(),
      json!({
        "channel_id": required("channel_id", context.channel_id.as_deref())?,
        "thread_id": required("thread_id", context.thread_id.as_deref())?,
      }),
    )),
  }
}

fn required<'a>(field: &str, value: Option<&'a str>) -> Result<&'a str, ScheduleServiceError> {
  bounded(field, value.unwrap_or_default())
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
) -> Result<DeliveryTargetSnapshot, ScheduleServiceError> {
  let address_json = canonical_json(&address)?;
  let identity_digest = digest_json(&json!({
    "provider": provider,
    "connector": connector,
    "tenant": tenant,
    "kind": kind,
    "address": address,
  }))?;
  DeliveryTargetSnapshot::new(
    format!("target_{}", &identity_digest[..32]),
    provider,
    connector,
    tenant,
    kind,
    address_json,
    SNAPSHOT_VERSION,
    digest_json(&json!({"resolver": provider, "version": SNAPSHOT_VERSION}))?,
    identity_digest,
  )
  .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))
}
