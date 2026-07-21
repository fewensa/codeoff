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
const SLACK_RESOLVER_DIGEST: &str = "slack-web-api-v1";

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
      InvocationPrincipalRef::ChannelActor { provider, .. } => provider,
      InvocationPrincipalRef::Service { .. } => return Vec::new(),
    };
    let mut kinds = self
      .registrations
      .iter()
      .filter(|registration| {
        registration.authority.provider == "none" || registration.authority.provider == provider
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
  ) -> Result<ResolvedTargetSet, ScheduleServiceError> {
    let kind = target_kind(target);
    let registration = self.registrations.iter().find(|registration| {
      (registration.authority.provider == "none"
        || registration.authority.provider == owner.provider())
        && registration.supported_kinds.contains(&kind)
    });
    let registration = registration.ok_or(ScheduleServiceError::ResolverNotAllowed)?;
    let snapshots = registration
      .resolver
      .resolve(invocation, owner, target)
      .await?;
    Ok(ResolvedTargetSet {
      authority: registration.authority.clone(),
      snapshots,
    })
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
  async fn verify_thread(
    &self,
    workspace_id: &str,
    actor_id: &str,
    channel_id: &str,
    thread_id: &str,
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
        "channel" => {
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
          if address["user_id"].as_str() != Some(actor) {
            return Err(TargetVerificationError::NotAllowed);
          }
          self
            .verifier
            .verify_user(
              owner.tenant(),
              actor,
              address["user_id"].as_str().unwrap_or_default(),
            )
            .await
        }
        "thread" => {
          self
            .verifier
            .verify_thread(
              owner.tenant(),
              actor,
              address["channel_id"].as_str().unwrap_or_default(),
              address["thread_id"].as_str().unwrap_or_default(),
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
      SLACK_CONNECTOR,
      owner.tenant(),
      &kind,
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
  owner: &PrincipalKey,
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
    let expected_address = expected_target_address(invocation, requested)?;
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
    if authority.provider != expected_provider
      || target.provider() != authority.provider
      || target.connector() != authority.connector
      || target.tenant() != owner.tenant()
      || !kind_matches
      || address != expected_address
      || target.resolver_version() != authority.resolver_version
      || target.resolver_digest() != authority.resolver_digest
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

fn expected_target_address(
  invocation: &ScheduleInvocation,
  requested: &DeliveryTargetRequest,
) -> Result<Value, ScheduleServiceError> {
  match requested {
    DeliveryTargetRequest::None => Ok(json!({})),
    DeliveryTargetRequest::Origin => invocation
      .channel
      .as_ref()
      .ok_or(ScheduleServiceError::ResolverNotAllowed)
      .and_then(origin_address)
      .map(|(_, address)| address),
    DeliveryTargetRequest::Channel { channel_id } => {
      Ok(json!({"channel_id": bounded("channel_id", channel_id)?}))
    }
    DeliveryTargetRequest::DirectMessage { user_id } => {
      Ok(json!({"user_id": bounded("user_id", user_id)?}))
    }
    DeliveryTargetRequest::Thread {
      channel_id,
      thread_id,
    } => Ok(json!({
      "channel_id": bounded("channel_id", channel_id)?,
      "thread_id": bounded("thread_id", thread_id)?,
    })),
  }
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
  resolver_version: u32,
  resolver_digest: &str,
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
    resolver_version,
    resolver_digest,
    identity_digest,
  )
  .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))
}
