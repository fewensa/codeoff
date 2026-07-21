use std::sync::Arc;

use codeoff_agent_contract::{
  ChannelTaskContext, InvocationPrincipal, InvocationPrincipalRef, InvocationSource,
};
use codeoff_state::{PrincipalKey, ScheduledJob};

use crate::schedule_service::ScheduleServiceError;

#[derive(Debug, Clone)]
pub struct ScheduleInvocation {
  pub source: InvocationSource,
  pub principal: InvocationPrincipal,
  pub channel: Option<ChannelTaskContext>,
}

impl ScheduleInvocation {
  pub(crate) fn canonical_actor(&self) -> Result<PrincipalKey, ScheduleServiceError> {
    let InvocationPrincipalRef::ChannelActor {
      provider,
      workspace_id,
      actor_id,
    } = self.principal.as_ref()
    else {
      return Err(ScheduleServiceError::Unauthorized);
    };
    let InvocationSource::ChannelEvent {
      provider: source_provider,
      workspace_id: source_workspace,
      ..
    } = &self.source
    else {
      return Err(ScheduleServiceError::Unauthorized);
    };
    if source_provider != provider || source_workspace != workspace_id {
      return Err(ScheduleServiceError::Unauthorized);
    }
    let context = self
      .channel
      .as_ref()
      .ok_or(ScheduleServiceError::Unauthorized)?;
    if context.provider != provider
      || context.workspace_id != workspace_id
      || context.user_id.as_deref() != Some(actor_id)
    {
      return Err(ScheduleServiceError::Unauthorized);
    }
    PrincipalKey::new("channel_actor", provider, workspace_id, actor_id)
      .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))
  }
}

pub trait OperatorIdentityPolicy: Send + Sync {
  fn authorize_operator(
    &self,
    invocation: &ScheduleInvocation,
  ) -> Result<PrincipalKey, ScheduleServiceError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledOperatorIdentityPolicy;

impl OperatorIdentityPolicy for DisabledOperatorIdentityPolicy {
  fn authorize_operator(
    &self,
    _invocation: &ScheduleInvocation,
  ) -> Result<PrincipalKey, ScheduleServiceError> {
    Err(ScheduleServiceError::Unauthorized)
  }
}

#[derive(Debug, Clone)]
pub struct ConfiguredOperatorIdentityPolicy {
  expected_service: String,
  principal: PrincipalKey,
}

impl ConfiguredOperatorIdentityPolicy {
  /// Creates one exact trusted-local operator mapping configured by the server process.
  ///
  /// # Errors
  /// Returns an error when the expected service identity or canonical operator realm is invalid.
  pub fn new(
    expected_service: &str,
    realm: &str,
    subject: &str,
  ) -> Result<Self, ScheduleServiceError> {
    crate::schedule_service::bounded("operator service identity", expected_service)?;
    let principal = PrincipalKey::new("operator", "local", realm, subject)
      .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))?;
    Ok(Self {
      expected_service: expected_service.to_owned(),
      principal,
    })
  }
}

impl OperatorIdentityPolicy for ConfiguredOperatorIdentityPolicy {
  fn authorize_operator(
    &self,
    invocation: &ScheduleInvocation,
  ) -> Result<PrincipalKey, ScheduleServiceError> {
    let InvocationSource::TrustedOperator { request_id } = &invocation.source else {
      return Err(ScheduleServiceError::Unauthorized);
    };
    let InvocationPrincipalRef::Service { service } = invocation.principal.as_ref() else {
      return Err(ScheduleServiceError::Unauthorized);
    };
    if invocation.channel.is_some() || service != self.expected_service {
      return Err(ScheduleServiceError::Unauthorized);
    }
    crate::schedule_service::bounded("trusted operator request id", request_id)?;
    Ok(self.principal.clone())
  }
}

pub trait AuthorizationPolicy: Send + Sync {
  fn authenticate(
    &self,
    invocation: &ScheduleInvocation,
  ) -> Result<PrincipalKey, ScheduleServiceError>;

  fn authorize_create(&self, _principal: &PrincipalKey) -> Result<(), ScheduleServiceError> {
    Ok(())
  }

  fn authorize_list(&self, _principal: &PrincipalKey) -> Result<(), ScheduleServiceError> {
    Ok(())
  }

  fn authorize_existing(
    &self,
    principal: &PrincipalKey,
    job: Option<ScheduledJob>,
  ) -> Result<ScheduledJob, ScheduleServiceError> {
    let job = job.ok_or(ScheduleServiceError::NotVisible)?;
    if job.owner != *principal {
      return Err(ScheduleServiceError::NotVisible);
    }
    Ok(job)
  }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OwnerOnlyAuthorizationPolicy;

impl AuthorizationPolicy for OwnerOnlyAuthorizationPolicy {
  fn authenticate(
    &self,
    invocation: &ScheduleInvocation,
  ) -> Result<PrincipalKey, ScheduleServiceError> {
    invocation.canonical_actor()
  }
}

#[derive(Clone)]
pub struct OperatorAuthorizationPolicy {
  identity: Arc<dyn OperatorIdentityPolicy>,
}

impl Default for OperatorAuthorizationPolicy {
  fn default() -> Self {
    Self {
      identity: Arc::new(DisabledOperatorIdentityPolicy),
    }
  }
}

impl OperatorAuthorizationPolicy {
  #[must_use]
  pub fn new(identity: Arc<dyn OperatorIdentityPolicy>) -> Self {
    Self { identity }
  }
}

impl AuthorizationPolicy for OperatorAuthorizationPolicy {
  fn authenticate(
    &self,
    invocation: &ScheduleInvocation,
  ) -> Result<PrincipalKey, ScheduleServiceError> {
    self.identity.authorize_operator(invocation)
  }
}
