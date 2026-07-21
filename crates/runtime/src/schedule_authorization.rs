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

pub trait AuthorizationPolicy: Send + Sync {
  fn authorize_create(
    &self,
    invocation: &ScheduleInvocation,
  ) -> Result<PrincipalKey, ScheduleServiceError>;

  fn authorize_existing(
    &self,
    invocation: &ScheduleInvocation,
    job: Option<ScheduledJob>,
  ) -> Result<(PrincipalKey, ScheduledJob), ScheduleServiceError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OwnerOnlyAuthorizationPolicy;

impl AuthorizationPolicy for OwnerOnlyAuthorizationPolicy {
  fn authorize_create(
    &self,
    invocation: &ScheduleInvocation,
  ) -> Result<PrincipalKey, ScheduleServiceError> {
    invocation.canonical_actor()
  }

  fn authorize_existing(
    &self,
    invocation: &ScheduleInvocation,
    job: Option<ScheduledJob>,
  ) -> Result<(PrincipalKey, ScheduledJob), ScheduleServiceError> {
    let owner = invocation.canonical_actor()?;
    let job = job.ok_or(ScheduleServiceError::NotVisible)?;
    if job.owner != owner {
      return Err(ScheduleServiceError::NotVisible);
    }
    Ok((owner, job))
  }
}
