//! Core domain types for Codeoff.

mod scheduled_identity;
mod scheduler_policy;

pub use scheduled_identity::{
  CredentialRevision, CriticalId, MAX_CREDENTIAL_REVISION_BYTES, MAX_CRITICAL_ID_BYTES,
  MAX_RUNNER_WORKLOAD_IDENTITY_BYTES, RunnerWorkloadIdentity, ScheduledIdentityError,
};
pub use scheduler_policy::{
  SCHEDULER_OPERATIONAL_POLICY_VERSION, SchedulerOperationalPolicy, SchedulerPolicyValidationError,
};
