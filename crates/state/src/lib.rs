//! State storage wiring for Codeoff.

mod error;
mod scheduler;
mod store;

pub use error::StateError;
pub use scheduler::{
  AcceptedDeliveryBaseline, AttestedExecutionProfileSnapshot, CapabilityProfileSnapshot,
  ClaimedScheduledRun, CreateScheduledJob, DeliveryTargetSnapshot, ExpiredRunReclaimOutcome,
  IdempotencyDecision, LateEvidenceAppendOutcome, MaterializationOutcome, OccurrenceError,
  OccurrenceWindow, PreflightFailureDisposition, PrincipalKey, RunLeaseBinding,
  ScheduleAuditSummary, ScheduleMutationAudit, ScheduleMutationIdempotency, ScheduleSpec,
  ScheduledDeliveryState, ScheduledJob, ScheduledJobDefinition, ScheduledJobListPage,
  ScheduledJobMutation, ScheduledJobStatus, ScheduledRun, ScheduledRunLateEvidenceKind,
  ScheduledRunResult, ScheduledRunState, ScheduledRunSuccessOutcome, StateValueError,
  TransactionalMutationOutcome, UpdateAcceptedDeliveryBaseline, UpdateExecutionBaseline,
  UpdateScheduledJob,
};
#[cfg(any(test, feature = "test-support"))]
pub use store::StateStoreTestLock;
pub use store::{
  AgentDraft, ChannelConversationKey, ChannelConversationSummary, ChannelEventStatus,
  ChannelEventStatusKind, ClaimedChannelEvent, ContextFetchAttempt, ContextFetchAttemptRecord,
  RetentionCleanupReport, RetentionPolicy, SlackDeliveryClaim, SlackDeliveryOperationClaim,
  SlackDeliveryReceipt, SlackDeliveryRequest, SlackDeliverySender, SlackDeliveryStatus,
  SlackDeliveryStatusKind, SlackProcessingIndicator, SlackProcessingIndicatorStatusKind,
  SlackSourceAttachment, SlackSourceEvent, SlackSourceFile, SlackSourceLink, SlackSourceReferences,
  SlackStopStreamDeliveryRequest, StateStore,
};
