//! State storage wiring for Codeoff.

mod error;
mod scheduler;
mod store;

pub use error::StateError;
pub use scheduler::{
  AcceptedDeliveryBaseline, AcceptedDeliveryBaselineIdentity, AttestedExecutionProfileSnapshot,
  CapabilityProfileSnapshot, ClaimedScheduledDelivery, ClaimedScheduledRun, CreateScheduledJob,
  DELIVERY_PAYLOAD_HASH_ALGORITHM, DELIVERY_PAYLOAD_SCHEMA_VERSION, DeliveryPayloadSnapshot,
  DeliveryTargetSnapshot, ExpiredRunReclaimOutcome, IdempotencyDecision, LateEvidenceAppendOutcome,
  MaterializationOutcome, OccurrenceError, OccurrenceWindow, PreflightFailureDisposition,
  PreparedScheduledDelivery, PrincipalKey, RunLeaseBinding, ScheduleAuditSummary,
  ScheduleMutationAudit, ScheduleMutationIdempotency, ScheduleSpec, ScheduledDeliveryBinding,
  ScheduledDeliveryFailure, ScheduledDeliveryRetentionReport, ScheduledDeliveryState,
  ScheduledExecutionDisposition, ScheduledExecutionTerminal, ScheduledJob, ScheduledJobDefinition,
  ScheduledJobListPage, ScheduledJobMutation, ScheduledJobStatus, ScheduledPrepareAuthority,
  ScheduledRun, ScheduledRunExecutionOutcome, ScheduledRunLateEvidenceKind, ScheduledRunResult,
  ScheduledRunState, ScheduledRunSuccessOutcome, SkippedNoneBaselinePolicy, StateValueError,
  TransactionalMutationOutcome, TransportConvergence, UpdateExecutionBaseline, UpdateScheduledJob,
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
