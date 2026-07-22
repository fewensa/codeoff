use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "codeoff", about = "Codeoff channel gateway")]
pub struct Cli {
  #[arg(long, global = true)]
  pub config: Option<PathBuf>,

  #[arg(long, global = true)]
  pub state_dir: Option<PathBuf>,

  #[command(subcommand)]
  pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
  Serve {
    #[arg(long)]
    check: bool,
  },
  Worker {
    #[command(subcommand)]
    command: WorkerCommand,
  },
  Migrate,
  Config {
    #[command(subcommand)]
    command: ConfigCommand,
  },
  /// Manages schedules as a trusted local operator configured only by deployment environment.
  #[command(
    long_about = "Manage schedules through the local SQLite control plane. This is a trusted-local entrypoint, not a remote authentication boundary. CODEOFF_SCHEDULER_OPERATOR_ID and CODEOFF_SCHEDULER_OPERATOR_REALM must be configured by the process environment; owner or user overrides are not accepted."
  )]
  Scheduler {
    #[command(subcommand)]
    command: SchedulerCommand,
  },
  Dev,
}

#[derive(Debug, Clone, Subcommand)]
pub enum SchedulerCommand {
  /// Reports sanitized scheduler reachability, enablement, claim switches, and batch limits.
  #[command(
    long_about = "Report sanitized scheduler control-plane reachability and configured scheduler enablement, claim switches, and batch limits. This diagnostic is not process readiness; use the operational HTTP GET endpoints /healthz, /readyz, and /metrics for runtime probes and telemetry."
  )]
  Status {
    #[arg(long)]
    json: bool,
  },
  /// Reads bounded sanitized run diagnostics.
  Runs {
    #[command(subcommand)]
    command: SchedulerRunsCommand,
  },
  /// Reads bounded sanitized delivery diagnostics.
  Deliveries {
    #[command(subcommand)]
    command: SchedulerDeliveriesCommand,
  },
  /// Plans or applies bounded exact lease reconciliation.
  Reconcile {
    #[arg(long, conflicts_with = "apply", required_unless_present = "apply")]
    dry_run: bool,
    #[arg(long, conflicts_with = "dry_run", required_unless_present = "dry_run")]
    apply: bool,
    #[arg(long, default_value_t = 32)]
    limit: u16,
    #[arg(long)]
    authority_file: Option<PathBuf>,
    #[arg(long)]
    json: bool,
  },
  /// Retries one conclusively terminal run under authenticated operator authority.
  RetryRun {
    run_id: String,
    #[arg(long, value_enum)]
    expected_state: SchedulerRetryRunState,
    #[arg(long)]
    request_id: String,
    #[arg(long)]
    expected_attempt: i64,
    #[arg(long)]
    expected_fence: i64,
    #[arg(long)]
    reason_file: PathBuf,
    #[arg(long)]
    authority_file: PathBuf,
  },
  /// Retries one conclusively unwritten delivery under authenticated operator authority.
  RetryDelivery {
    delivery_id: String,
    #[arg(long)]
    request_id: String,
    #[arg(long)]
    expected_attempt: i64,
    #[arg(long)]
    expected_fence: i64,
    #[arg(long)]
    reason_file: PathBuf,
    #[arg(long)]
    authority_file: PathBuf,
  },
  /// Resolves one ambiguous delivery using strict provider evidence.
  ResolveDeliveryUnknown {
    delivery_id: String,
    #[arg(long, value_enum)]
    disposition: SchedulerDeliveryDisposition,
    #[arg(long)]
    request_id: String,
    #[arg(long)]
    expected_attempt: i64,
    #[arg(long)]
    expected_fence: i64,
    #[arg(long)]
    evidence_file: PathBuf,
    #[arg(long, required_if_eq("disposition", "force-resend"))]
    reason_file: Option<PathBuf>,
    #[arg(long, required_if_eq("disposition", "force-resend"))]
    acknowledge_duplicate_risk: bool,
    #[arg(long)]
    authority_file: PathBuf,
  },
  /// Creates a schedule from a strict versioned JSON or TOML document.
  Create {
    #[arg(long)]
    file: PathBuf,
    #[arg(long, value_enum)]
    format: Option<SchedulerFileFormat>,
  },
  /// Reads bounded metadata for one owned schedule without printing its instruction.
  Get { job_id: String },
  /// Lists one bounded page of owned schedule identifiers.
  List {
    #[arg(long, default_value = "active")]
    status: String,
    #[arg(long)]
    cursor: Option<String>,
    #[arg(long, default_value_t = 50)]
    limit: u32,
  },
  /// Replaces a schedule from a strict versioned document using generation CAS.
  Update {
    job_id: String,
    #[arg(long)]
    file: PathBuf,
    #[arg(long, value_enum)]
    format: Option<SchedulerFileFormat>,
    #[arg(long)]
    generation: i64,
  },
  /// Pauses one owned schedule using generation CAS.
  Pause {
    job_id: String,
    #[arg(long)]
    generation: i64,
    #[arg(long)]
    request_id: String,
  },
  /// Resumes one owned schedule using generation CAS.
  Resume {
    job_id: String,
    #[arg(long)]
    generation: i64,
    #[arg(long)]
    request_id: String,
  },
  /// Soft-deletes one owned schedule using generation CAS.
  Delete {
    job_id: String,
    #[arg(long)]
    generation: i64,
    #[arg(long)]
    request_id: String,
  },
}

#[derive(Debug, Clone, Subcommand)]
pub enum SchedulerRunsCommand {
  List {
    #[arg(long, value_enum)]
    status: Option<SchedulerRunStatus>,
    #[arg(long, default_value_t = 50)]
    limit: u16,
    #[arg(long)]
    json: bool,
  },
  Show {
    run_id: String,
    #[arg(long)]
    json: bool,
  },
}

#[derive(Debug, Clone, Subcommand)]
pub enum SchedulerDeliveriesCommand {
  List {
    #[arg(long, value_enum)]
    status: Option<SchedulerDeliveryStatus>,
    #[arg(long, default_value_t = 50)]
    limit: u16,
    #[arg(long)]
    json: bool,
  },
  Show {
    delivery_id: String,
    #[arg(long)]
    json: bool,
  },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SchedulerDeliveryDisposition {
  ConfirmDelivered,
  ConfirmNoWriteTerminal,
  ForceResend,
  AcknowledgeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SchedulerRunStatus {
  Pending,
  Leased,
  Executing,
  Succeeded,
  Failed,
  TimedOut,
  Cancelled,
  OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SchedulerRetryRunState {
  Failed,
  TimedOut,
  Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SchedulerDeliveryStatus {
  Pending,
  Sending,
  Delivered,
  FailedRetryable,
  FailedTerminal,
  DeliveryUnknown,
  SkippedNone,
  SkippedUnchanged,
}

impl SchedulerCommand {
  #[must_use]
  pub(crate) const fn uses_legacy_service(&self) -> bool {
    matches!(
      self,
      Self::Create { .. }
        | Self::Get { .. }
        | Self::List { .. }
        | Self::Update { .. }
        | Self::Pause { .. }
        | Self::Resume { .. }
        | Self::Delete { .. }
    )
  }

  #[must_use]
  pub(crate) const fn uses_json_output(&self) -> bool {
    match self {
      Self::Status { json } | Self::Reconcile { json, .. } => *json,
      Self::Runs { command } => match command {
        SchedulerRunsCommand::List { json, .. } | SchedulerRunsCommand::Show { json, .. } => *json,
      },
      Self::Deliveries { command } => match command {
        SchedulerDeliveriesCommand::List { json, .. }
        | SchedulerDeliveriesCommand::Show { json, .. } => *json,
      },
      Self::RetryRun { .. }
      | Self::RetryDelivery { .. }
      | Self::ResolveDeliveryUnknown { .. }
      | Self::Create { .. }
      | Self::Get { .. }
      | Self::List { .. }
      | Self::Update { .. }
      | Self::Pause { .. }
      | Self::Resume { .. }
      | Self::Delete { .. } => true,
    }
  }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
pub enum SchedulerFileFormat {
  Json,
  Toml,
}

#[derive(Debug, Copy, Clone, Subcommand)]
pub enum WorkerCommand {
  Slack {
    #[arg(long)]
    check: bool,
  },
  ChannelEvents {
    #[arg(long)]
    dry_run: bool,
  },
}

#[derive(Debug, Copy, Clone, Subcommand)]
pub enum ConfigCommand {
  Check,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn scheduler_diagnostic_output_mode_follows_each_json_flag() {
    for command in [
      SchedulerCommand::Status { json: false },
      SchedulerCommand::Runs {
        command: SchedulerRunsCommand::List {
          status: None,
          limit: 1,
          json: false,
        },
      },
      SchedulerCommand::Runs {
        command: SchedulerRunsCommand::Show {
          run_id: "run".to_owned(),
          json: false,
        },
      },
      SchedulerCommand::Deliveries {
        command: SchedulerDeliveriesCommand::List {
          status: None,
          limit: 1,
          json: false,
        },
      },
      SchedulerCommand::Deliveries {
        command: SchedulerDeliveriesCommand::Show {
          delivery_id: "delivery".to_owned(),
          json: false,
        },
      },
      SchedulerCommand::Reconcile {
        dry_run: true,
        apply: false,
        limit: 1,
        authority_file: None,
        json: false,
      },
    ] {
      assert!(!command.uses_json_output());
    }

    for command in [
      SchedulerCommand::Status { json: true },
      SchedulerCommand::Runs {
        command: SchedulerRunsCommand::List {
          status: None,
          limit: 1,
          json: true,
        },
      },
      SchedulerCommand::Runs {
        command: SchedulerRunsCommand::Show {
          run_id: "run".to_owned(),
          json: true,
        },
      },
      SchedulerCommand::Deliveries {
        command: SchedulerDeliveriesCommand::List {
          status: None,
          limit: 1,
          json: true,
        },
      },
      SchedulerCommand::Deliveries {
        command: SchedulerDeliveriesCommand::Show {
          delivery_id: "delivery".to_owned(),
          json: true,
        },
      },
      SchedulerCommand::Reconcile {
        dry_run: false,
        apply: true,
        limit: 1,
        authority_file: Some(PathBuf::from("authority")),
        json: true,
      },
    ] {
      assert!(command.uses_json_output());
    }
  }
}
