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
