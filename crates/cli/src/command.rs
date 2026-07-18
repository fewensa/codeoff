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
  Dev,
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
