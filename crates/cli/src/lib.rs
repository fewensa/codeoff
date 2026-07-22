//! CLI wiring for Codeoff.
#![allow(
  clippy::collapsible_if,
  clippy::duration_suboptimal_units,
  clippy::ignored_unit_patterns,
  clippy::needless_pass_by_value,
  clippy::single_match_else,
  clippy::unnecessary_wraps
)]

mod command;
mod observability;
mod run;
mod scheduler;

pub use command::Cli;
pub use run::run;
