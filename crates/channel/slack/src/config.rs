use codeoff_config::SlackConfig;

use crate::SlackConfigError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackConfigCheck {
  workspace_id: String,
  secret_env_vars: Vec<String>,
}

impl SlackConfigCheck {
  #[must_use]
  pub fn status_line(&self) -> String {
    format!(
      "slack config ok: workspace_id={}, secrets={}",
      self.workspace_id,
      self.secret_env_vars.join(",")
    )
  }
}

/// Validates the Slack workspace configuration and required secret environment variables.
///
/// # Errors
///
/// Returns an error when a required Slack config value is empty or a named secret is absent.
pub fn validate_slack_config<F>(
  config: &SlackConfig,
  mut environment: F,
) -> Result<SlackConfigCheck, SlackConfigError>
where
  F: FnMut(&str) -> Option<String>,
{
  require_non_empty(&config.workspace_id, "workspace_id")?;

  let mut secret_env_vars = vec![config.bot_token_env.clone(), config.app_token_env.clone()];
  if config.transport == "http_events" {
    secret_env_vars.push(config.signing_secret_env.clone());
  }

  for env_var in &secret_env_vars {
    require_non_empty(env_var, "secret environment variable name")?;
    if environment(env_var).is_none_or(|value| value.trim().is_empty()) {
      return Err(SlackConfigError::MissingSecret {
        env_var: env_var.clone(),
      });
    }
  }

  Ok(SlackConfigCheck {
    workspace_id: config.workspace_id.clone(),
    secret_env_vars,
  })
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), SlackConfigError> {
  if value.trim().is_empty() {
    return Err(SlackConfigError::EmptyConfig { field });
  }

  Ok(())
}
