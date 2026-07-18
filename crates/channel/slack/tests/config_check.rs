use codeoff_channel_slack::{SlackConfigError, validate_slack_config};
use codeoff_config::SlackConfig;

#[test]
fn reports_each_missing_required_slack_secret_by_environment_variable_name() {
  let config = SlackConfig::default();

  for missing_env in ["SLACK_BOT_TOKEN", "SLACK_APP_TOKEN"] {
    let result = validate_slack_config(&config, |env_var| {
      if env_var == missing_env {
        None
      } else {
        Some("configured-secret".to_owned())
      }
    });

    assert!(matches!(
      result,
      Err(SlackConfigError::MissingSecret { env_var }) if env_var == missing_env
    ));
  }
}

#[test]
fn socket_mode_does_not_require_signing_secret() {
  let config = SlackConfig::default();

  validate_slack_config(&config, |env_var| {
    if env_var == "SLACK_SIGNING_SECRET" {
      None
    } else {
      Some("configured-secret".to_owned())
    }
  })
  .expect("socket mode should not require HTTP signing secret");
}

#[test]
fn http_events_requires_signing_secret() {
  let config = SlackConfig {
    transport: "http_events".to_owned(),
    ..SlackConfig::default()
  };

  let result = validate_slack_config(&config, |env_var| {
    if env_var == "SLACK_SIGNING_SECRET" {
      None
    } else {
      Some("configured-secret".to_owned())
    }
  });

  assert!(matches!(
    result,
    Err(SlackConfigError::MissingSecret { env_var }) if env_var == "SLACK_SIGNING_SECRET"
  ));
}

#[test]
fn status_output_names_secret_variables_without_exposing_values() {
  let config = SlackConfig::default();
  let check = validate_slack_config(&config, |_| Some("xoxb-secret-value".to_owned()))
    .expect("valid Slack config");

  let output = check.status_line();
  assert!(output.contains("SLACK_BOT_TOKEN"));
  assert!(output.contains("SLACK_APP_TOKEN"));
  assert!(!output.contains("SLACK_SIGNING_SECRET"));
  assert!(!output.contains("xoxb-secret-value"));
}
