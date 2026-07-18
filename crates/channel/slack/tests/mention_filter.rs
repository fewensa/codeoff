use codeoff_channel_slack::{SlackIntake, SlackMentionFilter};
use codeoff_config::{CodeoffConfig, ConfigLoadOptions, SlackConfig};
use codeoff_state::StateStore;
use tempfile::tempdir;

#[test]
fn empty_configured_users_match_no_mentions() {
  let filter = SlackMentionFilter::from(&SlackConfig::default());

  assert!(!filter.matches_text("please ask <@U0YALIN>"));
}

#[test]
fn configured_users_match_only_their_complete_slack_mentions() {
  let config = SlackConfig {
    mention_user_ids: vec!["U0YALIN".to_owned(), "U0SECOND".to_owned()],
    ..SlackConfig::default()
  };
  let filter = SlackMentionFilter::from(&config);

  assert!(filter.matches_text("please ask <@U0YALIN>"));
  assert!(filter.matches_text("<@U0SECOND> can you help?"));
  assert!(!filter.matches_text("<@U0YALIN_EXTRA>"));
  assert!(!filter.matches_text("U0YALIN"));
  assert!(!filter.matches_text("<@U0OTHER>"));
}

#[tokio::test]
async fn intake_exposes_the_filter_built_from_slack_config() {
  let temp = tempdir().expect("tempdir");
  let codeoff_config = CodeoffConfig::load(
    ConfigLoadOptions::new()
      .config_path(temp.path().join("missing.toml"))
      .explicit_state_dir(temp.path().into()),
  )
  .expect("config");
  let state = StateStore::initialize(codeoff_config.state_dir(), codeoff_config.database_url())
    .await
    .expect("state");
  let slack_config = SlackConfig {
    mention_user_ids: vec!["U0YALIN".to_owned()],
    ..SlackConfig::default()
  };

  let intake = SlackIntake::with_slack_config(state, "slack-main", &slack_config);

  assert!(intake.mention_filter().matches_text("hello <@U0YALIN>"));
}
