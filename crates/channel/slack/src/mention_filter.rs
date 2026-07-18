use std::collections::HashSet;

use codeoff_config::SlackConfig;

/// Matches Slack user mentions for the configured target users.
#[derive(Debug, Clone, Default)]
pub struct SlackMentionFilter {
  user_ids: HashSet<String>,
}

impl SlackMentionFilter {
  #[must_use]
  pub fn new(user_ids: impl IntoIterator<Item = String>) -> Self {
    Self {
      user_ids: user_ids.into_iter().collect(),
    }
  }

  /// Returns whether `text` includes a configured Slack mention in `<@USERID>` form.
  #[must_use]
  pub fn matches_text(&self, text: &str) -> bool {
    text.split("<@").skip(1).any(|mention| {
      mention
        .split_once('>')
        .is_some_and(|(user_id, _)| self.user_ids.contains(user_id))
    })
  }
}

impl From<&SlackConfig> for SlackMentionFilter {
  fn from(config: &SlackConfig) -> Self {
    Self::new(config.mention_user_ids.iter().cloned())
  }
}
