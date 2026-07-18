use codeoff_channel_slack::{SlackSocketClient, SlackSocketTransport};

#[tokio::test]
#[ignore = "requires a configured Slack app and CODEOFF_SLACK_LIVE=1"]
async fn opens_a_live_socket_mode_connection_when_explicitly_enabled() {
  if std::env::var("CODEOFF_SLACK_LIVE").as_deref() != Ok("1") {
    return;
  }

  let app_token = std::env::var("SLACK_APP_TOKEN")
    .expect("SLACK_APP_TOKEN is required when CODEOFF_SLACK_LIVE=1");
  let mut transport = SlackSocketClient::new();
  transport
    .open(&app_token)
    .await
    .expect("opens Slack Socket Mode");
}
