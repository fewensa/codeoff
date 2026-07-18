use codeoff_channel_contract::{ChannelEventKind, ChannelReplyTarget};
use codeoff_channel_slack::{
  SlackIntake, SlackIntakeResult, SlackMentionFilter, SlackNormalizeError,
  normalize_socket_mode_envelope, normalize_socket_mode_envelope_with_mention_filter,
};
use codeoff_config::SlackConfig;
use codeoff_state::StateStore;
use tempfile::tempdir;

fn fixture(name: &str) -> &'static str {
  match name {
    "app_mention" => include_str!("fixtures/app_mention.json"),
    "direct_message" => include_str!("fixtures/direct_message.json"),
    "slash_command" => include_str!("fixtures/slash_command.json"),
    "button_interaction" => include_str!("fixtures/button_interaction.json"),
    "unsupported" => include_str!("fixtures/unsupported.json"),
    "message_channel_mentions_example" => {
      include_str!("fixtures/message_channel_mentions_example.json")
    }
    "message_group_mentions_example" => {
      include_str!("fixtures/message_group_mentions_example.json")
    }
    "message_mpim_mentions_example" => include_str!("fixtures/message_mpim_mentions_example.json"),
    "message_channel_without_target" => {
      include_str!("fixtures/message_channel_without_target.json")
    }
    "message_bot_message" => include_str!("fixtures/message_bot_message.json"),
    "message_hidden" => include_str!("fixtures/message_hidden.json"),
    "message_changed" => include_str!("fixtures/message_changed.json"),
    "message_deleted" => include_str!("fixtures/message_deleted.json"),
    _ => panic!("unknown fixture"),
  }
}

fn self_dm_payload() -> &'static str {
  r#"{"envelope_id":"env-self-dm-1","type":"events_api","payload":{"event_id":"EvSelfDm1","team_id":"T1","authorizations":[{"user_id":"U0BHHR1TVD0"}],"event":{"type":"message","channel_type":"im","channel":"DSELF","user":"U0BHHR1TVD0","ts":"1710000010.001000","text":"queued bot echo"}}}"#
}

fn bot_id_dm_payload() -> &'static str {
  r#"{"envelope_id":"env-bot-id-dm-1","type":"events_api","payload":{"event_id":"EvBotIdDm1","team_id":"T1","event":{"type":"message","channel_type":"im","channel":"DBOT","user":"U0BHHR1TVD0","bot_id":"B0BHMGN2RBN","ts":"1710000011.001100","text":"bot id echo"}}}"#
}

fn dm_payload_from(user_id: &str, envelope_id: &str, event_id: &str, channel_id: &str) -> String {
  format!(
    r#"{{"envelope_id":"{envelope_id}","type":"events_api","payload":{{"event_id":"{event_id}","team_id":"T1","event":{{"type":"message","channel_type":"im","channel":"{channel_id}","user":"{user_id}","ts":"1710000100.001000","text":"hello"}}}}}}"#
  )
}

#[test]
fn normalizes_supported_socket_mode_fixtures_with_reply_targets_and_source_references() {
  let mention =
    normalize_socket_mode_envelope(fixture("app_mention"), "slack-main").expect("mention");
  assert_eq!(mention.event.kind, ChannelEventKind::MentionReceived);
  assert_eq!(mention.event.text.as_deref(), Some("<@B1> hello"));
  assert_eq!(mention.event.dedupe_key, "slack:envelope:env-app-mention-1");
  assert_eq!(
    mention.event.source_reference.as_deref(),
    Some("slack://T1/C1/1710000000.000100")
  );
  assert_eq!(
    mention.event.reply_target,
    Some(ChannelReplyTarget::Thread {
      channel_id: "C1".to_owned(),
      thread_id: "1710000000.000100".to_owned()
    })
  );

  let dm = normalize_socket_mode_envelope(fixture("direct_message"), "slack-main").expect("dm");
  assert_eq!(dm.event.kind, ChannelEventKind::DirectMessageReceived);
  assert_eq!(dm.event.text.as_deref(), Some("hello"));
  assert_eq!(
    dm.event.reply_target,
    Some(ChannelReplyTarget::DirectMessage {
      user_account_id: "U2".to_owned()
    })
  );

  let command =
    normalize_socket_mode_envelope(fixture("slash_command"), "slack-main").expect("command");
  assert_eq!(command.event.kind, ChannelEventKind::SlashCommandReceived);
  assert_eq!(
    command.event.reply_target,
    Some(ChannelReplyTarget::Ephemeral {
      channel_id: "C3".to_owned(),
      user_account_id: "U3".to_owned()
    })
  );

  let interaction = normalize_socket_mode_envelope(fixture("button_interaction"), "slack-main")
    .expect("interaction");
  assert_eq!(
    interaction.event.kind,
    ChannelEventKind::InteractionReceived
  );
  assert_eq!(
    interaction.event.reply_target,
    Some(ChannelReplyTarget::Thread {
      channel_id: "C4".to_owned(),
      thread_id: "1710000004.000400".to_owned()
    })
  );
}

#[test]
fn reports_unsupported_socket_mode_payloads_explicitly() {
  assert!(matches!(
    normalize_socket_mode_envelope(fixture("unsupported"), "slack-main"),
    Err(SlackNormalizeError::UnsupportedPayload { .. })
  ));
}

#[test]
fn falls_back_to_payload_specific_dedupe_identifiers_without_an_envelope_id() {
  let event = fixture("app_mention").replace("\"envelope_id\":\"env-app-mention-1\",", "");
  assert_eq!(
    normalize_socket_mode_envelope(&event, "slack-main")
      .expect("Events API fallback")
      .event
      .dedupe_key,
    "slack:event:Ev1"
  );

  let command = fixture("slash_command").replace("\"envelope_id\":\"env-command-1\",", "");
  assert_eq!(
    normalize_socket_mode_envelope(&command, "slack-main")
      .expect("slash command fallback")
      .event
      .dedupe_key,
    "slack:command:1337.42:T1:C3:U3:1710000002.000300"
  );

  let interaction =
    fixture("button_interaction").replace("\"envelope_id\":\"env-interaction-1\",", "");
  assert_eq!(
    normalize_socket_mode_envelope(&interaction, "slack-main")
      .expect("interaction fallback")
      .event
      .dedupe_key,
    "slack:interaction:acknowledge:action"
  );
}

#[tokio::test]
async fn accepts_live_envelopes_and_reports_their_intake_result() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  let intake = SlackIntake::new(store, "slack-main");

  assert_eq!(
    intake
      .accept(fixture("app_mention"))
      .await
      .expect("first envelope"),
    SlackIntakeResult::Queued
  );
  assert_eq!(
    intake
      .accept(fixture("app_mention"))
      .await
      .expect("duplicate envelope"),
    SlackIntakeResult::Duplicate
  );
  assert_eq!(
    intake
      .accept(fixture("unsupported"))
      .await
      .expect("unsupported envelope"),
    SlackIntakeResult::Ignored
  );
  assert_eq!(intake.queued_event_count().await.expect("queue count"), 1);
  assert_eq!(intake.source_event_count().await.expect("source count"), 1);
}

#[tokio::test]
async fn queues_target_mentions_from_ordinary_channel_message_contexts() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  let slack_config = SlackConfig {
    mention_user_ids: vec!["U0EXAMPLE".to_owned()],
    ..SlackConfig::default()
  };
  let intake = SlackIntake::with_slack_config(store, "slack-main", &slack_config);
  let mention_filter = SlackMentionFilter::from(&slack_config);

  for (name, channel_id, thread_id) in [
    (
      "message_channel_mentions_example",
      "C5",
      "1710000005.000100",
    ),
    ("message_group_mentions_example", "G1", "1710000006.000600"),
    ("message_mpim_mentions_example", "GMP1", "1710000007.000700"),
  ] {
    let normalized = normalize_socket_mode_envelope_with_mention_filter(
      fixture(name),
      "slack-main",
      Some(&mention_filter),
    )
    .expect("target mention normalizes");
    assert_eq!(
      normalized.event.kind,
      ChannelEventKind::MentionReceived,
      "{name}"
    );
    assert_eq!(
      normalized.event.reply_target,
      Some(ChannelReplyTarget::Thread {
        channel_id: channel_id.to_owned(),
        thread_id: thread_id.to_owned(),
      }),
      "{name}"
    );
    assert_eq!(
      intake.accept(fixture(name)).await.expect("target mention"),
      SlackIntakeResult::Queued,
      "{name}"
    );
  }

  assert_eq!(intake.queued_event_count().await.expect("queue count"), 3);
  assert_eq!(intake.source_event_count().await.expect("source count"), 3);
  assert_eq!(
    intake
      .accept(fixture("message_channel_mentions_example"))
      .await
      .expect("duplicate target mention"),
    SlackIntakeResult::Duplicate
  );
  assert_eq!(intake.queued_event_count().await.expect("queue count"), 3);
}

#[tokio::test]
async fn queues_non_target_ordinary_channel_messages_and_ignores_noisy_message_events() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  let slack_config = SlackConfig {
    mention_user_ids: vec!["U0EXAMPLE".to_owned()],
    ..SlackConfig::default()
  };
  let intake = SlackIntake::with_slack_config(store, "slack-main", &slack_config);

  let ordinary_message = normalize_socket_mode_envelope_with_mention_filter(
    fixture("message_channel_without_target"),
    "slack-main",
    Some(intake.mention_filter()),
  )
  .expect("ordinary channel message normalizes");
  assert_eq!(
    ordinary_message.event.kind,
    ChannelEventKind::MessageReceived
  );
  assert_eq!(
    ordinary_message.event.text.as_deref(),
    Some("Please help <@U0OTHER>")
  );
  assert_eq!(
    ordinary_message.event.reply_target,
    Some(ChannelReplyTarget::Thread {
      channel_id: "C6".to_owned(),
      thread_id: "1710000008.000800".to_owned(),
    })
  );
  assert_eq!(
    intake
      .accept(fixture("message_channel_without_target"))
      .await
      .expect("ordinary channel message"),
    SlackIntakeResult::Queued
  );

  for name in [
    "message_bot_message",
    "message_hidden",
    "message_changed",
    "message_deleted",
  ] {
    assert_eq!(
      intake.accept(fixture(name)).await.expect("ignored message"),
      SlackIntakeResult::Ignored,
      "{name}"
    );
  }

  for payload in [self_dm_payload(), bot_id_dm_payload()] {
    assert_eq!(
      intake
        .accept(payload)
        .await
        .expect("ignored bot/self message"),
      SlackIntakeResult::Ignored
    );
  }

  assert_eq!(intake.queued_event_count().await.expect("queue count"), 1);
  assert_eq!(intake.source_event_count().await.expect("source count"), 1);
}

#[tokio::test]
async fn direct_message_allowlist_queues_only_allowed_users() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  let slack_config = SlackConfig {
    allowed_dm_user_ids: vec!["U0EXAMPLE".to_owned()],
    ..SlackConfig::default()
  };
  let intake = SlackIntake::with_slack_config(store, "slack-main", &slack_config);

  assert_eq!(
    intake
      .accept(&dm_payload_from(
        "U0OTHER",
        "env-other-dm",
        "EvOtherDm",
        "DOTHER"
      ))
      .await
      .expect("other user dm"),
    SlackIntakeResult::Ignored
  );
  assert_eq!(
    intake
      .accept(&dm_payload_from(
        "U0EXAMPLE",
        "env-example-dm",
        "EvYalinDm",
        "DEXAMPLE"
      ))
      .await
      .expect("example dm"),
    SlackIntakeResult::Queued
  );
  assert_eq!(intake.queued_event_count().await.expect("queue count"), 1);
  assert_eq!(intake.source_event_count().await.expect("source count"), 1);
}

#[tokio::test]
async fn empty_direct_message_allowlist_keeps_existing_dm_behavior() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  let intake = SlackIntake::with_slack_config(store, "slack-main", &SlackConfig::default());

  assert_eq!(
    intake
      .accept(&dm_payload_from(
        "U0OTHER",
        "env-open-dm",
        "EvOpenDm",
        "DOPEN"
      ))
      .await
      .expect("open dm"),
    SlackIntakeResult::Queued
  );
  assert_eq!(intake.queued_event_count().await.expect("queue count"), 1);
}
