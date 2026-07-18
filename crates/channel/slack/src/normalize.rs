use codeoff_channel_contract::{ChannelEvent, ChannelEventKind, ChannelReplyTarget};
use codeoff_state::SlackSourceEvent;
use serde_json::Value;
use thiserror::Error;

use crate::{SlackMentionFilter, SocketModeEnvelope};

#[derive(Debug, Error)]
pub enum SlackNormalizeError {
  #[error("invalid Slack Socket Mode envelope: {source}")]
  InvalidEnvelope {
    #[source]
    source: serde_json::Error,
  },

  #[error("failed to serialize Slack payload: {source}")]
  SerializePayload {
    #[source]
    source: serde_json::Error,
  },

  #[error("unsupported Slack payload: {payload_type}")]
  UnsupportedPayload { payload_type: String },

  #[error("Slack payload {payload_type} is missing required field {field}")]
  MissingField {
    payload_type: &'static str,
    field: &'static str,
  },

  #[error("failed to construct normalized channel event: {source}")]
  ChannelEvent {
    #[source]
    source: codeoff_channel_contract::ChannelContractError,
  },
}

#[derive(Debug)]
pub struct NormalizedSlackEvent {
  pub event: ChannelEvent,
  pub source_event: SlackSourceEvent,
}

/// Normalizes one Socket Mode fixture or received envelope without opening a connection.
///
/// # Errors
///
/// Returns an error when the envelope is malformed, unsupported, lacks a stable identifier, or
/// cannot be converted to a valid channel event.
pub fn normalize_socket_mode_envelope(
  raw_envelope: &str,
  connector_id: &str,
) -> Result<NormalizedSlackEvent, SlackNormalizeError> {
  normalize_socket_mode_envelope_with_mention_filter(raw_envelope, connector_id, None)
}

/// Normalizes one Socket Mode envelope using the configured human mention filter for ordinary
/// Slack message events.
///
/// # Errors
///
/// Returns an error when the envelope is malformed, unsupported, lacks a stable identifier, or
/// cannot be converted to a valid channel event.
pub fn normalize_socket_mode_envelope_with_mention_filter(
  raw_envelope: &str,
  connector_id: &str,
  mention_filter: Option<&SlackMentionFilter>,
) -> Result<NormalizedSlackEvent, SlackNormalizeError> {
  let envelope: SocketModeEnvelope = serde_json::from_str(raw_envelope)
    .map_err(|source| SlackNormalizeError::InvalidEnvelope { source })?;
  let raw_payload_json = serde_json::to_string(&envelope.payload)
    .map_err(|source| SlackNormalizeError::SerializePayload { source })?;
  match envelope.envelope_type.as_str() {
    "events_api" => normalize_event_api(envelope, connector_id, raw_payload_json, mention_filter),
    "slash_commands" => normalize_slash_command(envelope, connector_id, raw_payload_json),
    "interactive" => normalize_interaction(envelope, connector_id, raw_payload_json),
    _ => Err(SlackNormalizeError::UnsupportedPayload {
      payload_type: envelope.envelope_type,
    }),
  }
}

fn normalize_event_api(
  envelope: SocketModeEnvelope,
  connector_id: &str,
  raw_payload_json: String,
  mention_filter: Option<&SlackMentionFilter>,
) -> Result<NormalizedSlackEvent, SlackNormalizeError> {
  let payload = &envelope.payload;
  let event = field(payload, "event", "events_api")?;
  let event_type = string(event, "type", "events_api")?;
  let workspace_id = string(payload, "team_id", "events_api")?;
  let event_id = optional_string(payload, "event_id");
  if is_ignored_events_api_event(payload, event) {
    return Err(SlackNormalizeError::UnsupportedPayload {
      payload_type: format!("events_api:{event_type}"),
    });
  }
  let channel_id = string(event, "channel", "events_api")?;
  let user_id = string(event, "user", "events_api")?;
  let message_ts = string(event, "ts", "events_api")?;
  let thread_ts = optional_string(event, "thread_ts").unwrap_or_else(|| message_ts.clone());
  let message_text = optional_string(event, "text");
  let (kind, reply_target) = match event_type.as_str() {
    "app_mention" => (
      ChannelEventKind::MentionReceived,
      ChannelReplyTarget::Thread {
        channel_id: channel_id.clone(),
        thread_id: thread_ts.clone(),
      },
    ),
    "message" => normalize_message_event(event, mention_filter, &channel_id, &user_id, &thread_ts)?,
    _ => {
      return Err(SlackNormalizeError::UnsupportedPayload {
        payload_type: format!("events_api:{event_type}"),
      });
    }
  };
  let dedupe_key = dedupe_key(
    envelope.envelope_id.as_deref(),
    event_id.as_deref(),
    None,
    None,
  )?;
  let source_reference = format!("slack://{workspace_id}/{channel_id}/{message_ts}");
  let normalized = ChannelEvent::new(
    "slack",
    connector_id,
    &workspace_id,
    event_id.clone().unwrap_or_else(|| message_ts.clone()),
    &dedupe_key,
    kind,
  )
  .map_err(|source| SlackNormalizeError::ChannelEvent { source })?
  .with_text(message_text)
  .with_source_details(reply_target, source_reference)
  .map_err(|source| SlackNormalizeError::ChannelEvent { source })?;
  Ok(NormalizedSlackEvent {
    event: normalized,
    source_event: SlackSourceEvent {
      workspace_id,
      event_kind: event_type,
      dedupe_key,
      envelope_id: envelope.envelope_id,
      event_id,
      channel_id: Some(channel_id),
      thread_ts: Some(thread_ts),
      message_ts: Some(message_ts),
      user_id: Some(user_id),
      raw_payload_json,
    },
  })
}

fn normalize_message_event(
  event: &Value,
  mention_filter: Option<&SlackMentionFilter>,
  channel_id: &str,
  user_id: &str,
  thread_ts: &str,
) -> Result<(ChannelEventKind, ChannelReplyTarget), SlackNormalizeError> {
  let text = optional_string(event, "text");
  let is_target_mention = mention_filter.is_some_and(|filter| {
    text
      .as_deref()
      .is_some_and(|message_text| filter.matches_text(message_text))
  });

  if is_target_mention {
    return Ok((
      ChannelEventKind::MentionReceived,
      ChannelReplyTarget::Thread {
        channel_id: channel_id.to_owned(),
        thread_id: thread_ts.to_owned(),
      },
    ));
  }

  if optional_string(event, "channel_type").as_deref() == Some("im") {
    return Ok((
      ChannelEventKind::DirectMessageReceived,
      ChannelReplyTarget::DirectMessage {
        user_account_id: user_id.to_owned(),
      },
    ));
  }

  Ok((
    ChannelEventKind::MessageReceived,
    ChannelReplyTarget::Thread {
      channel_id: channel_id.to_owned(),
      thread_id: thread_ts.to_owned(),
    },
  ))
}

fn is_ignored_events_api_event(payload: &Value, event: &Value) -> bool {
  event
    .get("hidden")
    .and_then(Value::as_bool)
    .unwrap_or(false)
    || optional_string(event, "bot_id").is_some()
    || optional_string(event, "subtype").is_some()
    || event_user_matches_authorized_user(payload, event)
}

fn event_user_matches_authorized_user(payload: &Value, event: &Value) -> bool {
  let Some(event_user) = optional_string(event, "user") else {
    return false;
  };

  payload
    .get("authorizations")
    .and_then(Value::as_array)
    .is_some_and(|authorizations| {
      authorizations.iter().any(|authorization| {
        optional_string(authorization, "user_id").as_deref() == Some(event_user.as_str())
      })
    })
}

fn normalize_slash_command(
  envelope: SocketModeEnvelope,
  connector_id: &str,
  raw_payload_json: String,
) -> Result<NormalizedSlackEvent, SlackNormalizeError> {
  let payload = &envelope.payload;
  let workspace_id = string(payload, "team_id", "slash_commands")?;
  let channel_id = string(payload, "channel_id", "slash_commands")?;
  let user_id = string(payload, "user_id", "slash_commands")?;
  let trigger_id = string(payload, "trigger_id", "slash_commands")?;
  let timestamp = optional_string(payload, "trigger_ts").unwrap_or_else(|| trigger_id.clone());
  let fallback = format!("command:{trigger_id}:{workspace_id}:{channel_id}:{user_id}:{timestamp}");
  let dedupe_key = dedupe_key(envelope.envelope_id.as_deref(), None, Some(&fallback), None)?;
  let normalized = ChannelEvent::new(
    "slack",
    connector_id,
    &workspace_id,
    &trigger_id,
    &dedupe_key,
    ChannelEventKind::SlashCommandReceived,
  )
  .map_err(|source| SlackNormalizeError::ChannelEvent { source })?
  .with_source_details(
    ChannelReplyTarget::Ephemeral {
      channel_id: channel_id.clone(),
      user_account_id: user_id.clone(),
    },
    format!("slack://{workspace_id}/{channel_id}/{timestamp}"),
  )
  .map_err(|source| SlackNormalizeError::ChannelEvent { source })?;
  Ok(NormalizedSlackEvent {
    event: normalized,
    source_event: SlackSourceEvent {
      workspace_id,
      event_kind: "slash_command".to_owned(),
      dedupe_key,
      envelope_id: envelope.envelope_id,
      event_id: None,
      channel_id: Some(channel_id),
      thread_ts: None,
      message_ts: Some(timestamp),
      user_id: Some(user_id),
      raw_payload_json,
    },
  })
}

fn normalize_interaction(
  envelope: SocketModeEnvelope,
  connector_id: &str,
  raw_payload_json: String,
) -> Result<NormalizedSlackEvent, SlackNormalizeError> {
  let payload = &envelope.payload;
  let workspace_id = nested_string(payload, "team", "id", "interactive")?;
  let channel_id = nested_string(payload, "channel", "id", "interactive")?;
  let user_id = nested_string(payload, "user", "id", "interactive")?;
  let action = field(payload, "actions", "interactive")?
    .as_array()
    .and_then(|actions| actions.first())
    .ok_or(SlackNormalizeError::MissingField {
      payload_type: "interactive",
      field: "actions[0]",
    })?;
  let action_id = string(action, "action_id", "interactive")?;
  let message_ts = nested_string(payload, "message", "ts", "interactive")?;
  let callback_id = optional_string(payload, "callback_id");
  let fallback = format!(
    "interaction:{action_id}:{}",
    callback_id.as_deref().unwrap_or(&message_ts)
  );
  let dedupe_key = dedupe_key(envelope.envelope_id.as_deref(), None, None, Some(&fallback))?;
  let normalized = ChannelEvent::new(
    "slack",
    connector_id,
    &workspace_id,
    &message_ts,
    &dedupe_key,
    ChannelEventKind::InteractionReceived,
  )
  .map_err(|source| SlackNormalizeError::ChannelEvent { source })?
  .with_source_details(
    ChannelReplyTarget::Thread {
      channel_id: channel_id.clone(),
      thread_id: message_ts.clone(),
    },
    format!("slack://{workspace_id}/{channel_id}/{message_ts}"),
  )
  .map_err(|source| SlackNormalizeError::ChannelEvent { source })?;
  Ok(NormalizedSlackEvent {
    event: normalized,
    source_event: SlackSourceEvent {
      workspace_id,
      event_kind: "interaction".to_owned(),
      dedupe_key,
      envelope_id: envelope.envelope_id,
      event_id: callback_id,
      channel_id: Some(channel_id),
      thread_ts: Some(message_ts.clone()),
      message_ts: Some(message_ts),
      user_id: Some(user_id),
      raw_payload_json,
    },
  })
}

fn dedupe_key(
  envelope_id: Option<&str>,
  event_id: Option<&str>,
  command_fallback: Option<&str>,
  interaction_fallback: Option<&str>,
) -> Result<String, SlackNormalizeError> {
  if let Some(value) = envelope_id.filter(|value| !value.is_empty()) {
    return Ok(format!("slack:envelope:{value}"));
  }
  if let Some(value) = event_id.filter(|value| !value.is_empty()) {
    return Ok(format!("slack:event:{value}"));
  }
  if let Some(value) = command_fallback {
    return Ok(format!("slack:{value}"));
  }
  if let Some(value) = interaction_fallback {
    return Ok(format!("slack:{value}"));
  }
  Err(SlackNormalizeError::MissingField {
    payload_type: "socket_mode",
    field: "dedupe identifier",
  })
}

fn field<'a>(
  value: &'a Value,
  field: &'static str,
  payload_type: &'static str,
) -> Result<&'a Value, SlackNormalizeError> {
  value.get(field).ok_or(SlackNormalizeError::MissingField {
    payload_type,
    field,
  })
}

fn string(
  value: &Value,
  field: &'static str,
  payload_type: &'static str,
) -> Result<String, SlackNormalizeError> {
  optional_string(value, field)
    .filter(|value| !value.is_empty())
    .ok_or(SlackNormalizeError::MissingField {
      payload_type,
      field,
    })
}

fn nested_string(
  value: &Value,
  parent: &'static str,
  child: &'static str,
  payload_type: &'static str,
) -> Result<String, SlackNormalizeError> {
  string(field(value, parent, payload_type)?, child, payload_type)
}

fn optional_string(value: &Value, field: &str) -> Option<String> {
  value.get(field)?.as_str().map(ToOwned::to_owned)
}
