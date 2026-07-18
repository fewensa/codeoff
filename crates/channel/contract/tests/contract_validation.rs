use codeoff_channel_contract::{
  ChannelConnector, ChannelConnectorCapabilities, ChannelContextRequest, ChannelContractError,
  ChannelEvent, ChannelEventKind, ChannelMessageRequest, ChannelReplyTarget,
  ChannelThreadReplyRequest, ChannelUserResolveResult, ChannelUserSummary,
};

#[test]
fn rejects_channel_events_with_empty_identifiers_and_dedupe_key() {
  let valid = || {
    ChannelEvent::new(
      "slack",
      "connector-1",
      "workspace-1",
      "event-1",
      "dedupe-1",
      ChannelEventKind::MessageReceived,
    )
  };

  assert!(matches!(
    ChannelEvent::new(
      "slack",
      "",
      "workspace-1",
      "event-1",
      "dedupe-1",
      ChannelEventKind::MessageReceived
    ),
    Err(ChannelContractError::EmptyField {
      field: "connector_id"
    })
  ));
  assert!(matches!(
    ChannelEvent::new(
      "slack",
      "connector-1",
      "",
      "event-1",
      "dedupe-1",
      ChannelEventKind::MessageReceived
    ),
    Err(ChannelContractError::EmptyField {
      field: "workspace_id"
    })
  ));
  assert!(matches!(
    ChannelEvent::new(
      "slack",
      "connector-1",
      "workspace-1",
      "",
      "dedupe-1",
      ChannelEventKind::MessageReceived
    ),
    Err(ChannelContractError::EmptyField { field: "event_id" })
  ));
  assert!(matches!(
    ChannelEvent::new(
      "slack",
      "connector-1",
      "workspace-1",
      "event-1",
      "",
      ChannelEventKind::MessageReceived
    ),
    Err(ChannelContractError::EmptyField {
      field: "dedupe_key"
    })
  ));
  assert!(valid().is_ok());
}

#[test]
fn rejects_message_targets_not_supported_by_connector_capabilities() {
  let request = ChannelMessageRequest::new(
    "connector-1",
    "workspace-1",
    "dedupe-1",
    ChannelReplyTarget::DirectMessage {
      user_account_id: "user-1".to_owned(),
    },
    "hello",
  )
  .expect("valid message request");

  let capabilities = ChannelConnectorCapabilities::default();

  assert!(matches!(
    request.validate_for(&capabilities),
    Err(ChannelContractError::UnsupportedReplyTarget { .. })
  ));
}

#[test]
fn default_optional_connector_operations_report_unsupported_capabilities() {
  struct ReceiveOnlyConnector {
    id: String,
  }

  impl ChannelConnector for ReceiveOnlyConnector {
    fn connector_id(&self) -> &str {
      &self.id
    }

    fn capabilities(&self) -> ChannelConnectorCapabilities {
      ChannelConnectorCapabilities {
        receive_events: true,
        ..ChannelConnectorCapabilities::default()
      }
    }
  }

  let connector = ReceiveOnlyConnector {
    id: "receive-only".to_owned(),
  };
  let request = ChannelContextRequest::new(
    "receive-only",
    "workspace-1",
    ChannelReplyTarget::Channel {
      channel_id: "channel-1".to_owned(),
    },
    10,
  )
  .expect("valid context request");
  assert!(matches!(
    connector.fetch_context(request),
    Err(ChannelContractError::UnsupportedCapability {
      capability: "history_fetch"
    })
  ));
}

#[test]
fn thread_reply_request_accepts_provider_neutral_send_as() {
  let request = ChannelThreadReplyRequest::new(
    "connector-1",
    "workspace-1",
    "channel-1",
    "thread-1",
    "reply-1",
    "hello",
    Some("sender:triage".to_owned()),
  )
  .expect("valid reply");

  assert_eq!(request.send_as.as_deref(), Some("sender:triage"));
}

#[test]
fn thread_reply_request_rejects_empty_required_fields() {
  assert!(matches!(
    ChannelThreadReplyRequest::new(
      "connector-1",
      "workspace-1",
      "",
      "thread-1",
      "reply-1",
      "hello",
      None::<String>,
    ),
    Err(ChannelContractError::EmptyField {
      field: "channel_id"
    })
  ));
}

#[test]
fn ambiguous_user_resolution_keeps_structured_candidates_without_resolved_user() {
  let candidates = vec![
    ChannelUserSummary {
      connector_id: "connector-1".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      user_id: "user-1".to_owned(),
      display_name: Some("Alex Chen".to_owned()),
      handle: Some("alex".to_owned()),
      email: None,
    },
    ChannelUserSummary {
      connector_id: "connector-1".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      user_id: "user-2".to_owned(),
      display_name: Some("Alex Chao".to_owned()),
      handle: Some("alex.c".to_owned()),
      email: None,
    },
  ];
  let result = ChannelUserResolveResult::ambiguous(candidates.clone());

  assert!(result.user.is_none());
  assert_eq!(result.candidates, candidates);
}
