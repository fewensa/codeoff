use futures_util::{SinkExt, StreamExt};
use reqwest::Client;
use serde::Deserialize;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

use crate::{SlackSocketError, SlackSocketTransport, TransportReceive};

type SocketStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Slack Socket Mode transport backed by Slack's Web API and WebSocket connection.
pub struct SlackSocketClient {
  http: Client,
  socket: Option<SocketStream>,
}

impl SlackSocketClient {
  #[must_use]
  pub fn new() -> Self {
    Self {
      http: Client::new(),
      socket: None,
    }
  }
}

impl Default for SlackSocketClient {
  fn default() -> Self {
    Self::new()
  }
}

#[async_trait::async_trait]
impl SlackSocketTransport for SlackSocketClient {
  async fn open(&mut self, app_token: &str) -> Result<(), SlackSocketError> {
    let response = self
      .http
      .post("https://slack.com/api/apps.connections.open")
      .bearer_auth(app_token)
      .send()
      .await
      .map_err(SlackSocketError::Open)?;
    let body: OpenConnectionResponse = response.json().await.map_err(SlackSocketError::Open)?;
    if !body.ok {
      return Err(SlackSocketError::OpenResponse(
        body
          .error
          .unwrap_or_else(|| "unknown Slack error".to_owned()),
      ));
    }
    let url = body.url.ok_or(SlackSocketError::MissingSocketUrl)?;
    let (socket, _) = connect_async(url)
      .await
      .map_err(SlackSocketError::WebSocketOpen)?;
    self.socket = Some(socket);
    Ok(())
  }

  async fn receive(&mut self) -> Result<TransportReceive, SlackSocketError> {
    let socket = self.socket.as_mut().ok_or(SlackSocketError::NotConnected)?;
    match socket.next().await {
      Some(Ok(Message::Text(payload))) => Ok(TransportReceive::Envelope(payload.to_string())),
      Some(Ok(Message::Close(_))) | None => {
        self.socket = None;
        Ok(TransportReceive::Disconnected)
      }
      Some(Ok(_)) => Ok(TransportReceive::Ignored),
      Some(Err(error)) => {
        self.socket = None;
        Err(SlackSocketError::Receive(error))
      }
    }
  }

  async fn acknowledge(&mut self, envelope_id: &str) -> Result<(), SlackSocketError> {
    let socket = self.socket.as_mut().ok_or(SlackSocketError::NotConnected)?;
    let payload = serde_json::json!({ "envelope_id": envelope_id }).to_string();
    socket
      .send(Message::Text(payload.into()))
      .await
      .map_err(SlackSocketError::Acknowledge)
  }
}

#[derive(Debug, Deserialize)]
struct OpenConnectionResponse {
  ok: bool,
  url: Option<String>,
  error: Option<String>,
}
