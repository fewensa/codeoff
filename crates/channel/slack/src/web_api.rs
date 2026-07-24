use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::{env, fs};

use async_trait::async_trait;
use codeoff_channel_contract::{
  ChannelConnectorCapabilities, ChannelConnectorStatus, ChannelContextPage, ChannelContextRequest,
  ChannelEvent, ChannelEventKind, ChannelLookupRequest, ChannelMessageFetchRequest,
  ChannelMessageSnapshot, ChannelReplyTarget, ChannelResourceDownload,
  ChannelResourceDownloadRequest, ChannelResourceInfo, ChannelResourceInfoRequest,
  ChannelResourceText, ChannelResourceTextRequest, ChannelSearchRequest, ChannelSenderSummary,
  ChannelSummary, ChannelThreadReplyReceipt, ChannelThreadReplyRequest, ChannelUserResolveRequest,
  ChannelUserResolveResult, ChannelUserSearchRequest, ChannelUserSummary, ChannelWorkspaceRequest,
  ChannelWorkspaceSummary,
};
use codeoff_config::SlackConfig;
use codeoff_runtime::channel_tools::{
  ChannelChannelProvider, ChannelContextProvider, ChannelContextProviderError,
  ChannelResourceProvider, ChannelResourceProviderError, ChannelSenderProvider,
  ChannelStatusProvider, ChannelThreadReplyProvider, ChannelToolError, ChannelUserProvider,
};
use codeoff_state::SlackDeliverySender;
use futures_util::StreamExt;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const CONVERSATION_TYPES: &str = "public_channel,private_channel,im";
const SLACK_WEB_API_BASE_URL: &str = "https://slack.com/api/";
const RESOURCE_THREAD_REPLY_LIMIT: usize = 50;
const RESOURCE_TEXT_MAX_BYTES: u64 = 1_048_576;
const RESOURCE_TEXT_MAX_CHARS: usize = 1_048_576;
const RESOURCE_DOWNLOAD_MAX_BYTES: u64 = 25 * 1_024 * 1_024;
const MEMBERSHIP_PAGE_LIMIT: usize = 1_000;

/// An async HTTP boundary for Slack Web API calls.
#[async_trait]
pub trait SlackHttpClient {
  /// Performs a GET request without exposing the authorization value in diagnostics.
  ///
  /// # Errors
  ///
  /// Returns a transport error description when the request cannot be completed.
  async fn get(&self, request: SlackHttpRequest) -> Result<SlackHttpResponse, String>;

  /// Performs a POST request without exposing the authorization value in diagnostics.
  ///
  /// # Errors
  ///
  /// Returns a transport error description when the request cannot be completed.
  async fn post(&self, _request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
    Err("Slack HTTP POST is not implemented".to_owned())
  }

  /// Downloads bytes from a Slack private file URL with an authorization header.
  ///
  /// # Errors
  ///
  /// Returns a transport error description when the request cannot be completed.
  async fn get_bytes(&self, _request: SlackHttpDownloadRequest) -> Result<Vec<u8>, String> {
    Err("Slack HTTP byte download is not implemented".to_owned())
  }
}

/// A Slack Web API request with a redacted `Debug` implementation.
#[derive(Clone, PartialEq, Eq)]
pub struct SlackHttpRequest {
  path: String,
  query: Vec<(String, String)>,
  json_body: Option<String>,
  authorization: String,
}

impl SlackHttpRequest {
  #[must_use]
  pub fn new<I, K, V>(
    path: impl Into<String>,
    query: I,
    json_body: Option<String>,
    authorization: impl Into<String>,
  ) -> Self
  where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
  {
    Self {
      path: path.into(),
      query: query
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect(),
      json_body,
      authorization: authorization.into(),
    }
  }

  #[must_use]
  pub fn path(&self) -> &str {
    &self.path
  }

  #[must_use]
  pub fn query_value(&self, key: &str) -> Option<&str> {
    self
      .query
      .iter()
      .find(|(candidate, _)| candidate == key)
      .map(|(_, value)| value.as_str())
  }

  #[must_use]
  pub fn json_value(&self, key: &str) -> Option<String> {
    let body: serde_json::Value = serde_json::from_str(self.json_body.as_deref()?).ok()?;
    body.get(key)?.as_str().map(ToOwned::to_owned)
  }

  #[must_use]
  pub fn json_string_array_value(&self, key: &str) -> Option<Vec<String>> {
    let body: serde_json::Value = serde_json::from_str(self.json_body.as_deref()?).ok()?;
    body
      .get(key)?
      .as_array()?
      .iter()
      .map(|value| value.as_str().map(ToOwned::to_owned))
      .collect()
  }

  #[must_use]
  pub fn json_boolean_value(&self, key: &str) -> Option<bool> {
    let body: serde_json::Value = serde_json::from_str(self.json_body.as_deref()?).ok()?;
    body.get(key)?.as_bool()
  }

  #[must_use]
  pub fn json_keys(&self) -> Option<Vec<String>> {
    let body: serde_json::Value = serde_json::from_str(self.json_body.as_deref()?).ok()?;
    let mut keys = body.as_object()?.keys().cloned().collect::<Vec<_>>();
    keys.sort_unstable();
    Some(keys)
  }

  #[must_use]
  pub fn authorization_is_bearer_token(&self, token: &str) -> bool {
    self.authorization == format!("Bearer {token}")
  }
}

impl fmt::Debug for SlackHttpRequest {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("SlackHttpRequest")
      .field("path", &self.path)
      .field("query", &self.query)
      .field("json_body", &self.json_body.as_ref().map(|_| "<omitted>"))
      .field("authorization", &"<redacted>")
      .finish()
  }
}

/// A private Slack file download request with redacted diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct SlackHttpDownloadRequest {
  url: String,
  authorization: String,
  max_bytes: usize,
}

impl SlackHttpDownloadRequest {
  #[must_use]
  pub fn new(url: impl Into<String>, authorization: impl Into<String>, max_bytes: usize) -> Self {
    Self {
      url: url.into(),
      authorization: authorization.into(),
      max_bytes,
    }
  }

  #[must_use]
  pub fn url(&self) -> &str {
    &self.url
  }

  #[must_use]
  pub const fn max_bytes(&self) -> usize {
    self.max_bytes
  }

  #[must_use]
  pub fn authorization_is_bearer_token(&self, token: &str) -> bool {
    self.authorization == format!("Bearer {token}")
  }
}

impl fmt::Debug for SlackHttpDownloadRequest {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("SlackHttpDownloadRequest")
      .field("url", &"<omitted>")
      .field("authorization", &"<redacted>")
      .field("max_bytes", &self.max_bytes)
      .finish()
  }
}

/// A Slack Web API response returned by the HTTP boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct SlackHttpResponse {
  status: u16,
  headers: Vec<(String, String)>,
  body: String,
}

impl fmt::Debug for SlackHttpResponse {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("SlackHttpResponse")
      .field("status", &self.status)
      .field("headers", &self.headers)
      .field("body", &"<omitted>")
      .finish()
  }
}

impl SlackHttpResponse {
  #[must_use]
  pub fn new<I, K, V>(status: u16, headers: I, body: impl Into<String>) -> Self
  where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
  {
    Self {
      status,
      headers: headers
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect(),
      body: body.into(),
    }
  }

  fn retry_after_seconds(&self) -> Option<u64> {
    self
      .headers
      .iter()
      .find(|(key, _)| key.eq_ignore_ascii_case("retry-after"))
      .and_then(|(_, value)| value.parse().ok())
  }
}

/// Sanitized request construction preview for tests and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackHttpRequestPreview {
  pub method: reqwest::Method,
  pub url: String,
  pub has_json_body: bool,
}

/// Production Slack Web API HTTP client backed by `reqwest`.
#[derive(Debug, Clone)]
pub struct SlackReqwestWebApiClient {
  client: Client,
  base_url: String,
}

impl SlackReqwestWebApiClient {
  /// Creates a production client that targets Slack's public Web API endpoint.
  ///
  /// # Panics
  ///
  /// Panics when the configured Slack Web API base URL is invalid.
  #[must_use]
  pub fn new() -> Self {
    Self {
      client: Client::new(),
      base_url: SLACK_WEB_API_BASE_URL.to_owned(),
    }
  }

  /// Builds a sanitized HTTP request preview without sending it.
  ///
  /// This is intentionally public so tests can verify construction without live Slack calls or
  /// access to authorization/body values.
  ///
  /// # Errors
  ///
  /// Returns a redacted error when the path, headers, or body cannot be represented as an HTTP
  /// request.
  pub fn build_request_preview(
    &self,
    request: &SlackHttpRequest,
  ) -> Result<SlackHttpRequestPreview, String> {
    let method = if request.json_body.is_some() {
      reqwest::Method::POST
    } else {
      reqwest::Method::GET
    };
    let url = self.build_url(request)?;
    Ok(SlackHttpRequestPreview {
      method,
      url: url.to_string(),
      has_json_body: request.json_body.is_some(),
    })
  }

  fn build_url(&self, request: &SlackHttpRequest) -> Result<reqwest::Url, String> {
    validate_slack_api_path(&request.path)?;
    let mut url =
      reqwest::Url::parse(&format!("{}{}", self.base_url, request.path)).map_err(redacted_error)?;
    if !request.query.is_empty() {
      url
        .query_pairs_mut()
        .extend_pairs(request.query.iter().map(|(key, value)| (&**key, &**value)));
    }
    Ok(url)
  }

  fn build_request_with_method(
    &self,
    method: reqwest::Method,
    request: &SlackHttpRequest,
  ) -> Result<reqwest::Request, String> {
    let url = self.build_url(request)?;
    let mut authorization = HeaderValue::from_str(&request.authorization)
      .map_err(|error| redact_secrets(&error.to_string(), Some(&request.authorization)))?;
    authorization.set_sensitive(true);
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, authorization);

    let mut builder = self.client.request(method, url).headers(headers);
    if let Some(body) = &request.json_body {
      builder = builder
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .body(body.clone());
    }
    builder
      .build()
      .map_err(|error| redact_secrets(&error.to_string(), Some(&request.authorization)))
  }

  async fn send(
    &self,
    method: reqwest::Method,
    request: SlackHttpRequest,
  ) -> Result<SlackHttpResponse, String> {
    let request = self.build_request_with_method(method, &request)?;
    let response = self.client.execute(request).await.map_err(redacted_error)?;
    let status = response.status().as_u16();
    let headers = response
      .headers()
      .iter()
      .filter_map(|(key, value)| {
        value
          .to_str()
          .ok()
          .map(|value| (key.as_str().to_owned(), value.to_owned()))
      })
      .collect::<Vec<_>>();
    let body = response.text().await.map_err(redacted_error)?;
    Ok(SlackHttpResponse::new(status, headers, body))
  }

  async fn send_bytes(&self, request: SlackHttpDownloadRequest) -> Result<Vec<u8>, String> {
    let url = reqwest::Url::parse(&request.url).map_err(redacted_error)?;
    if url.scheme() != "https" {
      return Err("unsafe slack file download url".to_owned());
    }
    let mut authorization = HeaderValue::from_str(&request.authorization)
      .map_err(|error| redact_secrets(&error.to_string(), Some(&request.authorization)))?;
    authorization.set_sensitive(true);
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, authorization);
    let response = self
      .client
      .get(url)
      .headers(headers)
      .send()
      .await
      .map_err(redacted_download_error)?;
    if !response.status().is_success() {
      return Err(format!("http status {}", response.status().as_u16()));
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
      let chunk = chunk.map_err(redacted_download_error)?;
      if body.len().saturating_add(chunk.len()) > request.max_bytes {
        return Err("slack file download exceeded byte limit".to_owned());
      }
      body.extend_from_slice(&chunk);
    }
    Ok(body)
  }
}

impl Default for SlackReqwestWebApiClient {
  fn default() -> Self {
    Self::new()
  }
}

#[async_trait]
impl SlackHttpClient for SlackReqwestWebApiClient {
  async fn get(&self, request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
    self.send(reqwest::Method::GET, request).await
  }

  async fn post(&self, request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
    self.send(reqwest::Method::POST, request).await
  }

  async fn get_bytes(&self, request: SlackHttpDownloadRequest) -> Result<Vec<u8>, String> {
    self.send_bytes(request).await
  }
}

fn redacted_error(error: impl fmt::Display) -> String {
  redact_secrets(&error.to_string(), None)
}

fn redacted_download_error(error: impl fmt::Display) -> String {
  let error = error.to_string();
  if error.contains("files.slack.com") {
    "slack file download failed".to_owned()
  } else {
    redact_secrets(&error, None)
  }
}

fn validate_slack_api_path(path: &str) -> Result<(), String> {
  if path.is_empty()
    || path.starts_with('/')
    || path.starts_with("//")
    || path.contains(':')
    || path.contains("://")
    || path.contains('%')
    || path.split('/').any(|segment| segment == "..")
  {
    return Err("unsafe slack web api path".to_owned());
  }
  Ok(())
}

fn redact_secrets(value: &str, authorization: Option<&str>) -> String {
  let mut redacted = value.to_owned();
  if let Some(authorization) = authorization {
    redacted = redacted.replace(authorization, "<redacted>");
  }
  redacted = redact_bearer_values(&redacted);
  redact_slack_tokens(&redacted)
}

fn redact_bearer_values(value: &str) -> String {
  let mut redacted = String::with_capacity(value.len());
  let mut remaining = value;
  while let Some(offset) = remaining.find("Bearer ") {
    redacted.push_str(&remaining[..offset]);
    redacted.push_str("Bearer <redacted>");
    let token_start = offset + "Bearer ".len();
    let token_len = remaining[token_start..]
      .find(|character: char| {
        character.is_ascii_whitespace() || matches!(character, '"' | '\'' | ',' | ')' | ']')
      })
      .unwrap_or(remaining.len() - token_start);
    remaining = &remaining[token_start + token_len..];
  }
  redacted.push_str(remaining);
  redacted
}

fn redact_slack_tokens(value: &str) -> String {
  const PREFIXES: [&str; 7] = [
    "xoxb-", "xoxp-", "xapp-", "xoxa-", "xoxr-", "xoxs-", "xoxe-",
  ];
  let mut redacted = String::with_capacity(value.len());
  let mut index = 0;
  while index < value.len() {
    if PREFIXES
      .iter()
      .any(|prefix| value[index..].starts_with(prefix))
    {
      redacted.push_str("<redacted>");
      index += value[index..]
        .find(|character: char| {
          !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        })
        .unwrap_or(value.len() - index);
    } else if let Some(character) = value[index..].chars().next() {
      redacted.push(character);
      index += character.len_utf8();
    } else {
      break;
    }
  }
  redacted
}

/// Errors reported while fetching Slack context. Values derived from requests are token-redacted.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SlackWebApiError {
  #[error("slack web api request failed: {message}")]
  Request { message: String },

  #[error("slack web api rate limited; retry after {retry_after_seconds:?} seconds")]
  RateLimited { retry_after_seconds: Option<u64> },

  #[error("slack channel is unavailable")]
  Unavailable,

  #[error("slack web api returned an invalid response: {message}")]
  InvalidResponse { message: String },

  #[error("slack web api provider error: {message}")]
  Provider { message: String },

  #[error("slack web api rejected the request: {classification}")]
  Api {
    classification: SlackApiErrorClass,
    scope: SlackApiErrorScope,
  },

  #[error("slack context target is unsupported")]
  UnsupportedTarget,

  #[error("slack delivery is deferred until {available_at}")]
  Deferred { available_at: u64 },
}

impl SlackWebApiError {
  #[must_use]
  pub const fn is_retryable(&self) -> bool {
    matches!(
      self,
      Self::Request { .. }
        | Self::RateLimited { .. }
        | Self::Api {
          classification: SlackApiErrorClass::Transient,
          ..
        }
    )
  }
}

/// Resolver-relevant classification for a Slack Web API rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlackApiErrorClass {
  Invalid,
  Unauthorized,
  TargetUnavailable,
  Transient,
}

/// Stable authority scope for Slack API rejections without retaining provider response text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlackApiErrorScope {
  GlobalProvider,
  Target,
  Unknown,
}

impl fmt::Display for SlackApiErrorClass {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(match self {
      Self::Invalid => "invalid request",
      Self::Unauthorized => "unauthorized",
      Self::TargetUnavailable => "target unavailable",
      Self::Transient => "transient failure",
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackAuthIdentity {
  pub team_id: String,
  pub enterprise_id: Option<String>,
  pub user_id: String,
  pub bot_id: String,
}

/// Fetches bounded Slack channel and thread context through a supplied HTTP client.
pub struct SlackWebApiClient<H> {
  http: H,
  connector_id: String,
  bot_token: String,
  config: SlackConfig,
  now_unix_seconds: u64,
  artifact_root: Option<PathBuf>,
  user_token_resolver: Arc<dyn Fn(&str) -> Result<String, env::VarError> + Send + Sync>,
}

impl<H: SlackHttpClient + Sync> SlackWebApiClient<H> {
  #[must_use]
  pub fn new(
    http: H,
    connector_id: impl Into<String>,
    bot_token: impl Into<String>,
    config: SlackConfig,
    now_unix_seconds: u64,
  ) -> Self {
    Self {
      http,
      connector_id: connector_id.into(),
      bot_token: bot_token.into(),
      config,
      now_unix_seconds,
      artifact_root: None,
      user_token_resolver: Arc::new(|name| env::var(name)),
    }
  }

  #[must_use]
  pub fn new_with_artifact_root(
    http: H,
    connector_id: impl Into<String>,
    bot_token: impl Into<String>,
    config: SlackConfig,
    now_unix_seconds: u64,
    artifact_root: impl Into<PathBuf>,
  ) -> Self {
    Self {
      http,
      connector_id: connector_id.into(),
      bot_token: bot_token.into(),
      config,
      now_unix_seconds,
      artifact_root: Some(artifact_root.into()),
      user_token_resolver: Arc::new(|name| env::var(name)),
    }
  }

  #[must_use]
  pub fn new_with_user_token_resolver(
    http: H,
    connector_id: impl Into<String>,
    bot_token: impl Into<String>,
    config: SlackConfig,
    now_unix_seconds: u64,
    user_token_resolver: Arc<dyn Fn(&str) -> Result<String, env::VarError> + Send + Sync>,
  ) -> Self {
    Self {
      http,
      connector_id: connector_id.into(),
      bot_token: bot_token.into(),
      config,
      now_unix_seconds,
      artifact_root: None,
      user_token_resolver,
    }
  }

  #[must_use]
  pub const fn http_client(&self) -> &H {
    &self.http
  }

  /// Returns the Slack connector capabilities advertised by this Web API adapter.
  #[must_use]
  pub const fn capabilities(&self) -> ChannelConnectorCapabilities {
    slack_capabilities()
  }

  /// Returns local connector status, including configured sender selectors.
  #[must_use]
  pub fn connector_status(&self) -> SlackConnectorStatus {
    SlackConnectorStatus {
      connector_id: self.connector_id.clone(),
      workspace_id: self.config.workspace_id.clone(),
      capabilities: self.capabilities(),
      senders: self.configured_senders(),
    }
  }

  /// Returns the configured Slack workspace without requiring the caller to know its id.
  #[must_use]
  pub fn workspace_summary(&self) -> ChannelWorkspaceSummary {
    ChannelWorkspaceSummary {
      provider: "slack".to_owned(),
      connector_id: self.connector_id.clone(),
      connector_name: Some("Slack".to_owned()),
      workspace_id: self.config.workspace_id.clone(),
      workspace_name: None,
      display_name: format!("Slack workspace {}", self.config.workspace_id),
    }
  }

  /// Returns configured sender selectors without resolving or exposing token values.
  #[must_use]
  pub fn configured_senders(&self) -> Vec<SlackConfiguredSender> {
    let mut senders = vec![SlackConfiguredSender {
      kind: "bot".to_owned(),
      key: None,
      user_id: None,
      token_env: Some(self.config.bot_token_env.clone()),
    }];
    senders.extend(
      self
        .config
        .user_tokens
        .iter()
        .map(|(key, config)| SlackConfiguredSender {
          kind: "user".to_owned(),
          key: Some(key.clone()),
          user_id: non_empty_string(Some(&config.user_id)).map(ToOwned::to_owned),
          token_env: non_empty_string(Some(&config.token_env)).map(ToOwned::to_owned),
        }),
    );
    senders
  }

  /// Searches Slack users through `users.list` and maps visible profiles into stable summaries.
  ///
  /// # Errors
  ///
  /// Returns an error when Slack rejects, rate-limits, or returns an invalid response.
  pub async fn search_users(&self, query: &str) -> Result<Vec<SlackUserAddress>, SlackWebApiError> {
    let needle = normalized_lookup(query);
    let mut users = Vec::new();
    let mut cursor = None;
    loop {
      let mut request_query = Vec::new();
      if let Some(cursor) = cursor.take() {
        request_query.push(("cursor".to_owned(), cursor));
      }
      let response = self.request("users.list", request_query).await?;
      let parsed = self.parse_api_response(&response)?;
      users.extend(
        parsed
          .members
          .iter()
          .filter(|user| !user.deleted)
          .filter_map(|user| self.to_user_address(user))
          .filter(|user| user.matches_query(&needle)),
      );
      cursor = parsed
        .response_metadata
        .next_cursor
        .filter(|cursor| !cursor.is_empty());
      if cursor.is_none() {
        return Ok(users);
      }
    }
  }

  /// Fetches one Slack user through `users.info`.
  ///
  /// # Errors
  ///
  /// Returns an error when Slack rejects, rate-limits, or returns an invalid response.
  pub async fn get_user(&self, user_id: &str) -> Result<SlackUserAddress, SlackWebApiError> {
    let response = self
      .request("users.info", vec![("user".to_owned(), user_id.to_owned())])
      .await?;
    let parsed = self.parse_api_response(&response)?;
    let user = parsed
      .user
      .as_ref()
      .ok_or_else(|| SlackWebApiError::InvalidResponse {
        message: "users.info response is missing user".to_owned(),
      })?;
    self
      .to_user_address(user)
      .ok_or(SlackWebApiError::Unavailable)
  }

  /// Resolves a user id, handle, display name, real name, or email into one unambiguous user.
  ///
  /// # Errors
  ///
  /// Returns an error when Slack rejects, rate-limits, or returns an invalid response.
  pub async fn resolve_user(
    &self,
    query: &str,
  ) -> Result<Option<SlackUserAddress>, SlackWebApiError> {
    let query = query.trim().trim_start_matches('@');
    if looks_like_slack_user_id(query) {
      return self.get_user(query).await.map(Some);
    }
    let needle = normalized_lookup(query);
    let matches = self
      .search_users(query)
      .await?
      .into_iter()
      .filter(|user| user.exactly_matches_query(&needle))
      .collect::<Vec<_>>();
    Ok(single_match(matches))
  }

  /// Searches Slack conversations through `conversations.list`.
  ///
  /// # Errors
  ///
  /// Returns an error when Slack rejects, rate-limits, or returns an invalid response.
  pub async fn search_channels(
    &self,
    query: &str,
  ) -> Result<Vec<SlackChannelAddress>, SlackWebApiError> {
    let needle = normalized_lookup(query.trim().trim_start_matches('#'));
    let mut channels = Vec::new();
    let mut cursor = None;
    loop {
      let mut request_query = vec![("types".to_owned(), CONVERSATION_TYPES.to_owned())];
      if let Some(cursor) = cursor.take() {
        request_query.push(("cursor".to_owned(), cursor));
      }
      let response = self.request("conversations.list", request_query).await?;
      let parsed = self.parse_api_response(&response)?;
      channels.extend(
        parsed
          .channels
          .iter()
          .filter(|channel| !channel.is_archived)
          .map(|channel| self.to_channel_address(channel))
          .filter(|channel| channel.matches_query(&needle)),
      );
      cursor = parsed
        .response_metadata
        .next_cursor
        .filter(|cursor| !cursor.is_empty());
      if cursor.is_none() {
        return Ok(channels);
      }
    }
  }

  /// Fetches one Slack conversation through `conversations.info`.
  ///
  /// # Errors
  ///
  /// Returns an error when Slack rejects, rate-limits, or returns an invalid response.
  pub async fn get_channel(
    &self,
    channel_id: &str,
  ) -> Result<SlackChannelAddress, SlackWebApiError> {
    let response = self
      .request(
        "conversations.info",
        vec![("channel".to_owned(), channel_id.to_owned())],
      )
      .await?;
    let parsed = self.parse_api_response(&response)?;
    let channel = parsed
      .channel_object()
      .ok_or_else(|| SlackWebApiError::InvalidResponse {
        message: "conversations.info response is missing channel".to_owned(),
      })?;
    Ok(self.to_channel_address(&channel))
  }

  /// Verifies the configured bot token and returns its provider-issued routing identity.
  ///
  /// # Errors
  /// Returns an error when the token is rejected or Slack omits required bot identity fields.
  pub async fn authenticate_bot(&self) -> Result<SlackAuthIdentity, SlackWebApiError> {
    let response = self
      .post_json("auth.test", "{}".to_owned(), &self.bot_token)
      .await?;
    let parsed = self.parse_api_response(&response)?;
    let identity = SlackAuthIdentity {
      team_id: required_identifier(parsed.team_id.as_deref(), "auth.test team_id")?,
      enterprise_id: optional_identifier(parsed.enterprise_id.as_deref(), 'E')?,
      user_id: required_identifier(parsed.user_id.as_deref(), "auth.test user_id")?,
      bot_id: required_identifier(parsed.bot_id.as_deref(), "auth.test bot_id")?,
    };
    if !identity.team_id.starts_with('T')
      || !(identity.user_id.starts_with('U') || identity.user_id.starts_with('W'))
      || !identity.bot_id.starts_with('B')
    {
      return Err(SlackWebApiError::InvalidResponse {
        message: "auth.test returned invalid bot identity".to_owned(),
      });
    }
    Ok(identity)
  }

  /// Opens or looks up the canonical one-to-one Slack conversation for a user.
  ///
  /// # Errors
  /// Returns an error when Slack rejects the request or omits the canonical conversation id.
  pub async fn open_direct_message(
    &self,
    user_id: &str,
  ) -> Result<SlackChannelAddress, SlackWebApiError> {
    let body = serde_json::to_string(&serde_json::json!({
      "return_im": true,
      "users": user_id,
    }))
    .map_err(|source| SlackWebApiError::InvalidResponse {
      message: self.redact(&source.to_string()),
    })?;
    let response = self
      .post_json("conversations.open", body, &self.bot_token)
      .await?;
    let parsed = self.parse_api_response(&response)?;
    let opened = parsed
      .channel_object()
      .ok_or_else(|| SlackWebApiError::InvalidResponse {
        message: "conversations.open response is missing channel id".to_owned(),
      })?;
    if !looks_like_slack_dm_id(&opened.id) {
      return Err(SlackWebApiError::Api {
        classification: SlackApiErrorClass::Invalid,
        scope: SlackApiErrorScope::Target,
      });
    }
    let canonical = self.get_channel(&opened.id).await?;
    if canonical.channel_id != opened.id {
      return Err(SlackWebApiError::InvalidResponse {
        message: "conversations.open returned an unstable conversation id".to_owned(),
      });
    }
    Ok(canonical)
  }

  /// Proves that a Slack actor belongs to a target conversation.
  ///
  /// The membership cursor is followed to exhaustion with a hard page bound. Missing, repeated,
  /// partial, or rejected pagination fails closed.
  ///
  /// # Errors
  /// Returns an error when Slack rejects the request, returns invalid pagination, or is unavailable.
  pub async fn actor_is_channel_member(
    &self,
    actor_id: &str,
    channel_id: &str,
  ) -> Result<bool, SlackWebApiError> {
    let mut cursor: Option<String> = None;
    for _ in 0..MEMBERSHIP_PAGE_LIMIT {
      let mut query = vec![("channel".to_owned(), channel_id.to_owned())];
      if let Some(value) = cursor.as_ref() {
        query.push(("cursor".to_owned(), value.clone()));
      }
      let response = self.request("conversations.members", query).await?;
      let page = self.parse_conversation_members_response(&response)?;
      if page.members.iter().any(|member| member == actor_id) {
        return Ok(true);
      }
      let next = page
        .response_metadata
        .next_cursor
        .filter(|value| !value.is_empty());
      if next.is_none() {
        return Ok(false);
      }
      if next == cursor {
        return Err(SlackWebApiError::InvalidResponse {
          message: "conversations.members returned a repeated cursor".to_owned(),
        });
      }
      cursor = next;
    }
    Err(SlackWebApiError::InvalidResponse {
      message: "conversations.members exceeded the pagination bound".to_owned(),
    })
  }

  /// Proves that the requested Slack thread parent exists in the target conversation.
  ///
  /// # Errors
  /// Returns an error when Slack rejects the request or returns an invalid response.
  pub async fn thread_parent_exists(
    &self,
    channel_id: &str,
    thread_id: &str,
  ) -> Result<bool, SlackWebApiError> {
    let response = self
      .request(
        "conversations.replies",
        vec![
          ("channel".to_owned(), channel_id.to_owned()),
          ("ts".to_owned(), thread_id.to_owned()),
          ("limit".to_owned(), "1".to_owned()),
        ],
      )
      .await?;
    let parsed = self.parse_api_response(&response)?;
    Ok(
      parsed
        .messages
        .first()
        .and_then(|message| message.ts.as_deref())
        == Some(thread_id),
    )
  }

  /// Proves that the supplied timestamp is an accessible root thread parent, never a reply.
  ///
  /// # Errors
  /// Returns an error when Slack rejects the request or returns an invalid response.
  pub async fn thread_parent_is_root(
    &self,
    channel_id: &str,
    thread_ts: &str,
  ) -> Result<bool, SlackWebApiError> {
    let response = self
      .request(
        "conversations.replies",
        vec![
          ("channel".to_owned(), channel_id.to_owned()),
          ("ts".to_owned(), thread_ts.to_owned()),
          ("limit".to_owned(), "1".to_owned()),
        ],
      )
      .await?;
    let parsed = self.parse_api_response(&response)?;
    Ok(parsed.messages.first().is_some_and(|message| {
      message.ts.as_deref() == Some(thread_ts)
        && message
          .thread_ts
          .as_deref()
          .is_none_or(|parent| parent == thread_ts)
    }))
  }

  /// Resolves a Slack channel id or name into one unambiguous conversation.
  ///
  /// # Errors
  ///
  /// Returns an error when Slack rejects, rate-limits, or returns an invalid response.
  pub async fn resolve_channel(
    &self,
    query: &str,
  ) -> Result<Option<SlackChannelAddress>, SlackWebApiError> {
    let query = query.trim().trim_start_matches('#');
    if looks_like_slack_channel_id(query) {
      return self.get_channel(query).await.map(Some);
    }
    let needle = normalized_lookup(query);
    let matches = self
      .search_channels(query)
      .await?
      .into_iter()
      .filter(|channel| channel.exactly_matches_query(&needle))
      .collect::<Vec<_>>();
    Ok(single_match(matches))
  }

  /// Fetches one bounded page of channel or thread context.
  ///
  /// # Errors
  ///
  /// Returns `Unavailable` when the channel is not visible to the token, and a retryable
  /// `RateLimited` error when Slack responds with `429`.
  pub async fn fetch_context(
    &self,
    request: &ChannelContextRequest,
  ) -> Result<ChannelContextPage, SlackWebApiError> {
    let (channel_id, thread_id) = match &request.target {
      ChannelReplyTarget::Channel { channel_id } => (channel_id.as_str(), None),
      ChannelReplyTarget::Thread {
        channel_id,
        thread_id,
      } => (channel_id.as_str(), Some(thread_id.as_str())),
      ChannelReplyTarget::DirectMessage { .. } | ChannelReplyTarget::Ephemeral { .. } => {
        return Err(SlackWebApiError::UnsupportedTarget);
      }
    };

    self.ensure_channel_is_available(channel_id).await?;

    let configured_limit = if thread_id.is_some() {
      self.config.thread_message_limit
    } else {
      self.config.recent_message_limit
    };
    let limit = usize::from(request.limit.min(configured_limit));
    let cutoff = self
      .now_unix_seconds
      .saturating_sub(u64::from(self.config.history_lookback_hours) * 60 * 60);
    let mut query = vec![
      ("channel".to_owned(), channel_id.to_owned()),
      ("limit".to_owned(), limit.to_string()),
      ("oldest".to_owned(), cutoff.to_string()),
    ];
    if let Some(cursor) = request.cursor.as_ref() {
      query.push(("cursor".to_owned(), cursor.clone()));
    }
    let path = if let Some(thread_id) = thread_id {
      query.push(("ts".to_owned(), thread_id.to_owned()));
      "conversations.replies"
    } else {
      "conversations.history"
    };
    let response = self.request(path, query).await?;
    let page = self.parse_api_response(&response)?;
    let events = page
      .messages
      .iter()
      .filter(|message| {
        message
          .timestamp()
          .is_some_and(|timestamp| timestamp >= cutoff)
      })
      .take(limit)
      .map(|message| self.to_event(channel_id, &request.workspace_id, message))
      .collect::<Result<Vec<_>, _>>()?;

    Ok(ChannelContextPage {
      events,
      next_cursor: page
        .response_metadata
        .next_cursor
        .filter(|cursor| !cursor.is_empty()),
    })
  }

  async fn ensure_channel_is_available(&self, channel_id: &str) -> Result<(), SlackWebApiError> {
    let mut cursor = None;
    loop {
      let mut query = vec![("types".to_owned(), CONVERSATION_TYPES.to_owned())];
      if let Some(cursor) = cursor.take() {
        query.push(("cursor".to_owned(), cursor));
      }
      let response = self.request("conversations.list", query).await?;
      let page = self.parse_api_response(&response)?;
      if page.channels.iter().any(|channel| channel.id == channel_id) {
        return Ok(());
      }
      cursor = page
        .response_metadata
        .next_cursor
        .filter(|cursor| !cursor.is_empty());
      if cursor.is_none() {
        return Err(SlackWebApiError::Unavailable);
      }
    }
  }

  async fn request(
    &self,
    path: &str,
    query: Vec<(String, String)>,
  ) -> Result<SlackHttpResponse, SlackWebApiError> {
    let response = self
      .http
      .get(SlackHttpRequest {
        path: path.to_owned(),
        query,
        json_body: None,
        authorization: format!("Bearer {}", self.bot_token),
      })
      .await
      .map_err(|message| SlackWebApiError::Request {
        message: self.redact(&message),
      })?;
    if response.status == 429 {
      return Err(SlackWebApiError::RateLimited {
        retry_after_seconds: response.retry_after_seconds(),
      });
    }
    if !(200..300).contains(&response.status) {
      return Err(SlackWebApiError::Api {
        classification: classify_http_status(response.status),
        scope: classify_http_status_scope(response.status),
      });
    }
    Ok(response)
  }

  async fn download_private_file_bytes(
    &self,
    url: &str,
    max_bytes: u64,
  ) -> Result<Vec<u8>, SlackWebApiError> {
    validate_slack_file_download_url(url).map_err(|message| SlackWebApiError::Request {
      message: self.redact(&message),
    })?;
    let max_bytes = usize::try_from(max_bytes).map_err(|_| SlackWebApiError::Provider {
      message: "download byte limit is too large".to_owned(),
    })?;
    self
      .http
      .get_bytes(SlackHttpDownloadRequest::new(
        url,
        format!("Bearer {}", self.bot_token),
        max_bytes,
      ))
      .await
      .map_err(|message| SlackWebApiError::Request {
        message: self.redact(&redacted_download_error(message)),
      })
  }

  fn parse_api_response(
    &self,
    response: &SlackHttpResponse,
  ) -> Result<SlackApiResponse, SlackWebApiError> {
    let parsed: SlackApiResponse =
      serde_json::from_str(&response.body).map_err(|source| SlackWebApiError::InvalidResponse {
        message: self.redact(&source.to_string()),
      })?;
    if parsed.ok {
      Ok(parsed)
    } else {
      let (classification, scope) = classify_slack_api_error(parsed.error.as_deref());
      Err(SlackWebApiError::Api {
        classification,
        scope,
      })
    }
  }

  fn parse_conversation_members_response(
    &self,
    response: &SlackHttpResponse,
  ) -> Result<SlackConversationMembersResponse, SlackWebApiError> {
    let parsed: SlackConversationMembersResponse =
      serde_json::from_str(&response.body).map_err(|source| SlackWebApiError::InvalidResponse {
        message: self.redact(&source.to_string()),
      })?;
    if parsed.ok {
      Ok(parsed)
    } else {
      let (classification, scope) = classify_slack_api_error(parsed.error.as_deref());
      Err(SlackWebApiError::Api {
        classification,
        scope,
      })
    }
  }

  fn to_event(
    &self,
    channel_id: &str,
    workspace_id: &str,
    message: &SlackMessage,
  ) -> Result<ChannelEvent, SlackWebApiError> {
    let timestamp = message
      .ts
      .as_deref()
      .ok_or_else(|| SlackWebApiError::InvalidResponse {
        message: "message is missing ts".to_owned(),
      })?;
    ChannelEvent::new(
      "slack",
      &self.connector_id,
      workspace_id,
      timestamp,
      format!("slack:{channel_id}:{timestamp}"),
      ChannelEventKind::MessageReceived,
    )
    .map(|event| event.with_text(message.summary_text()))
    .map_err(|source| SlackWebApiError::InvalidResponse {
      message: source.to_string(),
    })
  }

  fn to_user_address(&self, user: &SlackUser) -> Option<SlackUserAddress> {
    non_empty_string(Some(&user.id))?;
    Some(SlackUserAddress {
      connector_id: self.connector_id.clone(),
      workspace_id: self.config.workspace_id.clone(),
      user_id: user.id.clone(),
      handle: non_empty_string(user.name.as_deref()).map(ToOwned::to_owned),
      display_name: non_empty_string(user.profile.display_name.as_deref()).map(ToOwned::to_owned),
      real_name: non_empty_string(user.real_name.as_deref())
        .or_else(|| non_empty_string(user.profile.real_name.as_deref()))
        .map(ToOwned::to_owned),
      email: non_empty_string(user.profile.email.as_deref()).map(ToOwned::to_owned),
      team_id: non_empty_string(user.team_id.as_deref()).map(ToOwned::to_owned),
      enterprise_id: user
        .enterprise_user
        .as_ref()
        .and_then(|enterprise| non_empty_string(enterprise.enterprise_id.as_deref()))
        .map(ToOwned::to_owned),
      enterprise_team_ids: user
        .enterprise_user
        .as_ref()
        .map_or_else(Vec::new, |enterprise| enterprise.teams.clone()),
      deleted: user.deleted,
      is_bot: user.is_bot,
      is_app_user: user.is_app_user,
      is_restricted: user.is_restricted,
      is_ultra_restricted: user.is_ultra_restricted,
    })
  }

  fn to_channel_address(&self, channel: &SlackChannel) -> SlackChannelAddress {
    SlackChannelAddress {
      connector_id: self.connector_id.clone(),
      workspace_id: self.config.workspace_id.clone(),
      channel_id: channel.id.clone(),
      name: non_empty_string(channel.name.as_deref()).map(ToOwned::to_owned),
      is_private: channel.is_private,
      is_im: channel.is_im,
      is_mpim: channel.is_mpim,
      is_archived: channel.is_archived,
      is_member: channel.is_member,
      context_team_id: channel.context_team_id.clone(),
      enterprise_id: channel.enterprise_id.clone(),
      conversation_host_id: channel.conversation_host_id.clone(),
      shared_team_ids: channel.shared_team_ids.clone(),
      connected_team_ids: channel.connected_team_ids.clone(),
      is_shared: channel.is_shared,
      is_ext_shared: channel.is_ext_shared,
      is_org_shared: channel.is_org_shared,
    }
  }

  fn redact(&self, value: &str) -> String {
    redact_secrets(&value.replace(&self.bot_token, "<redacted>"), None)
  }

  async fn fetch_message_snapshot(
    &self,
    request: &ChannelMessageFetchRequest,
  ) -> Result<ChannelMessageSnapshot, SlackWebApiError> {
    let message = if request.thread_id.is_some() {
      self.fetch_threaded_message(request).await?
    } else {
      self.fetch_history_message(request).await?
    };
    Ok(ChannelMessageSnapshot {
      connector_id: request.connector_id.clone(),
      workspace_id: request.workspace_id.clone(),
      channel_id: request.channel_id.clone(),
      thread_id: request.thread_id.clone(),
      message_ts: request.message_ts.clone(),
      text: message.summary_text(),
      resources: message
        .files
        .iter()
        .filter_map(|file| slack_file_info(file, &request.connector_id, &request.workspace_id))
        .collect(),
    })
  }

  async fn fetch_history_message(
    &self,
    request: &ChannelMessageFetchRequest,
  ) -> Result<SlackMessage, SlackWebApiError> {
    let response = self
      .request(
        "conversations.history",
        vec![
          ("channel".to_owned(), request.channel_id.clone()),
          ("latest".to_owned(), request.message_ts.clone()),
          ("inclusive".to_owned(), "true".to_owned()),
          ("limit".to_owned(), "1".to_owned()),
        ],
      )
      .await?;
    let page = self.parse_api_response(&response)?;
    page
      .messages
      .into_iter()
      .find(|message| message.ts.as_deref() == Some(request.message_ts.as_str()))
      .ok_or(SlackWebApiError::Unavailable)
  }

  async fn fetch_threaded_message(
    &self,
    request: &ChannelMessageFetchRequest,
  ) -> Result<SlackMessage, SlackWebApiError> {
    let thread_id = request
      .thread_id
      .as_deref()
      .ok_or(SlackWebApiError::Unavailable)?;
    let mut cursor = None;
    loop {
      let mut query = vec![
        ("channel".to_owned(), request.channel_id.clone()),
        ("ts".to_owned(), thread_id.to_owned()),
        ("limit".to_owned(), RESOURCE_THREAD_REPLY_LIMIT.to_string()),
      ];
      if let Some(cursor) = cursor.take() {
        query.push(("cursor".to_owned(), cursor));
      }
      let response = self.request("conversations.replies", query).await?;
      let page = self.parse_api_response(&response)?;
      if let Some(message) = page
        .messages
        .into_iter()
        .find(|message| message.ts.as_deref() == Some(request.message_ts.as_str()))
      {
        return Ok(message);
      }
      cursor = page
        .response_metadata
        .next_cursor
        .filter(|cursor| !cursor.is_empty());
      if cursor.is_none() {
        return Err(SlackWebApiError::Unavailable);
      }
    }
  }

  async fn fetch_file_info(
    &self,
    connector_id: &str,
    workspace_id: &str,
    resource_id: &str,
  ) -> Result<SlackFileInfo, SlackWebApiError> {
    let response = self
      .request(
        "files.info",
        vec![("file".to_owned(), resource_id.to_owned())],
      )
      .await?;
    let parsed = self.parse_api_response(&response)?;
    let file = parsed
      .file
      .ok_or_else(|| SlackWebApiError::InvalidResponse {
        message: "files.info response is missing file".to_owned(),
      })?;
    Ok(SlackFileInfo::from_value(
      file,
      connector_id,
      workspace_id,
      resource_id,
    ))
  }

  async fn read_file_text(
    &self,
    request: &ChannelResourceTextRequest,
  ) -> Result<ChannelResourceText, ChannelResourceProviderError> {
    let file = self
      .fetch_file_info(
        &request.connector_id,
        &request.workspace_id,
        &request.resource_id,
      )
      .await
      .map_err(channel_resource_provider_error)?;
    if !file.is_text_like() || file.info.size_bytes.unwrap_or(0) > RESOURCE_TEXT_MAX_BYTES {
      return Err(ChannelResourceProviderError::UnsupportedResource);
    }
    let url = file
      .private_download_url()
      .ok_or(ChannelResourceProviderError::UnsupportedResource)?;
    let bytes = self
      .download_private_file_bytes(url, RESOURCE_TEXT_MAX_BYTES)
      .await
      .map_err(channel_resource_provider_error)?;
    let mut text =
      String::from_utf8(bytes).map_err(|source| ChannelResourceProviderError::InvalidResponse {
        message: self.redact(&source.to_string()),
      })?;
    if text.len() > RESOURCE_TEXT_MAX_CHARS {
      text.truncate(RESOURCE_TEXT_MAX_CHARS);
    }
    Ok(ChannelResourceText {
      connector_id: request.connector_id.clone(),
      workspace_id: request.workspace_id.clone(),
      resource_id: request.resource_id.clone(),
      text: Some(text),
    })
  }

  async fn download_file_resource(
    &self,
    request: &ChannelResourceDownloadRequest,
  ) -> Result<ChannelResourceDownload, ChannelResourceProviderError> {
    let root =
      self
        .artifact_root
        .as_ref()
        .ok_or_else(|| ChannelResourceProviderError::Provider {
          message: "slack artifact root is not configured".to_owned(),
        })?;
    let file = self
      .fetch_file_info(
        &request.connector_id,
        &request.workspace_id,
        &request.resource_id,
      )
      .await
      .map_err(channel_resource_provider_error)?;
    if file.info.size_bytes.unwrap_or(0) > RESOURCE_DOWNLOAD_MAX_BYTES {
      return Err(ChannelResourceProviderError::UnsupportedResource);
    }
    let url = file
      .private_download_url()
      .ok_or(ChannelResourceProviderError::UnsupportedResource)?;
    let bytes = self
      .download_private_file_bytes(url, RESOURCE_DOWNLOAD_MAX_BYTES)
      .await
      .map_err(channel_resource_provider_error)?;
    let filename = sanitize_artifact_filename(
      file
        .info
        .name
        .as_deref()
        .unwrap_or(request.resource_id.as_str()),
      &request.resource_id,
    );
    let directory = root
      .join("artifacts")
      .join("slack")
      .join(sanitize_path_segment(&request.workspace_id))
      .join(sanitize_path_segment(&request.resource_id));
    fs::create_dir_all(&directory).map_err(|source| ChannelResourceProviderError::Provider {
      message: self.redact(&source.to_string()),
    })?;
    let local_path = directory.join(&filename);
    fs::write(&local_path, bytes).map_err(|source| ChannelResourceProviderError::Provider {
      message: self.redact(&source.to_string()),
    })?;
    Ok(ChannelResourceDownload {
      connector_id: request.connector_id.clone(),
      workspace_id: request.workspace_id.clone(),
      resource_id: request.resource_id.clone(),
      artifact_uri: format!(
        "artifact://slack/{}/{}/{}",
        sanitize_path_segment(&request.workspace_id),
        sanitize_path_segment(&request.resource_id),
        filename
      ),
      local_path: Some(local_path.to_string_lossy().into_owned()),
    })
  }

  /// Posts a text message and returns Slack's canonical identifiers for a durable receipt.
  ///
  /// # Errors
  ///
  /// Returns an error when Slack rejects, rate-limits, or returns an invalid response.
  pub async fn post_message(
    &self,
    channel_id: &str,
    thread_ts: Option<&str>,
    text: &str,
  ) -> Result<SlackPostedMessage, SlackWebApiError> {
    self
      .post_message_with_token(channel_id, thread_ts, text, &self.bot_token)
      .await
  }

  /// Starts a Slack streamed message in a thread and returns its stream identifiers.
  ///
  /// # Errors
  ///
  /// Returns an error when Slack rejects, rate-limits, or returns an invalid response.
  pub async fn start_stream(
    &self,
    channel_id: &str,
    thread_ts: &str,
    markdown_text: &str,
  ) -> Result<SlackStreamMessage, SlackWebApiError> {
    let body = serde_json::to_string(&SlackStartStreamBody {
      channel: channel_id,
      thread_ts,
      markdown_text,
    })
    .map_err(|source| SlackWebApiError::InvalidResponse {
      message: self.redact(&source.to_string()),
    })?;
    let response = self
      .post_json("chat.startStream", body, &self.bot_token)
      .await?;
    let parsed = self.parse_api_response(&response)?;
    let message_ts = parsed
      .ts
      .clone()
      .or_else(|| {
        parsed
          .message
          .as_ref()
          .and_then(|message| message.ts.clone())
      })
      .ok_or_else(|| SlackWebApiError::InvalidResponse {
        message: "chat.startStream response is missing ts".to_owned(),
      })?;
    let channel_id = parsed
      .channel_string()
      .ok_or_else(|| SlackWebApiError::InvalidResponse {
        message: "chat.startStream response is missing channel".to_owned(),
      })?;
    let thread_ts = parsed
      .message
      .as_ref()
      .and_then(|message| message.thread_ts.clone())
      .or_else(|| Some(thread_ts.to_owned()));
    Ok(SlackStreamMessage {
      channel_id,
      thread_ts,
      message_ts,
      response_body: response.body,
    })
  }

  /// Appends markdown text to an existing Slack stream.
  ///
  /// # Errors
  ///
  /// Returns an error when Slack rejects, rate-limits, or returns an invalid response.
  pub async fn append_stream(
    &self,
    channel_id: &str,
    message_ts: &str,
    markdown_text: &str,
  ) -> Result<SlackStreamStatus, SlackWebApiError> {
    let body = serde_json::to_string(&SlackStreamMessageBody {
      channel: channel_id,
      ts: message_ts,
      markdown_text,
    })
    .map_err(|source| SlackWebApiError::InvalidResponse {
      message: self.redact(&source.to_string()),
    })?;
    let response = self
      .post_json("chat.appendStream", body, &self.bot_token)
      .await?;
    let parsed = self.parse_api_response(&response)?;
    Ok(SlackStreamStatus {
      channel_id: parsed
        .channel_string()
        .unwrap_or_else(|| channel_id.to_owned()),
      message_ts: parsed.ts.unwrap_or_else(|| message_ts.to_owned()),
      response_body: response.body,
    })
  }

  /// Stops a Slack stream and returns canonical identifiers when Slack provides them.
  ///
  /// # Errors
  ///
  /// Returns an error when Slack rejects, rate-limits, or returns an invalid response.
  pub async fn stop_stream(
    &self,
    channel_id: &str,
    message_ts: &str,
    markdown_text: &str,
  ) -> Result<SlackStreamMessage, SlackWebApiError> {
    let body = serde_json::to_string(&SlackStreamMessageBody {
      channel: channel_id,
      ts: message_ts,
      markdown_text,
    })
    .map_err(|source| SlackWebApiError::InvalidResponse {
      message: self.redact(&source.to_string()),
    })?;
    let response = self
      .post_json("chat.stopStream", body, &self.bot_token)
      .await?;
    let parsed = self.parse_api_response(&response)?;
    let message_ts = parsed
      .ts
      .clone()
      .or_else(|| {
        parsed
          .message
          .as_ref()
          .and_then(|message| message.ts.clone())
      })
      .unwrap_or_else(|| message_ts.to_owned());
    let thread_ts = parsed
      .message
      .as_ref()
      .and_then(|message| message.thread_ts.clone());
    Ok(SlackStreamMessage {
      channel_id: parsed
        .channel_string()
        .unwrap_or_else(|| channel_id.to_owned()),
      thread_ts,
      message_ts,
      response_body: response.body,
    })
  }

  /// Sets Slack assistant status for a thread.
  ///
  /// # Errors
  ///
  /// Returns an error when Slack rejects, rate-limits, or returns an invalid response.
  pub async fn set_assistant_status(
    &self,
    channel_id: &str,
    thread_ts: &str,
    status: &str,
    loading_messages: &[&str],
  ) -> Result<(), SlackWebApiError> {
    let body = serde_json::to_string(&SlackAssistantStatusBody {
      channel_id,
      thread_ts,
      status,
      loading_messages: (!loading_messages.is_empty()).then_some(loading_messages),
    })
    .map_err(|source| SlackWebApiError::InvalidResponse {
      message: self.redact(&source.to_string()),
    })?;
    let response = self
      .post_json("assistant.threads.setStatus", body, &self.bot_token)
      .await?;
    self.parse_api_response(&response)?;
    Ok(())
  }

  /// Clears Slack assistant status for a thread.
  ///
  /// # Errors
  ///
  /// Returns an error when Slack rejects, rate-limits, or returns an invalid response.
  pub async fn clear_assistant_status(
    &self,
    channel_id: &str,
    thread_ts: &str,
  ) -> Result<(), SlackWebApiError> {
    self
      .set_assistant_status(channel_id, thread_ts, "", &[])
      .await
  }

  /// Updates an existing Slack message.
  ///
  /// # Errors
  ///
  /// Returns an error when Slack rejects, rate-limits, or returns an invalid response.
  pub async fn update_message(
    &self,
    channel_id: &str,
    message_ts: &str,
    text: &str,
  ) -> Result<SlackPostedMessage, SlackWebApiError> {
    let body = serde_json::to_string(&SlackUpdateMessageBody {
      channel: channel_id,
      ts: message_ts,
      text,
    })
    .map_err(|source| SlackWebApiError::InvalidResponse {
      message: self.redact(&source.to_string()),
    })?;
    let response = self.post_json("chat.update", body, &self.bot_token).await?;
    let parsed = self.parse_api_response(&response)?;
    let message_ts = parsed
      .ts
      .clone()
      .or_else(|| {
        parsed
          .message
          .as_ref()
          .and_then(|message| message.ts.clone())
      })
      .unwrap_or_else(|| message_ts.to_owned());
    Ok(SlackPostedMessage {
      channel_id: parsed
        .channel_string()
        .unwrap_or_else(|| channel_id.to_owned()),
      thread_ts: parsed
        .message
        .as_ref()
        .and_then(|message| message.thread_ts.clone()),
      response_message_ts: parsed
        .message
        .as_ref()
        .and_then(|message| message.ts.clone()),
      response_team_id: parsed.team_id.clone(),
      message_ts,
      response_body: response.body,
    })
  }

  /// Posts a text message as a configured bot or user sender.
  ///
  /// # Errors
  ///
  /// Returns an error when the requested sender is not configured, its token environment variable
  /// is absent, or Slack rejects, rate-limits, or returns an invalid response.
  pub async fn post_message_as(
    &self,
    channel_id: &str,
    thread_ts: Option<&str>,
    text: &str,
    sender: &SlackDeliverySender,
  ) -> Result<SlackPostedMessage, SlackWebApiError> {
    let token = self.sender_token(sender)?;
    self
      .post_message_with_token(channel_id, thread_ts, text, &token)
      .await
  }

  fn sender_token(&self, sender: &SlackDeliverySender) -> Result<String, SlackWebApiError> {
    match sender {
      SlackDeliverySender::Bot => Ok(self.bot_token.clone()),
      SlackDeliverySender::User { key } => {
        let Some(config) = self.config.user_tokens.get(key) else {
          return Err(SlackWebApiError::Request {
            message: format!("slack sender user:{key} is not configured"),
          });
        };
        (self.user_token_resolver)(&config.token_env).map_err(|_| SlackWebApiError::Request {
          message: format!(
            "slack sender user:{key} token env {} is not set",
            config.token_env
          ),
        })
      }
    }
  }

  async fn post_message_with_token(
    &self,
    channel_id: &str,
    thread_ts: Option<&str>,
    text: &str,
    token: &str,
  ) -> Result<SlackPostedMessage, SlackWebApiError> {
    let body = serde_json::to_string(&SlackPostMessageBody {
      channel: channel_id,
      text,
      thread_ts,
    })
    .map_err(|source| SlackWebApiError::InvalidResponse {
      message: self.redact(&source.to_string()),
    })?;
    let response = self.post_json("chat.postMessage", body, token).await?;
    let parsed = self.parse_api_response(&response)?;
    let message_ts = parsed
      .ts
      .clone()
      .ok_or_else(|| SlackWebApiError::InvalidResponse {
        message: "chat.postMessage response is missing ts".to_owned(),
      })?;
    let channel_id = parsed
      .channel_string()
      .ok_or_else(|| SlackWebApiError::InvalidResponse {
        message: "chat.postMessage response is missing channel".to_owned(),
      })?;
    Ok(SlackPostedMessage {
      channel_id,
      thread_ts: parsed
        .message
        .as_ref()
        .and_then(|message| message.thread_ts.clone()),
      response_message_ts: parsed
        .message
        .as_ref()
        .and_then(|message| message.ts.clone()),
      response_team_id: parsed.team_id.clone(),
      message_ts,
      response_body: response.body,
    })
  }

  async fn post_json(
    &self,
    path: &str,
    body: String,
    token: &str,
  ) -> Result<SlackHttpResponse, SlackWebApiError> {
    let response = self
      .http
      .post(SlackHttpRequest {
        path: path.to_owned(),
        query: Vec::new(),
        json_body: Some(body),
        authorization: format!("Bearer {token}"),
      })
      .await
      .map_err(|message| SlackWebApiError::Request {
        message: self.redact(&message),
      })?;
    if response.status == 429 {
      return Err(SlackWebApiError::RateLimited {
        retry_after_seconds: response.retry_after_seconds(),
      });
    }
    if !(200..300).contains(&response.status) {
      return Err(SlackWebApiError::Api {
        classification: classify_http_status(response.status),
        scope: classify_http_status_scope(response.status),
      });
    }
    Ok(response)
  }
}

#[derive(Debug, Serialize)]
struct SlackPostMessageBody<'a> {
  channel: &'a str,
  text: &'a str,
  #[serde(skip_serializing_if = "Option::is_none")]
  thread_ts: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct SlackStartStreamBody<'a> {
  channel: &'a str,
  thread_ts: &'a str,
  markdown_text: &'a str,
}

#[derive(Debug, Serialize)]
struct SlackStreamMessageBody<'a> {
  channel: &'a str,
  ts: &'a str,
  markdown_text: &'a str,
}

#[derive(Debug, Serialize)]
struct SlackAssistantStatusBody<'a> {
  channel_id: &'a str,
  thread_ts: &'a str,
  status: &'a str,
  #[serde(skip_serializing_if = "Option::is_none")]
  loading_messages: Option<&'a [&'a str]>,
}

#[derive(Debug, Serialize)]
struct SlackUpdateMessageBody<'a> {
  channel: &'a str,
  ts: &'a str,
  text: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackPostedMessage {
  pub channel_id: String,
  pub thread_ts: Option<String>,
  pub response_message_ts: Option<String>,
  pub response_team_id: Option<String>,
  pub message_ts: String,
  pub response_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackStreamMessage {
  pub channel_id: String,
  pub thread_ts: Option<String>,
  pub message_ts: String,
  pub response_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackStreamStatus {
  pub channel_id: String,
  pub message_ts: String,
  pub response_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackUserAddress {
  pub connector_id: String,
  pub workspace_id: String,
  pub user_id: String,
  pub handle: Option<String>,
  pub display_name: Option<String>,
  pub real_name: Option<String>,
  pub email: Option<String>,
  pub team_id: Option<String>,
  pub enterprise_id: Option<String>,
  pub enterprise_team_ids: Vec<String>,
  pub deleted: bool,
  pub is_bot: bool,
  pub is_app_user: bool,
  pub is_restricted: bool,
  pub is_ultra_restricted: bool,
}

impl SlackUserAddress {
  fn matches_query(&self, needle: &str) -> bool {
    needle.is_empty()
      || self
        .search_values()
        .iter()
        .any(|value| normalized_lookup(value).contains(needle))
  }

  fn exactly_matches_query(&self, needle: &str) -> bool {
    self
      .search_values()
      .iter()
      .any(|value| normalized_lookup(value) == needle)
  }

  fn search_values(&self) -> Vec<&str> {
    [
      Some(self.user_id.as_str()),
      self.handle.as_deref(),
      self.display_name.as_deref(),
      self.real_name.as_deref(),
      self.email.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect()
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackChannelAddress {
  pub connector_id: String,
  pub workspace_id: String,
  pub channel_id: String,
  pub name: Option<String>,
  pub is_private: bool,
  pub is_im: bool,
  pub is_mpim: bool,
  pub is_archived: bool,
  pub is_member: bool,
  pub context_team_id: Option<String>,
  pub enterprise_id: Option<String>,
  pub conversation_host_id: Option<String>,
  pub shared_team_ids: Vec<String>,
  pub connected_team_ids: Vec<String>,
  pub is_shared: bool,
  pub is_ext_shared: bool,
  pub is_org_shared: bool,
}

impl SlackChannelAddress {
  fn matches_query(&self, needle: &str) -> bool {
    needle.is_empty()
      || self
        .search_values()
        .iter()
        .any(|value| normalized_lookup(value).contains(needle))
  }

  fn exactly_matches_query(&self, needle: &str) -> bool {
    self
      .search_values()
      .iter()
      .any(|value| normalized_lookup(value) == needle)
  }

  fn search_values(&self) -> Vec<&str> {
    [Some(self.channel_id.as_str()), self.name.as_deref()]
      .into_iter()
      .flatten()
      .collect()
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackConfiguredSender {
  pub kind: String,
  pub key: Option<String>,
  pub user_id: Option<String>,
  pub token_env: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackConnectorStatus {
  pub connector_id: String,
  pub workspace_id: String,
  pub capabilities: ChannelConnectorCapabilities,
  pub senders: Vec<SlackConfiguredSender>,
}

#[allow(clippy::match_same_arms)]
fn classify_slack_api_error(error: Option<&str>) -> (SlackApiErrorClass, SlackApiErrorScope) {
  let code = error
    .and_then(|error| error.split_ascii_whitespace().next())
    .unwrap_or("unknown_error");
  match code {
    "invalid_arg_name"
    | "invalid_arguments"
    | "invalid_array_arg"
    | "invalid_charset"
    | "invalid_cursor"
    | "invalid_form_data"
    | "invalid_post_type"
    | "invalid_ts_latest"
    | "invalid_ts_oldest"
    | "method_not_supported_for_channel_type"
    | "missing_post_type"
    | "not_enough_users"
    | "too_many_users"
    | "users_list_not_supplied"
    | "user_not_found"
    | "channel_not_found"
    | "thread_not_found" => (SlackApiErrorClass::Invalid, SlackApiErrorScope::Target),
    "no_permission" | "not_in_channel" | "user_not_visible" => {
      (SlackApiErrorClass::Unauthorized, SlackApiErrorScope::Target)
    }
    "access_denied"
    | "account_inactive"
    | "enterprise_is_restricted"
    | "invalid_auth"
    | "missing_scope"
    | "not_allowed_token_type"
    | "not_authed"
    | "restricted_action"
    | "team_access_not_granted"
    | "token_expired"
    | "token_revoked"
    | "two_factor_setup_required"
    | "user_disabled" => (
      SlackApiErrorClass::Unauthorized,
      SlackApiErrorScope::GlobalProvider,
    ),
    "fatal_error"
    | "internal_error"
    | "ratelimited"
    | "request_timeout"
    | "service_unavailable"
    | "team_added_to_org" => (SlackApiErrorClass::Transient, SlackApiErrorScope::Unknown),
    "is_archived" => (
      SlackApiErrorClass::TargetUnavailable,
      SlackApiErrorScope::Target,
    ),
    "accesslimited"
    | "deprecated_endpoint"
    | "ekm_access_denied"
    | "method_deprecated"
    | "org_login_required" => (
      SlackApiErrorClass::TargetUnavailable,
      SlackApiErrorScope::GlobalProvider,
    ),
    "unknown_error" => (
      SlackApiErrorClass::TargetUnavailable,
      SlackApiErrorScope::Unknown,
    ),
    _ => (
      SlackApiErrorClass::TargetUnavailable,
      SlackApiErrorScope::Unknown,
    ),
  }
}

const fn classify_http_status(status: u16) -> SlackApiErrorClass {
  match status {
    401 | 403 => SlackApiErrorClass::Unauthorized,
    400 | 404 | 405 | 409 | 422 => SlackApiErrorClass::Invalid,
    408 | 425 | 500..=599 => SlackApiErrorClass::Transient,
    _ => SlackApiErrorClass::TargetUnavailable,
  }
}

const fn classify_http_status_scope(status: u16) -> SlackApiErrorScope {
  match status {
    401 | 403 => SlackApiErrorScope::GlobalProvider,
    400 | 404 | 405 | 409 | 422 => SlackApiErrorScope::Target,
    _ => SlackApiErrorScope::Unknown,
  }
}

fn required_identifier(value: Option<&str>, field: &str) -> Result<String, SlackWebApiError> {
  non_empty_string(value)
    .map(ToOwned::to_owned)
    .ok_or_else(|| SlackWebApiError::InvalidResponse {
      message: format!("{field} is missing"),
    })
}

fn optional_identifier(
  value: Option<&str>,
  prefix: char,
) -> Result<Option<String>, SlackWebApiError> {
  let Some(value) = non_empty_string(value) else {
    return Ok(None);
  };
  if !value.starts_with(prefix) {
    return Err(SlackWebApiError::InvalidResponse {
      message: "Slack response contains an invalid provider identifier".to_owned(),
    });
  }
  Ok(Some(value.to_owned()))
}

fn looks_like_slack_dm_id(value: &str) -> bool {
  value.starts_with('D')
    && value.len() > 1
    && value
      .bytes()
      .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

#[derive(Debug, Deserialize)]
struct SlackApiResponse {
  ok: bool,
  #[serde(default)]
  error: Option<String>,
  #[serde(default)]
  channels: Vec<SlackChannel>,
  #[serde(default)]
  members: Vec<SlackUser>,
  #[serde(default)]
  user: Option<SlackUser>,
  #[serde(default)]
  messages: Vec<SlackMessage>,
  #[serde(default)]
  response_metadata: ResponseMetadata,
  #[serde(default)]
  channel: Option<Value>,
  #[serde(default)]
  ts: Option<String>,
  #[serde(default)]
  message: Option<SlackPostedResponseMessage>,
  #[serde(default)]
  file: Option<Value>,
  #[serde(default)]
  team_id: Option<String>,
  #[serde(default)]
  enterprise_id: Option<String>,
  #[serde(default)]
  user_id: Option<String>,
  #[serde(default)]
  bot_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SlackConversationMembersResponse {
  ok: bool,
  #[serde(default)]
  error: Option<String>,
  #[serde(default)]
  members: Vec<String>,
  #[serde(default)]
  response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
struct SlackChannel {
  id: String,
  #[serde(default)]
  name: Option<String>,
  #[serde(default)]
  is_private: bool,
  #[serde(default)]
  is_im: bool,
  #[serde(default)]
  is_mpim: bool,
  #[serde(default)]
  is_archived: bool,
  #[serde(default)]
  is_member: bool,
  #[serde(default)]
  context_team_id: Option<String>,
  #[serde(default)]
  enterprise_id: Option<String>,
  #[serde(default)]
  conversation_host_id: Option<String>,
  #[serde(default)]
  shared_team_ids: Vec<String>,
  #[serde(default)]
  connected_team_ids: Vec<String>,
  #[serde(default)]
  is_shared: bool,
  #[serde(default)]
  is_ext_shared: bool,
  #[serde(default)]
  is_org_shared: bool,
}

impl SlackApiResponse {
  fn channel_string(&self) -> Option<String> {
    self
      .channel
      .as_ref()
      .and_then(Value::as_str)
      .map(ToOwned::to_owned)
  }

  fn channel_object(&self) -> Option<SlackChannel> {
    serde_json::from_value(self.channel.as_ref()?.clone()).ok()
  }
}

#[derive(Debug, Deserialize)]
struct SlackUser {
  id: String,
  #[serde(default)]
  name: Option<String>,
  #[serde(default)]
  real_name: Option<String>,
  #[serde(default)]
  deleted: bool,
  #[serde(default)]
  team_id: Option<String>,
  #[serde(default)]
  is_bot: bool,
  #[serde(default)]
  is_app_user: bool,
  #[serde(default)]
  is_restricted: bool,
  #[serde(default)]
  is_ultra_restricted: bool,
  #[serde(default)]
  enterprise_user: Option<SlackEnterpriseUser>,
  #[serde(default)]
  profile: SlackUserProfile,
}

#[derive(Debug, Deserialize)]
struct SlackEnterpriseUser {
  #[serde(default)]
  enterprise_id: Option<String>,
  #[serde(default)]
  teams: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SlackUserProfile {
  #[serde(default)]
  display_name: Option<String>,
  #[serde(default)]
  real_name: Option<String>,
  #[serde(default)]
  email: Option<String>,
}

const fn slack_capabilities() -> ChannelConnectorCapabilities {
  ChannelConnectorCapabilities {
    receive_events: true,
    slash_commands: true,
    interactive_actions: true,
    modal_inputs: true,
    send_messages: true,
    thread_replies: true,
    direct_messages: true,
    ephemeral_messages: true,
    message_updates: true,
    history_fetch: true,
    user_profile_fetch: true,
    socket_transport: true,
    http_transport: true,
    proactive_delivery: true,
  }
}

fn normalized_lookup(value: &str) -> String {
  value.trim().to_ascii_lowercase()
}

fn single_match<T>(mut values: Vec<T>) -> Option<T> {
  if values.len() == 1 {
    values.pop()
  } else {
    None
  }
}

fn looks_like_slack_user_id(value: &str) -> bool {
  let mut characters = value.chars();
  matches!(characters.next(), Some('U' | 'W')) && characters.all(is_slack_id_character)
}

fn looks_like_slack_channel_id(value: &str) -> bool {
  let mut characters = value.chars();
  matches!(characters.next(), Some('C' | 'G' | 'D')) && characters.all(is_slack_id_character)
}

fn is_slack_id_character(character: char) -> bool {
  character.is_ascii_uppercase() || character.is_ascii_digit()
}

#[derive(Debug, Deserialize)]
struct SlackMessage {
  ts: Option<String>,
  #[serde(default)]
  thread_ts: Option<String>,
  #[serde(default)]
  text: Option<String>,
  #[serde(default)]
  blocks: Vec<Value>,
  #[serde(default)]
  attachments: Vec<Value>,
  #[serde(default)]
  files: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct SlackPostedResponseMessage {
  #[serde(default)]
  ts: Option<String>,
  #[serde(default)]
  thread_ts: Option<String>,
}

impl SlackMessage {
  fn timestamp(&self) -> Option<u64> {
    self.ts.as_deref()?.split_once('.').map_or_else(
      || self.ts.as_deref()?.parse().ok(),
      |(seconds, _)| seconds.parse().ok(),
    )
  }

  fn summary_text(&self) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(text) = non_empty_string(self.text.as_deref()) {
      parts.push(text.to_owned());
    }
    for block in &self.blocks {
      push_labeled_part(&mut parts, "block", slack_block_text(block));
    }
    for attachment in &self.attachments {
      push_labeled_part(&mut parts, "attachment", slack_attachment_text(attachment));
    }
    for file in &self.files {
      push_labeled_part(&mut parts, "file", slack_file_text(file));
    }
    join_non_empty(parts)
  }
}

fn non_empty_string(value: Option<&str>) -> Option<&str> {
  value.map(str::trim).filter(|value| !value.is_empty())
}

fn push_labeled_part(parts: &mut Vec<String>, label: &str, value: Option<String>) {
  let Some(value) = value else {
    return;
  };
  let value = value.trim();
  if value.is_empty() {
    return;
  }
  parts.push(format!("{label}: {value}"));
}

fn join_non_empty(parts: Vec<String>) -> Option<String> {
  let text = parts
    .into_iter()
    .map(|part| part.trim().to_owned())
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>()
    .join("\n");
  if text.is_empty() { None } else { Some(text) }
}

fn slack_block_text(block: &Value) -> Option<String> {
  let mut parts = Vec::new();
  collect_slack_text(block, &mut parts);
  let text = parts.into_iter().collect::<String>().trim().to_owned();
  if text.is_empty() { None } else { Some(text) }
}

fn slack_attachment_text(attachment: &Value) -> Option<String> {
  let mut parts = Vec::new();
  for key in [
    "title",
    "text",
    "fallback",
    "pretext",
    "author_name",
    "image_url",
  ] {
    if let Some(value) = value_string(attachment, key) {
      parts.push(value.to_owned());
    }
  }
  if let Some(fields) = attachment.get("fields").and_then(Value::as_array) {
    for field in fields {
      match (value_string(field, "title"), value_string(field, "value")) {
        (Some(title), Some(value)) => parts.push(format!("{title}: {value}")),
        (Some(title), None) => parts.push(title.to_owned()),
        (None, Some(value)) => parts.push(value.to_owned()),
        (None, None) => {}
      }
    }
  }
  join_non_empty(parts)
}

fn slack_file_text(file: &Value) -> Option<String> {
  let mut parts = Vec::new();
  let name = value_string(file, "name")
    .or_else(|| value_string(file, "title"))
    .or_else(|| value_string(file, "id"))?;
  parts.push(name.to_owned());
  for key in ["mimetype", "filetype", "id"] {
    if let Some(value) = value_string(file, key) {
      parts.push(format!("{key}={value}"));
    }
  }
  if let Some(size) = file.get("size").and_then(Value::as_u64) {
    parts.push(format!("size={size}"));
  }
  join_non_empty(parts)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SlackFileInfo {
  info: ChannelResourceInfo,
  filetype: Option<String>,
  url_private: Option<String>,
  url_private_download: Option<String>,
}

impl SlackFileInfo {
  fn from_value(
    file: Value,
    connector_id: &str,
    workspace_id: &str,
    fallback_resource_id: &str,
  ) -> Self {
    let resource_id = value_string(&file, "id")
      .unwrap_or(fallback_resource_id)
      .to_owned();
    let name = value_string(&file, "name")
      .or_else(|| value_string(&file, "title"))
      .map(ToOwned::to_owned);
    let media_type = value_string(&file, "mimetype").map(ToOwned::to_owned);
    let filetype = value_string(&file, "filetype").map(ToOwned::to_owned);
    let size_bytes = file.get("size").and_then(Value::as_u64);
    Self {
      info: ChannelResourceInfo {
        connector_id: connector_id.to_owned(),
        workspace_id: workspace_id.to_owned(),
        resource_id,
        name,
        media_type,
        size_bytes,
      },
      filetype,
      url_private: value_string(&file, "url_private").map(ToOwned::to_owned),
      url_private_download: value_string(&file, "url_private_download").map(ToOwned::to_owned),
    }
  }

  fn is_text_like(&self) -> bool {
    let media_type = self.info.media_type.as_deref().unwrap_or_default();
    let filetype = self.filetype.as_deref().unwrap_or_default();
    media_type.starts_with("text/")
      || matches!(
        media_type,
        "application/json"
          | "application/xml"
          | "application/javascript"
          | "application/x-javascript"
          | "application/x-ndjson"
          | "text/csv"
      )
      || matches!(
        filetype,
        "csv" | "json" | "javascript" | "markdown" | "md" | "text" | "xml"
      )
  }

  fn private_download_url(&self) -> Option<&str> {
    self
      .url_private_download
      .as_deref()
      .or(self.url_private.as_deref())
  }
}

fn slack_file_info(
  file: &Value,
  connector_id: &str,
  workspace_id: &str,
) -> Option<ChannelResourceInfo> {
  let resource_id = value_string(file, "id")?;
  Some(SlackFileInfo::from_value(file.clone(), connector_id, workspace_id, resource_id).info)
}

fn sanitize_artifact_filename(filename: &str, fallback: &str) -> String {
  let name = filename
    .rsplit(['/', '\\'])
    .next()
    .unwrap_or(filename)
    .trim();
  let sanitized = sanitize_path_segment(name);
  if sanitized.is_empty() {
    let fallback = sanitize_path_segment(fallback);
    if fallback.is_empty() {
      "resource".to_owned()
    } else {
      fallback
    }
  } else {
    sanitized
  }
}

fn validate_slack_file_download_url(url: &str) -> Result<(), String> {
  let parsed = reqwest::Url::parse(url).map_err(redacted_error)?;
  if parsed.scheme() != "https" {
    return Err("unsafe slack file download url".to_owned());
  }
  let Some(host) = parsed.host_str() else {
    return Err("unsafe slack file download url".to_owned());
  };
  if host == "files.slack.com" || host.ends_with(".files.slack.com") {
    Ok(())
  } else {
    Err("unsafe slack file download url".to_owned())
  }
}

fn sanitize_path_segment(value: &str) -> String {
  let mut sanitized = String::new();
  let mut last_was_separator = false;
  for character in value.chars() {
    let replacement = if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
      character
    } else {
      '_'
    };
    if replacement == '_' {
      if !last_was_separator {
        sanitized.push(replacement);
      }
      last_was_separator = true;
    } else {
      sanitized.push(replacement);
      last_was_separator = false;
    }
  }
  sanitized
    .trim_matches(|character| matches!(character, '.' | '-' | '_' | ' '))
    .to_owned()
}

fn channel_resource_provider_error(error: SlackWebApiError) -> ChannelResourceProviderError {
  match error {
    SlackWebApiError::Request { message } => ChannelResourceProviderError::Request { message },
    SlackWebApiError::RateLimited {
      retry_after_seconds,
    } => ChannelResourceProviderError::RateLimited {
      retry_after_seconds,
    },
    SlackWebApiError::Unavailable => ChannelResourceProviderError::Unavailable,
    SlackWebApiError::InvalidResponse { message } => {
      ChannelResourceProviderError::InvalidResponse { message }
    }
    SlackWebApiError::Provider { message } => ChannelResourceProviderError::Provider { message },
    SlackWebApiError::Api { classification, .. } => ChannelResourceProviderError::Provider {
      message: classification.to_string(),
    },
    SlackWebApiError::UnsupportedTarget => ChannelResourceProviderError::UnsupportedResource,
    SlackWebApiError::Deferred { available_at } => {
      ChannelResourceProviderError::Deferred { available_at }
    }
  }
}

fn channel_context_provider_error(error: SlackWebApiError) -> ChannelContextProviderError {
  match error {
    SlackWebApiError::Request { message } => ChannelContextProviderError::Request { message },
    SlackWebApiError::RateLimited {
      retry_after_seconds,
    } => ChannelContextProviderError::RateLimited {
      retry_after_seconds,
    },
    SlackWebApiError::Unavailable => ChannelContextProviderError::Unavailable,
    SlackWebApiError::InvalidResponse { message } => {
      ChannelContextProviderError::InvalidResponse { message }
    }
    SlackWebApiError::Provider { message } => ChannelContextProviderError::Provider { message },
    SlackWebApiError::Api { classification, .. } => ChannelContextProviderError::Provider {
      message: classification.to_string(),
    },
    SlackWebApiError::UnsupportedTarget => ChannelContextProviderError::UnsupportedTarget,
    SlackWebApiError::Deferred { available_at } => {
      ChannelContextProviderError::Deferred { available_at }
    }
  }
}

fn channel_tool_error(error: SlackWebApiError) -> ChannelToolError {
  ChannelToolError::ContextProvider(channel_context_provider_error(error))
}

fn user_summary(user: SlackUserAddress) -> ChannelUserSummary {
  ChannelUserSummary {
    connector_id: user.connector_id,
    workspace_id: user.workspace_id,
    user_id: user.user_id,
    display_name: user.display_name.or(user.real_name),
    handle: user.handle,
    email: user.email,
  }
}

fn channel_summary(channel: SlackChannelAddress) -> ChannelSummary {
  ChannelSummary {
    connector_id: channel.connector_id,
    workspace_id: channel.workspace_id,
    channel_id: channel.channel_id,
    name: channel.name,
    is_direct_message: channel.is_im,
  }
}

fn sender_summary(
  connector_id: &str,
  workspace_id: &str,
  sender: SlackConfiguredSender,
) -> ChannelSenderSummary {
  let sender_id = match sender.kind.as_str() {
    "user" => sender
      .key
      .as_ref()
      .map(|key| format!("user:{key}"))
      .unwrap_or_else(|| "user".to_owned()),
    _ => "bot".to_owned(),
  };
  let display_name = match sender.kind.as_str() {
    "user" => sender.key.map(|key| format!("user:{key}")),
    _ => Some("bot".to_owned()),
  };
  ChannelSenderSummary {
    connector_id: connector_id.to_owned(),
    workspace_id: workspace_id.to_owned(),
    sender_id,
    display_name,
  }
}

fn thread_reply_sender(send_as: Option<String>) -> Result<SlackDeliverySender, ChannelToolError> {
  match send_as.as_deref() {
    None | Some("bot") => Ok(SlackDeliverySender::Bot),
    Some(value) if value.starts_with("user:") && value.len() > "user:".len() => {
      Ok(SlackDeliverySender::User {
        key: value["user:".len()..].to_owned(),
      })
    }
    Some(value) => Err(ChannelToolError::InvalidSender {
      value: value.to_owned(),
    }),
  }
}

#[async_trait]
impl<H: SlackHttpClient + Send + Sync> ChannelContextProvider for SlackWebApiClient<H> {
  async fn fetch_context(
    &self,
    request: ChannelContextRequest,
  ) -> Result<ChannelContextPage, ChannelContextProviderError> {
    self
      .fetch_context(&request)
      .await
      .map_err(channel_context_provider_error)
  }
}

#[async_trait]
impl<H: SlackHttpClient + Send + Sync> ChannelUserProvider for SlackWebApiClient<H> {
  async fn search_users(
    &self,
    request: ChannelUserSearchRequest,
  ) -> Result<Vec<ChannelUserSummary>, ChannelToolError> {
    let mut users = self
      .search_users(&request.query)
      .await
      .map_err(channel_tool_error)?
      .into_iter()
      .map(user_summary)
      .collect::<Vec<_>>();
    users.truncate(usize::from(request.limit));
    Ok(users)
  }

  async fn get_user(
    &self,
    request: ChannelLookupRequest,
  ) -> Result<Option<ChannelUserSummary>, ChannelToolError> {
    match self.get_user(&request.id).await {
      Ok(user) => Ok(Some(user_summary(user))),
      Err(SlackWebApiError::Unavailable) => Ok(None),
      Err(error) => Err(channel_tool_error(error)),
    }
  }

  async fn resolve_user(
    &self,
    request: ChannelUserResolveRequest,
  ) -> Result<ChannelUserResolveResult, ChannelToolError> {
    let query = request.query.trim().trim_start_matches('@');
    if looks_like_slack_user_id(query) {
      return match self.get_user(query).await {
        Ok(user) => Ok(ChannelUserResolveResult::resolved(user_summary(user))),
        Err(SlackWebApiError::Unavailable) => Ok(ChannelUserResolveResult::ambiguous(Vec::new())),
        Err(error) => Err(channel_tool_error(error)),
      };
    }
    let needle = normalized_lookup(query);
    let users = self
      .search_users(query)
      .await
      .map_err(channel_tool_error)?
      .into_iter()
      .filter(|user| user.exactly_matches_query(&needle))
      .map(user_summary)
      .collect::<Vec<_>>();
    if users.len() == 1 {
      Ok(ChannelUserResolveResult::resolved(users[0].clone()))
    } else {
      Ok(ChannelUserResolveResult::ambiguous(users))
    }
  }
}

#[async_trait]
impl<H: SlackHttpClient + Send + Sync> ChannelChannelProvider for SlackWebApiClient<H> {
  async fn search_channels(
    &self,
    request: ChannelSearchRequest,
  ) -> Result<Vec<ChannelSummary>, ChannelToolError> {
    let mut channels = self
      .search_channels(&request.query)
      .await
      .map_err(channel_tool_error)?
      .into_iter()
      .map(channel_summary)
      .collect::<Vec<_>>();
    channels.truncate(usize::from(request.limit));
    Ok(channels)
  }

  async fn get_channel(
    &self,
    request: ChannelLookupRequest,
  ) -> Result<Option<ChannelSummary>, ChannelToolError> {
    match self.get_channel(&request.id).await {
      Ok(channel) => Ok(Some(channel_summary(channel))),
      Err(SlackWebApiError::Unavailable) => Ok(None),
      Err(error) => Err(channel_tool_error(error)),
    }
  }

  async fn resolve_channel(
    &self,
    request: ChannelSearchRequest,
  ) -> Result<Vec<ChannelSummary>, ChannelToolError> {
    let query = request.query.trim().trim_start_matches('#');
    if looks_like_slack_channel_id(query) {
      return match self.get_channel(query).await {
        Ok(channel) => Ok(vec![channel_summary(channel)]),
        Err(SlackWebApiError::Unavailable) => Ok(Vec::new()),
        Err(error) => Err(channel_tool_error(error)),
      };
    }
    let needle = normalized_lookup(query);
    let mut channels = self
      .search_channels(query)
      .await
      .map_err(channel_tool_error)?
      .into_iter()
      .filter(|channel| channel.exactly_matches_query(&needle))
      .map(channel_summary)
      .collect::<Vec<_>>();
    channels.truncate(usize::from(request.limit));
    Ok(channels)
  }
}

#[async_trait]
impl<H: SlackHttpClient + Send + Sync> ChannelSenderProvider for SlackWebApiClient<H> {
  async fn list_senders(
    &self,
    request: ChannelWorkspaceRequest,
  ) -> Result<Vec<ChannelSenderSummary>, ChannelToolError> {
    Ok(
      self
        .configured_senders()
        .into_iter()
        .map(|sender| sender_summary(&request.connector_id, &request.workspace_id, sender))
        .collect(),
    )
  }
}

#[async_trait]
impl<H: SlackHttpClient + Send + Sync> ChannelStatusProvider for SlackWebApiClient<H> {
  async fn list_workspaces(&self) -> Result<Vec<ChannelWorkspaceSummary>, ChannelToolError> {
    Ok(vec![self.workspace_summary()])
  }

  async fn get_connector_status(
    &self,
    request: ChannelWorkspaceRequest,
  ) -> Result<ChannelConnectorStatus, ChannelToolError> {
    let status = self.connector_status();
    Ok(ChannelConnectorStatus {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      connected: true,
      status: "ok".to_owned(),
      detail: Some(format!(
        "can_send={}, can_read_context={}, senders={}",
        status.capabilities.send_messages,
        status.capabilities.history_fetch,
        status.senders.len()
      )),
    })
  }
}

#[async_trait]
impl<H: SlackHttpClient + Send + Sync> ChannelThreadReplyProvider for SlackWebApiClient<H> {
  async fn reply_to_thread(
    &self,
    request: ChannelThreadReplyRequest,
  ) -> Result<ChannelThreadReplyReceipt, ChannelToolError> {
    let sender = thread_reply_sender(request.send_as.clone())?;
    let posted = self
      .post_message_as(
        &request.channel_id,
        Some(&request.thread_id),
        &request.text,
        &sender,
      )
      .await
      .map_err(channel_tool_error)?;
    Ok(ChannelThreadReplyReceipt {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      channel_id: posted.channel_id,
      thread_id: posted.thread_ts.unwrap_or(request.thread_id),
      request_dedupe_key: request.request_dedupe_key,
      message_id: posted.message_ts,
      send_as: request.send_as,
    })
  }
}

#[async_trait]
impl<H: SlackHttpClient + Send + Sync> ChannelResourceProvider for SlackWebApiClient<H> {
  async fn fetch_message(
    &self,
    request: ChannelMessageFetchRequest,
  ) -> Result<ChannelMessageSnapshot, ChannelResourceProviderError> {
    self
      .fetch_message_snapshot(&request)
      .await
      .map_err(channel_resource_provider_error)
  }

  async fn fetch_resource_info(
    &self,
    request: ChannelResourceInfoRequest,
  ) -> Result<ChannelResourceInfo, ChannelResourceProviderError> {
    self
      .fetch_file_info(
        &request.connector_id,
        &request.workspace_id,
        &request.resource_id,
      )
      .await
      .map(|file| file.info)
      .map_err(channel_resource_provider_error)
  }

  async fn read_resource_text(
    &self,
    request: ChannelResourceTextRequest,
  ) -> Result<ChannelResourceText, ChannelResourceProviderError> {
    self.read_file_text(&request).await
  }

  async fn download_resource(
    &self,
    request: ChannelResourceDownloadRequest,
  ) -> Result<ChannelResourceDownload, ChannelResourceProviderError> {
    self.download_file_resource(&request).await
  }
}

fn collect_slack_text(value: &Value, parts: &mut Vec<String>) {
  match value {
    Value::Object(object) => {
      match object.get("type").and_then(Value::as_str) {
        Some("link") => {
          let url = object.get("url").and_then(Value::as_str);
          let text = object.get("text").and_then(Value::as_str);
          match (text, url) {
            (Some(text), Some(url)) => parts.push(format!("{text} <{url}>")),
            (None, Some(url)) => parts.push(url.to_owned()),
            (Some(text), None) => parts.push(text.to_owned()),
            (None, None) => {}
          }
        }
        Some("user") => {
          if let Some(user_id) = object.get("user_id").and_then(Value::as_str) {
            parts.push(format!("<@{user_id}>"));
          }
        }
        Some("channel") => {
          if let Some(channel_id) = object.get("channel_id").and_then(Value::as_str) {
            parts.push(format!("<#{channel_id}>"));
          }
        }
        _ => {
          if let Some(text) = object.get("text").and_then(Value::as_str) {
            parts.push(text.to_owned());
          }
        }
      }
      for key in ["elements", "blocks", "fields"] {
        if let Some(values) = object.get(key).and_then(Value::as_array) {
          for value in values {
            collect_slack_text(value, parts);
          }
        }
      }
    }
    Value::Array(values) => {
      for value in values {
        collect_slack_text(value, parts);
      }
    }
    _ => {}
  }
}

fn value_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
  value
    .get(key)
    .and_then(Value::as_str)
    .map(str::trim)
    .filter(|value| !value.is_empty())
}

#[derive(Debug, Default, Deserialize)]
struct ResponseMetadata {
  #[serde(default)]
  next_cursor: Option<String>,
}

#[cfg(test)]
mod tests {
  use super::{redact_secrets, validate_slack_api_path};

  #[test]
  fn unsafe_slack_api_paths_are_rejected() {
    for path in [
      "https://example.com/api/chat.postMessage",
      "//example.com/api/chat.postMessage",
      "http:example.com/api/chat.postMessage",
      "%2e%2e/chat.postMessage",
      "%2E%2E/chat.postMessage",
      ".%2e/chat.postMessage",
      "%2e./chat.postMessage",
      "/chat.postMessage",
      "../chat.postMessage",
    ] {
      assert_eq!(
        validate_slack_api_path(path),
        Err("unsafe slack web api path".to_owned())
      );
    }
  }

  #[test]
  fn redaction_removes_authorization_values_and_slack_tokens() {
    let message = "failed Authorization: Bearer plain-secret and response token xoxb-secret-token";

    let redacted = redact_secrets(message, Some("Bearer explicit-secret"));

    assert!(redacted.contains("Bearer <redacted>"));
    assert!(redacted.contains("token <redacted>"));
    assert!(!redacted.contains("plain-secret"));
    assert!(!redacted.contains("xoxb-secret-token"));
    assert!(!redacted.contains("explicit-secret"));
  }
}
