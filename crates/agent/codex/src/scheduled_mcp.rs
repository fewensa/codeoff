//! Root-supervisor-owned GitHub MCP client for scheduled Codex dynamic tools.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MAX_HTTP_MESSAGE_BYTES: usize = 256 * 1024;
const MAX_TOOL_ARGUMENT_BYTES: usize = 32 * 1024;
const MAX_TOOL_RESULT_BYTES: usize = 64 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct ScheduledGithubMcpClient {
  endpoint: HttpEndpoint,
  bearer: String,
  state: Mutex<McpState>,
}

#[derive(Default)]
struct McpState {
  next_id: u64,
  session_id: Option<String>,
  tool_specs: Vec<Value>,
}

pub(crate) struct ScheduledMcpAttestation {
  pub tool_specs: Vec<Value>,
  pub tool_schema_sha256: String,
  pub health: Value,
}

#[derive(Clone)]
struct HttpEndpoint {
  address: SocketAddr,
  host: String,
  path: String,
}

struct HttpResponse {
  status: u16,
  session_id: Option<String>,
  content_type: String,
  body: Vec<u8>,
}

impl ScheduledGithubMcpClient {
  pub(crate) fn new(endpoint: &str, bearer: String) -> Result<Self, String> {
    if !is_safe_header_value(&bearer) {
      return Err(safe("bearer_invalid"));
    }
    Ok(Self {
      endpoint: HttpEndpoint::parse(endpoint)?,
      bearer,
      state: Mutex::new(McpState::default()),
    })
  }

  pub(crate) fn attest(
    &self,
    expected_server_name: &str,
    expected_server_version: &str,
    expected_tools: &BTreeSet<String>,
  ) -> Result<ScheduledMcpAttestation, String> {
    let mut state = self.state.lock().map_err(|_| safe("state_unavailable"))?;
    state.next_id = 1;
    state.session_id = None;
    state.tool_specs.clear();
    let initialized = self.rpc(
      &mut state,
      "initialize",
      &json!({
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "codeoff-scheduler", "version": env!("CARGO_PKG_VERSION")},
      }),
    )?;
    if initialized["serverInfo"]["name"].as_str() != Some(expected_server_name)
      || initialized["serverInfo"]["version"].as_str() != Some(expected_server_version)
    {
      return Err(safe("server_identity_mismatch"));
    }
    self.notification(&state, "notifications/initialized", &json!({}))?;
    let listed = self.rpc(&mut state, "tools/list", &json!({}))?;
    if !listed["nextCursor"].is_null() {
      return Err(safe("tool_inventory_paginated"));
    }
    let tools = listed["tools"]
      .as_array()
      .ok_or_else(|| safe("tool_inventory_invalid"))?;
    let actual: BTreeSet<_> = tools
      .iter()
      .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
      .collect();
    if actual != *expected_tools || tools.len() != expected_tools.len() {
      return Err(safe("tool_inventory_mismatch"));
    }
    let mut specs = Vec::with_capacity(tools.len());
    for tool in tools {
      let name = tool["name"]
        .as_str()
        .ok_or_else(|| safe("tool_inventory_invalid"))?;
      if tool["annotations"]["readOnlyHint"].as_bool() != Some(true)
        || !tool["inputSchema"].is_object()
        || tool["description"]
          .as_str()
          .is_none_or(|description| description.len() > 4 * 1024)
        || json_depth(&tool["inputSchema"]) > 16
      {
        return Err(safe("tool_not_read_only"));
      }
      let schema =
        serde_json::to_vec(&tool["inputSchema"]).map_err(|_| safe("tool_schema_invalid"))?;
      if schema.len() > 16 * 1024 {
        return Err(safe("tool_not_read_only"));
      }
      specs.push(json!({
        "name": name,
        "description": tool["description"].as_str().unwrap_or("GitHub read-only tool"),
        "inputSchema": tool["inputSchema"].clone(),
      }));
    }
    specs.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    let canonical_specs = serde_json::to_vec(&specs).map_err(|_| safe("tool_schema_invalid"))?;
    if canonical_specs.len() > MAX_HTTP_MESSAGE_BYTES {
      return Err(safe("tool_schema_too_large"));
    }
    let resources = self.rpc(&mut state, "resources/list", &json!({}))?;
    if !resources["resources"].as_array().is_some_and(Vec::is_empty)
      || !resources["nextCursor"].is_null()
    {
      return Err(safe("resources_not_empty"));
    }
    let templates = self.rpc(&mut state, "resources/templates/list", &json!({}))?;
    if !templates["resourceTemplates"]
      .as_array()
      .is_some_and(Vec::is_empty)
      || !templates["nextCursor"].is_null()
    {
      return Err(safe("resource_templates_not_empty"));
    }
    let health = self.rpc(
      &mut state,
      "tools/call",
      &json!({"name": "get_me", "arguments": {}}),
    )?;
    state.tool_specs.clone_from(&specs);
    Ok(ScheduledMcpAttestation {
      tool_specs: specs,
      tool_schema_sha256: format!("{:x}", Sha256::digest(&canonical_specs)),
      health,
    })
  }

  pub(crate) fn call(&self, tool: &str, arguments: &Value) -> Result<Value, String> {
    let encoded = serde_json::to_vec(&arguments).map_err(|_| safe("arguments_invalid"))?;
    if encoded.len() > MAX_TOOL_ARGUMENT_BYTES || !arguments.is_object() {
      return Err(safe("arguments_invalid"));
    }
    let mut state = self.state.lock().map_err(|_| safe("state_unavailable"))?;
    if !state
      .tool_specs
      .iter()
      .any(|spec| spec["name"].as_str() == Some(tool))
    {
      return Err(safe("tool_denied"));
    }
    let result = self.rpc(
      &mut state,
      "tools/call",
      &json!({"name": tool, "arguments": arguments}),
    )?;
    let encoded = serde_json::to_vec(&result).map_err(|_| safe("result_invalid"))?;
    if encoded.len() > MAX_TOOL_RESULT_BYTES || result["isError"].as_bool() == Some(true) {
      return Err(safe("tool_failed"));
    }
    Ok(result)
  }

  fn rpc(&self, state: &mut McpState, method: &str, params: &Value) -> Result<Value, String> {
    let id = state.next_id;
    state.next_id = state
      .next_id
      .checked_add(1)
      .ok_or_else(|| safe("request_id_exhausted"))?;
    let response = self.post(
      state.session_id.as_deref(),
      &json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
    )?;
    if method == "initialize" {
      state.session_id.clone_from(&response.session_id);
    }
    if response.status != 200 {
      return Err(safe("http_rejected"));
    }
    let body = decode_json_body(&response)?;
    if body["id"].as_u64() != Some(id) || body.get("error").is_some() {
      return Err(safe("rpc_rejected"));
    }
    body
      .get("result")
      .cloned()
      .ok_or_else(|| safe("rpc_result_missing"))
  }

  fn notification(&self, state: &McpState, method: &str, params: &Value) -> Result<(), String> {
    let response = self.post(
      state.session_id.as_deref(),
      &json!({"jsonrpc":"2.0","method":method,"params":params}),
    )?;
    if matches!(response.status, 200 | 202 | 204) {
      Ok(())
    } else {
      Err(safe("notification_rejected"))
    }
  }

  fn post(&self, session_id: Option<&str>, body: &Value) -> Result<HttpResponse, String> {
    let body = serde_json::to_vec(body).map_err(|_| safe("request_invalid"))?;
    if body.len() > MAX_HTTP_MESSAGE_BYTES {
      return Err(safe("request_too_large"));
    }
    let mut stream = TcpStream::connect_timeout(&self.endpoint.address, HTTP_TIMEOUT)
      .map_err(|_| safe("connect_failed"))?;
    stream
      .set_read_timeout(Some(HTTP_TIMEOUT))
      .map_err(|_| safe("timeout_configuration_failed"))?;
    stream
      .set_write_timeout(Some(HTTP_TIMEOUT))
      .map_err(|_| safe("timeout_configuration_failed"))?;
    let mut headers = format!(
      "POST {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n",
      self.endpoint.path,
      self.endpoint.host,
      self.bearer,
      body.len(),
    );
    if let Some(session_id) = session_id {
      if !is_safe_header_value(session_id) {
        return Err(safe("session_id_invalid"));
      }
      write!(headers, "Mcp-Session-Id: {session_id}\r\n").map_err(|_| safe("request_invalid"))?;
    }
    headers.push_str("\r\n");
    stream
      .write_all(headers.as_bytes())
      .and_then(|()| stream.write_all(&body))
      .and_then(|()| stream.flush())
      .map_err(|_| safe("request_write_failed"))?;
    let mut response = Vec::new();
    stream
      .take(u64::try_from(MAX_HTTP_MESSAGE_BYTES + 1).unwrap_or(u64::MAX))
      .read_to_end(&mut response)
      .map_err(|_| safe("response_read_failed"))?;
    parse_http_response(&response)
  }
}

impl HttpEndpoint {
  fn parse(value: &str) -> Result<Self, String> {
    let authority_and_path = value
      .strip_prefix("http://")
      .ok_or_else(|| safe("endpoint_invalid"))?;
    let (authority, path) = authority_and_path
      .split_once('/')
      .map_or((authority_and_path, "/"), |(authority, _path)| {
        (authority, &authority_and_path[authority.len()..])
      });
    if authority.is_empty() || path.contains(['?', '#', '\r', '\n']) || !path.starts_with('/') {
      return Err(safe("endpoint_invalid"));
    }
    let addresses: Vec<_> = authority
      .to_socket_addrs()
      .map_err(|_| safe("endpoint_invalid"))?
      .collect();
    if addresses.is_empty() || addresses.iter().any(|address| !address.ip().is_loopback()) {
      return Err(safe("endpoint_not_loopback"));
    }
    let address = addresses[0];
    if address.port() == 0 {
      return Err(safe("endpoint_invalid"));
    }
    let host = match address.ip() {
      IpAddr::V4(ip) => format!("{ip}:{}", address.port()),
      IpAddr::V6(ip) => format!("[{ip}]:{}", address.port()),
    };
    Ok(Self {
      address,
      host,
      path: path.to_owned(),
    })
  }
}

fn parse_http_response(encoded: &[u8]) -> Result<HttpResponse, String> {
  if encoded.len() > MAX_HTTP_MESSAGE_BYTES {
    return Err(safe("response_too_large"));
  }
  let header_end = encoded
    .windows(4)
    .position(|window| window == b"\r\n\r\n")
    .map(|index| index + 4)
    .ok_or_else(|| safe("response_invalid"))?;
  let headers =
    std::str::from_utf8(&encoded[..header_end]).map_err(|_| safe("response_invalid"))?;
  let mut lines = headers.lines();
  let mut status_parts = lines
    .next()
    .ok_or_else(|| safe("response_invalid"))?
    .split_whitespace();
  if status_parts.next() != Some("HTTP/1.1") {
    return Err(safe("response_invalid"));
  }
  let status = status_parts
    .next()
    .and_then(|value| value.parse::<u16>().ok())
    .filter(|status| (100..=599).contains(status))
    .ok_or_else(|| safe("response_invalid"))?;
  let mut parsed_headers = Vec::new();
  for line in lines.filter(|line| !line.is_empty()) {
    let (name, value) = line
      .split_once(':')
      .ok_or_else(|| safe("response_invalid"))?;
    if name.is_empty()
      || !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
      || !is_safe_response_header_value(value.trim())
    {
      return Err(safe("response_invalid"));
    }
    parsed_headers.push((name, value.trim()));
  }
  let header = |expected: &str| -> Result<Option<String>, String> {
    let mut matches = parsed_headers
      .iter()
      .filter(|(name, _)| name.eq_ignore_ascii_case(expected));
    let value = matches.next().map(|(_, value)| (*value).to_owned());
    if matches.next().is_some() {
      return Err(safe("response_invalid"));
    }
    Ok(value)
  };
  let transfer_encoding = header("transfer-encoding")?;
  let content_length = header("content-length")?;
  if transfer_encoding.is_some() && content_length.is_some() {
    return Err(safe("response_invalid"));
  }
  let body = if let Some(encoding) = transfer_encoding {
    if !encoding.eq_ignore_ascii_case("chunked") {
      return Err(safe("response_invalid"));
    }
    decode_chunked(&encoded[header_end..])?
  } else {
    let body = encoded[header_end..].to_vec();
    if let Some(length) = content_length {
      let length = length
        .parse::<usize>()
        .map_err(|_| safe("response_invalid"))?;
      if body.len() != length {
        return Err(safe("response_truncated"));
      }
    }
    body
  };
  Ok(HttpResponse {
    status,
    session_id: header("mcp-session-id")?,
    content_type: header("content-type")?.unwrap_or_default(),
    body,
  })
}

fn decode_chunked(mut encoded: &[u8]) -> Result<Vec<u8>, String> {
  let mut decoded = Vec::new();
  loop {
    let line_end = encoded
      .windows(2)
      .position(|window| window == b"\r\n")
      .ok_or_else(|| safe("chunk_invalid"))?;
    let size = std::str::from_utf8(&encoded[..line_end])
      .ok()
      .and_then(|line| line.split(';').next())
      .and_then(|value| usize::from_str_radix(value, 16).ok())
      .ok_or_else(|| safe("chunk_invalid"))?;
    encoded = &encoded[line_end + 2..];
    if size == 0 {
      return (encoded == b"\r\n")
        .then_some(decoded)
        .ok_or_else(|| safe("chunk_invalid"));
    }
    if size > encoded.len().saturating_sub(2)
      || &encoded[size..size + 2] != b"\r\n"
      || decoded.len().saturating_add(size) > MAX_HTTP_MESSAGE_BYTES
    {
      return Err(safe("chunk_invalid"));
    }
    decoded.extend_from_slice(&encoded[..size]);
    encoded = &encoded[size + 2..];
  }
}

fn decode_json_body(response: &HttpResponse) -> Result<Value, String> {
  if response.content_type.starts_with("text/event-stream") {
    let text = std::str::from_utf8(&response.body).map_err(|_| safe("sse_invalid"))?;
    let data = text
      .lines()
      .find_map(|line| line.strip_prefix("data: "))
      .ok_or_else(|| safe("sse_invalid"))?;
    serde_json::from_str(data).map_err(|_| safe("response_json_invalid"))
  } else if response.content_type.starts_with("application/json") {
    serde_json::from_slice(&response.body).map_err(|_| safe("response_json_invalid"))
  } else {
    Err(safe("response_content_type_invalid"))
  }
}

fn is_safe_header_value(value: &str) -> bool {
  !value.is_empty()
    && value.len() <= 256
    && value
      .bytes()
      .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'\r' | b'\n'))
}

fn is_safe_response_header_value(value: &str) -> bool {
  value.len() <= 4 * 1024
    && value
      .bytes()
      .all(|byte| byte == b'\t' || (byte.is_ascii() && !byte.is_ascii_control()))
}

fn safe(code: &str) -> String {
  format!("scheduled_github_mcp_{code}")
}

fn json_depth(value: &Value) -> usize {
  match value {
    Value::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or(0),
    Value::Object(values) => 1 + values.values().map(json_depth).max().unwrap_or(0),
    _ => 1,
  }
}

#[cfg(test)]
mod tests {
  use std::io::{Read, Write};
  use std::net::TcpListener;
  use std::sync::{Arc, Mutex};
  use std::thread::{self, JoinHandle};

  use super::*;

  const TEST_BEARER: &str = "github-mcp-test-bearer-sentinel-123456";

  struct ScriptedServer {
    url: String,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    handle: JoinHandle<()>,
  }

  fn scripted_server(responses: Vec<Vec<u8>>) -> ScriptedServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind scripted server");
    let address = listener.local_addr().expect("scripted server address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    let handle = thread::spawn(move || {
      for response in responses {
        let (mut stream, _) = listener.accept().expect("accept scripted request");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        let header_end = loop {
          let read = stream.read(&mut buffer).expect("read scripted request");
          assert_ne!(read, 0, "request ended before headers");
          request.extend_from_slice(&buffer[..read]);
          if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
          }
        };
        let headers = std::str::from_utf8(&request[..header_end]).expect("request headers utf8");
        let content_length = headers
          .lines()
          .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name
              .eq_ignore_ascii_case("content-length")
              .then(|| value.trim().parse::<usize>().expect("content length"))
          })
          .expect("content length header");
        while request.len() < header_end + content_length {
          let read = stream
            .read(&mut buffer)
            .expect("read scripted request body");
          assert_ne!(read, 0, "request body truncated");
          request.extend_from_slice(&buffer[..read]);
        }
        recorded.lock().expect("record requests").push(request);
        stream
          .write_all(&response)
          .expect("write scripted response");
      }
    });
    ScriptedServer {
      url: format!("http://{address}/mcp"),
      requests,
      handle,
    }
  }

  fn json_response(status: u16, session: Option<&str>, body: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(&body).expect("response JSON");
    let session = session.map_or(String::new(), |session| {
      format!("Mcp-Session-Id: {session}\r\n")
    });
    format!(
      "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n{session}Content-Length: {}\r\nConnection: close\r\n\r\n",
      body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body)
    .collect()
  }

  fn empty_response(status: u16) -> Vec<u8> {
    format!("HTTP/1.1 {status} Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
      .into_bytes()
  }

  fn expected_tools() -> Vec<Value> {
    super::super::scheduled::EXPECTED_GITHUB_TOOLS
      .iter()
      .map(|name| {
        json!({
          "name": name,
          "description": format!("Read-only {name}"),
          "inputSchema": {"type": "object", "additionalProperties": false},
          "annotations": {"readOnlyHint": true},
        })
      })
      .collect()
  }

  fn attestation_responses(tools: &[Value]) -> Vec<Vec<u8>> {
    vec![
      json_response(
        200,
        Some("test-session"),
        &json!({
          "jsonrpc": "2.0",
          "id": 1,
          "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "serverInfo": {"name": "github-mcp-server", "version": "1.6.0"},
          },
        }),
      ),
      empty_response(202),
      json_response(
        200,
        None,
        &json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": tools}}),
      ),
      json_response(
        200,
        None,
        &json!({"jsonrpc": "2.0", "id": 3, "result": {"resources": []}}),
      ),
      json_response(
        200,
        None,
        &json!({"jsonrpc": "2.0", "id": 4, "result": {"resourceTemplates": []}}),
      ),
      json_response(
        200,
        None,
        &json!({
          "jsonrpc": "2.0",
          "id": 5,
          "result": {"content": [{"type": "text", "text": "test-user"}]},
        }),
      ),
    ]
  }

  #[test]
  fn client_attests_exact_inventory_and_keeps_bearer_in_request_headers() {
    let mut responses = attestation_responses(&expected_tools());
    responses.push(json_response(
      200,
      None,
      &json!({
        "jsonrpc": "2.0",
        "id": 6,
        "result": {"content": [{"type": "text", "text": "issue"}]},
      }),
    ));
    let server = scripted_server(responses);
    let client =
      ScheduledGithubMcpClient::new(&server.url, TEST_BEARER.to_owned()).expect("client");
    let expected = super::super::scheduled::RequestedCapabilityProfile::github_tool_inventory();
    let attestation = client
      .attest("github-mcp-server", "1.6.0", &expected)
      .expect("attestation");
    assert_eq!(attestation.tool_specs.len(), 5);
    assert_eq!(attestation.tool_schema_sha256.len(), 64);
    client
      .call(
        "issue_read",
        &json!({"owner": "helixbox", "repo": "codeoff", "issue_number": 1}),
      )
      .expect("read-only tool call");
    assert_eq!(
      client.call("create_issue", &json!({})),
      Err(safe("tool_denied"))
    );
    server.handle.join().expect("scripted server");

    let requests = server.requests.lock().expect("recorded requests");
    assert_eq!(requests.len(), 7);
    for request in requests.iter() {
      let text = std::str::from_utf8(request).expect("request utf8");
      assert!(text.contains(&format!("Authorization: Bearer {TEST_BEARER}\r\n")));
      let body = text.split_once("\r\n\r\n").expect("request body").1;
      assert!(!body.contains(TEST_BEARER));
    }
    for request in &requests[1..] {
      assert!(
        std::str::from_utf8(request)
          .expect("request utf8")
          .contains("Mcp-Session-Id: test-session\r\n")
      );
    }
  }

  #[test]
  fn attestation_rejects_inventory_or_write_capability_drift() {
    let mut missing = expected_tools();
    missing.pop();
    let missing_server = scripted_server(attestation_responses(&missing)[..3].to_vec());
    let missing_client =
      ScheduledGithubMcpClient::new(&missing_server.url, TEST_BEARER.to_owned()).expect("client");
    assert_eq!(
      missing_client
        .attest(
          "github-mcp-server",
          "1.6.0",
          &super::super::scheduled::RequestedCapabilityProfile::github_tool_inventory()
        )
        .err(),
      Some(safe("tool_inventory_mismatch"))
    );
    missing_server
      .handle
      .join()
      .expect("missing inventory server");

    let mut writable = expected_tools();
    writable[0]["annotations"]["readOnlyHint"] = json!(false);
    let writable_server = scripted_server(attestation_responses(&writable)[..3].to_vec());
    let writable_client =
      ScheduledGithubMcpClient::new(&writable_server.url, TEST_BEARER.to_owned()).expect("client");
    assert_eq!(
      writable_client
        .attest(
          "github-mcp-server",
          "1.6.0",
          &super::super::scheduled::RequestedCapabilityProfile::github_tool_inventory()
        )
        .err(),
      Some(safe("tool_not_read_only"))
    );
    writable_server
      .handle
      .join()
      .expect("writable inventory server");
  }

  #[test]
  fn endpoint_and_bearer_validation_fail_closed() {
    assert_eq!(
      ScheduledGithubMcpClient::new("https://127.0.0.1:1234/mcp", TEST_BEARER.to_owned()).err(),
      Some(safe("endpoint_invalid"))
    );
    assert_eq!(
      ScheduledGithubMcpClient::new("http://192.0.2.1:1234/mcp", TEST_BEARER.to_owned()).err(),
      Some(safe("endpoint_not_loopback"))
    );
    assert_eq!(
      ScheduledGithubMcpClient::new(
        "http://127.0.0.1:1234/mcp?target=elsewhere",
        TEST_BEARER.to_owned()
      )
      .err(),
      Some(safe("endpoint_invalid"))
    );
    assert_eq!(
      ScheduledGithubMcpClient::new(
        "http://127.0.0.1:1234/mcp",
        "secret\r\nInjected: true".to_owned()
      )
      .err(),
      Some(safe("bearer_invalid"))
    );
  }

  #[test]
  fn response_decoding_accepts_json_sse_and_chunked_framing() {
    let json = parse_http_response(&json_response(
      200,
      None,
      &json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
    ))
    .expect("JSON response");
    assert_eq!(decode_json_body(&json).expect("JSON body")["id"], 1);

    let sse_body = b"data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n";
    let sse = HttpResponse {
      status: 200,
      session_id: None,
      content_type: "text/event-stream; charset=utf-8".to_owned(),
      body: sse_body.to_vec(),
    };
    assert_eq!(decode_json_body(&sse).expect("SSE body")["id"], 2);

    let chunked = parse_http_response(
      b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"ok\r\n4\r\n\":1}\r\n0\r\n\r\n",
    )
    .expect("chunked response");
    assert_eq!(chunked.body, br#"{"ok":1}"#);
  }

  #[test]
  fn response_decoding_rejects_ambiguous_malformed_and_oversize_messages() {
    assert_eq!(
      parse_http_response(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
      )
      .err(),
      Some(safe("response_invalid"))
    );
    assert_eq!(
      parse_http_response(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n").err(),
      Some(safe("response_invalid"))
    );
    assert_eq!(
      decode_chunked(b"1\r\na\r\n0\r\n").err(),
      Some(safe("chunk_invalid"))
    );
    assert_eq!(
      parse_http_response(&vec![b'x'; MAX_HTTP_MESSAGE_BYTES + 1]).err(),
      Some(safe("response_too_large"))
    );
  }

  #[test]
  fn tool_results_are_bounded_and_upstream_content_is_not_reflected() {
    let mut responses = attestation_responses(&expected_tools());
    responses.push(json_response(
      200,
      None,
      &json!({
        "jsonrpc": "2.0",
        "id": 6,
        "result": {"content": [{"type": "text", "text": "x".repeat(MAX_TOOL_RESULT_BYTES)}]},
      }),
    ));
    let server = scripted_server(responses);
    let client =
      ScheduledGithubMcpClient::new(&server.url, TEST_BEARER.to_owned()).expect("client");
    client
      .attest(
        "github-mcp-server",
        "1.6.0",
        &super::super::scheduled::RequestedCapabilityProfile::github_tool_inventory(),
      )
      .expect("attestation");
    assert_eq!(
      client.call("issue_read", &json!({})).err(),
      Some(safe("tool_failed"))
    );
    server.handle.join().expect("oversize result server");
  }
}
