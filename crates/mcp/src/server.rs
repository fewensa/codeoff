use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use codeoff_runtime::channel_tools::{
  ChannelChannelProvider, ChannelContextProvider, ChannelResourceProvider, ChannelSenderProvider,
  ChannelStatusProvider, ChannelThreadReplyProvider, ChannelUserProvider,
};
use codeoff_state::StateStore;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

use crate::{ChannelToolDispatcher, JsonRpcDispatcher, JsonRpcRequest};

/// Newline-delimited JSON-RPC MCP server for channel tools.
pub struct McpTcpServer<P> {
  listener: TcpListener,
  state: StateStore,
  context_provider: Arc<P>,
  resource_provider: Option<Arc<dyn ChannelResourceProvider>>,
  address_providers: Option<ChannelAddressProviders>,
}

#[derive(Clone)]
struct ChannelAddressProviders {
  user_provider: Arc<dyn ChannelUserProvider>,
  channel_provider: Arc<dyn ChannelChannelProvider>,
  sender_provider: Arc<dyn ChannelSenderProvider>,
  status_provider: Arc<dyn ChannelStatusProvider>,
  thread_reply_provider: Arc<dyn ChannelThreadReplyProvider>,
}

impl<P> McpTcpServer<P>
where
  P: ChannelContextProvider + Send + Sync + 'static,
{
  /// Binds a TCP MCP server to the configured address.
  ///
  /// # Errors
  ///
  /// Returns an I/O error when the listener cannot bind.
  pub async fn bind(
    address: impl ToSocketAddrs,
    state: StateStore,
    context_provider: P,
  ) -> io::Result<Self> {
    Ok(Self {
      listener: TcpListener::bind(address).await?,
      state,
      context_provider: Arc::new(context_provider),
      resource_provider: None,
      address_providers: None,
    })
  }
}

impl<P> McpTcpServer<P>
where
  P: ChannelContextProvider + Send + Sync + 'static,
{
  /// Binds a TCP MCP server with both context and resource providers.
  ///
  /// # Errors
  ///
  /// Returns an I/O error when the listener cannot bind.
  pub async fn bind_with_resource_provider(
    address: impl ToSocketAddrs,
    state: StateStore,
    context_provider: P,
    resource_provider: Arc<dyn ChannelResourceProvider>,
  ) -> io::Result<Self> {
    Ok(Self {
      listener: TcpListener::bind(address).await?,
      state,
      context_provider: Arc::new(context_provider),
      resource_provider: Some(resource_provider),
      address_providers: None,
    })
  }

  /// Binds a TCP MCP server with channel address/discovery providers.
  ///
  /// # Errors
  ///
  /// Returns an I/O error when the listener cannot bind.
  pub async fn bind_with_address_provider<A>(
    address: impl ToSocketAddrs,
    state: StateStore,
    context_provider: P,
    address_provider: Arc<A>,
  ) -> io::Result<Self>
  where
    A: ChannelUserProvider
      + ChannelChannelProvider
      + ChannelSenderProvider
      + ChannelStatusProvider
      + ChannelThreadReplyProvider
      + Send
      + Sync
      + 'static,
  {
    Ok(Self {
      listener: TcpListener::bind(address).await?,
      state,
      context_provider: Arc::new(context_provider),
      resource_provider: None,
      address_providers: Some(ChannelAddressProviders {
        user_provider: address_provider.clone(),
        channel_provider: address_provider.clone(),
        sender_provider: address_provider.clone(),
        status_provider: address_provider.clone(),
        thread_reply_provider: address_provider,
      }),
    })
  }

  /// Binds a TCP MCP server with resource and channel address/discovery providers.
  ///
  /// # Errors
  ///
  /// Returns an I/O error when the listener cannot bind.
  pub async fn bind_with_resource_and_address_provider<A>(
    address: impl ToSocketAddrs,
    state: StateStore,
    context_provider: P,
    resource_provider: Arc<dyn ChannelResourceProvider>,
    address_provider: Arc<A>,
  ) -> io::Result<Self>
  where
    A: ChannelUserProvider
      + ChannelChannelProvider
      + ChannelSenderProvider
      + ChannelStatusProvider
      + ChannelThreadReplyProvider
      + Send
      + Sync
      + 'static,
  {
    Ok(Self {
      listener: TcpListener::bind(address).await?,
      state,
      context_provider: Arc::new(context_provider),
      resource_provider: Some(resource_provider),
      address_providers: Some(ChannelAddressProviders {
        user_provider: address_provider.clone(),
        channel_provider: address_provider.clone(),
        sender_provider: address_provider.clone(),
        status_provider: address_provider.clone(),
        thread_reply_provider: address_provider,
      }),
    })
  }

  /// Returns the actual socket address for the server listener.
  ///
  /// # Errors
  ///
  /// Returns an I/O error when the listener address cannot be read.
  pub fn local_addr(&self) -> io::Result<SocketAddr> {
    self.listener.local_addr()
  }

  /// Accepts TCP clients and serves newline-delimited JSON-RPC requests.
  ///
  /// # Errors
  ///
  /// Returns an I/O error when accepting a TCP connection fails.
  pub async fn run(self) -> io::Result<()> {
    loop {
      let (stream, _) = self.listener.accept().await?;
      let state = self.state.clone();
      let context_provider = Arc::clone(&self.context_provider);
      let resource_provider = self.resource_provider.as_ref().map(Arc::clone);
      let address_providers = self.address_providers.clone();
      tokio::spawn(async move {
        if let Err(error) = handle_connection(
          stream,
          state,
          context_provider,
          resource_provider,
          address_providers,
        )
        .await
        {
          eprintln!("MCP TCP client connection stopped: {error}");
        }
      });
    }
  }
}

async fn handle_connection<P>(
  stream: TcpStream,
  state: StateStore,
  context_provider: Arc<P>,
  resource_provider: Option<Arc<dyn ChannelResourceProvider>>,
  address_providers: Option<ChannelAddressProviders>,
) -> io::Result<()>
where
  P: ChannelContextProvider + Send + Sync + 'static,
{
  let mut reader = BufReader::new(stream);
  let mut line = String::new();
  loop {
    line.clear();
    if reader.read_line(&mut line).await? == 0 {
      return Ok(());
    }
    let response = match serde_json::from_str::<JsonRpcRequest>(&line) {
      Ok(request) => {
        let now = current_unix_seconds();
        let tools = match (resource_provider.as_ref(), address_providers.as_ref()) {
          (Some(resource_provider), Some(address_providers)) => {
            ChannelToolDispatcher::new_with_resource_and_address_providers_and_now(
              &state,
              context_provider.as_ref(),
              resource_provider.as_ref(),
              address_providers.user_provider.as_ref(),
              address_providers.channel_provider.as_ref(),
              address_providers.sender_provider.as_ref(),
              address_providers.status_provider.as_ref(),
              address_providers.thread_reply_provider.as_ref(),
              now,
            )
          }
          (Some(resource_provider), None) => {
            ChannelToolDispatcher::new_with_resource_provider_and_now(
              &state,
              context_provider.as_ref(),
              resource_provider.as_ref(),
              now,
            )
          }
          (None, Some(address_providers)) => {
            ChannelToolDispatcher::new_with_address_providers_and_now(
              &state,
              context_provider.as_ref(),
              address_providers.user_provider.as_ref(),
              address_providers.channel_provider.as_ref(),
              address_providers.sender_provider.as_ref(),
              address_providers.status_provider.as_ref(),
              address_providers.thread_reply_provider.as_ref(),
              now,
            )
          }
          (None, None) => ChannelToolDispatcher::new(&state, context_provider.as_ref()),
        };
        let dispatcher = JsonRpcDispatcher::new(&tools);
        dispatcher.handle(request).await
      }
      Err(error) => Some(parse_error(error.to_string())),
    };
    if let Some(response) = response {
      reader
        .get_mut()
        .write_all(response.to_string().as_bytes())
        .await?;
      reader.get_mut().write_all(b"\n").await?;
    }
  }
}

fn current_unix_seconds() -> u64 {
  use std::time::{SystemTime, UNIX_EPOCH};

  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs()
}

fn parse_error(message: String) -> Value {
  json!({
    "jsonrpc": "2.0",
    "id": null,
    "error": {
      "code": -32700,
      "message": "parse error",
      "data": {
        "message": message,
      },
    },
  })
}
