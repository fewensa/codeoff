//! Provider-neutral channel connector contracts for Codeoff.

mod address;
mod capabilities;
mod connector;
mod context;
mod error;
mod event;
mod message;

pub use address::{
  ChannelConnectorStatus, ChannelLookupRequest, ChannelResolveResult, ChannelSearchRequest,
  ChannelSenderSummary, ChannelSummary, ChannelThreadReplyReceipt, ChannelThreadReplyRequest,
  ChannelUserResolveRequest, ChannelUserResolveResult, ChannelUserSearchRequest,
  ChannelUserSummary, ChannelWorkspaceRequest, ChannelWorkspaceSummary,
};
pub use capabilities::ChannelConnectorCapabilities;
pub use connector::ChannelConnector;
pub use context::{
  ChannelAvailableToolHint, ChannelContextPack, ChannelContextPage, ChannelContextRequest,
  ChannelCurrentContextRequest, ChannelCurrentConversation, ChannelCurrentEvent,
  ChannelMessageFetchRequest, ChannelMessageSnapshot, ChannelResourceDownload,
  ChannelResourceDownloadRequest, ChannelResourceInfo, ChannelResourceInfoRequest,
  ChannelResourceText, ChannelResourceTextRequest, ChannelSourceAttachment, ChannelSourceLink,
  ChannelSourceReference,
};
pub use error::ChannelContractError;
pub use event::{ChannelEvent, ChannelEventKind};
pub use message::{ChannelMessageReceipt, ChannelMessageRequest, ChannelReplyTarget};
