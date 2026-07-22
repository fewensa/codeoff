//! Slack channel connector wiring for Codeoff.
#![allow(
  clippy::map_unwrap_or,
  clippy::needless_pass_by_value,
  clippy::struct_excessive_bools,
  clippy::type_complexity,
  clippy::unnecessary_wraps
)]

mod client;
mod config;
mod delivery;
mod error;
mod intake;
mod mention_filter;
mod normalize;
mod schedule_target;
mod socket_mode;
mod web_api;
mod worker;

pub use client::SlackSocketClient;
pub use config::{SlackConfigCheck, validate_slack_config};
pub use delivery::SlackDeliveryQueue;
pub use error::{SlackConfigError, SlackSocketError};
pub use intake::{SlackIntake, SlackIntakeError, SlackIntakeResult};
pub use mention_filter::SlackMentionFilter;
pub use normalize::{
  NormalizedSlackEvent, SlackNormalizeError, normalize_socket_mode_envelope,
  normalize_socket_mode_envelope_with_mention_filter,
};
pub use schedule_target::SlackScheduleTargetVerifier;
pub use socket_mode::{SlackSocketTransport, SocketModeEnvelope, TransportReceive};
pub use web_api::{
  SlackChannelAddress, SlackConfiguredSender, SlackConnectorStatus, SlackHttpClient,
  SlackHttpDownloadRequest, SlackHttpRequest, SlackHttpResponse, SlackPostedMessage,
  SlackReqwestWebApiClient, SlackStreamMessage, SlackStreamStatus, SlackUserAddress,
  SlackWebApiClient, SlackWebApiError,
};
pub use worker::{SocketWorkerAction, SocketWorkerOptions, check_slack_worker, run_socket_worker};
