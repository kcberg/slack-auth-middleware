//! A layer that authenticates requests from Slack.
//!
//! This layer will check the `x-slack-signature` header and the `x-slack-request-timestamp` header
//! to ensure that the request is coming from Slack.
//! If the request is not coming from Slack, this layer will return a 401 Unauthorized response.
//!
//! # Example
//!
//! ```ignore
//! use axum::{routing::get, Router};
//! use slack_auth_middleware::{SlackAuthConfig, SlackAuthLayer};
//!
//! #[tokio::main]
//! async fn main() {
//!     tracing_subscriber::fmt::init();
//!
//!     let config = SlackAuthConfig {
//!         version_number: "v0".to_string(),
//!         slack_signing_secret: "123".to_string(),
//!     };
//!
//!     let app = Router::new().route("/", get(root).layer(SlackAuthLayer::new(config)));
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(listener, app).await.unwrap();
//! }
//!
//! async fn root() -> &'static str {
//!     "Hello, World!"
//! }
//! ```
//!

mod middleware;

pub use middleware::SlackAuthConfig;
pub use middleware::SlackAuthLayer;
