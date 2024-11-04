# slack-auth-middleware

A middleware layer for Axum to authenticate requests from Slack using HMAC signatures.

## Features

- Verifies Slack requests using HMAC signatures.
- Configurable version number and Slack signing secret.
- Middleware layer for Axum.

## Installation

```bash
cargo add slack-auth-middleware
```

## Usage

```rust
use axum::{routing::get, Router};
use slack_auth_middleware::{SlackAuthConfig, SlackAuthLayer};
use tracing_subscriber;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = SlackAuthConfig {
        version_number: "v0".to_string(),
        slack_signing_secret: "123".to_string(),
    };


    let app = Router::new().route("/", get(root).layer(SlackAuthLayer::new(config)));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> &'static str {
    "Hello, World!"
}
```

## Minimum supported Rust version

Rust 1.79