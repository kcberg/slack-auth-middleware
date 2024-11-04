use http_body_util::BodyExt;
use std::{
    convert::Infallible,
    task::{Context, Poll},
};

use axum::{body::Body, extract::Request, response::Response};
use futures_util::future::BoxFuture;
use hex;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tower::{Layer, Service};

#[derive(Clone)]
pub struct SlackAuthConfig {
    pub version_number: String,
    pub slack_signing_secret: String,
}

#[derive(Clone)]
pub struct SlackAuthLayer {
    config: SlackAuthConfig,
}

impl SlackAuthLayer {
    #[must_use]
    pub const fn new(config: SlackAuthConfig) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for SlackAuthLayer {
    type Service = SlackAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            config: self.config.clone(),
        }
    }
}

#[derive(Clone)]
pub struct SlackAuthService<S> {
    inner: S,
    config: SlackAuthConfig,
}

impl<S> Service<Request<Body>> for SlackAuthService<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let clone = self.config.clone();
        let config = std::mem::replace(&mut self.config, clone);
        Box::pin(async move {
            let deny = || {
                let response = Response::builder()
                    .status(401)
                    .body(Body::empty())
                    .expect("Building an empty response should not fail.");
                Ok(response)
            };

            let (parts, body) = req.into_parts();
            let bytes = match body.collect().await {
                Ok(bytes) => bytes.to_bytes(),
                Err(_) => return deny(),
            };
            let request_body = std::str::from_utf8(&bytes).expect(
                "Since we are collecting the body before into bytes, this should not fail.",
            );
            let slack_signature = match parts.headers.get("x-slack-signature") {
                Some(signature) => match signature.to_str() {
                    Ok(signature) => signature,
                    Err(_) => return deny(),
                },
                None => return deny(),
            };
            let Some(slack_request_timestamp) = parts.headers.get("x-slack-request-timestamp")
            else {
                return deny();
            };
            let slack_request_timestamp = slack_request_timestamp
                .to_str()
                .unwrap_or("")
                .parse::<i64>()
                .unwrap_or(0);
            let Some(parsed_slack_request_timestamp) =
                chrono::DateTime::from_timestamp(slack_request_timestamp, 0)
            else {
                return deny();
            };
            if chrono::offset::Utc::now()
                .signed_duration_since(parsed_slack_request_timestamp)
                .num_seconds()
                > 60 * 5
            {
                return deny();
            }
            let signer =
                SecretSigner::new(config, request_body.to_string(), slack_request_timestamp);
            let generated_hash = match signer.sign() {
                Ok(hash) => hash,
                Err(_) => return deny(),
            };
            if generated_hash != slack_signature {
                return deny();
            }
            let req = Request::from_parts(parts, Body::from(bytes));
            inner.call(req).await
        })
    }
}

pub struct SecretSigner {
    config: SlackAuthConfig,
    request_body: String,
    timestamp: i64,
}

impl SecretSigner {
    #[must_use]
    pub const fn new(config: SlackAuthConfig, request_body: String, timestamp: i64) -> Self {
        Self {
            config,
            request_body,
            timestamp,
        }
    }

    fn sign(&self) -> Result<String, hmac::digest::InvalidLength> {
        let base_string = format!(
            "{version_number}:{timestamp}:{request_body}",
            version_number = self.config.version_number,
            timestamp = self.timestamp,
            request_body = self.request_body
        );
        let hash = self.hmac_signature(&base_string)?;
        Ok(format!(
            "{version_number}={hash}",
            version_number = self.config.version_number,
            hash = hash
        ))
    }

    fn hmac_signature(&self, msg: &str) -> Result<String, hmac::digest::InvalidLength> {
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(self.config.slack_signing_secret.as_bytes())?;
        mac.update(msg.as_bytes());
        let code_bytes = mac.finalize().into_bytes();
        Ok(hex::encode(code_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use tokio;
    use tower::util::service_fn;
    use tower::ServiceExt;

    fn create_test_service() -> (
        SlackAuthConfig,
        impl Service<Request<Body>, Response = Response<Body>, Error = Infallible>,
    ) {
        let config = SlackAuthConfig {
            version_number: "v0".to_string(),
            slack_signing_secret: "8f742231b10e8888abcd99yyyzzz85a5".to_string(),
        };
        let layer = SlackAuthLayer::new(config.clone());
        let service = layer.layer(service_fn(|_req| async {
            Ok::<_, Infallible>(Response::new(Body::from("OK")))
        }));
        (config, service)
    }

    fn create_request_body() -> &'static str {
        concat!(
            "token=xyzz0WbapA4vBCDEFasx0q6G",
            "&team_id=T1DC2JH3J",
            "&team_domain=testteamnow",
            "&channel_id=G8PSS9T3V",
            "&channel_name=foobar",
            "&user_id=U2CERLKJA",
            "&user_name=roadrunner",
            "&command=%2Fwebhook-collect",
            "&text=",
            "&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN",
            "&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c",
        )
    }

    #[test]
    fn sign() {
        let config = SlackAuthConfig {
            version_number: "v0".to_string(),
            slack_signing_secret: "8f742231b10e8888abcd99yyyzzz85a5".to_string(),
        };
        let request_body = create_request_body();
        let signer = SecretSigner::new(config, request_body.to_string(), 1531420618);
        let hash = signer.sign().unwrap();

        assert_eq!(
            hash,
            "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503"
        );
    }

    #[tokio::test]
    async fn valid_request() {
        let (config, service) = create_test_service();
        let request_body = create_request_body();
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let signer = SecretSigner::new(
            config.clone(),
            request_body.to_string(),
            timestamp.parse().unwrap(),
        );
        let signature = signer.sign().unwrap();

        let request = Request::builder()
            .header("x-slack-signature", signature)
            .header("x-slack-request-timestamp", timestamp)
            .body(Body::from(request_body))
            .unwrap();

        let response = service.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_signature_header() {
        let (_, service) = create_test_service();
        let request_body = create_request_body();
        let timestamp = chrono::Utc::now().timestamp().to_string();

        let request = Request::builder()
            .header("x-slack-request-timestamp", timestamp)
            .body(Body::from(request_body))
            .unwrap();

        let response = service.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_signature_header() {
        let (_, service) = create_test_service();
        let request_body = create_request_body();
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let signature = "invalid_signature";

        let request = Request::builder()
            .header("x-slack-signature", signature)
            .header("x-slack-request-timestamp", timestamp)
            .body(Body::from(request_body))
            .unwrap();

        let response = service.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_timestamp_header() {
        let (config, service) = create_test_service();
        let request_body = create_request_body();
        let signer = SecretSigner::new(
            config.clone(),
            request_body.to_string(),
            chrono::Utc::now().timestamp(),
        );
        let signature = signer.sign().unwrap();

        let request = Request::builder()
            .header("x-slack-signature", signature)
            .body(Body::from(request_body))
            .unwrap();

        let response = service.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_timestamp_header() {
        let (config, service) = create_test_service();
        let request_body = create_request_body();
        let timestamp = "invalid_timestamp";
        let signer = SecretSigner::new(
            config.clone(),
            request_body.to_string(),
            chrono::Utc::now().timestamp(),
        );
        let signature = signer.sign().unwrap();

        let request = Request::builder()
            .header("x-slack-signature", signature)
            .header("x-slack-request-timestamp", timestamp)
            .body(Body::from(request_body))
            .unwrap();

        let response = service.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_timestamp() {
        let (config, service) = create_test_service();
        let request_body = create_request_body();
        let timestamp = (chrono::Utc::now().timestamp() - 60 * 6).to_string();
        let signer = SecretSigner::new(
            config.clone(),
            request_body.to_string(),
            timestamp.parse().unwrap(),
        );
        let signature = signer.sign().unwrap();

        let request = Request::builder()
            .header("x-slack-signature", signature)
            .header("x-slack-request-timestamp", timestamp)
            .body(Body::from(request_body))
            .unwrap();

        let response = service.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mismatched_signature() {
        let (_, service) = create_test_service();
        let request_body = create_request_body();
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let signature = "v0=some_invalid_signature";

        let request = Request::builder()
            .header("x-slack-signature", signature)
            .header("x-slack-request-timestamp", timestamp)
            .body(Body::from(request_body))
            .unwrap();

        let response = service.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
