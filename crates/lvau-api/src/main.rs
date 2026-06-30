#![allow(clippy::collapsible_if)]
use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
};
use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod routes;
mod transport;

fn build_app() -> Router {
    let allowed_origin =
        env::var("LVAU_ALLOWED_ORIGIN").unwrap_or_else(|_| "https://lattee.jp".to_string());
    let max_upload_mb = env::var("LVAU_MAX_UPLOAD_MB")
        .unwrap_or_else(|_| "50".to_string())
        .parse::<usize>()
        .unwrap_or(50);

    Router::new()
        .route("/lvau/health", get(routes::health))
        .route("/lvau/version", get(routes::version))
        .route("/lvau/encrypt", post(routes::encrypt_file))
        .route("/lvau/decrypt", post(routes::decrypt_file))
        .route("/lvau/inspect", post(routes::inspect_file))
        .route("/lvau/transport/server-info", get(transport::server_info))
        .route("/lvau/transport/open", post(transport::open_session))
        .route("/lvau/transport/message", post(transport::echo_message))
        .fallback(routes::not_found)
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::exact(allowed_origin.parse().unwrap()))
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(DefaultBodyLimit::max(max_upload_mb * 1024 * 1024))
        .layer(TimeoutLayer::new(Duration::from_secs(300)))
        .layer(middleware::from_fn(routes::rate_limiter))
        .layer(middleware::from_fn(routes::api_key_auth))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lvau_api=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Lvau API Service...");

    let bind_addr = env::var("LVAU_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();

    tracing::info!("Listening on {}", bind_addr);
    axum::serve(
        listener,
        build_app().into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::build_app;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use serde_json::Value;
    use tower::ServiceExt;

    async fn body_text(response: axum::response::Response) -> String {
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn multipart_body(boundary: &str, fields: &[(&str, Option<&str>, &str)]) -> String {
        let mut body = String::new();
        for (name, filename, value) in fields {
            body.push_str(&format!("--{boundary}\r\n"));
            if let Some(filename) = filename {
                body.push_str(&format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n"
                ));
                body.push_str("Content-Type: application/octet-stream\r\n\r\n");
            } else {
                body.push_str(&format!(
                    "Content-Disposition: form-data; name=\"{name}\"\r\n\r\n"
                ));
            }
            body.push_str(value);
            body.push_str("\r\n");
        }
        body.push_str(&format!("--{boundary}--\r\n"));
        body
    }

    #[tokio::test]
    async fn health_works() {
        let response = build_app()
            .oneshot(
                Request::builder()
                    .uri("/lvau/health")
                    .header("x-real-ip", "127.0.0.10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, "OK");
    }

    #[tokio::test]
    async fn version_works() {
        let response = build_app()
            .oneshot(
                Request::builder()
                    .uri("/lvau/version")
                    .header("x-real-ip", "127.0.0.11")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let payload: Value = serde_json::from_str(&body_text(response).await).unwrap();
        assert_eq!(payload["protocol"], "Lvau");
    }

    #[tokio::test]
    async fn encrypt_rejects_missing_file() {
        let boundary = "lvau-test-boundary";
        let body = multipart_body(boundary, &[("password", None, "test-password")]);
        let response = build_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/lvau/encrypt")
                    .header("x-real-ip", "127.0.0.12")
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let payload: Value = serde_json::from_str(&body_text(response).await).unwrap();
        assert_eq!(payload["code"], "MISSING_FILE");
    }

    #[tokio::test]
    async fn encrypt_rejects_missing_password() {
        let boundary = "lvau-test-boundary";
        let body = multipart_body(boundary, &[("file", Some("secret.txt"), "hello")]);
        let response = build_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/lvau/encrypt")
                    .header("x-real-ip", "127.0.0.13")
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let payload: Value = serde_json::from_str(&body_text(response).await).unwrap();
        assert_eq!(payload["code"], "MISSING_PASSWORD");
    }

    #[tokio::test]
    async fn encrypt_rejects_invalid_profile() {
        let boundary = "lvau-test-boundary";
        let body = multipart_body(
            boundary,
            &[
                ("file", Some("secret.txt"), "hello"),
                ("password", None, "test-password"),
                ("profile", None, "extreme"),
            ],
        );
        let response = build_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/lvau/encrypt")
                    .header("x-real-ip", "127.0.0.14")
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let payload: Value = serde_json::from_str(&body_text(response).await).unwrap();
        assert_eq!(payload["code"], "INVALID_PROFILE");
    }

    #[tokio::test]
    async fn inspect_rejects_invalid_envelope() {
        let boundary = "lvau-test-boundary";
        let body = multipart_body(boundary, &[("file", Some("not.lvau"), "not an envelope")]);
        let response = build_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/lvau/inspect")
                    .header("x-real-ip", "127.0.0.15")
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let payload: Value = serde_json::from_str(&body_text(response).await).unwrap();
        assert_eq!(payload["code"], "INVALID_ENVELOPE");
    }

    #[tokio::test]
    async fn transport_returns_501() {
        let response = build_app()
            .oneshot(
                Request::builder()
                    .uri("/lvau/transport/server-info")
                    .header("x-real-ip", "127.0.0.16")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let payload: Value = serde_json::from_str(&body_text(response).await).unwrap();
        assert_eq!(payload["code"], "NOT_IMPLEMENTED");
    }
}
