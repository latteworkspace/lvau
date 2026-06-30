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

    // Security constraints
    let allowed_origin =
        env::var("LVAU_ALLOWED_ORIGIN").unwrap_or_else(|_| "https://lattee.jp".to_string());
    let max_upload_mb = env::var("LVAU_MAX_UPLOAD_MB")
        .unwrap_or_else(|_| "50".to_string())
        .parse::<usize>()
        .unwrap_or(50);

    let app = Router::new()
        .route("/lvau/health", get(routes::health))
        .route("/lvau/version", get(routes::version))
        .route("/lvau/encrypt", post(routes::encrypt_file))
        .route("/lvau/decrypt", post(routes::decrypt_file))
        .route("/lvau/inspect", post(routes::inspect_file))
        .route("/lvau/transport/server-info", get(transport::server_info))
        .route("/lvau/transport/open", post(transport::open_session))
        .route("/lvau/transport/message", post(transport::echo_message))
        .fallback(routes::not_found)
        // Apply middleware (timeout, size limit, logging, CORS, API Key check, rate limit)
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
        .layer(middleware::from_fn(routes::api_key_auth));

    let bind_addr = env::var("LVAU_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();

    tracing::info!("Listening on {}", bind_addr);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();

    Ok(())
}
