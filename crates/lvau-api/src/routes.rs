use axum::{
    Json,
    extract::{ConnectInfo, Multipart, Request},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use lvau_core::crypto::{
    CryptoError, decrypt_file_password, encrypt_file_password, inspect_envelope,
};
use lvau_protocol::envelope::SecurityProfile;
use secrecy::{ExposeSecret, Secret};
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tempfile::Builder;
use tokio::fs::{File, remove_file};
use tokio::io::AsyncWriteExt;

#[derive(Serialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
}

impl ErrorResponse {
    fn new(code: &str, msg: &str) -> Self {
        Self {
            code: code.to_string(),
            message: msg.to_string(),
        }
    }
}

pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

pub async fn version() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": "Lvau",
    }))
}

pub async fn api_key_auth(req: Request, next: Next) -> Result<Response, StatusCode> {
    let api_keys = env::var("LVAU_API_KEYS").unwrap_or_default();
    if api_keys.is_empty() {
        return Ok(next.run(req).await);
    }

    // Always allow health and version endpoints without auth
    if req.uri().path() == "/lvau/health" || req.uri().path() == "/lvau/version" {
        return Ok(next.run(req).await);
    }

    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let mut authorized = false;
                for key in api_keys.split(',') {
                    let key = key.trim();
                    // Constant-time comparison
                    if token.as_bytes().ct_eq(key.as_bytes()).unwrap_u8() == 1 {
                        authorized = true;
                    }
                }
                if authorized {
                    return Ok(next.run(req).await);
                }
            }
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

struct RateLimitState {
    requests: HashMap<IpAddr, Vec<Instant>>,
}

impl RateLimitState {
    fn new() -> Self {
        Self {
            requests: HashMap::new(),
        }
    }

    fn check_and_record(&mut self, ip: IpAddr, limit: usize, window: Duration) -> bool {
        let now = Instant::now();
        let times = self.requests.entry(ip).or_default();
        times.retain(|t| now.duration_since(*t) < window);
        if times.len() >= limit {
            false
        } else {
            times.push(now);
            true
        }
    }
}

lazy_static::lazy_static! {
    static ref ENCRYPT_LIMITER: Arc<Mutex<RateLimitState>> = Arc::new(Mutex::new(RateLimitState::new()));
    static ref DECRYPT_LIMITER: Arc<Mutex<RateLimitState>> = Arc::new(Mutex::new(RateLimitState::new()));
    static ref INSPECT_LIMITER: Arc<Mutex<RateLimitState>> = Arc::new(Mutex::new(RateLimitState::new()));
}

fn get_client_ip(req: &Request) -> Option<IpAddr> {
    if let Some(header) = req.headers().get("x-real-ip") {
        if let Ok(s) = header.to_str() {
            if let Ok(ip) = s.parse() {
                return Some(ip);
            }
        }
    }
    if let Some(header) = req.headers().get("x-forwarded-for") {
        if let Ok(s) = header.to_str() {
            if let Some(ip_str) = s.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse() {
                    return Some(ip);
                }
            }
        }
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
}

pub async fn rate_limiter(
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let path = req.uri().path();

    let (limiter, limit) = match path {
        "/lvau/decrypt" => (DECRYPT_LIMITER.clone(), 5),
        "/lvau/encrypt" => (ENCRYPT_LIMITER.clone(), 10),
        "/lvau/inspect" => (INSPECT_LIMITER.clone(), 30),
        _ => return Ok(next.run(req).await),
    };

    let ip = get_client_ip(&req).unwrap_or_else(|| "127.0.0.1".parse().unwrap());

    let is_allowed = {
        let mut state = limiter.lock().unwrap();
        state.check_and_record(ip, limit, Duration::from_secs(60))
    };

    if !is_allowed {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse::new(
                "RATE_LIMITED",
                "Too many requests. Please try again later.",
            )),
        ));
    }

    Ok(next.run(req).await)
}

// Helper to stream a file and enforce max size
async fn stream_to_file(
    field: axum::extract::multipart::Field<'_>,
    path: &Path,
    max_mb: usize,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let max_bytes = max_mb * 1024 * 1024;
    let mut total_bytes = 0;

    let mut file = File::create(path).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "INTERNAL_ERROR",
                "Failed to create temp file",
            )),
        )
    })?;

    let mut stream = field;
    while let Some(chunk) = stream.chunk().await.map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "BAD_REQUEST",
                "Failed to read file chunk",
            )),
        )
    })? {
        total_bytes += chunk.len();
        if total_bytes > max_bytes {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(ErrorResponse::new(
                    "FILE_TOO_LARGE",
                    "File exceeds maximum allowed size",
                )),
            ));
        }
        file.write_all(&chunk).await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(
                    "INTERNAL_ERROR",
                    "Failed to write temp file",
                )),
            )
        })?;
    }

    file.flush().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "INTERNAL_ERROR",
                "Failed to flush temp file",
            )),
        )
    })?;
    Ok(())
}

fn get_max_mb() -> usize {
    env::var("LVAU_MAX_UPLOAD_MB")
        .unwrap_or_else(|_| "100".to_string())
        .parse()
        .unwrap_or(100)
}

pub async fn encrypt_file(
    mut multipart: Multipart,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let mut temp_dir_opt = None;
    let mut password = None;
    let mut profile = SecurityProfile::Balanced;
    let max_mb = get_max_mb();

    let temp_dir = Builder::new().prefix("lvau_enc_").tempdir().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "INTERNAL_ERROR",
                "Failed to create temp directory",
            )),
        )
    })?;
    let in_path = temp_dir.path().join("in.tmp");

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            stream_to_file(field, &in_path, max_mb).await?;
            temp_dir_opt = Some(true);
        } else if name == "password" {
            password = Some(Secret::new(field.text().await.map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse::new("BAD_REQUEST", "Failed to read password")),
                )
            })?));
        } else if name == "profile" {
            let p_str = field.text().await.unwrap_or_default();
            profile = match p_str.as_str() {
                "fast" => SecurityProfile::Fast,
                "balanced" => SecurityProfile::Balanced,
                "archive" => SecurityProfile::Archive,
                "paranoid" => SecurityProfile::Paranoid,
                _ => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse::new(
                            "INVALID_PROFILE",
                            "Invalid security profile",
                        )),
                    ));
                }
            };
        }
    }

    if temp_dir_opt.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("MISSING_FILE", "File is required")),
        ));
    }
    let password = password.ok_or((
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse::new(
            "MISSING_PASSWORD",
            "Password is required",
        )),
    ))?;

    let out_path = temp_dir.path().join("out.lvau");

    let res = tokio::task::spawn_blocking(move || {
        let res =
            encrypt_file_password(&in_path, &out_path, password, None, profile).map(|_| out_path);
        // Explicitly wipe the input file after processing
        let _ = std::fs::remove_file(&in_path);
        res
    })
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("INTERNAL_ERROR", "Task panicked")),
        )
    })?;

    match res {
        Ok(out_path) => {
            let out_data = tokio::fs::read(&out_path).await.map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::new(
                        "INTERNAL_ERROR",
                        "Failed to read output file",
                    )),
                )
            })?;
            let response = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"encrypted.lvau\"",
                )
                .body(axum::body::Body::from(out_data))
                .unwrap();
            Ok(response)
        }
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("ENCRYPT_FAILED", "Encryption failed")),
        )),
    }
}

pub async fn decrypt_file(
    mut multipart: Multipart,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let mut temp_dir_opt = None;
    let mut password = None;
    let max_mb = get_max_mb();

    let temp_dir = Builder::new().prefix("lvau_dec_").tempdir().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "INTERNAL_ERROR",
                "Failed to create temp directory",
            )),
        )
    })?;
    let in_path = temp_dir.path().join("in.lvau");

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            stream_to_file(field, &in_path, max_mb).await?;
            temp_dir_opt = Some(true);
        } else if name == "password" {
            password = Some(Secret::new(field.text().await.map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse::new("BAD_REQUEST", "Failed to read password")),
                )
            })?));
        }
    }

    if temp_dir_opt.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("MISSING_FILE", "File is required")),
        ));
    }
    let password = password.ok_or((
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse::new(
            "MISSING_PASSWORD",
            "Password is required",
        )),
    ))?;

    let out_path = temp_dir.path().join("out.tmp");

    let res = tokio::task::spawn_blocking(move || {
        let res = decrypt_file_password(&in_path, &out_path, password, None).map(|_| out_path);
        let _ = std::fs::remove_file(&in_path);
        res
    })
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("INTERNAL_ERROR", "Task panicked")),
        )
    })?;

    match res {
        Ok(out_path) => {
            let out_data = tokio::fs::read(&out_path).await.map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::new(
                        "INTERNAL_ERROR",
                        "Failed to read output file",
                    )),
                )
            })?;
            let response = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"decrypted.bin\"",
                )
                .body(axum::body::Body::from(out_data))
                .unwrap();
            Ok(response)
        }
        Err(CryptoError::DecryptionFailed) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "DECRYPT_FAILED",
                "Invalid password or corrupted file",
            )),
        )),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("DECRYPT_FAILED", "Decryption failed")),
        )),
    }
}

pub async fn inspect_file(
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let mut temp_dir_opt = None;
    let max_mb = get_max_mb();

    let temp_dir = Builder::new().prefix("lvau_ins_").tempdir().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "INTERNAL_ERROR",
                "Failed to create temp directory",
            )),
        )
    })?;
    let in_path = temp_dir.path().join("in.lvau");

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            stream_to_file(field, &in_path, max_mb).await?;
            temp_dir_opt = Some(true);
        }
    }

    if temp_dir_opt.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("MISSING_FILE", "File is required")),
        ));
    }

    let res = tokio::task::spawn_blocking(move || {
        let res = inspect_envelope(&in_path);
        let _ = std::fs::remove_file(&in_path);
        res
    })
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("INTERNAL_ERROR", "Task panicked")),
        )
    })?;

    match res {
        Ok(header) => Ok(Json(serde_json::json!({
            "version": header.version,
            "profile": format!("{:?}", header.profile),
            "algorithm": format!("{:?}", header.algorithm),
            "kdf": format!("{:?}", header.kdf),
        }))),
        Err(_) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "INVALID_ENVELOPE",
                "Invalid Lvau envelope",
            )),
        )),
    }
}
