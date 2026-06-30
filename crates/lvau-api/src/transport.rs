use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;

#[derive(Serialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
}

pub async fn server_info() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorResponse {
            code: "NOT_IMPLEMENTED".to_string(),
            message: "Lvau Transport Envelope is not implemented yet.".to_string(),
        }),
    )
}

pub async fn open_session() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorResponse {
            code: "NOT_IMPLEMENTED".to_string(),
            message: "Lvau Transport Envelope is not implemented yet.".to_string(),
        }),
    )
}

pub async fn echo_message() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorResponse {
            code: "NOT_IMPLEMENTED".to_string(),
            message: "Lvau Transport Envelope is not implemented yet.".to_string(),
        }),
    )
}
