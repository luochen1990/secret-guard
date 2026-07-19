//! `/__sg/api/*` JSON endpoints.
//!
//! 所有响应都带 `Cache-Control: no-store`, 避免浏览器对自动刷新返回缓存内容.

use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::Json,
};
use serde::Serialize;
use uuid::Uuid;

use crate::proxy::ProxyState;
use crate::record::ForwardRecord;

/// 共享的 `no-store` header 设置.
const NO_STORE: [(header::HeaderName, HeaderValue); 1] = [(
    header::CACHE_CONTROL,
    HeaderValue::from_static("no-store, no-cache, must-revalidate"),
)];

pub async fn list_records(State(state): State<ProxyState>) -> impl axum::response::IntoResponse {
    let records = state.records.list();
    (NO_STORE, Json(ListResponse { records }))
}

pub async fn get_record(
    State(state): State<ProxyState>,
    Path(id): Path<Uuid>,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    state
        .records
        .get(id)
        .map(|r| (NO_STORE, Json(r)))
        .ok_or(StatusCode::NOT_FOUND)
}

#[derive(Serialize)]
pub struct ListResponse {
    pub records: Vec<ForwardRecord>,
}
