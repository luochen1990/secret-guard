//! `/__sg/api/*` JSON endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::Serialize;
use uuid::Uuid;

use crate::proxy::ProxyState;
use crate::record::ForwardRecord;

pub async fn list_records(State(state): State<ProxyState>) -> Json<ListResponse> {
    let records = state.records.list();
    Json(ListResponse { records })
}

pub async fn get_record(
    State(state): State<ProxyState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ForwardRecord>, StatusCode> {
    state.records.get(id).map(Json).ok_or(StatusCode::NOT_FOUND)
}

#[derive(Serialize)]
pub struct ListResponse {
    pub records: Vec<ForwardRecord>,
}
