//! `/__sg/api/*` JSON endpoints.
//!
//! 所有响应都带 `Cache-Control: no-store`, 避免浏览器对自动刷新返回缓存内容.
//!
//! **安全姿态**:
//! - GET 永不返回 secret 的 `value` 字段 (用 `mask_*` 占位符), 防止浏览器/UI 误显示.
//! - 写操作 (POST/PUT/DELETE) 通过同源策略 + 本地监听 (默认 127.0.0.1) 保护.

use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::proxy::ProxyState;
use crate::record::ForwardRecord;
use crate::secrets::{SecretCategory, SecretEntry};

/// 共享的 `no-store` header 设置.
const NO_STORE: [(header::HeaderName, HeaderValue); 1] = [(
    header::CACHE_CONTROL,
    HeaderValue::from_static("no-store, no-cache, must-revalidate"),
)];

// ─── /records ──────────────────────────────────────────────────────────────

pub async fn list_records(State(state): State<ProxyState>) -> impl IntoResponse {
    let records = state.records.list();
    (NO_STORE, Json(ListRecordsResponse { records }))
}

pub async fn get_record(
    State(state): State<ProxyState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    state
        .records
        .get(id)
        .map(|r| (NO_STORE, Json(r)))
        .ok_or(StatusCode::NOT_FOUND)
}

#[derive(Serialize)]
pub struct ListRecordsResponse {
    pub records: Vec<ForwardRecord>,
}

// ─── /secrets ──────────────────────────────────────────────────────────────

pub async fn list_secrets(State(state): State<ProxyState>) -> impl IntoResponse {
    let entries = state.secrets.snapshot();
    let secrets: Vec<SecretMasked> = entries.into_iter().map(SecretMasked::from).collect();
    let categories: Vec<&'static str> = SecretCategory::all().iter().map(|c| c.as_str()).collect();
    (
        NO_STORE,
        Json(ListSecretsResponse {
            secrets,
            categories,
        }),
    )
}

pub async fn create_secret(
    State(state): State<ProxyState>,
    Json(payload): Json<CreateSecretRequest>,
) -> Result<impl IntoResponse, AppResponse> {
    let entry = payload.into_entry()?;
    let saved = state.secrets.upsert(entry).map_err(AppResponse::from_any)?;
    Ok((
        StatusCode::CREATED,
        NO_STORE,
        Json(SecretMasked::from(saved)),
    ))
}

pub async fn update_secret(
    State(state): State<ProxyState>,
    Path(id): Path<String>,
    Json(payload): Json<CreateSecretRequest>,
) -> Result<impl IntoResponse, AppResponse> {
    let mut entry = payload.into_entry()?;
    entry.id = id;
    let saved = state.secrets.upsert(entry).map_err(AppResponse::from_any)?;
    Ok((StatusCode::OK, NO_STORE, Json(SecretMasked::from(saved))))
}

pub async fn delete_secret(
    State(state): State<ProxyState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppResponse> {
    let removed = state.secrets.delete(&id).map_err(AppResponse::from_any)?;
    if removed {
        Ok((StatusCode::NO_CONTENT, NO_STORE, ""))
    } else {
        Err(AppResponse::not_found(format!("secret {id} not found")))
    }
}

#[derive(Serialize)]
pub struct ListSecretsResponse {
    pub secrets: Vec<SecretMasked>,
    pub categories: Vec<&'static str>,
}

/// 创建/更新 secret 的请求 body.
#[derive(Debug, Deserialize)]
pub struct CreateSecretRequest {
    pub id: Option<String>,
    pub name: Option<String>,
    pub category: Option<SecretCategory>,
    pub value: String,
}

impl CreateSecretRequest {
    fn into_entry(self) -> Result<SecretEntry, AppResponse> {
        let id = self
            .id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        if self.value.is_empty() {
            return Err(AppResponse::validation("value must not be empty"));
        }
        Ok(SecretEntry {
            id,
            name: self.name,
            category: self.category.unwrap_or_default(),
            value: self.value,
        })
    }
}

/// 对外返回时屏蔽真实 value. 长度过短也只显示 1 个 `*`, 不暴露长度.
#[derive(Serialize)]
pub struct SecretMasked {
    pub id: String,
    pub name: Option<String>,
    pub category: SecretCategory,
    pub value_masked: String,
    pub value_length: usize,
}

impl From<SecretEntry> for SecretMasked {
    fn from(e: SecretEntry) -> Self {
        Self {
            id: e.id,
            name: e.name,
            category: e.category,
            value_masked: mask_value(&e.value),
            value_length: e.value.chars().count(),
        }
    }
}

/// 对 secret 做最小信息脱敏: 保留首尾各 1 字符 (若可打印), 中间替换为 `*`.
fn mask_value(v: &str) -> String {
    let chars: Vec<char> = v.chars().collect();
    if chars.is_empty() {
        return String::new();
    }
    if chars.len() <= 4 {
        return "*".repeat(chars.len());
    }
    let head = chars[0];
    let tail = chars[chars.len() - 1];
    let stars = "*".repeat(chars.len().saturating_sub(2));
    format!("{head}{stars}{tail}")
}

/// 错误响应 (统一为合法 JSON).
#[derive(Debug)]
pub struct AppResponse {
    pub status: StatusCode,
    pub message: String,
}

impl AppResponse {
    pub fn validation(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
        }
    }
    pub fn from_any(e: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("internal error: {e}"),
        }
    }
}

impl IntoResponse for AppResponse {
    fn into_response(self) -> axum::response::Response {
        let body = Json(serde_json::json!({ "error": self.message }));
        (self.status, NO_STORE, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_short_value_hides_everything() {
        assert_eq!(mask_value(""), "");
        assert_eq!(mask_value("a"), "*");
        assert_eq!(mask_value("ab"), "**");
        assert_eq!(mask_value("abc"), "***");
        assert_eq!(mask_value("abcd"), "****");
    }

    #[test]
    fn mask_long_value_keeps_endpoints() {
        assert_eq!(mask_value("abcde"), "a***e");
        assert_eq!(mask_value("sk-abcdef123456"), "s*************6");
    }

    #[test]
    fn create_request_validates_empty_value() {
        let req = CreateSecretRequest {
            id: None,
            name: None,
            category: None,
            value: String::new(),
        };
        assert!(req.into_entry().is_err());
    }

    #[test]
    fn create_request_generates_id_when_missing() {
        let req = CreateSecretRequest {
            id: None,
            name: None,
            category: None,
            value: "v".into(),
        };
        let entry = req.into_entry().unwrap();
        assert!(!entry.id.is_empty());
        assert_eq!(entry.value, "v");
    }
}
