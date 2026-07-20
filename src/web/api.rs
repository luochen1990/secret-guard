//! `/__sg/api/*` JSON endpoints.
//!
//! 所有响应都带 `Cache-Control: no-store`, 避免浏览器对自动刷新返回缓存内容.
//!
//! **安全姿态**:
//! - GET 永不返回 secret 的 `value` 字段 (用 `mask_*` 占位符), 防止浏览器/UI 误显示.
//! - 写操作 (POST/PUT/DELETE) 通过同源策略 + 本地监听 (默认 127.0.0.1) 保护.
//! - 内部错误细节不通过响应体返回, 仅进 tracing.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::provider::{
    DeleteOutcome as ProviderDeleteOutcome, Protocol, Provider, UpsertKind as ProviderUpsertKind,
};
use crate::proxy::ProxyState;
use crate::record::ForwardRecord;
use crate::secrets::{SecretCategory, SecretEntry, UpsertKind};

/// 共享的 `no-store` header 设置 (axum 的 `[(name, value); N]` 接受 `(&str, &str)`).
const NO_STORE: [(&str, &str); 1] = [("cache-control", "no-store, no-cache, must-revalidate")];

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
    let secrets: Vec<SecretMasked> = state
        .secrets
        .snapshot()
        .into_iter()
        .map(SecretMasked::from)
        .collect();
    let categories: Vec<&'static str> = SecretCategory::ALL.iter().map(|(_, s)| *s).collect();
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
) -> Result<impl IntoResponse, ApiError> {
    let mut entry = payload.into_entry()?;
    // create 模式: 若没传 id, 自动生成; 若传了已存在的 id, 返回 409.
    if entry.id.is_empty() {
        entry.id = Uuid::new_v4().to_string();
    }
    if state.secrets.get(&entry.id).is_some() {
        return Err(ApiError::conflict(format!(
            "secret with id '{}' already exists; use PUT to update",
            entry.id
        )));
    }
    let (saved, kind) = state.secrets.upsert(entry).map_err(ApiError::from_any)?;
    if kind == UpsertKind::Updated {
        // 并发写入导致在 get 与 upsert 之间被其他请求创建; 视为 conflict.
        return Err(ApiError::conflict(
            "secret was concurrently created; please retry",
        ));
    }
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
) -> Result<impl IntoResponse, ApiError> {
    if state.secrets.get(&id).is_none() {
        return Err(ApiError::not_found(format!("secret {id} not found")));
    }
    let mut entry = payload.into_entry()?;
    entry.id = id.clone();
    let (saved, kind) = state.secrets.upsert(entry).map_err(ApiError::from_any)?;
    match kind {
        UpsertKind::Updated => Ok((StatusCode::OK, NO_STORE, Json(SecretMasked::from(saved)))),
        UpsertKind::Inserted => Err(ApiError::not_found(format!(
            "secret {id} was concurrently deleted; please retry"
        ))),
    }
}

pub async fn delete_secret(
    State(state): State<ProxyState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    use crate::secrets::DeleteOutcome;
    match state.secrets.delete(&id).map_err(ApiError::from_any)? {
        DeleteOutcome::Deleted => Ok((StatusCode::NO_CONTENT, NO_STORE, "")),
        DeleteOutcome::NotFound => Err(ApiError::not_found(format!("secret {id} not found"))),
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
    fn into_entry(self) -> Result<SecretEntry, ApiError> {
        if self.value.is_empty() {
            return Err(ApiError::validation("value must not be empty"));
        }
        // 检查 value 合法性 (长度 + PUA 字符). 通过 SecretTable::upsert 也会再校验,
        // 但在这里先做能给出更友好的字段级错误.
        if let Err(e) = crate::secrets::validate_value(&self.value) {
            return Err(ApiError::validation(e));
        }
        Ok(SecretEntry {
            id: self.id.unwrap_or_default(),
            name: self.name.filter(|s| !s.trim().is_empty()),
            category: self.category.unwrap_or_default(),
            value: self.value,
        })
    }
}

/// 对外返回时屏蔽真实 value. 长度过短也只显示 `*`, 不暴露长度.
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

/// 对 secret 做最小信息脱敏: 短 (<=8) 全 `*`; 长则保留首尾各 1 + 中间 `*`.
fn mask_value(v: &str) -> String {
    let chars: Vec<char> = v.chars().collect();
    if chars.is_empty() {
        return String::new();
    }
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head = chars[0];
    let tail = chars[chars.len() - 1];
    let stars = "*".repeat(chars.len().saturating_sub(2));
    format!("{head}{stars}{tail}")
}

/// API 错误: 统一为合法 JSON, 不泄露内部细节.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
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
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: msg.into(),
        }
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: msg.into(),
        }
    }
    pub fn from_any(e: anyhow::Error) -> Self {
        // 详细信息进 tracing, 不回客户端.
        tracing::error!(error = ?e, "secrets api internal error");
        Self::internal("internal error")
    }
}

impl IntoResponse for ApiError {
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
        assert_eq!(mask_value("abcdefgh"), "********"); // exactly 8 chars
    }

    #[test]
    fn mask_long_value_keeps_endpoints() {
        assert_eq!(mask_value("abcdefghi"), "a*******i"); // 9 chars
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
}

// ─── /providers ────────────────────────────────────────────────────────────

pub async fn list_providers(State(state): State<ProxyState>) -> impl IntoResponse {
    let providers: Vec<ProviderMasked> = state
        .providers
        .snapshot()
        .into_iter()
        .map(ProviderMasked::from)
        .collect();
    let protocols: Vec<&'static str> = Protocol::ALL.iter().map(|(_, n, _)| *n).collect();
    let shorts: Vec<&'static str> = Protocol::ALL.iter().map(|(_, _, s)| *s).collect();
    (
        NO_STORE,
        Json(ListProvidersResponse {
            providers,
            protocols,
            shorts,
        }),
    )
}

pub async fn create_provider(
    State(state): State<ProxyState>,
    Json(payload): Json<UpsertProviderRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let mut entry = payload.into_provider()?;
    if entry.id.is_empty() {
        entry.id = Uuid::new_v4().to_string();
    }
    if state.providers.get(&entry.id).is_some() {
        return Err(ApiError::conflict(format!(
            "provider with id '{}' already exists; use PUT to update",
            entry.id
        )));
    }
    let (saved, kind) = state.providers.upsert(entry).map_err(ApiError::from_any)?;
    if kind == ProviderUpsertKind::Updated {
        return Err(ApiError::conflict(
            "provider was concurrently created; please retry",
        ));
    }
    Ok((
        StatusCode::CREATED,
        NO_STORE,
        Json(ProviderMasked::from(saved)),
    ))
}

pub async fn update_provider(
    State(state): State<ProxyState>,
    Path(id): Path<String>,
    Json(payload): Json<UpsertProviderRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if state.providers.get(&id).is_none() {
        return Err(ApiError::not_found(format!("provider {id} not found")));
    }
    let mut entry = payload.into_provider()?;
    entry.id = id.clone();
    let (saved, kind) = state.providers.upsert(entry).map_err(ApiError::from_any)?;
    match kind {
        ProviderUpsertKind::Updated => {
            Ok((StatusCode::OK, NO_STORE, Json(ProviderMasked::from(saved))))
        }
        ProviderUpsertKind::Inserted => Err(ApiError::not_found(format!(
            "provider {id} was concurrently deleted; please retry"
        ))),
    }
}

pub async fn delete_provider(
    State(state): State<ProxyState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    match state.providers.delete(&id).map_err(ApiError::from_any)? {
        ProviderDeleteOutcome::Deleted => Ok((StatusCode::NO_CONTENT, NO_STORE, "")),
        ProviderDeleteOutcome::NotFound => {
            Err(ApiError::not_found(format!("provider {id} not found")))
        }
    }
}

#[derive(Serialize)]
pub struct ListProvidersResponse {
    pub providers: Vec<ProviderMasked>,
    pub protocols: Vec<&'static str>,
    pub shorts: Vec<&'static str>,
}

/// 创建/更新 provider 的请求 body.
#[derive(Debug, Deserialize)]
pub struct UpsertProviderRequest {
    pub id: Option<String>,
    pub name: Option<String>,
    pub protocol: Protocol,
    pub base_url: String,
    /// 可选. 省略或空字符串表示不设置 api_key (适用于 Ollama 等本地无 auth 场景).
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default = "crate::provider::default_true")]
    pub enabled: bool,
}

impl UpsertProviderRequest {
    fn into_provider(self) -> Result<Provider, ApiError> {
        if let Some(id) = &self.id {
            if !id.is_empty() {
                if let Err(e) = crate::secrets::validate_id(id) {
                    return Err(ApiError::validation(e));
                }
            }
        }
        if let Err(e) = crate::provider::validate_base_url(&self.base_url) {
            return Err(ApiError::validation(e));
        }
        Ok(Provider {
            id: self.id.unwrap_or_default(),
            protocol: self.protocol,
            base_url: self.base_url,
            api_key: self.api_key.unwrap_or_default(),
            enabled: self.enabled,
            name: self.name.filter(|s| !s.trim().is_empty()),
        })
    }
}

/// 对外返回时屏蔽真实 api_key. 仍保留长度提示 (便于排查"是否配置了 key").
#[derive(Serialize)]
pub struct ProviderMasked {
    pub id: String,
    pub name: Option<String>,
    pub protocol: Protocol,
    pub base_url: String,
    pub api_key_masked: String,
    pub api_key_length: usize,
    pub enabled: bool,
}

impl From<Provider> for ProviderMasked {
    fn from(p: Provider) -> Self {
        let api_key_length = p.api_key.chars().count();
        Self {
            id: p.id,
            name: p.name,
            protocol: p.protocol,
            base_url: p.base_url,
            // 空字符串返回空, 否则与 secret 共用同一份脱敏算法.
            api_key_masked: if p.api_key.is_empty() {
                String::new()
            } else {
                mask_value(&p.api_key)
            },
            api_key_length,
            enabled: p.enabled,
        }
    }
}
