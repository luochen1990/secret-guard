//! `/__sg/api/*` JSON endpoints.
//!
//! 所有响应都带 `Cache-Control: no-store`, 避免浏览器对自动刷新返回缓存内容.
//!
//! # 数据流
//!
//! - `GET /secrets` / `GET /providers` 返回 **effective** (static+dynamic+decision 合并后)
//!   的视图, 每个 item 同时携带 provenance (static/dynamic/override 标签) 与原始 static /
//!   dynamic 版本. UI 基于此渲染只读 / 可编辑 / 可切换状态.
//! - `POST / PUT / DELETE` 操作 **dynamic** 层. static 永远不可写.
//!   编辑 static-only id 时, 服务端自动 fork 一份 dynamic override (符合 git-style 心智模型).
//! - `PATCH /{id}/decision` 切换对 static id 的 per-item 决策
//!   (Default / PreferStatic / Disabled).
//!
//! # 安全姿态
//!
//! - GET 永不返回 secret 的 `value` / provider 的 `api_key` 真实值 (用 [`mask_value`] 占位).
//! - 写操作通过同源策略 + 本地监听 (默认 127.0.0.1) 保护.
//! - 内部错误细节不通过响应体返回, 仅进 tracing.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{DeleteOutcome, OverrideMode, UpsertKind};
use crate::provider::{EffectiveProvider, Protocol, Provider};
use crate::proxy::ProxyState;
use crate::record::ForwardRecord;
use crate::secrets::{EffectiveSecret, SecretCategory, SecretEntry};

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
    let secrets: Vec<EffectiveSecret> = state.secrets.effective_snapshot();
    let categories: Vec<&'static str> = SecretCategory::ALL.iter().map(|(_, s)| *s).collect();
    let decisions: Vec<&'static str> = OverrideMode::ALL.iter().map(|(_, s)| *s).collect();
    (
        NO_STORE,
        Json(ListSecretsResponse {
            secrets,
            categories,
            decisions,
        }),
    )
}

pub async fn create_secret(
    State(state): State<ProxyState>,
    Json(payload): Json<CreateSecretRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let mut entry = payload.into_entry()?;
    // create 模式: 若没传 id, 自动生成.
    if entry.id.is_empty() {
        entry.id = Uuid::new_v4().to_string();
    }
    // 完整 validate+resolve 序列 (互斥 / 文件可读 / value 内容合法).
    // 必须在 upsert 前跑: 否则内存中 value 为空 (value_file 模式), 当次 redact 不识别此 secret.
    // 也是 WebUI 路径上互斥校验的执行点 (见 into_entry 的注释 — 那里只做基础字段校验).
    entry.validate_and_resolve().map_err(ApiError::validation)?;
    // 检查 effective view 中是否已存在 (含 static 来源). 不允许覆盖 static 创建同 id.
    if state
        .secrets
        .effective_snapshot()
        .iter()
        .any(|s| s.id == entry.id)
    {
        return Err(ApiError::conflict(format!(
            "secret with id '{}' already exists (in static or dynamic); use PUT to override",
            entry.id
        )));
    }
    let (saved, kind) = state
        .secrets
        .upsert_dynamic(entry)
        .map_err(ApiError::from_any)?;
    if kind == UpsertKind::Updated {
        // 并发写入导致在 check 与 upsert 之间被其他请求创建; 视为 conflict.
        return Err(ApiError::conflict(
            "secret was concurrently created; please retry",
        ));
    }
    // upsert_dynamic 不返回 effective 视图, 这里再查一次给前端 (低成本, 创建场景罕见).
    let ev = state
        .secrets
        .effective_snapshot()
        .into_iter()
        .find(|s| s.id == saved.id)
        .expect("just upserted");
    Ok((StatusCode::CREATED, NO_STORE, Json(ev)))
}

pub async fn update_secret(
    State(state): State<ProxyState>,
    Path(id): Path<String>,
    Json(payload): Json<CreateSecretRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // 允许编辑 static-only id: 服务端自动 fork 出 dynamic override.
    // 但若 id 完全不存在 (effective 中查不到), 返回 404.
    let exists = state
        .secrets
        .effective_snapshot()
        .iter()
        .any(|s| s.id == id);
    if !exists {
        return Err(ApiError::not_found(format!("secret {id} not found")));
    }
    let mut entry = payload.into_entry()?;
    entry.id = id.clone();
    // 完整 validate+resolve 序列, 与 create_secret 一致 (见那里的注释).
    entry.validate_and_resolve().map_err(ApiError::validation)?;
    let (saved, _kind) = state
        .secrets
        .upsert_dynamic(entry)
        .map_err(ApiError::from_any)?;
    let ev = state
        .secrets
        .effective_snapshot()
        .into_iter()
        .find(|s| s.id == saved.id)
        .expect("just upserted");
    Ok((StatusCode::OK, NO_STORE, Json(ev)))
}

pub async fn delete_secret(
    State(state): State<ProxyState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // 若 dynamic 有此 id, 删除 (覆盖关系下仅移除 override, static 保留).
    // 若 dynamic 无此 id 但 static 有, 拒绝删除 (static 永不可写; 提示用 disabled decision).
    // 用 has_static 直接查 static 层, 不受 decision 影响 (disabled 的 id 也能正确报 409).
    match state
        .secrets
        .delete_dynamic(&id)
        .map_err(ApiError::from_any)?
    {
        DeleteOutcome::Deleted => Ok((StatusCode::NO_CONTENT, NO_STORE, "")),
        DeleteOutcome::NotFound => {
            if state.secrets.has_static(&id) {
                Err(ApiError::conflict(
                    "cannot delete a static secret; use PATCH .../decision with \
                     {\"mode\":\"disabled\"} to disable it",
                ))
            } else {
                Err(ApiError::not_found(format!("secret {id} not found")))
            }
        }
    }
}

/// 切换对 static id 的 per-item 决策. body: `{"mode": "default|prefer_static|disabled"}`.
///
/// 响应体是简短 ack (`{id, decision}`), 不返回 effective view — 因为切换到 `Disabled`
/// 后该 id 会从 effective view 中消失, 前端应在收到 200 后重新调 list 拉新状态.
///
/// 用 [`crate::secrets::SecretTable::has_static`] 直接查 static 层, 这样
/// decision=Disabled 状态下也能切回 Default / PreferStatic.
///
/// 注: `SecretTable` 现为 `DynamicTable<SecretEntry>` 的别名, has_static 是
/// 泛型 [`DynamicTable::has_static`](crate::config::DynamicTable) 提供的方法.
pub async fn set_secret_decision(
    State(state): State<ProxyState>,
    Path(id): Path<String>,
    Json(payload): Json<DecisionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let mode = payload.into_mode()?;
    if !state.secrets.has_static(&id) {
        return Err(ApiError::not_found(format!(
            "secret {id} is not a static id; decision does not apply"
        )));
    }
    state
        .secrets
        .set_decision(&id, mode)
        .map_err(ApiError::from_any)?;
    Ok((
        StatusCode::OK,
        NO_STORE,
        Json(DecisionAck {
            id,
            resource: "secret",
            decision: mode,
        }),
    ))
}

#[derive(Serialize)]
pub struct ListSecretsResponse {
    pub secrets: Vec<EffectiveSecret>,
    pub categories: Vec<&'static str>,
    /// 所有合法的 OverrideMode 字符串名, 供前端渲染 decision 选择器.
    pub decisions: Vec<&'static str>,
}

/// 创建/更新 secret 的请求 body.
#[derive(Debug, Deserialize)]
pub struct CreateSecretRequest {
    pub id: Option<String>,
    pub name: Option<String>,
    pub category: Option<SecretCategory>,
    /// 直接值. 与 `value_file` 互斥 (同时设置会在 `validate()` 报错).
    /// WebUI 默认用此字段 (用户手填); 留空且提供了 `value_file` 则走文件读取模式.
    #[serde(default)]
    pub value: String,
    /// 可选: 从文件路径读取 secret 明文. 与 `value` 互斥.
    /// 主要用于 static config (sops 注入), WebUI 创建 dynamic-only secret 时一般不用,
    /// 但保留字段以支持 "dynamic secret 引用 sops 解密路径" 的高级用例.
    #[serde(default)]
    pub value_file: Option<String>,
}

impl CreateSecretRequest {
    fn into_entry(self) -> Result<SecretEntry, ApiError> {
        // 早期字段级反馈: value 与 value_file 至少一个非空. 互斥校验和 value 内容校验
        // 由后续 handler 中的 SecretEntry::validate_and_resolve 统一执行 (SSOT).
        if self.value.is_empty() && self.value_file.is_none() {
            return Err(ApiError::validation(
                "either value or value_file must be set",
            ));
        }
        Ok(SecretEntry {
            id: self.id.unwrap_or_default(),
            name: self.name.filter(|s| !s.trim().is_empty()),
            category: self.category.unwrap_or_default(),
            value: self.value,
            value_file: self.value_file.map(std::path::PathBuf::from),
        })
    }
}

// ─── /providers ────────────────────────────────────────────────────────────

pub async fn list_providers(State(state): State<ProxyState>) -> impl IntoResponse {
    let providers: Vec<EffectiveProvider> = state.providers.effective_snapshot();
    let protocols: Vec<&'static str> = Protocol::ALL.iter().map(|(_, n, _)| *n).collect();
    let shorts: Vec<&'static str> = Protocol::ALL.iter().map(|(_, _, s)| *s).collect();
    let decisions: Vec<&'static str> = OverrideMode::ALL.iter().map(|(_, s)| *s).collect();
    (
        NO_STORE,
        Json(ListProvidersResponse {
            providers,
            protocols,
            shorts,
            decisions,
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
    // 不允许创建与 static id 冲突的新 provider (要 override 必须走 PUT 走 fork 流程).
    if state
        .providers
        .effective_snapshot()
        .iter()
        .any(|p| p.id == entry.id)
    {
        return Err(ApiError::conflict(format!(
            "provider with id '{}' already exists (in static or dynamic); use PUT to override",
            entry.id
        )));
    }
    let (saved, kind) = state
        .providers
        .upsert_dynamic(entry)
        .map_err(ApiError::from_any)?;
    if kind == UpsertKind::Updated {
        return Err(ApiError::conflict(
            "provider was concurrently created; please retry",
        ));
    }
    let ev = state
        .providers
        .effective_snapshot()
        .into_iter()
        .find(|p| p.id == saved.id)
        .expect("just upserted");
    Ok((StatusCode::CREATED, NO_STORE, Json(ev)))
}

pub async fn update_provider(
    State(state): State<ProxyState>,
    Path(id): Path<String>,
    Json(payload): Json<UpsertProviderRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // 允许编辑 static-only id: 服务端自动 fork.
    let exists = state
        .providers
        .effective_snapshot()
        .iter()
        .any(|p| p.id == id);
    if !exists {
        return Err(ApiError::not_found(format!("provider {id} not found")));
    }
    let mut entry = payload.into_provider()?;
    entry.id = id.clone();
    let (saved, _kind) = state
        .providers
        .upsert_dynamic(entry)
        .map_err(ApiError::from_any)?;
    let ev = state
        .providers
        .effective_snapshot()
        .into_iter()
        .find(|p| p.id == saved.id)
        .expect("just upserted");
    Ok((StatusCode::OK, NO_STORE, Json(ev)))
}

pub async fn delete_provider(
    State(state): State<ProxyState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    match state
        .providers
        .delete_dynamic(&id)
        .map_err(ApiError::from_any)?
    {
        DeleteOutcome::Deleted => Ok((StatusCode::NO_CONTENT, NO_STORE, "")),
        DeleteOutcome::NotFound => {
            if state.providers.has_static(&id) {
                Err(ApiError::conflict(
                    "cannot delete a static provider; use PATCH .../decision with \
                     {\"mode\":\"disabled\"} to disable it",
                ))
            } else {
                Err(ApiError::not_found(format!("provider {id} not found")))
            }
        }
    }
}

/// 切换对 static id 的 per-item 决策. 同 [`set_secret_decision`].
pub async fn set_provider_decision(
    State(state): State<ProxyState>,
    Path(id): Path<String>,
    Json(payload): Json<DecisionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let mode = payload.into_mode()?;
    if !state.providers.has_static(&id) {
        return Err(ApiError::not_found(format!(
            "provider {id} is not a static id; decision does not apply"
        )));
    }
    state
        .providers
        .set_decision(&id, mode)
        .map_err(ApiError::from_any)?;
    Ok((
        StatusCode::OK,
        NO_STORE,
        Json(DecisionAck {
            id,
            resource: "provider",
            decision: mode,
        }),
    ))
}

/// `PATCH /{id}/decision` 的 ack 响应.
#[derive(Serialize)]
pub struct DecisionAck {
    pub id: String,
    /// "provider" | "secret" — 前端可用于校验是否返回了正确资源类型.
    pub resource: &'static str,
    pub decision: OverrideMode,
}

#[derive(Serialize)]
pub struct ListProvidersResponse {
    pub providers: Vec<EffectiveProvider>,
    pub protocols: Vec<&'static str>,
    pub shorts: Vec<&'static str>,
    pub decisions: Vec<&'static str>,
}

/// 创建/更新 provider 的请求 body.
#[derive(Debug, Deserialize)]
pub struct UpsertProviderRequest {
    pub id: Option<String>,
    pub name: Option<String>,
    pub protocol: Protocol,
    pub base_url: String,
    /// 可选. 省略或空字符串表示不设置 api_key (适用于 Ollama 等本地无 auth 场景).
    /// 与 `api_key_file` 互斥 (同时设置会在 `validate()` 报错).
    #[serde(default)]
    pub api_key: Option<String>,
    /// 可选: 从文件路径读取 api_key. 与 `api_key` 互斥.
    /// WebUI 创建 dynamic-only provider 时可用, 但通常只在 static config (sops 注入) 用.
    #[serde(default)]
    pub api_key_file: Option<String>,
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
            api_key_file: self.api_key_file.map(std::path::PathBuf::from),
            enabled: self.enabled,
            name: self.name.filter(|s| !s.trim().is_empty()),
        })
    }
}

/// `PATCH /{id}/decision` 的请求 body.
#[derive(Debug, Deserialize)]
pub struct DecisionRequest {
    pub mode: String,
}

impl DecisionRequest {
    fn into_mode(self) -> Result<OverrideMode, ApiError> {
        OverrideMode::parse(&self.mode).ok_or_else(|| {
            ApiError::validation(format!(
                "unknown decision mode '{}' (expected one of: default, prefer_static, disabled)",
                self.mode
            ))
        })
    }
}

// ─── Error ────────────────────────────────────────────────────────────────

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
        tracing::error!(error = ?e, "api internal error");
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
    fn create_request_validates_empty_value() {
        let req = CreateSecretRequest {
            id: None,
            name: None,
            category: None,
            value: String::new(),
            value_file: None,
        };
        assert!(req.into_entry().is_err());
    }

    #[test]
    fn create_request_into_entry_does_not_check_mutex() {
        // into_entry 故意不做互斥校验 (由 SecretEntry::validate_and_resolve 在 handler 层做, SSOT).
        // 这里断言此契约: 同时填 value + value_file 时 into_entry 仍然成功,
        // 把校验责任显式交给后续 validate_and_resolve.
        let req = CreateSecretRequest {
            id: Some("x".into()),
            name: None,
            category: None,
            value: "direct-value".into(),
            value_file: Some("/some/path".into()),
        };
        let entry = req.into_entry().expect("into_entry skips mutex check");
        // 但 SecretEntry::validate_and_resolve 必须拒绝此组合.
        let mut entry = entry;
        let err = entry.validate_and_resolve().unwrap_err();
        assert!(
            err.contains("both value and value_file"),
            "validate_and_resolve should reject mutex violation: {err}"
        );
    }

    #[test]
    fn decision_request_parses_valid_modes() {
        for (_, name) in OverrideMode::ALL {
            let req = DecisionRequest {
                mode: name.to_string(),
            };
            assert!(req.into_mode().is_ok());
        }
    }

    #[test]
    fn decision_request_rejects_unknown_mode() {
        let req = DecisionRequest {
            mode: "bogus".to_string(),
        };
        assert!(req.into_mode().is_err());
    }
}
