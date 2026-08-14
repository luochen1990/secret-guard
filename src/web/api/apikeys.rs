//! API key CRUD: `GET/POST/DELETE /api-keys[/{id}]` + `PATCH /{id}/toggle`.
//!
//! 从 api.rs 单文件拆出 (见 #146 残留 1). 无条件挂载 (在 `web::router()`, 不依赖
//! `auth.enabled`), 不做用户隔离 — "只认证, 不隔离" 哲学.
//!
//! 设计权衡: 即便 `auth.enabled = false` (单用户模式) 也允许签发和管理 key,
//! 用户可以提前配置好 key, 等启用 auth 后即可使用. 因为 forwarding 路径的
//! `require_api_key` middleware 在 auth 关闭时不挂载, 这些 key 此时无消费方,
//! 但数据持久化在 state.toml, 不会丢失.
//!
//! 隔离的代价 vs 收益: per-user tenant_id 隔离在多用户共享一个 secret-guard 实例的场景
//! 才有价值. secret-guard 的部署形态主要是个人本地网关, 多用户场景下用户之间本身就是
//! 高度互信 (同一团队/家庭), 引入 tenant_id 隔离反而让"用户 A 签发的 key 用户 B 看不到"
//! 这种割裂体验成为常态. 移除后, 所有 (登录的) 用户共享同一份 key 池.
//!
//! tenant_id / created_by 字段保留 (兼容已有持久化数据), 但统一填 "admin" 占位值.
//! 这些字段当前不影响任何业务逻辑 (lookup 不读 tenant_id).
//!
//! # auth_enabled 与 key 三态
//!
//! `list_api_keys` 响应附带 `auth_enabled` (见 [`ListApiKeysResponse`]). 前端据此把
//! key 渲染为三态:
//!   - auth_enabled = true  + disabled = false → "enabled"  (启用中, 实际生效)
//!   - auth_enabled = true  + disabled = true  → "disabled" (用户主动禁用)
//!   - auth_enabled = false (不论 disabled)    → "inactive" (认证未启用, 无消费方)
//!
//! 第三态存在的理由: auth 关闭时 forwarding 路径根本不挂 require_api_key middleware,
//! 此时即便 key.disabled = false, 所有请求也都会被无条件接受, key 形同虚设.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::auth::apikey::ApiKeySummary;
use crate::state::{AppState, NO_STORE};

use super::error::ApiError;

#[derive(Debug, Deserialize)]
pub(crate) struct CreateApiKeyRequest {
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ToggleApiKeyRequest {
    pub disabled: bool,
}

/// `/api/api-keys` 列表响应. 与 `ListSecretsResponse` / `ListProvidersResponse` 同风格.
#[derive(Serialize)]
pub(crate) struct ListApiKeysResponse {
    pub keys: Vec<ApiKeySummary>,
    /// 来自 static config `[auth] enabled`. false = forwarding 路径未挂 require_api_key
    /// middleware, 前端据此把所有 key 渲染为 inactive 第三态.
    pub auth_enabled: bool,
}

/// 列出所有 key (静态 + 动态), 不按用户过滤. 响应附带 `auth_enabled` (见 struct 注释).
pub async fn list_api_keys(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let api_keys = &state.api_keys;
    Ok((
        NO_STORE,
        Json(ListApiKeysResponse {
            keys: api_keys.list(),
            auth_enabled: state.auth_enabled,
        }),
    ))
}

pub async fn create_api_key(
    State(state): State<AppState>,
    Json(payload): Json<CreateApiKeyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let api_keys = &state.api_keys;
    // tenant_id / created_by 用 "admin" 占位 — 不隔离, 字段仅作展示和审计保留.
    let issued = api_keys
        .issue("admin", "admin", &payload.label)
        .map_err(ApiError::from_any)?;
    Ok((StatusCode::CREATED, NO_STORE, Json(issued)))
}

/// 删除 (仅动态 key). 静态 key 返回 409 Conflict; 不存在返回 404 (与 toggle 对齐).
pub async fn delete_api_key(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let api_keys = &state.api_keys;
    // 提前检查 static: 把 revoke 内部的 anyhow::bail! 映射为 409 conflict
    // (否则 from_any 会把它当作 500 internal error).
    if crate::auth::apikey::is_static(&id) {
        return Err(ApiError::conflict(
            "static API key cannot be deleted; use disable instead",
        ));
    }
    let deleted = api_keys.revoke(&id).map_err(ApiError::from_any)?;
    if !deleted {
        return Err(ApiError::not_found(format!("API key {id} not found")));
    }
    Ok((StatusCode::NO_CONTENT, NO_STORE, ""))
}

/// 切换 disabled 状态.
///
/// 静态 / 动态 key 均可 toggle (与 delete 不同 — delete 对 static 短路返回 409).
/// 原因: set_disabled 对 static / dynamic 一视同仁, 不会 bail!.
pub async fn toggle_api_key(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<ToggleApiKeyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let api_keys = &state.api_keys;
    // 用 store 实际落库的值响应 (严格反映服务端状态, 而非回声请求).
    let disabled = api_keys
        .set_disabled(&id, payload.disabled)
        .map_err(ApiError::from_any)?
        .ok_or_else(|| ApiError::not_found(format!("API key {id} not found")))?;
    Ok((
        NO_STORE,
        Json(serde_json::json!({ "id": id, "disabled": disabled })),
    ))
}
