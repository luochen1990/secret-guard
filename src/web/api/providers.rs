//! providers CRUD: `GET/POST/PUT/DELETE /providers[/{id}]` + `PATCH /{id}/decision`.
//!
//! 从 api.rs 单文件拆出 (见 #146 残留 1). CRUD 流程骨架在 [`super::crud`]
//! (泛型, 与 secrets 共享), 本文件只承载 provider 特有的 entry 构造 / api_key
//! 保留逻辑 / 列表附加字段 (protocols/shorts).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::config::OverrideMode;
use crate::provider::{EffectiveProvider, Protocol, Provider};
use crate::state::{AppState, NO_STORE};

use super::crud::{Created, DecisionRequest, decision_flow};
use super::crud::{create_flow, delete_flow, update_flow};
use super::error::ApiError;

pub async fn list_providers(State(state): State<AppState>) -> impl IntoResponse {
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
    State(state): State<AppState>,
    Json(payload): Json<UpsertProviderRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let created: Created<EffectiveProvider> = create_flow(
        &state.providers,
        "provider",
        || payload.into_provider(),
        |_| Ok(()), // provider 无 secret 式的 resolve 钩子 (validate 在 upsert 内).
    )?;
    Ok((StatusCode::CREATED, NO_STORE, Json(created)))
}

pub async fn update_provider(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(mut payload): Json<UpsertProviderRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let ev = update_flow(
        &state.providers,
        "provider",
        &id,
        || {
            // api_key / api_key_file 缺省时保留旧值 (避免 WebUI 编辑表单留空意外清空既有 key).
            // 语义: payload None = 保留; Some(s) (含空串) = 显式覆盖.
            // 取旧值用 get_effective (返回未脱敏的原始 Provider, 路由层同款).
            //
            // 假设: 本地单用户场景, get_effective 与 upsert_dynamic 之间无并发修改.
            // 多用户/并发编辑场景下存在 TOCTOU (旧值可能过期), 但仅导致配置不一致, 无安全影响.
            //
            // 限制: 若 payload 显式提供 api_key (或 api_key_file), 另一字段仍从旧值保留,
            // 可能触发互斥校验报错 (例如旧值有 api_key, 新传 api_key_file). WebUI 不暴露
            // api_key_file 输入, 仅 SDK 直接调用可能触发, 影响低.
            if let Some(old) = state.providers.get_effective(&id) {
                if payload.api_key.is_none() {
                    payload.api_key = Some(old.api_key);
                }
                if payload.api_key_file.is_none() {
                    payload.api_key_file =
                        old.api_key_file.map(|p| p.to_string_lossy().into_owned());
                }
            }
            payload.into_provider()
        },
        |_| Ok(()),
    )?;
    Ok((StatusCode::OK, NO_STORE, Json(ev)))
}

pub async fn delete_provider(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    delete_flow(&state.providers, "provider", &id)?;
    Ok((StatusCode::NO_CONTENT, NO_STORE, ""))
}

/// 切换对 static id 的 per-item 决策. 同 [`super::secrets::set_secret_decision`].
pub async fn set_provider_decision(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<DecisionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let mode = payload.into_mode()?;
    let ack = decision_flow(&state.providers, "provider", id, mode)?;
    Ok((StatusCode::OK, NO_STORE, Json(ack)))
}

#[derive(Serialize)]
pub(crate) struct ListProvidersResponse {
    pub providers: Vec<EffectiveProvider>,
    pub protocols: Vec<&'static str>,
    pub shorts: Vec<&'static str>,
    pub decisions: Vec<&'static str>,
}

/// 创建/更新 provider 的请求 body.
#[derive(Debug, Deserialize)]
pub(crate) struct UpsertProviderRequest {
    pub id: Option<String>,
    pub name: Option<String>,
    pub protocol: Protocol,
    pub base_url: String,
    /// API key 明文值. 语义因 endpoint 而异:
    /// - POST (create): 省略 (None) 或空串 = 不设置 (适用 Ollama 等本地无 auth 场景).
    /// - PUT (update): 省略 (None) = 保留旧值; 空串或具体值 = 显式覆盖.
    ///
    /// WebUI 编辑表单依赖此语义: 用户留空 input 时前端发 null, 不破坏既有 key.
    /// 与 `api_key_file` 互斥 (同时设置会在 `validate()` 报错).
    #[serde(default)]
    pub api_key: Option<String>,
    /// 从文件路径读取 api_key. PUT 时若省略 (None) 则保留旧值, 同 `api_key`.
    /// 与 `api_key` 互斥. WebUI 创建 dynamic-only provider 时可用,
    /// 但通常只在 static config (sops 注入) 用.
    #[serde(default)]
    pub api_key_file: Option<String>,
    #[serde(default = "crate::provider::default_true")]
    pub enabled: bool,
}

impl UpsertProviderRequest {
    fn into_provider(self) -> Result<Provider, ApiError> {
        if let Some(id) = &self.id
            && !id.is_empty()
            && let Err(e) = crate::secrets::validate_id(id)
        {
            return Err(ApiError::validation(e));
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
