//! providers CRUD: `GET/POST/PUT/DELETE /providers[/{id}]` + `PATCH /{id}/decision`.
//!
//! 从 api.rs 单文件拆出 (见 #146 残留 1). CRUD 流程骨架在 [`super::crud`]
//! (泛型, 与 secrets 共享), 本文件只承载 provider 特有的 entry 构造 / api_key
//! 保留逻辑 / 列表附加字段 (protocols/shorts).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::config::DynamicEntry;
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
        // #179: upsert 后 route_to 链成环 → 400 (自环已由 Provider::validate 拒绝,
        // 这里覆盖跨条目环; 悬空目标放行 — 创建顺序无关, 运行时 503 兜底).
        |entry| validate_provider_upsert(&state.providers, entry),
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
            // 语义: payload None = 保留; Some(s) = 显式覆盖 (static 基线下空串的清空
            // 语义有已知限制, 见下方 api_key 字段注释).
            //
            // #157 关键: 只从 **dynamic 原始条目** (get_dynamic) 回填, 不用 get_effective.
            // 旧值若是 static 来源, 把已 resolve 的明文搬进 override 会让明文落盘
            // state.toml; 现在改为 override 不记录该字段 (None), effective 解析时由
            // `Provider::inherit_from_static` 回落 static (转发仍带旧 key, 行为不变).
            //
            // 假设: 本地单用户场景, get_dynamic 与 upsert_dynamic 之间无并发修改.
            // 多用户/并发编辑场景下存在 TOCTOU (旧值可能过期), 但仅导致配置不一致, 无安全影响.
            //
            // 限制: 若 payload 显式提供 api_key (或 api_key_file), 另一字段仍从旧值保留,
            // 可能触发互斥校验报错 (例如旧值有 api_key, 新传 api_key_file). WebUI 不暴露
            // api_key_file 输入, 仅 SDK 直接调用可能触发, 影响低.
            if let Some(old) = state.providers.get_dynamic(&id) {
                // "保留旧值" 回填, 按旧值的构造分派 (sum type 同构, #187):
                // Direct 旧值 → 鉴权字段回填; Virtual 旧值 → 指向回填.
                // 显式清空/切换由 WebUI 发 "" / "target-id" 表达 (见下方字段注释).
                match &old.kind {
                    crate::provider::ProviderKind::Direct(d) => {
                        if payload.api_key.is_none() {
                            payload.api_key = Some(d.api_key.clone());
                        }
                        if payload.api_key_file.is_none() {
                            payload.api_key_file = d
                                .api_key_file
                                .as_ref()
                                .map(|p| p.to_string_lossy().into_owned());
                        }
                    }
                    crate::provider::ProviderKind::Virtual(v) => {
                        // payload 省略 (None) = 保留旧指向; "" = 改回实体 (#187 根治).
                        // 守卫对象是 payload 的显式新值 (客户端发新目标时不被旧值覆盖).
                        if payload.route_to.is_none() {
                            payload.route_to = Some(v.route_to.clone());
                        }
                    }
                }
                // model_override 同 "保留" 语义 (#183), 与构造无关.
                if payload.model_override.is_none() {
                    payload.model_override = old.model_override;
                }
            }
            // protocol 回填 (#190 保留语义): 从 **effective** 的 Direct 负载回填 —
            // 覆盖 static-only 条目 (get_dynamic 无旧值的场景, PUT 即首次 override)。
            // 非敏感字段, 无 #157 明文落盘顾虑。守卫: 仅 **Direct 意图** 回填
            // (route_to 非空 = Virtual 意图 — 顺带持久化旧 protocol 会让列表 pill
            // 显示误导性协议); Virtual effective 无 Direct 负载可挖 → 不回填,
            // payload 要 Direct 又没带 → into_provider 400 兜底。
            let virtual_intent = matches!(&payload.route_to, Some(s) if !s.is_empty());
            if payload.protocol.is_none() && !virtual_intent {
                let eff = state.providers.get_effective(&id);
                if let Some(crate::provider::ProviderKind::Direct(d)) =
                    eff.as_ref().map(|e| &e.kind)
                {
                    payload.protocol = Some(d.protocol);
                }
            }
            payload.into_provider()
        },
        |entry| validate_provider_upsert(&state.providers, entry),
    )?;
    Ok((StatusCode::OK, NO_STORE, Json(ev)))
}

/// upsert 钩子 (#179): 类型校验收口到语义 SSOT `Provider::validate` (crud 钩子在
/// id 生成/填充后运行, 正是其正确位置 — into_provider 只做字段变换), 再叠加
/// web 特有的跨条目环检查. 消息只含 provider id.
fn validate_provider_upsert(
    table: &crate::provider::ProviderTable,
    entry: &Provider,
) -> Result<(), ApiError> {
    entry.validate().map_err(ApiError::validation)?;
    if table.would_cycle(entry) {
        return Err(ApiError::validation(format!(
            "provider '{}' route_to would create a cycle",
            entry.id
        )));
    }
    Ok(())
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
    /// 协议. **Direct 构造必填** (缺失 → 400, #190); **Virtual 构造不需要**
    /// (仅 WebUI 展示的派生信息, 由链尾实体决定真实 egress), 省略/null 即可.
    /// PUT 省略时若 effective 是 Direct → 回填其 protocol ("保留" 语义, 同 api_key;
    /// 注意 partial PUT 仍需完整 Direct 字段 — base_url 不回填, 缺失 400).
    #[serde(default)]
    pub protocol: Option<Protocol>,
    /// 上游 base URL. 实体 provider 必填 (http(s) + 无末尾 `/`); 虚拟 provider
    /// (route_to 非空) 忽略, 可省略/为空 (#179).
    #[serde(default)]
    pub base_url: String,
    /// API key 明文值. 语义因 endpoint 而异:
    /// - POST (create): 省略 (None) 或空串 = 不设置 (适用 Ollama 等本地无 auth 场景).
    /// - PUT (update): 省略 (None) = 保留旧值 — override **不记录**该字段 (不落盘明文,
    ///   #157), effective 解析由 `inherit_from_static` 回落 static / dynamic 旧值.
    ///   具体值 = 显式覆盖 (新值落盘 state.toml, 属预期).
    ///
    /// 已知限制: static 基线下显式空串 `""` 无法清空 key (会被继承回落 static),
    /// 停用走 decision=disabled. 详见根 AGENTS.md "#157 已知限制" 条目.
    ///
    /// WebUI 编辑表单依赖此语义: 用户留空 input 时前端发 null, 不破坏既有 key.
    /// 与 `api_key_file` 互斥 (同时设置会在 `validate()` 报错).
    #[serde(default)]
    pub api_key: Option<String>,
    /// 从文件路径读取 api_key. PUT 时若省略 (None) 则保留旧值 (同 `api_key` 的
    /// "不记录 + 回落" 语义). 与 `api_key` 互斥. WebUI 创建 dynamic-only provider
    /// 时可用, 但通常只在 static config (sops 注入) 用.
    #[serde(default)]
    pub api_key_file: Option<String>,
    /// 虚拟 endpoint 路由目标 (#179/#187 sum type). 三态语义:
    /// - 省略 (None): 保留旧值 (PUT) — dynamic 旧值是 Virtual 则回填其 route_to;
    ///   static 基线下未回填 (static Direct) 的鉴权字段由 `inherit_from_static` 继承.
    /// - `""` (空串): 显式 **Direct 构造** (改回实体 provider, #187 根治 — 不再被
    ///   继承回落 static 指向; 需同时提供合法 base_url, 否则 validate 400).
    /// - `"target-id"`: **Virtual 构造**, 指向目标 provider (悬空放行, 运行时 503).
    ///
    /// 成环 (含自环) 在 validate/upsert 钩子拒绝 (400).
    #[serde(default)]
    pub route_to: Option<String>,
    /// 出站 model 强制重写值 (#183). 三态语义同 `route_to`:
    /// - 省略 (None): 保留旧值 (PUT) / 不设置 (POST); static 基线下经
    ///   `inherit_from_static` 回落 static (#157 同型).
    /// - `""` (空串): 显式清空 (透传客户端 model). dynamic-only 条目可完整往返;
    ///   static 配置了 override 的条目会被继承回落 (#157 同型已知限制).
    /// - `"model-id"`: 生效值 (写入侧过滤后永非空串).
    #[serde(default)]
    pub model_override: Option<String>,
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
        // 结构校验 (base_url / route_to 目标 id / 自环 / api_key 互斥) 收口在
        // crud 钩子的 `Provider::validate` (见 validate_provider_upsert), 此处只做
        // 字段变换: 空串 route_to = 显式清空指向 ("虚拟 → 实体", #187 根治).
        let model_override = self.model_override.filter(|s| !s.is_empty());
        let kind = match self.route_to.filter(|s| !s.is_empty()) {
            Some(route_to) => {
                crate::provider::ProviderKind::Virtual(crate::provider::VirtualProvider {
                    route_to,
                    protocol: self.protocol,
                })
            }
            None => {
                let protocol = self.protocol.ok_or_else(|| {
                    ApiError::validation("protocol is required for direct providers")
                })?;
                crate::provider::ProviderKind::Direct(crate::provider::DirectProvider {
                    protocol,
                    base_url: self.base_url,
                    api_key: self.api_key.unwrap_or_default(),
                    api_key_file: self.api_key_file.map(std::path::PathBuf::from),
                })
            }
        };
        Ok(Provider {
            id: self.id.unwrap_or_default(),
            enabled: self.enabled,
            name: self.name.filter(|s| !s.trim().is_empty()),
            model_override,
            kind,
        })
    }
}
