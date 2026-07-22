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
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{DeleteOutcome, OverrideMode, UpsertKind};
use crate::provider::{EffectiveProvider, Protocol, Provider};
use crate::proxy::ProxyState;
use crate::record::{ForwardRecord, RecordFilter};
use crate::secrets::{EffectiveSecret, SecretCategory, SecretEntry};

/// 共享的 `no-store` header 设置 (axum 的 `[(name, value); N]` 接受 `(&str, &str)`).
const NO_STORE: [(&str, &str); 1] = [("cache-control", "no-store, no-cache, must-revalidate")];

// ─── /records ──────────────────────────────────────────────────────────────

/// `GET /api/records` 查询参数.
///
/// - `offset`: 0-based, 从最新一条算起 (与 [`RecordStore::list_page`] 一致). 默认 0.
/// - `limit`:  clamp 到 `[1, 200]`. 默认 50.
/// - `filter`: `all` (默认) 或 `hits` (只返回发生过 redact 的记录). 两个维度各自
///   独立分页, 响应 `total` 是当前 filter 维度下的总数.
///
/// 设计: 用 `Option<T>` 让缺失字段走默认值, 避免 axum Query 反序列化整体拒绝
/// (例如只传 `?offset=10` 时 limit 仍取默认). 非法 filter 值走 serde 默认 (None → All),
/// 不返回 400 — 前端 bug 不应让页面变白.
#[derive(Debug, Deserialize)]
pub struct RecordsQuery {
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub filter: Option<RecordFilter>,
}

impl RecordsQuery {
    /// 解析为生效的 `(offset, limit, filter)`. 单一事实来源: 默认值 + clamp 都在这里.
    fn resolve(&self) -> (usize, usize, RecordFilter) {
        let offset = self.offset.unwrap_or(0);
        // 默认 50: 足够 WebUI 首屏, 又不会一次拖太多 (单条 record body 可能很大).
        let limit = self.limit.unwrap_or(50);
        (offset, limit.clamp(1, 200), self.filter.unwrap_or_default())
    }
}

pub async fn list_records(
    State(state): State<ProxyState>,
    Query(q): Query<RecordsQuery>,
) -> impl IntoResponse {
    let (offset, limit, filter) = q.resolve();
    let (records, total) = state.records.list_page(offset, limit, filter);
    (
        NO_STORE,
        Json(ListRecordsResponse {
            records,
            total,
            offset,
            limit,
            filter,
        }),
    )
}

pub async fn get_record(
    State(state): State<ProxyState>,
    Path(id): Path<Uuid>,
    Query(q): Query<RecordQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    let record = state.records.get(id).ok_or(StatusCode::NOT_FOUND)?;
    // 默认 view=raw → 直接返回原 record, 无解析开销.
    // 注意: 我们**总是**返回 GetRecordResponse envelope, 让前端 shape 固定.
    // raw view 下 parsed_*/parse_error 全为 None.
    let wants_parsed = q.view.as_deref() == Some("parsed");
    if !wants_parsed {
        return Ok((
            NO_STORE,
            Json(GetRecordResponse {
                record,
                parsed_request: None,
                parsed_response: None,
                parse_error: None,
            }),
        ));
    }
    // parsed view: 用 codec 把 wire body parse → IR → 重新 serialize 给前端.
    let resp = build_parsed_response(record);
    Ok((NO_STORE, Json(resp)))
}

/// `GET /api/records/{id}?view=` 的查询参数.
///
/// - `view=raw` (默认 / 省略): 仅返回 record 原文.
/// - `view=parsed`: 尝试用 ingress 协议的 codec 把 req/resp body parse 成
///   结构化 JSON (chat-like 视图). 失败时填 `parse_error`, 不影响 HTTP 200.
#[derive(Debug, Deserialize)]
pub struct RecordQuery {
    #[serde(default)]
    pub view: Option<String>,
}

/// `GET /api/records/{id}` 的统一响应 envelope.
///
/// - raw view: `record` 是原文, `parsed_*` 全 None.
/// - parsed view: 若 codec 支持 + body 合法, `parsed_request`/`parsed_response`
///   是 ingress writer 重序列化后的 JSON (chat-bubble 友好); 失败时填 `parse_error`.
///
/// 前端拿到固定 shape 后, 根据 `parse_error` 决定 fallback 到原文展示.
#[derive(Serialize)]
pub struct GetRecordResponse {
    pub record: ForwardRecord,
    pub parsed_request: Option<serde_json::Value>,
    pub parsed_response: Option<serde_json::Value>,
    pub parse_error: Option<String>,
}

/// 解析 record 的 req/resp body 为结构化 JSON (ingress writer 投影).
///
/// 单一事实来源: 所有 "parsed view 不可用" 的原因都在这里分类:
/// - protocol 短名未知 → `parsed view not available for protocol '<X>'`
/// - codec 不支持此协议 (Gemini/Ollama) → 同上
/// - body 不是合法 JSON → `invalid JSON: <err>`
/// - codec reader 解析失败 → `<reader error message>`
///
/// 返回的 `parsed_request` / `parsed_response` 来自 ingress writer 的
/// `write_request` / `write_response` — 这是协议 canonical JSON 投影,
/// 前端可以按 chat-bubble 风格渲染.
///
/// MVP 限制: **流式响应不解析** (ForwardRecord.resp_body 是拼接后的 SSE chunk,
/// 不是单个 JSON). 若 `record.streamed`, 跳过 response 解析.
fn build_parsed_response(record: ForwardRecord) -> GetRecordResponse {
    // 1. 从 record.path 的首段提取 ingress protocol short (e.g. "/o/x/..." → "o").
    //    cross-proto 路径形如 "/o/x/...  [openai → anthropic]", 首段仍是 ingress.
    //    先 clone 出 short, 避免后续 move record 时 borrow 冲突.
    let proto_short = record
        .path
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();
    let Some(native) = Protocol::from_short(&proto_short) else {
        return GetRecordResponse {
            record,
            parsed_request: None,
            parsed_response: None,
            parse_error: Some(format!(
                "parsed view not available for protocol '{proto_short}'"
            )),
        };
    };
    let Some(codec_proto) = crate::codec::Protocol::from_native(native) else {
        return GetRecordResponse {
            record,
            parsed_request: None,
            parsed_response: None,
            parse_error: Some(format!(
                "parsed view not available for protocol '{}'",
                native.name()
            )),
        };
    };

    let reader = codec_proto.reader();
    let writer = codec_proto.writer();

    // 2. parsed_request: 总是尝试 (req_body 永远是单 JSON, 即便是 streaming 请求).
    let mut parsed_request = None;
    let mut parse_error: Option<String> = None;
    match serde_json::from_str::<serde_json::Value>(&record.req_body) {
        Ok(v) => match reader.read_request(&v) {
            Ok(ir) => parsed_request = Some(writer.write_request(&ir)),
            Err(e) => parse_error = Some(e.message),
        },
        Err(e) => parse_error = Some(format!("invalid JSON in req_body: {e}")),
    }

    // 3. parsed_response: 仅在非流式 + 2xx + 非空时尝试.
    //    流式响应的 resp_body 是 SSE 拼接, 不是单个 JSON, 解析必失败 → 直接跳过.
    let mut parsed_response = None;
    if !record.streamed
        && record.resp_status >= 200
        && record.resp_status < 300
        && !record.resp_body.is_empty()
    {
        match serde_json::from_str::<serde_json::Value>(&record.resp_body) {
            Ok(v) => match reader.read_response(&v) {
                Ok(ir) => parsed_response = Some(writer.write_response(&ir)),
                // response parse 失败: 不覆盖 request 的 parse_error (request 更重要).
                Err(e) => {
                    if parse_error.is_none() {
                        parse_error = Some(format!("resp_body parse failed: {}", e.message));
                    }
                }
            },
            Err(e) => {
                if parse_error.is_none() {
                    parse_error = Some(format!("invalid JSON in resp_body: {e}"));
                }
            }
        }
    }

    GetRecordResponse {
        record,
        parsed_request,
        parsed_response,
        parse_error,
    }
}

#[derive(Serialize)]
pub struct ListRecordsResponse {
    pub records: Vec<ForwardRecord>,
    /// 当前 filter 维度下的总数 (用于前端分页器).
    ///
    /// `filter=all` 时等于 records 总量; `filter=hits` 时等于发生过 redact 的记录总数.
    pub total: usize,
    /// 当前页 offset (0-based).
    pub offset: usize,
    /// 当前页 limit (clamp 后的实际生效值, 便于前端校验).
    pub limit: usize,
    /// 当前生效的 filter (回显, 让前端无状态地确认).
    pub filter: RecordFilter,
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
    /// 可选: mock 策略. 省略时后端用 [`crate::mock::MockStrategy::default`]
    /// (Auto + sticky + resolve 时 infer gen spec).
    #[serde(default)]
    pub mock_strategy: Option<crate::mock::MockStrategy>,
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
            mock_strategy: self.mock_strategy.unwrap_or_default(),
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
            mock_strategy: None,
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
            mock_strategy: None,
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

    // ─── RecordsQuery ──────────────────────────────────────────────────────

    #[test]
    fn records_query_defaults_offset_zero_limit_fifty() {
        let q = RecordsQuery {
            offset: None,
            limit: None,
            filter: None,
        };
        assert_eq!(q.resolve(), (0, 50, RecordFilter::All));
    }

    #[test]
    fn records_query_clamps_limit_to_range() {
        // limit = 0 → clamp 到 1.
        let q = RecordsQuery {
            offset: None,
            limit: Some(0),
            filter: None,
        };
        assert_eq!(q.resolve(), (0, 1, RecordFilter::All));
        // limit 超大 → clamp 到 200.
        let q = RecordsQuery {
            offset: None,
            limit: Some(10_000),
            filter: None,
        };
        assert_eq!(q.resolve(), (0, 200, RecordFilter::All));
    }

    #[test]
    fn records_query_passes_hits_filter_through() {
        // 显式传 filter=hits 应原样透传.
        let q = RecordsQuery {
            offset: Some(10),
            limit: Some(20),
            filter: Some(RecordFilter::Hits),
        };
        assert_eq!(q.resolve(), (10, 20, RecordFilter::Hits));
    }

    // ─── build_parsed_response ────────────────────────────────────────────

    /// 构造一个最小可用的 ForwardRecord for parsed-view 测试.
    fn parsed_test_record(
        path: &str,
        req_body: &str,
        resp_body: &str,
        streamed: bool,
    ) -> crate::record::ForwardRecord {
        let mut r =
            crate::record::ForwardRecord::new("POST".into(), path.into(), vec![], req_body.into());
        r.resp_status = 200;
        r.resp_body = resp_body.into();
        r.streamed = streamed;
        r.resp_complete = true;
        r
    }

    #[test]
    fn parsed_view_openai_request_returns_structured_json() {
        // 合法 OpenAI chat request: codec 应当 parse 成功, write_request 输出
        // 一个含 messages 数组的 JSON (前端 chat-bubble 渲染的基础).
        let req_body = r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#;
        let record = parsed_test_record("/o/oa-main/v1/chat/completions", req_body, "", false);
        let resp = build_parsed_response(record);
        assert!(
            resp.parse_error.is_none(),
            "unexpected: {:?}",
            resp.parse_error
        );
        let parsed_req = resp.parsed_request.expect("parsed_request should be set");
        assert!(
            parsed_req.get("messages").is_some(),
            "parsed_request should have messages"
        );
    }

    #[test]
    fn parsed_view_unsupported_protocol_returns_error() {
        // Gemini 的 codec 尚未实现 → parse_error 应当包含 protocol 名.
        let req_body = r#"{"prompt":"hi"}"#;
        let record = parsed_test_record("/g/gem/v1/generateContent", req_body, "", false);
        let resp = build_parsed_response(record);
        assert!(resp.parsed_request.is_none());
        let err = resp.parse_error.expect("gemini should report parse_error");
        assert!(
            err.contains("gemini") || err.contains("protocol"),
            "error should mention protocol, got: {err}"
        );
    }

    #[test]
    fn parsed_view_unknown_proto_short_returns_error() {
        // 路径首段是未知简写 (非 o/a/g/l) → from_short 返回 None.
        let req_body = r#"{"q":"hi"}"#;
        let record = parsed_test_record("/x/foo/bar", req_body, "", false);
        let resp = build_parsed_response(record);
        assert!(resp.parsed_request.is_none());
        let err = resp
            .parse_error
            .expect("unknown proto should report parse_error");
        assert!(
            err.contains("'x'"),
            "error should mention the short, got: {err}"
        );
    }

    #[test]
    fn parsed_view_malformed_body_returns_error() {
        // req_body 不是合法 JSON → parse_error 应当包含 "invalid JSON".
        let record = parsed_test_record("/o/oa-main/v1/chat/completions", "not-json{", "", false);
        let resp = build_parsed_response(record);
        assert!(resp.parsed_request.is_none());
        let err = resp
            .parse_error
            .expect("malformed body should report parse_error");
        assert!(
            err.contains("invalid JSON"),
            "error should mention invalid JSON, got: {err}"
        );
    }

    #[test]
    fn parsed_view_streamed_response_not_parsed() {
        // 即使 resp_body 是合法 JSON, streamed=true 也应跳过 response 解析
        // (因为实际 resp_body 是 SSE 拼接, 不是单个 JSON).
        let req_body = r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#;
        let resp_body = r#"{"id":"x","choices":[]}"#;
        let record =
            parsed_test_record("/o/oa-main/v1/chat/completions", req_body, resp_body, true);
        let resp = build_parsed_response(record);
        // request 仍应被解析.
        assert!(resp.parsed_request.is_some());
        // response 不应被解析 (streamed).
        assert!(resp.parsed_response.is_none());
        // 不应有 error (request 成功了, response 是被显式跳过的).
        assert!(resp.parse_error.is_none());
    }

    #[test]
    fn parsed_view_non_2xx_response_not_parsed() {
        // 非 2xx 响应通常是 error envelope, 不应被当作 chat response 解析.
        let req_body = r#"{"model":"gpt-4","messages":[]}"#;
        let mut record =
            parsed_test_record("/o/oa-main/v1/chat/completions", req_body, "err", false);
        record.resp_status = 500;
        let resp = build_parsed_response(record);
        assert!(resp.parsed_request.is_some());
        assert!(resp.parsed_response.is_none());
        assert!(resp.parse_error.is_none());
    }
}
