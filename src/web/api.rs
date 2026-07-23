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
use crate::dag::{NodeDetail, NodeView, ResponseData};
use crate::provider::{EffectiveProvider, Protocol, Provider};
use crate::proxy::ProxyState;
use crate::record::{ForwardRecord, RecordFilter};
use crate::secrets::{EffectiveSecret, SecretCategory, SecretEntry};

/// 共享的 `no-store` header 设置 (axum 的 `[(name, value); N]` 接受 `(&str, &str)`).
const NO_STORE: [(&str, &str); 1] = [("cache-control", "no-store, no-cache, must-revalidate")];

// ─── /records ──────────────────────────────────────────────────────────────

/// `GET /api/records` 查询参数.
///
/// - `offset`: 0-based, 从最新一条算起. 默认 0.
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
    let hits_only = matches!(filter, RecordFilter::Hits);
    let (views, total) = state.dag.list_page(offset, limit, hits_only);
    let summaries: Vec<RecordSummary> = views.into_iter().map(RecordSummary::from).collect();
    (
        NO_STORE,
        Json(ListRecordsResponse {
            records: summaries,
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
    // 从 DAG 派生 ForwardRecord DTO.
    let view = state.dag.get_node(id).ok_or(StatusCode::NOT_FOUND)?;
    let detail = state.dag.get_node_detail(id).ok_or(StatusCode::NOT_FOUND)?;
    let resp = state.dag.get_response(id);
    let record = build_forward_record(view, detail, resp);
    // 我们总是返回 GetRecordResponse envelope, 让前端 shape 固定.
    // raw view: parsed_*/parse_error 全 None.
    // parsed view: parsed_response 直接从 record.resp_parsed 读取 (流式/非流式统一);
    //   parsed_request 仍需按需从 req_body 计算.
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
    let resp = build_parsed_response(record);
    Ok((NO_STORE, Json(resp)))
}

/// 从 DAG 视图构造 [`ForwardRecord`] DTO (Web API 的 record 字段).
///
/// 拼接 NodeView (元数据) + NodeDetail (req_headers / req_body_raw) + ResponseData (响应字段).
/// ResponseData 缺失时 (上游错误 / 尚未响应), 响应字段填默认空值 (resp_status=0 等).
fn build_forward_record(
    view: NodeView,
    detail: NodeDetail,
    resp: Option<ResponseData>,
) -> ForwardRecord {
    ForwardRecord {
        id: view.id,
        created_at: view.created_at,
        method: view.method,
        path: view.path,
        req_headers: detail.req_headers,
        req_body: detail.req_body_raw,
        resp_status: view.resp_status,
        resp_headers: resp
            .as_ref()
            .map(|r| r.resp_headers.clone())
            .unwrap_or_default(),
        resp_body: resp
            .as_ref()
            .map(|r| r.raw_resp_body.clone())
            .unwrap_or_default(),
        resp_parsed: resp.as_ref().and_then(|r| r.parsed.clone()),
        elapsed_ms: view.elapsed_ms,
        streamed: view.streamed,
        resp_complete: view.resp_complete,
        error: view.error,
        redactions: view.redactions,
    }
}

/// `GET /api/records/{id}?view=` 的查询参数.
///
/// - `view=raw` (默认 / 省略): 仅返回 record 原文.
/// - `view=parsed`: parsed_response 直接从 record.resp_parsed 读取;
///   parsed_request 按需用 ingress codec 从 req_body 计算.
#[derive(Debug, Deserialize)]
pub struct RecordQuery {
    #[serde(default)]
    pub view: Option<String>,
}

/// `GET /api/records/{id}` 的统一响应 envelope.
///
/// - raw view: `record` 是原文, `parsed_*` 全 None.
/// - parsed view: `parsed_response` 直接从 `record.resp_parsed` 读取
///   (流式/非流式统一, 由 proxy 层的 StreamScan 累积或非流式路径一次性计算);
///   `parsed_request` 按需用 codec 计算.
///
/// 前端拿到固定 shape 后, 根据 `parse_error` 决定 fallback 到原文展示.
#[derive(Serialize)]
pub struct GetRecordResponse {
    pub record: ForwardRecord,
    pub parsed_request: Option<serde_json::Value>,
    pub parsed_response: Option<serde_json::Value>,
    pub parse_error: Option<String>,
}

/// 解析 record 的 req body 为结构化 JSON (ingress writer 投影).
///
/// parsed_response 直接从 `record.resp_parsed` 读取 (proxy 层已计算).
/// parsed_request 仍需按需从 `record.req_body` 计算:
/// - protocol 短名未知 → `parsed view not available for protocol '<X>'`
/// - codec 不支持此协议 (Gemini/Ollama) → 同上
/// - body 不是合法 JSON → `invalid JSON: <err>`
/// - codec reader 解析失败 → `<reader error message>`
fn build_parsed_response(record: ForwardRecord) -> GetRecordResponse {
    // parsed_response 直接取 record 内的累积结果.
    let parsed_response = record.resp_parsed.clone();

    // parsed_request: 从 req_body 计算.
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
            parsed_response,
            parse_error: Some(format!(
                "parsed view not available for protocol '{proto_short}'"
            )),
        };
    };
    let Some(codec_proto) = crate::codec::Protocol::from_native(native) else {
        return GetRecordResponse {
            record,
            parsed_request: None,
            parsed_response,
            parse_error: Some(format!(
                "parsed view not available for protocol '{}'",
                native.name()
            )),
        };
    };

    let reader = codec_proto.reader();
    let writer = codec_proto.writer();

    let mut parsed_request = None;
    let mut parse_error: Option<String> = None;
    match serde_json::from_str::<serde_json::Value>(&record.req_body) {
        Ok(v) => match reader.read_request(&v) {
            Ok(ir) => parsed_request = Some(writer.write_request(&ir)),
            Err(e) => parse_error = Some(e.message),
        },
        Err(e) => parse_error = Some(format!("invalid JSON in req_body: {e}")),
    }

    GetRecordResponse {
        record,
        parsed_request,
        parsed_response,
        parse_error,
    }
}

/// list_records 返回的轻量 record 摘要 (不含 body 字段).
///
/// req_body / resp_body / resp_parsed 可能很大 (流式响应累积内容 / 大 prompt),
/// list 场景不需要它们 — 前端 sidebar 只显示 preview / model / status / hitN 等元数据,
/// body 由 GET /records/{id}?view=... 按需拉取.
///
/// `preview` 与 `model` 由 push 时一次性从 req_body 提取 (存 CallEvent),
/// list 响应直接读 NodeView, 保证始终轻量 (preview 截断到 [`PREVIEW_MAX`] chars).
#[derive(Serialize)]
pub struct RecordSummary {
    pub id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub method: String,
    pub path: String,
    pub resp_status: u16,
    pub elapsed_ms: u64,
    pub streamed: bool,
    pub resp_complete: bool,
    pub error: Option<String>,
    #[serde(default)]
    pub redactions: Vec<(String, String)>,
    /// 会话标题: 从 req_body 提取的首条 user message 文本 (截断).
    /// 提取失败 (非 JSON / 无 user message) 时为 None, 前端 fallback 到 method+path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    /// 模型名: 从 req_body 顶层 `model` 字段提取 (OpenAI / Anthropic 共有).
    /// 非 chat 协议或缺失时为 None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// preview 截断上限 (char count). 后端唯一截断点, 前端直接渲染.
const PREVIEW_MAX: usize = 48;
/// 超过此大小的 req_body 跳过 preview 提取 (避免大 body 无谓 JSON parse).
/// 1 MiB 足以覆盖绝大多数 LLM 请求 (system prompt + 多轮对话); 超出此大小的请求
/// preview 留空, sidebar fallback 到 method+path.
const PREVIEW_BODY_MAX: usize = 1024 * 1024;

impl From<NodeView> for RecordSummary {
    fn from(v: NodeView) -> Self {
        // preview / model 已在 push 时预计算并存在 CallEvent 里 (NodeView 直接携带).
        Self {
            id: v.id,
            created_at: v.created_at,
            method: v.method,
            path: v.path,
            resp_status: v.resp_status,
            elapsed_ms: v.elapsed_ms,
            streamed: v.streamed,
            resp_complete: v.resp_complete,
            error: v.error,
            redactions: v.redactions,
            preview: v.preview,
            model: v.model,
        }
    }
}

/// 从 chat request body 中提取 (首条 user message preview, model 名).
///
/// 协议无关的字节级提取 (不依赖 codec reader): OpenAI 和 Anthropic 都把 `model`
/// 放在顶层, `messages[]` 也共享 `{role, content}` 形状. content 支持 string 和
/// `[{type:"text", text}]` 两种形态 (OpenAI / Anthropic 一致).
///
/// 设计权衡:
/// - 不复用 codec reader: reader 会做更重的协议归一化 (tool_calls / system 顶层等),
///   list 路径只需 preview + model, 用轻量 serde_json::Value 提取即可, 避免把
///   codec 模块耦合进 web/api.
/// - 失败容错: 非 JSON / 字段缺失 / 类型不匹配一律返回 (None, None), 不影响 list 响应.
///   前端按 None fallback 到 method+path (与旧行为一致).
pub(crate) fn extract_preview_and_model(req_body: &str) -> (Option<String>, Option<String>) {
    // 跳过明显非 JSON 的 body (快速路径, 避免大 body 无谓 try_parse).
    if req_body.is_empty() || req_body.len() > PREVIEW_BODY_MAX || !req_body.starts_with('{') {
        return (None, None);
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(req_body) else {
        return (None, None);
    };
    let model = v
        .get("model")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string());
    let preview = v
        .get("messages")
        .and_then(|m| m.as_array())
        .and_then(|msgs| {
            msgs.iter().find_map(|m| {
                if m.get("role").and_then(|r| r.as_str()) != Some("user") {
                    return None;
                }
                let content = m.get("content")?;
                // string content: 直接取.
                if let Some(s) = content.as_str() {
                    return Some(s.to_string());
                }
                // array content: 拼接所有 type=text 的 text 字段.
                if let Some(arr) = content.as_array() {
                    let texts: Vec<&str> = arr
                        .iter()
                        .filter_map(|b| {
                            if b.get("type").and_then(|t| t.as_str()) != Some("text") {
                                return None;
                            }
                            b.get("text").and_then(|t| t.as_str())
                        })
                        .collect();
                    if texts.is_empty() {
                        return None;
                    }
                    return Some(texts.join(" "));
                }
                None
            })
        })
        .map(|s| {
            // 归一化空白 + 截断 (与前端 messagePreview 逻辑一致, SSOT 在此).
            let normalized = s.split_whitespace().collect::<Vec<_>>().join(" ");
            if normalized.chars().count() > PREVIEW_MAX {
                let end = normalized
                    .char_indices()
                    .nth(PREVIEW_MAX)
                    .map(|(i, _)| i)
                    .unwrap_or(normalized.len());
                format!("{}…", &normalized[..end])
            } else {
                normalized
            }
        });
    (preview, model)
}

#[derive(Serialize)]
pub struct ListRecordsResponse {
    pub records: Vec<RecordSummary>,
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
    /// (Auto + resolve 时 infer gen spec).
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

    // ─── extract_preview_and_model ────────────────────────────────────────

    #[test]
    fn extract_preview_model_openai_string_content() {
        let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"}]}"#;
        let (preview, model) = extract_preview_and_model(body);
        assert_eq!(model.as_deref(), Some("gpt-4o"));
        assert_eq!(preview.as_deref(), Some("hello world"));
    }

    #[test]
    fn extract_preview_model_anthropic_array_content() {
        let body = r#"{"model":"claude-3","messages":[{"role":"user","content":[{"type":"text","text":"hi there"}]}]}"#;
        let (preview, model) = extract_preview_and_model(body);
        assert_eq!(model.as_deref(), Some("claude-3"));
        assert_eq!(preview.as_deref(), Some("hi there"));
    }

    #[test]
    fn extract_preview_picks_first_user_message() {
        // 多个 user message: 取第一个.
        let body = r#"{"model":"x","messages":[{"role":"assistant","content":"noop"},{"role":"user","content":"first user"},{"role":"user","content":"second"}]}"#;
        let (preview, _) = extract_preview_and_model(body);
        assert_eq!(preview.as_deref(), Some("first user"));
    }

    #[test]
    fn extract_preview_truncates_long_text() {
        let long = "a".repeat(100);
        let body = format!(r#"{{"model":"x","messages":[{{"role":"user","content":"{long}"}}]}}"#);
        let (preview, _) = extract_preview_and_model(&body);
        let p = preview.expect("preview should be set");
        assert_eq!(p.chars().count(), PREVIEW_MAX + 1); // 48 chars + '…'
        assert!(p.ends_with('…'));
    }

    #[test]
    fn extract_preview_normalizes_whitespace() {
        let body = r#"{"model":"x","messages":[{"role":"user","content":"  hello\n\n  world  "}]}"#;
        let (preview, _) = extract_preview_and_model(body);
        assert_eq!(preview.as_deref(), Some("hello world"));
    }

    #[test]
    fn extract_preview_no_user_message_returns_none() {
        let body = r#"{"model":"x","messages":[{"role":"system","content":"sys"}]}"#;
        let (preview, model) = extract_preview_and_model(body);
        assert_eq!(model.as_deref(), Some("x"));
        assert!(preview.is_none());
    }

    #[test]
    fn extract_preview_non_json_returns_none() {
        let (preview, model) = extract_preview_and_model("not json{");
        assert!(preview.is_none());
        assert!(model.is_none());
    }

    #[test]
    fn extract_preview_empty_body_returns_none() {
        let (preview, model) = extract_preview_and_model("");
        assert!(preview.is_none());
        assert!(model.is_none());
    }

    #[test]
    fn extract_preview_oversized_body_returns_none() {
        // > PREVIEW_BODY_MAX (1 MiB) 的 body 直接跳过 (快速路径).
        let big = "x".repeat(PREVIEW_BODY_MAX + 1);
        let body = format!(r#"{{"model":"x","messages":[{{"role":"user","content":"{big}"}}]}}"#);
        let (preview, model) = extract_preview_and_model(&body);
        assert!(preview.is_none());
        assert!(model.is_none());
    }

    #[test]
    fn extract_preview_large_but_under_threshold_is_extracted() {
        // 接近 1 MiB 的合法 chat body 仍应正常提取 (覆盖典型 LLM 长 prompt 场景).
        // content 用 100 KiB 文本, 整个 body 约 100 KiB, 远低于阈值.
        let big_content = "a".repeat(100 * 1024);
        let body = format!(
            r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"{big_content}"}}]}}"#
        );
        let (preview, model) = extract_preview_and_model(&body);
        assert_eq!(model.as_deref(), Some("gpt-4o"));
        // content 被截断到 PREVIEW_MAX chars + '…'.
        let p = preview.expect("preview should be set");
        assert!(p.ends_with('…'));
        assert_eq!(p.chars().count(), PREVIEW_MAX + 1);
    }

    #[test]
    fn extract_preview_not_starting_with_brace_returns_none() {
        // 快速路径: 不以 { 开头直接跳过 (catches GET / DELETE 等无 body 场景).
        let (preview, model) = extract_preview_and_model("plain text");
        assert!(preview.is_none());
        assert!(model.is_none());
    }

    #[test]
    fn extract_preview_multibyte_truncation_safe() {
        // 截断在 UTF-8 char boundary 安全 (用 char_indices).
        let body = r#"{"model":"x","messages":[{"role":"user","content":"你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界"}]}"#;
        let (preview, _) = extract_preview_and_model(body);
        let p = preview.unwrap();
        // 截断点在 48 chars 处, 末尾加 '…', UTF-8 不应 panic.
        assert!(p.ends_with('…'));
        assert_eq!(p.chars().count(), PREVIEW_MAX + 1);
    }

    #[test]
    fn record_summary_from_extracts_preview_and_model() {
        // 端到端: NodeView -> RecordSummary 应当带上 preview + model.
        // (preview/model 在 push 时预计算, NodeView 直接携带.)
        let v = crate::dag::NodeView {
            id: Uuid::nil(),
            parent: None,
            req_delta_count: 0,
            has_response: false,
            created_at: chrono::Utc::now(),
            elapsed_ms: 0,
            method: "POST".into(),
            path: "/o/oa-main/v1/chat/completions".into(),
            resp_status: 200,
            redact_seed: 0,
            preview: Some("hi".into()),
            model: Some("gpt-4o".into()),
            streamed: false,
            resp_complete: false,
            error: None,
            redactions: vec![],
        };
        let s = RecordSummary::from(v);
        assert_eq!(s.model.as_deref(), Some("gpt-4o"));
        assert_eq!(s.preview.as_deref(), Some("hi"));
    }

    #[test]
    fn record_summary_from_empty_body_yields_none_fields() {
        // 空请求 body (如 GET) -> preview/model 都 None (push 时 extract 返回 None).
        let v = crate::dag::NodeView {
            id: Uuid::nil(),
            parent: None,
            req_delta_count: 0,
            has_response: false,
            created_at: chrono::Utc::now(),
            elapsed_ms: 0,
            method: "GET".into(),
            path: "/o/oa-main/v1/models".into(),
            resp_status: 0,
            redact_seed: 0,
            preview: None,
            model: None,
            streamed: false,
            resp_complete: false,
            error: None,
            redactions: vec![],
        };
        let s = RecordSummary::from(v);
        assert!(s.preview.is_none());
        assert!(s.model.is_none());
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
    fn parsed_view_streamed_response_uses_resp_parsed() {
        // streamed record 的 parsed_response 直接来自 record.resp_parsed
        // (由 proxy 层的 StreamScan 累积), 不再从 resp_body fold.
        let req_body = r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#;
        let mut record = parsed_test_record("/o/oa-main/v1/chat/completions", req_body, "", true);
        // 模拟 StreamScan 产出的 resp_parsed.
        record.resp_parsed = Some(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "hello"}}]
        }));
        let resp = build_parsed_response(record);
        // request 仍应被解析.
        assert!(resp.parsed_request.is_some());
        // response 直接来自 resp_parsed.
        let parsed_resp = resp
            .parsed_response
            .expect("resp_parsed should be returned");
        assert!(parsed_resp.get("choices").is_some());
        assert!(resp.parse_error.is_none());
    }

    #[test]
    fn parsed_view_non_2xx_response_no_resp_parsed() {
        // 非 2xx 响应: proxy 层不会设置 resp_parsed (只处理 2xx 成功响应).
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
