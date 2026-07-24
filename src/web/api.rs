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
pub const NO_STORE: [(&str, &str); 1] = [("cache-control", "no-store, no-cache, must-revalidate")];

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
    /// 所属会话的稳定标识 (前端 sidebar 二级菜单归属).
    pub session_id: crate::dag::SessionId,
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
    /// 会话标题: 从 req_body 提取的最后一条 user message 文本 (截断).
    /// 提取失败 (非 JSON / 无 user message) 时为 None, 前端 fallback 到 method+path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    /// 模型名: 从 req_body 顶层 `model` 字段提取 (OpenAI / Anthropic 共有).
    /// 非 chat 协议或缺失时为 None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// parsed view (ingress codec writer 序列化的 IrResponse).
    /// timeline 路径直接消费, 前端不再 N+1 拉 /records/{id}?view=parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parsed_response: Option<serde_json::Value>,
    /// 本轮 request delta (wire JSON messages, 从 req_body_raw 末尾截取).
    /// 只在 timeline 路径非空; list 路径留空.
    /// 前端按 role 渲染气泡 (system/user/tool), 与 preview 互补 (issue #27).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub req_delta_messages: Vec<serde_json::Value>,
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
            session_id: v.session_id,
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
            parsed_response: v.parsed_response,
            req_delta_messages: v.req_delta_messages,
        }
    }
}

/// 从 chat request body 中提取 (sidebar 标题 preview, model 名).
///
/// 协议无关的字节级提取 (不依赖 codec reader): OpenAI 和 Anthropic 都把 `model`
/// 放在顶层, `messages[]` 也共享 `{role, content}` 形状. content 支持 string 和
/// `[{type:"text", text}]` 两种形态 (OpenAI / Anthropic 一致).
///
/// 标题选择策略 (issue #27):
/// 取 messages 数组中**最后一条有文本内容的 message**, 不限 role.
/// 这让 tool-call 循环的每一轮有不同 preview:
///   轮1: [sys, u1] → preview = u1 (用户问题)
///   轮2: [sys, u1, a1(tc), tool1] → preview = tool1 内容 (不同于 u1!)
///   轮3: [sys, u1, a1(tc), tool1, a2(tc), tool2] → preview = tool2 内容 (不同于 tool1!)
///
/// 压缩 marker 特殊处理: 若最后一条恰好是 "What did we do so far?" (opencode 压缩
/// marker), 改取最后一条 assistant (即压缩摘要).
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

    // opencode 压缩会话注入的固定 user message (opencode 源码:
    // packages/opencode/src/session/message-v2.ts:231). 命中时优先取最后一条 assistant 摘要.
    // 精确匹配依赖 opencode 内部实现; 若 opencode 改变 marker, 匹配失败会优雅降级到
    // 正常的 "最后一条有文本的 message" 路径 (有测试覆盖该降级).
    const COMPRESSED_MARKER: &str = "What did we do so far?";
    let messages = v.get("messages").and_then(|m| m.as_array());
    // preview 优先级 (issue #27):
    // 1. 最后一条 user message (人类可读, 反映本轮问题)
    // 2. 最后一条有文本的 message (不限 role, 覆盖纯 tool-call 轮次)
    // 3. 压缩 marker 命中时 → 最后一条 assistant 摘要
    let last_user = messages.and_then(|msgs| last_message_text_by_role(msgs, "user"));
    let last_any = messages.and_then(|msgs| last_message_text(msgs));
    let raw = match last_user.as_deref() {
        Some(COMPRESSED_MARKER) => messages
            .and_then(|msgs| last_message_text_by_role(msgs, "assistant"))
            .or(last_user),
        // 有 user message → 优先用 (可读性好, 不暴露 tool_result 结构化数据).
        Some(_) => last_user,
        // 无 user message → 回退到最后一条有文本的 message (tool_result / assistant).
        None => last_any,
    };
    let preview = raw.map(|s| {
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

/// 从 messages 数组中提取指定 role 的**最后一条** message 文本.
///
/// content 兼容 string 与 `[{type:"text", text}]` 两种形态 (OpenAI / Anthropic 一致).
/// 返回原始文本 (未归一化 / 未截断), 由调用方决定后处理.
///
/// 取 "最后一条" 而非 "首条": chat API 的 messages 数组是累积的, 每轮请求都含完整历史.
/// 最后一条才反映 "这一轮的实际内容" (issue #25).
fn last_message_text_by_role(messages: &[serde_json::Value], role: &str) -> Option<String> {
    messages.iter().rev().find_map(|m| {
        if m.get("role").and_then(|r| r.as_str()) != Some(role) {
            return None;
        }
        message_text(m)
    })
}

/// 从 messages 数组中提取**最后一条有可展示文本的 message** (不限 role).
///
/// 用于 preview: tool-call 循环中最后一条可能是 tool_result (role=tool),
/// 让每轮 preview 反映本轮的实际增量, 而非永远是同一条 user message (issue #27).
/// 跳过 tool_call (assistant 无 content / 只有 tool_calls) 和其他无文本 message.
fn last_message_text(messages: &[serde_json::Value]) -> Option<String> {
    messages.iter().rev().find_map(message_text)
}

/// 从单条 message 中提取可展示文本 (content string 或 array of text blocks).
/// 跳过无文本的 message (tool_call only / null content / 空串).
pub(crate) fn message_text(m: &serde_json::Value) -> Option<String> {
    let content = m.get("content")?;
    // string content: 直接取 (空串视为无文本).
    if let Some(s) = content.as_str() {
        return if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        };
    }
    // array content: 拼接所有 type=text 的 text 字段.
    if let Some(arr) = content.as_array() {
        return extract_text_blocks(arr).map(|t| t.join(" "));
    }
    None
}

/// 从 content blocks 数组中收集所有 text 块的文本.
/// 用于 message.content (array 形态) 和 Anthropic system (array 形态).
/// 返回原始文本片段 (未 join), 调用方决定分隔符 (message 用 space, system 用 newline).
pub(crate) fn extract_text_blocks(arr: &[serde_json::Value]) -> Option<Vec<String>> {
    let texts: Vec<String> = arr
        .iter()
        .filter_map(|b| {
            if b.get("type").and_then(|t| t.as_str()) != Some("text") {
                return None;
            }
            b.get("text")
                .and_then(|t| t.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        })
        .collect();
    if texts.is_empty() { None } else { Some(texts) }
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

// ─── /sessions ─────────────────────────────────────────────────────────────

/// 会话列表 (叶子节点), sidebar 两级树的一级项.
#[derive(Serialize)]
pub struct SessionSummary {
    /// 会话稳定标识 (前端选中/展开用, 刷新后不变).
    pub session_id: crate::dag::SessionId,
    pub leaf_id: Uuid,
    pub root_id: Uuid,
    pub record_count: usize,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub latest_at: chrono::DateTime<chrono::Utc>,
    pub preview: Option<String>,
    pub model: Option<String>,
    pub latest_resp_status: u16,
    pub latest_error: Option<String>,
    pub redactions: Vec<(String, String)>,
    /// 叶子节点 HTTP path (前端 provider icon 解析 proto 角标 + provider id).
    pub path: String,
}

impl From<crate::dag::SessionView> for SessionSummary {
    fn from(s: crate::dag::SessionView) -> Self {
        Self {
            session_id: s.session_id,
            leaf_id: s.leaf_id,
            root_id: s.root_id,
            record_count: s.record_count,
            created_at: s.created_at,
            latest_at: s.latest_at,
            preview: s.preview,
            model: s.model,
            latest_resp_status: s.latest_resp_status,
            latest_error: s.latest_error,
            redactions: s.redactions,
            path: s.path,
        }
    }
}

#[derive(Serialize)]
struct ListSessionsResponse {
    sessions: Vec<SessionSummary>,
    total: usize,
}

pub async fn list_sessions(State(state): State<ProxyState>) -> impl IntoResponse {
    let sessions: Vec<SessionSummary> = state
        .dag
        .list_sessions()
        .into_iter()
        .map(SessionSummary::from)
        .collect();
    let total = sessions.len();
    (NO_STORE, Json(ListSessionsResponse { sessions, total }))
}

// ─── /nodes/{id}/timeline ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TimelineQuery {
    /// 取多少个祖先 (含 node 自身). 默认 10.
    #[serde(default)]
    pub limit: Option<usize>,
}

pub async fn get_timeline(
    State(state): State<ProxyState>,
    Path(id): Path<Uuid>,
    Query(q): Query<TimelineQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    // limit 上限 50 (而非 list 的 200): timeline 路径对每个 node 都 parse req_body_raw
    // 提取 delta messages, 大 body + 高 limit 会造成延迟尖峰 (issue #27 review #1).
    let limit = q.limit.unwrap_or(10).clamp(1, 50);
    let views = state.dag.timeline(id, limit);
    if views.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }
    let summaries: Vec<RecordSummary> = views.into_iter().map(RecordSummary::from).collect();
    Ok((NO_STORE, Json(serde_json::json!({ "records": summaries }))))
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
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
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
    fn extract_preview_picks_last_user_message() {
        // 累积数组: 多条 user message → 取最后一条 (本轮问题, issue #25).
        let body = r#"{"model":"x","messages":[{"role":"user","content":"first user"},{"role":"assistant","content":"noop"},{"role":"user","content":"second user"}]}"#;
        let (preview, _) = extract_preview_and_model(body);
        assert_eq!(preview.as_deref(), Some("second user"));
    }

    #[test]
    fn extract_preview_accumulated_history_each_round_unique() {
        // 模拟同一会话的 3 轮累积请求 (OpenAI 风格 messages 数组逐轮增长):
        // 三轮的 preview 应分别为 Q1/Q2/Q3 (而非全都是 Q1).
        let r1 = r#"{"model":"x","messages":[{"role":"user","content":"Q1"}]}"#;
        let r2 = r#"{"model":"x","messages":[{"role":"user","content":"Q1"},{"role":"assistant","content":"A1"},{"role":"user","content":"Q2"}]}"#;
        let r3 = r#"{"model":"x","messages":[{"role":"user","content":"Q1"},{"role":"assistant","content":"A1"},{"role":"user","content":"Q2"},{"role":"assistant","content":"A2"},{"role":"user","content":"Q3"}]}"#;
        assert_eq!(extract_preview_and_model(r1).0.as_deref(), Some("Q1"));
        assert_eq!(extract_preview_and_model(r2).0.as_deref(), Some("Q2"));
        assert_eq!(extract_preview_and_model(r3).0.as_deref(), Some("Q3"));
    }

    // ─── PR26 bug #1 修复验证: tool-call 循环 preview 策略 ──────────────────
    //
    // agent tool-call 循环: 用户问一次, agent 多轮 tool_call + tool_result.
    // preview 优先取最后一条 user (可读性好); 无 user 时回退到最后一条有文本的 message.
    // tool-call 循环中 user 不变 (都是初始问题), 但二级菜单靠轮次序号 + 时间戳区分.
    #[test]
    fn extract_preview_tool_call_cycle_prefers_user() {
        // 轮1: 用户问 "list files"
        let r1 = r#"{"model":"x","messages":[
            {"role":"system","content":"sys"},
            {"role":"user","content":"list files"}
        ]}"#;
        // 轮2: agent 调 tool, tool 返回结果.
        let r2 = r#"{"model":"x","messages":[
            {"role":"system","content":"sys"},
            {"role":"user","content":"list files"},
            {"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"ls","arguments":"{}"}}]},
            {"role":"tool","tool_call_id":"c1","content":"file1\nfile2"}
        ]}"#;
        let p1 = extract_preview_and_model(r1).0;
        let p2 = extract_preview_and_model(r2).0;
        // 优先取 user message (可读性好, 不暴露 tool_result 结构化数据).
        assert_eq!(p1.as_deref(), Some("list files"));
        assert_eq!(
            p2.as_deref(),
            Some("list files"),
            "优先取 user 而非 tool_result"
        );
    }

    #[test]
    fn extract_preview_no_user_falls_back_to_tool_result() {
        // 无 user message 时, 回退到最后一条有文本的 message (tool_result / assistant).
        let body = r#"{"model":"x","messages":[
            {"role":"system","content":"sys"},
            {"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"ls","arguments":"{}"}}]},
            {"role":"tool","tool_call_id":"c1","content":"result data"}
        ]}"#;
        let (preview, _) = extract_preview_and_model(body);
        assert_eq!(
            preview.as_deref(),
            Some("result data"),
            "无 user → 回退到 tool_result"
        );
    }

    #[test]
    fn extract_preview_compressed_session_falls_back_to_last_assistant() {
        // opencode 压缩会话: 最后一条 user = "What did we do so far?" → 改取最后一条 assistant 摘要.
        let body = r###"{"model":"x","messages":[
            {"role":"user","content":"earlier question"},
            {"role":"assistant","content":"earlier answer"},
            {"role":"user","content":"What did we do so far?"},
            {"role":"assistant","content":"## 目标\n实现 secret-guard WebUI 标题优化"}
        ]}"###;
        let (preview, _) = extract_preview_and_model(body);
        assert_eq!(
            preview.as_deref(),
            Some("## 目标 实现 secret-guard WebUI 标题优化")
        );
    }

    #[test]
    fn extract_preview_compressed_session_array_content_assistant() {
        // 同上但 assistant 用 array content (Anthropic 风格).
        let body = r###"{"model":"claude-3","messages":[
            {"role":"user","content":"What did we do so far?"},
            {"role":"assistant","content":[{"type":"text","text":"## 目标 重构 preview 提取"}]}
        ]}"###;
        let (preview, _) = extract_preview_and_model(body);
        assert_eq!(preview.as_deref(), Some("## 目标 重构 preview 提取"));
    }

    #[test]
    fn extract_preview_compressed_marker_not_normalized_still_normal_path() {
        // marker 比对用原始文本 (未归一化空白). 非精确匹配 (如本例多一个单词) 走正常路径,
        // 不触发 assistant fallback.
        let body = r#"{"model":"x","messages":[
            {"role":"user","content":"What did we do so far? extra"}
        ]}"#;
        let (preview, _) = extract_preview_and_model(body);
        assert_eq!(preview.as_deref(), Some("What did we do so far? extra"));
    }

    #[test]
    fn extract_preview_compressed_session_no_assistant_falls_back_to_marker() {
        // 压缩 marker 命中但无 assistant 消息 → last_assistant 返回 None.
        // marker 本身作为 preview (总比 None 强).
        let body = r#"{"model":"x","messages":[
            {"role":"user","content":"What did we do so far?"}
        ]}"#;
        let (preview, _) = extract_preview_and_model(body);
        assert_eq!(preview.as_deref(), Some("What did we do so far?"));
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
    fn extract_preview_system_only_returns_system_text() {
        // 只有 system message (无 user): 修复后取最后一条有文本的 message = system.
        // (旧行为: 只找 user → 返回 None; 新行为: 不限 role → 返回 system 文本)
        let body = r#"{"model":"x","messages":[{"role":"system","content":"sys text"}]}"#;
        let (preview, model) = extract_preview_and_model(body);
        assert_eq!(model.as_deref(), Some("x"));
        assert_eq!(preview.as_deref(), Some("sys text"));
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
            session_id: crate::dag::SessionId::new(),
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
            parsed_response: None,
            req_delta_messages: vec![],
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
            session_id: crate::dag::SessionId::new(),
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
            parsed_response: None,
            req_delta_messages: vec![],
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

// ─── /api-keys ──────────────────────────────────────────────────────────────
//
// 仅在 auth.enabled = true 时挂载 (由 server.rs 条件化装配).
// 这些 handler 需要 OIDC 登录 (通过 login_required guard 保护).
// handler 从 AuthSession 取当前用户 sub 作为 tenant_id + created_by.

use axum_login::AuthSession;

/// `POST /api/api-keys` 请求体.
#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    /// 人类可读标签.
    #[serde(default)]
    pub label: String,
}

/// 当前已登录用户信息 (从 AuthSession 提取).
/// 用于 API key 签发时绑定 tenant_id + created_by.
fn current_user_sub(auth_session: &AuthSession<crate::auth::OidcBackend>) -> Option<String> {
    auth_session.user.as_ref().map(|u| u.sub.clone())
}

/// 同时校验登录态 + API key store 可用性, 返回 (user_sub, store).
/// 消除 3 个 handler 的重复样板.
fn require_user_and_store<'a>(
    state: &'a ProxyState,
    auth_session: &AuthSession<crate::auth::OidcBackend>,
) -> Result<(String, &'a crate::auth::ApiKeyStore), ApiError> {
    let user_sub = current_user_sub(auth_session)
        .ok_or_else(|| ApiError::unauthorized("not authenticated"))?;
    let api_keys = state
        .api_keys
        .as_ref()
        .ok_or_else(|| ApiError::internal("API key store not configured (auth disabled?)"))?;
    Ok((user_sub, api_keys))
}

/// 列出当前用户的所有 API key 摘要.
///
/// 从所有 keys 中过滤出 tenant_id == 当前用户 sub 的条目.
/// (M1 中 tenant_id = OIDC sub, 每个用户只能看到自己的 key.)
pub async fn list_api_keys(
    State(state): State<ProxyState>,
    auth_session: AuthSession<crate::auth::OidcBackend>,
) -> Result<impl IntoResponse, ApiError> {
    let (user_sub, api_keys) = require_user_and_store(&state, &auth_session)?;
    let all_keys = api_keys.list();
    let user_keys: Vec<_> = all_keys
        .into_iter()
        .filter(|k| k.tenant_id == user_sub)
        .collect();
    Ok((NO_STORE, Json(serde_json::json!({ "keys": user_keys }))))
}

/// 签发新的 API key. 返回明文 (仅此一次).
pub async fn create_api_key(
    State(state): State<ProxyState>,
    auth_session: AuthSession<crate::auth::OidcBackend>,
    Json(payload): Json<CreateApiKeyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let (user_sub, api_keys) = require_user_and_store(&state, &auth_session)?;
    let issued = api_keys
        .issue(&user_sub, &user_sub, &payload.label)
        .map_err(ApiError::from_any)?;
    Ok((StatusCode::CREATED, NO_STORE, Json(issued)))
}

/// 撤销 API key (按 id).
pub async fn delete_api_key(
    State(state): State<ProxyState>,
    auth_session: AuthSession<crate::auth::OidcBackend>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let (user_sub, api_keys) = require_user_and_store(&state, &auth_session)?;
    // 只能撤销自己的 key (tenant_id == user_sub).
    // 先查是否属于当前用户, 不属于则 404 (避免泄漏 key 是否存在).
    let belongs_to_user = api_keys
        .list()
        .into_iter()
        .any(|k| k.id == id && k.tenant_id == user_sub);
    if !belongs_to_user {
        return Err(ApiError::not_found(format!("API key {id} not found")));
    }
    let deleted = api_keys.revoke(&id).map_err(ApiError::from_any)?;
    if deleted {
        Ok((StatusCode::NO_CONTENT, NO_STORE, ""))
    } else {
        Err(ApiError::not_found(format!("API key {id} not found")))
    }
}
