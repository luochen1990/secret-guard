//! WebUI 响应序列化的 DTO 类型 (域 B → 域 C 的 wire shape).
//!
//! # 职责边界
//!
//! 本模块定义 Web API 响应 (`/api/sessions`, `/api/sessions/{sid}/timeline`,
//! `POST /api/sync`) 的 JSON 形态. 这些类型是 **域 B (派生链) → 域 C (渲染层)** 的
//! wire shape: 从 DAG 读取数据后构造, 序列化为前端消费的 JSON.
//!
//! # 为什么不在 `dag.rs`
//!
//! 历史上这些 DTO 定义在 [`crate::dag`], 但 [`crate::dag`] 是纯内存的内容寻址存储
//! (BlockPool + Node + Merkle), 不关心也不应该关心序列化形态. 让 `dag.rs` derive
//! `Serialize` 把存储层与 wire shape 耦合, 违反单一职责. 故把 DTO 定义下沉到本模块
//! (web 层), 让 dag.rs 只保留核心数据结构 (BlockPool / Node / Session / ConversationDAG).
//!
//! # 构造方法留 dag.rs (不在本模块)
//!
//! 这些 DTO 的**构造逻辑** (从 DAG 内部字段填充) 仍保留在 `dag.rs` 的方法 / free
//! function 中 (`node_view` / `session_view` / `build_timeline_round` 等), 因为它们需
//! 持 `DagInner` 读锁访问私有字段 (`Node.event` / `Node.response` / `Session` 等).
//! 移到 web 层会要求暴露 DAG 内部结构, 代价超过收益. dag.rs 依赖 web::dto (本模块)
//! 的类型定义是可接受的域内依赖 (web::dto 是哑数据载体, 非 web::api 展示层 handler).
//!
//! # 与 `record::ForwardRecord` 的分工
//!
//! [`crate::record::ForwardRecord`] 是另一个 web 层 DTO (GET /records/{id} 响应),
//! 历史上独立维护 "维持 Web API JSON shape 稳定" 的职责. 本模块的 9 个 DTO 与之同源
//! (都是 web 层 wire shape), 仅按 endpoint 分文件: 本模块服务 sessions/timeline/sync,
//! record.rs 服务 records 单条详情.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::codec::ir::IrRole;
use crate::dag::SessionId;

/// 会话视图 (sidebar 一级树).
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionView {
    /// 会话稳定标识 (前端选中/展开用, 刷新后不变).
    pub session_id: SessionId,
    /// 叶子节点 id (会话最新一轮). timeline 请求起点.
    pub leaf_id: Uuid,
    /// 根节点 id (会话第一轮 或 fork 点).
    pub root_id: Uuid,
    /// 会话内轮次数 (push 时增量维护, 无需走 parent 链).
    pub record_count: usize,
    /// 会话开始时间 (根节点 created_at).
    pub created_at: DateTime<Utc>,
    /// 最新活动时间 (叶子节点 created_at, LRU 淘汰用).
    pub latest_at: DateTime<Utc>,
    /// preview (叶子节点的最后一条 user msg 截断).
    ///
    /// `Arc<str>`: list_sessions (3s 轮询) 路径共享切片而非 clone 字符串.
    /// serde 透明序列化为 string, 前端无感知.
    pub preview: Option<Arc<str>>,
    /// model (叶子节点). `Arc<str>` 同上.
    pub model: Option<Arc<str>>,
    /// 最新轮次的上游响应状态.
    pub latest_resp_status: u16,
    /// 最新轮次的错误 (若有).
    pub latest_error: Option<String>,
    /// 最新轮次的 redactions. `Arc<[(String,String)]>`: 共享切片而非 clone Vec.
    pub redactions: Arc<[(String, String)]>,
    /// 叶子节点 HTTP path (形如 "/o/<provider_id>/..."), 前端 provider icon 据此解析
    /// protocol 角标 + provider id. 取最近一轮的 provider, 跨 provider 重试场景下
    /// 可能不代表整条会话的 provider.
    pub path: String,
}

/// Node 的轻量只读视图 (供 list / 元数据查询).
///
/// 不含 messages body 与 resp_body / req_body_raw (避免 clone 大量数据);
/// 含 list 场景需要的所有元数据 (preview / model / redactions / 响应状态等).
///
/// `parsed_response`: timeline 路径用 (前端不再 N+1 拉 /records/{id}?view=parsed).
/// 从 node.response.parsed clone (仅在有解析结果时), 避免前端再发请求.
#[derive(Debug, Clone)]
pub struct NodeView {
    pub id: Uuid,
    pub parent: Option<Uuid>,
    /// 所属会话的稳定标识 (push 时确定).
    pub session_id: SessionId,
    /// 本轮的主导角色 = req_delta 最后一条 message 的 role.
    /// 语义: "由于谁发了最后一条消息而触发了这次 HTTP 请求".
    /// WebUI 用它决定 sidebar 条目样式 + timeline 气泡渲染.
    pub round_role: IrRole,
    pub req_delta_count: usize,
    pub has_response: bool,
    pub created_at: DateTime<Utc>,
    pub elapsed_ms: u64,
    pub method: String,
    pub path: String,
    pub resp_status: u16,
    pub redact_seed: u64,
    /// WebUI sidebar 标题 (最后一条 user message 截断).
    /// `Arc<str>`: list/timeline 路径共享切片而非 clone (serde 透明序列化).
    pub preview: Option<Arc<str>>,
    /// 请求 body 顶层 model 字段. `Arc<str>` 同上.
    pub model: Option<Arc<str>>,
    /// 是否流式响应.
    pub streamed: bool,
    /// 响应是否完整 (上游错误 / 客户端断开 → false).
    pub resp_complete: bool,
    /// 错误诊断.
    pub error: Option<String>,
    /// (mock, secret_id) 投影. 永不含真实 secret value.
    /// `Arc<[(String,String)]>`: 共享切片而非 clone Vec.
    pub redactions: Arc<[(String, String)]>,
    /// parsed view (ingress codec writer 序列化的 IrResponse, LLM 视角含 mock).
    /// timeline 路径直接消费, 前端不再 N+1 拉 /records/{id}?view=parsed.
    pub parsed_response: Option<serde_json::Value>,
    /// 本轮 request delta (相对 parent 的增量 messages, 协议无关 wire JSON).
    ///
    /// 只在 timeline 路径填充 (list_page 路径留空, 避免 O(n) 全量 resolve).
    /// 前端用于渲染本轮新增的气泡 (system / user / tool_result 等),
    /// 实现每轮 preview + 完整 delta 展示 (issue #27).
    ///
    /// 每个元素是 message 的 wire JSON (OpenAI / Anthropic 原生格式),
    /// 前端按 role 分发气泡样式, 与 response 气泡区分.
    pub req_delta_messages: Vec<serde_json::Value>,
}

/// Node 的请求侧详情 (GET /records/{id} 按需拉取).
#[derive(Debug, Clone)]
pub struct NodeDetail {
    pub req_headers: Vec<(String, String)>,
    pub req_body_raw: String,
}

// ─── WebUI sync API 数据结构 (session-aware timeline + sync) ───────────────
//
// 替代旧的 NodeView timeline (基于 node_id) + list_records (扁平分页).
// 新模型基于 SessionId: sidebar 折叠会话树 + timeline 按 session 分页 + sync diff.
//
// 三条查询路径:
// - session_rounds(sid): sidebar 三级菜单的轻量 round 摘要.
// - timeline_view(sid, before, limit): timeline 初始加载 + lazy load (向前翻更老).
// - timeline_diff(sid, after, tail_length): sync 轮询的 diff.
// 三者共享 TimelineRound 结构 (含 req_delta_messages).

/// sidebar 三级菜单的轻量 round 摘要 (不含 req_delta_messages, 节省 3s 轮询带宽).
///
/// 字段直接从 `Node.event` 派生 (push 时预计算), 不 walk parent 链, 不 resolve block.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RoundBrief {
    pub id: Uuid,
    pub round_role: IrRole,
    /// `Arc<str>`: 共享 event.preview, 轮询路径零拷贝.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<Arc<str>>,
    pub created_at: DateTime<Utc>,
}

/// timeline 每轮的完整数据 (含 request delta messages 的 wire JSON).
///
/// 与 RoundBrief 的区别: 多了 redactions + req_delta_messages (前端渲染气泡用).
/// `req_delta_messages` 通过 ingress codec writer 序列化 (BlockPool resolve → IR → wire),
/// 保证同协议路径正确; 跨协议 / codec 缺失时 fallback 到 req_body_raw 末尾切片
/// (旧实现, 已知有跨协议切片错位 bug, 见 AGENTS.md "已知限制").
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimelineRound {
    pub id: Uuid,
    pub round_role: IrRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<Arc<str>>,
    pub created_at: DateTime<Utc>,
    /// `Arc<[(String,String)]>`: 共享 event.redactions, 零拷贝.
    /// 每个 tuple = (mock_value, secret_id), **永不**含真实 secret.
    pub redactions: Arc<[(String, String)]>,
    /// 本轮 request delta (相对 parent 的增量 messages, wire JSON).
    /// 前端按 role 渲染气泡 (system/user/tool), 与末轮 response 抽屉互补.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub req_delta_messages: Vec<serde_json::Value>,
}

/// timeline 抽屉 (视图级, 当前末轮的 response 内容).
///
/// 仅 timeline_view 的初始加载 / timeline_diff 的更新会推送新 tail;
/// 前端用 length 做 diff 判定 (是否需要更新抽屉内容).
/// 非 timeline 末轮的 response 内容已被下一轮 delta 的 assistant message 包含
/// (Phase A 决策, 详见旧 timeline 实现), 故 tail 只代表"最新尚未被 delta 消费的 response".
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimelineTail {
    pub round_id: Uuid,
    /// response 内容的字节长度 (前端用它判定是否需要更新抽屉).
    /// = parsed 序列化字节数 (parsed 为 None 时 fallback 到 raw_resp_body.len()).
    pub length: usize,
    pub resp_status: u16,
    pub elapsed_ms: u64,
    pub streamed: bool,
    pub resp_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// parsed view (ingress codec writer 序列化的 IrResponse, LLM 视角含 mock).
    /// 流式响应由 StreamScan 累积; 非流式在响应完成时一次性计算.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parsed: Option<serde_json::Value>,
}

/// GET /sessions/{sid}/timeline 的完整响应.
///
/// `rounds`: oldest-first, limit 条 (含末轮).
/// `tail`: 末轮 (rounds 最后一个) 的 response 抽屉数据.
/// `has_more`: 链上还有更老的 node (limit 之外), 前端用于显示 "load more" 提示.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimelinePage {
    pub rounds: Vec<TimelineRound>,
    pub tail: TimelineTail,
    pub has_more: bool,
}

/// sync 的 timeline diff 部分 (POST /api/sync 的 response.timeline).
///
/// `new_rounds`: after 游标之后新增的 round (oldest-first).
/// `tail`: 当前末轮的 response 抽屉 (前端用它 + length 判定是否需要更新).
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimelineDiffData {
    pub new_rounds: Vec<TimelineRound>,
    pub tail: TimelineTail,
}

/// POST /api/sync 的完整快照 (一个 read lock 内采集).
///
/// 三部分:
/// - `sessions`: 所有 session 的 SessionView (sidebar 一级树).
/// - `rounds`: 仅 expanded session 的 RoundBrief 列表 (sidebar 三级菜单).
/// - `timeline`: 仅 selected session 的 diff (timeline 初始加载 / 增量更新).
///
/// 在单个 `inner.read()` 锁内一次性采集, 避免多次 list_sessions / timeline_view
/// 之间数据漂移 (典型: 新 push 在两次读锁之间到达, sessions 与 rounds 不一致).
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncSnapshot {
    pub sessions: Vec<SessionView>,
    pub rounds: HashMap<SessionId, Vec<RoundBrief>>,
    /// None = 无选中 / 无 diff (前端持有的游标已是最新, 304 等价).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline: Option<TimelineDiffData>,
}
