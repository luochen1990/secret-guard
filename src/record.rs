//! 转发记录 DTO (web 层响应序列化用).
//!
//! 历史上这里是 RecordStore (扁平 VecDeque 存储), 现已迁移到 [`crate::dag::ConversationDag`]
//! (内容寻址 + Merkle prefix + FIFO 淘汰). 本文件仅保留 [`ForwardRecord`] 与
//! [`RecordFilter`] 两个 DTO, 作为 Web API 响应的 JSON shape (供 [`crate::web::api`] 构造).
//!
//! DTO 字段从 [`crate::dag`] 的 NodeView / NodeDetail / ResponseData 派生, 由
//! [`crate::web::api`] 在查询时填充. 保留这个独立 DTO (而非直接 serialize DAG 内部类型)
//! 是为了:
//! - 维持 Web API JSON shape 稳定 (不随 DAG 内部结构变化而漂移);
//! - 集中"暴露哪些字段给前端"的决策 (eg `redactions` 不含真实 secret value).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// 列表过滤维度. WebUI 的 All / Hits 两个 tab 各自独立分页,
/// 服务端按此枚举过滤并返回该维度下的 total.
///
/// - `All`: 不过滤 (默认, 向后兼容).
/// - `Hits`: 只保留 `redactions` 非空的记录 (本次请求实际发生了 redact).
///
/// 序列化为小写字符串, 直接作 query param 值: `?filter=all` / `?filter=hits`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordFilter {
    #[default]
    All,
    Hits,
}

/// 单条转发记录 (Web DTO).
///
/// 字段从 [`crate::dag::NodeView`] / [`crate::dag::NodeDetail`] / [`crate::dag::ResponseData`]
/// 派生, 由 [`crate::web::api`] 构造. 不再是存储后端 (那是 DAG 的职责).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardRecord {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub method: String,
    pub path: String,
    /// 客户端请求的所有 header (敏感 header 如 Authorization 会被脱敏).
    pub req_headers: Vec<(String, String)>,
    /// 客户端请求 body (LLM 视角, 已 redact; UTF-8 视图).
    pub req_body: String,
    /// 上游响应状态码 (0 表示尚未收到响应 / 上游错误).
    pub resp_status: u16,
    /// 上游响应的所有 header.
    pub resp_headers: Vec<(String, String)>,
    /// 上游响应 body.
    ///
    /// - **非流式响应**: 原始 JSON body (与上游返回的字节一致, UTF-8 视图).
    /// - **流式响应**: **不再保留原始 SSE 字节** (骨架开销大、可读性差).
    ///   流式响应的语义内容通过 [`resp_parsed`](Self::resp_parsed) 累积.
    ///   raw view 在流式场景下显示 "raw bytes not retained for streamed responses".
    pub resp_body: String,
    /// 解析后的响应 (ingress 协议的 canonical chat JSON, chat-bubble 友好).
    ///
    /// - **非流式**: 在响应完成时由 codec reader → IR → writer 计算一次.
    /// - **流式**: 在流过程中由 `StreamScan` 增量累积, 节流写入.
    ///
    /// `None` 表示尚未有解析结果 (流刚开始 / codec 不支持此协议 / 解析失败).
    /// 对应 `GET /records/{id}?view=parsed` 的 `parsed_response` 字段.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resp_parsed: Option<serde_json::Value>,
    /// 端到端耗时 (毫秒).
    pub elapsed_ms: u64,
    /// 流式标记: true 表示响应是 chunked / SSE.
    pub streamed: bool,
    /// 响应完整性: false 表示上游错误/客户端断开导致响应中断.
    pub resp_complete: bool,
    /// 错误诊断 (仅在出错时填入; 用于 Web UI 展示).
    pub error: Option<String>,
    /// 本次请求中实际发生的 redact 结果 (权威投影, 供 WebUI 渲染).
    ///
    /// 每个 tuple = `(mock_value, secret_id)`. **永不**包含真实 secret 值, 因此可以
    /// 直接序列化到 GET API 响应. 空 vec 表示本次请求没有发生 redact
    /// (passthrough 路径, 或同/跨协议路径但 IR 中没有 secret 命中).
    ///
    /// 来源: 在 [`crate::proxy`] 三处 push 点, 从 `RedactionMap` + `secrets_snapshot`
    /// 派生而来. 仅记录命中的 secret — 若 secret 在表中但本次请求体没有, 不进入此列表.
    ///
    /// `#[serde(default)]` 让旧版序列化数据 (无此字段) 仍能反序列化为空 vec.
    #[serde(default)]
    pub redactions: Vec<(String, String)>,
}

impl ForwardRecord {
    pub fn new(
        method: String,
        path: String,
        req_headers: Vec<(String, String)>,
        req_body: String,
    ) -> Self {
        Self {
            id: Uuid::nil(),
            created_at: Utc::now(),
            method,
            path,
            req_headers,
            req_body,
            resp_status: 0,
            resp_headers: Vec::new(),
            resp_body: String::new(),
            resp_parsed: None,
            elapsed_ms: 0,
            streamed: false,
            resp_complete: false,
            error: None,
            redactions: Vec::new(),
        }
    }
}
