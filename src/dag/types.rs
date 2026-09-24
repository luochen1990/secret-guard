//! DAG 实体类型: Node / CallEvent / ResponseData / Session / SessionId / PolicySnapshot.
//!
//! # 职责边界
//!
//! 本模块是纯数据定义 (struct / enum), 不含任何业务逻辑 (无 impl 块, 除 SessionId::new).
//! 这些类型被 [`super`] (mod.rs mutator + reader) 和 [`super::view`] / [`super::timeline`]
//! (视图构造) 共同使用.
//!
//! # 可见性
//!
//! 公开 API 类型 (Node / CallEvent / ResponseData / SessionId / PolicySnapshot) 标 `pub`,
//! 通过 `crate::dag::*` 路径对外暴露 (mod.rs 用 `pub use types::*` re-export).
//! Session 是 dag 模块内部类型 (不在外部 API), 标 `pub(super)` 让视图层访问.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use uuid::Uuid;

use crate::codec::Protocol as CodecProtocol;
use crate::codec::ir::{IrRole, IrStopReason, IrUsage};

use super::pool::MessageRef;

// ─── PolicySnapshot ────────────────────────────────────────────────────────

/// SecretTable 的 effective view 快照 (COW 共享).
///
/// push node 时取一个 Arc 引用存 node, 用于日后重建 redactMap.
/// 用户编辑 secret 时, SecretTable 替换内部 Arc 指向新版本 (COW), 老版本仍被历史 node 引用.
///
/// 注意: 这里持有的是 SecretEntry (含真实 value), **永不通过 WebUI API 暴露**.
/// 它只在后端内部用于 redactMap 重建.
#[derive(Debug, Default)]
pub struct PolicySnapshot {
    /// 命中的 secret 列表 (已 resolve value 的 SecretEntry).
    pub secrets: Arc<[crate::secrets::SecretEntry]>,
}

// ─── SessionId + Session ───────────────────────────────────────────────────

/// 会话的稳定标识 (运行时生成, 生命周期同 DAG 内存实例).
///
/// 与 leaf_id (游标, 随新请求变化) 和 root_id (fork 时不唯一) 不同,
/// session_id 在会话整个存活期内不变: push 延续时复用, fork / 新根时生成新 id.
/// 前端用它做选中 / 展开标识, 刷新后仍能匹配.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    Default,
)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

/// 轮次的展示类别 (UI-1 契约: 空 delta 轮的渲染语义按此枚举分发, 消除前端捏造).
///
/// 判定是 `(split_at, msgs)` 的纯函数, 在 `push_messages` 内一次性预计算
/// (与 round_role 同位置修正, SSOT); 查询路径零成本透传:
/// - delta 非空 (`split_at < msgs.len()`) → `Normal`: 常规轮, 前端渲染 delta 气泡.
/// - delta 空 + msgs 非空 (全前缀重复, `split_at == msgs.len()`) → `Retry`:
///   客户端重发了 IR 等价的请求 (判定在 IR 哈希层 — 字节级相同是典型场景,
///   JSON 空白/键序差异但 IR 相同的重发同样命中; 重试/批量重测), **用户没有发新消息** —
///   前端渲染 retry 徽章而非消息气泡 (防止捏造 "用户把同一句话说了一遍").
/// - msgs 为空 → `NoMessages`: 请求侧确实无 messages 可渲染
///   (空 body / Responses ingress 的 `input[]` 等), 前端保留 preview fallback 气泡.
///
/// Retry 的展示元数据 (round_role + preview) 继承 parent: parent 的完整 messages
/// == 本请求 body, 其角色/preview 描述的就是同一内容 — 工具轮重试呈 sub-dot 同型
/// 展示, 而非捏造 round_role=User 的伪组首. session 归属: 重发当前 leaf → 延续同
/// session (重试合并); 重发较旧轮次 → fork 开新 session (CDAG-8).
///
/// serde snake_case: "normal" / "retry" / "no_messages" (wire 字段, 前端 switch 消费).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundKind {
    Normal,
    Retry,
    NoMessages,
}

/// 一个会话的元数据 (sidebar 一级树).
///
/// leaf_id 是游标 (最新轮次), 随新请求前移. root_id 是会话根 (parent=None 的那个).
/// node_count 由 push/evict 增量维护, 避免每次 list 都走 parent 链.
///
/// title 是会话标题 (sidebar 主文本): 取自**会话最早 round 的第一条 user msg**
/// (push 时一次性从根 node 的 preview 提取), 之后不再随 leaf 前移而更新.
/// 见 issue #36: 旧实现取 leaf.event.preview (最新轮), 多轮对话中标题随用户每轮
/// 新问题而漂移, 体验差. 现在写入 session map 的 value, 仅在 session 创建时计算一次.
#[derive(Debug, Clone)]
pub(crate) struct Session {
    pub(super) leaf_id: Uuid,
    pub(super) root_id: Uuid,
    pub(super) node_count: usize,
    pub(super) created_at: DateTime<Utc>,
    pub(super) latest_at: DateTime<Utc>,
    /// 会话标题 (sidebar 主文本). 仅在 session 创建时从根 node 的 preview 提取,
    /// 之后不再更新 (即便有新 round 加入). 见上方类型注释.
    ///
    /// `Arc<str>`: 直接共享根 node 的 preview, list_sessions 路径只增引用计数.
    pub(super) title: Option<Arc<str>>,
}

// ─── Node + CallEvent + ResponseMeta ───────────────────────────────────────

/// DAG 节点 = 一次 API 调用.
#[derive(Debug)]
pub struct Node {
    pub id: Uuid,
    /// 父节点 (前缀关系). None = 会话根或孤立节点 (无 messages 的请求).
    pub parent: Option<Uuid>,
    /// 所属会话的稳定标识 (push 时确定, 生命周期同 DAG 内存实例).
    /// fork 场景: 新 node 的 parent 不是其 session 的当前 leaf → fork → 新 SessionId.
    pub session_id: SessionId,
    /// 引用计数: 有多少 node 把本 node 作为 parent. leaf 的 child_count=0.
    /// evict 时从 leaf 级联 GC: child_count=0 可删, 删后递减 parent, 若也变 0 则级联.
    pub child_count: usize,
    /// 客户端发出的 request 中, 相对 parent 的增量.
    ///
    /// 存储的是**真实内容** (含真实 secret, 即 OriginRecord 视角).
    /// 输出给 LLM / WebUI 时 apply redactMap 转为 SecureRecord (含 mock).
    ///
    /// **不含** LLM 返回的 response — response 独立存在 `response` 字段,
    /// 且存储语义不同 (response 存 LLM 视角的 mock 版本, req_delta 存客户端视角的 real 版本).
    ///
    /// 冗余通过 BlockPool 内容寻址自然消化 (相同 block 物理共享).
    pub req_delta: Arc<[MessageRef]>,
    /// 根节点 (parent=None) 请求的 system blocks (real 视角, 内容寻址引用).
    ///
    /// 仅根节点持有 (非根节点的 system 属于根的上下文, timeline 只在根注入 —
    /// 与旧 `extract_delta_messages_from_raw` 的注入条件 `parent.is_none() && start > 0`
    /// 等价, 见 `derive::extract_delta_messages_from_blocks`). block 经
    /// [`super::BlockPool::intern`] 入池 (跨节点 system 文本相同则物理共享),
    /// evict 时随 node 一起 release refcount.
    ///
    /// 消费方: `derive::extract_delta_messages_from_blocks` (B1, timeline 根节点
    /// system 气泡派生 — req_body_raw 不再是 system 的唯一存储位置).
    pub system_refs: Arc<[super::pool::BlockHash]>,
    /// 本 node 自身 req_delta 的 hash (不含祖先).
    pub own_hash: u64,
    /// 从根到本 node 的累积 hash: 逐条 req_delta message 累积.
    /// 用于新请求到达时 O(N) 比对前缀.
    pub prefix_hash: u64,
    pub event: CallEvent,
    /// LLM 返回的 response (独立存储). 初始 None, 上游响应到达时填入.
    ///
    /// 存储的是 **LLM 原始返回** (含 mock secret, 即 SecureRecord 视角).
    /// 这是"忠实于原始数据"的体现: LLM 返回什么就存什么, 不提前 restore.
    ///
    /// restore (mock → real) 是 lazy 的, 只在构造发给客户端的响应时触发,
    /// **restore 不发生在 DAG 存储路径上** (只在 proxy → client 实时转发路径上做).
    ///
    /// WebUI 读取 response 时原样展示 (LLM 视角, 含 mock).
    /// WebUI 读取 req_delta 时 apply redactMap 转 mock (LLM 视角).
    /// 两边都是 LLM 视角, 审计语义一致 ("LLM 实际看到了什么").
    ///
    /// response 的 message content 也通过 BlockPool intern (享受跨节点 dedup).
    pub response: RwLock<Option<ResponseData>>,
}

/// 一次 API 调用的事件元数据.
///
/// 响应侧元数据 (`resp_status` / `resp_headers` / `elapsed_ms`) **不在此处** —
/// 它们只存在于 [`Node::response`] (`ResponseData`) 的 RwLock 内, 让
/// [`super::ConversationDag::attach_response`] 能在外层 read lock 下通过 node-level 锁
/// 更新单节点, 不阻塞并发 push / 其他节点的 attach (perf: 两级锁).
/// `ConversationDag::node_view` / `ConversationDag::session_view` 从
/// `node.response.read()` 取这些字段.
#[derive(Debug)]
pub struct CallEvent {
    pub created_at: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub req_headers: Vec<(String, String)>,
    // 历史曾保留 `req_envelope` (请求侧非 message 字段: model / temperature / tools /
    // system 等) 用于"未来 WebUI 展示 system/tools", 但从未读取, 2026-07 删除 (YAGNI).
    // 需要时通过 git log 找回: commit 删除 req_envelope.
    pub ingress_protocol: Option<CodecProtocol>,
    /// redact 的随机性来源 (probe 后的最终值).
    /// - 0 = passthrough (无 secret 命中 / SecretTable 为空).
    /// - 非 0 = derive(policy, OriginRecord, seed) 可重建 redactMap.
    pub redact_seed: u64,
    /// **瞬态载荷**: redact 前 (real 视角) 快照的请求 system blocks.
    ///
    /// 由 `build_call_event` 从 pre-redact IR 填入, `push_messages` 消费:
    /// 根节点 → intern 进 [`Node::system_refs`] 后**清空本字段**; 非根 → 直接
    /// 丢弃 (清空). 稳态下 Node.event 内本字段恒为空 vec, 不占运行内存.
    ///
    /// 放 CallEvent 而非 push 参数: 与 `req_body_raw` 同属 "请求侧快照",
    /// 由同一构造器收口, push 签名不变 (测试调用点零改动).
    pub req_system: Vec<crate::codec::ir::IrBlock>,
    /// redact 时使用的 policy 快照 (Arc COW 共享).
    /// redact_seed=0 时此字段可为 default (空 secrets).
    pub policy: Arc<PolicySnapshot>,
    /// 请求 body 快照 (LLM 视角, 已 redact, UTF-8 视图).
    ///
    /// 这是 WebUI 的 `req_body` 字段权威来源:
    /// - **codec 路径** (same-proto + redact / cross-proto): redact 后的 IR 经 ingress
    ///   writer 重序列化为 wire JSON 字符串. 与原始请求字节不同 (redact + 重序列化).
    /// - **passthrough 路径** (same-proto 无 redact): 客户端原始请求字节 (未 redact,
    ///   因为无机密命中). Gemini/Ollama 等无 codec 协议也走此路径.
    ///
    /// 设计权衡: 虽然 DAG 的 `req_delta` (真实消息) 理论上足以在查询时重建 redact 后
    /// 的请求体, 但那需要在 Web 查询路径上跑 redact + codec writer, 对偶尔翻页的 WebUI
    /// 场景性价比低. 直接存快照 (一次写, 多次读) 是更经济的选择.
    /// `req_delta` 仍用于内容寻址去重 (DAG 核心价值) + 未来 lazy redact 功能.
    pub req_body_raw: String,
    /// 本轮的主导角色 = "用户是否主动输入了新内容".
    /// 语义: round_role == User 表示这一轮有用户的新提问 (sidebar 显示为 round-item 组首);
    ///       round_role == Tool 表示这一轮是工具调用循环 (sidebar 折叠为 sub-dot).
    /// push 时一次性预计算, O(0) 查询.
    ///
    /// 判定基于 `IrMessage::contains_user_text` (reader 入口预计算, 标记 "真用户文本输入"
    /// 而非 "工具结果借 user 角色承载"). delta 任一条 contains_user_text → User.
    /// 不依赖 `IrMessage.role`: codec 归一化把 tool 消息也映射为 IrRole::User.
    pub round_role: IrRole,
    /// 轮次展示类别 (Normal / Retry / NoMessages), 判定语义见 `RoundKind` 文档.
    /// 构造点占位 Normal; push_messages 内按 split_at 修正 (与 round_role 同模式).
    pub round_kind: RoundKind,
    /// WebUI sidebar / timeline preview 文本 (push 时从 req_body_raw 提取, 截断 48 chars).
    ///
    /// 提取逻辑见 derive::extract_preview_and_model (协议无关字节级):
    /// 优先取最后一条 user message, 无 user 时 fallback 到最后一条有文本的 message
    /// (tool_result / assistant). 不按 round_role 分发 (历史决策, 简单但非最优).
    ///
    /// `Arc<str>` 让 list/session 路径只增引用计数, 不复制字符串 (3s 轮询场景).
    pub preview: Option<Arc<str>>,
    /// 请求 body 顶层 model 字段 (OpenAI / Anthropic 共有). push 时一次性提取.
    /// `Arc<str>` 同上 (list 路径免 clone).
    pub model: Option<Arc<str>>,
    /// 本轮实际承载转发的 provider id (#179): 路由 provider 经
    /// `resolve_route` 解析后的**链尾实体 provider** id; 非路由请求时即 URL 中的
    /// provider id. 可观测性字段 — WebUI 用它区分 "客户端连的路由 endpoint" 与
    /// "实际命中的上游" (规则切换后, 历史轮次仍如实记录各自的实际归属).
    pub upstream_id: Arc<str>,
    /// 本次请求中实际发生的 redact 结果 (权威投影, 供 WebUI 渲染).
    /// 每个 tuple = `(mock_value, secret_id)`. **永不**包含真实 secret 值.
    /// 在 push 时设置 (redactions 是请求侧属性, 不依赖 response).
    ///
    /// `Arc<[(String,String)]>` 让 list/session 路径共享切片而非 clone Vec
    /// (clone 成本随命中 secret 数线性增长).
    pub redactions: Arc<[(String, String)]>,
    /// 实际发往上游的 model 值 (#183 D4): 仅当路由规则 **实际改写**了
    /// egress IR 时 Some (passthrough / 无 codec 降级恒 None — 非 None-ness 即
    /// "本轮被改写" 的信号). `event.model` 保持 egress 视角派生
    /// (req_body_raw SSOT), 改写生效时两者同值.
    pub upstream_model: Option<Arc<str>>,
    /// 本轮 push 时 audit_capture 档位的快照. `Off` = 该请求未捕获 raw
    /// (`req_body_raw` 为空串); `Errors` = 在途暂存 (响应落地后成功清除 / 错误
    /// 保留 — attach 沿用**本快照**决策, per-request 原子, 决策 SSOT 见
    /// `crate::config::AuditCaptureMode`). WebUI 经
    /// `ForwardRecord.audit_capture_off` 消费 (区分 "空 body" vs "未捕获").
    pub capture_mode: crate::config::AuditCaptureMode,
}

/// LLM 返回的 response 数据 (message content + 元数据).
///
/// 存储的是 LLM 原始返回 (含 mock, restore 前).
#[derive(Debug, Clone, Default)]
pub struct ResponseData {
    /// response 的 assistant message (LLM 原始返回, 含 mock, **未 restore**).
    /// 通常是一条 IrMessage (role=assistant), 但错误响应时可能为空.
    pub message: Option<MessageRef>,
    /// 上游回显的 token 用量 (usage-stats 采集, docs/design/usage-stats.md §5).
    ///
    /// `Some` ⇔ `IrResponse.usage_present` (wire 显式携带 usage 对象 — 区分
    /// "无回显" 与 "显式零回显", P-3 缺失显式原则). 流式侧 = StreamScan 曾观测到
    /// usage 承载事件 (中断流的已累积部分值, 配合 `resp_complete=false` 语义).
    /// `None` = 无回显 (非 2xx / parse 失败 / OpenAI 流式未开 include_usage /
    /// 无 codec 协议) — 请求数仍进统计, token 不进 (USAGE-4).
    pub usage: Option<IrUsage>,
    pub stop_reason: Option<IrStopReason>,
    pub stop_sequence: Option<String>,
    pub id: Option<String>,
    pub created: Option<u64>,
    pub model: Option<String>,
    /// 原始上游 response wire bytes (审计/调试).
    pub raw_resp_body: String,
    pub streamed: bool,
    pub resp_complete: bool,
    pub error: Option<String>,
    /// parsed view (ingress codec writer 序列化的 IrResponse, LLM 视角含 mock).
    /// B1 双态: **流式进行中** = ParsedSync 节流写入的快照 (前端实时进度, 经
    /// `update_parsed_response`); **finalize 后被清除** (set None) — 渲染点从
    /// `message` + 元字段派生 (`derive::response_parsed_from_parts`, 稳态不再
    /// 长期存 Value — B2 "详细日志" 开关的硬前置).
    pub parsed: Option<serde_json::Value>,
    /// 上游响应状态码 (attach 时填入; 也镜像到 CallEvent 供 NodeView).
    pub resp_status: u16,
    /// 上游响应 headers (敏感 header 已脱敏).
    pub resp_headers: Vec<(String, String)>,
    /// 端到端耗时 (毫秒).
    pub elapsed_ms: u64,
}

impl ResponseData {
    /// 错误判定 (audit_capture "errors" 档的保留判据, SSOT):
    /// 显式 error 字段 (超时/连接失败/流中断等) 或 HTTP 状态非 2xx.
    /// `resp_status == 0` 且无 error (理论外的空态) 按错误处理 — 偏保留
    /// (排障语义下宁可多留一条, 与 Off 的偏丢弃不对称是有意的).
    ///
    /// 隐式依赖 (调整 status=0 分支前必读): 在途 partial ResponseData
    /// (update_parsed_response 建的 default) 走此分支 → `retain(Errors, true)`
    /// = true — 这正是 "在途未定按保留 (暂存可看)" 语义 (NodeView.audit_retained)
    /// 的实现载体, 改动此分支会让在途窗口的 retained 静默翻转.
    pub fn is_error(&self) -> bool {
        self.error.is_some() || !(200..300).contains(&self.resp_status)
    }
}
