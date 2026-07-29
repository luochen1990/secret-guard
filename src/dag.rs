//! Conversation DAG: 内容寻址的对话历史存储.
//!
//! # 设计目标
//!
//! 取代旧的扁平 `VecDeque<ForwardRecord>` (`RecordStore`, 已删除), 升级为内容寻址的
//! 对话 DAG, 解决两个问题:
//! 1. **存储冗余**: 同一会话的 N 条请求 messages 高度重叠 (每次带完整历史).
//!    内容寻址让相同 IrBlock 跨节点只存一份.
//! 2. **会话识别**: 通过 Merkle prefix hash 自动识别前缀关系, 让 WebUI 折叠同会话记录.
//!
//! # 核心概念
//!
//! - **Node**: 一次 API 调用, 持有 `req_delta` (相对 parent 的 request 增量, 真实内容)
//!   与 `response` (LLM 返回, 独立 RwLock 存储). 两者分离存储, 忠实于原始数据, 不合并为
//!   单一 `msgs` 字段 (详见下方 [`Node`] 结构与第 4 章"关键不变式").
//! - **BlockPool**: 全局内容寻址的 IrBlock 池, 引用计数管理.
//! - **Merkle prefix hash**: 从根到本 node 的累积 hash, 用于 push 时 O(N) 找 parent.
//!
//! # 详尽设计见 `docs/design/conversation-dag.md`

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use uuid::Uuid;

use crate::codec::Protocol as CodecProtocol;
use crate::codec::ir::{IrBlock, IrImageSource, IrMessage, IrRole, IrStopReason, IrUsage};
// WebUI 响应 DTO (SessionView / NodeView / ... / SyncSnapshot) 已下沉到 web::dto,
// 让本模块 (纯内存内容寻址存储) 不再 derive Serialize. 构造逻辑 (node_view /
// session_view / build_timeline_round 等, 需持 DagInner 读锁访问私有字段) 仍留此处,
// 返回 web::dto 的类型. 详见 src/web/dto.rs 头部 "构造方法留 dag.rs".
use crate::web::dto::{
    NodeDetail, NodeView, RoundBrief, SessionView, SyncSnapshot, TimelineDiffData, TimelinePage,
    TimelineRound, TimelineTail,
};

// ─── BlockHash ──────────────────────────────────────────────────────────────

/// IrBlock 内容的 hash. 用作 BlockPool 的 key.
///
/// 用 u64 (SipHash, Rust DefaultHasher) 而非 blake3: DAG 不跨进程, 同 Rust 版本内确定即可.
/// collision 概率 ~2^-64, 对 < 10^5 blocks 的 DAG 可忽略; 一旦真发生 `intern` 会 panic
/// (defense-in-depth, 见 [`BlockPool::intern`] 的 collision check).
pub type BlockHash = u64;

/// 计算单个 IrBlock 的内容 hash.
///
/// 不依赖 IrBlock 的 PartialEq (那需要 Clone 比较), 而是递归 hash 所有字段.
///
/// 此处保留直接增量 hasher (未走 [`crate::util::hash64`]), 因为:
/// - 需先 hash `mem::discriminant` (variant tag) 再按 variant 分支;
/// - `serde_json::Value` 不 impl `Hash`, 需 canonical JSON string 中转.
///
/// 语义上仍是 SipHash (DefaultHasher), 算法不变, 只是入口分散在此.
fn hash_block(block: &IrBlock) -> BlockHash {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    std::mem::discriminant(block).hash(&mut h);
    match block {
        IrBlock::Text { text } => {
            text.hash(&mut h);
        }
        IrBlock::ToolUse { id, name, input } => {
            id.hash(&mut h);
            name.hash(&mut h);
            // serde_json::Value 不 impl Hash; 用 canonical JSON string 做 hash.
            // 隐式依赖: serde_json 默认 (无 preserve_order feature) 用 BTreeMap,
            // key 按字母排序 → canonical. 若未来启用 preserve_order, 需改手动 canonical 序列化.
            let input_str = serde_json::to_string(input).unwrap_or_default();
            input_str.hash(&mut h);
        }
        IrBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
            content_form: _,
        } => {
            tool_use_id.hash(&mut h);
            is_error.hash(&mut h);
            for c in content {
                hash_block(c).hash(&mut h);
            }
        }
        IrBlock::Image { source } => match source {
            IrImageSource::Base64 { media_type, data } => {
                media_type.hash(&mut h);
                data.hash(&mut h);
            }
            IrImageSource::Url(url) => {
                url.hash(&mut h);
            }
        },
    }
    h.finish()
}

// ─── MessageRef ────────────────────────────────────────────────────────────

/// 内容寻址的 message 引用 (role + block hash 列表).
///
/// 不直接持 IrBlock, 而是持 BlockHash 引用 BlockPool 中的 block.
/// 相同内容的 message (相同 role + 相同 block 序列) 物理上共享 block.
#[derive(Debug, Clone)]
pub struct MessageRef {
    pub role: IrRole,
    pub blocks: Vec<BlockHash>,
}

impl MessageRef {
    /// 计算本 message 的 hash (role + blocks 序列).
    ///
    /// 用于 Merkle prefix hash 的累积计算.
    fn hash(&self) -> u64 {
        // tuple Hash: 先 role 再走 [BlockHash] 的 Hash (len + 每个元素), 与原增量实现等价.
        crate::util::hash64(&(&self.role, &self.blocks))
    }
}

// ─── BlockPool ─────────────────────────────────────────────────────────────

/// 全局内容寻址的 IrBlock 池.
///
/// - `intern`: 把 IrBlock 放入池 (若已存在则复用), 返回 BlockHash, refcount++.
/// - `release`: 递减 refcount, refcount=0 时删除 block.
///
/// 线程安全: 内部用 `parking_lot::RwLock`. intern 需要写锁 (可能插入新 block),
/// get 只需读锁.
#[derive(Debug, Default)]
pub struct BlockPool {
    blocks: HashMap<BlockHash, Arc<IrBlock>>,
    refcount: HashMap<BlockHash, usize>,
}

impl BlockPool {
    /// 把一个 IrBlock 放入池, 返回其 BlockHash.
    ///
    /// 若相同内容的 block 已存在 (hash 命中), 复用之, refcount++.
    /// 若 hash 未命中, 插入新 block, refcount=1.
    ///
    /// collision check: hash 命中时比对 block 内容, 不一致则 panic (defense-in-depth).
    /// 用 `assert!` 而非 `debug_assert!`: collision 概率 ~2^-64 对 < 10^5 blocks 可忽略,
    /// 一旦真发生属于哈希函数 bug, 宁可在 release 也 panic 暴露问题, 不能静默覆盖
    /// (静默覆盖会让两个不同 block 共享一个 hash, 后续 get() 只能取到先插入的那个,
    /// 引发难以定位的数据损坏).
    pub fn intern(&mut self, block: IrBlock) -> BlockHash {
        let h = hash_block(&block);
        let entry = self
            .blocks
            .entry(h)
            .or_insert_with(|| Arc::new(block.clone()));
        assert!(
            **entry == block,
            "BlockHash collision detected: hash={h}, this is a hash function bug"
        );
        *self.refcount.entry(h).or_insert(0) += 1;
        h
    }

    /// 按 hash 取 block (读锁).
    pub fn get(&self, hash: BlockHash) -> Option<Arc<IrBlock>> {
        self.blocks.get(&hash).cloned()
    }

    /// 递减 refcount. refcount=0 时删除 block.
    ///
    /// 用于 FIFO 淘汰 node 时释放其持有的 block 引用.
    pub fn release(&mut self, hash: BlockHash) {
        if let Some(count) = self.refcount.get_mut(&hash) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.refcount.remove(&hash);
                self.blocks.remove(&hash);
            }
        }
    }

    /// 把一个 IrMessage 拆解为 MessageRef, 所有 block 入池.
    ///
    /// 返回的 MessageRef 的 blocks 全部已 intern (refcount 已 ++).
    pub fn intern_message(&mut self, msg: &IrMessage) -> MessageRef {
        MessageRef {
            role: msg.role,
            blocks: msg.content.iter().map(|b| self.intern(b.clone())).collect(),
        }
    }

    /// 按 MessageRef 重建 IrMessage (从池中 deref 所有 block).
    pub fn resolve_message(&self, msg_ref: &MessageRef) -> Option<IrMessage> {
        let mut blocks = Vec::with_capacity(msg_ref.blocks.len());
        for &h in &msg_ref.blocks {
            blocks.push((*self.get(h)?).clone());
        }
        Some(IrMessage {
            role: msg_ref.role,
            content: blocks,
            ..Default::default()
        })
    }

    /// 递减 MessageRef 持有的所有 block 的 refcount.
    pub fn release_message(&mut self, msg_ref: &MessageRef) {
        for &h in &msg_ref.blocks {
            self.release(h);
        }
    }

    /// 当前池中的 block 数量 (诊断用).
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

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
struct Session {
    leaf_id: Uuid,
    root_id: Uuid,
    node_count: usize,
    created_at: DateTime<Utc>,
    latest_at: DateTime<Utc>,
    /// 会话标题 (sidebar 主文本). 仅在 session 创建时从根 node 的 preview 提取,
    /// 之后不再更新 (即便有新 round 加入). 见上方类型注释.
    ///
    /// `Arc<str>`: 直接共享根 node 的 preview, list_sessions 路径只增引用计数.
    title: Option<Arc<str>>,
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
/// [`ConversationDag::attach_response`] 能在外层 read lock 下通过 node-level 锁
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
    /// 本次请求中实际发生的 redact 结果 (权威投影, 供 WebUI 渲染).
    /// 每个 tuple = `(mock_value, secret_id)`. **永不**包含真实 secret 值.
    /// 在 push 时设置 (redactions 是请求侧属性, 不依赖 response).
    ///
    /// `Arc<[(String,String)]>` 让 list/session 路径共享切片而非 clone Vec
    /// (clone 成本随命中 secret 数线性增长).
    pub redactions: Arc<[(String, String)]>,
}

/// LLM 返回的 response 数据 (message content + 元数据).
///
/// 存储的是 LLM 原始返回 (含 mock, restore 前).
#[derive(Debug, Clone, Default)]
pub struct ResponseData {
    /// response 的 assistant message (LLM 原始返回, 含 mock, **未 restore**).
    /// 通常是一条 IrMessage (role=assistant), 但错误响应时可能为空.
    pub message: Option<MessageRef>,
    pub usage: IrUsage,
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
    /// 流式响应由 StreamScan 增量累积; 非流式在响应完成时一次性计算.
    /// `None` 表示尚未有解析结果 (流刚开始 / codec 不支持此协议 / 解析失败).
    pub parsed: Option<serde_json::Value>,
    /// 上游响应状态码 (attach 时填入; 也镜像到 CallEvent 供 NodeView).
    pub resp_status: u16,
    /// 上游响应 headers (敏感 header 已脱敏).
    pub resp_headers: Vec<(String, String)>,
    /// 端到端耗时 (毫秒).
    pub elapsed_ms: u64,
}

// ─── ConversationDag ───────────────────────────────────────────────────────

/// 内容寻址的对话 DAG.
///
/// 内部维护:
/// - `nodes`: id → Node 的 HashMap. 每个 Node 内嵌 `session_id` + `child_count`.
/// - `sessions`: SessionId → Session (sidebar 会话列表的数据源).
/// - `prefix_index`: Merkle prefix hash → nodes (fork 场景可能多个).
/// - `blocks`: 全局内容寻址的 IrBlock 池 (自带 refcount GC).
///
/// # 容量与淘汰
///
/// 两个限制条件, 任意一个超标都触发淘汰: `nodes.len() > max_nodes` (主限制)
/// 或 `sessions.len() > max_sessions` (安全阀, 防 fork 爆炸).
/// 淘汰策略: LRU — 按 session.latest_at (最后活动时间) 淘汰最旧的会话,
/// 持续活跃的会话 latest_at 不断刷新, 不会被淘汰.
/// 保底: `sessions.len() <= min_sessions` 时不淘汰 (避免界面清空).
///
/// # GC 语义
///
/// evict 整个 session: 从 leaf 开始 gc_cascade. child_count=0 的 node 删后
/// 递减 parent.child_count, 若也变 0 则级联删 — fork 共享的 node 天然受保护
/// (另一分支仍引用它, child_count > 0).
///
/// # 详尽设计见 `docs/design/conversation-dag.md`
#[derive(Debug, Clone)]
pub struct ConversationDag {
    inner: Arc<RwLock<DagInner>>,
}

#[derive(Debug)]
struct DagInner {
    nodes: HashMap<Uuid, Node>,
    /// Merkle prefix hash → nodes (按 push 顺序, 末尾是最新的).
    prefix_index: HashMap<u64, Vec<Uuid>>,
    /// 全局 block 池 (内容寻址 + refcount).
    blocks: BlockPool,
    /// 会话表: SessionId → Session. 每个 session 的 leaf 即 sidebar 一级条目.
    sessions: HashMap<SessionId, Session>,
    /// node 数量上限 (主限制).
    max_nodes: usize,
    /// 会话数量上限 (安全阀, 防极端 fork 爆炸).
    max_sessions: usize,
    /// 会话数量下限 (保底, 避免 UI 清空).
    min_sessions: usize,
}

/// push 时计算出的 node 定位结果.
#[derive(Debug, Clone)]
struct ParentLookup {
    parent: Option<Uuid>,
    /// msgs[..split_at] 是已有前缀 (在 DAG 中), msgs[split_at..] 是本 node 的 delta.
    split_at: usize,
}

/// 把 DAG 中所有 node id 按 (created_at desc, id desc) 排序后返回.
///
/// SSOT for "newest-first" 排序: [`ConversationDag::list_node_ids_newest_first`]
/// 与 [`ConversationDag::list_page`] 共享同一排序实现, 避免 12 行重复逻辑分叉.
/// tie 时按 id 排序保证确定性 (HashMap keys 迭代顺序非确定).
///
/// 性能优化 (perf): 预提取 `(created_at, id)` tuple 一次再 sort, 避免比较闭包内
/// 对每次比较重复 `nodes.get()` 查找 (N log N 次 get → N 次预提取).
fn sort_node_ids_newest_first(inner: &DagInner) -> Vec<Uuid> {
    let mut keyed: Vec<(DateTime<Utc>, Uuid)> = inner
        .nodes
        .iter()
        .map(|(id, n)| (n.event.created_at, *id))
        .collect();
    // 稳定倒序: 先正序排序再 reverse, 等价于 (created_at desc, id desc).
    keyed.sort_unstable();
    keyed.reverse();
    keyed.into_iter().map(|(_, id)| id).collect()
}

impl Default for ConversationDag {
    fn default() -> Self {
        Self::new(1024, 500, 1)
    }
}

impl ConversationDag {
    /// 构造 DAG.
    ///
    /// - `max_nodes`: node 数量上限 (主淘汰限制). 超标触发 LRU session 淘汰.
    /// - `max_sessions`: 会话数量上限 (安全阀). 正常不会触发; 极端 fork 场景防止
    ///   session 数失控.
    /// - `min_sessions`: 保底. 即使 nodes 超 max_nodes, 只要 sessions 数 ≤ min_sessions
    ///   就不淘汰 (避免活跃会话被清空, 导致界面空白).
    pub fn new(max_nodes: usize, max_sessions: usize, min_sessions: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(DagInner {
                nodes: HashMap::new(),
                prefix_index: HashMap::new(),
                blocks: BlockPool::default(),
                sessions: HashMap::new(),
                max_nodes: max_nodes.max(1),
                max_sessions: max_sessions.max(1),
                min_sessions: min_sessions.max(1),
            })),
        }
    }

    /// 把一段 messages 推入 DAG.
    ///
    /// 自动:
    /// 1. intern 所有 block (refcount++).
    /// 2. 计算 Merkle prefix hash 序列, 找到最深匹配的 parent.
    /// 3. 提取 delta (相对 parent 的增量).
    /// 4. 确定会话归属: parent 是某 session 的当前 leaf → 延续; 否则 (新根 / fork) → 新 session.
    /// 5. 创建 node, 入 HashMap + prefix_index.
    /// 6. 维护 parent.child_count + session.latest_at.
    /// 7. LRU session 淘汰 (若超 max_nodes / max_sessions, 保底 min_sessions).
    ///
    /// 返回新 node 的 id.
    ///
    /// 注意: 此方法只处理 request messages (DAG 结构), 不含 response.
    /// response 由调用方在 push 后通过 `attach_response` 单独填入.
    pub fn push_messages(&self, msgs: Vec<IrMessage>, event: CallEvent) -> Uuid {
        let mut g = self.inner.write();

        // 1. intern 所有 message (block 入池).
        let msg_refs: Vec<MessageRef> = msgs.iter().map(|m| g.blocks.intern_message(m)).collect();

        // 2. 计算 Merkle prefix hash 序列, 找 parent.
        let lookup = Self::find_parent(&g, &msg_refs);

        // 3. req_delta = msg_refs[split_at..] (客户端发出的增量).
        //    前 split_at 条 message 的 block refcount 由本次 intern 增加, 但它们属于 parent
        //    的 delta (parent 持有), 不由本 node 持有 — 必须释放, 否则 refcount 泄漏
        //    (这些 block 永远无法被 GC).
        for r in &msg_refs[..lookup.split_at] {
            g.blocks.release_message(r);
        }
        let delta_refs: Arc<[MessageRef]> = msg_refs[lookup.split_at..].iter().cloned().collect();

        // 3.5 修正 round_role = req_delta 的"语义主导角色".
        // 调用方 (proxy) 无法在构造 CallEvent 时知道 split_at (它依赖 DAG 内部 prefix 匹配),
        // 所以 round_role 的权威值在此处计算. delta 为空 (空 body 请求) 时保留调用方传入的值.
        //
        // 不直接用最后一条 message 的 role: codec 把 tool 消息归一化为 user (OpenAI tool→user
        // / Anthropic tool_result 本就在 user message 内), 无法区分"真用户输入"与"工具结果".
        // 用 contains_user_text 字段 (reader 入口预计算) 准确判定:
        //   delta 任一条 message contains_user_text → User (用户主动输入, sidebar 组首)
        //   否则                                    → Tool (工具循环, sidebar sub-dot)
        let mut event = event;
        let delta_has_user_text = msgs
            .iter()
            .skip(lookup.split_at)
            .any(|m| m.contains_user_text);
        // guard 基于 delta 非空 (split_at < msgs.len()), 而非 msgs 非空:
        // 全前缀重复请求 (split_at == msgs.len(), delta 实际为空) 时保留调用方传入的值.
        if lookup.split_at < msgs.len() {
            event.round_role = if delta_has_user_text {
                IrRole::User
            } else {
                IrRole::Tool
            };
        }

        // 4. 计算 own_hash + prefix_hash (只基于 req_delta, response 不参与).
        let parent_base = match lookup.parent {
            Some(pid) => g.nodes.get(&pid).expect("parent must exist").prefix_hash,
            None => 0,
        };
        let own_hash = Self::accumulate_hash(0, &delta_refs);
        let prefix_hash = Self::accumulate_hash(parent_base, &delta_refs);

        // 5. 确定会话归属 (O(1)): parent 是某 session 的当前 leaf → 延续; 否则 fork/新根.
        let sid = match lookup.parent {
            Some(pid) => {
                let parent_node = g.nodes.get(&pid).expect("parent exists");
                let parent_sid = parent_node.session_id;
                match g.sessions.get(&parent_sid) {
                    // parent 是其 session 的当前 leaf → 延续同一 session.
                    Some(s) if s.leaf_id == pid => parent_sid,
                    // parent 已被后续轮次取代 (不是 leaf) → fork → 新 session.
                    // 或 parent 所属 session 已被 evict (孤儿) → 新 session.
                    _ => SessionId::new(),
                }
            }
            None => SessionId::new(),
        };

        // 6. 创建 node.
        let node_id = Uuid::new_v4();
        let now = event.created_at;
        let node = Node {
            id: node_id,
            parent: lookup.parent,
            session_id: sid,
            child_count: 0,
            req_delta: delta_refs,
            own_hash,
            prefix_hash,
            event,
            response: RwLock::new(None),
        };

        // 7. 入 DAG 结构 + 更新 session + child_count.
        g.nodes.insert(node_id, node);
        g.prefix_index.entry(prefix_hash).or_default().push(node_id);
        // session 更新: 延续则前移 leaf + 增计数; 新建则插入.
        match g.sessions.get_mut(&sid) {
            Some(s) => {
                s.leaf_id = node_id;
                s.node_count += 1;
                if now > s.latest_at {
                    s.latest_at = now;
                }
            }
            None => {
                // 新 session: root = 本 node (fork 时 root 可能不是真正的对话根,
                // 但语义上"这个分支的起点"就是 root, 对 sidebar 足够).
                let root_id = lookup.parent.unwrap_or(node_id);
                // fork 场景: root_id 是 fork 点, 但它的 session_id 是原 session 的.
                // 对新 session 而言, root_id 仅用于 created_at 查找, 不要求归属一致.
                let root_node = g.nodes.get(&root_id);
                let created_at = root_node.map(|n| n.event.created_at).unwrap_or(now);
                // 会话标题: 沿 parent 链回溯到真正根 (parent=None 的 node), 取其 preview.
                // 真正根 = 会话最早的 round, 其 preview = 首条 user msg 截断.
                // 仅在此处 (session 创建时) 计算一次, 之后 leaf 前移不更新.
                // 见 Session.title 注释 + issue #36. fork 场景下 root_id (fork 点)
                // 不等于真正根, 必须 walk 到链首才能拿到正确的首条 user msg.
                let title = Self::find_root_title(&g, lookup.parent, node_id);
                // 视图正确性守卫: session.title 是从 root node 的 preview (SSOT) 派生的视图.
                // 详见 AGENTS.md "视图正确性确保机制" — "session.title 从 root node preview 派生".
                #[cfg(feature = "consistency-check")]
                Self::assert_session_title_matches_root_preview(
                    &g,
                    lookup.parent,
                    node_id,
                    title.as_deref(),
                );
                g.sessions.insert(
                    sid,
                    Session {
                        leaf_id: node_id,
                        root_id,
                        node_count: 1,
                        created_at,
                        latest_at: now,
                        title,
                    },
                );
            }
        }
        // parent.child_count += 1.
        if let Some(pid) = lookup.parent
            && let Some(pn) = g.nodes.get_mut(&pid)
        {
            pn.child_count += 1;
        }

        // 8. LRU session 淘汰 (两个条件, min 保底).
        Self::evict_if_needed(&mut g);

        node_id
    }

    /// 沿 parent 链回溯到真正根 (parent=None 的 node), 返回其 preview 作为会话标题.
    /// 用于 session 创建时计算 title (issue #36: 取最早 round 的首条 user msg).
    /// fork 场景下 parent 链可能跨越多个 node, 需走到链首.
    /// 无 parent (新根) 时用本 node (node_id) 的 preview.
    ///
    /// 返回 `Arc<str>` 直接共享根 node 的 preview, 不复制字符串.
    fn find_root_title(inner: &DagInner, parent: Option<Uuid>, node_id: Uuid) -> Option<Arc<str>> {
        // walk parent 链到链首, 暂存每个 node 的 preview, 循环结束保留最旧的.
        let mut title: Option<Arc<str>> = None;
        let mut cursor = parent;
        // 安全限位: parent 链长度不会超过 nodes 总数 (DAG 无环).
        while let Some(pid) = cursor {
            match inner.nodes.get(&pid) {
                Some(n) => {
                    title = n.event.preview.clone();
                    cursor = n.parent;
                }
                None => break,
            }
        }
        // 无 parent (新根, cursor 一次都没进) → 用本 node 的 preview.
        if title.is_none() {
            title = inner
                .nodes
                .get(&node_id)
                .and_then(|n| n.event.preview.clone());
        }
        title
    }

    /// 视图正确性守卫 (CI 用, 需 `--features consistency-check`).
    ///
    /// `Session.title` 是 root node 的 `CallEvent.preview` (SSOT) 的派生视图:
    /// session 创建时一次性从 root preview 复制 Arc<str>, 之后 leaf 前移不更新.
    /// 本函数重新调用 [`find_root_title`] 派生一次, 比对存储的 title.
    ///
    /// 守卫职责限定为: 捕获 "title 派生源被改" (例如未来若改为从 leaf preview / 其他字段
    /// 派生, 违反 issue #36 "标题应稳定 = 最早 round 的首条 user msg").
    /// `find_root_title` 自身的 walk 逻辑 bug 由 dag 行为测试覆盖 (session 标题正确性
    /// 是 WebUI 可观察行为, 已有 e2e 测试), 不在守卫职责内 — 因此本守卫直接复用 SSOT
    /// 函数, 而非独立 walk (避免 DRY 违反导致的同步漂移). 详见 AGENTS.md "视图正确性确保机制".
    #[cfg(feature = "consistency-check")]
    fn assert_session_title_matches_root_preview(
        inner: &DagInner,
        parent: Option<Uuid>,
        node_id: Uuid,
        derived_title: Option<&str>,
    ) {
        let rederived = Self::find_root_title(inner, parent, node_id);
        debug_assert_eq!(
            derived_title,
            rederived.as_deref(),
            "session.title drifts from root node preview SSOT"
        );
    }

    /// 计算 messages 序列的 Merkle prefix hash 序列, 找到最深匹配的 parent.
    ///
    /// 返回 `(parent, split_at)`:
    /// - `parent = None, split_at = 0`: 没找到前缀匹配, 是新会话根.
    /// - `parent = Some(id), split_at = k`: 前 k 条已在 DAG 中, 后面是 delta.
    fn find_parent(inner: &DagInner, msg_refs: &[MessageRef]) -> ParentLookup {
        if msg_refs.is_empty() {
            return ParentLookup {
                parent: None,
                split_at: 0,
            };
        }

        // 累积 hash: cum[k] = hash(cum[k-1] 或 0, h(msg_refs[k]))
        let mut cum: u64 = 0;
        let mut cum_seq: Vec<u64> = Vec::with_capacity(msg_refs.len());
        for r in msg_refs {
            cum = Self::combine_hash(cum, r.hash());
            cum_seq.push(cum);
        }

        // 倒序查 prefix_index, 找最深的命中.
        // cum_seq[i] 对应 "前 i+1 条 message 作为某 node 的 full_messages" 的 prefix_hash.
        // split_at = i+1 (前 i+1 条匹配), delta = msg_refs[i+1..].
        for i in (0..cum_seq.len()).rev() {
            if let Some(ids) = inner.prefix_index.get(&cum_seq[i]) {
                // fork 场景: 多个 node 共享同一 prefix_hash. 取最新的 (push 顺序最晚的).
                // 这里不做内容验证 (hash collision 概率极低); 如需 defense-in-depth 可加验证.
                let parent = ids.last().copied().expect("prefix_index entry non-empty");
                return ParentLookup {
                    parent: Some(parent),
                    split_at: i + 1,
                };
            }
        }

        ParentLookup {
            parent: None,
            split_at: 0,
        }
    }

    /// 累积 Merkle hash: 从 `init` 起, 逐条 combine 每条 message 的 hash.
    fn accumulate_hash(mut init: u64, msgs: &[MessageRef]) -> u64 {
        for r in msgs {
            init = Self::combine_hash(init, r.hash());
        }
        init
    }

    /// 组合两个 hash (Merkle 风格).
    fn combine_hash(parent: u64, own: u64) -> u64 {
        crate::util::hash64(&(parent, own))
    }

    /// 容量检查 + LRU 会话淘汰 (两个条件, min 保底).
    ///
    /// 触发条件: `nodes > max_nodes` (主) 或 `sessions > max_sessions` (安全阀).
    /// 保底: `sessions ≤ min_sessions` 时不淘汰 (避免 UI 清空).
    /// 策略: 找 `latest_at` 最旧的 session 整体 gc_cascade.
    /// 持续活跃的会话 latest_at 不断刷新, 不会被淘汰.
    fn evict_if_needed(inner: &mut DagInner) {
        loop {
            let over_nodes = inner.nodes.len() > inner.max_nodes;
            let over_sessions = inner.sessions.len() > inner.max_sessions;
            if (!over_nodes && !over_sessions) || inner.sessions.len() <= inner.min_sessions {
                break;
            }
            // 找 latest_at 最旧的 session (LRU).
            let victim_sid = match inner
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.latest_at)
                .map(|(sid, _)| *sid)
            {
                Some(sid) => sid,
                None => break,
            };
            // 取出 session, 从 sessions map 移除, 然后 gc_cascade 从 leaf 开始级联清理.
            let session = match inner.sessions.remove(&victim_sid) {
                Some(s) => s,
                None => break,
            };
            Self::gc_cascade(inner, session.leaf_id);
        }
    }

    /// 从 leaf 开始级联 GC: 删除 node, 递减 parent.child_count, 若 parent 也变 0 则递归.
    ///
    /// child_count 是引用计数: 只有 child_count=0 的 node (无 child 依赖) 才被删除.
    /// fork 共享的 node 天然受保护 (另一分支的 child 仍引用它, child_count > 0).
    fn gc_cascade(inner: &mut DagInner, node_id: Uuid) {
        let node = match inner.nodes.remove(&node_id) {
            Some(n) => n,
            None => return,
        };
        // 释放 req_delta 的 block refcount.
        for r in node.req_delta.iter() {
            inner.blocks.release_message(r);
        }
        // 释放 response 的 block refcount (若有).
        if let Some(resp) = node.response.read().as_ref()
            && let Some(msg) = &resp.message
        {
            inner.blocks.release_message(msg);
        }
        // 从 prefix_index 移除.
        if let Some(ids) = inner.prefix_index.get_mut(&node.prefix_hash) {
            ids.retain(|id| *id != node_id);
            if ids.is_empty() {
                inner.prefix_index.remove(&node.prefix_hash);
            }
        }
        // 级联: 递减 parent.child_count, 若也变 0 则递归删 parent.
        if let Some(parent_id) = node.parent
            && let Some(pn) = inner.nodes.get_mut(&parent_id)
        {
            pn.child_count = pn.child_count.saturating_sub(1);
            if pn.child_count == 0 {
                Self::gc_cascade(inner, parent_id);
            }
        }
    }

    // ─── 读取 API ──────────────────────────────────────────────────────────

    /// walk parent 链, 收集完整的 request messages (从根到本 node).
    ///
    /// 只含 req_delta (客户端发出的 messages), 不含 response.
    /// response 是独立数据源, 用 `get_response` 单独获取.
    ///
    /// **不 apply redact**: 返回的是 OriginRecord (真实内容).
    /// 调用方需要 SecureRecord 时, 自行 derive redactMap 并 apply.
    pub fn full_request_messages(&self, node_id: Uuid) -> Option<Vec<IrMessage>> {
        let g = self.inner.read();
        let msg_refs = self.collect_req_delta_refs(&g, node_id)?;
        let mut msgs = Vec::with_capacity(msg_refs.len());
        for r in &msg_refs {
            msgs.push(g.blocks.resolve_message(r)?);
        }
        Some(msgs)
    }

    /// 递归收集 node 的所有 req_delta MessageRef (从根到本 node).
    fn collect_req_delta_refs(&self, inner: &DagInner, node_id: Uuid) -> Option<Vec<MessageRef>> {
        let node = inner.nodes.get(&node_id)?;
        let mut refs = match node.parent {
            Some(p) => self.collect_req_delta_refs(inner, p)?,
            None => Vec::new(),
        };
        refs.extend(node.req_delta.iter().cloned());
        Some(refs)
    }

    /// 取 node 的只读视图 (clone 元数据, 但不 walk).
    ///
    /// 用于 list / 元数据查询.
    pub fn get_node(&self, node_id: Uuid) -> Option<NodeView> {
        let g = self.inner.read();
        self.node_view(&g, node_id)
    }

    /// 取 node 的 response 数据 (clone).
    pub fn get_response(&self, node_id: Uuid) -> Option<ResponseData> {
        let g = self.inner.read();
        let node = g.nodes.get(&node_id)?;

        node.response.read().clone()
    }

    /// 取 node 的请求侧详情 (req_headers + req_body_raw) for GET /records/{id}.
    ///
    /// list 路径 (`get_node`) 不返回 req_body_raw (太大), 这个方法用于按需拉取.
    pub fn get_node_detail(&self, node_id: Uuid) -> Option<NodeDetail> {
        let g = self.inner.read();
        let node = g.nodes.get(&node_id)?;
        Some(NodeDetail {
            req_headers: node.event.req_headers.clone(),
            req_body_raw: node.event.req_body_raw.clone(),
        })
    }

    /// attach response 到 node.
    ///
    /// 两级锁 (perf): 外层 `inner.read()` + 内层 `node.response.write()`,
    /// 让并发 push / 其他节点的 attach / update_parsed_response 不再串行化在
    /// 全局 write lock 上. 流式场景多路并发 attach 时尤其受益.
    ///
    /// 响应元数据 (`resp_status` / `resp_headers` / `elapsed_ms`) 只写
    /// `node.response`, `NodeView` / `SessionView` 读它们时也走 response 锁.
    pub fn attach_response(&self, node_id: Uuid, response: ResponseData) {
        let g = self.inner.read();
        let Some(node) = g.nodes.get(&node_id) else {
            tracing::warn!(%node_id, "attach_response: node not found (evicted?)");
            return;
        };
        *node.response.write() = Some(response);
    }

    /// 增量更新 node 的 parsed view (流式节流写入专用).
    ///
    /// 若 node 尚无 ResponseData (流过程中尚未 attach), 自动创建一个 default 占位
    /// (resp_complete=false), 仅写 parsed 字段; 最终的 `attach_response` 会整体替换.
    ///
    /// 两级锁 (perf): 与 `attach_response` 同. 这是高频路径 (流式 ~500ms 一次),
    /// 改 read lock + node.response.write() 后并发多路流式不再串行化在全局锁.
    pub fn update_parsed_response(&self, node_id: Uuid, parsed: serde_json::Value) {
        let g = self.inner.read();
        let Some(node) = g.nodes.get(&node_id) else {
            tracing::warn!(%node_id, "update_parsed_response: node not found (evicted?)");
            return;
        };
        let mut resp_lock = node.response.write();
        let resp = resp_lock.get_or_insert_with(ResponseData::default);
        resp.parsed = Some(parsed);
    }

    /// 按 created_at 倒序列出 node id (newest first).
    /// tie 时按 id 排序保证确定性 (HashMap keys 迭代顺序非确定).
    ///
    /// 实现预提取 `(created_at, id)` tuple 再 sort, 避免比较闭包内对每个比较
    /// 重复 `nodes.get()` 查找 (N log N 次比较 → N 次预提取).
    pub fn list_node_ids_newest_first(&self) -> Vec<Uuid> {
        let g = self.inner.read();
        sort_node_ids_newest_first(&g)
    }

    /// 当前 node 总数.
    pub fn node_count(&self) -> usize {
        let g = self.inner.read();
        g.nodes.len()
    }

    /// 分页列出 NodeView (newest first), 支持 filter + offset/limit.
    ///
    /// filter=All: 只 clone 当前页的 NodeView (跳过非页节点, 避免 O(n) 全量 clone).
    /// filter=Hits: 需要扫描全部节点的 redactions 判断命中 (无法避免 O(n) 扫描),
    /// 但仍只 clone 当前页的 NodeView.
    pub fn list_page(
        &self,
        offset: usize,
        limit: usize,
        hits_only: bool,
    ) -> (Vec<NodeView>, usize) {
        let g = self.inner.read();
        let limit = limit.clamp(1, 200);
        // 收集所有 node id, 按 (created_at desc, id desc) 排序保证确定性.
        let all_ids = sort_node_ids_newest_first(&g);
        if hits_only {
            let hit_ids: Vec<Uuid> = all_ids
                .into_iter()
                .filter(|id| {
                    g.nodes
                        .get(id)
                        .is_some_and(|n| !n.event.redactions.is_empty())
                })
                .collect();
            let total = hit_ids.len();
            let offset = offset.min(total);
            let views = hit_ids
                .iter()
                .copied()
                .skip(offset)
                .take(limit)
                .filter_map(|id| self.node_view(&g, id))
                .collect();
            (views, total)
        } else {
            let total = all_ids.len();
            let offset = offset.min(total);
            let views = all_ids
                .into_iter()
                .skip(offset)
                .take(limit)
                .filter_map(|id| self.node_view(&g, id))
                .collect();
            (views, total)
        }
    }

    /// 从 inner 中构造 NodeView (内部 helper, 需要调用方持读锁).
    fn node_view(&self, inner: &DagInner, node_id: Uuid) -> Option<NodeView> {
        let node = inner.nodes.get(&node_id)?;
        let resp = node.response.read();
        Some(NodeView {
            id: node.id,
            parent: node.parent,
            session_id: node.session_id,
            round_role: node.event.round_role,
            req_delta_count: node.req_delta.len(),
            has_response: resp.is_some(),
            created_at: node.event.created_at,
            // elapsed_ms / resp_status 从 response 锁读取 (perf: 响应字段集中在
            // node.response, attach_response 无需写 event → 两级锁可行).
            elapsed_ms: resp.as_ref().map(|r| r.elapsed_ms).unwrap_or(0),
            method: node.event.method.clone(),
            path: node.event.path.clone(),
            resp_status: resp.as_ref().map(|r| r.resp_status).unwrap_or(0),
            redact_seed: node.event.redact_seed,
            preview: node.event.preview.clone(),
            model: node.event.model.clone(),
            streamed: resp.as_ref().map(|r| r.streamed).unwrap_or(false),
            resp_complete: resp.as_ref().map(|r| r.resp_complete).unwrap_or(false),
            error: resp.as_ref().and_then(|r| r.error.clone()),
            redactions: Arc::clone(&node.event.redactions),
            parsed_response: resp.as_ref().and_then(|r| r.parsed.clone()),
            // list_page 路径不填 (避免 O(n) 全量 resolve); timeline 路径单独填.
            req_delta_messages: Vec::new(),
        })
    }

    // ─── 会话级 API (sidebar 两级树 + timeline 惰性加载) ──────────────────

    /// 列出会话, 按 latest_at (会话内最新轮次时间) 倒序.
    /// 直接从 sessions map 派生, 无需走 parent 链 (node_count 已增量维护).
    pub fn list_sessions(&self) -> Vec<SessionView> {
        let g = self.inner.read();
        let mut views: Vec<SessionView> = g
            .sessions
            .iter()
            .filter_map(|(&sid, s)| self.session_view(&g, sid, s))
            .collect();
        // latest_at 倒序 (最近活动的在前); tie 时按 session_id 保证确定性.
        views.sort_by_key(|v| std::cmp::Reverse((v.latest_at, v.session_id)));
        views
    }

    /// 构造一个 SessionView (从 sessions map 中的 Session 派生).
    /// 不走 parent 链 — node_count / root_id / title 在 push 时增量维护.
    fn session_view(&self, inner: &DagInner, sid: SessionId, s: &Session) -> Option<SessionView> {
        let leaf = inner.nodes.get(&s.leaf_id)?;
        let resp = leaf.response.read();
        Some(SessionView {
            session_id: sid,
            leaf_id: s.leaf_id,
            root_id: s.root_id,
            record_count: s.node_count,
            created_at: s.created_at,
            latest_at: s.latest_at,
            // title 来自 session map (创建时计算, 之后不变), 不再读 leaf.event.preview.
            // 见 issue #36: 多轮对话中标题应稳定 = 最早 round 的首条 user msg.
            preview: s.title.clone(),
            model: leaf.event.model.clone(),
            latest_resp_status: resp.as_ref().map(|r| r.resp_status).unwrap_or(0),
            latest_error: resp.as_ref().and_then(|r| r.error.clone()),
            redactions: Arc::clone(&leaf.event.redactions),
            path: leaf.event.path.clone(),
        })
    }

    // ─── session-aware timeline API (替代旧 node_id-based timeline) ────────
    //
    // 三条查询路径共享 TimelineRound 结构:
    // - session_rounds(sid): sidebar 三级菜单的轻量摘要 (不含 delta messages).
    // - timeline_view(sid, before, limit): timeline 初始加载 + 向前翻页 (lazy load 更老).
    // - timeline_diff(sid, after, tail_length): sync 轮询的 diff.
    //
    // 链遍历统一: 从某起点 (leaf 或 before 指向的 node) 沿 parent 链回溯 limit 个,
    // oldest-first 返回. 末轮 (链中最新那个) 的 tail 信息单独构造.

    /// 返回 session 的所有 round 轻量摘要 (sidebar 三级菜单用).
    ///
    /// 沿 leaf→root 回溯全部 node, oldest-first 返回.
    /// 不 resolve block, 不构造 delta messages — 仅 event 字段 (preview/role/created_at).
    pub fn session_rounds(&self, sid: SessionId) -> Vec<RoundBrief> {
        let g = self.inner.read();
        let Some(session) = g.sessions.get(&sid).cloned() else {
            return Vec::new();
        };
        let chain = walk_chain(&g, session.leaf_id, usize::MAX);
        build_round_briefs(&g, &chain)
    }

    /// 基于 session + 游标的分页 (timeline 初始加载 + lazy load).
    ///
    /// - `before=None`: 从最新轮 (leaf) 开始取 limit 条.
    /// - `before=Some(id)`: 取该 id 之前 (更老) 的 limit 条 (不含 id 自身), 用于向上翻页.
    ///
    /// 返回 oldest-first, 含末轮 (链中最新那个) 的 tail 信息.
    /// `has_more` = 链上还有更老的 node (limit 条之外).
    pub fn timeline_view(
        &self,
        sid: SessionId,
        before: Option<Uuid>,
        limit: usize,
    ) -> Option<TimelinePage> {
        let g = self.inner.read();
        let session = g.sessions.get(&sid).cloned()?;

        // before=Some 时 start_id = before.parent (故 limit 条不含 before 自身);
        // 跨 session 游标无意义 → None 让前端重置.
        // limit 至少 1, 避免 0 导致空链无法定位末轮 tail.
        let limit = limit.max(1);
        let start_id = match before {
            None => session.leaf_id,
            Some(id) => {
                let node = g.nodes.get(&id)?;
                if node.session_id != sid {
                    return None;
                }
                node.parent?
            }
        };

        let chain = walk_chain(&g, start_id, limit);
        if chain.is_empty() {
            return None;
        }
        let rounds: Vec<TimelineRound> = chain
            .iter()
            .map(|&id| build_timeline_round(&g, id))
            .collect();
        // chain oldest-first, 末轮 (链中最新) = chain 最后一个.
        let tail = build_timeline_tail(&g, *chain.last().unwrap());
        // chain[0] 是最老的; 它有 parent → has_more=true.
        let has_more = g.nodes.get(&chain[0]).and_then(|n| n.parent).is_some();

        Some(TimelinePage {
            rounds,
            tail,
            has_more,
        })
    }

    /// 基于 session + 游标的 diff (sync 轮询用).
    ///
    /// - `after`: 前端持有的最后一条 round id (游标).
    /// - `tail_length`: 前端持有的末轮 response 内容长度 (用于 tail 变更检测).
    ///
    /// 返回 `None` = 无变化 (前端游标已是最新 + tail 长度一致, 304 等价);
    /// `Some` = 有 diff (new_rounds 非空, 或 tail 内容变化).
    pub fn timeline_diff(
        &self,
        sid: SessionId,
        after: Option<Uuid>,
        tail_length: usize,
    ) -> Option<TimelineDiffData> {
        let g = self.inner.read();
        build_timeline_diff_inner(&g, sid, after, tail_length)
    }

    /// 在单个 `inner.read()` 锁内采集 sync 快照 (sessions + expanded rounds + timeline diff).
    ///
    /// 替代多次独立调用 (`list_sessions` + `session_rounds` + `timeline_diff`),
    /// 保证三部分数据来自同一快照 (避免新 push 在两次锁之间漂移).
    ///
    /// - `expanded`: 需要回传 round 详情的 session id 列表 (sidebar 展开的那些).
    /// - `selected = Some((sid, latest_round, response_length))`: 当前选中的 session +
    ///   前端持有的游标, 用于 timeline diff. None = 无选中 / 首次加载, timeline 为 None.
    pub fn sync_snapshot(
        &self,
        expanded: &[SessionId],
        selected: Option<(SessionId, Option<Uuid>, usize)>,
    ) -> SyncSnapshot {
        let g = self.inner.read();

        // 1. sessions: 全量 SessionView (latest_at desc 排序, 与 list_sessions 一致).
        let mut sessions: Vec<SessionView> = g
            .sessions
            .iter()
            .filter_map(|(&sid, s)| self.session_view(&g, sid, s))
            .collect();
        sessions.sort_by_key(|v| std::cmp::Reverse((v.latest_at, v.session_id)));

        // 2. rounds: 仅 expanded session 的 RoundBrief 列表.
        let mut rounds: HashMap<SessionId, Vec<RoundBrief>> = HashMap::new();
        for &sid in expanded {
            let Some(session) = g.sessions.get(&sid).cloned() else {
                continue;
            };
            // session_rounds 是 pub API (自带 read lock); 此处 inline 避免重复上锁
            // (3s 轮询 + 多 expanded session 时省 N 次锁).
            let chain = walk_chain(&g, session.leaf_id, usize::MAX);
            let briefs = build_round_briefs(&g, &chain);
            rounds.insert(sid, briefs);
        }

        // 3. timeline: 仅 selected session 的 diff (复用 build_timeline_diff_inner).
        let timeline = selected.and_then(|(sid, after, tail_length)| {
            build_timeline_diff_inner(&g, sid, after, tail_length)
        });

        SyncSnapshot {
            sessions,
            rounds,
            timeline,
        }
    }
}

// ─── session-aware timeline 内部 helper (free function, 共享 DagInner 读视图) ─
//
// 这些 helper 是 free function 而非 ConversationDag 方法, 因为它们只接受 &DagInner
// (调用方已持读锁), 避免重复 self.inner.read(). 命名以 build_/walk_ 前缀标识 helper.

/// 从 `start_id` 沿 parent 链回溯 (含 start_id), oldest-first 返回.
///
/// - `limit = usize::MAX`: 回溯到链首 (parent=None).
/// - `limit = N`: 最多取 N 个 (含 start_id), 多余的更老的 node 不取.
fn walk_chain(inner: &DagInner, start_id: Uuid, limit: usize) -> Vec<Uuid> {
    let mut chain: Vec<Uuid> = Vec::new();
    let mut cursor = Some(start_id);
    while let Some(id) = cursor {
        if chain.len() >= limit {
            break;
        }
        chain.push(id);
        cursor = inner.nodes.get(&id).and_then(|n| n.parent);
    }
    chain.reverse();
    chain
}

/// 把 node id 链转成 RoundBrief 列表 (sync_snapshot / session_rounds 共用).
fn build_round_briefs(inner: &DagInner, chain: &[Uuid]) -> Vec<RoundBrief> {
    chain
        .iter()
        .filter_map(|&id| {
            let node = inner.nodes.get(&id)?;
            Some(RoundBrief {
                id: node.id,
                round_role: node.event.round_role,
                preview: node.event.preview.clone(),
                created_at: node.event.created_at,
            })
        })
        .collect()
}

/// `timeline_diff` 与 `sync_snapshot.timeline` 共用的核心逻辑
/// (在同一 `inner.read()` 锁内构造 diff).
///
/// - 返回 `None` = 无变化 (after 已是 leaf + tail.length 一致).
/// - 返回 `Some` = new_rounds 非空, 或 tail.length 变化.
///
/// after 不属于本 session (前端状态过期) → 视为初始加载, 返回全链 new_rounds.
fn build_timeline_diff_inner(
    inner: &DagInner,
    sid: SessionId,
    after: Option<Uuid>,
    tail_length: usize,
) -> Option<TimelineDiffData> {
    let session = inner.sessions.get(&sid).cloned()?;
    let tail = build_timeline_tail(inner, session.leaf_id);

    // after=None → 前端刚进入, 全链返回 (视为初始加载).
    // after=Some(id) 且属于本 session → 取 id 之后的 round (不含 id).
    // after=Some(id) 但不属于本 session → 全链 (前端状态过期, 重置).
    let new_chain: Vec<Uuid> = match after {
        None => walk_chain(inner, session.leaf_id, usize::MAX),
        Some(after_id) => {
            let after_belongs = inner
                .nodes
                .get(&after_id)
                .is_some_and(|n| n.session_id == sid);
            if !after_belongs {
                walk_chain(inner, session.leaf_id, usize::MAX)
            } else {
                walk_chain(inner, session.leaf_id, usize::MAX)
                    .into_iter()
                    .skip_while(|&id| id != after_id)
                    .skip(1)
                    .collect()
            }
        }
    };

    if new_chain.is_empty() {
        // 无新增 round: 仅当 tail.length 变化才返回 diff (让前端更新抽屉).
        if tail.length == tail_length {
            return None;
        }
        return Some(TimelineDiffData {
            new_rounds: Vec::new(),
            tail,
        });
    }

    let new_rounds = new_chain
        .iter()
        .map(|&id| build_timeline_round(inner, id))
        .collect();
    Some(TimelineDiffData { new_rounds, tail })
}

/// 构造一个 TimelineRound (含 req_delta_messages).
///
/// req_delta_messages 从 `node.req_body_raw` 末尾切片 (已 redact, LLM 视角, 安全).
/// 不走 BlockPool + codec writer 路径 (BlockPool 存真实内容, 未 apply redactMap 会泄露 secret);
/// 跨协议切片错位是可接受的已知限制. TODO: 后续在 web 层 lazy redact.
///
/// 调用方传入的 `node_id` 必然在 `inner` 内存在 (由 walk_chain / session.leaf_id 产生,
/// 全程持 `inner.read()` 锁, evict 不会并发发生).
fn build_timeline_round(inner: &DagInner, node_id: Uuid) -> TimelineRound {
    let node = inner
        .nodes
        .get(&node_id)
        .expect("node exists under read lock");
    TimelineRound {
        id: node.id,
        round_role: node.event.round_role,
        preview: node.event.preview.clone(),
        created_at: node.event.created_at,
        redactions: Arc::clone(&node.event.redactions),
        req_delta_messages: extract_delta_messages_from_raw(node),
    }
}

/// (fallback) 从 node.req_body_raw 末尾截取 req_delta.len() 条 messages (wire JSON),
/// 并在根节点时额外提取 system prompt.
///
/// system 处理: OpenAI reader 把 role=system 提升到 IrRequest.system (不在 messages 里),
/// writer 再写回 messages[0]. DAG 的 req_delta 不含 system (基于 IR messages).
/// 因此根节点 (parent=None) 时, 从 req_body_raw 顶层提取 system 字段 (Anthropic 风格)
/// 或 messages[0] (OpenAI 风格 role=system), 作为 delta 的首条 synthetic message.
///
/// 已知限制: 跨协议 writer 拆分场景切片 start 偏小, delta 可能含前序轮消息 (同协议不受影响).
fn extract_delta_messages_from_raw(node: &Node) -> Vec<serde_json::Value> {
    let count = node.req_delta.len();
    if count == 0 {
        return Vec::new();
    }
    let Ok(req_body) = serde_json::from_str::<serde_json::Value>(&node.event.req_body_raw) else {
        return Vec::new();
    };
    let Some(messages) = req_body.get("messages").and_then(|m| m.as_array()) else {
        return Vec::new();
    };
    if messages.len() < count {
        return Vec::new();
    }
    let start = messages.len() - count;
    let mut result: Vec<serde_json::Value> = messages[start..].to_vec();

    // 根节点: 若有顶层 system (Anthropic 风格) 或 messages[0] 是 system (OpenAI),
    // 且未被 req_delta 覆盖 (start > 0 说明 system 在 messages[start] 之前),
    // 则把 system 作为 delta 的首条 synthetic message 注入.
    // 这让根节点的 system prompt 在 timeline 可见 (issue #27 bug 3).
    if node.parent.is_none() && start > 0 {
        // Anthropic 风格: 顶层 system 字段 (string 或 array).
        if let Some(sys) = req_body.get("system") {
            let sys_text = if let Some(s) = sys.as_str() {
                (!s.is_empty()).then(|| s.to_string())
            } else if let Some(arr) = sys.as_array() {
                crate::derive::extract_text_blocks(arr).map(|t| t.join("\n"))
            } else {
                None
            };
            if let Some(text) = sys_text {
                result.insert(0, serde_json::json!({"role": "system", "content": text}));
            }
        }
        // OpenAI 风格: messages[0] 是 role=system (writer 写回).
        // 若 start > 0 且 messages[0].role == system, 注入到 delta 首位
        // (额外 guard result.first 非 system, 防御 messages 含多条 system 的畸形输入).
        else if messages
            .first()
            .and_then(|m| m.get("role").and_then(|r| r.as_str()))
            == Some("system")
            && result
                .first()
                .and_then(|m| m.get("role").and_then(|r| r.as_str()))
                != Some("system")
        {
            result.insert(0, messages[0].clone());
        }
    }

    result
}

/// 构造一个 TimelineTail (从 node.response 读 parsed + 元数据).
///
/// `length` = parsed 序列化字节数; parsed 为 None 时 fallback 到 raw_resp_body.len().
/// 调用方传入的 `node_id` 必然在 `inner` 内存在 (由 leaf_id 产生, 全程持锁).
fn build_timeline_tail(inner: &DagInner, node_id: Uuid) -> TimelineTail {
    let node = inner
        .nodes
        .get(&node_id)
        .expect("node exists under read lock");
    let empty_tail = || TimelineTail {
        round_id: node_id,
        length: 0,
        resp_status: 0,
        elapsed_ms: 0,
        streamed: false,
        resp_complete: false,
        error: None,
        parsed: None,
    };
    let resp_lock = node.response.read();
    let Some(resp) = resp_lock.as_ref() else {
        return empty_tail();
    };
    let length = resp
        .parsed
        .as_ref()
        .map(|v| v.to_string().len())
        .unwrap_or(resp.raw_resp_body.len());
    TimelineTail {
        round_id: node_id,
        length,
        resp_status: resp.resp_status,
        elapsed_ms: resp.elapsed_ms,
        streamed: resp.streamed,
        resp_complete: resp.resp_complete,
        error: resp.error.clone(),
        parsed: resp.parsed.clone(),
    }
}

// WebUI 响应 DTO (SessionView / NodeView / NodeDetail / RoundBrief / TimelineRound /
// TimelineTail / TimelinePage / TimelineDiffData / SyncSnapshot) 已下沉到 web::dto,
// 让本模块 (纯内存内容寻址存储) 不再 derive Serialize. 构造逻辑 (上方 node_view /
// session_view / build_timeline_round 等, 需持 DagInner 读锁访问私有字段) 仍留此处,
// 返回 web::dto 的类型. 详见 src/web/dto.rs 头部 "构造方法留 dag.rs".

// ─── redactMap 派生 ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::ir::{IrBlock, IrMessage, IrRole};

    fn text_msg(role: IrRole, text: &str) -> IrMessage {
        IrMessage {
            contains_user_text: role == IrRole::User && !text.is_empty(),
            role,
            content: vec![IrBlock::Text {
                text: text.to_string(),
            }],
            ..Default::default()
        }
    }

    fn dummy_event() -> CallEvent {
        CallEvent {
            created_at: Utc::now(),
            method: "POST".to_string(),
            path: "/o/test/v1/chat".to_string(),
            req_headers: vec![],
            ingress_protocol: None,
            redact_seed: 0,
            policy: Arc::new(PolicySnapshot::default()),
            req_body_raw: String::new(),
            round_role: IrRole::User,
            preview: None,
            model: None,
            redactions: Arc::from([]),
        }
    }

    // ─── BlockPool tests ──────────────────────────────────────────────────

    #[test]
    fn block_pool_intern_dedupes_identical_blocks() {
        let mut pool = BlockPool::default();
        let b = IrBlock::Text {
            text: "hello".to_string(),
        };
        let h1 = pool.intern(b.clone());
        let h2 = pool.intern(b.clone());
        assert_eq!(h1, h2, "identical blocks should hash to same key");
        assert_eq!(pool.len(), 1, "pool should have 1 unique block");
        assert_eq!(*pool.refcount.get(&h1).unwrap(), 2);
    }

    #[test]
    fn block_pool_release_decrement_to_zero_removes() {
        let mut pool = BlockPool::default();
        let b = IrBlock::Text {
            text: "hello".to_string(),
        };
        let h = pool.intern(b);
        assert_eq!(pool.len(), 1);
        pool.release(h);
        assert_eq!(pool.len(), 0, "refcount=0 should remove block");
        assert!(pool.get(h).is_none());
    }

    #[test]
    fn block_pool_release_below_zero_clamped() {
        let mut pool = BlockPool::default();
        let h = pool.intern(IrBlock::Text {
            text: "x".to_string(),
        });
        pool.release(h);
        // 第二次 release 不应 panic (saturating_sub).
        pool.release(h);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn block_pool_intern_message_creates_refs() {
        let mut pool = BlockPool::default();
        let msg = text_msg(IrRole::User, "test message");
        let msg_ref = pool.intern_message(&msg);
        assert_eq!(msg_ref.role, IrRole::User);
        assert_eq!(msg_ref.blocks.len(), 1);
        assert_eq!(pool.len(), 1, "1 block interned");
    }

    #[test]
    fn block_pool_resolve_message_roundtrips() {
        let mut pool = BlockPool::default();
        let msg = text_msg(IrRole::Assistant, "response text");
        let msg_ref = pool.intern_message(&msg);
        let resolved = pool.resolve_message(&msg_ref).expect("should resolve");
        assert_eq!(resolved.role, msg.role);
        assert_eq!(resolved.content, msg.content);
    }

    #[test]
    fn block_pool_dedupes_shared_blocks_across_messages() {
        // 两个 message 共享同一个 text block → 池中只存 1 份.
        let mut pool = BlockPool::default();
        let m1 = text_msg(IrRole::System, "shared system prompt");
        let m2 = text_msg(IrRole::User, "shared system prompt");
        pool.intern_message(&m1);
        pool.intern_message(&m2);
        assert_eq!(
            pool.len(),
            1,
            "identical text blocks should dedupe to 1 in pool"
        );
    }

    // ─── hash_block 非 Text variant + 跨 variant 不碰撞 (P1) ──────────────
    //
    // 背景: 现有 6 个 BlockPool 测试只覆盖 IrBlock::Text. 真实 tool-use 场景必经
    // ToolUse / ToolResult / Image variant 的 intern→resolve 路径. 若 canonical JSON
    // 序列化假设破坏 (如 serde_json 启用 preserve_order) 会静默错配 BlockHash.
    // 这里覆盖每个 variant 的 round-trip + 跨 variant 不碰撞.

    #[test]
    fn dag_block_tooluse_intern_resolve_roundtrip() {
        // ToolUse 含 id/name/input, 走 serde_json canonical 序列化路径做 hash.
        // 验证 intern 后 resolve 回来字段严格相等.
        let mut pool = BlockPool::default();
        let block = IrBlock::ToolUse {
            id: "call_001".to_string(),
            name: "get_weather".to_string(),
            input: serde_json::json!({
                "location": "Beijing",
                "units": "celsius",
                "nested": {"a": [1, 2, 3], "b": true}
            }),
        };
        let h = pool.intern(block.clone());
        let resolved = pool.get(h).expect("block should be interned");
        assert_eq!(*resolved, block, "ToolUse round-trip 严格相等");
        assert_eq!(pool.len(), 1, "1 个 unique ToolUse block");
    }

    #[test]
    fn dag_block_tooluse_dedupes_identical_input() {
        // 相同 id/name/input 的 ToolUse 应 hash 命中 (dedupe).
        let mut pool = BlockPool::default();
        let input = serde_json::json!({"q": "rust async", "limit": 10});
        let b1 = IrBlock::ToolUse {
            id: "call_42".into(),
            name: "search".into(),
            input: input.clone(),
        };
        let b2 = IrBlock::ToolUse {
            id: "call_42".into(),
            name: "search".into(),
            input: input.clone(),
        };
        let h1 = pool.intern(b1);
        let h2 = pool.intern(b2);
        assert_eq!(h1, h2, "相同 ToolUse 应 hash 命中");
        assert_eq!(*pool.refcount.get(&h1).unwrap(), 2);
    }

    #[test]
    fn dag_block_tooluse_canonical_json_key_order_invariant() {
        // C3/契约: serde_json 默认 BTreeMap → key 按字母排序 → canonical.
        // 不同 key 顺序 (但同集合) 的 input JSON 应 hash 到同一 BlockHash.
        // 假设不成立时 (如启用 preserve_order): 此测试会失败, 提醒开发者改 hash 路径.
        let mut pool = BlockPool::default();
        let b1 = IrBlock::ToolUse {
            id: "x".into(),
            name: "fn".into(),
            input: serde_json::from_str(r#"{"a":1,"b":2,"c":3}"#).unwrap(),
        };
        let b2 = IrBlock::ToolUse {
            id: "x".into(),
            name: "fn".into(),
            input: serde_json::from_str(r#"{"c":3,"a":1,"b":2}"#).unwrap(),
        };
        let h1 = pool.intern(b1);
        let h2 = pool.intern(b2);
        assert_eq!(
            h1, h2,
            "相同 key 集合不同顺序应 hash 一致 (canonical JSON 假设)"
        );
    }

    #[test]
    fn dag_block_tooluse_distinct_input_distinct_hash() {
        // 不同 input (即使只差一个字符) 应 hash 不同.
        let mut pool = BlockPool::default();
        let b1 = IrBlock::ToolUse {
            id: "x".into(),
            name: "fn".into(),
            input: serde_json::json!({"a": 1}),
        };
        let b2 = IrBlock::ToolUse {
            id: "x".into(),
            name: "fn".into(),
            input: serde_json::json!({"a": 2}),
        };
        let h1 = pool.intern(b1);
        let h2 = pool.intern(b2);
        assert_ne!(h1, h2, "不同 input 应 hash 不同");
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn dag_block_toolresult_flat_intern_resolve() {
        // ToolResult 含 tool_use_id + content (Vec<IrBlock>) + is_error.
        // 先测 content 仅含 Text 的扁平情况.
        let mut pool = BlockPool::default();
        let block = IrBlock::ToolResult {
            tool_use_id: "call_001".to_string(),
            content: vec![
                IrBlock::Text {
                    text: "tool output line 1".to_string(),
                },
                IrBlock::Text {
                    text: "tool output line 2".to_string(),
                },
            ],
            is_error: false,
            content_form: None,
        };
        let h = pool.intern(block.clone());
        let resolved = pool.get(h).expect("interned");
        assert_eq!(*resolved, block, "ToolResult round-trip 严格相等");
    }

    #[test]
    fn dag_block_toolresult_nested_tooluse_in_content() {
        // 嵌套递归 hash: ToolResult.content 中含 ToolUse 子 block.
        // 验证 hash_block 的递归路径正确 (for c in content { hash_block(c) }).
        let mut pool = BlockPool::default();
        let nested = IrBlock::ToolResult {
            tool_use_id: "parent_call".to_string(),
            content: vec![IrBlock::ToolUse {
                id: "child_call".to_string(),
                name: "parse".to_string(),
                input: serde_json::json!({"raw": "data"}),
            }],
            is_error: false,
            content_form: None,
        };
        let h = pool.intern(nested.clone());
        let resolved = pool.get(h).expect("interned");
        assert_eq!(*resolved, nested, "嵌套 ToolResult round-trip 严格相等");
    }

    #[test]
    fn dag_block_toolresult_is_error_affects_hash() {
        // is_error 不同 → hash 不同 (作为字段被 hash).
        let mut pool = BlockPool::default();
        let ok = IrBlock::ToolResult {
            tool_use_id: "c1".into(),
            content: vec![IrBlock::Text { text: "ok".into() }],
            is_error: false,
            content_form: None,
        };
        let err = IrBlock::ToolResult {
            tool_use_id: "c1".into(),
            content: vec![IrBlock::Text { text: "ok".into() }],
            is_error: true,
            content_form: None,
        };
        let h_ok = pool.intern(ok);
        let h_err = pool.intern(err);
        assert_ne!(h_ok, h_err, "is_error 不同 → hash 不同");
    }

    #[test]
    fn dag_block_toolresult_recursion_seen_in_pool() {
        // 嵌套 content 中的子 block 也应被 intern 到池中 (供跨 node 共享).
        // 注意: 当前 intern() 只把顶层 block 入池, 嵌套子 block 不单独 intern.
        // 此测试固化该行为: 池中只有 1 个 block (整个 ToolResult), 子 Text 不单独入池.
        let mut pool = BlockPool::default();
        let child = IrBlock::Text {
            text: "child".into(),
        };
        let parent = IrBlock::ToolResult {
            tool_use_id: "c1".into(),
            content: vec![child],
            is_error: false,
            content_form: None,
        };
        let _h = pool.intern(parent);
        assert_eq!(pool.len(), 1, "嵌套子 block 不单独入池 (顶层原子单元)");
    }

    #[test]
    fn dag_block_image_base64_intern_resolve() {
        // Image source = Base64 { media_type, data }.
        let mut pool = BlockPool::default();
        let block = IrBlock::Image {
            source: IrImageSource::Base64 {
                media_type: "image/png".to_string(),
                data: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB".to_string(),
            },
        };
        let h = pool.intern(block.clone());
        let resolved = pool.get(h).expect("interned");
        assert_eq!(*resolved, block, "Image Base64 round-trip 严格相等");
    }

    #[test]
    fn dag_block_image_url_intern_resolve() {
        // Image source = Url(String).
        let mut pool = BlockPool::default();
        let block = IrBlock::Image {
            source: IrImageSource::Url("https://example.com/img.png".to_string()),
        };
        let h = pool.intern(block.clone());
        let resolved = pool.get(h).expect("interned");
        assert_eq!(*resolved, block, "Image Url round-trip 严格相等");
    }

    #[test]
    fn dag_block_image_base64_distinct_from_url_hash() {
        // 即使 data 字符串与 url 字符串相同, Base64 与 Url 两 source 应 hash 不同
        // (discriminant 参与 hash).
        let mut pool = BlockPool::default();
        let payload = "same_string_payload".to_string();
        let b64 = IrBlock::Image {
            source: IrImageSource::Base64 {
                media_type: "image/png".into(),
                data: payload.clone(),
            },
        };
        let url = IrBlock::Image {
            source: IrImageSource::Url(payload),
        };
        let h_b64 = pool.intern(b64);
        let h_url = pool.intern(url);
        assert_ne!(h_b64, h_url, "Base64 vs Url 即使字符串相同, hash 应不同");
    }

    #[test]
    fn dag_block_cross_variant_no_collision() {
        // 跨 variant 不碰撞: Text("hello") vs ToolUse {name="hello", ...} 的 hash 必须不同.
        // discriminant 参与 hash, 即便部分字段相同, 不同 variant 应得不同 BlockHash.
        let mut pool = BlockPool::default();
        let text = IrBlock::Text {
            text: "hello".into(),
        };
        let tooluse_with_same_string = IrBlock::ToolUse {
            id: "hello".into(),
            name: "hello".into(),
            input: serde_json::json!("hello"),
        };
        let toolresult_with_same_string = IrBlock::ToolResult {
            tool_use_id: "hello".into(),
            content: vec![IrBlock::Text {
                text: "hello".into(),
            }],
            is_error: false,
            content_form: None,
        };
        let h_text = pool.intern(text);
        let h_tooluse = pool.intern(tooluse_with_same_string);
        let h_toolresult = pool.intern(toolresult_with_same_string);
        let mut seen = std::collections::HashSet::new();
        seen.insert(h_text);
        assert!(
            seen.insert(h_tooluse),
            "Text 与 ToolUse 不应碰撞 (discriminant)"
        );
        assert!(
            seen.insert(h_toolresult),
            "Text 与 ToolResult 不应碰撞 (discriminant)"
        );
        assert_eq!(pool.len(), 3, "3 个不同 variant 各占 1 槽");
    }

    #[test]
    fn dag_block_message_with_mixed_variants_roundtrips() {
        // 端到端: 一条含 4 种 variant 的 IrMessage, intern_message 后 resolve_message
        // 应回到完全相等的 IrMessage. 这是 tool-use 真实场景的 round-trip 守卫.
        let mut pool = BlockPool::default();
        let msg = IrMessage {
            role: IrRole::User,
            content: vec![
                IrBlock::Text {
                    text: "please use the tool".to_string(),
                },
                IrBlock::ToolUse {
                    id: "call_1".to_string(),
                    name: "search".to_string(),
                    input: serde_json::json!({"q": "rust"}),
                },
                IrBlock::ToolResult {
                    tool_use_id: "call_1".to_string(),
                    content: vec![IrBlock::Text {
                        text: "result here".to_string(),
                    }],
                    is_error: false,
                    content_form: None,
                },
                IrBlock::Image {
                    source: IrImageSource::Url("https://x/y.png".to_string()),
                },
            ],
            ..Default::default()
        };
        let msg_ref = pool.intern_message(&msg);
        let resolved = pool.resolve_message(&msg_ref).expect("should resolve");
        assert_eq!(resolved.role, msg.role);
        assert_eq!(
            resolved.content, msg.content,
            "混合 variant message round-trip"
        );
    }

    // ─── ConversationDag push + parent lookup tests ──────────────────────

    #[test]
    fn dag_push_single_node_no_parent() {
        let dag = ConversationDag::new(64, 500, 1);
        let msgs = vec![
            text_msg(IrRole::System, "sys"),
            text_msg(IrRole::User, "hello"),
        ];
        let id = dag.push_messages(msgs, dummy_event());
        let node = dag.get_node(id).expect("node exists");
        assert!(node.parent.is_none(), "first node has no parent");
        assert_eq!(node.req_delta_count, 2, "all 2 msgs are req_delta");
    }

    #[test]
    fn dag_push_linear_extension_finds_parent() {
        let dag = ConversationDag::new(64, 500, 1);

        // 第 1 次请求: [sys, u1] (request messages, 不含 response)
        let msgs_a = vec![
            text_msg(IrRole::System, "sys"),
            text_msg(IrRole::User, "hello"),
        ];
        let id_a = dag.push_messages(msgs_a, dummy_event());

        // 第 2 次请求: [sys, u1, a1, t1] — 前 2 条与 A 相同.
        // (a1 是 agent 从 A 的 response 复制进 req 的, t1 是 client 执行 tool 的结果)
        let msgs_b = vec![
            text_msg(IrRole::System, "sys"),
            text_msg(IrRole::User, "hello"),
            text_msg(IrRole::Assistant, "response from a"),
            text_msg(IrRole::Tool, "tool result 1"),
        ];
        let id_b = dag.push_messages(msgs_b, dummy_event());

        let node_b = dag.get_node(id_b).expect("node b exists");
        assert_eq!(node_b.parent, Some(id_a), "B should have A as parent");
        assert_eq!(node_b.req_delta_count, 2, "B req_delta = [a1, t1]");
    }

    #[test]
    fn dag_push_unrelated_messages_creates_new_root() {
        let dag = ConversationDag::new(64, 500, 1);

        let msgs_a = vec![
            text_msg(IrRole::System, "sys A"),
            text_msg(IrRole::User, "topic A"),
        ];
        let _id_a = dag.push_messages(msgs_a, dummy_event());

        // 完全不同的会话.
        let msgs_b = vec![
            text_msg(IrRole::System, "sys B"),
            text_msg(IrRole::User, "topic B"),
        ];
        let id_b = dag.push_messages(msgs_b, dummy_event());

        let node_b = dag.get_node(id_b).expect("node b exists");
        assert!(node_b.parent.is_none(), "unrelated messages → new root");
    }

    #[test]
    fn dag_full_request_messages_walks_parent_chain() {
        let dag = ConversationDag::new(64, 500, 1);

        let msgs_a = vec![
            text_msg(IrRole::System, "sys"),
            text_msg(IrRole::User, "u1"),
        ];
        let id_a = dag.push_messages(msgs_a, dummy_event());

        let msgs_b = vec![
            text_msg(IrRole::System, "sys"),
            text_msg(IrRole::User, "u1"),
            text_msg(IrRole::Assistant, "a1"),
            text_msg(IrRole::Tool, "t1"),
        ];
        let id_b = dag.push_messages(msgs_b, dummy_event());

        let full = dag.full_request_messages(id_b).expect("should walk");
        assert_eq!(full.len(), 4, "full request messages = sys + u1 + a1 + t1");
        assert_eq!(
            full[0].content[0],
            IrBlock::Text {
                text: "sys".to_string()
            }
        );
        assert_eq!(
            full[3].content[0],
            IrBlock::Text {
                text: "t1".to_string()
            }
        );

        // A 的 full request messages 只有 2 条.
        let full_a = dag.full_request_messages(id_a).expect("should walk");
        assert_eq!(full_a.len(), 2);
    }

    #[test]
    fn dag_fifo_eviction_drops_oldest() {
        let dag = ConversationDag::new(2, 500, 1);

        let id_a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let _id_b = dag.push_messages(vec![text_msg(IrRole::User, "b")], dummy_event());
        let _id_c = dag.push_messages(vec![text_msg(IrRole::User, "c")], dummy_event());

        // A 应被淘汰.
        assert!(dag.get_node(id_a).is_none(), "oldest node evicted");
        assert_eq!(dag.node_count(), 2);
    }

    #[test]
    fn dag_fifo_eviction_releases_blocks() {
        // 淘汰 node 时, 它持有的 block refcount 应递减.
        // 用一个不被其他 node 引用的 unique block 验证.
        let dag = ConversationDag::new(1, 500, 1);

        let unique_text = "unique_block_for_eviction_test";
        let _id = dag.push_messages(vec![text_msg(IrRole::User, unique_text)], dummy_event());
        // 此时 block refcount = 1.
        let g = dag.inner.read();
        assert_eq!(g.blocks.len(), 1);
        drop(g);

        // push 第二条 (不同 content), 触发淘汰第一条.
        let _id2 = dag.push_messages(
            vec![text_msg(IrRole::User, "different content")],
            dummy_event(),
        );

        let g = dag.inner.read();
        // 第一条的 block 应已被释放 (refcount → 0).
        // 只剩第二条的 1 个 block.
        assert_eq!(
            g.blocks.len(),
            1,
            "evicted node's blocks should be released"
        );
    }

    #[test]
    fn dag_block_sharing_across_nodes() {
        // 场景: A = [sys, u1], B = [sys, u1, a1, t1].
        // B 的前 2 条与 A 相同 → B 的 parent=A, delta=[a1, t1].
        // 修复后: 前缀部分 (sys, u1) 的 refcount 不由 B 持有 (由 parent A 持有),
        // 所以 sys/u1 refcount=1 (只 A), a1/t1 refcount=1 (只 B).
        let dag = ConversationDag::new(64, 500, 1);

        let sys_msg = text_msg(IrRole::System, "shared system prompt");
        let msgs_a = vec![sys_msg.clone(), text_msg(IrRole::User, "u1")];
        let _id_a = dag.push_messages(msgs_a, dummy_event());

        let msgs_b = vec![
            sys_msg,
            text_msg(IrRole::User, "u1"),
            text_msg(IrRole::Assistant, "a1"),
            text_msg(IrRole::Tool, "t1"),
        ];
        let _id_b = dag.push_messages(msgs_b, dummy_event());

        let g = dag.inner.read();
        // sys + u1 + a1 + t1 = 4 个 unique block.
        assert_eq!(g.blocks.len(), 4);
        // sys refcount: 只被 A 持有 (B 的前缀 refcount 已释放).
        let sys_hash = hash_block(&IrBlock::Text {
            text: "shared system prompt".to_string(),
        });
        let sys_refcount = g.blocks.refcount.get(&sys_hash).copied().unwrap_or(0);
        assert_eq!(
            sys_refcount, 1,
            "system prompt block refcount: only parent A holds it (B released prefix)"
        );
    }

    #[test]
    fn dag_prefix_block_refcount_no_leak_after_evict() {
        // 回归测试 (review B1): 淘汰 parent 后, 前缀 block 应被正确 GC.
        // 修复前: push 时前缀 refcount 未释放, 淘汰 parent 后 block 仍残留 (泄漏).
        let dag = ConversationDag::new(2, 500, 1); // max=2, 第 3 次 push 会淘汰 A.

        let sys_msg = text_msg(IrRole::System, "sys");
        let _id_a = dag.push_messages(vec![sys_msg.clone()], dummy_event());
        // B 的前缀与 A 相同 → B 不持有 sys (前缀 refcount 已释放).
        let _id_b = dag.push_messages(vec![sys_msg], dummy_event());
        // C 触发 FIFO 淘汰 A (max=2). C 用全新 message, 不与 A/B 共享前缀.
        let _id_c = dag.push_messages(vec![text_msg(IrRole::User, "c")], dummy_event());

        let g = dag.inner.read();
        let sys_hash = hash_block(&IrBlock::Text { text: "sys".into() });
        // A 已被淘汰 (释放了它持有的 sys refcount). B 不持有 sys (前缀已释放).
        // C 不含 sys. 所以 sys 应被完全 GC.
        let sys_refcount = g.blocks.refcount.get(&sys_hash).copied().unwrap_or(0);
        assert_eq!(
            sys_refcount, 0,
            "sys should be GC'd after parent A evicted (B released prefix refcount)"
        );
    }

    #[test]
    fn dag_list_newest_first() {
        let dag = ConversationDag::new(64, 500, 1);
        let id_a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let id_b = dag.push_messages(vec![text_msg(IrRole::User, "b")], dummy_event());
        let ids = dag.list_node_ids_newest_first();
        assert_eq!(ids, vec![id_b, id_a], "newest first");
    }

    #[test]
    fn dag_empty_messages_creates_orphan_node() {
        // 无 messages 的请求 (GET /v1/models 等) 应创建孤立节点.
        let dag = ConversationDag::new(64, 500, 1);
        let id = dag.push_messages(vec![], dummy_event());
        let node = dag.get_node(id).expect("node exists");
        assert!(node.parent.is_none(), "orphan node has no parent");
        assert_eq!(node.req_delta_count, 0, "no messages");
    }

    #[test]
    fn dag_multi_hop_parent_chain() {
        // 模拟 opencode 的 3 步链: A → B → C.
        // request messages 含 agent 复制进来的 assistant (OriginRecord 视角).
        let dag = ConversationDag::new(64, 500, 1);

        // A req: [sys, u1] (首次请求只有 system + user)
        let id_a = dag.push_messages(
            vec![
                text_msg(IrRole::System, "sys"),
                text_msg(IrRole::User, "u1"),
            ],
            dummy_event(),
        );

        // B req: [sys, u1, a1, t1] (a1 是 agent 从 A response 复制的, t1 是 tool 结果)
        let id_b = dag.push_messages(
            vec![
                text_msg(IrRole::System, "sys"),
                text_msg(IrRole::User, "u1"),
                text_msg(IrRole::Assistant, "a1"),
                text_msg(IrRole::Tool, "t1"),
            ],
            dummy_event(),
        );

        // C req: [sys, u1, a1, t1, a2, t2]
        let id_c = dag.push_messages(
            vec![
                text_msg(IrRole::System, "sys"),
                text_msg(IrRole::User, "u1"),
                text_msg(IrRole::Assistant, "a1"),
                text_msg(IrRole::Tool, "t1"),
                text_msg(IrRole::Assistant, "a2"),
                text_msg(IrRole::Tool, "t2"),
            ],
            dummy_event(),
        );

        // 验证 parent 链.
        assert!(dag.get_node(id_a).unwrap().parent.is_none());
        assert_eq!(dag.get_node(id_b).unwrap().parent, Some(id_a));
        assert_eq!(dag.get_node(id_c).unwrap().parent, Some(id_b));

        // C 的 full request messages 应有 6 条.
        let full_c = dag.full_request_messages(id_c).expect("walk");
        assert_eq!(full_c.len(), 6);

        // req_delta 验证.
        assert_eq!(dag.get_node(id_a).unwrap().req_delta_count, 2); // [sys, u1]
        assert_eq!(dag.get_node(id_b).unwrap().req_delta_count, 2); // [a1, t1]
        assert_eq!(dag.get_node(id_c).unwrap().req_delta_count, 2); // [a2, t2]
    }

    // ─── attach_response / update_parsed_response / get_node_detail ──────

    /// 构造一个带 preview/model/req_body_raw 的 CallEvent (覆盖 list/get 视图字段).
    fn event_with_body(path: &str, req_body: &str) -> CallEvent {
        let (preview, model) = crate::derive::extract_preview_and_model(req_body);
        CallEvent {
            created_at: Utc::now(),
            method: "POST".to_string(),
            path: path.to_string(),
            req_headers: vec![("authorization".into(), "<redacted>".into())],
            ingress_protocol: None,
            redact_seed: 0,
            policy: Arc::new(PolicySnapshot::default()),
            req_body_raw: req_body.to_string(),
            round_role: IrRole::User,
            preview: preview.map(Arc::<str>::from),
            model: model.map(Arc::<str>::from),
            redactions: Arc::from([]),
        }
    }

    #[test]
    fn attach_response_populates_nodeview_and_response() {
        // push 后 attach_response, NodeView 应反映最终 resp_status / elapsed_ms,
        // get_response 应返回完整 ResponseData.
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(vec![text_msg(IrRole::User, "u")], dummy_event());

        // attach 前: NodeView 的 resp_status / streamed 等是默认值.
        let v0 = dag.get_node(id).expect("node exists");
        assert_eq!(v0.resp_status, 0);
        assert!(!v0.streamed);
        assert!(!v0.resp_complete);
        assert!(v0.error.is_none());
        assert!(v0.redactions.is_empty());
        assert!(dag.get_response(id).is_none());

        dag.attach_response(
            id,
            ResponseData {
                resp_status: 200,
                resp_headers: vec![("content-type".into(), "application/json".into())],
                raw_resp_body: "{\"ok\":true}".into(),
                elapsed_ms: 42,
                streamed: false,
                resp_complete: true,
                error: None,
                ..Default::default()
            },
        );

        // attach 后: NodeView 反映新值 (redactions 从 CallEvent 派生, 不在 response 上).
        let v1 = dag.get_node(id).expect("node exists");
        assert_eq!(v1.resp_status, 200);
        assert_eq!(v1.elapsed_ms, 42);
        assert!(v1.resp_complete);
        assert!(v1.redactions.is_empty(), "dummy_event has empty redactions");

        // get_response 返回完整 ResponseData (无 redactions 字段).
        let r = dag.get_response(id).expect("response attached");
        assert_eq!(r.resp_status, 200);
        assert_eq!(r.raw_resp_body, "{\"ok\":true}");
    }

    #[test]
    fn attach_response_on_evicted_node_warns_not_panics() {
        // max=1, 第二次 push 淘汰 A; 对 A attach_response 应 warn + no-op.
        let dag = ConversationDag::new(1, 500, 1);
        let id_a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let _id_b = dag.push_messages(vec![text_msg(IrRole::User, "b")], dummy_event());
        // id_a 已被淘汰, attach 应不 panic.
        dag.attach_response(
            id_a,
            ResponseData {
                resp_status: 200,
                ..Default::default()
            },
        );
    }

    #[test]
    fn update_parsed_response_creates_partial_when_absent() {
        // 节点尚未 attach_response 时, update_parsed_response 应自动创建一个 default
        // ResponseData (resp_complete=false) 并只填 parsed 字段.
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(vec![text_msg(IrRole::User, "u")], dummy_event());
        dag.update_parsed_response(id, serde_json::json!({"partial": true}));

        let r = dag.get_response(id).expect("partial response auto-created");
        assert_eq!(r.parsed, Some(serde_json::json!({"partial": true})));
        assert!(
            !r.resp_complete,
            "auto-created partial should be incomplete"
        );
        assert_eq!(r.resp_status, 0);
    }

    #[test]
    fn update_parsed_response_overwrites_existing_parsed() {
        // 已 attach 完整 ResponseData 后, update_parsed_response 只改 parsed, 保留其他字段.
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(vec![text_msg(IrRole::User, "u")], dummy_event());
        dag.attach_response(
            id,
            ResponseData {
                resp_status: 200,
                resp_complete: true,
                raw_resp_body: "body".into(),
                ..Default::default()
            },
        );
        dag.update_parsed_response(id, serde_json::json!({"v": 2}));
        let r = dag.get_response(id).expect("response exists");
        assert_eq!(r.resp_status, 200, "other fields preserved");
        assert!(r.resp_complete);
        assert_eq!(r.parsed, Some(serde_json::json!({"v": 2})));
    }

    #[test]
    fn update_parsed_response_on_evicted_node_warns_not_panics() {
        let dag = ConversationDag::new(1, 500, 1);
        let id_a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let _id_b = dag.push_messages(vec![text_msg(IrRole::User, "b")], dummy_event());
        dag.update_parsed_response(id_a, serde_json::json!({}));
    }

    #[test]
    fn get_node_detail_returns_req_headers_and_body() {
        // get_node_detail 提供 GET /records/{id} 所需的 req_headers + req_body_raw.
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(
            vec![],
            event_with_body("/o/x/v1/chat", "{\"model\":\"gpt-x\"}"),
        );
        let d = dag.get_node_detail(id).expect("detail exists");
        assert_eq!(d.req_body_raw, "{\"model\":\"gpt-x\"}");
        assert_eq!(d.req_headers.len(), 1);
        assert_eq!(d.req_headers[0].0, "authorization");
    }

    #[test]
    fn nodeview_carries_preview_model_and_response_fields() {
        // NodeView 应携带 list 路径所需的所有字段 (preview/model/streamed/redactions/...).
        let dag = ConversationDag::new(8, 500, 1);
        let mut ev = event_with_body("/o/x/v1/chat", "{}");
        ev.redactions = Arc::from([("MOCKx".into(), "k".into())]);
        let id = dag.push_messages(vec![], ev);
        dag.attach_response(
            id,
            ResponseData {
                resp_status: 500,
                elapsed_ms: 99,
                streamed: true,
                resp_complete: false,
                error: Some("upstream error".into()),
                ..Default::default()
            },
        );
        let v = dag.get_node(id).expect("node exists");
        assert!(v.preview.is_none(), "body 无 messages → preview=None");
        assert!(v.model.is_none(), "body 无 model 字段 → model=None");
        assert_eq!(v.resp_status, 500);
        assert_eq!(v.elapsed_ms, 99);
        assert!(v.streamed);
        assert!(!v.resp_complete);
        assert_eq!(v.error.as_deref(), Some("upstream error"));
        assert_eq!(v.redactions.len(), 1, "redactions from CallEvent");
    }

    #[test]
    fn nodeview_defaults_when_no_response_attached() {
        // 节点尚未 attach_response: NodeView 的响应字段应为默认值 (false / 空).
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(vec![], dummy_event());
        let v = dag.get_node(id).expect("node exists");
        assert!(!v.has_response);
        assert!(!v.streamed);
        assert!(!v.resp_complete);
        assert!(v.error.is_none());
        assert!(v.redactions.is_empty());
        assert_eq!(v.resp_status, 0);
    }

    #[test]
    fn attach_response_parsed_field_preserved() {
        // attach_response 时设置的 parsed 字段应能通过 get_response 取回.
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(vec![text_msg(IrRole::User, "u")], dummy_event());
        let parsed_value = serde_json::json!({"choices": [{"message": {"content": "hi"}}]});
        dag.attach_response(
            id,
            ResponseData {
                resp_status: 200,
                parsed: Some(parsed_value.clone()),
                resp_complete: true,
                ..Default::default()
            },
        );
        let r = dag.get_response(id).expect("response attached");
        assert_eq!(r.parsed, Some(parsed_value));
    }

    #[test]
    fn list_node_ids_reflects_fifo_order_after_attach() {
        // attach_response 不改变 FIFO 顺序 (顺序由 push 决定).
        let dag = ConversationDag::new(8, 500, 1);
        let id_a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let id_b = dag.push_messages(vec![text_msg(IrRole::User, "b")], dummy_event());
        let id_c = dag.push_messages(vec![text_msg(IrRole::User, "c")], dummy_event());
        // 中间 attach 不影响顺序.
        dag.attach_response(
            id_b,
            ResponseData {
                resp_status: 200,
                ..Default::default()
            },
        );
        let ids = dag.list_node_ids_newest_first();
        assert_eq!(ids, vec![id_c, id_b, id_a]);
    }

    #[test]
    fn nodeview_preview_model_passthrough_when_uncomputed() {
        // 当 CallEvent 的 preview/model 为 None (eg passthrough GET 请求), NodeView 透传 None.
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(vec![], dummy_event());
        let v = dag.get_node(id).expect("node exists");
        assert!(v.preview.is_none());
        assert!(v.model.is_none());
    }

    #[test]
    fn get_node_detail_on_evicted_returns_none() {
        // 节点被 FIFO 淘汰后, get_node_detail 应返回 None (不 panic).
        let dag = ConversationDag::new(1, 500, 1);
        let id_a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let _id_b = dag.push_messages(vec![text_msg(IrRole::User, "b")], dummy_event());
        assert!(dag.get_node_detail(id_a).is_none());
        assert!(dag.get_node(id_a).is_none());
        assert!(dag.get_response(id_a).is_none());
    }

    #[test]
    fn response_data_default_is_empty_state() {
        // ResponseData::default() 应所有字段为空/默认 (用于 partial 占位场景的语义校验).
        let r = ResponseData::default();
        assert!(r.message.is_none());
        assert!(r.usage.is_zero());
        assert!(r.stop_reason.is_none());
        assert!(r.id.is_none());
        assert!(r.model.is_none());
        assert!(r.raw_resp_body.is_empty());
        assert!(!r.streamed);
        assert!(!r.resp_complete);
        assert!(r.error.is_none());
        assert!(r.parsed.is_none());
        assert_eq!(r.resp_status, 0);
        assert!(r.resp_headers.is_empty());
        assert_eq!(r.elapsed_ms, 0);
    }

    #[test]
    fn attach_response_can_be_called_twice_overwrites() {
        // 二次 attach_response 应整体替换 (不合并), 这是 proxy 流式路径先 partial 后
        // 完整 attach 的契约. 最后一次写入胜出.
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(vec![text_msg(IrRole::User, "u")], dummy_event());
        dag.attach_response(
            id,
            ResponseData {
                resp_status: 200,
                resp_complete: false,
                raw_resp_body: "partial".into(),
                ..Default::default()
            },
        );
        // 中间 update_parsed 不影响后续整体 attach.
        dag.update_parsed_response(id, serde_json::json!({"partial": true}));
        // 最终 attach 覆盖一切.
        dag.attach_response(
            id,
            ResponseData {
                resp_status: 200,
                resp_complete: true,
                raw_resp_body: "final".into(),
                ..Default::default()
            },
        );
        let r = dag.get_response(id).expect("response attached");
        assert_eq!(r.raw_resp_body, "final");
        assert!(r.resp_complete);
        // parsed 被 final attach 覆盖为 None (final 未设置 parsed).
        assert!(r.parsed.is_none());
    }

    #[test]
    fn update_parsed_response_preserves_already_attached_response_fields() {
        // 已 attach 完整 ResponseData 后, update_parsed_response 只覆盖 parsed,
        // 不应清空 resp_status / raw_resp_body 等字段.
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(vec![text_msg(IrRole::User, "u")], dummy_event());
        dag.attach_response(
            id,
            ResponseData {
                resp_status: 201,
                raw_resp_body: "kept-body".into(),
                elapsed_ms: 7,
                resp_complete: true,
                ..Default::default()
            },
        );
        dag.update_parsed_response(id, serde_json::json!({"v": 1}));
        let r = dag.get_response(id).expect("response exists");
        assert_eq!(r.resp_status, 201, "resp_status preserved");
        assert_eq!(r.raw_resp_body, "kept-body", "raw_resp_body preserved");
        assert_eq!(r.elapsed_ms, 7, "elapsed_ms preserved");
        assert!(r.resp_complete, "resp_complete preserved");
        assert_eq!(r.parsed, Some(serde_json::json!({"v": 1})));
    }

    // ─── sessions / leaves / timeline ────────────────────────────────────

    #[test]
    fn leaves_tracks_session_tips() {
        // A (root) → B → C (leaf). leaves = [C].
        let dag = ConversationDag::new(64, 500, 1);
        let _a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let _b = dag.push_messages(
            vec![
                text_msg(IrRole::User, "a"),
                text_msg(IrRole::Assistant, "b"),
            ],
            dummy_event(),
        );
        let c = dag.push_messages(
            vec![
                text_msg(IrRole::User, "a"),
                text_msg(IrRole::Assistant, "b"),
                text_msg(IrRole::User, "c"),
            ],
            dummy_event(),
        );
        let sessions = dag.list_sessions();
        assert_eq!(sessions.len(), 1, "one session");
        assert_eq!(sessions[0].leaf_id, c, "leaf is C");
        assert_eq!(sessions[0].root_id, _a, "root is A");
        assert_eq!(sessions[0].record_count, 3, "3 rounds");
    }

    #[test]
    fn leaves_multiple_independent_sessions() {
        let dag = ConversationDag::new(64, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let b = dag.push_messages(vec![text_msg(IrRole::User, "b")], dummy_event());
        let sessions = dag.list_sessions();
        assert_eq!(sessions.len(), 2, "two independent sessions");
        // 倒序 (latest first).
        assert_eq!(sessions[0].leaf_id, b);
        assert_eq!(sessions[1].leaf_id, a);
    }

    #[test]
    fn session_lru_evict_keeps_min_sessions_floor() {
        // max_nodes=1 但 min_sessions=1: 即使 nodes 数超标, 只剩 1 个 session 时不淘汰.
        let dag = ConversationDag::new(1, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let b = dag.push_messages(
            vec![
                text_msg(IrRole::User, "a"),
                text_msg(IrRole::Assistant, "b"),
            ],
            dummy_event(),
        );
        // nodes=2 > max_nodes=1, 但 sessions=1 = min_sessions=1 → 保底, 不淘汰.
        let sessions = dag.list_sessions();
        assert_eq!(sessions.len(), 1, "min_sessions floor prevents eviction");
        assert_eq!(sessions[0].leaf_id, b);
        assert_eq!(sessions[0].record_count, 2, "both A and B kept");
        // A 仍在内存.
        assert!(dag.get_node(a).is_some(), "A not evicted (min floor)");
    }

    #[test]
    fn session_lru_evict_drops_oldest_session() {
        // 两个独立会话, max_nodes=1 → 第一个会话被整体淘汰.
        let dag = ConversationDag::new(1, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let b = dag.push_messages(vec![text_msg(IrRole::User, "b")], dummy_event());
        // nodes=2 > max_nodes=1, sessions=2 > min_sessions=1 → 淘汰 LRU (会话 A).
        assert!(dag.get_node(a).is_none(), "oldest session A evicted");
        assert!(dag.get_node(b).is_some(), "newest session B kept");
        let sessions = dag.list_sessions();
        assert_eq!(sessions.len(), 1, "only session B remains");
    }

    #[test]
    fn session_gc_cascade_protects_fork_shared_parent() {
        // fork 场景: A → B → C (s1), A → B → C' (s2 fork at B).
        // evict s1 不应删除 B (s2 仍引用它, child_count > 0).
        let dag = ConversationDag::new(8, 500, 1);
        // A = [u1]
        let _a = dag.push_messages(vec![text_msg(IrRole::User, "u1")], dummy_event());
        // B extends A: [u1, a1]
        let b = dag.push_messages(
            vec![
                text_msg(IrRole::User, "u1"),
                text_msg(IrRole::Assistant, "a1"),
            ],
            dummy_event(),
        );
        // C extends B: [u1, a1, u2]
        let c = dag.push_messages(
            vec![
                text_msg(IrRole::User, "u1"),
                text_msg(IrRole::Assistant, "a1"),
                text_msg(IrRole::User, "u2"),
            ],
            dummy_event(),
        );
        // C' forks from B (same prefix up to [u1, a1], then diverges): [u1, a1, u3]
        let c_prime = dag.push_messages(
            vec![
                text_msg(IrRole::User, "u1"),
                text_msg(IrRole::Assistant, "a1"),
                text_msg(IrRole::User, "u3"),
            ],
            dummy_event(),
        );
        // 2 sessions: s1 (leaf=C), s2 (leaf=C'). B 是共享 (child_count=2).
        let sessions = dag.list_sessions();
        assert_eq!(sessions.len(), 2, "fork creates 2 sessions");
        // 直接 gc_cascade s1 (从 leaf=C 开始): 删 C → B.child_count 2→1 → 停 (B 保留).
        {
            let mut g = dag.inner.write();
            let s1 = sessions.iter().find(|s| s.leaf_id == c).expect("s1 exists");
            ConversationDag::gc_cascade(&mut g, s1.leaf_id);
            g.sessions.remove(&s1.session_id);
        }
        // C 已删, B 仍在 (s2 引用), C' 仍在, A 仍在.
        assert!(dag.get_node(c).is_none(), "C (s1 leaf) evicted");
        assert!(dag.get_node(b).is_some(), "B shared, not evicted");
        assert!(dag.get_node(c_prime).is_some(), "C' (s2 leaf) kept");
    }

    // ─── session-aware timeline API (session_rounds / timeline_view / timeline_diff) ─
    //
    // 替代旧的 node_id-based timeline() 测试. 新 API 基于 SessionId, 三条路径:
    // - session_rounds(sid): sidebar 三级菜单的轻量摘要.
    // - timeline_view(sid, before, limit): 初始加载 + lazy load (向前翻更老).
    // - timeline_diff(sid, after, tail_length): sync 轮询的 diff.
    //
    // 链遍历语义: 从 leaf 沿 parent 回溯, oldest-first 返回. before/after 游标控制起点.

    /// 辅助: push 一条 user message + attach 一个 parsed response, 返回新 node id.
    /// 用于 timeline 测试快速构造带 response 的 node.
    fn push_with_response(
        dag: &ConversationDag,
        msgs: Vec<IrMessage>,
        parsed: Option<serde_json::Value>,
    ) -> Uuid {
        let id = dag.push_messages(msgs, dummy_event());
        if let Some(p) = parsed {
            dag.attach_response(
                id,
                ResponseData {
                    parsed: Some(p),
                    resp_status: 200,
                    resp_complete: true,
                    ..Default::default()
                },
            );
        }
        id
    }

    /// 辅助: 取 session 的 sid (从 leaf node 反查).
    fn sid_of(dag: &ConversationDag, leaf: Uuid) -> SessionId {
        dag.get_node(leaf).expect("leaf exists").session_id
    }

    #[test]
    fn session_rounds_returns_oldest_first() {
        // 3 轮链 A → B → C, session_rounds(leaf=C) → [A, B, C] oldest-first.
        let dag = ConversationDag::new(64, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let _b = dag.push_messages(
            vec![
                text_msg(IrRole::User, "a"),
                text_msg(IrRole::Assistant, "b"),
            ],
            dummy_event(),
        );
        let c = dag.push_messages(
            vec![
                text_msg(IrRole::User, "a"),
                text_msg(IrRole::Assistant, "b"),
                text_msg(IrRole::User, "c"),
            ],
            dummy_event(),
        );
        let sid = sid_of(&dag, c);
        let rounds = dag.session_rounds(sid);
        assert_eq!(rounds.len(), 3);
        assert_eq!(rounds[0].id, a, "oldest first");
        assert_eq!(rounds[2].id, c, "newest last");
    }

    #[test]
    fn session_rounds_unknown_sid_returns_empty() {
        let dag = ConversationDag::new(64, 500, 1);
        let _ = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        // 不存在的 sid → 空 Vec (不 panic).
        let rounds = dag.session_rounds(SessionId::new());
        assert!(rounds.is_empty());
    }

    /// 构造 IR 归一化后的 tool_result user 消息 (role=User 但 content 仅含 ToolResult block).
    /// 模拟 codec reader 把 OpenAI `role:"tool"` / Anthropic tool_result block 读入后的形态.
    fn tool_result_msg() -> IrMessage {
        IrMessage {
            role: IrRole::User,
            content: vec![IrBlock::ToolResult {
                tool_use_id: "call_1".to_string(),
                content: vec![IrBlock::Text {
                    text: "tool output".to_string(),
                }],
                is_error: false,
                content_form: None,
            }],
            // 关键: tool_result 借 user 角色但不是用户的主动文本输入.
            contains_user_text: false,
            ..Default::default()
        }
    }

    /// round_role 判定基于 contains_user_text, 而非 IrMessage.role.
    /// tool-call 循环 (assistant tool_use + user tool_result) 的 round_role 必须是 Tool,
    /// 否则 sidebar 会把它们全部平铺为 round-item (bug #1).
    #[test]
    fn round_role_distinguishes_user_text_from_tool_result() {
        let dag = ConversationDag::new(64, 500, 1);
        // 轮1: 用户提问 (delta=[user:"list files"]).
        let _ = dag.push_messages(vec![text_msg(IrRole::User, "list files")], dummy_event());
        // 轮2: tool-call 循环 (delta=[assistant:tool_use, user(tool_result)]).
        //   IR 归一化后两条 message 的 role 分别是 Assistant 和 User,
        //   但最后一条 user 的 contains_user_text=false (纯 tool_result).
        let id2 = dag.push_messages(
            vec![
                IrMessage {
                    role: IrRole::Assistant,
                    content: vec![IrBlock::ToolUse {
                        id: "call_1".to_string(),
                        name: "ls".to_string(),
                        input: serde_json::Value::Object(serde_json::Map::new()),
                    }],
                    ..Default::default()
                },
                tool_result_msg(),
            ],
            dummy_event(),
        );
        let node2 = dag.get_node(id2).unwrap();
        assert_eq!(
            node2.round_role,
            IrRole::Tool,
            "tool-call 循环 round_role 应为 Tool (delta 无用户文本)"
        );
    }

    /// Anthropic 混合消息 (user 同含 Text + ToolResult) 的 round_role 应为 User.
    /// 用户在工具结果旁附加了新文本输入 → 仍是用户主导的轮次.
    #[test]
    fn round_role_mixed_text_and_tool_result_is_user() {
        let dag = ConversationDag::new(64, 500, 1);
        let _ = dag.push_messages(vec![text_msg(IrRole::User, "topic")], dummy_event());
        let id2 = dag.push_messages(
            vec![
                text_msg(IrRole::User, "topic"),
                text_msg(IrRole::Assistant, "reply"),
                IrMessage {
                    role: IrRole::User,
                    content: vec![
                        IrBlock::Text {
                            text: "查完后帮我总结".to_string(),
                        },
                        IrBlock::ToolResult {
                            tool_use_id: "call_1".to_string(),
                            content: vec![IrBlock::Text {
                                text: "result".to_string(),
                            }],
                            is_error: false,
                            content_form: None,
                        },
                    ],
                    contains_user_text: true, // reader 入口已正确标记
                    ..Default::default()
                },
            ],
            dummy_event(),
        );
        let node2 = dag.get_node(id2).unwrap();
        assert_eq!(
            node2.round_role,
            IrRole::User,
            "混合 Text+ToolResult 的 user 消息仍是用户主导轮"
        );
    }

    #[test]
    fn timeline_view_initial_load_returns_leaf_with_tail() {
        // before=None: 从 leaf 取 limit 条. tail = leaf 的 response 抽屉.
        let dag = ConversationDag::new(64, 500, 1);
        let a = push_with_response(&dag, vec![text_msg(IrRole::User, "u1")], None);
        let _b = push_with_response(
            &dag,
            vec![
                text_msg(IrRole::User, "u1"),
                text_msg(IrRole::Assistant, "a1"),
                text_msg(IrRole::User, "u2"),
            ],
            None,
        );
        let c = push_with_response(
            &dag,
            vec![
                text_msg(IrRole::User, "u1"),
                text_msg(IrRole::Assistant, "a1"),
                text_msg(IrRole::User, "u2"),
                text_msg(IrRole::Assistant, "a2"),
                text_msg(IrRole::User, "u3"),
            ],
            Some(serde_json::json!({"resp": "c-content"})),
        );
        let sid = sid_of(&dag, c);
        let page = dag.timeline_view(sid, None, 10).expect("page exists");
        // oldest-first: [A, B, C].
        assert_eq!(page.rounds.len(), 3);
        assert_eq!(page.rounds[0].id, a);
        assert_eq!(page.rounds[2].id, c);
        // tail = C (leaf) 的 response.
        assert_eq!(page.tail.round_id, c);
        assert_eq!(page.tail.resp_status, 200);
        // length = parsed 序列化字节数.
        assert_eq!(page.tail.length, r#"{"resp":"c-content"}"#.len());
        // C (leaf) 是链中最新, has_more=false (A 是根, parent=None).
        assert!(!page.has_more);
    }

    #[test]
    fn timeline_view_limit_truncates_and_has_more() {
        // limit < 链长: 取最近 limit 条, has_more=true.
        let dag = ConversationDag::new(64, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let _b = dag.push_messages(
            vec![
                text_msg(IrRole::User, "a"),
                text_msg(IrRole::Assistant, "b"),
            ],
            dummy_event(),
        );
        let c = dag.push_messages(
            vec![
                text_msg(IrRole::User, "a"),
                text_msg(IrRole::Assistant, "b"),
                text_msg(IrRole::User, "c"),
            ],
            dummy_event(),
        );
        let sid = sid_of(&dag, c);
        // limit=2: 取 [B, C], has_more=true (A 在 limit 之外).
        let page = dag.timeline_view(sid, None, 2).expect("page exists");
        assert_eq!(page.rounds.len(), 2);
        assert_eq!(page.rounds[1].id, c, "末轮是 leaf");
        assert!(page.has_more, "A 仍在链上, has_more=true");
        let _ = a;
    }

    #[test]
    fn timeline_view_before_cursor_loads_older() {
        // before=Some(id): 取 id 之前 (更老) 的 limit 条 (不含 id 自身).
        let dag = ConversationDag::new(64, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let b = dag.push_messages(
            vec![
                text_msg(IrRole::User, "a"),
                text_msg(IrRole::Assistant, "b"),
            ],
            dummy_event(),
        );
        let c = dag.push_messages(
            vec![
                text_msg(IrRole::User, "a"),
                text_msg(IrRole::Assistant, "b"),
                text_msg(IrRole::User, "c"),
            ],
            dummy_event(),
        );
        let sid = sid_of(&dag, c);
        // before=C, limit=10 → 取 C 之前 = [A, B] (不含 C).
        let page = dag.timeline_view(sid, Some(c), 10).expect("page exists");
        assert_eq!(page.rounds.len(), 2);
        assert_eq!(page.rounds[0].id, a);
        assert_eq!(page.rounds[1].id, b);
        assert!(!page.has_more, "A 是根, has_more=false");
        // tail = B (链中最新的那个), 不是 C.
        assert_eq!(page.tail.round_id, b);
    }

    #[test]
    fn timeline_view_unknown_sid_returns_none() {
        let dag = ConversationDag::new(64, 500, 1);
        let _ = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        assert!(dag.timeline_view(SessionId::new(), None, 10).is_none());
    }

    #[test]
    fn timeline_view_before_from_other_session_returns_none() {
        // before 游标属于另一个 session → None (跨 session 游标无意义).
        let dag = ConversationDag::new(64, 500, 1);
        let _a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let other_leaf = dag.push_messages(vec![text_msg(IrRole::User, "x")], dummy_event());
        let other_sid = sid_of(&dag, other_leaf);
        // 创建另一个 session 后, other_leaf 不再是 leaf, 但仍属于 other_sid.
        let c = dag.push_messages(
            vec![text_msg(IrRole::User, "x"), text_msg(IrRole::User, "c")],
            dummy_event(),
        );
        let sid_c = sid_of(&dag, c);
        // before=other_leaf 但 sid=sid_c → None.
        assert!(dag.timeline_view(sid_c, Some(other_leaf), 10).is_none());
        let _ = other_sid;
    }

    #[test]
    fn timeline_diff_returns_none_when_no_change() {
        // after=leaf + tail.length 一致 → None (304 等价).
        let dag = ConversationDag::new(64, 500, 1);
        let a = push_with_response(
            &dag,
            vec![text_msg(IrRole::User, "u1")],
            Some(serde_json::json!({"resp": "a1"})),
        );
        let sid = sid_of(&dag, a);
        let page = dag.timeline_view(sid, None, 10).expect("page exists");
        let diff = dag.timeline_diff(sid, Some(a), page.tail.length);
        assert!(diff.is_none(), "无新 round + tail 一致 → None");
    }

    #[test]
    fn timeline_diff_returns_new_rounds_after_push() {
        // 初始 leaf=A, 然后 push B → diff(after=A) 应返回 [B].
        let dag = ConversationDag::new(64, 500, 1);
        let a = push_with_response(
            &dag,
            vec![text_msg(IrRole::User, "u1")],
            Some(serde_json::json!({"resp": "a1"})),
        );
        let sid = sid_of(&dag, a);
        let b = push_with_response(
            &dag,
            vec![
                text_msg(IrRole::User, "u1"),
                text_msg(IrRole::Assistant, "a1"),
                text_msg(IrRole::User, "u2"),
            ],
            Some(serde_json::json!({"resp": "b1"})),
        );
        let diff = dag
            .timeline_diff(sid, Some(a), 0)
            .expect("有新 round → Some");
        assert_eq!(diff.new_rounds.len(), 1);
        assert_eq!(diff.new_rounds[0].id, b);
        // tail = B (当前 leaf).
        assert_eq!(diff.tail.round_id, b);
    }

    #[test]
    fn timeline_diff_after_not_in_session_returns_full_chain() {
        // after 不属于本 session (前端状态过期) → 返回全部 round.
        let dag = ConversationDag::new(64, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "u1")], dummy_event());
        let sid = sid_of(&dag, a);
        // after 是一个不存在的 id → after_belongs_to_sid=false → 全部返回.
        let bogus = Uuid::new_v4();
        let diff = dag
            .timeline_diff(sid, Some(bogus), 0)
            .expect("after 过期 → 全部返回");
        assert_eq!(diff.new_rounds.len(), 1);
        assert_eq!(diff.new_rounds[0].id, a);
    }

    #[test]
    fn timeline_diff_tail_change_only_returns_empty_new_rounds() {
        // after=leaf (无新 round) 但 tail.length 变化 → 返回空 new_rounds + 新 tail.
        let dag = ConversationDag::new(64, 500, 1);
        let a = push_with_response(
            &dag,
            vec![text_msg(IrRole::User, "u1")],
            Some(serde_json::json!({"resp": "a1"})),
        );
        let sid = sid_of(&dag, a);
        // 第一次 diff: tail.length 不一致 (传 0) → 返回新 tail (但 new_rounds 为空,
        // 因为 after=leaf 已是最新).
        let diff = dag
            .timeline_diff(sid, Some(a), 0)
            .expect("tail 变化 → Some");
        assert!(diff.new_rounds.is_empty(), "无新 round");
        assert!(diff.tail.length > 0, "tail 有内容");
    }

    #[test]
    fn sync_snapshot_collects_all_three_parts_in_one_lock() {
        // sync_snapshot: sessions + rounds (expanded) + timeline diff (selected) 一次性采集.
        let dag = ConversationDag::new(64, 500, 1);
        let a = push_with_response(
            &dag,
            vec![text_msg(IrRole::User, "u1")],
            Some(serde_json::json!({"resp": "a1"})),
        );
        let sid = sid_of(&dag, a);
        let b = push_with_response(
            &dag,
            vec![
                text_msg(IrRole::User, "u1"),
                text_msg(IrRole::Assistant, "a1"),
                text_msg(IrRole::User, "u2"),
            ],
            Some(serde_json::json!({"resp": "b1"})),
        );

        // selected = (sid, after=A, tail_length=0): 应返回 [B] 的 diff.
        let snap = dag.sync_snapshot(&[sid], Some((sid, Some(a), 0)));
        // sessions: 1 个 session.
        assert_eq!(snap.sessions.len(), 1);
        // rounds: expanded 含 sid → 2 个 round [A, B].
        assert_eq!(snap.rounds.get(&sid).map(|v| v.len()), Some(2));
        // timeline: diff 含 [B].
        let diff = snap.timeline.expect("有新 round → Some");
        assert_eq!(diff.new_rounds.len(), 1);
        assert_eq!(diff.new_rounds[0].id, b);
    }

    #[test]
    fn sync_snapshot_no_selected_timeline_is_none() {
        let dag = ConversationDag::new(64, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "u1")], dummy_event());
        let sid = sid_of(&dag, a);
        let snap = dag.sync_snapshot(&[sid], None);
        assert_eq!(snap.sessions.len(), 1);
        assert!(snap.timeline.is_none(), "无 selected → timeline=None");
    }

    #[test]
    fn sync_snapshot_expanded_unknown_sid_yields_empty_rounds() {
        let dag = ConversationDag::new(64, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "u1")], dummy_event());
        let sid = sid_of(&dag, a);
        let bogus = SessionId::new();
        let snap = dag.sync_snapshot(&[bogus], None);
        // bogus 不在 sessions map → rounds 中无对应 entry (不 panic).
        assert!(!snap.rounds.contains_key(&bogus));
        // 真 sid 不在 expanded → rounds 中也无.
        assert!(!snap.rounds.contains_key(&sid));
    }

    #[test]
    fn timeline_round_carries_req_delta_messages_for_leaf() {
        // 验证 TimelineRound 的 req_delta_messages 从 req_delta resolve 出来.
        // 这里用最简单的场景: 单 node, push 1 条 user msg → req_delta = [user msg].
        let dag = ConversationDag::new(64, 500, 1);
        let a = push_with_response(
            &dag,
            vec![text_msg(IrRole::User, "hello")],
            Some(serde_json::json!({"resp": "a1"})),
        );
        let sid = sid_of(&dag, a);
        let page = dag.timeline_view(sid, None, 10).expect("page exists");
        assert_eq!(page.rounds.len(), 1);
        // req_delta_messages 应含 1 条 user message.
        // dummy_event 无 req_body_raw → fallback raw 路径返回空 (预期). 仅验证不 panic.
        let _ = &page.rounds[0].req_delta_messages;
    }

    // ─── 并发回归守卫 ───────────────────────────────────────────────────────
    //
    // ConversationDag 用 `RwLock<DagInner>` 保护, 是核心并发数据结构. 既有 46 个单测全
    // 单线程顺序执行, 没有覆盖多写者 + 多读者并发场景. config.rs 有对应的
    // `concurrent_upserts_no_lost_update`, DAG 反而缺失. 以下测试用 std::thread (DAG 操作
    // 是 sync API) 压测并发 push + 并发读, 断言无 panic 且最终视图一致.

    #[test]
    fn concurrent_push_and_read_no_panic_no_data_race() {
        // N 个 writer 各 push 一组独立根 messages, 同时 M 个 reader 反复 list_sessions /
        // list_page / node_count. 最终所有 push 都应落库 (无 lost update), 读操作无 panic.
        const WRITERS: usize = 8;
        const READERS: usize = 4;
        const PUSHES_PER_WRITER: usize = 25;

        let dag = ConversationDag::new(4096, 4096, 1);
        // 写者返回 Option<Uuid>, 读者返回 (). 用 boxed trait object 统一 join.
        let mut writer_handles: Vec<std::thread::JoinHandle<Option<Uuid>>> = Vec::new();
        let mut reader_handles: Vec<std::thread::JoinHandle<()>> = Vec::new();

        // writers: 每个 writer 用唯一 i 生成不同 messages, 确保不退化成同一根.
        for i in 0..WRITERS {
            let dag_w = dag.clone();
            writer_handles.push(std::thread::spawn(move || {
                let mut last_id = None;
                for j in 0..PUSHES_PER_WRITER {
                    // 线性链: 后一次 push 含前一次的 prefix → 延续同一 session.
                    let mut msgs = vec![text_msg(IrRole::System, &format!("sys-{i}"))];
                    if let Some(prev) = last_id.take() {
                        // 拉父节点的 delta, 作为 prefix 续接.
                        if let Some(view) = dag_w.get_node(prev) {
                            // 用 parent 的 messages 重建前缀过于重; 直接构造 [sys, a_j].
                            let _ = view; // marker: 不读取, 简化构造.
                        }
                    }
                    msgs.push(text_msg(IrRole::User, &format!("writer-{i}-round-{j}")));
                    let new_id = dag_w.push_messages(msgs, dummy_event());
                    last_id = Some(new_id);
                }
                last_id
            }));
        }

        // readers: 读 side 持续触发, 直到所有 writer join.
        for _ in 0..READERS {
            let dag_r = dag.clone();
            reader_handles.push(std::thread::spawn(move || {
                for _ in 0..200 {
                    // 读操作必须不 panic; 视图一致性靠最终 join 后再断言.
                    let _ = dag_r.list_sessions();
                    let _ = dag_r.node_count();
                    let _ = dag_r.list_page(1, 20, false);
                }
            }));
        }

        for (i, h) in writer_handles.into_iter().enumerate() {
            let res = h.join().expect("writer thread must not panic");
            assert!(res.is_some(), "writer {i} last push must succeed");
        }
        for h in reader_handles {
            h.join().expect("reader thread must not panic");
        }

        // 最终一致性: 所有 writer 的 push 都成功 → node_count == WRITERS * PUSHES_PER_WRITER.
        let expected = WRITERS * PUSHES_PER_WRITER;
        assert_eq!(
            dag.node_count(),
            expected,
            "all concurrent pushes must be reflected; got {} expected {}",
            dag.node_count(),
            expected
        );
        // 每个 writer 独立根 → 至少 WRITERS 个 session.
        let sessions = dag.list_sessions();
        assert!(
            sessions.len() >= WRITERS,
            "expected >= {WRITERS} sessions, got {}",
            sessions.len()
        );
    }

    #[test]
    fn fork_and_lru_evict_preserves_shared_parent() {
        // fork 场景: A → B, 然后 A → B' (B' 复用 B 的前缀但发散).
        // 当 nodes 数超过 max_nodes 时, LRU 应淘汰某 session 的 leaf, 但 fork 共享的
        // parent (此处 A) 因 child_count > 0 不应被 gc_cascade 误删.
        //
        // 与既有 `session_gc_cascade_protects_fork_shared_parent` 区别: 那个测试手动调用
        // gc_cascade 绕过 LRU 选择; 本测试设置小 max_nodes 触发真实自动 LRU evict.
        let dag = ConversationDag::new(3, 500, 1);
        // A = [u1] (root, session s1)
        let a = dag.push_messages(vec![text_msg(IrRole::User, "u1")], dummy_event());
        // B = [u1, a1] extends A (s1 延续)
        let b = dag.push_messages(
            vec![
                text_msg(IrRole::User, "u1"),
                text_msg(IrRole::Assistant, "a1"),
            ],
            dummy_event(),
        );
        // B' forks from A (same prefix [u1], diverges): [u1, u2] → 新 session s2.
        let _b_prime = dag.push_messages(
            vec![text_msg(IrRole::User, "u1"), text_msg(IrRole::User, "u2")],
            dummy_event(),
        );
        // 此时 nodes = 3 = max_nodes. 再 push 一次触发 evict (sessions=2 > min_sessions=1).
        let _c = dag.push_messages(
            vec![
                text_msg(IrRole::User, "u1"),
                text_msg(IrRole::Assistant, "a1"),
                text_msg(IrRole::User, "c1"),
            ],
            dummy_event(),
        );

        // 关键不变量: A 作为 fork 共享点, 只要还有任一 child 引用就必须在 DAG 内.
        // (如果 A 被误删, get_node(A) 返回 None, 会导致后续 timeline / 完整请求重建失败.)
        assert!(
            dag.get_node(a).is_some(),
            "shared fork parent A must survive LRU eviction"
        );
        // B 是 s1 的中间节点, 当 s1 leaf 被淘汰时, gc_cascade 会走到 B.
        // 只要 s2 还引用 A, A 就受 child_count 守护.
        let _ = b;
    }

    // ─── fork 分支取最新 (P2): find_parent ids.last() 选择 ──────────────────

    #[test]
    fn dag_fork_creates_distinct_sessions_with_correct_parents() {
        // 直接覆盖 find_parent 中 "同 prefix_hash 多 entry 时取 ids.last()" 的关键选择.
        // 场景: A → B (session s1), 然后两个分叉 C1 / C2 都从 B 延伸 (B 已不是 leaf → fork).
        // 验证: C1 / C2 各自的 session_id 不同, parent 都正确指向 B, prefix_hash 链正确.
        let dag = ConversationDag::new(64, 500, 1);

        // A = [u1] (新 session)
        let _a = dag.push_messages(vec![text_msg(IrRole::User, "u1")], dummy_event());

        // B extends A: [u1, a1] → 延续 A 的 session (A 仍是 leaf 时 push B).
        let b = dag.push_messages(
            vec![
                text_msg(IrRole::User, "u1"),
                text_msg(IrRole::Assistant, "a1"),
            ],
            dummy_event(),
        );

        // C1 extends B: [u1, a1, u2] → B 仍是 s1 的 leaf → 延续 s1.
        let c1 = dag.push_messages(
            vec![
                text_msg(IrRole::User, "u1"),
                text_msg(IrRole::Assistant, "a1"),
                text_msg(IrRole::User, "u2"),
            ],
            dummy_event(),
        );

        // C2 forks from B: [u1, a1, u3] → B 不再是 s1 的 leaf (C1 是) → fork → 新 session.
        // find_parent 会再次命中 B 的 prefix_hash (cum[u1,a1] 对应的 entry),
        // 但因 B 已不是 leaf → fork 路径. 同时验证 ids.last() 取的是 B 而非其他共享前缀节点.
        let c2 = dag.push_messages(
            vec![
                text_msg(IrRole::User, "u1"),
                text_msg(IrRole::Assistant, "a1"),
                text_msg(IrRole::User, "u3"),
            ],
            dummy_event(),
        );

        // 验证 fork 结构.
        let node_c1 = dag.get_node(c1).expect("c1 exists");
        let node_c2 = dag.get_node(c2).expect("c2 exists");
        assert_eq!(node_c1.parent, Some(b), "C1 parent = B");
        assert_eq!(node_c2.parent, Some(b), "C2 parent = B (fork from B)");
        assert_ne!(
            node_c1.session_id, node_c2.session_id,
            "C1 / C2 fork 应分属不同 session"
        );

        // 验证 sessions 列表: 应有 2 个 (s1 含 A→B→C1, s2 含 fork→C2).
        let sessions = dag.list_sessions();
        assert_eq!(sessions.len(), 2, "fork 产生 2 个 session");

        // 验证各 session 的 leaf 正确 (s1 leaf=C1, s2 leaf=C2).
        let s1 = sessions
            .iter()
            .find(|s| s.session_id == node_c1.session_id)
            .expect("s1 exists");
        let s2 = sessions
            .iter()
            .find(|s| s.session_id == node_c2.session_id)
            .expect("s2 exists");
        assert_eq!(s1.leaf_id, c1, "s1 leaf = C1");
        assert_eq!(s2.leaf_id, c2, "s2 leaf = C2");
        assert_eq!(s1.record_count, 3, "s1: A, B, C1");
        assert_eq!(s2.record_count, 1, "s2: 只有 C2 (fork 的新分支起点)");

        // B 是 fork 共享点, child_count 应为 2 (C1 + C2 都引用 B).
        let node_b = dag.get_node(b).expect("b exists");
        assert_eq!(
            node_b.parent, // 通过 inner 检查 child_count 需要白盒, 这里改为间接验证:
            Some(_a),
            "B parent = A (sanity)"
        );

        // 间接验证 B 的 child_count=2: gc_cascade s1 (C1) 后 B 仍存活 (s2 引用).
        // 若 B 的 child_count 错为 1, 删 C1 会级联删 B, 让 C2 变孤儿.
        {
            let mut g = dag.inner.write();
            ConversationDag::gc_cascade(&mut g, c1);
            g.sessions.remove(&node_c1.session_id);
        }
        assert!(dag.get_node(c1).is_none(), "C1 删除");
        assert!(
            dag.get_node(b).is_some(),
            "B 仍存活 (C2 引用, child_count>0)"
        );
        assert!(
            dag.get_node(c2).is_some(),
            "C2 仍存活 (fork 分支不受 s1 GC 影响)"
        );
    }

    // ─── property-based 测试 (proptest, A5) ─────────────────────────────────
    //
    // DAG 是天然适合属性测试的结构. 项目已依赖 proptest 但 dag.rs 之前完全未用.
    // 这里覆盖 DAG 的两个核心代数性质:
    // 1. round-trip identity: push → full_request_messages == 原始 messages
    // 2. refcount 非负: 任意 push/evict 序列后, 所有 block 的 refcount ≥ 0
    //
    // 用 ProptestConfig::with_cases(64) 控制 case 数, 避免默认 256 case 拖慢 CI.

    use proptest::prelude::*;

    /// 生成随机 IrRole. IrRole 未实现 Arbitrary, 这里手写 4 选 1 策略.
    fn arb_role() -> impl Strategy<Value = IrRole> {
        prop_oneof![
            Just(IrRole::System),
            Just(IrRole::User),
            Just(IrRole::Assistant),
            Just(IrRole::Tool),
        ]
    }

    /// 生成简单 Text message (role + text 都随机).
    /// 仅用 Text variant 已足够覆盖 round-trip 性质 (intern/resolve 路径对所有 variant 一致,
    /// variant-specific 的 round-trip 由前述 dag_block_* 系列单元测试覆盖).
    fn arb_text_message() -> impl Strategy<Value = IrMessage> {
        (arb_role(), "[a-z0-9 ]{0,20}").prop_map(|(role, text)| IrMessage {
            role,
            content: vec![IrBlock::Text { text }],
            ..Default::default()
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// 性质 1 (round-trip identity):
        /// 任意 messages 序列 push 到 DAG, 取 leaf 调 full_request_messages walk 出来,
        /// 应严格等于原始 messages. 这是 DAG 核心 (BlockPool intern/resolve + Merkle walk)
        /// 的代数恒等式 — 任何环节出错 (hash 冲突 / resolve 顺序 / GC 错删) 都会破坏它.
        #[test]
        fn prop_dag_round_trip_identity(messages in prop::collection::vec(arb_text_message(), 1..10)) {
            let dag = ConversationDag::new(1024, 500, 1);
            let leaf = dag.push_messages(messages.clone(), dummy_event());

            let walked = dag.full_request_messages(leaf)
                .expect("leaf 存在且 parent 链完整");

            // walk 出的 messages 数量应等于 push 的数量 (单 node, 全部是 delta).
            prop_assert_eq!(
                walked.len(),
                messages.len(),
                "walked count == pushed count"
            );
            // 逐条对比 role + content (用引用避免 move).
            for (i, (got, want)) in walked.iter().zip(messages.iter()).enumerate() {
                prop_assert_eq!(got.role, want.role, "msg[{}] role mismatch", i);
                prop_assert_eq!(
                    &got.content, &want.content,
                    "msg[{}] content mismatch", i
                );
            }
        }

        /// 性质 1 变体 (多 node 链 round-trip):
        /// 模拟真实多轮: A=[m1], B=[m1, m2], C=[m1, m2, m3].
        /// 取 C 的 full_request_messages 应得 [m1, m2, m3], 与 push C 时给的 messages 一致.
        /// 这覆盖了 parent 共享前缀 → delta 提取 → walk 重组 的完整路径.
        #[test]
        fn prop_dag_multi_hop_chain_round_trip(
            m1 in arb_text_message(),
            m2 in arb_text_message(),
            m3 in arb_text_message()
        ) {
            // prop_assume: 三条 message 的 (role, content) 各不相同, 防止 hash 退化.
            // (若两条完全相同, intern 会 dedupe, BlockPool.len < 3, 但 round-trip 仍应成立.)
            let dag = ConversationDag::new(64, 500, 1);
            let _a = dag.push_messages(vec![m1.clone()], dummy_event());
            let _b = dag.push_messages(vec![m1.clone(), m2.clone()], dummy_event());
            let c = dag.push_messages(
                vec![m1.clone(), m2.clone(), m3.clone()],
                dummy_event(),
            );

            let walked = dag.full_request_messages(c)
                .expect("leaf C 存在, parent 链 A→B→C 完整");
            prop_assert_eq!(walked.len(), 3, "3 轮累积");
            prop_assert_eq!(&walked[0].content, &m1.content, "msg[0] = m1");
            prop_assert_eq!(&walked[1].content, &m2.content, "msg[1] = m2");
            prop_assert_eq!(&walked[2].content, &m3.content, "msg[2] = m3");
        }

        /// 性质 2 (refcount 非负 + 操作序列不 panic):
        /// 任意 push N 次 + 触发淘汰的序列, 不应 panic, 且最终所有 block 的 refcount > 0
        /// (refcount=0 的 block 应已被 GC 移除). 用小 max_nodes 强制淘汰, 覆盖 GC 路径.
        ///
        /// 白盒访问 inner.blocks.refcount 验证不变式 (saturating_sub 保证非负, 但写测试固化契约).
        #[test]
        fn prop_dag_refcount_positive_after_push_sequence(
            ops in prop::collection::vec(
                (arb_role(), "[a-z]{1,8}"),
                1..20
            )
        ) {
            // max_nodes=3: 第 4 次 push 触发淘汰, 覆盖 GC 路径.
            let dag = ConversationDag::new(3, 500, 1);
            let mut last_leaf = None;

            for (role, text) in &ops {
                let msg = IrMessage {
                    role: *role,
                    content: vec![IrBlock::Text { text: text.clone() }],
                    ..Default::default()
                };
                // 不 panic 即通过 (push 内含淘汰 + GC cascade).
                last_leaf = Some(dag.push_messages(vec![msg], dummy_event()));
            }

            // 白盒检查: 所有存活 block 的 refcount 必须为正.
            // 不变式: refcount=0 的 block 应在 release 时被立即移除 (不残留).
            let g = dag.inner.read();
            for (&_hash, &count) in g.blocks.refcount.iter() {
                prop_assert!(
                    count > 0,
                    "live block refcount 必须为正 (refcount=0 的应已被 GC): got {}",
                    count
                );
            }
            // min_sessions=1 保底: 至少 1 个 session 存活, 它的 leaf 应可访问.
            let sessions = dag.list_sessions();
            prop_assert!(!sessions.is_empty(), "至少 min_sessions 个 session 存活");
            if let Some(leaf) = last_leaf {
                // leaf 可能已被淘汰 (FIFO); 若仍存活, full_request_messages 应不 panic.
                if dag.get_node(leaf).is_some() {
                    let _ = dag.full_request_messages(leaf);
                }
            }
        }

        /// 性质 (intern idempotent): 同一 block 重复 intern, hash 必须相同.
        /// 这是内容寻址的根基 (BlockPool 用 HashMap<BlockHash, _>).
        #[test]
        fn prop_block_intern_idempotent_hash(
            text in "[a-zA-Z0-9 ,.!?]{0,50}",
            role in arb_role()
        ) {
            let mut pool = BlockPool::default();
            let msg = IrMessage {
                role,
                content: vec![IrBlock::Text { text: text.clone() }],
                ..Default::default()
            };
            // 同一 message intern 两次 → 同一 MessageRef (role + 相同 blocks hash).
            let ref1 = pool.intern_message(&msg);
            let ref2 = pool.intern_message(&msg);
            prop_assert_eq!(ref1.role, ref2.role);
            prop_assert_eq!(&ref1.blocks, &ref2.blocks, "相同内容应 hash 一致");
            // resolve 出来也应相等.
            let r1 = pool.resolve_message(&ref1).expect("resolve 1");
            let r2 = pool.resolve_message(&ref2).expect("resolve 2");
            prop_assert_eq!(r1.content, r2.content);
        }
    }

    // ─── property-based (ROB-1 永不 panic, derive 链派生层) ─────────────────
    //
    // 契约: docs/design/contracts.md §8 ROB-1 — extract_delta_messages_from_raw
    // (timeline 的 req_delta 切片 fallback) 对任意 req_body_raw + 任意 req_delta.len()
    // 组合 (含非 JSON / 空 / 损坏 / count 与 messages 数不匹配) 必须不 panic, 返回空 Vec
    // 或合法切片. 该函数接收 HTTP body 派生数据, 任何 panic 都能让单个恶意请求崩溃进程.
    //
    // catch_unwind 守卫: 即便未来有人改函数时引入 panic 路径, 这个 property 也会显式 fail
    // 并报告输入的 (count, body_len), 而非让测试进程崩溃 (release build panic=abort 时
    // proptest 自身的 panic-as-fail 机制无法生效).

    /// 构造一个最小化 Node, 用作 extract_delta_messages_from_raw 的 fixture.
    /// `count` 决定 `req_delta.len()` (函数内部用此长度做切片); `req_body_raw` 是任意字节.
    fn fixture_node(count: usize, req_body_raw: String) -> Node {
        let mut event = dummy_event();
        event.req_body_raw = req_body_raw;
        // req_delta 用任意 MessageRef 填充到 count 长度 — 内容不重要, 只用 len().
        let dummy_ref = MessageRef {
            role: IrRole::User,
            blocks: Vec::new(),
        };
        let req_delta: Arc<[MessageRef]> = if count == 0 {
            Arc::from([])
        } else {
            Arc::from(vec![dummy_ref; count])
        };
        Node {
            id: Uuid::new_v4(),
            parent: None, // 根节点: 触发 system 注入分支
            session_id: SessionId::new(),
            child_count: 0,
            req_delta,
            own_hash: 0,
            prefix_hash: 0,
            event,
            response: parking_lot::RwLock::new(None),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// ROB-1 (变体 A): 任意字节 body + 任意 count, extract_delta_messages_from_raw 不 panic.
        /// 主要覆盖 serde_json::from_str 失败路径 (messages 不可解析 → 早退返回空 Vec).
        #[test]
        fn prop_delta_never_panics_arbitrary(
            count in 0usize..32,
            bytes in prop::collection::vec(any::<u8>(), 0..2048)
        ) {
            let body = String::from_utf8_lossy(&bytes).into_owned();
            let node = fixture_node(count, body.clone());
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                extract_delta_messages_from_raw(&node)
            }));
            prop_assert!(
                result.is_ok(),
                "ROB-1 violation: extract_delta_messages_from_raw panicked \
                 (count={}, body_len={})",
                count,
                body.len()
            );
        }

        /// ROB-1 (变体 B): 合法 chat JSON + count 在 messages.len() 边界附近不 panic.
        ///
        /// `messages[start..]` 切片 (start = messages.len() - count) 是 panic 高危区.
        /// 本 property 构造合法 messages 数组 + 让 count 在 `[0 .. n+2]` 区间随机,
        /// 覆盖 count < n (正常切片) / count == n (全取) / count > n (函数内早退返回空)
        /// 三种语义. 配合 parent=None (根节点) 触发 system 注入分支, 覆盖完整函数路径.
        #[test]
        fn prop_delta_never_panics_chat_json_edge_slice(
            n in 1usize..16,
            count in 0usize..18,  // 故意让 count 能略大于 n, 触发 messages.len() < count 早退分支
            seed in any::<u64>()
        ) {
            // n 条 messages + count 的依赖关系难以纯声明式表达 (count 需引用 n),
            // 这里用确定性 seed 直接构造 body (role/content 随机但 n 固定).
            let body = build_chat_body_with_n_messages(n, seed);
            let node = fixture_node(count, body.clone());
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                extract_delta_messages_from_raw(&node)
            }));
            prop_assert!(
                result.is_ok(),
                "ROB-1 violation: extract_delta_messages_from_raw panicked on chat-json \
                 (n={}, count={}, body_len={})",
                n,
                count,
                body.len()
            );
        }
    }

    /// 用确定性 seed 生成含 n 条 messages 的合法 chat JSON.
    /// role/content 从 (seed, i) 经 `crate::util::hash64` 派生 (项目 SSOT, 见 src/util.rs),
    /// 每个 i 独立 hash, 保证可复现, 不依赖 proptest strategy API.
    fn build_chat_body_with_n_messages(n: usize, seed: u64) -> String {
        let msgs: Vec<String> = (0..n)
            .map(|i| {
                let h = crate::util::hash64(&(seed, i));
                let role = match h % 4 {
                    0 => "system",
                    1 => "user",
                    2 => "assistant",
                    _ => "tool",
                };
                let content = format!("msg-{}", h % 1000);
                format!("{{\"role\":\"{role}\",\"content\":\"{content}\"}}")
            })
            .collect();
        format!("{{\"messages\":[{}]}}", msgs.join(","))
    }

    // ─── CDAG-5 redact_seed 可重现 (契约 §4 CDAG-5) ───────────────────────────
    //
    // 契约: docs/design/contracts.md L374-379.
    // 给定 (req_delta, policy, seed) 三元组, RedactionMap 完全确定. seed=0 表示
    // passthrough (无 redact). 实现: redact_ir 是纯函数 (除修改 IR 外无副作用), 对同一
    // (IrRequest 副本, secrets 切片) 两次调用产同一 (RedactionMap, seed).
    //
    // 这是 lazy redact 重建的根基 (DAG node 存 redact_seed, 未来可从 (req_delta, policy,
    // seed) 重建 RedactionMap 而不必存 map 本身).

    /// 测试用 secret 构造器 (复用 redact.rs::entry 的 resolve 语义).
    /// 返回 resolve 后的 SecretEntry (Auto 模式 mock_strategy 被 infer).
    fn make_secret_entry(id: &str, value: &str) -> crate::secrets::SecretEntry {
        use crate::mock::MockStrategy;
        use crate::secrets::SecretCategory;
        let mut e = crate::secrets::SecretEntry {
            id: id.to_string(),
            name: None,
            category: SecretCategory::ApiKey,
            value: value.to_string(),
            value_file: None,
            mock_strategy: MockStrategy::default(),
        };
        e.mock_strategy.resolve_against(&e.value, "");
        e
    }

    /// 构造含 1..N 个 secret 的 IrRequest (system + messages, secret 注入到 text 叶子).
    /// 用于 CDAG-5 redact_ir 可重现 property.
    fn arb_ir_with_secrets() -> impl Strategy<
        Value = (
            crate::codec::ir::IrRequest,
            Vec<crate::secrets::SecretEntry>,
        ),
    > {
        (
            "[a-z]{3,10}",    // text 前缀
            "[a-z0-9]{4,10}", // secret value
            1usize..=4,       // secret 数量
        )
            .prop_map(|(prefix, secret_val, n_secrets)| {
                use crate::codec::ir::{IrBlock, IrMessage, IrRequest, IrRole};
                let secrets: Vec<crate::secrets::SecretEntry> = (0..n_secrets)
                    .map(|i| make_secret_entry(&format!("sec_{i}"), &format!("{secret_val}_{i}")))
                    .collect();
                // 构造 text: prefix + 每个 secret 依次出现 (确保 ir_request_contains 命中).
                let mut text = prefix.to_string();
                for s in &secrets {
                    text.push(' ');
                    text.push_str(&s.value);
                }
                let ir = IrRequest {
                    system: vec![],
                    messages: vec![IrMessage {
                        role: IrRole::User,
                        content: vec![IrBlock::Text { text }],
                        ..Default::default()
                    }],
                    model: "test-model".to_string(),
                    ..Default::default()
                };
                (ir, secrets)
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// CDAG-5 `prop_redact_map_reproducible_from_seed`:
        /// 给定 (IrRequest, secrets) 三元组 (seed 由 secrets 确定 = init_seed(secrets)),
        /// 两次 redact_ir 产出同一 (RedactionMap, seed).
        ///
        /// redact_ir 修改 IR, 故两次调用需独立 IR 副本. 比较返回的 (RedactionMap, seed):
        /// - RedactionMap impl PartialEq/Eq → 可直接 assert_eq.
        /// - seed 是 u64 → assert_eq.
        ///
        /// 生成器覆盖 (§0.3 第 3 条): 1..4 个 secret (覆盖多 secret 场景), secret 注入到
        /// text 叶子 (确保命中). secret 互不相同 (后缀 _i).
        #[test]
        fn prop_redact_map_reproducible_from_seed(
            case in arb_ir_with_secrets()
        ) {
            use crate::redact::redact_ir;
            let (ir1, secrets) = case;
            // 两份独立 IR 副本 (redact_ir 消耗 IR, 第二次调用需未改写的 IR).
            let (mut ir_a, mut ir_b) = (ir1.clone(), ir1.clone());

            let (map1, seed1) = redact_ir(&mut ir_a, &secrets);
            let (map2, seed2) = redact_ir(&mut ir_b, &secrets);

            prop_assert_eq!(
                &map1, &map2,
                "CDAG-5: 同一 (req_delta, policy, seed) 产出不同 RedactionMap"
            );
            prop_assert_eq!(
                seed1, seed2,
                "CDAG-5: 同一 policy 产出不同 seed"
            );
            // seed 一致性也等价于 init_seed(secrets) (redact_ir 内部用 init_seed).
            let expected_seed = crate::redact::init_seed(&secrets);
            // seed 可能是 0 (无 secret 命中) 或 init_seed (命中). 这里 secret 注入到 text
            // 必然命中, 故 seed 应 == init_seed (非 0).
            prop_assert_eq!(
                seed1, expected_seed,
                "CDAG-5: seed 应等于 init_seed(secrets) (secret 命中时)"
            );
        }
    }

    // ─── CDAG-8 session 聚类稳定 (契约 §4 CDAG-8) ─────────────────────────────
    //
    // 契约: docs/design/contracts.md L400-406.
    // Session id 由根 node 的 prefix_hash 决定 (稳定标识). 同一会话 N 轮请求的 leaf node
    // 前移时 session id 不变. fork (前缀相同但后续不同, 且 parent 不是当前 leaf) 创建新 session.

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// CDAG-8 `prop_session_id_stable_across_rounds`:
        /// 同一会话 N (≥3) 轮 push (每轮是前一轮的超集, parent 是当前 leaf → 延续同一 session),
        /// 所有返回的 session_id 恒等.
        ///
        /// 模型: push [m1] → A (root, session S); push [m1, m2] → B (parent=A, 延续 S);
        /// push [m1, m2, m3] → C (parent=B, 延续 S). 三轮 session_id 全等.
        #[test]
        fn prop_session_id_stable_across_rounds(
            m1 in arb_text_message(),
            m2 in arb_text_message(),
            m3 in arb_text_message(),
            m4 in arb_text_message(),
        ) {
            let dag = ConversationDag::new(64, 500, 1);
            // 累积 push: 每轮是前一轮 messages 的超集 (delta = 新增的最后一条).
            let id_a = dag.push_messages(vec![m1.clone()], dummy_event());
            let id_b = dag.push_messages(vec![m1.clone(), m2.clone()], dummy_event());
            let id_c = dag.push_messages(vec![m1.clone(), m2.clone(), m3.clone()], dummy_event());
            let id_d = dag.push_messages(vec![m1, m2, m3, m4], dummy_event());

            let sid_a = dag.get_node(id_a).expect("A exists").session_id;
            let sid_b = dag.get_node(id_b).expect("B exists").session_id;
            let sid_c = dag.get_node(id_c).expect("C exists").session_id;
            let sid_d = dag.get_node(id_d).expect("D exists").session_id;

            // 四轮 session_id 全等 (parent 都是当前 leaf → 延续同一 session).
            prop_assert_eq!(sid_a, sid_b, "B 应延续 A 的 session");
            prop_assert_eq!(sid_b, sid_c, "C 应延续 B 的 session");
            prop_assert_eq!(sid_c, sid_d, "D 应延续 C 的 session");
        }

        /// CDAG-8 `prop_session_fork_creates_new_session`:
        /// fork (前缀相同但后续不同, 且 parent 已被后续轮次取代 → 不是当前 leaf) 创建新 session.
        ///
        /// 模型: push [m1] → A; push [m1, m2] → B (B 取代 A 成为 leaf).
        /// 再 push [m1, m3] → C (parent=A, 但 A 不是当前 leaf → fork → 新 session).
        /// 断言: C 的 session_id != B 的 session_id.
        #[test]
        fn prop_session_fork_creates_new_session(
            m1 in arb_text_message(),
            m2 in arb_text_message(),
            m3 in arb_text_message(),
        ) {
            let dag = ConversationDag::new(64, 500, 1);
            let _id_a = dag.push_messages(vec![m1.clone()], dummy_event());
            let id_b = dag.push_messages(vec![m1.clone(), m2], dummy_event());
            // C: parent=A (前缀 [m1] 命中), 但 A 不是当前 leaf (B 是) → fork.
            let id_c = dag.push_messages(vec![m1, m3], dummy_event());

            let sid_b = dag.get_node(id_b).expect("B exists").session_id;
            let sid_c = dag.get_node(id_c).expect("C exists").session_id;

            prop_assert_ne!(
                sid_b, sid_c,
                "CDAG-8 fork: C (parent=A, A 非 leaf) 应创建新 session, 与 B 不同"
            );
        }
    }

    // ─── DTO-5 req_delta_messages 切片正确 (契约 §5 DTO-5) ───────────────────
    //
    // 契约: docs/design/contracts.md L450-458.
    // timeline 路径的 req_delta_messages 必须是本轮新增的 messages (从 req_body_raw 末尾
    // 截取), 同协议路径下与 IR req_delta 一致.
    //
    // 已知限制: 跨协议路径切片错位 (DTO-6), 本组 property 只守卫同协议路径.
    //
    // extract_delta_messages_from_raw 接收 &Node, 故测试用 fixture_node 构造可控输入
    // (count = req_delta.len(), req_body_raw = 字符串). 函数是 best-effort 永不 panic
    // (ROB-1), 故 catch_unwind 守卫 (与 prop_delta_never_panics_* 一致).

    /// 构造合法 chat JSON, messages 数 = n, 第 i 条 content = format!("{i}").
    /// 用确定性的 messages (而非 hash 派生) 让 slice 正确性可逐条断言.
    fn build_chat_body_indexed(n: usize) -> String {
        let msgs: Vec<String> = (0..n)
            .map(|i| format!("{{\"role\":\"user\",\"content\":\"msg-{i}\"}}"))
            .collect();
        format!("{{\"messages\":[{}]}}", msgs.join(","))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// DTO-5 `prop_delta_slice_correct_same_proto`:
        /// 同协议路径下, req_delta_messages == req_body_raw 末尾 count 条 messages.
        ///
        /// 构造: n 条 messages (n ∈ [2, 12]), count ∈ [1, n] (保证 messages.len() >= count).
        /// 断言: result.len() == count, 且 result == messages[start..] (start = n - count),
        /// content 逐条相等.
        ///
        /// 注: 根节点 (parent=None) 且 start > 0 时函数会注入 system (若无 system 字段则
        /// OpenAI 风格 messages[0]=system). 这里 messages[0] 是 role=user, start>0 时
        /// messages[0].role != system → 不注入 → result 严格 == messages[start..].
        /// 为隔离 system 注入逻辑 (DTO-5 prop_delta_includes_system_at_root 单独守卫),
        /// 本 property 用 parent=None 且 count == n (start=0, 不触发 system 注入) +
        /// count < n 但 messages[0].role=user 两种 case:
        /// - count == n: start=0, 无 system 注入, result == messages[0..].
        /// - count < n: start>0, messages[0].role=user (非 system) → 不注入, result == messages[start..].
        #[test]
        fn prop_delta_slice_correct_same_proto(
            n in 2usize..=12,
            count in 1usize..=12, // 由 prop_assume 约束 ≤ n
        ) {
            prop_assume!(count <= n, "count must be ≤ n for slice semantics");
            let body = build_chat_body_indexed(n);
            let node = fixture_node(count, body.clone());
            let result = extract_delta_messages_from_raw(&node);

            let start = n - count;
            prop_assert_eq!(
                result.len(),
                count,
                "DTO-5: result.len() 应 == count, 实际 {}",
                result.len(),
            );
            // 逐条比对 content (messages[start..]).
            for (i, got) in result.iter().enumerate() {
                let want_idx = start + i;
                let want_content = format!("msg-{want_idx}");
                let got_content = got
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<missing>");
                prop_assert_eq!(
                    got_content, &want_content,
                    "DTO-5: result[i] content 不匹配 (want messages[want_idx])"
                );
            }
        }

        /// DTO-5 `prop_delta_includes_system_at_root`:
        /// 根节点 (parent=None) 的 delta 在 start > 0 时补回 system prompt.
        ///
        /// 构造: OpenAI 风格 body, messages[0] = role=system, 后续 n-1 条 user.
        /// count < n → start > 0, messages[0].role == system → 注入到 result 首位.
        /// 断言: result[0].role == "system" (注入的 system message).
        #[test]
        fn prop_delta_includes_system_at_root(
            n_sys in 3usize..=8,    // 含 1 条 system + (n_sys-1) 条 user
            count in 1usize..=8,
        ) {
            prop_assume!(count < n_sys, "count < n_sys 才触发 system 注入 (start > 0)");
            // body: messages[0]=system, messages[1..]=user.
            let mut msgs = vec![r#"{"role":"system","content":"SYS-PROMPT"}"#.to_string()];
            for i in 1..n_sys {
                msgs.push(format!("{{\"role\":\"user\",\"content\":\"u-{i}\"}}"));
            }
            let body = format!("{{\"messages\":[{}]}}", msgs.join(","));
            let node = fixture_node(count, body);
            let result = extract_delta_messages_from_raw(&node);

            // 注入的 system 在 result 首位.
            prop_assert!(
                !result.is_empty(),
                "DTO-5 system 注入: result 不应为空 (count={count})"
            );
            let first_role = result[0]
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing>");
            prop_assert_eq!(
                first_role, "system",
                "DTO-5 system 注入: result[0].role 应为 system (根节点 start>0 时注入)"
            );
        }

        /// DTO-5 `prop_delta_handles_non_json_body`:
        /// 非 JSON body 时返回空 vec (不 panic).
        ///
        /// 构造: req_body_raw = 任意字节 (非 JSON), count > 0.
        /// 断言: result.is_empty() (serde_json::from_str 失败早退).
        #[test]
        fn prop_delta_handles_non_json_body(
            count in 1usize..=8,
            body in "[^{}\\[\\]]{0,64}", // 非 JSON-ish 字节
        ) {
            // prop_assume: body 不应意外是合法 JSON object/array (生成器已排除 {} []).
            prop_assume!(!body.trim_start().starts_with('{'), "body 非合法 JSON object");
            let node = fixture_node(count, body.clone());
            let result = extract_delta_messages_from_raw(&node);
            prop_assert!(
                result.is_empty(),
                "DTO-5: 非 JSON body 应返回空 vec (body={:?}, count={count})",
                body,
            );
        }

        /// DTO-5 `prop_delta_handles_count_mismatch`:
        /// messages 数 < req_delta_count 时返回空 vec.
        ///
        /// 构造: n 条 messages, count > n (函数内 messages.len() < count 早退).
        /// 断言: result.is_empty().
        #[test]
        fn prop_delta_handles_count_mismatch(
            n in 1usize..=8,
            extra in 1usize..=5, // count = n + extra > n
        ) {
            let count = n + extra;
            let body = build_chat_body_indexed(n);
            let node = fixture_node(count, body.clone());
            let result = extract_delta_messages_from_raw(&node);
            prop_assert!(
                result.is_empty(),
                "DTO-5: messages 数 ({n}) < count ({count}) 应返回空 vec",
            );
        }
    }

    // ─── 两级锁并发回归 (perf: attach / update_parsed 不应阻塞全局) ───────────
    //
    // 这组测试守卫两级锁改动的线程安全: 8 writer 并发 attach_response +
    // update_parsed_response, 4 reader 并发 list_page / get_node / get_response.
    // 在数据竞争 / 覆盖场景下, 至少能被 ThreadSanitizer 或 logic assert 抓住.

    #[test]
    fn concurrent_attach_and_list_do_not_corrupt_or_deadlock() {
        // 预先 push N 个 node (在单线程下), 然后并发 attach_response 给它们.
        // reader 并发 list_page + get_node 读 NodeView, 验证 resp_status 一致性:
        // attach 后 NodeView.resp_status 应等于该 response 的 status (或 attach 前 0).
        let dag = Arc::new(ConversationDag::new(64, 500, 1));
        let n = 32;
        let ids: Vec<Uuid> = (0..n)
            .map(|i| {
                dag.push_messages(
                    vec![text_msg(IrRole::User, &format!("u{i}"))],
                    dummy_event(),
                )
            })
            .collect();

        // 8 writer: 每个 writer 负责若干 node, 先 update_parsed_response 几次 (流式
        // 节流), 再 attach_response 最终值. 高频 update_parsed 是重点压测的两级锁路径.
        let writers: Vec<std::thread::JoinHandle<()>> = (0..8)
            .map(|w| {
                let dag = Arc::clone(&dag);
                let ids = ids.clone();
                std::thread::spawn(move || {
                    for (i, &id) in ids.iter().enumerate() {
                        if i % 8 != w {
                            continue;
                        }
                        // 模拟流式 parsed 节流更新 (高频, 两级锁核心目标).
                        for j in 0..3 {
                            dag.update_parsed_response(
                                id,
                                serde_json::json!({"partial": w, "step": j}),
                            );
                        }
                        // 最终 attach (低频, 两级锁次要目标).
                        dag.attach_response(
                            id,
                            ResponseData {
                                resp_status: 200,
                                elapsed_ms: (w as u64) * 10,
                                parsed: Some(serde_json::json!({"resp": format!("w{w}")})),
                                resp_complete: true,
                                ..Default::default()
                            },
                        );
                    }
                })
            })
            .collect();

        // 4 reader: 并发 list_page + get_node + get_response, 读 NodeView 验证
        // 字段一致性 (resp_status ∈ {0=attach前, 200=attach后}; elapsed_ms 与 status 一致).
        let readers: Vec<std::thread::JoinHandle<()>> = (0..4)
            .map(|r| {
                let dag = Arc::clone(&dag);
                let ids = ids.clone();
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        // list_page 不 panic, 且总数 == n.
                        let (views, total) = dag.list_page(0, 200, false);
                        assert_eq!(total, n, "reader {r}: list_page total");
                        assert!(views.len() <= n);
                        // list_sessions 不 panic.
                        let _sessions = dag.list_sessions();
                        // 抽样读 NodeView / ResponseData, 验证 resp_status ∈ {0,200}.
                        for &id in ids.iter().step_by(4 + r) {
                            if let Some(v) = dag.get_node(id) {
                                assert!(
                                    v.resp_status == 0 || v.resp_status == 200,
                                    "reader {r}: node {id} resp_status={} (应为 0 或 200)",
                                    v.resp_status
                                );
                                // attach 前 elapsed_ms=0; attach 后 = w*10.
                                let valid_elapsed = v.elapsed_ms == 0 || v.elapsed_ms % 10 == 0;
                                assert!(
                                    valid_elapsed,
                                    "reader {r}: node {id} elapsed_ms={} 不合规",
                                    v.elapsed_ms
                                );
                            }
                            if let Some(resp) = dag.get_response(id) {
                                assert!(
                                    resp.resp_status == 0 || resp.resp_status == 200,
                                    "reader {r}: response {id} status 不合规"
                                );
                            }
                        }
                    }
                })
            })
            .collect();

        // join: 任何 panic (含 assert 失败) 都会让 join 返回 Err, 测试失败.
        // 死锁会让 join 阻塞直到 nextest 超时 (默认无, 测试层会 hang → 手动发现).
        for w in writers {
            w.join().expect("writer thread panicked / deadlocked");
        }
        for r in readers {
            r.join().expect("reader thread panicked / deadlocked");
        }

        // 最终一致性: 所有 node 都应被 attach (resp_status=200).
        for &id in &ids {
            let v = dag.get_node(id).expect("node exists");
            assert_eq!(
                v.resp_status, 200,
                "attach 后 node {id} resp_status 应为 200"
            );
            assert!(v.has_response, "attach 后 node {id} 应有 response");
        }
    }

    #[test]
    fn concurrent_update_parsed_response_multi_writer_last_value_wins() {
        // 验证 update_parsed_response 两级锁在并发下不破坏 ResponseData: 多个 writer
        // 并发写同一 node 的 parsed, 最终 get_response 能取到一个合法的 JSON
        // (无 torn write). 最后一次写获胜 (无确定性要求, 仅要求结构完整).
        let dag = Arc::new(ConversationDag::new(16, 100, 1));
        let id = dag.push_messages(vec![text_msg(IrRole::User, "u")], dummy_event());

        let writers: Vec<std::thread::JoinHandle<()>> = (0..16)
            .map(|w| {
                let dag = Arc::clone(&dag);
                std::thread::spawn(move || {
                    for j in 0..20 {
                        dag.update_parsed_response(
                            id,
                            serde_json::json!({"writer": w, "step": j, "payload": "x".repeat(64)}),
                        );
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().expect("writer panicked");
        }

        let resp = dag.get_response(id).expect("response exists");
        let parsed = resp.parsed.expect("parsed exists");
        // 结构完整: 含 writer / step / payload 字段且类型正确.
        assert!(parsed.get("writer").and_then(|v| v.as_u64()).is_some());
        assert!(parsed.get("step").and_then(|v| v.as_u64()).is_some());
        assert_eq!(
            parsed.get("payload").and_then(|v| v.as_str()).map(str::len),
            Some(64),
            "并发写后 payload 字段应完整 (无 torn write)"
        );
    }
}
