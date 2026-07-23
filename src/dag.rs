//! Conversation DAG: 内容寻址的对话历史存储.
//!
//! # 设计目标
//!
//! 把扁平的 `VecDeque<ForwardRecord>` 升级为内容寻址的对话 DAG, 解决两个问题:
//! 1. **存储冗余**: 同一会话的 N 条请求 messages 高度重叠 (每次带完整历史).
//!    内容寻址让相同 IrBlock 跨节点只存一份.
//! 2. **会话识别**: 通过 Merkle prefix hash 自动识别前缀关系, 让 WebUI 折叠同会话记录.
//!
//! # 核心概念
//!
//! - **Node**: 一次 API 调用, 持有该次调用产出的 messages (request delta + response).
//!   `msgs` 最后一条恒为 response (assistant role), 其余是相对 parent 的 request 增量.
//! - **BlockPool**: 全局内容寻址的 IrBlock 池, 引用计数管理.
//! - **Merkle prefix hash**: 从根到本 node 的累积 hash, 用于 push 时 O(N) 找 parent.
//!
//! # 详尽设计见 `docs/design/conversation-dag.md`

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use uuid::Uuid;

use crate::codec::ir::{IrBlock, IrImageSource, IrMessage, IrRole, IrStopReason, IrUsage};
use crate::codec::Protocol as CodecProtocol;
use crate::redact::RedactionMap;

// ─── BlockHash ──────────────────────────────────────────────────────────────

/// IrBlock 内容的 hash. 用作 BlockPool 的 key.
///
/// 用 u64 (SipHash, Rust DefaultHasher) 而非 blake3: DAG 不跨进程, 同 Rust 版本内确定即可.
/// collision 概率 ~2^-64, 对 < 10^5 blocks 的 DAG 可忽略; 真发生会 panic (defense-in-depth).
pub type BlockHash = u64;

/// 计算单个 IrBlock 的内容 hash.
///
/// 不依赖 IrBlock 的 PartialEq (那需要 Clone 比较), 而是递归 hash 所有字段.
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
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.role.hash(&mut h);
        for b in &self.blocks {
            b.hash(&mut h);
        }
        h.finish()
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
    pub fn intern(&mut self, block: IrBlock) -> BlockHash {
        let h = hash_block(&block);
        let entry = self
            .blocks
            .entry(h)
            .or_insert_with(|| Arc::new(block.clone()));
        // collision check (仅 debug build; collision 概率 ~2^-64 对 < 10^5 blocks 可忽略,
        // release build 遇到 collision 会静默覆盖, 但概率低到可以接受).
        debug_assert!(
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

// ─── Node + CallEvent + ResponseMeta ───────────────────────────────────────

/// DAG 节点 = 一次 API 调用.
#[derive(Debug)]
pub struct Node {
    pub id: Uuid,
    /// 父节点 (前缀关系). None = 会话根或孤立节点 (无 messages 的请求).
    pub parent: Option<Uuid>,
    /// 客户端发出的 request 中, 相对 parent 的增量.
    ///
    /// 存储的是**真实内容** (含真实 secret, 即 OriginRecord 视角).
    /// 输出给 LLM / WebUI 时 apply redactMap 转为 SecureRecord (含 mock).
    ///
    /// **不含** LLM 返回的 response — response 独立存在 [`response`] 字段,
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
#[derive(Debug)]
pub struct CallEvent {
    pub created_at: DateTime<Utc>,
    pub elapsed_ms: u64,
    pub method: String,
    pub path: String,
    pub req_headers: Vec<(String, String)>,
    pub resp_status: u16,
    pub resp_headers: Vec<(String, String)>,
    /// 请求侧非 message 字段 (model / temperature / tools / system 等).
    pub req_envelope: serde_json::Value,
    pub ingress_protocol: Option<CodecProtocol>,
    /// redact 的随机性来源 (probe 后的最终值).
    /// - 0 = passthrough (无 secret 命中 / SecretTable 为空).
    /// - 非 0 = derive(policy, OriginRecord, seed) 可重建 redactMap.
    pub redact_seed: u64,
    /// redact 时使用的 policy 快照 (Arc COW 共享).
    /// redact_seed=0 时此字段可为 default (空 secrets).
    pub policy: Arc<PolicySnapshot>,
}

/// LLM 返回的 response 数据 (message content + 元数据).
///
/// 存储的是 LLM 原始返回 (含 mock, restore 前).
#[derive(Debug, Clone)]
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
    /// (mock, secret_id) 投影, WebUI 渲染 hit badge 用.
    /// 永不含真实 secret value.
    pub redactions: Vec<(String, String)>,
}

// ─── ConversationDag ───────────────────────────────────────────────────────

/// 内容寻址的对话 DAG.
///
/// 内部维护:
/// - `nodes`: id → Node 的 HashMap.
/// - `prefix_index`: Merkle prefix hash → nodes (fork 场景可能多个).
/// - `order`: FIFO push 顺序, 用于淘汰.
/// - `blocks`: 全局 block 池.
#[derive(Debug)]
pub struct ConversationDag {
    inner: Arc<RwLock<DagInner>>,
}

#[derive(Debug)]
struct DagInner {
    nodes: HashMap<Uuid, Node>,
    /// Merkle prefix hash → nodes (按 push 顺序, 末尾是最新的).
    prefix_index: HashMap<u64, Vec<Uuid>>,
    /// FIFO push 顺序, 用于淘汰最老节点.
    order: VecDeque<Uuid>,
    /// 最大节点数.
    max: usize,
    /// 全局 block 池 (内容寻址 + refcount).
    blocks: BlockPool,
}

/// push 时计算出的 node 定位结果.
#[derive(Debug, Clone)]
struct ParentLookup {
    parent: Option<Uuid>,
    /// msgs[..split_at] 是已有前缀 (在 DAG 中), msgs[split_at..] 是本 node 的 delta.
    split_at: usize,
}

impl Default for ConversationDag {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl ConversationDag {
    pub fn new(max: usize) -> Self {
        let max = max.max(1);
        Self {
            inner: Arc::new(RwLock::new(DagInner {
                nodes: HashMap::new(),
                prefix_index: HashMap::new(),
                order: VecDeque::with_capacity(max.min(128)),
                max,
                blocks: BlockPool::default(),
            })),
        }
    }

    /// 把一段 messages 推入 DAG.
    ///
    /// 自动:
    /// 1. intern 所有 block (refcount++).
    /// 2. 计算 Merkle prefix hash 序列, 找到最深匹配的 parent.
    /// 3. 提取 delta (相对 parent 的增量).
    /// 4. 创建 node, 入 HashMap + prefix_index + order.
    /// 5. FIFO 淘汰 (若超 max).
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

        // 4. 计算 own_hash + prefix_hash (只基于 req_delta, response 不参与).
        let parent_base = match lookup.parent {
            Some(pid) => g.nodes.get(&pid).expect("parent must exist").prefix_hash,
            None => 0,
        };
        let own_hash = Self::accumulate_hash(0, &delta_refs);
        let prefix_hash = Self::accumulate_hash(parent_base, &delta_refs);

        // 5. 创建 node (response 初始 None).
        let node_id = Uuid::new_v4();
        let node = Node {
            id: node_id,
            parent: lookup.parent,
            req_delta: delta_refs,
            own_hash,
            prefix_hash,
            event,
            response: RwLock::new(None),
        };

        // 6. 入 DAG 结构.
        g.nodes.insert(node_id, node);
        g.prefix_index.entry(prefix_hash).or_default().push(node_id);
        g.order.push_back(node_id);

        // 7. FIFO 淘汰.
        while g.order.len() > g.max {
            if let Some(evicted_id) = g.order.pop_front() {
                Self::evict_node(&mut g, evicted_id);
            }
        }

        node_id
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
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        parent.hash(&mut h);
        own.hash(&mut h);
        h.finish()
    }

    /// FIFO 淘汰一个 node: 释放 block refcount, 从结构中移除.
    fn evict_node(inner: &mut DagInner, node_id: Uuid) {
        let node = match inner.nodes.remove(&node_id) {
            Some(n) => n,
            None => return,
        };
        // 释放 req_delta 的 block refcount.
        for r in node.req_delta.iter() {
            inner.blocks.release_message(r);
        }
        // 释放 response 的 block refcount (若有).
        if let Some(resp) = node.response.read().as_ref() {
            if let Some(msg) = &resp.message {
                inner.blocks.release_message(msg);
            }
        }
        // 从 prefix_index 移除.
        if let Some(ids) = inner.prefix_index.get_mut(&node.prefix_hash) {
            ids.retain(|id| *id != node_id);
            if ids.is_empty() {
                inner.prefix_index.remove(&node.prefix_hash);
            }
        }
        // 注意: 若有其他 node 的 parent == node_id (fork 场景), 它们的 parent 指针会悬空.
        // MVP 不处理 fork tombstone; 当前业务模式是线性链, 淘汰顺序天然安全
        // (引用者永远先于被引用者被淘汰).
    }

    // ─── 读取 API ──────────────────────────────────────────────────────────

    /// walk parent 链, 收集完整的 request messages (从根到本 node).
    ///
    /// 只含 req_delta (客户端发出的 messages), 不含 response.
    /// response 是独立数据源, 用 [`get_response`] 单独获取.
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
        let node = g.nodes.get(&node_id)?;
        let has_response = node.response.read().is_some();
        Some(NodeView {
            id: node.id,
            parent: node.parent,
            req_delta_count: node.req_delta.len(),
            has_response,
            created_at: node.event.created_at,
            elapsed_ms: node.event.elapsed_ms,
            method: node.event.method.clone(),
            path: node.event.path.clone(),
            resp_status: node.event.resp_status,
            redact_seed: node.event.redact_seed,
        })
    }

    /// 取 node 的 response 数据 (clone).
    pub fn get_response(&self, node_id: Uuid) -> Option<ResponseData> {
        let g = self.inner.read();
        let node = g.nodes.get(&node_id)?;
        let resp = node.response.read().clone();
        resp
    }

    /// attach response 到 node.
    ///
    /// TODO(perf): 当前持有全局 write lock 更新单个 node, 高并发下可能成为瓶颈.
    /// 后续接入时可改为 read lock + node.response.write() 两级锁.
    pub fn attach_response(&self, node_id: Uuid, response: ResponseData) {
        let mut g = self.inner.write();
        let Some(node) = g.nodes.get_mut(&node_id) else {
            tracing::warn!(%node_id, "attach_response: node not found (evicted?)");
            return;
        };
        *node.response.write() = Some(response);
    }

    /// 按 FIFO 顺序的倒序列出 node id (newest first), 供 WebUI list.
    pub fn list_node_ids_newest_first(&self) -> Vec<Uuid> {
        let g = self.inner.read();
        g.order.iter().rev().copied().collect()
    }

    /// 当前 node 总数.
    pub fn node_count(&self) -> usize {
        let g = self.inner.read();
        g.nodes.len()
    }
}

/// Node 的轻量只读视图 (供 list / 元数据查询).
///
/// 不含 messages body (避免 clone 大量数据).
#[derive(Debug, Clone)]
pub struct NodeView {
    pub id: Uuid,
    pub parent: Option<Uuid>,
    pub req_delta_count: usize,
    pub has_response: bool,
    pub created_at: DateTime<Utc>,
    pub elapsed_ms: u64,
    pub method: String,
    pub path: String,
    pub resp_status: u16,
    pub redact_seed: u64,
}

// ─── redactMap 派生 ────────────────────────────────────────────────────────

/// 给定 (policy, OriginRecord messages, seed), 派生 redactMap.
///
/// 这是 lazy redact 的核心纯函数: node 不存 redactMap, 只存 seed;
/// 读取时调用此函数重建.
///
/// seed=0 表示 passthrough, 返回空 map.
///
/// # 安全警示 (后续接入时必须处理)
///
/// 此函数当前只把 `origin_messages` 填入临时 IrRequest 的 `messages` 字段,
/// **不扫描** `system` / `tools` / `stop` / `user` / `extra` 字段. 但 [`crate::redact::redact_ir`]
/// 的扫描范围包括这些字段.
///
/// **风险**: 若某个 secret 只出现在 system prompt 或 tools 定义中 (不在 messages 中),
/// 此函数重建的 redactMap 不含该 secret 的映射. 用这个 redactMap apply 到 OriginRecord 时,
/// system/tools 中的真实 secret 不会被替换为 mock → 泄漏到 WebUI.
///
/// 后续 PR 接入 WebUI 展示时, 必须从 `CallEvent.req_envelope` 重建完整 IrRequest
/// (含 system/tools/envelope), 确保 redact 扫描范围与原始 push 时一致.
pub fn derive_redact_map(
    policy: &PolicySnapshot,
    origin_messages: &[IrMessage],
    seed: u64,
) -> RedactionMap {
    if seed == 0 || policy.secrets.is_empty() {
        return RedactionMap::default();
    }
    // 构造临时 IrRequest 跑 redact_ir. 当前只填 messages (见上方安全警示).
    let mut ir = crate::codec::ir::IrRequest {
        messages: origin_messages.to_vec(),
        ..Default::default()
    };
    crate::redact::redact_ir(&mut ir, &policy.secrets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::ir::{IrBlock, IrMessage, IrRole};

    fn text_msg(role: IrRole, text: &str) -> IrMessage {
        IrMessage {
            role,
            content: vec![IrBlock::Text {
                text: text.to_string(),
            }],
        }
    }

    fn dummy_event() -> CallEvent {
        CallEvent {
            created_at: Utc::now(),
            elapsed_ms: 0,
            method: "POST".to_string(),
            path: "/o/test/v1/chat".to_string(),
            req_headers: vec![],
            resp_status: 0,
            resp_headers: vec![],
            req_envelope: serde_json::json!({}),
            ingress_protocol: None,
            redact_seed: 0,
            policy: Arc::new(PolicySnapshot::default()),
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

    // ─── ConversationDag push + parent lookup tests ──────────────────────

    #[test]
    fn dag_push_single_node_no_parent() {
        let dag = ConversationDag::new(64);
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
        let dag = ConversationDag::new(64);

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
        let dag = ConversationDag::new(64);

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
        let dag = ConversationDag::new(64);

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
        let dag = ConversationDag::new(2);

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
        let dag = ConversationDag::new(1);

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
        let dag = ConversationDag::new(64);

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
        let dag = ConversationDag::new(2); // max=2, 第 3 次 push 会淘汰 A.

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
        let dag = ConversationDag::new(64);
        let id_a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let id_b = dag.push_messages(vec![text_msg(IrRole::User, "b")], dummy_event());
        let ids = dag.list_node_ids_newest_first();
        assert_eq!(ids, vec![id_b, id_a], "newest first");
    }

    #[test]
    fn dag_empty_messages_creates_orphan_node() {
        // 无 messages 的请求 (GET /v1/models 等) 应创建孤立节点.
        let dag = ConversationDag::new(64);
        let id = dag.push_messages(vec![], dummy_event());
        let node = dag.get_node(id).expect("node exists");
        assert!(node.parent.is_none(), "orphan node has no parent");
        assert_eq!(node.req_delta_count, 0, "no messages");
    }

    #[test]
    fn dag_multi_hop_parent_chain() {
        // 模拟 opencode 的 3 步链: A → B → C.
        // request messages 含 agent 复制进来的 assistant (OriginRecord 视角).
        let dag = ConversationDag::new(64);

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
}
