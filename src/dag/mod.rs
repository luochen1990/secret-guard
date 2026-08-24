//! Conversation DAG: 内容寻址的对话历史存储 (模块目录根).
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
//! # 模块组织
//!
//! 历史上是单文件 `dag.rs` (4198 行, 承载 6 类职责). 按职责拆分为模块目录
//! (沿用 proxy/ 拆分先例):
//! - `mod` (本文件): `ConversationDag` + `DagInner` + `ParentLookup` + mutator
//!   (push_messages / attach_response / update_parsed_response) + 内部 helper
//!   (find_parent / gc_cascade / evict_if_needed) + 类型 re-export.
//! - `pool`: BlockPool + MessageRef + hash_block + combine_hash (内容寻址核心).
//! - `types`: Node / CallEvent / ResponseData / Session / SessionId / PolicySnapshot 实体.
//! - `view`: node_view / session_view / list_sessions / list_page / full_request_messages
//!   (读路径, 派生 WebUI 视图).
//! - `timeline`: walk_chain / build_timeline_round / build_timeline_diff_inner /
//!   sync_snapshot / timeline_view / timeline_diff (session-aware timeline).
//! - `crate::derive` 的 `extract_delta_messages_from_raw`: 从 req_body_raw 切片 delta
//!   messages (域 B 派生链, 与 extract_preview_and_model 同源).
//!
//! # 详尽设计见 `docs/design/conversation-dag.md`

mod pool;
mod timeline;
mod types;
mod view;

// 公开类型 re-export: 保持 `crate::dag::*` 路径稳定 (外部 caller 无需改 import).
pub use pool::{BlockHash, BlockPool, MessageRef};
pub use types::{CallEvent, Node, PolicySnapshot, ResponseData, SessionId};

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use uuid::Uuid;

use crate::codec::ir::{IrMessage, IrRole};

use types::Session;

// ─── ConversationDag + DagInner ─────────────────────────────────────────────

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
    /// `pub(super)` 让 view / timeline 子模块的读路径方法直接访问 (避免每个方法
    /// 都加 thin wrapper). 子模块都在 `crate::dag::*` 路径下, 不泄漏到 crate 外.
    pub(super) inner: Arc<RwLock<DagInner>>,
}

#[derive(Debug)]
pub(super) struct DagInner {
    pub(super) nodes: HashMap<Uuid, Node>,
    /// Merkle prefix hash → nodes (按 push 顺序, 末尾是最新的).
    pub(super) prefix_index: HashMap<u64, Vec<Uuid>>,
    /// 全局 block 池 (内容寻址 + refcount).
    pub(super) blocks: BlockPool,
    /// 会话表: SessionId → Session. 每个 session 的 leaf 即 sidebar 一级条目.
    pub(super) sessions: HashMap<SessionId, Session>,
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
            if delta_has_user_text {
                event.round_role = IrRole::User;
            } else {
                event.round_role = IrRole::Tool;
                // 工具轮次 (sub-dot): preview 覆盖为首个 ToolUse 的 tool name.
                //
                // 前端 index.html 三级菜单 (.sub-dot) 的 tooltip 文本 + providerColor 哈希
                // 源都依赖 preview = tool name. 但 build_call_event 时 extract_preview 在
                // 整个 req_body 上提取 (不知道 split_at), 对工具轮次会 fallback 到 "最后一条
                // 有文本的 message" (可能是 tool_result 片段 / assistant thinking), 导致
                // tooltip 显示杂乱文本 + 颜色哈希不稳定. 这里在 delta 切片上重新提取首个
                // ToolUse name, 覆盖错误的 preview (与 round_role 同一位置修正, SSOT).
                // 无 ToolUse (如纯 ToolResult 回复轮次) → 保留原 preview.
                //
                // 边界: 若本 node 是会话根 (parent=None), session.title 也会变成 tool name
                // (find_root_title 取根 preview). 正常对话根总是用户文本轮次, 此场景仅在
                // 自动化调用 / fork 边界出现, 属可接受的降级.
                let delta_msgs = &msgs[lookup.split_at..];
                if let Some(tool_name) = crate::derive::extract_tool_use_name(delta_msgs) {
                    event.preview = Some(Arc::<str>::from(tool_name));
                }
            }
        }

        // 4. 计算 own_hash + prefix_hash (只基于 req_delta, response 不参与).
        //
        // 持锁不变式: push_messages 持 write lock, evict 也需 write lock, 故 parent 不会被
        // 并发 evict. find_parent 返回的 parent_id 在此锁内必然仍存在. 但 find_parent 内部
        // 的 `prefix_index` 查找可能返回空 Vec 残留 (gc_cascade 的 retain 清理在另一路径) —
        // 用 `?`-style fallback (None → 新根) 而非 expect, 防御理论外的残留状态.
        let parent_base = match lookup.parent {
            Some(pid) => g.nodes.get(&pid).map(|n| n.prefix_hash).unwrap_or(0), // 持锁不变式下不会触发; 触发则当新根处理.
            None => 0,
        };
        let own_hash = Self::accumulate_hash(0, &delta_refs);
        let prefix_hash = Self::accumulate_hash(parent_base, &delta_refs);

        // 5. 确定会话归属 (O(1)): parent 是某 session 的当前 leaf → 延续; 否则 fork/新根.
        let sid = match lookup.parent {
            Some(pid) => {
                let parent_sid = g.nodes.get(&pid).map(|n| n.session_id).unwrap_or_default(); // 持锁不变式下不会触发.
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
                //
                // 持锁不变式: gc_cascade 移除 node 时会同步清理 prefix_index (retain +
                // remove 空向量), 但作为防御性编程, 用 `last()` 的 Option 而非 expect
                // 处理理论外的空 Vec 残留 (返回 None → 继续找更浅的匹配, 或返回新根).
                let parent = ids.last().copied();
                if let Some(parent) = parent {
                    return ParentLookup {
                        parent: Some(parent),
                        split_at: i + 1,
                    };
                }
                // 空 Vec 残留: 继续向更浅的 cum_seq 查找.
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

    // ─── mutator: response 写入 (两级锁) ──────────────────────────────────

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::ir::{IrBlock, IrMessage, IrRole};

    // ─── 共享 fixture ──────────────────────────────────────────────────────
    //
    // mod.rs 测试 fixture. view/timeline 子模块无独立 tests — 它们的行为测试通过
    // pub API 在本文件 tests 中调用 (见 "session_rounds / timeline_view" 段).

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
            created_at: chrono::Utc::now(),
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
            upstream_id: Arc::from("test"),
            redactions: Arc::from([]),
        }
    }

    /// 构造一个带 preview/model/req_body_raw 的 CallEvent (覆盖 list/get 视图字段).
    fn event_with_body(path: &str, req_body: &str) -> CallEvent {
        let (preview, model) = crate::derive::extract_preview_and_model(req_body);
        CallEvent {
            created_at: chrono::Utc::now(),
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
            upstream_id: Arc::from("test"),
            redactions: Arc::from([]),
        }
    }

    // ─── push_messages / find_parent / Merkle prefix hash ─────────────────

    #[test]
    fn conversation_dag_default_is_empty() {
        let dag = ConversationDag::default();
        assert_eq!(dag.node_count(), 0);
        assert!(dag.list_sessions().is_empty());
    }

    #[test]
    fn dag_push_single_node_no_parent() {
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(vec![text_msg(IrRole::User, "hello")], dummy_event());
        let v = dag.get_node(id).expect("node exists");
        assert_eq!(v.parent, None);
        assert_eq!(v.req_delta_count, 1);
        assert!(dag.list_sessions().iter().any(|s| s.leaf_id == id));
    }

    #[test]
    fn dag_push_linear_extension_finds_parent() {
        let dag = ConversationDag::new(8, 500, 1);
        let _a = dag.push_messages(vec![text_msg(IrRole::User, "m1")], dummy_event());
        let b = dag.push_messages(
            vec![text_msg(IrRole::User, "m1"), text_msg(IrRole::User, "m2")],
            dummy_event(),
        );
        let v = dag.get_node(b).expect("b exists");
        assert_eq!(v.req_delta_count, 1, "delta = [m2] only (m1 是前缀)");
        // b 的 parent 应是 a, 但这里不暴露 parent id 间接验证: b 单独成 delta 说明前缀命中.
    }

    #[test]
    fn dag_push_unrelated_messages_creates_new_root() {
        let dag = ConversationDag::new(8, 500, 1);
        let _a = dag.push_messages(vec![text_msg(IrRole::User, "alpha")], dummy_event());
        let b = dag.push_messages(vec![text_msg(IrRole::User, "beta")], dummy_event());
        let v = dag.get_node(b).expect("b exists");
        assert_eq!(v.parent, None, "无前缀匹配 → 新根");
        assert_eq!(v.req_delta_count, 1);
        assert_eq!(dag.list_sessions().len(), 2, "两个独立根 → 两个 session");
    }

    #[test]
    fn dag_full_request_messages_walks_parent_chain() {
        let dag = ConversationDag::new(8, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "m1")], dummy_event());
        let b = dag.push_messages(
            vec![
                text_msg(IrRole::User, "m1"),
                text_msg(IrRole::Assistant, "m2"),
            ],
            dummy_event(),
        );
        let c = dag.push_messages(
            vec![
                text_msg(IrRole::User, "m1"),
                text_msg(IrRole::Assistant, "m2"),
                text_msg(IrRole::User, "m3"),
            ],
            dummy_event(),
        );
        let full = dag.full_request_messages(c).expect("should walk");
        assert_eq!(full.len(), 3);
        assert_eq!(full[0].role, IrRole::User);
        assert_eq!(full[1].role, IrRole::Assistant);
        assert_eq!(full[2].role, IrRole::User);
        // a / b 也应能 walk.
        let _ = dag.full_request_messages(a).expect("a walks");
        let _ = dag.full_request_messages(b).expect("b walks");
    }

    // ─── FIFO 淘汰 + block refcount ────────────────────────────────────────

    #[test]
    fn dag_fifo_eviction_drops_oldest() {
        let dag = ConversationDag::new(2, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let _b = dag.push_messages(vec![text_msg(IrRole::User, "b")], dummy_event());
        let _c = dag.push_messages(vec![text_msg(IrRole::User, "c")], dummy_event());
        // a 应已被淘汰 (max=2, 第三次 push 触发淘汰 a 的 session).
        assert!(dag.get_node(a).is_none(), "a should be evicted");
        assert_eq!(dag.node_count(), 2, "只剩 b / c");
    }

    #[test]
    fn dag_fifo_eviction_releases_blocks() {
        let dag = ConversationDag::new(1, 500, 1);
        let _a = dag.push_messages(vec![text_msg(IrRole::System, "sys")], dummy_event());
        {
            let g = dag.inner.read();
            assert_eq!(g.blocks.len(), 1, "sys block interned");
        }
        let _b = dag.push_messages(vec![text_msg(IrRole::User, "user")], dummy_event());
        {
            let g = dag.inner.read();
            // a 被 evict → sys block refcount→0 → 移除. 只剩 user block.
            assert_eq!(
                g.blocks.len(),
                1,
                "evict should release sys block, only user block remains"
            );
        }
    }

    #[test]
    fn dag_block_sharing_across_nodes() {
        let dag = ConversationDag::new(8, 500, 1);
        let _a = dag.push_messages(vec![text_msg(IrRole::System, "shared-sys")], dummy_event());
        let _b = dag.push_messages(
            vec![
                text_msg(IrRole::System, "shared-sys"),
                text_msg(IrRole::User, "u1"),
            ],
            dummy_event(),
        );
        let g = dag.inner.read();
        // a 的 sys block + b 的 sys block (共享) + b 的 u1 block = 2 个 unique blocks.
        assert_eq!(g.blocks.len(), 2, "shared sys block deduped; only sys + u1");
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
        let sys_hash = super::pool::hash_block(&IrBlock::Text { text: "sys".into() });
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
        let dag = ConversationDag::new(8, 500, 1);
        let _a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        std::thread::sleep(std::time::Duration::from_millis(2));
        let _b = dag.push_messages(vec![text_msg(IrRole::User, "b")], dummy_event());
        let ids = dag.list_node_ids_newest_first();
        assert_eq!(ids.len(), 2);
        // b 后 push → b 在前.
        assert_eq!(ids[0], _b);
        assert_eq!(ids[1], _a);
    }

    #[test]
    fn dag_empty_messages_creates_orphan_node() {
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(vec![], dummy_event());
        let v = dag.get_node(id).expect("node exists");
        assert_eq!(v.parent, None, "空 messages → orphan");
        assert_eq!(v.req_delta_count, 0);
    }

    #[test]
    fn dag_multi_hop_parent_chain() {
        // 4 轮累积 push, 验证 parent 链 walk 正确.
        let dag = ConversationDag::new(8, 500, 1);
        let msgs = [
            text_msg(IrRole::System, "sys"),
            text_msg(IrRole::User, "u1"),
            text_msg(IrRole::Assistant, "a1"),
            text_msg(IrRole::User, "u2"),
        ];
        let mut last = None;
        for k in 1..=msgs.len() {
            last = Some(dag.push_messages(msgs[..k].to_vec(), dummy_event()));
        }
        let full = dag
            .full_request_messages(last.expect("last set"))
            .expect("walk");
        assert_eq!(full.len(), 4);
    }

    // ─── attach_response / update_parsed_response / get_node_detail ──────

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
        let dag = ConversationDag::new(8, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let b = dag.push_messages(vec![text_msg(IrRole::User, "b")], dummy_event());
        dag.attach_response(
            a,
            ResponseData {
                resp_status: 200,
                ..Default::default()
            },
        );
        let ids = dag.list_node_ids_newest_first();
        assert_eq!(ids, vec![b, a], "b 后 push → b 在前");
    }

    #[test]
    fn nodeview_preview_model_passthrough_when_uncomputed() {
        // req_body_raw 无 messages 无 model → preview / model 都是 None.
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(vec![], event_with_body("/o/x", "{}"));
        let v = dag.get_node(id).expect("node exists");
        assert!(v.preview.is_none());
        assert!(v.model.is_none());
    }

    #[test]
    fn get_node_detail_on_evicted_returns_none() {
        let dag = ConversationDag::new(1, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let _b = dag.push_messages(vec![text_msg(IrRole::User, "b")], dummy_event());
        assert!(dag.get_node_detail(a).is_none(), "a evicted");
    }

    #[test]
    fn response_data_default_is_empty_state() {
        let r = ResponseData::default();
        assert!(r.message.is_none());
        assert_eq!(r.resp_status, 0);
        assert!(r.parsed.is_none());
        assert!(!r.streamed);
        assert!(!r.resp_complete);
    }

    #[test]
    fn attach_response_can_be_called_twice_overwrites() {
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(vec![text_msg(IrRole::User, "u")], dummy_event());
        dag.attach_response(
            id,
            ResponseData {
                resp_status: 200,
                raw_resp_body: "first".into(),
                ..Default::default()
            },
        );
        dag.attach_response(
            id,
            ResponseData {
                resp_status: 500,
                raw_resp_body: "second".into(),
                ..Default::default()
            },
        );
        let r = dag.get_response(id).expect("response exists");
        assert_eq!(r.resp_status, 500, "second attach overwrites");
        assert_eq!(r.raw_resp_body, "second");
    }

    #[test]
    fn update_parsed_response_preserves_already_attached_response_fields() {
        // 已 attach 完整 ResponseData (含 resp_status / headers), update_parsed_response
        // 只改 parsed, 不丢失其他字段.
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(vec![text_msg(IrRole::User, "u")], dummy_event());
        dag.attach_response(
            id,
            ResponseData {
                resp_status: 200,
                resp_headers: vec![("x-trace".into(), "abc".into())],
                raw_resp_body: "body".into(),
                elapsed_ms: 10,
                ..Default::default()
            },
        );
        dag.update_parsed_response(id, serde_json::json!({"k": "v"}));
        let r = dag.get_response(id).expect("response exists");
        assert_eq!(r.resp_status, 200, "resp_status preserved");
        assert_eq!(r.elapsed_ms, 10, "elapsed_ms preserved");
        assert_eq!(r.raw_resp_body, "body", "raw_resp_body preserved");
        assert_eq!(r.parsed, Some(serde_json::json!({"k": "v"})));
    }

    // ─── session 聚类 + LRU evict + gc_cascade ─────────────────────────────

    #[test]
    fn leaves_tracks_session_tips() {
        let dag = ConversationDag::new(8, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "u1")], dummy_event());
        let b = dag.push_messages(
            vec![
                text_msg(IrRole::User, "u1"),
                text_msg(IrRole::Assistant, "a1"),
            ],
            dummy_event(),
        );
        // a 和 b 延续同一 session (前缀匹配), leaf 应是 b.
        let sessions = dag.list_sessions();
        assert_eq!(sessions.len(), 1, "a + b 同 session");
        assert_eq!(sessions[0].leaf_id, b);
        assert_eq!(sessions[0].record_count, 2);
        // a 仍可访问 (未被淘汰).
        assert!(dag.get_node(a).is_some());
    }

    #[test]
    fn leaves_multiple_independent_sessions() {
        let dag = ConversationDag::new(8, 500, 1);
        let _a = dag.push_messages(vec![text_msg(IrRole::User, "alpha")], dummy_event());
        let _b = dag.push_messages(vec![text_msg(IrRole::User, "beta")], dummy_event());
        assert_eq!(dag.list_sessions().len(), 2);
    }

    #[test]
    fn session_lru_evict_keeps_min_sessions_floor() {
        // min_sessions=2 保底: 即便 nodes 超 max, 也保留至少 2 个 session.
        let dag = ConversationDag::new(2, 500, 2);
        let _a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let _b = dag.push_messages(vec![text_msg(IrRole::User, "b")], dummy_event());
        let _c = dag.push_messages(vec![text_msg(IrRole::User, "c")], dummy_event());
        // min_sessions=2 → 至少 2 session 存活 (即便 nodes 超 max).
        assert!(
            dag.list_sessions().len() >= 2,
            "min_sessions 保底: 至少 2 session 存活"
        );
    }

    #[test]
    fn session_lru_evict_drops_oldest_session() {
        // max_sessions=1 + min_sessions=1: 第二个独立 session push 后, 最旧的被淘汰.
        let dag = ConversationDag::new(100, 1, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "a")], dummy_event());
        let _b = dag.push_messages(vec![text_msg(IrRole::User, "b")], dummy_event());
        // max_sessions=1 → a 的 session 应被淘汰 (latest_at 更旧).
        assert!(dag.get_node(a).is_none(), "a 的 session 被 LRU 淘汰");
    }

    #[test]
    fn session_gc_cascade_protects_fork_shared_parent() {
        // fork 场景: A 是共享 parent (B 和 C 都以 A 为 parent). 淘汰 B 不应删除 A
        // (A 的 child_count 仍 ≥1 因 C 引用).
        let dag = ConversationDag::new(8, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "m1")], dummy_event());
        let b = dag.push_messages(
            vec![
                text_msg(IrRole::User, "m1"),
                text_msg(IrRole::Assistant, "m2"),
            ],
            dummy_event(),
        );
        // fork: 再 push [m1, m3] (m1 前缀匹配 a, 但不延续 b 的链).
        let _c = dag.push_messages(
            vec![text_msg(IrRole::User, "m1"), text_msg(IrRole::User, "m3")],
            dummy_event(),
        );
        // a 被 b 和 c 共同引用 (child_count=2).
        // 手动淘汰 b 的 session: 取 sessions 列表, 找 leaf=b 的, 删之.
        {
            let mut g = dag.inner.write();
            // 找 leaf=b 的 session 并移除 (触发 gc_cascade on b).
            let victim_sid = g
                .sessions
                .iter()
                .find(|(_, s)| s.leaf_id == b)
                .map(|(sid, _)| *sid);
            if let Some(sid) = victim_sid {
                let session = g.sessions.remove(&sid).expect("session exists");
                super::ConversationDag::gc_cascade(&mut g, session.leaf_id);
            }
        }
        // a 应仍存在 (被 c 引用, child_count > 0).
        assert!(
            dag.get_node(a).is_some(),
            "a protected by fork (c still refs)"
        );
    }

    // ─── round_role (contains_user_text 判定) ──────────────────────────────

    fn tool_result_msg() -> IrMessage {
        IrMessage {
            contains_user_text: false, // 工具结果不是用户文本
            role: IrRole::User,
            content: vec![IrBlock::ToolResult {
                tool_use_id: "call_1".to_string(),
                content: vec![IrBlock::Text {
                    text: "result".to_string(),
                }],
                is_error: false,
                content_form: None,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn round_role_distinguishes_user_text_from_tool_result() {
        let dag = ConversationDag::new(8, 500, 1);
        // 工具结果轮次: round_role 应为 Tool.
        let id_tool = dag.push_messages(vec![tool_result_msg()], dummy_event());
        let v_tool = dag.get_node(id_tool).expect("tool node exists");
        assert_eq!(
            v_tool.round_role,
            IrRole::Tool,
            "tool_result-only → round_role=Tool"
        );

        // 用户文本轮次: round_role 应为 User.
        let id_user =
            dag.push_messages(vec![text_msg(IrRole::User, "real question")], dummy_event());
        let v_user = dag.get_node(id_user).expect("user node exists");
        assert_eq!(v_user.round_role, IrRole::User);
    }

    #[test]
    fn round_role_mixed_text_and_tool_result_is_user() {
        // delta 含一条 user text + 一条 tool_result → round_role=User (任一条 contains_user_text).
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(
            vec![
                tool_result_msg(),
                text_msg(IrRole::User, "follow up question"),
            ],
            dummy_event(),
        );
        let v = dag.get_node(id).expect("node exists");
        assert_eq!(
            v.round_role,
            IrRole::User,
            "mixed → User (任一条 user text)"
        );
    }

    /// 构造含 ToolUse 的 assistant 消息 (contains_user_text = false).
    fn tool_use_msg(name: &str) -> IrMessage {
        IrMessage {
            contains_user_text: false,
            role: IrRole::Assistant,
            content: vec![IrBlock::ToolUse {
                id: "call_1".to_string(),
                name: name.to_string(),
                input: serde_json::json!({}),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn tool_round_preview_is_tool_name() {
        // 工具轮次 (assistant ToolUse + user ToolResult, 无 user text): round_role=Tool,
        // preview 应被覆盖为首个 ToolUse 的 name.
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(
            vec![tool_use_msg("read_file"), tool_result_msg()],
            dummy_event(),
        );
        let v = dag.get_node(id).expect("node exists");
        assert_eq!(v.round_role, IrRole::Tool);
        assert_eq!(
            v.preview.as_deref(),
            Some("read_file"),
            "工具轮次 preview 应为 tool name"
        );
    }

    #[test]
    fn tool_round_without_tool_use_keeps_original_preview() {
        // 纯 ToolResult 回复 (delta 无 user text 也无 ToolUse): round_role=Tool,
        // 但无 ToolUse → 不覆盖 preview, 保留 extract_preview 的 fallback 结果.
        // body 只有 tool message (无 user text), extract_preview fallback 到 "result data".
        let body = r#"{"model":"x","messages":[{"role":"tool","tool_call_id":"c1","content":"result data"}]}"#;
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(vec![tool_result_msg()], event_with_body("/o/x", body));
        let v = dag.get_node(id).expect("node exists");
        assert_eq!(v.round_role, IrRole::Tool);
        // 无 ToolUse → 保留 extract_preview 的 fallback 结果, 不覆盖.
        assert_eq!(
            v.preview.as_deref(),
            Some("result data"),
            "无 ToolUse 时保留 extract_preview 的 fallback 结果"
        );
    }

    #[test]
    fn user_round_preview_unaffected_by_tool_name_override() {
        // 用户轮次 (delta 含 user text) → round_role=User, preview 不受 tool name 覆盖影响.
        // 即使 delta 恰好也含 ToolUse (混合轮次), preview 仍走 user text 路径.
        let dag = ConversationDag::new(8, 500, 1);
        let id = dag.push_messages(
            vec![
                tool_use_msg("some_tool"),
                text_msg(IrRole::User, "my question"),
            ],
            dummy_event(),
        );
        let v = dag.get_node(id).expect("node exists");
        assert_eq!(v.round_role, IrRole::User);
        // dummy_event preview = None, 工具轮次覆盖逻辑不触发 (round_role != Tool).
        assert!(
            v.preview.is_none(),
            "User round preview 应保持 None (dummy_event 无 body, 不被覆盖)"
        );
    }

    // ─── session_rounds / timeline_view / timeline_diff / sync_snapshot ───
    //
    // 这些测试覆盖 timeline.rs 的逻辑, 但通过 pub API (session_rounds / timeline_view /
    // timeline_diff / sync_snapshot) 调用, 故放在 mod.rs 的 tests (无需白盒访问 timeline
    // 私有 helper).

    fn sid_of(dag: &ConversationDag, leaf: Uuid) -> SessionId {
        dag.get_node(leaf).expect("leaf exists").session_id
    }

    fn push_with_response(dag: &ConversationDag, msgs: Vec<IrMessage>, body: &str) -> Uuid {
        let mut ev = event_with_body("/o/x/v1/chat", body);
        ev.created_at = chrono::Utc::now();
        let id = dag.push_messages(msgs, ev);
        dag.attach_response(
            id,
            ResponseData {
                resp_status: 200,
                raw_resp_body: body.to_string(),
                resp_complete: true,
                ..Default::default()
            },
        );
        id
    }

    #[test]
    fn session_rounds_returns_oldest_first() {
        let dag = ConversationDag::new(8, 500, 1);
        let a = push_with_response(&dag, vec![text_msg(IrRole::User, "u1")], "{\"a\":1}");
        let _b = push_with_response(
            &dag,
            vec![text_msg(IrRole::User, "u1"), text_msg(IrRole::User, "u2")],
            "{\"b\":2}",
        );
        let sid = sid_of(&dag, a);
        let rounds = dag.session_rounds(sid);
        assert_eq!(rounds.len(), 2);
        // oldest-first: a 在前.
        assert_eq!(rounds[0].id, a);
    }

    #[test]
    fn session_rounds_unknown_sid_returns_empty() {
        let dag = ConversationDag::default();
        let rounds = dag.session_rounds(SessionId::new());
        assert!(rounds.is_empty());
    }

    // ─── timeline_view ────────────────────────────────────────────────────

    #[test]
    fn timeline_view_initial_load_returns_leaf_with_tail() {
        let dag = ConversationDag::new(8, 500, 1);
        let a = push_with_response(&dag, vec![text_msg(IrRole::User, "u1")], "{\"a\":1}");
        let b = push_with_response(
            &dag,
            vec![text_msg(IrRole::User, "u1"), text_msg(IrRole::User, "u2")],
            "{\"b\":2}",
        );
        let sid = sid_of(&dag, a);
        let page = dag.timeline_view(sid, None, 10).expect("page exists");
        assert_eq!(page.rounds.len(), 2);
        assert!(!page.has_more, "链短, 无更多");
        assert_eq!(page.tail.round_id, b, "tail = leaf");
        assert_eq!(page.tail.resp_status, 200);
    }

    #[test]
    fn timeline_view_limit_truncates_and_has_more() {
        // 累积 push 5 轮到同一 session, 验证 limit 截断 + has_more.
        let dag = ConversationDag::new(8, 500, 1);
        let mut msgs_acc: Vec<IrMessage> = Vec::new();
        let mut leaf = None;
        for i in 0..5 {
            msgs_acc.push(text_msg(IrRole::User, &format!("u{i}")));
            leaf = Some(push_with_response(&dag, msgs_acc.clone(), "{}"));
        }
        let leaf = leaf.expect("leaf set");
        let sid = sid_of(&dag, leaf);
        let page = dag.timeline_view(sid, None, 2).expect("page exists");
        assert_eq!(page.rounds.len(), 2, "limit=2 truncates");
        assert!(page.has_more, "链上有更老的 round");
    }

    #[test]
    fn timeline_view_before_cursor_loads_older() {
        let dag = ConversationDag::new(8, 500, 1);
        let mut msgs_acc: Vec<IrMessage> = Vec::new();
        let mut ids = Vec::new();
        for i in 0..4 {
            msgs_acc.push(text_msg(IrRole::User, &format!("u{i}")));
            ids.push(push_with_response(&dag, msgs_acc.clone(), "{}"));
        }
        let sid = sid_of(&dag, ids[3]);
        // before=ids[2] → 取 ids[2] 之前 (更老) 的, 不含 ids[2].
        let page = dag
            .timeline_view(sid, Some(ids[2]), 10)
            .expect("page exists");
        // 应取到 ids[0], ids[1] (在 ids[2] 之前).
        let returned_ids: Vec<Uuid> = page.rounds.iter().map(|r| r.id).collect();
        assert!(
            !returned_ids.contains(&ids[2]),
            "before cursor 不含 cursor 自身"
        );
        assert!(returned_ids.contains(&ids[0]), "含最老的");
    }

    #[test]
    fn timeline_view_unknown_sid_returns_none() {
        let dag = ConversationDag::default();
        assert!(dag.timeline_view(SessionId::new(), None, 10).is_none());
    }

    #[test]
    fn timeline_view_before_from_other_session_returns_none() {
        let dag = ConversationDag::new(8, 500, 1);
        let a = push_with_response(&dag, vec![text_msg(IrRole::User, "u1")], "{}");
        let _b = push_with_response(&dag, vec![text_msg(IrRole::User, "other")], "{}");
        let sid_a = sid_of(&dag, a);
        // 用 _b 的 id 作为 before 查 sid_a → None (跨 session).
        let _b_id = dag
            .list_sessions()
            .iter()
            .find(|s| s.leaf_id != a)
            .unwrap()
            .leaf_id;
        assert!(dag.timeline_view(sid_a, Some(_b_id), 10).is_none());
    }

    // ─── timeline_diff ────────────────────────────────────────────────────

    #[test]
    fn timeline_diff_returns_none_when_no_change() {
        let dag = ConversationDag::new(8, 500, 1);
        let a = push_with_response(&dag, vec![text_msg(IrRole::User, "u1")], "{}");
        let sid = sid_of(&dag, a);
        // after=Some(a) + tail_length 匹配 → None (无变化).
        let tail_length = dag.timeline_view(sid, None, 10).unwrap().tail.length;
        assert!(dag.timeline_diff(sid, Some(a), tail_length).is_none());
    }

    #[test]
    fn timeline_diff_returns_new_rounds_after_push() {
        let dag = ConversationDag::new(8, 500, 1);
        let a = push_with_response(&dag, vec![text_msg(IrRole::User, "u1")], "{}");
        let sid = sid_of(&dag, a);
        // 新 round b.
        let _b = push_with_response(
            &dag,
            vec![text_msg(IrRole::User, "u1"), text_msg(IrRole::User, "u2")],
            "{}",
        );
        let diff = dag
            .timeline_diff(sid, Some(a), 0)
            .expect("有新 round → Some");
        assert_eq!(diff.new_rounds.len(), 1, "新增 b 一轮");
    }

    #[test]
    fn timeline_diff_after_not_in_session_returns_full_chain() {
        let dag = ConversationDag::new(8, 500, 1);
        let a = push_with_response(&dag, vec![text_msg(IrRole::User, "u1")], "{}");
        let sid = sid_of(&dag, a);
        // after=Some(unknown_id) 不属于本 session → 视为初始加载, 返回全链.
        let diff = dag
            .timeline_diff(sid, Some(Uuid::new_v4()), 0)
            .expect("after 过期 → 全部返回");
        assert_eq!(diff.new_rounds.len(), 1, "全链 = 1 round");
    }

    #[test]
    fn timeline_diff_tail_change_only_returns_empty_new_rounds() {
        let dag = ConversationDag::new(8, 500, 1);
        let a = push_with_response(&dag, vec![text_msg(IrRole::User, "u1")], "{}");
        let sid = sid_of(&dag, a);
        // tail.length 变化 (传 0, 实际非 0) → 返回 empty new_rounds + 新 tail.
        let actual_tail = dag.timeline_view(sid, None, 10).unwrap().tail.length;
        if actual_tail > 0 {
            let diff = dag
                .timeline_diff(sid, Some(a), 0)
                .expect("tail 变化 → Some");
            assert!(diff.new_rounds.is_empty(), "无新 round");
            assert_eq!(diff.tail.length, actual_tail, "新 tail");
        }
    }

    // ─── sync_snapshot ────────────────────────────────────────────────────

    #[test]
    fn sync_snapshot_collects_all_three_parts_in_one_lock() {
        let dag = ConversationDag::new(8, 500, 1);
        let a = push_with_response(&dag, vec![text_msg(IrRole::User, "u1")], "{}");
        let _b = push_with_response(
            &dag,
            vec![text_msg(IrRole::User, "u1"), text_msg(IrRole::User, "u2")],
            "{}",
        );
        let sid = sid_of(&dag, a);
        let snap = dag.sync_snapshot(&[sid], Some((sid, Some(a), 0)));
        assert_eq!(snap.sessions.len(), 1, "1 session");
        assert_eq!(snap.sessions[0].leaf_id, _b);
        let rounds = snap.timeline.expect("有新 round → Some");
        assert_eq!(rounds.new_rounds.len(), 1, "新增 b");
        let session_rounds = snap.rounds.get(&sid).expect("sid in expanded");
        assert_eq!(session_rounds.len(), 2, "全链 2 round");
    }

    #[test]
    fn sync_snapshot_no_selected_timeline_is_none() {
        let dag = ConversationDag::new(8, 500, 1);
        let _a = push_with_response(&dag, vec![text_msg(IrRole::User, "u1")], "{}");
        let snap = dag.sync_snapshot(&[], None);
        assert!(snap.timeline.is_none(), "无 selected → timeline=None");
    }

    #[test]
    fn sync_snapshot_expanded_unknown_sid_yields_empty_rounds() {
        let dag = ConversationDag::default();
        let unknown = SessionId::new();
        let snap = dag.sync_snapshot(&[unknown], None);
        assert!(
            !snap.rounds.contains_key(&unknown),
            "unknown sid 不在 rounds map"
        );
    }

    #[test]
    fn timeline_round_carries_req_delta_messages_for_leaf() {
        // leaf 节点的 TimelineRound 应携带 req_delta_messages (从 req_body_raw 切片).
        let body = r#"{"messages":[{"role":"user","content":"hello"}]}"#;
        let dag = ConversationDag::new(8, 500, 1);
        let a = push_with_response(&dag, vec![text_msg(IrRole::User, "hello")], body);
        let sid = sid_of(&dag, a);
        let page = dag.timeline_view(sid, None, 10).expect("page exists");
        let round = &page.rounds[0];
        assert_eq!(
            round.req_delta_messages.len(),
            1,
            "leaf round has 1 delta message"
        );
    }

    // ─── 并发测试 ──────────────────────────────────────────────────────────

    #[test]
    fn concurrent_push_and_read_no_panic_no_data_race() {
        use std::sync::Arc as StdArc;
        use std::thread;

        let dag = StdArc::new(ConversationDag::new(64, 500, 1));
        let dag_w = StdArc::clone(&dag);
        let dag_r = StdArc::clone(&dag);

        let writer = thread::spawn(move || {
            for i in 0..32 {
                let msg = text_msg(IrRole::User, &format!("msg-{i}"));
                let _id = dag_w.push_messages(vec![msg], dummy_event());
            }
        });
        let reader = thread::spawn(move || {
            for _ in 0..32 {
                let _sessions = dag_r.list_sessions();
                let _ids = dag_r.list_node_ids_newest_first();
            }
        });
        writer.join().expect("writer thread must not panic");
        reader.join().expect("reader thread must not panic");
    }

    // ─── fork + LRU evict ─────────────────────────────────────────────────

    #[test]
    fn fork_and_lru_evict_preserves_shared_parent() {
        // fork: A=[m1], B=[m1,m2] (延续 A 的 session), C=[m1,m3] (fork, 新 session).
        // evict C 的 session 后, A 不应被 cascade GC (B 仍引用).
        let dag = ConversationDag::new(8, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "m1")], dummy_event());
        let _b = dag.push_messages(
            vec![
                text_msg(IrRole::User, "m1"),
                text_msg(IrRole::Assistant, "m2"),
            ],
            dummy_event(),
        );
        let _c = dag.push_messages(
            vec![text_msg(IrRole::User, "m1"), text_msg(IrRole::User, "m3")],
            dummy_event(),
        );
        // 手动 evict C 的 session (fork 的新 session).
        {
            let mut g = dag.inner.write();
            // 找 leaf=_c 的 session.
            let victim_sid = g
                .sessions
                .iter()
                .find(|(_, s)| {
                    // _c 的 leaf: 找 parent=Some(a) 且 leaf != _b 的
                    // 简化: 找 fork 出来的新 session (record_count==1 且 leaf 不是 a 也不是 _b).
                    // 这里用一个间接判定: 取最新 push 的 session (fork session).
                    s.node_count == 1
                })
                .map(|(sid, _)| *sid);
            if let Some(sid) = victim_sid {
                let session = g.sessions.remove(&sid).unwrap();
                super::ConversationDag::gc_cascade(&mut g, session.leaf_id);
            }
        }
        // a 应仍存在 (B 引用).
        assert!(dag.get_node(a).is_some(), "a protected by B");
    }

    #[test]
    fn dag_fork_creates_distinct_sessions_with_correct_parents() {
        let dag = ConversationDag::new(8, 500, 1);
        let a = dag.push_messages(vec![text_msg(IrRole::User, "m1")], dummy_event());
        let b = dag.push_messages(
            vec![
                text_msg(IrRole::User, "m1"),
                text_msg(IrRole::Assistant, "m2"),
            ],
            dummy_event(),
        );
        let c = dag.push_messages(
            vec![text_msg(IrRole::User, "m1"), text_msg(IrRole::User, "m3")],
            dummy_event(),
        );
        let sid_a = sid_of(&dag, a);
        let sid_b = sid_of(&dag, b);
        let sid_c = sid_of(&dag, c);
        // a 和 b 延续同一 session.
        assert_eq!(sid_a, sid_b, "a + b 同 session");
        // c 是 fork → 新 session.
        assert_ne!(sid_c, sid_a, "c fork → 新 session");
        // c 的 parent 是 a (不是 b, 因为 [m1,m3] 的前缀只匹配 a 的 [m1]).
        let c_node = dag.get_node(c).expect("c exists");
        assert_eq!(c_node.parent, Some(a), "c 的 parent 是 a");
    }

    // ─── list_page hits_only ──────────────────────────────────────────────

    #[test]
    fn list_page_hits_only_filters_nodes_without_redactions() {
        let dag = ConversationDag::new(8, 500, 1);
        // 一个带 redactions, 一个不带.
        let mut ev_hit = dummy_event();
        ev_hit.redactions = Arc::from([("MOCK".into(), "sec".into())]);
        let _id_hit = dag.push_messages(vec![text_msg(IrRole::User, "hit")], ev_hit);
        let _id_miss = dag.push_messages(vec![text_msg(IrRole::User, "miss")], dummy_event());

        let (views, total) = dag.list_page(0, 10, true);
        assert_eq!(total, 1, "hits_only → 只有 1 个命中");
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].redactions.len(), 1);
    }

    #[test]
    fn list_page_hits_only_with_offset_clamps() {
        let dag = ConversationDag::new(8, 500, 1);
        let mut ev = dummy_event();
        ev.redactions = Arc::from([("MOCK".into(), "sec".into())]);
        let _id = dag.push_messages(vec![text_msg(IrRole::User, "hit")], ev);

        let (views, total) = dag.list_page(10, 10, true);
        assert_eq!(total, 1);
        assert!(views.is_empty(), "offset 超过 total → 空");
    }

    // ─── 并发 attach / list / update_parsed_response ─────────────────────

    #[test]
    fn concurrent_attach_and_list_do_not_corrupt_or_deadlock() {
        use std::sync::Arc as StdArc;
        use std::thread;

        let dag = StdArc::new(ConversationDag::new(16, 500, 1));
        let ids: Vec<Uuid> = (0..4)
            .map(|i| {
                dag.push_messages(
                    vec![text_msg(IrRole::User, &format!("u{i}"))],
                    dummy_event(),
                )
            })
            .collect();

        let dag_w = StdArc::clone(&dag);
        let dag_r = StdArc::clone(&dag);
        let ids_w = ids.clone();
        let writer = thread::spawn(move || {
            for id in ids_w {
                dag_w.attach_response(
                    id,
                    ResponseData {
                        resp_status: 200,
                        resp_complete: true,
                        ..Default::default()
                    },
                );
            }
        });
        let reader = thread::spawn(move || {
            for _ in 0..10 {
                let _views = dag_r.list_page(0, 10, false);
            }
        });
        writer.join().expect("writer thread panicked / deadlocked");
        reader.join().expect("reader thread panicked / deadlocked");
        // 验证: 所有 node 都应有 response.
        for id in &ids {
            let r = dag.get_response(*id).expect("response exists");
            assert_eq!(r.resp_status, 200);
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

    // ─── proptest (DAG 核心代数性质: CDAG-2/3/4/5/8) ──────────────────────
    //
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
    ///
    /// 文本非空 (`{1,20}`): 空消息是退化场景, 实际 LLM client 几乎不发.
    /// (CDAG-8 fork 测试对 m2==m3 的过滤由该测试自身的 prop_filter 兜底, 见 issue #113.)
    fn arb_text_message() -> impl Strategy<Value = IrMessage> {
        (arb_role(), "[a-z0-9 ]{1,20}").prop_map(|(role, text)| IrMessage {
            role,
            content: vec![IrBlock::Text { text }],
            ..Default::default()
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// 结构性回归守卫: 内容寻址 round-trip identity (BlockPool intern/resolve + Merkle
        /// walk 的代数恒等式 — CDAG-2/3/4 的共同前置条件, 无单一契约 ID).
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

        /// 守卫 CDAG-2: 多 node 链 round-trip (parent 共享前缀 + Merkle prefix hash 找 parent).
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
            // 不约束三条 message 各不相同: 若两条完全相同, intern 会 dedupe
            // (BlockPool.len < 3), 但 round-trip 恒等式仍应成立.
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

        /// 守卫 CDAG-3: 任意 push + 淘汰序列后所有存活 block refcount > 0.
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

        /// 结构性回归守卫: intern idempotent hash (内容寻址根基, CDAG-2/6 的共同前置条件,
        /// 无单一契约 ID). 同一 block 重复 intern, hash 必须相同.
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

    // ─── CDAG-5 redact_seed 可重现 (契约 §4 CDAG-5) ───────────────────────────

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

            prop_assert_eq!(sid_a, sid_b, "A+B 同 session");
            prop_assert_eq!(sid_b, sid_c, "B+C 同 session");
            prop_assert_eq!(sid_c, sid_d, "C+D 同 session");
        }

        /// CDAG-8 变体: fork 场景 (前缀相同但后续不同, parent 不是当前 leaf) 创建新 session.
        /// push [m1, m2] → B (延续 A); push [m1, m3] → C (fork, 因为 [m1] 的 leaf 是 B 不是 A,
        /// 但 C 的 parent 是 A → A 不是当前 leaf → fork).
        ///
        /// prop_filter: m2 != m3 (否则 C 与 B 完全相同, 不构成 fork).
        #[test]
        fn prop_session_fork_creates_new_session_id(
            m1 in arb_text_message(),
            m2 in arb_text_message(),
            m3 in arb_text_message()
        ) {
            prop_assume!(m2.content != m3.content, "m2 != m3 才构成 fork");
            let dag = ConversationDag::new(64, 500, 1);
            let _a = dag.push_messages(vec![m1.clone()], dummy_event());
            let _b = dag.push_messages(vec![m1.clone(), m2], dummy_event());
            let c = dag.push_messages(vec![m1, m3], dummy_event());

            let sid_b = dag.list_sessions().iter()
                .find(|s| s.record_count == 2)
                .map(|s| s.session_id);
            let sid_c = dag.get_node(c).expect("C exists").session_id;

            if let Some(sid_b) = sid_b {
                prop_assert_ne!(
                    sid_c, sid_b,
                    "fork (parent 不是当前 leaf) → 新 session"
                );
            }
        }
    }
}
