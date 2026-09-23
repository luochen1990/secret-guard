//! BlockPool: 全局内容寻址的 IrBlock 池 + MessageRef 引用.
//!
//! # 职责边界
//!
//! 本模块是 DAG 内容寻址的存储根基, 提供:
//! - [`BlockHash`] (= u64 SipHash): IrBlock 内容的 hash, 用作池 key.
//! - [`hash_block`]: 计算 IrBlock 的内容 hash (递归, 含 variant tag).
//! - [`MessageRef`]: 内容寻址的 message 引用 (role + block hash 列表).
//! - [`BlockPool`]: 全局 IrBlock 池, intern/release + refcount GC.
//!
//! # 与父模块 [`super`] 的关系
//!
//! BlockPool 是 [`super::DagInner`] 的字段 (`blocks`), 由 [`super::ConversationDag`]
//! 的 mutator (push_messages / gc_cascade) 与 reader (full_request_messages) 操作.
//! 本模块只负责存储语义, 不涉及 Merkle prefix hash 或 session 聚类.
//!
//! # collision check (CDAG-6 契约例外)
//!
//! [`BlockPool::intern`] 用 `assert!` (非 debug_assert!) 做 collision check:
//! hash 命中时比对 block 内容, 不一致则 panic (release 也 panic). 详见该函数注释.

use std::collections::HashMap;
use std::sync::Arc;

use crate::codec::ir::{
    ContentForm, IrBlock, IrImageSource, IrMessage, IrRole, ReasoningContentForm,
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
///
/// # 性能 — 未做 memoize 的原因
///
/// `push_messages → intern_message → intern` 路径中, `hash_block` 在 `intern` 入口
/// 无条件调用 (即使 block 已在池中), 因为必须先 hash 才能查 HashMap; BlockPool 去重
/// 消除的是 `Arc::new(block.clone())`, 不消除 hash 本身. 历史 message 的 block 在每次
/// `push_messages` 都被重新 intern, 是真实重复开销来源.
///
/// 未做 memoize 因 `IrBlock` 是核心数据结构 (enum, derive PartialEq/Clone), 加
/// `OnceCell<BlockHash>` 会破坏派生 + 跨 clone 不共享缓存 + blast radius 过大.
/// `MessageRef::hash` 已直接 hash `Vec<BlockHash>` (u64) 而非重调本函数, Merkle
/// 累积路径 (`find_parent` / `accumulate_hash`) 不重复 walk block 内容.
/// profiling 与 follow-up 选项见 AGENTS.md "已知搁置".
/// block 级 `extra` (Map<String, Value>, #269) 参与内容寻址: 两个仅差
/// cache_control 的 block 必须是不同池条目 (intern 正确性前提).
/// canonical 依赖同 `input`: serde_json 无 preserve_order 时 key 有序.
fn hash_extra(
    extra: &serde_json::Map<String, serde_json::Value>,
    h: &mut std::collections::hash_map::DefaultHasher,
) {
    use std::hash::Hash;
    if extra.is_empty() {
        // 空与 "无字段" 同哈希: 语义等价 (空 Map 是填充默认, 非信息).
        0u8.hash(h);
        return;
    }
    1u8.hash(h);
    let s = serde_json::to_string(extra).unwrap_or_default();
    s.hash(h);
}

pub(super) fn hash_block(block: &IrBlock) -> BlockHash {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    std::mem::discriminant(block).hash(&mut h);
    match block {
        IrBlock::Text { text, extra } => {
            text.hash(&mut h);
            hash_extra(extra, &mut h);
        }
        IrBlock::ToolUse {
            id,
            name,
            input,
            extra,
        } => {
            id.hash(&mut h);
            name.hash(&mut h);
            // serde_json::Value 不 impl Hash; 用 canonical JSON string 做 hash.
            // 隐式依赖: serde_json 默认 (无 preserve_order feature) 用 BTreeMap,
            // key 按字母排序 → canonical. 若未来启用 preserve_order, 需改手动 canonical 序列化.
            let input_str = serde_json::to_string(input).unwrap_or_default();
            input_str.hash(&mut h);
            hash_extra(extra, &mut h);
        }
        IrBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
            content_form: _,
            extra,
        } => {
            tool_use_id.hash(&mut h);
            // Option<bool> 参与 hash: None (缺席) 与 Some(false) (显式) 是不同 wire 形态,
            // intern 必须区分 (#269 is_error 保真).
            is_error.hash(&mut h);
            for c in content {
                hash_block(c).hash(&mut h);
            }
            hash_extra(extra, &mut h);
        }
        IrBlock::Image { source, extra } => {
            match source {
                IrImageSource::Base64 { media_type, data } => {
                    media_type.hash(&mut h);
                    data.hash(&mut h);
                }
                IrImageSource::Url(url) => {
                    url.hash(&mut h);
                }
            }
            hash_extra(extra, &mut h);
        }
        IrBlock::Reasoning { summary } => {
            for s in summary {
                s.hash(&mut h);
            }
        }
        IrBlock::ReasoningContent { text } => {
            text.hash(&mut h);
        }
    }
    h.finish()
}

// ─── MessageRef ────────────────────────────────────────────────────────────

/// 内容寻址的 message 引用 (role + block hash 列表 + wire 形态元数据).
///
/// 不直接持 IrBlock, 而是持 BlockHash 引用 BlockPool 中的 block.
/// 相同内容的 message (相同 role + 相同 block 序列) 物理上共享 block.
///
/// # wire 形态元数据 (content_form / reasoning_content_form)
///
/// 随 message 原样存储, 让 `resolve_message` 重建的 IrMessage 与原始
/// IrMessage **字节级等价** (经同协议 writer 重序列化后一致) — timeline
/// delta 派生 (`derive::extract_delta_messages_from_blocks`) 的等价性根基.
/// 若不存, resolve 后 content 形态回退 None (array), 裸 string content
/// (`"content":"hi"`) 会变成 array 形态, 破坏与 req_body_raw 切片的等价.
#[derive(Debug, Clone)]
pub struct MessageRef {
    pub role: IrRole,
    pub blocks: Vec<BlockHash>,
    /// 原始 wire 的 content 形态 (string / array / null). 见 `IrMessage::content_form`.
    pub content_form: Option<ContentForm>,
    /// assistant 消息 `reasoning_content` 字段的显式空/null 形态 (#176).
    pub reasoning_content_form: Option<ReasoningContentForm>,
    /// message 级未建模字段 (#269 M1/L4, 仅 Anthropic reader 收集; 如 future-proof
    /// 的 message 顶层字段). `None` = 空 — 避免绝大多数无 extra 消息的 Arc 分配.
    /// 语义同 content_form: 随 ref 保存, resolve 恢复, **不参与 hash** (prefix 匹配
    /// 语义 = 内容相等, 同 blocks 不同 wire 元数据的重发视为前缀命中).
    pub extra: Option<Arc<serde_json::Map<String, serde_json::Value>>>,
}

impl MessageRef {
    /// 计算本 message 的 hash (role + blocks 序列).
    ///
    /// 用于 Merkle prefix hash 的累积计算.
    ///
    /// **wire 形态元数据不参与 hash** (content_form / reasoning_content_form /
    /// message extra 同立场): prefix 匹配的语义是 "内容相等" (相同 role + 相同
    /// block 内容); 同内容不同 wire 形态 (string vs array) 的重发视为前缀命中,
    /// 与 hash 语义一致 (历史行为保持).
    pub(super) fn hash(&self) -> u64 {
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
    pub(super) blocks: HashMap<BlockHash, Arc<IrBlock>>,
    pub(super) refcount: HashMap<BlockHash, usize>,
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
    /// 引发难以定位的数据损坏). 详见 AGENTS.md "例外 — DAG 核心数据结构不用 best-effort"
    /// + CDAG-6 契约.
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
    /// 返回的 MessageRef 的 blocks 全部已 intern (refcount 已 ++),
    /// wire 形态元数据 (content_form / reasoning_content_form) 随 ref 保存.
    pub fn intern_message(&mut self, msg: &IrMessage) -> MessageRef {
        MessageRef {
            role: msg.role,
            content_form: msg.content_form,
            reasoning_content_form: msg.reasoning_content_form,
            extra: (!msg.extra.is_empty()).then(|| Arc::new(msg.extra.clone())),
            blocks: msg.content.iter().map(|b| self.intern(b.clone())).collect(),
        }
    }

    /// 按 MessageRef 重建 IrMessage (从池中 deref 所有 block).
    ///
    /// wire 形态元数据从 ref 恢复 (B1); `contains_user_text` 不保留
    /// (push 时一次性消耗, 见 `IrMessage` 文档), 重建后恒 false.
    pub fn resolve_message(&self, msg_ref: &MessageRef) -> Option<IrMessage> {
        let mut blocks = Vec::with_capacity(msg_ref.blocks.len());
        for &h in &msg_ref.blocks {
            blocks.push((*self.get(h)?).clone());
        }
        Some(IrMessage {
            role: msg_ref.role,
            content: blocks,
            content_form: msg_ref.content_form,
            reasoning_content_form: msg_ref.reasoning_content_form,
            // message 级 extra 恢复 (#269): resolve 重建必须与 push 时的原始
            // IrMessage 字节级等价 — 丢弃会让 Anthropic 请求侧 timeline 派生
            // 缺字段, 破坏 DTO-5 (B1 rebase #269 复核 FAIL-2).
            extra: msg_ref
                .extra
                .as_ref()
                .map(|a| (**a).clone())
                .unwrap_or_default(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::ir::{IrBlock, IrMessage, IrRole};

    // ─── BlockPool intern/release 基础性质 ──────────────────────────────────

    #[test]
    fn block_pool_intern_dedupes_identical_blocks() {
        let mut pool = BlockPool::default();
        let b = IrBlock::Text {
            text: "hello".to_string(),
            extra: Default::default(),
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
            extra: Default::default(),
        };
        let h = pool.intern(b);
        assert_eq!(pool.len(), 1);
        pool.release(h);
        assert_eq!(pool.len(), 0, "block removed after refcount hits 0");
        assert!(!pool.refcount.contains_key(&h));
    }

    #[test]
    fn block_pool_release_below_zero_clamped() {
        // saturating_sub 保证 refcount 不会下溢为负.
        let mut pool = BlockPool::default();
        let b = IrBlock::Text {
            text: "hello".to_string(),
            extra: Default::default(),
        };
        let h = pool.intern(b);
        pool.release(h);
        // refcount 已为 0 且 block 已删除; 再次 release 应 no-op (不 panic).
        pool.release(h);
    }

    #[test]
    fn block_pool_is_empty_and_default() {
        let pool = BlockPool::default();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn block_pool_intern_message_creates_refs() {
        let mut pool = BlockPool::default();
        let msg = IrMessage {
            role: IrRole::User,
            content: vec![
                IrBlock::Text {
                    text: "a".to_string(),
                    extra: Default::default(),
                },
                IrBlock::Text {
                    text: "b".to_string(),
                    extra: Default::default(),
                },
            ],
            ..Default::default()
        };
        let msg_ref = pool.intern_message(&msg);
        assert_eq!(msg_ref.role, IrRole::User);
        assert_eq!(msg_ref.blocks.len(), 2);
        assert_eq!(pool.len(), 2, "two distinct blocks interned");
    }

    #[test]
    fn block_pool_resolve_message_roundtrips() {
        let mut pool = BlockPool::default();
        let msg = IrMessage {
            role: IrRole::Assistant,
            content: vec![IrBlock::Text {
                text: "hi".to_string(),
                extra: Default::default(),
            }],
            ..Default::default()
        };
        let msg_ref = pool.intern_message(&msg);
        let resolved = pool.resolve_message(&msg_ref).expect("should resolve");
        assert_eq!(resolved.role, IrRole::Assistant);
        assert_eq!(resolved.content.len(), 1);
        match &resolved.content[0] {
            IrBlock::Text { text, .. } => assert_eq!(text, "hi"),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn block_pool_dedupes_shared_blocks_across_messages() {
        // 两条 message 共享一个 Text block → pool 应只有 1 个 block, refcount=2.
        let mut pool = BlockPool::default();
        let shared = IrBlock::Text {
            text: "shared".to_string(),
            extra: Default::default(),
        };
        let m1 = IrMessage {
            role: IrRole::User,
            content: vec![shared.clone()],
            ..Default::default()
        };
        let m2 = IrMessage {
            role: IrRole::Assistant,
            content: vec![shared],
            ..Default::default()
        };
        let r1 = pool.intern_message(&m1);
        let r2 = pool.intern_message(&m2);
        assert_eq!(r1.blocks, r2.blocks, "shared block → same hash");
        assert_eq!(pool.len(), 1);
        assert_eq!(*pool.refcount.get(&r1.blocks[0]).unwrap(), 2);
    }

    // ─── 各 IrBlock variant 的 intern/resolve round-trip ───────────────────
    //
    // 覆盖所有 IrBlock variant: Text / ToolUse / ToolResult / Image / Reasoning.
    // 这是 CDAG-2 (round-trip identity) 的 variant-by-variant 守卫.

    #[test]
    fn dag_block_tooluse_intern_resolve_roundtrip() {
        let mut pool = BlockPool::default();
        let input = serde_json::json!({"path": "/tmp", "mode": "rw"});
        let block = IrBlock::ToolUse {
            id: "call_1".to_string(),
            name: "read_file".to_string(),
            input: input.clone(),
            extra: Default::default(),
        };
        let h = pool.intern(block.clone());
        let got = pool.get(h).expect("interned");
        match &*got {
            IrBlock::ToolUse {
                id, name, input: i, ..
            } => {
                assert_eq!(id, "call_1");
                assert_eq!(name, "read_file");
                assert_eq!(i, &input);
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
    }

    #[test]
    fn dag_block_tooluse_dedupes_identical_input() {
        let mut pool = BlockPool::default();
        let input = serde_json::json!({"k": 1});
        let b1 = IrBlock::ToolUse {
            id: "x".into(),
            name: "n".into(),
            input: input.clone(),
            extra: Default::default(),
        };
        let b2 = IrBlock::ToolUse {
            id: "x".into(),
            name: "n".into(),
            input,
            extra: Default::default(),
        };
        let h1 = pool.intern(b1);
        let h2 = pool.intern(b2);
        assert_eq!(h1, h2, "identical ToolUse → same hash");
        assert_eq!(*pool.refcount.get(&h1).unwrap(), 2);
    }

    #[test]
    fn dag_block_tooluse_canonical_json_key_order_invariant() {
        // serde_json::Value 用 BTreeMap → key 字母排序 → {"a":1,"b":2} 与 {"b":2,"a":1} hash 相同.
        let mut pool = BlockPool::default();
        let b1 = IrBlock::ToolUse {
            id: "x".into(),
            name: "n".into(),
            input: serde_json::json!({"a": 1, "b": 2}),
            extra: Default::default(),
        };
        let b2 = IrBlock::ToolUse {
            id: "x".into(),
            name: "n".into(),
            input: serde_json::json!({"b": 2, "a": 1}),
            extra: Default::default(),
        };
        let h1 = pool.intern(b1);
        let h2 = pool.intern(b2);
        assert_eq!(h1, h2, "canonical JSON key order → same hash");
    }

    #[test]
    fn dag_block_tooluse_distinct_input_distinct_hash() {
        let mut pool = BlockPool::default();
        let b1 = IrBlock::ToolUse {
            id: "x".into(),
            name: "n".into(),
            input: serde_json::json!({"k": 1}),
            extra: Default::default(),
        };
        let b2 = IrBlock::ToolUse {
            id: "x".into(),
            name: "n".into(),
            input: serde_json::json!({"k": 2}),
            extra: Default::default(),
        };
        let h1 = pool.intern(b1);
        let h2 = pool.intern(b2);
        assert_ne!(h1, h2, "distinct input → distinct hash");
    }

    #[test]
    fn dag_block_toolresult_flat_intern_resolve() {
        let mut pool = BlockPool::default();
        let block = IrBlock::ToolResult {
            tool_use_id: "call_1".to_string(),
            content: vec![IrBlock::Text {
                text: "result".to_string(),
                extra: Default::default(),
            }],
            is_error: None,
            content_form: None,
            extra: Default::default(),
        };
        let h = pool.intern(block.clone());
        let got = pool.get(h).expect("interned");
        match &*got {
            IrBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
                ..
            } => {
                assert_eq!(tool_use_id, "call_1");
                assert_eq!(is_error, &None);
                assert_eq!(content.len(), 1);
            }
            other => panic!("expected ToolResult, got {other:?}"),
        }
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
                extra: Default::default(),
            }],
            is_error: None,
            content_form: None,
            extra: Default::default(),
        };
        let h = pool.intern(nested.clone());
        let resolved = pool.get(h).expect("interned");
        assert_eq!(*resolved, nested, "嵌套 ToolResult round-trip 严格相等");
    }

    #[test]
    fn dag_block_toolresult_is_error_affects_hash() {
        let mut pool = BlockPool::default();
        let mk = |err: bool| IrBlock::ToolResult {
            tool_use_id: "c".into(),
            content: vec![IrBlock::Text {
                text: "x".into(),
                extra: Default::default(),
            }],
            is_error: Some(err),
            content_form: None,
            extra: Default::default(),
        };
        let h_ok = pool.intern(mk(false));
        let h_err = pool.intern(mk(true));
        assert_ne!(h_ok, h_err, "is_error flag must affect hash");
    }

    #[test]
    fn dag_block_toolresult_recursion_seen_in_pool() {
        // 嵌套 content 中的子 block 不单独 intern 到池中 (顶层原子单元).
        // 此测试固化该行为: 池中只有 1 个 block (整个 ToolResult), 子 Text 不单独入池.
        let mut pool = BlockPool::default();
        let child = IrBlock::Text {
            text: "child".into(),
            extra: Default::default(),
        };
        let parent = IrBlock::ToolResult {
            tool_use_id: "c1".into(),
            content: vec![child],
            is_error: None,
            content_form: None,
            extra: Default::default(),
        };
        let _h = pool.intern(parent);
        assert_eq!(pool.len(), 1, "嵌套子 block 不单独入池 (顶层原子单元)");
    }

    #[test]
    fn dag_block_image_base64_intern_resolve() {
        let mut pool = BlockPool::default();
        let block = IrBlock::Image {
            source: IrImageSource::Base64 {
                media_type: "image/png".to_string(),
                data: "iVBORw0KGgo=".to_string(),
            },
            extra: Default::default(),
        };
        let h = pool.intern(block);
        let got = pool.get(h).expect("interned");
        match &*got {
            IrBlock::Image {
                source: IrImageSource::Base64 { media_type, data },
                ..
            } => {
                assert_eq!(media_type, "image/png");
                assert_eq!(data, "iVBORw0KGgo=");
            }
            other => panic!("expected Image Base64, got {other:?}"),
        }
    }

    #[test]
    fn dag_block_image_url_intern_resolve() {
        let mut pool = BlockPool::default();
        let block = IrBlock::Image {
            source: IrImageSource::Url("https://example.com/x.png".to_string()),
            extra: Default::default(),
        };
        let h = pool.intern(block);
        let got = pool.get(h).expect("interned");
        match &*got {
            IrBlock::Image {
                source: IrImageSource::Url(u),
                ..
            } => assert_eq!(u, "https://example.com/x.png"),
            other => panic!("expected Image Url, got {other:?}"),
        }
    }

    #[test]
    fn dag_block_image_base64_distinct_from_url_hash() {
        let mut pool = BlockPool::default();
        let b1 = IrBlock::Image {
            source: IrImageSource::Base64 {
                media_type: "image/png".into(),
                data: "data".into(),
            },
            extra: Default::default(),
        };
        let b2 = IrBlock::Image {
            source: IrImageSource::Url("data".into()),
            extra: Default::default(),
        };
        let h1 = pool.intern(b1);
        let h2 = pool.intern(b2);
        assert_ne!(h1, h2, "Base64 vs Url variants must hash distinctly");
    }

    #[test]
    fn dag_block_cross_variant_no_collision() {
        // 不同 variant 的 block 即便字段值相同 (例如 Text "x" vs ToolUse id="x"), hash 必须不同.
        let mut pool = BlockPool::default();
        let text = IrBlock::Text {
            text: "x".into(),
            extra: Default::default(),
        };
        let tool = IrBlock::ToolUse {
            id: "x".into(),
            name: "x".into(),
            input: serde_json::json!("x"),
            extra: Default::default(),
        };
        let ht = pool.intern(text);
        let hu = pool.intern(tool);
        assert_ne!(ht, hu, "cross-variant must not collide (discriminant tag)");
    }

    #[test]
    fn dag_block_message_with_mixed_variants_roundtrips() {
        let mut pool = BlockPool::default();
        let msg = IrMessage {
            role: IrRole::Assistant,
            content: vec![
                IrBlock::Text {
                    text: "thinking".into(),
                    extra: Default::default(),
                },
                IrBlock::ToolUse {
                    id: "c1".into(),
                    name: "do".into(),
                    input: serde_json::json!({"x": 1}),
                    extra: Default::default(),
                },
            ],
            ..Default::default()
        };
        let r = pool.intern_message(&msg);
        let resolved = pool.resolve_message(&r).expect("should resolve");
        assert_eq!(resolved.content.len(), 2);
        match &resolved.content[0] {
            IrBlock::Text { text, .. } => assert_eq!(text, "thinking"),
            other => panic!("expected Text, got {other:?}"),
        }
    }
}
