//! 会话文本搜索 (#317): 服务端扫描 + Block 级 memoize (零索引冷启动).
//!
//! # 职责边界
//!
//! 本模块实现 [`ConversationDag::search`] — 按文本子串定位 (会话, 轮次):
//! - **搜索范围** (决策点①默认): 仅请求侧文本 = 各 Node 的 `req_delta` messages
//!   (真实内容, OriginRecord 视角). 不含 response (决策点②范围减半的理由) 与
//!   根节点 system_refs (通常是 boilerplate; 扩展只需在 walk 处加一段).
//! - **匹配语义** (决策点③默认): 大小写不敏感子串 (`to_lowercase` 后 `find`),
//!   匹配必须落在**单个文本叶子内** — 跨叶子/跨 block 不拼接 (query "foobar"
//!   不命中叶子 "foo" + "bar").
//! - 文本叶子提取见 [`text_leaves`]: Text.text / ToolUse.name + input 的 JSON
//!   字符串值 / ToolResult 嵌套 content / Reasoning.summary / ReasoningContent.text;
//!   **Image 不参与** (base64 是无语义大 blob, 进扫描面会炸预算).
//!
//! # 性能设计 (issue #317 红线: 不引入性能问题)
//!
//! - **Block 级双层去重**: BlockPool 内容寻址 (相同 block 物理一份) +
//!   [`BlockPool::search_cache`] 的 lowercase 记忆化 — 稳态下每个唯一 block
//!   只付一次 `to_lowercase` 成本, 对话前缀复用 (增量会话的主体) 免付;
//!   查询期纯内存子串扫描.
//! - **per-query 扫描记忆**: 单次查询内 `scanned: HashMap<BlockHash, Option<..>>`
//!   保证每个唯一 block 只 `find` 一次 — fork 共享祖先链的场景同一 block 被
//!   多个 session 的 walk 触达, 命中信息 (而非跳过) 被复用, 保证每个 walked
//!   session 都得到自己的 hit (跳转语义正确).
//! - **结果 cap** ([`MAX_HITS`]): 达到即停, `truncated=true`.
//! - **扫描预算** ([`SEARCH_BUDGET`]): deadline 双粒度检查 (逐 node + 逐未扫描
//!   block — 后者覆盖缓存全命中的纯查找 walk), 超时即停并 `truncated=true` —
//!   best-effort 红线 (ROB 纪律: 搜索是增强, 不许拖垮转发/`/api/sync`). 整个扫描持
//!   `inner.read()` 锁, 预算同时是**写锁 starving 的上界** (parking_lot task-fair:
//!   pending writer 阻塞新 reader, 已持锁的 reader 最长持锁 ≈ 预算 + 单 block
//!   处理时长).
//!
//! # 排序与去重
//!
//! session 按 `latest_at` 降序 (与 sync_snapshot 一致, tie → session_id),
//! session 内轮次 newest-first (leaf→root) — 整体呈 "最近会话优先". 一个 Node
//! 至多一条 hit (delta 中首个命中 block 胜出): 搜索目标是定位轮次而非穷举位置.
//!
//! # ROB
//!
//! 查询路径永不 panic: 空/超长 query 在 web 层 400 (本层对空 query 返回空
//! 结果防御), block resolve 失败按 "无文本" 处理 (skip), snippet 提取全程
//! char-boundary 安全.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::codec::ir::{IrBlock, IrRole};
use crate::dto::{SearchHit, SearchResponse};

use super::pool::BlockHash;
use super::timeline::walk_chain;
use super::{ConversationDag, DagInner, Session, SessionId};

/// 结果数 cap: 达到即停止扫描 (`truncated=true`, 可能还有更多命中).
pub(crate) const MAX_HITS: usize = 200;

/// 单次查询的扫描预算 (red line): 逐 block 检查 deadline, 超时返回部分结果.
///
/// 50ms 的量纲依据: 草案实测预期万级 node <50ms — 预算取同量级, 让典型查询
/// 天然完成、病态数据 (巨型文本叶) 被硬性截断.
pub(crate) const SEARCH_BUDGET: Duration = Duration::from_millis(50);

/// snippet 中命中点前后各取的字符预算.
const SNIPPET_RADIUS: usize = 40;

/// 单个 block 内的首个命中位置 (lowercase 叶子的下标 + 字节偏移).
#[derive(Debug, Clone, Copy)]
struct LeafMatch {
    leaf: usize,
    /// 命中起点在 lowercase 叶子中的字节偏移 (等长快路径下与原文偏移一致).
    pos: usize,
}

impl ConversationDag {
    /// 会话文本搜索 (#317): 大小写不敏感子串, 返回 (session, node) 命中列表.
    ///
    /// 生产入口 (预算 = `SEARCH_BUDGET`, cap = `MAX_HITS`); 测试可用
    /// `search_with_deadline` 注入确定性 deadline. 空/纯空白 query 返回空结果
    /// (web 层已 400, 此处防御).
    pub fn search(&self, query: &str) -> SearchResponse {
        self.search_with_deadline(query, Instant::now() + SEARCH_BUDGET)
    }

    /// 带显式 deadline 的搜索 (测试注入点; 语义同 [`Self::search`]).
    pub(crate) fn search_with_deadline(&self, query: &str, deadline: Instant) -> SearchResponse {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return SearchResponse {
                hits: Vec::new(),
                truncated: false,
            };
        }
        let g = self.inner.read();
        let mut sessions: Vec<(&SessionId, &Session)> = g.sessions.iter().collect();
        // latest-first (与 sync_snapshot 同序): 最近会话的命中排前面.
        sessions.sort_by_key(|p| std::cmp::Reverse((p.1.latest_at, *p.0)));

        let mut scanned: HashMap<BlockHash, Option<LeafMatch>> = HashMap::new();
        let mut hits: Vec<SearchHit> = Vec::new();
        let mut truncated = false;

        'outer: for (&sid, session) in sessions {
            // walk_chain 返回 oldest-first; 搜索要 newest-first → 反向遍历.
            let chain = walk_chain(&g, session.leaf_id, usize::MAX);
            for &nid in chain.iter().rev() {
                // 预算检查 (node 粒度): 覆盖 "全部 block 已缓存" 的纯查找 walk —
                // miss 粒度的检查 (下方) 只覆盖新扫描, 缓存命中的长链遍历在此兜底.
                if Instant::now() >= deadline {
                    truncated = true;
                    break 'outer;
                }
                let Some(node) = g.nodes.get(&nid) else {
                    continue;
                };
                // node 内首个命中 block → 唯一 hit (一轮一 hit). LeafMatch 随
                // found 携带, 免二次 map 查找 (也更不存在 "found 但无 match" 分支).
                let mut found: Option<(IrRole, BlockHash, LeafMatch)> = None;
                'msgs: for msg in node.req_delta.iter() {
                    for &h in msg.blocks.iter() {
                        let m = match scanned.get(&h) {
                            Some(&m) => m,
                            None => {
                                // 首次触达该 block: 预算检查 + 扫描 + 记忆.
                                if Instant::now() >= deadline {
                                    truncated = true;
                                    break 'outer;
                                }
                                let m = lower_texts(&g, h)
                                    .as_deref()
                                    .and_then(|texts| first_match(texts, &q));
                                scanned.insert(h, m);
                                m
                            }
                        };
                        if let Some(m) = m {
                            found = Some((msg.role, h, m));
                            break 'msgs;
                        }
                    }
                }
                let Some((role, h, m)) = found else { continue };
                hits.push(SearchHit {
                    session_id: sid,
                    node_id: nid,
                    role,
                    preview: node.event.preview.clone(),
                    // snippet 只对记录的 ≤MAX_HITS 条支付原文提取成本.
                    snippet: hit_snippet(&g, h, m, &q),
                    created_at: node.event.created_at,
                });
                if hits.len() >= MAX_HITS {
                    // 未继续扫描剩余候选 → 如实报告 "可能还有更多".
                    truncated = true;
                    break 'outer;
                }
            }
        }
        SearchResponse { hits, truncated }
    }
}

/// 取 block 的 lowercase 文本叶子 (BlockPool.search_cache get-or-insert).
///
/// 池外 hash (池损坏, 理论不可达) → None. 提取在锁外做, 锁只护 map 读写
/// (并发双 miss 双算无害, 后写覆盖同值).
fn lower_texts(g: &DagInner, h: BlockHash) -> Option<Arc<Vec<String>>> {
    if let Some(v) = g.blocks.search_cache.lock().get(&h) {
        return Some(Arc::clone(v));
    }
    let block = g.blocks.get(h)?;
    let mut leaves = Vec::new();
    text_leaves(&block, &mut leaves);
    let texts: Vec<String> = leaves.iter().map(|s| s.to_lowercase()).collect();
    let arc = Arc::new(texts);
    g.blocks.search_cache.lock().insert(h, Arc::clone(&arc));
    Some(arc)
}

/// 叶子序列中的首个子串命中 (`to_lowercase` 域内).
fn first_match(texts: &[String], q: &str) -> Option<LeafMatch> {
    for (i, t) in texts.iter().enumerate() {
        if t.len() < q.len() {
            continue;
        }
        if let Some(pos) = t.find(q) {
            return Some(LeafMatch { leaf: i, pos });
        }
    }
    None
}

/// 构造 hit 的 snippet (只对记录的 ≤[`MAX_HITS`] 条支付原文提取成本).
///
/// `q` = 已 lowercase 的 query (匹配段长度 = `q.len()`, 由 find 语义保证).
/// 命中叶子的原文: 重新提取该 block 的叶子序列, 按下标取. 假设: 同一 block 的
/// 提取序确定 (纯函数遍历), 与缓存构建序一致; 不成立时 (理论不可达) snippet
/// 退化为空串, 永不 panic (ROB).
fn hit_snippet(g: &DagInner, h: BlockHash, m: LeafMatch, q: &str) -> String {
    g.blocks
        .get(h)
        .and_then(|b| {
            let mut orig = Vec::new();
            text_leaves(&b, &mut orig);
            orig.get(m.leaf)
                .map(|leaf| snippet_around(leaf, &leaf.to_lowercase(), m.pos, q.len()))
        })
        .unwrap_or_default()
}

/// 从命中叶子原文截取上下文窗口 (前后各 [`SNIPPET_RADIUS`] chars, "…" 标记截断).
///
/// 假设: `orig.len() == lower.len()` **且** `pos` / `pos + qlen` 在原文中也是 char
/// boundary (to_lowercase 未改变字节布局 — 全 ASCII 与绝大多数文本成立) 时,
/// lowercase 中的字节区间可直接映射回原文. 长度相等但布局漂移 (罕见 case-folding
/// 组合, 如 'Å' 3→2 与 'İ' 2→3 净长度相抵) 会被 boundary 守卫拦下.
/// 降级 (长度不等 / boundary 不对齐): 偏移不可映射 → 取叶子头部, 永不 panic.
fn snippet_around(orig: &str, lower: &str, pos: usize, qlen: usize) -> String {
    if orig.len() == lower.len() && orig.is_char_boundary(pos) && orig.is_char_boundary(pos + qlen)
    {
        let pre = &orig[..pos];
        let post = &orig[pos + qlen..];
        let start = pre
            .char_indices()
            .rev()
            .nth(SNIPPET_RADIUS)
            .map(|(i, _)| i)
            .unwrap_or(0);
        let end = post
            .char_indices()
            .nth(SNIPPET_RADIUS)
            .map(|(i, _)| pos + qlen + i)
            .unwrap_or(orig.len());
        let mut s = String::new();
        if start > 0 {
            s.push('…');
        }
        s.push_str(&orig[start..end]);
        if end < orig.len() {
            s.push('…');
        }
        return s;
    }
    let mut s: String = orig.chars().take(2 * SNIPPET_RADIUS).collect();
    if s.chars().count() == 2 * SNIPPET_RADIUS {
        s.push('…');
    }
    s
}

/// 提取 block 的文本叶子 (原文, 保持确定序 — 缓存与 snippet 共用该序).
///
/// Image 不参与 (见模块头). 嵌套 JSON 只取字符串**值** (键是结构元数据).
fn text_leaves(block: &IrBlock, out: &mut Vec<String>) {
    match block {
        IrBlock::Text { text, .. } => out.push(text.clone()),
        IrBlock::ToolUse { name, input, .. } => {
            out.push(name.clone());
            json_string_leaves(input, out);
        }
        IrBlock::ToolResult { content, .. } => {
            for c in content {
                text_leaves(c, out);
            }
        }
        IrBlock::Image { .. } => {}
        IrBlock::Reasoning { summary, .. } => {
            out.extend(summary.iter().cloned());
        }
        IrBlock::ReasoningContent { text, .. } => out.push(text.clone()),
    }
}

fn json_string_leaves(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => {
            for x in a {
                json_string_leaves(x, out);
            }
        }
        serde_json::Value::Object(o) => {
            for x in o.values() {
                json_string_leaves(x, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::ir::{IrBlock, IrMessage, IrRole};
    use crate::dag::RoundKind;
    use chrono::{DateTime, TimeZone, Utc};
    use proptest::prelude::*;

    // ─── fixtures (与 dag/mod.rs tests 同型; 子模块独立 tests 先例见 pool.rs) ──

    fn text_msg(role: IrRole, text: &str) -> IrMessage {
        IrMessage {
            role,
            content: vec![IrBlock::Text {
                text: text.to_string(),
                extra: Default::default(),
            }],
            ..Default::default()
        }
    }

    fn ev_at(ts: DateTime<Utc>) -> crate::dag::CallEvent {
        crate::dag::CallEvent {
            created_at: ts,
            method: "POST".to_string(),
            path: "/o/test/v1/chat".to_string(),
            req_headers: vec![],
            ingress_protocol: None,
            redact_seed: 0,
            req_system: vec![],
            policy: Arc::new(crate::dag::PolicySnapshot::default()),
            req_body_raw: String::new(),
            round_role: IrRole::User,
            round_kind: RoundKind::Normal,
            preview: None,
            model: None,
            upstream_id: Arc::from("test"),
            redactions: Arc::from([]),
            upstream_model: None,
            capture_mode: crate::config::AuditCaptureMode::Full,
        }
    }

    fn ev() -> crate::dag::CallEvent {
        ev_at(Utc::now())
    }

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    // ─── 命中正确性 ─────────────────────────────────────────────────────────

    #[test]
    fn search_case_insensitive_substring_hit() {
        let dag = ConversationDag::default();
        let id = dag.push_messages(
            vec![text_msg(IrRole::User, "Hello SearchWorld Marker end")],
            ev(),
        );
        // 小写 query 命中大写原文 (大小写不敏感).
        let r = dag.search("searchworld");
        assert_eq!(r.hits.len(), 1);
        assert_eq!(r.hits[0].node_id, id);
        assert_eq!(r.hits[0].role, IrRole::User);
        assert!(!r.truncated);
        // snippet 保留原文大小写.
        assert!(
            r.hits[0].snippet.contains("SearchWorld"),
            "snippet keeps original case: {}",
            r.hits[0].snippet
        );
        // 反向: 大写 query 命中小写原文.
        let msg = text_msg(IrRole::User, "lowercase needle here");
        let dag2 = ConversationDag::default();
        dag2.push_messages(vec![msg], ev());
        assert_eq!(dag2.search("NEEDLE").hits.len(), 1);
    }

    #[test]
    fn search_no_cross_leaf_join() {
        let dag = ConversationDag::default();
        let msg = IrMessage {
            role: IrRole::User,
            content: vec![
                IrBlock::Text {
                    text: "foo".into(),
                    extra: Default::default(),
                },
                IrBlock::Text {
                    text: "bar".into(),
                    extra: Default::default(),
                },
            ],
            ..Default::default()
        };
        dag.push_messages(vec![msg], ev());
        // 叶子 "foo" + "bar" 不拼接: 跨叶子 query 不命中 (决策点③: 匹配落在单叶内).
        assert_eq!(
            dag.search("foobar").hits.len(),
            0,
            "cross-leaf join must not match"
        );
        assert_eq!(
            dag.search("obar").hits.len(),
            0,
            "cross-leaf join must not match"
        );
        assert_eq!(dag.search("foo").hits.len(), 1);
        assert_eq!(dag.search("bar").hits.len(), 1);
    }

    #[test]
    fn search_empty_query_returns_empty() {
        let dag = ConversationDag::default();
        dag.push_messages(vec![text_msg(IrRole::User, "anything")], ev());
        for q in ["", "   ", "\t\n"] {
            let r = dag.search(q);
            assert!(r.hits.is_empty(), "q={q:?}");
            assert!(!r.truncated, "empty query completes trivially: q={q:?}");
        }
    }

    #[test]
    fn search_covers_tooluse_name_and_input_json_strings() {
        let dag = ConversationDag::default();
        let msg = IrMessage {
            role: IrRole::Assistant,
            content: vec![IrBlock::ToolUse {
                id: "call_1".into(),
                name: "deploy_svc".into(),
                input: serde_json::json!({"path": "/srv/app", "nested": {"host": "web-1"}}),
                extra: Default::default(),
            }],
            ..Default::default()
        };
        dag.push_messages(vec![msg], ev());
        assert_eq!(
            dag.search("deploy_svc").hits.len(),
            1,
            "tool name is a text leaf"
        );
        assert_eq!(
            dag.search("/srv/app").hits.len(),
            1,
            "input string values are leaves"
        );
        assert_eq!(
            dag.search("web-1").hits.len(),
            1,
            "nested string values are leaves"
        );
        assert_eq!(
            dag.search("path").hits.len(),
            0,
            "JSON keys are structural, not leaves"
        );
        assert_eq!(
            dag.search("call_1").hits.len(),
            0,
            "tool call id is noise, not a leaf"
        );
    }

    #[test]
    fn search_ignores_image_blocks() {
        let dag = ConversationDag::default();
        let msg = IrMessage {
            role: IrRole::User,
            content: vec![IrBlock::Image {
                source: crate::codec::ir::IrImageSource::Base64 {
                    media_type: "image/png".into(),
                    data: "aE9SRU5FTE9DS0VE".into(), // "NEEDLE" 混排的 base64 形状
                },
                extra: Default::default(),
            }],
            ..Default::default()
        };
        dag.push_messages(vec![msg], ev());
        assert_eq!(
            dag.search("aE9SRU5FTE9DS0VE").hits.len(),
            0,
            "image payload must not enter the scan surface"
        );
    }

    #[test]
    fn search_newest_session_first_ordering() {
        // 显式 created_at 驱动 latest_at, 让排序确定 (时钟精度不足时 tie 不可控).
        let dag = ConversationDag::default();
        let older = dag.push_messages(
            vec![text_msg(IrRole::User, "ordering needle old")],
            ev_at(ts(0)),
        );
        let newer = dag.push_messages(
            vec![text_msg(IrRole::User, "ordering needle new")],
            ev_at(ts(10)),
        );
        let r = dag.search("ordering needle");
        assert_eq!(r.hits.len(), 2);
        assert_eq!(r.hits[0].node_id, newer, "latest session's hit comes first");
        assert_eq!(r.hits[1].node_id, older);
    }

    #[test]
    fn search_shared_block_attributed_to_both_fork_sessions() {
        // fork 场景: 同一祖先 node 出现在两个 session 的链上, 且其 block 物理共享.
        // per-query 扫描记忆复用 "命中信息" 而非跳过 → 两个 session 各得一条 hit.
        let dag = ConversationDag::default();
        let base = vec![
            text_msg(IrRole::User, "fork-base"),
            text_msg(IrRole::User, "fork-needle"),
        ];
        dag.push_messages(base.clone(), ev_at(ts(0)));
        // 延续 (leaf → 同 session) + 分叉 (parent 非当前 leaf → 新 session).
        dag.push_messages(
            [base.clone(), vec![text_msg(IrRole::User, "left")]].concat(),
            ev_at(ts(1)),
        );
        dag.push_messages(
            [base, vec![text_msg(IrRole::User, "right")]].concat(),
            ev_at(ts(2)),
        );
        let r = dag.search("fork-needle");
        assert_eq!(
            r.hits.len(),
            2,
            "both fork sessions attribute the shared node"
        );
        let sids: Vec<_> = r.hits.iter().map(|h| h.session_id).collect();
        assert_ne!(sids[0], sids[1]);
        // 两条 hit 指向同一个祖先 node.
        assert_eq!(r.hits[0].node_id, r.hits[1].node_id);
    }

    #[test]
    fn search_snippet_boundary_mismatch_never_panics() {
        // case-folding 净长度相抵但布局漂移的组合 ('Å' U+212B 3→2 bytes 与
        // 'İ' U+0130 2→3 bytes): orig 与 lower 等长, 但 lower 的 byte-2 边界
        // ('i' 起点) 在 orig 中是 Å 的第 2 字节 — 等长快路径若无 boundary 守卫
        // 会切片 panic (ROB 违例; 精雕细琢 review 发现). 守卫须拦下并降级为
        // 叶子头部窗口.
        let orig = "\u{212B}\u{130}tail";
        let lower = orig.to_lowercase();
        assert_eq!(orig.len(), lower.len(), "fixture must net equal lengths");
        assert!(lower.is_char_boundary(2), "byte 2 is a boundary in lower");
        assert!(
            !orig.is_char_boundary(2),
            "byte 2 is NOT a boundary in orig"
        );
        let s = snippet_around(orig, &lower, 2, 1);
        // 降级 = 叶子头部窗口 (短叶不截断, 原样返回).
        assert_eq!(s, orig, "fallback takes head-of-leaf window");
    }

    // ─── 性能红线: cap + 预算 ───────────────────────────────────────────────

    #[test]
    fn search_hits_capped_at_max_with_truncated() {
        let dag = ConversationDag::new(4096, 5000, 1);
        for i in 0..(MAX_HITS + 5) {
            dag.push_messages(
                vec![text_msg(IrRole::User, &format!("cap-needle #{i}"))],
                ev_at(ts(i as i64)),
            );
        }
        let r = dag.search("cap-needle");
        assert_eq!(r.hits.len(), MAX_HITS, "hits capped at MAX_HITS");
        assert!(r.truncated, "cap reached → truncated (may be more matches)");
        // cap 序 = recency 序: 最新的 200 条 (最新在前).
        assert!(r.hits[0].snippet.contains(&format!("#{}", MAX_HITS + 4)));
    }

    #[test]
    fn search_expired_deadline_truncated_partial() {
        // 预算红线 (确定性形态): 已过期的 deadline + 非空 DAG → 首个未扫描 block
        // 即停, truncated=true; 空 DAG → 无候选可扫, truncated=false.
        let dag = ConversationDag::default();
        dag.push_messages(vec![text_msg(IrRole::User, "budget needle")], ev());
        let r = dag.search_with_deadline("budget needle", Instant::now() - Duration::from_secs(1));
        assert!(r.truncated, "expired deadline on non-empty DAG → truncated");
        assert!(r.hits.is_empty(), "stopped before first scan");

        let empty = ConversationDag::default();
        let r2 = empty.search_with_deadline("x", Instant::now() - Duration::from_secs(1));
        assert!(!r2.truncated, "nothing to scan → completed");
        // 宽裕 deadline 下正常完成 (对照).
        let r3 = dag.search("budget needle");
        assert_eq!(r3.hits.len(), 1);
        assert!(!r3.truncated);
    }

    #[test]
    fn search_concurrent_with_push_completes() {
        // 共享读锁的并发冒烟: 搜索与 push 并行, 无死锁/panic, 且 push 的内容
        // 最终可被搜索到 ("搜索不阻塞写入路径, 写入不丢搜索可见性" 的 e2e 形态).
        let dag = ConversationDag::new(4096, 5000, 1);
        dag.push_messages(vec![text_msg(IrRole::User, "concurrent base")], ev());
        let dag_w = dag.clone();
        let writer = std::thread::spawn(move || {
            for i in 0..50 {
                dag_w.push_messages(
                    vec![text_msg(IrRole::User, &format!("concurrent push {i}"))],
                    ev(),
                );
            }
        });
        let dag_s = dag.clone();
        let searcher = std::thread::spawn(move || {
            for _ in 0..50 {
                let r = dag_s.search("concurrent");
                assert!(r.hits.len() <= MAX_HITS);
            }
        });
        writer.join().expect("writer thread must not deadlock");
        searcher.join().expect("searcher thread must not deadlock");
        let r = dag.search("concurrent push 49");
        assert_eq!(r.hits.len(), 1, "final state searchable after concurrency");
    }

    // ─── lowercase 缓存生命周期 ─────────────────────────────────────────────

    #[test]
    fn search_cache_purged_when_block_released() {
        // max_nodes=2: 第 3 个 session push 触发 LRU 淘汰最旧 session → 其 block
        // refcount 归零被 release → search_cache 同步清除 (防 hash 复用后陈旧命中).
        let dag = ConversationDag::new(2, 500, 1);
        let id = dag.push_messages(
            vec![text_msg(IrRole::User, "cache-purge-needle")],
            ev_at(ts(0)),
        );
        let h = {
            let g = dag.inner.read();
            let node = g.nodes.get(&id).expect("node exists");
            node.req_delta[0].blocks[0]
        };
        dag.search("cache-purge-needle"); // 填充缓存.
        {
            let g = dag.inner.read();
            assert!(
                g.blocks.search_cache.lock().contains_key(&h),
                "cache populated after first search"
            );
        }
        dag.push_messages(vec![text_msg(IrRole::User, "evictor a")], ev_at(ts(1)));
        dag.push_messages(vec![text_msg(IrRole::User, "evictor b")], ev_at(ts(2)));
        {
            let g = dag.inner.read();
            assert!(
                !g.blocks.search_cache.lock().contains_key(&h),
                "cache entry purged when block released (LRU evict)"
            );
        }
        assert_eq!(
            dag.search("cache-purge-needle").hits.len(),
            0,
            "evicted content unsearchable"
        );
    }

    // ─── property-based ────────────────────────────────────────────────────

    proptest! {
        /// 大小写翻转子串必命中: query 取自某叶子的连续子串并整体翻转大小写 →
        /// 该 node 必在 hits 中 (匹配语义 = to_lowercase 后子串).
        #[test]
        fn prop_search_finds_case_flipped_substring(
            prefix in "[a-zA-Z0-9 ]{0,40}",
            needle in "[a-zA-Z0-9]{1,20}",
            suffix in "[a-zA-Z0-9 ]{0,40}",
        ) {
            let full = format!("{prefix}{needle}{suffix}");
            let flipped: String = needle.chars().map(|c| if c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }).collect();
            let dag = ConversationDag::default();
            let id = dag.push_messages(vec![text_msg(IrRole::User, &full)], ev());
            let r = dag.search(&flipped);
            prop_assert!(
                r.hits.iter().any(|h| h.node_id == id),
                "case-flipped substring {:?} of {:?} must hit its node", flipped, full
            );
        }

        /// 不存在于任何叶子的 query 零命中: query 字符取自生成器字母表之外的
        /// 字符 ('z'/'Z' 不在 [a-yA-Y] 内), 结构性保证不可能命中.
        #[test]
        fn prop_search_no_hit_for_absent_needle(
            text in "[a-yA-Y0-9 ]{0,200}",
            mid in "[a-yA-Y]{0,20}",
        ) {
            let full = format!("{text}{mid}{text}");
            let dag = ConversationDag::default();
            dag.push_messages(vec![text_msg(IrRole::User, &full)], ev());
            let r = dag.search("zZzZ");
            prop_assert!(r.hits.is_empty(), "query from absent alphabet must not hit");
            prop_assert!(!r.truncated);
        }
    }
}
