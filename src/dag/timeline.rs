//! session-aware timeline 视图构造 (session_rounds / timeline_view / timeline_diff / sync_snapshot).
//!
//! # 职责边界
//!
//! 本模块构造 WebUI timeline 三条查询路径的视图 (均持 `&DagInner` 读视图):
//! - [`ConversationDag::session_rounds`]: sidebar 三级菜单的轻量摘要 (RoundBrief).
//! - [`ConversationDag::timeline_view`]: timeline 初始加载 + 向前翻页 (TimelinePage).
//! - [`ConversationDag::timeline_diff`]: sync 轮询的 diff (TimelineDiffData).
//! - [`ConversationDag::sync_snapshot`]: 单锁内采集 sessions + rounds + timeline diff.
//!
//! # 鲁棒性 (ROB-* 纪律)
//!
//! timeline 是 web::api 调用路径, 必须永不 panic. [`build_timeline_round`] 与
//! [`build_timeline_tail`] 的 node 查找失败 (理论持锁不变式下不会发生) 一律返回 `None`
//! 让调用方 skip, 而非 `.expect()`. timeline 少一条 round 远好过 500 panic.

use std::collections::HashMap;

use uuid::Uuid;

use crate::dto::{
    RoundBrief, SyncSnapshot, TimelineDiffData, TimelinePage, TimelineRound, TimelineTail,
};

use super::view::session_view;
use super::{ConversationDag, DagInner, SessionId};

/// 全默认字段的占位 tail (node 无 response 或 查找失败时用).
/// 只填 round_id, 其余字段全默认值 (length=0 / resp_status=0 / ...).
fn empty_tail(round_id: Uuid) -> TimelineTail {
    TimelineTail {
        round_id,
        length: 0,
        resp_status: 0,
        elapsed_ms: 0,
        streamed: false,
        resp_complete: false,
        error: None,
        parsed: None,
    }
}

// ─── walk_chain / build_round_briefs (链遍历, 共享 &DagInner 读视图) ──────────

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
///
/// 持锁不变式: chain 中的 id 在生成时 (walk_chain 出口) 都存在; 但 build 时再次 get
/// 仍可能失败 (理论上持读锁不会并发 evict). 失败的 node 用 `filter_map` 跳过 (ROB-* 降级).
fn build_round_briefs(inner: &DagInner, chain: &[Uuid]) -> Vec<RoundBrief> {
    chain
        .iter()
        .filter_map(|&id| {
            let node = inner.nodes.get(&id)?;
            Some(RoundBrief {
                id: node.id,
                round_role: node.event.round_role,
                round_kind: node.event.round_kind,
                preview: node.event.preview.clone(),
                created_at: node.event.created_at,
            })
        })
        .collect()
}

// ─── build_timeline_round / build_timeline_tail (单 node 视图构造) ───────────

/// 构造一个 TimelineRound (含 req_delta_messages).
///
/// req_delta_messages 从 BlockPool 结构化派生 (B1): req_delta (MessageRef, real
/// 视角) → resolve → real→mock (投影重建映射) → ingress writer 序列化 (+ 根节点
/// system 注入). 与旧 req_body_raw 切片路径逐字节等价 — consistency-check 下由
/// [`crate::derive::assert_delta_view_matches_raw`] shadow 守卫 (VIEW-2),
/// 常驻等价性质 `prop_blocks_derivation_matches_raw` (derive.rs) 守卫.
/// 详见 `derive::extract_delta_messages_from_blocks`.
///
/// # 持锁不变式 + ROB-* 降级
///
/// 调用方传入的 `node_id` 由 walk_chain / session.leaf_id 产生, 全程持 `inner.read()` 锁,
/// evict 不会并发发生. 但仍用 `?` + `Option` 而非 `.expect()`: ROB-* 纪律要求 web::api
/// 路径永不 panic, 即便理论不变式被未来 bug 打破也只少一条 round, 不 500.
fn build_timeline_round(inner: &DagInner, node_id: Uuid) -> Option<TimelineRound> {
    let node = inner.nodes.get(&node_id)?;
    // usage 徽章数据 (usage-stats): 上游回显的 token 用量, None = 无回显.
    let usage = node
        .response
        .read()
        .as_ref()
        .and_then(|r| r.usage.as_ref())
        .map(crate::dto::UsageView::from_ir);
    #[cfg(feature = "consistency-check")]
    crate::derive::assert_delta_view_matches_raw(node, &inner.blocks);
    Some(TimelineRound {
        id: node.id,
        round_role: node.event.round_role,
        round_kind: node.event.round_kind,
        preview: node.event.preview.clone(),
        created_at: node.event.created_at,
        // 实际承载转发的 provider id (#179, 虚拟 endpoint 切换的可观测性).
        upstream_id: std::sync::Arc::clone(&node.event.upstream_id),
        redactions: std::sync::Arc::clone(&node.event.redactions),
        req_delta_messages: crate::derive::extract_delta_messages_from_blocks(node, &inner.blocks),
        usage,
    })
}

/// 构造一个 TimelineTail (response 抽屉数据).
///
/// B1 双态数据源:
/// - **finalize 后** (`response.message` 存在): parsed 从 message ref + 元字段
///   经 ingress writer 派生 (`derive::response_parsed_from_parts`), `length` =
///   派生序列化字节数 — 稳态不再依赖 stored parsed (attach 时已清除, B2 的前置).
/// - **流式进行中** (message 尚缺, ParsedSync 节流写入的 parsed 仍在): 沿用旧
///   行为读 stored parsed (前端实时进度依赖它), `length` = parsed 序列化字节数,
///   fallback 到 raw_resp_body.len().
///
/// # 持锁不变式 + ROB-* 降级
///
/// 同 [`build_timeline_round`]: node 查找失败返回 `None` 而非 panic. 派生内部
/// resolve 失败 (池损坏, 理论不变式下不可达) → fallback stored parsed / raw len.
fn build_timeline_tail(inner: &DagInner, node_id: Uuid) -> Option<TimelineTail> {
    let node = inner.nodes.get(&node_id)?;
    let resp_lock = node.response.read();
    let Some(resp) = resp_lock.as_ref() else {
        return Some(empty_tail(node_id));
    };
    // B1 双态单点 (derive::parsed_view): 流式中读 stored 节流快照, finalize 后
    // 从 message + 元字段派生 (两态互斥, 优先序单点定义).
    let parsed = crate::derive::parsed_view(node, &inner.blocks, resp);
    let length = parsed
        .as_ref()
        .map(|v| v.to_string().len())
        .unwrap_or(resp.raw_resp_body.len());
    Some(TimelineTail {
        round_id: node_id,
        length,
        resp_status: resp.resp_status,
        elapsed_ms: resp.elapsed_ms,
        streamed: resp.streamed,
        resp_complete: resp.resp_complete,
        error: resp.error.clone(),
        parsed,
    })
}

// ─── build_timeline_diff_inner (timeline_diff + sync_snapshot 共用核心) ──────

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
    // tail 查找失败 (理论不变式下 leaf 必存在) → 降级为 None → 整体 None (无变化).
    let tail = build_timeline_tail(inner, session.leaf_id)?;

    // walk_chain 一次, 按 after 三种情况派生 new_chain (避免重复 O(N) 遍历).
    let chain = walk_chain(inner, session.leaf_id, usize::MAX);
    let new_chain: Vec<Uuid> = match after {
        None => chain,
        Some(after_id) => {
            let after_belongs = inner
                .nodes
                .get(&after_id)
                .is_some_and(|n| n.session_id == sid);
            if !after_belongs {
                // after 不属于本 session (前端状态过期) → 全链返回.
                chain
            } else {
                // 取 after_id 之后的 round (不含 after_id 自身).
                chain
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

    // build_timeline_round 失败的 node (理论不应发生) 用 filter_map 跳过 (ROB-* 降级).
    let new_rounds = new_chain
        .iter()
        .filter_map(|&id| build_timeline_round(inner, id))
        .collect();
    Some(TimelineDiffData { new_rounds, tail })
}

// ─── ConversationDag timeline 方法 (impl 扩展) ──────────────────────────────

impl ConversationDag {
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
        // build_timeline_round 失败的 node 用 filter_map 跳过 (ROB-* 降级).
        let rounds: Vec<TimelineRound> = chain
            .iter()
            .filter_map(|&id| build_timeline_round(&g, id))
            .collect();
        // chain oldest-first, 末轮 (链中最新) = chain 最后一个.
        // 不变量: 上方 chain.is_empty() 已 guard, 此处 chain.last() 必 Some.
        let last_id = *chain.last().expect("chain non-empty (guarded above)");
        // tail 构造失败 (理论持锁不变式下必存在) 降级为空 tail 占位, 避免 timeline 整体 500.
        let tail = build_timeline_tail(&g, last_id).unwrap_or_else(|| empty_tail(last_id));
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
        let mut sessions: Vec<_> = g
            .sessions
            .iter()
            .filter_map(|(&sid, s)| session_view(&g, sid, s))
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
