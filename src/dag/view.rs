//! DAG 读视图构造 (node_view / session_view / list / full_request_messages).
//!
//! # 职责边界
//!
//! 本模块是 [`super::ConversationDag`] 的**读路径**实现: 从 `DagInner` 派生 WebUI
//! 用的视图 (NodeView / SessionView / NodeDetail / RoundBrief 不在此, 后者在 timeline).
//! 所有方法都是 `&self` 读锁 + clone 出视图, 不修改 DAG 结构.
//!
//! # 与 mutator 的隔离
//!
//! mutator (push_messages / attach_response / update_parsed_response) 留在 [`super`]
//! (mod.rs), 本模块不写 DAG 字段. 共享的 `inner: Arc<RwLock<DagInner>>` 通过
//! `pub(super)` 可见性访问.
//!
//! # 性能注
//!
//! `node_view` / `session_view` 是 free function 形态 (接收 `&DagInner`), 避免在
//! `list_page` / `list_sessions` / `sync_snapshot` 路径重复 `self.inner.read()`.
//! 公开的 `get_node` / `get_response` / `get_node_detail` 是 thin wrapper (各自上一次读锁).
//!
//! # SEC 约束 (full_request_messages)
//!
//! `full_request_messages` 是**内存明文存量面** (BlockPool 持有 redact 前的真实
//! 内容, 含历史真实 secret), **禁止**直接出 web 层 — redact_map 是 per-request
//! 不持久化的, restart 后无从 lazy apply, 直出即泄露真实 secret (SEC-1).
//! 详见该方法的红线注记.

use std::sync::Arc;

use uuid::Uuid;

use crate::codec::ir::IrMessage;
use crate::dto::{NodeDetail, NodeView, SessionView, UsageView};

use super::types::Session;
use super::{ConversationDag, DagInner, SessionId};

// ─── newest-first 排序 SSOT ─────────────────────────────────────────────────

/// 把 DAG 中所有 node id 按 (created_at desc, id desc) 排序后返回.
///
/// SSOT for "newest-first" 排序: [`ConversationDag::list_node_ids_newest_first`]
/// 与 [`ConversationDag::list_page`] 共享同一排序实现, 避免 12 行重复逻辑分叉.
/// tie 时按 id 排序保证确定性 (HashMap keys 迭代顺序非确定).
///
/// 性能优化 (perf): 预提取 `(created_at, id)` tuple 一次再 sort, 避免比较闭包内
/// 对每次比较重复 `nodes.get()` 查找 (N log N 次 get → N 次预提取).
pub(super) fn sort_node_ids_newest_first(inner: &DagInner) -> Vec<Uuid> {
    let mut keyed: Vec<(chrono::DateTime<chrono::Utc>, Uuid)> = inner
        .nodes
        .iter()
        .map(|(id, n)| (n.event.created_at, *id))
        .collect();
    // 稳定倒序: 先正序排序再 reverse, 等价于 (created_at desc, id desc).
    keyed.sort_unstable();
    keyed.reverse();
    keyed.into_iter().map(|(_, id)| id).collect()
}

// ─── 视图构造 (free function, 共享调用方持有的 &DagInner) ───────────────────

/// 从 inner 中构造 NodeView (内部 helper, 需要调用方持读锁).
pub(super) fn node_view(inner: &DagInner, node_id: Uuid) -> Option<NodeView> {
    let node = inner.nodes.get(&node_id)?;
    let resp = node.response.read();
    Some(NodeView {
        id: node.id,
        parent: node.parent,
        // CDAG-7 孤儿标记: parent 有值但在 nodes 中缺席 = parent 已被淘汰.
        // 纯派生 (只读 inner, 不 mutate); 根 (parent=None) 恒 false.
        is_orphan: node.parent.is_some_and(|p| !inner.nodes.contains_key(&p)),
        session_id: node.session_id,
        round_role: node.event.round_role,
        round_kind: node.event.round_kind,
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
        // 实际承载转发的 provider id (#179; 非虚拟请求 = URL provider id).
        upstream_id: std::sync::Arc::clone(&node.event.upstream_id),
        // 实际改写的 model 值 (#183; None = 未 override / 透传).
        upstream_model: node.event.upstream_model.clone(),
        streamed: resp.as_ref().map(|r| r.streamed).unwrap_or(false),
        resp_complete: resp.as_ref().map(|r| r.resp_complete).unwrap_or(false),
        // audit_capture 三态的最终结果 (B2/#273 errors 档): 响应已落地 →
        // retain(mode, is_error); 在途 (response 未 attach) → 暂存可看, 按 true
        // (errors 档的回收发生在 attach, 之前的窗口 body 在场).
        audit_retained: resp
            .as_ref()
            .is_none_or(|r| node.event.capture_mode.retain(r.is_error())),
        error: resp.as_ref().and_then(|r| r.error.clone()),
        redactions: Arc::clone(&node.event.redactions),
        // B1 双态单点 (derive::parsed_view): 流式中读 stored, finalize 后派生.
        parsed_response: resp
            .as_ref()
            .and_then(|r| crate::derive::parsed_view(node, &inner.blocks, r)),
        // list_page 路径不填 (避免 O(n) 全量 resolve); timeline 路径单独填.
        req_delta_messages: Vec::new(),
    })
}

/// 构造一个 SessionView (从 sessions map 中的 Session 派生).
/// 不走 parent 链 — node_count / root_id / title 在 push 时增量维护.
///
/// 例外: `usage_total` 沿链折叠各轮 `ResponseData.usage` (usage-stats §6).
/// O(chain) 但仅在 3s 轮询路径执行一次, 且总和 ≤ 全部 nodes 数 (FIFO cap 内),
/// 微秒级; 语义 = "本次进程内该会话已渲染轮次的累计" (restart 归零 / 淘汰缩水,
/// 与 Usage 页持久账本口径不同, 前端脚注说明).
pub(super) fn session_view(inner: &DagInner, sid: SessionId, s: &Session) -> Option<SessionView> {
    // usage 折叠**先于** leaf 的 response 读锁执行: 循环首轮会再次读 leaf 的同一把
    // 锁, 若与外层持有嵌套, parking_lot RwLock 在有 writer 排队时递归读锁会死锁
    // (read-me-maybe 语义, 2026-09 简化走查发现). 循环内逐节点短持锁, 循环外再取
    // leaf 锁读 status/error — 两次**顺序**获取, 无嵌套.
    let mut usage_total = UsageView::default();
    {
        // 沿 parent 链折叠 usage (leaf → root; ROB: 节点缺失即止, 不 panic).
        let mut cursor = Some(s.leaf_id);
        while let Some(id) = cursor {
            let Some(node) = inner.nodes.get(&id) else {
                break;
            };
            if let Some(u) = node.response.read().as_ref().and_then(|r| r.usage.as_ref()) {
                usage_total = usage_total.saturating_add(UsageView::from_ir(u));
            }
            cursor = node.parent;
        }
    }
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
        usage_total,
    })
}

// ─── ConversationDag 读路径方法 (impl 扩展, 与 mod.rs 的 impl 块分离) ───────

/// 转发摘要日志所需的标量字段集 (#160).
///
/// 与 [`NodeView`] 的区别: **不 clone 大字段** (parsed_response 的深拷贝 /
/// req_delta resolve), 只取摘要日志需要的标量. 每笔转发完成都会打一行 INFO 摘要,
/// 该路径必须避免为打日志付出 O(body) 的 JSON clone (见 view.rs 头部 "性能注").
#[derive(Debug, Clone)]
pub struct ForwardSummary {
    pub method: String,
    pub path: String,
    pub resp_status: u16,
    pub elapsed_ms: u64,
    pub streamed: bool,
    pub resp_complete: bool,
    pub error: Option<String>,
    pub redactions: usize,
}

impl ConversationDag {
    /// 读取摘要日志所需的标量字段 (轻量版 `get_node`, 不构造完整 NodeView).
    ///
    /// 与 `get_node` 的分工: `get_node` 服务 WebUI (需要全部字段含 parsed);
    /// 本方法服务转发完成时的 INFO 摘要 (热路径, 只需 8 个标量).
    pub fn forward_summary_fields(&self, node_id: Uuid) -> Option<ForwardSummary> {
        let g = self.inner.read();
        let node = g.nodes.get(&node_id)?;
        let resp = node.response.read();
        Some(ForwardSummary {
            method: node.event.method.clone(),
            path: node.event.path.clone(),
            resp_status: resp.as_ref().map(|r| r.resp_status).unwrap_or(0),
            elapsed_ms: resp.as_ref().map(|r| r.elapsed_ms).unwrap_or(0),
            streamed: resp.as_ref().map(|r| r.streamed).unwrap_or(false),
            resp_complete: resp.as_ref().map(|r| r.resp_complete).unwrap_or(false),
            error: resp.as_ref().and_then(|r| r.error.clone()),
            redactions: node.event.redactions.len(),
        })
    }

    /// walk parent 链, 收集完整的 request messages (从根到本 node).
    ///
    /// 只含 req_delta (客户端发出的 messages), 不含 response.
    /// response 是独立数据源, 用 `get_response` 单独获取.
    ///
    /// **不 apply redact**: 返回的是 OriginRecord (真实内容).
    /// 调用方需要 SecureRecord 时, 自行 derive redactMap 并 apply.
    ///
    /// **红线 (内存明文存量面, SEC-1)**: 本方法返回 redact 前真实内容 (BlockPool
    /// 持有历史真实 secret), **禁止**直接出 web 层 —— redact_map 是 per-request
    /// 不持久化的, restart 后无从 lazy apply, 直出即泄露真实 secret. 当前调用方
    /// 仅限测试; 任何新调用点必须先过 SEC 评审.
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
    fn collect_req_delta_refs(
        &self,
        inner: &DagInner,
        node_id: Uuid,
    ) -> Option<Vec<super::pool::MessageRef>> {
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
        node_view(&g, node_id)
    }

    /// 取 node 的 response 数据 (clone).
    pub fn get_response(&self, node_id: Uuid) -> Option<super::types::ResponseData> {
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
        // hits_only 时先过滤, 否则全量. 后续 offset/limit/clone 收尾逻辑共享 (SSOT).
        let filtered_ids: Vec<Uuid> = if hits_only {
            all_ids
                .into_iter()
                .filter(|id| {
                    g.nodes
                        .get(id)
                        .is_some_and(|n| !n.event.redactions.is_empty())
                })
                .collect()
        } else {
            all_ids
        };
        let total = filtered_ids.len();
        let offset = offset.min(total);
        let views = filtered_ids
            .iter()
            .copied()
            .skip(offset)
            .take(limit)
            .filter_map(|id| node_view(&g, id))
            .collect();
        (views, total)
    }

    /// 列出会话, 按 latest_at (会话内最新轮次时间) 倒序.
    /// 直接从 sessions map 派生, 无需走 parent 链 (node_count 已增量维护).
    pub fn list_sessions(&self) -> Vec<SessionView> {
        let g = self.inner.read();
        let mut views: Vec<SessionView> = g
            .sessions
            .iter()
            .filter_map(|(&sid, s)| session_view(&g, sid, s))
            .collect();
        // latest_at 倒序 (最近活动的在前); tie 时按 session_id 保证确定性.
        views.sort_by_key(|v| std::cmp::Reverse((v.latest_at, v.session_id)));
        views
    }
}
