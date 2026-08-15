//! session-aware timeline API: `GET /sessions` + `GET /sessions/{sid}/timeline` +
//! `POST /sync`.
//!
//! 从 api.rs 单文件拆出 (见 #146 残留 1).
//!
//! 替代旧的 GET /api/nodes/{id}/timeline (基于 node_id). 新 API 基于 SessionId:
//! - GET /api/sessions/{sid}/timeline?before=&limit=: 初始加载 + lazy load (向前翻更老).
//! - POST /api/sync: sidebar (sessions + expanded rounds) + timeline diff 一次性采集.
//!
//! 详见 dag 模块的 session_rounds / timeline_view / timeline_diff / sync_snapshot.

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::dto::{RoundBrief, SessionView, TimelineDiffData};
use crate::state::{AppState, NO_STORE};

// ─── /sessions ─────────────────────────────────────────────────────────────

/// 会话列表项 (sidebar 两级树的一级项). 直接复用中立层 [`SessionView`]
/// (字段集合 / serde wire shape 完全一致, 历史上的恒等映射空壳已删, 见 #146 simplify).
pub(crate) type SessionSummary = SessionView;

#[derive(Serialize)]
struct ListSessionsResponse {
    sessions: Vec<SessionSummary>,
    total: usize,
}

pub async fn list_sessions(State(state): State<AppState>) -> impl IntoResponse {
    let sessions: Vec<SessionSummary> = state.dag.list_sessions();
    let total = sessions.len();
    (NO_STORE, Json(ListSessionsResponse { sessions, total }))
}

// ─── /sessions/{sid}/timeline ──────────────────────────────────────────────

/// `GET /api/sessions/{sid}/timeline` 查询参数.
///
/// - `before`: 游标 (某轮的 id). 省略 = 从最新轮 (leaf) 起取 limit 条;
///   传 id = 取该 id **之前** (更老) 的 limit 条 (不含 id 自身), 用于向上 lazy load.
/// - `limit`: 默认 10, clamp [1, 50]. 上限 50 (而非旧 list 的 200): timeline 路径对每个
///   node 都 resolve block + 序列化 wire JSON, 高限会造成延迟尖峰.
#[derive(Debug, Deserialize)]
pub(crate) struct TimelineQuery {
    #[serde(default)]
    pub before: Option<Uuid>,
    #[serde(default)]
    pub limit: Option<usize>,
}

impl TimelineQuery {
    /// 解析为生效的 `(before, limit)`. 单一事实来源: 默认值 + clamp 都在这里.
    fn resolve(&self) -> (Option<Uuid>, usize) {
        let limit = self.limit.unwrap_or(10).clamp(1, 50);
        (self.before, limit)
    }
}

/// GET /api/sessions/{sid}/timeline handler.
///
/// 返回 timeline 分页 (oldest-first) + 末轮 tail + has_more.
/// session 不存在 / leaf 无法定位 → 404.
pub async fn session_timeline(
    State(state): State<AppState>,
    Path(sid): Path<crate::dag::SessionId>,
    Query(q): Query<TimelineQuery>,
) -> Result<impl IntoResponse, axum::http::StatusCode> {
    let (before, limit) = q.resolve();
    let page = state
        .dag
        .timeline_view(sid, before, limit)
        .ok_or(axum::http::StatusCode::NOT_FOUND)?;
    Ok((NO_STORE, Json(page)))
}

// ─── POST /api/sync ─────────────────────────────────────────────────────────
//
// WebUI 3s 轮询的统一入口: 一次请求拿到 sidebar (sessions + expanded rounds) +
// timeline diff (仅 selected session). DAG 层在单个 read lock 内采集, 保证三部分
// 数据来自同一快照 (避免新 push 在两次锁之间漂移).

/// POST /api/sync 请求体.
///
/// - `selected`: 当前选中的 session + 游标 (用于 timeline diff). None = 无选中 / 首次加载.
/// - `expanded`: 展开的 session id 列表 (需要回传 round 详情的那些).
#[derive(Debug, Deserialize)]
pub(crate) struct SyncRequest {
    #[serde(default)]
    pub selected: Option<SelectedCursor>,
    #[serde(default)]
    pub expanded: Vec<crate::dag::SessionId>,
}

/// selected session 的游标 (前端持有的最后一条 round + tail 长度).
#[derive(Debug, Deserialize)]
pub(crate) struct SelectedCursor {
    pub session_id: crate::dag::SessionId,
    /// 前端持有的最后一条 round id (timeline 已渲染到的最新一条).
    /// None = 前端刚进入会话但 timeline 尚未加载 (首次 sync).
    pub latest_round: Option<Uuid>,
    /// 前端持有的末轮 response 内容长度 (用于 tail 变更检测, 与 TimelineTail.length 比对).
    pub response_length: usize,
}

/// POST /api/sync 响应体.
///
/// 字段直接透传 [`crate::dag::ConversationDag::sync_snapshot`] 产出的
/// [`crate::dto::SyncSnapshot`] (`Vec<SessionView>` + `HashMap<SessionId, Vec<RoundBrief>>` +
/// `Option<TimelineDiffData>`). `timeline = None` 表示无 diff (前端游标已是最新, 等价 304).
#[derive(Serialize)]
pub(crate) struct SyncResponse {
    pub sessions: Vec<SessionSummary>,
    pub rounds: std::collections::HashMap<crate::dag::SessionId, Vec<RoundBrief>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline: Option<TimelineDiffData>,
}

/// POST /api/sync handler.
///
/// 在 DAG 层单个 read lock 内采集 sessions + expanded rounds + timeline diff
/// (SessionSummary 是 SessionView 的恒等 alias, 直接透传). 无选中时 timeline 为 None.
pub async fn sync(
    State(state): State<AppState>,
    Json(req): Json<SyncRequest>,
) -> impl IntoResponse {
    let selected = req
        .selected
        .map(|c| (c.session_id, c.latest_round, c.response_length));
    let snap = state.dag.sync_snapshot(&req.expanded, selected);
    let sessions: Vec<SessionSummary> = snap.sessions;
    (
        NO_STORE,
        Json(SyncResponse {
            sessions,
            rounds: snap.rounds,
            timeline: snap.timeline,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ─── TimelineQuery (session-aware timeline 分页参数) ───────────────────

    #[test]
    fn timeline_query_defaults_before_none_limit_ten() {
        let q = TimelineQuery {
            before: None,
            limit: None,
        };
        assert_eq!(q.resolve(), (None, 10));
    }

    #[test]
    fn timeline_query_clamps_limit_to_range() {
        // limit = 0 → clamp 到 1.
        let q = TimelineQuery {
            before: None,
            limit: Some(0),
        };
        assert_eq!(q.resolve(), (None, 1));
        // limit 超大 → clamp 到 50.
        let q = TimelineQuery {
            before: None,
            limit: Some(10_000),
        };
        assert_eq!(q.resolve(), (None, 50));
    }

    #[test]
    fn timeline_query_passes_before_cursor_through() {
        // 显式传 before 游标应原样透传.
        let id = Uuid::new_v4();
        let q = TimelineQuery {
            before: Some(id),
            limit: Some(20),
        };
        assert_eq!(q.resolve(), (Some(id), 20));
    }

    // ─── property-based (SEC-5: SessionSummary 不含 PolicySnapshot) ──────────

    proptest! {
        /// SEC-5: SessionSummary 序列化后的 JSON 不含 PolicySnapshot 字段.
        ///
        /// 契约 (docs/design/contracts.md §7 SEC-5): SessionSummary (GET /sessions 响应
        /// 元素) 字段集合不含 PolicySnapshot. 类型系统层: SessionSummary 的字段都是
        /// 基础类型 (SessionId / Uuid / usize / DateTime / Arc<str> / String) — 见 struct
        /// 定义. 本 property 是防御性第二道闸 — 序列化扫描 JSON.
        ///
        /// 生成器: 用可识别 marker 填充字符串字段 (path / latest_error), marker 字符集
        /// [a-z] 避免 "policy" 子串意外重叠 (assume 守卫).
        #[test]
        fn prop_policy_snapshot_not_in_session_summary(
            path_marker in "[a-z]{3,8}",
            err_marker in "[a-z]{3,8}",
            preview_marker in "[a-z]{3,8}",
        ) {
            prop_assume!(
                !path_marker.contains("policy") && !err_marker.contains("policy")
                    && !preview_marker.contains("policy"),
                "marker must not contain 'policy' substring"
            );
            let summary = SessionView {
                session_id: crate::dag::SessionId::new(),
                leaf_id: Uuid::new_v4(),
                root_id: Uuid::new_v4(),
                record_count: 1,
                created_at: chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                latest_at: chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                preview: Some(std::sync::Arc::from(preview_marker.as_str())),
                model: Some(std::sync::Arc::from("gpt-test")),
                latest_resp_status: 200,
                latest_error: Some(format!("err-{err_marker}")),
                redactions: std::sync::Arc::from([(String::from("mock-x"), String::from("sid"))]),
                path: format!("/o/{path_marker}/v1/chat"),
            };
            let json = serde_json::to_string(&summary).expect("serialize SessionSummary");
            prop_assert!(
                !json.contains("\"policy\"") && !json.contains("PolicySnapshot"),
                "SEC-5 violation: SessionSummary JSON contains PolicySnapshot. json={}",
                json
            );
        }
    }

    /// SEC-5 扫描器灵敏度守卫 (SessionSummary): 验证 `json.contains("\"policy\"")` 在
    /// JSON 真含该字段时返回 true, 防止上方 proptest 因扫描器失效而空洞通过. 详见
    /// record.rs 同名 sanity test 的设计依据.
    #[test]
    fn sec5_scanner_detects_policy_field_in_session_summary() {
        let json_with_policy = serde_json::json!({"policy": "secret-value"});
        let serialized = serde_json::to_string(&json_with_policy).unwrap();
        assert!(
            serialized.contains("\"policy\""),
            "SEC-5 scanner broken: json.contains(\"\\\"policy\\\"\") is false even when field \
             present. sec5 proptest would pass vacuously. json={serialized}"
        );
    }
}
