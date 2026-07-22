//! 转发记录模型与内存存储.
//!
//! 设计目标:
//! - 每条记录完整保存请求与响应的文本快照 (字节同义, 但以 UTF-8 视图呈现).
//! - 支持流式响应: 即使响应是 SSE, 也将各 chunk 拼接后保存.
//! - 并发安全: 使用 `parking_lot::RwLock` 读写, MVP 阶段不做淘汰策略.
//!
//! 数据结构选择: `VecDeque` + `HashMap<Uuid, usize>` 索引, 兼顾 FIFO 淘汰 (O(1)) 与
//! 按 id 查找/更新 (O(1)). 索引在淘汰时同步前移 (因 VecDeque pop_front 后所有
//! 索引都要减 1, 选用一次性 batch 前移 + 增量维护).
//!
//! 后续步骤中, body 会先经"secret 改写"再被存档, 因此记录保存的是改写后的视图 (即
//! LLM 实际看到的版本). 这有助于审计"我们到底泄露了什么".

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
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

/// 单条转发记录.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardRecord {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub method: String,
    pub path: String,
    /// 客户端请求的所有 header (敏感 header 如 Authorization 会被脱敏).
    pub req_headers: Vec<(String, String)>,
    /// 客户端请求 body (UTF-8 视图; 非 UTF-8 用 lossy 转换).
    pub req_body: String,
    /// 上游响应状态码 (0 表示尚未收到响应 / 上游错误).
    pub resp_status: u16,
    /// 上游响应的所有 header.
    pub resp_headers: Vec<(String, String)>,
    /// 上游响应 body (流式 SSE 也会被拼接保存).
    pub resp_body: String,
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

/// 响应更新参数. 抽为结构体以避免 `update_response_full` 函数参数过多.
#[derive(Debug, Clone)]
pub struct ResponseUpdate {
    pub resp_status: u16,
    pub resp_headers: Vec<(String, String)>,
    pub resp_body: String,
    pub elapsed_ms: u64,
    pub streamed: bool,
    pub resp_complete: bool,
    pub error: Option<String>,
}

impl ForwardRecord {
    pub fn new(
        method: String,
        path: String,
        req_headers: Vec<(String, String)>,
        req_body: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            method,
            path,
            req_headers,
            req_body,
            resp_status: 0,
            resp_headers: Vec::new(),
            resp_body: String::new(),
            elapsed_ms: 0,
            streamed: false,
            resp_complete: false,
            error: None,
            redactions: Vec::new(),
        }
    }

    /// Builder: 附上 redactions (来自 `RedactionMap` + `secrets_snapshot` 的投影).
    /// 不调用则默认空 vec (passthrough 路径).
    pub fn with_redactions(mut self, redactions: Vec<(String, String)>) -> Self {
        self.redactions = redactions;
        self
    }
}

/// 进程内转发记录存储.
///
/// MVP 采用 FIFO 淘汰策略, 上限通过 `max` 控制 (默认 1024).
#[derive(Debug, Clone)]
pub struct RecordStore {
    inner: Arc<RwLock<RecordStoreInner>>,
}

#[derive(Debug)]
struct RecordStoreInner {
    records: VecDeque<ForwardRecord>,
    index: HashMap<Uuid, usize>,
    max: usize,
}

impl Default for RecordStore {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl RecordStore {
    pub fn new(max: usize) -> Self {
        let max = max.max(1);
        Self {
            inner: Arc::new(RwLock::new(RecordStoreInner {
                records: VecDeque::with_capacity(max.min(128)),
                index: HashMap::new(),
                max,
            })),
        }
    }

    /// 追加一条记录, 返回其 id; 若超出上限则按 FIFO 淘汰.
    pub fn push(&self, record: ForwardRecord) -> Uuid {
        let id = record.id;
        let mut g = self.inner.write();
        if g.records.len() >= g.max {
            if let Some(evicted) = g.records.pop_front() {
                g.index.remove(&evicted.id);
                // 所有索引前移 1
                for v in g.index.values_mut() {
                    *v = v.saturating_sub(1);
                }
            }
        }
        let idx = g.records.len();
        g.index.insert(id, idx);
        g.records.push_back(record);
        id
    }

    /// 按 id 更新已有记录的响应部分 (成功完成).
    pub fn update_response(
        &self,
        id: Uuid,
        resp_status: u16,
        resp_headers: Vec<(String, String)>,
        resp_body: String,
        elapsed_ms: u64,
        streamed: bool,
    ) {
        self.update_response_full(
            id,
            ResponseUpdate {
                resp_status,
                resp_headers,
                resp_body,
                elapsed_ms,
                streamed,
                resp_complete: true,
                error: None,
            },
        );
    }

    /// 按 id 更新记录, 允许标记 incomplete 与错误诊断 (用于上游错误 / 客户端断开).
    pub fn update_response_full(&self, id: Uuid, update: ResponseUpdate) {
        let mut g = self.inner.write();
        let idx = match g.index.get(&id) {
            Some(&i) => i,
            None => {
                tracing::warn!(%id, "record not found in update_response (evicted?)");
                return;
            }
        };
        if let Some(r) = g.records.get_mut(idx) {
            r.resp_status = update.resp_status;
            r.resp_headers = update.resp_headers;
            r.resp_body = update.resp_body;
            r.elapsed_ms = update.elapsed_ms;
            r.streamed = update.streamed;
            r.resp_complete = update.resp_complete;
            r.error = update.error;
        }
    }

    /// 按 id 取一条记录.
    pub fn get(&self, id: Uuid) -> Option<ForwardRecord> {
        let g = self.inner.read();
        let idx = *g.index.get(&id)?;
        g.records.get(idx).cloned()
    }

    /// 列出所有记录 (按时间倒序).
    pub fn list(&self) -> Vec<ForwardRecord> {
        let g = self.inner.read();
        let mut v: Vec<_> = g.records.iter().cloned().collect();
        v.reverse();
        v
    }

    /// 分页列出记录 (按时间倒序). 返回 `(当前页 records, 该 filter 维度下的总数)`.
    ///
    /// - `offset`: 0-based, 从最新一条算起. 会 clamp 到 `[0, total]`.
    /// - `limit`: clamp 到 `[1, 200]`.
    /// - `filter`: `All` 不过滤; `Hits` 只保留 `redactions` 非空的记录.
    /// - `offset >= total`: 返回空 vec + total.
    ///
    /// 用 `VecDeque` 的双向迭代做高效切片 (避免全量 clone + reverse).
    /// 适合偶尔翻页的 WebUI 场景; 若未来要做大量扫描/筛选, 再考虑加索引.
    ///
    /// `filter=Hits` 需要先扫一遍全量计数 + 过滤出命中索引, 再切片.
    /// `VecDeque` ≤1024 条 + 每条只看 `redactions.is_empty()` (无 body 拷贝),
    /// O(n) 扫描对 WebUI 偶发翻页场景完全无感知.
    pub fn list_page(
        &self,
        offset: usize,
        limit: usize,
        filter: RecordFilter,
    ) -> (Vec<ForwardRecord>, usize) {
        let g = self.inner.read();
        let limit = limit.clamp(1, 200);

        // All 路径 (最常见): 直接在原 VecDeque 上倒序切片, total = records.len().
        // 这是热路径, 保持零额外分配.
        if filter == RecordFilter::All {
            let total = g.records.len();
            let offset = offset.min(total);
            if offset >= total {
                return (Vec::new(), total);
            }
            let take = limit.min(total - offset);
            let out: Vec<ForwardRecord> = g
                .records
                .iter()
                .rev()
                .skip(offset)
                .take(take)
                .cloned()
                .collect();
            return (out, total);
        }

        // Hits 路径: 先倒序扫一遍, 过滤出命中记录的索引, 再切片.
        // 不做 clone 直到确定要返回哪几条, 避免无谓的 body 拷贝.
        let hit_indices: Vec<usize> = g
            .records
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, r)| !r.redactions.is_empty())
            .map(|(i, _)| i)
            .collect();
        let total = hit_indices.len();
        let offset = offset.min(total);
        if offset >= total {
            return (Vec::new(), total);
        }
        let take = limit.min(total - offset);
        let out: Vec<ForwardRecord> = hit_indices
            .iter()
            .skip(offset)
            .take(take)
            .map(|&i| g.records.get(i).cloned().unwrap())
            .collect();
        (out, total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_record(method: &str, path: &str) -> ForwardRecord {
        ForwardRecord::new(method.into(), path.into(), vec![], String::new())
    }

    #[test]
    fn push_and_get_roundtrip() {
        let store = RecordStore::new(8);
        let r = fake_record("POST", "/v1/messages");
        let id = store.push(r);
        let got = store.get(id).expect("record must exist");
        assert_eq!(got.method, "POST");
        assert_eq!(got.path, "/v1/messages");
    }

    #[test]
    fn list_returns_newest_first() {
        let store = RecordStore::new(8);
        let a = store.push(fake_record("POST", "/a"));
        let b = store.push(fake_record("POST", "/b"));
        let list = store.list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, b);
        assert_eq!(list[1].id, a);
    }

    #[test]
    fn fifo_eviction_drops_oldest_index() {
        let store = RecordStore::new(2);
        let a = store.push(fake_record("POST", "/a"));
        let _ = store.push(fake_record("POST", "/b"));
        let c = store.push(fake_record("POST", "/c"));
        // a 应已被淘汰 (index 中也消失)
        assert!(store.get(a).is_none());
        assert!(store.get(c).is_some());
        assert_eq!(store.list().len(), 2);
    }

    #[test]
    fn update_response_persists() {
        let store = RecordStore::new(8);
        let id = store.push(fake_record("POST", "/x"));
        store.update_response(id, 200, vec![], "hello".into(), 5, false);
        let got = store.get(id).expect("record exists");
        assert_eq!(got.resp_status, 200);
        assert_eq!(got.resp_body, "hello");
        assert!(got.resp_complete);
        assert!(got.error.is_none());
    }

    #[test]
    fn update_response_full_marks_incomplete() {
        let store = RecordStore::new(8);
        let id = store.push(fake_record("POST", "/x"));
        store.update_response_full(
            id,
            ResponseUpdate {
                resp_status: 200,
                resp_headers: vec![],
                resp_body: "partial".into(),
                elapsed_ms: 5,
                streamed: true,
                resp_complete: false,
                error: Some("upstream stream error".into()),
            },
        );
        let got = store.get(id).expect("record exists");
        assert!(!got.resp_complete);
        assert_eq!(got.error.as_deref(), Some("upstream stream error"));
    }

    #[test]
    fn update_response_on_evicted_record_warns_not_panics() {
        let store = RecordStore::new(1);
        let a = store.push(fake_record("POST", "/a"));
        let _ = store.push(fake_record("POST", "/b")); // evicts a
        store.update_response(a, 200, vec![], "late".into(), 1, false);
        // 不 panic 即可; 期望行为: warn + no-op.
    }

    #[test]
    fn max_clamped_to_one() {
        let store = RecordStore::new(0);
        let _ = store.push(fake_record("POST", "/a"));
        let _ = store.push(fake_record("POST", "/b"));
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn redactions_roundtrip_preserved() {
        // 验证 with_redactions 设置的 redactions 能通过 push + get 完整还原.
        // 这是 WebUI 读取 "本次请求 redact 了哪些 secret" 的权威数据源.
        let store = RecordStore::new(8);
        let r = fake_record("POST", "/o/x/v1/chat")
            .with_redactions(vec![("sgm_abc".into(), "my_key".into())]);
        let id = store.push(r);
        let got = store.get(id).expect("record exists");
        assert_eq!(got.redactions.len(), 1);
        assert_eq!(got.redactions[0].0, "sgm_abc");
        assert_eq!(got.redactions[0].1, "my_key");
    }

    #[test]
    fn redactions_default_empty_when_not_set() {
        // 验证 ForwardRecord::new 默认 redactions 为空 (passthrough 路径的语义).
        let store = RecordStore::new(8);
        let id = store.push(fake_record("POST", "/a"));
        let got = store.get(id).expect("record exists");
        assert!(got.redactions.is_empty());
    }

    #[test]
    fn list_page_returns_newest_slice_and_total() {
        // 5 条记录, path 标记插入顺序方便断言 "newest first".
        let store = RecordStore::new(64);
        for i in 0..5 {
            let _ = store.push(fake_record("POST", &format!("/r{i}")));
        }
        // list_page(0, 2, All) → 最新两条 (/r4, /r3) + total=5.
        let (page, total) = store.list_page(0, 2, RecordFilter::All);
        assert_eq!(total, 5);
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].path, "/r4");
        assert_eq!(page[1].path, "/r3");
    }

    #[test]
    fn list_page_offset_reaches_oldest() {
        // offset = 4 → 跳过 4 条最新, 取 1 条最旧 (/r0).
        let store = RecordStore::new(64);
        for i in 0..5 {
            let _ = store.push(fake_record("POST", &format!("/r{i}")));
        }
        // limit 给 10, 应被 clamp 到剩余 1.
        let (page, total) = store.list_page(4, 10, RecordFilter::All);
        assert_eq!(total, 5);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].path, "/r0");
    }

    #[test]
    fn list_page_clamps_inputs() {
        let store = RecordStore::new(64);
        for i in 0..5 {
            let _ = store.push(fake_record("POST", &format!("/r{i}")));
        }
        // limit=0 → clamp 到 1.
        let (page, total) = store.list_page(0, 0, RecordFilter::All);
        assert_eq!(total, 5);
        assert_eq!(page.len(), 1);
        // limit 超大 → clamp 到 200, 但实际只有 5 条, 返回全部.
        let (page, total) = store.list_page(0, 10_000, RecordFilter::All);
        assert_eq!(total, 5);
        assert_eq!(page.len(), 5);
        // offset 超大 → 空页 + total.
        let (page, total) = store.list_page(1_000, 10, RecordFilter::All);
        assert_eq!(total, 5);
        assert!(page.is_empty());
    }

    #[test]
    fn list_page_hits_filter_returns_only_redacted_records() {
        // 3 条带 redactions + 2 条不带 → Hits 维度 total=3, 顺序仍为 newest first.
        let store = RecordStore::new(64);
        let _ = store.push(fake_record("POST", "/plain0"));
        let _ = store.push(
            fake_record("POST", "/hit1").with_redactions(vec![("sgm_a".into(), "k1".into())]),
        );
        let _ = store.push(fake_record("POST", "/plain2"));
        let _ = store.push(
            fake_record("POST", "/hit3").with_redactions(vec![("sgm_b".into(), "k2".into())]),
        );
        let _ = store.push(
            fake_record("POST", "/hit4").with_redactions(vec![("sgm_c".into(), "k3".into())]),
        );
        // 第一页 limit=2: 取最新两条 hits (/hit4, /hit3), total=3.
        let (page, total) = store.list_page(0, 2, RecordFilter::Hits);
        assert_eq!(total, 3);
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].path, "/hit4");
        assert_eq!(page[1].path, "/hit3");
        // 第二页 offset=2 limit=2: 只剩最旧一条 hit (/hit1).
        let (page, total) = store.list_page(2, 2, RecordFilter::Hits);
        assert_eq!(total, 3);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].path, "/hit1");
    }

    #[test]
    fn list_page_hits_filter_empty_when_no_redactions() {
        // 所有记录都无 redactions → Hits 维度 total=0, 空页.
        let store = RecordStore::new(64);
        for i in 0..3 {
            let _ = store.push(fake_record("POST", &format!("/r{i}")));
        }
        let (page, total) = store.list_page(0, 10, RecordFilter::Hits);
        assert_eq!(total, 0);
        assert!(page.is_empty());
    }

    #[test]
    fn list_page_hits_filter_clamps_inputs() {
        // 与 All 路径对称: offset/limit clamp 行为应一致.
        let store = RecordStore::new(64);
        for i in 0..3 {
            let _ = store.push(
                fake_record("POST", &format!("/r{i}"))
                    .with_redactions(vec![("sgm".into(), "k".into())]),
            );
        }
        // offset 超大 → 空页 + total=3.
        let (page, total) = store.list_page(1_000, 10, RecordFilter::Hits);
        assert_eq!(total, 3);
        assert!(page.is_empty());
    }
}
