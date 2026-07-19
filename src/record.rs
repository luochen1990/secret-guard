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
        }
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
}
