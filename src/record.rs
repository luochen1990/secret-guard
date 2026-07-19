//! 转发记录模型与内存存储.
//!
//! 设计目标:
//! - 每条记录完整保存请求与响应的文本快照 (字节同义, 但以 UTF-8 视图呈现).
//! - 支持流式响应: 即使响应是 SSE, 也将各 chunk 拼接后保存.
//! - 并发安全: 使用 `parking_lot::RwLock` 读写, MVP 阶段不做淘汰策略.
//!
//! 后续步骤中, body 会先经"secret 改写"再被存档, 因此记录保存的是改写后的视图 (即
//! LLM 实际看到的版本). 这有助于审计"我们到底泄露了什么".

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
    /// 上游响应状态码.
    pub resp_status: u16,
    /// 上游响应的所有 header.
    pub resp_headers: Vec<(String, String)>,
    /// 上游响应 body (流式 SSE 也会被拼接保存).
    pub resp_body: String,
    /// 端到端耗时 (毫秒).
    pub elapsed_ms: u64,
    /// 流式标记: true 表示响应是 chunked / SSE.
    pub streamed: bool,
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
        }
    }
}

/// 进程内转发记录存储.
///
/// MVP 采用环形缓冲或全保留策略, 当前选择全保留 + 上限 1024 条避免内存爆炸.
/// 上限通过 `MAX_RECORDS` 常量控制.
#[derive(Debug, Clone)]
pub struct RecordStore {
    inner: Arc<RwLock<RecordStoreInner>>,
}

#[derive(Debug)]
struct RecordStoreInner {
    records: Vec<ForwardRecord>,
    max: usize,
}

impl Default for RecordStore {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl RecordStore {
    pub fn new(max: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(RecordStoreInner {
                records: Vec::with_capacity(max.min(128)),
                max,
            })),
        }
    }

    /// 追加一条记录, 返回其 id; 若超出上限则按 FIFO 淘汰.
    pub fn push(&self, record: ForwardRecord) -> Uuid {
        let id = record.id;
        let mut g = self.inner.write();
        if g.records.len() >= g.max {
            g.records.remove(0);
        }
        g.records.push(record);
        id
    }

    /// 按 id 更新已有记录的响应部分.
    pub fn update_response(
        &self,
        id: Uuid,
        resp_status: u16,
        resp_headers: Vec<(String, String)>,
        resp_body: String,
        elapsed_ms: u64,
        streamed: bool,
    ) {
        let mut g = self.inner.write();
        if let Some(r) = g.records.iter_mut().find(|r| r.id == id) {
            r.resp_status = resp_status;
            r.resp_headers = resp_headers;
            r.resp_body = resp_body;
            r.elapsed_ms = elapsed_ms;
            r.streamed = streamed;
        }
    }

    /// 按 id 取一条记录.
    pub fn get(&self, id: Uuid) -> Option<ForwardRecord> {
        self.inner
            .read()
            .records
            .iter()
            .find(|r| r.id == id)
            .cloned()
    }

    /// 列出所有记录 (按时间倒序).
    pub fn list(&self) -> Vec<ForwardRecord> {
        let g = self.inner.read();
        let mut v = g.records.clone();
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
    fn fifo_eviction_when_full() {
        let store = RecordStore::new(2);
        let _ = store.push(fake_record("POST", "/a"));
        let _ = store.push(fake_record("POST", "/b"));
        let c = store.push(fake_record("POST", "/c"));
        let list = store.list();
        assert_eq!(list.len(), 2, "oldest should be evicted");
        assert!(list.iter().any(|r| r.id == c));
    }

    #[test]
    fn update_response_persists() {
        let store = RecordStore::new(8);
        let id = store.push(fake_record("POST", "/x"));
        store.update_response(id, 200, vec![], "hello".into(), 5, false);
        let got = store.get(id).expect("record exists");
        assert_eq!(got.resp_status, 200);
        assert_eq!(got.resp_body, "hello");
    }
}
