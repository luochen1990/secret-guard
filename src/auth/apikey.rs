//! API key 存储: 签发 / 校验 / 撤销 + state.toml 持久化.
//!
//! # 设计
//!
//! - 独立的 `Arc<RwLock<Vec<ApiKeyEntry>>>` (不复用 DynamicTable — API key 是纯动态的,
//!   没有 static 基线 / decision override, 套用 DynamicTable 是过度设计).
//! - 持久化复用 [`crate::config::atomic_write`], 与 provider/secret 共享 `persist_lock`.
//! - key 明文永不持久化, 只存 SHA-256 hash. 校验时对请求中的 key 做 hash 比对.
//!
//! # 安全
//!
//! - key 格式: `sg_` 前缀 + 32 字符 base62 随机串.
//! - 签发时生成明文, 返回给前端一次, 之后只存 hash.
//! - 撤销 = 从 store 中删除 entry + 持久化.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{DynamicState, atomic_write};

/// 一条 API key 注册项. 存 hash, 不存明文.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyEntry {
    /// key 的 id (用于删除). 格式: `ak_` + 随机 slug.
    pub id: String,
    /// SHA-256 hash of the plaintext key (hex). 永不存明文.
    pub key_hash: String,
    /// 明文 key 的前缀 (如 `sg_abc1`), 用于 WebUI 辨识. 不含完整 key, 不可逆推.
    pub key_prefix: String,
    /// 绑定的租户 id (M1 = OIDC user sub; M2 用于数据隔离 scope).
    pub tenant_id: String,
    /// 创建者 OIDC subject (审计用).
    pub created_by: String,
    /// 创建时间.
    pub created_at: DateTime<Utc>,
    /// 人类可读标签 (WebUI 显示).
    pub label: String,
}

/// API key 签发结果 (包含明文, 仅此一次返回给前端).
#[derive(Debug, Serialize)]
pub struct IssuedApiKey {
    /// key 的 id (用于后续删除).
    pub id: String,
    /// 明文 key (仅签发时返回一次, 之后不可恢复).
    pub key: String,
    /// 人类可读标签.
    pub label: String,
    /// 创建时间.
    pub created_at: DateTime<Utc>,
}

/// API key 摘要 (列表展示, 不含明文也不含 hash).
#[derive(Debug, Serialize)]
pub struct ApiKeySummary {
    pub id: String,
    pub tenant_id: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    /// 明文 key 的前缀 (如 `sg_abc1…`), 供用户识别.
    pub key_prefix: String,
}

impl From<&ApiKeyEntry> for ApiKeySummary {
    fn from(e: &ApiKeyEntry) -> Self {
        Self {
            id: e.id.clone(),
            tenant_id: e.tenant_id.clone(),
            label: e.label.clone(),
            created_at: e.created_at,
            key_prefix: e.key_prefix.clone(),
        }
    }
}

/// API key 存储: 内存层 + state.toml 持久化.
///
/// 与 provider/secret 共享 `persist_lock` (state.toml 是同一文件),
/// 保证三者的 read-modify-write 串行, 不会互相覆盖.
#[derive(Clone)]
pub struct ApiKeyStore {
    entries: Arc<RwLock<Vec<ApiKeyEntry>>>,
    /// hash → entry index 的查找索引 (避免每次校验都线性扫描 + hash).
    /// 由 entries 派生, 写操作时同步更新.
    hash_index: Arc<RwLock<HashMap<String, ApiKeyEntry>>>,
    state_path: Arc<PathBuf>,
    persist_lock: Arc<Mutex<()>>,
}

impl std::fmt::Debug for ApiKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entries = self.entries.read();
        f.debug_struct("ApiKeyStore")
            .field("count", &entries.len())
            .field("state_path", &self.state_path)
            .finish()
    }
}

impl ApiKeyStore {
    /// 构造 store. 初始 entries 来自 state.toml 的 `[api_keys]` 段.
    pub fn new(
        entries: Vec<ApiKeyEntry>,
        state_path: PathBuf,
        persist_lock: Arc<Mutex<()>>,
    ) -> Self {
        let hash_index: HashMap<String, ApiKeyEntry> = entries
            .iter()
            .map(|e| (e.key_hash.clone(), e.clone()))
            .collect();
        Self {
            entries: Arc::new(RwLock::new(entries)),
            hash_index: Arc::new(RwLock::new(hash_index)),
            state_path: Arc::new(state_path),
            persist_lock,
        }
    }

    /// 签发一个新的 API key. 返回明文 (仅此一次) + entry.
    /// 明文 = `sg_` + 32 字符 base62 随机串.
    pub fn issue(
        &self,
        tenant_id: &str,
        created_by: &str,
        label: &str,
    ) -> anyhow::Result<IssuedApiKey> {
        let plaintext = generate_key();
        let key_hash = hash_key(&plaintext);
        let key_prefix = plaintext.chars().take(8).collect::<String>();
        let id = format!("ak_{}", random_slug(8));
        let created_at = Utc::now();
        let entry = ApiKeyEntry {
            id: id.clone(),
            key_hash,
            key_prefix,
            tenant_id: tenant_id.to_string(),
            created_by: created_by.to_string(),
            created_at,
            label: label.to_string(),
        };
        self.persist_add(entry)?;
        Ok(IssuedApiKey {
            id,
            key: plaintext,
            label: label.to_string(),
            created_at,
        })
    }

    /// 按 key hash 查找 entry (校验用). 返回 entry 的 clone.
    ///
    /// 用预建的 hash_index 做 O(1) 查找, 避免线性扫描.
    pub fn lookup(&self, plaintext_key: &str) -> Option<ApiKeyEntry> {
        let h = hash_key(plaintext_key);
        self.hash_index.read().get(&h).cloned()
    }

    /// 按 id 删除 entry (撤销 key). 不存在 → NotFound.
    pub fn revoke(&self, id: &str) -> anyhow::Result<bool> {
        let _guard = self.persist_lock.lock();
        let exists = self.entries.read().iter().any(|e| e.id == id);
        if !exists {
            return Ok(false);
        }
        let new_entries: Vec<ApiKeyEntry> = self
            .entries
            .read()
            .iter()
            .filter(|e| e.id != id)
            .cloned()
            .collect();
        self.persist_and_rebuild(&new_entries)?;
        Ok(true)
    }

    /// 列出所有 entry 的摘要 (不含明文/hash).
    pub fn list(&self) -> Vec<ApiKeySummary> {
        self.entries
            .read()
            .iter()
            .map(ApiKeySummary::from)
            .collect()
    }

    // ─── 内部持久化 helper ──────────────────────────────────────────────

    /// 添加单个 entry 并持久化 (持有 persist_lock).
    fn persist_add(&self, entry: ApiKeyEntry) -> anyhow::Result<()> {
        let _guard = self.persist_lock.lock();
        let mut new_entries = self.entries.read().clone();
        new_entries.push(entry);
        self.persist_and_rebuild(&new_entries)?;
        Ok(())
    }

    /// 持久化到 state.toml + 原子更新内存 (entries + hash_index).
    /// 调用方必须已持有 persist_lock.
    fn persist_and_rebuild(&self, new_entries: &[ApiKeyEntry]) -> anyhow::Result<()> {
        let mut state = DynamicState::load_or_empty(&self.state_path)?;
        state.api_keys = new_entries.to_vec();
        let text = state.to_toml()?;
        atomic_write(&self.state_path, &text)?;
        // 一次性更新内存: 先建 index, 再同时替换两个字段.
        let index: HashMap<String, ApiKeyEntry> = new_entries
            .iter()
            .map(|e| (e.key_hash.clone(), e.clone()))
            .collect();
        *self.hash_index.write() = index;
        *self.entries.write() = new_entries.to_vec();
        Ok(())
    }
}

// ─── 纯函数: key 生成 + hash ──────────────────────────────────────────────

/// 生成明文 API key: `sg_` + 32 字符 base62 随机串.
fn generate_key() -> String {
    format!("sg_{}", random_slug(32))
}

/// 生成 n 字符的 alphanumeric 随机串 (base62: [A-Za-z0-9]).
fn random_slug(n: usize) -> String {
    use rand::Rng;
    (0..n)
        .map(|_| rand::thread_rng().sample(rand::distributions::Alphanumeric) as char)
        .collect()
}

/// 计算 key 的 SHA-256 hash (hex).
pub(crate) fn hash_key(plaintext: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    hex_encode(&hasher.finalize())
}

/// hex encoding: 常量查表, 避免 format! 的逐字节堆分配.
const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(label: &str) -> PathBuf {
        let id = uuid::Uuid::new_v4().to_string();
        let path = PathBuf::from(format!("/tmp/opencode/tmp/test-apikey-{label}-{id}.toml"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        path
    }

    fn make_store() -> ApiKeyStore {
        let path = tmp_path("store");
        let lock = Arc::new(Mutex::new(()));
        ApiKeyStore::new(vec![], path, lock)
    }

    #[test]
    fn issue_returns_plaintext_and_stores_hash() {
        let store = make_store();
        let issued = store.issue("user-1", "user-1", "test").unwrap();
        assert!(issued.key.starts_with("sg_"));
        assert!(issued.key.len() > 10);
        // 明文不在 entries 中.
        let entries = store.entries.read();
        assert_eq!(entries.len(), 1);
        assert_ne!(entries[0].key_hash, issued.key);
        assert!(entries[0].key_hash.len() == 64); // SHA-256 hex
    }

    #[test]
    fn lookup_finds_issued_key() {
        let store = make_store();
        let issued = store.issue("user-1", "user-1", "test").unwrap();
        let entry = store.lookup(&issued.key).expect("should find issued key");
        assert_eq!(entry.tenant_id, "user-1");
        assert_eq!(entry.label, "test");
    }

    #[test]
    fn lookup_rejects_unknown_key() {
        let store = make_store();
        store.issue("user-1", "user-1", "test").unwrap();
        assert!(store.lookup("sg_wrong_key").is_none());
        assert!(store.lookup("").is_none());
    }

    #[test]
    fn revoke_removes_key() {
        let store = make_store();
        let issued = store.issue("user-1", "user-1", "test").unwrap();
        assert!(store.lookup(&issued.key).is_some());
        let deleted = store.revoke(&issued.id).unwrap();
        assert!(deleted);
        assert!(store.lookup(&issued.key).is_none());
    }

    #[test]
    fn revoke_unknown_id_returns_false() {
        let store = make_store();
        let deleted = store.revoke("ak_nonexistent").unwrap();
        assert!(!deleted);
    }

    #[test]
    fn list_returns_summaries_without_plaintext() {
        let store = make_store();
        store.issue("user-1", "user-1", "label-1").unwrap();
        store.issue("user-2", "user-2", "label-2").unwrap();
        let list = store.list();
        assert_eq!(list.len(), 2);
        // 摘要不含 hash 也不含明文.
        assert!(list.iter().all(|s| !s.id.contains("sg_")));
    }

    #[test]
    fn persistence_survives_reload() {
        let path = tmp_path("persist");
        let lock = Arc::new(Mutex::new(()));
        {
            let store = ApiKeyStore::new(vec![], path.clone(), lock.clone());
            store.issue("user-1", "user-1", "persisted").unwrap();
        }
        // 从同一 state.toml 重新加载.
        let state = DynamicState::load_or_empty(&path).unwrap();
        let store2 = ApiKeyStore::new(state.api_keys, path, lock);
        assert_eq!(store2.entries.read().len(), 1);
        assert_eq!(store2.entries.read()[0].label, "persisted");
    }

    #[test]
    fn hash_key_is_deterministic() {
        assert_eq!(hash_key("sg_abc"), hash_key("sg_abc"));
        assert_ne!(hash_key("sg_abc"), hash_key("sg_abd"));
    }

    #[test]
    fn generated_keys_are_unique() {
        let mut keys = std::collections::HashSet::new();
        for _ in 0..100 {
            keys.insert(generate_key());
        }
        assert_eq!(keys.len(), 100, "100 keys should all be unique");
    }
}
