//! API key 存储: 签发 / 校验 / 撤销 + state.toml 持久化.
//!
//! - 独立的 `Arc<RwLock<Vec<ApiKeyEntry>>>` (不复用 DynamicTable — API key 是纯动态的,
//!   没有 static 基线 / decision override, 套用 DynamicTable 是过度设计).
//! - 持久化复用 [`crate::config::atomic_write`], 与 provider/secret 共享 `persist_lock`.
//! - key 明文永不持久化, 只存 SHA-256 hash. 校验时对请求中的 key 做 hash 比对.
//!
//! # 静态 key
//!
//! 来自 `secret-guard.toml` 的 `[[auth.api_keys]]` 段, 启动时 resolve → hash →
//! 注入 store. 静态 key 的 id 形如 `ak_static_<label>`, 不可删除 (只能 disable/enable).
//! 静态 key 的 disabled 状态持久化在 state.toml 的 `api_keys_disabled` 字段 (以 label 为 key),
//! 以保证用户 disable 后重启仍生效.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::StaticApiKey;
use crate::config::{DynamicState, atomic_write};

/// 一条 API key 注册项. 存 hash, 不存明文.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyEntry {
    pub id: String,
    /// SHA-256 hash of the plaintext key (hex). 永不存明文.
    pub key_hash: String,
    /// 明文 key 的前缀 (如 `sg_abc1`), 用于 WebUI 辨识.
    pub key_prefix: String,
    pub tenant_id: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub label: String,
    /// 是否被禁用. lookup 会跳过 disabled = true 的 key.
    #[serde(default)]
    pub disabled: bool,
}

/// 静态 key 的 id 形如 `ak_static_<label>`, 动态 key 形如 `ak_<random>`.
/// `source` 由 id 前缀推断, 不单独存字段.
pub fn is_static(id: &str) -> bool {
    id.starts_with("ak_static_")
}

/// API key 签发结果 (包含明文, 仅此一次返回给前端).
#[derive(Debug, Serialize)]
pub struct IssuedApiKey {
    pub id: String,
    pub key: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
}

/// API key 摘要 (列表展示, 不含明文也不含 hash).
#[derive(Debug, Serialize)]
pub struct ApiKeySummary {
    pub id: String,
    pub tenant_id: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub key_prefix: String,
    pub source: &'static str,
    pub disabled: bool,
}

impl From<&ApiKeyEntry> for ApiKeySummary {
    fn from(e: &ApiKeyEntry) -> Self {
        Self {
            id: e.id.clone(),
            tenant_id: e.tenant_id.clone(),
            label: e.label.clone(),
            created_at: e.created_at,
            key_prefix: e.key_prefix.clone(),
            source: if is_static(&e.id) {
                "static"
            } else {
                "dynamic"
            },
            disabled: e.disabled,
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
    /// hash → entry 的查找索引 (由 entries 派生, 仅含 enabled entry).
    hash_index: Arc<RwLock<HashMap<String, ApiKeyEntry>>>,
    state_path: Arc<PathBuf>,
    persist_lock: Arc<Mutex<()>>,
}

impl std::fmt::Debug for ApiKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyStore")
            .field("count", &self.entries.read().len())
            .field("state_path", &self.state_path)
            .finish()
    }
}

impl ApiKeyStore {
    /// 构造 store: 合并静态 key (来自 static config) + 动态 key (来自 state.toml).
    /// 静态 key 的 disabled 状态从 `api_keys_disabled` 集合恢复.
    pub fn new(
        static_keys: &[StaticApiKey],
        config_path: &std::path::Path,
        mut entries: Vec<ApiKeyEntry>,
        static_disabled: HashSet<String>,
        state_path: PathBuf,
        persist_lock: Arc<Mutex<()>>,
    ) -> Self {
        // 合并静态 key: resolve 明文 → hash → 注入 entry.
        for sk in static_keys {
            match sk.resolve(config_path) {
                Ok(plaintext) => {
                    let disabled = static_disabled.contains(&sk.label);
                    entries.push(ApiKeyEntry {
                        id: format!("ak_static_{}", sk.label),
                        key_hash: hash_key(&plaintext),
                        key_prefix: plaintext.chars().take(8).collect(),
                        tenant_id: format!("static:{}", sk.label),
                        created_by: "static-config".into(),
                        // UNIX_EPOCH 占位; 前端用 source 字段判断是否显示真实时间.
                        created_at: DateTime::<Utc>::from_timestamp(0, 0).unwrap_or_default(),
                        label: sk.label.clone(),
                        disabled,
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, label = %sk.label, "skipping malformed static API key")
                }
            }
        }
        let hash_index = entries
            .iter()
            .filter(|e| !e.disabled)
            .map(|e| (e.key_hash.clone(), e.clone()))
            .collect();
        Self {
            entries: Arc::new(RwLock::new(entries)),
            hash_index: Arc::new(RwLock::new(hash_index)),
            state_path: Arc::new(state_path),
            persist_lock,
        }
    }

    /// 签发一个新的 API key. 返回明文 (仅此一次).
    pub fn issue(
        &self,
        tenant_id: &str,
        created_by: &str,
        label: &str,
    ) -> anyhow::Result<IssuedApiKey> {
        let plaintext = format!("sg_{}", random_slug(32));
        let created_at = Utc::now();
        let entry = ApiKeyEntry {
            id: format!("ak_{}", random_slug(8)),
            key_hash: hash_key(&plaintext),
            key_prefix: plaintext.chars().take(8).collect(),
            tenant_id: tenant_id.into(),
            created_by: created_by.into(),
            created_at,
            label: label.into(),
            disabled: false,
        };
        let id = entry.id.clone();
        let mut new_entries = self.locked_snapshot();
        new_entries.push(entry);
        self.persist_and_rebuild(&new_entries)?;
        Ok(IssuedApiKey {
            id,
            key: plaintext,
            label: label.into(),
            created_at,
        })
    }

    /// 按 key hash 查找 entry (校验用). 跳过 disabled 的 entry.
    pub fn lookup(&self, plaintext_key: &str) -> Option<ApiKeyEntry> {
        self.hash_index
            .read()
            .get(&hash_key(plaintext_key))
            .cloned()
    }

    /// 按 id 删除 entry. 静态 key 不可删除 (只能 disable).
    pub fn revoke(&self, id: &str) -> anyhow::Result<bool> {
        let _guard = self.persist_lock.lock();
        if is_static(id) {
            anyhow::bail!("static API key cannot be revoked; use disable instead");
        }
        let exists = self.entries.read().iter().any(|e| e.id == id);
        if !exists {
            return Ok(false);
        }
        let new_entries: Vec<_> = self
            .locked_snapshot()
            .into_iter()
            .filter(|e| e.id != id)
            .collect();
        self.persist_and_rebuild(&new_entries)?;
        Ok(true)
    }

    /// 切换 entry 的 disabled 状态. 返回 Some(新状态); None = entry 不存在.
    pub fn set_disabled(&self, id: &str, disabled: bool) -> anyhow::Result<Option<bool>> {
        let _guard = self.persist_lock.lock();
        let Some(_) = self.entries.read().iter().find(|e| e.id == id) else {
            return Ok(None);
        };
        let mut new_entries = self.locked_snapshot();
        for e in new_entries.iter_mut() {
            if e.id == id {
                e.disabled = disabled;
            }
        }
        self.persist_and_rebuild(&new_entries)?;
        Ok(Some(disabled))
    }

    /// 列出所有 entry 的摘要.
    pub fn list(&self) -> Vec<ApiKeySummary> {
        self.entries
            .read()
            .iter()
            .map(ApiKeySummary::from)
            .collect()
    }

    // ─── 内部 helper ────────────────────────────────────────────────────

    /// 快照当前 entries (调用方自行决定是否持锁).
    fn locked_snapshot(&self) -> Vec<ApiKeyEntry> {
        self.entries.read().clone()
    }

    /// 持久化到 state.toml + 重建内存. 调用方必须已持有 persist_lock.
    fn persist_and_rebuild(&self, new_entries: &[ApiKeyEntry]) -> anyhow::Result<()> {
        let mut state = DynamicState::load_or_empty(&self.state_path, "")?;
        // 动态 key 持久化到 [[api_keys]]; 静态 key 的 disabled 状态持久化到 api_keys_disabled.
        state.api_keys = new_entries
            .iter()
            .filter(|e| !is_static(&e.id))
            .cloned()
            .collect();
        state.api_keys_disabled = new_entries
            .iter()
            .filter(|e| is_static(&e.id) && e.disabled)
            .map(|e| e.label.clone())
            .collect();
        let text = state.to_toml()?;
        atomic_write(&self.state_path, &text)?;
        let index = new_entries
            .iter()
            .filter(|e| !e.disabled)
            .map(|e| (e.key_hash.clone(), e.clone()))
            .collect();
        *self.hash_index.write() = index;
        *self.entries.write() = new_entries.to_vec();
        Ok(())
    }
}

// ─── 纯函数: key 生成 + hash ──────────────────────────────────────────────

fn random_slug(n: usize) -> String {
    use rand::Rng;
    (0..n)
        .map(|_| rand::thread_rng().sample(rand::distributions::Alphanumeric) as char)
        .collect()
}

pub(crate) fn hash_key(plaintext: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    hex_encode(&hasher.finalize())
}

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
        let path = PathBuf::from(format!(
            "/tmp/opencode/tmp/test-apikey-{label}-{}.toml",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        path
    }

    fn make_store() -> ApiKeyStore {
        ApiKeyStore::new(
            &[],
            std::path::Path::new("."),
            vec![],
            HashSet::new(),
            tmp_path("store"),
            Arc::new(Mutex::new(())),
        )
    }

    #[test]
    fn issue_and_lookup_roundtrip() {
        let store = make_store();
        let issued = store.issue("u1", "u1", "test").unwrap();
        assert!(issued.key.starts_with("sg_"));
        assert_eq!(store.lookup(&issued.key).unwrap().label, "test");
        assert!(store.lookup("wrong").is_none());
    }

    #[test]
    fn revoke_dynamic_key() {
        let store = make_store();
        let issued = store.issue("u1", "u1", "t").unwrap();
        assert!(store.revoke(&issued.id).unwrap());
        assert!(store.lookup(&issued.key).is_none());
        assert!(!store.revoke(&issued.id).unwrap());
    }

    #[test]
    fn static_key_loaded_and_toggleable() {
        let sk = vec![StaticApiKey {
            label: "ci".into(),
            key: Some("sg_abc12345".into()),
            key_file: None,
        }];
        let store = ApiKeyStore::new(
            &sk,
            std::path::Path::new("."),
            vec![],
            HashSet::new(),
            tmp_path("s"),
            Arc::new(Mutex::new(())),
        );
        assert!(store.lookup("sg_abc12345").is_some());
        // 静态 key 不可删除.
        assert!(store.revoke("ak_static_ci").is_err());
        // disable 后 lookup 找不到.
        assert_eq!(
            store.set_disabled("ak_static_ci", true).unwrap(),
            Some(true)
        );
        assert!(store.lookup("sg_abc12345").is_none());
        // 重新 enable.
        assert_eq!(
            store.set_disabled("ak_static_ci", false).unwrap(),
            Some(false)
        );
        assert!(store.lookup("sg_abc12345").is_some());
    }

    #[test]
    fn static_disabled_persists_across_reload() {
        let sk = vec![StaticApiKey {
            label: "ci".into(),
            key: Some("sg_abc12345".into()),
            key_file: None,
        }];
        let path = tmp_path("persist");
        let lock = Arc::new(Mutex::new(()));
        {
            let store = ApiKeyStore::new(
                &sk,
                std::path::Path::new("."),
                vec![],
                HashSet::new(),
                path.clone(),
                lock.clone(),
            );
            store.set_disabled("ak_static_ci", true).unwrap();
        }
        let state = DynamicState::load_or_empty(&path, "").unwrap();
        let store2 = ApiKeyStore::new(
            &sk,
            std::path::Path::new("."),
            vec![],
            state.api_keys_disabled,
            path,
            lock,
        );
        assert!(
            store2.lookup("sg_abc12345").is_none(),
            "disabled should persist"
        );
    }

    #[test]
    fn dynamic_disabled_persists_across_reload() {
        let path = tmp_path("dyn-persist");
        let lock = Arc::new(Mutex::new(()));
        let issued_id;
        let issued_key;
        {
            let store = ApiKeyStore::new(
                &[],
                std::path::Path::new("."),
                vec![],
                HashSet::new(),
                path.clone(),
                lock.clone(),
            );
            let issued = store.issue("u1", "u1", "t").unwrap();
            issued_id = issued.id;
            issued_key = issued.key;
            store.set_disabled(&issued_id, true).unwrap();
        }
        let state = DynamicState::load_or_empty(&path, "").unwrap();
        let store2 = ApiKeyStore::new(
            &[],
            std::path::Path::new("."),
            state.api_keys,
            state.api_keys_disabled,
            path,
            lock,
        );
        assert!(
            store2.lookup(&issued_key).is_none(),
            "disabled dynamic key should not be found"
        );
        let s = store2
            .list()
            .into_iter()
            .find(|s| s.id == issued_id)
            .unwrap();
        assert!(s.disabled);
    }

    #[test]
    fn list_shows_source() {
        let sk = vec![StaticApiKey {
            label: "ci".into(),
            key: Some("sg_abc12345".into()),
            key_file: None,
        }];
        let store = ApiKeyStore::new(
            &sk,
            std::path::Path::new("."),
            vec![],
            HashSet::new(),
            tmp_path("list"),
            Arc::new(Mutex::new(())),
        );
        store.issue("u1", "u1", "dyn").unwrap();
        let list = store.list();
        assert_eq!(list.len(), 2);
        assert!(list.iter().any(|s| s.source == "static" && s.label == "ci"));
        assert!(
            list.iter()
                .any(|s| s.source == "dynamic" && s.label == "dyn")
        );
    }

    #[test]
    fn hash_key_is_deterministic() {
        assert_eq!(hash_key("sg_abc"), hash_key("sg_abc"));
        assert_ne!(hash_key("sg_abc"), hash_key("sg_abd"));
    }
}
