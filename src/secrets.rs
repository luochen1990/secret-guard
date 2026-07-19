//! Secret 注册表: 类型定义 + 内存存储 + 配置文件持久化.
//!
//! 设计:
//! - [`SecretTable`] 是进程级共享状态, 由 `ProxyState` 持有.
//! - 内存层: `Arc<RwLock<Vec<SecretEntry>>>`, 读写并发安全.
//! - 持久化层: 任何修改都立即写回 TOML 配置文件 (原子 rename + fsync, 防止半写状态).
//! - 失败回滚: **先持久化, 再更新内存** — 保证内存永远是已持久化的子集.
//! - 持久化串行化: 一把独立的 `Mutex` 串行所有 persist 调用, 避免 tmp 文件冲突.
//!
//! 第四步的 find-and-replace 将读取这里的 [`SecretTable::snapshot`] 获取最新列表.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::config::Config;

/// 单条 secret 注册项.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// 唯一 id (slug). 同一份表中必须唯一.
    /// 通过 [`validate_id`] 校验合法字符集.
    pub id: String,
    /// 可选的人类可读名称 (用于 Web UI 显示).
    #[serde(default)]
    pub name: Option<String>,
    /// 类别: 影响 mock_secret 的生成策略 (第四步细化).
    #[serde(default)]
    pub category: SecretCategory,
    /// 真实 secret 明文 (服务端使用; 永不通过 API 返回).
    pub value: String,
}

/// Secret 类别. 用于第四步选择不同的 mock 生成器.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecretCategory {
    /// 密码 (相对短, 任意可打印字符).
    Password,
    /// API key (通常较长, 固定前缀如 sk-/ANTHROPIC-/AKIA).
    #[default]
    ApiKey,
    /// 长 bearer token (JWT 等).
    Token,
    /// Cookie 值.
    Cookie,
    /// 私钥 (PEM 等, 多行).
    PrivateKey,
    /// 兜底.
    Other,
}

impl SecretCategory {
    /// 所有变体及其字符串名 (与 `#[serde(rename_all = "lowercase")]` 同步).
    /// 单一事实来源: `all()` 与 `as_str()` 均从这里派生.
    pub const ALL: [(Self, &'static str); 6] = [
        (Self::Password, "password"),
        (Self::ApiKey, "apikey"),
        (Self::Token, "token"),
        (Self::Cookie, "cookie"),
        (Self::PrivateKey, "privatekey"),
        (Self::Other, "other"),
    ];

    pub fn as_str(self) -> &'static str {
        Self::ALL
            .into_iter()
            .find(|(c, _)| *c == self)
            .map(|(_, s)| s)
            .expect("ALL covers every variant")
    }
}

/// 校验 secret id (slug). 允许: 字母/数字开头, 长度 1-64, 仅含 `[A-Za-z0-9_-]`.
/// 防止 XSS / 路径冲突 / 路由切段问题.
pub fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 64 {
        return Err(format!("id length must be 1..=64, got {}", id.len()));
    }
    let mut chars = id.chars();
    let first = chars.next().expect("non-empty checked above");
    if !first.is_ascii_alphanumeric() {
        return Err(format!("id must start with [A-Za-z0-9], got '{first}'"));
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(format!(
                "id contains illegal character '{c}' (allowed: alphanumeric, '_', '-')"
            ));
        }
    }
    Ok(())
}

/// Secret 表. 在 ProxyState 中作为共享可变状态.
#[derive(Clone)]
pub struct SecretTable {
    inner: Arc<RwLock<Vec<SecretEntry>>>,
    /// 独立的持久化锁: 串行所有 persist 调用, 避免 tmp 文件名竞态.
    persist_lock: Arc<Mutex<()>>,
    config_path: Arc<PathBuf>,
}

impl std::fmt::Debug for SecretTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretTable")
            .field("count", &self.inner.read().len())
            .field("config_path", &self.config_path)
            .finish()
    }
}

/// `upsert` / `delete` 的返回值: 明确区分 "新增" / "更新" / "不存在" 语义.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertKind {
    Inserted,
    Updated,
}

impl SecretTable {
    pub fn new(entries: Vec<SecretEntry>, config_path: PathBuf) -> Self {
        Self {
            inner: Arc::new(RwLock::new(entries)),
            persist_lock: Arc::new(Mutex::new(())),
            config_path: Arc::new(config_path),
        }
    }

    /// 当前所有 secret 的快照 (深拷贝, 调用方可自由修改).
    pub fn snapshot(&self) -> Vec<SecretEntry> {
        self.inner.read().clone()
    }

    /// 通过 id 查找单条 secret.
    pub fn get(&self, id: &str) -> Option<SecretEntry> {
        self.inner.read().iter().find(|e| e.id == id).cloned()
    }

    /// 新增 / 覆盖 (按 id 去重). 返回最终保存的 entry + insert/update 标记.
    /// 写回 config 文件 (失败时内存自动回滚, 因为是"先持久化再更新内存").
    ///
    /// 并发语义: 整个 RMW (read-modify-write) 在 [`persist_lock`] 内串行执行,
    /// 保证两个并发 upsert 不会互相覆盖. 读取 (snapshot/get) 不持此锁, 不阻塞.
    pub fn upsert(&self, entry: SecretEntry) -> anyhow::Result<(SecretEntry, UpsertKind)> {
        validate_id(&entry.id).map_err(anyhow::Error::msg)?;
        let _guard = self.persist_lock.lock();
        // 1. 读当前 entries, 计算新版本.
        let (new_entries, kind) = {
            let g = self.inner.read();
            let mut v = g.clone();
            if let Some(e) = v.iter_mut().find(|e| e.id == entry.id) {
                *e = entry.clone();
                (v, UpsertKind::Updated)
            } else {
                v.push(entry.clone());
                (v, UpsertKind::Inserted)
            }
        };
        // 2. 先持久化 (失败时 inner 未变, 自动回滚).
        self.persist_entries(&new_entries)?;
        // 3. 持久化成功后再更新内存.
        *self.inner.write() = new_entries;
        Ok((entry, kind))
    }

    /// 按 id 删除. 不存在时返回 NotFound (由调用方决定 404).
    pub fn delete(&self, id: &str) -> anyhow::Result<DeleteOutcome> {
        let _guard = self.persist_lock.lock();
        // 1. 计算新 entries.
        let (new_entries, existed) = {
            let g = self.inner.read();
            let existed = g.iter().any(|e| e.id == id);
            if !existed {
                return Ok(DeleteOutcome::NotFound);
            }
            let v: Vec<_> = g.iter().filter(|e| e.id != id).cloned().collect();
            (v, true)
        };
        // 2. 先持久化.
        self.persist_entries(&new_entries)?;
        // 3. 更新内存.
        *self.inner.write() = new_entries;
        debug_assert!(existed);
        Ok(DeleteOutcome::Deleted)
    }

    /// 写回 config 文件. 调用方必须持有 [`persist_lock`] (避免并发 persist 互相覆盖).
    fn persist_entries(&self, entries: &[SecretEntry]) -> anyhow::Result<()> {
        let mut cfg = Config::load_or_default(&self.config_path)?;
        cfg.secrets.entries = entries.to_vec();
        let text = cfg.to_toml()?;
        atomic_write(&self.config_path, &text)
    }
}

/// `delete` 的返回值, 明确区分"删除了"vs"不存在".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    Deleted,
    NotFound,
}

/// 原子写文件: 先写带 UUID 的 `.tmp`, sync, 再 rename.
fn atomic_write(path: &Path, text: &str) -> anyhow::Result<()> {
    use std::io::Write;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config path has no parent: {}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid config file name: {}", path.display()))?;
    // tmp 名带 UUID: 防止并发 persist 互相覆盖.
    let tmp_name = format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4().simple());
    let tmp = parent.join(&tmp_name);

    let mut f = std::fs::File::create(&tmp)
        .map_err(|e| anyhow::anyhow!("create tmp {} failed: {e}", tmp.display()))?;
    f.write_all(text.as_bytes())
        .map_err(|e| anyhow::anyhow!("write tmp {} failed: {e}", tmp.display()))?;
    f.sync_all()
        .map_err(|e| anyhow::anyhow!("fsync tmp {} failed: {e}", tmp.display()))?;
    drop(f);

    std::fs::rename(&tmp, path).map_err(|e| {
        // 失败时尝试清理 tmp.
        let _ = std::fs::remove_file(&tmp);
        anyhow::anyhow!("rename {} -> {} failed: {e}", tmp.display(), path.display())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, value: &str) -> SecretEntry {
        SecretEntry {
            id: id.into(),
            name: Some(format!("name-{id}")),
            category: SecretCategory::ApiKey,
            value: value.into(),
        }
    }

    fn tempfile_path() -> PathBuf {
        let id = uuid::Uuid::new_v4().to_string();
        let path = PathBuf::from(format!("/tmp/opencode/tmp/test-secrets-{id}.toml"));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn snapshot_is_isolated() {
        let t = SecretTable::new(vec![entry("a", "v1")], PathBuf::from("/tmp/x.toml"));
        let mut snap = t.snapshot();
        snap.clear();
        assert_eq!(t.snapshot().len(), 1);
    }

    #[test]
    fn upsert_inserts_then_updates() {
        let tmp = tempfile_path();
        let t = SecretTable::new(vec![], tmp.clone());
        let (_, k1) = t.upsert(entry("a", "v1")).unwrap();
        assert_eq!(k1, UpsertKind::Inserted);
        assert_eq!(t.snapshot().len(), 1);
        let (_, k2) = t.upsert(entry("a", "v2")).unwrap();
        assert_eq!(k2, UpsertKind::Updated);
        assert_eq!(t.snapshot().len(), 1);
        assert_eq!(t.get("a").unwrap().value, "v2");
    }

    #[test]
    fn delete_removes_and_persists() {
        let tmp = tempfile_path();
        let t = SecretTable::new(vec![entry("a", "v1"), entry("b", "v2")], tmp.clone());
        assert_eq!(t.delete("a").unwrap(), DeleteOutcome::Deleted);
        assert_eq!(t.snapshot().len(), 1);
        let cfg = Config::load_or_default(&tmp).unwrap();
        assert_eq!(cfg.secrets.entries.len(), 1);
        assert_eq!(cfg.secrets.entries[0].id, "b");
    }

    #[test]
    fn delete_missing_returns_not_found() {
        let tmp = tempfile_path();
        let t = SecretTable::new(vec![], tmp);
        assert_eq!(t.delete("nope").unwrap(), DeleteOutcome::NotFound);
    }

    #[test]
    fn invalid_id_rejected() {
        let tmp = tempfile_path();
        let t = SecretTable::new(vec![], tmp);
        let bad = SecretEntry {
            id: "has space".into(),
            name: None,
            category: SecretCategory::Other,
            value: "v".into(),
        };
        assert!(t.upsert(bad).is_err());
    }

    #[test]
    fn leading_dash_id_rejected() {
        let tmp = tempfile_path();
        let t = SecretTable::new(vec![], tmp);
        let bad = SecretEntry {
            id: "-leading-dash".into(),
            name: None,
            category: SecretCategory::Other,
            value: "v".into(),
        };
        assert!(t.upsert(bad).is_err());
    }

    #[test]
    fn concurrent_upserts_no_lost_update() {
        // Smoke test: 两个线程并发 upsert 不同的 id, 两者都应该最终可见.
        let tmp = tempfile_path();
        let t = SecretTable::new(vec![], tmp);
        let t1 = t.clone();
        let t2 = t.clone();
        let h1 = std::thread::spawn(move || t1.upsert(entry("a", "v1")));
        let h2 = std::thread::spawn(move || t2.upsert(entry("b", "v2")));
        h1.join().unwrap().unwrap();
        h2.join().unwrap().unwrap();
        let snap = t.snapshot();
        let ids: Vec<_> = snap.iter().map(|e| e.id.clone()).collect();
        assert!(ids.contains(&"a".to_string()), "lost update: {ids:?}");
        assert!(ids.contains(&"b".to_string()), "lost update: {ids:?}");
    }
    #[test]
    fn validate_id_accepts_valid_slugs() {
        assert!(validate_id("a").is_ok());
        assert!(validate_id("abc-123_XYZ").is_ok());
        assert!(validate_id(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn validate_id_rejects_invalid() {
        assert!(validate_id("").is_err());
        assert!(validate_id(&"a".repeat(65)).is_err());
        assert!(validate_id("-abc").is_err());
        assert!(validate_id("_abc").is_err());
        assert!(validate_id("has space").is_err());
        assert!(validate_id("slash/here").is_err());
        assert!(validate_id("quote'here").is_err());
        assert!(validate_id("<html>").is_err());
    }
}
