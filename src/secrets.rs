//! Secret 注册表: 类型定义 + 内存存储 + 配置文件持久化.
//!
//! 设计:
//! - [`SecretTable`] 是进程级共享状态, 由 `ProxyState` 持有.
//! - 内存层: `Arc<RwLock<Vec<SecretEntry>>>`, 读写并发安全.
//! - 持久化层: 任何修改都立即写回 TOML 配置文件 (原子 rename, 防止半写状态).
//!
//! 第四步的 find-and-replace 将读取这里的 [`SecretTable::snapshot`] 获取最新列表.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::config::Config;

/// 单条 secret 注册项.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// 唯一 id (slug). 同一份表中必须唯一.
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
    pub fn all() -> &'static [SecretCategory] {
        &[
            SecretCategory::Password,
            SecretCategory::ApiKey,
            SecretCategory::Token,
            SecretCategory::Cookie,
            SecretCategory::PrivateKey,
            SecretCategory::Other,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SecretCategory::Password => "password",
            SecretCategory::ApiKey => "apikey",
            SecretCategory::Token => "token",
            SecretCategory::Cookie => "cookie",
            SecretCategory::PrivateKey => "privatekey",
            SecretCategory::Other => "other",
        }
    }
}

/// Secret 表. 在 ProxyState 中作为共享可变状态.
#[derive(Clone)]
pub struct SecretTable {
    inner: Arc<RwLock<Vec<SecretEntry>>>,
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

impl SecretTable {
    pub fn new(entries: Vec<SecretEntry>, config_path: PathBuf) -> Self {
        Self {
            inner: Arc::new(RwLock::new(entries)),
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

    /// 新增 / 覆盖 (按 id 去重). 写回 config 文件.
    pub fn upsert(&self, entry: SecretEntry) -> anyhow::Result<SecretEntry> {
        {
            let mut g = self.inner.write();
            if let Some(existing) = g.iter_mut().find(|e| e.id == entry.id) {
                *existing = entry.clone();
            } else {
                g.push(entry.clone());
            }
        }
        self.persist()?;
        Ok(entry)
    }

    /// 按 id 删除. 不存在时返回 false (不视为错误). 写回 config 文件.
    pub fn delete(&self, id: &str) -> anyhow::Result<bool> {
        let removed = {
            let mut g = self.inner.write();
            let before = g.len();
            g.retain(|e| e.id != id);
            before != g.len()
        };
        if removed {
            self.persist()?;
        }
        Ok(removed)
    }

    /// 把当前内存中的 entries 写回 config 文件 (原子 rename).
    fn persist(&self) -> anyhow::Result<()> {
        let entries = self.inner.read().clone();
        let mut cfg = Config::load_or_default(&self.config_path)?;
        cfg.secrets.entries = entries;
        let text = cfg.to_toml()?;
        atomic_write(&self.config_path, &text)
    }
}

/// 原子写文件: 先写 `.tmp`, 再 rename. 防止半写状态.
fn atomic_write(path: &Path, text: &str) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config path has no parent: {}", path.display()))?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("invalid config file name: {}", path.display()))?
    ));
    std::fs::write(&tmp, text)
        .map_err(|e| anyhow::anyhow!("write tmp {} failed: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
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

    #[test]
    fn snapshot_is_isolated() {
        let t = SecretTable::new(vec![entry("a", "v1")], PathBuf::from("/tmp/x.toml"));
        let mut snap = t.snapshot();
        snap.clear();
        // 修改 snapshot 不影响 table.
        assert_eq!(t.snapshot().len(), 1);
    }

    #[test]
    fn upsert_inserts_then_updates() {
        let tmp = tempfile_path();
        let t = SecretTable::new(vec![], tmp.clone());
        t.upsert(entry("a", "v1")).unwrap();
        assert_eq!(t.snapshot().len(), 1);
        t.upsert(entry("a", "v2")).unwrap();
        assert_eq!(t.snapshot().len(), 1);
        assert_eq!(t.get("a").unwrap().value, "v2");
    }

    #[test]
    fn delete_removes_and_persists() {
        let tmp = tempfile_path();
        let t = SecretTable::new(vec![entry("a", "v1"), entry("b", "v2")], tmp.clone());
        let removed = t.delete("a").unwrap();
        assert!(removed);
        assert_eq!(t.snapshot().len(), 1);
        // 重新加载配置: 持久化生效.
        let cfg = Config::load_or_default(&tmp).unwrap();
        assert_eq!(cfg.secrets.entries.len(), 1);
        assert_eq!(cfg.secrets.entries[0].id, "b");
    }

    #[test]
    fn delete_missing_returns_false() {
        let tmp = tempfile_path();
        let t = SecretTable::new(vec![], tmp);
        let removed = t.delete("nope").unwrap();
        assert!(!removed);
    }

    fn tempfile_path() -> PathBuf {
        let id = uuid::Uuid::new_v4().to_string();
        let path = PathBuf::from(format!("/tmp/opencode/tmp/test-secrets-{id}.toml"));
        // 删除可能存在的旧文件 (load_or_default 会处理不存在情况).
        let _ = std::fs::remove_file(&path);
        path
    }
}
