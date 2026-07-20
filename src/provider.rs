//! Provider 注册表: 类型定义 + 内存存储 + 配置文件持久化.
//!
//! 设计同 [`crate::secrets`]: `Arc<RwLock<Vec<Provider>>>` + 共享 `persist_lock`
//! 串行化整个 RMW, 先持久化 (atomic rename + fsync) 再更新内存.
//!
//! **跨表并发安全**: [`ProviderTable`] 与 [`crate::secrets::SecretTable`] 共享同一把
//! `persist_lock` (见 [`ProviderTable::with_persist_lock`]). 这是必须的, 因为两者都
//! 通过 `Config::load_or_default` → `Config::to_toml` → `atomic_write` 改写同一份
//! `secret-guard.toml`; 若不串行, 一方的读-改-写会覆盖另一方刚写入的字段.
//!
//! **URL 路由**: 见 `server::build_router`, 路径 `/{proto_short}/{provider_id}/*path`
//! 同时编码 ingress protocol 与目标 provider, 为未来跨协议转换预留钩子.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::config::Config;

/// 支持的 LLM 协议.
///
/// `serde(rename_all = "lowercase")` 与 [`Protocol::ALL`] 中的 `name` 字段保持同步,
/// 后者是单一事实来源 (`from_name` / `from_short` 都从 `ALL` 派生).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    OpenAI,
    Anthropic,
    Gemini,
    Ollama,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl Protocol {
    /// 所有变体 + 完整名 (serde 名) + URL 单字母简写. 单一事实来源.
    /// 简写映射: o=OpenAI, a=Anthropic, g=Gemini, l=oLLama.
    pub const ALL: [(Self, &'static str, &'static str); 4] = [
        (Self::OpenAI, "openai", "o"),
        (Self::Anthropic, "anthropic", "a"),
        (Self::Gemini, "gemini", "g"),
        (Self::Ollama, "ollama", "l"),
    ];

    pub fn short(self) -> &'static str {
        Self::ALL
            .into_iter()
            .find(|(p, _, _)| *p == self)
            .map(|(_, _, s)| s)
            .expect("ALL covers every variant")
    }

    pub fn name(self) -> &'static str {
        Self::ALL
            .into_iter()
            .find(|(p, _, _)| *p == self)
            .map(|(_, n, _)| n)
            .expect("ALL covers every variant")
    }

    pub fn from_short(s: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|(_, _, sh)| *sh == s)
            .map(|(p, _, _)| p)
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|(_, n, _)| *n == s)
            .map(|(p, _, _)| p)
    }
}

/// 单个 provider 实例.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    /// 唯一 id (slug). 同一份表中必须唯一. 通过 [`crate::secrets::validate_id`] 校验.
    pub id: String,
    /// 协议: 决定上游的 egress protocol. 当前 MVP 要求 ingress == egress.
    pub protocol: Protocol,
    /// 上游 base URL, 末尾**不带** `/`. 通过 [`validate_base_url`] 校验.
    pub base_url: String,
    /// API key. 明文存储在本地 config 文件中 (本地进程, 不通过网络暴露).
    #[serde(default)]
    pub api_key: String,
    /// 是否启用. `false` 时转发到该 provider 返回 503.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 可选人类可读名称 (Web UI 显示).
    #[serde(default)]
    pub name: Option<String>,
}

/// serde `default` helper: 让 `enabled` 字段缺省为 `true`.
/// `pub(crate)` 以便 `web::api` 复用 (避免重复定义).
pub(crate) fn default_true() -> bool {
    true
}

/// 校验 base_url. 必须是 http/https, 末尾不带 `/` (避免拼路径时双 `/`).
pub fn validate_base_url(url: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err("base_url must not be empty".to_string());
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("base_url must start with http:// or https://".to_string());
    }
    if url.ends_with('/') {
        return Err("base_url must not end with '/' (path is appended automatically)".to_string());
    }
    Ok(())
}

/// Provider 注册表. 进程级共享状态, 由 `ProxyState` 持有.
#[derive(Clone)]
pub struct ProviderTable {
    inner: Arc<RwLock<Vec<Provider>>>,
    /// 与 SecretTable 共享的持久化锁, 避免两表并发写 config 互相覆盖.
    persist_lock: Arc<Mutex<()>>,
    config_path: Arc<PathBuf>,
}

impl std::fmt::Debug for ProviderTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderTable")
            .field("count", &self.inner.read().len())
            .field("config_path", &self.config_path)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertKind {
    Inserted,
    Updated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    Deleted,
    NotFound,
}

impl ProviderTable {
    pub fn new(entries: Vec<Provider>, config_path: PathBuf) -> Self {
        Self::with_persist_lock(entries, config_path, Arc::new(Mutex::new(())))
    }

    /// 用外部共享的 `persist_lock` 构造. server 启动时创建一把锁传给 SecretTable
    /// 与 ProviderTable, 保证两者对 config 文件的 RMW 串行化.
    pub fn with_persist_lock(
        entries: Vec<Provider>,
        config_path: PathBuf,
        persist_lock: Arc<Mutex<()>>,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(entries)),
            persist_lock,
            config_path: Arc::new(config_path),
        }
    }

    pub fn snapshot(&self) -> Vec<Provider> {
        self.inner.read().clone()
    }

    pub fn get(&self, id: &str) -> Option<Provider> {
        self.inner.read().iter().find(|p| p.id == id).cloned()
    }

    /// 新增 / 覆盖 (按 id 去重). 与 `SecretTable::upsert` 同构.
    pub fn upsert(&self, entry: Provider) -> anyhow::Result<(Provider, UpsertKind)> {
        crate::secrets::validate_id(&entry.id).map_err(anyhow::Error::msg)?;
        validate_base_url(&entry.base_url).map_err(anyhow::Error::msg)?;
        let _guard = self.persist_lock.lock();
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
        persist_providers(&self.config_path, &new_entries)?;
        *self.inner.write() = new_entries;
        Ok((entry, kind))
    }

    pub fn delete(&self, id: &str) -> anyhow::Result<DeleteOutcome> {
        let _guard = self.persist_lock.lock();
        let (new_entries, _existed) = {
            let g = self.inner.read();
            let existed = g.iter().any(|e| e.id == id);
            if !existed {
                return Ok(DeleteOutcome::NotFound);
            }
            let v: Vec<_> = g.iter().filter(|e| e.id != id).cloned().collect();
            (v, true)
        };
        persist_providers(&self.config_path, &new_entries)?;
        *self.inner.write() = new_entries;
        Ok(DeleteOutcome::Deleted)
    }
}

/// 写回 config 文件的 `[providers]` 段. 调用方必须持有 (共享的) `persist_lock`.
fn persist_providers(path: &Path, providers: &[Provider]) -> anyhow::Result<()> {
    let mut cfg = Config::load_or_default(path)?;
    cfg.providers = providers.to_vec();
    let text = cfg.to_toml()?;
    crate::secrets::atomic_write(path, &text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(id: &str, proto: Protocol, base: &str) -> Provider {
        Provider {
            id: id.into(),
            protocol: proto,
            base_url: base.into(),
            api_key: "k".into(),
            enabled: true,
            name: Some(format!("name-{id}")),
        }
    }

    fn tempfile_path() -> PathBuf {
        let id = uuid::Uuid::new_v4().to_string();
        let path = PathBuf::from(format!("/tmp/opencode/tmp/test-providers-{id}.toml"));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn protocol_short_roundtrip() {
        for (proto, _, short) in Protocol::ALL {
            assert_eq!(Protocol::from_short(short), Some(proto));
            assert_eq!(proto.short(), short);
        }
        assert_eq!(Protocol::from_short("x"), None);
    }

    #[test]
    fn protocol_name_roundtrip() {
        for (proto, name, _) in Protocol::ALL {
            assert_eq!(Protocol::from_name(name), Some(proto));
            assert_eq!(proto.name(), name);
        }
        assert_eq!(Protocol::from_name("xxx"), None);
    }

    #[test]
    fn validate_base_url_rejects_bad_inputs() {
        assert!(validate_base_url("").is_err());
        assert!(validate_base_url("ftp://x").is_err());
        assert!(validate_base_url("http://x/").is_err());
        assert!(validate_base_url("https://api.openai.com").is_ok());
        assert!(validate_base_url("http://localhost:11434").is_ok());
    }

    #[test]
    fn upsert_insert_then_update() {
        let tmp = tempfile_path();
        let t = ProviderTable::new(vec![], tmp.clone());
        let (_, k1) = t
            .upsert(p("oa-1", Protocol::OpenAI, "https://api.openai.com"))
            .unwrap();
        assert_eq!(k1, UpsertKind::Inserted);
        let (_, k2) = t
            .upsert(p("oa-1", Protocol::OpenAI, "https://api.openai.com/v2"))
            .unwrap();
        assert_eq!(k2, UpsertKind::Updated);
        assert_eq!(t.snapshot().len(), 1);
        assert_eq!(t.get("oa-1").unwrap().base_url, "https://api.openai.com/v2");
    }

    #[test]
    fn delete_removes_and_persists() {
        let tmp = tempfile_path();
        let t = ProviderTable::new(
            vec![
                p("a", Protocol::OpenAI, "https://x"),
                p("b", Protocol::Anthropic, "https://y"),
            ],
            tmp.clone(),
        );
        assert_eq!(t.delete("a").unwrap(), DeleteOutcome::Deleted);
        assert_eq!(t.snapshot().len(), 1);
        let cfg = Config::load_or_default(&tmp).unwrap();
        assert_eq!(cfg.providers.len(), 1);
        assert_eq!(cfg.providers[0].id, "b");
    }

    #[test]
    fn delete_missing_returns_not_found() {
        let tmp = tempfile_path();
        let t = ProviderTable::new(vec![], tmp);
        assert_eq!(t.delete("nope").unwrap(), DeleteOutcome::NotFound);
    }

    #[test]
    fn invalid_id_rejected() {
        let tmp = tempfile_path();
        let t = ProviderTable::new(vec![], tmp);
        let bad = Provider {
            id: "has space".into(),
            protocol: Protocol::OpenAI,
            base_url: "https://x".into(),
            api_key: String::new(),
            enabled: true,
            name: None,
        };
        assert!(t.upsert(bad).is_err());
    }

    #[test]
    fn invalid_base_url_rejected() {
        let tmp = tempfile_path();
        let t = ProviderTable::new(vec![], tmp);
        let bad = Provider {
            id: "x".into(),
            protocol: Protocol::OpenAI,
            base_url: "not-a-url".into(),
            api_key: String::new(),
            enabled: true,
            name: None,
        };
        assert!(t.upsert(bad).is_err());
    }
}
