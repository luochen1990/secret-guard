//! Provider 注册表: 类型定义 + 内存存储 + 双层 (static + dynamic) 持久化.
//!
//! # 三层数据模型
//!
//! [`ProviderTable`] 同时持有:
//! - `static_entries`: 来自 `secret-guard.toml` 的只读基线, 启动时加载, 进程内不可变.
//! - `dynamic_entries`: 来自 `secret-guard.state.toml` 的 WebUI 编辑结果, 可 CRUD.
//! - `decisions`: 对 static id 的 per-item 决策 ([`crate::config::OverrideMode`]),
//!   与 [`crate::secrets::SecretTable`] 共享同一份 [`Decisions`] 实例.
//!
//! # 合并语义 (effective view)
//!
//! 对每个 id, [`ProviderTable::effective_snapshot`] 按 [`OverrideMode`] 计算实际生效值:
//! - `Default`: 若 dynamic 有同 id 则用 dynamic, 否则用 static.
//! - `PreferStatic`: 强制使用 static 原值 (忽略 dynamic override).
//! - `Disabled`: 从 effective view 中完全排除.
//!
//! dynamic-only 的 id (即 static 中不存在的) 总是直接生效, 不受 decision 影响.
//!
//! # 并发与持久化
//!
//! - 内存层: `Arc<RwLock<...>>` 读写并发安全.
//! - 持久化: 任何修改都立即写回 state.toml (atomic rename + fsync).
//! - 跨表并发: `ProviderTable` 与 [`crate::secrets::SecretTable`] 共享同一把
//!   `persist_lock`, 因为两者都改写 state.toml; 不串行化会丢失更新.
//! - 失败回滚: **先持久化, 再更新内存** — 保证内存永远是已持久化的子集.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::config::{
    classify_source, pick_effective, Decisions, DynamicState, EffectiveSource, OverrideMode,
};

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
    /// 唯一 id (slug). 同一份表 (static 或 dynamic) 中必须唯一.
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

// ─── Effective view (合并后的对外视图) ─────────────────────────────────────

// EffectiveSource 现已抽到 `crate::config`, provider / secret 共用同一份 SSOT.
// 详见 [`crate::config::EffectiveSource`].

/// Provider 的合并视图项. 同时携带生效值与 provenance, 供路由层与 WebUI 共用.
///
/// - `effective_*` 字段是路由层实际使用的值;
/// - `static_version` / `dynamic_version` 是原始 baseline, 供 WebUI 渲染对比 / 切换.
#[derive(Debug, Clone, Serialize)]
pub struct EffectiveProvider {
    // ─── effective 字段 (路由层用) ───
    pub id: String,
    pub protocol: Protocol,
    pub base_url: String,
    pub api_key_masked: String,
    pub api_key_length: usize,
    pub enabled: bool,
    pub name: Option<String>,

    // ─── provenance 元信息 (WebUI 渲染用) ───
    pub source: EffectiveSource,
    /// 对此 static id 的决策. 若 static 中无此 id 则恒为 Default.
    pub decision: OverrideMode,
    /// static 中的原始版本 (若存在). 已脱敏 (api_key masked).
    pub static_version: Option<ProviderMasked>,
    /// dynamic 中的覆盖版本 (若存在). 已脱敏.
    pub dynamic_version: Option<ProviderMasked>,
}

/// 对外返回时屏蔽真实 api_key. 仍保留长度提示 (便于排查"是否配置了 key").
#[derive(Debug, Clone, Serialize)]
pub struct ProviderMasked {
    pub id: String,
    pub name: Option<String>,
    pub protocol: Protocol,
    pub base_url: String,
    pub api_key_masked: String,
    pub api_key_length: usize,
    pub enabled: bool,
}

impl From<Provider> for ProviderMasked {
    fn from(p: Provider) -> Self {
        let api_key_length = p.api_key.chars().count();
        Self {
            id: p.id,
            name: p.name,
            protocol: p.protocol,
            base_url: p.base_url,
            api_key_masked: crate::secrets::mask_value(&p.api_key),
            api_key_length,
            enabled: p.enabled,
        }
    }
}

// ─── Upsert / Delete 返回值 ────────────────────────────────────────────────

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

// ─── ProviderTable ─────────────────────────────────────────────────────────

/// Provider 注册表. 进程级共享状态, 由 `ProxyState` 持有.
///
/// 设计见模块顶部文档.
#[derive(Clone)]
pub struct ProviderTable {
    /// 来自 `secret-guard.toml` 的只读基线.
    static_entries: Arc<RwLock<Vec<Provider>>>,
    /// 来自 `secret-guard.state.toml` 的 WebUI 编辑结果.
    dynamic_entries: Arc<RwLock<Vec<Provider>>>,
    /// 与 [`crate::secrets::SecretTable`] 共享的 per-id 决策.
    decisions: Arc<RwLock<Decisions>>,
    /// 与 SecretTable 共享的持久化锁, 避免两表并发写 state 互相覆盖.
    persist_lock: Arc<Mutex<()>>,
    state_path: Arc<PathBuf>,
}

impl std::fmt::Debug for ProviderTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.static_entries.read();
        let d = self.dynamic_entries.read();
        f.debug_struct("ProviderTable")
            .field("static_count", &s.len())
            .field("dynamic_count", &d.len())
            .field("state_path", &self.state_path)
            .finish()
    }
}

impl ProviderTable {
    /// 构造一个空 static 的表 (主要用于测试). 共享 lock 与 decisions 由调用方提供.
    pub fn new(
        static_entries: Vec<Provider>,
        dynamic_entries: Vec<Provider>,
        decisions: Arc<RwLock<Decisions>>,
        state_path: PathBuf,
    ) -> Self {
        Self::with_persist_lock(
            static_entries,
            dynamic_entries,
            decisions,
            state_path,
            Arc::new(Mutex::new(())),
        )
    }

    /// 用外部共享的 `persist_lock` 构造. server 启动时创建一把锁传给 SecretTable
    /// 与 ProviderTable, 保证两者对 state 文件的 RMW 串行化.
    pub fn with_persist_lock(
        static_entries: Vec<Provider>,
        dynamic_entries: Vec<Provider>,
        decisions: Arc<RwLock<Decisions>>,
        state_path: PathBuf,
        persist_lock: Arc<Mutex<()>>,
    ) -> Self {
        Self {
            static_entries: Arc::new(RwLock::new(static_entries)),
            dynamic_entries: Arc::new(RwLock::new(dynamic_entries)),
            decisions,
            persist_lock,
            state_path: Arc::new(state_path),
        }
    }

    /// 返回 effective view (路由 / WebUI 列表 用). 顺序: 先 static 中出现的 id,
    /// 然后仅 dynamic 独有的 id.
    pub fn effective_snapshot(&self) -> Vec<EffectiveProvider> {
        let statics = self.static_entries.read();
        let dynamics = self.dynamic_entries.read();
        let decisions = self.decisions.read();

        let mut out: Vec<EffectiveProvider> = Vec::with_capacity(statics.len() + dynamics.len());
        let mut seen: HashSet<String> = HashSet::new();

        // 1. 遍历 static ids, 按 decision 决定 effective.
        for s in statics.iter() {
            seen.insert(s.id.clone());
            let dyn_opt = dynamics.iter().find(|d| d.id == s.id).cloned();
            let mode = decisions.provider(&s.id);
            let effective = compute_effective_provider(Some(s.clone()), dyn_opt.clone(), mode);
            if let Some(ev) = effective {
                out.push(ev);
            }
        }
        // 2. dynamic-only ids: decision 不适用, 直接生效.
        for d in dynamics.iter() {
            if seen.contains(&d.id) {
                continue;
            }
            seen.insert(d.id.clone());
            let effective =
                compute_effective_provider(None, Some(d.clone()), OverrideMode::Default);
            if let Some(ev) = effective {
                out.push(ev);
            }
        }
        out
    }

    /// 路由层使用: 按 id 取 effective provider (返回完整 Provider, 不脱敏).
    /// 不存在 / Disabled → None.
    pub fn get_effective(&self, id: &str) -> Option<Provider> {
        let statics = self.static_entries.read();
        let dynamics = self.dynamic_entries.read();
        let decisions = self.decisions.read();

        let s = statics.iter().find(|p| p.id == id).cloned();
        let d = dynamics.iter().find(|p| p.id == id).cloned();
        let mode = s
            .as_ref()
            .map(|p| decisions.provider(&p.id))
            .unwrap_or(OverrideMode::Default);

        pick_effective(s, d, mode)
    }

    /// 仅 dynamic 层 CRUD —— upsert. 若 id 同时存在于 static, 此操作创建 / 更新 override.
    pub fn upsert_dynamic(&self, entry: Provider) -> anyhow::Result<(Provider, UpsertKind)> {
        crate::secrets::validate_id(&entry.id).map_err(anyhow::Error::msg)?;
        validate_base_url(&entry.base_url).map_err(anyhow::Error::msg)?;

        let _guard = self.persist_lock.lock();
        let (new_entries, kind) = {
            let g = self.dynamic_entries.read();
            let mut v = g.clone();
            if let Some(e) = v.iter_mut().find(|e| e.id == entry.id) {
                *e = entry.clone();
                (v, UpsertKind::Updated)
            } else {
                v.push(entry.clone());
                (v, UpsertKind::Inserted)
            }
        };
        self.persist_dynamic(&new_entries)?;
        *self.dynamic_entries.write() = new_entries;
        Ok((entry, kind))
    }

    /// 仅 dynamic 层 CRUD —— delete. 若 id 同时存在于 static, 此操作仅移除 override,
    /// 保留 static (decision 不变).
    pub fn delete_dynamic(&self, id: &str) -> anyhow::Result<DeleteOutcome> {
        let _guard = self.persist_lock.lock();
        let new_entries = {
            let g = self.dynamic_entries.read();
            let existed = g.iter().any(|e| e.id == id);
            if !existed {
                return Ok(DeleteOutcome::NotFound);
            }
            g.iter().filter(|e| e.id != id).cloned().collect::<Vec<_>>()
        };
        self.persist_dynamic(&new_entries)?;
        *self.dynamic_entries.write() = new_entries;
        Ok(DeleteOutcome::Deleted)
    }

    /// 设置对某 static id 的决策. 持久化到 state.toml.
    ///
    /// 满足"先持久化, 再更新内存"契约: 若 atomic_write 失败, 内存 decisions 保持旧值
    /// (不会出现内存已切到 disabled 但磁盘还是 default 的漂移).
    pub fn set_decision(&self, id: &str, mode: OverrideMode) -> anyhow::Result<()> {
        let _guard = self.persist_lock.lock();
        // 计算新 decisions, 但不立即提交到内存.
        let new_decisions = {
            let cur = self.decisions.read().clone();
            let mut next = cur;
            next.set_provider(id, mode);
            next
        };
        // 先持久化.
        let mut state = DynamicState::load_or_empty(&self.state_path)?;
        state.decisions = new_decisions.clone();
        let text = state.to_toml()?;
        crate::secrets::atomic_write(&self.state_path, &text)?;
        // 持久化成功后再更新内存.
        *self.decisions.write() = new_decisions;
        Ok(())
    }

    /// 直接查 static 层, 不受 decision 影响. 供 Web handler 在判断 "该 id 是否为 static
    /// 来源" 时使用 — 特别是当 decision=Disabled 时该 id 不在 effective_snapshot 中.
    pub fn has_static(&self, id: &str) -> bool {
        self.static_entries.read().iter().any(|p| p.id == id)
    }

    // ─── 内部持久化 helper ──────────────────────────────────────────────

    /// 重写 state.toml 的 `[[providers]]` 段. 调用方必须持有 persist_lock.
    fn persist_dynamic(&self, new_dynamic: &[Provider]) -> anyhow::Result<()> {
        let mut state = DynamicState::load_or_empty(&self.state_path)?;
        state.providers = new_dynamic.to_vec();
        let text = state.to_toml()?;
        crate::secrets::atomic_write(&self.state_path, &text)
    }
}

// ─── 合并算法 (薄包装, 事实源在 `crate::config`) ───────────────────────────

/// 给定 static / dynamic / decision, 计算 effective provider 的合并视图.
/// 若 Disabled 或三者皆空, 返回 None.
fn compute_effective_provider(
    static_ver: Option<Provider>,
    dynamic_ver: Option<Provider>,
    mode: OverrideMode,
) -> Option<EffectiveProvider> {
    let raw = pick_effective(static_ver.clone(), dynamic_ver.clone(), mode)?;
    let source = classify_source(static_ver.is_some(), dynamic_ver.is_some(), mode)
        .expect("pick_effective Some ⇒ classify_source Some");
    let api_key_length = raw.api_key.chars().count();
    let static_masked = static_ver.map(ProviderMasked::from);
    let dynamic_masked = dynamic_ver.map(ProviderMasked::from);
    Some(EffectiveProvider {
        id: raw.id,
        protocol: raw.protocol,
        base_url: raw.base_url,
        api_key_masked: crate::secrets::mask_value(&raw.api_key),
        api_key_length,
        enabled: raw.enabled,
        name: raw.name,
        source,
        decision: mode,
        static_version: static_masked,
        dynamic_version: dynamic_masked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(id: &str, proto: Protocol, base: &str) -> Provider {
        Provider {
            id: id.into(),
            protocol: proto,
            base_url: base.into(),
            api_key: format!("k-{id}"),
            enabled: true,
            name: Some(format!("name-{id}")),
        }
    }

    fn empty_decisions() -> Arc<RwLock<Decisions>> {
        Arc::new(RwLock::new(Decisions::default()))
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

    // ─── merge 算法 (事实源在 crate::config, 这里测 provider 层薄包装) ──

    #[test]
    fn pick_static_only_default() {
        let s = p("a", Protocol::OpenAI, "https://x");
        let r = pick_effective(Some(s.clone()), None, OverrideMode::Default);
        assert_eq!(r.unwrap().base_url, "https://x");
    }

    #[test]
    fn pick_dynamic_override() {
        let s = p("a", Protocol::OpenAI, "https://static");
        let d = p("a", Protocol::OpenAI, "https://dynamic");
        let r = pick_effective(Some(s), Some(d.clone()), OverrideMode::Default);
        assert_eq!(r.unwrap().base_url, "https://dynamic");
    }

    #[test]
    fn pick_prefer_static_wins_over_dynamic() {
        let s = p("a", Protocol::OpenAI, "https://static");
        let d = p("a", Protocol::OpenAI, "https://dynamic");
        let r = pick_effective(Some(s.clone()), Some(d), OverrideMode::PreferStatic);
        assert_eq!(r.unwrap().base_url, "https://static");
    }

    #[test]
    fn pick_disabled_drops_everything() {
        let s = p("a", Protocol::OpenAI, "https://static");
        let d = p("a", Protocol::OpenAI, "https://dynamic");
        assert!(pick_effective(Some(s), Some(d), OverrideMode::Disabled).is_none());
    }

    #[test]
    fn pick_dynamic_only() {
        let d = p("a", Protocol::OpenAI, "https://d");
        let r = pick_effective(None, Some(d.clone()), OverrideMode::Default);
        assert_eq!(r.unwrap().base_url, "https://d");
    }

    // ─── table 行为 (含持久化) ──────────────────────────────────────────

    #[test]
    fn upsert_dynamic_insert_then_update() {
        let tmp = tempfile_path();
        let t = ProviderTable::new(vec![], vec![], empty_decisions(), tmp.clone());
        let (_, k1) = t
            .upsert_dynamic(p("oa-1", Protocol::OpenAI, "https://api.openai.com"))
            .unwrap();
        assert_eq!(k1, UpsertKind::Inserted);
        let (_, k2) = t
            .upsert_dynamic(p("oa-1", Protocol::OpenAI, "https://api.openai.com/v2"))
            .unwrap();
        assert_eq!(k2, UpsertKind::Updated);
        let snap = t.effective_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].base_url, "https://api.openai.com/v2");
    }

    #[test]
    fn delete_dynamic_removes_and_persists() {
        let tmp = tempfile_path();
        let t = ProviderTable::new(
            vec![],
            vec![
                p("a", Protocol::OpenAI, "https://x"),
                p("b", Protocol::Anthropic, "https://y"),
            ],
            empty_decisions(),
            tmp.clone(),
        );
        assert_eq!(t.delete_dynamic("a").unwrap(), DeleteOutcome::Deleted);
        assert_eq!(t.effective_snapshot().len(), 1);
        let state = DynamicState::load_or_empty(&tmp).unwrap();
        assert_eq!(state.providers.len(), 1);
        assert_eq!(state.providers[0].id, "b");
    }

    #[test]
    fn delete_dynamic_missing_returns_not_found() {
        let tmp = tempfile_path();
        let t = ProviderTable::new(vec![], vec![], empty_decisions(), tmp);
        assert_eq!(t.delete_dynamic("nope").unwrap(), DeleteOutcome::NotFound);
    }

    #[test]
    fn delete_dynamic_keeps_static_baseline() {
        // 当 static + dynamic 同时有此 id, 删除 dynamic 仅移除 override, static 仍生效.
        let tmp = tempfile_path();
        let s = p("a", Protocol::OpenAI, "https://static");
        let d = p("a", Protocol::OpenAI, "https://dynamic");
        let t = ProviderTable::new(vec![s], vec![d], empty_decisions(), tmp);
        assert_eq!(t.delete_dynamic("a").unwrap(), DeleteOutcome::Deleted);
        let snap = t.effective_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].base_url, "https://static"); // 回到 static 基线
    }

    #[test]
    fn set_decision_disabled_then_default() {
        let tmp = tempfile_path();
        let s = p("a", Protocol::OpenAI, "https://x");
        let t = ProviderTable::new(vec![s], vec![], empty_decisions(), tmp.clone());

        t.set_decision("a", OverrideMode::Disabled).unwrap();
        assert!(t.get_effective("a").is_none());
        let snap = t.effective_snapshot();
        assert!(snap.is_empty(), "disabled drops from effective view");

        // 重启 (重新加载 state) 后 decision 应持久化.
        let state = DynamicState::load_or_empty(&tmp).unwrap();
        assert_eq!(state.decisions.provider("a"), OverrideMode::Disabled);

        // 切回 Default.
        t.set_decision("a", OverrideMode::Default).unwrap();
        assert!(t.get_effective("a").is_some());
    }

    #[test]
    fn invalid_id_rejected_on_upsert() {
        let tmp = tempfile_path();
        let t = ProviderTable::new(vec![], vec![], empty_decisions(), tmp);
        let bad = Provider {
            id: "has space".into(),
            protocol: Protocol::OpenAI,
            base_url: "https://x".into(),
            api_key: String::new(),
            enabled: true,
            name: None,
        };
        assert!(t.upsert_dynamic(bad).is_err());
    }

    #[test]
    fn invalid_base_url_rejected() {
        let tmp = tempfile_path();
        let t = ProviderTable::new(vec![], vec![], empty_decisions(), tmp);
        let bad = Provider {
            id: "x".into(),
            protocol: Protocol::OpenAI,
            base_url: "not-a-url".into(),
            api_key: String::new(),
            enabled: true,
            name: None,
        };
        assert!(t.upsert_dynamic(bad).is_err());
    }

    #[test]
    fn effective_snapshot_includes_static_dynamic_and_override() {
        let tmp = tempfile_path();
        let s_only = p("static-only", Protocol::OpenAI, "https://static-only");
        let d_only = p("dynamic-only", Protocol::Anthropic, "https://dynamic-only");
        let s_base = p("override-id", Protocol::Gemini, "https://static-base");
        let d_over = p("override-id", Protocol::Gemini, "https://dynamic-override");

        let t = ProviderTable::new(
            vec![s_only, s_base],
            vec![d_only, d_over],
            empty_decisions(),
            tmp,
        );
        let snap = t.effective_snapshot();
        assert_eq!(snap.len(), 3);

        let by_id: std::collections::HashMap<String, EffectiveProvider> =
            snap.into_iter().map(|e| (e.id.clone(), e)).collect();

        let s = by_id.get("static-only").unwrap();
        assert_eq!(s.source, EffectiveSource::Static);
        assert!(s.dynamic_version.is_none());

        let d = by_id.get("dynamic-only").unwrap();
        assert_eq!(d.source, EffectiveSource::Dynamic);
        assert!(d.static_version.is_none());

        let ov = by_id.get("override-id").unwrap();
        assert_eq!(ov.source, EffectiveSource::DynamicOverride);
        assert_eq!(ov.base_url, "https://dynamic-override");
        assert!(ov.static_version.is_some());
        assert!(ov.dynamic_version.is_some());
    }
}
