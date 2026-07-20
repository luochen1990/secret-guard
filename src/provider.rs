//! Provider 类型定义 + Protocol 枚举 + [`DynamicEntry`] 实现 + effective 视图.
//!
//! # 三层数据模型 (与 [`crate::secrets`] 完全对称)
//!
//! [`ProviderTable`] (= [`DynamicTable<Provider>`](crate::config::DynamicTable)) 同时持有:
//! - `static_entries`: 来自 `secret-guard.toml` 的只读基线, 启动时加载, 进程内不可变.
//! - `dynamic_entries`: 来自 `secret-guard.state.toml` 的 WebUI 编辑结果, 可 CRUD.
//! - `decisions`: 对 static id 的 per-item 决策 ([`crate::config::OverrideMode`]),
//!   与 [`crate::secrets::SecretTable`] 共享同一份 [`Decisions`] 实例.
//!
//! 合并 / CRUD / 持久化等所有通用逻辑都在 [`crate::config::DynamicTable`] 中实现,
//! 本模块只补充 Provider 类型特定的小部分: [`DynamicEntry`] impl + effective 视图
//! 的 masked 映射 ([`compute_effective_provider`]).
//!
//! # 并发与持久化
//!
//! 见 [`crate::config::DynamicTable`] 的文档.

use serde::{Deserialize, Serialize};

use crate::config::{
    classify_source, pick_effective, Decisions, DynamicEntry, DynamicState, DynamicTable,
    EffectiveSource, OverrideMode,
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

// ─── DynamicEntry impl: 把 Provider 接入泛型 DynamicTable ─────────────────

impl DynamicEntry for Provider {
    fn id(&self) -> &str {
        &self.id
    }

    fn validate(&self) -> Result<(), String> {
        crate::secrets::validate_id(&self.id)?;
        validate_base_url(&self.base_url)?;
        Ok(())
    }

    fn set_state_field(state: &mut DynamicState, entries: Vec<Self>) {
        state.providers = entries;
    }

    fn get_decision(d: &Decisions, id: &str) -> OverrideMode {
        d.provider(id)
    }

    fn set_decision(d: &mut Decisions, id: &str, mode: OverrideMode) {
        d.set_provider(id, mode);
    }
}

// ─── ProviderTable 别名 + 类型特定 effective 视图 ──────────────────────────

/// Provider 注册表. 进程级共享状态, 由 `ProxyState` 持有.
///
/// 实际类型是 [`DynamicTable<Provider>`](crate::config::DynamicTable),
/// 所有通用方法 (effective_raw / get_effective / upsert_dynamic / ...) 在那里实现;
/// 下面的 `impl DynamicTable<Provider>` 仅补充 Provider 特有的 effective 视图.
pub type ProviderTable = DynamicTable<Provider>;

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

impl DynamicTable<Provider> {
    /// 返回 effective 视图 (WebUI 列表 / 路由层快照). 顺序: 先 static 出现的 id,
    /// 然后仅 dynamic 独有的 id. Disabled 项被排除.
    pub fn effective_snapshot(&self) -> Vec<EffectiveProvider> {
        self.effective_triples()
            .into_iter()
            .filter_map(|(s, d, m)| compute_effective_provider(s, d, m))
            .collect()
    }
}

/// 给定 (static_ver, dynamic_ver, mode), 计算 effective provider 的合并视图.
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
        api_key_masked: crate::secrets::mask_value(&raw.api_key),
        api_key_length,
        id: raw.id,
        protocol: raw.protocol,
        base_url: raw.base_url,
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
    use std::path::PathBuf;
    use std::sync::Arc;

    use parking_lot::RwLock;

    use crate::config::Decisions;

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

    // ─── Protocol / validate_base_url (类型特定) ────────────────────────

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

    // ─── DynamicEntry impl: Provider 特有的 validate 钩子 ───────────────

    #[test]
    fn validate_rejects_bad_id_and_base_url() {
        // id 校验失败.
        let bad_id = Provider {
            id: "has space".into(),
            protocol: Protocol::OpenAI,
            base_url: "https://x".into(),
            api_key: String::new(),
            enabled: true,
            name: None,
        };
        assert!(bad_id.validate().is_err());

        // base_url 校验失败.
        let bad_url = Provider {
            id: "x".into(),
            protocol: Protocol::OpenAI,
            base_url: "not-a-url".into(),
            api_key: String::new(),
            enabled: true,
            name: None,
        };
        assert!(bad_url.validate().is_err());

        // 合法 provider 通过.
        assert!(p("ok", Protocol::OpenAI, "https://x").validate().is_ok());
    }

    // ─── effective_snapshot: 类型特定的 masked 视图 ─────────────────────
    //
    // 通用合并 / CRUD / 持久化行为已在 `crate::config::table_tests` 覆盖
    // (用 SecretEntry 作为 canonical 类型). 这里只测 Provider 特有的
    // EffectiveProvider 字段映射 (api_key masked / source / static_version / ...).

    #[test]
    fn effective_snapshot_includes_provenance_and_masks_api_key() {
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

        // 序列化结果中真实 api_key ("k-...") 不应出现 — masked 字段已脱敏.
        let json = serde_json::to_string(&snap).unwrap();
        assert!(!json.contains("k-static-only"));
        assert!(!json.contains("k-dynamic-only"));
        assert!(json.contains("api_key_masked"));

        let by_id: std::collections::HashMap<String, EffectiveProvider> =
            snap.into_iter().map(|e| (e.id.clone(), e)).collect();

        let s = by_id.get("static-only").unwrap();
        assert_eq!(s.source, EffectiveSource::Static);
        assert!(s.dynamic_version.is_none());
        assert!(s.static_version.is_some());
        assert_ne!(s.api_key_masked, "k-static-only");
        assert_eq!(s.api_key_length, "k-static-only".chars().count());

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
