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
//! 的 masked 映射 (`compute_effective_provider`).
//!
//! # 并发与持久化
//!
//! 见 [`crate::config::DynamicTable`] 的文档.
//!
//! # api_key 的两种来源 (`effective_api_key`)
//!
//! `Provider` 同时支持两种 api_key 配置方式 (互斥, 同时设置会在 `validate()` 报错):
//!
//! | 字段 | 类型 | 适用场景 |
//! |---|---|---|
//! | `api_key` | `String` (直接值) | 本地 dev / 简单部署 |
//! | `api_key_file` | `Option<PathBuf>` (从文件读取) | 生产部署 / sops-nix / systemd LoadCredential |
//!
//! 优先级: 直接值 > 文件 > 空. **运行时每次请求读文件** (热路径), 读不到 → warn + 空字符串 fallback
//! (单 provider 配置错误不拖垮进程, 因为 provider 失败只影响转发, 不影响安全性).
//! 文件内容会被 `trim()` (容忍 sops / `echo | tee` 末尾换行符). 部署示例见 `docs/deployment-nixos.md`.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::LazyLock;

use parking_lot::Mutex;

use crate::config::{
    Decisions, DynamicEntry, DynamicState, DynamicTable, EffectiveSource, OverrideMode,
    classify_source, pick_effective,
};

/// 记录已经 warn 过 api_key_file 读失败的 provider id.
/// 实现健康→失败 warn 一次, 恢复后下次失败再 warn 的模式, 避免 LLM 高 QPS 场景下日志爆.
/// 文件可读时清除记录, 让后续失败能再次 warn (运维改了配置后会看到新 warn).
/// 用 parking_lot::Mutex 与项目其他模块 (config/server/record/secrets) 同步原语一致.
static WARNED_API_KEY_FILE: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

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
    /// OpenAI Responses API (`POST /v1/responses`).
    ///
    /// 与 [`Self::OpenAI`] (Chat Completions) 是同一供应商的两套不同 wire 协议,
    /// 字段结构差异显著 (input/instructions vs messages, output items vs choices,
    /// typed SSE events vs flat chunks), 故独立为一个 protocol 变体.
    /// proto_short = `r` (Responses).
    OpenAIResponses,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl Protocol {
    /// 所有变体 + 完整名 (serde 名) + URL 单字母简写. 单一事实来源.
    /// 简写映射: o=OpenAI, a=Anthropic, g=Gemini, l=oLLama, r=Responses.
    pub const ALL: [(Self, &'static str, &'static str); 5] = [
        (Self::OpenAI, "openai", "o"),
        (Self::Anthropic, "anthropic", "a"),
        (Self::Gemini, "gemini", "g"),
        (Self::Ollama, "ollama", "l"),
        (Self::OpenAIResponses, "openairesponses", "r"),
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
    /// API key 直接值. 明文存储在本地 config 文件中 (本地进程, 不通过网络暴露).
    /// 与 [`Provider::api_key_file`] 互斥 — 同时设置会在 [`Provider::validate`] 中报错.
    #[serde(default)]
    pub api_key: String,
    /// 可选: 从文件路径读取 api_key. 优先级低于 [`Provider::api_key`].
    ///
    /// 用法: 让 toml 本身不含敏感数据, secret 由外部机制 (sops-nix / systemd LoadCredential /
    /// docker secrets / k8s secrets) 解密到独立路径, secret-guard 在请求时读取.
    ///
    /// 文件内容会被 `trim()` (容忍末尾换行符, 这是 sops / `echo | tee` 的常见副作用).
    /// 文件读不到时按空 key 处理 (与 `api_key` 为空时一致), 由 `apply_provider_auth`
    /// (在 `crate::proxy`) 决定是否跳过 auth header 注入.
    #[serde(default)]
    pub api_key_file: Option<std::path::PathBuf>,
    /// 是否启用. `false` 时转发到该 provider 返回 503.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 可选人类可读名称 (Web UI 显示).
    #[serde(default)]
    pub name: Option<String>,
}

impl Provider {
    /// 返回生效的 api_key: 优先 [`Provider::api_key`] 直接值, 否则从
    /// [`Provider::api_key_file`] 读取 (trim 后). 两者都未配置 → 返回空字符串.
    ///
    /// 不报告错误: 上层 (`apply_provider_auth` 在 `crate::proxy`) 会基于空 key 决定是否跳过 auth 注入,
    /// 单个 provider 配置错误不应拖垮整个进程.
    ///
    /// 但会 `warn!` 一次让运维可观测 — 文件读不到时, 仅从上游 401/403 反推原因很痛苦.
    /// 与项目其他错误路径 (`proxy/` 中 `warn!` 各种 IO/header 错误) 风格一致.
    pub fn effective_api_key(&self) -> String {
        if !self.api_key.is_empty() {
            return self.api_key.clone();
        }
        if let Some(path) = &self.api_key_file {
            match std::fs::read_to_string(path) {
                Ok(s) => {
                    // 文件恢复可读, 清除 warn 记录, 让下次失败能再次 warn.
                    WARNED_API_KEY_FILE.lock().remove(&self.id);
                    return s.trim().to_string();
                }
                Err(e) => {
                    // 首次失败 warn 一次, 后续同样错误静默 — 避免 LLM 高 QPS 场景日志爆.
                    // (恢复后会再次 warn, 让运维感知到再次发生的失败.)
                    let first_failure = WARNED_API_KEY_FILE.lock().insert(self.id.clone());
                    if first_failure {
                        tracing::warn!(
                            provider_id = %self.id,
                            path = %path.display(),
                            error = %e,
                            "failed to read api_key_file; falling back to empty key \
                             (apply_provider_auth will skip auth injection, \
                             subsequent failures for this provider will be silent \
                             until the file becomes readable again)"
                        );
                    }
                }
            }
        }
        String::new()
    }
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
        // api_key 与 api_key_file 互斥: 同时设置时语义不明 (effective_api_key 会优先 api_key,
        // 但这种配置几乎肯定是误操作 — 比如 toml 既填了 api_key 又忘了删 api_key_file).
        if !self.api_key.is_empty() && self.api_key_file.is_some() {
            return Err(format!(
                "provider {} has both api_key and api_key_file set; pick one",
                self.id
            ));
        }
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
    /// 直接值 (api_key 字段) 的 masked 视图. 若 provider 用 api_key_file,
    /// 这里是空字符串 — 文件内容由 effective_api_key() 在转发时读取, 不进 effective 视图.
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
            api_key_file: None,
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
        // 确保父目录存在, 否则 atomic_write 的 File::create 会因 ENOENT 失败
        // (测试不应依赖外部预先创建的目录).
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
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

    // ─── toml 反序列化: api_key_file 字段必须能从 toml 正确解析为 PathBuf ──
    //
    // PathBuf 在 toml crate 中没有直接实现 Deserialize, 但 std::path::PathBuf
    // 通过 serde "newtype struct" 自动获得 string → PathBuf 的反序列化能力.
    // 这个测试 pin 住该隐含约定, 防止未来重构成 String 类型时静默破坏 toml schema.

    #[test]
    fn toml_deserializes_api_key_file_as_pathbuf() {
        let toml_text = r#"
            id = "test"
            protocol = "openai"
            base_url = "https://api.example.com"
            api_key_file = "/run/secrets/test-key"
            enabled = true
        "#;
        let p: Provider = toml::from_str(toml_text).expect("toml parse");
        assert_eq!(
            p.api_key_file.as_deref(),
            Some(std::path::Path::new("/run/secrets/test-key"))
        );
        assert_eq!(p.api_key, ""); // 默认值
    }

    #[test]
    fn toml_deserializes_legacy_api_key_still_works() {
        // 只有 api_key (无 api_key_file) 的老格式必须仍然能解析.
        let toml_text = r#"
            id = "test"
            protocol = "openai"
            base_url = "https://api.example.com"
            api_key = "sk-legacy"
            enabled = true
        "#;
        let p: Provider = toml::from_str(toml_text).expect("toml parse");
        assert_eq!(p.api_key, "sk-legacy");
        assert!(p.api_key_file.is_none());
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
            api_key_file: None,
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
            api_key_file: None,
            enabled: true,
            name: None,
        };
        assert!(bad_url.validate().is_err());

        // 合法 provider 通过.
        assert!(p("ok", Protocol::OpenAI, "https://x").validate().is_ok());
    }

    #[test]
    fn validate_rejects_api_key_and_file_both_set() {
        let both = Provider {
            id: "x".into(),
            protocol: Protocol::OpenAI,
            base_url: "https://x".into(),
            api_key: "sk-direct".into(),
            api_key_file: Some(PathBuf::from("/run/secrets/whatever")),
            enabled: true,
            name: None,
        };
        let err = both.validate().unwrap_err();
        assert!(err.contains("both api_key and api_key_file"), "got: {err}");
    }

    // ─── effective_api_key: api_key 直接值 vs api_key_file ──────────────────

    #[test]
    fn effective_api_key_prefers_direct_value() {
        // 即便 api_key_file 指向不存在的文件, 直接值优先 (且 validate 不会让你同时设两者).
        let p = Provider {
            id: "x".into(),
            protocol: Protocol::OpenAI,
            base_url: "https://x".into(),
            api_key: "sk-direct".into(),
            api_key_file: None,
            enabled: true,
            name: None,
        };
        assert_eq!(p.effective_api_key(), "sk-direct");
    }

    #[test]
    fn effective_api_key_reads_from_file_with_trim() {
        // sops / echo | tee 普遍会在文件末尾留换行符, effective_api_key 应当 trim.
        let tmp = PathBuf::from(format!(
            "/tmp/opencode/tmp/test-api-key-{}.txt",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(tmp.parent().unwrap()).unwrap();
        std::fs::write(&tmp, "sk-from-file\n").unwrap();

        let p = Provider {
            id: "x".into(),
            protocol: Protocol::OpenAI,
            base_url: "https://x".into(),
            api_key: String::new(),
            api_key_file: Some(tmp.clone()),
            enabled: true,
            name: None,
        };
        assert_eq!(p.effective_api_key(), "sk-from-file");

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn effective_api_key_missing_file_returns_empty() {
        // 单 provider 配置错误不应拖垮整个进程 — 返回空让 apply_provider_auth 跳过.
        let p = Provider {
            id: "x".into(),
            protocol: Protocol::OpenAI,
            base_url: "https://x".into(),
            api_key: String::new(),
            api_key_file: Some(PathBuf::from("/nonexistent/path/should/not/exist")),
            enabled: true,
            name: None,
        };
        assert_eq!(p.effective_api_key(), "");
    }

    // ─── effective_api_key warn-once 恢复契约 ────────────────────────────────
    //
    // 核心契约 (provider.rs 头部): "首次失败 warn 一次, 恢复后清除记录, 再次失败再 warn".
    // WARNED_API_KEY_FILE 在文件可读时清除该 provider 的记录, 让后续失败能再次 warn.
    //
    // 日志次数难直接断言 (tracing 全局 subscriber), 这里测可观测的行为契约:
    //   1. 文件不存在 → 返回空 + WARNED 记录被插入 (insert 返回 true).
    //   2. 文件恢复 (重新创建) → 返回文件内容 + WARNED 记录被清除.
    //   3. 文件再次消失 → 仍能正确返回空 (warn-once 状态机正确重置, 不会卡死).
    //
    // 这条路径是"运维改了配置后能看到新 warn"的关键, 一旦回归会导致 provider
    // 永久静默 (api_key_file 修复后下次失败也不再 warn), 排障极痛苦.

    #[test]
    fn effective_api_key_file_recovers_after_recreate() {
        let unique = uuid::Uuid::new_v4().to_string();
        let tmp = PathBuf::from(format!(
            "/tmp/opencode/tmp/test-api-key-recover-{unique}.txt"
        ));
        std::fs::create_dir_all(tmp.parent().unwrap()).unwrap();

        // 用唯一 provider id 隔离全局 WARNED_API_KEY_FILE 状态 (并行测试安全).
        let pid = format!("recover-test-{unique}");
        let make_provider = || Provider {
            id: pid.clone(),
            protocol: Protocol::OpenAI,
            base_url: "https://x".into(),
            api_key: String::new(),
            api_key_file: Some(tmp.clone()),
            enabled: true,
            name: None,
        };

        // 1. 文件不存在 → 空 + WARNED 被插入 (首次失败).
        assert_eq!(make_provider().effective_api_key(), "");
        assert!(
            WARNED_API_KEY_FILE.lock().contains(&pid),
            "first failure must record provider in WARNED set"
        );

        // 2. 创建文件 → 读到内容 + WARNED 被清除 (恢复路径).
        std::fs::write(&tmp, "sk-recovered\n").unwrap();
        assert_eq!(make_provider().effective_api_key(), "sk-recovered");
        assert!(
            WARNED_API_KEY_FILE.lock().get(&pid).is_none(),
            "recovery must clear WARNED record so next failure re-warns"
        );

        // 3. 再次删除文件 → 仍能正确返回空 + 重新插入 WARNED (状态机可循环).
        std::fs::remove_file(&tmp).unwrap();
        assert_eq!(make_provider().effective_api_key(), "");
        assert!(
            WARNED_API_KEY_FILE.lock().contains(&pid),
            "failure after recovery must re-record (warn-once state machine resets)"
        );

        // 清理全局状态, 避免污染其他测试.
        WARNED_API_KEY_FILE.lock().remove(&pid);
    }

    #[test]
    fn effective_api_key_missing_file_sets_warned_state() {
        // 补强: 单独验证 "首次失败必定插入 WARNED" 这个可观测副作用.
        // (上面 recover 测试串了三步, 这里独立断言第一步, 让回归定位更精确.)
        let unique = uuid::Uuid::new_v4().to_string();
        let pid = format!("warn-once-{unique}");
        let p = Provider {
            id: pid.clone(),
            protocol: Protocol::OpenAI,
            base_url: "https://x".into(),
            api_key: String::new(),
            api_key_file: Some(PathBuf::from("/nonexistent/warn-once-test")),
            enabled: true,
            name: None,
        };
        assert_eq!(p.effective_api_key(), "");
        assert!(
            WARNED_API_KEY_FILE.lock().contains(&pid),
            "missing file must populate WARNED set for warn-once dedup"
        );
        // 清理.
        WARNED_API_KEY_FILE.lock().remove(&pid);
    }

    #[test]
    fn effective_api_key_neither_set_returns_empty() {
        let p = Provider {
            id: "x".into(),
            protocol: Protocol::OpenAI,
            base_url: "https://x".into(),
            api_key: String::new(),
            api_key_file: None,
            enabled: true,
            name: None,
        };
        assert_eq!(p.effective_api_key(), "");
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
