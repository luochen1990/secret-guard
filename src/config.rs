//! 配置文件 schema (TOML + serde).
//!
//! # 双层配置模型 (Static + Dynamic)
//!
//! secret-guard 把配置拆成两个独立文件, 各自承担不同职责:
//!
//! | 文件 | 角色 | 谁写 | 进入 git? |
//! |---|---|---|---|
//! | `secret-guard.toml`        | **声明式 (static)** 配置: providers / secrets / server. | 用户手写 | ✅ 推荐 |
//! | `secret-guard.state.toml`  | **动态 (dynamic)** 状态: WebUI 编辑结果 + 对 static 项的 decision. | 程序自动 | ❌ 推荐 .gitignore |
//!
//! 两者由 [`Config`] (static) 与 [`DynamicState`] (dynamic) 分别建模.
//!
//! # 合并语义
//!
//! 对每个 id, 实际生效值由 [`OverrideMode`] 决定:
//! - `Default`: 若 dynamic 中有同 id 则用 dynamic, 否则用 static.
//! - `PreferStatic`: 强制使用 static 原值, 忽略 dynamic override (若有).
//! - `Disabled`: 从 effective view 中完全排除, 既不用 static 也不用 dynamic.
//!
//! `OverrideMode` 仅对 **static 中已存在的 id** 有意义; dynamic-only item 直接通过
//! CRUD 删除即可移除, 不走 decision 机制.
//!
//! state.toml 的 `[decisions]` 段持久化这些 per-id 决策, 见 [`Decisions`].

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::provider::Provider;
use crate::secrets::SecretEntry;

// ─── Static (declarative) ─────────────────────────────────────────────────

/// 顶层**声明式**配置. 用户通过 `secret-guard.toml` 提供, 进程内只读.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,

    /// 静态 provider 列表. WebUI 不能改写, 只能 disable 或 override.
    #[serde(default)]
    pub providers: Vec<Provider>,

    /// 静态 secret 列表. WebUI 不能改写, 只能 disable 或 override.
    #[serde(default)]
    pub secrets: SecretsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// 内存中保留的转发记录条数上限 (FIFO 淘汰).
    pub records_capacity: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8787,
            records_capacity: 1024,
        }
    }
}

/// 静态 secret 注册表 (`[secrets]` 段, 与 `[[secrets.entries]]` 列表对齐).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretsConfig {
    pub entries: Vec<SecretEntry>,
}

impl Config {
    /// 从 TOML 文件加载; 若文件不存在返回默认值并 warn.
    pub fn load_or_default(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            tracing::warn!(
                path = %path.display(),
                "static config file not found; using defaults"
            );
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read config {}: {e}", path.display()))?;
        let cfg: Self = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parse config {}: {e}", path.display()))?;
        Ok(cfg)
    }

    /// 序列化为 TOML (主要供测试与调试; WebUI 不再写回此文件).
    pub fn to_toml(&self) -> anyhow::Result<String> {
        toml::to_string_pretty(self).map_err(|e| anyhow::anyhow!("serialize config: {e}"))
    }
}

// ─── Dynamic (WebUI-managed) state ────────────────────────────────────────

/// 顶层**动态**状态. 由 WebUI 持久化到 `secret-guard.state.toml`.
///
/// 设计原则: **state 永远可重建 / 可丢弃** — 删除 state.toml 后再启动,
/// secret-guard 会回到 `secret-guard.toml` 所声明的纯净状态.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DynamicState {
    /// WebUI 创建 / 编辑过的 providers. 可能与 static 同 id (作为 override).
    #[serde(default)]
    pub providers: Vec<Provider>,

    /// WebUI 创建 / 编辑过的 secrets. 可能与 static 同 id (作为 override).
    #[serde(default)]
    pub secrets: Vec<SecretEntry>,

    /// 对 static id 的 per-item 决策.
    #[serde(default)]
    pub decisions: Decisions,
}

impl DynamicState {
    /// 从 TOML 文件加载; 若文件不存在返回空 state (不 warn, 这是正常情况).
    pub fn load_or_empty(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read state {}: {e}", path.display()))?;
        let state: Self = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parse state {}: {e}", path.display()))?;
        Ok(state)
    }

    /// 序列化为 TOML (供 WebUI 写回 state.toml).
    pub fn to_toml(&self) -> anyhow::Result<String> {
        toml::to_string_pretty(self).map_err(|e| anyhow::anyhow!("serialize state: {e}"))
    }
}

// ─── Effective view 共用类型 + 合并算法 (provider / secret 通用) ──────────

/// 合并视图中 item 的来源标签. provider 与 secret 共用同一份 enum, 保证字段演进时
/// 两个 table 的序列化结果完全对齐.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveSource {
    /// 仅 static 有此 id, decision = Default → 用 static.
    Static,
    /// 仅 dynamic 有此 id (static 无), decision 不适用 → 用 dynamic.
    Dynamic,
    /// static + dynamic 都有, decision = Default → 用 dynamic (WebUI 修改生效).
    DynamicOverride,
    /// static + dynamic 都有, decision = PreferStatic → 强制用 static.
    StaticPreferred,
}

/// 纯合并逻辑: 给定 static / dynamic / decision, 返回实际生效的原始项.
/// Disabled 或两者皆 None → None.
///
/// 此函数是整个双层配置的**单一事实源**: provider / secret 的合并算法都来自它,
/// 演进 (例如新增 OverrideMode 变体) 时编译器强制两表对齐.
pub fn pick_effective<T>(
    static_ver: Option<T>,
    dynamic_ver: Option<T>,
    mode: OverrideMode,
) -> Option<T> {
    match (static_ver, dynamic_ver, mode) {
        (_, _, OverrideMode::Disabled) => None,
        (Some(s), _, OverrideMode::PreferStatic) => Some(s),
        (None, _, OverrideMode::PreferStatic) => None,
        (_, Some(d), OverrideMode::Default) => Some(d),
        (Some(s), None, OverrideMode::Default) => Some(s),
        (None, None, _) => None,
    }
}

/// 由 (has_static, has_dynamic, mode) 推导 EffectiveSource. 与 [`pick_effective`] 对偶:
/// `pick_effective` 返回 None 时 (Disabled) 此函数也返回 None.
pub fn classify_source(
    has_static: bool,
    has_dynamic: bool,
    mode: OverrideMode,
) -> Option<EffectiveSource> {
    match (has_static, has_dynamic, mode) {
        (true, false, _) => Some(EffectiveSource::Static),
        (true, true, OverrideMode::Default) => Some(EffectiveSource::DynamicOverride),
        (true, true, OverrideMode::PreferStatic) => Some(EffectiveSource::StaticPreferred),
        (false, true, _) => Some(EffectiveSource::Dynamic),
        // Disabled / 全空 → None.
        _ => None,
    }
}

// ─── Per-id override decisions ────────────────────────────────────────────

/// 对 static id 的 per-item 决策. 仅对 static 中已存在的 id 生效.
///
/// 序列化为 lowercase 字符串, 便于在 TOML / JSON 中读写.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideMode {
    /// 默认: 若 dynamic 有同 id override 则用 dynamic, 否则用 static.
    #[default]
    Default,
    /// 强制使用 static 原值, 忽略可能存在的 dynamic override.
    PreferStatic,
    /// 完全禁用: 从 effective view 中排除 (既不用 static 也不用 dynamic).
    Disabled,
}

impl OverrideMode {
    /// 所有变体及其字符串名. 单一事实来源.
    pub const ALL: [(Self, &'static str); 3] = [
        (Self::Default, "default"),
        (Self::PreferStatic, "prefer_static"),
        (Self::Disabled, "disabled"),
    ];

    pub fn as_str(self) -> &'static str {
        Self::ALL
            .into_iter()
            .find(|(m, _)| *m == self)
            .map(|(_, s)| s)
            .expect("ALL covers every variant")
    }

    /// 按 name 解析 mode. 命名为 `parse` 而非 `from_str`, 避免与 `std::str::FromStr` 冲突.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|(_, n)| *n == s).map(|(m, _)| m)
    }
}

/// `Decisions` 的存储容器: 两张独立的 id→mode 表 (provider / secret).
///
/// 序列化为 TOML 时形如:
///
/// ```toml
/// [decisions.providers]
/// "openai-main" = "disabled"
///
/// [decisions.secrets]
/// "pwd" = "prefer_static"
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decisions {
    #[serde(default)]
    pub providers: HashMap<String, OverrideMode>,
    #[serde(default)]
    pub secrets: HashMap<String, OverrideMode>,
}

impl Decisions {
    /// 读取 provider id 的决策 (默认 `Default`).
    pub fn provider(&self, id: &str) -> OverrideMode {
        self.providers.get(id).copied().unwrap_or_default()
    }

    /// 读取 secret id 的决策 (默认 `Default`).
    pub fn secret(&self, id: &str) -> OverrideMode {
        self.secrets.get(id).copied().unwrap_or_default()
    }

    /// 设置 provider id 的决策. 若 mode == Default 则移除条目 (保持文件精简).
    pub fn set_provider(&mut self, id: &str, mode: OverrideMode) {
        match mode {
            OverrideMode::Default => {
                self.providers.remove(id);
            }
            other => {
                self.providers.insert(id.to_string(), other);
            }
        }
    }

    /// 设置 secret id 的决策.
    pub fn set_secret(&mut self, id: &str, mode: OverrideMode) {
        match mode {
            OverrideMode::Default => {
                self.secrets.remove(id);
            }
            other => {
                self.secrets.insert(id.to_string(), other);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_mode_roundtrip() {
        for (mode, name) in OverrideMode::ALL {
            assert_eq!(mode.as_str(), name);
            assert_eq!(OverrideMode::parse(name), Some(mode));
        }
        assert_eq!(OverrideMode::parse("xxx"), None);
        assert_eq!(OverrideMode::default(), OverrideMode::Default);
    }

    #[test]
    fn decisions_default_returns_default_mode() {
        let d = Decisions::default();
        assert_eq!(d.provider("any"), OverrideMode::Default);
        assert_eq!(d.secret("any"), OverrideMode::Default);
    }

    #[test]
    fn decisions_set_then_clear_compacts_storage() {
        let mut d = Decisions::default();
        d.set_provider("p1", OverrideMode::Disabled);
        d.set_secret("s1", OverrideMode::PreferStatic);
        assert_eq!(d.provider("p1"), OverrideMode::Disabled);
        assert_eq!(d.secret("s1"), OverrideMode::PreferStatic);
        assert_eq!(d.providers.len(), 1);
        assert_eq!(d.secrets.len(), 1);

        // Default 等价于"无条目", 设置时应自动 compact.
        d.set_provider("p1", OverrideMode::Default);
        d.set_secret("s1", OverrideMode::Default);
        assert!(d.providers.is_empty());
        assert!(d.secrets.is_empty());
    }

    #[test]
    fn dynamic_state_roundtrip_toml() {
        let mut state = DynamicState::default();
        state.providers.push(Provider {
            id: "p1".into(),
            protocol: crate::provider::Protocol::OpenAI,
            base_url: "https://api.openai.com".into(),
            api_key: "sk-test".into(),
            enabled: true,
            name: Some("P1".into()),
        });
        state
            .decisions
            .set_provider("static-p", OverrideMode::Disabled);
        state
            .decisions
            .set_secret("static-s", OverrideMode::PreferStatic);

        let text = state.to_toml().unwrap();
        let parsed: DynamicState = toml::from_str(&text).unwrap();
        assert_eq!(parsed.providers.len(), 1);
        assert_eq!(parsed.providers[0].id, "p1");
        assert_eq!(
            parsed.decisions.provider("static-p"),
            OverrideMode::Disabled
        );
        assert_eq!(
            parsed.decisions.secret("static-s"),
            OverrideMode::PreferStatic
        );
    }
}
