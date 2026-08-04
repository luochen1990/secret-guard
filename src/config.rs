//! 配置文件 schema (TOML + serde) + 双层 (static + dynamic) 合并的泛型基础设施.
//!
//! # 双层配置模型 (Static + Dynamic)
//!
//! secret-guard 把配置拆成两个独立文件, 各自承担不同职责:
//!
//! | 文件 | 角色 | 谁写 | 进入 git? |
//! |---|---|---|---|
//! | `secret-guard.toml`        | **声明式 (static)** 配置: providers / secrets / server / redact / auth. | 用户手写 | ✅ 推荐 |
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
//!
//! # 泛型表 (`DynamicTable<T>`)
//!
//! [`ProviderTable`](crate::provider::ProviderTable) 与
//! [`SecretTable`](crate::secrets::SecretTable) 的合并 / CRUD / 持久化逻辑完全对称,
//! 因此本模块提供泛型基础设施: [`DynamicEntry`] (类型特定钩子) + [`DynamicTable`]
//! (共享的内存结构 + 合并 / CRUD / 持久化算法). 类型特定方法 (如 effective_snapshot
//! 返回 `EffectiveProvider` / `EffectiveSecret`) 在各自模块以
//! `impl DynamicTable<Provider>` / `impl DynamicTable<SecretEntry>` 的形式补充
//! (Rust 允许对泛型具体实例添加 inherent impl, 前提是泛型本身在本地 crate).
//!
//! # 持久化策略 (`DynamicTable::upsert` / `delete`)
//!
//! - 内存层: `Arc<RwLock<Vec<T>>>` × 2 (static_entries 只读 + dynamic_entries 可变).
//! - 持久化顺序: **先写 state.toml (atomic + fsync), 再更新内存** (失败自动回滚).
//! - `tmp` 文件名带 UUID, 避免并发 `atomic_write` 互相覆盖.
//! - 每次写 dynamic 时 `DynamicState::load_or_empty(state_path, "")` → 改对应段 → `to_toml` → `atomic_write`.
//!   (持久化路径用空 prefix 跳过 re-validate, 因为 secret 早已 validate 过.)
//!
//! # 跨表并发安全 (由 `server.rs` 装配)
//!
//! `SecretTable` 与 `ProviderTable` (都是 `DynamicTable<T>` 别名) 共享两份同步原语
//! (server 启动时构造并注入):
//! - **`Arc<Mutex<()>> persist_lock`**: 串行整个 RMW, 避免两表并发写 state.toml 互相覆盖.
//! - **`Arc<RwLock<Decisions>>` decisions**: 同一份 per-id 决策 (因为 `[decisions]` 段同时含
//!   providers + secrets 两个子表, 任何一方修改都要触发 state.toml 重写, 共享同一份内存).
//!
//! # Effective source (4 种, 供 UI 区分)
//!
//! | `source` 字段 | 含义 |
//! |---|---|
//! | `static` | 仅 static 有此 id, 用 static. |
//! | `dynamic` | 仅 dynamic 有此 id (WebUI 创建的). |
//! | `dynamic_override` | static + dynamic 都有, decision=Default → 用 dynamic. |
//! | `static_preferred` | static + dynamic 都有, decision=PreferStatic → 用 static. |
//!
//! Disabled 项不进入 effective view (UI 看不到, 路由层也拿不到).
//!
//! # CRUD 操作语义
//!
//! - **POST** 创建 dynamic-only item. 若 id 与 static 冲突 → 409 (要用 PUT 走 fork 流程).
//! - **PUT** 编辑: 若 id 在 static 中, 服务端自动 fork 出一份 dynamic override (git-style 心智模型).
//! - **DELETE** 仅作用于 dynamic: 若有 dynamic 删除之 (override 关系下保留 static + 重置 decision);
//!   若 id 仅在 static 中 → 409 (提示用 PATCH .../decision + mode=disabled).
//! - **PATCH `/{id}/decision`** 切换对 static id 的决策. 返回 `{id, resource, decision}` ack.
//!
//! 类型钩子: `DynamicEntry` trait 让泛型表知道如何把 entry 写入 state 的对应字段
//! (`set_state_field`) 与读写 decisions 的对应子表 (`get_decision` / `set_decision`).
//! 新增第三种 entry 类型只需 impl 该 trait (~25 行) 即可获得完整 CRUD / 持久化 / decision 通道.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
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

    /// Redact 行为配置 (global mock prefix 等). 进程内只读.
    #[serde(default)]
    pub redact: RedactConfig,

    /// 认证配置 (OIDC + API key 开关). `enabled = false` (默认) = 单用户模式,
    /// 所有路由无认证 (向后兼容本地部署).
    #[serde(default)]
    pub auth: crate::auth::AuthConfig,
}

/// Redact 相关配置 (静态, 仅 `[redact]` 段).
///
/// `global_mock_prefix` 控制 Auto 模式生成的 mock 的统一前缀.
/// 默认空串 = mock 无前缀 (纯 hash body). 设置后 (如 `"sgm_"`) 让 mock 在
/// 日志 / WebUI timeline 中视觉可辨识. 详见 `redact.rs` 的 C5 契约.
///
/// `on_probe_exhausted` 控制 redact probing 耗尽 (弱配置 + 对抗性 IR) 时的策略:
/// `FailOpen` (默认, 向后兼容) 跳过该 secret 原样转发; `FailClosed` 拒绝转发
/// (返回 503). 详见 `redact.rs` 的 redact_ir_checked.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RedactConfig {
    /// Auto 模式 mock 的统一前缀, 在 secret resolve 阶段注入到每个 secret 的
    /// `gen_spec.prefix` (per-secret prefix 仍可覆盖). 默认空串.
    pub global_mock_prefix: String,
    /// Mock probing 耗尽时的策略 (默认 `FailOpen` 向后兼容).
    pub on_probe_exhausted: OnProbeExhausted,
}

/// Mock probing 耗尽时 (弱配置 + 对抗性 IR 无法生成唯一 mock) 的处理策略.
///
/// - `FailOpen`: 跳过该 secret 原样转发到上游 (历史行为, 向后兼容).
/// - `FailClosed`: 拒绝转发整个请求 (返回 503), 防止 secret 泄露到 LLM provider.
///
/// 配置示例 (`secret-guard.toml`):
/// ```toml
/// [redact]
/// on_probe_exhausted = "fail_closed"
/// ```
///
/// # 设计动机
///
/// `FailOpen` 优先保进程存活, 但与 secret-guard 的核心使命 (防 secret 泄露) 相悖:
/// 对抗性请求可构造让 mock probing 必然耗尽的 IR, 从而把 secret 原样发往上游.
/// `FailClosed` 让运维在敏感场景显式拒绝这种降级, 即便付出请求失败的代价.
/// 默认仍 `FailOpen` 以避免升级时破坏现有部署.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnProbeExhausted {
    /// 跳过该 secret 原样转发 (warn 日志, 历史行为, 向后兼容).
    #[default]
    FailOpen,
    /// 拒绝转发整个请求 (返回 503, 防止 secret 泄露).
    FailClosed,
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
    ///
    /// 加载序列 (启动 fail-fast):
    /// 1. [`DynamicEntry::validate`] — 结构校验 (id 格式 / value 与 value_file 互斥).
    /// 2. [`SecretEntry::resolve_value`] — 若设置了 `value_file`, 从文件读取写入 `value`.
    /// 3. `validate_value` — resolve 后跑最终内容校验 (长度 / mock prefix / PUA),
    ///    因为 trim 后的 value 才是 redact 实际使用的字节.
    ///
    /// 任一步失败都返回 `Err`, 让误配在启动时就暴露, 而不是被运行时代码路径静默吞掉.
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
        let mut cfg: Self = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parse config {}: {e}", path.display()))?;
        validate_and_resolve_secrets(
            path,
            &mut cfg.secrets.entries,
            &cfg.redact.global_mock_prefix,
        )?;
        validate_providers(path, &cfg.providers)?;
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

    /// WebUI 签发的 API keys (用于 SDK 转发路径认证). 存 hash, 不存明文.
    #[serde(default)]
    pub api_keys: Vec<crate::auth::ApiKeyEntry>,

    /// 静态 API key 中被用户 disable 的 label 集合 (持久化跨重启).
    #[serde(default)]
    pub api_keys_disabled: std::collections::HashSet<String>,
}

impl DynamicState {
    /// 从 TOML 文件加载; 若文件不存在返回空 state (不 warn, 这是正常情况).
    ///
    /// 与 [`Config::load_or_default`] 一样, 加载后会跑 validate + resolve + 内容校验 —
    /// 用户手编 state.toml 时也应当尽早暴露契约违反.
    ///
    /// `global_mock_prefix` 来自 static config (`[redact]` 段), 用于校验 dynamic secrets
    /// 的 value 不含该 prefix, 以及 resolve Auto 模式的 gen_spec.prefix. 调用方应在
    /// 加载完 static config 后将其传入.
    pub fn load_or_empty(path: &Path, global_mock_prefix: &str) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read state {}: {e}", path.display()))?;
        let mut state: Self = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parse state {}: {e}", path.display()))?;
        validate_and_resolve_secrets(path, &mut state.secrets, global_mock_prefix)?;
        validate_providers(path, &state.providers)?;
        Ok(state)
    }

    /// 序列化为 TOML (供 WebUI 写回 state.toml).
    pub fn to_toml(&self) -> anyhow::Result<String> {
        toml::to_string_pretty(self).map_err(|e| anyhow::anyhow!("serialize state: {e}"))
    }
}

/// 对 secret 列表跑完整 validate+resolve 序列 (fail-fast).
///
/// 这是 [`SecretEntry::validate_and_resolve`] 的批量包装: 三步序列 (结构 validate →
/// resolve_value → 内容 validate_value) 的契约定义在 `SecretEntry` 上 (SSOT),
/// 本函数只负责错误消息的 path/id 包装.
///
/// `global_mock_prefix` 透传给每个 entry 的 validate_and_resolve.
///
/// Provider 不需要此序列 — 见 [`SecretEntry::validate_and_resolve`] 的"与 Provider 的差异"段.
fn validate_and_resolve_secrets(
    path: &Path,
    secrets: &mut [SecretEntry],
    global_mock_prefix: &str,
) -> anyhow::Result<()> {
    for s in secrets.iter_mut() {
        s.validate_and_resolve(global_mock_prefix).map_err(|e| {
            anyhow::anyhow!("config {}: invalid secret {}: {e}", path.display(), s.id)
        })?;
    }
    Ok(())
}

/// 对 provider 列表只跑结构 validate (不需要 resolve, 见 [`validate_and_resolve_secrets`] 注释).
fn validate_providers(path: &Path, providers: &[Provider]) -> anyhow::Result<()> {
    for p in providers {
        p.validate().map_err(|e| {
            anyhow::anyhow!("config {}: invalid provider {}: {e}", path.display(), p.id)
        })?;
    }
    Ok(())
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

/// 由 (has_static, has_dynamic, mode) 推导 EffectiveSource. 与 [`pick_effective`] 严格对偶:
/// `pick_effective` 返回 None 的输入 (Disabled / 全空 / dynamic-only+PreferStatic),
/// 本函数也返回 None. 这样 `compute_effective_*` 中的 `.expect` 不会在生产 panic.
pub fn classify_source(
    has_static: bool,
    has_dynamic: bool,
    mode: OverrideMode,
) -> Option<EffectiveSource> {
    match (has_static, has_dynamic, mode) {
        // Disabled: pick_effective 必返回 None.
        (_, _, OverrideMode::Disabled) => None,
        // 仅 static 有此 id: pick_effective 返回 static.
        (true, false, _) => Some(EffectiveSource::Static),
        // static + dynamic 都有, mode 决定谁生效.
        (true, true, OverrideMode::Default) => Some(EffectiveSource::DynamicOverride),
        (true, true, OverrideMode::PreferStatic) => Some(EffectiveSource::StaticPreferred),
        // 仅 dynamic 有: 仅 Default 下生效 (PreferStatic 找不到 static 时 pick_effective 返回 None).
        (false, true, OverrideMode::Default) => Some(EffectiveSource::Dynamic),
        // (false, true, PreferStatic) + (false, false, _) — 与 pick_effective 对偶地返回 None.
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

// ─── atomic_write 共用工具 ─────────────────────────────────────────────────

/// 原子写文件: 先写带 UUID 的 `.tmp`, sync, 再 rename.
///
/// 同时被 [`DynamicTable::persist_dynamic`] (provider / secret 共享) 调用.
/// `pub(crate)` 暴露给 redact 等需要原子写的模块.
pub(crate) fn atomic_write(path: &Path, text: &str) -> anyhow::Result<()> {
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
        let _ = std::fs::remove_file(&tmp);
        anyhow::anyhow!("rename {} -> {} failed: {e}", tmp.display(), path.display())
    })?;
    Ok(())
}

// ─── CRUD 返回值 (provider / secret 共用同一份) ────────────────────────────

/// upsert 操作是新建还是覆盖. provider 与 secret 共用.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertKind {
    Inserted,
    Updated,
}

/// delete 操作的结果. provider 与 secret 共用.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    Deleted,
    NotFound,
}

// ─── 泛型表 (provider / secret 共享的内存结构 + 合并算法) ──────────────────

/// 类型特定的钩子: 让泛型 [`DynamicTable`] 知道如何把一个 entry 类型
/// 接入到合并 / CRUD / 持久化流水线.
///
/// 每个具体类型 ([`Provider`], [`SecretEntry`]) 在各自模块 impl 本 trait,
/// 把"哪一段 state 字段是我的 / 哪一段 decisions 子表是我的"等小细节抽出来,
/// 让 [`DynamicTable`] 的所有共有逻辑只写一次.
pub trait DynamicEntry: Clone + Send + Sync + 'static {
    /// 此 entry 的 id (用于去重 + decision 查找).
    fn id(&self) -> &str;

    /// 校验自身合法性 (id / value / base_url 等). 失败时返回 message.
    fn validate(&self) -> Result<(), String>;

    /// 把 entries 写到 state 对应字段 (provider → state.providers, secret → state.secrets).
    fn set_state_field(state: &mut DynamicState, entries: Vec<Self>);

    /// 读 decisions 中对应子表 (provider / secret) 的某 id.
    fn get_decision(d: &Decisions, id: &str) -> OverrideMode;

    /// 写 decisions 中对应子表的某 id.
    fn set_decision(d: &mut Decisions, id: &str, mode: OverrideMode);
}

/// 双层 (static + dynamic) + per-id decision 的泛型表.
///
/// [`ProviderTable`](crate::provider::ProviderTable) / [`SecretTable`](crate::secrets::SecretTable)
/// 都是本类型的别名. 类型特定的"对外视图"方法 (返回 EffectiveProvider / EffectiveSecret
/// 等带 masked 字段的结构) 通过在各自模块里写 `impl DynamicTable<T>` 提供.
///
/// # 并发与持久化契约
///
/// - 内存层: `Arc<RwLock<Vec<T>>>` × 2 (static 只读 + dynamic 可变) + `Arc<RwLock<Decisions>>`.
/// - 持久化锁: 多个 `DynamicTable` 实例 (provider + secret) 共享同一把
///   `Arc<Mutex<()>> persist_lock`, 串行整个 read-modify-write, 防止两表互相覆盖 state.toml.
/// - 持久化策略: **先持久化, 再更新内存** — 保证内存永远是已持久化的子集 (失败自动回滚).
#[derive(Clone)]
pub struct DynamicTable<T: DynamicEntry> {
    static_entries: Arc<RwLock<Vec<T>>>,
    dynamic_entries: Arc<RwLock<Vec<T>>>,
    decisions: Arc<RwLock<Decisions>>,
    persist_lock: Arc<Mutex<()>>,
    state_path: Arc<PathBuf>,
}

impl<T: DynamicEntry> std::fmt::Debug for DynamicTable<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.static_entries.read();
        let d = self.dynamic_entries.read();
        f.debug_struct("DynamicTable")
            .field("entry_type", &std::any::type_name::<T>())
            .field("static_count", &s.len())
            .field("dynamic_count", &d.len())
            .field("state_path", &self.state_path)
            .finish()
    }
}

impl<T: DynamicEntry> DynamicTable<T> {
    /// 构造表 (测试常用). 共享 lock 与 decisions 由调用方提供.
    pub fn new(
        static_entries: Vec<T>,
        dynamic_entries: Vec<T>,
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

    /// 用外部共享的 `persist_lock` 构造. server 启动时创建一把锁传给 provider 与
    /// secret 两张表, 保证两者对 state 文件的 RMW 串行化.
    pub fn with_persist_lock(
        static_entries: Vec<T>,
        dynamic_entries: Vec<T>,
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

    // ─── 读: 合并视图 ──────────────────────────────────────────────────

    /// 按 (static, dynamic, decision) 三元组计算 effective 视图的**原始项**.
    /// 顺序: 先 static 出现的 id (Disabled 自动排除), 再仅 dynamic 独有的 id.
    ///
    /// 类型无关; 类型特定的"加 masked / provenance 字段"逻辑在调用方通过
    /// [`Self::effective_triples`] 取三元组后自行映射.
    pub fn effective_raw(&self) -> Vec<T> {
        self.effective_triples()
            .into_iter()
            .filter_map(|(s, d, m)| pick_effective(s, d, m))
            .collect()
    }

    /// 列出每个可见 id 的 (static_ver, dynamic_ver, mode) 三元组.
    /// Disabled 的项 (经 pick_effective 判定返回 None) 不在结果中.
    ///
    /// 这是 effective_snapshot 这类"对外视图"方法的统一数据源: 调用方拿到三元组后
    /// 用类型特定的 `compute_effective_*` 函数映射到 masked 视图.
    pub fn effective_triples(&self) -> Vec<(Option<T>, Option<T>, OverrideMode)> {
        let statics = self.static_entries.read();
        let dynamics = self.dynamic_entries.read();
        let decisions = self.decisions.read();

        let mut out: Vec<(Option<T>, Option<T>, OverrideMode)> =
            Vec::with_capacity(statics.len() + dynamics.len());
        // seen 借 statics/dynamics 的 id 切片 (read guard 全程持有), 无需 String 分配.
        let mut seen: HashSet<&str> = HashSet::new();

        // 预构建 dynamic id → entry 索引: O(S×D) → O(S+D).
        // 假设 dynamics 内 id 唯一 (由 upsert_dynamic 保证); 反序列化路径同样需保证,
        // 否则 HashMap last-wins 与原 find first-wins 取舍不同.
        let dyn_map: HashMap<&str, &T> = dynamics.iter().map(|d| (d.id(), d)).collect();

        // 1. 遍历 static ids, 按 decision 决定 effective.
        for s in statics.iter() {
            seen.insert(s.id());
            let dyn_opt = dyn_map.get(s.id()).copied().cloned();
            let mode = T::get_decision(&decisions, s.id());
            if pick_effective(Some(s.clone()), dyn_opt.clone(), mode).is_some() {
                out.push((Some(s.clone()), dyn_opt, mode));
            }
        }
        // 2. dynamic-only ids: decision 不适用, 直接生效.
        for d in dynamics.iter() {
            if !seen.insert(d.id()) {
                continue;
            }
            out.push((None, Some(d.clone()), OverrideMode::Default));
        }
        out
    }

    /// 路由层使用: 按 id 取 effective 原始项 (不脱敏). 不存在 / Disabled → None.
    pub fn get_effective(&self, id: &str) -> Option<T> {
        let statics = self.static_entries.read();
        let dynamics = self.dynamic_entries.read();
        let decisions = self.decisions.read();

        let s = statics.iter().find(|p| p.id() == id).cloned();
        let d = dynamics.iter().find(|p| p.id() == id).cloned();
        let mode = s
            .as_ref()
            .map(|p| T::get_decision(&decisions, p.id()))
            .unwrap_or(OverrideMode::Default);

        pick_effective(s, d, mode)
    }

    /// 直接查 static 层, 不受 decision 影响. 供 Web handler 判断 "该 id 是否为 static
    /// 来源", 特别是 decision=Disabled 时该 id 不在 effective_snapshot 中也仍能识别.
    pub fn has_static(&self, id: &str) -> bool {
        self.static_entries.read().iter().any(|e| e.id() == id)
    }

    // ─── 写: dynamic 层 CRUD + decision ────────────────────────────────

    /// 仅 dynamic 层 CRUD —— upsert. 若 id 同时存在于 static, 此操作创建 / 更新 override.
    /// 通过 `T::validate` 校验合法性, 持久化失败时内存自动回滚.
    pub fn upsert_dynamic(&self, entry: T) -> anyhow::Result<(T, UpsertKind)> {
        entry.validate().map_err(anyhow::Error::msg)?;

        let _guard = self.persist_lock.lock();
        let (new_entries, kind) = {
            let g = self.dynamic_entries.read();
            let mut v = g.clone();
            if let Some(e) = v.iter_mut().find(|e| e.id() == entry.id()) {
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
            if !g.iter().any(|e| e.id() == id) {
                return Ok(DeleteOutcome::NotFound);
            }
            g.iter()
                .filter(|e| e.id() != id)
                .cloned()
                .collect::<Vec<_>>()
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
        let new_decisions = {
            let cur = self.decisions.read().clone();
            let mut next = cur;
            T::set_decision(&mut next, id, mode);
            next
        };
        // 持久化 RMW: 只为合并字段后写回, secret 早已 validate 过, 用空 prefix 跳过 re-validate.
        let mut state = DynamicState::load_or_empty(&self.state_path, "")?;
        state.decisions = new_decisions.clone();
        let text = state.to_toml()?;
        atomic_write(&self.state_path, &text)?;
        *self.decisions.write() = new_decisions;
        Ok(())
    }

    // ─── 内部持久化 helper ──────────────────────────────────────────────

    /// 重写 state.toml 中本表对应的段 (provider / secret). 调用方必须持有 persist_lock.
    fn persist_dynamic(&self, new_dynamic: &[T]) -> anyhow::Result<()> {
        // 持久化 RMW: 同 set_decision, 用空 prefix 跳过 re-validate.
        let mut state = DynamicState::load_or_empty(&self.state_path, "")?;
        T::set_state_field(&mut state, new_dynamic.to_vec());
        let text = state.to_toml()?;
        atomic_write(&self.state_path, &text)
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

    // ─── OnProbeExhausted serde + Default ─────────────────────────────────

    #[test]
    fn on_probe_exhausted_default_is_fail_open() {
        assert_eq!(OnProbeExhausted::default(), OnProbeExhausted::FailOpen);
        // RedactConfig::default() 也必须是 FailOpen (向后兼容旧配置无此字段).
        assert_eq!(
            RedactConfig::default().on_probe_exhausted,
            OnProbeExhausted::FailOpen
        );
    }

    #[test]
    fn on_probe_exhausted_serde_snake_case_roundtrip() {
        // serde rename_all = "snake_case": fail_open / fail_closed.
        for (variant, name) in [
            (OnProbeExhausted::FailOpen, "fail_open"),
            (OnProbeExhausted::FailClosed, "fail_closed"),
        ] {
            let s = serde_json::to_string(&variant).unwrap();
            assert_eq!(s, format!("\"{name}\""));
            let back: OnProbeExhausted = serde_json::from_str(&s).unwrap();
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn on_probe_exhausted_serde_rejects_unknown_variant() {
        // 未知字符串应反序列化失败 (fail-closed on config typos, 避免静默回退到默认).
        let err = serde_json::from_str::<OnProbeExhausted>("\"fail-closed\"");
        assert!(err.is_err(), "hyphenated form must be rejected");
        let err = serde_json::from_str::<OnProbeExhausted>("\"unknown\"");
        assert!(err.is_err(), "unknown variant must be rejected");
    }

    #[test]
    fn redact_config_toml_default_omits_on_probe_exhausted_field() {
        // 空 [redact] 段应解析为默认 (FailOpen + 空 prefix), 向后兼容.
        let cfg: Config = toml::from_str("[redact]\n").unwrap();
        assert_eq!(cfg.redact.global_mock_prefix, "");
        assert_eq!(cfg.redact.on_probe_exhausted, OnProbeExhausted::FailOpen);
    }

    #[test]
    fn redact_config_toml_parses_fail_closed() {
        let text = r#"
[redact]
global_mock_prefix = "sgm_"
on_probe_exhausted = "fail_closed"
"#;
        let cfg: Config = toml::from_str(text).unwrap();
        assert_eq!(cfg.redact.global_mock_prefix, "sgm_");
        assert_eq!(cfg.redact.on_probe_exhausted, OnProbeExhausted::FailClosed);
    }

    // ─── Config::load_or_default: 启动时校验 ──────────────────────────────
    //
    // 互斥契约 (api_key 与 api_key_file 不能同时设) 必须在启动时就暴露,
    // 不能被静默吞掉 — 否则用户以为在用 api_key_file, 实际 effective_api_key()
    // 优先返回 api_key 直接值, 削弱 secret 脱敏的安全价值.

    fn write_config_tmp(text: &str) -> PathBuf {
        let id = uuid::Uuid::new_v4().to_string();
        let path = PathBuf::from(format!("/tmp/opencode/tmp/test-cfg-{id}.toml"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn load_or_default_rejects_provider_with_both_api_key_and_file() {
        let path = write_config_tmp(
            r#"
            [[providers]]
            id = "bad"
            protocol = "openai"
            base_url = "https://api.example.com"
            api_key = "sk-direct"
            api_key_file = "/run/secrets/whatever"
            enabled = true
            "#,
        );
        let err = Config::load_or_default(&path).unwrap_err().to_string();
        assert!(err.contains("invalid provider"), "got: {err}");
        assert!(
            err.contains("bad"),
            "error should name the offending provider"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn load_or_default_accepts_api_key_file_only() {
        let path = write_config_tmp(
            r#"
            [[providers]]
            id = "ok"
            protocol = "openai"
            base_url = "https://api.example.com"
            api_key_file = "/run/secrets/ok-key"
            enabled = true
            "#,
        );
        Config::load_or_default(&path).expect("api_key_file only should pass validation");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn load_or_empty_rejects_state_with_both_api_key_and_file() {
        // 同样的契约必须在 dynamic state 加载时也生效 (用户手编 state.toml 也能绕过).
        let path = write_config_tmp(
            r#"
            [[providers]]
            id = "bad"
            protocol = "openai"
            base_url = "https://api.example.com"
            api_key = "sk-direct"
            api_key_file = "/run/secrets/whatever"
            enabled = true
            "#,
        );
        let err = DynamicState::load_or_empty(&path, "")
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid provider"), "got: {err}");
        assert!(
            err.contains("bad"),
            "error should name the offending provider"
        );
        std::fs::remove_file(&path).ok();
    }

    // ─── Config::load_or_default: secret 的 value_file 三步序列 ──────────
    //
    // value_file 模式: validate (结构) → resolve (读文件) → validate_value (内容).
    // 与 Provider 的 api_key_file 不同点: 读文件失败要 fail-fast (secret 缺失会让
    // redact 失效, 进而导致 secret 泄漏到 LLM provider — 正是 secret-guard 要防的事故).

    /// 辅助: 创建一个临时 secret 文件.
    fn write_secret_file(content: &str) -> PathBuf {
        let id = uuid::Uuid::new_v4().to_string();
        let path = PathBuf::from(format!("/tmp/opencode/tmp/test-secret-file-{id}.txt"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn load_or_default_resolves_secret_value_file() {
        // secret value_file 指向真实文件 → load 后 value 应当是文件内容 (trim 后).
        let secret_path = write_secret_file("sk-loaded-from-file\n");
        let cfg_text = format!(
            r#"
            [[secrets.entries]]
            id = "from-file"
            category = "apikey"
            value_file = "{}"
            "#,
            secret_path.display()
        );
        let path = write_config_tmp(&cfg_text);
        let cfg = Config::load_or_default(&path).expect("value_file should resolve");

        assert_eq!(cfg.secrets.entries.len(), 1);
        let e = &cfg.secrets.entries[0];
        assert_eq!(e.id, "from-file");
        assert_eq!(e.value, "sk-loaded-from-file"); // 末尾换行被 trim.
        assert!(
            e.value_file.is_none(),
            "value_file should be cleared after resolve"
        );
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&secret_path).ok();
    }

    #[test]
    fn load_or_default_rejects_secret_with_both_value_and_value_file() {
        // value 与 value_file 互斥, 启动时必须报错 (与 provider api_key 互斥对称).
        let secret_path = write_secret_file("irrelevant");
        let cfg_text = format!(
            r#"
            [[secrets.entries]]
            id = "bad"
            value = "direct-value"
            value_file = "{}"
            "#,
            secret_path.display()
        );
        let path = write_config_tmp(&cfg_text);
        let err = Config::load_or_default(&path).unwrap_err().to_string();
        assert!(err.contains("invalid secret"), "got: {err}");
        assert!(
            err.contains("both value and value_file"),
            "err should explain mutual exclusion: {err}"
        );
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&secret_path).ok();
    }

    #[test]
    fn load_or_default_fails_fast_on_unreadable_secret_value_file() {
        // value_file 指向不存在的文件 → fail-fast 启动失败.
        // 语义不同于 Provider (warn+fallback): secret 缺失会让 redact 静默失效, 必须报错.
        let cfg_text = r#"
            [[secrets.entries]]
            id = "missing"
            value_file = "/nonexistent/secret-guard-test/no-such-file"
            "#;
        let path = write_config_tmp(cfg_text);
        let err = Config::load_or_default(&path).unwrap_err().to_string();
        assert!(err.contains("invalid secret"), "got: {err}");
        assert!(
            err.contains("failed to read value_file"),
            "err should mention file read failure: {err}"
        );
        std::fs::remove_file(&path).ok();
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
            api_key_file: None,
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

    /// 不变式: `classify_source` 必须与 `pick_effective` 严格对偶.
    /// 即 pick_effective 返回 None 时 classify_source 也返回 None, 反之亦然.
    /// 用穷举所有 (has_static, has_dynamic, mode) 组合验证.
    #[test]
    fn classify_source_dual_to_pick_effective() {
        #[derive(Debug)]
        struct Dummy;
        for has_static in [false, true] {
            for has_dynamic in [false, true] {
                for (mode, _) in OverrideMode::ALL {
                    let s = has_static.then_some(Dummy);
                    let d = has_dynamic.then_some(Dummy);
                    let pick = pick_effective(s, d, mode).is_some();
                    let classify = classify_source(has_static, has_dynamic, mode).is_some();
                    assert_eq!(
                        pick, classify,
                        "dual violation: has_static={has_static} has_dynamic={has_dynamic} mode={mode:?}"
                    );
                }
            }
        }
    }

    // ─── DynamicTable Debug impl (覆盖手动 impl, 不泄漏内部锁) ──────────────

    #[test]
    fn dynamic_table_debug_shows_counts_not_internals() {
        // Debug impl 手写 (非 derive), 只暴露 entry_type / static_count / dynamic_count /
        // state_path, 避免把 RwLock<HashMap> 的内部结构 dump 出来 (噪音 + 可能泄漏 value).
        // 本测试守卫: Debug 输出含关键字段且不含 entry 明文.
        // 注: mod proptests 有类似的 provider(id, base_url) helper, 但跨 mod 不可见,
        // 此处为 local copy (api_key 空串适配 Debug 测试, 不关心鉴权字段).
        use crate::provider::Protocol;
        use crate::provider::{Provider, ProviderTable};

        fn make_provider(id: &str) -> Provider {
            Provider {
                id: id.to_string(),
                name: Some(format!("name-{id}")),
                protocol: Protocol::OpenAI,
                base_url: "http://up".to_string(),
                api_key: String::new(),
                api_key_file: None,
                enabled: true,
            }
        }

        let decisions = Arc::new(RwLock::new(Decisions::default()));
        let table: ProviderTable = DynamicTable::new(
            vec![make_provider("s1")],
            vec![make_provider("d1")],
            decisions,
            PathBuf::from("/tmp/test-state.toml"),
        );
        let s = format!("{table:?}");
        // 关键字段出现.
        assert!(s.contains("Provider"), "missing entry_type: {s}");
        assert!(s.contains("static_count"), "missing static_count: {s}");
        assert!(s.contains("dynamic_count"), "missing dynamic_count: {s}");
        // 明文 entry id 不应出现在 Debug 输出中 (只有 count).
        assert!(!s.contains("s1"), "Debug leaked static entry id: {s}");
        assert!(!s.contains("d1"), "Debug leaked dynamic entry id: {s}");
    }

    // ─── Config::to_toml / load_or_default 辅助路径 ─────────────────────────

    #[test]
    fn config_to_toml_serializes_default_without_error() {
        // to_toml 对默认配置应成功 (覆盖 to_toml 的 Ok 路径).
        // 不做完整 round-trip 断言 (默认 Config 字段多, 逐字段比对脆弱),
        // 只验证序列化不报错 + 输出非空.
        let cfg = Config::default();
        let toml = cfg.to_toml().expect("default config serializes");
        assert!(!toml.is_empty(), "serialized config should be non-empty");
    }

    #[test]
    fn load_or_default_returns_default_when_file_missing() {
        // 文件不存在 → warn + 返回默认 Config (覆盖 161-166 的早退分支).
        // 用不存在的路径触发; 断言返回的是默认配置 (providers/secrets 为空).
        let path = PathBuf::from("/tmp/opencode/nonexistent-config-does-not-exist.toml");
        let cfg = Config::load_or_default(&path).expect("missing file → default, not error");
        assert!(cfg.providers.is_empty(), "default has no providers");
        assert!(cfg.secrets.entries.is_empty(), "default has no secrets");
    }
}

// ─── DynamicTable<T> 通用行为测试 ──────────────────────────────────────────
//
// provider 与 secret 的 table 行为完全对称 (两者都是 `DynamicTable<T>`),
// 这里用 `SecretEntry` 作为 canonical 测试类型覆盖一遍, 避免在每个具体模块里重复
// 同样的 upsert / delete / decision / persist 场景. 类型特定测试 (validate_*
// 校验函数、effective_snapshot 的 masked 字段映射) 仍在各自模块.
#[cfg(test)]
mod table_tests {
    use super::*;
    use crate::secrets::{SecretCategory, SecretEntry, SecretTable};

    // pub(super): 让兄弟测试 mod (proptests) 可复用, 避免 DRY 重复.
    pub(super) fn entry(id: &str, value: &str) -> SecretEntry {
        SecretEntry {
            id: id.into(),
            name: Some(format!("name-{id}")),
            category: SecretCategory::ApiKey,
            value: value.into(),
            value_file: None,
            mock_strategy: crate::mock::MockStrategy::default(),
        }
    }

    pub(super) fn empty_decisions() -> Arc<RwLock<Decisions>> {
        Arc::new(RwLock::new(Decisions::default()))
    }

    fn tempfile_path(prefix: &str) -> PathBuf {
        let id = uuid::Uuid::new_v4().to_string();
        let path = PathBuf::from(format!("/tmp/opencode/tmp/test-{prefix}-{id}.toml"));
        // 确保父目录存在, 否则 atomic_write 的 File::create 会因 ENOENT 失败
        // (测试不应依赖外部预先创建的目录).
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        path
    }

    // ─── 合并算法 (pick_effective 通过 effective_raw / get_effective 端到端验证) ──

    #[test]
    fn effective_raw_isolated_from_internal_state() {
        let t = SecretTable::new(
            vec![entry("a", "secret-a"), entry("b", "secret-b")],
            vec![],
            empty_decisions(),
            PathBuf::from("/tmp/x.toml"),
        );
        // 拿到的快照是 clone, 修改不应回写.
        let mut snap = t.effective_raw();
        snap.clear();
        assert_eq!(t.effective_raw().len(), 2);
    }

    #[test]
    fn dynamic_overrides_static_by_default() {
        let t = SecretTable::new(
            vec![entry("a", "static-value")],
            vec![entry("a", "dynamic-value")],
            empty_decisions(),
            PathBuf::from("/tmp/x.toml"),
        );
        assert_eq!(t.effective_raw()[0].value, "dynamic-value");
    }

    #[test]
    fn disabled_drops_secret() {
        let t = SecretTable::new(
            vec![entry("a", "secret-value")],
            vec![],
            empty_decisions(),
            PathBuf::from("/tmp/x.toml"),
        );
        t.set_decision("a", OverrideMode::Disabled).unwrap();
        assert!(t.effective_raw().is_empty());
        assert!(t.get_effective("a").is_none());
        // has_static 不受 decision 影响, 仍能识别该 id.
        assert!(t.has_static("a"));
    }

    #[test]
    fn get_effective_falls_back_to_static() {
        let t = SecretTable::new(
            vec![entry("a", "secret-value")],
            vec![],
            empty_decisions(),
            PathBuf::from("/tmp/x.toml"),
        );
        assert_eq!(t.get_effective("a").unwrap().value, "secret-value");
        assert!(t.get_effective("missing").is_none());
    }

    // ─── upsert_dynamic / delete_dynamic (含持久化) ─────────────────────

    #[test]
    fn upsert_dynamic_insert_then_update() {
        let tmp = tempfile_path("upsert");
        let t = SecretTable::new(vec![], vec![], empty_decisions(), tmp);
        let (_, k1) = t.upsert_dynamic(entry("a", "value-one")).unwrap();
        assert_eq!(k1, UpsertKind::Inserted);
        let (_, k2) = t.upsert_dynamic(entry("a", "value-two")).unwrap();
        assert_eq!(k2, UpsertKind::Updated);
        assert_eq!(t.effective_raw()[0].value, "value-two");
    }

    #[test]
    fn delete_dynamic_removes_and_persists() {
        let tmp = tempfile_path("delete");
        let t = SecretTable::new(
            vec![],
            vec![entry("a", "v1-secret"), entry("b", "vb-secret")],
            empty_decisions(),
            tmp.clone(),
        );
        assert_eq!(t.delete_dynamic("a").unwrap(), DeleteOutcome::Deleted);
        assert_eq!(t.effective_raw().len(), 1);
        let state = DynamicState::load_or_empty(&tmp, "").unwrap();
        assert_eq!(state.secrets.len(), 1);
        assert_eq!(state.secrets[0].id, "b");
    }

    #[test]
    fn delete_dynamic_missing_returns_not_found() {
        let tmp = tempfile_path("del-miss");
        let t = SecretTable::new(vec![], vec![], empty_decisions(), tmp);
        assert_eq!(t.delete_dynamic("nope").unwrap(), DeleteOutcome::NotFound);
    }

    #[test]
    fn delete_dynamic_keeps_static_baseline() {
        let tmp = tempfile_path("del-base");
        let t = SecretTable::new(
            vec![entry("a", "static")],
            vec![entry("a", "dynamic")],
            empty_decisions(),
            tmp,
        );
        assert_eq!(t.delete_dynamic("a").unwrap(), DeleteOutcome::Deleted);
        // dynamic override 删了, static 基线仍生效.
        assert_eq!(t.effective_raw()[0].value, "static");
    }

    #[test]
    fn set_decision_disabled_then_default_persists() {
        let tmp = tempfile_path("decide");
        let t = SecretTable::new(
            vec![entry("a", "secret-value")],
            vec![],
            empty_decisions(),
            tmp.clone(),
        );

        t.set_decision("a", OverrideMode::Disabled).unwrap();
        assert!(t.get_effective("a").is_none());

        // 重启 (重新加载 state) 后 decision 应持久化.
        let state = DynamicState::load_or_empty(&tmp, "").unwrap();
        assert_eq!(state.decisions.secret("a"), OverrideMode::Disabled);

        // 切回 Default 后再验证 effective.
        t.set_decision("a", OverrideMode::Default).unwrap();
        assert!(t.get_effective("a").is_some());
    }

    #[test]
    fn prefer_static_overrides_dynamic() {
        let t = SecretTable::new(
            vec![entry("a", "static")],
            vec![entry("a", "dynamic")],
            empty_decisions(),
            PathBuf::from("/tmp/x.toml"),
        );
        t.set_decision("a", OverrideMode::PreferStatic).unwrap();
        assert_eq!(t.effective_raw()[0].value, "static");
    }

    #[test]
    fn validate_failure_rejects_upsert() {
        let tmp = tempfile_path("bad");
        let t = SecretTable::new(vec![], vec![], empty_decisions(), tmp);
        // 空 value 不通过 validate_value.
        let bad = SecretEntry {
            id: "x".into(),
            name: None,
            category: SecretCategory::ApiKey,
            value: "x".into(), // 太短 (< 3 字节) → validate_value 失败.
            value_file: None,
            mock_strategy: crate::mock::MockStrategy::default(),
        };
        assert!(t.upsert_dynamic(bad).is_err());
    }

    #[test]
    fn concurrent_upserts_no_lost_update() {
        let tmp = tempfile_path("concurrent");
        let t = SecretTable::new(vec![], vec![], empty_decisions(), tmp);
        let t1 = t.clone();
        let t2 = t.clone();
        let h1 = std::thread::spawn(move || t1.upsert_dynamic(entry("a", "value-aaa")));
        let h2 = std::thread::spawn(move || t2.upsert_dynamic(entry("b", "value-bbb")));
        h1.join().unwrap().unwrap();
        h2.join().unwrap().unwrap();
        let ids: Vec<_> = t.effective_raw().into_iter().map(|e| e.id).collect();
        assert!(ids.contains(&"a".to_string()), "lost update: {ids:?}");
        assert!(ids.contains(&"b".to_string()), "lost update: {ids:?}");
    }

    // ─── atomic_write 共用工具 ──────────────────────────────────────────

    #[test]
    fn atomic_write_roundtrip() {
        let tmp = tempfile_path("atomic");
        atomic_write(&tmp, "hello").unwrap();
        assert_eq!(std::fs::read_to_string(&tmp).unwrap(), "hello");
        let _ = std::fs::remove_file(&tmp);
    }

    // ─── 持久化失败内存回滚契约 (核心并发安全保证) ──────────────────────────
    //
    // 头部契约 (config.rs//!): "先持久化, 再更新内存, 失败自动回滚" 和
    // "不会出现内存已切到 disabled 但磁盘还是 default 的漂移".
    //
    // 这两条是双层配置的核心并发安全保证. 若 atomic_write 失败时内存被部分更新,
    // 会导致: 重启后内存与磁盘不一致 (drift), 或并发场景下读到中间态.
    //
    // 触发方式: 把 state.toml 放到一个只读目录, atomic_write 的 File::create(tmp)
    // 会因 EACCES 失败. 验证 upsert_dynamic / set_decision 返回 Err 且内存 map 未变.

    /// 构造一个只读目录 + 其中的 state.toml 路径.
    /// 返回 (dir, state_path). 调用方需在测试结束时恢复权限以便清理 (drop guard).
    ///
    /// `pub(super)`: 兄弟测试 mod (`proptests`) 复用以模拟 atomic_write 失败 (DRY).
    pub(super) struct ReadOnlyDir {
        dir: PathBuf,
    }

    impl ReadOnlyDir {
        pub(super) fn new(prefix: &str) -> Self {
            let id = uuid::Uuid::new_v4().to_string();
            let dir = PathBuf::from(format!("/tmp/opencode/tmp/test-ro-{prefix}-{id}"));
            std::fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        /// 切换到只读. 之后 atomic_write 写新文件会 EACCES.
        pub(super) fn make_readonly(&self) {
            // 0o500 = r-x for owner: 允许进入目录但禁止创建/删除文件.
            std::fs::set_permissions(
                &self.dir,
                std::os::unix::fs::PermissionsExt::from_mode(0o500),
            )
            .unwrap();
        }

        pub(super) fn state_path(&self) -> PathBuf {
            self.dir.join("state.toml")
        }
    }

    impl Drop for ReadOnlyDir {
        fn drop(&mut self) {
            // 必须先恢复可写权限才能删除目录.
            let _ = std::fs::set_permissions(
                &self.dir,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            );
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn upsert_dynamic_rolls_back_memory_on_persist_failure() {
        // 契约: atomic_write 失败时, dynamic_entries 内存保持旧值 (不能出现
        // "调用方以为 upsert 成功但磁盘没写" 的漂移).
        let ro = ReadOnlyDir::new("upsert-rollback");
        let state_path = ro.state_path();
        // 先写一个合法的初始 state, 让 load_or_empty 能成功读到.
        atomic_write(&state_path, "").unwrap();

        let t = SecretTable::new(vec![], vec![], empty_decisions(), state_path.clone());

        // 初始: 空.
        assert!(t.effective_raw().is_empty());

        // 切只读, 然后 upsert — persist_dynamic 的 atomic_write 必须失败.
        ro.make_readonly();
        let err = t
            .upsert_dynamic(entry("new", "value-new"))
            .expect_err("upsert into read-only dir must fail");
        assert!(
            err.to_string().contains("create tmp") || err.to_string().contains("failed"),
            "error should be from atomic_write failure, got: {err}"
        );

        // 核心断言: 内存未变 (回滚生效). 若内存被部分更新, effective_raw 会含 "new".
        assert!(
            t.effective_raw().is_empty(),
            "memory must roll back on persist failure; got non-empty effective_raw"
        );
        // decisions 也未受影响.
        assert!(t.decisions.read().secret("new") == OverrideMode::Default);

        // 恢复权限后 (Drop guard 会做, 但这里显式做以验证后续可写).
        std::fs::set_permissions(&ro.dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        // 同一 table 恢复后应能正常 upsert (状态未被半破坏).
        t.upsert_dynamic(entry("new", "value-new"))
            .expect("upsert must succeed after permissions restored");
        assert_eq!(t.effective_raw().len(), 1);
    }

    #[test]
    fn set_decision_rolls_back_memory_on_persist_failure() {
        // 契约 (set_decision 文档): "若 atomic_write 失败, 内存 decisions 保持旧值
        // (不会出现内存已切到 disabled 但磁盘还是 default 的漂移)".
        let ro = ReadOnlyDir::new("decision-rollback");
        let state_path = ro.state_path();
        atomic_write(&state_path, "").unwrap();

        let t = SecretTable::new(
            vec![entry("a", "secret-a")],
            vec![],
            empty_decisions(),
            state_path.clone(),
        );

        // 初始 decision = Default, effective 包含 "a".
        assert_eq!(t.decisions.read().secret("a"), OverrideMode::Default);
        assert!(t.get_effective("a").is_some());

        // 切只读, set_decision(Disabled) 的 atomic_write 必须失败.
        ro.make_readonly();
        let err = t
            .set_decision("a", OverrideMode::Disabled)
            .expect_err("set_decision into read-only dir must fail");
        assert!(
            err.to_string().contains("create tmp") || err.to_string().contains("failed"),
            "error should be from atomic_write failure, got: {err}"
        );

        // 核心断言: 内存 decisions 未变 (仍是 Default, 而非 Disabled).
        // 这正是契约要防的 "内存 disabled 但磁盘 default" 漂移.
        assert_eq!(
            t.decisions.read().secret("a"),
            OverrideMode::Default,
            "decisions memory must roll back; must NOT be Disabled"
        );
        // effective view 也仍包含 "a" (因为 decision 没切).
        assert!(
            t.get_effective("a").is_some(),
            "effective must reflect rolled-back decision (still visible)"
        );

        // 磁盘上的 decisions 段也未被写入 (load 出来应仍是 default).
        let disk_state = DynamicState::load_or_empty(&state_path, "").unwrap();
        assert_eq!(disk_state.decisions.secret("a"), OverrideMode::Default);
    }

    #[test]
    fn delete_dynamic_rolls_back_memory_on_persist_failure() {
        // delete_dynamic 同样遵循 "先持久化再更新内存" 契约. 验证删除路径的回滚.
        let ro = ReadOnlyDir::new("delete-rollback");
        let state_path = ro.state_path();
        // 预置一个 dynamic entry 并持久化到磁盘 (保持内存与磁盘初始一致).
        let existing = entry("existing", "v-existing");
        let initial = DynamicState {
            secrets: vec![existing.clone()],
            ..Default::default()
        };
        atomic_write(&state_path, &initial.to_toml().unwrap()).unwrap();

        // 内存 dynamic_entries 也带同一 entry (new() 不从磁盘加载, 需显式传入).
        let t = SecretTable::new(
            vec![],
            vec![existing],
            empty_decisions(),
            state_path.clone(),
        );
        // 确认初始状态: 有一个 entry.
        assert_eq!(t.effective_raw().len(), 1);

        ro.make_readonly();
        let err = t
            .delete_dynamic("existing")
            .expect_err("delete into read-only dir must fail");
        assert!(
            err.to_string().contains("create tmp") || err.to_string().contains("failed"),
            "error should be from atomic_write failure, got: {err}"
        );

        // 核心断言: 内存未回滚, entry 仍在 (删除未生效).
        assert_eq!(
            t.effective_raw().len(),
            1,
            "memory must roll back on delete persist failure"
        );
        assert!(t.get_effective("existing").is_some());
    }
}

// ─── Property-based tests (CFG-1 / CFG-2 / CFG-5) ──────────────────────────
//
// 用 `proptest!` 覆盖双层配置的合并 / source 标签 / 跨表并发安全契约.
// 契约 SSOT: `docs/design/contracts.md` §6 (CFG-1..CFG-5, 行 486-545).
//
// 与 `mod tests` (固定用例) / `mod table_tests` (canonical CRUD 场景) 平级,
// 这里用随机生成器覆盖更大输入空间, 锁住"外部可观察行为"层面的不变量.
// 用 `SecretEntry` 作为 canonical 测试类型 (与 table_tests 一致, provider 行为对称).
#[cfg(test)]
mod proptests {
    use super::table_tests::{ReadOnlyDir, empty_decisions, entry};
    use super::*;
    use crate::provider::{Protocol, Provider, ProviderTable};
    use crate::secrets::SecretTable;
    use proptest::prelude::*;
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;

    // ─── 共享 helpers ─────────────────────────────────────────────────────
    //
    // `entry` / `empty_decisions` 复用 super::table_tests 内的定义 (pub(super)),
    // 避免 DRY 重复. tempfile_path 与 table_tests 的版本返回类型不同
    // (PathBuf vs TempPath), 此处独立保留 RAII 版本以自动清理 proptest tmp 文件.

    /// 创建真实 tmp 文件路径 (upsert_dynamic 会写盘). 父目录预先创建, 避免 ENOENT.
    ///
    /// 返回 `TempPath` (Drop 时自动删除文件) — proptest 每个 case 产生一个 tmp 文件,
    /// 若不清理会快速累积 (一次 nextest 产生数百个); 用 RAII guard 确保跨 panic 与
    /// 测试失败也能清理.
    fn tempfile_path(prefix: &str) -> TempPath {
        let id = uuid::Uuid::new_v4().to_string();
        let path = PathBuf::from(format!("/tmp/opencode/tmp/test-prop-{prefix}-{id}.toml"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        TempPath(path)
    }

    /// RAII guard: 持有 tmp 文件路径, Drop 时删除. 解引用为 `&PathBuf` 兼容现有调用.
    /// `Debug` 不实现 (避免 ApiKey/Path 序列化场景误用), 仅作内部测试 fixture.
    ///
    /// 调用方约定: 通过 `tmp.clone()` (经 Deref 落到 `PathBuf::clone`, 返回 owned PathBuf)
    /// 传给 `SecretTable::new` 等需要 owned PathBuf 的 API. TempPath 本身保留所有权直到
    /// 函数返回, Drop 时清理文件.
    struct TempPath(PathBuf);

    impl std::ops::Deref for TempPath {
        type Target = PathBuf;
        fn deref(&self) -> &PathBuf {
            &self.0
        }
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    // ─── 跨表 (CFG-5) fixture: 合法 Provider 构造 ──────────────────────────
    //
    // 与 entry() 对称的 Provider 构造器: 跨表并发测试需要 ProviderTable 与
    // SecretTable 同时 upsert 合法项. base_url 必须通过 validate_base_url
    // (http(s) + 不带末尾 '/'), id 通过 validate_id.
    fn provider(id: &str, base_url: &str) -> Provider {
        Provider {
            id: id.into(),
            protocol: Protocol::OpenAI,
            base_url: base_url.into(),
            api_key: format!("k-{id}"),
            api_key_file: None,
            enabled: true,
            name: Some(format!("name-{id}")),
        }
    }

    /// u8 → OverrideMode 的测试 strategy 映射 (0..3), 供跨表 decision 测试参数化用.
    /// DRY: secret 表与 provider 表的 mode 映射逻辑相同, 提取后单点维护.
    fn mode_of(m: u8) -> OverrideMode {
        match m {
            0 => OverrideMode::Default,
            1 => OverrideMode::PreferStatic,
            _ => OverrideMode::Disabled,
        }
    }

    // ─── 生成器 ───────────────────────────────────────────────────────────
    //
    // id 必须满足 validate_id: 1..=64 字符, 首字符 alphanumeric, 余字符 [A-Za-z0-9_-].
    // value 必须满足 validate_value: ≥3 字节, 无 PUA (U+E000..U+F8FF), 无 mock prefix (测试用空).
    //
    // 生成器覆盖度本身作为契约要求 (AGENTS.md §0.3): 关键陷阱是 "id 冲突".
    // 简单生成两个独立 HashMap<id, value> 几乎不会产生重叠 id (id 空间远大于 8 项),
    // 会让"测 conflict 行为"的 property 退化为"测 static-only". 故显式用 ConfigScenario
    // 把 id 分桶: static_only / dynamic_only / both (冲突), **每桶 ≥1 项**确保三种语义
    // (conflict / static-only / dynamic-only) 都被每条 property 触达, 不依赖概率.

    /// 合法 secret value 生成器: `[a-z0-9]{4,16}` (≥3 字节, 纯 ASCII, 无 PUA).
    fn arb_value() -> impl Strategy<Value = String> {
        "[a-z0-9]{4,16}"
    }

    /// 一份"分桶"配置场景: 把 id 分到三个互不相交的 bucket.
    /// - `static_only`: 仅出现在 static 的 (id, value).
    /// - `dynamic_only`: 仅出现在 dynamic 的 (id, value).
    /// - `both`: 同时在 static + dynamic 的 id, 含两份不同的 value (保证冲突可观测).
    ///
    /// 用 `both` 桶恒含 ≥1 项保证 conflict 路径被覆盖, 避免独立生成两个 HashMap 时
    /// id 碰撞概率极低导致 property 退化 (见上方"生成器覆盖度"注释). 三桶均 ≥1 项,
    /// 让依赖特定桶非空的 property (如 prop_default_static_fallback 依赖 static_only)
    /// 不再需要 prop_assume 跳过 (历史跳过率 ~25%, 浪费 case 数).
    #[derive(Debug, Clone)]
    struct ConfigScenario {
        static_only: Vec<(String, String)>,
        dynamic_only: Vec<(String, String)>,
        both: Vec<(String, String, String)>, // (id, static_value, dynamic_value)
    }

    impl ConfigScenario {
        fn static_entries(&self) -> Vec<SecretEntry> {
            self.static_only
                .iter()
                .map(|(id, v)| entry(id, v))
                .chain(self.both.iter().map(|(id, sv, _)| entry(id, sv)))
                .collect()
        }

        fn dynamic_entries(&self) -> Vec<SecretEntry> {
            self.dynamic_only
                .iter()
                .map(|(id, v)| entry(id, v))
                .chain(self.both.iter().map(|(id, _, dv)| entry(id, dv)))
                .collect()
        }

        /// 收集所有 static id (static_only + both).
        fn static_ids(&self) -> Vec<String> {
            self.static_only
                .iter()
                .map(|(id, _)| id.clone())
                .chain(self.both.iter().map(|(id, _, _)| id.clone()))
                .collect()
        }
    }

    /// 生成 ConfigScenario. static_only / dynamic_only / both 桶各 1..4 项 (总 id ≤ 12),
    /// 三桶均 ≥1 项以避免依赖特定桶的 property 因桶空而退化 (历史跳过率 ~25%).
    /// 三桶 id 用不同前缀 (`s`/`d`/`b`) 保证**互不相交** (避免桶间污染, 例如同一 id
    /// 既进 static_only 又进 both 会破坏 bucket 语义). 桶内 id 用 HashMap 去重.
    fn arb_scenario() -> impl Strategy<Value = ConfigScenario> {
        (
            prop::collection::vec(("[a-z][a-z0-9]{0,3}", arb_value()), 1..4),
            prop::collection::vec(("[a-z][a-z0-9]{0,3}", arb_value()), 1..4),
            prop::collection::vec(("[a-z][a-z0-9]{0,3}", arb_value(), arb_value()), 1..4),
        )
            .prop_map(|(static_only, dynamic_only, both)| {
                let static_only: Vec<(String, String)> = static_only
                    .into_iter()
                    .map(|(id, v)| (format!("s{id}"), v))
                    .collect::<HashMap<_, _>>()
                    .into_iter()
                    .collect();
                let dynamic_only: Vec<(String, String)> = dynamic_only
                    .into_iter()
                    .map(|(id, v)| (format!("d{id}"), v))
                    .collect::<HashMap<_, _>>()
                    .into_iter()
                    .collect();
                // both 桶: 去重 id, 且保证 static_value ≠ dynamic_value (避免平凡相等
                // 掩盖 "Default 选 dynamic 但两者相等" 这种伪通过).
                let mut both_map: HashMap<String, (String, String)> = HashMap::new();
                for (id, sv, dv) in both {
                    both_map.insert(format!("b{id}"), (sv, dv));
                }
                let both: Vec<(String, String, String)> = both_map
                    .into_iter()
                    .map(|(id, (sv, dv))| {
                        // 若相等, 加前缀让 dynamic ≠ static (保证 conflict 可观测).
                        let dv = if sv == dv { format!("dyn-{dv}") } else { dv };
                        (id, sv, dv)
                    })
                    .collect();
                ConfigScenario {
                    static_only,
                    dynamic_only,
                    both,
                }
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        // ─── CFG-1: OverrideMode 合并语义 ──────────────────────────────

        /// CFG-1: Default 模式下, conflict id (both 桶) 的 effective 取 dynamic 值,
        /// static_only id 取 static 值, dynamic_only id 取 dynamic 值.
        ///
        /// 用 `arb_scenario` 的 `both` 桶**强制**保证 conflict 路径被覆盖
        /// (独立生成两个 HashMap 时 id 碰撞概率极低, 会让本 property 退化为 static_fallback).
        #[test]
        fn prop_default_dynamic_wins(scenario in arb_scenario()) {
            let t = SecretTable::new(
                scenario.static_entries(),
                scenario.dynamic_entries(),
                empty_decisions(),
                PathBuf::from("/tmp/x.toml"), // 不写盘 (无 upsert)
            );

            // both 桶: effective == dynamic value (Default 让 dynamic 胜出).
            for (id, _sv, dv) in &scenario.both {
                let eff = t.get_effective(id).expect("conflict id must be effective");
                prop_assert_eq!(
                    &eff.value, dv,
                    "Default mode: conflict id '{}' must take dynamic value", id
                );
            }
            // static_only 桶: effective == static value.
            for (id, sv) in &scenario.static_only {
                let eff = t.get_effective(id).expect("static-only id must be effective");
                prop_assert_eq!(&eff.value, sv, "static-only id stays static");
            }
            // dynamic_only 桶: effective == dynamic value.
            for (id, dv) in &scenario.dynamic_only {
                let eff = t.get_effective(id).expect("dynamic-only id must be effective");
                prop_assert_eq!(&eff.value, dv, "dynamic-only id uses dynamic");
            }
        }

        /// CFG-1: Default 模式下, 仅 static 有此 id → effective 取 static 值 (无 dynamic override).
        ///
        /// 这是 `prop_default_dynamic_wins` 的退化子集, 单独保留以明确覆盖 "无 dynamic" 边界
        /// (该 property 不依赖 both 桶, 排除 dynamic 路径的干扰).
        #[test]
        fn prop_default_static_fallback(scenario in arb_scenario()) {
            // arb_scenario 保证 static_only ≥1 项 (历史 prop_assume 已不再需要).
            // 只放 static_only 桶, 不放 dynamic / both.
            let t = SecretTable::new(
                scenario.static_only.iter()
                    .map(|(id, v)| entry(id, v))
                    .collect::<Vec<_>>(),
                vec![],
                empty_decisions(),
                PathBuf::from("/tmp/x.toml"),
            );

            // 全部 static_only id 在 effective view 中, 值等于 static.
            let effective = t.effective_raw();
            prop_assert_eq!(effective.len(), scenario.static_only.len());
            for e in &effective {
                let want = &scenario.static_only.iter()
                    .find(|(id, _)| id == &e.id)
                    .map(|(_, v)| v.clone())
                    .expect("effective id must be in static_only");
                prop_assert_eq!(&e.value, want, "static-only effective value must equal static");
            }
        }

        /// CFG-1: PreferStatic 模式下, conflict id (both 桶) 的 effective 强制取 static 原值,
        /// 忽略 dynamic override. decision 仅对 static id 有意义, 故仅对 static id (static_only
        /// + both) 设置 PreferStatic.
        #[test]
        fn prop_prefer_static_ignores_dynamic(scenario in arb_scenario()) {
            // arb_scenario 保证 both ≥1 项 (历史 prop_assume 已不再需要).
            let tmp = tempfile_path("prefer-static");
            let t = SecretTable::new(
                scenario.static_entries(),
                scenario.dynamic_entries(),
                empty_decisions(),
                tmp.clone(),
            );
            // 对所有 static id (static_only + both) 设置 PreferStatic.
            for id in scenario.static_ids() {
                t.set_decision(&id, OverrideMode::PreferStatic).unwrap();
            }

            // both 桶: PreferStatic 强制 static value (而非 dynamic).
            for (id, sv, _dv) in &scenario.both {
                let eff = t.get_effective(id).expect("PreferStatic keeps conflict id effective");
                prop_assert_eq!(
                    &eff.value, sv,
                    "PreferStatic must force static value for conflict id '{}'", id
                );
            }
            // static_only 桶: PreferStatic 对 static-only 无副作用, 仍取 static value.
            for (id, sv) in &scenario.static_only {
                let eff = t.get_effective(id).expect("PreferStatic keeps static-only effective");
                prop_assert_eq!(&eff.value, sv, "static-only stays static under PreferStatic");
            }
            // dynamic_only 桶: PreferStatic 不适用 (无 static), 仍取 dynamic value.
            for (id, dv) in &scenario.dynamic_only {
                let eff = t.get_effective(id).expect("dynamic-only still effective");
                prop_assert_eq!(&eff.value, dv, "dynamic-only unaffected by PreferStatic");
            }
        }

        /// CFG-1: Disabled 模式下, static id (static_only + both) 从 effective view 中完全排除
        /// (get_effective → None, effective_raw 不含). 仅对 static id 设置 Disabled
        /// (契约: decision 仅对 static id 有意义).
        #[test]
        fn prop_disabled_excluded(scenario in arb_scenario()) {
            // arb_scenario 保证 static_only ≥1 项, 故 static_ids() 必非空 (历史 prop_assume 已不再需要).
            let tmp = tempfile_path("disabled");
            let t = SecretTable::new(
                scenario.static_entries(),
                scenario.dynamic_entries(),
                empty_decisions(),
                tmp.clone(),
            );
            // 全部 static id 设 Disabled.
            for id in scenario.static_ids() {
                t.set_decision(&id, OverrideMode::Disabled).unwrap();
            }

            // static id (static_only + both): get_effective 必须返回 None.
            for id in scenario.static_ids() {
                prop_assert!(
                    t.get_effective(&id).is_none(),
                    "Disabled static id '{}' must not be effective", id
                );
                // has_static 不受 decision 影响 (仍能识别为 static 来源).
                prop_assert!(t.has_static(&id), "has_static must be decision-invariant");
            }
            // both 桶: 即使有 dynamic override, Disabled 也排除 (契约: Disabled 优先于 override).
            // (上面 static_ids() 已含 both 的 id, 此处不重复断言.)

            // dynamic_only 桶不受 Disabled 影响 (decision 仅对 static id 有意义).
            for (id, dv) in &scenario.dynamic_only {
                let eff = t.get_effective(id).expect("dynamic-only unaffected by static Disabled");
                prop_assert_eq!(&eff.value, dv, "dynamic-only stays effective");
            }
        }

        // ─── CFG-2: EffectiveSource 4 种标签正确 ──────────────────────

        /// CFG-2: 对每个 effective item 的 (has_static, has_dynamic, mode) 三元组,
        /// classify_source 返回的标签必须严格匹配契约表:
        ///   - 仅 static 有 (无 dynamic)              → Static
        ///   - 仅 dynamic 有 (无 static), mode=Default → Dynamic
        ///   - static + dynamic, mode=Default          → DynamicOverride
        ///   - static + dynamic, mode=PreferStatic     → StaticPreferred
        /// (Disabled / 全空 / dynamic-only+PreferStatic 不进 effective_triples, 由对偶性保证.)
        ///
        /// 用 `arb_scenario` 的三桶 + 对部分 both 桶 id 随机设置 PreferStatic,
        /// 保证四种 source 标签都有机会被触发. 用 effective_triples() 间接验证
        /// (effective_snapshot 在 secrets.rs 不在 config.rs).
        #[test]
        fn prop_source_label_matches_actual_origin(
            scenario in arb_scenario(),
            prefer_static_flags in prop::collection::vec(any::<bool>(), 0..16)
        ) {
            let tmp = tempfile_path("source-label");
            let t = SecretTable::new(
                scenario.static_entries(),
                scenario.dynamic_entries(),
                empty_decisions(),
                tmp.clone(),
            );
            // 对 both 桶的部分 id 设置 PreferStatic (用 prefer_static_flags 控制每个).
            for (i, (id, _, _)) in scenario.both.iter().enumerate() {
                if prefer_static_flags.get(i).copied().unwrap_or(false) {
                    t.set_decision(id, OverrideMode::PreferStatic).unwrap();
                }
            }

            for (s, d, m) in t.effective_triples() {
                let has_s = s.is_some();
                let has_d = d.is_some();
                let src = classify_source(has_s, has_d, m)
                    .expect("effective triple must classify to Some");
                let expected = match (has_s, has_d, m) {
                    (true, false, _) => EffectiveSource::Static,
                    (false, true, OverrideMode::Default) => EffectiveSource::Dynamic,
                    (true, true, OverrideMode::Default) => EffectiveSource::DynamicOverride,
                    (true, true, OverrideMode::PreferStatic) => EffectiveSource::StaticPreferred,
                    // 其他组合经 pick_effective 判定为 None, 不会出现在 effective_triples 中.
                    _ => panic!(
                        "unexpected effective triple: has_s={has_s} has_d={has_d} mode={m:?}"
                    ),
                };
                prop_assert_eq!(src, expected);
            }
        }

        /// CFG-2 (source 与生效值一致性 property): 对每个 effective item, pick_effective 选中的
        /// 值必须与 classify_source 标签语义一致:
        ///   - Static          → 值来自 static_ver
        ///   - Dynamic         → 值来自 dynamic_ver
        ///   - DynamicOverride → 值来自 dynamic_ver (Default 下 dynamic 胜出)
        ///   - StaticPreferred → 值来自 static_ver (PreferStatic 强制 static)
        /// 即 source 标签不能"说谎": 标 Static 就不能返回 dynamic 的字节.
        ///
        /// 这条 property 锁住 compute_effective_secret (secrets.rs) 内的 `.expect` 假设
        /// "pick_effective Some ⇒ classify_source Some 且方向一致".
        ///
        /// 命名说明: 此处 "runtime assert" 指 property 形式的运行时一致性检查, 不是
        /// `#[cfg(feature = "consistency-check")]` 的 feature flag 守卫 (后者用于热路径
        /// 派生字段断言, 见 AGENTS.md "视图正确性确保机制").
        #[test]
        fn prop_runtime_assert_effective_value_matches_source(
            scenario in arb_scenario(),
            prefer_static_flags in prop::collection::vec(any::<bool>(), 0..16),
            disabled_flags in prop::collection::vec(any::<bool>(), 0..16)
        ) {
            let tmp = tempfile_path("src-value-match");
            let t = SecretTable::new(
                scenario.static_entries(),
                scenario.dynamic_entries(),
                empty_decisions(),
                tmp.clone(),
            );
            // 对 both 桶 id 随机设置 PreferStatic / Disabled.
            for (i, (id, _, _)) in scenario.both.iter().enumerate() {
                if disabled_flags.get(i).copied().unwrap_or(false) {
                    t.set_decision(id, OverrideMode::Disabled).unwrap();
                } else if prefer_static_flags.get(i).copied().unwrap_or(false) {
                    t.set_decision(id, OverrideMode::PreferStatic).unwrap();
                }
            }
            for (i, (id, _)) in scenario.static_only.iter().enumerate() {
                if disabled_flags.get(i).copied().unwrap_or(false) {
                    t.set_decision(id, OverrideMode::Disabled).unwrap();
                }
            }

            for (s, d, m) in t.effective_triples() {
                let has_s = s.is_some();
                let has_d = d.is_some();
                let src = classify_source(has_s, has_d, m)
                    .expect("effective triple ⇒ classify Some");
                let eff = pick_effective(s.clone(), d.clone(), m)
                    .expect("effective triple ⇒ pick_effective Some");

                match src {
                    EffectiveSource::Static => {
                        let s = s.expect("Static ⇒ static_ver present");
                        prop_assert_eq!(eff.value, s.value, "Static source must return static bytes");
                    }
                    EffectiveSource::Dynamic | EffectiveSource::DynamicOverride => {
                        let d = d.expect("Dynamic(Override) ⇒ dynamic_ver present");
                        prop_assert_eq!(eff.value, d.value, "Dynamic(Override) must return dynamic bytes");
                    }
                    EffectiveSource::StaticPreferred => {
                        let s = s.expect("StaticPreferred ⇒ static_ver present");
                        prop_assert_eq!(eff.value, s.value, "StaticPreferred must return static bytes");
                    }
                }
            }
        }
    }

    // ─── CFG-5: 跨表并发安全 (单独 block, case 数压到 16 避免拖慢 CI) ────────
    //
    // 并发测试涉及真实线程 + 真实写盘, case 数与纯函数 property 区别对待.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// CFG-5: N (2..=8) 个线程并发 upsert 不同 id 到同一 SecretTable, 最终 effective 必须
        /// 包含全部 N 个 id (无 lost update). persist_lock 串行整个 RMW, 保证并发写不丢.
        ///
        /// 既有固定用例 `table_tests::concurrent_upserts_no_lost_update` (2 线程 × 2 entry)
        /// 不构成 property; 本测试把 N 扩到随机 2..=8 锁住"任意并发度都不丢"的不变量.
        #[test]
        fn prop_concurrent_upserts_no_lost_update(
            n in 2usize..=8,
            value_seed in "[a-z0-9]{4,12}"
        ) {
            let tmp = tempfile_path("concurrent");
            let t = SecretTable::new(vec![], vec![], empty_decisions(), tmp.clone());

            // N 个线程, 每个 upsert 一个独立 id (id-{i}).
            let handles: Vec<_> = (0..n)
                .map(|i| {
                    let t = t.clone();
                    let v = format!("{value_seed}{i}"); // 每线程值不同, 但都合法.
                    std::thread::spawn(move || {
                        t.upsert_dynamic(entry(&format!("id-{i}"), &v))
                            .expect("upsert must succeed");
                    })
                })
                .collect();
            for h in handles {
                h.join().expect("worker must not panic");
            }

            // 核心断言: N 个 id 全部出现在 effective.
            let ids: std::collections::HashSet<String> =
                t.effective_raw().into_iter().map(|e| e.id).collect();
            for i in 0..n {
                let want = format!("id-{i}");
                prop_assert!(
                    ids.contains(&want),
                    "lost update: id '{}' missing from effective (got {:?})",
                    want, ids
                );
            }
            // 顺便验证 count == n (无重复 / 无多余).
            prop_assert_eq!(ids.len(), n, "effective count must equal number of upserts");
        }

        /// 守卫 CFG-5 跨表并发安全 (contracts.md §6 CFG-5).
        ///
        /// 跨表场景: SecretTable 与 ProviderTable 共享同一 `persist_lock` + 同一 `state_path`
        /// + 同一 `Decisions` Arc (与 server 启动装配方式一致, 见 server.rs). N (=2*half,
        /// half∈2..=4) 个线程对半拆分: 前一半 upsert SecretTable, 后一半 upsert
        /// ProviderTable, 并发执行后 join 等待 (确定性屏障, 无 sleep).
        ///
        /// 核心断言 (覆盖 contracts.md CFG-5 两个 property):
        /// (a) 两表 effective 视图各自含全部 upsert 的项 — 跨表并发不丢更新
        ///     (`prop_concurrent_upserts_no_lost_update` 的单表版本在此扩展为双表).
        /// (b) persist_lock 串行所有 RMW, state.toml 不出现撕裂 — 从磁盘 `load_or_empty`
        ///     重新加载, 得到的 DynamicState 同时含全部 dynamic providers 与 secrets.
        #[test]
        fn prop_concurrent_writes_serialized_via_persist_lock(
            half in 2usize..=4,               // 每表线程数 (两表共 2*half 个线程并发).
            value_seed in "[a-z0-9]{4,12}"
        ) {
            let n = half * 2;
            let tmp = tempfile_path("cross-table");
            let shared_lock = Arc::new(Mutex::new(()));
            let shared_decisions = empty_decisions();
            let state_path = tmp.clone();

            let secrets = SecretTable::with_persist_lock(
                vec![], vec![], shared_decisions.clone(), state_path.clone(),
                shared_lock.clone(),
            );
            let providers = ProviderTable::with_persist_lock(
                vec![], vec![], shared_decisions.clone(), state_path.clone(),
                shared_lock.clone(),
            );

            let handles: Vec<_> = (0..n)
                .map(|i| {
                    if i < half {
                        // 前半写 SecretTable: id-s{0..half}.
                        let t = secrets.clone();
                        let v = format!("{value_seed}-s{i}");
                        std::thread::spawn(move || {
                            t.upsert_dynamic(entry(&format!("id-s{i}"), &v))
                                .expect("secret upsert must succeed");
                        })
                    } else {
                        // 后半写 ProviderTable: id-p{0..half}.
                        let j = i - half;
                        let t = providers.clone();
                        let base = format!("https://up-{value_seed}-{j}.example.com");
                        std::thread::spawn(move || {
                            t.upsert_dynamic(provider(&format!("id-p{j}"), base.as_str()))
                                .expect("provider upsert must succeed");
                        })
                    }
                })
                .collect();
            for h in handles {
                h.join().expect("worker must not panic");
            }

            // (a) 跨表并发不丢更新: 两表 effective 各含 half 项.
            let secret_ids: HashSet<String> =
                secrets.effective_raw().into_iter().map(|e| e.id).collect();
            let provider_ids: HashSet<String> =
                providers.effective_raw().into_iter().map(|e| e.id).collect();
            for i in 0..half {
                let want_s = format!("id-s{i}");
                prop_assert!(
                    secret_ids.contains(&want_s),
                    "lost secret update: '{}' missing (got {:?})", want_s, secret_ids
                );
                let want_p = format!("id-p{i}");
                prop_assert!(
                    provider_ids.contains(&want_p),
                    "lost provider update: '{}' missing (got {:?})", want_p, provider_ids
                );
            }
            prop_assert_eq!(secret_ids.len(), half, "secret effective count");
            prop_assert_eq!(provider_ids.len(), half, "provider effective count");

            // (b) state.toml 不撕裂: persist_lock 串行 RMW 保证 atomic_write 不交错,
            // 重新 load 必须成功且同时含两表的 dynamic 段 (验证跨表 RMW 没让一表覆盖另一表段).
            // 用空 global_mock_prefix 跳过 secret re-validate (persist_dynamic 同款约定).
            let reloaded = DynamicState::load_or_empty(&state_path, "")
                .expect("state.toml must be loadable (no torn write across tables)");
            let loaded_secret_ids: HashSet<String> =
                reloaded.secrets.iter().map(|e| e.id.clone()).collect();
            let loaded_provider_ids: HashSet<String> =
                reloaded.providers.iter().map(|e| e.id.clone()).collect();
            prop_assert_eq!(
                loaded_secret_ids, secret_ids,
                "state.toml secrets segment must match effective (no cross-table overwrite)"
            );
            prop_assert_eq!(
                loaded_provider_ids, provider_ids,
                "state.toml providers segment must match effective (no cross-table overwrite)"
            );
        }

        /// 守卫 CFG-5 跨表并发安全 (contracts.md §6 CFG-5) — 共享 Decisions 跨表隔离.
        ///
        /// SecretTable 与 ProviderTable 共享同一 `Decisions` Arc. 跨表并发 `set_decision`
        /// (各改自己子表: secret 表改 secrets 子表, provider 表改 providers 子表) 必须互不
        /// 串扰 — 即 secret 表的 decision 不影响 provider 表的 decision, 反之亦然, 且
        /// 合并后的 state.toml 同时保留两子表的 decision.
        ///
        /// 这是共享 Decisions Arc 的正确性证明: 若实现误用同一 HashMap (而非
        /// Decisions 内分 providers/secrets 两子表), 跨表并发会互相覆盖.
        #[test]
        fn prop_cross_table_shared_decisions_isolation(
            secret_mode in 0u8..3,
            provider_mode in 0u8..3,
        ) {
            let tmp = tempfile_path("cross-decisions");
            let shared_lock = Arc::new(Mutex::new(()));
            let shared_decisions = empty_decisions();
            let state_path = tmp.clone();

            // 各表带 1 个 static entry (id 互不相同), 让 set_decision 有作用对象.
            let secrets = SecretTable::with_persist_lock(
                vec![entry("s-static", "seed-secret-value")], vec![],
                shared_decisions.clone(), state_path.clone(), shared_lock.clone(),
            );
            let providers = ProviderTable::with_persist_lock(
                vec![provider("p-static", "https://up.example.com")], vec![],
                shared_decisions.clone(), state_path.clone(), shared_lock.clone(),
            );

            let sm = mode_of(secret_mode);
            let pm = mode_of(provider_mode);

            // 两线程并发, 各改自己子表; join 后确定性检查.
            let ts = {
                let t = secrets.clone();
                std::thread::spawn(move || {
                    t.set_decision("s-static", sm)
                        .expect("secret set_decision must succeed");
                })
            };
            let tp = {
                let t = providers.clone();
                std::thread::spawn(move || {
                    t.set_decision("p-static", pm)
                        .expect("provider set_decision must succeed");
                })
            };
            ts.join().expect("secret worker must not panic");
            tp.join().expect("provider worker must not panic");

            // (a) 共享 Decisions 跨表隔离: 两子表各自记录正确 mode, 互不串扰.
            let decisions = shared_decisions.read().clone();
            prop_assert_eq!(
                decisions.secret("s-static"), sm,
                "secret decision must survive cross-table concurrent set_decision"
            );
            prop_assert_eq!(
                decisions.provider("p-static"), pm,
                "provider decision must survive cross-table concurrent set_decision"
            );
            // 跨子表不串: secret 表的 decision 没误写到 providers 子表, 反之亦然.
            prop_assert_eq!(
                decisions.provider("s-static"), OverrideMode::Default,
                "secret decision must not leak into providers sub-table"
            );
            prop_assert_eq!(
                decisions.secret("p-static"), OverrideMode::Default,
                "provider decision must not leak into secrets sub-table"
            );

            // (b) 合并后 state.toml 同时保留两子表 decision (persist_lock 串行 RMW,
            // 一表的 set_decision load-modify-write 不会丢另一表刚写的 decision 段).
            let reloaded = DynamicState::load_or_empty(&state_path, "")
                .expect("state.toml must be loadable after cross-table set_decision");
            prop_assert_eq!(
                reloaded.decisions.secret("s-static"), sm,
                "persisted secret decision must survive"
            );
            prop_assert_eq!(
                reloaded.decisions.provider("p-static"), pm,
                "persisted provider decision must survive"
            );
        }
    }

    // ─── CFG-4: 持久化原子性 (case 数压到 16, 涉及真实写盘 + chmod) ──────────
    //
    // 契约 (config.rs//! "持久化策略"): "先写 state.toml (atomic + fsync), 再更新内存,
    // 失败自动回滚". 既有 table_tests 的 3 个 ReadOnlyDir 固定用例 (upsert/set_decision/
    // delete 各一) 覆盖回滚机制, 本 block 把它们 property 化: 参数化操作种类 / 初始内存
    // 状态 / 失败时机, 锁住 "任意写操作在 persist 失败时内存都不漂移" 的不变量.
    //
    // ReadOnlyDir / TempPath 复用自 super::table_tests / 本 mod (DRY).
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// CFG-4: state.toml 写失败时, 内存层不留下半提交状态.
        ///
        /// 参数化: 初始 dynamic 数 (0..3) + 操作种类 (upsert_new / upsert_update_existing /
        /// delete_existing / set_decision). 对每个组合, 切只读目录后执行操作 → 必须返回 Err,
        /// 且内存 dynamic_entries / decisions 与操作前完全一致 (没漂移).
        #[test]
        fn prop_persist_failure_rolls_back_memory(
            initial_dyn in prop::collection::vec(("[a-z][a-z0-9]{0,3}", arb_value()), 0..3),
            // 操作种类: 0 = upsert 新 id, 1 = upsert 已有 id (若非空), 2 = delete 已有 id (若非空),
            // 3 = set_decision.
            op_kind in 0u8..4,
        ) {
            // 去重初始 dynamic entries (用 HashMap 保证 id 唯一, 与 arb_scenario 风格一致).
            let initial: Vec<SecretEntry> = initial_dyn.into_iter()
                .collect::<HashMap<_, _>>()
                .into_iter()
                .map(|(id, v)| entry(&format!("d{id}"), &v))
                .collect();
            let initial_ids: HashSet<String> = initial.iter().map(|e| e.id().to_string()).collect();

            // 只读目录: 预写一个合法的初始 state, 让 load_or_empty 能读到.
            let ro = ReadOnlyDir::new("prop-rollback");
            let state_path = ro.state_path();
            let init_state = DynamicState {
                secrets: initial.clone(),
                ..Default::default()
            };
            atomic_write(&state_path, &init_state.to_toml().unwrap()).unwrap();

            let t = SecretTable::new(
                vec![entry("s-base", "static-base-value")],
                initial.clone(),
                empty_decisions(),
                state_path.clone(),
            );
            // 快照操作前的内存状态 (用作回滚基准).
            let mem_before: Vec<(String, String)> = t.effective_raw().into_iter()
                .map(|e| (e.id, e.value)).collect();
            let dec_before = t.decisions.read().clone();

            // 切只读, 任何写操作都会在 persist_dynamic / set_decision 的 atomic_write 失败.
            ro.make_readonly();

            let res = match op_kind {
                0 => t.upsert_dynamic(entry("brand-new", "brand-new-value"))
                    .map(|_| ()),
                1 => {
                    // 编辑已有 dynamic id (若存在), 否则 fallback 到编辑 s-base (static fork).
                    let target = initial.first().map(|e| e.id().to_string())
                        .unwrap_or_else(|| "s-base".into());
                    t.upsert_dynamic(entry(&target, "edited-value")).map(|_| ())
                }
                2 => {
                    // 删除已有 dynamic id. 注意: delete_dynamic 仅当 id 在 dynamic 中才触发
                    // persist; 若 initial 为空, target fallback 到 s-base (不在 dynamic),
                    // delete_dynamic 返回 Ok(NotFound) 不触发 persist — 此组合无 persist 失败
                    // 可测, 由 `expect_persist_failure` 标志区分断言.
                    let target = initial.first().map(|e| e.id().to_string())
                        .unwrap_or_else(|| "s-base".into());
                    t.delete_dynamic(&target).map(|_| ())
                }
                _ => t.set_decision("s-base", OverrideMode::Disabled),
            };
            // 是否期望本次操作触发 persist (从而在只读目录下必失败)?
            // op_kind 0/1/3 总触发 persist (upsert / set_decision 无条件持久化);
            // op_kind 2 (delete) 仅当 initial 非空 (即 target 是真实存在的 dynamic id) 才触发.
            let expect_persist_failure = op_kind != 2 || !initial.is_empty();
            if expect_persist_failure {
                // 契约: persist 失败 → 操作返回 Err (调用方能感知失败).
                prop_assert!(res.is_err(), "write into read-only dir must fail");
            }
            // op_kind 2 且 initial 空: delete_dynamic(s-base) 返回 Ok(NotFound), 无 persist 无失败,
            // 此分支 res.is_ok() 是正确的 (delete 不存在的 dynamic id 本就该返回 NotFound).

            // 核心断言: 内存 dynamic_entries / decisions 完全回滚到操作前.
            let mem_after: Vec<(String, String)> = t.effective_raw().into_iter()
                .map(|e| (e.id, e.value)).collect();
            prop_assert_eq!(
                mem_after, mem_before,
                "memory must roll back on persist failure (no half-committed state)"
            );
            // decisions 也未变 (set_decision 失败时尤其重要, 防 "内存 disabled 但磁盘 default").
            prop_assert_eq!(
                t.decisions.read().clone(), dec_before,
                "decisions memory must roll back on persist failure"
            );
            // 初始 dynamic id 仍全部在内存 (新增 id 不应混入).
            let after_ids: HashSet<String> = t.effective_raw().into_iter()
                .map(|e| e.id).collect();
            for id in &initial_ids {
                prop_assert!(after_ids.contains(id), "initial dynamic id '{id}' must survive");
            }
            prop_assert!(!after_ids.contains("brand-new"),
                "newly-attempted id must NOT leak into memory on persist failure");
        }

        /// CFG-4: atomic_write 用 tmp + rename, 不留下损坏的 state.toml.
        ///
        /// 两个不变量分场景验证:
        ///  - **成功路径**: atomic_write 成功后, state.toml 内容 == 期望 toml (字节级);
        ///    且目录中无残留 `.tmp` 文件 (rename 已消费 tmp).
        ///  - **失败路径** (只读目录): atomic_write 失败时, 原 state.toml 内容**完全不变**
        ///    (字节级), 也无残留 `.tmp` 文件 (原子性: 要么全成功, 要么全无, 无中间态).
        ///
        /// 不直接模拟进程崩溃 (需 kill 进程), 而是用 "失败时文件不变 + 无 tmp 残留" 锁住
        /// atomic_write 的可观察契约 — 这正是 tmp + rename 模式对调用方的核心保证.
        #[test]
        fn prop_atomic_write_no_corrupt_file(content in "[a-z0-9 \\n]{1,64}") {
            // ── 成功路径 ──
            let ok = ReadOnlyDir::new("atomic-ok");
            let ok_path = ok.state_path();
            atomic_write(&ok_path, &content).expect("writable dir: atomic_write must succeed");
            // 文件内容字节级相等.
            let on_disk = std::fs::read_to_string(&ok_path).unwrap();
            prop_assert_eq!(&on_disk, &content, "successful write: disk == content (no corruption)");
            // 无残留 tmp 文件 (rename 已消费).
            let tmp_leftover = std::fs::read_dir(ok.state_path().parent().unwrap()).unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
                .count();
            prop_assert_eq!(tmp_leftover, 0, "success path: no leftover .tmp file");

            // ── 失败路径 ──
            let ro = ReadOnlyDir::new("atomic-fail");
            let ro_path = ro.state_path();
            // 预置一个旧内容 (非空), 模拟 "已有合法 state.toml".
            let old_content = "old-preserved-content";
            atomic_write(&ro_path, old_content).unwrap();
            // 切只读, 再尝试写新内容 — 必须失败.
            ro.make_readonly();
            let res = atomic_write(&ro_path, &content);
            prop_assert!(res.is_err(), "read-only dir: atomic_write must fail");
            // 核心断言: 原文件内容字节级不变 (没撕裂, 没部分覆盖).
            let still_on_disk = std::fs::read_to_string(&ro_path).unwrap();
            prop_assert_eq!(
                still_on_disk, old_content,
                "failed write: original file must be byte-identical (atomic: no partial write)"
            );
            // 失败时也无残留 tmp (File::create 失败前不应创建, rename 失败前应清理).
            let tmp_leftover = std::fs::read_dir(ro.state_path().parent().unwrap()).unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
                .count();
            prop_assert_eq!(tmp_leftover, 0, "failure path: no leftover .tmp file (atomic cleanup)");
        }

        /// CFG-4: 并发写时, persist 失败回滚不影响其他 in-flight 写入.
        ///
        /// **降级说明 (契约 CFG-4 诚实标注)**: 契约原文要求"**跨表**并发写时, **一表** persist
        /// 失败回滚**不影响另一表** in-flight 写入". 真正的"跨表"覆盖需要装配 SecretTable +
        /// ProviderTable 共享 persist_lock + Decisions + 同一 state_path, 复杂度高. 本测试
        /// **降级为单表** (同一 SecretTable) N 线程并发, 覆盖"persist_lock 串行 RMW + 失败回滚"
        /// 这一核心不变量, 但**未触及**跨表 state.toml 文件交互 (一表 atomic_write 损坏文件
        /// 影响另一表 load_or_empty) 与共享 Decisions Arc 的跨表隔离. 跨表完整覆盖作为后续工作.
        ///
        /// N (2..=6) 线程并发对只读目录上的 SecretTable 写, 断言所有写入都失败且内存不留半提交.
        /// 成功路径 (并发不丢更新) 由 CFG-5 的 `prop_concurrent_upserts_no_lost_update` 覆盖,
        /// 本测试纯粹聚焦失败路径, 避免与 CFG-5 重叠.
        #[test]
        fn prop_persist_failure_rollback_under_concurrency(
            n in 2usize..=6,
            value_seed in "[a-z0-9]{4,12}",
        ) {
            let ro = ReadOnlyDir::new("prop-conc-fail");
            let state_path = ro.state_path();
            atomic_write(&state_path, "").unwrap();
            let t = SecretTable::new(vec![], vec![], empty_decisions(), state_path.clone());
            ro.make_readonly();

            let handles: Vec<_> = (0..n).map(|i| {
                let t = t.clone();
                let v = format!("{value_seed}{i}");
                std::thread::spawn(move || {
                    // 故意忽略 Err: 测试关心的是 "失败的并发写不留半提交".
                    let _ = t.upsert_dynamic(entry(&format!("id-{i}"), &v));
                })
            }).collect();
            for h in handles { h.join().unwrap(); }

            // 核心: 所有写入都失败, 内存 effective 完全空 (无半提交).
            prop_assert!(
                t.effective_raw().is_empty(),
                "concurrent failed writes must leave NO half-committed entries in memory"
            );
            // state.toml 仍是空 (字节级, 无撕裂).
            let disk = std::fs::read_to_string(&state_path).unwrap();
            prop_assert!(
                disk.is_empty() || !disk.contains("id-"),
                "concurrent failed writes: state.toml must not contain any new id"
            );
        }
    }

    // ─── SEC-6: 默认监听 127.0.0.1 ────────────────────────────────────
    //
    // 契约 (docs/design/contracts.md §7 SEC-6): 默认 host=127.0.0.1.
    // 单用户本地网关的安全姿态 — 不意外暴露到外网. ServerConfig::default 是
    // 启动时的 fail-safe 默认, 用户未显式配置 [server] host 时生效.

    /// SEC-6: ServerConfig::default().host == "127.0.0.1".
    ///
    /// 这是 fail-safe 默认: 即便用户忘配 [server] host, 进程也只绑回环地址,
    /// 不会把 secret 网关暴露到 LAN/WAN. 固定值断言 (无随机输入, 故用 #[test]
    /// 而非 proptest! — 契约登记 + 文档化价值).
    #[test]
    fn prop_default_host_localhost() {
        let cfg = ServerConfig::default();
        assert_eq!(
            cfg.host, "127.0.0.1",
            "SEC-6 violation: default host must be 127.0.0.1 (loopback only), got '{}'",
            cfg.host
        );
    }
}
