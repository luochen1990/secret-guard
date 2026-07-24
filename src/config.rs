//! 配置文件 schema (TOML + serde) + 双层 (static + dynamic) 合并的泛型基础设施.
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
//! - 每次写 dynamic 时 `DynamicState::load_or_empty(state_path)` → 改对应段 → `to_toml` → `atomic_write`.
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
    /// 3. [`validate_value`] — resolve 后跑最终内容校验 (长度 / mock prefix / PUA),
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
        validate_and_resolve_secrets(path, &mut cfg.secrets.entries)?;
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
}

impl DynamicState {
    /// 从 TOML 文件加载; 若文件不存在返回空 state (不 warn, 这是正常情况).
    ///
    /// 与 [`Config::load_or_default`] 一样, 加载后会跑 validate + resolve + 内容校验 —
    /// 用户手编 state.toml 时也应当尽早暴露契约违反.
    pub fn load_or_empty(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read state {}: {e}", path.display()))?;
        let mut state: Self = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parse state {}: {e}", path.display()))?;
        validate_and_resolve_secrets(path, &mut state.secrets)?;
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
/// Provider 不需要此序列 — 见 [`SecretEntry::validate_and_resolve`] 的"与 Provider 的差异"段.
fn validate_and_resolve_secrets(path: &Path, secrets: &mut [SecretEntry]) -> anyhow::Result<()> {
    for s in secrets.iter_mut() {
        s.validate_and_resolve().map_err(|e| {
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
/// 本函数也返回 None. 这样 [`compute_effective_*`] 中的 `.expect` 不会在生产 panic.
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
        let mut seen: HashSet<String> = HashSet::new();

        // 1. 遍历 static ids, 按 decision 决定 effective.
        for s in statics.iter() {
            seen.insert(s.id().to_string());
            let dyn_opt = dynamics.iter().find(|d| d.id() == s.id()).cloned();
            let mode = T::get_decision(&decisions, s.id());
            if pick_effective(Some(s.clone()), dyn_opt.clone(), mode).is_some() {
                out.push((Some(s.clone()), dyn_opt, mode));
            }
        }
        // 2. dynamic-only ids: decision 不适用, 直接生效.
        for d in dynamics.iter() {
            if seen.contains(d.id()) {
                continue;
            }
            seen.insert(d.id().to_string());
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
        let mut state = DynamicState::load_or_empty(&self.state_path)?;
        state.decisions = new_decisions.clone();
        let text = state.to_toml()?;
        atomic_write(&self.state_path, &text)?;
        *self.decisions.write() = new_decisions;
        Ok(())
    }

    // ─── 内部持久化 helper ──────────────────────────────────────────────

    /// 重写 state.toml 中本表对应的段 (provider / secret). 调用方必须持有 persist_lock.
    fn persist_dynamic(&self, new_dynamic: &[T]) -> anyhow::Result<()> {
        let mut state = DynamicState::load_or_empty(&self.state_path)?;
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
        let err = DynamicState::load_or_empty(&path).unwrap_err().to_string();
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

    fn entry(id: &str, value: &str) -> SecretEntry {
        SecretEntry {
            id: id.into(),
            name: Some(format!("name-{id}")),
            category: SecretCategory::ApiKey,
            value: value.into(),
            value_file: None,
            mock_strategy: crate::mock::MockStrategy::default(),
        }
    }

    fn empty_decisions() -> Arc<RwLock<Decisions>> {
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
        let state = DynamicState::load_or_empty(&tmp).unwrap();
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
        let state = DynamicState::load_or_empty(&tmp).unwrap();
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
}
