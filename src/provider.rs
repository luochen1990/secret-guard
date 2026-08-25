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
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use parking_lot::Mutex;

use crate::config::{
    Decisions, DynamicEntry, DynamicState, DynamicTable, EffectiveSource, OverrideMode,
    classify_source, pick_with_inherit,
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

/// 单个 provider 实例 — **sum type** (#187): 直连上游 (`Direct`) 或虚拟路由
/// (`Virtual`) 两种构造, 配置项完全不同, 非法状态不可表示 (Virtual 根本没有
/// base_url/api_key 字段).
///
/// 共享字段: `id` / `name` / `enabled` / `model_override` (两种构造都可配).
///
/// serde 层经 `ProviderWire` (平铺 legacy 形态) 双向转换 — 磁盘 TOML / API
/// payload 格式零变化 (有 `route_to` 即虚拟), 既有 secret-guard.toml / state.toml
/// 直接兼容.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "ProviderWire", into = "ProviderWire")]
pub struct Provider {
    /// 唯一 id (slug). 同一份表 (static 或 dynamic) 中必须唯一.
    pub id: String,
    /// 是否启用. `false` 时转发到该 provider 返回 503.
    pub enabled: bool,
    /// 可选人类可读名称 (Web UI 显示).
    pub name: Option<String>,
    /// 可选: 出站请求的 model 字段强制重写值 (#183). 两种构造均可配; 链上解析
    /// first-wins (见 `resolve_route`). 代价与限制的 SSOT: FWD-1 修订 + FWD-5
    /// `prop_model_override_*` (`docs/design/contracts.md`).
    pub model_override: Option<String>,
    /// 构造判别: 直连上游 or 虚拟路由.
    pub kind: ProviderKind,
}

/// Provider 的两种构造 (#187 sum type).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProviderKind {
    /// 直连上游: 真实 LLM 端点, 承载转发.
    Direct(DirectProvider),
    /// 虚拟 endpoint: 不承载转发, 请求经 `route_to` 链解析到链尾实体 (#179).
    Virtual(VirtualProvider),
}

/// 直连上游 provider 的构造负载 ([`ProviderKind::Direct`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectProvider {
    /// 协议: 决定上游的 egress protocol (跨协议请求自动走 codec 翻译).
    pub protocol: Protocol,
    /// 上游 base URL, 末尾**不带** `/`. 通过 [`validate_base_url`] 校验.
    pub base_url: String,
    /// API key 直接值. 明文存储在本地 config 文件中 (本地进程, 不通过网络暴露).
    /// 与 [`DirectProvider::api_key_file`] 互斥 — 同时设置会在 validate 中报错.
    #[serde(default)]
    pub api_key: String,
    /// 可选: 从文件路径读取 api_key. 优先级低于 [`DirectProvider::api_key`].
    ///
    /// 用法: 让 toml 本身不含敏感数据, secret 由外部机制 (sops-nix / systemd LoadCredential /
    /// docker secrets / k8s secrets) 解密到独立路径, secret-guard 在请求时读取.
    ///
    /// 文件内容会被 `trim()` (容忍末尾换行符, 这是 sops / `echo | tee` 的常见副作用).
    /// 文件读不到时按空 key 处理 (与 `api_key` 为空时一致), 由 `apply_provider_auth`
    /// (在 `crate::proxy`) 决定是否跳过 auth header 注入.
    #[serde(default)]
    pub api_key_file: Option<std::path::PathBuf>,
}

/// 虚拟 endpoint provider 的构造负载 ([`ProviderKind::Virtual`]).
///
/// base_url / api_key / api_key_file **在此构造下不存在** (sum type 根治
/// "配置了被忽略" 的非法状态). 路由语义 (per-request 解析 / 坏路由 503 / 环与
/// 悬空处置) 的 SSOT: [`ProviderTable::resolve_route`] +
/// [`ProviderTable::would_cycle`] + FWD-5 契约 (`docs/design/contracts.md`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualProvider {
    /// 路由目标 (另一 provider 的 id). 非空 (wire 层已 filter 空串).
    pub route_to: String,
    /// 协议: **仅 WebUI 展示** — ingress 由 URL proto_short 决定, egress 由链尾
    /// 实体的 protocol 决定 (不同则自动走 cross_proto 翻译). sum 化后真正可选
    /// (旧格式必有值, 读入保留).
    #[serde(default)]
    pub protocol: Option<Protocol>,
}

/// Provider 的**平铺 wire 形态** (磁盘 TOML / 既有 API payload).
///
/// 判别规则: `route_to` 非空 → [`ProviderKind::Virtual`] (忽略 base_url/api_key,
/// 兼容旧格式虚拟条目残留的实体字段); 否则 → [`ProviderKind::Direct`].
///
/// 这是 #187 重构的兼容层: 领域模型 sum 化, 序列化格式保持 #179/#183 之前的
/// 平铺形态, 既有配置文件零破坏. 新代码不应直接使用本类型 (除 serde 边界).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProviderWire {
    pub id: String,
    /// Direct 必填 (缺失时 try_from 报错); Virtual 可选 (仅展示).
    pub protocol: Option<Protocol>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub base_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub api_key: String,
    #[serde(default)]
    pub api_key_file: Option<std::path::PathBuf>,
    #[serde(default)]
    pub route_to: Option<String>,
    #[serde(default)]
    pub model_override: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub name: Option<String>,
}

impl TryFrom<ProviderWire> for Provider {
    type Error = String;

    fn try_from(w: ProviderWire) -> Result<Self, Self::Error> {
        let route_to = w.route_to.filter(|s| !s.is_empty());
        let kind = match route_to {
            Some(route_to) => ProviderKind::Virtual(VirtualProvider {
                route_to,
                protocol: w.protocol,
            }),
            None => {
                let protocol = w.protocol.ok_or_else(|| {
                    format!(
                        "provider {}: protocol is required for direct providers",
                        w.id
                    )
                })?;
                ProviderKind::Direct(DirectProvider {
                    protocol,
                    base_url: w.base_url,
                    api_key: w.api_key,
                    api_key_file: w.api_key_file,
                })
            }
        };
        Ok(Provider {
            id: w.id,
            enabled: w.enabled,
            name: w.name,
            model_override: w.model_override,
            kind,
        })
    }
}

impl From<Provider> for ProviderWire {
    fn from(p: Provider) -> Self {
        let (protocol, base_url, api_key, api_key_file, route_to) = match p.kind {
            ProviderKind::Direct(d) => (
                Some(d.protocol),
                d.base_url,
                d.api_key,
                d.api_key_file,
                None,
            ),
            ProviderKind::Virtual(v) => {
                // 实体字段写空值: 虚拟条目在平铺格式下不携带实体配置.
                (
                    v.protocol,
                    String::new(),
                    String::new(),
                    None,
                    Some(v.route_to),
                )
            }
        };
        ProviderWire {
            id: p.id,
            protocol,
            base_url,
            api_key,
            api_key_file,
            route_to,
            model_override: p.model_override,
            enabled: p.enabled,
            name: p.name,
        }
    }
}

/// serde `default` helper: 让 `enabled` 字段缺省为 `true`.
/// `pub(crate)` 以便 `web::api` 复用 (避免重复定义).
pub(crate) fn default_true() -> bool {
    true
}

impl DirectProvider {
    /// 返回生效的 api_key: 优先 [`DirectProvider::api_key`] 直接值, 否则从
    /// [`DirectProvider::api_key_file`] 读取 (trim 后). 两者都未配置 → 返回空字符串.
    ///
    /// 不报告错误: 上层 (`apply_provider_auth` 在 `crate::proxy`) 会基于空 key 决定是否跳过 auth 注入,
    /// 单个 provider 配置错误不应拖垮整个进程.
    ///
    /// 但会 `warn!` 一次让运维可观测 — 文件读不到时, 仅从上游 401/403 反推原因很痛苦.
    /// 与项目其他错误路径 (`proxy/` 中 `warn!` 各种 IO/header 错误) 风格一致.
    ///
    /// `id` 仅用于 warn-once 去重键 (DirectProvider 自身不持有 id).
    pub fn effective_api_key(&self, id: &str) -> String {
        if !self.api_key.is_empty() {
            return self.api_key.clone();
        }
        if let Some(path) = &self.api_key_file {
            match std::fs::read_to_string(path) {
                Ok(s) => {
                    // 文件恢复可读, 清除 warn 记录, 让下次失败能再次 warn.
                    WARNED_API_KEY_FILE.lock().remove(id);
                    return s.trim().to_string();
                }
                Err(e) => {
                    // 首次失败 warn 一次, 后续同样错误静默 — 避免 LLM 高 QPS 场景日志爆.
                    // (恢复后会再次 warn, 让运维感知到再次发生的失败.)
                    let first_failure = WARNED_API_KEY_FILE.lock().insert(id.to_string());
                    if first_failure {
                        tracing::warn!(
                            provider_id = %id,
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
        match &self.kind {
            ProviderKind::Direct(d) => {
                validate_base_url(&d.base_url)?;
                // api_key 与 api_key_file 互斥: 同时设置时语义不明 (effective_api_key
                // 会优先 api_key, 但这种配置几乎肯定是误操作 — 比如 toml 既填了
                // api_key 又忘了删 api_key_file).
                if !d.api_key.is_empty() && d.api_key_file.is_some() {
                    return Err(format!(
                        "provider {} has both api_key and api_key_file set; pick one",
                        self.id
                    ));
                }
            }
            ProviderKind::Virtual(v) => {
                // 自环在此拒绝 (entry-local, 覆盖 static 加载与所有 upsert);
                // 跨条目成环由 upsert 侧 would_cycle + 运行时 resolve_route 兜底.
                crate::secrets::validate_id(&v.route_to)?;
                if v.route_to == self.id {
                    return Err(format!("provider {} routes to itself", self.id));
                }
            }
        }
        // model_override 空串非法 (#183): "清空" 语义应省略字段 (TOML) / WebUI 发 "".
        // 静默 normalize (Some("") → None) 会掩盖手滑留下的空配置, fail-fast 更优.
        // 长度上限与空白拒绝: 对齐 id/name 的输入卫生 (超长值进 WebUI pill / JSON /
        // per-node DAG 存储; 纯空白在 WebUI 侧被 trim 掉, 配置侧同标准拒绝).
        if let Some(m) = &self.model_override {
            if m.is_empty() {
                return Err(format!(
                    "provider {} has empty model_override; omit the field to clear it",
                    self.id
                ));
            }
            if m.chars().count() > 128 {
                return Err(format!(
                    "provider {} model_override exceeds 128 chars",
                    self.id
                ));
            }
            if m.trim().is_empty() {
                return Err(format!(
                    "provider {} model_override is whitespace-only",
                    self.id
                ));
            }
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

    /// #157: override 未记录鉴权字段 (api_key 与 api_key_file 均空) → 两者从 static
    /// 继承. 让 "PUT api_key=null 保留旧值" 的 override 不落盘明文, 转发仍带旧 key.
    /// 已知限制 (static 基线下空串无法清空): 见根 AGENTS.md "#157 已知限制" 条目.
    ///
    /// sum type 语义 (#187): 继承只在**同型构造**内发生 (Direct↔Direct 继承鉴权字段).
    /// 跨型不继承 — override 的构造本身就是显式决策:
    /// - Direct override + Virtual static = **改回实体** (route_to 无 None 歧义,
    ///   #179 登记的 "无法改回实体" 限制由类型系统根治);
    /// - Virtual override + Direct static = 切为虚拟 (Virtual static 无鉴权字段
    ///   可继承, 与旧行为等价 — 旧实现继承到的也是空).
    fn inherit_from_static(&mut self, static_ver: &Self) {
        // model_override 共享字段, #157 语义不变: override 未记录 → 从 static 继承.
        // 已知限制: static 配置了 override 的条目无法经 override 清空; 根治属
        // #157 请求 schema 演进 (PUT null vs ""), 与构造类型无关.
        if self.model_override.is_none() {
            self.model_override = static_ver.model_override.clone();
        }
        if let (ProviderKind::Direct(d), ProviderKind::Direct(sd)) =
            (&mut self.kind, &static_ver.kind)
            && d.api_key.is_empty()
            && d.api_key_file.is_none()
        {
            d.api_key = sd.api_key.clone();
            d.api_key_file = sd.api_key_file.clone();
        }
    }
}

// ─── ProviderTable 别名 + 类型特定 effective 视图 ──────────────────────────

/// Provider 注册表. 进程级共享状态, 由 `AppState` (crate::state) 持有.
///
/// 实际类型是 [`DynamicTable<Provider>`](crate::config::DynamicTable),
/// 所有通用方法 (effective_raw / get_effective / upsert_dynamic / ...) 在那里实现;
/// 下面的 `impl DynamicTable<Provider>` 仅补充 Provider 特有的 effective 视图.
pub type ProviderTable = DynamicTable<Provider>;

/// Provider 的合并视图项. 同时携带生效值与 provenance, 供路由层与 WebUI 共用.
///
/// - effective 字段是路由层实际使用的值;
/// - `static_version` / `dynamic_version` 是原始 baseline, 供 WebUI 渲染对比 / 切换.
#[derive(Debug, Clone, Serialize)]
pub struct EffectiveProvider {
    // ─── effective 共享字段 ───
    pub id: String,
    pub enabled: bool,
    pub name: Option<String>,
    /// 出站 model 强制重写值 (#183). 见 [`Provider::model_override`].
    pub model_override: Option<String>,
    /// 构造判别 (直连 / 虚拟), JSON 为 internally tagged flatten:
    /// `{"kind": "direct", "protocol": ..., "base_url": ...}` /
    /// `{"kind": "virtual", "route_to": ...}`.
    #[serde(flatten)]
    pub kind: EffectiveProviderKind,

    // ─── provenance 元信息 (WebUI 渲染用) ───
    pub source: EffectiveSource,
    /// 对此 static id 的决策. 若 static 中无此 id 则恒为 Default.
    pub decision: OverrideMode,
    /// static 中的原始版本 (若存在). 已脱敏 (api_key masked).
    pub static_version: Option<ProviderMasked>,
    /// dynamic 中的覆盖版本 (若存在). 已脱敏.
    pub dynamic_version: Option<ProviderMasked>,
}

/// EffectiveProvider 的构造判别 (sum, #187). 字段集与 [`ProviderKind`] 对应
/// (api_key 脱敏为 masked 视图; Virtual 的 protocol 可选).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EffectiveProviderKind {
    Direct {
        protocol: Protocol,
        base_url: String,
        /// 直接值 (api_key 字段) 的 masked 视图. 若 provider 用 api_key_file,
        /// 这里是空字符串 — 文件内容由 effective_api_key() 在转发时读取, 不进 effective 视图.
        api_key_masked: String,
        api_key_length: usize,
    },
    Virtual {
        route_to: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        protocol: Option<Protocol>,
    },
}

/// 对外返回时屏蔽真实 api_key. 仍保留长度提示 (便于排查"是否配置了 key").
#[derive(Debug, Clone, Serialize)]
pub struct ProviderMasked {
    pub id: String,
    pub name: Option<String>,
    pub enabled: bool,
    /// 出站 model 强制重写值 (#183). 见 [`Provider::model_override`].
    pub model_override: Option<String>,
    #[serde(flatten)]
    pub kind: EffectiveProviderKind,
}

impl From<Provider> for ProviderMasked {
    fn from(p: Provider) -> Self {
        let kind = match p.kind {
            ProviderKind::Direct(d) => {
                let api_key_length = d.api_key.chars().count();
                EffectiveProviderKind::Direct {
                    protocol: d.protocol,
                    api_key_masked: crate::secrets::mask_value(&d.api_key),
                    api_key_length,
                    base_url: d.base_url,
                }
            }
            ProviderKind::Virtual(v) => EffectiveProviderKind::Virtual {
                route_to: v.route_to,
                protocol: v.protocol,
            },
        };
        Self {
            id: p.id,
            name: p.name,
            enabled: p.enabled,
            model_override: p.model_override,
            kind,
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

    /// 解析虚拟 provider 路由链 (#179): 跟随 `route_to` 直到链尾的实体 provider,
    /// 并收集链上生效的 `model_override` (#183).
    ///
    /// - **per-request 语义**: dispatch 每次转发前调用, 切换指向只影响新请求
    ///   (in-flight 请求已拿到解析结果, 按旧目标完成, 无需 drain);
    /// - 每跳走 [`Self::get_effective`] (含 static+dynamic+decision 合并与 #157 继承),
    ///   链上每个 provider 必须存在且 entry-level enabled;
    /// - **model_override first-wins** (#183): 沿链从入口起第一个非空 override 生效
    ///   — 入口 (虚拟级 "端点=模型X") > 中间跳 > 链尾实体 ("channel 强制模型"),
    ///   高层意图优先, 切换 target 不隐式改变生效模型;
    /// - **链内非原子**: 两跳以上链的逐跳解析各自独立读表, 解析期间表被修改时
    ///   本请求可能走 "切换前 + 切换后" 的混合链 — 这是 per-request 解析的自然
    ///   语义 (本请求视角, 链在解析起点时刻的快照), 不额外加锁;
    /// - visited-set 保证**有限步终止**: 表有限, 重复 id 即环 (validate/would_cycle
    ///   之外的运行时兜底 — 手改 state.toml 或并发写入造成的环在这里安全降级为
    ///   503, 不挂起);
    /// - `entry` 自身是 Direct 时原样返回 (实体 provider 快路径, 零开销一跳).
    ///
    /// 错误消息只含 provider id 与 reason 枚举 (SEC-2 同型, 无 secret),
    /// 经 `AppError::Unavailable` 原样回传客户端 503 body.
    pub fn resolve_route(&self, entry: Provider) -> Result<ResolvedRoute, RouteError> {
        let mut cur = entry;
        let mut visited = HashSet::from([cur.id.clone()]);
        let mut model_override = cur.model_override.clone();
        loop {
            match cur.kind {
                // 链尾 (或入口即实体): 返回. `id` 一并带出 (DirectProvider 不持有 id,
                // downstream 的 CallEvent.upstream_id 需要).
                ProviderKind::Direct(direct) => {
                    return Ok(ResolvedRoute {
                        id: cur.id,
                        provider: direct,
                        model_override,
                    });
                }
                ProviderKind::Virtual(virtual_) => {
                    let next = self
                        .get_effective(&virtual_.route_to)
                        .ok_or_else(|| RouteError::Missing(virtual_.route_to.clone()))?;
                    if !next.enabled {
                        return Err(RouteError::Disabled(next.id.clone()));
                    }
                    if !visited.insert(next.id.clone()) {
                        return Err(RouteError::Cycle(next.id));
                    }
                    if model_override.is_none() {
                        model_override = next.model_override.clone();
                    }
                    cur = next;
                }
            }
        }
    }

    /// upsert 前校验: 写入 `entry` 后 route_to 链是否会成环 (WebUI 侧拒绝, 400).
    ///
    /// 用 effective 视图构造 id → route_to 映射, 用 entry 的新值覆盖其 id 后从
    /// entry 起步走链 (与 `resolve_route` 同一走链语义); 目标不在映射中 (悬空 /
    /// decision-disabled) 视为链断 — **不算环** (悬空写入放行以保证创建顺序无关,
    /// 运行时由 `resolve_route` 503 兜底).
    ///
    /// 并发写入的 TOCTOU 窗口 (检查与 upsert 非同一临界区): 两个并发 PUT 交错可让
    /// 环落库 — 单用户本地工具的可接受假设 (与 update_provider 的 #157 TOCTOU 声明
    /// 一致), 漏网环由 `resolve_route` visited-set 兜底为 503.
    pub fn would_cycle(&self, entry: &Provider) -> bool {
        // 检查图: id → route_to (Virtual 构造的目标; Direct 为 None = 链终止).
        let mut hops: HashMap<String, Option<String>> = self
            .effective_snapshot()
            .into_iter()
            .map(|e| {
                let target = match &e.kind {
                    EffectiveProviderKind::Virtual { route_to, .. } => Some(route_to.clone()),
                    EffectiveProviderKind::Direct { .. } => None,
                };
                (e.id.clone(), target)
            })
            .collect();
        let entry_target = match &entry.kind {
            ProviderKind::Virtual(v) => Some(v.route_to.clone()),
            ProviderKind::Direct(..) => None,
        };
        hops.insert(entry.id.clone(), entry_target.clone());
        let mut visited = HashSet::from([entry.id.clone()]);
        let mut cur = entry_target;
        while let Some(id) = cur {
            if !visited.insert(id.clone()) {
                return true;
            }
            cur = match hops.get(&id) {
                Some(r) => r.clone(),
                None => return false, // 悬空: 链断, 无环.
            };
        }
        false
    }
}

/// 虚拟 provider 路由解析错误 (`resolve_route`). Display 消息进 503 body,
/// 只含 provider id 与 reason (SEC-2 同型).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    /// 链上一跳在 effective 视图中不存在 (目标缺失, 或被 decision=Disabled 排除).
    Missing(String),
    /// 链上一跳 entry-level enabled=false.
    Disabled(String),
    /// 链上出现环 (含自环). 字段 = 环回到的 provider id.
    Cycle(String),
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteError::Missing(id) => {
                write!(
                    f,
                    "route target '{id}' not found (missing or disabled by decision)"
                )
            }
            RouteError::Disabled(id) => write!(f, "route target '{id}' is disabled"),
            RouteError::Cycle(id) => write!(f, "route cycle detected at '{id}'"),
        }
    }
}

impl std::error::Error for RouteError {}

/// 路由解析结果 (#179/#183): 链尾实体 provider + 链上生效的 model_override.
///
/// `model_override` = 沿链 first-wins 收集的非空值 (全链未配置 → None, 即透传).
#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    /// 链尾实体 provider 的 id (非虚拟请求即入口 id; CallEvent.upstream_id 用).
    pub id: String,
    /// 链尾实体 provider — **类型上保证是 Direct** (转发链只处理实体, #187).
    pub provider: DirectProvider,
    /// 链上生效的 model_override (first-wins; None = 客户端 model 透传).
    pub model_override: Option<String>,
}

/// 给定 (static_ver, dynamic_ver, mode), 计算 effective provider 的合并视图.
/// 若 Disabled 或三者皆空, 返回 None.
///
/// #157: 用 `pick_with_inherit` (与 `get_effective` 同一收口) — override 未记录
/// 鉴权字段时从 static 继承, 保证 WebUI 视图 (masked / length) 与路由层行为一致.
fn compute_effective_provider(
    static_ver: Option<Provider>,
    dynamic_ver: Option<Provider>,
    mode: OverrideMode,
) -> Option<EffectiveProvider> {
    let raw = pick_with_inherit(static_ver.clone(), dynamic_ver.clone(), mode)?;
    let source = classify_source(static_ver.is_some(), dynamic_ver.is_some(), mode)
        .expect("pick (with inherit) Some ⇒ classify_source Some");
    // kind 派生: 复用 ProviderMasked 的脱敏映射 (同一映射逻辑, SSOT).
    let ProviderMasked {
        id,
        name,
        enabled,
        model_override,
        kind,
    } = ProviderMasked::from(raw);
    let static_masked = static_ver.map(ProviderMasked::from);
    let dynamic_masked = dynamic_ver.map(ProviderMasked::from);
    Some(EffectiveProvider {
        id,
        enabled,
        name,
        model_override,
        kind,
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
            enabled: true,
            name: Some(format!("name-{id}")),
            model_override: None,
            kind: ProviderKind::Direct(DirectProvider {
                protocol: proto,
                base_url: base.into(),
                api_key: format!("k-{id}"),
                api_key_file: None,
            }),
        }
    }

    /// 虚拟 provider (route_to = target). protocol 默认 Some(OpenAI) 模拟旧格式
    /// (平铺 wire 必有 protocol, 读入的 Virtual 总携带).
    fn v(id: &str, target: &str) -> Provider {
        Provider {
            kind: ProviderKind::Virtual(VirtualProvider {
                route_to: target.into(),
                protocol: Some(Protocol::OpenAI),
            }),
            ..p(id, Protocol::OpenAI, "")
        }
    }

    /// 取 Provider 的 Direct 负载 (测试断言用; panic 表明构造不是 Direct).
    fn direct(p: &Provider) -> &DirectProvider {
        match &p.kind {
            ProviderKind::Direct(d) => d,
            ProviderKind::Virtual(_) => panic!("expected Direct provider"),
        }
    }

    /// 可变取 Direct 负载 (测试改造用).
    fn direct_mut(p: &mut Provider) -> &mut DirectProvider {
        match &mut p.kind {
            ProviderKind::Direct(d) => d,
            ProviderKind::Virtual(_) => panic!("expected Direct provider"),
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
        let ProviderKind::Direct(d) = &p.kind else {
            panic!("legacy direct provider must parse as Direct");
        };
        assert_eq!(
            d.api_key_file.as_deref(),
            Some(std::path::Path::new("/run/secrets/test-key"))
        );
        assert_eq!(d.api_key, ""); // 默认值
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
        let ProviderKind::Direct(d) = &p.kind else {
            panic!("legacy direct provider must parse as Direct");
        };
        assert_eq!(d.api_key, "sk-legacy");
        assert!(d.api_key_file.is_none());
    }

    // ─── DynamicEntry impl: Provider 特有的 validate 钩子 ───────────────

    #[test]
    fn validate_rejects_bad_id_and_base_url() {
        // id 校验失败.
        let bad_id = Provider {
            id: "has space".into(),
            enabled: true,
            name: None,
            model_override: None,
            kind: ProviderKind::Direct(DirectProvider {
                protocol: Protocol::OpenAI,
                base_url: "https://x".into(),
                api_key: String::new(),
                api_key_file: None,
            }),
        };
        assert!(bad_id.validate().is_err());

        // base_url 校验失败.
        let bad_url = Provider {
            id: "x".into(),
            enabled: true,
            name: None,
            model_override: None,
            kind: ProviderKind::Direct(DirectProvider {
                protocol: Protocol::OpenAI,
                base_url: "not-a-url".into(),
                api_key: String::new(),
                api_key_file: None,
            }),
        };
        assert!(bad_url.validate().is_err());

        // 合法 provider 通过.
        assert!(p("ok", Protocol::OpenAI, "https://x").validate().is_ok());
    }

    #[test]
    fn validate_rejects_api_key_and_file_both_set() {
        let both = Provider {
            id: "x".into(),
            enabled: true,
            name: None,
            model_override: None,
            kind: ProviderKind::Direct(DirectProvider {
                protocol: Protocol::OpenAI,
                base_url: "https://x".into(),
                api_key: "sk-direct".into(),
                api_key_file: Some(PathBuf::from("/run/secrets/whatever")),
            }),
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
            enabled: true,
            name: None,
            model_override: None,
            kind: ProviderKind::Direct(DirectProvider {
                protocol: Protocol::OpenAI,
                base_url: "https://x".into(),
                api_key: "sk-direct".into(),
                api_key_file: None,
            }),
        };
        assert_eq!(direct(&p).effective_api_key("x"), "sk-direct");
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
            enabled: true,
            name: None,
            model_override: None,
            kind: ProviderKind::Direct(DirectProvider {
                protocol: Protocol::OpenAI,
                base_url: "https://x".into(),
                api_key: String::new(),
                api_key_file: Some(tmp.clone()),
            }),
        };
        assert_eq!(direct(&p).effective_api_key("x"), "sk-from-file");

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn effective_api_key_missing_file_returns_empty() {
        // 单 provider 配置错误不应拖垮整个进程 — 返回空让 apply_provider_auth 跳过.
        let p = Provider {
            id: "x".into(),
            enabled: true,
            name: None,
            model_override: None,
            kind: ProviderKind::Direct(DirectProvider {
                protocol: Protocol::OpenAI,
                base_url: "https://x".into(),
                api_key: String::new(),
                api_key_file: Some(PathBuf::from("/nonexistent/path/should/not/exist")),
            }),
        };
        assert_eq!(direct(&p).effective_api_key("x"), "");
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
            enabled: true,
            name: None,
            model_override: None,
            kind: ProviderKind::Direct(DirectProvider {
                protocol: Protocol::OpenAI,
                base_url: "https://x".into(),
                api_key: String::new(),
                api_key_file: Some(tmp.clone()),
            }),
        };

        // 1. 文件不存在 → 空 + WARNED 被插入 (首次失败).
        assert_eq!(direct(&make_provider()).effective_api_key(&pid), "");
        assert!(
            WARNED_API_KEY_FILE.lock().contains(&pid),
            "first failure must record provider in WARNED set"
        );

        // 2. 创建文件 → 读到内容 + WARNED 被清除 (恢复路径).
        std::fs::write(&tmp, "sk-recovered\n").unwrap();
        assert_eq!(
            direct(&make_provider()).effective_api_key(&pid),
            "sk-recovered"
        );
        assert!(
            WARNED_API_KEY_FILE.lock().get(&pid).is_none(),
            "recovery must clear WARNED record so next failure re-warns"
        );

        // 3. 再次删除文件 → 仍能正确返回空 + 重新插入 WARNED (状态机可循环).
        std::fs::remove_file(&tmp).unwrap();
        assert_eq!(direct(&make_provider()).effective_api_key(&pid), "");
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
            enabled: true,
            name: None,
            model_override: None,
            kind: ProviderKind::Direct(DirectProvider {
                protocol: Protocol::OpenAI,
                base_url: "https://x".into(),
                api_key: String::new(),
                api_key_file: Some(PathBuf::from("/nonexistent/warn-once-test")),
            }),
        };
        assert_eq!(direct(&p).effective_api_key(&pid), "");
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
            enabled: true,
            name: None,
            model_override: None,
            kind: ProviderKind::Direct(DirectProvider {
                protocol: Protocol::OpenAI,
                base_url: "https://x".into(),
                api_key: String::new(),
                api_key_file: None,
            }),
        };
        assert_eq!(direct(&p).effective_api_key("x"), "");
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
        let EffectiveProviderKind::Direct {
            api_key_masked,
            api_key_length,
            ..
        } = &s.kind
        else {
            panic!("static-only must be Direct");
        };
        assert_ne!(api_key_masked, "k-static-only");
        assert_eq!(*api_key_length, "k-static-only".chars().count());

        let d = by_id.get("dynamic-only").unwrap();
        assert_eq!(d.source, EffectiveSource::Dynamic);
        assert!(d.static_version.is_none());

        let ov = by_id.get("override-id").unwrap();
        assert_eq!(ov.source, EffectiveSource::DynamicOverride);
        let EffectiveProviderKind::Direct { base_url, .. } = &ov.kind else {
            panic!("override-id must be Direct");
        };
        assert_eq!(base_url, "https://dynamic-override");
        assert!(ov.static_version.is_some());
        assert!(ov.dynamic_version.is_some());
    }

    // ─── inherit_from_static (#157): override 未记录鉴权字段时回落 static ──
    //
    // 语义: PUT api_key=null (保留旧值) 的 override 不落盘明文, effective 解析时
    // 从 static 继承. 三条边界: 均未记录 → 继承; 有任一显式记录 → 不继承;
    // get_effective 仅在 Default 模式下继承 (PreferStatic 选中的是 static 本身).

    #[test]
    fn inherit_from_static_fills_unrecorded_auth_fields() {
        let mut s = p("x", Protocol::OpenAI, "https://s");
        direct_mut(&mut s).api_key = "sk-static".into();
        let mut d = p("x", Protocol::OpenAI, "https://d");
        direct_mut(&mut d).api_key = String::new();
        direct_mut(&mut d).api_key_file = None;
        d.inherit_from_static(&s);
        assert_eq!(direct(&d).api_key, "sk-static");
        assert_eq!(
            direct(&d).base_url,
            "https://d",
            "non-auth fields must stay from override"
        );
    }

    #[test]
    fn inherit_from_static_skips_when_override_records_auth() {
        let mut s = p("x", Protocol::OpenAI, "https://s");
        direct_mut(&mut s).api_key = "sk-static".into();

        // override 显式记录了 api_key → 不继承.
        let mut d1 = p("x", Protocol::OpenAI, "https://d");
        direct_mut(&mut d1).api_key = "sk-dyn".into();
        d1.inherit_from_static(&s);
        assert_eq!(direct(&d1).api_key, "sk-dyn");

        // override 显式记录了 api_key_file → 不继承 (含 static 的 api_key).
        let mut d2 = p("x", Protocol::OpenAI, "https://d");
        direct_mut(&mut d2).api_key = String::new();
        direct_mut(&mut d2).api_key_file = Some(PathBuf::from("/run/secrets/k"));
        d2.inherit_from_static(&s);
        assert_eq!(direct(&d2).api_key, "");
        assert_eq!(
            direct(&d2).api_key_file,
            Some(PathBuf::from("/run/secrets/k"))
        );
    }

    #[test]
    fn get_effective_inherits_unrecorded_api_key_from_static() {
        let tmp = tempfile_path();
        let mut s = p("x", Protocol::OpenAI, "https://s");
        direct_mut(&mut s).api_key = "sk-static".into();
        let mut d = p("x", Protocol::OpenAI, "https://d");
        direct_mut(&mut d).api_key = String::new(); // override 未记录 key (#157: 不落盘明文)
        let t = ProviderTable::new(vec![s], vec![d], empty_decisions(), tmp);

        // Default: dynamic 被选中 + 未记录 key → effective 从 static 继承.
        let eff = t.get_effective("x").unwrap();
        assert_eq!(direct(&eff).base_url, "https://d");
        assert_eq!(direct(&eff).api_key, "sk-static");

        // PreferStatic: static 本身被选中, 继承无意义但也无害.
        t.set_decision("x", OverrideMode::PreferStatic).unwrap();
        let eff = t.get_effective("x").unwrap();
        assert_eq!(direct(&eff).base_url, "https://s");
        assert_eq!(direct(&eff).api_key, "sk-static");

        // Disabled: 不存在 effective.
        t.set_decision("x", OverrideMode::Disabled).unwrap();
        assert!(t.get_effective("x").is_none());
    }

    #[test]
    fn effective_snapshot_reflects_inherited_api_key() {
        // WebUI 视图与路由层行为一致 (#157): 继承后的 masked/length 也要反映 static key.
        let tmp = tempfile_path();
        let mut s = p("x", Protocol::OpenAI, "https://s");
        direct_mut(&mut s).api_key = "sk-static-key".into();
        let mut d = p("x", Protocol::OpenAI, "https://d");
        direct_mut(&mut d).api_key = String::new();
        let t = ProviderTable::new(vec![s], vec![d], empty_decisions(), tmp);
        let snap = t.effective_snapshot();
        assert_eq!(snap.len(), 1);
        let eff_len = match &snap[0].kind {
            EffectiveProviderKind::Direct { api_key_length, .. } => *api_key_length,
            _ => panic!("must be Direct"),
        };
        assert_eq!(eff_len, "sk-static-key".chars().count());
        // dynamic_version 的 masked 仍显示 override 自身 (空) — 派生视图分离, 不混入.
        let dyn_len = match &snap[0].dynamic_version.as_ref().unwrap().kind {
            EffectiveProviderKind::Direct { api_key_length, .. } => *api_key_length,
            _ => panic!("must be Direct"),
        };
        assert_eq!(dyn_len, 0);
    }

    // ─── 虚拟 provider 路由 (#179): resolve_route / would_cycle / validate ──
    //
    // 契约: FWD-5 (per-request 解析 / 坏路由 503 / 环终止).

    /// 表: real → mock 上游; v1 → v2 → real (两跳链).
    fn route_table() -> ProviderTable {
        let mut real = p("real", Protocol::OpenAI, "https://upstream");
        direct_mut(&mut real).api_key = "sk-real".into();
        let v2 = v("v2", "real");
        let v1 = v("v1", "v2");
        ProviderTable::new(
            vec![real, v2, v1],
            vec![],
            empty_decisions(),
            tempfile_path(),
        )
    }

    #[test]
    fn resolve_route_real_provider_passthrough() {
        // 实体 provider (route_to=None) 原样返回, 零额外跳.
        let t = route_table();
        let real = t.get_effective("real").unwrap();
        let out = t.resolve_route(real.clone()).unwrap();
        assert_eq!(out.id, "real");
        assert_eq!(out.provider.base_url, "https://upstream");
        assert_eq!(
            out.provider.api_key, "sk-real",
            "resolved provider carries real key"
        );
    }

    #[test]
    fn resolve_route_follows_chain_to_real_provider() {
        // v1 → v2 → real: 解析到链尾实体, 携带其实体字段 (base_url/api_key).
        let t = route_table();
        let v1 = t.get_effective("v1").unwrap();
        let out = t.resolve_route(v1).unwrap();
        assert_eq!(out.id, "real");
        assert_eq!(out.provider.base_url, "https://upstream");
        assert_eq!(out.provider.api_key, "sk-real");
    }

    #[test]
    fn resolve_route_missing_target() {
        let t = ProviderTable::new(
            vec![v("v", "ghost")],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let err = t.resolve_route(t.get_effective("v").unwrap()).unwrap_err();
        assert_eq!(err, RouteError::Missing("ghost".into()));
        assert!(err.to_string().contains("ghost"), "msg names the id: {err}");
    }

    #[test]
    fn resolve_route_disabled_target() {
        let mut real = p("real", Protocol::OpenAI, "https://u");
        real.enabled = false;
        let t = ProviderTable::new(
            vec![real, v("v", "real")],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        // 入口 provider 自身 disabled 在 dispatch 层已挡 (503); 这里测链上中间跳.
        let err = t.resolve_route(t.get_effective("v").unwrap()).unwrap_err();
        assert_eq!(err, RouteError::Disabled("real".into()));
    }

    #[test]
    fn resolve_route_detects_cycles() {
        // 双节点环 (绕过 validate 直接构造 — 模拟手改 state.toml 的运行时兜底场景).
        let t = ProviderTable::new(
            vec![v("a", "b"), v("b", "a")],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let err = t.resolve_route(t.get_effective("a").unwrap()).unwrap_err();
        assert_eq!(err, RouteError::Cycle("a".into()));

        // 自环 (单节点).
        let t2 = ProviderTable::new(
            vec![v("s", "s")],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        assert!(matches!(
            t2.resolve_route(t2.get_effective("s").unwrap()),
            Err(RouteError::Cycle(_))
        ));
    }

    #[test]
    fn would_cycle_rejects_indirect_cycle() {
        // 已有 a → b; upsert b.route_to = a 形成环 → 必须拒绝.
        let t = ProviderTable::new(
            vec![
                v("a", "b"),
                v("b", "real"),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let b_to_a = v("b", "a");
        assert!(t.would_cycle(&b_to_a), "b→a closes the a→b cycle");
        // b → real (现状) 与 b → 悬空 都不成环.
        assert!(!t.would_cycle(&v("b", "real")));
        assert!(!t.would_cycle(&v("b", "ghost")));
        // 自环.
        assert!(t.would_cycle(&v("b", "b")));
    }

    #[test]
    fn would_cycle_updates_entry_in_place() {
        // upsert 替换已有条目: 表中 b → a 已有, 现在写入 a → b 也要识别为环
        // (walk 必须用新 entry 值覆盖旧值, 而非读到旧 a 的 route_to=None 而漏判).
        let t = ProviderTable::new(
            vec![
                v("a", "real"),
                v("b", "a"),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let a_to_b = v("a", "b");
        assert!(t.would_cycle(&a_to_b), "a→b closes the existing b→a cycle");
    }

    #[test]
    fn validate_virtual_provider_semantics() {
        // 虚拟: 允许空 base_url; 目标 id 必须合法; 自环拒绝.
        assert!(v("v", "real").validate().is_ok());
        let bad_target = v("v", "has space");
        assert!(bad_target.validate().is_err());
        let self_loop = v("v", "v");
        let err = self_loop.validate().unwrap_err();
        assert!(err.contains("routes to itself"), "got: {err}");
        // 实体: 空 base_url 仍然拒绝 (现有行为不变).
        let real = p("r", Protocol::OpenAI, "");
        assert!(real.validate().is_err());
    }

    #[test]
    fn toml_route_to_roundtrip_and_default() {
        // 缺省字段 (既有配置) → None; 显式 route_to → Some.
        let legacy = r#"
            id = "test"
            protocol = "openai"
            base_url = "https://api.example.com"
        "#;
        let p: Provider = toml::from_str(legacy).expect("legacy parse");
        assert!(matches!(p.kind, ProviderKind::Direct(_)));

        let virtual_toml = r#"
            id = "my-virtual"
            protocol = "openai"
            route_to = "openai-main"
        "#;
        let p: Provider = toml::from_str(virtual_toml).expect("virtual parse");
        let ProviderKind::Virtual(v) = &p.kind else {
            panic!("route_to present must parse as Virtual");
        };
        assert_eq!(v.route_to, "openai-main");
        assert_eq!(v.protocol, Some(Protocol::OpenAI));
        assert!(p.validate().is_ok());
    }

    #[test]
    fn direct_override_replaces_static_virtual() {
        // #187 根治: static 虚拟 + Direct override = **改回实体** — 跨型不继承,
        // route_to 无 None 歧义 (#179 时代的 "无法改回实体" 限制由类型系统消灭).
        let tmp = tempfile_path();
        let mut d = p("x", Protocol::OpenAI, "https://d");
        direct_mut(&mut d).api_key = "sk-dyn".into();
        let t = ProviderTable::new(
            vec![v("x", "real"), p("real", Protocol::OpenAI, "https://u")],
            vec![d],
            empty_decisions(),
            tmp,
        );
        let eff = t.get_effective("x").unwrap();
        assert!(matches!(eff.kind, ProviderKind::Direct(_)));
        // 路由解析直达自身 (实体快路径), 携带 override 的鉴权字段.
        let r = t.resolve_route(eff).unwrap();
        assert_eq!(r.id, "x");
        assert_eq!(r.provider.base_url, "https://d");
        assert_eq!(r.provider.api_key, "sk-dyn");
    }

    #[test]
    fn static_direct_key_survives_virtual_excursion() {
        // 互补链 (#187): static Direct → Virtual override → 再 Direct override —
        // 第二次 override 的 api_key 未记录 → Direct↔Direct 继承从 static 复原.
        // (dynamic-only 条目无此复原来源, 是 AGENTS.md 登记的已知限制.)
        let tmp = tempfile_path();
        let mut s = p("x", Protocol::OpenAI, "https://s");
        direct_mut(&mut s).api_key = "sk-static".into();
        // 第一步: Virtual override (切换为虚拟).
        let t1 = ProviderTable::new(
            vec![s.clone(), p("real", Protocol::OpenAI, "https://u")],
            vec![v("x", "real")],
            empty_decisions(),
            tempfile_path(),
        );
        assert!(matches!(
            t1.get_effective("x").unwrap().kind,
            ProviderKind::Virtual(_)
        ));
        // 第二步: 再切回 Direct override, api_key 未记录 (PUT null 语义).
        let mut back = p("x", Protocol::OpenAI, "https://d");
        direct_mut(&mut back).api_key = String::new();
        let t2 = ProviderTable::new(vec![s], vec![back], empty_decisions(), tmp);
        let eff = t2.get_effective("x").unwrap();
        // Direct override 胜出 + key 从 static Direct 继承复原.
        assert_eq!(direct(&eff).base_url, "https://d");
        assert_eq!(direct(&eff).api_key, "sk-static");
    }

    #[test]
    fn prefer_static_decision_uses_static_route() {
        // static 虚拟 (→ real1) + dynamic override (→ real2) + PreferStatic:
        // 整条回 static, 路由随之 — decision 与 route 的组合不产生第三种语义.
        let tmp = tempfile_path();
        let t = ProviderTable::new(
            vec![
                v("x", "real1"),
                p("real1", Protocol::OpenAI, "https://u1"),
                p("real2", Protocol::OpenAI, "https://u2"),
            ],
            vec![v("x", "real2")],
            empty_decisions(),
            tmp,
        );

        // Default: override 生效 → real2.
        assert!(matches!(
            &t.get_effective("x").unwrap().kind,
            ProviderKind::Virtual(v) if v.route_to == "real2"
        ));
        // PreferStatic: static 整条生效 → real1 (inherit 对 static 自身是 no-op).
        t.set_decision("x", OverrideMode::PreferStatic).unwrap();
        let eff = t.get_effective("x").unwrap();
        assert!(matches!(
            &eff.kind,
            ProviderKind::Virtual(v) if v.route_to == "real1"
        ));
        assert_eq!(t.resolve_route(eff).unwrap().id, "real1");
    }

    #[test]
    fn resolve_route_target_disabled_by_decision_reports_missing() {
        // decision=Disabled 的目标不在 effective 视图 → Missing (message 提示
        // "disabled by decision", 与 entry-level disabled 区分).
        let tmp = tempfile_path();
        let t = ProviderTable::new(
            vec![v("v", "real"), p("real", Protocol::OpenAI, "https://u")],
            vec![],
            empty_decisions(),
            tmp,
        );
        t.set_decision("real", OverrideMode::Disabled).unwrap();
        let err = t.resolve_route(t.get_effective("v").unwrap()).unwrap_err();
        assert_eq!(err, RouteError::Missing("real".into()));
        assert!(err.to_string().contains("disabled by decision"));
    }

    // ─── model_override (#183, FWD-5 first-wins / FWD-1 修订) ──────────────

    /// 表: entry(override=A) → mid(override=B) → real(override=C). 三层全配.
    fn override_chain() -> ProviderTable {
        let mut entry = v("entry", "mid");
        entry.model_override = Some("model-A".into());
        let mut mid = v("mid", "real");
        mid.model_override = Some("model-B".into());
        let mut real = p("real", Protocol::OpenAI, "https://u");
        real.model_override = Some("model-C".into());
        ProviderTable::new(
            vec![entry, mid, real],
            vec![],
            empty_decisions(),
            tempfile_path(),
        )
    }

    #[test]
    fn resolve_route_model_override_first_hop_wins() {
        // FWD-5 prop_model_override_first_hop_wins: 沿链从入口起第一个非空值生效.
        let t = override_chain();
        // 三层全配 → 入口的 A 胜.
        let r = t.resolve_route(t.get_effective("entry").unwrap()).unwrap();
        assert_eq!(r.model_override.as_deref(), Some("model-A"));
        assert_eq!(r.id, "real");

        // 中间层直连 (跳过 entry) → B 胜.
        let r = t.resolve_route(t.get_effective("mid").unwrap()).unwrap();
        assert_eq!(r.model_override.as_deref(), Some("model-B"));

        // 链尾直连 → C 胜 (实体级 "channel 强制模型" 用法).
        let r = t.resolve_route(t.get_effective("real").unwrap()).unwrap();
        assert_eq!(r.model_override.as_deref(), Some("model-C"));
    }

    #[test]
    fn resolve_route_model_override_skips_unconfigured_hops() {
        // 入口/中间跳均未配 → 链尾实体的 override 生效; 全链未配 → None (透传).
        // 直接构造目标形状 (三层链, 仅链尾配 C)。
        let mut entry = v("entry", "mid");
        entry.model_override = None;
        let mut mid = v("mid", "real");
        mid.model_override = None;
        let mut real = p("real", Protocol::OpenAI, "https://u");
        real.model_override = Some("model-C".into());
        let t = ProviderTable::new(
            vec![entry, mid, real],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let r = t.resolve_route(t.get_effective("entry").unwrap()).unwrap();
        assert_eq!(r.model_override.as_deref(), Some("model-C"));
        // 全链未配 → None (透传).
        let none_table = ProviderTable::new(
            vec![v("e", "r"), p("r", Protocol::OpenAI, "https://u")],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let r = none_table
            .resolve_route(none_table.get_effective("e").unwrap())
            .unwrap();
        assert_eq!(r.model_override, None);
    }

    #[test]
    fn inherit_from_static_covers_model_override() {
        // static 配了 override + override 未记录 → 继承 (三层读路径一致).
        let tmp = tempfile_path();
        let mut s = p("x", Protocol::OpenAI, "https://s");
        s.model_override = Some("m-static".into());
        let mut d = p("x", Protocol::OpenAI, "https://d");
        d.model_override = None;
        let t = ProviderTable::new(vec![s], vec![d], empty_decisions(), tmp);
        assert_eq!(
            t.get_effective("x").unwrap().model_override.as_deref(),
            Some("m-static")
        );
        let x = t.effective_snapshot().into_iter().next().unwrap();
        assert_eq!(x.model_override.as_deref(), Some("m-static"));
    }

    #[test]
    fn validate_rejects_empty_model_override() {
        let mut bad = p("x", Protocol::OpenAI, "https://u");
        bad.model_override = Some(String::new());
        let err = bad.validate().unwrap_err();
        assert!(err.contains("empty model_override"), "got: {err}");
        // 纯空白 / 超长同样拒绝 (输入卫生, 对齐 id/name 纪律).
        let mut ws = p("x", Protocol::OpenAI, "https://u");
        ws.model_override = Some("   ".into());
        assert!(ws.validate().is_err());
        let mut long = p("x", Protocol::OpenAI, "https://u");
        long.model_override = Some("m".repeat(129));
        assert!(long.validate().is_err());
        // 省略 (None) / 非空均合法.
        assert!(p("x", Protocol::OpenAI, "https://u").validate().is_ok());
        let mut ok = p("y", Protocol::OpenAI, "https://u");
        ok.model_override = Some("claude-sonnet-4".into());
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn resolve_route_model_override_static_middle_hop_inherits() {
        // L5: 继承 × first-wins 交互 — static 中间跳配了 override, dynamic override
        // 未记录 → get_effective 展开后参与链上收集.
        let tmp = tempfile_path();
        let mut mid_static = v("mid", "real");
        mid_static.model_override = Some("m-mid".into());
        let t = ProviderTable::new(
            vec![mid_static, p("real", Protocol::OpenAI, "https://u")],
            vec![v("mid", "real")], // dynamic override 未记录 model_override
            empty_decisions(),
            tmp,
        );
        let mut entry = v("entry", "mid"); // 入口未配
        entry.model_override = None;
        let r = t.resolve_route(entry).unwrap();
        // mid 的 effective override 从 static 继承 m-mid → 链上第一个非空.
        assert_eq!(r.model_override.as_deref(), Some("m-mid"));
    }

    #[test]
    fn toml_model_override_roundtrip_and_default() {
        // 缺省 → None; 显式 → Some.
        let legacy = r#"
            id = "test"
            protocol = "openai"
            base_url = "https://api.example.com"
        "#;
        let p: Provider = toml::from_str(legacy).expect("legacy parse");
        assert!(p.model_override.is_none());

        let with_override = r#"
            id = "my-model"
            protocol = "openai"
            route_to = "openai-main"
            model_override = "gpt-4o-mini"
        "#;
        let p: Provider = toml::from_str(with_override).expect("parse");
        assert_eq!(p.model_override.as_deref(), Some("gpt-4o-mini"));
        assert!(p.validate().is_ok());

        // 空串在 static 加载即 fail-fast (validate 拒绝).
        let empty_str = r#"
            id = "bad"
            protocol = "openai"
            base_url = "https://u"
            model_override = ""
        "#;
        let p: Provider = toml::from_str(empty_str).expect("parse");
        assert!(p.validate().is_err());
    }

    // FWD-5 环终止 property: 任意 route 图 (含环), `resolve_route` 有限步返回
    // (Ok ⇒ 链尾必为实体 provider, route_to=None; Err ⇒ 明确错误类别).
    // 历史教训 (生成器覆盖度): 图必须包含环与悬空, 否则 property 退化为恒真.
    // 生成器: p{i} 的 route_to 由 edges.get(i) 决定 — 无边 → 实体, 目标 < n →
    // 指向表内 (可成环/自环), 目标 ≥ n → 悬空 (ghost).
    proptest::proptest! {
        #[test]
        fn prop_resolve_route_terminates_on_random_graphs(
            n in 2usize..8,
            edges in proptest::collection::vec(0usize..8, 0..16),
        ) {
            // n 个 provider: id = p0..p{n-1}; edges[i] 决定 p{i % n} 的 route_to
            // (目标均匀取 0..8 → 覆盖存在/缺失/自环/成环).
            let ids: Vec<String> = (0..n).map(|i| format!("p{i}")).collect();
            let entries: Vec<Provider> = (0..n)
                .map(|i| match edges.get(i) {
                    Some(&t) if t < n => v(&ids[i], &ids[t]),
                    Some(&t) => v(&ids[i], &format!("ghost-{t}")), // 悬空
                    None => p(&ids[i], Protocol::OpenAI, "https://u"), // 实体
                })
                .collect();
            let t = ProviderTable::new(entries, vec![], empty_decisions(), tempfile_path());
            for id in &ids {
                if let Some(entry) = t.get_effective(id) {
                    // Err 分支 = 有限步返回明确错误 (同样满足终止性), 无需断言.
                    // Ok ⇒ 链尾必为 Direct (类型保证, 无需运行时断言); 有限步返回即满足终止性.
                    let _ = t.resolve_route(entry);
                }
            }
        }
    }
}
