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

    /// 该协议族是否有完整 codec 覆盖 (Reader/Writer/IR 路径可用 — Redact 与跨协议
    /// 翻译都依赖 codec; 模型列表解析与之正交, 全 5 族均支持). Gemini/Ollama 目前
    /// 仅字节透传、无 codec, Redact 在这两族上不可用 (默认
    /// `on_unsupported_protocol = "fail_closed"` 拒绝). 消费方: WebUI 新建 provider
    /// 的协议词表只引导 codec 覆盖族 (`webui_protocols`, 见 `web/api/providers.rs`);
    /// 透传族仍可手写配置文件使用 (实验性, 见 README "协议支持").
    /// 与 `codec::Protocol::from_native` 的 Some 集合同一事实两处编码, 同步守卫
    /// 测试见 `tests::test_codec_covered_matches_codec_from_native`.
    pub const fn codec_covered(self) -> bool {
        matches!(self, Self::OpenAI | Self::Anthropic | Self::OpenAIResponses)
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

/// 单个 provider 实例 — **sum type** (#187): 直连上游 (`Direct`) 或路由
/// (`Router`) 两种构造, 配置项完全不同, 非法状态不可表示 (Router 根本没有
/// endpoints/api_key 字段)。
///
/// 共享字段: `id` / `name` / `enabled` (两种构造都可配)。出站 model 重写不再是
/// provider 级字段 — 由 [`Route::upstream_model`] 承载 (路由命中即改写, #183 语义被
/// 路由吸收)。
///
/// serde: `kind` 字段为 internally tagged (`kind = "direct"/"router"`), variant
/// 字段平铺在同一层 — 磁盘 TOML / state.toml / EffectiveProvider JSON 共用同一
/// 形态 (SSOT):
///
/// ```toml
/// [[providers]]
/// id = "openai-main"
/// kind = "direct"
/// [[providers.endpoints]]
/// protocol = "openai"
/// base_url = "https://api.openai.com"
///
/// # 多协议端点 (单条目多端点, 共享 api_key):
/// # [[providers]]
/// # id = "zhipu"
/// # kind = "direct"
/// # api_key = "sk-..."
/// # [[providers.endpoints]]
/// # protocol = "openai"
/// # base_url = "https://open.bigmodel.cn/api/paas/v4"
/// # [[providers.endpoints]]
/// # protocol = "anthropic"
/// # base_url = "https://open.bigmodel.cn/api/anthropic"
///
/// [[providers]]
/// id = "router"
/// kind = "router"
/// [[providers.routes]]
/// model_pattern = "gpt-*"
/// target = "openai-main"
/// upstream_model = "gpt-4o"   # 省略此字段 = 透传
/// priority = 100        # 省略此字段 (或 null) = 该路由禁用
/// ```
///
/// 单端点紧凑写法 (endpoints 内联数组): `endpoints = [ { protocol = "openai",
/// base_url = "https://api.openai.com" } ]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    /// 唯一 id (slug). 同一份表 (static 或 dynamic) 中必须唯一.
    pub id: String,
    /// 是否启用. `false` 时转发到该 provider 返回 503.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 可选人类可读名称 (Web UI 显示).
    #[serde(default)]
    pub name: Option<String>,
    /// 构造判别: 直连上游 or 路由 (`kind` tag).
    #[serde(flatten)]
    pub kind: ProviderKind,
}

/// Provider 的构造 (#187 sum type, Pool 延伸). serde internally tagged: `kind` 字段
/// 判别, variant 字段平铺 (见 [`Provider`] 文档的 TOML 示例).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderKind {
    /// 直连上游: 真实 LLM 端点, 承载转发.
    Direct(DirectProvider),
    /// 虚拟 endpoint: 不承载转发, 请求按请求 model 匹配 `routes` 路由链式
    /// 解析到链尾实体 (#179 多规则化).
    Router(RouterProvider),
    /// 套餐池 (pool): 不承载转发, 有序成员列表 (= 一份独立凭证的 Direct
    /// provider) + 耗尽信号配置. 顺序 failover — 正常全打第一个可用成员
    /// (前缀缓存友好), 检测到窗口限额耗尽信号后自动切换下一个, 耗尽成员
    /// 按恢复时刻自动回归. 运行时状态机见 [`crate::pool`].
    Pool(PoolProvider),
}

/// Direct provider 的一个协议端点 (multi-endpoint; 术语见根 AGENTS.md "Endpoint").
///
/// 同一 [`DirectProvider`] 内 [`Endpoint::protocol`] 唯一 (validate 拒绝重复);
/// `base_url` / `common_uri` 语义与旧单端点 schema 的同名字段一致, 但 per-endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Endpoint {
    /// 该端点的协议. 同一 DirectProvider 内 protocol 唯一 (validate 拒绝重复).
    pub protocol: Protocol,
    /// 该端点的上游 base URL, 末尾**不带** `/`. 通过 [`validate_base_url`] 校验.
    pub base_url: String,
    /// 该端点的 secret-guard **自建请求** (fetch_model_list — router /models 本地
    /// 合成拉上游清单) 的公共 URI 前缀, 亦即三段式 `base_url + common_uri +
    /// request_uri` 的中段. **不影响转发** — 转发的 request_uri 随客户端请求
    /// rest 原样流过.
    ///
    /// 值语义: `"/v1"` = 裸根布局 (OpenAI/Anthropic 官方形态, base 不含版本前缀);
    /// `""` = 版本前缀已含布局 (智谱 coding plan / DeepSeek / Moonshot 等国产系,
    /// models 端点 = `base + /models`); `None` (字段缺席) = 未探测, fetch 侧用
    /// 候选序列现场推导 (`proxy::models::V1_COMMON_URIS`).
    ///
    /// 知识来源: WebUI detect 探测 (`POST /api/providers/probe` 响应的
    /// `common_uri`) 自动填充, 随表单保存落盘; 手写 toml 可显式声明. base_url
    /// 变更后此值可能失配 — fetch 侧遇 404 回退候选序列兜底 (WARN), 不静默.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub common_uri: Option<String>,
}

impl Endpoint {
    /// 测试便捷构造 (common_uri = None 未探测形态). 跨模块统一口径
    /// (provider / proxy::models / config 的测试共用), 先例同
    /// `mock::assert_no_c5_substring`.
    #[cfg(test)]
    pub(crate) fn new(protocol: Protocol, base_url: &str) -> Self {
        Self {
            protocol,
            base_url: base_url.into(),
            common_uri: None,
        }
    }
}

/// 直连上游 provider 的构造负载 ([`ProviderKind::Direct`]) — **多协议端点**:
/// 一份共享凭证 (D3) + 有序端点列表. 同一上游的多协议兼容端点 (智谱/Kimi/
/// DeepSeek 的 OpenAI + Anthropic 双端点) 收敛为单条目, 各 ingress 协议按
/// [`DirectProvider::select_endpoint`] 选端点 (精确匹配 → 同协议透传; 无匹配
/// → 首端点跨协议翻译, D2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectProvider {
    /// 有序端点列表. 至少一条, 每协议至多一条 (validate 强制).
    /// 数组序 = fallback 序 (第一条 = 默认端点, ingress 无精确匹配时兜底).
    ///
    /// 合并语义 (§5.6): **整体替换** — dynamic override 携带的 endpoints 整体
    /// 覆盖 static (与 routes/members 的 Vec 整体提交先例一致); 鉴权字段的
    /// #157 继承不触及本字段 (WebUI PUT 全量必填, "保留" 由前端回填后整体提交).
    /// serde default 空 Vec 让 "字段缺席" 落到 validate 的语义化错误
    /// ("at least one endpoint required"), 而非 serde 的 missing field 报错.
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
    /// 共享凭证 (D3: 所有端点共用). 明文存储在本地 config 文件中 (本地进程,
    /// 不通过网络暴露). 与 [`DirectProvider::api_key_file`] 互斥 — 同时设置会在
    /// validate 中报错. skip 空串写出 (无 key 场景如 Ollama, 消 state.toml 噪音;
    /// 读回 default 等价).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub api_key: String,
    /// 可选: 从文件路径读取 api_key (所有端点共享). 优先级低于
    /// [`DirectProvider::api_key`].
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

impl DirectProvider {
    /// 端点选择 (multi-endpoint 语义核心, D2): ingress 精确匹配 → `(该端点, true)`;
    /// 无匹配 → `(第一个端点, false)` — 跨协议翻译 fallback, 单端点配置下自然
    /// 退化为演进前行为. `endpoints` 为空是绕过 validate 的非法配置 → `None`
    /// (dispatch 503, ROB 不 panic).
    ///
    /// 不变式: `exact == true` 时端点协议必等于 ingress, `exact == false` 时必
    /// 不等 — 由 find 谓词结构直接保证 (不命中 ⟹ 全体端点协议 ≠ ingress,
    /// 首端点亦然), 不依赖 validate 的唯一性; 唯一性仅让 "精确匹配" 语义无歧义
    /// (重复协议时命中列表序先者). dispatch 以 `exact` 为 same/cross 分叉判据.
    pub fn select_endpoint(&self, ingress: Protocol) -> Option<(&Endpoint, bool)> {
        self.endpoints
            .iter()
            .find(|e| e.protocol == ingress)
            .map(|e| (e, true))
            .or_else(|| self.endpoints.first().map(|e| (e, false)))
    }
}

/// 虚拟 endpoint (路由表) provider 的构造负载 ([`ProviderKind::Router`]).
///
/// base_url / api_key / api_key_file **在此构造下不存在** (sum type 根治
/// "配置了被忽略" 的非法状态). 路由语义 (per-request 解析 / 坏路由 503 / 环与
/// 悬空处置) 的 SSOT: [`ProviderTable::resolve_route`] +
/// [`ProviderTable::would_cycle`] + [`ProviderTable::find_cycles`] (启动诊断) +
/// FWD-5 契约 (`docs/design/contracts.md`).
///
/// **无 protocol 字段**: router 没有事实意义上的协议 — ingress 由 per-request
/// URL 的 proto_short 决定, egress 由 per-route 链尾实体的 protocol 决定 (混合
/// egress 时单字段装不下, 声明也不产生任何行为约束), 故无可陈述的事实.
/// 展示需求 (转换徽标) 由前端 per-route walk 链尾派生.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterProvider {
    /// 路由列表. 至少一条 (validate 拒绝空表 — 空 routes 的 router 无法
    /// 转发任何请求, 几乎肯定是配置残缺).
    #[serde(default)]
    pub routes: Vec<Route>,
}

/// 一条路由: `model_pattern` 匹配请求 model 时, 把请求路由到 `target`。
///
/// `upstream_model` / `priority` 均可省略: 省略 `upstream_model` = 透传请求原
/// model; 省略 `priority` = 该路由**禁用** (WebUI 的 enabled 开关由 priority
/// null 表达)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    /// model 名通配符. 仅支持 `'*'` 通配 (任意串, 含空), 大小写敏感; 其余字符
    /// 字面匹配. 见 [`wildcard_match`].
    pub model_pattern: String,
    /// 目标 provider id (可指向另一 router, 链式解析).
    pub target: String,
    /// 出站 model 重写值; `None` = 透传请求原 model。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_model: Option<String>,
    /// 优先级, 越大越优先; `None` = 该路由禁用 (不参与匹配与环检查)。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i64>,
}

impl RouterProvider {
    /// 路由选择: **启用** (`priority` 非 None) 且 model_pattern 匹配 `model` 的路由中
    /// `priority` 最大者; 同值并列按**列表出现顺序**先者 (用户认可的确定性
    /// tie-break, 由测试锁定)。
    pub fn select_route<'a>(&'a self, model: &str) -> Option<&'a Route> {
        self.routes
            .iter()
            .filter(|r| r.priority.is_some() && wildcard_match(&r.model_pattern, model))
            // fold 而非 max_by: max_by 取并列最大值的**最后一个**, 与 "列表序
            // 先者胜" 的 tie-break 相反; 此处只有**严格更大**才替换。
            .fold(None, |best: Option<&Route>, r| match best {
                Some(b) if r.priority <= b.priority => best,
                _ => Some(r),
            })
    }
}

// ─── Pool 构造 (套餐池): 类型与默认信号表 ─────────────────────────────────
//
// 默认信号表与类型同域 (serde default 函数天然在此), 语义 SSOT 引用见
// `crate::pool` 头部 ("内置默认信号表" 段). 语义域 = 订阅窗口限额耗尽
// (会自动恢复), 付费/账单类信号一律不进默认 — 用户 opt-in 自行配置.

/// 内置默认 body 码表: 智谱 GLM Coding Plan 窗口限额 (429 + `error.code`
/// = "1308" 5h 窗 / "1310" 周窗配额耗尽, 响应另带 `next_flush_time`).
/// 故意不含瞬态 (1302 并发限流 / 1305 平台过载) 与付费/政策语义
/// (1113 欠费 / 1309 套餐到期 / 1313 公平限流 / 1311 模型未开放) — 见
/// `crate::pool` 头部 "故意不进默认" 清单.
pub const DEFAULT_WINDOW_EXHAUST_CODES: [&str; 2] = ["1308", "1310"];

/// 内置默认 header 表: Anthropic Claude Pro/Max 订阅 (OAuth 流量) 撞窗时
/// 429 + 专属 header `anthropic-ratelimit-unified-{5h,weekly}-status: blocked`.
pub const DEFAULT_WINDOW_EXHAUST_HEADERS: [&str; 2] = [
    "anthropic-ratelimit-unified-5h-status=blocked",
    "anthropic-ratelimit-unified-weekly-status=blocked",
];

/// serde default: `PoolProvider::cooldown_secs` = 60s (信号无精确恢复时刻的
/// 兜底闹钟时长). pub: web upsert 的 Pool 构造 (`UpsertProviderRequest`) 缺省
/// 回填与此共享同一 SSOT (先例同 `default_true`).
pub fn default_pool_cooldown_secs() -> u64 {
    60
}

/// serde default: `ExhaustConfig::codes` = 内置窗口限额码表.
fn default_window_exhaust_codes() -> Vec<String> {
    DEFAULT_WINDOW_EXHAUST_CODES
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// serde default: `ExhaustConfig::headers` = 内置 Claude 订阅 header 表.
fn default_window_exhaust_headers() -> Vec<String> {
    DEFAULT_WINDOW_EXHAUST_HEADERS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// 套餐池 provider 的构造负载 ([`ProviderKind::Pool`]).
///
/// base_url / api_key 等直连字段**在此构造下不存在** (sum type); 成员各自是
/// 独立的 Direct provider (一份独立凭证). pick 语义 (无游标列表序 / 闹钟回归
/// / 全耗尽 Err) 与耗尽检测的 SSOT: [`crate::pool`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolProvider {
    /// 有序成员列表 (Direct provider ids). 顺序 failover: 列表序即优先级
    /// (`crate::pool::PoolStates::active_members` 候选的列表序解析), 正常全打第一个可用成员.
    /// validate 拒绝空表 (空 members 的 pool 无法转发任何请求, 几乎肯定是
    /// 配置残缺) 与自环 (member 含自身 id).
    pub members: Vec<String>,
    /// 耗尽信号配置 (三通道 OR: statuses / codes / headers). 省略 = 内置
    /// 窗口限额默认表 (见上方常量). **字段级替换语义**: 显式配某字段 = 替换
    /// 该字段默认值 (空数组 = 显式关闭该通道); 想 "删掉默认表里某个码" =
    /// 重抄剩余码 — 有意保留删除能力.
    #[serde(default)]
    pub exhaust: ExhaustConfig,
    /// 兜底闹钟时长 (秒). 信号命中但解析不出精确恢复时刻时, 成员挂起
    /// now + cooldown (防探测风暴的下限也用它).
    #[serde(default = "default_pool_cooldown_secs")]
    pub cooldown_secs: u64,
}

/// 耗尽信号配置 (三通道 OR, 空通道 = 关闭). 匹配语义与恢复时刻解析的
/// SSOT: `crate::pool::detect_exhaustion`.
///
/// `Default` = **内置窗口限额默认表** (手写而非 derive — derive 的全空形态
/// 与 "省略 \[exhaust\] 段 = 内置表" 的 serde 语义冲突, 统一于此单一事实:
/// `exhaust` 段整体缺席时 serde 走本 Default; 段内单字段缺席走字段级
/// default, 两者产出一致)。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExhaustConfig {
    /// status 触发线: 上游 HTTP status ∈ 此列表 → 耗尽. 默认空 (关闭 —
    /// 无一家窗口限额可用纯 status 判别, 429 混杂瞬态限速).
    #[serde(default)]
    pub statuses: Vec<u16>,
    /// body 码触发线: 从 body JSON 四个候选位置提取的字符串码 ∈ 此列表 →
    /// 耗尽. 默认 = [`DEFAULT_WINDOW_EXHAUST_CODES`] (智谱窗口限额).
    #[serde(default = "default_window_exhaust_codes")]
    pub codes: Vec<String>,
    /// header 触发线: `"name=value"` 精确匹配 (name 大小写不敏感).
    /// 默认 = [`DEFAULT_WINDOW_EXHAUST_HEADERS`] (Claude 订阅 unified 两项).
    #[serde(default = "default_window_exhaust_headers")]
    pub headers: Vec<String>,
}

impl Default for ExhaustConfig {
    fn default() -> Self {
        Self {
            statuses: Vec::new(),
            codes: default_window_exhaust_codes(),
            headers: default_window_exhaust_headers(),
        }
    }
}

impl ExhaustConfig {
    /// 配置期 lint: headers 通道中畸形的规则条目 — 检测器
    /// (`crate::pool::header_rule_matches`) 对这类条目 ROB 静默跳过, 用户手滑
    /// 写错会表现为 "该通道永远不命中" 而无任何线索。此处让脏条目在写入时
    /// WARN 可见 (仿 `MockStrategy::lint_candidate_space` 先例: WARN 不 reject —
    /// 合法但高危的配置是用户意图, 不替用户决策)。畸形判定与检测器的跳过集
    /// 对齐 (无 `=` / `=` 前空 name / 非法 header name 字节); 返回**原始条目**
    /// (与配置文件可 grep 对齐), 空 = 干净; 空白条目跳过不报 (等价关闭该条,
    /// 无歧义)。
    pub fn lint_malformed_header_rules(&self) -> Vec<&str> {
        // 畸形判定 = parse_header_rule 失败 (与检测器 matcher 共享同一 parser,
        // 对齐是结构性的而非注释约定 — matcher 静默跳过的集合恰是这里 WARN 的
        // 集合; 空白条目先过滤: 完全空串跳过不告警, 与 serde 空串条目语义一致).
        self.headers
            .iter()
            .filter(|s| {
                let trimmed = s.trim();
                !trimmed.is_empty() && parse_header_rule(trimmed).is_none()
            })
            .map(|s| s.as_str())
            .collect()
    }
}

/// header 触发规则 `"name=value"` 的共享 parser (lint 与检测器 matcher 的
/// 单一事实来源; 规则格式是 [`ExhaustConfig`] schema 的一部分, 故住本模块 —
/// pool 消费方向合法)。失败 = 畸形 (无 `=` / 空 name / 非法 header 名)。
pub fn parse_header_rule(rule: &str) -> Option<(axum::http::HeaderName, &str)> {
    let (name, value) = rule.split_once('=')?;
    let name = axum::http::HeaderName::from_bytes(name.trim().as_bytes()).ok()?;
    Some((name, value))
}

/// `'*'` 通配符匹配 (仅 `'*'` 是元字符, 其余字符字面匹配; 大小写敏感)。
///
/// 按 `'*'` 分段实现: 首段必须前缀匹配, 尾段必须后缀匹配, 中间段依序子串匹配。
/// 性质:
/// - `"*"` 匹配一切 (含空串);
/// - 连续 `"**"` 折叠为单个 `"*"` (空段跳过);
/// - 无 `'*'` 的 pattern 退化为全等比较。
///
/// 纯函数 (pub), 供 [`RouterProvider::select_route`] 与测试复用。
pub fn wildcard_match(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name; // 无通配符: 字面全等.
    }
    // 首段: 前缀.
    let first = parts[0];
    if !name.starts_with(first) {
        return false;
    }
    let mut rest = &name[first.len()..];
    // 中间段: 依序子串 (空段 = 连续 '*', 跳过).
    for seg in &parts[1..parts.len() - 1] {
        if seg.is_empty() {
            continue;
        }
        match rest.find(seg) {
            Some(i) => rest = &rest[i + seg.len()..],
            None => return false,
        }
    }
    // 尾段: 后缀 (空尾段 = pattern 以 '*' 结尾, 已消费完毕; ends_with 已蕴含
    // 长度检查).
    let last = parts[parts.len() - 1];
    if last.is_empty() {
        return true;
    }
    rest.ends_with(last)
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
                // 端点表三规则 (§5.5): 非空 / 每协议至多一条 / 每 endpoint 的
                // base_url 过 validate_base_url (错误文案指明重复的 protocol 名 /
                // 序号, 便于定位). 空 endpoints (字段缺席经 serde default 或显式
                // 空数组) 的 Direct 无法转发任何请求, 几乎肯定是配置残缺 —
                // 与 Router 空 routes / Pool 空 members 同型 fail-fast.
                if d.endpoints.is_empty() {
                    return Err(format!(
                        "provider {} must declare at least one endpoint",
                        self.id
                    ));
                }
                let mut seen = HashSet::new();
                for (idx, ep) in d.endpoints.iter().enumerate() {
                    validate_base_url(&ep.base_url).map_err(|e| {
                        format!(
                            "provider {} endpoint #{} ({}): {e}",
                            self.id, idx, ep.protocol
                        )
                    })?;
                    if !seen.insert(ep.protocol) {
                        return Err(format!(
                            "provider {} declares multiple endpoints for protocol {}; \
                             at most one endpoint per protocol is allowed",
                            self.id,
                            ep.protocol.name()
                        ));
                    }
                    // common_uri 值域: "" (版本前缀已含) 或以 '/' 开头的合法 path
                    // 片段 (无尾斜杠 / 无 query-fragment 分隔符 / 长度上限). 拒绝
                    // 怪值防止手写 toml 的笔误悄悄改变 fetch 出站 URL.
                    if let Some(cu) = &ep.common_uri {
                        let valid = cu.is_empty()
                            || (cu.starts_with('/')
                                && !cu.ends_with('/')
                                && !cu.contains(['?', '#', ' '])
                                && cu.chars().count() <= 64);
                        if !valid {
                            return Err(format!(
                                "provider {} endpoint {} common_uri must be \"\" or a \
                                 '/'-prefixed path segment without trailing '/', '?' or \
                                 '#' (got {cu:?})",
                                self.id,
                                ep.protocol.name()
                            ));
                        }
                    }
                }
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
            ProviderKind::Router(r) => {
                // 空 routes 拒绝: 空 router 无法转发任何请求 (NoMatch 恒真),
                // 几乎肯定是配置残缺 — fail-fast 优于运行时 503 排障.
                if r.routes.is_empty() {
                    return Err(format!(
                        "provider {} must declare at least one route",
                        self.id
                    ));
                }
                for route in &r.routes {
                    // model_pattern 非空 + 长度上限: 输入卫生 (对齐 id/name 纪律,
                    // 超长 model_pattern 进 WebUI / per-request 匹配热路径).
                    if route.model_pattern.is_empty() {
                        return Err(format!(
                            "provider {} has a route with empty model_pattern",
                            self.id
                        ));
                    }
                    if route.model_pattern.chars().count() > 64 {
                        return Err(format!(
                            "provider {} route model_pattern exceeds 64 chars",
                            self.id
                        ));
                    }
                    // target 的 id 卫生对所有路由生效 (含禁用 — 落盘数据的
                    // 合法性与启用状态无关);
                    crate::secrets::validate_id(&route.target)?;
                    // 自环仅对**启用**路由拒绝 — 与 would_cycle 的 "禁用路由不
                    // 构成环检查的边" 语义对齐 (禁用路由不参与匹配与环遍历,
                    // 拒绝它会阻止用户暂存一条自指路由). 跨条目成环由 upsert
                    // 侧 would_cycle + 运行时 resolve_route 兜底.
                    if route.target == self.id && route.priority.is_some() {
                        return Err(format!("provider {} routes to itself", self.id));
                    }
                    // route.upstream_model 重写值的输入卫生 (校验措辞沿用原 provider 级改写):
                    // 空串/纯空白/超长拒绝, 清空语义 = 省略字段.
                    if let Some(m) = &route.upstream_model {
                        if m.is_empty() {
                            return Err(format!(
                                "provider {} has empty route upstream_model; omit the field to clear it",
                                self.id
                            ));
                        }
                        if m.chars().count() > 128 {
                            return Err(format!(
                                "provider {} route upstream_model exceeds 128 chars",
                                self.id
                            ));
                        }
                        if m.trim().is_empty() {
                            return Err(format!(
                                "provider {} route upstream_model is whitespace-only",
                                self.id
                            ));
                        }
                    }
                    // priority 数值不加范围限制 (i64 任意); 重复 model_pattern /
                    // 重复优先级合法 (tie 按列表序, select_route 锁定).
                }
            }
            ProviderKind::Pool(p) => {
                // 空 members 拒绝: 空 pool 无法转发任何请求, 几乎肯定是配置
                // 残缺 — 与 Router 空 routes 同型 fail-fast.
                if p.members.is_empty() {
                    return Err(format!(
                        "provider {} must declare at least one pool member",
                        self.id
                    ));
                }
                for member in &p.members {
                    // 成员 id 卫生 (与 Router target 同型先例).
                    crate::secrets::validate_id(member)?;
                    // 自环拒绝: member 指向自身 = 立即 Cycle, 配置残缺.
                    // (运行时 visited-set 兜底手改 state.toml 漏网.)
                    if member == &self.id {
                        return Err(format!("provider {} lists itself as pool member", self.id));
                    }
                }
                // 重复成员不拒绝: 同一 provider 占两个 slot, 各有独立的闹钟
                // 生命, 行为无歧义 (与 Router 平行路由边先例一致).
                //
                // 配置期 lint (WARN 不 reject, 仿 `MockStrategy::lint_candidate_space`
                // 先例): 畸形 header 规则在检测器里被 ROB 静默跳过, 此处让手滑在
                // 写入时可见。validate 是所有 entry 进入系统的公共 choke point
                // (static 加载 / dynamic 加载 / WebUI upsert 都经过), 与 secrets 的
                // validate_and_resolve lint 挂点同型。
                let malformed = p.exhaust.lint_malformed_header_rules();
                if !malformed.is_empty() {
                    tracing::warn!(
                        provider_id = %self.id,
                        rules = ?malformed,
                        "pool exhaust header rules are malformed (expected 'name=value'); they will never match"
                    );
                }
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
    /// sum type 语义 (#187): 继承只在**同型构造**内发生 (Direct↔Direct 只继承
    /// 鉴权字段; **endpoints 不继承** — WebUI PUT 全量必填, override 携带的
    /// endpoints 整体替换 static, §5.6 合并语义). 跨型不继承 — override 的构造
    /// 本身就是显式决策:
    /// - Direct override + Router static = **改回实体** (routes 无 None 歧义,
    ///   #179 登记的 "无法改回实体" 限制由类型系统根治);
    /// - Router override + Direct static = 切为路由 (Router static 无鉴权字段
    ///   可继承, 与旧行为等价 — 旧实现继承到的也是空).
    fn inherit_from_static(&mut self, static_ver: &Self) {
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
    /// 构造判别 (直连 / 路由), JSON 为 internally tagged flatten:
    /// `{"kind": "direct", "protocol": ..., "base_url": ...}` /
    /// `{"kind": "router", "routes": [...]}`.
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
/// (api_key 脱敏为 masked 视图; Router 的 routes 非敏感直接序列化给前端,
/// 无 protocol — 见 [`RouterProvider`]).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EffectiveProviderKind {
    Direct {
        /// 有序端点列表 (非敏感直接透出 — 协议/base_url/common_uri 均无敏感面).
        /// wire 形态与存储一致 (`[{protocol, base_url, common_uri?}]`),
        /// WebUI 编辑表单全量回填后整体提交.
        endpoints: Vec<Endpoint>,
        /// 直接值 (api_key 字段) 的 masked 视图. 若 provider 用 api_key_file,
        /// 这里是空字符串 — 文件内容由 effective_api_key() 在转发时读取, 不进 effective 视图.
        api_key_masked: String,
        api_key_length: usize,
    },
    Router {
        routes: Vec<Route>,
    },
    /// Pool 构造 (spec §10 的 WebUI 面在 T3 扩展运行时状态观察; 本变体先落
    /// 纯配置字段). 无 protocol — 与 Router 同理 (egress 由成员决定).
    Pool {
        members: Vec<String>,
        exhaust: ExhaustConfig,
        cooldown_secs: u64,
    },
}

/// 对外返回时屏蔽真实 api_key. 仍保留长度提示 (便于排查"是否配置了 key").
#[derive(Debug, Clone, Serialize)]
pub struct ProviderMasked {
    pub id: String,
    pub name: Option<String>,
    pub enabled: bool,
    #[serde(flatten)]
    pub kind: EffectiveProviderKind,
}

impl From<Provider> for ProviderMasked {
    fn from(p: Provider) -> Self {
        let kind = match p.kind {
            ProviderKind::Direct(d) => EffectiveProviderKind::Direct {
                endpoints: d.endpoints,
                api_key_masked: crate::secrets::mask_value(&d.api_key),
                api_key_length: d.api_key.chars().count(),
            },
            ProviderKind::Router(r) => EffectiveProviderKind::Router { routes: r.routes },
            ProviderKind::Pool(p) => EffectiveProviderKind::Pool {
                members: p.members,
                exhaust: p.exhaust,
                cooldown_secs: p.cooldown_secs,
            },
        };
        Self {
            id: p.id,
            name: p.name,
            enabled: p.enabled,
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

    /// 解析路由 provider 的路由链 (#179 多规则化 + Pool 成员选择): 从 `entry`
    /// 出发, 按请求 model 逐跳匹配路由 (Router 跳) / 按状态机选成员 (Pool 跳),
    /// 直到链尾的实体 provider, 并收集链上生效的 model 重写值
    /// (`Route::upstream_model`, #183 语义被路由吸收) 与经过的第一个 pool 跳
    /// ([`PoolHop`], 响应侧耗尽检测的归因锚点).
    ///
    /// - **per-request 语义**: dispatch 每次转发前调用 (携带本请求的 model),
    ///   切换路由只影响新请求 (in-flight 请求已拿到解析结果, 按旧目标完成);
    /// - 每跳走 [`Self::get_effective`] (含 static+dynamic+decision 合并与 #157 继承),
    ///   链上每个 provider 必须存在且 entry-level enabled;
    /// - **路由选择** ([`RouterProvider::select_route`]): 启用路由中 model_pattern
    ///   匹配 **in-flight model** 的最大 priority 者, 并列按列表序; 无命中 → [`RouteError::NoMatch`];
    /// - **Pool 分支** ([`PoolPicker`]): `active_members` 返回候选列表 (无闹钟/
    ///   闹钟已过, 列表序即优先级), 取第一个配置可用 (effective 存在且 enabled)
    ///   成员; missing/disabled 候选跳过但不标记 (配置可用性不进状态机 —
    ///   重新 enable 即时回归); 全部不可用 → [`RouteError::AllMembersExhausted`]. 状态机实现 [`crate::pool::PoolStates`]
    ///   由调用方注入 (接口倒置, 先例同 codec::StreamRestoreHook — 保持
    ///   pool → provider 单向依赖);
    /// - **model 重写 pipeline 语义**: 路由的 `upstream_model` 为 Some 时改写**立即生效** —
    ///   后续 router 按改写后的 model 匹配, 多次改写后者覆盖前者 (与旧 #183
    ///   first-wins 不同: 改写值参与下一跳的路由匹配);
    /// - **链内非原子**: 两跳以上链的逐跳解析各自独立读表, 解析期间表被修改时
    ///   本请求可能走 "切换前 + 切换后" 的混合链 — 这是 per-request 解析的自然
    ///   语义 (本请求视角, 链在解析起点时刻的快照), 不额外加锁;
    /// - visited-set 保证**有限步终止**: 表有限, 重复 id 即环 (validate/would_cycle
    ///   之外的运行时兜底 — 手改 state.toml 或并发写入造成的环在这里安全降级为
    ///   503, 不挂起);
    /// - `entry` 按借用传入 (per-model 批量解析场景 — `/models` 合成 (FWD-7) 对
    ///   每个候选 model 解析一次 — 避免整棵 Provider 逐次 clone): 首跳零拷贝,
    ///   仅换跳 (`get_effective`) 与 Direct 返回 (id + DirectPayload) 才构造
    ///   owned 值;
    /// - `entry` 自身是 Direct 时原样返回 (实体 provider 快路径, 零路由匹配一跳).
    ///
    /// 错误消息只含 provider id / model 名与 reason 枚举 (SEC-2 同型, 无 secret,
    /// AllMembersExhausted 亦不含上游 body 原文), 经 `AppError::Unavailable`
    /// 原样回传客户端 503 body.
    pub fn resolve_route(
        &self,
        entry: &Provider,
        request_model: &str,
        pools: &dyn PoolPicker,
    ) -> Result<ResolvedRoute, RouteError> {
        let mut visited = HashSet::from([entry.id.clone()]);
        let mut in_flight_model = request_model.to_string();
        let mut model_rewrite: Option<String> = None;
        // 本请求经过的第一个 pool 跳 (嵌套多 pool 只记第一个 — 罕见场景,
        // 响应侧耗尽检测只归因到最外层; spec §7 声明假设).
        let mut pool_hop: Option<PoolHop> = None;
        // 借用语义经 Cow 表达: 首跳借用调用方 entry, 换跳才构造 owned —
        // 峰值至多保留一跳中间 Provider, 与原实现的 `cur = next` 一致.
        let mut cur = std::borrow::Cow::Borrowed(entry);
        loop {
            match &cur.kind {
                // 链尾 (或入口即实体): 返回. `id` 一并带出 (DirectProvider 不持有 id,
                // downstream 的 CallEvent.upstream_id 需要).
                ProviderKind::Direct(direct) => {
                    return Ok(ResolvedRoute {
                        id: cur.id.clone(),
                        provider: direct.clone(),
                        model_rewrite,
                        pool: pool_hop,
                    });
                }
                ProviderKind::Router(router) => {
                    // NoMatch 的 model 回显在构造处截断 (超长 model 名防日志
                    // 洪水 / 503 body 膨胀); 匹配本身用未截断的 in_flight_model.
                    let route = router.select_route(&in_flight_model).ok_or_else(|| {
                        RouteError::NoMatch {
                            id: cur.id.clone(),
                            model: truncate_model_for_echo(&in_flight_model),
                        }
                    })?;
                    // pipeline 语义: 改写立即生效 (后续 router 按改写后 model 匹配),
                    // 多次改写后者覆盖前者.
                    if let Some(m) = &route.upstream_model {
                        model_rewrite = Some(m.clone());
                        in_flight_model = m.clone();
                    }
                    let next = self
                        .get_effective(&route.target)
                        .ok_or_else(|| RouteError::Missing(route.target.clone()))?;
                    if !next.enabled {
                        return Err(RouteError::Disabled(next.id.clone()));
                    }
                    if !visited.insert(next.id.clone()) {
                        return Err(RouteError::Cycle(next.id));
                    }
                    cur = std::borrow::Cow::Owned(next);
                }
                ProviderKind::Pool(pool) => {
                    // 候选 = 状态机的 active 成员 (无闹钟/闹钟已过, 列表序即
                    // 优先级); 配置可用性在此逐个检查: missing (被 decision
                    // 排除) / disabled 的候选**跳过但不标记** — 配置可用性不
                    // 进状态机 (无持久副作用: 重新 enable 自动回归, GET
                    // /models 的可解析性探针复用同一路径亦安全), 与 Router 的
                    // Missing/Disabled 503 语义不同: pool 的存在意义就是 failover.
                    // 候选耗尽 (闹钟) 或候选全配置不可用 → AllMembersExhausted
                    // (earliest_resume: None = 配置面全不可用, 无闹钟可期).
                    //
                    // members 直接借用 `cur.kind` (NLL: 最后使用点在本分支内,
                    // 此后 cur 被 move 合法) — 与 Router 臂的 route 借用同形态,
                    // 零成员表 clone.
                    let pool_id = cur.id.clone();
                    let candidates = pools
                        .active_members(&pool_id, &pool.members, std::time::Instant::now())
                        .map_err(RouteError::AllMembersExhausted)?;
                    // 悬空 / disabled 候选 → 跳过 (无标记) 取下一候选.
                    let (member_idx, next) = candidates
                        .into_iter()
                        .find_map(|idx| {
                            self.get_effective(&pool.members[idx])
                                .filter(|p| p.enabled)
                                .map(|p| (idx, p))
                        })
                        .ok_or(RouteError::AllMembersExhausted(AllMembersExhausted {
                            pool_id: pool_id.clone(),
                            // 全部候选配置不可用: 无闹钟信息 (区别于闹钟型耗尽).
                            earliest_resume: None,
                        }))?;
                    if !visited.insert(next.id.clone()) {
                        return Err(RouteError::Cycle(next.id));
                    }
                    // 嵌套多 pool 只记第一个遇到的 (get_or_insert 语义, 罕见场景
                    // 声明见函数头).
                    pool_hop.get_or_insert(PoolHop {
                        pool_id,
                        member_idx,
                    });
                    cur = std::borrow::Cow::Owned(next);
                }
            }
        }
    }

    /// upsert 前校验: 写入 `entry` 后 entry 的路由可达子图内是否存在环
    /// (WebUI 侧拒绝, 400). 边集语义 (启用路由 / 悬空 / decision-disabled
    /// 均不算环) 见 `route_graph` doc — 边集 SSOT; 悬空写入放行以保证创建
    /// 顺序无关, 运行时由 `resolve_route` 503 兜底.
    ///
    /// 并发写入的 TOCTOU 窗口 (检查与 upsert 非同一临界区): 两个并发 PUT 交错可让
    /// 环落库 — 单用户本地工具的可接受假设 (与 update_provider 的 #157 TOCTOU 声明
    /// 一致), 漏网环由 `resolve_route` visited-set 兜底为 503.
    pub fn would_cycle(&self, entry: &Provider) -> bool {
        // 检查图 = merged 视图邻接表, 用 entry 新值覆盖其 id (walk 必须看到
        // upsert 后的形态, 而非表中旧值).
        let mut hops = self.route_graph();
        let entry_targets = match &entry.kind {
            ProviderKind::Router(r) => enabled_targets_of(&r.routes),
            // Pool members 与 route target 同型构成图边 (无禁用语义 — 全算).
            ProviderKind::Pool(p) => p.members.clone(),
            ProviderKind::Direct(..) => vec![],
        };
        hops.insert(entry.id.clone(), entry_targets);
        // 从 entry 起步扫其可达子图: 存在性完备 (有环 ⇔ 至少报一条), 布尔即非空.
        let mut scan = CycleScan::new(&hops);
        scan.visit(&entry.id);
        !scan.out.is_empty()
    }

    /// merged (static+dynamic+decision) 视图的路由邻接表: provider id → 启用
    /// 路由的 target 列表 (Pool 构造 = members, 与 route target 同型的图边).
    /// Direct 构造为空 (链终止); dangling target 不在键集
    /// (走到即止). [`Self::would_cycle`] 与 [`Self::find_cycles`] 的边集 SSOT:
    /// 禁用路由 (priority=None) 不构成边, decision-disabled 项被 effective
    /// 视图排除; entry 级 `enabled=false` 的 router/pool 仍贡献边 (潜伏环也值得
    /// 启动时暴露 — 踏上它的请求实际以 Disabled 503 终止, 语义偏保守无害).
    fn route_graph(&self) -> HashMap<String, Vec<String>> {
        self.effective_snapshot()
            .into_iter()
            .map(|e| {
                let targets = match &e.kind {
                    EffectiveProviderKind::Router { routes } => enabled_targets_of(routes),
                    EffectiveProviderKind::Pool { members, .. } => members.clone(),
                    EffectiveProviderKind::Direct { .. } => vec![],
                };
                (e.id.clone(), targets)
            })
            .collect()
    }

    /// 对 merged (static+dynamic+decision) 视图整体做路由环检测 (启动诊断用,
    /// #179 可选加固). 返回检测到的环, 每个环是 provider id 序列
    /// (a → b → ... → a, 首尾相同). 保证**存在性完备** (图有环 ⇔ 至少报一条)
    /// 且零误报, 但不保证枚举全部简单环 — 经已探索节点绕行的替代环不单独
    /// 报告, 修复已报告环后重启即暴露残余环 (启动诊断的迭代发现语义).
    ///
    /// 边集 = `route_graph` (边集 SSOT, 语义见其 doc); dangling target 走到
    /// 即止, 不算环 — 与 `resolve_route` 语义一致, 目标缺失是请求期 503 的事.
    ///
    /// 同一环只报告一次: canonical 形态旋转到字典序最小 id 起步 (\[a,b\] 与
    /// \[b,a\] 是同一环). 消费点: `server::serve` 启动 WARN — 把手改 state.toml
    /// / 并发 upsert TOCTOU 漏网的环提前到启动日志暴露, 而非等到首个请求 503.
    pub fn find_cycles(&self) -> Vec<Vec<String>> {
        let hops = self.route_graph();
        // 起点按 id 排序 (HashMap 遍历序不确定, 诊断输出需稳定).
        let mut starts: Vec<&String> = hops.keys().collect();
        starts.sort();
        let mut scan = CycleScan::new(&hops);
        for start in starts {
            scan.visit(start);
        }
        scan.out
    }
}

/// 路由列表 → 启用路由 (priority 非 None) 的 target 列表. 环检查的边集单元
/// (`route_graph` 与 `would_cycle` 的 entry 覆盖共用): 禁用路由不可遍历.
fn enabled_targets_of(routes: &[Route]) -> Vec<String> {
    routes
        .iter()
        .filter(|route| route.priority.is_some())
        .map(|route| route.target.clone())
        .collect()
}

/// 路由图环检测的 DFS 扫描器 (`would_cycle` 与 `find_cycles` 共用的遍历核心,
/// path-based 三色标记): `on_stack` 是当前递归栈 (灰色), 回到栈上节点 = 环;
/// `done` 记忆已探索的节点 (黑色 — 存在性完备: 其可达子图有环则必有一条已
/// 报告, 但经它绕行的替代环不再单独报告); `seen` 去重**平行路由边**: 同一
/// router 多条启用路由指向同一 on-stack target 时同一栈段会被报告多次
/// (不同入口的再发现由 `done` 短路, 到不了这).
struct CycleScan<'a> {
    hops: &'a HashMap<String, Vec<String>>,
    stack: Vec<String>,
    on_stack: HashSet<String>,
    done: HashSet<String>,
    seen: HashSet<Vec<String>>,
    out: Vec<Vec<String>>,
}

impl<'a> CycleScan<'a> {
    fn new(hops: &'a HashMap<String, Vec<String>>) -> Self {
        Self {
            hops,
            stack: Vec::new(),
            on_stack: HashSet::new(),
            done: HashSet::new(),
            seen: HashSet::new(),
            out: Vec::new(),
        }
    }

    fn visit(&mut self, node: &str) {
        if !self.done.insert(node.to_string()) {
            return; // 黑色: 该子图的所有环已报告过.
        }
        self.stack.push(node.to_string());
        self.on_stack.insert(node.to_string());
        for target in self.hops.get(node).into_iter().flatten() {
            if self.on_stack.contains(target) {
                self.report_cycle(target);
            } else {
                self.visit(target);
            }
        }
        self.stack.pop();
        self.on_stack.remove(node);
    }

    /// 栈上回到 `target` = 环: 截取栈上 `target..=top` 段, 旋转到字典序最小
    /// id 起步去重后 (平行路由边防护), 以首尾相同的完整形态 (a → ... → a) 报告.
    fn report_cycle(&mut self, target: &str) {
        let start = self
            .stack
            .iter()
            .position(|id| id == target)
            .expect("on_stack hit implies stack position");
        let cycle = &self.stack[start..];
        let min_idx = cycle
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.cmp(b))
            .expect("cycle is non-empty")
            .0;
        let canonical: Vec<String> = {
            // 后段接前段 = 旋转到 min_idx 起步.
            let (before, after) = cycle.split_at(min_idx);
            after.iter().chain(before).cloned().collect()
        };
        if self.seen.insert(canonical.clone()) {
            let mut full = canonical;
            full.push(full[0].clone());
            self.out.push(full);
        }
    }
}

/// NoMatch 错误回显 model 的截断上限 (chars): model 来自请求 body (可任意长,
/// 如 10 MiB 的畸形 model 名), 回显进 503 body 与日志前截断, 防日志洪水.
/// (私有: 仅本文件消费; tests 模块同文件可直接访问.)
const NOMATCH_MODEL_ECHO_LIMIT: usize = 64;

/// 错误/日志回显 model 的截断: 超 64 chars 截到 64 + `…` 后缀.
/// 消费点: NoMatch 构造处 (Display 保持纯粹, 同一值进 503 body 与 warn!) +
/// proxy 的 "route resolved" info! (成功路径回显, 同类洪水风险).
pub(crate) fn truncate_model_for_echo(model: &str) -> String {
    crate::util::truncate_chars_with_ellipsis(model, NOMATCH_MODEL_ECHO_LIMIT)
}

/// 路由 provider 解析错误 (`resolve_route`). Display 消息进 503 body,
/// 只含 provider id / model 名与 reason (SEC-2 同型).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    /// 链上一跳在 effective 视图中不存在 (目标缺失, 或被 decision=Disabled 排除).
    Missing(String),
    /// 链上一跳 entry-level enabled=false.
    Disabled(String),
    /// 链上出现环 (含自环). 字段 = 环回到的 provider id.
    Cycle(String),
    /// router 的启用路由中无 model_pattern 匹配当前请求 model 的路由.
    /// 字段 = 该 router 的 id + 当时的 in-flight model 名.
    NoMatch { id: String, model: String },
    /// pool 的全部成员不可用 (耗尽 / missing / disabled).
    AllMembersExhausted(AllMembersExhausted),
}

/// [`RouteError::AllMembersExhausted`] 的 payload: pool id + 最早到期闹钟.
/// message 契约 (SEC-2): 只含 pool id + reason 枚举 + 恢复时刻, 绝不含
/// 上游 body 原文 (可能含敏感信息) — 与其他 RouteError 变体同型.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllMembersExhausted {
    pub pool_id: String,
    /// 最早到期的闹钟 (`None` = 本路径无闹钟信息 — 通常是候选全部为配置
    /// 不可用 (missing/disabled), 重新 enable 即时回归, 无需复位端点).
    pub earliest_resume: Option<std::time::Instant>,
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
            RouteError::NoMatch { id, model } => write!(
                f,
                "router provider '{id}' has no route matching model '{model}'"
            ),
            RouteError::AllMembersExhausted(e) => match e.earliest_resume {
                // 恢复时刻以剩余秒数呈现 (Instant 无墙钟表示; SEC-2 — 不含 body).
                Some(t) => write!(
                    f,
                    "pool provider '{}' has no available member (all exhausted, missing or disabled; earliest resumes in ~{}s)",
                    e.pool_id,
                    t.saturating_duration_since(std::time::Instant::now())
                        .as_secs()
                ),
                None => write!(
                    f,
                    "pool provider '{}' has no available member (all exhausted, missing or disabled; no scheduled recovery)",
                    e.pool_id
                ),
            },
        }
    }
}

impl std::error::Error for RouteError {}

/// Pool 成员状态机的消费接口 (**接口倒置**, 先例同 codec::StreamRestoreHook):
/// [`DynamicTable::<Provider>::resolve_route`] 的图遍历需要读 pool 状态机
/// (候选成员 + 耗尽标记), 而状态机实现 [`crate::pool::PoolStates`] 又依赖
/// provider 类型 — trait 定义在本模块 (被 resolve_route 消费), 生产实现由
/// 调用方 (proxy dispatch / 测试) 注入, 保持 pool → provider 单向依赖.
pub trait PoolPicker: Send + Sync {
    /// 候选成员: 返回全部无闹钟/闹钟已过成员的下标列表 (列表序保持 members
    /// 优先级, 闹钟过期的顺带清除 — 成员回归列表头, 前缀缓存最大化); 全部
    /// 成员在闹钟期内 → [`AllMembersExhausted`] (含最早到期闹钟). `members`
    /// 是当前配置快照 — 实现方每次调用先做配置对齐 (WebUI 可随时改配置).
    ///
    /// **只反映耗尽闹钟, 不反映配置可用性** — missing/disabled 成员的跳过
    /// 由调用方 (resolve_route) 对候选逐个 get_effective 检查, 无持久副作用
    /// (重新 enable 自动回归; GET /models 探针复用同一路径亦安全).
    fn active_members(
        &self,
        pool_id: &str,
        members: &[String],
        now: std::time::Instant,
    ) -> Result<Vec<usize>, AllMembersExhausted>;

    /// 标记成员耗尽 (幂等: 重复标记刷新 until — 探测失败重挂闹钟).
    /// `members` 同上 (对齐基准).
    fn mark_member_exhausted(
        &self,
        pool_id: &str,
        members: &[String],
        member_idx: usize,
        until: std::time::Instant,
    );
}

/// 路由解析结果 (#179/#183 + Pool): 链尾实体 provider + 链上生效的 model
/// 重写值 + 经过的第一个 pool 跳.
///
/// `model_rewrite` = 命中路由的 `upstream_model` 字段 (pipeline 语义, 多跳改写
/// 后者覆盖前者; 全链路由均未配置 → None, 即透传).
#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    /// 链尾实体 provider 的 id (非路由请求即入口 id; CallEvent.upstream_id 用).
    pub id: String,
    /// 链尾实体 provider — **类型上保证是 Direct** (转发链只处理实体, #187).
    pub provider: DirectProvider,
    /// 链上生效的 model 重写值 (路由 pipeline; None = 客户端 model 透传).
    pub model_rewrite: Option<String>,
    /// 本请求经过的 (第一个) pool 跳 (响应侧耗尽检测的归因锚点: 检测命中时
    /// `mark_member_exhausted(pool_id, member_idx, ...)`). 非 pool 流量为 None
    /// (T2 挂接层据此零开销短路).
    pub pool: Option<PoolHop>,
}

/// 一次解析经过的 pool 跳 (spec §7): pool id + 命中成员下标.
/// 嵌套多 pool 只记第一个遇到的 (罕见场景, 声明见 `resolve_route` doc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolHop {
    pub pool_id: String,
    pub member_idx: usize,
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
        kind,
    } = ProviderMasked::from(raw);
    let static_masked = static_ver.map(ProviderMasked::from);
    let dynamic_masked = dynamic_ver.map(ProviderMasked::from);
    Some(EffectiveProvider {
        id,
        enabled,
        name,
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
    use proptest::prelude::*;

    use crate::config::Decisions;
    use crate::pool::PoolStates;

    /// 测试便捷: Direct 负载首端点的 base_url (p() 家族恒构造单端点;
    /// 空表 panic = 测试构造 bug, 不是被测行为).
    fn first_url(d: &DirectProvider) -> &str {
        &d.endpoints[0].base_url
    }

    fn p(id: &str, proto: Protocol, base: &str) -> Provider {
        Provider {
            id: id.into(),
            enabled: true,
            name: Some(format!("name-{id}")),
            kind: ProviderKind::Direct(DirectProvider {
                endpoints: vec![Endpoint::new(proto, base)],
                api_key: format!("k-{id}"),
                api_key_file: None,
            }),
        }
    }

    /// 路由: model_pattern → target (priority 默认 Some(0) = 启用, 无 upstream_model 改写).
    fn route(model_pattern: &str, target: &str) -> Route {
        Route {
            model_pattern: model_pattern.into(),
            target: target.into(),
            upstream_model: None,
            priority: Some(0),
        }
    }

    /// 路由 provider: 单路由 model_pattern="*" 指向 target (等价旧 route_to
    /// 硬指向的等价形态). 构造无 protocol 字段 (见 RouterProvider 注释).
    fn router_to(id: &str, target: &str) -> Provider {
        router(id, vec![route("*", target)])
    }

    /// 路由 provider (显式路由列表). 无 protocol 字段 (见 RouterProvider 注释).
    fn router(id: &str, routes: Vec<Route>) -> Provider {
        Provider {
            kind: ProviderKind::Router(RouterProvider { routes }),
            ..p(id, Protocol::OpenAI, "")
        }
    }

    /// 取 Provider 的 Direct 负载 (测试断言用; panic 表明构造不是 Direct).
    fn direct(p: &Provider) -> &DirectProvider {
        match &p.kind {
            ProviderKind::Direct(d) => d,
            _ => panic!("expected Direct provider"),
        }
    }

    /// 可变取 Direct 负载 (测试改造用).
    fn direct_mut(p: &mut Provider) -> &mut DirectProvider {
        match &mut p.kind {
            ProviderKind::Direct(d) => d,
            _ => panic!("expected Direct provider"),
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

    /// `codec_covered` 与 `codec::Protocol::from_native` 的 Some 集合同一事实两处
    /// 编码 (from_native 有 `_ => None` 通配, 漏更新不报编译错) — 本测试双向锁死:
    /// 将来任一侧新增协议覆盖 (如 Gemini codec) 而忘改另一侧会在此红灯
    /// (WebUI 词表静默隐藏 / 静默放行均不可接受).
    #[test]
    fn test_codec_covered_matches_codec_from_native() {
        for (proto, _, _) in Protocol::ALL {
            assert_eq!(
                proto.codec_covered(),
                crate::codec::Protocol::from_native(proto).is_some(),
                "codec_covered 与 codec::Protocol::from_native 对 {proto} 不一致"
            );
        }
    }

    #[test]
    fn validate_base_url_rejects_bad_inputs() {
        assert!(validate_base_url("").is_err());
        assert!(validate_base_url("ftp://x").is_err());
        assert!(validate_base_url("http://x/").is_err());
        assert!(validate_base_url("https://api.openai.com").is_ok());
        assert!(validate_base_url("http://localhost:11434").is_ok());
    }

    // ─── multi-endpoint: select_endpoint 三态 (D2 语义核心) ──────────────

    /// 双端点 (openai 首, anthropic 次):
    /// - ingress 精确匹配 → (该端点, exact=true) — 命中者与声明序无关;
    /// - ingress 无匹配 → (首端点, exact=false) — fallback 走跨协议翻译.
    #[test]
    fn select_endpoint_exact_match_and_fallback() {
        let mut d = direct(&p("x", Protocol::OpenAI, "https://openai-first")).clone();
        d.endpoints.push(Endpoint::new(
            Protocol::Anthropic,
            "https://anthropic-second",
        ));

        let (e, exact) = d.select_endpoint(Protocol::Anthropic).unwrap();
        assert!(exact);
        assert_eq!(e.base_url, "https://anthropic-second");

        let (e, exact) = d.select_endpoint(Protocol::OpenAI).unwrap();
        assert!(exact, "首端点自身协议也是精确匹配");
        assert_eq!(e.base_url, "https://openai-first");

        // 未配置的协议 → 首端点 fallback (声明序).
        let (e, exact) = d.select_endpoint(Protocol::OpenAIResponses).unwrap();
        assert!(!exact);
        assert_eq!(e.base_url, "https://openai-first");
    }

    /// 单端点退化 (D2: 单端点配置下行为与演进前逐字节一致): 匹配 → exact;
    /// 不匹配 → 首端点 (即唯一端点) + exact=false, 与旧 "ingress != provider.protocol
    /// 走跨协议翻译" 等价.
    #[test]
    fn select_endpoint_single_endpoint_degenerates() {
        let d = direct(&p("x", Protocol::OpenAI, "https://only")).clone();
        let (e, exact) = d.select_endpoint(Protocol::OpenAI).unwrap();
        assert!(exact);
        assert_eq!(e.base_url, "https://only");

        let (e, exact) = d.select_endpoint(Protocol::Gemini).unwrap();
        assert!(!exact, "单端点 + 异协议 ingress → 首端点 fallback");
        assert_eq!(e.base_url, "https://only");
    }

    /// 空 endpoints 是绕过 validate 的非法配置 (serde default 容忍字段缺席) —
    /// select 返回 None 而非 panic, dispatch 据此 503 (ROB).
    #[test]
    fn select_endpoint_empty_returns_none() {
        let d = DirectProvider {
            endpoints: vec![],
            api_key: String::new(),
            api_key_file: None,
        };
        assert!(d.select_endpoint(Protocol::OpenAI).is_none());
    }

    // FWD-5 端点选择 property (multi-endpoint D2, contracts.md): 上方三个确定性
    // 用例锁定具体边界, 本 property 对任意 (endpoints, ingress) 组合穷举性质 —
    // 两者独立形式化 (§0.4 冗余覆盖: 单点定位 vs 全空间扫描).

    /// 任意协议子集 (无重复 — 与 validate 的协议唯一约束同构) 的**随机排列**.
    /// 覆盖度 (§0.3-3): 空集 (全假, "绕过 validate 的非法配置" → None 路径) /
    /// 单协议 (恰 1 真) / 多协议 (≥2 真) 全空间, 且排列随机 — fallback 断言
    /// (¬exact ⇒ 首端点) 能区分 "声明序首" 与 "固定协议偏好" (如 "openai 优先")
    /// 两类回归 (生成器太窄的历史教训, §0.3-3).
    fn arb_endpoint_protocols() -> impl Strategy<Value = Vec<Protocol>> {
        proptest::collection::vec(any::<bool>(), Protocol::ALL.len())
            .prop_map(|flags| {
                Protocol::ALL
                    .iter()
                    .zip(flags)
                    .filter_map(|((p, _, _), on)| on.then_some(*p))
                    .collect::<Vec<_>>()
            })
            .prop_shuffle()
    }

    proptest! {
        /// ∀ (endpoints, ingress): 空 → None; 否则 (e, exact) 满足
        /// e ∈ endpoints ∧ exact ⟺ ∃ x.protocol == ingress (双向蕴含) ∧
        /// exact ⇒ e 为列表序首个匹配者 ∧ ¬exact ⇒ e == 首端点 (fallback 序, D2).
        #[test]
        fn prop_select_endpoint_membership_exactness_fallback(
            protocols in arb_endpoint_protocols(),
            ingress in proptest::sample::select(
                Protocol::ALL.iter().map(|(p, _, _)| *p).collect::<Vec<_>>(),
            ),
        ) {
            // base_url 内嵌位置下标 (生成器内唯一) — 端点身份的判别依据
            // (Endpoint 无 Ord, 用 base_url 比对位置).
            let d = DirectProvider {
                endpoints: protocols
                    .iter()
                    .enumerate()
                    .map(|(i, p)| Endpoint::new(*p, &format!("https://u-{i}")))
                    .collect(),
                api_key: String::new(),
                api_key_file: None,
            };
            match d.select_endpoint(ingress) {
                None => prop_assert!(
                    protocols.is_empty(),
                    "None 仅当空 endpoints (非法配置, ROB)"
                ),
                Some((e, exact)) => {
                    let first_match = protocols.iter().position(|p| *p == ingress);
                    prop_assert_eq!(
                        exact,
                        first_match.is_some(),
                        "exact ⟺ ∃ endpoint.protocol == ingress"
                    );
                    match first_match {
                        Some(i) => prop_assert_eq!(
                            &e.base_url,
                            &format!("https://u-{i}"),
                            "exact: 列表序首个 (且唯一, validate 协议唯一) 匹配者"
                        ),
                        None => prop_assert_eq!(
                            &e.base_url,
                            "https://u-0",
                            "无匹配 → 首端点 (fallback 序, D2)"
                        ),
                    }
                }
            }
        }
    }

    // ─── multi-endpoint: validate 三规则 (§5.5) ──────────────────────────

    #[test]
    fn validate_rejects_empty_endpoints() {
        let mut prov = p("x", Protocol::OpenAI, "https://x");
        direct_mut(&mut prov).endpoints.clear();
        let err = prov.validate().unwrap_err();
        assert!(err.contains("at least one endpoint"), "got: {err}");
    }

    #[test]
    fn validate_rejects_duplicate_endpoint_protocol() {
        let mut prov = p("x", Protocol::OpenAI, "https://x");
        direct_mut(&mut prov)
            .endpoints
            .push(Endpoint::new(Protocol::OpenAI, "https://x2"));
        let err = prov.validate().unwrap_err();
        // message 指明重复的 protocol 名 (定位友好).
        assert!(
            err.contains("multiple endpoints") && err.contains("openai"),
            "got: {err}"
        );
        // 不同协议的多端点合法.
        let mut prov = p("x", Protocol::OpenAI, "https://x");
        direct_mut(&mut prov)
            .endpoints
            .push(Endpoint::new(Protocol::Anthropic, "https://x2"));
        assert!(prov.validate().is_ok());
    }

    /// 每 endpoint 的 base_url 过 validate_base_url (复用), 错误文案携带
    /// endpoint 定位 (序号 + 协议名).
    #[test]
    fn validate_rejects_bad_endpoint_base_url_with_location() {
        let mut prov = p("x", Protocol::OpenAI, "https://x");
        direct_mut(&mut prov)
            .endpoints
            .push(Endpoint::new(Protocol::Anthropic, "not-a-url"));
        let err = prov.validate().unwrap_err();
        assert!(
            err.contains("endpoint #1") && err.contains("anthropic"),
            "got: {err}"
        );
        assert!(err.contains("base_url"), "got: {err}");
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
            kind = "direct"
            endpoints = [ { protocol = "openai", base_url = "https://api.example.com" } ]
            api_key_file = "/run/secrets/test-key"
            enabled = true
        "#;
        let p: Provider = toml::from_str(toml_text).expect("toml parse");
        let ProviderKind::Direct(d) = &p.kind else {
            panic!("direct provider must parse as Direct");
        };
        assert_eq!(
            d.api_key_file.as_deref(),
            Some(std::path::Path::new("/run/secrets/test-key"))
        );
        assert_eq!(d.api_key, ""); // 默认值
    }

    #[test]
    fn toml_direct_without_api_key_file_still_works() {
        // 只有 api_key (无 api_key_file) 的条目必须仍然能解析.
        let toml_text = r#"
            id = "test"
            kind = "direct"
            endpoints = [ { protocol = "openai", base_url = "https://api.example.com" } ]
            api_key = "sk-legacy"
            enabled = true
        "#;
        let p: Provider = toml::from_str(toml_text).expect("toml parse");
        let ProviderKind::Direct(d) = &p.kind else {
            panic!("direct provider must parse as Direct");
        };
        assert_eq!(d.api_key, "sk-legacy");
        assert!(d.api_key_file.is_none());
    }

    /// multi-endpoint TOML round-trip (§5.2 形态 SSOT): `[[providers.endpoints]]`
    /// 平铺数组写出 → 读回, 端点序 / per-endpoint common_uri (含 None skip 形态)
    /// / 共享 api_key 均无损存活.
    #[test]
    fn toml_multi_endpoint_roundtrip_preserves_order_and_common_uri() {
        let mut prov = p(
            "zhipu",
            Protocol::OpenAI,
            "https://open.bigmodel.cn/api/paas/v4",
        );
        direct_mut(&mut prov).endpoints.push(Endpoint {
            protocol: Protocol::Anthropic,
            base_url: "https://open.bigmodel.cn/api/anthropic".into(),
            common_uri: Some(String::new()), // "" 显式布局断言必须写出 (非 None skip)
        });
        direct_mut(&mut prov).endpoints[0].common_uri = Some("/api/paas/v4".into());
        direct_mut(&mut prov).api_key = "sk-shared".into();

        let text = toml::to_string(&prov).unwrap();
        let back: Provider = toml::from_str(&text).unwrap();
        let d = direct(&back);
        assert_eq!(d.endpoints.len(), 2);
        // 数组序 = fallback 序, 必须无损.
        assert_eq!(d.endpoints[0].protocol, Protocol::OpenAI);
        assert_eq!(
            d.endpoints[0].base_url,
            "https://open.bigmodel.cn/api/paas/v4"
        );
        assert_eq!(d.endpoints[0].common_uri.as_deref(), Some("/api/paas/v4"));
        assert_eq!(d.endpoints[1].protocol, Protocol::Anthropic);
        assert_eq!(
            d.endpoints[1].common_uri.as_deref(),
            Some(""),
            "空串 common_uri 是显式布局断言, 不与 None (skip) 混淆"
        );
        assert_eq!(d.api_key, "sk-shared", "api_key 共享于构造层 (D3)");
    }

    // ─── DynamicEntry impl: Provider 特有的 validate 钩子 ───────────────

    #[test]
    fn validate_rejects_bad_id_and_base_url() {
        // id 校验失败.
        let mut bad_id = p("ok", Protocol::OpenAI, "https://x");
        bad_id.id = "has space".into();
        assert!(bad_id.validate().is_err());

        // base_url 校验失败.
        let bad_url = p("x", Protocol::OpenAI, "not-a-url");
        assert!(bad_url.validate().is_err());

        // 合法 provider 通过.
        assert!(p("ok", Protocol::OpenAI, "https://x").validate().is_ok());
    }

    #[test]
    fn validate_rejects_api_key_and_file_both_set() {
        let mut both = p("x", Protocol::OpenAI, "https://x");
        direct_mut(&mut both).api_key = "sk-direct".into();
        direct_mut(&mut both).api_key_file = Some(PathBuf::from("/run/secrets/whatever"));
        let err = both.validate().unwrap_err();
        assert!(err.contains("both api_key and api_key_file"), "got: {err}");
    }

    // ─── common_uri: 值域校验 (detect 知识的持久化形态) ────────────────────

    #[test]
    fn validate_common_uri_accepts_legal_forms() {
        // 合法: None (未探测) / "" (版本前缀已含) / "/v1" (裸根) / 多级 / 有界长度.
        let legal = [
            None,
            Some(""),
            Some("/v1"),
            Some("/api/paas/v4"),
            Some(&"/a".repeat(30)),
        ];
        for cu in legal {
            let mut prov = p("ok", Protocol::OpenAI, "https://x");
            direct_mut(&mut prov).endpoints[0].common_uri = cu.map(str::to_string);
            assert!(prov.validate().is_ok(), "cu={cu:?} should be legal");
        }
    }

    #[test]
    fn validate_common_uri_rejects_malformed() {
        let bad = [
            Some("v1"),            // 缺前导 /
            Some("/v1/"),          // 尾斜杠
            Some("/v1?x"),         // query 分隔符
            Some("/a#b"),          // fragment 分隔符
            Some("/a b"),          // 空格
            Some(&"/".repeat(65)), // 超长 (>64)
            Some("/"),             // 仅斜杠 (等价空前缀但非规范形态)
        ];
        for cu in bad {
            let mut prov = p("x", Protocol::OpenAI, "https://x");
            direct_mut(&mut prov).endpoints[0].common_uri = cu.map(str::to_string);
            assert!(
                prov.validate().unwrap_err().contains("common_uri"),
                "cu={cu:?} should be rejected"
            );
        }
    }

    // ─── effective_api_key: api_key 直接值 vs api_key_file ──────────────────

    #[test]
    fn effective_api_key_prefers_direct_value() {
        // 即便 api_key_file 指向不存在的文件, 直接值优先 (且 validate 不会让你同时设两者).
        let mut p = p("x", Protocol::OpenAI, "https://x");
        direct_mut(&mut p).api_key = "sk-direct".into();
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

        let mut p = p("x", Protocol::OpenAI, "https://x");
        direct_mut(&mut p).api_key = String::new();
        direct_mut(&mut p).api_key_file = Some(tmp.clone());
        assert_eq!(direct(&p).effective_api_key("x"), "sk-from-file");

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn effective_api_key_missing_file_returns_empty() {
        // 单 provider 配置错误不应拖垮整个进程 — 返回空让 apply_provider_auth 跳过.
        let mut p = p("x", Protocol::OpenAI, "https://x");
        direct_mut(&mut p).api_key = String::new();
        direct_mut(&mut p).api_key_file = Some(PathBuf::from("/nonexistent/path/should/not/exist"));
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
        let make_provider = || {
            let mut p = p(&pid, Protocol::OpenAI, "https://x");
            direct_mut(&mut p).api_key = String::new();
            direct_mut(&mut p).api_key_file = Some(tmp.clone());
            p
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
        let mut p = p(&pid, Protocol::OpenAI, "https://x");
        direct_mut(&mut p).api_key = String::new();
        direct_mut(&mut p).api_key_file = Some(PathBuf::from("/nonexistent/warn-once-test"));
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
        let mut p = p("x", Protocol::OpenAI, "https://x");
        direct_mut(&mut p).api_key = String::new();
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
        let EffectiveProviderKind::Direct { endpoints, .. } = &ov.kind else {
            panic!("override-id must be Direct");
        };
        assert_eq!(
            endpoints.first().map(|e| (e.protocol, e.base_url.as_str())),
            Some((Protocol::Gemini, "https://dynamic-override"))
        );
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
            first_url(direct(&d)),
            "https://d",
            "non-auth fields must stay from override"
        );
    }

    /// multi-endpoint 合并语义 (§5.6): `endpoints` **整体替换** — dynamic
    /// override 携带的 endpoints 整个覆盖 static (不做按 protocol 键的字段级
    /// 合并, 数组序是 fallback 序); #157 鉴权继承只触及 api_key/api_key_file,
    /// endpoints 完全来自 override (无 "None → 继承 static" 的回填语义 —
    /// wire 层全量必填, 由 integration 的 partial PUT 400 测试锁定).
    #[test]
    fn effective_endpoints_replaced_wholesale_and_auth_inherited() {
        let tmp = tempfile_path();
        let mut s = p("x", Protocol::OpenAI, "https://static-openai");
        direct_mut(&mut s).endpoints.push(Endpoint::new(
            Protocol::Anthropic,
            "https://static-anthropic",
        ));
        direct_mut(&mut s).api_key = "sk-static".into();
        // override 只带一个 anthropic 端点 (窄于 static), api_key 未记录 (#157).
        let mut d = p("x", Protocol::Anthropic, "https://override-anthropic");
        direct_mut(&mut d).api_key = String::new();
        let t = ProviderTable::new(vec![s], vec![d], empty_decisions(), tmp);

        let eff = t.get_effective("x").unwrap();
        let d = direct(&eff);
        // 整体替换: 恰是 override 的单端点列表 — 非 static 两端点的并集/子集.
        assert_eq!(d.endpoints.len(), 1);
        assert_eq!(d.endpoints[0].protocol, Protocol::Anthropic);
        assert_eq!(first_url(d), "https://override-anthropic");
        // 鉴权继承照常 (#157 语义不受 endpoints 影响).
        assert_eq!(d.api_key, "sk-static");
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
        assert_eq!(first_url(direct(&eff)), "https://d");
        assert_eq!(direct(&eff).api_key, "sk-static");

        // PreferStatic: static 本身被选中, 继承无意义但也无害.
        t.set_decision("x", OverrideMode::PreferStatic).unwrap();
        let eff = t.get_effective("x").unwrap();
        assert_eq!(first_url(direct(&eff)), "https://s");
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

    // ─── wildcard_match (路由 model_pattern 通配语义) ────────────────────
    //
    // 仅 '*' 是元字符; 大小写敏感; "*" 匹配一切 (含空串); "**" 折叠为 "*".

    #[test]
    fn wildcard_match_exact_name() {
        assert!(wildcard_match("gpt-4o", "gpt-4o"));
        assert!(!wildcard_match("gpt-4o", "gpt-4o-mini"));
        assert!(!wildcard_match("gpt-4o", "GPT-4O"), "大小写敏感");
        // 无 '*' 的 pattern 退化为字面全等 (含空串边界).
        assert!(wildcard_match("", ""));
        assert!(!wildcard_match("", "x"));
    }

    #[test]
    fn wildcard_match_prefix_suffix_infix() {
        // 前缀 "gpt-*".
        assert!(wildcard_match("gpt-*", "gpt-4o"));
        assert!(wildcard_match("gpt-*", "gpt-"));
        assert!(!wildcard_match("gpt-*", "xgpt-4o"));
        assert!(!wildcard_match("gpt-*", "claude-3"));
        // 后缀 "*-mini".
        assert!(wildcard_match("*-mini", "gpt-4o-mini"));
        assert!(!wildcard_match("*-mini", "gpt-4o"));
        // 中缀 "gpt-*-mini".
        assert!(wildcard_match("gpt-*-mini", "gpt-4o-mini"));
        assert!(wildcard_match("gpt-*-mini", "gpt--mini"), "空中段");
        assert!(!wildcard_match("gpt-*-mini", "gpt-4o"));
        assert!(!wildcard_match("gpt-*-mini", "claude-4o-mini"));
        // 多段组合 "*a*".
        assert!(wildcard_match("*a*", "bab"));
        assert!(!wildcard_match("*a*", "bb"));
    }

    #[test]
    fn wildcard_match_star_matches_all_including_empty() {
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("*", "a*b*c"));
    }

    #[test]
    fn wildcard_match_consecutive_stars_collapse() {
        // "**" 等价 "*" (空段跳过).
        assert!(wildcard_match("**", "x"));
        assert!(wildcard_match("**", ""));
        assert!(wildcard_match("a**b", "axbxb"));
        assert!(!wildcard_match("a**b", "b"));
    }

    /// 独立朴素参考实现 (递归回溯) — 与主实现的分段扫描写法**刻意不同**,
    /// 供 proptest 交叉验证 (同构复用主实现逻辑无意义). 字节级递归与主实现的
    /// str 级匹配等价: `*` 是单字节 ASCII, 不会落入多字节 UTF-8 序列中间,
    /// 字节序相等 ⇔ 字符串相等 (生成器含多字节字符, 覆盖此等价性).
    fn wildcard_match_reference(pattern: &str, name: &str) -> bool {
        fn go(p: &[u8], n: &[u8]) -> bool {
            match p.first() {
                None => n.is_empty(),
                Some(b'*') => (0..=n.len()).any(|skip| go(&p[1..], &n[skip..])),
                Some(&c) => n.first() == Some(&c) && go(&p[1..], &n[1..]),
            }
        }
        go(pattern.as_bytes(), name.as_bytes())
    }

    proptest! {
        /// 基本性质: 对任意 s, pattern "{s}*{s}" 必匹配 "{s}{s}".
        #[test]
        fn prop_wildcard_split_pattern_matches_concat(s in "[a-z0-9-]{0,12}") {
            let pattern = format!("{s}*{s}");
            let name = format!("{s}{s}");
            prop_assert!(wildcard_match(&pattern, &name),
                "pattern={pattern:?} name={name:?}");
        }

        /// 基本性质: wildcard_match("*", x) 恒真 (含空串).
        #[test]
        fn prop_wildcard_star_matches_anything(x in "[a-zA-Z0-9-]{0,16}") {
            prop_assert!(wildcard_match("*", &x));
        }

        /// 主实现 vs 参考实现一致性: 任意 pattern/name 组对结果相同.
        /// 生成器: 字面段 ([a-z0-9é-], 可空 → 覆盖首尾 '*' / 连续 '**' 折叠 /
        /// 无 '*' 纯字面) 以 '*' join 拼 pattern; 单段 = 无通配符边界.
        /// 字符集含多字节字符 é → 非 ASCII 输入下的字节级/字符级等价性获得
        /// 覆盖 (安全性: `*` 是单字节 ASCII, 不会落入多字节序列中间).
        #[test]
        fn prop_wildcard_matches_reference_impl(
            lit_segs in proptest::collection::vec("[a-z0-9é-]{0,4}", 1..6),
            name in "[a-z0-9é-]{0,12}",
        ) {
            let pattern = lit_segs.join("*");
            // 注: prop_assert_eq 的消息经 concat! 展开, 不支持内联捕获,
            // 用位置参数传诊断值.
            prop_assert_eq!(
                wildcard_match(&pattern, &name),
                wildcard_match_reference(&pattern, &name),
                "pattern={:?} name={:?}",
                pattern,
                name
            );
        }
    }

    // ─── 路由选择 (RouterProvider::select_route) ─────────────────────────
    //
    // 语义: 启用 (priority 非 None) 且匹配的路由中 priority 最大者;
    // 并列按列表出现顺序先者; 禁用路由不参与.

    #[test]
    fn select_route_highest_priority_wins() {
        let rp = RouterProvider {
            routes: vec![
                route("gpt-*", "low"),
                Route {
                    model_pattern: "gpt-4*".into(),
                    target: "high".into(),
                    upstream_model: None,
                    priority: Some(100),
                },
                route("*", "fallback"),
            ],
        };
        assert_eq!(rp.select_route("gpt-4o").unwrap().target, "high");
        // 宽 pattern 低优先级只在高优先级路由不匹配时兜底.
        assert_eq!(rp.select_route("claude-3").unwrap().target, "fallback");
    }

    #[test]
    fn select_route_tie_breaks_by_list_order() {
        // 同 priority 两条都匹配 → 列表序先者 (用户认可的确定性 tie-break).
        let rp = RouterProvider {
            routes: vec![route("*", "first"), route("*", "second")],
        };
        assert_eq!(rp.select_route("m").unwrap().target, "first");
    }

    #[test]
    fn select_route_skips_disabled_routes() {
        // priority None = 禁用: 匹配也不选, 落到次优启用路由.
        let mut disabled = route("gpt-*", "disabled-target");
        disabled.priority = None;
        let rp = RouterProvider {
            routes: vec![disabled, route("*", "fallback")],
        };
        assert_eq!(rp.select_route("gpt-4o").unwrap().target, "fallback");
        // 全禁用 → None (resolve_route 层表现为 NoMatch).
        let mut all_off = route("*", "x");
        all_off.priority = None;
        let rp2 = RouterProvider {
            routes: vec![all_off],
        };
        assert!(rp2.select_route("gpt-4o").is_none());
    }

    // ─── validate: Router 构造的路由校验 ────────────────────────────────

    #[test]
    fn validate_router_rejects_empty_routes() {
        let err = router("r", vec![]).validate().unwrap_err();
        assert!(err.contains("at least one route"), "got: {err}");
    }

    #[test]
    fn validate_router_rejects_bad_model_patterns() {
        // 空 model_pattern.
        assert!(router("r", vec![route("", "real")]).validate().is_err());
        // 恰 64 chars 合法 (边界), 65 拒绝.
        assert!(
            router("r", vec![route(&"a".repeat(64), "real")])
                .validate()
                .is_ok()
        );
        assert!(
            router("r", vec![route(&"a".repeat(65), "real")])
                .validate()
                .is_err()
        );
    }

    #[test]
    fn validate_router_semantics() {
        // 合法: 目标 id 合法且非自环; 重复 model_pattern / 重复 priority 合法 (tie 按列表序).
        assert!(router("r", vec![route("*", "real")]).validate().is_ok());
        assert!(
            router("r", vec![route("*", "a"), route("*", "b")])
                .validate()
                .is_ok()
        );
        // 目标 id 非法.
        assert!(
            router("r", vec![route("*", "has space")])
                .validate()
                .is_err()
        );
        // 自环 (启用路由拒绝).
        let err = router("r", vec![route("*", "r")]).validate().unwrap_err();
        assert!(err.contains("routes to itself"), "got: {err}");
        // 禁用自环路由合法 — 与 would_cycle "禁用路由不构成环检查的边" 对齐
        // (用户暂存一条自指路由不被 400 拒绝).
        let mut disabled_self = route("*", "r");
        disabled_self.priority = None;
        assert!(router("r", vec![disabled_self]).validate().is_ok());
        // 实体: 空 base_url 仍然拒绝 (现有行为不变).
        assert!(p("x", Protocol::OpenAI, "").validate().is_err());
    }

    #[test]
    fn validate_router_route_upstream_model_hygiene() {
        // route.upstream_model 的输入卫生: 空串 / 纯空白 / 超长 (>128) 拒绝.
        for bad in ["", "   ", &"m".repeat(129)] {
            let mut ru = route("*", "real");
            ru.upstream_model = Some(bad.into());
            assert!(router("r", vec![ru]).validate().is_err(), "model={bad:?}");
        }
        // 正常值 / 恰 128 chars (边界) / None 合法.
        let mut ok = route("*", "real");
        ok.upstream_model = Some("gpt-4o".into());
        assert!(router("r", vec![ok]).validate().is_ok());
        let mut edge = route("*", "real");
        edge.upstream_model = Some("m".repeat(128));
        assert!(router("r", vec![edge]).validate().is_ok());
    }

    // ─── 路由 provider 解析 (#179 多规则化): resolve_route / would_cycle ──
    //
    // 契约: FWD-5 (per-request 解析 / 坏路由 503 / 环终止 / NoMatch).

    /// 表: real → mock 上游; rt2 → real; rt1 → rt2 (两跳链).
    fn route_table() -> ProviderTable {
        let mut real = p("real", Protocol::OpenAI, "https://upstream");
        direct_mut(&mut real).api_key = "sk-real".into();
        let rt2 = router_to("rt2", "real");
        let rt1 = router_to("rt1", "rt2");
        ProviderTable::new(
            vec![real, rt2, rt1],
            vec![],
            empty_decisions(),
            tempfile_path(),
        )
    }

    #[test]
    fn resolve_route_real_provider_passthrough() {
        // Direct provider 原样返回, 零额外跳; 无路由改写.
        let t = route_table();
        let real = t.get_effective("real").unwrap();
        let out = t
            .resolve_route(&real, "any-model", &PoolStates::new())
            .unwrap();
        assert_eq!(out.id, "real");
        assert_eq!(first_url(&out.provider), "https://upstream");
        assert_eq!(
            out.provider.api_key, "sk-real",
            "resolved provider carries real key"
        );
        assert_eq!(out.model_rewrite, None, "no route rewrite on direct entry");
    }

    #[test]
    fn resolve_route_follows_chain_to_real_provider() {
        // rt1 → rt2 → real: 解析到链尾实体, 携带其实体字段 (base_url/api_key).
        let t = route_table();
        let rt1 = t.get_effective("rt1").unwrap();
        let out = t.resolve_route(&rt1, "gpt-4o", &PoolStates::new()).unwrap();
        assert_eq!(out.id, "real");
        assert_eq!(first_url(&out.provider), "https://upstream");
        assert_eq!(out.provider.api_key, "sk-real");
    }

    #[test]
    fn resolve_route_missing_target() {
        let t = ProviderTable::new(
            vec![router_to("rt", "ghost")],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let err = t
            .resolve_route(&t.get_effective("rt").unwrap(), "m", &PoolStates::new())
            .unwrap_err();
        assert_eq!(err, RouteError::Missing("ghost".into()));
        assert!(err.to_string().contains("ghost"), "msg names the id: {err}");
    }

    #[test]
    fn resolve_route_disabled_target() {
        let mut real = p("real", Protocol::OpenAI, "https://u");
        real.enabled = false;
        let t = ProviderTable::new(
            vec![real, router_to("rt", "real")],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        // 入口 provider 自身 disabled 在 dispatch 层已挡 (503); 这里测链上中间跳.
        let err = t
            .resolve_route(&t.get_effective("rt").unwrap(), "m", &PoolStates::new())
            .unwrap_err();
        assert_eq!(err, RouteError::Disabled("real".into()));
    }

    #[test]
    fn resolve_route_detects_cycles() {
        // 双节点环 (绕过 validate 直接构造 — 模拟手改 state.toml 的运行时兜底场景).
        let t = ProviderTable::new(
            vec![router_to("a", "b"), router_to("b", "a")],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let err = t
            .resolve_route(&t.get_effective("a").unwrap(), "m", &PoolStates::new())
            .unwrap_err();
        assert_eq!(err, RouteError::Cycle("a".into()));

        // 自环 (单节点).
        let t2 = ProviderTable::new(
            vec![router_to("s", "s")],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        assert!(matches!(
            t2.resolve_route(&t2.get_effective("s").unwrap(), "m", &PoolStates::new()),
            Err(RouteError::Cycle(_))
        ));
    }

    #[test]
    fn resolve_route_no_matching_route() {
        // 启用路由中无 model_pattern 匹配请求 model → NoMatch (id + model 名进 503 body).
        let t = ProviderTable::new(
            vec![
                router("rt", vec![route("gpt-*", "real")]),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let err = t
            .resolve_route(
                &t.get_effective("rt").unwrap(),
                "claude-3",
                &PoolStates::new(),
            )
            .unwrap_err();
        assert_eq!(
            err,
            RouteError::NoMatch {
                id: "rt".into(),
                model: "claude-3".into(),
            }
        );
        assert!(err.to_string().contains("no route matching"), "msg: {err}");
        assert!(err.to_string().contains("rt") && err.to_string().contains("claude-3"));

        // 全禁用路由同样 NoMatch (禁用 = 不存在).
        let mut all_off = route("*", "real");
        all_off.priority = None;
        let t2 = ProviderTable::new(
            vec![router("rt", vec![all_off])],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        assert!(matches!(
            t2.resolve_route(&t2.get_effective("rt").unwrap(), "m", &PoolStates::new()),
            Err(RouteError::NoMatch { .. })
        ));
    }

    /// m2: NoMatch 回显的 model 在**构造处**截断 (超长 model 名不进 503 body
    /// / WARN 日志, 防洪水). 边界: 恰 64 chars 原样, 65 起截断 + `…` 后缀.
    #[test]
    fn resolve_route_no_match_model_truncated_for_echo() {
        // helper 边界 (64 原样 / 65 = 64 chars + 省略号).
        assert_eq!(
            truncate_model_for_echo(&"m".repeat(64)),
            "m".repeat(64),
            "exactly at limit: no truncation"
        );
        let got = truncate_model_for_echo(&"m".repeat(100));
        assert_eq!(got.chars().count(), NOMATCH_MODEL_ECHO_LIMIT + 1);
        assert!(got.starts_with(&"m".repeat(NOMATCH_MODEL_ECHO_LIMIT)));
        assert!(got.ends_with('…'));

        // 全链锁定: resolve_route 产出的 NoMatch 值已截断 (Display/503 同源).
        let t = ProviderTable::new(
            vec![
                router("rt", vec![route("gpt-*", "real")]),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let err = t
            .resolve_route(
                &t.get_effective("rt").unwrap(),
                &"x".repeat(100),
                &PoolStates::new(),
            )
            .unwrap_err();
        match err {
            RouteError::NoMatch { model, .. } => {
                assert_eq!(model.chars().count(), NOMATCH_MODEL_ECHO_LIMIT + 1);
                assert!(model.ends_with('…'));
            }
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    #[test]
    fn resolve_route_routes_by_request_model() {
        // 多路由按请求 model 分流: gpt-* → real1, 其余 → real2.
        let t = ProviderTable::new(
            vec![
                router("rt", vec![route("gpt-*", "real1"), route("*", "real2")]),
                p("real1", Protocol::OpenAI, "https://u1"),
                p("real2", Protocol::OpenAI, "https://u2"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let entry = t.get_effective("rt").unwrap();
        assert_eq!(
            t.resolve_route(&entry, "gpt-4o", &PoolStates::new())
                .unwrap()
                .id,
            "real1"
        );
        assert_eq!(
            t.resolve_route(&entry, "claude-3", &PoolStates::new())
                .unwrap()
                .id,
            "real2"
        );
        // 空 model (非 JSON / 无 model 字段请求): 只匹配 "*".
        assert_eq!(
            t.resolve_route(&entry, "", &PoolStates::new()).unwrap().id,
            "real2"
        );
    }

    #[test]
    fn resolve_route_model_rewrite_pipeline_feeds_next_hop() {
        // pipeline 语义锁定: rt1 路由改写 model=claude-3 后, rt2 必须按**改写后**
        // 的 model 匹配 (而非请求原 model gpt-4o) — rt2 只有 claude-* 路由能到达
        // real, "错误" 路由 (匹配 gpt-*) 指向不存在目标.
        let t = ProviderTable::new(
            vec![
                router(
                    "rt1",
                    vec![Route {
                        model_pattern: "gpt-*".into(),
                        target: "rt2".into(),
                        upstream_model: Some("claude-3".into()),
                        priority: Some(0),
                    }],
                ),
                router(
                    "rt2",
                    vec![route("claude-*", "real"), route("gpt-*", "wrong-ghost")],
                ),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let out = t
            .resolve_route(
                &t.get_effective("rt1").unwrap(),
                "gpt-4o",
                &PoolStates::new(),
            )
            .unwrap();
        assert_eq!(out.id, "real", "rt2 matched rewritten model");
        assert_eq!(out.model_rewrite.as_deref(), Some("claude-3"));

        // 对照: 直入 rt2 (无改写) — 请求 model 自行匹配, 无 override.
        let out2 = t
            .resolve_route(
                &t.get_effective("rt2").unwrap(),
                "claude-3",
                &PoolStates::new(),
            )
            .unwrap();
        assert_eq!(out2.id, "real");
        assert_eq!(out2.model_rewrite, None);
    }

    #[test]
    fn resolve_route_later_rewrite_overrides_earlier() {
        // 多跳改写: 后者覆盖前者 (pipeline, 非 first-wins).
        let t = ProviderTable::new(
            vec![
                router(
                    "rt1",
                    vec![Route {
                        model_pattern: "*".into(),
                        target: "rt2".into(),
                        upstream_model: Some("model-a".into()),
                        priority: Some(0),
                    }],
                ),
                router(
                    "rt2",
                    vec![Route {
                        model_pattern: "*".into(),
                        target: "real".into(),
                        upstream_model: Some("model-b".into()),
                        priority: Some(0),
                    }],
                ),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let out = t
            .resolve_route(
                &t.get_effective("rt1").unwrap(),
                "gpt-4o",
                &PoolStates::new(),
            )
            .unwrap();
        assert_eq!(out.id, "real");
        assert_eq!(out.model_rewrite.as_deref(), Some("model-b"));
    }

    #[test]
    fn resolve_route_without_upstream_model_passes_through() {
        // 路由无 upstream_model → 透传; 下游 router 按请求原 model 匹配.
        let t = ProviderTable::new(
            vec![
                router("rt1", vec![route("*", "rt2")]),
                router("rt2", vec![route("gpt-*", "real1"), route("*", "real2")]),
                p("real1", Protocol::OpenAI, "https://u1"),
                p("real2", Protocol::OpenAI, "https://u2"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let out = t
            .resolve_route(
                &t.get_effective("rt1").unwrap(),
                "gpt-4o",
                &PoolStates::new(),
            )
            .unwrap();
        assert_eq!(out.id, "real1", "no rewrite: next hop sees original model");
        assert_eq!(out.model_rewrite, None);
    }

    #[test]
    fn would_cycle_rejects_indirect_cycle() {
        // 已有 a → b; upsert b 的路由指向 a 形成环 → 必须拒绝.
        let t = ProviderTable::new(
            vec![
                router_to("a", "b"),
                router_to("b", "real"),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let b_to_a = router_to("b", "a");
        assert!(t.would_cycle(&b_to_a), "b→a closes the a→b cycle");
        // b → real (现状) 与 b → 悬空 都不成环.
        assert!(!t.would_cycle(&router_to("b", "real")));
        assert!(!t.would_cycle(&router_to("b", "ghost")));
        // 自环.
        assert!(t.would_cycle(&router_to("b", "b")));
    }

    #[test]
    fn would_cycle_updates_entry_in_place() {
        // upsert 替换已有条目: 表中 b → a 已有, 现在写入 a → b 也要识别为环
        // (walk 必须用新 entry 值覆盖旧值, 而非读到旧 a 的 Direct 构造而漏判).
        let t = ProviderTable::new(
            vec![
                router_to("a", "real"),
                router_to("b", "a"),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let a_to_b = router_to("a", "b");
        assert!(t.would_cycle(&a_to_b), "a→b closes the existing b→a cycle");
    }

    #[test]
    fn would_cycle_rejects_entry_reaching_existing_cycle() {
        // entry 不在环上但**可达**既有环 (手改 state 落库 a↔b 后, upsert 无辜
        // feeder c→a): 拒绝条件是 entry 可达子图存在环, 而非 entry 自身在环上.
        let t = ProviderTable::new(
            vec![
                router_to("a", "b"),
                router_to("b", "a"),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        assert!(
            t.would_cycle(&router_to("c", "a")),
            "c reaches the existing a↔b cycle"
        );
        assert!(!t.would_cycle(&router_to("c", "real")));
    }

    #[test]
    fn would_cycle_checks_every_enabled_route_branch() {
        // 多路由: b 的两条启用路由中一条回到 a → 环 (只走单链会漏判).
        let t = ProviderTable::new(
            vec![
                router_to("a", "b"),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let b_multi = router("b", vec![route("*", "real"), route("claude-*", "a")]);
        assert!(
            t.would_cycle(&b_multi),
            "any enabled branch closing a cycle counts"
        );

        // 同形状但回边禁用 (priority None) → 不构成环 (禁用路由不可遍历).
        let mut disabled_back = route("claude-*", "a");
        disabled_back.priority = None;
        let b_disabled = router("b", vec![route("*", "real"), disabled_back]);
        assert!(!t.would_cycle(&b_disabled), "disabled route is not an edge");
    }

    #[test]
    fn would_cycle_diamond_convergence_is_not_a_cycle() {
        // 汇聚型 DAG (两条路径到同一节点) 不是环 — 检测用递归 path 而非全局 visited.
        let t = ProviderTable::new(
            vec![
                router("entry", vec![route("a*", "mid1"), route("b*", "mid2")]),
                router_to("mid1", "tail"),
                router_to("mid2", "tail"),
                p("tail", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let entry = router("entry", vec![route("a*", "mid1"), route("b*", "mid2")]);
        assert!(
            !t.would_cycle(&entry),
            "converging DAG branches are not a cycle"
        );
    }

    // ─── find_cycles (启动诊断, #179 可选加固) ────────────────────────

    #[test]
    fn find_cycles_detects_two_node_cycle() {
        // static a→b + dynamic b→a 合并成环 — 正是既有拦截点都漏网的形态:
        // static validate 只查单条目 (自环), dynamic 落库不经 would_cycle
        // (手改 state.toml). 恰好检出 1 个环, 路径首尾相同.
        let t = ProviderTable::new(
            vec![
                router_to("a", "b"),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![router_to("b", "a")],
            empty_decisions(),
            tempfile_path(),
        );
        let cycles = t.find_cycles();
        assert_eq!(cycles.len(), 1, "a↔b closes exactly one cycle");
        assert_eq!(cycles[0], vec!["a", "b", "a"]);
    }

    #[test]
    fn find_cycles_empty_when_acyclic() {
        // 链式 (router→router→direct) 与汇聚 diamond 都无环 (不误报).
        let t = ProviderTable::new(
            vec![
                router("entry", vec![route("a*", "mid1"), route("b*", "mid2")]),
                router_to("mid1", "tail"),
                router_to("mid2", "tail"),
                router_to("chain", "entry"),
                p("tail", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        assert!(t.find_cycles().is_empty(), "chain + diamond have no cycle");
    }

    #[test]
    fn find_cycles_ignores_disabled_route_edges() {
        // 禁用路由 (priority=None) 不构成边: a→b (启用) + b→a (禁用) 不成环.
        let mut back = route("*", "a");
        back.priority = None;
        let t = ProviderTable::new(
            vec![
                router_to("a", "b"),
                router("b", vec![back]),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        assert!(t.find_cycles().is_empty(), "disabled route is not an edge");
    }

    #[test]
    fn find_cycles_dangling_target_is_not_a_cycle() {
        // dangling target 指向不存在的 id: 走到即止, 不算环 (与 resolve_route
        // 语义一致 — 目标缺失是请求期 503 的事).
        let t = ProviderTable::new(
            vec![
                router_to("a", "ghost"),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        assert!(
            t.find_cycles().is_empty(),
            "dangling target breaks the walk"
        );
    }

    #[test]
    fn find_cycles_detects_self_loop() {
        // dynamic 侧自环可绕过 static validate (fail-fast 只覆盖 static 加载)
        // 与 would_cycle (手改 state.toml 不经 upsert) 落库 — 启动诊断应检出.
        let t = ProviderTable::new(
            vec![p("real", Protocol::OpenAI, "https://u")],
            vec![router_to("a", "a")],
            empty_decisions(),
            tempfile_path(),
        );
        let cycles = t.find_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0], vec!["a", "a"]);
    }

    #[test]
    fn find_cycles_reports_shared_cycle_once() {
        // 环外 feeder c→a: a 的再入在 done 短路 (不同入口不会重新发现环),
        // 环仍恰好报一次.
        let t = ProviderTable::new(
            vec![
                router_to("a", "b"),
                router_to("b", "a"),
                router_to("c", "a"),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let cycles = t.find_cycles();
        assert_eq!(cycles.len(), 1, "feeder rediscovery deduped");
        assert_eq!(cycles[0], vec!["a", "b", "a"]);
    }

    #[test]
    fn find_cycles_dedupes_parallel_route_edges() {
        // 平行路由边: b 的两条启用路由指向同一 target a — 同一栈段会被报告
        // 两次, `seen` canonical 去重后只报一次 (enabled_targets_of 不去重
        // target, 不同 model_pattern 同 target 是完全合法配置).
        let t = ProviderTable::new(
            vec![
                router_to("a", "b"),
                router("b", vec![route("gpt-*", "a"), route("claude-*", "a")]),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let cycles = t.find_cycles();
        assert_eq!(cycles.len(), 1, "parallel edges to same target deduped");
        assert_eq!(cycles[0], vec!["a", "b", "a"]);
    }

    #[test]
    fn find_cycles_walks_extra_edges_off_cycle() {
        // 环上节点带额外出边 (b→[a, c], c 又指回环上的 b): 报告 a↔b 环后
        // walk 继续当前节点的其余边, b↔c 环也被检出 — 若实现改为报告后 break
        // 边循环, start c 时 b 已 done 会短路, 第二个环漏报 (本断言必红).
        let t = ProviderTable::new(
            vec![
                router_to("a", "b"),
                router("b", vec![route("*", "a"), route("gpt-*", "c")]),
                router_to("c", "b"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let mut cycles = t.find_cycles();
        cycles.sort();
        assert_eq!(cycles.len(), 2, "off-cycle edges keep being walked");
        assert_eq!(cycles[0], vec!["a", "b", "a"]);
        assert_eq!(cycles[1], vec!["b", "c", "b"]);
    }

    #[test]
    fn find_cycles_decision_disabled_breaks_cycle() {
        // decision=Disabled 把环上条目从 effective 视图排除 → 边消失, 不成环
        // (doc 承诺的 decision-disabled 排除语义).
        let t = ProviderTable::new(
            vec![
                router_to("a", "b"),
                router_to("b", "a"),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        t.set_decision("b", OverrideMode::Disabled).unwrap();
        assert!(
            t.find_cycles().is_empty(),
            "decision-disabled router contributes no edge"
        );
    }

    #[test]
    fn toml_router_routes_roundtrip_and_default() {
        // Direct 条目 (kind tag + 必填字段).
        let direct = r#"
            id = "test"
            kind = "direct"
            protocol = "openai"
            base_url = "https://api.example.com"
        "#;
        let p: Provider = toml::from_str(direct).expect("direct parse");
        assert!(matches!(p.kind, ProviderKind::Direct(_)));

        // Router 条目: routes 数组; 构造**无 protocol 字段** (ingress per-request
        // URL / egress per-route 链尾决定, 见 RouterProvider 注释). route 的
        // upstream_model/priority 可省略.
        let router_toml = r#"
            id = "my-router"
            kind = "router"

            [[routes]]
            model_pattern = "gpt-*"
            target = "openai-main"

            [[routes]]
            model_pattern = "*"
            target = "fallback"
            upstream_model = "gpt-4o"
            priority = 100
        "#;
        let p: Provider = toml::from_str(router_toml).expect("router parse");
        let ProviderKind::Router(r) = &p.kind else {
            panic!("kind tag must parse as Router");
        };
        assert_eq!(r.routes.len(), 2);
        assert_eq!(r.routes[0].model_pattern, "gpt-*");
        assert_eq!(r.routes[0].target, "openai-main");
        assert_eq!(
            r.routes[0].upstream_model, None,
            "upstream_model omitted → None (透传)"
        );
        assert_eq!(r.routes[0].priority, None, "priority omitted → disabled");
        assert_eq!(r.routes[1].upstream_model.as_deref(), Some("gpt-4o"));
        assert_eq!(r.routes[1].priority, Some(100));
        assert!(p.validate().is_ok());

        // 缺 kind → fail-fast (sum type 无缺省构造, 不猜测).
        let untagged = r#"
            id = "test"
            protocol = "openai"
            base_url = "https://api.example.com"
        "#;
        assert!(
            toml::from_str::<Provider>(untagged).is_err(),
            "missing kind tag must fail fast"
        );

        // 旧配置残留 protocol (字段删除前的必填字段) → serde 静默忽略,
        // 不拒绝加载 (audit 也不告警: protocol 仍是 Direct 构造的合法字段,
        // KNOWN_FIELDS 按 section 平铺无法区分构造).
        let stray_proto = r#"
            id = "r"
            kind = "router"
            protocol = "openai"

            [[routes]]
            model_pattern = "*"
            target = "x"
        "#;
        let p: Provider = toml::from_str(stray_proto).expect("stray protocol ignored");
        let ProviderKind::Router(r) = &p.kind else {
            panic!("must stay Router");
        };
        assert_eq!(r.routes.len(), 1);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn direct_override_replaces_static_router() {
        // #187 根治: static 路由 + Direct override = **改回实体** — 跨型不继承,
        // routes 无 None 歧义 (#179 时代的 "无法改回实体" 限制由类型系统消灭).
        let tmp = tempfile_path();
        let mut d = p("x", Protocol::OpenAI, "https://d");
        direct_mut(&mut d).api_key = "sk-dyn".into();
        let t = ProviderTable::new(
            vec![
                router_to("x", "real"),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![d],
            empty_decisions(),
            tmp,
        );
        let eff = t.get_effective("x").unwrap();
        assert!(matches!(eff.kind, ProviderKind::Direct(_)));
        // 路由解析直达自身 (实体快路径), 携带 override 的鉴权字段.
        let r = t.resolve_route(&eff, "m", &PoolStates::new()).unwrap();
        assert_eq!(r.id, "x");
        assert_eq!(first_url(&r.provider), "https://d");
        assert_eq!(r.provider.api_key, "sk-dyn");
    }

    #[test]
    fn static_direct_key_survives_router_excursion() {
        // 互补链 (#187): static Direct → Router override → 再 Direct override —
        // 第二次 override 的 api_key 未记录 → Direct↔Direct 继承从 static 复原.
        // (dynamic-only 条目无此复原来源, 是 AGENTS.md 登记的已知限制.)
        let tmp = tempfile_path();
        let mut s = p("x", Protocol::OpenAI, "https://s");
        direct_mut(&mut s).api_key = "sk-static".into();
        // 第一步: Router override (切换为路由).
        let t1 = ProviderTable::new(
            vec![s.clone(), p("real", Protocol::OpenAI, "https://u")],
            vec![router_to("x", "real")],
            empty_decisions(),
            tempfile_path(),
        );
        assert!(matches!(
            t1.get_effective("x").unwrap().kind,
            ProviderKind::Router(_)
        ));
        // 第二步: 再切回 Direct override, api_key 未记录 (PUT null 语义).
        let mut back = p("x", Protocol::OpenAI, "https://d");
        direct_mut(&mut back).api_key = String::new();
        let t2 = ProviderTable::new(vec![s], vec![back], empty_decisions(), tmp);
        let eff = t2.get_effective("x").unwrap();
        // Direct override 胜出 + key 从 static Direct 继承复原.
        assert_eq!(first_url(direct(&eff)), "https://d");
        assert_eq!(direct(&eff).api_key, "sk-static");
    }

    #[test]
    fn prefer_static_decision_uses_static_route() {
        // static 路由 (→ real1) + dynamic override (→ real2) + PreferStatic:
        // 整条回 static, 路由随之 — decision 与 route 的组合不产生第三种语义.
        let tmp = tempfile_path();
        let t = ProviderTable::new(
            vec![
                router_to("x", "real1"),
                p("real1", Protocol::OpenAI, "https://u1"),
                p("real2", Protocol::OpenAI, "https://u2"),
            ],
            vec![router_to("x", "real2")],
            empty_decisions(),
            tmp,
        );

        // Default: override 生效 → real2.
        assert!(matches!(
            &t.get_effective("x").unwrap().kind,
            ProviderKind::Router(r) if r.routes[0].target == "real2"
        ));
        // PreferStatic: static 整条生效 → real1 (inherit 对 static 自身是 no-op).
        t.set_decision("x", OverrideMode::PreferStatic).unwrap();
        let eff = t.get_effective("x").unwrap();
        assert!(matches!(
            &eff.kind,
            ProviderKind::Router(r) if r.routes[0].target == "real1"
        ));
        assert_eq!(
            t.resolve_route(&eff, "m", &PoolStates::new()).unwrap().id,
            "real1"
        );
    }

    #[test]
    fn resolve_route_target_disabled_by_decision_reports_missing() {
        // decision=Disabled 的目标不在 effective 视图 → Missing (message 提示
        // "disabled by decision", 与 entry-level disabled 区分).
        let tmp = tempfile_path();
        let t = ProviderTable::new(
            vec![
                router_to("rt", "real"),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tmp,
        );
        t.set_decision("real", OverrideMode::Disabled).unwrap();
        let err = t
            .resolve_route(&t.get_effective("rt").unwrap(), "m", &PoolStates::new())
            .unwrap_err();
        assert_eq!(err, RouteError::Missing("real".into()));
        assert!(err.to_string().contains("disabled by decision"));
    }

    // FWD-5 环终止 property: 任意路由图 (含环), `resolve_route` 有限步返回
    // (Ok ⇒ 链尾必为 Direct 构造 — 类型保证, 见 contracts.md FWD-5; Err ⇒ 明确错误类别).
    // 历史教训 (生成器覆盖度): 图必须包含环与悬空, 否则 property 退化为恒真.
    // 生成器: p{i} 的路由目标由 edges.get(i) 决定 — 无边 → 实体, 目标 < n →
    // 指向表内 (可成环/自环), 目标 ≥ n → 悬空 (ghost).
    proptest! {
        #[test]
        fn prop_resolve_route_terminates_on_random_graphs(
            n in 2usize..8,
            edges in proptest::collection::vec(0usize..8, 0..16),
        ) {
            // n 个 provider: id = p0..p{n-1}; edges[i] 决定 p{i % n} 的路由目标
            // (目标均匀取 0..8 → 覆盖存在/缺失/自环/成环).
            let ids: Vec<String> = (0..n).map(|i| format!("p{i}")).collect();
            let entries: Vec<Provider> = (0..n)
                .map(|i| match edges.get(i) {
                    Some(&t) if t < n => router_to(&ids[i], &ids[t]),
                    Some(&t) => router_to(&ids[i], &format!("ghost-{t}")), // 悬空
                    None => p(&ids[i], Protocol::OpenAI, "https://u"), // 实体
                })
                .collect();
            let t = ProviderTable::new(entries, vec![], empty_decisions(), tempfile_path());
            for id in &ids {
                if let Some(entry) = t.get_effective(id) {
                    // Err 分支 = 有限步返回明确错误 (同样满足终止性), 无需断言.
                    // Ok ⇒ 链尾必为 Direct (类型保证, 无需运行时断言); 有限步返回即满足终止性.
                    let _ = t.resolve_route(&entry, "gpt-4o", &PoolStates::new());
                }
            }
        }
    }

    // ─── find_cycles property 交叉验证 (启动环诊断的存在性完备 + 零误报) ──────

    /// 测试参考侧的启用路由边判定, 独立于生产 `route_graph` (测试原则: 不信任
    /// 被测代码): `from` 是 Router 且存在启用路由 (priority 非 None) target == `to`.
    fn ref_route_edge(entries: &[Provider], from: &str, to: &str) -> bool {
        entries.iter().any(|e| {
            e.id == from
                && matches!(&e.kind, ProviderKind::Router(r)
                    if r.routes.iter().any(|rt| rt.priority.is_some() && rt.target == to))
        })
    }

    /// 独立参考实现: 朴素 path-DFS 判图是否有环 (邻接只含表内存在的目标,
    /// 与 find_cycles 的 "dangling 即止" 语义一致; 生成器无 decisions, 全启用).
    fn ref_has_cycle_impl(ids: &[String], entries: &[Provider]) -> bool {
        use std::collections::{HashMap, HashSet};

        // 邻接表: Router id → 启用路由的表内目标列表.
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
        for e in entries {
            if let ProviderKind::Router(r) = &e.kind {
                for rt in &r.routes {
                    if rt.priority.is_some() && ids.iter().any(|id| id == &rt.target) {
                        adj.entry(e.id.as_str()).or_default().push(&rt.target);
                    }
                }
            }
        }
        // 逐起点 path-DFS: 目标已在当前路径上 = 环.
        fn dfs<'a>(
            cur: &'a str,
            adj: &HashMap<&'a str, Vec<&'a str>>,
            on_path: &mut HashSet<&'a str>,
        ) -> bool {
            adj.get(cur).is_some_and(|targets| {
                targets.iter().any(|&t| {
                    on_path.contains(t) || {
                        on_path.insert(t);
                        let hit = dfs(t, adj, on_path);
                        on_path.remove(t);
                        hit
                    }
                })
            })
        }
        ids.iter().any(|start| {
            let mut on_path = HashSet::from([start.as_str()]);
            dfs(start, &adj, &mut on_path)
        })
    }

    proptest! {
        /// find_cycles 与独立参考实现交叉验证: (a) 存在性完备 — 图有环 ⇔ 检出
        /// 非空; (b) 零误报 — 每条报告的环首尾相同且相邻 id 间有真实启用路由边.
        /// 生成器复用 prop_resolve_route 的图分布 (历史教训: 必须含环/自环/悬空).
        #[test]
        fn prop_find_cycles_matches_reference(
            n in 2usize..8,
            edges in proptest::collection::vec(0usize..8, 0..16),
        ) {
            let ids: Vec<String> = (0..n).map(|i| format!("p{i}")).collect();
            let entries: Vec<Provider> = (0..n)
                .map(|i| match edges.get(i) {
                    Some(&t) if t < n => router_to(&ids[i], &ids[t]),
                    Some(&t) => router_to(&ids[i], &format!("ghost-{t}")),
                    None => p(&ids[i], Protocol::OpenAI, "https://u"),
                })
                .collect();
            let t = ProviderTable::new(entries.clone(), vec![], empty_decisions(), tempfile_path());
            let cycles = t.find_cycles();

            // (a) 存在性: 独立 path-DFS 参考实现.
            let expected = ref_has_cycle_impl(&ids, &entries);
            prop_assert_eq!(cycles.is_empty(), !expected, "existence mismatch");

            // (b) 零误报: 每条环路径闭合 + 相邻 id 间有启用路由边.
            for cyc in &cycles {
                prop_assert_eq!(cyc.first(), cyc.last(), "cycle must be closed: {:?}", cyc);
                for w in cyc.windows(2) {
                    prop_assert!(
                        ref_route_edge(&entries, &w[0], &w[1]),
                        "edge {} -> {} must be an enabled route edge: {:?}",
                        w[0],
                        w[1],
                        cyc
                    );
                }
            }
        }
    }

    // ─── Pool 构造 (套餐池): serde / validate / resolve_route / 图校验 ────────
    //
    // 契约: spec-pool-provider (T1). 状态机的细粒度行为 (pick 顺序 / 闹钟回归 /
    // 对齐重建) 见 src/pool.rs tests; 这里测 provider 集成面.

    /// pool provider: 默认 exhaust (内置窗口限额表) + cooldown 60.
    fn pool(id: &str, members: &[&str]) -> Provider {
        Provider {
            id: id.into(),
            enabled: true,
            name: Some(format!("name-{id}")),
            kind: ProviderKind::Pool(PoolProvider {
                members: members.iter().map(|s| s.to_string()).collect(),
                exhaust: ExhaustConfig::default(),
                cooldown_secs: default_pool_cooldown_secs(),
            }),
        }
    }

    #[test]
    fn toml_pool_roundtrip_full_and_defaults() {
        // 完整形态: members + exhaust 三通道 + cooldown_secs. (单条反序列化
        // 上下文 — 完整 config 文件中这些行在 `[[providers]]` 内, 前缀剥掉;
        // cooldown_secs 必须位于 [exhaust] 段头**之前**, TOML 表段后的键归属
        // 该子表.)
        let full = r#"
            id = "glm-pool"
            kind = "pool"
            members = ["glm-acc1", "glm-acc2"]
            cooldown_secs = 120

            [exhaust]
            statuses = [429]
            codes = ["1308"]
            headers = ["x-status=blocked"]
        "#;
        let p: Provider = toml::from_str(full).expect("pool parse");
        let ProviderKind::Pool(pl) = &p.kind else {
            panic!("kind tag must parse as Pool");
        };
        assert_eq!(
            pl.members,
            vec!["glm-acc1".to_string(), "glm-acc2".to_string()]
        );
        assert_eq!(pl.exhaust.statuses, vec![429]);
        assert_eq!(pl.exhaust.codes, vec!["1308".to_string()]);
        assert_eq!(pl.exhaust.headers, vec!["x-status=blocked".to_string()]);
        assert_eq!(pl.cooldown_secs, 120);
        assert!(p.validate().is_ok());

        // 省略整个 [providers.exhaust] = 全默认 (内置窗口限额表, spec §4).
        let minimal = r#"
            id = "glm-pool"
            kind = "pool"
            members = ["glm-acc1"]
        "#;
        let p: Provider = toml::from_str(minimal).expect("minimal pool parse");
        let ProviderKind::Pool(pl) = &p.kind else {
            panic!("must stay Pool");
        };
        assert_eq!(
            pl.exhaust,
            ExhaustConfig {
                statuses: vec![],
                codes: default_window_exhaust_codes(),
                headers: default_window_exhaust_headers(),
            },
            "omitted exhaust = built-in window-limit table"
        );
        assert_eq!(pl.cooldown_secs, 60, "omitted cooldown = 60s default");
        assert!(p.validate().is_ok());

        // 字段级替换: 显式配某字段 = 替换该字段默认 (空数组 = 显式关闭通道);
        // 未配字段保持默认.
        let partial = r#"
            id = "glm-pool"
            kind = "pool"
            members = ["glm-acc1"]

            [exhaust]
            codes = []
        "#;
        let p: Provider = toml::from_str(partial).expect("partial pool parse");
        let ProviderKind::Pool(pl) = &p.kind else {
            panic!("must stay Pool");
        };
        assert!(
            pl.exhaust.codes.is_empty(),
            "explicit empty closes code channel"
        );
        assert_eq!(
            pl.exhaust.headers,
            default_window_exhaust_headers(),
            "unconfigured channel keeps its default"
        );
        assert!(p.validate().is_ok());
    }

    #[test]
    fn validate_pool_rejects_empty_members_self_ref_and_bad_ids() {
        // 空 members (配置残缺 fail-fast, 与空 routes 同型).
        let err = pool("pl", &[]).validate().unwrap_err();
        assert!(err.contains("at least one pool member"), "got: {err}");
        // 自环 (member 含自身 id).
        let err = pool("pl", &["pl", "real"]).validate().unwrap_err();
        assert!(err.contains("lists itself"), "got: {err}");
        // 成员 id 非法 (validate_id 同 Router target 先例).
        assert!(pool("pl", &["has space"]).validate().is_err());
        // 合法: 重复成员不拒绝 (第二次 pick 到时已耗尽, 行为无歧义).
        assert!(pool("pl", &["a", "a"]).validate().is_ok());
    }

    #[test]
    fn exhaust_lint_flags_malformed_header_rules_only() {
        // lint 只抓 "永远不命中" 的畸形条目 (无 '=' / 空 name / 非法 header name
        // 字节 — 与检测器 header_rule_matches 的跳过集对齐); 合法条目与空白条目
        // (等价关闭, 无歧义) 不报。上报**原始条目** (含周边空白, 与配置文件可
        // grep 对齐)。WARN 不 reject: validate 仍 Ok。
        let clean = ExhaustConfig {
            headers: vec![
                "x-status=blocked".into(),
                "anthropic-ratelimit-unified-5h-status = blocked".into(), // 双侧容忍空白
                "   ".into(),                                             // 空白条目跳过
            ],
            ..ExhaustConfig::default()
        };
        assert!(clean.lint_malformed_header_rules().is_empty());
        assert!(pool("pl", &["a"]).validate().is_ok());

        let dirty = ExhaustConfig {
            headers: vec![
                "no-equals-sign".into(),
                "=empty-name".into(),
                " =also-empty".into(),
                "bad name[]=v".into(), // 非法 header name 字节 (空格/方括号)
                "x-status=blocked".into(),
            ],
            ..ExhaustConfig::default()
        };
        let malformed = dirty.lint_malformed_header_rules();
        assert_eq!(
            malformed,
            vec![
                "no-equals-sign",
                "=empty-name",
                " =also-empty",
                "bad name[]=v"
            ]
        );
        // lint 不影响 validate 结论 (WARN 通道, 非 reject).
        let prov = Provider {
            id: "pl".into(),
            enabled: true,
            name: None,
            kind: ProviderKind::Pool(PoolProvider {
                members: vec!["a".into()],
                exhaust: dirty,
                cooldown_secs: default_pool_cooldown_secs(),
            }),
        };
        assert!(prov.validate().is_ok());
    }

    #[test]
    fn resolve_route_pool_picks_first_member() {
        // pool → direct: 正常全打列表第一个成员 (顺序 failover), PoolHop 归因.
        let t = ProviderTable::new(
            vec![
                pool("pl", &["m1", "m2"]),
                p("m1", Protocol::OpenAI, "https://u1"),
                p("m2", Protocol::OpenAI, "https://u2"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let out = t
            .resolve_route(&t.get_effective("pl").unwrap(), "m", &PoolStates::new())
            .unwrap();
        assert_eq!(out.id, "m1", "list order is the priority");
        assert_eq!(first_url(&out.provider), "https://u1");
        assert_eq!(
            out.pool,
            Some(PoolHop {
                pool_id: "pl".into(),
                member_idx: 0,
            })
        );
        assert_eq!(out.model_rewrite, None, "pool does not rewrite model");
    }

    #[test]
    fn resolve_route_pool_skips_missing_and_disabled_members() {
        // missing / disabled 成员 = 跳过取下一个候选 (不直接报错 — pool 的
        // 存在意义就是 failover), 且**无持久标记**: 配置可用性不进状态机,
        // 成员后来补上 / 重新 enable 后下一次解析即自动回归列表头
        // (GET /models 的可解析性探针复用同一路径, 无持久副作用).
        let pools = PoolStates::new();
        let t = ProviderTable::new(
            vec![
                pool("pl", &["ghost", "off", "m2"]),
                p("m2", Protocol::OpenAI, "https://u2"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let mut disabled = p("off", Protocol::OpenAI, "https://u-off");
        disabled.enabled = false;
        t.upsert_dynamic(disabled).unwrap();

        let out = t
            .resolve_route(&t.get_effective("pl").unwrap(), "m", &pools)
            .unwrap();
        assert_eq!(out.id, "m2", "ghost (missing) + disabled skipped");
        assert_eq!(out.pool.as_ref().unwrap().member_idx, 2);

        // 无持久标记可观察: 补上 ghost 为实体后再解析 — ghost 回归列表头
        // (配置可用性的恢复即时生效, 无需 reset / 重启).
        t.upsert_dynamic(p("ghost", Protocol::OpenAI, "https://u-ghost"))
            .unwrap();
        let out2 = t
            .resolve_route(&t.get_effective("pl").unwrap(), "m", &pools)
            .unwrap();
        assert_eq!(out2.id, "ghost", "re-added member returns to head");
        assert_eq!(out2.pool.as_ref().unwrap().member_idx, 0);
    }

    #[test]
    fn resolve_route_pool_all_unavailable_sanitized_message() {
        // 全部成员 missing → AllMembersExhausted; message SEC-2 净化:
        // 只含 pool id + reason 枚举, 不含任何成员 url / 上游形态.
        let t = ProviderTable::new(
            vec![pool("pl", &["ghost1", "ghost2"])],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let err = t
            .resolve_route(&t.get_effective("pl").unwrap(), "m", &PoolStates::new())
            .unwrap_err();
        let RouteError::AllMembersExhausted(e) = &err else {
            panic!("expected AllMembersExhausted, got {err:?}");
        };
        assert_eq!(e.pool_id, "pl");
        assert_eq!(
            e.earliest_resume, None,
            "no alarm among candidates (all missing/disabled)"
        );
        let msg = err.to_string();
        assert!(msg.contains("pl"), "message names the pool: {msg}");
        assert!(msg.contains("no available member"), "msg: {msg}");
        assert!(!msg.contains("http"), "SEC-2: no upstream urls in message");
    }

    #[test]
    fn resolve_route_router_to_pool_nesting() {
        // Router → Pool → Direct 嵌套 (spec §7): 嵌套组合天然支持;
        // PoolHop 记录经过的 pool.
        let t = ProviderTable::new(
            vec![
                router_to("rt", "pl"),
                pool("pl", &["m1"]),
                p("m1", Protocol::OpenAI, "https://u1"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let out = t
            .resolve_route(&t.get_effective("rt").unwrap(), "m", &PoolStates::new())
            .unwrap();
        assert_eq!(out.id, "m1");
        assert_eq!(
            out.pool,
            Some(PoolHop {
                pool_id: "pl".into(),
                member_idx: 0,
            })
        );
    }

    #[test]
    fn resolve_route_pool_cycle_detected() {
        // pool 互指环 (绕过 validate 直接构造 — 模拟手改 state.toml 的运行时
        // 兜底场景): visited-set 有限步终止.
        let t = ProviderTable::new(
            vec![pool("pa", &["pb"]), pool("pb", &["pa"])],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let err = t
            .resolve_route(&t.get_effective("pa").unwrap(), "m", &PoolStates::new())
            .unwrap_err();
        assert!(matches!(err, RouteError::Cycle(_)), "got: {err:?}");

        // 成员自指 (member 指向自身 pool).
        let t2 = ProviderTable::new(
            vec![pool("s", &["s"])],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        assert!(matches!(
            t2.resolve_route(&t2.get_effective("s").unwrap(), "m", &PoolStates::new()),
            Err(RouteError::Cycle(_))
        ));
    }

    #[test]
    fn would_cycle_covers_pool_member_edges() {
        // pool members 与 route target 同型构成环检查边 (spec §7).
        let t = ProviderTable::new(
            vec![
                router_to("a", "b"),
                pool("b", &["real"]),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        // b 的成员改指 a → 闭合 a→b 环.
        assert!(
            t.would_cycle(&pool("b", &["a"])),
            "pool member closes the cycle"
        );
        // 悬空成员不成环.
        assert!(!t.would_cycle(&pool("b", &["ghost"])));
        // pool 自环.
        assert!(t.would_cycle(&pool("b", &["b"])));
    }

    #[test]
    fn find_cycles_detects_pool_edges() {
        // 启动诊断: router→pool→router 闭环被检出 (边集 = route target ∪ pool members).
        let t = ProviderTable::new(
            vec![
                router_to("a", "b"),
                pool("b", &["a"]),
                p("real", Protocol::OpenAI, "https://u"),
            ],
            vec![],
            empty_decisions(),
            tempfile_path(),
        );
        let cycles = t.find_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0], vec!["a", "b", "a"]);
    }
}
