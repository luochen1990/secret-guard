//! 进程级共享状态 [`AppState`] + HTTP 层共享常量.
//!
//! # 职责边界
//!
//! `AppState` (历史上名 `ProxyState`, 定义在 `proxy/mod.rs`) 是**整个进程**的共享状态:
//! router 与全部 handler (forwarding 转发链 / WebUI JSON API / auth) 通过 axum 的
//! `State` 槽位共享它. 它定义在转发层模块内是历史落点 — 实质是进程级 AppState,
//! 让 web / auth (展示与鉴权层) 反向依赖 proxy (转发层) 违反 "域 A → 域 B → 域 C
//! 单向承诺" (#145 偏差 3). 上移为顶层模块后, proxy / web / auth 各自**单向**依赖之.
//!
//! # 字段语义
//!
//! 各字段的来源与语义注释见结构体定义; 装配点在 `server.rs::serve`
//! (双层配置 → 两张表 + ApiKeyStore + DAG + 超时快照 → AppState).

use std::sync::Arc;

use crate::auth::ApiKeyStore;
use crate::config::{OnFallbackRestore, OnProbeExhausted, OnUnsupportedProtocol};
use crate::dag::ConversationDag;
use crate::provider::ProviderTable;
use crate::secrets::SecretTable;

/// 进程级共享状态, 在 router 与 handler 间共享.
#[derive(Clone, Debug)]
pub struct AppState {
    pub upstream: reqwest::Client,
    pub providers: ProviderTable,
    pub dag: ConversationDag,
    pub secrets: SecretTable,
    /// API key 存储 (server.rs 无条件构造, 与 auth.enabled 无关 — 单用户模式下
    /// WebUI 仍可签发/管理 key). 设计详见 `src/web/api/apikeys.rs` 头部注释.
    pub api_keys: ApiKeyStore,
    /// 服务端认证是否启用 (来自 static config `[auth] enabled`). 与 ApiKeyStore
    /// 的"无条件构造"正交: store 总存在, 但 forwarding 路径的 require_api_key
    /// middleware 仅在 auth_enabled = true 时挂载. WebUI 用此标志区分 key 的
    /// "启用中 / 已禁用 / 认证未启用" 三态 (见 src/web/api/apikeys.rs::list_api_keys).
    pub auth_enabled: bool,
    /// 来自 `[redact] global_mock_prefix` (默认空串). WebUI secret upsert 时
    /// 透传给 validate_and_resolve, 用于校验 value 不含此 prefix + 注入 Auto gen_spec.prefix.
    pub global_mock_prefix: Arc<str>,
    /// 来自 `[redact] on_probe_exhausted` (默认 FailClosed, SEC-10 降级偏安全).
    /// 控制 redact probing 耗尽时是 fail-closed (返回 503 拒绝转发) 还是
    /// fail-open (显式 opt-in, skip + 原样转发).
    pub on_probe_exhausted: OnProbeExhausted,
    /// 来自 `[redact] on_unsupported_protocol` (默认 FailClosed, SEC-10). 控制
    /// codec 不覆盖的协议 (gemini/ollama) 上配置了 secrets 时是 fail-closed
    /// (返回 503 拒绝转发) 还是 fail-open (显式 opt-in, WARN + 透传放行).
    /// 仅管 secret 安全性 — 仅 model 重写降级 (无 secret) 时两模式都维持 WARN
    /// 透传. 消费点 `proxy::same_proto`.
    pub on_unsupported_protocol: OnUnsupportedProtocol,
    /// 来自 `[redact] on_fallback_restore` (默认 Withhold, SEC-10). 控制 codec
    /// 无法 parse 上游响应的 fallback 路径 (reader 拒绝但 body 仍是合法 JSON)
    /// 上, 是否把 Mock 还原为 real 发给客户端: Withhold (默认) 保留 Mock 透传
    /// (降级偏安全 — 失败响应体高概率进入客户端日志系统, Mock 按设计可安全
    /// 暴露); Restore (显式 opt-in) 恢复 RED-8 行为 (本地工具直接可用, 但 real
    /// 可能随日志扩散). 消费点 `proxy::helpers::restore_via_json_leaf_fallback`
    /// (fan_out / cross_proto 的 reader-拒绝臂共享). 非 JSON 分支不受影响.
    pub on_fallback_restore: OnFallbackRestore,
    /// 来自 `[server] upstream_*_timeout_secs` 的上游超时配置.
    /// forward 路径用它给 send().await / stream chunk 加超时保护.
    pub upstream_timeouts: crate::config::UpstreamTimeouts,
    /// Router provider GET /models 的上游模型清单缓存 (#196, FWD-7):
    /// per-Direct-provider, TTL 300s + serve-stale-on-error + single-flight,
    /// 语义 SSOT 见 `src/proxy/models.rs` 头部. 类型是纯数据 store (无 proxy
    /// 行为依赖), 经 `crate::proxy` re-export 在此聚合 — 组合根先例同
    /// `api_keys` (state 聚合各 feature 模块的 store 类型).
    pub model_lists: Arc<crate::proxy::ModelListCache>,
    /// 模型用量统计 + redact 审计 store (usage-stats, docs/design/usage-stats.md):
    /// SQLite 持久化 (writer 线程批量事务 insert) + SQL 聚合查询 (无内存双份簿记).
    /// `enabled = false` 时是 no-op store (record 零开销). 纯数据 store,
    /// 聚合先例同 `api_keys` / `model_lists`.
    pub usage: Arc<crate::usage::UsageStore>,
    /// models.dev 定价缓存 (usage-stats §7): 惰性首拉 + TTL + serve-stale +
    /// single-flight; 只被 /api/usage 查询路径触碰, 不在转发链上.
    pub pricing: Arc<crate::usage::PricingCache>,
}

// ─── HTTP 层共享常量 ────────────────────────────────────────────────────────

/// 共享的响应安全 header 组 (axum 的 `[(name, value); N]` 接受 `(&str, &str)`).
///
/// - `cache-control: no-store, ...` — WebUI/API 响应是动态数据, 不经任何缓存.
/// - `x-content-type-options: nosniff` (SEC-S1) — 阻止浏览器 MIME sniffing:
///   JSON/文本端点即使被注入也不得被重新解释为脚本/HTML (纵深防御, 对
///   `escapeHtml` 纪律的兜底).
///
/// 仅用于 WebUI / JSON API / auth 响应 — **转发链响应绝不带** (FWD-1: 网关对
/// wire 的唯一合法修改是 real↔mock 替换, 不追加 header).
///
/// 历史上定义在 `web::api` (资源组 CRUD 模块) → `web::mod` (web 层共享常量), 但消费者
/// 跨层: web::api (本模块所有 endpoint) + `crate::auth::handlers` (OIDC login/logout/me).
/// 让 auth 反向依赖 web 违反层间单向承诺 (鉴权层是更低层基础设施), 故落位顶层
/// HTTP 常量小模块, web / auth 各自单向取用 (#145 偏差 3).
pub const NO_STORE: [(&str, &str); 2] = [
    ("cache-control", "no-store, no-cache, must-revalidate"),
    ("x-content-type-options", "nosniff"),
];
