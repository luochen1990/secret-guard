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
use crate::config::OnProbeExhausted;
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
    /// 来自 `[redact] on_probe_exhausted` (默认 FailOpen). 控制 redact probing 耗尽时
    /// 是 fail-open (skip + 原样转发) 还是 fail-closed (返回 503 拒绝转发).
    pub on_probe_exhausted: OnProbeExhausted,
    /// 来自 `[server] upstream_*_timeout_secs` 的上游超时配置.
    /// forward 路径用它给 send().await / stream chunk 加超时保护.
    pub upstream_timeouts: crate::config::UpstreamTimeouts,
}

// ─── HTTP 层共享常量 ────────────────────────────────────────────────────────

/// 共享的 `no-store` header 设置 (axum 的 `[(name, value); N]` 接受 `(&str, &str)`).
///
/// 历史上定义在 `web::api` (资源组 CRUD 模块) → `web::mod` (web 层共享常量), 但消费者
/// 跨层: web::api (本模块所有 endpoint) + `crate::auth::handlers` (OIDC login/logout/me).
/// 让 auth 反向依赖 web 违反层间单向承诺 (鉴权层是更低层基础设施), 故落位顶层
/// HTTP 常量小模块, web / auth 各自单向取用 (#145 偏差 3).
pub const NO_STORE: [(&str, &str); 1] = [("cache-control", "no-store, no-cache, must-revalidate")];
