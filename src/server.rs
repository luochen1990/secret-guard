//! axum router 装配与服务启动.
//!
//! # 安全层 (最外层, 所有路由)
//! Host/Origin guard (SEC-7, 防 DNS rebinding + CSRF 纵深) 以最外层 middleware
//! 挂载, 定义与白名单语义见 [`crate::server_host_guard`].
//!
//! # 路由策略
//! - `/`                —— Web UI 入口 (单页 HTML).
//! - `/api/*`           —— Web UI JSON API (未匹配子路径 404, 绝不进 forward).
//! - `/login`, `/oauth2/callback`, `/logout` —— OIDC 认证 (auth 启用时).
//! - `/{proto}/{name}`        —— forward (`rest = "/"`).
//! - `/{proto}/{name}/{*rest}`—— forward (含 sub-path).
//! - 其他 —— 404 (不再 catch-all 透传, 避免误转发 + 明确契约).
//!
//! 完整的 URI 分配规划 (顶级保留字 / 命名空间不相交论证) 见 `docs/design/url-layout.md`.
//!
//! # 认证 (可选, 由 `[auth] enabled` 控制)
//!
//! `auth.enabled = false` (默认): 单用户模式, 所有路由无认证 (向后兼容).
//! `auth.enabled = true`: 双轨认证 —
//! - 浏览器 WebUI (`/`, `/api/*`): OIDC Authorization Code + PKCE → cookie session.
//! - SDK 转发 (`/{proto_short}/{name}/*`, proto_short ∈ o/a/g/l/r): 本地 API key (`Authorization: Bearer sg_...`).
//!
//! ApiKeyStore 总是构造 (与 `auth.enabled` 无关), 让 WebUI 在单用户模式下也能
//! 管理和预配置 key. `/api/api-keys` CRUD 路由在 `web::router()` 里无条件挂载
//! (不隔离, 见 `src/web/api/apikeys.rs`); `require_api_key` middleware 仅在 auth 启用时挂载
//! 到 forwarding 路径.
//!
//! # 协议简写
//! 完整映射见 [`crate::provider::Protocol::ALL`] (SSOT), 以代码为准.
//!
//! # Shutdown
//! 默认监听 SIGTERM / Ctrl-C, axum 进入 graceful shutdown 期间不再接受新连接,
//! 已建立的连接会等到完成或超时.
//!
//! # 双层状态装配
//! [`serve`] 接收 static + dynamic 两份配置, 在内部:
//! 1. 共享一把 `persist_lock` 给 ProviderTable / SecretTable / ApiKeyStore
//!    (避免并发 RMW 互相覆盖 state.toml).
//! 2. 共享同一份 `Decisions` 给两个表 (因为 decisions 同时含 provider / secret 决策,
//!    任何一方修改都要触发 state.toml 重写).
//!
//! # 内存模型 (SSOT — 缓冲 / 容量上限汇总)
//!
//! secret-guard 的内存上界由以下常量 + 并发度决定. 新增 / 调整任意一项时,
//! 同步更新此表 (SSOT). 每项在自身定义点保留行内注释, 此处提供交叉引用 + 上界贡献分析.
//!
//! | 常量 | 值 | 位置 | 作用 | 上界贡献 |
//! |---|---|---|---|---|
//! | `MAX_REQ_BODY` | 16 MiB | `proxy/mod.rs` | 单请求 body 收集上限 (字节透传前的 `to_bytes` cap) | 16 MiB × 并发请求数 |
//! | `MAX_RESP_BODY_RECORD` | 32 MiB | `proxy/mod.rs` | 单响应 record 累积上限 (**仅 DAG record, 客户端响应无上限**) | 32 MiB × 并发请求数 |
//! | `MAX_BUF` | 16 MiB | `codec/stream.rs` | SSE reassembly 缓冲 (跨协议翻译 / 同协议 restore 路径) | 16 MiB × 并发流 |
//! | `MAX_ERROR_MSG_LEN` | 4 KiB | `proxy/mod.rs` | 错误响应回放 message 截断 | 4 KiB × 失败请求数 (常量小) |
//! | `C5_INTERNAL_RETRIES` | 10_000 | `mock.rs` | mock 候选生成内部重试链 (safety bound, 防 C5 退化为概率) | CPU 限界, 不占内存 |
//! | `MOCK_PROBE_LIMIT` | 2^20 (prod) / 512 (test) | `redact.rs` | gen_mock_for_ir 的 probing 上限 | CPU 限界, 不占内存 |
//! | `PARSED_SYNC_INTERVAL` | 500 ms | `proxy/recorder.rs` | 流式 parsed view 节流写入间隔 (UX 与锁竞争折中) | 时间常量, 不占内存 |
//! | `records_capacity` (ServerConfig) | 1024 (默认, 用户可配) | `config.rs::ServerConfig` → `main.rs` → `serve()` → `ConversationDag::new(max_nodes, ...)` | DAG node 总数上限 (FIFO 淘汰) | ~每 node 几 KB (request/response body + metadata) × records_capacity |
//! | `max_sessions` (硬编码 500) | 500 | `server.rs::serve()` → `ConversationDag::new(_, 500, _)` → `dag::DagInner::max_sessions` | session 总数上限 (安全阀, 防 fork 爆炸) | session 元数据 × 500 (常量小) |
//! | `min_sessions` (硬编码 1) | 1 | 同上 → `dag::DagInner::min_sessions` | session 数下限 (保底, 避免界面清空) | 下限, 非上界 |
//!
//! **最坏情况估算**: 在 N 个并发请求下, 主要内存上界 =
//! N × (16 MiB request + 32 MiB response record + 16 MiB SSE reassembly) ≈ N × 64 MiB
//! + DAG 持有量 (records_capacity × ~10 KB) ≈ 10 MiB (默认 1024). 1000 并发时 ≈ 64 GiB,
//!   远超典型单机内存 — 实践中 LLM 请求远小于 16 MiB cap, 真实占用由 RPS × 平均 body size 决定,
//!   cap 是防御恶意 / 误传大 body 的 safety bound, 不是稳态运行预算.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::middleware;
use axum::{
    Router,
    routing::{any, get, post},
};
use parking_lot::{Mutex, RwLock};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::auth::{ApiKeyStore, AuthConfig, OidcBackend};
use crate::dag::ConversationDag;
use crate::provider::{Provider, ProviderTable};
use crate::proxy::{forward, forward_no_rest};
use crate::secrets::{SecretEntry, SecretTable};
use crate::server_host_guard::{self, HostGuard};
use crate::state::AppState;
use crate::web;

/// 构建 [`TraceLayer`] (SEC-3 加固: 显式限定 span 字段, 不记录 headers).
///
/// **为什么用宏而非函数**: `TraceLayer::new_for_http().make_span_with(closure)` 返回
/// `TraceLayer<DefaultClass, RequestBody, DefaultMakeSpan, ...>` 的复合泛型类型, 显式
/// 写出签名既冗长又脆弱 (随 tower-http 版本变). 宏在调用点展开, 让 `.layer(trace_layer!())`
/// 保持简洁且类型自动推断. 这是 Rust 生态对 "返回复杂泛型 layer" 的惯用取舍.
///
/// **为什么需要显式 `make_span_with`**:
/// `tower_http::trace::TraceLayer::new_for_http()` 的默认 `MakeSpan` 在不同版本间
/// 行为不一致 (0.6 默认不记 headers, 但未来升级可能改变). Authorization / x-api-key /
/// cookie 等 header 一旦进入 tracing span, 会通过 tracing subscriber 落到日志,
/// 构成 SEC 红线 (与 [`crate::proxy::helpers::redact_headers`] 在 record 侧的脱敏职责对应,
/// 本宏守护 span 侧, 同属 SEC-3 "assert/panic/log 不泄漏 secret" 的实现 — 防止敏感
/// header 经 tracing span 泄露到日志). 显式 `make_span_with` 把 "只记 method/uri/version"
/// 这条不变量固化在代码里, 升级 tower-http 时无需复核默认行为是否变更.
///
/// 不在此处记录的字段:
/// - **headers** (含 Authorization / x-api-key / x-goog-api-key / cookie / set-cookie)
/// - **request body** / **response body** (不会进 span)
macro_rules! trace_layer {
    () => {
        TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<_>| {
            // SEC-3: 字段白名单 — 见宏 doc (不在此处记 headers/body).
            // SEC-C4a: 只记 path 不记完整 uri — query 可能携带 key/token 类敏感
            // 参数, 一律丢弃 (契约边界见 contracts.md SEC-3
            // `prop_trace_span_no_query_string`).
            tracing::info_span!(
                "http.request",
                method = %request.method(),
                path = %request.uri().path(),
                version = ?request.version(),
            )
        })
    };
}

/// 构建 axum Router (单用户模式, 无认证).
///
/// 这是 `auth.enabled = false` 时的入口, 与旧版完全兼容.
/// `guard`: Host/Origin 校验白名单 (SEC-7, 由 [`crate::server_host_guard`] 定义;
/// 调用方需用与实际监听 port 一致的 [`HostGuard::new`] 构造 — 测试 spawn 时
/// 从已 bind 的 listener 取 port).
pub fn build_router(state: AppState, guard: HostGuard) -> Router {
    build_router_inner(state, None, guard)
}

/// 构建 axum Router (带认证).
///
/// `auth_stack` 由 [`serve`] 在启用认证时构造.
pub fn build_router_with_auth(state: AppState, auth_stack: AuthStack, guard: HostGuard) -> Router {
    build_router_inner(state, Some(auth_stack), guard)
}

/// state 目录内的运行时工件路径 (**固定名**, 不带 config stem): usage SQLite 库
/// (`usage.sqlite3`, 设计 §4) 与 models.dev 定价缓存 (`pricing.json`, 原样落盘
/// 供冷启动读回).
///
/// 为什么挂 state 目录而非 config 目录, 且不用 config 文件名做 stem:
/// - 部署形态中 static config 常在只读位置 (nixos 模块: /nix/store), state
///   目录才是部署声明的唯一可写域 (systemd StateDirectory). 旧实现派生 config
///   同目录, 令 usage 库打开恒失败 → 恒降级 `:memory:`, 统计重启即丢
///   (2026-09-12 home-pc 生产事故).
/// - nix store 文件名含内容 hash (内容变更即变), 做 stem 会令每次 rebuild
///   切到一个新的空库文件, 持久化名存实亡.
/// - state 目录即实例身份 (一目录一实例), 工件无需 config 前缀消歧.
///
/// standalone: state 默认在 config 旁 (main.rs default_state_path), 旧
/// `<stem>.usage.sqlite3` 不自动迁移, 首启前手动改名即可.
fn state_dir_artifact(state_path: &Path, file_name: &str) -> PathBuf {
    // parent 为空目录 (裸文件名 state) 时 join 即裸文件名 — PathBuf::push 对空
    // buffer 直接追加, 不引入 "./" 前缀.
    state_path.parent().unwrap_or(Path::new("")).join(file_name)
}

/// 内部: 根据 auth_stack 是否存在, 条件化装配认证 layer.
///
/// trace + Host/Origin guard 在两个分支的结果上**统一**叠加 (后挂者为最外层):
/// guard 对任何装配分支恒为最外层是 SEC-7 不变量, 结构性保证而非各分支自行记得.
/// 403 拒绝发生在认证 / trace 之前 (guard 内自带 WARN 日志, 保证可观测).
fn build_router_inner(state: AppState, auth_stack: Option<AuthStack>, guard: HostGuard) -> Router {
    // Forward router: 使用 AppState, 在 merge 前不调用 with_state.
    // 首段 proto 简写 (o/a/g/l/r) 由 dispatch 校验; 顶级保留字 (api/login/logout/oauth2)
    // 的静态路由优先于本参数路由, 二者天然不相交 (见 docs/design/url-layout.md).
    let forward_router: Router<AppState> = Router::new()
        .route("/{proto}/{name}", any(forward_no_rest))
        .route("/{proto}/{name}/{*rest}", any(forward));

    let router = match auth_stack {
        None => {
            // 单用户模式: 所有路由无认证.
            Router::new()
                .merge(web::router())
                .route("/api/{*rest}", any(web::not_found))
                .merge(forward_router)
                .with_state(state)
        }
        Some(auth) => build_router_with_auth_layers(state, auth, forward_router),
    };
    router
        .layer(trace_layer!())
        .layer(middleware::from_fn_with_state(
            guard,
            server_host_guard::guard,
        ))
}

/// 认证层的完整装配状态 (启用认证时由 serve 构造).
pub struct AuthStack {
    pub backend: OidcBackend,
    pub api_keys: ApiKeyStore,
    /// session cookie Secure flag (来自 `[auth] secure_cookie`).
    pub secure_cookie: bool,
}

/// 构建带认证的 router.
///
/// - WebUI 路由: OIDC session guard (login_required).
/// - 转发路由: API key middleware (require_api_key).
/// - 登录路由 (/login, /callback, /logout): 公开 (不需要认证).
/// - trace / Host guard 由 build_router_inner 在本函数结果之外统一叠加.
fn build_router_with_auth_layers(
    state: AppState,
    auth: AuthStack,
    forward_router: Router<AppState>,
) -> Router {
    use axum_login::AuthManagerLayerBuilder;

    let AuthStack {
        backend,
        api_keys,
        secure_cookie,
    } = auth;
    let auth_state = crate::auth::handlers::AuthState {
        backend: backend.clone(),
        api_keys: api_keys.clone(),
    };

    // 公开路由 (login/callback/logout/me): 不挂 login_required guard.
    // AuthState 通过 Extension 注入 (与 AppState 的 State 槽位正交).
    // me handler 不需要 AuthState, 只需要 AuthSession.
    let webui_public: Router<AppState> = Router::new()
        .route(
            "/login",
            get(crate::auth::handlers::login_start).post(crate::auth::handlers::login_start),
        )
        .route(
            "/oauth2/callback",
            get(crate::auth::handlers::oauth_callback),
        )
        .route("/logout", post(crate::auth::handlers::logout))
        .route("/api/me", get(crate::auth::handlers::me))
        .layer(axum::Extension(auth_state));

    // 受保护路由: WebUI, 需要 login_required guard + AppState.
    // 注: /api/api-keys CRUD 不在此处挂载 — 见 `web::router()` (无条件挂载, 不隔离用户).
    let webui_protected: Router<AppState> = web::router().route_layer(axum_login::login_required!(
        OidcBackend,
        login_url = "/login"
    ));

    // 转发路由: 应用 API key middleware.
    // from_fn_with_state 在 layer 层注入 ApiKeyStore, 不改变 Router 的 state 类型.
    let forward_protected = forward_router.route_layer(middleware::from_fn_with_state(
        api_keys,
        crate::auth::require_api_key,
    ));

    // session + auth layer (应用于整个 app).
    let session_layer = crate::auth::build_session_layer(secure_cookie);
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();

    Router::new()
        .merge(webui_public)
        .merge(webui_protected)
        // /api/{*rest} 兜底在 login_required 之外 (有意): 未登录的未知 /api/* 路径
        // 直接 404 而非 307 — 兜底作为 SEC-6 安全网应在任何认证状态下工作.
        .route("/api/{*rest}", any(web::not_found))
        .merge(forward_protected)
        .with_state(state)
        .layer(auth_layer)
}

/// 构造 reqwest 客户端 (与上游连接复用).
///
/// gzip/brotli/deflate 自动解压由 Cargo.toml 的 reqwest features 控制 —
/// 启用 feature 后 reqwest 自动解压并剥除 content-encoding header,
/// 无需在 builder 上调 `.gzip(true)` (调了反而是冗余).
///
/// `connect_timeout`: DNS+TCP+TLS 握手超时. `None` = 无限 (向后兼容, 不建议;
/// 上游网络异常时会永久 hang). 由 `[server] upstream_connect_timeout_secs` 配置.
pub fn build_upstream_client(connect_timeout: Option<Duration>) -> anyhow::Result<reqwest::Client> {
    let mut builder =
        reqwest::Client::builder().user_agent(concat!("secret-guard/", env!("CARGO_PKG_VERSION")));
    if let Some(t) = connect_timeout {
        builder = builder.connect_timeout(t);
    }
    builder.build().context("failed to build upstream client")
}

/// 启动服务. 阻塞直到 shutdown 信号到达且 drain 完成.
///
/// - `static_providers` / `static_secrets`: 来自 `secret-guard.toml`, 进程内只读.
/// - `dyn_state`: 来自 `secret-guard.state.toml`, 拆为 dynamic 列表 + decisions.
/// - `state_path`: state.toml 的写回路径.
/// - `auth_config`: 认证配置 (来自 static config 的 `[auth]` 段).
/// - `global_mock_prefix`: 来自 static config 的 `[redact] global_mock_prefix`,
///   存入 AppState 供 WebUI handler 在 secret upsert 时校验 + resolve.
/// - `on_probe_exhausted`: 来自 static config 的 `[redact] on_probe_exhausted`,
///   存入 AppState 供 forwarding 路径决定 probing 耗尽时 fail-open / fail-closed.
/// - `on_unsupported_protocol`: 来自 static config 的
///   `[redact] on_unsupported_protocol`, 存入 AppState 供 forwarding 路径决定
///   codec 不覆盖的协议 (gemini/ollama) 上配置了 secrets 时 fail-open / fail-closed.
/// - `on_fallback_restore`: 来自 static config 的 `[redact] on_fallback_restore`,
///   存入 AppState 供响应侧 parse-失败 fallback 路径决定是否把 Mock 还原为
///   real 发给客户端 (withhold 保留 Mock / restore 还原, SEC-10).
/// - `upstream_timeouts`: 来自 static config 的 `[server] upstream_*_timeout_secs`,
///   存入 AppState 供 forward 路径给 send().await / stream chunk 加超时保护
///   (防上游网络异常时 record 永久 pending).
#[allow(clippy::too_many_arguments)]
pub async fn serve(
    host: &str,
    port: u16,
    records_capacity: usize,
    static_providers: Vec<Provider>,
    static_secrets: Vec<SecretEntry>,
    mut dyn_state: crate::config::DynamicState,
    state_path: PathBuf,
    config_path: PathBuf,
    auth_config: AuthConfig,
    global_mock_prefix: String,
    on_probe_exhausted: crate::config::OnProbeExhausted,
    on_unsupported_protocol: crate::config::OnUnsupportedProtocol,
    on_fallback_restore: crate::config::OnFallbackRestore,
    upstream_timeouts: crate::config::UpstreamTimeouts,
    usage_config: crate::config::UsageConfig,
    allowed_domains: Vec<String>,
) -> anyhow::Result<()> {
    auth_config.validate().map_err(|e| anyhow::anyhow!(e))?;

    let upstream = build_upstream_client(upstream_timeouts.connect)?;
    let dag = ConversationDag::new(records_capacity, 500, 1);

    // 跨表共享: persist_lock 串行整个 RMW, decisions 是同一份 mutable map.
    let persist_lock = Arc::new(Mutex::new(()));

    // 悬空 decision prune (CFG-6): 清除 state.toml 中指向已不存在 static id 的
    // decision 条目, 防 "static id 复活后静默继承旧 decision" (如 disabled →
    // WebUI 条目消失无提示)。必须在 decisions 装入 Arc 前做 (此后只读语义)。
    let provider_ids: std::collections::HashSet<String> =
        static_providers.iter().map(|p| p.id.clone()).collect();
    let secret_ids: std::collections::HashSet<String> =
        static_secrets.iter().map(|s| s.id.clone()).collect();
    let pruned = crate::config::prune_dangling_decisions(
        &mut dyn_state.decisions,
        &provider_ids,
        &secret_ids,
    );
    if !pruned.is_empty() {
        for (kind, id) in &pruned {
            tracing::warn!(
                kind = kind,
                id = %id,
                "pruned dangling decision (static id no longer exists)"
            );
        }
        // 启动期单线程 (表未构造, 无并发写), 整文件重写不走 persist_lock。
        // 失败仅 WARN 不阻塞启动: 内存 decisions 已清理, 本次运行正确;
        // 磁盘残留下次启动会被再次 prune (state.toml 本就"永远可丢弃重置")。
        match dyn_state
            .to_toml()
            .and_then(|text| crate::config::atomic_write(&state_path, &text))
        {
            Ok(()) => {}
            Err(e) => tracing::warn!(
                error = ?e,
                "state.toml rewrite after decision prune failed; dangling entries persist on disk"
            ),
        }
    }

    let decisions = Arc::new(RwLock::new(dyn_state.decisions));

    let secret_table = SecretTable::with_persist_lock(
        static_secrets,
        dyn_state.secrets,
        decisions.clone(),
        state_path.clone(),
        persist_lock.clone(),
    );

    // API key store: 总是构造, 不依赖 auth.enabled.
    // 设计: /api/api-keys CRUD 无条件挂载 (不隔离, 只认证); 见 web::router().
    // - auth 关闭 (单用户模式): store 用于 WebUI 管理 key (签发的 key 暂时无消费方,
    //   因为 forwarding 路径的 require_api_key middleware 不挂载, 但数据可预先配置好).
    // - auth 启用: store 同时服务于 WebUI 管理 + forwarding middleware 鉴权.
    let api_keys = ApiKeyStore::new(
        &auth_config.api_keys,
        &config_path,
        dyn_state.api_keys.clone(),
        dyn_state.api_keys_disabled.clone(),
        state_path.clone(),
        persist_lock.clone(),
    );
    let provider_table = ProviderTable::with_persist_lock(
        static_providers,
        dyn_state.providers,
        decisions,
        state_path.clone(),
        persist_lock.clone(),
    );

    // #179 可选加固: 启动时对 merged provider 视图做路由环检查, 每环一条 WARN.
    // 漏网来源 = 手改 state.toml / 并发 upsert TOCTOU (`would_cycle` 检查与
    // 落库非同一临界区), 否则要等首个请求 503 才暴露 (可观测性弱).
    // 不阻塞启动: 环只影响这些 router 的请求 (`resolve_route` 503 兜底),
    // state.toml 永远可删除重置 — fail-fast 会把可恢复状态变成启动死锁.
    for cycle in provider_table.find_cycles() {
        tracing::warn!(
            cycle = ?cycle,
            "router provider cycle detected (hand-edited state.toml or concurrent upsert?); requests to these routers will 503"
        );
    }

    let proxy = AppState {
        upstream,
        providers: provider_table,
        dag,
        secrets: secret_table,
        api_keys: api_keys.clone(),
        auth_enabled: auth_config.enabled,
        global_mock_prefix: Arc::from(global_mock_prefix),
        on_probe_exhausted,
        on_unsupported_protocol,
        on_fallback_restore,
        upstream_timeouts,
        model_lists: Arc::new(crate::proxy::ModelListCache::new()),
        usage: Arc::new(crate::usage::UsageStore::open(
            &usage_config,
            &state_dir_artifact(&state_path, "usage.sqlite3"),
        )),
        pricing: Arc::new(crate::usage::PricingCache::new(
            usage_config.pricing_url.clone(),
            std::time::Duration::from_secs(usage_config.pricing_refresh_secs.max(60)),
            state_dir_artifact(&state_path, "pricing.json"),
            crate::usage::price_overrides_from_config(&usage_config.pricing_override),
        )),
    };

    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .with_context(|| format!("invalid listen address {host}:{port}"))?;
    let listener = bind_listener(addr).await?;
    // 实际监听 port (bind 后取 — 配置 port=0 时 OS 分配临时端口, 配置值不可用):
    // 供 SEC-7 Host guard 白名单与 OIDC redirect_url 派生共用.
    let listen_port = listener
        .local_addr()
        .expect("bound listener has addr")
        .port();
    let host_guard = HostGuard::new(host, listen_port).allow_domains(&allowed_domains);

    // 条件化: 启用认证时构造 AuthStack, 否则单用户模式.
    let app = if auth_config.enabled {
        let oidc_cfg = auth_config
            .oidc
            .as_ref()
            .expect("validated: enabled=true implies oidc exists");

        // 读取 client_secret (若配了 client_secret_file).
        let client_secret = match &oidc_cfg.client_secret_file {
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .map_err(|e| {
                        anyhow::anyhow!("read client_secret_file {}: {e}", path.display())
                    })?
                    .trim()
                    .to_string(),
            ),
            None => None,
        };

        // redirect_url: 显式配置优先, 否则由 host + 实际监听 port 派生 (port=0
        // 时配置值会派生 http://host:0 — 浏览器实际访问的是真实端口).
        let redirect_url = oidc_cfg
            .redirect_url
            .clone()
            .unwrap_or_else(|| format!("http://{host}:{listen_port}/oauth2/callback"));

        info!(
            issuer = %oidc_cfg.issuer_url,
            client_id = %oidc_cfg.client_id,
            "OIDC auth enabled, discovering IdP metadata..."
        );

        let backend = OidcBackend::discover(
            &oidc_cfg.issuer_url,
            &oidc_cfg.client_id,
            client_secret,
            &redirect_url,
        )
        .await
        .map_err(|e| anyhow::anyhow!("OIDC initialization failed: {e}"))?;

        // api_keys 已在 auth 分支外构造 (与 AppState 共享同一份).
        let auth_stack = AuthStack {
            backend,
            api_keys,
            secure_cookie: auth_config.secure_cookie,
        };
        build_router_with_auth(proxy, auth_stack, host_guard)
    } else {
        build_router(proxy, host_guard)
    };

    let auth_mode = if auth_config.enabled {
        "OIDC"
    } else {
        "single-user"
    };
    info!(%addr, %auth_mode, ?state_path, "secret-guard listening (Ctrl-C to stop)");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("axum serve failed")?;
    Ok(())
}

/// 绑定监听端口, 失败时把 OS 错误 (事实) 放在首行、把猜测性提示降为 hint (#164 子项 4).
///
/// 历史文案 `bind {addr} failed: is another secret-guard already running?` 把猜测当
/// 首行事实 — 实际占用者可以是任意进程 (实测 python 占位脚本即触发). 现在首行只
/// 陈述事实 (bind 失败 + OS 错误的完整 Display, 如 "Address already in use (os error 98)"),
/// 猜测性排查提示作为 hint 行附注且明确标示为猜测.
async fn bind_listener(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    TcpListener::bind(addr).await.map_err(|e| {
        anyhow::anyhow!(
            "bind {addr} failed: {e}\n  \
             hint: the port may be taken by another process (perhaps another \
             secret-guard instance?); check with `ss -ltnp | grep :{port}` or \
             pick another port (--port flag or [server] port in config)",
            port = addr.port(),
        )
    })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install ctrl_c handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received Ctrl-C, shutting down"),
        _ = terminate => info!("received SIGTERM, shutting down"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #164 子项 4: 端口被占时首行陈述事实 ("Address already in use"), 不再断言式猜测.
    /// 猜测只允许出现在 hint 行 (且仅作为附注, 不进 anyhow Caused by 链的首行).
    #[tokio::test]
    async fn bind_error_reports_fact_first_guess_as_hint() {
        // 真占一个端口 (持有 listener 不 drop), 再绑同端口 → AddrInUse.
        let holder = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = holder.local_addr().unwrap();
        let err = bind_listener(addr).await.unwrap_err();
        let msg = format!("{err:#}");
        let first_line = msg.lines().next().unwrap_or_default();
        // 事实: 首行含 bind + 地址 + OS 错误 Display.
        assert!(first_line.contains("bind"), "first line: {first_line}");
        assert!(
            first_line.contains(&addr.to_string()),
            "first line: {first_line}"
        );
        assert!(
            first_line.contains("Address already in use"),
            "first line must state the OS fact: {first_line}"
        );
        // 不再把猜测当事实: 首行不得含猜测性问句 (它只允许出现在 hint 行).
        assert!(
            !first_line.contains("already running"),
            "first line must not assert a guess: {first_line}"
        );
        // hint: 猜测性提示存在且明确标示为猜测.
        assert!(msg.contains("hint:"), "full message: {msg}");
        assert!(
            msg.contains("another process (perhaps another secret-guard instance?)"),
            "guess must be explicitly marked as a guess: {msg}"
        );
    }

    /// SEC-3 (SEC-C4a): trace span 只记 path, 不记 query — query 可能携带
    /// key/token 类敏感参数. 本测试锁定 "取 path 后不含 '?'" 的性质, 宏调用处
    /// (trace_layer!) 依赖该性质丢弃 query.
    #[test]
    fn trace_span_no_query_string() {
        let uri: axum::http::Uri = "/v1/chat/completions?api-key=sk-secret&x=1"
            .parse()
            .unwrap();
        let path = uri.path();
        assert_eq!(path, "/v1/chat/completions");
        assert!(!path.contains('?'), "path must not carry query: {path}");
    }

    // ─── 运行时工件路径派生: 跟随 state 目录 (固定名) ─────────────────────
    //
    // 回归 2026-09-12 home-pc 生产事故, 根因详见 state_dir_artifact docstring.
    // config 无关性由函数签名固定 (不接收 config 参数), 无需运行时断言.
    #[test]
    fn runtime_artifacts_follow_state_dir_with_fixed_name() {
        let state = Path::new("/var/lib/secret-guard/state.toml");
        assert_eq!(
            state_dir_artifact(state, "usage.sqlite3"),
            PathBuf::from("/var/lib/secret-guard/usage.sqlite3"),
            "usage 库必须落 state 目录且用固定名 (StateDirectory 可写域)"
        );
        assert_eq!(
            state_dir_artifact(state, "pricing.json"),
            PathBuf::from("/var/lib/secret-guard/pricing.json"),
            "定价缓存同一规则 (同类运行时可写工件)"
        );
    }

    #[test]
    fn runtime_artifacts_bare_state_path_derives_cwd_relative() {
        // 相对裸文件名 state (无目录成分): 产物也落裸文件名 (cwd 相对), 不引入
        // 冗余 "./" 前缀.
        assert_eq!(
            state_dir_artifact(Path::new("state.toml"), "usage.sqlite3"),
            PathBuf::from("usage.sqlite3")
        );
    }
}
