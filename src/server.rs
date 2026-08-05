//! axum router 装配与服务启动.
//!
//! # 路由策略
//! - `/`                —— Web UI 入口 (新, 便于用户直接打开浏览器访问根 URL).
//! - `/__sg`, `/__sg/*` —— Web UI + JSON API (保留旧入口以向后兼容).
//! - `/{proto}/{name}`        —— forward (`rest = "/"`).
//! - `/{proto}/{name}/{*rest}`—— forward (含 sub-path).
//! - 其他 —— 404 (不再 catch-all 透传, 避免误转发 + 明确契约).
//!
//! # 认证 (可选, 由 `[auth] enabled` 控制)
//!
//! `auth.enabled = false` (默认): 单用户模式, 所有路由无认证 (向后兼容).
//! `auth.enabled = true`: 双轨认证 —
//! - 浏览器 WebUI (`/__sg/*`): OIDC Authorization Code + PKCE → cookie session.
//! - SDK 转发 (`/{o|a|g|l}/*`): 本地 API key (`Authorization: Bearer sg_...`).
//!
//! ApiKeyStore 总是构造 (与 `auth.enabled` 无关), 让 WebUI 在单用户模式下也能
//! 管理和预配置 key. `/api/api-keys` CRUD 路由在 `web::router()` 里无条件挂载
//! (不隔离, 见 `src/web/api.rs`); `require_api_key` middleware 仅在 auth 启用时挂载
//! 到 forwarding 路径.
//!
//! # 协议简写
//! `o`=OpenAI, `a`=Anthropic, `g`=Gemini, `l`=oLLama. 见 [`crate::provider::Protocol`].
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
//! | `PARSED_SYNC_INTERVAL` | 500 ms | `proxy/record.rs` | 流式 parsed view 节流写入间隔 (UX 与锁竞争折中) | 时间常量, 不占内存 |
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
use std::path::PathBuf;
use std::sync::Arc;

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
use crate::proxy::{ProxyState, forward, forward_no_rest};
use crate::secrets::{SecretEntry, SecretTable};
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
            tracing::info_span!(
                "http.request",
                method = %request.method(),
                uri = %request.uri(),
                version = ?request.version(),
            )
        })
    };
}

/// 构建 axum Router (单用户模式, 无认证).
///
/// 这是 `auth.enabled = false` 时的入口, 与旧版完全兼容.
pub fn build_router(state: ProxyState) -> Router {
    build_router_inner(state, None)
}

/// 构建 axum Router (带认证).
///
/// `auth_stack` 由 [`serve`] 在启用认证时构造.
pub fn build_router_with_auth(state: ProxyState, auth_stack: AuthStack) -> Router {
    build_router_inner(state, Some(auth_stack))
}

/// 内部: 根据 auth_stack 是否存在, 条件化装配认证 layer.
fn build_router_inner(state: ProxyState, auth_stack: Option<AuthStack>) -> Router {
    // Forward router: 使用 ProxyState, 在 merge 前不调用 with_state.
    let forward_router: Router<ProxyState> = Router::new()
        .route("/{proto}/{name}", any(forward_no_rest))
        .route("/{proto}/{name}/{*rest}", any(forward));

    match auth_stack {
        None => {
            // 单用户模式: 所有路由无认证.
            Router::new()
                .route("/", get(web::index_handler))
                .nest("/__sg", web::router())
                .route("/__sg/", get(web::slash_redirect))
                .route("/__sg/{*rest}", get(web::not_found))
                .merge(forward_router)
                .with_state(state)
                .layer(trace_layer!())
        }
        Some(auth) => build_router_with_auth_layers(state, auth, forward_router),
    }
}

/// 认证层的完整装配状态 (启用认证时由 serve 构造).
pub struct AuthStack {
    pub backend: OidcBackend,
    pub api_keys: ApiKeyStore,
}

/// 构建带认证的 router.
///
/// - WebUI 路由: OIDC session guard (login_required).
/// - 转发路由: API key middleware (require_api_key).
/// - 登录路由 (/login, /callback, /logout): 公开 (不需要认证).
fn build_router_with_auth_layers(
    state: ProxyState,
    auth: AuthStack,
    forward_router: Router<ProxyState>,
) -> Router {
    use axum_login::AuthManagerLayerBuilder;

    let AuthStack { backend, api_keys } = auth;
    let auth_state = crate::auth::handlers::AuthState {
        backend: backend.clone(),
        api_keys: api_keys.clone(),
    };

    // 公开路由 (login/callback/logout/me): 不挂 login_required guard.
    // AuthState 通过 Extension 注入 (与 ProxyState 的 State 槽位正交).
    // me handler 不需要 AuthState, 只需要 AuthSession.
    let webui_public: Router<ProxyState> = Router::new()
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

    // 受保护路由: WebUI, 需要 login_required guard + ProxyState.
    // 注: /api/api-keys CRUD 不在此处挂载 — 见 `web::router()` (无条件挂载, 不隔离用户).
    let webui_protected: Router<ProxyState> = web::router().route_layer(
        axum_login::login_required!(OidcBackend, login_url = "/__sg/login"),
    );

    // 转发路由: 应用 API key middleware.
    // from_fn_with_state 在 layer 层注入 ApiKeyStore, 不改变 Router 的 state 类型.
    let forward_protected = forward_router.route_layer(middleware::from_fn_with_state(
        api_keys,
        crate::auth::require_api_key,
    ));

    // session + auth layer (应用于整个 app).
    let session_layer = crate::auth::build_session_layer();
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();

    Router::new()
        // auth 模式下根路径重定向到 /__sg (受 login_required 保护).
        .route("/", get(|| async { axum::response::Redirect::to("/__sg") }))
        .nest("/__sg", webui_public.merge(webui_protected))
        .route("/__sg/", get(web::slash_redirect))
        .route("/__sg/{*rest}", get(web::not_found))
        .merge(forward_protected)
        .with_state(state)
        .layer(auth_layer)
        .layer(trace_layer!())
}

/// 构造 reqwest 客户端 (与上游连接复用).
///
/// gzip/brotli/deflate 自动解压由 Cargo.toml 的 reqwest features 控制 —
/// 启用 feature 后 reqwest 自动解压并剥除 content-encoding header,
/// 无需在 builder 上调 `.gzip(true)` (调了反而是冗余).
pub fn build_upstream_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("secret-guard/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build upstream client")
}

/// 启动服务. 阻塞直到 shutdown 信号到达且 drain 完成.
///
/// - `static_providers` / `static_secrets`: 来自 `secret-guard.toml`, 进程内只读.
/// - `dyn_state`: 来自 `secret-guard.state.toml`, 拆为 dynamic 列表 + decisions.
/// - `state_path`: state.toml 的写回路径.
/// - `auth_config`: 认证配置 (来自 static config 的 `[auth]` 段).
/// - `global_mock_prefix`: 来自 static config 的 `[redact] global_mock_prefix`,
///   存入 ProxyState 供 WebUI handler 在 secret upsert 时校验 + resolve.
/// - `on_probe_exhausted`: 来自 static config 的 `[redact] on_probe_exhausted`,
///   存入 ProxyState 供 forwarding 路径决定 probing 耗尽时 fail-open / fail-closed.
#[allow(clippy::too_many_arguments)]
pub async fn serve(
    host: &str,
    port: u16,
    records_capacity: usize,
    static_providers: Vec<Provider>,
    static_secrets: Vec<SecretEntry>,
    dyn_state: crate::config::DynamicState,
    state_path: PathBuf,
    config_path: PathBuf,
    auth_config: AuthConfig,
    global_mock_prefix: String,
    on_probe_exhausted: crate::config::OnProbeExhausted,
) -> anyhow::Result<()> {
    auth_config.validate().map_err(|e| anyhow::anyhow!(e))?;

    let upstream = build_upstream_client()?;
    let dag = ConversationDag::new(records_capacity, 500, 1);

    // 跨表共享: persist_lock 串行整个 RMW, decisions 是同一份 mutable map.
    let persist_lock = Arc::new(Mutex::new(()));
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

    let proxy = ProxyState {
        upstream,
        providers: provider_table,
        dag,
        secrets: secret_table,
        api_keys: Some(api_keys.clone()),
        auth_enabled: auth_config.enabled,
        global_mock_prefix: Arc::from(global_mock_prefix),
        on_probe_exhausted,
    };

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

        // redirect_url: 显式配置优先, 否则由 host+port 派生 (历史行为).
        let redirect_url = oidc_cfg
            .redirect_url
            .clone()
            .unwrap_or_else(|| format!("http://{host}:{port}/__sg/oauth2/callback"));

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

        // api_keys 已在 auth 分支外构造 (与 ProxyState 共享同一份).
        let auth_stack = AuthStack { backend, api_keys };
        build_router_with_auth(proxy, auth_stack)
    } else {
        build_router(proxy)
    };

    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .with_context(|| format!("invalid listen address {host}:{port}"))?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr} failed: is another secret-guard already running?"))?;
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
