//! axum router 装配与服务启动.
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
use std::path::PathBuf;
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
pub fn build_router(state: AppState) -> Router {
    build_router_inner(state, None)
}

/// 构建 axum Router (带认证).
///
/// `auth_stack` 由 [`serve`] 在启用认证时构造.
pub fn build_router_with_auth(state: AppState, auth_stack: AuthStack) -> Router {
    build_router_inner(state, Some(auth_stack))
}

/// 内部: 根据 auth_stack 是否存在, 条件化装配认证 layer.
/// usage JSONL 的默认路径: 与 static config 同目录, `<stem>.usage.jsonl`
/// (派生规则同 main.rs 的 default_state_path `<stem>.state.toml` 约定, 设计 §4).
fn default_usage_jsonl_path(config_path: &std::path::Path) -> std::path::PathBuf {
    let file_name = config_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("secret-guard.toml");
    let stem = file_name.strip_suffix(".toml").unwrap_or(file_name);
    config_path.with_file_name(format!("{stem}.usage.jsonl"))
}

/// 定价缓存文件路径 (`<stem>.pricing.json`, 与 usage JSONL 同目录; models.dev
/// 原样落盘, 冷启动无网络时读回).
fn default_pricing_json_path(config_path: &std::path::Path) -> std::path::PathBuf {
    let file_name = config_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("secret-guard.toml");
    let stem = file_name.strip_suffix(".toml").unwrap_or(file_name);
    config_path.with_file_name(format!("{stem}.pricing.json"))
}

/// `[usage.pricing_override]` → PricingTable 的 override map (cache 价回退规则
/// 同 models.dev 解析: cache_read → input, cache_write → 1.25×input).
fn price_overrides_to_table(
    o: &std::collections::HashMap<String, crate::config::PriceOverride>,
) -> std::collections::HashMap<String, crate::usage::ModelPrice> {
    o.iter()
        .map(|(k, v)| {
            (
                k.clone(),
                crate::usage::ModelPrice {
                    input: v.input,
                    output: v.output,
                    cache_read: v.cache_read.unwrap_or(v.input),
                    cache_write: v.cache_write.unwrap_or(v.input * 1.25),
                },
            )
        })
        .collect()
}

fn build_router_inner(state: AppState, auth_stack: Option<AuthStack>) -> Router {
    // Forward router: 使用 AppState, 在 merge 前不调用 with_state.
    // 首段 proto 简写 (o/a/g/l/r) 由 dispatch 校验; 顶级保留字 (api/login/logout/oauth2)
    // 的静态路由优先于本参数路由, 二者天然不相交 (见 docs/design/url-layout.md).
    let forward_router: Router<AppState> = Router::new()
        .route("/{proto}/{name}", any(forward_no_rest))
        .route("/{proto}/{name}/{*rest}", any(forward));

    match auth_stack {
        None => {
            // 单用户模式: 所有路由无认证.
            Router::new()
                .merge(web::router())
                .route("/api/{*rest}", any(web::not_found))
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
    state: AppState,
    auth: AuthStack,
    forward_router: Router<AppState>,
) -> Router {
    use axum_login::AuthManagerLayerBuilder;

    let AuthStack { backend, api_keys } = auth;
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
    let session_layer = crate::auth::build_session_layer();
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
        .layer(trace_layer!())
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
    dyn_state: crate::config::DynamicState,
    state_path: PathBuf,
    config_path: PathBuf,
    auth_config: AuthConfig,
    global_mock_prefix: String,
    on_probe_exhausted: crate::config::OnProbeExhausted,
    upstream_timeouts: crate::config::UpstreamTimeouts,
    usage_config: crate::config::UsageConfig,
) -> anyhow::Result<()> {
    auth_config.validate().map_err(|e| anyhow::anyhow!(e))?;

    let upstream = build_upstream_client(upstream_timeouts.connect)?;
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

    let proxy = AppState {
        upstream,
        providers: provider_table,
        dag,
        secrets: secret_table,
        api_keys: api_keys.clone(),
        auth_enabled: auth_config.enabled,
        global_mock_prefix: Arc::from(global_mock_prefix),
        on_probe_exhausted,
        upstream_timeouts,
        model_lists: Arc::new(crate::proxy::ModelListCache::new()),
        usage: Arc::new(crate::usage::UsageStore::open(
            &usage_config,
            &default_usage_jsonl_path(&config_path),
        )),
        pricing: Arc::new(crate::usage::PricingCache::new(
            usage_config.pricing_url.clone(),
            std::time::Duration::from_secs(usage_config.pricing_refresh_secs.max(60)),
            default_pricing_json_path(&config_path),
            price_overrides_to_table(&usage_config.pricing_override),
        )),
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

        // redirect_url: 显式配置优先, 否则由 host+port 派生.
        let redirect_url = oidc_cfg
            .redirect_url
            .clone()
            .unwrap_or_else(|| format!("http://{host}:{port}/oauth2/callback"));

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
        let auth_stack = AuthStack { backend, api_keys };
        build_router_with_auth(proxy, auth_stack)
    } else {
        build_router(proxy)
    };

    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .with_context(|| format!("invalid listen address {host}:{port}"))?;
    let listener = bind_listener(addr).await?;
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
}
