//! axum router 装配与服务启动.
//!
//! # 路由策略
//! - `/`                —— Web UI 入口 (新, 便于用户直接打开浏览器访问根 URL).
//! - `/__sg`, `/__sg/*` —— Web UI + JSON API (保留旧入口以向后兼容).
//! - `/{proto}/{name}`        —— forward (`rest = "/"`).
//! - `/{proto}/{name}/{*rest}`—— forward (含 sub-path).
//! - 其他 —— 404 (不再 catch-all 透传, 避免误转发 + 明确契约).
//!
//! # 协议简写
//! `o`=OpenAI, `a`=Anthropic, `g`=Gemini, `l`=oLLama. 见 [`crate::provider::Protocol`].
//!
//! # Shutdown
//! 默认监听 SIGTERM / Ctrl-C, axum 进入 graceful shutdown 期间不再接受新连接,
//! 已建立的连接会等到完成或超时.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use axum::{
    routing::{any, get},
    Router,
};
use parking_lot::Mutex;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::provider::{Provider, ProviderTable};
use crate::proxy::{forward, forward_no_rest, ProxyState};
use crate::record::RecordStore;
use crate::secrets::{SecretEntry, SecretTable};
use crate::web;

/// 构建 axum Router.
pub fn build_router(state: ProxyState) -> Router {
    Router::new()
        // 根路径: Web UI (主入口, 替代旧版默认转发到上游).
        .route("/", get(web::index_handler))
        // Web UI / API 命名空间 (保留旧入口).
        .nest("/__sg", web::router())
        .route("/__sg/", get(web::slash_redirect))
        // `/__sg/*` 中未匹配的子路径必须返回 404, 避免被 catch-all 吞掉并转发到上游
        // (否则用户配错 URL 时会泄漏 secret-guard 的内部 URL 给 LLM provider).
        .route("/__sg/{*rest}", get(web::not_found))
        // Forward: `/{proto}/{name}/{*rest}` 同时编码 ingress 协议与目标 provider.
        .route("/{proto}/{name}", any(forward_no_rest))
        .route("/{proto}/{name}/{*rest}", any(forward))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

/// 构造 reqwest 客户端 (与上游连接复用).
pub fn build_upstream_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("secret-guard/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build upstream client")
}

/// 启动服务. 阻塞直到 shutdown 信号到达且 drain 完成.
pub async fn serve(
    host: &str,
    port: u16,
    records_capacity: usize,
    config_path: PathBuf,
    providers: Vec<Provider>,
    secrets: Vec<SecretEntry>,
) -> anyhow::Result<()> {
    let upstream = build_upstream_client()?;
    let records = RecordStore::new(records_capacity);
    // 共享一把 persist_lock 给两个 table, 保证它们对 config 文件的 RMW 串行化,
    // 避免 SecretTable 写完 secrets 段后, ProviderTable 基于旧 cfg 写回把 secrets 覆盖掉.
    let persist_lock = Arc::new(Mutex::new(()));
    let secret_table =
        SecretTable::with_persist_lock(secrets, config_path.clone(), persist_lock.clone());
    let provider_table =
        ProviderTable::with_persist_lock(providers, config_path.clone(), persist_lock);
    let proxy = ProxyState {
        upstream,
        providers: provider_table,
        records,
        secrets: secret_table,
    };
    let app = build_router(proxy);

    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .with_context(|| format!("invalid listen address {host}:{port}"))?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr} failed: is another secret-guard already running?"))?;
    info!(%addr, config = ?config_path, "secret-guard listening (Ctrl-C to stop)");
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
