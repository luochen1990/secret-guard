//! axum router 装配与服务启动.
//!
//! 路由策略:
//! - `/__sg/*` 走 [`web`] 子路由 (Web UI + JSON API).
//! - 其他所有路径进入 [`proxy::forward`] handler, 实现透明转发.
//!
//! axum 按精确匹配优先, `/__sg/*` 不会被 catch-all 吞掉.
//!
//! Shutdown: 默认监听 SIGTERM / Ctrl-C, axum 进入 graceful shutdown 期间不再接受新连接,
//! 已建立的连接会等到完成或超时.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use axum::{
    routing::{any, get},
    Router,
};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::proxy::{forward, ProxyState};
use crate::record::RecordStore;
use crate::secrets::{SecretEntry, SecretTable};
use crate::web;

/// 构建 axum Router.
pub fn build_router(state: ProxyState) -> Router {
    Router::new()
        // Web UI / API (与业务流量隔离).
        .nest("/__sg", web::router())
        .route("/__sg/", get(web::slash_redirect))
        // `/__sg/*` 中未匹配的子路径必须返回 404, 避免被 catch-all 吞掉并转发到上游
        // (否则用户配错 URL 时会泄漏 secret-guard 的内部 URL 给 LLM provider).
        .route("/__sg/{*rest}", get(web::not_found))
        // catch-all: 任意方法 + 任意路径透传到上游.
        .route("/", any(forward))
        .route("/{*path}", any(forward))
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
    upstream_base: String,
    records_capacity: usize,
    config_path: PathBuf,
    secrets: Vec<SecretEntry>,
) -> anyhow::Result<()> {
    let upstream = build_upstream_client()?;
    let records = RecordStore::new(records_capacity);
    let secret_table = SecretTable::new(secrets, config_path.clone());
    let proxy = ProxyState {
        upstream,
        upstream_base,
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
    info!(%addr, "secret-guard listening (Ctrl-C to stop)");
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
