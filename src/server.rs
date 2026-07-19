//! axum router 装配与服务启动.
//!
//! 路由策略: 所有路径都进入 [`proxy::forward`] handler, 实现透明转发.
//! 第二步会引入 `/__sg/*` 命名空间作为 Web UI / API 入口 (与业务流量隔离).
//!
//! Shutdown: 默认监听 SIGTERM / Ctrl-C, axum 进入 graceful shutdown 期间不再接受新连接,
//! 已建立的连接会等到完成或超时.

use std::net::SocketAddr;

use anyhow::Context;
use axum::{routing::any, Router};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::proxy::{forward, ProxyState};
use crate::record::RecordStore;

/// 构建 axum Router.
pub fn build_router(state: ProxyState) -> Router {
    Router::new()
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
) -> anyhow::Result<()> {
    let upstream = build_upstream_client()?;
    let records = RecordStore::new(records_capacity);
    let proxy = ProxyState {
        upstream,
        upstream_base,
        records,
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
