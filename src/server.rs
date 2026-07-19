//! axum router 装配与服务启动.
//!
//! 路由策略: 所有路径都进入 [`proxy::forward`] handler, 实现透明转发.
//! 第二步会引入 `/__sg/*` 命名空间作为 Web UI / API 入口 (与业务流量隔离).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::{routing::any, Router};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::proxy::{forward, ProxyState};
use crate::record::RecordStore;

/// 进程级服务句柄. 在 Web UI / 配置热加载等场景下复用.
#[derive(Clone)]
pub struct AppState {
    pub proxy: ProxyState,
}

impl AppState {
    pub fn new(proxy: ProxyState) -> Self {
        Self { proxy }
    }
}

/// 构建 axum Router.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        // catch-all: 任意方法 + 任意路径透传到上游.
        .route("/{*path}", any(forward))
        .route("/", any(forward))
        .with_state(state.proxy)
        .layer(TraceLayer::new_for_http())
}

/// 构造 reqwest 客户端 (与上游连接复用).
pub fn build_upstream_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("secret-guard/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build upstream client")
}

/// 启动服务. 阻塞直到 shutdown.
pub async fn serve(
    host: &str,
    port: u16,
    upstream_base: String,
    records_capacity: usize,
) -> anyhow::Result<()> {
    let upstream = build_upstream_client()?;
    let records = RecordStore::new(records_capacity);
    let proxy = ProxyState::new(upstream, upstream_base, records);
    let state = AppState::new(proxy);
    let app = build_router(state);

    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .with_context(|| format!("invalid listen address {host}:{port}"))?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr} failed: is another secret-guard already running?"))?;
    info!(%addr, "secret-guard listening");
    axum::serve(listener, app)
        .await
        .context("axum serve failed")?;
    Ok(())
}

// 防止 unused 警告 (Arc 后续会被引入).
#[allow(dead_code)]
type _ArcState = Arc<()>;
