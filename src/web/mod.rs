//! Web UI 模块: 转发记录浏览器 + (第三步起) secret 配置面板.
//!
//! 路由前缀 `/__sg` 与业务流量隔离, 由 [`crate::server::build_router`] 通过
//! `Router::nest` 挂载. 子路由:
//! - `GET /__sg`                —— 单页 HTML (内嵌 CSS + vanilla JS, 零外部依赖)
//! - `GET /__sg/api/records`    —— 所有转发记录列表 (JSON)
//! - `GET /__sg/api/records/:id`—— 单条记录详情 (JSON)
//!
//! 注意: axum 0.8 的 `nest("/__sg", ...)` 默认匹配不带尾斜杠的 `/__sg`, 而不是 `/__sg/`.
//! server.rs 中显式注册了 `/__sg/` -> `/__sg` 的 redirect, 保证两种 URL 都可用.

mod api;

use axum::{response::Html, routing::get, Router};

use crate::proxy::ProxyState;

/// 内嵌的 HTML 单页 (build 时 `include_str!`).
const INDEX_HTML: &str = include_str!("index.html");

/// 构建 `/__sg` 子 Router. 复用主 Router 的 `ProxyState`.
pub fn router() -> Router<ProxyState> {
    Router::new()
        .route("/", get(index))
        .route("/api/records", get(api::list_records))
        .route("/api/records/{id}", get(api::get_record))
}

/// `/__sg/` -> `/__sg` 的 trailing-slash redirect.
pub async fn slash_redirect() -> axum::response::Redirect {
    axum::response::Redirect::permanent("/__sg")
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}
