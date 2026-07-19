//! Web UI 模块: 转发记录浏览器 + secret 配置面板.
//!
//! 路由前缀 `/__sg` 与业务流量隔离, 由 [`crate::server::build_router`] 通过
//! `Router::nest` 挂载. 子路由:
//! - `GET /__sg`                  —— 单页 HTML (内嵌 CSS + vanilla JS, 零外部依赖)
//! - `GET /__sg/api/records`      —— 所有转发记录列表 (JSON)
//! - `GET /__sg/api/records/{id}` —— 单条记录详情 (JSON)
//! - `GET /__sg/api/secrets`      —— secret 注册表列表 (value 已脱敏)
//! - `POST /__sg/api/secrets`     —— 新增 secret
//! - `PUT /__sg/api/secrets/{id}` —— 更新 secret
//! - `DELETE /__sg/api/secrets/{id}` —— 删除 secret
//!
//! 注意: axum 0.8 的 `nest("/__sg", ...)` 默认匹配不带尾斜杠的 `/__sg`, 而不是 `/__sg/`.
//! server.rs 中显式注册了 `/__sg/` -> `/__sg` 的 redirect (307, 临时), 保证两种 URL 都可用.

mod api;

use axum::{http::StatusCode, response::Html, routing::get, Router};

use crate::proxy::ProxyState;

/// 内嵌的 HTML 单页 (build 时 `include_str!`).
const INDEX_HTML: &str = include_str!("index.html");

/// 构建 `/__sg` 子 Router. 复用主 Router 的 `ProxyState`.
pub fn router() -> Router<ProxyState> {
    Router::new()
        .route("/", get(index))
        .route("/api/records", get(api::list_records))
        .route("/api/records/{id}", get(api::get_record))
        .route(
            "/api/secrets",
            get(api::list_secrets).post(api::create_secret),
        )
        .route(
            "/api/secrets/{id}",
            axum::routing::put(api::update_secret).delete(api::delete_secret),
        )
}

/// `/__sg/` -> `/__sg` 的 trailing-slash redirect.
///
/// 用 307 (临时) 而非 301 (永久): 避免浏览器永久缓存, 开发期改动路由更安全.
pub async fn slash_redirect() -> axum::response::Redirect {
    axum::response::Redirect::temporary("/__sg")
}

/// `/__sg/*` 中未匹配的子路径返回 404, 防止被 catch-all 转发到上游.
pub async fn not_found() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "not found")
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}
