//! Web UI 模块: 转发记录浏览器 + secret 配置面板 + provider 配置面板.
//!
//! 路由策略 (由 [`crate::server::build_router`] 装配):
//! - `GET /`             —— 单页 HTML (根路径主入口, 新).
//! - `GET /__sg`         —— 同上 (保留旧入口, 向后兼容).
//! - `GET /__sg/api/records[/{id}]`            —— 转发记录 API.
//! - `GET /__sg/api/secrets`                   —— effective secret 列表.
//! - `POST /__sg/api/secrets`                  —— 创建 dynamic secret.
//! - `PUT /__sg/api/secrets/{id}`              —— 编辑 (static 自动 fork).
//! - `DELETE /__sg/api/secrets/{id}`           —— 删除 (仅 dynamic).
//! - `PATCH /__sg/api/secrets/{id}/decision`   —— 切换 OverrideMode.
//! - `GET/POST/PUT/DELETE/PATCH /__sg/api/providers[/{id}[/decision]]` —— 同上.
//!
//! 注意: axum 0.8 的 `nest("/__sg", ...)` 默认匹配不带尾斜杠的 `/__sg`, 而不是 `/__sg/`.
//! server.rs 中显式注册了 `/__sg/` -> `/__sg` 的 redirect (307, 临时), 保证两种 URL 都可用.

mod api;

use axum::{
    http::StatusCode,
    response::Html,
    routing::{get, patch},
    Router,
};

use crate::proxy::ProxyState;

/// 内嵌的 HTML 单页 (build 时 `include_str!`).
const INDEX_HTML: &str = include_str!("index.html");

/// `/` 与 `/__sg` 共用的 index handler.
pub async fn index_handler() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// 构建 `/__sg` 子 Router. 复用主 Router 的 `ProxyState`.
pub fn router() -> Router<ProxyState> {
    Router::new()
        .route("/", get(index_handler))
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
        .route(
            "/api/secrets/{id}/decision",
            patch(api::set_secret_decision),
        )
        .route(
            "/api/providers",
            get(api::list_providers).post(api::create_provider),
        )
        .route(
            "/api/providers/{id}",
            axum::routing::put(api::update_provider).delete(api::delete_provider),
        )
        .route(
            "/api/providers/{id}/decision",
            patch(api::set_provider_decision),
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
