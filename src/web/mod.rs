//! Web UI 模块: 转发记录浏览器 + secret 配置面板 + provider 配置面板.
//!
//! 路由策略 (由 [`crate::server::build_router`] 装配, URL 布局的 SSOT 见
//! `docs/design/url-layout.md`):
//! - `GET /`                            —— 单页 HTML (唯一 WebUI 入口).
//! - `GET /api/records/{id}`            —— 单条 record raw/parsed view (弹窗用).
//! - `GET /api/sessions`                —— 会话列表 (首次加载/无选中时).
//! - `GET /api/sessions/{sid}/timeline` —— session-aware timeline 分页.
//! - `POST /api/sync`                   —— 统一轮询 (sessions + rounds + timeline diff).
//! - `GET /api/secrets`                 —— effective secret 列表.
//! - `POST /api/secrets`                —— 创建 dynamic secret.
//! - `PUT /api/secrets/{id}`            —— 编辑 (static 自动 fork).
//! - `DELETE /api/secrets/{id}`         —— 删除 (仅 dynamic-only; static 基线一律 409, #156).
//! - `PATCH /api/secrets/{id}/decision` —— 切换 OverrideMode.
//! - `GET/POST/PUT/DELETE/PATCH /api/providers[/{id}[/decision]]` —— 同上.
//! - `GET/POST/DELETE/PATCH /api/api-keys[/{id}[/toggle]]` —— API key CRUD (无条件挂载, 见 api/apikeys.rs).
//!
//! 注 1: 旧的 `GET /api/records` (扁平分页) + `GET /api/nodes/{id}/timeline` (基于 node_id)
//! 已删除, 由 session-aware sync API 替代.
//!
//! 注 2: 旧入口 `/__sg` 前缀已于 URL 硬切重构中移除 (历史可 `git log -S "__sg"` 找回).
//! `/api` 是顶级保留字, 与 forward 命名空间 (`/{o|a|g|l|r}/...` 首段必须是 proto 简写)
//! 天然不相交, 见 url-layout.md "保留字" 一节.

pub(crate) mod api;

use axum::{
    Router,
    http::StatusCode,
    response::Html,
    routing::{get, patch, post},
};

use crate::state::AppState;

/// 内嵌的 HTML 单页 (build 时 `include_str!`).
const INDEX_HTML: &str = include_str!("index.html");

/// `/` 根入口的 index handler.
pub async fn index_handler() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// 构建 WebUI + JSON API 的顶级子 Router (`/api/*` + `/`). 复用主 Router 的 [`AppState`].
///
/// `NO_STORE` 常量已上移 `crate::state` (消费者跨 web/auth 两层, 见 #145 偏差 3).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(index_handler))
        .route("/api/records/{id}", get(api::get_record))
        .route("/api/sessions", get(api::list_sessions))
        .route("/api/sessions/{sid}/timeline", get(api::session_timeline))
        .route("/api/sync", post(api::sync))
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
        // API key CRUD: 无条件挂载 (不依赖 auth.enabled), 不做用户隔离.
        // 设计哲学: 只认证, 不隔离 — 见 src/web/api/apikeys.rs 头部注释.
        //
        // 安全契约: auth 启用时, 整个 web::router() (含本段) 都被上层
        // login_required guard 守卫 (server.rs build_router_with_auth_layers).
        // auth 关闭时, 单用户模式默认本地监听 (127.0.0.1) + 同源策略兜底.
        .route(
            "/api/api-keys",
            get(api::list_api_keys).post(api::create_api_key),
        )
        .route(
            "/api/api-keys/{id}",
            axum::routing::delete(api::delete_api_key),
        )
        .route("/api/api-keys/{id}/toggle", patch(api::toggle_api_key))
}

/// `/api/*` 未匹配子路径的 404 handler (SEC-6: 内部 URL 绝不进入 forward).
pub async fn not_found() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "not found")
}
