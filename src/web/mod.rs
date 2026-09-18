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
//! - `POST /api/providers/probe` —— base_url 协议自动探测 (探测算法在
//!   `proxy::models`, 薄壳 handler 在 `api/providers.rs`).
//! - `PUT/DELETE /api/providers/probe` —— 存量 id="probe" 条目的管理薄 wrapper
//!   (静态段阴影 {id} 路由的 405 补齐, 见 `api::update_provider_probe`).
//! - `POST /api/providers/{id}/pool-reset` —— pool 条目成员闹钟清空
//!   (两段路径与 `{id}/decision` 同型, 见 `api::pool_reset`).
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

use crate::state::{AppState, NO_STORE};

/// 内嵌的 HTML 单页 (build 时 `include_str!`).
const INDEX_HTML: &str = include_str!("index.html");

/// `/` 根入口的 index handler.
///
/// 带 NO_STORE (含 nosniff, SEC-S1): WebUI HTML 与 API 响应同一安全 header 组.
pub async fn index_handler() -> impl axum::response::IntoResponse {
    (StatusCode::OK, NO_STORE, Html(INDEX_HTML))
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
        .route("/api/usage/summary", get(api::usage_summary))
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
        // 协议探测 (POST) + 存量 id="probe" 条目的管理 wrapper (PUT/DELETE 以
        // 固定 id 适配到 update/delete flow, api/providers.rs). 静态段优先于
        // {id} 参数段: 该 id 的 PUT/DELETE 只能经此路由进 — 补齐前存量条目
        // 不可编辑/删除 (405), 新建该 id 仍被 upsert 校验拒绝 (纯防混淆) — 见
        // url-layout.md.
        .route(
            "/api/providers/probe",
            post(api::probe_provider)
                .put(api::update_provider_probe)
                .delete(api::delete_provider_probe),
        )
        .route(
            "/api/providers/{id}",
            axum::routing::put(api::update_provider).delete(api::delete_provider),
        )
        .route(
            "/api/providers/{id}/decision",
            patch(api::set_provider_decision),
        )
        // pool 条目成员闹钟清空 (T3; 两段路径与 {id}/decision 同型 — 静态尾段
        // 优先于任何未来单段扩展, 无 "probe" 型阴影问题).
        .route("/api/providers/{id}/pool-reset", post(api::pool_reset))
        // API key CRUD: 无条件挂载 (不依赖 auth.enabled), 不做用户隔离.
        // 设计哲学: 只认证, 不隔离 — 见 src/web/api/apikeys.rs 头部注释.
        //
        // 安全契约: auth 启用时, 整个 web::router() (含本段) 都被上层
        // login_required guard 守卫 (server.rs build_router_with_auth_layers).
        // auth 关闭时, 单用户模式默认本地监听 (127.0.0.1) + server 层 Host guard
        // (src/server_host_guard.rs, SEC-7) 防 DNS rebinding — 外部页面的域名
        // Host 无法通过校验; /api/* 写操作另由 Origin/Sec-Fetch-Site 纵深校验
        // 兜底 ("同源策略兜底" 的旧假设已被 rebinding 攻破, 不再单独依赖).
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
pub async fn not_found() -> impl axum::response::IntoResponse {
    (StatusCode::NOT_FOUND, NO_STORE, "not found")
}
