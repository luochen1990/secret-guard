//! Web UI 模块: 转发记录浏览器 + secret 配置面板 + provider 配置面板.
//!
//! 路由策略 (由 [`crate::server::build_router`] 装配):
//! - `GET /`             —— 单页 HTML (根路径主入口, 新).
//! - `GET /__sg`         —— 同上 (保留旧入口, 向后兼容).
//! - `GET /__sg/api/records/{id}`            —— 单条 record raw/parsed view (弹窗用).
//! - `GET /__sg/api/sessions`                —— 会话列表 (首次加载/无选中时).
//! - `GET /__sg/api/sessions/{sid}/timeline` —— session-aware timeline 分页.
//! - `POST /__sg/api/sync`                   —— 统一轮询 (sessions + rounds + timeline diff).
//! - `GET /__sg/api/secrets`                 —— effective secret 列表.
//! - `POST /__sg/api/secrets`                —— 创建 dynamic secret.
//! - `PUT /__sg/api/secrets/{id}`            —— 编辑 (static 自动 fork).
//! - `DELETE /__sg/api/secrets/{id}`         —— 删除 (仅 dynamic).
//! - `PATCH /__sg/api/secrets/{id}/decision` —— 切换 OverrideMode.
//! - `GET/POST/PUT/DELETE/PATCH /__sg/api/providers[/{id}[/decision]]` —— 同上.
//! - `GET/POST/DELETE/PATCH /__sg/api/api-keys[/{id}[/toggle]]` —— API key CRUD (无条件挂载, 见 api.rs).
//!
//! 注: 旧的 `GET /api/records` (扁平分页) + `GET /api/nodes/{id}/timeline` (基于 node_id)
//! 已删除, 由 session-aware sync API 替代.
//!
//! 注意: axum 0.8 的 `nest("/__sg", ...)` 默认匹配不带尾斜杠的 `/__sg`, 而不是 `/__sg/`.
//! server.rs 中显式注册了 `/__sg/` -> `/__sg` 的 redirect (307, 临时), 保证两种 URL 都可用.

pub(crate) mod api;

use axum::{
    Router,
    http::StatusCode,
    response::Html,
    routing::{get, patch, post},
};

use crate::proxy::ProxyState;

/// 共享的 `no-store` header 设置 (axum 的 `[(name, value); N]` 接受 `(&str, &str)`).
///
/// 历史上定义在 `web::api` (资源组 CRUD 模块), 但消费者跨模块:
/// - `web::api` (本模块所有 endpoint).
/// - `crate::auth::handlers` (OIDC login/logout/me 响应).
///
/// 让 `auth` 反向依赖 `web::api` 违反层间单向承诺 (鉴权层是更低层基础设施).
/// 故下沉到本模块 (`web::mod`) 作为整个 web 层的共享常量, `auth/handlers` 从
/// `crate::web::NO_STORE` 取用, 不再触达 `web::api` 的资源组定义.
pub const NO_STORE: [(&str, &str); 1] = [("cache-control", "no-store, no-cache, must-revalidate")];

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
        // 设计哲学: 只认证, 不隔离 — 见 src/web/api.rs 中 /api-keys 段注释.
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
