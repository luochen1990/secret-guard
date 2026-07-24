//! Session layer 装配 (tower-sessions).
//!
//! 用 MemoryStore (MVP): 进程重启丢 session, 用户需重新登录.
//! 后续可平滑切 SQLite/Redis store (tower-sessions 可插拔).

use tower_sessions::{
    Expiry, MemoryStore, SessionManagerLayer, cookie::SameSite,
    cookie::time::Duration as CookieDuration,
};

/// 构造 SessionManagerLayer (MemoryStore).
///
/// - `with_secure(false)`: 本地 HTTP dev 必须 false, 否则浏览器不回传 cookie.
/// - `with_same_site(Lax)`: OIDC callback 跨站重定向需要 Lax (Strict 会阻断).
/// - `with_http_only(true)`: 防 XSS 读取 cookie (默认, 不要改).
/// - `with_expiry(OnInactivity 1 day)`: 1 天不活动后过期.
pub fn build_session_layer() -> SessionManagerLayer<MemoryStore> {
    SessionManagerLayer::new(MemoryStore::default())
        .with_secure(false)
        .with_same_site(SameSite::Lax)
        .with_http_only(true)
        .with_name("sg.sid")
        .with_path("/")
        .with_expiry(Expiry::OnInactivity(CookieDuration::days(1)))
}
