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
///   **生产注意**: 经反向代理暴露 HTTPS 时此设置会让 session cookie 不带 Secure flag,
///   详见 `docs/deployment-nixos.md` "HTTPS 反向代理" 段. 根治 (配置开关 / X-Forwarded-Proto
///   推断) 是后续工作.
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

#[cfg(test)]
mod tests {
    //! build_session_layer 的配置正确性单测.
    //!
    //! SessionManagerLayer 的 builder 方法都是私有字段 setter, 无公共 getter 可直接断言.
    //! 故用 "构造 layer → 挂到 axum Router → 起最小 server → 检查响应 Set-Cookie" 的端到端
    //! 方式验证配置生效 (与 tests/integration.rs 同模式, 不引入额外依赖). 守卫两条契约:
    //!   1. cookie 名为 "sg.sid" (前端 / OIDC callback 依赖此名读 session).
    //!   2. cookie 带 HttpOnly (XSS 防护红线, build_session_layer 注释明示不可改).

    use axum::Router;
    use axum::routing::get;

    use super::*;

    #[tokio::test]
    async fn session_layer_emits_cookie_with_configured_name_and_httponly() {
        // 挂 build_session_layer 到最小 Router, 探针 handler 写一个 session 值
        // 触发 Set-Cookie 写回 (tower-sessions 仅对已修改 session 写 cookie;
        // 空 session.save() 是 no-op).
        let app = Router::new()
            .route(
                "/",
                get(|session: tower_sessions::Session| async move {
                    session.insert("k", "v").await.ok();
                    axum::http::StatusCode::NO_CONTENT
                }),
            )
            .layer(build_session_layer());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service()).await;
        });

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap();
        // 修改过的 session 触发 layer 写回 Set-Cookie.
        let set_cookie = resp
            .headers()
            .get(reqwest::header::SET_COOKIE)
            .expect("Set-Cookie header should be present after session modification");
        let val = set_cookie.to_str().unwrap();
        assert!(
            val.contains("sg.sid="),
            "cookie name must be 'sg.sid', got: {val}"
        );
        assert!(
            val.to_ascii_lowercase().contains("httponly"),
            "cookie must carry HttpOnly (XSS 红线), got: {val}"
        );
    }
}
