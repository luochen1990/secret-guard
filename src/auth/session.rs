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
/// - `secure` (来自 `[auth] secure_cookie`): session cookie 是否带 Secure flag.
///   默认 false (本地 HTTP dev 必须 — true 时浏览器拒绝在 HTTP 连接上回传 cookie,
///   OIDC 流程无法登录). 经反向代理以 HTTPS 暴露 secret-guard 时应设 true, 见
///   `docs/deployment-nixos.md` "HTTPS 反向代理" 段. 从 `X-Forwarded-Proto` 动态
///   推断仍是后续工作.
/// - `with_same_site(Lax)`: OIDC callback 跨站重定向需要 Lax (Strict 会阻断).
/// - `with_http_only(true)`: 防 XSS 读取 cookie (默认, 不要改).
/// - `with_expiry(OnInactivity 1 day)`: 1 天不活动后过期.
pub fn build_session_layer(secure: bool) -> SessionManagerLayer<MemoryStore> {
    SessionManagerLayer::new(MemoryStore::default())
        .with_secure(secure)
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
    //! 方式验证配置生效 (与 tests/integration.rs 同模式, 不引入额外依赖). 守卫三条契约:
    //!   1. cookie 名为 "sg.sid" (前端 / OIDC callback 依赖此名读 session).
    //!   2. cookie 带 HttpOnly (XSS 防护红线, build_session_layer 注释明示不可改).
    //!   3. Secure flag 严格跟随 secure 参数 (true 带 / false 不带 — 反向断言防默认漂移).

    use axum::Router;
    use axum::routing::get;

    use super::*;

    /// 起 mini server 挂给定 secure 配置的 session layer, 探针 handler 写一个 session
    /// 值触发 Set-Cookie 写回 (tower-sessions 仅对已修改 session 写 cookie;
    /// 空 session.save() 是 no-op), 返回响应的 Set-Cookie header 值.
    async fn set_cookie_of(secure: bool) -> String {
        let app = Router::new()
            .route(
                "/",
                get(|session: tower_sessions::Session| async move {
                    session.insert("k", "v").await.ok();
                    axum::http::StatusCode::NO_CONTENT
                }),
            )
            .layer(build_session_layer(secure));

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
        set_cookie.to_str().unwrap().to_string()
    }

    /// Set-Cookie 值 → cookie 属性集合 (按 `;` 切分, 跳过首段 name=value, 其余 trim +
    /// 小写). 精确断言属性的出席/缺席, 避免朴素 contains 误匹配 cookie 值本身 (随机
    /// session id) 的子串.
    fn cookie_attrs(val: &str) -> Vec<String> {
        val.split(';')
            .skip(1)
            .map(|a| a.trim().to_ascii_lowercase())
            .collect()
    }

    #[tokio::test]
    async fn session_layer_secure_false_cookie_has_name_httponly_no_secure() {
        let val = set_cookie_of(false).await;
        assert!(
            val.starts_with("sg.sid="),
            "cookie name must be 'sg.sid', got: {val}"
        );
        let attrs = cookie_attrs(&val);
        assert!(
            attrs.iter().any(|a| a == "httponly"),
            "cookie must carry HttpOnly (XSS 红线), got: {val}"
        );
        assert!(
            !attrs.iter().any(|a| a == "secure"),
            "secure=false must not carry Secure flag, got: {val}"
        );
    }

    #[tokio::test]
    async fn session_layer_secure_true_cookie_carries_secure_flag() {
        let val = set_cookie_of(true).await;
        assert!(
            cookie_attrs(&val).iter().any(|a| a == "secure"),
            "cookie must carry Secure flag when secure=true, got: {val}"
        );
    }
}
