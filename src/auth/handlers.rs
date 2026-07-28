//! OIDC 登录 / 回调 / 登出 handler.
//!
//! # 路由
//!
//! - `GET/POST /__sg/login` — 发起 OIDC 流程 (生成 PKCE + nonce, redirect 到 IdP).
//! - `GET /__sg/oauth2/callback` — IdP 回调 (交换 token, 验证 ID token, 登录).
//! - `POST /__sg/logout` — 清除 session.
//! - `GET /__sg/api/me` — 返回当前登录用户信息.
//!
//! # Session key
//!
//! OIDC 流程中需要跨请求传递 PKCE verifier + nonce + CSRF state, 存在 server-side
//! session 的以下 key 中:
//! - `oidc.pkce_verifier`
//! - `oidc.nonce`
//! - `oidc.csrf_state`
//! - `oidc.next_url` (登录后回跳的原始 URL)

use axum::Extension;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Redirect, Response};
use serde::Deserialize;
use tower_sessions::Session;

use crate::auth::ApiKeyStore;
use crate::auth::oidc::{AuthSession, OidcBackend};
use crate::web::NO_STORE;

/// session 中存储 PKCE verifier 的 key.
const SK_PKCE_VERIFIER: &str = "oidc.pkce_verifier";
/// session 中存储 nonce 的 key.
const SK_NONCE: &str = "oidc.nonce";
/// session 中存储 CSRF state 的 key.
const SK_CSRF_STATE: &str = "oidc.csrf_state";
/// session 中存储登录后回跳 URL 的 key.
const SK_NEXT_URL: &str = "oidc.next_url";

/// 共享状态: 供 login/callback handler 访问 OIDC backend + API key store.
/// 通过 axum Extension 注入 (不占用 Router 的 State 槽位, 让 ProxyState 保持唯一 State).
#[derive(Clone, Debug)]
pub struct AuthState {
    pub backend: OidcBackend,
    pub api_keys: ApiKeyStore,
}

/// 发起 OIDC 流程: 生成 PKCE + nonce + CSRF state, redirect 到 IdP.
///
/// 同时处理 GET 和 POST (`?next=/path` 指定登录后回跳的 URL).
/// GET 直接发起流程 (无中间登录页), 避免无限重定向.
pub async fn login_start(
    Extension(auth): Extension<AuthState>,
    session: Session,
    Query(next_query): Query<NextQuery>,
) -> Response {
    let parts = auth.backend.authorize_url();

    // 存 verifier + nonce + state 到 server-side session (绝不放 cookie).
    if let Err(e) = session.insert(SK_PKCE_VERIFIER, &parts.pkce_verifier).await {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    if let Err(e) = session.insert(SK_NONCE, &parts.nonce).await {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    if let Err(e) = session.insert(SK_CSRF_STATE, &parts.csrf_state).await {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    // next URL: 只接受站内相对路径 (防 open redirect); 无效时清除旧值.
    match next_query.next.as_deref().and_then(sanitize_next_url) {
        Some(safe) => {
            let _ = session.insert(SK_NEXT_URL, safe).await;
        }
        None => {
            let _ = session.remove::<String>(SK_NEXT_URL).await;
        }
    }

    Redirect::to(parts.auth_url.as_str()).into_response()
}

/// IdP 回调查询参数.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
    /// IdP 返回的错误 (如用户拒绝授权).
    #[serde(default, rename = "error")]
    pub error: Option<String>,
    #[serde(default, rename = "error_description")]
    pub error_description: Option<String>,
}

/// 登录后回跳查询参数.
#[derive(Debug, Default, Deserialize)]
pub struct NextQuery {
    #[serde(default)]
    pub next: Option<String>,
}

/// IdP 回调: 验证 state, 交换 token, 登录.
pub async fn oauth_callback(
    mut auth_session: AuthSession,
    session: Session,
    Query(q): Query<CallbackQuery>,
) -> Response {
    // IdP 返回错误 (如用户拒绝授权).
    if let Some(err) = &q.error {
        let desc = q.error_description.as_deref().unwrap_or("");
        return error_response(
            StatusCode::UNAUTHORIZED,
            format!("OIDC provider error: {err} ({desc})"),
        );
    }

    // 从 session 取出 PKCE verifier + nonce + CSRF state.
    let pkce_verifier = require_session_value(&session, SK_PKCE_VERIFIER, "PKCE verifier").await;
    let pkce_verifier: String = match pkce_verifier {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let nonce = require_session_value(&session, SK_NONCE, "nonce").await;
    let nonce: String = match nonce {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let old_state = require_session_value(&session, SK_CSRF_STATE, "CSRF state").await;
    let old_state: String = match old_state {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // 清理 session 中的临时凭证 (一次性使用).
    let _ = session.remove::<String>(SK_PKCE_VERIFIER).await;
    let _ = session.remove::<String>(SK_NONCE).await;
    let _ = session.remove::<String>(SK_CSRF_STATE).await;

    // 构造 Credentials, 交给 backend.authenticate.
    let creds = crate::auth::OidcCredentials {
        code: q.code,
        pkce_verifier,
        nonce,
        old_state,
        new_state: q.state,
    };

    match auth_session.authenticate(creds).await {
        Ok(Some(user)) => {
            if let Err(e) = auth_session.login(&user).await {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, e);
            }
            let next: Option<String> = session.get(SK_NEXT_URL).await.ok().flatten();
            let _ = session.remove::<String>(SK_NEXT_URL).await;
            let target = next.as_deref().unwrap_or("/__sg");
            Redirect::to(target).into_response()
        }
        Ok(None) => error_response(StatusCode::UNAUTHORIZED, "authentication failed"),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// 登出: 清除 session.
pub async fn logout(mut auth_session: AuthSession) -> Response {
    let _ = auth_session.logout().await;
    Redirect::to("/__sg/login").into_response()
}

/// 返回当前登录用户信息 (WebUI header 显示用).
pub async fn me(auth_session: AuthSession) -> impl IntoResponse {
    let body = match &auth_session.user {
        Some(user) => serde_json::json!({
            "authenticated": true,
            "sub": user.sub,
            "email": user.email,
            "name": user.name,
        }),
        None => serde_json::json!({"authenticated": false}),
    };
    (StatusCode::OK, NO_STORE, Json(body))
}

// ─── Helpers ──────────────────────────────────────────────────────────────

/// 从 session 取出一个必须存在的值, 缺失则返回 400 error response.
async fn require_session_value<T: serde::de::DeserializeOwned>(
    session: &Session,
    key: &str,
    what: &str,
) -> Result<T, Response> {
    match session.get::<T>(key).await {
        Ok(Some(v)) => Ok(v),
        _ => Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("missing {what} in session (session expired?)"),
        )),
    }
}

/// 构造错误响应 (统一 JSON envelope + no-store).
fn error_response(status: StatusCode, e: impl std::fmt::Display) -> Response {
    tracing::error!(status = %status, error = %e, "OIDC auth error");
    (
        status,
        NO_STORE,
        Json(serde_json::json!({ "error": e.to_string() })),
    )
        .into_response()
}

/// 校验 next URL: 只允许站内相对路径, 防止 open redirect.
///
/// 合法: `/path`, `/__sg/records`
/// 非法: `https://evil.com`, `//evil.com`, `/\\evil.com`
fn sanitize_next_url(next: &str) -> Option<&str> {
    if next.starts_with('/')
        && !next.starts_with("//")
        && !next.starts_with("/\\")
        && !next.contains('\n')
        && !next.contains('\r')
    {
        Some(next)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_next_url_accepts_relative_paths() {
        assert_eq!(sanitize_next_url("/__sg/records"), Some("/__sg/records"));
        assert_eq!(sanitize_next_url("/"), Some("/"));
        assert_eq!(sanitize_next_url("/a/b/c"), Some("/a/b/c"));
    }

    #[test]
    fn sanitize_next_url_rejects_absolute_urls() {
        assert_eq!(sanitize_next_url("https://evil.com"), None);
        assert_eq!(sanitize_next_url("http://evil.com"), None);
        assert_eq!(sanitize_next_url("//evil.com"), None);
        assert_eq!(sanitize_next_url("/\\evil.com"), None);
    }

    #[test]
    fn sanitize_next_url_rejects_crlf_injection() {
        assert_eq!(sanitize_next_url("/\nevil"), None);
        assert_eq!(sanitize_next_url("/\revil"), None);
    }
}
