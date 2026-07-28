//! API key 校验 middleware + AuthenticatedTenant Extension.
//!
//! # 用法
//!
//! 作为 layer 挂在 forward 路由上:
//! ```ignore
//! Router::new()
//!     .route("/{proto}/{name}/{*rest}", any(forward))
//!     .route_layer(middleware::from_fn_with_state(api_key_store, require_api_key));
//! ```
//!
//! 校验成功后, `AuthenticatedTenant` 被注入 request extension,
//! 下游 handler 可通过 `Extension(tenant)` 提取.
//! (M1 中 tenant_id 不用于数据隔离, M2 起作为 scope key.)

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;

use crate::auth::ApiKeyStore;
use crate::error::AppError;

/// 已认证的租户身份. 注入 request extension, 供下游 handler 用.
/// M1 不做隔离 (所有 tenant 共享数据), M2 起作为 scope key.
#[derive(Clone, Debug)]
pub struct AuthenticatedTenant {
    pub tenant_id: String,
}

/// API key 校验 middleware.
///
/// 从 `Authorization: Bearer <key>` 提取 key, SHA-256 hash 后查 ApiKeyStore.
/// 命中 → 注入 AuthenticatedTenant; 未命中 → 401 Unauthorized.
///
/// 安全边界: 校验成功后**剥离** Authorization header.
/// 原因: 若 provider 未配 api_key (如 Ollama), apply_provider_auth 会跳过注入,
/// 导致 secret-guard 自己的 API key 原样到达上游 LLM provider —
/// 这正是 secret-guard 要防止的 secret 泄漏事故.
/// 剥离后, apply_provider_auth 只负责注入 provider 的 key, 不再隐式依赖"覆盖"语义.
pub async fn require_api_key(
    State(store): State<ApiKeyStore>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let key = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| AppError::Unauthorized("missing Authorization: Bearer header".into()))?;

    let entry = store
        .lookup(key)
        .ok_or_else(|| AppError::Unauthorized("invalid or revoked API key".into()))?;

    // 剥离客户端的 API key, 防止泄漏到上游.
    // apply_provider_auth 会注入 provider 自己的 api_key (若有).
    req.headers_mut().remove(axum::http::header::AUTHORIZATION);

    req.extensions_mut().insert(AuthenticatedTenant {
        tenant_id: entry.tenant_id,
    });
    Ok(next.run(req).await)
}
