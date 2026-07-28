//! 统一应用错误类型 (顶层, 跨转发链与鉴权层共用).
//!
//! # 职责边界
//!
//! 定义 [`AppError`]: 自动转换为合适的 HTTP 状态码, 响应体永远是合法 JSON,
//! 内部错误细节不回写客户端 (避免信息泄露 — reqwest::Error 等通常含完整上游 URL,
//! 直接返回给客户端会暴露内部拓扑). 仅记录到 tracing.
//!
//! # 归属判断
//!
//! 历史上 `AppError` 定义在 [`crate::proxy`] 中, 但它的实际消费者跨两层:
//! - 转发链 [`crate::proxy`] (forward handler 的 `Result<_, AppError>`).
//! - 鉴权层 [`crate::auth::middleware`] (`require_api_key` 返回 `Result<_, AppError>`).
//!
//! 让 `auth` 依赖 `proxy` 是反向依赖 (鉴权层是更低层的基础设施, 转发层依赖它, 而非反过来).
//! 故把错误类型抽到此独立顶层模块, 让两层各自从 `crate::error` 取用, 不引入层间依赖.
//!
//! # 与 `web::api::ApiError` 的分工
//!
//! `web::api::ApiError` (定义在 `src/web/api.rs`) 是 WebUI CRUD (`/api/secrets`,
//! `/api/providers` 等) 的错误类型, 用 `struct { status, message }` 形态 (手动映射
//! 状态码, message 原样回客户端, 因为 CRUD 错误是用户可读的校验/冲突消息). 两者形态与
//! 信息泄露策略都不同, 故不合并:
//! - `AppError`: 转发/鉴权, message 按变体选择性回传 (Upstream/Internal 不回传).
//! - `ApiError`: CRUD, message 总是回传 (用户可操作的错误描述).

use axum::{
    body::Body,
    http::{HeaderValue, Response, StatusCode},
    response::IntoResponse,
};
use tracing::error;

/// 应用错误: 自动转换为合适的 HTTP 状态, 响应体永远是合法 JSON.
///
/// 各变体的 `message` 信息泄露策略见 [`IntoResponse`] 实现 (按变体选择性回传).
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("invalid request body: {0}")]
    BadBody(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("service unavailable: {0}")]
    Unavailable(String),
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// 错误响应的 JSON body shape (`{error, message}`).
#[derive(serde::Serialize)]
struct ErrorBody {
    error: &'static str,
    /// 人类可读的额外说明 (不泄露内部细节, 仅描述协议 / 路由层面的常见错误).
    message: Option<String>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response<Body> {
        // 内部错误细节仅记录到日志, 不回写到响应 (避免信息泄露 — reqwest::Error 等通常
        // 含完整上游 URL, 直接返回给客户端会暴露内部拓扑).
        // 因此 Upstream / BadBody / Internal 的 message 字段用 None (客户端只看到 kind);
        // NotFound / Unavailable / NotImplemented 的 message 描述协议/路由层面的问题,
        // 信息量对客户端排查有用且不含敏感字段, 原样返回.
        let (status, kind, message) = match &self {
            AppError::BadBody(_) => (StatusCode::BAD_REQUEST, "bad_request", None),
            AppError::Upstream(_) => (StatusCode::BAD_GATEWAY, "upstream_error", None),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, "not_found", Some(m.clone())),
            AppError::Unavailable(m) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                Some(m.clone()),
            ),
            AppError::NotImplemented(m) => (
                StatusCode::NOT_IMPLEMENTED,
                "not_implemented",
                Some(m.clone()),
            ),
            AppError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "unauthorized", None),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal", None),
        };
        error!(error = %self, kind, "proxy error");
        let body = serde_json::to_vec(&ErrorBody {
            error: kind,
            message,
        })
        .unwrap_or_else(|_| b"{\"error\":\"internal\"}".to_vec());
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = status;
        resp.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        resp
    }
}
