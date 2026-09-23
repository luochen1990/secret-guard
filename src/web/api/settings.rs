//! `GET/PUT /api/settings`: WebUI 全局设置 (当前仅 audit_capture).
//!
//! # 字段语义
//!
//! - `audit_capture` (详细日志, 三态 `"off" / "errors" / "full"` — 反序列化兼容
//!   旧 bool): `off` 极致省内存; `errors` 仅错误请求保留 body (在途暂存, 排障
//!   主力档); `full` 全量. timeline 不受影响 (B1 起从 BlockPool 派生).
//!   per-request 原子语义 + 持久化契约见 `crate::state::AuditCapture` 文档 (SSOT).
//!
//! # 安全
//!
//! PUT 是 `/api/*` 非安全方法 — SEC-7 的 Origin/Sec-Fetch-Site 校验由最外层
//! middleware 自动覆盖 (server_host_guard), 本模块无需额外处理.

use axum::extract::rejection::JsonRejection;
use axum::extract::{Json, State};
use axum::response::{IntoResponse, Json as JsonResponse};
use serde::{Deserialize, Serialize};

use crate::state::{AppState, NO_STORE};

use super::error::ApiError;

/// `GET /api/settings` / `PUT /api/settings` 的统一响应 shape.
///
/// 两端点共用 (GET 返回当前值, PUT 返回落库后的新值) — 前端 shape 固定.
#[derive(Serialize)]
pub(crate) struct SettingsResponse {
    pub audit_capture: crate::config::AuditCaptureMode,
}

/// `PUT /api/settings` 的请求 body (string 三态; 反序列化兼容旧 bool —
/// `AuditCaptureMode` 的自定义 Deserialize).
#[derive(Deserialize)]
pub(crate) struct UpdateSettingsRequest {
    pub audit_capture: crate::config::AuditCaptureMode,
}

pub async fn get_settings(State(state): State<AppState>) -> impl IntoResponse {
    (
        NO_STORE,
        JsonResponse(SettingsResponse {
            audit_capture: state.audit_capture.mode(),
        }),
    )
}

/// 切换设置: 持久化 state.toml + 更新内存 (原子, 见 [`AuditCapture::set_mode`]).
///
/// 非法 body (非 JSON / 字段类型错 / 缺字段) → 统一 400 (JsonRejection 显式
/// 收敛, 不依赖 axum 默认的 400/422 混合).
pub async fn update_settings(
    State(state): State<AppState>,
    body: Result<Json<UpdateSettingsRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(payload) =
        body.map_err(|e| ApiError::validation(format!("invalid settings body: {e}")))?;
    state
        .audit_capture
        .set_mode(payload.audit_capture)
        .map_err(ApiError::from_any)?;
    // 返回服务端实际落库值 (严格反映服务端状态, 而非回声请求 — 与
    // toggle_api_key 同风格).
    Ok((
        NO_STORE,
        JsonResponse(SettingsResponse {
            audit_capture: state.audit_capture.mode(),
        }),
    ))
}
