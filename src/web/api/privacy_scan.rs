//! `/api/privacy-scan/*`: 隐私旁路扫描的告警视图 + 状态机动作 (#257 S0.5;
//! R2 扩展见 PR #303 review).
//!
//! # 端点
//!
//! - `GET  /api/privacy-scan/alerts`: `{enabled, alerts: [AlertDto…]}` —
//!   `enabled: false` (mode=off) 时 alerts 恒空, 前端据此**隐藏整个面板**
//!   (显式 enabled 标志区分 "没扫到" 与 "没开启", 不让空面板误导用户排查).
//! - `POST /api/privacy-scan/alerts/{id}/rotated`: 标记用户已在平台侧
//!   吊销/轮换 (R2 状态机; id 为 hash 形态 — 疑似明文不进 URL path).
//! - `POST /api/privacy-scan/alerts/{id}/ignored`: 标记误报.
//!
//! # 视图过滤 (登记后告警消失)
//!
//! 告警 value ∈ 当前 effective secrets 值集的条目被过滤 — 用户经预填表单登记
//! 后, 对应告警行在下次刷新即消失; 删除 secret 后告警自然重现, 语义自洽:
//! "疑似未登记" 重新成立. (Rotated/Ignored 状态与登记正交: 已轮换的死值再
//! 登记 ≠ 处置, 状态机的防打扰语义独立于视图过滤.)
//!
//! # 安全
//!
//! 告警含疑似明文 token (匹配到的完整 value + 上下文摘要) — 与 `req_body_raw`
//! 回显 (`GET /api/records/{id}`, audit capture) 同信任域同先例: 本地单用户
//! (默认 127.0.0.1 监听 + SEC-7 Host/Origin guard), GET 安全方法不触发 Origin
//! 纵深校验 (与 records 端点一致). **SEC-1 裁决 (2026-10-10, PR #303 review):
//! 告警回显疑似明文不构成 SEC-1 破坏 — 疑似值非登记 secret, SEC-1 的保护
//! 对象不在回显面内, 无需例外条款.** (告警必须携带完整 value 才能支撑
//! 「一键登记预填」闭环 — mask 会使产品形态失效.) OIDC 模式下本端点随整个
//! `web::router()` 受 login_required 保护 (同 records).
//!
//! mode 是静态档位 (启动读一次), 无 PUT — 切换需改 `secret-guard.toml` 重启
//! (与 `[redact]`/`[server]` 同哲学, 保持转发核心路径零运行时配置开销).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json as JsonResponse};
use serde::Serialize;

use crate::state::{AppState, NO_STORE};

use super::error::ApiError;

/// `GET /api/privacy-scan/alerts` 响应 (`alerts_view` 的 wire 包装).
#[derive(Serialize)]
pub(crate) struct AlertsResponse {
    pub enabled: bool,
    pub alerts: Vec<crate::privacy::AlertDto>,
}

pub async fn list_alerts(State(state): State<AppState>) -> impl IntoResponse {
    // 排除集 = 当前 effective secrets (投影 SSOT `secrets::non_empty_values`,
    // 与扫描侧排除规则同源) — 视图侧再过滤一次, 覆盖 "登记后未及再扫描" 的在途告警.
    let registered = state.secrets.effective_raw();
    let values = crate::secrets::non_empty_values(&registered);
    let (enabled, alerts) = state.privacy_scan.alerts_view(&values);
    (NO_STORE, JsonResponse(AlertsResponse { enabled, alerts }))
}

/// 状态机动作 ack (轻量 — 状态明细走随后的 GET /api/privacy-scan/alerts,
/// 与 pool_reset 同风格).
#[derive(Serialize)]
struct MarkAck {
    id: String,
    status: &'static str,
}

/// `POST /api/privacy-scan/alerts/{id}/rotated` / `…/{id}/ignored` 的共享
/// 落点: off 档与未知 id 统一 404 (off 档无告警存在, "没有这个告警" 语义
/// 准确; 不引入 503 形态 — 端点本身可用, 只是对象不存在).
async fn mark_alert(
    state: AppState,
    id: String,
    status: crate::privacy::AlertStatus,
) -> Result<impl IntoResponse, ApiError> {
    match state.privacy_scan.mark_alert(&id, status) {
        Some(true) => Ok((
            StatusCode::OK,
            NO_STORE,
            JsonResponse(MarkAck {
                id,
                status: match status {
                    crate::privacy::AlertStatus::Active => "active",
                    crate::privacy::AlertStatus::Rotated => "rotated",
                    crate::privacy::AlertStatus::Ignored => "ignored",
                },
            }),
        )),
        // off 档 (None) 与未知 id (Some(false)) 同语义: 对象不存在.
        _ => Err(ApiError::not_found(format!("alert {id} not found"))),
    }
}

pub async fn mark_rotated(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    mark_alert(state, id, crate::privacy::AlertStatus::Rotated).await
}

pub async fn mark_ignored(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    mark_alert(state, id, crate::privacy::AlertStatus::Ignored).await
}
