//! `/api/privacy-scan/*`: 隐私旁路扫描的告警视图 + 状态机动作 + 组开关
//! (#257 S0.5; R2/R3 扩展见 PR #303 review).
//!
//! # 端点
//!
//! - `GET  /api/privacy-scan/alerts`: `{enabled, groups, alerts: [AlertDto…]}` —
//!   `enabled: false` (mode=off) 时 alerts 恒空, 前端据此**隐藏整个面板**
//!   (显式 enabled 标志区分 "没扫到" 与 "没开启", 不让空面板误导用户排查);
//!   `groups` 内嵌当前生效组态 (面板组开关行一次拉全, 免二次 RTT).
//! - `POST /api/privacy-scan/alerts/{id}/rotated`: 标记用户已在平台侧
//!   吊销/轮换 (R2 状态机; id 为 hash 形态 — 疑似明文不进 URL path).
//! - `POST /api/privacy-scan/alerts/{id}/ignored`: 标记误报.
//! - `GET  /api/privacy-scan/settings`: `{enabled, groups}` — 组开关读端点
//!   (off 档返回 enabled:false + 持久化组态, 供 UI 回显).
//! - `PUT  /api/privacy-scan/settings`: body `{groups: {cloud: true, …}}`
//!   **全量替换** (未出现的组 = 启用); 未知名/形态错误 → 400 (fail-fast 不
//!   静默忽略). **off 档拒绝** (400 — mode=off 时一切不发生, 组开关无从
//!   生效; 开启扫描须改 static toml 重启, 不在本端点的职责内).
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
//! 「一键登记预填」闭环 — mask 会使产品形态失效.) 裁决前提的技术保证
//! (2026-10-10 验收补): context 窗口内的**登记值**经 [`crate::privacy`]
//! 的 `MaskedLeaf` 遮盖为 `[managed]` 占位 (先遮盖后取窗口), 登记值的完整
//! 出现不进回显面 (同语义残余例外见 docs/known-limitations.md privacy-scan 节).
//! OIDC 模式下本端点随整个 `web::router()` 受 login_required 保护 (同 records).
//!
//! mode 是静态档位 (启动读一次), 无 PUT — 切换需改 `secret-guard.toml` 重启
//! (与 `[redact]`/`[server]` 同哲学, 保持转发核心路径零运行时配置开销).

use std::collections::BTreeMap;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Json, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json as JsonResponse};
use serde::{Deserialize, Serialize};

use crate::state::{AppState, NO_STORE};

use super::error::ApiError;

/// `GET /api/privacy-scan/alerts` 响应 (`alerts_view` 的 wire 包装). `groups`
/// 是当前生效组态 (数据源; 面板组开关行按前端规范序重排展示 — map 序列化
/// 走字典序, 非规范序).
#[derive(Serialize)]
pub(crate) struct AlertsResponse {
    pub enabled: bool,
    pub groups: BTreeMap<&'static str, bool>,
    pub alerts: Vec<crate::privacy::AlertDto>,
}

/// `GET/PUT /api/privacy-scan/settings` 的统一响应 shape (两端点共用, 前端
/// shape 固定 — 与 `/api/settings` 同风格).
#[derive(Serialize)]
pub(crate) struct PrivacySettingsResponse {
    pub enabled: bool,
    pub groups: BTreeMap<&'static str, bool>,
}

/// settings 视图构造 (GET/PUT 两端点共用 — 响应形状单点维护).
fn settings_view(state: &AppState) -> PrivacySettingsResponse {
    PrivacySettingsResponse {
        enabled: state.privacy_scan.enabled(),
        groups: groups_map(state),
    }
}

/// 组态 map 的公共构造 (alerts 内嵌与 settings 响应共用).
fn groups_map(state: &AppState) -> BTreeMap<&'static str, bool> {
    state
        .privacy_scan_groups
        .enabled_groups()
        .into_iter()
        .collect()
}

pub async fn list_alerts(State(state): State<AppState>) -> impl IntoResponse {
    // 排除集 = 当前 effective secrets (投影 SSOT `secrets::non_empty_values`,
    // 与扫描侧排除规则同源) — 视图侧再过滤一次, 覆盖 "登记后未及再扫描" 的在途告警.
    let registered = state.secrets.effective_raw();
    let values = crate::secrets::non_empty_values(&registered);
    let (enabled, alerts) = state.privacy_scan.alerts_view(&values);
    (
        NO_STORE,
        JsonResponse(AlertsResponse {
            enabled,
            groups: groups_map(&state),
            alerts,
        }),
    )
}

/// 状态机动作 ack (轻量 — 状态明细走随后的 GET /api/privacy-scan/alerts,
/// 与 pool_reset 同风格). `status` 直接用 [`AlertStatus`] (serde lowercase
/// = wire 串的 SSOT, 不另手抄映射).
#[derive(Serialize)]
struct MarkAck {
    id: String,
    status: crate::privacy::AlertStatus,
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
            JsonResponse(MarkAck { id, status }),
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

// ─── R3: 组开关 settings 端点 ───────────────────────────────────────────────

/// `PUT` 请求 body: `groups` 全量替换 (未出现的组 = 启用; 未知名 → 400).
#[derive(Deserialize)]
pub(crate) struct UpdatePrivacySettingsRequest {
    pub groups: BTreeMap<String, bool>,
}

pub async fn get_settings(State(state): State<AppState>) -> impl IntoResponse {
    (NO_STORE, JsonResponse(settings_view(&state)))
}

/// 全量替换组态: 持久化 state.toml + 更新内存位掩码 (原子, 见
/// [`crate::state::PrivacyScanGroups::set_groups`]). off 档 (mode=off) → 400:
/// 组开关无从生效 (扫描器空壳), 引导用户改 static toml. 非法 body (非 JSON /
/// 非 bool 值 / 缺字段 / 未知名) → 统一 400.
pub async fn update_settings(
    State(state): State<AppState>,
    body: Result<Json<UpdatePrivacySettingsRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    if !state.privacy_scan.enabled() {
        return Err(ApiError::validation(
            "privacy scan is off ([privacy_scan] mode = \"off\"); nothing to configure",
        ));
    }
    let Json(payload) =
        body.map_err(|e| ApiError::validation(format!("invalid privacy settings body: {e}")))?;
    // 未知名在 API 层 fail-fast (400) — set_groups 的同名防线兜底 direct 调用方;
    // 其余持久化类失败经 from_any 收敛 500 (与 settings.rs 同型).
    if let Some(name) = payload
        .groups
        .keys()
        .find(|n| crate::privacy::PatternGroup::from_name(n).is_none())
    {
        return Err(ApiError::validation(format!(
            "unknown privacy-scan pattern group '{name}' (expect cloud/ai/vcs/chat/crypto)"
        )));
    }
    state
        .privacy_scan_groups
        .set_groups(&payload.groups)
        .map_err(ApiError::from_any)?;
    // 返回服务端实际落库值 (严格反映服务端状态, 而非回声请求).
    Ok((NO_STORE, JsonResponse(settings_view(&state))))
}
