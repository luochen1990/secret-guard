//! `GET /api/privacy-scan/alerts`: 隐私旁路扫描告警视图 (#257 S0.5).
//!
//! # 响应 shape
//!
//! `{enabled: bool, alerts: [AlertDto…]}` — `enabled: false` (mode=off) 时
//! alerts 恒空, 前端据此**隐藏整个面板** (显式 enabled 标志区分 "没扫到" 与
//! "没开启", 不让空面板误导用户排查).
//!
//! # 视图过滤 (登记后告警消失)
//!
//! 告警 value ∈ 当前 effective secrets 值集的条目被过滤 — 用户经预填表单登记
//! 后, 对应告警行在下次刷新即消失 (无需新增 dismiss 写端点; 删除 secret 后
//! 告警自然重现, 语义自洽: "疑似未登记" 重新成立).
//!
//! # 安全
//!
//! 告警含疑似明文 token (匹配到的完整 value + 上下文摘要) — 与 `req_body_raw`
//! 回显 (`GET /api/records/{id}`, audit capture) 同信任域同先例: 本地单用户
//! (默认 127.0.0.1 监听 + SEC-7 Host/Origin guard), GET 安全方法不触发 Origin
//! 纵深校验 (与 records 端点一致). **SEC-1 例外的显式裁决请求见 PR 描述**
//! (#257: 告警必须携带完整 value 才能支撑「一键登记预填」闭环 — mask 会
//! 使产品形态失效). OIDC 模式下本端点随整个 `web::router()` 受 login_required
//! 保护 (同 records).
//!
//! mode 是静态档位 (启动读一次), 无 PUT — 切换需改 `secret-guard.toml` 重启
//! (与 `[redact]`/`[server]` 同哲学, 保持转发核心路径零运行时配置开销).

use axum::extract::State;
use axum::response::{IntoResponse, Json as JsonResponse};
use serde::Serialize;

use crate::state::{AppState, NO_STORE};

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
