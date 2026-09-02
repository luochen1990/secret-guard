//! `GET /api/usage/summary` — 模型用量统计的汇总查询 (usage-stats §8).
//!
//! 薄包装: 定价表经 [`crate::usage::PricingCache`] (惰性首拉 + TTL + serve-stale,
//! 可能异步等待一次刷新), 聚合派生是 [`crate::usage::summary::build_summary`] 纯函数
//! (单测在 usage 模块). domain hint: provider id → base_url host (models.dev
//! vendor 消歧, 设计 §7 规则 2).

use axum::Json;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::state::{AppState, NO_STORE};
use crate::usage::summary::{SummaryInputs, build_summary};

/// days 的硬上限 (与 retention 无关): 防 `days=u32::MAX` 触发 by_day 补零序列的
/// 巨量分配 (ROB: GET 参数直达的分配 abort 不可接受). 400 天 ≈ 13 个月, 覆盖
/// 本地工具的合理回看窗口; retention 更小则进一步被 min 压缩.
const MAX_DAYS: u32 = 400;

#[derive(Debug, Deserialize)]
pub struct SummaryQuery {
    /// 查询窗口天数. 0 = 今日; 缺省 7; 上限 = min(retention_days, 400).
    pub days: Option<u32>,
}

pub async fn usage_summary(
    State(state): State<AppState>,
    Query(q): Query<SummaryQuery>,
) -> impl IntoResponse {
    let retention = state.usage.retention_days();
    let cap = if retention > 0 {
        retention.min(MAX_DAYS)
    } else {
        MAX_DAYS
    };
    let days = q.days.unwrap_or(7).max(1).min(cap);
    let (table, status) = state.pricing.table(&state.upstream).await;
    // domain hint: 闭包借用 providers 表 (router 条目无 base_url → None).
    let hint = |pid: &str| -> Option<String> {
        let p = state.providers.get_effective(pid)?;
        match &p.kind {
            crate::provider::ProviderKind::Direct(d) => crate::usage::extract_host(&d.base_url),
            crate::provider::ProviderKind::Router(_) => None,
        }
    };
    let summary = build_summary(
        SummaryInputs {
            store: &state.usage,
            table: &table,
            days,
            domain_hint: &hint,
        },
        status,
    );
    (NO_STORE, Json(summary))
}

#[cfg(test)]
mod tests {
    use super::MAX_DAYS;

    /// days 归一逻辑 pin: 缺省 7 / 0 → 1 / retention 上限 / retention 0 无上限.
    #[test]
    fn days_normalization_matches_design() {
        // (query, retention) → expected — 直接复刻 handler 内联逻辑做回归锚.
        let norm = |q: Option<u32>, retention: u32| {
            let cap = if retention > 0 {
                retention.min(MAX_DAYS)
            } else {
                MAX_DAYS
            };
            q.unwrap_or(7).max(1).min(cap)
        };
        assert_eq!(norm(None, 90), 7);
        assert_eq!(norm(Some(0), 90), 1);
        assert_eq!(norm(Some(365), 90), 90, "capped by retention");
        assert_eq!(
            norm(Some(365), 0),
            365,
            "retention 0: capped by MAX_DAYS only"
        );
        assert_eq!(
            norm(Some(u32::MAX), 0),
            MAX_DAYS,
            "hard cap prevents abort (ROB)"
        );
    }
}
