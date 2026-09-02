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

#[derive(Debug, Deserialize)]
pub struct SummaryQuery {
    /// 查询窗口天数. 0 = 今日; 缺省 7; 上限 = retention_days (0 = 无上限).
    pub days: Option<u32>,
}

pub async fn usage_summary(
    State(state): State<AppState>,
    Query(q): Query<SummaryQuery>,
) -> impl IntoResponse {
    let retention = state.usage.retention_days();
    let days = q.days.unwrap_or(7).max(1).min(if retention > 0 {
        retention.max(1)
    } else {
        u32::MAX
    });
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
    /// days 归一逻辑 pin: 缺省 7 / 0 → 1 / retention 上限 / retention 0 无上限.
    #[test]
    fn days_normalization_matches_design() {
        // (query, retention) → expected — 直接复刻 handler 内联逻辑做回归锚.
        let norm = |q: Option<u32>, retention: u32| {
            q.unwrap_or(7).max(1).min(if retention > 0 {
                retention.max(1)
            } else {
                u32::MAX
            })
        };
        assert_eq!(norm(None, 90), 7);
        assert_eq!(norm(Some(0), 90), 1);
        assert_eq!(norm(Some(365), 90), 90, "capped by retention");
        assert_eq!(norm(Some(365), 0), 365, "retention 0 = no cap");
    }
}
