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

/// hours 的硬上限 (与 retention 无关): 防 `hours=u32::MAX` 触发补零序列的巨量
/// 分配 (ROB: GET 参数直达的分配 abort 不可接受). 400 天 ≈ 13 个月, 覆盖本地
/// 工具的合理回看窗口; retention 更小则进一步被 min 压缩.
const MAX_HOURS: u32 = 400 * 24;

#[derive(Debug, Deserialize)]
pub struct SummaryQuery {
    /// 查询窗口小时数. 0 → 1 (当前小时); 缺省 168 (7 天); 上限 =
    /// min(retention_days × 24, MAX_HOURS). ≤14 天按小时粒度, 更长按天折叠.
    pub hours: Option<u32>,
}

pub async fn usage_summary(
    State(state): State<AppState>,
    Query(q): Query<SummaryQuery>,
) -> impl IntoResponse {
    let retention = state.usage.retention_days();
    let cap = if retention > 0 {
        retention.saturating_mul(24).min(MAX_HOURS)
    } else {
        MAX_HOURS
    };
    let hours = q.hours.unwrap_or(168).max(1).min(cap);
    let (table, status) = state.pricing.table(&state.upstream).await;
    // domain hint: 闭包借用 providers 表 (取**首端点**的 host — 多端点共享同一
    // 凭证/供应商, 首端点 (= 默认端点) 的 host 足以消歧 models.dev vendor;
    // router/pool 条目无端点 → None).
    let hint = |pid: &str| -> Option<String> {
        let p = state.providers.get_effective(pid)?;
        match &p.kind {
            crate::provider::ProviderKind::Direct(d) => d
                .endpoints
                .first()
                .and_then(|ep| crate::usage::extract_host(&ep.base_url)),
            // 虚拟构造 (router/pool) 无端点 → 无 domain hint.
            crate::provider::ProviderKind::Router(_) | crate::provider::ProviderKind::Pool(_) => {
                None
            }
        }
    };
    let summary = build_summary(
        SummaryInputs {
            store: &state.usage,
            table: &table,
            hours,
            domain_hint: &hint,
        },
        status,
    );
    (NO_STORE, Json(summary))
}

#[cfg(test)]
mod tests {
    use super::MAX_HOURS;

    /// hours 归一逻辑 pin: 缺省 168 / 0 → 1 / retention 上限 / retention 0 无上限.
    #[test]
    fn hours_normalization_matches_design() {
        // (query, retention) → expected — 直接复刻 handler 内联逻辑做回归锚.
        let norm = |q: Option<u32>, retention: u32| {
            let cap = if retention > 0 {
                retention.saturating_mul(24).min(MAX_HOURS)
            } else {
                MAX_HOURS
            };
            q.unwrap_or(168).max(1).min(cap)
        };
        assert_eq!(norm(None, 90), 168);
        assert_eq!(norm(Some(0), 90), 1);
        assert_eq!(norm(Some(3000), 90), 90 * 24, "capped by retention");
        assert_eq!(
            norm(Some(20000), 0),
            MAX_HOURS,
            "retention 0: capped by MAX_HOURS only"
        );
        assert_eq!(
            norm(Some(u32::MAX), 0),
            MAX_HOURS,
            "hard cap prevents abort (ROB)"
        );
    }
}
