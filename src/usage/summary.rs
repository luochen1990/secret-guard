//! usage summary 视图派生: cells × 定价 → API 响应形状 (usage-stats §8).
//!
//! # 契约锚点
//!
//! - **USAGE-1 聚合一致性**: totals == 窗口内明细 fold; by_day / by_model /
//!   by_provider 分项之和 == totals (本模块是纯函数, property 测试在 store 侧 +
//!   本模块侧分别守卫).
//! - **USAGE-3 成本纯函数与可复算**: [`cost_usd`] 确定性纯函数, 对 fold 后的
//!   agg 与逐事件求和线性一致 (input/cache 数字累加, 成本对数字线性).
//! - **USAGE-4 缺失显式**: without_usage 的行对 token / cost 贡献恒 0 (agg 折叠
//!   时已保证); `cost_coverage` 只把**有 usage 的请求**作为分母.
//!
//! # 口径注
//!
//! - `cache_hit_rate = cache_read / (input + cache_read + cache_write)` —
//!   cache_write 也是 input 的一部分 (写入缓存的 input), 故计入分母 (设计 §8).
//! - 响应类型即本模块的 wire shape (usage API 专属, 不进 dto.rs — 那里是
//!   sessions/timeline 家族).

use serde::Serialize;

use super::pricing::{ModelPrice, PricingStatus, PricingTable};
use super::store::{UsageAgg, UsageStore};

/// GET /api/usage/summary 的响应.
#[derive(Debug, Clone, Serialize)]
pub struct UsageSummary {
    pub range: SummaryRange,
    pub pricing_status: &'static str,
    pub totals: Totals,
    pub by_day: Vec<DayRow>,
    pub by_model: Vec<ModelRow>,
    pub by_provider: Vec<ProviderRow>,
    /// 无价 model 清单 (提示用户配 pricing_override; P-4).
    pub unpriced_models: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryRange {
    /// 起始日 (本地时区 "YYYY-MM-DD", 含).
    pub from: String,
    /// 结束日 == 今天 (本地时区).
    pub to: String,
    pub days: u32,
}

/// 汇总卡 (UsageAgg 的超集 + 派生率).
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Totals {
    pub requests: u64,
    pub requests_without_usage: u64,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub cache_hit_rate: Option<f64>,
    /// 估算成本 (仅含有价 cell 的贡献; P-4 恒为估算).
    pub est_cost_usd: f64,
    /// 有价且有 usage 请求占比 (0..1; 无 usage 请求时 None).
    pub cost_coverage: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DayRow {
    pub day: String,
    pub requests: u64,
    pub requests_without_usage: u64,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub est_cost_usd: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelRow {
    pub model: Option<String>,
    pub provider: String,
    pub requests: u64,
    pub requests_without_usage: u64,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub est_cost_usd: f64,
    /// 占总量 cost 的比例 (0..1; totals 为 0 时 0).
    pub cost_share: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderRow {
    pub provider: String,
    pub requests: u64,
    pub requests_without_usage: u64,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub est_cost_usd: f64,
}

/// 成本公式 (opencode 语义; USAGE-3 纯函数, $/1M):
/// `(i×in + cr×cache_read + cw×cache_write + o×out) / 1e6`.
pub fn cost_usd(p: &ModelPrice, agg: &UsageAgg) -> f64 {
    (agg.input as f64 * p.input
        + agg.cache_read as f64 * p.cache_read
        + agg.cache_write as f64 * p.cache_write
        + agg.output as f64 * p.output)
        / 1_000_000.0
}

/// summary 构建参数.
pub struct SummaryInputs<'a> {
    pub store: &'a UsageStore,
    pub table: &'a PricingTable,
    /// 请求窗口天数 (0 = 今日; 缺省 7 由 handler 归一).
    pub days: u32,
    /// provider id → base_url host (域名启发消歧; None = 不消歧).
    pub domain_hint: &'a dyn Fn(&str) -> Option<String>,
}

/// 纯派生入口 (web handler 薄包装).
///
/// day 视图对窗口内每一天补零 (连续序列, 图表友好); by_model 按 (model, provider)
/// cell 直出 (设计 §9 "By Model 表含 provider 列"), cost 降序 (无价最后);
/// by_provider fold by provider.
pub fn build_summary(input: SummaryInputs<'_>, status: PricingStatus) -> UsageSummary {
    let today = chrono::Local::now().date_naive();
    let days = input.days.max(1);
    let from_date = today - chrono::Duration::days((days - 1) as i64);
    let from = from_date.format("%Y-%m-%d").to_string();
    let to = today.format("%Y-%m-%d").to_string();

    // 窗口内 cells 过滤 (day 字符串字典序 == 日期序).
    let cells: Vec<((String, String, Option<String>), UsageAgg)> = input
        .store
        .snapshot_cells()
        .into_iter()
        .filter(|((day, _, _), _)| day.as_str() >= from.as_str())
        .collect();

    // 定价缓存: 同一 (model, provider-domain) 只查一次表.
    let mut price_cache: std::collections::HashMap<(Option<String>, String), Option<ModelPrice>> =
        std::collections::HashMap::new();
    let mut price_of = |model: &Option<String>, provider: &str| -> Option<ModelPrice> {
        let hint = (input.domain_hint)(provider);
        *price_cache
            .entry((model.clone(), provider.to_string()))
            .or_insert_with(|| input.table.price_for(model.as_deref().unwrap_or(""), hint.as_deref()))
    };

    // ── totals + by_model (一次遍历; USAGE-1: 分项之和 == totals) ──
    let mut totals = Totals::default();
    let mut with_usage_requests = 0u64;
    let mut priced_requests = 0u64;
    let mut unpriced: Vec<String> = Vec::new();
    let mut model_rows: Vec<ModelRow> = Vec::new();
    let mut provider_agg: std::collections::HashMap<String, (UsageAgg, f64)> =
        std::collections::HashMap::new();
    let mut day_agg: std::collections::HashMap<String, (UsageAgg, f64)> =
        std::collections::HashMap::new();

    for ((day, provider, model), agg) in &cells {
        totals.requests += agg.requests;
        totals.requests_without_usage += agg.requests_without_usage;
        totals.input = totals.input.saturating_add(agg.input);
        totals.output = totals.output.saturating_add(agg.output);
        totals.cache_read = totals.cache_read.saturating_add(agg.cache_read);
        totals.cache_write = totals.cache_write.saturating_add(agg.cache_write);

        let with_usage = agg.requests - agg.requests_without_usage;
        with_usage_requests += with_usage;
        let price = price_of(model, provider);
        let cost = price.map_or(0.0, |p| cost_usd(&p, agg));
        // coverage / unpriced 只看有 usage 的请求 (USAGE-4).
        if with_usage > 0 {
            match price {
                Some(_) => priced_requests += with_usage,
                None => {
                    let name = model.clone().unwrap_or_else(|| "(unknown)".to_string());
                    if !unpriced.contains(&name) {
                        unpriced.push(name);
                    }
                }
            }
        }
        model_rows.push(ModelRow {
            model: model.clone(),
            provider: provider.clone(),
            requests: agg.requests,
            requests_without_usage: agg.requests_without_usage,
            input: agg.input,
            output: agg.output,
            cache_read: agg.cache_read,
            cache_write: agg.cache_write,
            est_cost_usd: cost,
            cost_share: 0.0, // totals cost 就绪后填.
        });
        let p = provider_agg.entry(provider.clone()).or_default();
        merge_agg(&mut p.0, agg);
        p.1 += cost;
        let d = day_agg.entry(day.clone()).or_default();
        merge_agg(&mut d.0, agg);
        d.1 += cost;
    }

    totals.est_cost_usd = model_rows.iter().map(|r| r.est_cost_usd).sum();
    let denom = totals.est_cost_usd;
    for r in &mut model_rows {
        r.cost_share = if denom > 0.0 { r.est_cost_usd / denom } else { 0.0 };
    }
    let input_sum = totals.input + totals.cache_read + totals.cache_write;
    totals.cache_hit_rate = (input_sum > 0).then(|| totals.cache_read as f64 / input_sum as f64);
    totals.cost_coverage =
        (with_usage_requests > 0).then(|| priced_requests as f64 / with_usage_requests as f64);

    // ── by_day: 窗口内每天补零, 连续序列 ──
    let mut by_day = Vec::with_capacity(days as usize);
    for i in 0..days {
        let day = (from_date + chrono::Duration::days(i as i64))
            .format("%Y-%m-%d")
            .to_string();
        let (agg, cost) = day_agg.remove(&day).unwrap_or_default();
        by_day.push(DayRow {
            day,
            requests: agg.requests,
            requests_without_usage: agg.requests_without_usage,
            input: agg.input,
            output: agg.output,
            cache_read: agg.cache_read,
            cache_write: agg.cache_write,
            est_cost_usd: cost,
        });
    }

    // ── by_model: cost 降序, 无价最后 (稳定: 次键 model 名) ──
    model_rows.sort_by(|a, b| {
        b.est_cost_usd
            .partial_cmp(&a.est_cost_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.model.cmp(&b.model))
    });

    // ── by_provider: cost 降序 ──
    let mut by_provider: Vec<ProviderRow> = provider_agg
        .into_iter()
        .map(|(provider, (agg, cost))| ProviderRow {
            provider,
            requests: agg.requests,
            requests_without_usage: agg.requests_without_usage,
            input: agg.input,
            output: agg.output,
            cache_read: agg.cache_read,
            cache_write: agg.cache_write,
            est_cost_usd: cost,
        })
        .collect();
    by_provider.sort_by(|a, b| {
        b.est_cost_usd
            .partial_cmp(&a.est_cost_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.provider.cmp(&b.provider))
    });

    UsageSummary {
        range: SummaryRange { from, to, days },
        pricing_status: status.as_str(),
        totals,
        by_day,
        by_model: model_rows,
        by_provider,
        unpriced_models: unpriced,
    }
}

fn merge_agg(dst: &mut UsageAgg, src: &UsageAgg) {
    dst.requests += src.requests;
    dst.requests_without_usage += src.requests_without_usage;
    dst.input = dst.input.saturating_add(src.input);
    dst.output = dst.output.saturating_add(src.output);
    dst.cache_read = dst.cache_read.saturating_add(src.cache_read);
    dst.cache_write = dst.cache_write.saturating_add(src.cache_write);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usage::UsageQuanta;
    use std::collections::HashMap;

    fn store_with(events: &[crate::usage::UsageEvent]) -> UsageStore {
        let s = UsageStore::for_tests();
        for e in events {
            s.record(e.clone());
        }
        s
    }

    fn ev(day_offset_h: i64, provider: &str, model: Option<&str>, q: Option<UsageQuanta>) -> crate::usage::UsageEvent {
        crate::usage::UsageEvent {
            ts: chrono::Utc::now() - chrono::Duration::hours(day_offset_h),
            provider: provider.to_string(),
            model: model.map(String::from),
            model_req: None,
            proto: "o".to_string(),
            method: "POST".to_string(),
            ok: true,
            complete: true,
            usage: q,
        }
    }

    fn priced_table() -> PricingTable {
        let mut overrides = HashMap::new();
        overrides.insert(
            "m-priced".to_string(),
            ModelPrice { input: 1.0, output: 2.0, cache_read: 0.1, cache_write: 0.5 },
        );
        PricingTable::new(None, overrides)
    }

    // ─── USAGE-1: 分项之和 == totals ───────────────────────────────────

    #[test]
    fn summary_sums_match_totals_across_all_views() {
        let s = store_with(&[
            ev(0, "p1", Some("m-priced"), Some(UsageQuanta { i: 1000, o: 500, cr: 0, cw: 0 })),
            ev(0, "p1", Some("m-unpriced"), Some(UsageQuanta { i: 100, o: 0, cr: 0, cw: 0 })),
            ev(0, "p2", Some("m-priced"), None),
            ev(48, "p1", Some("m-priced"), Some(UsageQuanta { i: 100, o: 100, cr: 0, cw: 0 })), // 窗口外
        ]);
        let table = priced_table();
        let no_hint = |_p: &str| None;
        let sum = build_summary(
            SummaryInputs { store: &s, table: &table, days: 1, domain_hint: &no_hint },
            PricingStatus::Ok,
        );
        let t = &sum.totals;
        assert_eq!(t.requests, 3, "window = today only (48h-old event excluded)");
        assert_eq!(t.requests_without_usage, 1);
        assert_eq!(t.input, 1100);
        assert_eq!(t.output, 500);
        // USAGE-1: by_model 之和 == totals.
        let m_req: u64 = sum.by_model.iter().map(|r| r.requests).sum();
        let m_in: u64 = sum.by_model.iter().map(|r| r.input).sum();
        assert_eq!((m_req, m_in), (t.requests, t.input));
        // by_provider 之和 == totals.
        let p_req: u64 = sum.by_provider.iter().map(|r| r.requests).sum();
        assert_eq!(p_req, t.requests);
        // by_day 之和 == totals (窗口内仅今天有数据).
        let d_req: u64 = sum.by_day.iter().map(|r| r.requests).sum();
        assert_eq!(d_req, t.requests);
        // USAGE-4: cost_coverage 只算有 usage 的请求: 有 usage 2 (1 priced + 1 unpriced) → 0.5.
        assert!((t.cost_coverage.unwrap() - 0.5).abs() < 1e-9);
        assert_eq!(sum.unpriced_models, vec!["m-unpriced"]);
        // USAGE-3: cost = 1000×1 + 500×2 (M) = $0.002.
        assert!((t.est_cost_usd - 0.002).abs() < 1e-12);
    }

    // ─── USAGE-3: 逐事件算再求和 == fold 后再算 (线性性) ───────────────

    #[test]
    fn cost_is_linear_in_aggregation() {
        let s = store_with(&[
            ev(0, "p", Some("m-priced"), Some(UsageQuanta { i: 1000, o: 500, cr: 0, cw: 0 })),
            ev(0, "p", Some("m-priced"), Some(UsageQuanta { i: 2000, o: 1500, cr: 0, cw: 0 })),
        ]);
        let table = priced_table();
        let no_hint = |_p: &str| None;
        let sum = build_summary(
            SummaryInputs { store: &s, table: &table, days: 1, domain_hint: &no_hint },
            PricingStatus::Ok,
        );
        let folded = sum.totals.est_cost_usd;
        // 逐事件: (1000×1+500×2 + 2000×1+1500×2)/1e6.
        let per_event = (1000.0 * 1.0 + 500.0 * 2.0 + 2000.0 * 1.0 + 1500.0 * 2.0) / 1e6;
        assert!((folded - per_event).abs() < 1e-12);
    }

    // ─── cache_hit_rate 口径 (cr / (i + cr + cw)) ──────────────────────

    #[test]
    fn cache_hit_rate_denominator_includes_cache_write() {
        let s = store_with(&[ev(
            0,
            "p",
            Some("m-priced"),
            Some(UsageQuanta { i: 100, o: 0, cr: 100, cw: 300 }),
        )]);
        let table = priced_table();
        let no_hint = |_p: &str| None;
        let sum = build_summary(
            SummaryInputs { store: &s, table: &table, days: 1, domain_hint: &no_hint },
            PricingStatus::Ok,
        );
        // 100 / (100+100+300) = 0.2.
        assert!((sum.totals.cache_hit_rate.unwrap() - 0.2).abs() < 1e-9);
    }

    // ─── 空数据 / 补零日 ────────────────────────────────────────────────

    #[test]
    fn empty_store_yields_zeroed_days_and_none_rates() {
        let s = UsageStore::for_tests();
        let table = PricingTable::empty();
        let no_hint = |_p: &str| None;
        let sum = build_summary(
            SummaryInputs { store: &s, table: &table, days: 7, domain_hint: &no_hint },
            PricingStatus::Ok,
        );
        assert_eq!(sum.by_day.len(), 7, "zero-filled contiguous days");
        assert_eq!(sum.totals.requests, 0);
        assert!(sum.totals.cache_hit_rate.is_none());
        assert!(sum.totals.cost_coverage.is_none());
    }
}
