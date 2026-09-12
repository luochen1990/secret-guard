//! usage summary 视图派生: SQL cells × 定价 → API 响应形状 (usage-stats §8).
//!
//! # 契约锚点
//!
//! - **USAGE-1 聚合一致性**: totals == 窗口内明细 fold; by_bucket / by_model /
//!   by_provider 分项之和 == totals (本模块是纯函数, property 测试在 store 侧 +
//!   本模块侧分别守卫).
//! - **USAGE-3 成本纯函数与可复算**: [`cost_usd`] 确定性纯函数, 对 fold 后的
//!   agg 与逐事件求和线性一致 (input/cache 数字累加, 成本对数字线性).
//! - **USAGE-4 缺失显式**: without_usage 的行对 token / cost 贡献恒 0 (agg 折叠
//!   时已保证); `cost_coverage` 只把**有 usage 的请求**作为分母; 零价 (免费档 /
//!   套餐 vendor, #202) 与无价分开显式 —— `zero_priced_models` 清单.
//! - **USAGE-7 redact 审计视图**: redactions 子对象来自 store 的 SQL 直查,
//!   与 usage 同窗口 (cutoff 同源).
//!
//! # 粒度策略 (2026-09: day → hour 升级)
//!
//! 窗口 ≤ [`HOURLY_MAX_HOURS`] (14 天) → bucket = hour (`YYYY-MM-DDTHH`), 柱状图
//! 按小时; 更长窗口 → bucket = day (hour 前缀折叠), 控制补零序列与 payload 体积.
//! 补零连续序列 (图表友好) 在本模块完成.
//!
//! # 口径注
//!
//! - `cache_hit_rate = cache_read / (input + cache_read + cache_write)` —
//!   cache_write 也是 input 的一部分 (写入缓存的 input), 故计入分母 (设计 §8).
//! - rounds 三态: `requests` == Σ(normal + retry + no_messages); normal 是派生值
//!   (requests - retries - no_messages), 不单独落列.
//! - 响应类型即本模块的 wire shape (usage API 专属, 不进 dto.rs — 那里是
//!   sessions/timeline 家族).

use chrono::Timelike;
use serde::Serialize;

use super::pricing::{ModelPrice, PricingStatus, PricingTable};
use super::store::{Granularity, RedactRecentRow, RedactSecretRow, UsageAgg, UsageStore};

/// 短窗口阈值 (小时): ≤ 此值按 hour 粒度, 更长按 day 折叠 (14 天 ≈ 图表可读上限).
pub const HOURLY_MAX_HOURS: u32 = 14 * 24;

/// GET /api/usage/summary 的响应.
#[derive(Debug, Clone, Serialize)]
pub struct UsageSummary {
    pub range: SummaryRange,
    pub pricing_status: &'static str,
    pub totals: Totals,
    /// 时间序列 (hour 或 day bucket, 由 range.granularity 决定; 连续补零).
    pub by_bucket: Vec<BucketRow>,
    pub by_model: Vec<ModelRow>,
    pub by_provider: Vec<ProviderRow>,
    /// 无价 model 清单 (提示用户配 pricing_override; P-4).
    pub unpriced_models: Vec<String>,
    /// 有价但四价全零的 model 清单 (models.dev 免费档 / 套餐 vendor 的计量口径,
    /// 含 override 显式置零). "$0 已知价"与"无价"分开显式 (USAGE-4): 防 cost=0 +
    /// cost_coverage=1.0 掩盖实际零价口径 (#202).
    pub zero_priced_models: Vec<String>,
    /// redact 审计 (USAGE-7; 与 usage 同窗口).
    pub redactions: Redactions,
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryRange {
    /// 起始 bucket (含; 本地时区 hour 或 day, 由 granularity 决定).
    pub from: String,
    /// 结束 bucket == 当前小时 / 今天 (本地时区).
    pub to: String,
    pub hours: u32,
    /// "hour" | "day" (前端柱状图 x 轴格式化依据).
    pub granularity: &'static str,
}

/// 六维计数的 wire 载体: [`UsageAgg`] 经 `#[serde(flatten)]` 内嵌 — JSON 键与
/// 直接声明完全一致 (USAGE-1 的 "分项之和 == totals" 由结构同源保证, 而非四处
/// 拷贝字段碰巧一致).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Totals {
    #[serde(flatten)]
    pub agg: UsageAgg,
    pub cache_hit_rate: Option<f64>,
    /// 估算成本 (仅含有价 cell 的贡献; P-4 恒为估算).
    pub est_cost_usd: f64,
    /// 有价且有 usage 请求占比 (0..1; 无 usage 请求时 None).
    pub cost_coverage: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BucketRow {
    /// hour (`YYYY-MM-DDTHH`) 或 day (`YYYY-MM-DD`), 由 granularity 决定.
    pub bucket: String,
    #[serde(flatten)]
    pub agg: UsageAgg,
    pub est_cost_usd: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelRow {
    pub model: Option<String>,
    pub provider: String,
    #[serde(flatten)]
    pub agg: UsageAgg,
    pub est_cost_usd: f64,
    /// 占总量 cost 的比例 (0..1; totals 为 0 时 0).
    pub cost_share: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderRow {
    pub provider: String,
    #[serde(flatten)]
    pub agg: UsageAgg,
    pub est_cost_usd: f64,
}

/// redact 审计视图 (USAGE-7).
#[derive(Debug, Clone, Serialize)]
pub struct Redactions {
    /// 按 (secret_id, mock) 聚合, hits 降序.
    pub by_secret: Vec<RedactSecretRow>,
    /// 最近事件 (倒序, 上限见 [`RECENT_LIMIT`]).
    pub recent: Vec<RedactRecentRow>,
}

/// recent 明细条数上限 (payload 控制; 本地工具回看够用).
pub const RECENT_LIMIT: usize = 100;

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
    /// 请求窗口小时数 (缺省 168 由 handler 归一; 0 归一为 1).
    pub hours: u32,
    /// provider id → base_url host (域名启发消歧; None = 不消歧).
    pub domain_hint: &'a dyn Fn(&str) -> Option<String>,
}

/// 窗口 (hours → granularity, cutoff bucket, 补零序列迭代器).
///
/// day 粒度的 cutoff = 窗口起始**日** (hour >= day 前缀的字典序包含该日起全部
/// hour, 见 store::query_cells 注); 补零序列按天生成.
fn window(hours: u32) -> (Granularity, String, Vec<String>) {
    let hours = hours.max(1);
    let now_local = chrono::Local::now();
    if hours <= HOURLY_MAX_HOURS {
        let from = now_local
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .expect("midnight is valid")
            + chrono::Duration::hours(now_local.hour() as i64 - (hours as i64 - 1));
        let buckets: Vec<String> = (0..hours as i64)
            .map(|i| {
                (from + chrono::Duration::hours(i))
                    .format("%Y-%m-%dT%H")
                    .to_string()
            })
            .collect();
        let cutoff = buckets[0].clone();
        (Granularity::Hour, cutoff, buckets)
    } else {
        let days = hours.div_ceil(24);
        let today = now_local.date_naive();
        let from_day = today - chrono::Duration::days((days - 1) as i64);
        let buckets: Vec<String> = (0..days)
            .map(|i| {
                (from_day + chrono::Duration::days(i as i64))
                    .format("%Y-%m-%d")
                    .to_string()
            })
            .collect();
        let cutoff = buckets[0].clone();
        (Granularity::Day, cutoff, buckets)
    }
}

/// 纯派生入口 (web handler 薄包装).
///
/// by_bucket 对窗口内每个 bucket 补零 (连续序列, 图表友好); by_model 按 (model,
/// provider) 键跨 bucket 折叠 (设计 §9 "By Model 表含 provider 列", 时间维度由
/// by_bucket 承担), cost 降序 (无价最后); by_provider fold by provider; redactions
/// 与 usage 同 cutoff 直查.
pub fn build_summary(input: SummaryInputs<'_>, status: PricingStatus) -> UsageSummary {
    let (gran, cutoff, buckets) = window(input.hours);
    let granularity_str = match gran {
        Granularity::Hour => "hour",
        Granularity::Day => "day",
    };

    // 窗口内 cells (SQL 已按 (bucket, provider, model) 排序 — USAGE-3 确定性:
    // f64 求和顺序固定, 同两次查询的 cost 末位 ULP 一致).
    let cells = input.store.query_cells(&cutoff, gran);

    // 定价缓存: 同一 (model, provider-domain) 只查一次表.
    let mut price_cache: std::collections::HashMap<(Option<String>, String), Option<ModelPrice>> =
        std::collections::HashMap::new();
    let mut price_of = |model: &Option<String>, provider: &str| -> Option<ModelPrice> {
        *price_cache
            .entry((model.clone(), provider.to_string()))
            .or_insert_with(|| {
                // domain_hint (providers 表查询, 最贵的部分) 惰性执行 — 缓存命中时零成本.
                let hint = (input.domain_hint)(provider);
                input
                    .table
                    .price_for(model.as_deref().unwrap_or(""), hint.as_deref())
            })
    };

    // ── totals + by_model (一次遍历; USAGE-1: 分项之和 == totals) ──
    let mut totals = Totals::default();
    let mut with_usage_requests = 0u64;
    let mut priced_requests = 0u64;
    let mut unpriced: Vec<String> = Vec::new();
    let mut zero_priced: Vec<String> = Vec::new();
    // by_model 折叠表: (model, provider) → (agg, cost) — 跨 bucket 合并, 与
    // provider_agg / bucket_agg 同型同 idiom (USAGE-1 键唯一).
    let mut model_agg: std::collections::HashMap<(Option<String>, String), (UsageAgg, f64)> =
        std::collections::HashMap::new();
    let mut provider_agg: std::collections::HashMap<String, (UsageAgg, f64)> =
        std::collections::HashMap::new();
    let mut bucket_agg: std::collections::HashMap<String, (UsageAgg, f64)> =
        std::collections::HashMap::new();

    for ((bucket, provider, model), agg) in &cells {
        merge_agg(&mut totals.agg, agg);

        let with_usage = agg.requests.saturating_sub(agg.requests_without_usage);
        with_usage_requests += with_usage;
        let price = price_of(model, provider);
        let cost = price.map_or(0.0, |p| cost_usd(&p, agg));
        // coverage / unpriced / zero_priced 只看有 usage 的请求 (USAGE-4).
        if with_usage > 0 {
            match price {
                Some(p) => {
                    priced_requests += with_usage;
                    // 零价也是"已知的价" → coverage 仍算 priced (口径不变);
                    // 但单独列出, 不让 $0 冒充"全覆盖的成本估算".
                    if p.is_all_zero() {
                        let name = model.clone().unwrap_or_else(|| "(unknown)".to_string());
                        if !zero_priced.contains(&name) {
                            zero_priced.push(name);
                        }
                    }
                }
                None => {
                    let name = model.clone().unwrap_or_else(|| "(unknown)".to_string());
                    if !unpriced.contains(&name) {
                        unpriced.push(name);
                    }
                }
            }
        }
        let m = model_agg
            .entry((model.clone(), provider.clone()))
            .or_default();
        merge_agg(&mut m.0, agg);
        m.1 += cost;
        let p = provider_agg.entry(provider.clone()).or_default();
        merge_agg(&mut p.0, agg);
        p.1 += cost;
        let b = bucket_agg.entry(bucket.clone()).or_default();
        merge_agg(&mut b.0, agg);
        b.1 += cost;
    }

    // ── by_model: 从折叠表构建行 + 排序 (cost 降序, 次键 model 名, 末键
    //    provider — 折叠后同 model 可跨 provider, 三键全序保证 USAGE-3 确定性) ──
    let mut model_rows: Vec<ModelRow> = model_agg
        .into_iter()
        .map(|((model, provider), (agg, cost))| ModelRow {
            model,
            provider,
            agg,
            est_cost_usd: cost,
            cost_share: 0.0, // totals cost 就绪后填.
        })
        .collect();
    model_rows.sort_by(|a, b| {
        b.est_cost_usd
            .partial_cmp(&a.est_cost_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.model.cmp(&b.model))
            .then_with(|| a.provider.cmp(&b.provider))
    });
    // totals cost 在排序后求和 — 全序 ⇒ f64 求和顺序固定 (同上 cells 排序注释).
    totals.est_cost_usd = model_rows.iter().map(|r| r.est_cost_usd).sum();
    let denom = totals.est_cost_usd;
    for r in &mut model_rows {
        r.cost_share = if denom > 0.0 {
            r.est_cost_usd / denom
        } else {
            0.0
        };
    }
    let input_sum = totals.agg.input + totals.agg.cache_read + totals.agg.cache_write;
    totals.cache_hit_rate =
        (input_sum > 0).then(|| totals.agg.cache_read as f64 / input_sum as f64);
    totals.cost_coverage =
        (with_usage_requests > 0).then(|| priced_requests as f64 / with_usage_requests as f64);

    // ── by_bucket: 窗口内每个 bucket 补零, 连续序列 ──
    let by_bucket: Vec<BucketRow> = buckets
        .into_iter()
        .map(|bucket| {
            let (agg, cost) = bucket_agg.remove(&bucket).unwrap_or_default();
            BucketRow {
                bucket,
                agg,
                est_cost_usd: cost,
            }
        })
        .collect();

    // ── by_provider: cost 降序 ──
    let mut by_provider: Vec<ProviderRow> = provider_agg
        .into_iter()
        .map(|(provider, (agg, cost))| ProviderRow {
            provider,
            agg,
            est_cost_usd: cost,
        })
        .collect();
    by_provider.sort_by(|a, b| {
        b.est_cost_usd
            .partial_cmp(&a.est_cost_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.provider.cmp(&b.provider))
    });

    // ── redactions (USAGE-7): 与 usage 同 cutoff ──
    let (by_secret, recent) = input.store.query_redacts(&cutoff, RECENT_LIMIT);

    let to = by_bucket
        .last()
        .map(|b| b.bucket.clone())
        .unwrap_or_default();
    UsageSummary {
        range: SummaryRange {
            from: cutoff,
            to,
            hours: input.hours.max(1),
            granularity: granularity_str,
        },
        pricing_status: status.as_str(),
        totals,
        by_bucket,
        by_model: model_rows,
        by_provider,
        unpriced_models: unpriced,
        zero_priced_models: zero_priced,
        redactions: Redactions { by_secret, recent },
    }
}

fn merge_agg(dst: &mut UsageAgg, src: &UsageAgg) {
    dst.requests = dst.requests.saturating_add(src.requests);
    dst.requests_without_usage = dst
        .requests_without_usage
        .saturating_add(src.requests_without_usage);
    dst.retries = dst.retries.saturating_add(src.retries);
    dst.no_messages = dst.no_messages.saturating_add(src.no_messages);
    dst.rate_limited_429 = dst.rate_limited_429.saturating_add(src.rate_limited_429);
    dst.errors_4xx = dst.errors_4xx.saturating_add(src.errors_4xx);
    dst.errors_5xx = dst.errors_5xx.saturating_add(src.errors_5xx);
    dst.input = dst.input.saturating_add(src.input);
    dst.output = dst.output.saturating_add(src.output);
    dst.cache_read = dst.cache_read.saturating_add(src.cache_read);
    dst.cache_write = dst.cache_write.saturating_add(src.cache_write);
}

#[cfg(test)]
mod tests {
    /// 无域名启发的 hint (所有测试共享, 替代 4 处重复闭包).
    fn no_hint(_p: &str) -> Option<String> {
        None
    }

    use super::*;
    use crate::dag::RoundKind;
    use crate::usage::{UsageEvent, UsageQuanta};
    use std::collections::HashMap;

    fn store_with(events: &[UsageEvent]) -> UsageStore {
        let s = UsageStore::in_memory();
        for e in events {
            s.record(e.clone());
        }
        s
    }

    fn ev(
        hour_offset: i64,
        provider: &str,
        model: Option<&str>,
        q: Option<UsageQuanta>,
    ) -> UsageEvent {
        UsageEvent {
            ts: chrono::Utc::now() - chrono::Duration::hours(hour_offset),
            provider: provider.to_string(),
            model: model.map(String::from),
            model_req: None,
            proto: "o".to_string(),
            status: 200,
            complete: true,
            round_kind: RoundKind::Normal,
            usage: q,
        }
    }

    /// build_summary 样板收口 (7 处调用共享).
    fn summarize(s: &UsageStore, table: &PricingTable, hours: u32) -> UsageSummary {
        build_summary(
            SummaryInputs {
                store: s,
                table,
                hours,
                domain_hint: &no_hint,
            },
            PricingStatus::Ok,
        )
    }

    fn priced_table() -> PricingTable {
        let mut overrides = HashMap::new();
        overrides.insert(
            "m-priced".to_string(),
            ModelPrice {
                input: 1.0,
                output: 2.0,
                cache_read: 0.1,
                cache_write: 0.5,
            },
        );
        PricingTable::new(None, overrides)
    }

    // ─── USAGE-1: 分项之和 == totals ───────────────────────────────────

    #[test]
    fn summary_sums_match_totals_across_all_views() {
        let s = store_with(&[
            ev(
                0,
                "p1",
                Some("m-priced"),
                Some(UsageQuanta {
                    i: 1000,
                    o: 500,
                    cr: 0,
                    cw: 0,
                }),
            ),
            ev(
                0,
                "p1",
                Some("m-unpriced"),
                Some(UsageQuanta {
                    i: 100,
                    o: 0,
                    cr: 0,
                    cw: 0,
                }),
            ),
            ev(0, "p2", Some("m-priced"), None),
            ev(
                48,
                "p1",
                Some("m-priced"),
                Some(UsageQuanta {
                    i: 100,
                    o: 100,
                    cr: 0,
                    cw: 0,
                }),
            ), // 窗口外
        ]);
        let table = priced_table();
        let sum = summarize(&s, &table, 24);
        assert_eq!(sum.range.granularity, "hour");
        let t = &sum.totals;
        assert_eq!(t.agg.requests, 3, "window = 24h (48h-old event excluded)");
        assert_eq!(t.agg.requests_without_usage, 1);
        assert_eq!(t.agg.input, 1100);
        assert_eq!(t.agg.output, 500);
        // USAGE-1: by_model 之和 == totals.
        let m_req: u64 = sum.by_model.iter().map(|r| r.agg.requests).sum();
        let m_in: u64 = sum.by_model.iter().map(|r| r.agg.input).sum();
        assert_eq!((m_req, m_in), (t.agg.requests, t.agg.input));
        // by_provider 之和 == totals.
        let p_req: u64 = sum.by_provider.iter().map(|r| r.agg.requests).sum();
        assert_eq!(p_req, t.agg.requests);
        // by_bucket 之和 == totals (窗口内仅当前小时有数据, 其余补零).
        let b_req: u64 = sum.by_bucket.iter().map(|r| r.agg.requests).sum();
        assert_eq!(b_req, t.agg.requests);
        assert_eq!(sum.by_bucket.len(), 24, "zero-filled contiguous hours");
        // USAGE-4: cost_coverage 只算有 usage 的请求: 有 usage 2 (1 priced + 1 unpriced) → 0.5.
        assert!((t.cost_coverage.unwrap() - 0.5).abs() < 1e-9);
        assert_eq!(sum.unpriced_models, vec!["m-unpriced"]);
        // USAGE-3: cost = 1000×1 + 500×2 (M) = $0.002.
        assert!((t.est_cost_usd - 0.002).abs() < 1e-12);
    }

    // ─── USAGE-1: by_model (model, provider) 键唯一 (跨 bucket 折叠) ────

    #[test]
    fn by_model_folds_buckets_into_one_row_per_model_provider() {
        // 同 (provider, model) 跨 3 个 hour bucket + 同 model 不同 provider →
        // by_model 恰好 2 行 (键唯一), agg 与 cost 合并; 时间维度由 by_bucket 承担.
        // 回归: 旧实现按 (bucket, provider, model) cell 直出, 同 model 每
        // 小时一行 (WebUI "By model" 表同 provider+model 多行).
        let s = store_with(&[
            ev(
                0,
                "p1",
                Some("m-priced"),
                Some(UsageQuanta {
                    i: 10,
                    o: 1,
                    cr: 0,
                    cw: 0,
                }),
            ),
            ev(
                2,
                "p1",
                Some("m-priced"),
                Some(UsageQuanta {
                    i: 20,
                    o: 2,
                    cr: 0,
                    cw: 0,
                }),
            ),
            ev(4, "p1", Some("m-priced"), None),
            ev(
                0,
                "p2",
                Some("m"),
                Some(UsageQuanta {
                    i: 30,
                    o: 3,
                    cr: 0,
                    cw: 0,
                }),
            ),
        ]);
        let table = priced_table();
        let sum = summarize(&s, &table, 24);
        assert_eq!(
            sum.by_model.len(),
            2,
            "one row per (model, provider): {:#?}",
            sum.by_model
        );
        let p1 = sum
            .by_model
            .iter()
            .find(|r| r.provider == "p1")
            .expect("p1 row folded");
        assert_eq!(p1.model.as_deref(), Some("m-priced"));
        assert_eq!(p1.agg.requests, 3);
        assert_eq!(p1.agg.requests_without_usage, 1);
        assert_eq!(p1.agg.input, 30);
        assert_eq!(p1.agg.output, 3);
        // cost 随折叠合并: (10×1+1×2 + 20×1+2×2) / 1e6 = 3.6e-5 ($/1M 价表).
        assert!((p1.est_cost_usd - 3.6e-5).abs() < 1e-12);
        // USAGE-1 折叠后仍成立: by_model 分项之和 == totals.
        let m_req: u64 = sum.by_model.iter().map(|r| r.agg.requests).sum();
        assert_eq!(m_req, sum.totals.agg.requests);
    }

    // ─── 长窗口: day 折叠粒度 ──────────────────────────────────────────

    #[test]
    fn long_window_folds_to_day_granularity() {
        let s = store_with(&[
            ev(0, "p", Some("m"), None),
            ev(23, "p", Some("m"), None),
            ev(24, "p", Some("m"), None),
        ]);
        let table = PricingTable::empty();
        let sum = build_summary(
            SummaryInputs {
                store: &s,
                table: &table,
                hours: 24 * 30,
                domain_hint: &no_hint,
            },
            PricingStatus::Ok,
        );
        assert_eq!(sum.range.granularity, "day");
        assert_eq!(sum.by_bucket.len(), 30, "zero-filled contiguous days");
        assert_eq!(sum.totals.agg.requests, 3);
        // 2 个自然日有数据 (48h 窗口跨 3 个事件 → 今天 1 + 昨天 2).
        let nonzero = sum.by_bucket.iter().filter(|b| b.agg.requests > 0).count();
        assert_eq!(nonzero, 2);
    }

    // ─── 粒度切换边界 (HOURLY_MAX_HOURS = 336) ──────────────────────────

    #[test]
    fn granularity_switches_exactly_at_threshold() {
        let s = UsageStore::in_memory();
        let table = PricingTable::empty();
        let build = |hours: u32| {
            build_summary(
                SummaryInputs {
                    store: &s,
                    table: &table,
                    hours,
                    domain_hint: &no_hint,
                },
                PricingStatus::Ok,
            )
        };
        // ≤336h → hour bucket; >336h → day 折叠; hours=0 归一为 1 (单个 hour).
        assert_eq!(build(336).range.granularity, "hour");
        assert_eq!(build(336).by_bucket.len(), 336);
        assert_eq!(build(337).range.granularity, "day");
        assert_eq!(build(337).by_bucket.len(), 15); // ceil(337/24) 天
        let one = build(0);
        assert_eq!(one.range.granularity, "hour");
        assert_eq!(one.by_bucket.len(), 1, "hours=0 → 1 (当前小时)");
    }

    // ─── USAGE-3: 逐事件算再求和 == fold 后再算 (线性性) ───────────────

    #[test]
    fn cost_is_linear_in_aggregation() {
        let s = store_with(&[
            ev(
                0,
                "p",
                Some("m-priced"),
                Some(UsageQuanta {
                    i: 1000,
                    o: 500,
                    cr: 0,
                    cw: 0,
                }),
            ),
            ev(
                0,
                "p",
                Some("m-priced"),
                Some(UsageQuanta {
                    i: 2000,
                    o: 1500,
                    cr: 0,
                    cw: 0,
                }),
            ),
        ]);
        let table = priced_table();
        let sum = summarize(&s, &table, 24);
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
            Some(UsageQuanta {
                i: 100,
                o: 0,
                cr: 100,
                cw: 300,
            }),
        )]);
        let table = priced_table();
        let sum = summarize(&s, &table, 24);
        // 100 / (100+100+300) = 0.2.
        assert!((sum.totals.cache_hit_rate.unwrap() - 0.2).abs() < 1e-9);
    }

    // ─── 空数据 / 补零 bucket ────────────────────────────────────────────

    #[test]
    fn empty_store_yields_zeroed_buckets_and_none_rates() {
        let s = UsageStore::in_memory();
        let table = PricingTable::empty();
        let sum = summarize(&s, &table, 168);
        assert_eq!(sum.by_bucket.len(), 168, "zero-filled contiguous hours");
        assert_eq!(sum.totals.agg.requests, 0);
        assert!(sum.totals.cache_hit_rate.is_none());
        assert!(sum.totals.cost_coverage.is_none());
        // USAGE-7: 空窗口 redactions 视图为空.
        assert!(sum.redactions.by_secret.is_empty());
        assert!(sum.redactions.recent.is_empty());
    }

    // ─── USAGE-4: zero_priced 显式 ($0 不冒充"全覆盖估算", #202) ──────

    #[test]
    fn zero_priced_models_listed_without_breaking_coverage() {
        // m-zero: 四价全零 (套餐 vendor / 免费档形态); m-priced: 正常价.
        let mut overrides = HashMap::new();
        overrides.insert("m-zero".to_string(), ModelPrice::default());
        overrides.insert(
            "m-priced".to_string(),
            ModelPrice {
                input: 1.0,
                output: 2.0,
                cache_read: 0.1,
                cache_write: 0.5,
            },
        );
        let table = PricingTable::new(None, overrides);
        let s = store_with(&[
            ev(
                0,
                "p",
                Some("m-zero"),
                Some(UsageQuanta {
                    i: 100,
                    o: 50,
                    cr: 0,
                    cw: 0,
                }),
            ),
            ev(
                0,
                "p",
                Some("m-priced"),
                Some(UsageQuanta {
                    i: 100,
                    o: 0,
                    cr: 0,
                    cw: 0,
                }),
            ),
        ]);
        let sum = summarize(&s, &table, 24);
        // 零价是"已知的价" → coverage 仍算 fully priced (口径不变),
        // 但 m-zero 显式出现在 zero_priced_models 而非 unpriced_models.
        assert_eq!(sum.totals.cost_coverage, Some(1.0));
        assert_eq!(sum.zero_priced_models, vec!["m-zero"]);
        assert_eq!(sum.unpriced_models, Vec::<String>::new());
        // cost 只有 m-priced 的贡献 (m-zero ×$0).
        assert!((sum.totals.est_cost_usd - 0.0001).abs() < 1e-12);
    }
}
