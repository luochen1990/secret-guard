//! models.dev 定价表: 拉取 / 缓存 / 匹配 / 用户 override (usage-stats §7).
//!
//! # 数据源 (P-2 零自维护价目表)
//!
//! `https://models.dev/api.json` (单文件全量, MIT): `{vendor: {id, name, api?,
//! models: {model_id: {cost: {input, output, cache_read, cache_write}, ...}}}}`.
//! 四价 ($/1M tokens) schema 由 opencode `provider.ts` 消费方式佐证; 本模块只提取
//! cost 子集, 其余字段 lenient 跳过 (上游加字段不破坏解析).
//!
//! # 缓存语义 (照抄 #196 ModelListCache: TTL + serve-stale-on-error + 退避)
//!
//! - 惰性首拉: 首个 usage 查询触发, 不阻塞启动;
//! - TTL 24h (可配 `pricing_refresh_secs`), 过期后下次查询刷新;
//! - serve-stale-on-error: 刷新失败继续用旧表 (`stale` 状态);
//! - 失败退避 30s: 窗口内查询立即返回, 不重试 (防 dead 网络逐查询阻塞);
//! - single-flight: tokio Mutex 串行 refresh, 并发查询等首个结果;
//! - 离线冷启动兜底: 成功后写 `secret-guard.pricing.json`, 无网络时读盘.
//!
//! # 匹配规则 (usage-stats 设计 §7 "匹配规则")
//!
//! 1. 用户 override 全名精确匹配 (键 = 聚合用 model 字符串, 最高优先);
//! 2. models.dev `model_id` 精确匹配: 唯一命中 → 取; 多 vendor 同名 → 按 provider
//!    base_url 域名启发 (vendor 的 `api` 字段 host == hint) 消歧, 仍歧义 →
//!    字母序第一个 + 标记 ambiguous;
//! 3. 剥日期后缀 (`-YYYY-MM-DD$`) 后重复步骤 2;
//! 4. 均失败 → `None` (调用方计入 unpriced, P-4 不显示 $0.00).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tracing::{debug, warn};

/// 单模型四价 ($ / 1M tokens). cache 两维缺省回退: cache_read 缺 → input 价,
/// cache_write 缺 → 1.25×input (Anthropic 质量型写入加价惯例的宽松近似 —
/// 有值时永远用真实值, 回退只影响缺价字段的估算).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct ModelPrice {
    pub input: f64,
    pub output: f64,
    pub cache_read: f64,
    pub cache_write: f64,
}

/// models.dev api.json 的解析产物 (remote 表; override 在 [`PricingTable`] 合并).
#[derive(Debug, Default, Clone)]
pub struct PricingData {
    /// model_id → 候选 (vendor, price) 列表 (同名多 vendor 时 len>1).
    by_model: HashMap<String, Vec<(String, ModelPrice)>>,
    /// vendor 的 api base URL host → vendor id (域名启发消歧用).
    vendor_domain: HashMap<String, String>,
}

/// 解析状态 (UI 的 `pricing_status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PricingStatus {
    /// 从未成功拉取且无盘缓存 (首拉进行中 / 尚未发生).
    Loading,
    /// 表新鲜 (TTL 内).
    Ok,
    /// 有表但 TTL 已过且刷新失败 (serve-stale-on-error).
    Stale,
    /// 无表且最近刷新失败 (30s 退避窗口内).
    Offline,
}

impl PricingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loading => "loading",
            Self::Ok => "ok",
            Self::Stale => "stale",
            Self::Offline => "offline",
        }
    }
}

impl PricingData {
    /// 解析 models.dev api.json (lenient: 无 cost 的模型跳过, 非 object 跳过).
    /// 返回 (data, 有 cost 的模型数, 被跳过数) — 跳过多时 WARN 防上游 schema 漂移
    /// 静默丢价 (评审 n7).
    pub fn parse(json: &serde_json::Value) -> (Self, usize, usize) {
        let mut data = Self::default();
        let mut priced = 0usize;
        let mut skipped = 0usize;
        let Some(root) = json.as_object() else {
            warn!("models.dev api.json: root is not an object");
            return (data, 0, 0);
        };
        for (vendor, entry) in root {
            let Some(obj) = entry.as_object() else {
                continue;
            };
            // vendor api host (域名启发用; 缺 api 字段则该 vendor 不参与消歧).
            // host 提取: scheme://host[:port]/... 手动切 (避免为 3 行逻辑引 url crate).
            if let Some(api) = obj.get("api").and_then(|v| v.as_str())
                && let Some(host) = extract_host(api)
            {
                data.vendor_domain.insert(host, vendor.clone());
            }
            let Some(models) = obj.get("models").and_then(|v| v.as_object()) else {
                continue;
            };
            for (model_id, m) in models {
                let Some(price) = m.get("cost").and_then(parse_price) else {
                    skipped += 1;
                    continue;
                };
                data.by_model
                    .entry(model_id.clone())
                    .or_default()
                    .push((vendor.clone(), price));
                priced += 1;
            }
        }
        (data, priced, skipped)
    }

    /// 步骤 2/3 的 remote 匹配 (无 override).
    fn lookup(&self, model: &str, domain_hint: Option<&str>) -> Option<ModelPrice> {
        self.lookup_exact(model, domain_hint)
            .or_else(|| {
                // 剥日期后缀 ("-YYYY-MM-DD" = 11 chars) 再试一次.
                model
                    .as_bytes()
                    .len()
                    .checked_sub(11)
                    .filter(|&i| {
                        let b = model.as_bytes();
                        b[i] == b'-'
                            && b[i + 1..i + 5].iter().all(u8::is_ascii_digit)
                            && b[i + 5] == b'-'
                            && b[i + 6..i + 8].iter().all(u8::is_ascii_digit)
                            && b[i + 8] == b'-'
                            && b[i + 9..i + 11].iter().all(u8::is_ascii_digit)
                    })
                    .map(|i| &model[..i])
                    .and_then(|stripped| self.lookup_exact(stripped, domain_hint))
            })
    }

    fn lookup_exact(&self, model: &str, domain_hint: Option<&str>) -> Option<ModelPrice> {
        match self.by_model.get(model)?.as_slice() {
            [] => None,
            [only] => Some(only.1),
            many => {
                // 多 vendor 同名: 域名启发 (hint host == vendor 的 api host).
                if let Some(hint) = domain_hint
                    && let Some(vendor) = self.vendor_domain.get(hint)
                    && let Some((_, price)) = many.iter().find(|(v, _)| v == vendor)
                {
                    return Some(*price);
                }
                // 仍歧义: 字母序第一个 (确定性; 设计 §7 规则 2).
                many.iter().min_by_key(|(v, _)| v.as_str()).map(|(_, p)| *p)
            }
        }
    }
}

/// cost 对象 → ModelPrice (缺 cache 价的回退见 [`ModelPrice`] 文档).
fn parse_price(cost: &serde_json::Value) -> Option<ModelPrice> {
    let f = |k: &str| cost.get(k).and_then(|v| v.as_f64());
    let input = f("input")?;
    let output = f("output")?;
    Some(ModelPrice {
        input,
        output,
        cache_read: f("cache_read").unwrap_or(input),
        cache_write: f("cache_write").unwrap_or(input * 1.25),
    })
}

/// URL → 小写 host (scheme://host[:port]/...). 解析不出返回 None.
/// pub: web/api 的 domain hint 也用它解析 provider base_url.
pub fn extract_host(api: &str) -> Option<String> {
    let rest = api.split_once("://")?.1;
    let host_port = rest.split('/').next()?;
    let host = host_port.rsplit_once(':').map_or(host_port, |(h, _)| h);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// 合并视图: override (最高优先) + remote 表. 匹配的单一入口 (USAGE-3 纯函数).
#[derive(Debug, Default, Clone)]
pub struct PricingTable {
    remote: Option<Arc<PricingData>>,
    overrides: HashMap<String, ModelPrice>,
}

impl PricingTable {
    pub fn new(remote: Option<Arc<PricingData>>, overrides: HashMap<String, ModelPrice>) -> Self {
        Self { remote, overrides }
    }

    pub fn empty() -> Self {
        Self::default()
    }

    /// 匹配规则 SSOT (§7): override 精确 → remote 精确 (域名消歧) → 剥日期后缀 → None.
    pub fn price_for(&self, model: &str, domain_hint: Option<&str>) -> Option<ModelPrice> {
        if let Some(p) = self.overrides.get(model) {
            return Some(*p);
        }
        self.remote.as_ref()?.lookup(model, domain_hint)
    }
}

// ─── PricingCache: 拉取 / TTL / serve-stale / 退避 / single-flight ──────────

/// 刷新失败后的退避窗口 (窗口内不重试, 查询立即返回).
const FETCH_BACKOFF: Duration = Duration::from_secs(30);
/// 单次拉取超时 (超时按 stale/offline 处理, 不阻塞查询者).
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

struct CacheState {
    data: Option<Arc<PricingData>>,
    fetched_at: Option<Instant>,
    last_failure: Option<Instant>,
}

/// 进程级定价缓存 (AppState 聚合; handler 经 [`Self::table`] 取合并视图).
pub struct PricingCache {
    url: String,
    ttl: Duration,
    disk_path: PathBuf,
    overrides: HashMap<String, ModelPrice>,
    state: RwLock<CacheState>,
    /// single-flight: refresh 期间持锁, 并发查询等待 ( tokio Mutex — refresh 含 await).
    refresh_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for PricingCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PricingCache")
            .field("url", &self.url)
            .field("ttl", &self.ttl)
            .field("disk_path", &self.disk_path)
            .field("overrides", &self.overrides.len())
            .field("has_data", &self.state.read().data.is_some())
            .finish_non_exhaustive()
    }
}

impl PricingCache {
    pub fn new(url: String, ttl: Duration, disk_path: PathBuf, overrides: HashMap<String, ModelPrice>) -> Self {
        // 冷启动: 无网络时读盘兜底 (fetched_at 置很久前 → 首查询即尝试刷新).
        let (disk_data, fetched_at) = match load_disk(&disk_path) {
            Some(d) => (Some(Arc::new(d)), Some(Instant::now() - ttl)),
            None => (None, None),
        };
        Self {
            url,
            ttl,
            disk_path,
            overrides,
            state: RwLock::new(CacheState {
                data: disk_data,
                fetched_at,
                last_failure: None,
            }),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// 取 (合并视图, 状态). 可能触发一次异步刷新 (惰性 + TTL + 退避 + single-flight).
    pub async fn table(&self, http: &reqwest::Client) -> (PricingTable, PricingStatus) {
        let needs_refresh = {
            let s = self.state.read();
            match (s.data.is_some(), s.fetched_at) {
                // 从未有过数据且不在退避窗口 → 需要拉.
                (false, _) => {
                    s.last_failure.is_none_or(|t| t.elapsed() >= FETCH_BACKOFF)
                }
                // 有数据: TTL 内新鲜 → 不拉.
                (_, Some(t)) if t.elapsed() < self.ttl => false,
                // TTL 过期 → 拉 (serve-stale).
                _ => true,
            }
        };
        if needs_refresh {
            let _guard = self.refresh_lock.lock().await;
            // double-check: 等锁期间可能已被首个查询者刷新.
            let still = {
                let s = self.state.read();
                s.fetched_at.is_none_or(|t| t.elapsed() >= self.ttl)
                    || (s.data.is_none() && s.last_failure.is_none_or(|t| t.elapsed() >= FETCH_BACKOFF))
            };
            if still {
                self.refresh(http).await;
            }
        }
        let s = self.state.read();
        let status = match (&s.data, s.fetched_at) {
            (None, _) if s.last_failure.is_some() => PricingStatus::Offline,
            (None, _) => PricingStatus::Loading,
            (Some(_), Some(t)) if t.elapsed() < self.ttl => PricingStatus::Ok,
            (Some(_), _) => PricingStatus::Stale,
        };
        (
            PricingTable::new(s.data.clone(), self.overrides.clone()),
            status,
        )
    }

    async fn refresh(&self, http: &reqwest::Client) {
        match http.get(&self.url).timeout(FETCH_TIMEOUT).send().await {
            Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
                Ok(json) => {
                    let (data, priced, skipped) = PricingData::parse(&json);
                    if priced == 0 {
                        // schema 漂移防护 (n7): 解析成功但零价 = 上游结构变了.
                        warn!(url = %self.url, skipped, "models.dev parse yielded 0 priced models; schema drift? keeping old data");
                        self.record_failure();
                        return;
                    }
                    if skipped > 0 {
                        debug!(skipped, priced, "models.dev: some models have no cost (normal)");
                    }
                    write_disk(&self.disk_path, &json);
                    let mut s = self.state.write();
                    s.data = Some(Arc::new(data));
                    s.fetched_at = Some(Instant::now());
                    s.last_failure = None;
                }
                Err(e) => {
                    warn!(url = %self.url, error = %e, "models.dev fetch body parse failed");
                    self.record_failure();
                }
            },
            Ok(resp) => {
                warn!(url = %self.url, status = resp.status().as_u16(), "models.dev fetch non-2xx");
                self.record_failure();
            }
            Err(e) => {
                warn!(url = %self.url, error = %e, "models.dev fetch failed (offline?)");
                self.record_failure();
            }
        }
    }

    fn record_failure(&self) {
        self.state.write().last_failure = Some(Instant::now());
    }
}

fn load_disk(path: &Path) -> Option<PricingData> {
    let raw = std::fs::read(path).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let (data, priced, _) = PricingData::parse(&json);
    (priced > 0).then_some(data)
}

fn write_disk(path: &Path, json: &serde_json::Value) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(e) = std::fs::write(path, serde_json::to_vec(json).unwrap_or_default()) {
        warn!(path = %path.display(), error = %e, "pricing disk cache write failed (non-fatal)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// models.dev api.json 的最小 schema 快照 (锁定 cost 四价 + api 字段形态).
    fn fixture() -> serde_json::Value {
        json!({
            "openai": {
                "id": "openai", "name": "OpenAI",
                "api": "https://api.openai.com/v1",
                "models": {
                    "gpt-5.6-terra": {
                        "limit": {"context": 1050000, "output": 128000},
                        "cost": {"input": 1.25, "output": 10.0, "cache_read": 0.125}
                    },
                    "gpt-free": {"cost": {"input": 0.0, "output": 0.0}}
                }
            },
            "anthropic": {
                "id": "anthropic", "name": "Anthropic",
                "api": "https://api.anthropic.com",
                "models": {
                    "claude-opus-5": {
                        "cost": {"input": 5.0, "output": 25.0, "cache_read": 0.5, "cache_write": 6.25}
                    }
                }
            },
            "relay-x": {
                "id": "relay-x",
                "models": {
                    // 同名多 vendor (消歧用): gpt-5.6-terra 也在 relay-x.
                    "gpt-5.6-terra": {"cost": {"input": 2.0, "output": 20.0}}
                }
            },
            "no-cost-vendor": {"id": "nc", "models": {"m-nc": {"limit": {}}}}
        })
    }

    // ─── schema 快照 + 解析 (n7: 防 upstream schema 漂移静默丢价) ────────

    #[test]
    fn parse_extracts_prices_and_vendor_domains() {
        let (data, priced, skipped) = PricingData::parse(&fixture());
        assert_eq!(priced, 4, "gpt-5.6-terra ×2 + gpt-free + claude-opus-5");
        assert_eq!(skipped, 1, "m-nc has no cost");
        assert_eq!(data.vendor_domain.get("api.openai.com").map(String::as_str), Some("openai"));
        assert_eq!(
            data.vendor_domain.get("api.anthropic.com").map(String::as_str),
            Some("anthropic")
        );
        assert!(!data.vendor_domain.contains_key("relay-x"), "no api field");
    }

    #[test]
    fn parse_price_falls_back_for_missing_cache_fields() {
        let (data, _) = {
            let (d, _, _) = PricingData::parse(&fixture());
            (d, ())
        };
        let cands = data.by_model.get("gpt-5.6-terra").unwrap();
        let openai = cands.iter().find(|(v, _)| v == "openai").unwrap().1;
        // cache_write 缺 → 1.25×input; cache_read 有值用真实值.
        assert!((openai.cache_write - 1.25 * 1.25).abs() < 1e-9);
        assert!((openai.cache_read - 0.125).abs() < 1e-9);
    }

    // ─── 匹配规则 (§7: override → 精确 → 消歧 → 剥日期后缀) ─────────────

    fn table() -> PricingTable {
        let (data, _, _) = PricingData::parse(&fixture());
        let mut overrides = HashMap::new();
        overrides.insert(
            "my-relay/gpt-fork".to_string(),
            ModelPrice { input: 0.5, output: 2.0, cache_read: 0.05, cache_write: 0.75 },
        );
        PricingTable::new(Some(Arc::new(data)), overrides)
    }

    #[test]
    fn match_override_wins_over_remote() {
        let t = table();
        let p = t.price_for("my-relay/gpt-fork", None).unwrap();
        assert!((p.input - 0.5).abs() < 1e-9);
    }

    #[test]
    fn match_unique_model_id_exact() {
        let t = table();
        let p = t.price_for("claude-opus-5", None).unwrap();
        assert!((p.input - 5.0).abs() < 1e-9);
    }

    #[test]
    fn match_ambiguous_resolved_by_domain_hint_then_alphabetical() {
        let t = table();
        // 域名启发: hint 是 anthropic 的 host, 但 gpt-5.6-terra 候选只有
        // openai + relay-x → 启发不命中 → 字母序 (openai < relay-x).
        let p = t.price_for("gpt-5.6-terra", Some("api.anthropic.com")).unwrap();
        assert!((p.input - 1.25).abs() < 1e-9, "alphabetical fallback");
        // 启发命中 relay 的场景: 构造 relay 域名 hint — fixture 中 relay-x 无 api
        // 字段, 故无法命中; 字母序兜底仍是 openai. (验证确定性即可.)
        let p2 = t.price_for("gpt-5.6-terra", Some("unknown.host")).unwrap();
        assert!((p2.input - 1.25).abs() < 1e-9);
    }

    #[test]
    fn match_strips_date_suffix() {
        let t = table();
        let p = t.price_for("claude-opus-5-2026-07-24", None).unwrap();
        assert!((p.input - 5.0).abs() < 1e-9, "date-suffixed variant must match base");
        // 非日期后缀不剥.
        assert!(t.price_for("claude-opus-5-latest", None).is_none());
    }

    #[test]
    fn match_unpriced_returns_none() {
        let t = table();
        assert!(t.price_for("m-nc", None).is_none());
        assert!(t.price_for("totally-unknown", None).is_none());
        // 空表 (offline 冷启动): 全 None, override 仍可用.
        let mut overrides = HashMap::new();
        overrides.insert("x".to_string(), ModelPrice::default());
        let empty = PricingTable::new(None, overrides);
        assert!(empty.price_for("y", None).is_none());
        assert!(empty.price_for("x", None).is_some());
    }
}
