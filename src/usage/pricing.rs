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
//! - 离线冷启动兜底: 成功后写 state 目录固定名 `pricing.json`
//!   (SSOT: `server.rs::state_dir_artifact`), 无网络时读盘.
//!
//! # 匹配规则 (usage-stats 设计 §7 "匹配规则")
//!
//! 1. 用户 override 全名精确匹配 (键 = 聚合用 model 字符串, 最高优先);
//! 2. models.dev `model_id` 精确匹配: 唯一命中 → 取; 多 vendor 同名 → 域名启发
//!    消歧 (hint host 的 vendor 集 ∩ 候选集**非空则收缩到交集**; 空 = 无信号,
//!    不收缩、全池落偏好序), 池内按**确定性偏好序**取第一: 无 `-plan` 段 >
//!    名短 > 字母序 (同 host 多 vendor 碰撞场景, #202). 偏好序是启发式策略而非
//!    正确性保证, 被击穿时零价结果由 `zero_priced_models` 显式暴露 (USAGE-4),
//!    用户可用 `pricing_override` 一锤定音;
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
    /// vendor 的 api base URL host → 候选 vendor 列表 (域名启发消歧用;
    /// 同 host 多 vendor 碰撞时**全部保留** — 单值 last-wins 会静默依赖上游
    /// JSON 键序决定胜者, #202. parse 时排序保证与迭代序无关).
    vendor_domain: HashMap<String, Vec<String>>,
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
                // 同 host 碰撞全保留 (Vec), 不覆盖 (#202).
                data.vendor_domain
                    .entry(host)
                    .or_default()
                    .push(vendor.clone());
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
        // 仅为存储形态规范化 + 测试断言确定性 (查询语义由偏好序全序保证,
        // 不依赖此序).
        for vendors in data.vendor_domain.values_mut() {
            vendors.sort();
        }
        (data, priced, skipped)
    }

    /// 步骤 2/3 的 remote 匹配 (无 override).
    fn lookup(&self, model: &str, domain_hint: Option<&str>) -> Option<ModelPrice> {
        self.lookup_exact(model, domain_hint).or_else(|| {
            // 剥日期后缀 ("-YYYY-MM-DD" = 11 chars) 再试一次.
            model
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
                // 多 vendor 同名消歧 (#202), 两级信号强度递减:
                // 1) host 信号 (部署侧事实): hint host 的 vendor 集与候选的**交集非空
                //    则收缩到交集** (用户 provider 就部署在该 host 上, 交集外的候选
                //    是别家 host 的 vendor); 空交集 / 无 hint = 无信号, 不收缩.
                let pool: Vec<&(String, ModelPrice)> = domain_hint
                    .and_then(|h| self.vendor_domain.get(h))
                    .and_then(|host_vendors| {
                        let matched: Vec<_> = many
                            .iter()
                            .filter(|(v, _)| host_vendors.contains(v))
                            .collect();
                        (!matched.is_empty()).then_some(matched)
                    })
                    .unwrap_or_else(|| many.iter().collect());
                // 2) 确定性偏好序 (数据侧先验, **启发式而非正确性保证**):
                //    无 `-plan` 段 > 名字短 > 字母序. (bool, usize, &str) 是全序 →
                //    唯一最小元, 结果与数据迭代序无关. 偏好序被击穿时 (如不含
                //    plan 段的订阅系命名), 零价结果由 zero_priced_models 显式暴露.
                pool.into_iter()
                    .min_by_key(|(v, _)| disambig_key(v))
                    .map(|(_, p)| *p)
            }
        }
    }
}

/// vendor 名是否为订阅/套餐系 (`-` 分段含 `plan`, 如 `zhipuai-coding-plan` /
/// `tencent-token-plan`). 段匹配防 `planetscale` 型子串误伤.
fn is_plan_vendor(v: &str) -> bool {
    v.split('-').any(|seg| seg == "plan")
}

/// 碰撞消歧的偏好序键: (是否 plan vendor, 名长, 名字) 逐级字典序比较.
fn disambig_key(v: &str) -> (bool, usize, &str) {
    (is_plan_vendor(v), v.len(), v)
}

/// 缺 cache 价的回退规则 SSOT (P-2 的宽松近似, 有值时永远用真实值):
/// `cache_read` 缺 → 按 `input` 价; `cache_write` 缺 → 按 **1.25×input**
/// (Anthropic 质量型缓存写入加价的惯例近似). parse 与 config override 共用.
impl ModelPrice {
    pub fn with_cache_fallback(
        input: f64,
        output: f64,
        cache_read: Option<f64>,
        cache_write: Option<f64>,
    ) -> Self {
        Self {
            input,
            output,
            cache_read: cache_read.unwrap_or(input),
            cache_write: cache_write.unwrap_or(input * 1.25),
        }
    }

    /// 四价全零 (models.dev 的免费档 / 套餐 vendor 计量口径). summary 据此把
    /// model 列入 `zero_priced_models` — "$0 已知价" 与 "无价" 分开显式 (USAGE-4),
    /// 防 cost=0 + coverage=1.0 掩盖 (#202).
    pub fn is_all_zero(&self) -> bool {
        self.input == 0.0 && self.output == 0.0 && self.cache_read == 0.0 && self.cache_write == 0.0
    }
}

/// cost 对象 → ModelPrice (缺 cache 价回退见 [`ModelPrice::with_cache_fallback`]).
fn parse_price(cost: &serde_json::Value) -> Option<ModelPrice> {
    let f = |k: &str| cost.get(k).and_then(|v| v.as_f64());
    let input = f("input")?;
    let output = f("output")?;
    Some(ModelPrice::with_cache_fallback(
        input,
        output,
        f("cache_read"),
        f("cache_write"),
    ))
}

/// `[usage.pricing_override]` 配置 → override map (server.rs 装配调用).
pub fn price_overrides_from_config(
    o: &std::collections::HashMap<String, crate::config::PriceOverride>,
) -> HashMap<String, ModelPrice> {
    o.iter()
        .map(|(k, v)| {
            (
                k.clone(),
                ModelPrice::with_cache_fallback(v.input, v.output, v.cache_read, v.cache_write),
            )
        })
        .collect()
}

/// URL → 小写 host (`scheme://host[:port]/...` 形态). 解析不出返回 None.
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
    backoff: Duration,
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
    pub fn new(
        url: String,
        ttl: Duration,
        disk_path: PathBuf,
        overrides: HashMap<String, ModelPrice>,
    ) -> Self {
        Self::with_backoff(url, ttl, FETCH_BACKOFF, disk_path, overrides)
    }

    /// 测试构造 (dead URL + /dev/null 盘 + 无 override): AppState fixture 用,
    /// 与 `UsageStore::in_memory` 模式对称. TTL 取大值防测试环境意外拉取.
    pub fn for_tests() -> Self {
        Self::new(
            "about:blank".to_string(),
            Duration::from_secs(3600),
            PathBuf::from("/dev/null"),
            HashMap::new(),
        )
    }

    /// 测试可注入退避窗口 (生产经 [`Self::new`] 用 FETCH_BACKOFF 常量).
    pub fn with_backoff(
        url: String,
        ttl: Duration,
        backoff: Duration,
        disk_path: PathBuf,
        overrides: HashMap<String, ModelPrice>,
    ) -> Self {
        // 冷启动: 无网络时读盘兜底 (fetched_at 置"过期" → 首查询即尝试刷新).
        // checked_sub: uptime < ttl 的平台 (Windows Instant 单调钟不可表示过去点,
        // 直接减会 panic) 退化为 None = "从未刷新", 首查询同样触发拉取 — 语义等价.
        let stale_marker = Instant::now().checked_sub(ttl);
        let (disk_data, fetched_at) = match load_disk(&disk_path) {
            // fetched_at 直接透传 stale_marker (Option): None = "从未刷新" → 首查询
            // 触发拉取 (fresh=false), status 落 Stale — 与可减平台语义一致.
            Some(d) => (Some(Arc::new(d)), stale_marker),
            None => (None, None),
        };
        Self {
            url,
            ttl,
            backoff,
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
        // 刷新门控 (与 #196 语义对齐): 表新鲜 → 不拉; 退避窗口内 (含 serve-stale 与
        // 无数据两形态) → 不拉; 其余 (TTL 过期 / 从未拉过) → 拉.
        // 注: 退避窗口同样约束 stale 表的重试 — 否则 dead 网络下每个查询都打一次上游.
        let gate = |s: &CacheState| {
            let fresh = s.fetched_at.is_some_and(|t| t.elapsed() < self.ttl);
            let in_backoff = s.last_failure.is_some_and(|t| t.elapsed() < self.backoff);
            !fresh && !in_backoff
        };
        let needs_refresh = gate(&self.state.read());
        if needs_refresh {
            let _guard = self.refresh_lock.lock().await;
            // double-check: 等锁期间可能已被首个查询者刷新 (或刷新失败进入退避).
            if gate(&self.state.read()) {
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
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    Ok(json) => {
                        let (data, priced, skipped) = PricingData::parse(&json);
                        if priced == 0 {
                            // schema 漂移防护 (n7): 解析成功但零价 = 上游结构变了.
                            warn!(url = %self.url, skipped, "models.dev parse yielded 0 priced models; schema drift? keeping old data");
                            self.record_failure();
                            return;
                        }
                        if skipped > 0 {
                            debug!(
                                skipped,
                                priced, "models.dev: some models have no cost (normal)"
                            );
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
                }
            }
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
    // SEC-8: 旧版本写的缓存文件可能过宽 — 读时 best-effort 收紧 (与 state 目录
    // 内其他工件一致; /dev/null 等非普通文件由 helper 内部跳过).
    crate::util::tighten_file_permissions(path);
    let raw = std::fs::read(path).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let (data, priced, _) = PricingData::parse(&json);
    (priced > 0).then_some(data)
}

fn write_disk(path: &Path, json: &serde_json::Value) {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // SEC-8: 创建即 0600 (util::create_owner_only, 消除 umask 0644 中间窗口);
    // 非 unix 平台退化为 File::create 同语义.
    let bytes = serde_json::to_vec(json).unwrap_or_default();
    let res = crate::util::create_owner_only(path).and_then(|mut f| f.write_all(&bytes));
    if let Err(e) = res {
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
            // ─── 同 host 多 vendor 碰撞样本 (镜像 2026-09 models.dev 实测, #202) ───
            // zhipuai 对 (按量 vs 套餐): host 均为 open.bigmodel.cn; 套餐侧 glm-5.3
            // 全零价, glm-4.6v (套餐不含视觉) 保留按量价 → 套餐 vendor 非全零.
            "zhipuai": {
                "id": "zhipuai", "name": "Zhipu AI",
                "api": "https://open.bigmodel.cn/api/paas/v4",
                "models": {
                    "glm-5.3": {"cost": {"input": 1.4, "output": 4.4, "cache_read": 0.26, "cache_write": 0}},
                    "glm-4.6v": {"cost": {"input": 0.3, "output": 0.9}}
                }
            },
            "zhipuai-coding-plan": {
                "id": "zhipuai-coding-plan",
                "api": "https://open.bigmodel.cn/api/coding/paas/v4",
                "models": {
                    "glm-5.3": {"cost": {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}},
                    "glm-4.6v": {"cost": {"input": 0.3, "output": 0.9}}
                }
            },
            // 127.0.0.1 本地 vendor: openai/gpt-oss-20b 同时被 groq (异 host) 收录,
            // 用于验证 "host 信号收缩交集" 优于偏好序全长比较.
            "lmstudio": {
                "id": "lmstudio",
                "api": "http://127.0.0.1:1234/v1",
                "models": {
                    "openai/gpt-oss-20b": {"cost": {"input": 0.1, "output": 0.1}}
                }
            },
            "groq": {
                "id": "groq",
                "api": "https://api.groq.com",
                "models": {
                    "openai/gpt-oss-20b": {"cost": {"input": 0.6, "output": 0.6}}
                }
            },
            // llmgateway 对 (均无 plan 段, 前缀对): 锁定真实碰撞数据的确定性.
            "llmgateway": {
                "id": "llmgateway",
                "api": "https://api.llmgateway.io",
                "models": {
                    "shared-model": {"cost": {"input": 3.0, "output": 9.0}}
                }
            },
            "llmgateway-providers": {
                "id": "llmgateway-providers",
                "api": "https://api.llmgateway.io",
                "models": {
                    "shared-model": {"cost": {"input": 9.0, "output": 27.0}}
                }
            },
            // 合成对 (非真实数据): 刻意让长度序与字典序**分歧** — 字母序选
            // aa-hub-aggregator, 长度序选 zz-relay — 给偏好序的"名短"层判别力
            // (前缀型真实碰撞对两序同向, 判别不出该层).
            "zz-relay": {
                "id": "zz-relay",
                "api": "https://relay.example.net",
                "models": {
                    "discrim-model": {"cost": {"input": 0.7, "output": 0.7}}
                }
            },
            "aa-hub-aggregator": {
                "id": "aa-hub-aggregator",
                "api": "https://hub.example.org",
                "models": {
                    "discrim-model": {"cost": {"input": 7.0, "output": 7.0}}
                }
            },
            "no-cost-vendor": {"id": "nc", "models": {"m-nc": {"limit": {}}}}
        })
    }

    // ─── schema 快照 + 解析 (n7: 防 upstream schema 漂移静默丢价) ────────

    #[test]
    fn parse_extracts_prices_and_vendor_domains() {
        let (data, priced, skipped) = PricingData::parse(&fixture());
        assert_eq!(
            priced, 14,
            "gpt-5.6-terra ×2 + gpt-free + claude-opus-5 + 碰撞样本 10"
        );
        assert_eq!(skipped, 1, "m-nc has no cost");
        assert_eq!(
            data.vendor_domain.get("api.openai.com"),
            Some(&vec!["openai".to_string()])
        );
        assert_eq!(
            data.vendor_domain.get("api.anthropic.com"),
            Some(&vec!["anthropic".to_string()])
        );
        // 同 host 碰撞: 候选全保留且有序 (#202), 不再 last-wins.
        assert_eq!(
            data.vendor_domain.get("open.bigmodel.cn"),
            Some(&vec![
                "zhipuai".to_string(),
                "zhipuai-coding-plan".to_string()
            ])
        );
        assert_eq!(
            data.vendor_domain.get("api.llmgateway.io"),
            Some(&vec![
                "llmgateway".to_string(),
                "llmgateway-providers".to_string()
            ])
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
            ModelPrice {
                input: 0.5,
                output: 2.0,
                cache_read: 0.05,
                cache_write: 0.75,
            },
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
    fn match_ambiguous_hint_miss_falls_back_to_preference_order() {
        let t = table();
        // host 信号缺席 (hint 的 vendor 集与候选无交集) → 偏好序全长比较:
        // openai 与 relay-x 均无 plan 段, openai 名短 → openai 胜.
        let p = t
            .price_for("gpt-5.6-terra", Some("api.anthropic.com"))
            .unwrap();
        assert!((p.input - 1.25).abs() < 1e-9, "preference-order fallback");
        // hint host 未注册: 同样落偏好序 (确定性).
        let p2 = t.price_for("gpt-5.6-terra", Some("unknown.host")).unwrap();
        assert!((p2.input - 1.25).abs() < 1e-9);
    }

    #[test]
    fn match_strips_date_suffix() {
        let t = table();
        let p = t.price_for("claude-opus-5-2026-07-24", None).unwrap();
        assert!(
            (p.input - 5.0).abs() < 1e-9,
            "date-suffixed variant must match base"
        );
        // 非日期后缀不剥.
        assert!(t.price_for("claude-opus-5-latest", None).is_none());
    }

    // ─── 同 host 多 vendor 碰撞消歧 (#202) ─────────────────────────────

    /// 回归锚 (issue #202): 套餐入口部署 (base_url host 与按量 vendor 共享) 查
    /// 共享 model, 不得命中套餐 vendor 的零价 —— plan 偏好序取代 last-wins /
    /// 字母序巧合, 消歧结果与上游数据键序无关.
    #[test]
    fn match_host_collision_prefers_non_plan_vendor() {
        let t = table();
        let p = t.price_for("glm-5.3", Some("open.bigmodel.cn")).unwrap();
        assert!(
            (p.input - 1.4).abs() < 1e-9,
            "zhipuai (metered) must win over coding-plan zeros, got input={}",
            p.input
        );
        // 无 hint 路径同样 plan-last (字母序巧合被显式规则取代).
        let p2 = t.price_for("glm-5.3", None).unwrap();
        assert!((p2.input - 1.4).abs() < 1e-9);
        // 套餐 vendor 非全零的实证: glm-4.6v (套餐不含视觉, 两侧同价) 消歧结果
        // 不可观测, 断言其非零 — 把 fixture 的文档主张变成可执行断言.
        let p3 = t.price_for("glm-4.6v", Some("open.bigmodel.cn")).unwrap();
        assert!(!p3.is_all_zero());
    }

    /// host 信号收缩: 候选含别家 host 的 vendor 时, 收缩到本 host 交集 ——
    /// 即使偏好序全长比较本会选别的 (groq 名比 lmstudio 短).
    #[test]
    fn match_host_pool_shrinks_to_own_host_vendors() {
        let t = table();
        // 候选 = [groq, lmstudio] (openai/gpt-oss-20b); hint 127.0.0.1 的 vendor 集
        // 含 lmstudio → 交集 = [lmstudio] → 采信 lmstudio 的价.
        let p = t
            .price_for("openai/gpt-oss-20b", Some("127.0.0.1"))
            .unwrap();
        assert!(
            (p.input - 0.1).abs() < 1e-9,
            "own-host lmstudio must win over shorter-named groq, got input={}",
            p.input
        );
        // 无 hint: 偏好序全长比较 → groq (4 字符) < lmstudio (8 字符) → groq.
        let p2 = t.price_for("openai/gpt-oss-20b", None).unwrap();
        assert!((p2.input - 0.6).abs() < 1e-9);
    }

    /// 偏好序第 2 级: 均无 plan 段时短名优先 (llmgateway vs llmgateway-providers;
    /// 纯字母序会错选 providers 聚合视图).
    #[test]
    fn match_length_tiebreak_prefers_shorter_name() {
        let t = table();
        // 合成对 (zz-relay 8 字符 vs aa-hub-aggregator 17 字符) 刻意让长度序与
        // 字典序分歧 — 字母序会选 aa-hub-aggregator, 此处断言长度序胜出;
        // 真实前缀对 (llmgateway 对) 两序同向, 仅锁确定性.
        let p = t.price_for("discrim-model", None).unwrap();
        assert!(
            (p.input - 0.7).abs() < 1e-9,
            "zz-relay (shorter) must win over alphabetically-first aa-hub-aggregator"
        );
        let p2 = t.price_for("shared-model", None).unwrap();
        assert!(
            (p2.input - 3.0).abs() < 1e-9,
            "prefix pair: deterministic pick"
        );
    }

    /// plan 段匹配防误伤: `planetscale` 不含 `-plan` 段, 不被当作套餐 vendor.
    #[test]
    fn plan_vendor_detection_uses_segment_match() {
        assert!(is_plan_vendor("zhipuai-coding-plan"));
        assert!(is_plan_vendor("tencent-token-plan"));
        assert!(is_plan_vendor("stepfun-ai-step-plan"));
        assert!(!is_plan_vendor("planetscale"));
        assert!(!is_plan_vendor("openai"));
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
    // ─── PricingCache 状态机 (TTL / serve-stale / 退避 / 盘冷启动) ────────
    // 语义照抄 #196 ModelListCache; mockito 构造真实 HTTP 上下文 (lib test 可用 dev-dep).

    fn fixture_body() -> String {
        serde_json::to_string(&fixture()).unwrap()
    }

    /// SEC-8: pricing 缓存落盘 owner-only (0600) — 与 state 目录内其他工件一致.
    #[cfg(unix)]
    #[test]
    fn write_disk_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "sg-pricing-perm-{}.json",
            uuid::Uuid::new_v4().simple()
        ));
        write_disk(&path, &json!({}));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "pricing cache must be owner-only");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn pricing_cache_ttl_stale_backoff_and_disk_cold_start() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api.json", server.url());
        let dir = std::env::temp_dir().join(format!("sg-pricing-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let disk = dir.join("pricing.json");
        let _ = std::fs::remove_file(&disk);

        let ttl = Duration::from_millis(120);
        // 余量放宽 (重负载 CI 的 assert_async 网络往返可能吃掉窗口): ttl 120ms /
        // backoff 500ms, step3→step4 的退避窗口足够容纳一次往返.
        let backoff = Duration::from_millis(500);
        let cache =
            PricingCache::with_backoff(url.clone(), ttl, backoff, disk.clone(), HashMap::new());
        let http = reqwest::Client::new();

        // 1. 首查询: Loading → fetch 成功 → Ok + 价格可用.
        let ok_mock = server
            .mock("GET", "/api.json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(fixture_body())
            .expect(1)
            .create_async()
            .await;
        let (t, s) = cache.table(&http).await;
        assert_eq!(s, PricingStatus::Ok);
        assert!(t.price_for("claude-opus-5", None).is_some());
        ok_mock.assert_async().await;

        // 2. TTL 内: 不再 fetch, 仍 Ok.
        let (_, s2) = cache.table(&http).await;
        assert_eq!(s2, PricingStatus::Ok);

        // 3. TTL 过期 + 上游 500 → serve-stale (旧表保留, 状态 Stale).
        tokio::time::sleep(ttl + Duration::from_millis(30)).await;
        let err_mock = server
            .mock("GET", "/api.json")
            .with_status(500)
            .expect(1)
            .create_async()
            .await;
        let (t3, s3) = cache.table(&http).await;
        assert_eq!(s3, PricingStatus::Stale, "serve-stale-on-error");
        assert!(
            t3.price_for("claude-opus-5", None).is_some(),
            "stale table still usable"
        );
        err_mock.assert_async().await;

        // 4. 退避窗口内: 不重试 (无新请求), 状态仍 Stale.
        let (_, s4) = cache.table(&http).await;
        assert_eq!(s4, PricingStatus::Stale);
        // (无 mock expect=0 断言手段下的近似: 上一个 err_mock expect(1) 已 assert,
        //  若此处重试会命中默认 404 → 状态仍 Stale 但多一次请求 — 用计数器 mock 兜底)
        let probe = server
            .mock("GET", "/api.json")
            .with_status(200)
            .with_body(fixture_body())
            .expect(0) // 退避窗口内绝不应被请求
            .create_async()
            .await;
        let _ = cache.table(&http).await;
        probe.assert_async().await;

        // 5. 退避窗口过后 + 上游恢复 → 重新 Ok.
        tokio::time::sleep(backoff + Duration::from_millis(80)).await;
        let ok2 = server
            .mock("GET", "/api.json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(fixture_body())
            .expect(1)
            .create_async()
            .await;
        let (_, s5) = cache.table(&http).await;
        assert_eq!(s5, PricingStatus::Ok);
        ok2.assert_async().await;

        // 6. 盘冷启动: 上游 dead URL + 同一 disk path → 读盘兜底, 状态 Stale.
        let cache2 = PricingCache::with_backoff(
            "http://127.0.0.1:1/dead.json".to_string(),
            ttl,
            backoff,
            disk.clone(),
            HashMap::new(),
        );
        let (t6, s6) = cache2.table(&http).await;
        assert_eq!(s6, PricingStatus::Stale, "disk cold-start serves stale");
        assert!(t6.price_for("claude-opus-5", None).is_some());

        let _ = std::fs::remove_file(&disk);
    }
}
