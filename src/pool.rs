//! Pool provider 运行时: 成员状态机 + 耗尽信号检测器 (spec: Pool Provider).
//!
//! # 职责边界
//!
//! 本模块实现 Pool Provider (套餐池) 的两块核心逻辑, 只向下依赖 provider
//! 类型 ([`crate::provider::ExhaustConfig`] / [`crate::provider::PoolPicker`])
//! 与基础层 (axum::http / serde_json / chrono), 不反向依赖 proxy/web:
//!
//! 1. **[`PoolStates`]**: 进程级成员状态机 (Active / Exhausted{until}).
//!    pick 无游标列表序 (**顺序 failover**, 非轮转 — 正常全打列表第一个可用
//!    成员, 成员闹钟过期后自然回归列表头, 前缀缓存最大化命中); `mark_exhausted`
//!    幂等刷新; 配置变更 (WebUI 随时可改 members) 时按位置对齐重建
//!    (同位置同 id 保留耗尽状态, id 变了视为新成员)。
//!    运行时状态**仅存内存, 不持久化** — 真相在上游 (窗口会自动恢复), 本地
//!    是缓存, 重启重新探测 (与 RedactionMap 同哲学)。
//! 2. **[`detect_exhaustion`]**: 判定一次上游响应是否为 "成员所属凭证的
//!    窗口限额耗尽" (三通道 OR: HTTP status / body 码 / response header),
//!    并尽力解析恢复时刻。纯函数, ROB-*: 对任意字节输入零 panic。
//!
//! # 内置默认信号表 (窗口限额语义域, SSOT 引用)
//!
//! 语义域 = **订阅窗口限额耗尽** (5h 滚动窗 / 周限 / 月限 — 会自动恢复),
//! **不关注**订单付费机制 (余额/欠费/账单 — pay-as-you-go)。付费类信号一律
//! 不进默认表 (用户可自行配置)。常量定义与 serde default 在
//! [`crate::provider`] (与 `ExhaustConfig` 类型同域):
//!
//! | 通道 | 默认值 | 来源 |
//! |---|---|---|
//! | codes | `["1308", "1310"]` | 智谱 GLM Coding Plan: 429 + body `error.code` (5h 窗/周窗配额耗尽), 响应另带 `next_flush_time` |
//! | headers | `["anthropic-ratelimit-unified-5h-status=blocked", "anthropic-ratelimit-unified-weekly-status=blocked"]` | Anthropic Claude Pro/Max 订阅 (OAuth 流量): 429 + 专属 header |
//! | statuses | `[]` (关闭) | 无一家窗口限额可用纯 status 判别 (429 混杂瞬态限速; DeepSeek 402 是付费语义) |
//!
//! **故意不进默认** (用户 opt-in 自行配置, 语义边界):
//! 智谱 `1302`(并发限流, 瞬态 — 切换丢前缀缓存)/`1305`(平台过载)/`1113`(欠费)/
//! `1309`(套餐到期)/`1313`(公平限流)/`1311`(模型未开放); OpenAI
//! `insufficient_quota`/`credit_balance_exhausted`/`*_spend_limit_exceeded`
//! (付费语义); Codex `rate_limit_exceeded` 系 / Gemini `RESOURCE_EXHAUSTED`
//! (与瞬态限速浅层不可区分, opt-in 自担误切风险); `statuses=["402"]`
//! (DeepSeek/Anthropic 平台欠费, 付费语义)。
//!
//! # 设计依据: 提取宽 + 判别严 (检测器码通道, 勿 "修复")
//!
//! 四个候选位置**宽松收集**字符串码 (`error.code` / `error.type` /
//! `error.status` / 顶层 `code`), 判别严在配置表的值域。各家码值命名空间
//! 正交 (智谱纯数字串 / OpenAI+Anthropic snake_case 各占不同值 / Gemini
//! SCREAMING / DashScope Pascal+点分), 并集默认表在每家身上的投影恰好等于
//! 该家专属表, 无跨家歧义。误报仅在用户把瞬态值写进 codes 时发生 — 那是
//! 配置意图本身。只取**字符串**值, 非字符串跳过 (Gemini 的 `error.code` 是
//! 数字 429, 天然过滤)。

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, HeaderName, StatusCode};
use parking_lot::RwLock;

use crate::provider::{AllMembersExhausted, ExhaustConfig, PoolHop, PoolPicker, PoolProvider};

// ─── 成员状态机 ─────────────────────────────────────────────────────────────

/// 单个成员的运行时状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberSlot {
    /// 可用 (从未耗尽, 或闹钟已过被 pick 顺带清除)。
    Active,
    /// 窗口限额耗尽, 挂起至 `until`; `None` = **永久** (成员 missing/disabled —
    /// disabled 是用户显式动作, 不做闹钟探测)。
    Exhausted { until: Option<Instant> },
}

/// 一个 pool 的运行时状态: slots 与配置 members 按位置对齐。`member_ids`
/// 记忆对齐基准 — "同位置同 id 的耗尽状态保留, id 变了视为新成员" 需要
/// 逐位置比较 id (只存 slots 无法区分 "改配置" 与 "闹钟语义")。
#[derive(Debug)]
struct PoolRuntime {
    member_ids: Vec<String>,
    slots: Vec<MemberSlot>,
}

impl PoolRuntime {
    fn fresh(members: &[String]) -> Self {
        Self {
            member_ids: members.to_vec(),
            slots: vec![MemberSlot::Active; members.len()],
        }
    }
}

/// 配置对齐 (每次 pick/mark 的第一步): runtime 与 cfg members 完全一致
/// (含顺序) → 原样保留; 否则按位置重建 — 同位置**同 id** 的耗尽状态保留,
/// id 变了 (含长度/顺序变化导致的错位) 视为新成员 (Active)。
fn align_runtime(rt: &mut PoolRuntime, members: &[String]) {
    if rt.member_ids.as_slice() == members {
        return;
    }
    let old_ids = std::mem::take(&mut rt.member_ids);
    let old_slots = std::mem::take(&mut rt.slots);
    rt.member_ids = members.to_vec();
    rt.slots = members
        .iter()
        .enumerate()
        .map(|(i, id)| match (old_ids.get(i), old_slots.get(i)) {
            // (Some, None) 组合不可达: member_ids 与 slots 等长由 fresh/本函数
            // 共同维护 — 配对比较显式化该不变量.
            (Some(old_id), Some(slot)) if old_id == id => *slot,
            _ => MemberSlot::Active,
        })
        .collect();
}

/// 进程级 pool 运行时状态, 聚合进 `AppState.pools` (读多写少, RwLock)。
/// key = pool provider id。运行时状态仅存内存, 不持久化 (重启重新探测)。
///
/// `Arc` 包装使 AppState 的 `Clone` (axum State 注入每 handler) 共享同一份
/// 状态 — 语义即 "进程级共享", 先例同 `ApiKeyStore`。
///
/// 并发声明确认 (单用户本地工具的可接受假设, 与 #157/#179 的 TOCTOU 同型):
/// 两个并发请求各自持有**新旧不同的 members 快照**交错调用 pick/mark 时,
/// align 互相重建可让 stale 标记按位置落到已变更的 id 头上 — 状态错误是
/// 暂态且会被下一次耗尽信号自愈 (上游会再次 429), 不加锁防 (快照语义与
/// `resolve_route` 的 per-request 解析一致)。
#[derive(Debug, Default, Clone)]
pub struct PoolStates {
    inner: std::sync::Arc<RwLock<HashMap<String, PoolRuntime>>>,
}

impl PoolStates {
    pub fn new() -> Self {
        Self::default()
    }

    /// 锁 + 取 pool 运行时 (不存在则按当前 members 新建) 并对齐配置 —
    /// 一切读写入口的前奏: 后续代码可假设 rt 与 members 按位置对齐.
    fn with_pool<R>(
        &self,
        pool_id: &str,
        members: &[String],
        f: impl FnOnce(&mut PoolRuntime) -> R,
    ) -> R {
        let mut guard = self.inner.write();
        let rt = guard
            .entry(pool_id.to_string())
            .or_insert_with(|| PoolRuntime::fresh(members));
        align_runtime(rt, members);
        f(rt)
    }
}

impl MemberSlot {
    /// 闹钟时刻 (Active → None; Exhausted 原样透传 until — None 即永久)。
    fn alarm(&self) -> Option<Instant> {
        match *self {
            MemberSlot::Active => None,
            MemberSlot::Exhausted { until } => until,
        }
    }
}

impl PoolPicker for PoolStates {
    /// pick 语义 (spec §6): 无显式 cursor — 列表序即优先级, 找第一个 Active
    /// slot (闹钟已过的顺带清除为 Active → 成员回归列表头); 全部 Exhausted →
    /// Err (含最早到期的闹钟; 全 None = 全永久, 无自动恢复)。
    ///
    /// 拿写锁而非读锁: pick 可能写三处 (首次 entry 插入 / 配置对齐重建 /
    /// 过期闹钟清除), 读升级写不存在, 语义简单优先。
    fn pick_member(
        &self,
        pool_id: &str,
        members: &[String],
        now: Instant,
    ) -> Result<usize, AllMembersExhausted> {
        self.with_pool(pool_id, members, |rt| {
            for (idx, slot) in rt.slots.iter_mut().enumerate() {
                match *slot {
                    MemberSlot::Active => return Ok(idx),
                    MemberSlot::Exhausted { until: Some(t) } if t <= now => {
                        // 闹钟过期: 顺带清除为 Active (下次 pick 不会再走到这里)。
                        *slot = MemberSlot::Active;
                        return Ok(idx);
                    }
                    MemberSlot::Exhausted { .. } => {}
                }
            }
            // 全部 Exhausted: earliest = Some(until) 的最小值; 全永久 (None) → None。
            Err(AllMembersExhausted {
                pool_id: pool_id.to_string(),
                earliest_resume: rt.slots.iter().filter_map(|s| s.alarm()).min(),
            })
        })
    }

    /// mark 语义 (spec §6): 该 slot → Exhausted{until} (**幂等**: 重复标记
    /// 刷新 until — 探测失败重挂闹钟)。idx 越界 (配置并发变更窗口内对齐后
    /// 失效) 静默忽略 — 下次 pick 对齐后自然收敛, 不 panic (ROB-*)。
    fn mark_member_exhausted(
        &self,
        pool_id: &str,
        members: &[String],
        member_idx: usize,
        until: Option<Instant>,
    ) {
        self.with_pool(pool_id, members, |rt| {
            if let Some(slot) = rt.slots.get_mut(member_idx) {
                *slot = MemberSlot::Exhausted { until };
            }
        });
    }
}

// ─── 耗尽信号检测器 (纯函数) ────────────────────────────────────────────────

/// 一次耗尽检测的结果 (纯数据)。
///
/// `resume_at = None` = 三条恢复时刻来源全部解析失败, 调用方用
/// `now + cooldown_secs` 兜底 (语义: 精确闹钟优先, 固定 cooldown 兜底);
/// `Some(t)` = 已 clamp 到 `[now+cooldown, now+7d]` 的恢复时刻。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExhaustHit {
    pub resume_at: Option<Instant>,
}

/// 闹钟封顶: 防解析出天文数字 (或上游给出极远时刻) → 成员永久休眠。
const RESUME_CAP: Duration = Duration::from_secs(7 * 24 * 3600);

/// Anthropic 订阅 reset header 族的匹配前缀/后缀 (`anthropic-ratelimit-*-reset`,
/// 含 unified-5h-reset / unified-weekly-reset — 格式未完全实证, 解析尽力而为)。
const ANTHROPIC_RESET_PREFIX: &str = "anthropic-ratelimit-";
const ANTHROPIC_RESET_SUFFIX: &str = "-reset";

/// code 通道的 is_error 判定 (spec 伪代码 `status.is_error()`): 4xx ∪ 5xx —
/// 2xx body 不是错误信封, 解析纯浪费。
fn is_error(status: StatusCode) -> bool {
    status.is_client_error() || status.is_server_error()
}

/// 判定一次上游响应是否为 "成员所属凭证的窗口限额耗尽" (三通道 OR):
///
/// ```text
/// 触发 = (status.as_u16() ∈ cfg.statuses)
///     OR (header 通道: 任一 cfg.headers 条目 "name=value" 精确匹配,
///         name 大小写不敏感)
///     OR (code 通道: status.is_error() 且 body JSON parse 成功 且
///          四候选位置的字符串码 ∩ cfg.codes ≠ ∅)
/// ```
///
/// 纯函数, 无副作用 (状态更新由调用方做)。ROB-*: 对任意字节输入零 panic —
/// 非法 header 规则 / 非 JSON body / 越界时间值全部走 None/跳过。
///
/// **code 通道的 is_error 闸门**: 2xx body 不是错误信封, 解析纯浪费;
/// status/header 通道无此闸门 (2xx 响应不会带那些值 — 门槛由配置表值域
/// 天然保证, spec §5 fixture 表锁定)。
///
/// 命中后按优先序解析恢复时刻: `Retry-After` → `next_flush_time` (body)
/// → anthropic reset header 族; 全部失败 → `resume_at = None`。
pub fn detect_exhaustion(
    cfg: &ExhaustConfig,
    cooldown_secs: u64,
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
) -> Option<ExhaustHit> {
    let now = Instant::now();

    // 通道 1: HTTP status ∈ cfg.statuses (空表 = 关闭).
    let status_hit = cfg.statuses.contains(&status.as_u16());
    // 通道 2: header "name=value" 精确匹配 (空表 = 关闭).
    let header_hit = cfg.headers.iter().any(|r| header_rule_matches(headers, r));
    // 通道 3: body 码 — 仅 is_error 时尝试解析 (省 2xx 的 parse).
    let parsed_body = if is_error(status) && !cfg.codes.is_empty() {
        serde_json::from_slice::<serde_json::Value>(body).ok()
    } else {
        None
    };
    let code_hit = parsed_body.as_ref().is_some_and(|v| {
        collect_body_codes(v)
            .iter()
            .any(|c| cfg.codes.iter().any(|k| k == c))
    });
    if !(status_hit || header_hit || code_hit) {
        return None;
    }

    // 命中: 恢复时刻按优先序取第一个可解析的; clamp 到
    // [now+cooldown, now+7d] (下限防 Retry-After: 0 探测风暴, 上限防天文数字).
    let body_json = parsed_body.or_else(|| serde_json::from_slice(body).ok());
    let resume = parse_retry_after(headers, now)
        .or_else(|| parse_next_flush_time(body_json.as_ref(), now))
        .or_else(|| parse_anthropic_reset(headers, now));
    Some(ExhaustHit {
        resume_at: resume.map(|t| clamp_resume(t, now, cooldown_secs)),
    })
}

/// header 通道单条规则 `"name=value"` 的匹配 (name 大小写不敏感交给
/// `HeaderMap::get` — HeaderName 规范化; value 精确匹配, 双侧容忍周边空白 —
/// 配置 `"x-status = blocked"` 形态的手滑)。非法条目 (无 '=' / 非法 header
/// 名 / 非法 value 字节) 跳过 — 配置卫生问题不让检测路径 panic (ROB-*),
/// 静默不匹配。
fn header_rule_matches(headers: &HeaderMap, rule: &str) -> bool {
    let Some((name, value)) = rule.split_once('=') else {
        return false;
    };
    let Ok(name) = HeaderName::from_bytes(name.trim().as_bytes()) else {
        return false;
    };
    headers
        .get(&name)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() == value.trim())
}

/// code 通道四候选位置的宽松收集 (只取**字符串**值, 非字符串跳过 — Gemini
/// 的 `error.code` 是数字 429, 天然过滤; 设计依据见模块头 "提取宽 + 判别严"):
/// `error.code` (OpenAI/智谱/DashScope 包装) / `error.type` (Anthropic) /
/// `error.status` (Gemini google.rpc) / 顶层 `code` (DashScope)。
fn collect_body_codes(body: &serde_json::Value) -> Vec<&str> {
    let mut out = Vec::new();
    if let Some(error) = body.get("error") {
        for key in ["code", "type", "status"] {
            if let Some(s) = error.get(key).and_then(|v| v.as_str()) {
                out.push(s);
            }
        }
    }
    if let Some(s) = body.get("code").and_then(|v| v.as_str()) {
        out.push(s);
    }
    out
}

/// 解析出的恢复时刻 clamp 到 `[now+cooldown, now+7d]` (cap 优先于下限 —
/// 用户配 cooldown > 7d 时按封顶; `checked_add` 防极端 cooldown 溢出,
/// 溢出按封顶处理)。
fn clamp_resume(t: Instant, now: Instant, cooldown_secs: u64) -> Instant {
    let upper = now + RESUME_CAP; // 7d 恒在单调钟安全边界内
    let lower = now
        .checked_add(Duration::from_secs(cooldown_secs))
        .unwrap_or(upper);
    if t < lower {
        lower
    } else if t > upper {
        upper
    } else {
        t
    }
}

/// `Retry-After` (HTTP 标准): 非负整数秒或 HTTP-date (IMF-fixdate 是
/// RFC 2822 日期的子集)。窗口型 429 此值是小时级大数; 顺带天然覆盖其他
/// 标准实现家。
fn parse_retry_after(headers: &HeaderMap, now: Instant) -> Option<Instant> {
    let raw = headers.get("retry-after")?.to_str().ok()?.trim();
    if let Ok(secs) = raw.parse::<u64>() {
        return now.checked_add(Duration::from_secs(secs));
    }
    let dt = chrono::DateTime::parse_from_rfc2822(raw).ok()?;
    instant_from_unix(dt.timestamp(), now)
}

/// 智谱 `next_flush_time`: body JSON 的 `error.next_flush_time` 或顶层
/// `next_flush_time` (两位置候选 — 信封根级与 error 对象内, 生产两形态)。
fn parse_next_flush_time(body: Option<&serde_json::Value>, now: Instant) -> Option<Instant> {
    let body = body?;
    let raw = body
        .pointer("/error/next_flush_time")
        .or_else(|| body.get("next_flush_time"))?
        .as_str()?;
    parse_wall_clock(raw, now)
}

/// 墙钟字符串 → Instant (多格式 best-effort, ROB: 失败 None):
/// RFC3339 (带时区) / `"%Y-%m-%d %H:%M:%S"` 按本地时区 (智谱生产实证形态,
/// agent-service ledger 同口径)。
fn parse_wall_clock(raw: &str, now: Instant) -> Option<Instant> {
    let raw = raw.trim();
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(raw) {
        return instant_from_unix(dt.timestamp(), now);
    }
    let naive = chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S").ok()?;
    let local = chrono::TimeZone::from_local_datetime(&chrono::Local, &naive).single()?;
    instant_from_unix(local.timestamp(), now)
}

/// Anthropic reset header 族: `anthropic-ratelimit-*-reset` (unified-5h /
/// unified-weekly 等)。格式未完全实证 — RFC3339 / unix 秒均尝试; 多个可
/// 解析值取**最晚** (5h 与 weekly 同时 blocked 时按晚者恢复)。
fn parse_anthropic_reset(headers: &HeaderMap, now: Instant) -> Option<Instant> {
    let mut best: Option<Instant> = None;
    for (name, value) in headers {
        let name = name.as_str();
        if !name.starts_with(ANTHROPIC_RESET_PREFIX) || !name.ends_with(ANTHROPIC_RESET_SUFFIX) {
            continue;
        }
        let Ok(raw) = value.to_str() else { continue };
        let raw = raw.trim();
        let parsed = chrono::DateTime::parse_from_rfc3339(raw)
            .ok()
            .and_then(|dt| instant_from_unix(dt.timestamp(), now))
            .or_else(|| {
                raw.parse::<i64>()
                    .ok()
                    .and_then(|unix| instant_from_unix(unix, now))
            });
        if let Some(t) = parsed {
            best = Some(best.map_or(t, |b| b.max(t)));
        }
    }
    best
}

/// unix epoch 秒 → Instant (std 无直接转换 — Instant 是单调钟, 只能表达为
/// now + delta)。过去的时刻折叠为 `now` (表示 "已过期", 由调用方 clamp 到
/// now+cooldown 下限); 溢出防御走 checked (`checked_add` None = 极端大
/// delta, 本条解析失败回落下一来源)。
fn instant_from_unix(target_unix: i64, now: Instant) -> Option<Instant> {
    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    let delta = target_unix.checked_sub(now_unix)?;
    if delta <= 0 {
        return Some(now);
    }
    let d = Duration::from_secs(u64::try_from(delta).ok()?);
    now.checked_add(d)
}

// ─── 响应侧检测编排 (PoolWatch, proxy 挂接的消费面) ─────────────────────────

/// 一次请求的 pool 耗尽检测上下文: dispatch 层从 `ResolvedRoute.pool` + pool
/// 配置**入口快照**构造, 随转发路径传递到上游响应 body 已可见的位置消费
/// ([`PoolWatch::detect_and_mark`]).
///
/// 职责: 把 [`detect_exhaustion`] (纯函数) 与 [`PoolStates::mark_member_exhausted`]
/// (状态机写入) 编排成一个旁路动作 — proxy 各转发路径只需一处调用, 挂接细节
/// 不泄漏到转发代码.
///
/// **FWD-1 红线**: 检测是旁路 — `detect_and_mark` 无返回值, 不修改调用方的
/// 任何字节; 非 pool 流量由 `Option<PoolWatch>` = None 表达, 检测点零开销短路.
///
/// 配置快照取**请求入口时刻** (per-request 解析精神): 在途配置变更 (WebUI 改
/// members/exhaust) 由 `PoolStates` 的按位置对齐机制收敛 — mark 落到快照
/// members 上, 下次 pick 对齐后状态按 id 匹配保留或重置.
#[derive(Debug, Clone)]
pub struct PoolWatch {
    pool_id: String,
    member_idx: usize,
    /// 入口配置快照: `members` = mark 的对齐基准 + INFO 日志的成员 id 来源;
    /// `exhaust` / `cooldown_secs` = 检测与兜底闹钟参数. 按值持有 (整体快照,
    /// 非 & 借用 — 需 'static 进 fan_out 的 spawn task).
    cfg: PoolProvider,
    states: PoolStates,
}

impl PoolWatch {
    /// 从路由解析产出的 pool 跳 + pool 配置快照构造 (`cfg` 按值 move — dispatch
    /// 侧 `get_effective` 已 clone 整个 Provider, 此处不再二次深拷贝). 配置表
    /// 读取由调用方 (proxy dispatch) 完成 — 本模块只依赖 provider **类型**,
    /// 不触 ProviderTable 行为 (依赖方向: proxy → pool → provider).
    pub fn new(hop: &PoolHop, cfg: PoolProvider, states: &PoolStates) -> Self {
        Self {
            pool_id: hop.pool_id.clone(),
            member_idx: hop.member_idx,
            cfg,
            states: states.clone(),
        }
    }

    /// 旁路检测: 上游响应非 2xx (拒绝, body 非 SSE 已缓冲) 时跑三通道判定,
    /// 命中则 mark 该成员耗尽 (精确闹钟优先, `now + cooldown` 兜底) 并打一条
    /// INFO (SEC-2: 只含 pool id / 成员 id / 恢复时长, 绝不含 body 原文).
    ///
    /// 短路: **非 error status 直接返回** — 覆盖流式 2xx mid-stream SSE error
    /// event 不检测的假设 (智谱/Claude 撞窗在 HTTP 层拒绝, 不在 SSE 中;
    /// spec §8 声明). 调用方只需 `if let Some(w) = &watch` 一行, 无额外条件.
    ///
    /// body 可能是截断字节 (record cap / 客户端断开后的部分累积) — JSON
    /// parse 失败时 code 通道自然失效, status/header 通道不受影响
    /// (best-effort, ROB-*).
    ///
    /// 日志节流: 每次命中打一条 INFO (而非仅状态翻转时) — 全耗尽期间 pick
    /// 跳过该成员, 重复 INFO 的唯一来源是闹钟过期后探测请求再 429 (重挂闹钟,
    /// 值得记录), 无洪水风险.
    pub fn detect_and_mark(&self, status: StatusCode, headers: &HeaderMap, body: &[u8]) {
        if !is_error(status) {
            return;
        }
        let Some(hit) = detect_exhaustion(
            &self.cfg.exhaust,
            self.cfg.cooldown_secs,
            status,
            headers,
            body,
        ) else {
            return;
        };
        let now = Instant::now();
        // 兜底闹钟: checked_add 防极端 cooldown (≥ ~9.2e9s 超单调钟表示域)
        // 溢出 panic — 与 clamp_resume 同型防御, 溢出按 7d 封顶 (ROB-*).
        let until = hit.resume_at.unwrap_or_else(|| {
            now.checked_add(Duration::from_secs(self.cfg.cooldown_secs))
                .unwrap_or(now + RESUME_CAP)
        });
        self.states.mark_member_exhausted(
            &self.pool_id,
            &self.cfg.members,
            self.member_idx,
            Some(until),
        );
        let member = self
            .cfg
            .members
            .get(self.member_idx)
            .map(String::as_str)
            .unwrap_or("?");
        // saturating (非裸 duration_since): until 可能基于 detect_exhaustion 内部
        // 更早的 now (cooldown_secs=0 + Retry-After: 0 时早于本行 now), 裸形态
        // 对 "later time" panic — saturating 折叠为 0 (ROB-*).
        tracing::info!(
            pool = %self.pool_id,
            member,
            resume_in_secs = until.saturating_duration_since(now).as_secs(),
            "pool member exhausted; subsequent requests will fail over"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use axum::http::HeaderValue;
    use proptest::prelude::*;

    use crate::provider::PoolPicker;

    fn members(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    /// 内部状态观察 (同模块测试特权): 指定 pool 的 slots 快照.
    fn slots_of(pools: &PoolStates, pool_id: &str) -> Vec<MemberSlot> {
        pools.inner.read().get(pool_id).unwrap().slots.clone()
    }

    // ─── detect_exhaustion: 六家真实 fixture (spec §5 表) ──────────────────

    fn hdrs(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    fn status(code: u16) -> StatusCode {
        StatusCode::from_u16(code).unwrap()
    }

    /// Instant 近似断言 (检测器内部取 now 与测试侧有微秒级抖动).
    fn assert_instant_close(actual: Instant, expected: Instant, ctx: &str) {
        let diff = if actual > expected {
            actual - expected
        } else {
            expected - actual
        };
        assert!(
            diff <= Duration::from_secs(3),
            "{ctx}: actual {actual:?} vs expected {expected:?} (diff {diff:?})"
        );
    }

    /// 未来时刻的 RFC3339 / 本地 naive 两形态字符串 (基于真实墙钟动态构造,
    /// 测试在任何时区/任何日期运行都成立).
    fn future_rfc3339(from_now: u64) -> String {
        let dt: chrono::DateTime<chrono::Local> = SystemTime::now().into();
        (dt + chrono::Duration::seconds(from_now as i64)).to_rfc3339()
    }

    fn future_naive_local(from_now: u64) -> String {
        let dt: chrono::DateTime<chrono::Local> = SystemTime::now().into();
        (dt + chrono::Duration::seconds(from_now as i64))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    }

    #[test]
    fn detect_zhipu_window_exhaust_hits_with_next_flush_time() {
        // 智谱 429 + error.code="1308" + 顶层 next_flush_time (RFC3339 形态):
        // 命中 (码通道), resume_at 来自 next_flush_time.
        let body = format!(
            r#"{{"error":{{"code":"1308","message":"quota exceeded"}},"next_flush_time":"{}"}}"#,
            future_rfc3339(3600)
        );
        let hit = detect_exhaustion(
            &ExhaustConfig::default(),
            60,
            status(429),
            &HeaderMap::new(),
            body.as_bytes(),
        )
        .expect("zhipu 1308 must hit");
        let expect = Instant::now() + Duration::from_secs(3600);
        assert_instant_close(
            hit.resume_at.expect("resume from next_flush_time"),
            expect,
            "zhipu next_flush_time",
        );
    }

    #[test]
    fn detect_zhipu_transient_code_not_in_default_table() {
        // 1302 (账户级并发限流) 是瞬态信号, 故意不进默认表 — 不命中.
        let body = br#"{"error":{"code":"1302"}}"#;
        assert!(
            detect_exhaustion(
                &ExhaustConfig::default(),
                60,
                status(429),
                &HeaderMap::new(),
                body,
            )
            .is_none()
        );
    }

    #[test]
    fn detect_claude_subscription_header_channel_hits() {
        // Claude 订阅: header 通道命中; body 的 error.type=rate_limit_error
        // 本身不在默认 codes (不依赖它). 无恢复时刻来源 → resume_at None.
        let body = br#"{"type":"error","error":{"type":"rate_limit_error"}}"#;
        let hit = detect_exhaustion(
            &ExhaustConfig::default(),
            60,
            status(429),
            &hdrs(&[("anthropic-ratelimit-unified-5h-status", "blocked")]),
            body,
        )
        .expect("claude subscription header must hit");
        assert_eq!(
            hit.resume_at, None,
            "no recovery source → None (cooldown fallback)"
        );
    }

    #[test]
    fn detect_openai_paid_signal_default_off_configurable_on() {
        // insufficient_quota 是付费语义, 默认不命中; 用户 opt-in 配置后命中.
        let body = br#"{"error":{"code":"insufficient_quota","type":"insufficient_quota"}}"#;
        assert!(
            detect_exhaustion(
                &ExhaustConfig::default(),
                60,
                status(429),
                &HeaderMap::new(),
                body,
            )
            .is_none()
        );
        let cfg = ExhaustConfig {
            codes: vec!["insufficient_quota".into()],
            ..ExhaustConfig::default()
        };
        assert!(detect_exhaustion(&cfg, 60, status(429), &HeaderMap::new(), body).is_some());
    }

    #[test]
    fn detect_gemini_numeric_code_skipped_string_status_optional() {
        // Gemini: error.code 是数字 429 → 跳过 (只取字符串); error.status =
        // "RESOURCE_EXHAUSTED" 不在默认表 → 默认不命中; opt-in 后经
        // error.status 位置命中 (spec §4 opt-in 清单语义).
        let body = br#"{"error":{"code":429,"message":"...","status":"RESOURCE_EXHAUSTED"}}"#;
        assert!(
            detect_exhaustion(
                &ExhaustConfig::default(),
                60,
                status(429),
                &HeaderMap::new(),
                body,
            )
            .is_none()
        );
        let cfg = ExhaustConfig {
            codes: vec!["RESOURCE_EXHAUSTED".into()],
            ..ExhaustConfig::default()
        };
        assert!(detect_exhaustion(&cfg, 60, status(429), &HeaderMap::new(), body).is_some());
    }

    #[test]
    fn detect_deepseek_status_channel() {
        // 402 付费语义默认不命中; 用户配 statuses=[402] 后命中 (status 通道).
        let body = br#"{"error":{"message":"Insufficient Balance","type":"unknown_error","code":"invalid_request_error"}}"#;
        assert!(
            detect_exhaustion(
                &ExhaustConfig::default(),
                60,
                status(402),
                &HeaderMap::new(),
                body,
            )
            .is_none()
        );
        let cfg = ExhaustConfig {
            statuses: vec![402],
            ..ExhaustConfig::default()
        };
        assert!(detect_exhaustion(&cfg, 60, status(402), &HeaderMap::new(), body).is_some());
    }

    #[test]
    fn detect_dashscope_top_level_code_position() {
        // DashScope 顶层 code 位置: "Arrearage" 默认不命中; opt-in 后命中.
        let body = br#"{"code":"Arrearage","message":"Access denied as no enough balance"}"#;
        assert!(
            detect_exhaustion(
                &ExhaustConfig::default(),
                60,
                status(400),
                &HeaderMap::new(),
                body,
            )
            .is_none()
        );
        let cfg = ExhaustConfig {
            codes: vec!["Arrearage".into()],
            ..ExhaustConfig::default()
        };
        assert!(detect_exhaustion(&cfg, 60, status(400), &HeaderMap::new(), body).is_some());
    }

    #[test]
    fn detect_2xx_never_hits_even_with_matching_code() {
        // code 通道的 is_error 闸门: 200 + body 含 "1308" 也不命中.
        let body = br#"{"error":{"code":"1308"}}"#;
        assert!(
            detect_exhaustion(
                &ExhaustConfig::default(),
                60,
                status(200),
                &HeaderMap::new(),
                body,
            )
            .is_none()
        );
    }

    #[test]
    fn detect_arbitrary_bytes_never_panics() {
        // ROB-*: 非 JSON / 空body / 畸形 UTF-8 字节零 panic, 不命中即 None.
        for body in [
            &b""[..],
            b"\xff\xfe not utf8 \x00\x01",
            b"null",
            b"[]",
            b"{\"error\": 42}",                   // error 非对象
            b"{\"error\":{\"code\":[\"1308\"]}}", // code 非字符串 (数组)
        ] {
            let _ = detect_exhaustion(
                &ExhaustConfig::default(),
                60,
                status(429),
                &HeaderMap::new(),
                body,
            );
            let _ = detect_exhaustion(
                &ExhaustConfig::default(),
                60,
                status(500),
                &hdrs(&[("retry-after", "not-a-date-or-number")]),
                body,
            );
        }
    }

    #[test]
    fn detect_malformed_header_rules_skipped() {
        // 配置卫生脏条目 (无 '=' / 非法 header 名) 跳过不匹配, 不 panic.
        let cfg = ExhaustConfig {
            headers: vec![
                "no-equals-sign".into(),
                "=empty-name".into(),
                "bad name[]=v".into(),
            ],
            ..ExhaustConfig::default()
        };
        assert!(
            detect_exhaustion(
                &cfg,
                60,
                status(429),
                &hdrs(&[("anthropic-ratelimit-unified-5h-status", "blocked")]),
                b"{}",
            )
            .is_none()
        );
    }

    // ─── 恢复时刻解析: 优先序 / 多格式 / 封顶 / 下限 ──────────────────────

    #[test]
    fn resume_retry_after_seconds_wins_over_body_sources() {
        // 优先序: Retry-After (3600s) 胜过 body 里更晚的 next_flush_time.
        let body = format!(
            r#"{{"error":{{"code":"1308"}},"next_flush_time":"{}"}}"#,
            future_rfc3339(86400)
        );
        let hit = detect_exhaustion(
            &ExhaustConfig::default(),
            60,
            status(429),
            &hdrs(&[("retry-after", "3600")]),
            body.as_bytes(),
        )
        .unwrap();
        assert_instant_close(
            hit.resume_at.unwrap(),
            Instant::now() + Duration::from_secs(3600),
            "retry-after seconds priority",
        );
    }

    #[test]
    fn resume_retry_after_http_date() {
        // HTTP-date (IMF-fixdate) 形态: RFC 2822 解析. 时区偏移用 %z
        // ("+0800" 无冒号 — RFC 2822 解析器不认 "+08:00" 形态).
        let dt: chrono::DateTime<chrono::Local> = SystemTime::now().into();
        let http_date = (dt + chrono::Duration::seconds(7200))
            .format("%a, %d %b %Y %H:%M:%S %z")
            .to_string();
        let hit = detect_exhaustion(
            &ExhaustConfig::default(),
            60,
            status(429),
            &hdrs(&[("retry-after", http_date.as_str())]),
            br#"{"error":{"code":"1308"}}"#,
        )
        .unwrap();
        assert_instant_close(
            hit.resume_at.unwrap(),
            Instant::now() + Duration::from_secs(7200),
            "retry-after http-date",
        );
    }

    #[test]
    fn resume_next_flush_time_naive_local_and_error_position() {
        // 智谱生产实证形态: "%Y-%m-%d %H:%M:%S" (本地时区, 无时区后缀),
        // 顶层位置 (与 error.code 并存 — 命中由码通道保证).
        let body = format!(
            r#"{{"error":{{"code":"1308"}},"next_flush_time":"{}"}}"#,
            future_naive_local(1800)
        );
        let hit = detect_exhaustion(
            &ExhaustConfig::default(),
            60,
            status(429),
            &HeaderMap::new(),
            body.as_bytes(),
        )
        .unwrap();
        assert_instant_close(
            hit.resume_at.unwrap(),
            Instant::now() + Duration::from_secs(1800),
            "next_flush_time naive local",
        );

        let body2 = format!(
            r#"{{"error":{{"code":"1310","next_flush_time":"{}"}}}}"#,
            future_rfc3339(2400)
        );
        let hit2 = detect_exhaustion(
            &ExhaustConfig::default(),
            60,
            status(429),
            &HeaderMap::new(),
            body2.as_bytes(),
        )
        .unwrap();
        assert_instant_close(
            hit2.resume_at.unwrap(),
            Instant::now() + Duration::from_secs(2400),
            "next_flush_time inside error object",
        );
    }

    #[test]
    fn resume_capped_at_seven_days() {
        // 天文数字 Retry-After → 封顶 7 天 (防成员永久休眠).
        let hit = detect_exhaustion(
            &ExhaustConfig::default(),
            60,
            status(429),
            &hdrs(&[("retry-after", "999999999")]),
            br#"{"error":{"code":"1308"}}"#,
        )
        .unwrap();
        let expect = Instant::now() + RESUME_CAP;
        assert_instant_close(hit.resume_at.unwrap(), expect, "7d cap");
    }

    #[test]
    fn resume_floored_at_cooldown() {
        // Retry-After: 0 → 下限 cooldown (防探测风暴); 过去时刻的
        // next_flush_time 同样折叠到下限.
        let hit = detect_exhaustion(
            &ExhaustConfig::default(),
            300,
            status(429),
            &hdrs(&[("retry-after", "0")]),
            br#"{"error":{"code":"1308"}}"#,
        )
        .unwrap();
        assert_instant_close(
            hit.resume_at.unwrap(),
            Instant::now() + Duration::from_secs(300),
            "cooldown floor",
        );
    }

    #[test]
    fn resume_anthropic_reset_headers_rfc3339_unix_and_latest_wins() {
        // anthropic reset header 族: RFC3339 / unix 秒两形态; 多值取最晚
        // (weekly 比 5h 晚 → 按 weekly 恢复).
        let earlier = future_rfc3339(3600);
        let later_unix = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 7200) as i64;
        let cfg = ExhaustConfig::default();
        let hit = detect_exhaustion(
            &cfg,
            60,
            status(429),
            &hdrs(&[
                ("anthropic-ratelimit-unified-5h-status", "blocked"),
                ("anthropic-ratelimit-unified-5h-reset", earlier.as_str()),
                (
                    "anthropic-ratelimit-unified-weekly-reset",
                    &later_unix.to_string(),
                ),
            ]),
            br#"{"type":"error","error":{"type":"rate_limit_error"}}"#,
        )
        .unwrap();
        assert_instant_close(
            hit.resume_at.unwrap(),
            Instant::now() + Duration::from_secs(7200),
            "latest anthropic reset wins (unix secs form)",
        );

        // 单 RFC3339 形态.
        let hit2 = detect_exhaustion(
            &cfg,
            60,
            status(429),
            &hdrs(&[
                ("anthropic-ratelimit-unified-5h-status", "blocked"),
                ("anthropic-ratelimit-unified-5h-reset", earlier.as_str()),
            ]),
            b"{}",
        )
        .unwrap();
        assert_instant_close(
            hit2.resume_at.unwrap(),
            Instant::now() + Duration::from_secs(3600),
            "anthropic reset rfc3339 form",
        );
    }

    // ─── pick: 无游标列表序 + 闹钟语义 ───────────────────────────────────

    #[test]
    fn pick_returns_first_active_in_list_order() {
        // 列表序即优先级: 正常全打第一个成员 (顺序 failover).
        let pools = PoolStates::new();
        let m = members(&["a", "b", "c"]);
        let now = Instant::now();
        assert_eq!(pools.pick_member("pl", &m, now).unwrap(), 0);
        // 重复 pick 稳定 (无游标 — 状态不变则结果不变).
        assert_eq!(pools.pick_member("pl", &m, now).unwrap(), 0);
    }

    #[test]
    fn pick_skips_exhausted_until_alarm_expires_then_returns_to_head() {
        // 成员 0 耗尽 → pick 落到成员 1; 闹钟过期后成员 0 回归**列表头**
        // (前缀缓存最大化 — 无游标设计的核心收益).
        let pools = PoolStates::new();
        let m = members(&["a", "b"]);
        let t0 = Instant::now();
        pools.mark_member_exhausted("pl", &m, 0, Some(t0 + Duration::from_secs(100)));
        assert_eq!(
            pools
                .pick_member("pl", &m, t0 + Duration::from_secs(1))
                .unwrap(),
            1
        );
        // 闹钟未过: 仍在成员 1.
        assert_eq!(
            pools
                .pick_member("pl", &m, t0 + Duration::from_secs(99))
                .unwrap(),
            1
        );
        // 闹钟已过: 成员 0 回归 (顺带清除为 Active).
        assert_eq!(
            pools
                .pick_member("pl", &m, t0 + Duration::from_secs(101))
                .unwrap(),
            0
        );
        assert_eq!(
            slots_of(&pools, "pl")[0],
            MemberSlot::Active,
            "expired alarm cleared"
        );
        // 清除后再 pick (闹钟早已过去): 仍选成员 0.
        assert_eq!(
            pools
                .pick_member("pl", &m, t0 + Duration::from_secs(200))
                .unwrap(),
            0
        );
    }

    #[test]
    fn pick_permanent_marks_never_expire() {
        // until=None 永久 (missing/disabled 成员): 任意时刻不再回归.
        let pools = PoolStates::new();
        let m = members(&["a", "b"]);
        let t0 = Instant::now();
        pools.mark_member_exhausted("pl", &m, 0, None);
        pools.mark_member_exhausted("pl", &m, 1, Some(t0 + Duration::from_secs(10)));
        assert_eq!(
            pools
                .pick_member("pl", &m, t0 + Duration::from_secs(1000))
                .unwrap(),
            1,
            "only the alarmed member recovers; the permanent one never does"
        );
    }

    #[test]
    fn pick_all_exhausted_reports_earliest_alarm() {
        // 全部 Exhausted → Err(earliest = Some(until) 的最小值).
        let pools = PoolStates::new();
        let m = members(&["a", "b", "c"]);
        let t0 = Instant::now();
        pools.mark_member_exhausted("pl", &m, 0, Some(t0 + Duration::from_secs(300)));
        pools.mark_member_exhausted("pl", &m, 1, None);
        pools.mark_member_exhausted("pl", &m, 2, Some(t0 + Duration::from_secs(100)));
        let err = pools.pick_member("pl", &m, t0).unwrap_err();
        assert_eq!(err.pool_id, "pl");
        assert_eq!(err.earliest_resume, Some(t0 + Duration::from_secs(100)));

        // 全永久 → earliest = None (无自动恢复).
        pools.mark_member_exhausted("pl", &m, 0, None);
        pools.mark_member_exhausted("pl", &m, 2, None);
        let err = pools.pick_member("pl", &m, t0).unwrap_err();
        assert_eq!(err.earliest_resume, None);
    }

    // ─── mark_exhausted: 幂等刷新 + 越界防御 ─────────────────────────────

    #[test]
    fn mark_is_idempotent_and_refreshes_until() {
        // 重复标记刷新 until (探测失败 → 重挂闹钟), 不叠加不报错.
        let pools = PoolStates::new();
        let m = members(&["a"]);
        let t0 = Instant::now();
        pools.mark_member_exhausted("pl", &m, 0, Some(t0 + Duration::from_secs(10)));
        pools.mark_member_exhausted("pl", &m, 0, Some(t0 + Duration::from_secs(999)));
        assert_eq!(
            slots_of(&pools, "pl")[0],
            MemberSlot::Exhausted {
                until: Some(t0 + Duration::from_secs(999))
            },
            "repeated mark refreshes (not min/max — last write wins)"
        );
        // 永久 ↔ 闹钟互转同样直接覆盖.
        pools.mark_member_exhausted("pl", &m, 0, None);
        assert_eq!(
            slots_of(&pools, "pl")[0],
            MemberSlot::Exhausted { until: None }
        );
    }

    #[test]
    fn mark_out_of_range_index_is_ignored() {
        // idx 越界 (配置并发变更窗口) 静默忽略 — ROB-*: 不 panic, 不误标.
        let pools = PoolStates::new();
        let m = members(&["a"]);
        pools.mark_member_exhausted("pl", &m, 7, Some(Instant::now()));
        assert_eq!(slots_of(&pools, "pl"), vec![MemberSlot::Active]);
    }

    // ─── 配置对齐重建 ─────────────────────────────────────────────────────

    #[test]
    fn align_rebuilds_on_member_changes_preserving_same_position_same_id() {
        // 对齐三态 (spec §6): 长度变化 / 顺序变化 / 同位置同 id 保留.
        let pools = PoolStates::new();
        let t0 = Instant::now();
        // 初始 [a, b, c]: a 永久, b 闹钟.
        let m0 = members(&["a", "b", "c"]);
        pools.mark_member_exhausted("pl", &m0, 0, None);
        pools.mark_member_exhausted("pl", &m0, 1, Some(t0 + Duration::from_secs(50)));

        // ① 长度变化 [a, b, c] → [a, c]: 位置 0 同 id a → 永久保留; 位置 1
        //    旧 b vs 新 c → 新成员 Active.
        let m1 = members(&["a", "c"]);
        assert_eq!(
            pools.pick_member("pl", &m1, t0).unwrap(),
            1,
            "c is active, a stays permanent"
        );
        assert_eq!(
            slots_of(&pools, "pl")[0],
            MemberSlot::Exhausted { until: None }
        );

        // ② 顺序变化 [a, c] → [c, a]: 逐位置比较 → 两位置 id 都变了 → 全新
        //    Active (耗尽状态不跨顺序迁移 — id 变了视为新成员).
        let m2 = members(&["c", "a"]);
        assert_eq!(pools.pick_member("pl", &m2, t0).unwrap(), 0);
        assert_eq!(
            slots_of(&pools, "pl"),
            vec![MemberSlot::Active, MemberSlot::Active]
        );

        // ③ 同列表重复 pick: 状态保留 (完全一致不重建).
        pools.mark_member_exhausted("pl", &m2, 1, None);
        assert_eq!(pools.pick_member("pl", &m2, t0).unwrap(), 0);
        assert_eq!(
            slots_of(&pools, "pl")[1],
            MemberSlot::Exhausted { until: None }
        );
    }

    // ─── PoolWatch: 响应侧检测编排 (短路 / mark / 兜底闹钟) ────────────────

    fn watch(pools: &PoolStates, members: &[String], cooldown_secs: u64) -> PoolWatch {
        PoolWatch::new(
            &PoolHop {
                pool_id: "pl".into(),
                member_idx: 0,
            },
            PoolProvider {
                members: members.to_vec(),
                exhaust: ExhaustConfig::default(),
                cooldown_secs,
            },
            pools,
        )
    }

    #[test]
    fn watch_marks_member_on_exhaust_signal_with_cooldown_fallback() {
        // 命中 (纯 code 通道, 无恢复来源) → mark; resume 走 now+cooldown 兜底.
        let pools = PoolStates::new();
        let m = members(&["a", "b"]);
        let w = watch(&pools, &m, 30);
        w.detect_and_mark(
            status(429),
            &HeaderMap::new(),
            br#"{"error":{"code":"1308"}}"#,
        );
        match slots_of(&pools, "pl")[0] {
            MemberSlot::Exhausted { until: Some(t) } => {
                let expect = Instant::now() + Duration::from_secs(30);
                assert_instant_close(t, expect, "cooldown fallback alarm");
            }
            other => panic!("expected alarmed Exhausted, got {other:?}"),
        }
    }

    #[test]
    fn watch_marks_member_with_parsed_resume_at() {
        // 命中且 Retry-After 可解析 → 闹钟来自精确信号 (优先于 cooldown).
        let pools = PoolStates::new();
        let m = members(&["a", "b"]);
        let w = watch(&pools, &m, 1);
        w.detect_and_mark(
            status(429),
            &hdrs(&[("retry-after", "120")]),
            br#"{"error":{"code":"1308"}}"#,
        );
        match slots_of(&pools, "pl")[0] {
            MemberSlot::Exhausted { until: Some(t) } => {
                let expect = Instant::now() + Duration::from_secs(120);
                assert_instant_close(t, expect, "retry-after precise alarm");
            }
            other => panic!("expected alarmed Exhausted, got {other:?}"),
        }
    }

    #[test]
    fn watch_fallback_alarm_with_absurd_cooldown_caps_at_7d_no_panic() {
        // M1 回归锁: cooldown_secs = u64::MAX + 无恢复来源 → 兜底闹钟
        // checked_add 溢出按 7d 封顶, 不 panic (裸 `now + duration` 会溢出).
        let pools = PoolStates::new();
        let m = members(&["a", "b"]);
        let w = watch(&pools, &m, u64::MAX);
        w.detect_and_mark(
            status(429),
            &HeaderMap::new(),
            br#"{"error":{"code":"1308"}}"#,
        );
        match slots_of(&pools, "pl")[0] {
            MemberSlot::Exhausted { until: Some(t) } => {
                let expect = Instant::now() + RESUME_CAP;
                assert_instant_close(t, expect, "overflow fallback capped at 7d");
            }
            other => panic!("expected alarmed Exhausted, got {other:?}"),
        }
    }

    #[test]
    fn watch_short_circuits_on_success_and_non_signal_errors() {
        // 2xx (含 mid-stream SSE 语义 — status 短路) 与非信号 429 都不动状态
        // (以 pick 仍选中成员 0 观察 — 全程未 mark 时 pool 条目不存在, slots
        // 快照不可用).
        let pools = PoolStates::new();
        let m = members(&["a", "b"]);
        let w = watch(&pools, &m, 30);
        for (status, body) in [
            (status(200), &b"{\"error\":{\"code\":\"1308\"}}"[..]),
            (status(204), b""),
            (status(301), b"redirect"),
            (status(429), b"{\"error\":{\"code\":\"1302\"}}"), // 瞬态码不在默认表
            (status(502), b"bad gateway html"),
        ] {
            w.detect_and_mark(status, &HeaderMap::new(), body);
        }
        assert_eq!(
            pools.pick_member("pl", &m, Instant::now()).unwrap(),
            0,
            "no signal → member 0 stays active (2xx short-circuit + non-signal errors)"
        );
    }

    // ─── proptest: 状态机全态空间鲁棒性 ───────────────────────────────────

    // 任意耗尽/恢复/配置变更序列下: pick 永不 panic 且返回值 sound
    // (Ok ⇒ idx < members.len(); Err ⇒ AllMembersExhausted 且 pool_id 回显).
    // 结构: 每步先 pick (在任意中间状态下断言 soundness), 再做一次状态变更
    // (mark 带闹钟/永久两态, 或配置重组覆盖长度/顺序变化) — 保证 pick 分支
    // 恒被覆盖 (生成器覆盖度, 历史教训: 生成器太窄致漏测).
    proptest! {
        #[test]
        fn prop_pool_states_arbitrary_sequences_never_panic(
            n_members in 1usize..6,
            ops in proptest::collection::vec(
                (0usize..8, proptest::option::of(0u64..600), 0u64..300, proptest::bool::ANY),
                0..60,
            ),
        ) {
            let id_pool: Vec<String> = (0..n_members).map(|i| format!("m{i}")).collect();
            let pools = PoolStates::new();
            let t0 = Instant::now();
            let mut now = t0;
            let mut members = id_pool.clone();
            let mut pick_count = 0usize;
            for (op_idx, until_off, advance, reconfig) in &ops {
                now += Duration::from_secs(*advance);
                // 每步 pick: 任意中间状态下 sound.
                match pools.pick_member("pl", &members, now) {
                    Ok(i) => {
                        pick_count += 1;
                        prop_assert!(i < members.len(), "pick index out of range");
                    }
                    Err(e) => {
                        prop_assert_eq!(e.pool_id, "pl");
                    }
                }
                // 状态变更: 配置重组 (长度/顺序变化/重复成员 — validate 允许
                // 重复 id, 生成器须覆盖) 或 mark (闹钟/永久).
                let op_idx = *op_idx;
                let idx = op_idx % members.len();
                if *reconfig {
                    members = (0..(op_idx % n_members) + 1)
                        .map(|k| id_pool[(k + idx) % n_members].clone())
                        .collect();
                    if op_idx % 4 == 0 && !members.is_empty() {
                        // 重复成员注入: 同一 id 出现两次 (独立 slot, 第二次
                        // pick 到时它已耗尽 — validate 允许的合法配置).
                        let dup = members[0].clone();
                        members.push(dup);
                    }
                } else {
                    pools.mark_member_exhausted(
                        "pl",
                        &members,
                        idx,
                        until_off.map(|s| now + Duration::from_secs(s)),
                    );
                }
            }
            // 生成器覆盖度守卫: 非空序列必有 pick (每步都 pick).
            prop_assert!(pick_count > 0 || ops.is_empty());
        }
    }
}
