//! 纯模式化 PII 旁路扫描器 (privacy scan, #257 S0.5 切片).
//!
//! # 职责边界
//!
//! 对**请求侧** pre-redact IR 的字符串叶子做固定 pattern 集 (常见 token 形状)
//! 的旁路扫描, 产出「疑似未登记」告警, 供 WebUI 引导用户登记 (人回路确认).
//! 这是 #257 Laya 主线 (S0 人工标注 → S1 微调 POC → S2 集成) 之外的独立切片,
//! 目标是更早验证「告警 → 登记」闭环产品形态是否真的有人用.
//!
//! # 五条红线 (#257, 实现面逐条落实)
//!
//! 1. **不进转发链做 Redact 决策** — 本模块对 wire 的修改恒为零. 捕获是只读
//!    遍历 (`capture` 只 clone 字符串叶子), 提交是 `try_send` (满则丢弃).
//!    FWD-1 透明中继的字节流不经过本模块的任何写路径.
//! 2. **永不 filter/拦截/改写** — 唯一产物是内存告警 + WARN 日志. 误判的
//!    worst case = 一条告警行.
//! 3. **零新依赖** — pattern 匹配为手写字节扫描 (literal prefix + charset
//!    run), 不引入 regex crate (它仅在 dev-dependency 树, 升为生产依赖违反
//!    红线). 所有 pattern 是 ASCII 锚定, UTF-8 下 ASCII 字节不可能出现在
//!    多字节序列内部, 因此字节偏移天然落在 char boundary 上.
//! 4. **功能默认关闭** — `[privacy_scan] mode = "off"` 默认; off 时
//!    [`PrivacyScanner`] 是 `None` 内壳, capture/submit 均为零开销 no-op,
//!    转发热路径与现状逐字节一致.
//! 5. **告警永不自动登记** — 本模块无任何写 SecretTable 的路径; 登记只能由
//!    用户在 WebUI 预填表单中确认提交 (`POST /api/secrets`).
//!
//! # 数据流
//!
//! ```text
//! proxy seam (same_proto / cross_proto, redact 调用点)
//!   │ capture(&ir)          ← redact 前, 只读 clone pre-redact 字符串叶子
//!   │                         (独立于 secrets 是否为空 — 未登记侦测最有价值
//!   │                          的场景恰是没登记几个 secret)
//!   ▼
//! submit(job, excluded)     ← redact 后, excluded = 本次请求生效的已登记值
//!   │ try_send (有界 channel, 满则丢弃 + 计数)
//!   ▼
//! 后台 task (mode=batch) ── pattern 匹配 ── 排除已登记值 ── AlertStore (去重合并)
//!   │
//!   ▼
//! GET /api/privacy-scan/alerts → 过滤已登记值 → WebUI「疑似未登记」面板
//! ```
//!
//! # 排除规则 (告警语义 = 「未被登记管理的 token 形状」)
//!
//! 扫描时排除 `excluded` (= 本次请求的 effective secrets 快照, 非空值);
//! API 视图再过滤一次当前已登记值 (登记后告警行立即消失, 无需新增 dismiss
//! 端点; 删掉 secret 后告警自然重现). 语义精确性: 已登记 (含已被 redact
//! 替换) 的值永不告警 — pre-redact 视图保证 mock 替身永不进入扫描输入,
//! "post-redact 不扫" 由数据源选择结构性保证.
//!
//! # 已知限制 (best-effort, 详见 docs/known-limitations.md privacy-scan 节)
//!
//! - 告警为内存态, 重启清空 (不落盘, 一次会话内验证闭环足够).
//! - Gemini/Ollama 字节透传族无 codec IR, 不扫描.
//! - 正则形状判定有误报可能 (告警非定罪); 通用 high-entropy 长串**刻意不做**
//!   (误报不可控, 留给 Laya S1+).
//! - `realtime` 档位属 Laya S2, 不实现不预留枚举值.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::Serialize;
use tracing::warn;

use crate::codec::ir::IrRequest;
use crate::redact::StringLeafOps;

/// 告警存储容量上限 (FIFO 淘汰). 一次会话内验证闭环足够; 超出后最老告警被挤出.
pub(crate) const ALERT_CAP: usize = 256;

/// 有界 channel 容量 (在途捕获 job 数上限). 满则 try_send 丢弃 (fail-open,
/// 热路径零阻塞). 最坏在途内存 ≈ CHANNEL_CAP × (SCAN_BUDGET_BYTES +
/// MAX_LEAF_BYTES) — budget 按叶子粒度扣减, 单叶可超预算整体扫描 (见下).
const CHANNEL_CAP: usize = 32;

/// 单个捕获 job 的字符串叶子总字节预算 (叶子粒度扣减: 累计首超预算后剩余叶子
/// 跳过; 单叶可超预算整体扫描 — 上下文常按消息分叶, 单叶巨型消息中的 token
/// 不应因恰好超线被整体丢弃). 截断的是扫描覆盖面, 不是请求转发 (红线 1/2).
const SCAN_BUDGET_BYTES: usize = 1024 * 1024;

/// 单叶捕获上限: 超过此尺寸的叶子整体跳过 (单条消息 > 2 MiB 已属病理性粘贴,
/// 且不经此上限时单叶即可达 MAX_REQ_BODY 16 MiB, 击穿内存上界论证).
const MAX_LEAF_BYTES: usize = 2 * 1024 * 1024;

/// 上下文摘要的前后字符预算 (per 侧, char 计数, 截断走 util 族保证
/// char-boundary 安全).
const CONTEXT_CHARS: usize = 40;

// ─── pattern 集 (手写字节扫描, 零依赖) ─────────────────────────────────────

/// 单条 pattern 的命中 (字节区间, ASCII 锚定 ⇒ 区间端点必在 char boundary).
type Span = (usize, usize);

/// 扫描 run 的长度约束.
#[derive(Clone, Copy)]
enum RunLen {
    /// 恰好 N 个 (如 AWS key id 的 16 尾字符; 多一个即非 canonical 形状, 放弃).
    Exact(usize),
    /// 至少 N 个 (如 GitHub token 的 ≥36 尾字符; 匹配覆盖整个 run).
    AtLeast(usize),
}

/// 通用形状: literal prefix + charset run + 左边界 (prefix 前一字节非 ASCII
/// 字母数字, 防 mid-token 误命中).
fn find_prefixed(hay: &str, prefixes: &[&str], class: fn(u8) -> bool, run: RunLen) -> Vec<Span> {
    let b = hay.as_bytes();
    let mut out = Vec::new();
    for &prefix in prefixes {
        let pb = prefix.as_bytes();
        let mut from = 0;
        while let Some(pos) = find_sub(b, from, pb) {
            from = pos + 1;
            // 左边界: 前一字节不得是 ASCII 字母数字.
            if pos > 0 && b[pos - 1].is_ascii_alphanumeric() {
                continue;
            }
            let run_start = pos + pb.len();
            let mut end = run_start;
            while end < b.len() && class(b[end]) {
                end += 1;
            }
            let n = end - run_start;
            let hit = match run {
                RunLen::Exact(k) => n == k,
                RunLen::AtLeast(k) => n >= k,
            };
            if hit {
                out.push((pos, end));
            }
        }
    }
    out
}

/// 字节子串查找 (`haystack[from..]` 中找 `needle`), 避免反复 slice 出 &str
/// (匹配点可能在多字节序列中间, 不能用 str 索引).
///
/// 终止性契约: 返回值 `pos >= from` 恒成立 — 调用方以 `from = pos + 1` 推进,
/// 绝不能被钳回 (历史 bug: min-clamp 版本在 needle 恰为 haystack 后缀时把
/// from 钳回最后一个窗口起点, 返回 pos < from, 全部调用方死循环).
fn find_sub(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let i = haystack
        .get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)?;
    Some(from + i)
}

fn is_base64ish(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')
}

fn is_wordish(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')
}

fn is_alnum_or_hyphen(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

/// OpenAI 形状: `sk-` + ≥40 word 字符, 但**排除 `sk-ant-` 前缀交叠**
/// (那是 Anthropic 形状, 由独立 pattern 负责 — 两个 pattern 各管各的, 不重复告警).
fn find_openai(hay: &str) -> Vec<Span> {
    let mut out = find_prefixed(hay, &["sk-"], is_wordish, RunLen::AtLeast(40));
    // 剔除 "sk-ant-..." (Anthropic key, 交给 anthropic pattern).
    out.retain(|&(s, _)| !hay[s..].starts_with("sk-ant-"));
    out
}

/// JWT: `eyJ…\.eyJ…\.…` 三段 base64url (各段 ≥10 字符, 签名段同).
fn find_jwt(hay: &str) -> Vec<Span> {
    let b = hay.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = find_sub(b, from, b"eyJ") {
        from = pos + 1;
        if pos > 0 && is_wordish(b[pos - 1]) {
            continue; // 左边界: 前一字节非 word 字符.
        }
        let seg1_end = scan_while(b, pos + 3, is_wordish);
        if seg1_end - pos < 10 || b.get(seg1_end) != Some(&b'.') {
            continue;
        }
        // seg1_end < b.len() 已由上方的 '.' 匹配保证, seg2_start <= b.len() 安全.
        let seg2_start = seg1_end + 1;
        if !b[seg2_start..].starts_with(b"eyJ") {
            continue;
        }
        let seg2_end = scan_while(b, seg2_start + 3, is_wordish);
        if seg2_end - seg2_start < 10 || b.get(seg2_end) != Some(&b'.') {
            continue;
        }
        let seg3_start = seg2_end + 1;
        let seg3_end = scan_while(b, seg3_start, is_wordish);
        if seg3_end - seg3_start >= 10 {
            out.push((pos, seg3_end));
        }
    }
    out
}

fn scan_while(b: &[u8], from: usize, pred: fn(u8) -> bool) -> usize {
    let mut i = from;
    while i < b.len() && pred(b[i]) {
        i += 1;
    }
    i
}

/// AWS Secret Access Key (高置信组合形态): 邻近 label (`aws_secret_access_key`
/// 等) 之后恰好 40 个 base64ish 字符. 裸 40 字符 base64 串 (含 sha1 hex) 误报
/// 不可控, 刻意不单独成 pattern — 只在 label 在场时判定.
fn find_aws_secret(hay: &str) -> Vec<Span> {
    const LABELS: &[&str] = &[
        "aws_secret_access_key",
        "AWS_SECRET_ACCESS_KEY",
        "AWS Secret Access Key",
        "aws secret access key",
    ];
    let b = hay.as_bytes();
    let mut out = Vec::new();
    for &label in LABELS {
        let lb = label.as_bytes();
        let mut from = 0;
        while let Some(pos) = find_sub(b, from, lb) {
            from = pos + 1;
            // label 后允许 ≤8 个分隔字符 (空白/引号/冒号/等号), 再接 40-char 值.
            let mut i = pos + lb.len();
            let sep_start = i;
            while i < b.len() && matches!(b[i], b' ' | b'\t' | b'"' | b'\'' | b'=' | b':' | b'`') {
                i += 1;
            }
            if i - sep_start > 8 {
                continue;
            }
            let val_start = i;
            let val_end = scan_while(b, val_start, is_base64ish);
            if val_end - val_start == 40 {
                out.push((val_start, val_end));
            }
        }
    }
    out
}

/// PEM 私钥头 (块首行 literal, 4 变体互不为子串).
fn find_pem(hay: &str) -> Vec<Span> {
    const HEADERS: &[&str] = &[
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    ];
    let b = hay.as_bytes();
    let mut out = Vec::new();
    for &h in HEADERS {
        let hb = h.as_bytes();
        let mut from = 0;
        while let Some(pos) = find_sub(b, from, hb) {
            from = pos + 1;
            out.push((pos, pos + hb.len()));
        }
    }
    out
}

/// 内置 pattern 表 (const, 添加新形状 = 加一行 + 单测正/负例).
pub(crate) struct PatternDef {
    pub id: &'static str,
    pub label: &'static str,
    find: fn(&str) -> Vec<Span>,
}

pub(crate) const PATTERNS: &[PatternDef] = &[
    PatternDef {
        id: "aws-access-key-id",
        label: "AWS Access Key ID",
        find: |s| {
            find_prefixed(
                s,
                &["AKIA"],
                |b| b.is_ascii_uppercase() || b.is_ascii_digit(),
                RunLen::Exact(16),
            )
        },
    },
    PatternDef {
        id: "aws-secret-access-key",
        label: "AWS Secret Access Key",
        find: find_aws_secret,
    },
    PatternDef {
        id: "github-token",
        label: "GitHub token",
        find: |s| {
            find_prefixed(
                s,
                &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
                |b| b.is_ascii_alphanumeric(),
                RunLen::AtLeast(36),
            )
        },
    },
    PatternDef {
        id: "gitlab-token",
        label: "GitLab token",
        find: |s| find_prefixed(s, &["glpat-"], is_wordish, RunLen::AtLeast(20)),
    },
    PatternDef {
        id: "slack-token",
        label: "Slack token",
        find: |s| {
            find_prefixed(
                s,
                &["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"],
                is_alnum_or_hyphen,
                RunLen::AtLeast(10),
            )
        },
    },
    PatternDef {
        id: "openai-api-key",
        label: "OpenAI API key",
        find: find_openai,
    },
    PatternDef {
        id: "anthropic-api-key",
        label: "Anthropic API key",
        find: |s| find_prefixed(s, &["sk-ant-"], is_wordish, RunLen::AtLeast(20)),
    },
    PatternDef {
        id: "google-api-key",
        label: "Google API key",
        find: |s| find_prefixed(s, &["AIza"], is_wordish, RunLen::Exact(35)),
    },
    PatternDef {
        id: "jwt",
        label: "JWT",
        find: find_jwt,
    },
    PatternDef {
        id: "pem-private-key",
        label: "PEM private key",
        find: find_pem,
    },
];

// ─── 告警存储 ───────────────────────────────────────────────────────────────

/// 一条告警 (同 value+pattern 去重合并: hit_count / last_seen / context 更新,
/// first_seen 保留首次). `pattern_id` 恒来自 [`PATTERNS`] 的 `&'static str`.
#[derive(Debug, Clone)]
pub(crate) struct Alert {
    pub value: String,
    pub pattern_id: &'static str,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub hit_count: u64,
    pub context: String,
}

/// 内存告警存储: `VecDeque` + 容量 FIFO 淘汰. 不落盘 (重启清空, 见模块头
/// 已知限制).
#[derive(Debug, Default)]
pub(crate) struct AlertStore {
    alerts: VecDeque<Alert>,
}

impl AlertStore {
    /// 记录一次命中: 已存在 (value, pattern_id) 则合并, 否则插入; 超容从队头淘汰.
    pub(crate) fn record(
        &mut self,
        value: String,
        pattern_id: &'static str,
        context: String,
        now: DateTime<Utc>,
    ) {
        if let Some(a) = self
            .alerts
            .iter_mut()
            .find(|a| a.value == value && a.pattern_id == pattern_id)
        {
            a.hit_count += 1;
            a.last_seen = now;
            a.context = context;
            return;
        }
        if self.alerts.len() >= ALERT_CAP {
            self.alerts.pop_front();
        }
        self.alerts.push_back(Alert {
            value,
            pattern_id,
            first_seen: now,
            last_seen: now,
            hit_count: 1,
            context,
        });
    }

    /// 当前告警快照 (新→旧, 最近的在前 — 面板默认最关心最新命中).
    pub(crate) fn snapshot(&self) -> Vec<Alert> {
        self.alerts.iter().rev().cloned().collect()
    }
}

// ─── 扫描器 ( AppState 持有; off = 零开销空壳 ) ───────────────────────────

/// 一次捕获的载荷: pre-redact IR 的字符串叶子集合 (字节预算内) + 提交时注入的
/// 排除集 (本次请求生效的已登记 secret 值 — 随 job 走, 后台 task 扫描时消费).
pub(crate) struct ScanJob {
    leaves: Vec<String>,
    excluded: Vec<String>,
}

/// 进程级隐私扫描器. `mode = off` 时 [`PrivacyScanner::disabled`] 构造空壳
/// (capture 返回 None, submit no-op, API 返回 enabled:false); `batch` 时构造
/// 内壳并 spawn 后台扫描 task (构造点必须在 tokio runtime 内 — 生产装配在
/// `server::serve`, 测试装配在 async harness, 均满足).
///
/// Clone 语义: 内壳 Arc 共享 (sender + store), 与 `PoolStates` / `ModelListCache`
/// 的 "state 聚合各 feature store" 先例同型.
#[derive(Clone, Debug)]
pub struct PrivacyScanner {
    inner: Option<Arc<ScannerInner>>,
}

#[derive(Debug)]
struct ScannerInner {
    tx: tokio::sync::mpsc::Sender<ScanJob>,
    store: Arc<Mutex<AlertStore>>,
    /// try_send 满丢弃计数 (热路径只做原子自增; WARN 由后台 task 消费侧发出,
    /// 保持发送闭包零 IO).
    dropped: Arc<AtomicU64>,
}

impl Default for PrivacyScanner {
    /// `Default` = off 档空壳 (与 `[privacy_scan] mode` 缺省值对齐 — off 是默认,
    /// 启用须显式 `PrivacyScanner::new()`, 见红线 4).
    fn default() -> Self {
        Self::disabled()
    }
}

impl PrivacyScanner {
    /// `mode = batch`: spawn 后台 task. 需在 tokio runtime 内调用.
    pub fn new() -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ScanJob>(CHANNEL_CAP);
        let store = Arc::new(Mutex::new(AlertStore::default()));
        let dropped = Arc::new(AtomicU64::new(0));
        let task_store = store.clone();
        let task_dropped = dropped.clone();
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                scan_job(&job, &task_store);
                // 丢弃计数消费: 每次 recv 后观察累计增量, 有丢弃才 WARN (一次性,
                // 不逐条刷屏; 热路径侧零日志开销).
                let d = task_dropped.swap(0, Ordering::Relaxed);
                if d > 0 {
                    warn!(
                        count = d,
                        "privacy scan queue full; capture job(s) dropped (scan is best-effort)"
                    );
                }
            }
        });
        Self {
            inner: Some(Arc::new(ScannerInner { tx, store, dropped })),
        }
    }

    /// `mode = off`: 零开销空壳 (默认档).
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    pub fn enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// 捕获 pre-redact IR 的字符串叶子 (redact 调用**前**; 只读, 不触碰 IR).
    /// disabled → None (零 clone 零分配). 字节预算按叶子粒度扣减: 累计首超
    /// 预算后剩余叶子跳过 (截断的是扫描覆盖面, 不是转发 — 巨型上下文不拖垮
    /// 扫描内存; 单叶超预算仍整体扫描, 见 SCAN_BUDGET_BYTES 注).
    pub(crate) fn capture(&self, ir: &IrRequest) -> Option<ScanJob> {
        self.inner.as_ref()?;
        let mut leaves = Vec::new();
        let mut budget = SCAN_BUDGET_BYTES;
        ir.for_each_str_leaf(&mut |s| {
            if s.is_empty() || budget == 0 || s.len() > MAX_LEAF_BYTES {
                return;
            }
            budget = budget.saturating_sub(s.len());
            leaves.push(s.to_string());
        });
        if leaves.is_empty() {
            return None; // 空载荷不占 channel 配额.
        }
        Some(ScanJob {
            leaves,
            excluded: Vec::new(),
        })
    }

    /// 提交捕获 (redact 调用**后**): `excluded_entries` = 本次请求的 effective
    /// secrets 快照, 在早退**之后**才投影为非空值集合 (off 档 capture=None 时
    /// 零投影开销, 红线 4). try_send 满则丢弃 + 计数 (fail-open, 永不阻塞/失败传播).
    pub(crate) fn submit(
        &self,
        job: Option<ScanJob>,
        excluded_entries: &[crate::secrets::SecretEntry],
    ) {
        let Some(inner) = &self.inner else { return };
        let Some(mut job) = job else { return };
        job.excluded = crate::secrets::non_empty_values(excluded_entries);
        // try_send 路径内不允许 panic/IO (红线 1 的热路径实现面): 唯一可 Err 的
        // 路径是 channel 满 → 原子计数后返回.
        match inner.tx.try_send(job) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                inner.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                // 后台 task 已退出 (仅进程 shutdown 时可能): 静默丢弃.
            }
        }
    }

    /// API 视图: 告警快照过滤当前已登记值 (`registered` = effective secrets
    /// 值集), 映射为 DTO (附 pattern label). 返回 (enabled, alerts) — enabled
    /// 让前端隐藏整个面板, 区分 "没扫到" 与 "没开启".
    pub(crate) fn alerts_view(&self, registered: &[String]) -> (bool, Vec<AlertDto>) {
        let Some(inner) = &self.inner else {
            return (false, Vec::new());
        };
        let snapshot = inner.store.lock().snapshot();
        let alerts = snapshot
            .into_iter()
            .filter(|a| !registered.iter().any(|r| r == &a.value))
            .map(|a| {
                let label = PATTERNS
                    .iter()
                    .find(|p| p.id == a.pattern_id)
                    .map(|p| p.label)
                    .unwrap_or(a.pattern_id);
                AlertDto {
                    value: a.value,
                    pattern_id: a.pattern_id.to_string(),
                    pattern_label: label.to_string(),
                    first_seen: a.first_seen,
                    last_seen: a.last_seen,
                    hit_count: a.hit_count,
                    context: a.context,
                }
            })
            .collect();
        (true, alerts)
    }
}

/// 后台 task 的单 job 处理: 每叶子 × 每 pattern 匹配 → 排除已登记 → 记录.
/// 匹配阶段无锁 (大 job 不阻塞 alerts API 读), 仅落账时短临界区.
fn scan_job(job: &ScanJob, store: &Mutex<AlertStore>) {
    let now = Utc::now();
    // (value, pattern_id, context) — 先算后锁.
    let mut hits: Vec<(String, &'static str, String)> = Vec::new();
    for leaf in &job.leaves {
        for pattern in PATTERNS {
            for (start, end) in (pattern.find)(leaf) {
                let value = match leaf.get(start..end) {
                    Some(v) => v,
                    // 理论不可达 (ASCII 锚定 ⇒ 端点必在 boundary); ROB 兜底跳过.
                    None => continue,
                };
                if job.excluded.iter().any(|x| x == value) {
                    continue;
                }
                hits.push((
                    value.to_string(),
                    pattern.id,
                    context_around(leaf, start, end, value),
                ));
            }
        }
    }
    let mut guard = store.lock();
    for (value, pattern_id, context) in hits {
        guard.record(value, pattern_id, context, now);
    }
}

/// 命中点上下文摘要: `…{before}{value}{after}…` — 前后各 ≤CONTEXT_CHARS 字符
/// (char 计数截断, 复用 util 截断族), 发生截断的侧加 `…` 标记. value 原样内嵌
/// (等宽字体展示 "它出现在什么话里"; 行内 value 与 value 列重复是有意的 —
/// 摘要自成一体, 不要求读行时横向对齐). best-effort: 区间越界 (不可达) 时
/// 回退空串.
fn context_around(leaf: &str, start: usize, end: usize, value: &str) -> String {
    let before = leaf.get(..start).unwrap_or("");
    let after = leaf.get(end..).unwrap_or("");
    let b = crate::util::truncate_chars(before, CONTEXT_CHARS);
    let a = crate::util::truncate_chars(after, CONTEXT_CHARS);
    let b_mark = if b.len() < before.len() { "…" } else { "" };
    let a_mark = if a.len() < after.len() { "…" } else { "" };
    format!("{b_mark}{b}{value}{a}{a_mark}")
}

/// `GET /api/privacy-scan/alerts` 的响应条目 (wire shape).
#[derive(Debug, Serialize)]
pub(crate) struct AlertDto {
    pub value: String,
    pub pattern_id: String,
    pub pattern_label: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub hit_count: u64,
    pub context: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS Access Key ID 形状工厂 (AKIA + 16 位大写字母数字).
    fn aws_key(seed: &str) -> String {
        let mut tail: String = seed
            .chars()
            .filter(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            .collect();
        while tail.len() < 16 {
            tail.push('Q');
        }
        format!("AKIA{}", &tail[..16])
    }

    /// 按 id 走**真 PATTERNS 表**取 matcher 执行 (断言的是产品实际生效的形状,
    /// 不是测试侧复制的参数副本 — 改表项后本组测试随行为红/绿, 无漂移盲区).
    /// nextest 默认无 per-test 超时, 终止性由下方 suffix 回归用例守卫.
    fn hits(id: &str, hay: &str) -> Vec<String> {
        let p = PATTERNS
            .iter()
            .find(|p| p.id == id)
            .unwrap_or_else(|| panic!("unknown pattern id: {id}"));
        (p.find)(hay)
            .iter()
            .map(|&(s, e)| hay[s..e].to_string())
            .collect()
    }

    // ─── pattern 正/负例 (走真表) ────────────────────────────────────────

    #[test]
    fn aws_key_positive_and_negative() {
        let k = aws_key("ABCDEFGH12345678");
        let hay = format!("use key {k} for aws");
        assert_eq!(hits("aws-access-key-id", &hay), vec![k.clone()]);

        // 负例: 尾部 17 位 (非 canonical), 小写前缀, mid-token.
        assert!(hits("aws-access-key-id", &format!("AKIA{}", "Q".repeat(17))).is_empty());
        assert!(hits("aws-access-key-id", &format!("akia{}", "q".repeat(16))).is_empty());
        assert!(
            hits("aws-access-key-id", &format!("x{k}")).is_empty(),
            "mid-token AKIA must not match"
        );
    }

    #[test]
    fn github_token_shapes() {
        let tok = format!("ghp_{}", "a".repeat(40));
        assert_eq!(hits("github-token", &tok), vec![tok.clone()]);
        for p in ["gho_", "ghu_", "ghs_", "ghr_"] {
            let t = format!("{p}{}", "z9".repeat(20));
            assert_eq!(hits("github-token", &t), vec![t], "prefix {p} must match");
        }
        // 负例: 太短.
        assert!(hits("github-token", &format!("ghp_{}", "a".repeat(20))).is_empty());
    }

    #[test]
    fn openai_vs_anthropic_prefix_disjoint() {
        let oai = format!("sk-{}", "ab".repeat(25));
        assert_eq!(hits("openai-api-key", &oai), vec![oai]);
        // sk-ant- 交叠排除: 只由 anthropic pattern 命中.
        let ant = format!("sk-ant-api03-{}", "c1".repeat(20));
        assert!(
            hits("openai-api-key", &ant).is_empty(),
            "openai matcher must skip sk-ant-"
        );
        assert_eq!(hits("anthropic-api-key", &ant), vec![ant]);
        // 短 sk- 不告警 (防 "sk-test" 类口语值).
        assert!(hits("openai-api-key", "sk-test").is_empty());
    }

    #[test]
    fn google_slack_gitlab_shapes() {
        let g = format!("AIza{}", "SyA-9".repeat(7)); // 35 chars
        assert_eq!(g.len(), 39);
        assert_eq!(hits("google-api-key", &g), vec![g]);
        let s = "xoxb-123456789012-abcdef";
        assert_eq!(hits("slack-token", s), vec![s.to_string()]);
        let gl = format!("glpat-{}", "x0".repeat(10));
        assert_eq!(hits("gitlab-token", &gl), vec![gl]);
    }

    #[test]
    fn jwt_positive_negative() {
        let jwt = format!("eyJhbGciOi.eyJzdWIiOi.{}", "c2ln".repeat(5));
        assert_eq!(hits("jwt", &jwt), vec![jwt]);
        // 负例: 缺第三段.
        assert!(hits("jwt", "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0NQ").is_empty());
        // 负例: 第二段不以 eyJ 开头.
        let bad = format!("eyJhbGciOiJIUzI1.aGVsbG8.{}", "c2ln".repeat(5));
        assert!(hits("jwt", &bad).is_empty());
    }

    #[test]
    fn aws_secret_requires_label_proximity() {
        let sec = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789aB+/".to_string();
        assert_eq!(sec.len(), 40);
        // 正例: label + 分隔 + 40-char 值 (snake / 大写 / 冒号三形态).
        let hay = format!("aws_secret_access_key = \"{sec}\"");
        assert_eq!(hits("aws-secret-access-key", &hay), vec![sec.clone()]);
        let hay2 = format!("AWS_SECRET_ACCESS_KEY: {sec}");
        assert_eq!(hits("aws-secret-access-key", &hay2), vec![sec.clone()]);
        // 负例: 裸 40-char base64 (eg sha1 hex) 不告警 — label 不在场.
        assert!(hits("aws-secret-access-key", &format!("hash = {sec}")).is_empty());
        // 负例: label 后值长度 != 40.
        assert!(
            hits(
                "aws-secret-access-key",
                &format!("aws_secret_access_key = {}", "a".repeat(39))
            )
            .is_empty()
        );
    }

    #[test]
    fn pem_header_variants() {
        for h in [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
        ] {
            let hay = format!("cert: {h}\nMIIB...");
            assert_eq!(
                hits("pem-private-key", &hay),
                vec![h.to_string()],
                "variant {h}"
            );
        }
        assert!(hits("pem-private-key", "no keys here").is_empty());
    }

    /// **终止性回归 (P0, 两个 reviewer 独立发现的死循环 bug)**: needle 恰为
    /// 叶子后缀时 (用户粘贴半截 token 收尾消息), 旧 find_sub 的 min-clamp 会
    /// 把扫描起点钳回, 返回 pos < from, while-let 永不前进 → 后台 task 活锁.
    /// 每条 prefix/label/literal 形态逐一守卫: 断言能返回 (即终止).
    #[test]
    fn needle_as_leaf_suffix_terminates() {
        // prefix 族: 前缀字面量收尾 (无后续 run, 不命中但必须终止).
        for hay in [
            "my key starts with ghp_",
            "token leaked: sk-",
            "anthropic style sk-ant-",
            "aws id AKIA",
            "google AIza",
            "glpat-",
            "slack xoxb-",
            "jwt header eyJ",
            "aws_secret_access_key",
            "AWS Secret Access Key",
        ] {
            for p in PATTERNS {
                let _ = (p.find)(hay); // 不挂死即通过.
            }
        }
        // literal 族完整收尾恰命中一次 (pem header 整行结尾).
        let full = "-----BEGIN PRIVATE KEY-----";
        assert_eq!(hits("pem-private-key", full), vec![full.to_string()]);
        // 前缀 + 恰好 16 位收尾 = 恰好命中在末尾.
        let k = aws_key("SUFFIXEND00000A");
        let hay = format!("trailing {k}");
        assert_eq!(hits("aws-access-key-id", &hay), vec![k]);
    }

    /// 每条 pattern 对多字节内容 (CJK / emoji) 永不 panic 且不产生半字符命中
    /// (ROB-1 + ASCII 锚定的 char-boundary 安全性).
    #[test]
    fn patterns_never_panic_on_multibyte() {
        let hay =
            "中文 AKIAidonotmatch 因为后缀不足 🎉 glpat-短 sk-短 eyJ.eyJ.x -----BEGIN 私钥-----";
        for p in PATTERNS {
            let _ = (p.find)(hay); // 不 panic 即通过.
        }
        assert!(PATTERNS.iter().all(|p| (p.find)(hay).is_empty()));
    }

    // ─── AlertStore: 去重合并 + cap FIFO ─────────────────────────────────

    #[test]
    fn store_merges_same_value_pattern() {
        let mut s = AlertStore::default();
        let t0 = Utc::now();
        s.record("v1".into(), "jwt", "ctx-a".into(), t0);
        s.record(
            "v1".into(),
            "jwt",
            "ctx-b".into(),
            t0 + chrono::Duration::seconds(10),
        );
        s.record("v1".into(), "openai-api-key", "ctx-c".into(), t0); // 同值不同 pattern = 独立条目.
        let snap = s.snapshot();
        assert_eq!(snap.len(), 2);
        let jwt = snap.iter().find(|a| a.pattern_id == "jwt").unwrap();
        assert_eq!(jwt.hit_count, 2);
        assert_eq!(jwt.context, "ctx-b", "context keeps latest");
        assert_eq!(jwt.first_seen, t0, "first_seen preserved");
        assert_eq!(jwt.last_seen, t0 + chrono::Duration::seconds(10));
    }

    #[test]
    fn store_evicts_fifo_beyond_cap() {
        let mut s = AlertStore::default();
        let t0 = Utc::now();
        for i in 0..ALERT_CAP + 10 {
            s.record(format!("v{i}"), "jwt", String::new(), t0);
        }
        let snap = s.snapshot();
        assert_eq!(snap.len(), ALERT_CAP);
        // 最新的在前; 队头 (v0..v9) 已被淘汰.
        assert!(snap.iter().all(|a| a.value != "v0" && a.value != "v9"));
        assert_eq!(snap[0].value, format!("v{}", ALERT_CAP + 9));
    }

    // ─── context 截断 (char-boundary) ────────────────────────────────────

    #[test]
    fn context_truncates_on_char_boundary() {
        // 前后各塞 100 个 CJK 字符 (3 bytes each), 命中点居中.
        let pad: String = "汉".repeat(100);
        let leaf = format!("{pad}TOKEN{pad}");
        let start = leaf.find("TOKEN").unwrap();
        let ctx = context_around(&leaf, start, start + 5, "TOKEN");
        assert!(ctx.starts_with('…'), "head truncation marker");
        assert!(ctx.ends_with('…'), "tail truncation marker");
        assert!(ctx.contains("TOKEN"), "value embedded inline");
        // 两侧各 ≤ 40 chars + markers + token.
        let side = ctx.split("TOKEN").collect::<Vec<_>>();
        assert!(side[0].chars().count() <= 41, "before side within budget");
        assert!(side[1].chars().count() <= 41, "after side within budget");
        // 短上下文 (无截断) 不加 marker.
        let short = context_around("a TOKEN b", 2, 7, "TOKEN");
        assert_eq!(short, "a TOKEN b");
    }

    // ─── 后台 task: 排除规则 + 端到端 (tokio) ─────────────────────────────

    fn sample_ir_with(text: &str) -> IrRequest {
        // 最小 OpenAI 形态 IR (经 serde JSON 构造, 避免 hand-assembly 漂移).
        let body = serde_json::json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": text}],
        });
        let codec = crate::codec::Protocol::OpenAI;
        let reader = codec.reader();
        reader.read_request(&body).expect("sample IR parse")
    }

    fn registered_secret(value: &str) -> crate::secrets::SecretEntry {
        crate::secrets::SecretEntry {
            id: "reg".into(),
            name: None,
            category: Default::default(),
            value: value.into(),
            value_file: None,
            mock_strategy: Default::default(),
        }
    }

    #[tokio::test]
    async fn scanner_end_to_end_excludes_registered_values() {
        let scanner = PrivacyScanner::new();
        assert!(scanner.enabled());

        let unregistered = aws_key("ZZZZYYYYXXXXWWWW");
        let registered = format!("ghp_{}", "r".repeat(40));
        let ir = sample_ir_with(&format!("keys: {unregistered} {registered}"));

        let job = scanner.capture(&ir).expect("capture when enabled");
        scanner.submit(Some(job), &[registered_secret(&registered)]);

        // 后台 task 异步消费: 轮询直到告警出现 (有界等待).
        for _ in 0..100 {
            let (_, alerts) = scanner.alerts_view(&[]);
            if alerts.iter().any(|a| a.value == unregistered) {
                // 已登记值被排除 (扫描侧 excluded).
                assert!(
                    alerts.iter().all(|a| a.value != registered),
                    "registered value must not alert"
                );
                // API 视图侧再过滤: 即使混入 store, registered 过滤后不可见.
                let (_, view) = scanner.alerts_view(std::slice::from_ref(&registered));
                assert!(view.iter().all(|a| a.value != registered));
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("alert for unregistered key never appeared");
    }

    #[tokio::test]
    async fn disabled_scanner_is_zero_cost_noop() {
        let scanner = PrivacyScanner::disabled();
        assert!(!scanner.enabled());
        let ir = sample_ir_with("AKIAQQQQQQQQQQQQQQQQ");
        assert!(scanner.capture(&ir).is_none(), "capture no-op when off");
        scanner.submit(None, &[]); // 不 panic.
        let (enabled, alerts) = scanner.alerts_view(&[]);
        assert!(!enabled);
        assert!(alerts.is_empty());
    }

    #[tokio::test]
    async fn same_value_multiple_occurrences_increments_hits() {
        let scanner = PrivacyScanner::new();
        let k = aws_key("MULTIHIT00000001");
        let ir = sample_ir_with(&format!("{k} and again {k}"));
        let job = scanner.capture(&ir).unwrap();
        scanner.submit(Some(job), &[]);
        for _ in 0..100 {
            let (_, alerts) = scanner.alerts_view(&[]);
            if let Some(a) = alerts.iter().find(|a| a.value == k) {
                assert_eq!(a.hit_count, 2, "two occurrences in one leaf");
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("alert never appeared");
    }

    /// 字节预算: 超大叶子不 panic; 预算内叶子仍被扫描; 单叶超上限被跳过.
    #[tokio::test]
    async fn capture_respects_byte_budget() {
        let scanner = PrivacyScanner::new();
        // 单叶 1.2MB (超 1MB 预算但 < 2MB 单叶上限): 整体扫描 (budget 叶子粒度).
        // 注: token 与填充之间必须分隔 (左边界检查把 "xxxAKIA..." 判为 mid-token
        // 跳过 — 那是产品行为, 早期版本焊死相邻曾让本断言静默丢失).
        let big: String = "x".repeat(1200 * 1024);
        let token = aws_key("BUDGET0000000001");
        let ir = sample_ir_with(&format!("{big} {token}"));
        let job = scanner.capture(&ir).expect("capture");
        let total: usize = job.leaves.iter().map(|s| s.len()).sum();
        assert!(
            total <= SCAN_BUDGET_BYTES + MAX_LEAF_BYTES,
            "budget bounds total (leaf granularity): {total}"
        );
        scanner.submit(Some(job), &[]);
        let mut appeared = false;
        for _ in 0..100 {
            let (_, alerts) = scanner.alerts_view(&[]);
            if alerts.iter().any(|a| a.value == token) {
                appeared = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            appeared,
            "token in over-budget (but under-cap) leaf must still be scanned"
        );
        // 单叶超上限 (3MB > MAX_LEAF_BYTES): 跳过 — 唯一叶子被跳过后载荷为空,
        // capture 返回 None (空载荷不占 channel 配额), token 不可能告警.
        let huge: String = "y".repeat(3 * 1024 * 1024);
        let token2 = aws_key("HUGELEAF00000002");
        let ir2 = sample_ir_with(&format!("{huge} {token2}"));
        assert!(
            scanner.capture(&ir2).is_none(),
            "oversize sole leaf => empty payload => None"
        );
        let (_, alerts) = scanner.alerts_view(&[]);
        assert!(
            alerts.iter().all(|a| a.value != token2),
            "token in oversize leaf is skipped"
        );
    }
}
