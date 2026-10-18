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
//! **context 字段对登记值遮盖 (SEC-1 裁决前提的技术保证, 2026-10-10)**:
//! 告警 context 是 pre-redact 原文的 ±40 char 窗口, 窗口内可能含已登记
//! secret 明文 — 登记值的**完整出现**经遮盖不进回显面: 生成时先在完整叶子
//! 上把所有登记值遮盖为 `[managed]` 占位符再取窗口 (实现 = 模块内
//! `MaskedLeaf`, 顺序不可倒 — 先截后盖会半截泄漏; 与 redact 管道同语义的
//! 截断片段等残余例外见 docs/known-limitations.md). 疑似值明文回显是裁决
//! 明确允许的, 不遮.
//!
//! # 告警状态机 (R2, PR #303 review)
//!
//! 扫描点在 redact seam (pre-redact) — 每条告警背后是一次**疑似已发生的
//! 外发** (除非 fail_closed 拒绝). 因此告警带三态 status (`Active` 默认 /
//! `Rotated` 用户已在平台侧吊销轮换 / `Ignored` 误报), 由用户经
//! `POST /api/privacy-scan/alerts/{id}/rotated|ignored` 显式流转.
//! 防打扰语义: 同 (value, pattern) 的后续命中**只静默累计** hit_count /
//! last_seen / context, **永不回退 status** — "已轮换的值仍在请求中出现"
//! (旧工具还在用死值) 是重要诊断信号, 用 hit_count 保留; 重新打扰用户的
//! 唯一途径是 FIFO 容量淘汰后同值再命中 (新建 Active, 见已知限制).
//!
//! # pattern 分组与组开关 (R3, PR #303 review)
//!
//! 10 条 pattern 归入 5 个语义组 (`PatternGroup`: cloud / ai / vcs / chat /
//! crypto), 组开关是**动态设置** (state.toml 持久化, WebUI 即时切换, 运行时
//! 态 SSOT = `state::PrivacyScanGroups`) — 经共享 `Arc<AtomicU32>` 位掩码
//! 送达本模块: 后台 task 每次 scan_job 读一次快照 (关组 pattern 不扫描),
//! alerts 视图同闸门 (关组的历史告警隐藏, 重开自然重现; store 不清).
//! 组开关只收窄 pattern 生效面, **不能越过 mode=off** (off 时扫描器是空壳,
//! 一切不发生; settings 端点 GET 返回 enabled:false, PUT 拒绝).
//! 不做的边界 (如实登记): 用户自定义正则 pattern 不做 (regex crate 不进
//! 产线依赖); 组的增删不做 (内置 5 组).
//!
//! # 已知限制 (best-effort, 详见 docs/known-limitations.md privacy-scan 节)
//!
//! - 告警为内存态, 重启清空 (不落盘, 一次会话内验证闭环足够) — status /
//!   Rotated/Ignored 标记同样随重启丢失.
//! - Gemini/Ollama 字节透传族无 codec IR, 不扫描.
//! - 正则形状判定有误报可能 (告警非定罪); 通用 high-entropy 长串**刻意不做**
//!   (误报不可控, 留给 Laya S1+).
//! - `realtime` 档位属 Laya S2, 不实现不预留枚举值.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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

/// context 窗口内**已登记** secret 值的遮盖占位符 (SEC-1: 登记值的完整
/// 出现不进回显面 — 见 [`MaskedLeaf`] 文档. 数据常量, 非 UI 文案, i18n 无关).
const MANAGED_PLACEHOLDER: &str = "[managed]";

// ─── pattern 集 (手写字节扫描, 零依赖) ─────────────────────────────────────

/// pattern 的语义分组 (R3, PR #303 review): 组开关 (`/api/privacy-scan/settings`)
/// 的控制粒度. 组名是 wire/存储/i18n 的稳定 id; 组集**内置固定** (增删组 =
/// 改本枚举 + PATTERNS 表, 不支持用户自定义).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PatternGroup {
    /// 云平台凭据 (AWS key id / AWS secret / Google API key).
    Cloud,
    /// AI 服务商凭据 (OpenAI / Anthropic).
    Ai,
    /// 代码托管 token (GitHub / GitLab).
    Vcs,
    /// 聊天平台 token (Slack).
    Chat,
    /// 加密凭据形状 (JWT / PEM 私钥).
    Crypto,
}

impl PatternGroup {
    /// 规范序全集 (wire/存储遍历序; mask bit = 索引位).
    pub(crate) const ALL: [PatternGroup; 5] = [
        PatternGroup::Cloud,
        PatternGroup::Ai,
        PatternGroup::Vcs,
        PatternGroup::Chat,
        PatternGroup::Crypto,
    ];

    /// 全组启用的位掩码 (缺省态).
    pub(crate) const ALL_MASK: u32 = 0b1_1111;

    pub(crate) const fn name(self) -> &'static str {
        match self {
            PatternGroup::Cloud => "cloud",
            PatternGroup::Ai => "ai",
            PatternGroup::Vcs => "vcs",
            PatternGroup::Chat => "chat",
            PatternGroup::Crypto => "crypto",
        }
    }

    /// 组名 → 枚举 (PUT body / state.toml 的 key 校验; 未知名 = None).
    pub(crate) fn from_name(name: &str) -> Option<PatternGroup> {
        Self::ALL.iter().copied().find(|g| g.name() == name)
    }

    /// 该组在 mask 中的启用位.
    pub(crate) const fn bit(self) -> u32 {
        1 << (self as u32)
    }

    /// mask 下该组是否启用.
    pub(crate) const fn enabled_in(self, mask: u32) -> bool {
        mask & self.bit() != 0
    }
}

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

/// 内置 pattern 表 (const, 添加新形状 = 加一行 + 单测正/负例). `group` 是
/// R3 组开关的控制粒度 (见 [`PatternGroup`]).
pub(crate) struct PatternDef {
    pub id: &'static str,
    pub label: &'static str,
    pub group: PatternGroup,
    find: fn(&str) -> Vec<Span>,
}

pub(crate) const PATTERNS: &[PatternDef] = &[
    PatternDef {
        id: "aws-access-key-id",
        label: "AWS Access Key ID",
        group: PatternGroup::Cloud,
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
        group: PatternGroup::Cloud,
        find: find_aws_secret,
    },
    PatternDef {
        id: "github-token",
        label: "GitHub token",
        group: PatternGroup::Vcs,
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
        group: PatternGroup::Vcs,
        find: |s| find_prefixed(s, &["glpat-"], is_wordish, RunLen::AtLeast(20)),
    },
    PatternDef {
        id: "slack-token",
        label: "Slack token",
        group: PatternGroup::Chat,
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
        group: PatternGroup::Ai,
        find: find_openai,
    },
    PatternDef {
        id: "anthropic-api-key",
        label: "Anthropic API key",
        group: PatternGroup::Ai,
        find: |s| find_prefixed(s, &["sk-ant-"], is_wordish, RunLen::AtLeast(20)),
    },
    PatternDef {
        id: "google-api-key",
        label: "Google API key",
        group: PatternGroup::Cloud,
        find: |s| find_prefixed(s, &["AIza"], is_wordish, RunLen::Exact(35)),
    },
    PatternDef {
        id: "jwt",
        label: "JWT",
        group: PatternGroup::Crypto,
        find: find_jwt,
    },
    PatternDef {
        id: "pem-private-key",
        label: "PEM private key",
        group: PatternGroup::Crypto,
        find: find_pem,
    },
];

/// 值是否命中任一 pattern (组开关不参与 — 调用方语义是 "形状是否可被识别").
/// 供 protect 模块 "mock 对 privacy 不可见" 前提的测试复用 (pattern 引擎端到端断言,
/// 防 pattern 集未来加入通用形状规则时静默破坏 protect 的强制 Plain 前提).
#[cfg(test)]
pub(crate) fn matches_any_pattern(s: &str) -> bool {
    PATTERNS.iter().any(|p| !(p.find)(s).is_empty())
}

// ─── 告警存储 ───────────────────────────────────────────────────────────────

/// 告警处置状态 (R2 状态机, 见模块头「告警状态机」节; 序列化 wire = 小写串).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AlertStatus {
    /// 未处置 (默认). 背后是一次疑似已发生的外发, 待用户轮换/登记/忽略.
    Active,
    /// 用户已在对应平台吊销/轮换该值 — 处置完成, 后续命中只静默累计.
    Rotated,
    /// 用户判定误报 — 不再打扰, 后续命中只静默累计.
    Ignored,
}

/// 告警的稳定短 id: hash(value, pattern_id) 的 hex 前 16 字符. 用 hash 而非
/// 原值作 URL path 参数, 避免疑似明文裸进 URL (access log / 浏览器历史).
/// **进程内**确定 (per-process 随机 key 的 `RandomState`, 见 `alert_id` 实现 —
/// 无键 `DefaultHasher` 会让 URL 观察者可对候选 secret 值做离线穷举确认,
/// 随机 key 消除该 oracle; 跨进程本就无需稳定 — 告警是内存态). 256 容量下
/// 64-bit 碰撞概率可忽略.
pub(crate) fn alert_id(value: &str, pattern_id: &str) -> String {
    use std::hash::BuildHasher;
    static KEYS: std::sync::OnceLock<std::collections::hash_map::RandomState> =
        std::sync::OnceLock::new();
    let h = KEYS
        .get_or_init(std::collections::hash_map::RandomState::new)
        .hash_one((value, pattern_id));
    format!("{h:016x}")
}

/// 一条告警 (同 value+pattern 去重合并: hit_count / last_seen / context 更新,
/// first_seen 保留首次, status 只经用户动作端点流转 — 见 [`AlertStatus`]).
/// `pattern_id` 恒来自 [`PATTERNS`] 的 `&'static str`.
#[derive(Debug, Clone)]
pub(crate) struct Alert {
    pub value: String,
    pub pattern_id: &'static str,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub hit_count: u64,
    pub context: String,
    pub status: AlertStatus,
}

/// 内存告警存储: `VecDeque` + 容量 FIFO 淘汰. 不落盘 (重启清空, 见模块头
/// 已知限制).
#[derive(Debug, Default)]
pub(crate) struct AlertStore {
    alerts: VecDeque<Alert>,
}

impl AlertStore {
    /// 记录一次命中: 已存在 (value, pattern_id) 则合并 (status 不回退, 见
    /// 模块头防打扰语义), 否则插入 Active 新告警; 超容从队头淘汰.
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
            status: AlertStatus::Active,
        });
    }

    /// 当前告警快照 (新→旧, 最近的在前 — 面板默认最关心最新命中).
    pub(crate) fn snapshot(&self) -> Vec<Alert> {
        self.alerts.iter().rev().cloned().collect()
    }

    /// 用户动作端点的落点: 按 id 流转 status. 返回是否命中 (未知 id = false,
    /// 调用方回 404). 对 Active 告警重复标记同状态是幂等 no-op.
    pub(crate) fn set_status(&mut self, id: &str, status: AlertStatus) -> bool {
        let Some(a) = self
            .alerts
            .iter_mut()
            .find(|a| alert_id(&a.value, a.pattern_id) == id)
        else {
            return false;
        };
        a.status = status;
        true
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
/// `groups_mask` 是组开关 (`PatternGroup`) 的共享位掩码 — 与
/// `state::PrivacyScanGroups` (写侧: PUT 持久化 + 内存) 共享同一 `Arc<AtomicU32>`
/// (读侧: 后台 task 每次扫描 + alerts 视图过滤, 读多写少零锁竞争).
///
/// Clone 语义: 内壳 Arc 共享 (sender + store + mask), 与 `PoolStates` /
/// `ModelListCache` 的 "state 聚合各 feature store" 先例同型.
#[derive(Clone, Debug)]
pub struct PrivacyScanner {
    inner: Option<Arc<ScannerInner>>,
}

#[derive(Debug)]
struct ScannerInner {
    tx: tokio::sync::mpsc::Sender<ScanJob>,
    store: Arc<Mutex<AlertStore>>,
    /// 组开关位掩码 (写侧 = state::PrivacyScanGroups; 1 = 组启用).
    groups_mask: Arc<AtomicU32>,
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
    /// `mode = batch`: spawn 后台 task. 需在 tokio runtime 内调用. `groups_mask`
    /// 通常来自 `state::PrivacyScanGroups::mask_handle` (与写侧共享); 测试可用
    /// `Arc::new(AtomicU32::new(PatternGroup::ALL_MASK))`.
    pub fn new(groups_mask: Arc<AtomicU32>) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ScanJob>(CHANNEL_CAP);
        let store = Arc::new(Mutex::new(AlertStore::default()));
        let dropped = Arc::new(AtomicU64::new(0));
        let task_store = store.clone();
        let task_dropped = dropped.clone();
        let task_mask = groups_mask.clone();
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                // 组态快照: 每 job 读一次 (关组的 pattern 不参与扫描 — 热路径
                // 侧 capture 不感知组, 组过滤集中在后台消费侧).
                let mask = task_mask.load(Ordering::Relaxed);
                scan_job(&job, &task_store, mask);
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
            inner: Some(Arc::new(ScannerInner {
                tx,
                store,
                groups_mask,
                dropped,
            })),
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

    /// API 视图: 告警快照过滤 ① 当前已登记值 (`registered` = effective
    /// secrets 值集) ② 当前关组的 pattern (组开关对已有告警同样生效 — 关组
    /// = "这个维度整体不要打扰", 旧告警隐藏; 重开组后经快照自然重现).
    /// 返回 (enabled, alerts) — enabled 让前端隐藏整个面板, 区分 "没扫到"
    /// 与 "没开启".
    pub(crate) fn alerts_view(&self, registered: &[String]) -> (bool, Vec<AlertDto>) {
        let Some(inner) = &self.inner else {
            return (false, Vec::new());
        };
        let mask = inner.groups_mask.load(Ordering::Relaxed);
        let snapshot = inner.store.lock().snapshot();
        let alerts = snapshot
            .into_iter()
            .filter(|a| !registered.iter().any(|r| r == &a.value))
            .filter_map(|a| {
                let p = PATTERNS.iter().find(|p| p.id == a.pattern_id)?;
                if !p.group.enabled_in(mask) {
                    return None;
                }
                Some(AlertDto {
                    id: alert_id(&a.value, a.pattern_id),
                    value: a.value,
                    pattern_id: a.pattern_id.to_string(),
                    pattern_label: p.label.to_string(),
                    group: p.group.name(),
                    status: a.status,
                    first_seen: a.first_seen,
                    last_seen: a.last_seen,
                    hit_count: a.hit_count,
                    context: a.context,
                })
            })
            .collect();
        (true, alerts)
    }

    /// 用户动作 (R2 状态机流转): 按 id 标记 Rotated/Ignored. `None` = 扫描器
    /// 关闭 (off 档无告警可标, 调用方回 404 同语义); `Some(false)` = 未知 id.
    pub(crate) fn mark_alert(&self, id: &str, status: AlertStatus) -> Option<bool> {
        let inner = self.inner.as_ref()?;
        Some(inner.store.lock().set_status(id, status))
    }
}

/// 后台 task 的单 job 处理: 每叶子 × 每启用 pattern 匹配 → 排除已登记 →
/// 记录. 关组 (`mask` 位清零) 的 pattern 跳过 — 组过滤的扫描侧落点.
/// 匹配阶段无锁 (大 job 不阻塞 alerts API 读), 仅落账时短临界区.
/// context 生成走 [`MaskedLeaf`] (先遮盖登记值再取窗口, SEC-1), 匹配本身
/// 仍在**原始叶子**上进行 (遮盖不得影响疑似值的检出).
fn scan_job(job: &ScanJob, store: &Mutex<AlertStore>, groups_mask: u32) {
    let now = Utc::now();
    // (value, pattern_id, context) — 先算后锁.
    let mut hits: Vec<(String, &'static str, String)> = Vec::new();
    for leaf in &job.leaves {
        // 遮盖视图 lazy 构建: 首个非排除命中时才建 (无命中叶子占绝对多数,
        // 零遮盖开销); 每叶至多一次.
        let mut masked: Option<MaskedLeaf> = None;
        for pattern in PATTERNS {
            if !pattern.group.enabled_in(groups_mask) {
                continue;
            }
            for (start, end) in (pattern.find)(leaf) {
                let value = match leaf.get(start..end) {
                    Some(v) => v,
                    // 理论不可达 (ASCII 锚定 ⇒ 端点必在 boundary); ROB 兜底跳过.
                    None => continue,
                };
                if job.excluded.iter().any(|x| x == value) {
                    continue;
                }
                let m = masked.get_or_insert_with(|| MaskedLeaf::new(leaf, &job.excluded));
                hits.push((value.to_string(), pattern.id, m.context_around(start, end)));
            }
        }
    }
    let mut guard = store.lock();
    for (value, pattern_id, context) in hits {
        guard.record(value, pattern_id, context, now);
    }
}

/// 叶子的**登记值遮盖视图**: 先在完整叶子上把所有 `excluded` (已登记值,
/// 与匹配排除集同源 SSOT) 的出现区间遮盖为 [`MANAGED_PLACEHOLDER`], 再在
/// 遮盖文本上取 context 窗口 — **顺序不可倒** (SEC-1, 2026-10-10 验收缺口).
///
/// # 为什么先遮盖后取窗口
///
/// 若先截 ±40 char 窗口再替换, 窗口边界与登记值交叉会把值截成两半, 完整值
/// 匹配永远命不中, 半截明文前缀直接回显 (验收实录: 39-char 登记值被右边界
/// 截出 30-char 前缀). 先遮盖后取窗口: 窗口边界最多截到占位符中间, 登记值
/// 的完整出现不出现在窗口文本中.
///
/// # 重叠处理 (区间并集)
///
/// 多个登记值互为子串 / 区间交叠时 (长值含短值, 值 A 尾接值 B 头), 逐值独立
/// 替换会留残留 (短值先替换, 长值匹配失败, 尾巴泄漏). 收集全部出现区间后做
/// **并集合并**, 每个连通区间整体替换为一个占位符 — 遮盖文本中不含任何登记
/// 值的**完整出现**. 三种已接受的例外形态: (i) 源文本含登记值的**截断片段**
/// 与 (ii) 周期值的 tiling 残余 — 与 redact 管道 `replace_all` 同语义, context
/// 回显不差于 wire 侧; (iii) 登记值恰为占位符 `[managed]` 子串的病态配置 —
/// context 侧独有 (wire 的 mock 按契约不含 secret 子串), 但占位符是公开
/// 常量, 出现不携带 secret 信息增量, 独立成立可接受. 三者详见
/// docs/known-limitations.md privacy-scan 节.
///
/// # 与疑似值的关系 (如实呈现)
///
/// 疑似值的**匹配**在原始叶子完成 (遮盖不参与检出); context 展示时疑似值
/// 取遮盖文本中的对应片段 — 若疑似值内嵌登记值 (理论 case: ghp_ 串里含
/// sk- 值), 该处呈现为占位符, 疑似值的完整性让位于登记值不泄漏 (裁决允许
/// 疑似值明文, 但不允许登记值明文; span 平移见 [`MaskedLeaf::map_pos`]).
struct MaskedLeaf {
    /// 遮盖后的叶子文本 (登记值区间已替换为 [`MANAGED_PLACEHOLDER`]).
    text: String,
    /// 遮盖区间表 (原始叶子坐标系, 有序不重叠): 每项是**合并后**的连通区间.
    edits: Vec<Span>,
}

impl MaskedLeaf {
    /// 构建遮盖视图. `excluded` 与匹配排除集同源 ([`ScanJob::excluded`]);
    /// 空值跳过 — `match_indices` 对空串不死循环, 但会在每个 char boundary
    /// 产出 (i, i) 空区间, 重建产物逐 boundary 穿插占位符 (垃圾 context);
    /// 相邻空区间不满足合并条件 `s <= last.1`, 并集不会吞并它们 (防御;
    /// 上游 `non_empty_values` 本就不产空值, 此分支是双保险).
    fn new(leaf: &str, excluded: &[String]) -> Self {
        // 1. 收集全部出现区间 (`match_indices` = 非重叠顺序匹配, 标准库
        //    保证终止 — 本模块手写推进循环有死循环前科, 能替代就替代;
        //    跨值重叠交给合并步).
        let mut spans: Vec<Span> = Vec::new();
        for v in excluded {
            if v.is_empty() {
                continue;
            }
            for (start, _) in leaf.match_indices(v.as_str()) {
                spans.push((start, start + v.len()));
            }
        }
        // 2. 并集合并 (同起点时长值覆盖短值由 max 端点达成).
        spans.sort_unstable();
        let mut edits: Vec<Span> = Vec::new();
        for (s, e) in spans {
            match edits.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => edits.push((s, e)),
            }
        }
        // 3. 逐段重建 (boundary 安全: str::find 的匹配端点天然在 char
        //    boundary — needle 是合法 UTF-8 序列, 自同步性保证).
        let mut text = String::with_capacity(leaf.len());
        let mut cursor = 0;
        for &(os, oe) in &edits {
            text.push_str(&leaf[cursor..os]);
            text.push_str(MANAGED_PLACEHOLDER);
            cursor = oe;
        }
        text.push_str(&leaf[cursor..]);
        Self { text, edits }
    }

    /// 原始叶子偏移 → 遮盖文本偏移 (span 平移). edit 完全在左 → 累积长度
    /// 差 (占位符 9 字节可短于被遮盖值, 差值可负 — 用 isize 累积; 和恒
    /// ≥ 0, 因 pos 必在全部左侧 edit 的右侧, 左侧 edits 总长 ≤ pos);
    /// `pos` 落在 edit 区间内部 (疑似值与登记值边界重叠的防御形态) →
    /// 钳到该 edit 在遮盖文本中的起点 (就近端点, 如实呈现语义下可接受);
    /// edit 在右 → 后续更靠右, 提前退出.
    fn map_pos(&self, pos: usize) -> usize {
        let mut delta: isize = 0;
        for &(os, oe) in &self.edits {
            if oe <= pos {
                delta += MANAGED_PLACEHOLDER.len() as isize - (oe - os) as isize;
            } else if os < pos {
                return (os as isize + delta) as usize;
            } else {
                break;
            }
        }
        (pos as isize + delta) as usize
    }

    /// 命中点上下文摘要 (遮盖文本坐标系): `…{before}{疑似值片段}{after}…` —
    /// 前后各 ≤CONTEXT_CHARS 字符 (char 计数截断, 复用 util 截断族), 发生
    /// 截断的侧加 `…` 标记. 疑似值片段取遮盖文本 (内嵌登记值处为占位符,
    /// 见类型文档 "如实呈现"; 极端形态 — 疑似值完全落在单个登记值内部 —
    /// 片段为空, context 呈现为占位符邻接). best-effort: 区间越界 (不可达)
    /// 时回退空串.
    fn context_around(&self, start: usize, end: usize) -> String {
        let (ms, me) = (self.map_pos(start), self.map_pos(end));
        let (before, mid, after) = match (
            self.text.get(..ms),
            self.text.get(ms..me),
            self.text.get(me..),
        ) {
            (Some(b), Some(m), Some(a)) => (b, m, a),
            _ => ("", "", ""),
        };
        let b = crate::util::truncate_chars(before, CONTEXT_CHARS);
        let a = crate::util::truncate_chars(after, CONTEXT_CHARS);
        let b_mark = if b.len() < before.len() { "…" } else { "" };
        let a_mark = if a.len() < after.len() { "…" } else { "" };
        format!("{b_mark}{b}{mid}{a}{a_mark}")
    }
}

/// `GET /api/privacy-scan/alerts` 的响应条目 (wire shape). `id` 是用户动作
/// 端点的路径参数 (hash 形态, 见 [`alert_id`]); `group` 是 pattern 语义组名
/// (API 可见性/调试 — 前端组开关回显走响应级 `groups` map, 不消费行级字段).
#[derive(Debug, Serialize)]
pub(crate) struct AlertDto {
    pub id: String,
    pub value: String,
    pub pattern_id: String,
    pub pattern_label: String,
    pub group: &'static str,
    pub status: AlertStatus,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub hit_count: u64,
    pub context: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用全组启用 mask (生产 mask 来自 state::PrivacyScanGroups 共享 Arc).
    fn test_mask() -> Arc<AtomicU32> {
        Arc::new(AtomicU32::new(PatternGroup::ALL_MASK))
    }

    // ─── R3 分组: 表完整性 + mask 消费 ───────────────────────────────────

    #[test]
    fn pattern_groups_cover_all_patterns_and_names_unique() {
        // 每条 pattern 都有归属组; 组名 (wire id) 互异; from_name 与 name 互逆.
        let mut names = std::collections::BTreeSet::new();
        for g in PatternGroup::ALL {
            assert!(names.insert(g.name()), "duplicate group name");
            assert_eq!(PatternGroup::from_name(g.name()), Some(g));
        }
        assert_eq!(names.len(), 5);
        assert!(PATTERNS.iter().all(|p| names.contains(p.group.name())));
        // 逐组断言归属 (分组即契约 — 调整分组应显式改这里).
        let ids_of = |g: PatternGroup| {
            PATTERNS
                .iter()
                .filter(|p| p.group == g)
                .map(|p| p.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ids_of(PatternGroup::Cloud),
            [
                "aws-access-key-id",
                "aws-secret-access-key",
                "google-api-key"
            ]
        );
        assert_eq!(
            ids_of(PatternGroup::Ai),
            ["openai-api-key", "anthropic-api-key"]
        );
        assert_eq!(ids_of(PatternGroup::Vcs), ["github-token", "gitlab-token"]);
        assert_eq!(ids_of(PatternGroup::Chat), ["slack-token"]);
        assert_eq!(ids_of(PatternGroup::Crypto), ["jwt", "pem-private-key"]);
        assert_eq!(
            PATTERNS.len(),
            10,
            "10 patterns across 5 groups (per-group id lists above are the contract)"
        );
        assert_eq!(PatternGroup::from_name("nope"), None);
    }

    /// mask 消费: 关 vcs → github/gitlab pattern 不产告警, aws (cloud) 仍报;
    /// alerts 视图对关组的历史告警同样过滤 (重开自然重现).
    #[tokio::test]
    async fn group_mask_gates_scanning_and_view() {
        let mask = test_mask();
        let scanner = PrivacyScanner::new(mask.clone());
        let aws = aws_key("GROUPMASKTEST01");
        let gh = format!("ghp_{}", "g".repeat(40));
        let ir = sample_ir_with(&format!("keys: {aws} {gh}"));

        // 关 vcs (github/gitlab 所在组).
        mask.store(
            PatternGroup::ALL_MASK & !PatternGroup::Vcs.bit(),
            Ordering::Relaxed,
        );
        let job = scanner.capture(&ir).unwrap();
        scanner.submit(Some(job), &[]);
        for _ in 0..100 {
            let (_, alerts) = scanner.alerts_view(&[]);
            if alerts.iter().any(|a| a.value == aws) {
                assert!(
                    alerts.iter().all(|a| a.value != gh),
                    "vcs-group (github) value must not alert while group off"
                );
                assert_eq!(
                    alerts.iter().find(|a| a.value == aws).unwrap().group,
                    "cloud",
                    "DTO carries group name"
                );
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("cloud-group alert never appeared with vcs off");
    }

    /// 全关 → 无告警; 已有告警在重开组后经视图自然重现 (store 仍在).
    #[tokio::test]
    async fn all_groups_off_then_reopen_recovers_view() {
        let mask = test_mask();
        let scanner = PrivacyScanner::new(mask.clone());
        let aws = aws_key("ALLMASKTEST0002");

        // 先全开扫一枪 → 告警在场.
        let ir = sample_ir_with(&aws);
        scanner.submit(Some(scanner.capture(&ir).unwrap()), &[]);
        for _ in 0..100 {
            let (_, alerts) = scanner.alerts_view(&[]);
            if alerts.iter().any(|a| a.value == aws) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // 全关: 视图为空 (扫描侧与视图侧双层闸门).
        mask.store(0, Ordering::Relaxed);
        let (_, alerts) = scanner.alerts_view(&[]);
        assert!(alerts.is_empty(), "all groups off hides everything");

        // 重开 cloud: 告警自然重现 (store 未清 — 组开关只是视图/扫描闸门).
        mask.store(PatternGroup::Cloud.bit(), Ordering::Relaxed);
        let (_, alerts) = scanner.alerts_view(&[]);
        assert!(alerts.iter().any(|a| a.value == aws));
    }

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

    // ─── R2 状态机: id 稳定性 + 流转 + 防打扰 ────────────────────────────

    #[test]
    fn alert_id_is_stable_and_pattern_sensitive() {
        let a = alert_id("some-value", "jwt");
        assert_eq!(a.len(), 16, "16-hex short id");
        assert_eq!(alert_id("some-value", "jwt"), a, "same input → same id");
        assert_ne!(alert_id("some-value", "openai-api-key"), a);
        assert_ne!(alert_id("other-value", "jwt"), a);
    }

    #[test]
    fn set_status_transitions_and_unknown_id_misses() {
        let mut s = AlertStore::default();
        let t0 = Utc::now();
        s.record("v1".into(), "jwt", String::new(), t0);
        let id = alert_id("v1", "jwt");
        assert!(matches!(s.snapshot()[0].status, AlertStatus::Active));
        assert!(s.set_status(&id, AlertStatus::Rotated));
        assert!(matches!(s.snapshot()[0].status, AlertStatus::Rotated));
        // 幂等重复标记.
        assert!(s.set_status(&id, AlertStatus::Rotated));
        assert!(!s.set_status("deadbeefdeadbeef", AlertStatus::Ignored));
    }

    /// 防打扰语义 (R2 核心): Rotated/Ignored 后同 (value, pattern) 的后续命中
    /// 只静默累计 hit_count/last_seen, **status 永不回退 Active** — 保留
    /// "已轮换的值仍在请求中出现" 的诊断信号而不重新打扰用户.
    #[test]
    fn subsequent_hits_never_regress_terminal_status() {
        let mut s = AlertStore::default();
        let t0 = Utc::now();
        s.record("v1".into(), "jwt", "ctx-1".into(), t0);
        s.set_status(&alert_id("v1", "jwt"), AlertStatus::Rotated);
        s.record(
            "v1".into(),
            "jwt",
            "ctx-2".into(),
            t0 + chrono::Duration::seconds(30),
        );
        let a = &s.snapshot()[0];
        assert!(matches!(a.status, AlertStatus::Rotated), "status kept");
        assert_eq!(a.hit_count, 2, "hit_count silently accumulates");
        assert_eq!(a.last_seen, t0 + chrono::Duration::seconds(30));
        assert_eq!(a.context, "ctx-2", "context keeps latest sighting");
        // Ignored 同型.
        s.set_status(&alert_id("v1", "jwt"), AlertStatus::Ignored);
        s.record("v1".into(), "jwt", String::new(), t0);
        assert!(matches!(s.snapshot()[0].status, AlertStatus::Ignored));
        // 不同 pattern 的同值是独立告警, 不受流转影响.
        s.record("v1".into(), "openai-api-key", String::new(), t0);
        assert_eq!(s.snapshot().len(), 2);
        assert!(matches!(
            s.snapshot()
                .iter()
                .find(|a| a.pattern_id == "openai-api-key")
                .unwrap()
                .status,
            AlertStatus::Active
        ));
    }

    // ─── context 截断 (char-boundary) + 登记值遮盖 (SEC-1) ────────────────

    /// 防假绿断言: 登记值的任意 ≥8 字符前缀不得残留在 context. 定向于前缀
    /// 是完备的 — 窗口截断 (`truncate_chars`) 取前缀, before/after 两侧的
    /// 截断留下的都是登记值前缀 (头部保留/尾部丢弃), "替换了但被窗口边界
    /// 截断残留" 的半截泄漏必是前缀形态. 阈值 8: 更短的前缀 ("sk-"/"ghp_"
    /// 等公共词干) 会误伤正常文本造成假红. `&registered[..n]` 切片假设
    /// registered 为 ASCII (当前调用点全部满足; 多字节值需 char_indices).
    #[track_caller]
    fn assert_no_registered_prefix_leak(ctx: &str, registered: &str, label: &str) {
        for n in 8..=registered.len() {
            assert!(
                !ctx.contains(&registered[..n]),
                "{label}: leaks registered prefix ({} chars): {}",
                n,
                ctx
            );
        }
    }

    #[test]
    fn context_truncates_on_char_boundary() {
        // 前后各塞 100 个 CJK 字符 (3 bytes each), 命中点居中. excluded 为空
        // (edits 空 → 遮盖文本 == 原文, 平移恒等) — 行为与遮盖前逐字节一致.
        let pad: String = "汉".repeat(100);
        let leaf = format!("{pad}TOKEN{pad}");
        let start = leaf.find("TOKEN").unwrap();
        let masked = MaskedLeaf::new(&leaf, &[]);
        let ctx = masked.context_around(start, start + 5);
        assert!(ctx.starts_with('…'), "head truncation marker");
        assert!(ctx.ends_with('…'), "tail truncation marker");
        assert!(ctx.contains("TOKEN"), "value embedded inline");
        // 两侧各 ≤ 40 chars + markers + token.
        let side = ctx.split("TOKEN").collect::<Vec<_>>();
        assert!(side[0].chars().count() <= 41, "before side within budget");
        assert!(side[1].chars().count() <= 41, "after side within budget");
        // 短上下文 (无截断) 不加 marker.
        let short = MaskedLeaf::new("a TOKEN b", &[]).context_around(2, 7);
        assert_eq!(short, "a TOKEN b");
        // 防御: excluded 含空串不得挂死 (空串 find 恒命中起点, 推进死循环).
        let _ = MaskedLeaf::new("a TOKEN b", &[String::new()]).context_around(2, 7);
    }

    /// SEC-1 遮盖: 登记值与 ±40 char 窗口边界的三种交叉形态, 全部不得在
    /// context 中留下登记值明文 (任意 ≥8 字符前缀扫描, 防半截残留假绿).
    /// 命中值用 ghp_ token (Vcs 组, 独立于登记值形状).
    #[test]
    fn context_masks_registered_secret_across_window_boundaries() {
        let registered = "sk-registered-SECRET-do-not-leak-000000"; // 39 chars
        let gh = format!("ghp_{}", "F".repeat(44));
        let gh_span = |leaf: &str| {
            let s = leaf.find(&gh).expect("token in leaf");
            (s, s + gh.len())
        };
        // 跨左边界: before = "My key is {39 chars} and also " (59 chars > 40),
        // 截断点落在登记值内部 (2026-10-10 验收复现形态).
        let left = format!("My key is {registered} and also {gh}");
        // 跨右边界: after = " t "(3) + pad(17) + 登记值, 截断点 40 落在
        // 登记值内部 (3 + 17 = 20 < 40 < 20 + 39).
        let right = format!("{gh} t {}{registered}", "p".repeat(17));
        // 恰好填满: before = "x" + 登记值 = 40 chars, 不截断, 整值在窗口内.
        let fills = format!("x{registered} {gh}");
        for (name, leaf) in [
            ("crosses-left-boundary", &left),
            ("crosses-right-boundary", &right),
            ("fills-window-exactly", &fills),
        ] {
            let (s, e) = gh_span(leaf);
            let masked = MaskedLeaf::new(leaf, &[registered.to_string()]);
            let ctx = masked.context_around(s, e);
            assert!(
                ctx.contains("[managed]"),
                "{name}: placeholder present: {ctx}"
            );
            assert!(ctx.contains(&gh), "{name}: suspect value intact: {ctx}");
            assert_no_registered_prefix_leak(&ctx, registered, name);
        }
    }

    /// SEC-1 遮盖的重叠防御: 同一段文本被两个登记值交叠命中 (值 A = 前缀段,
    /// 值 B = 后缀段, 区间交叠) — 并集合并整段遮盖, 逐值独立替换会留尾巴
    /// (A 先替换后 B 匹配不到, B 的独有尾部残留). 全子串扫描一网打尽.
    /// 另覆盖包含形态 (值 A 整体含值 B, B 仅在 A 内出现).
    #[test]
    fn context_masks_overlapping_registered_values_union() {
        // T 同时含 A (头部 20 chars) 与 B (第 13 字符起到尾) 为子串, 区间交叠.
        let t = "sk-overlap-long-value-0000000011111";
        let a = &t[..20];
        let b = &t[12..];
        let gh = format!("ghp_{}", "F".repeat(44));
        let leaf = format!("found {t} then {gh}");
        let s = leaf.find(&gh).unwrap();
        // 交叠形态: [A, B] — 并集 = T 的整段区间.
        let masked = MaskedLeaf::new(&leaf, &[a.to_string(), b.to_string()]);
        let ctx = masked.context_around(s, s + gh.len());
        // 并集整段遮盖: T 的位置呈现单个占位符.
        assert!(
            ctx.contains("found [managed] then"),
            "union masked as one placeholder: {ctx}"
        );
        // T 的任意 ≥8 字符子串 (含 B 独有尾部) 不得残留.
        for i in 0..t.len() {
            for j in (i + 8)..=t.len() {
                assert!(
                    !ctx.contains(&t[i..j]),
                    "overlap union leaves residue {:?}: {}",
                    &t[i..j],
                    ctx
                );
            }
        }
        // 包含形态: 值 super 整体含值 sub, sub 仅在 super 内出现 —
        // 并集吞并 sub 的 span, 单占位符, sub 无独立残留.
        let super_val = "sk-container-of-a-shorter-value-000001";
        let sub_val = &super_val[3..25];
        let leaf2 = format!("k {super_val} t {gh}");
        let s2 = leaf2.find(&gh).unwrap();
        let masked2 = MaskedLeaf::new(&leaf2, &[super_val.to_string(), sub_val.to_string()]);
        let ctx2 = masked2.context_around(s2, s2 + gh.len());
        assert!(
            ctx2.contains("k [managed] t"),
            "containment union masked as one placeholder: {ctx2}"
        );
        assert_no_registered_prefix_leak(&ctx2, super_val, "containment");
    }

    /// 如实呈现 (防御形态): 疑似值内嵌登记值为子串 (理论 case: ghp_ 串里含
    /// sk- 值) — 匹配在原始文本完成 (检出不受遮盖影响), context 中疑似值
    /// 的该处呈现为占位符, 两端片段保留; 疑似值整体仍在 value 字段明文
    /// 回显 (SEC-1 裁决允许疑似值). 登记值取纯 alnum (含 `-`/`_` 会截断
    /// github-token 的 run 形状, 干扰检出断言).
    #[test]
    fn context_presents_placeholder_inside_suspect_value() {
        let registered = "skembedSECRETvalue00000000000000000000"; // 38 chars alnum
        let suspect = format!("ghp_{registered}tail123"); // run 45 ≥ 36 ✓
        let leaf = format!("leak: {suspect} end");
        let s = leaf.find(&suspect).unwrap();
        let e = s + suspect.len();
        // 匹配在原始叶子: pattern 必须能检出疑似值 (遮盖不参与检出).
        assert_eq!(
            hits("github-token", &leaf),
            vec![suspect.clone()],
            "matching runs on raw leaf"
        );
        let masked = MaskedLeaf::new(&leaf, &[registered.to_string()]);
        let ctx = masked.context_around(s, e);
        // 疑似值片段中登记值位置呈现占位符, 两端片段保留.
        assert!(
            ctx.contains("ghp_[managed]tail123"),
            "suspect fragment shows placeholder in place of registered: {ctx}"
        );
        assert_no_registered_prefix_leak(&ctx, registered, "embedded");
    }

    /// `map_pos` 钳制分支 (review 补): 疑似值**完全落在单个登记值内部**
    /// (登记值 = 长 token 形状串, 内嵌 AKIA 命中) — span 双端都落在同一
    /// edit 内, 双侧钳到同点 → mid 为空, context 呈现占位符邻接. 检出
    /// 仍在原始叶子发生 (span 不因遮盖丢失), 展示让位于登记值不泄漏.
    #[test]
    fn context_hit_entirely_inside_registered_value_clamps_to_placeholder() {
        // 登记值内嵌可检出的 AKIA 形状: '[' 非 alnum 满足左边界, ']' 不在
        // charset 内截断 run 恰 16.
        let registered = "[AKIAQQQQQQQQQQQQQQQQ]key-secret-value-0000";
        let suspect = "AKIAQQQQQQQQQQQQQQQQ";
        let leaf = format!("leak {registered} end");
        // 检出在原始叶子: AKIA pattern 必须命中 (span ⊂ 登记值).
        assert_eq!(
            hits("aws-access-key-id", &leaf),
            vec![suspect.to_string()],
            "matching runs on raw leaf even inside a registered value"
        );
        let s = leaf.find(suspect).unwrap();
        let e = s + suspect.len();
        let masked = MaskedLeaf::new(&leaf, &[registered.to_string()]);
        let ctx = masked.context_around(s, e);
        // mid 收缩为空: 登记值整体呈现为占位符, 疑似值不内嵌 (它本就是
        // 登记值的内部片段, value 列已回显完整明文 — 裁决允许).
        assert!(
            ctx.contains("[managed]"),
            "registered value shown as placeholder: {ctx}"
        );
        assert!(
            !ctx.contains(suspect),
            "suspect inline fragment is empty: {ctx}"
        );
        assert_no_registered_prefix_leak(&ctx, registered, "clamped");
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
            strategy: crate::secrets::SecretStrategy::default(),
        }
    }

    #[tokio::test]
    async fn scanner_end_to_end_excludes_registered_values() {
        let scanner = PrivacyScanner::new(test_mask());
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

    /// SEC-1 (context 遮盖): 告警 context 是 pre-redact 原文的 ±40 char 窗口,
    /// 窗口内可能含**已登记** secret 明文 (复现: 2026-10-10 验收, 窗口右边界
    /// 把 39-char 登记值截成 30-char 前缀回显). 裁决前提是 "回显的是疑似值,
    /// 不是登记 secret" — context 必须把窗口内登记值遮盖为占位符.
    /// 防假绿: 除断言占位符在场, 还对登记值做 **≥8 字符前缀全扫描** (防
    /// "替换了但被窗口边界截断残留" 的半截泄漏).
    #[tokio::test]
    async fn alert_context_masks_registered_secret_in_window() {
        let scanner = PrivacyScanner::new(test_mask());
        let registered = "sk-registered-SECRET-do-not-leak-000000"; // 39 chars
        let gh = format!("ghp_{}", "F".repeat(44));
        // before 窗口 = "My key is {registered} and also " (59 chars > 40):
        // 截断点落在 registered 内部 (左边界交叉形态, 即验收复现).
        let ir = sample_ir_with(&format!("My key is {registered} and also {gh}"));
        let job = scanner.capture(&ir).unwrap();
        scanner.submit(Some(job), &[registered_secret(registered)]);
        for _ in 0..100 {
            let (_, alerts) = scanner.alerts_view(&[]);
            if let Some(a) = alerts.iter().find(|a| a.value == gh) {
                assert!(
                    a.context.contains("[managed]"),
                    "context must mask registered value, got: {}",
                    a.context
                );
                assert_no_registered_prefix_leak(&a.context, registered, "e2e");
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("github-token alert never appeared");
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
        let scanner = PrivacyScanner::new(test_mask());
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
        let scanner = PrivacyScanner::new(test_mask());
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
