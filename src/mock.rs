//! Mock 策略: 为每个 secret 配置 redact 用的 mock 生成方式 (两维度正交).
//!
//! # 两维度
//!
//! 1. **初始值** ([`InitialValue`]): `Auto` (系统按 gen spec 生成) 或
//!    `Fixed { value }` (用户固定值; 冲突时加 `_1`/`_2`... 后缀 probing).
//! 2. **生成策略** ([`GenSpec`]): `prefix` + `charset` + `length_range`.
//!
//! # 确定性 (C3 前缀缓存友好性)
//!
//! 候选序列由 [`deterministic_seed`] 驱动 — 同一 `(real, strategy)` 总产生同一候选序列
//! (counter=0,1,2,...). 这是 C3 的根基: 多轮对话中同一 secret 的 mock 保持稳定,
//! 不破坏 LLM provider 的前缀缓存命中. 见 [`crate::redact`] 模块的 C3 契约.
//!
//! 候选序列稳定**不**意味着 "redact 总是产出同一个 mock". redact 时仍需满足 C2
//! (in-context uniqueness): 若候选 mock 已出现在当前请求 IR 中, 系统 probing 到序列的
//! 下一个候选 (counter 递增). 多数请求命中首项候选; 冲突时稳定跳到后续项, 后续项在多次
//! "首项冲突"的请求间也能共享前缀缓存.
//!
//! # 与 redact pipeline 的分工
//!
//! 本模块只负责 **候选生成** (给定策略 + seed + counter, 产出单个 mock 字符串).
//! C2 (不在 IR 中) 与 C4 (单射性) 的检查仍由 [`crate::redact::redact_ir`] 完成 —
//! 调用方按 probing 协议 (counter 递增) 消费本模块的候选, 直到找到合格的.
//!
//! # 向后兼容 + global_mock_prefix
//!
//! 未配置 `mock_strategy` 的旧 secret (`crate::secrets::SecretEntry`) 在 resolve 时
//! 自动得到 `MockStrategy::default_for` (Auto + infer 自 real 的 gen spec).
//! 行为尽可能接近原固定算法 (用 hash 生成等长 mock, charset 来自 real).
//!
//! `[redact] global_mock_prefix` (默认空串) 在 resolve 阶段注入到每个 secret 的
//! `gen_spec.prefix`, 让 Auto 模式生成的 mock 带统一可辨识前缀 (如 `"sgm_"`).
//! 空 prefix = mock 无前缀 (纯 hash body). 见 [`GenSpec::infer_default_for`].
//!
//! # C5: 不含 real_secret 子串 (实质确定性契约)
//!
//! C5 要求 mock 不含 real_secret 的**长**子串. 阈值 [`c5_threshold_len`] 随 real 长度 L
//! 自适应: `k(L) = max(4, ⌈L/3⌉)`. 设计依据 (信息论 + 业界 secret scanner 阈值):
//! - **短 secret (L ≤ 12)**: k=4. L=12 时信息比率 1/3, L=8 时 1/2, L<4 时 100%
//!   (此时退化为 [`MockStrategy::validate_against_real`] 的 `value == real` 检查).
//!   是 LLM reconstruct 与 secret scanner 阈值之上.
//! - **长 secret (L > 12)**: k=⌈L/3⌉, 单子串信息泄露率上界随 L 趋近 1/3 (因 div_ceil,
//!   实际峰值在 L=13 时约 36%, L mod 3=0 时恰为 1/3). 远低于 LLM reconstruct 所需的半数
//!   信息量, 也远低于 GitHub Secret Scanning / TruffleHog / gitleaks 最小匹配长度.
//! - 固定 k=4 对长 secret (real=23 base62) 在默认 proptest 下失败率 ≈ 4%; 固定 k=8 对短
//!   secret 几乎 trivially 成立但意义弱. k(L) 让阈值随 secret 长度走, 短强长弱, 总信息
//!   泄露率有上界.
//!
//! 即使有自适应阈值, 长 real + 高基数 charset 下单次 hash 生成仍有 ~1e-5 量级碰撞概率.
//! `gen_candidate` Auto 分支因此内置 **C5 内部重试链** (见 `C5_INTERNAL_RETRIES`):
//! 完全确定性地循环重 hash body 直到候选满足 C5. 重试上限 `C5_INTERNAL_RETRIES` = 10000
//! 是 **safety bound (仅防死循环)**, 非概率目标 — `(1e-5)^10000 = 1e-50000` 远超宇宙原子
//! 数 (~1e80), 因此 C5 在 Auto 模式下**实质等价于确定性契约**, 仅在理论上保留 best-effort
//! 兜底 (重试链耗尽时返回最后一次候选, 由上层 redact 的 C2/C4 probing 与下游 LLM provider
//! 兜底). 重试链不破坏 C3 (无副作用, 不消耗外部 counter).
//!
//! 本段是 C5 设计论据与概率数字的 **SSOT**, 其它位置 (如 [`c5_threshold_len`] 文档、
//! [`crate::redact`] 模块头部 C5 段) 只指针引用, 不重述.

use serde::{Deserialize, Serialize};

// ─── Charset ───────────────────────────────────────────────────────────────

/// 6 类正交字符集开关 + 自定义字符 (`other`).
///
/// `other` 收集 real secret 中出现但不属于 5 类标准字符的字符 (infer 时自动填充),
/// 让 infer 结果能完整覆盖 real 的字符使用情况. 用户也可手动添加任意字符.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Charset {
    /// `0-9` (10 chars).
    #[serde(default)]
    pub digits: bool,
    /// `a-z` (26 chars).
    #[serde(default)]
    pub lowercase: bool,
    /// `A-Z` (26 chars).
    #[serde(default)]
    pub uppercase: bool,
    /// `_` (1 char).
    #[serde(default)]
    pub underscore: bool,
    /// `-` (1 char).
    #[serde(default)]
    pub hyphen: bool,
    /// real 中出现但不属于以上 5 类的字符 (去重). 用户可手动补充.
    #[serde(default)]
    pub other: Vec<char>,
}

impl Charset {
    /// 从 real secret 推断字符集: 每类开关在 real 中出现对应字符时自动开启;
    /// 不属于任何标准类的字符去重收集到 `other`.
    pub fn infer_from(real: &str) -> Self {
        let mut cs = Self::default();
        for c in real.chars() {
            if c.is_ascii_digit() {
                cs.digits = true;
            } else if c.is_ascii_lowercase() {
                cs.lowercase = true;
            } else if c.is_ascii_uppercase() {
                cs.uppercase = true;
            } else if c == '_' {
                cs.underscore = true;
            } else if c == '-' {
                cs.hyphen = true;
            } else if !cs.other.contains(&c) {
                cs.other.push(c);
            }
        }
        cs
    }

    /// 展开为有序字符列表 (去重). 生成器从此列表中按 hash 选字符.
    /// 顺序固定: digits → lowercase → uppercase → `_` → `-` → other.
    pub fn enabled_chars(&self) -> Vec<char> {
        let mut out = Vec::new();
        if self.digits {
            out.extend('0'..='9');
        }
        if self.lowercase {
            out.extend('a'..='z');
        }
        if self.uppercase {
            out.extend('A'..='Z');
        }
        if self.underscore {
            out.push('_');
        }
        if self.hyphen {
            out.push('-');
        }
        for &c in &self.other {
            if !out.contains(&c) {
                out.push(c);
            }
        }
        out
    }

    /// 字符集是否为空 (无法生成 mock).
    pub fn is_empty(&self) -> bool {
        !self.digits
            && !self.lowercase
            && !self.uppercase
            && !self.underscore
            && !self.hyphen
            && self.other.is_empty()
    }
}

// ─── GenSpec ───────────────────────────────────────────────────────────────

/// 生成策略 (维度三): 固定前缀 + 字符集 + 长度范围.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GenSpec {
    /// 固定前缀. 默认空串 (不固定任何前缀, 全部随机).
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub charset: Charset,
    /// 闭区间 `[min, max]` (char count, 非 byte count).
    /// `(0, 0)` = 未配置 (由 [`MockStrategy::resolve_against`] 在拿到 real 后 infer).
    #[serde(default)]
    pub length_range: (usize, usize),
}

impl GenSpec {
    /// 从 real secret 推断默认 gen spec:
    /// `prefix=global_prefix`, `charset=infer_from(real)` (**+ widen 兜底**),
    /// `length_range=(global_prefix.chars + n, ...)` (mock 总长 = global_prefix + real 等长 body).
    ///
    /// `global_prefix` 来自 `[redact] global_mock_prefix` 配置 (默认空串).
    /// 让 Auto 模式生成的 mock 带可配置的统一前缀, 便于在日志 / WebUI 中视觉辨识.
    ///
    /// # Auto widen 兜底 (2026-09, 生成器扩宽发现的老缺陷)
    ///
    /// 退化 real (全同字符, 如 `""""`) 推断出单字符 charset → 等长候选空间 = 1,
    /// 唯一候选 == real 本身 → probing 必拒 → 耗尽 (fail_closed 下 503).
    /// Auto 的产品语义是**开箱即用**, 不应要求用户懂 charset 配置, 故推断后
    /// 候选空间 < [`MIN_CANDIDATE_SPACE_WARN`] 时逐级并入标准类
    /// (lowercase → digits → uppercase), 直到达标或全部并入.
    /// - 与 lint 阈值对齐 ⇒ Auto 模式永不落入弱配置区 (lint 只对手动配置有意义);
    /// - widen 是 (real, prefix) 的纯函数 ⇒ C3 确定性保持;
    /// - 空间充足的 secret 不触发 ⇒ 已生成的 mock 不变, 前缀缓存兼容;
    /// - 并入只增不减 (charset ⊇ real 字符) ⇒ 仿真度单调不降;
    /// - 极短 real (n ≤ 3: 全开标准类后 65³ ≈ 27 万仍 < 2^20) 兜到"最大可达"即停 —
    ///   等长约束下空间上限 = charset_size^n, 属物理边界 (n ≥ 4 恒可达标: 62⁴ ≈ 1480 万),
    ///   残余由 fail_closed 兜底.
    pub fn infer_default_for(real: &str, global_prefix: &str) -> Self {
        let n = real.chars().count();
        let prefix_len = global_prefix.chars().count();
        let mut charset = Charset::infer_from(real);
        // body 候选空间 = charset_size^n (等长, 与 candidate_space 的单区间项一致).
        // saturating_pow: 空间封顶 u64::MAX, 溢出不 panic.
        // 注: `n as u32` 对 >u32::MAX (≈4.3e9 chars, 需 ≥4GB secret) 截断 — 物理不可达.
        let space_short = |cs: &Charset| {
            (cs.enabled_chars().len() as u64).saturating_pow(n as u32) < MIN_CANDIDATE_SPACE_WARN
        };
        // 逐级并入: lowercase 可能已被 infer 开启 (如全小写 real) — 第一步 no-op,
        // 由 recheck 驱动向 digits 推进, 自校正无需特判.
        if space_short(&charset) {
            charset.lowercase = true;
        }
        if space_short(&charset) {
            charset.digits = true;
        }
        if space_short(&charset) {
            charset.uppercase = true;
        }
        Self {
            prefix: global_prefix.to_string(),
            charset,
            length_range: (prefix_len + n, prefix_len + n),
        }
    }

    /// 校验合法性 (Auto 模式且 gen 已配置时调用).
    pub fn validate(&self) -> Result<(), String> {
        let (min, max) = self.length_range;
        if min == 0 || max == 0 {
            return Err("length_range must be > 0".into());
        }
        if min > max {
            return Err(format!("length_range min({min}) > max({max})"));
        }
        let prefix_len = self.prefix.chars().count();
        if prefix_len > min {
            return Err(format!(
                "prefix length ({prefix_len}) > length_range min ({min}); body would be negative"
            ));
        }
        if self.charset.is_empty() {
            return Err("charset is empty (enable at least one character class)".into());
        }
        Ok(())
    }
}

// ─── 候选空间 lint (配置期 WARN) ──────────────────────────────────────────

/// 配置期候选空间 lint 的 WARN 阈值: Auto 模式 gen spec 的候选空间低于此值时,
/// [`MockStrategy::lint_candidate_space`] 返回 `Some` (由调用方 WARN).
///
/// # rationale
///
/// 运行时 mock probing 上限是 `redact::MOCK_PROBE_LIMIT` (生产 2^20, 见
/// `src/redact.rs`): redact 需要为每个 secret 找到**不在 IR 中且未被分配**的 mock,
/// 有效空间还要再扣除 IR 已有内容与已分配 mock — 因此名义候选空间一旦低于探测
/// 上限, 配合对抗性 IR 内容即可让 probing 耗尽 (触发
/// `[redact] on_probe_exhausted` 的 fail-open/fail-closed). 本 lint 把这类弱配置
/// 提前到配置写入时 (static 加载 / WebUI upsert) 暴露.
///
/// # 与 `redact::MOCK_PROBE_LIMIT` 的关系
///
/// 阈值语义独立成常量, **不引用** `redact::MOCK_PROBE_LIMIT` — mock → redact 是
/// 反向依赖 (依赖方向图见根 AGENTS.md, redact → codec/mock 才是合法方向).
/// 两者数值若需联动, 由人维护同步 (当前同为 2^20).
pub const MIN_CANDIDATE_SPACE_WARN: u64 = 1 << 20;

/// 弱候选空间 lint 的结果 (纯数据; 由调用方决定 WARN 文案, 便于单元测试).
/// 严禁携带 secret value 或 mock 明文 (SEC 红线).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateSpaceLint {
    /// 候选空间 Σ charset_size^len (body 区间, u64 saturating — 超大空间封顶).
    pub space: u64,
    /// 去重后 charset 大小 ([`Charset::enabled_chars`] 的长度).
    pub charset_size: usize,
    /// 参与求和的 body 长度闭区间 (总长 `length_range` 减 prefix 字符数;
    /// prefix 是固定字节不参与随机选择, 同 `GenSpec::body_length_range` 的语义).
    pub body_length_range: (usize, usize),
}

impl GenSpec {
    /// body (随机部分) 的长度闭区间: 总长 `length_range` 减 prefix 字符数
    /// (saturating). 与 `gen_one_auto_body` 的生成语义对齐 — prefix 固定不随机.
    fn body_length_range(&self) -> (usize, usize) {
        let prefix_len = self.prefix.chars().count();
        (
            self.length_range.0.saturating_sub(prefix_len),
            self.length_range.1.saturating_sub(prefix_len),
        )
    }

    /// 候选空间大小: 对 body 长度区间求和 `Σ charset_size^len`, u64 saturating
    /// (超大空间封顶于 `u64::MAX`, 不因溢出 panic).
    ///
    /// # 假设声明 (lenient, 纯算术不 panic)
    ///
    /// 输入按"已 resolve + 已 validate"的 spec 设计 (min ≥ 1, min ≤ max,
    /// prefix ≤ min, charset 非空), 但对未 resolve / 畸形形态按字面求和:
    /// - charset 为空 → `0` (无法生成任何候选; validate 已拒绝此形态);
    /// - `length_range = (0, 0)` (未配置) → `charset_size^0 = 1` (唯一空 body 候选);
    /// - `min > max` (畸形区间) → 求和为空集 → `0` (validate 已拒绝此形态).
    pub fn candidate_space(&self) -> u64 {
        let charset_size = self.charset.enabled_chars().len() as u64;
        if charset_size == 0 {
            return 0;
        }
        let (bmin, bmax) = self.body_length_range();
        if bmax < bmin {
            return 0;
        }
        if charset_size == 1 {
            // 每个长度恰 1 个候选: 空间 = 区间宽度. 直接算, 避免对极宽区间逐长度循环.
            return ((bmax - bmin) as u64).saturating_add(1);
        }
        // charset ≥ 2: term 每步至少 ×2, ≤64 步内饱和; 饱和后早退, 循环有界
        // (防极宽 length_range 造成 lint 自身长循环).
        let mut term: u64 = if bmin >= 64 {
            u64::MAX
        } else {
            charset_size.saturating_pow(bmin as u32)
        };
        let mut total = term;
        for _ in (bmin + 1)..=bmax {
            if term == u64::MAX {
                break;
            }
            term = term.saturating_mul(charset_size);
            total = total.saturating_add(term);
        }
        total
    }
}

impl MockStrategy {
    /// 配置期 lint: gen spec 的候选空间 < [`MIN_CANDIDATE_SPACE_WARN`] 时返回
    /// `Some` (弱配置信号). **纯函数不直接打日志**, 由调用方 WARN — 便于单元测试.
    ///
    /// # 语义边界 (Auto widen 后)
    ///
    /// Auto 推断路径经 [`GenSpec::infer_default_for`] 的 widen 兜底, resolve 后
    /// 空间恒 ≥ 阈值 (极短 real 的物理边界除外) — Auto 场景实际不再触发本 lint;
    /// lint 的有效对象是**用户手动配置**的 gen_spec (`lint_explicit_weak_spec_is_some`).
    ///
    /// # 调用前提 (无重复 resolve 副作用)
    ///
    /// 必须在 [`MockStrategy::resolve_against`] **之后**调用 (如
    /// `crate::secrets::SecretEntry::validate_and_resolve` 的第四步后): Auto 模式
    /// 此时 `gen_spec` 已是 `Some` (用户显式设置或 infer 填充), 直接读取即可,
    /// 本函数不做任何 resolve / 变异. 以下形态返回 `None` (无法 lint, 不误报):
    /// - `gen_spec = None` (Auto 未 resolve, 或 Fixed 模式): 前者空间未知,
    ///   后者的 probing 候选是 `{value}_{counter}` (counter 无上界), 不受 gen spec 限制.
    pub fn lint_candidate_space(&self) -> Option<CandidateSpaceLint> {
        let gen_spec = self.gen_spec.as_ref()?;
        let space = gen_spec.candidate_space();
        (space < MIN_CANDIDATE_SPACE_WARN).then(|| CandidateSpaceLint {
            space,
            charset_size: gen_spec.charset.enabled_chars().len(),
            body_length_range: gen_spec.body_length_range(),
        })
    }
}

// ─── InitialValue ──────────────────────────────────────────────────────────

/// 初始值模式 (维度一).
///
/// - `Auto`: 系统按 [`GenSpec`] 实时生成候选序列.
/// - `Fixed`: 用户固定值; 与 IR 冲突时按 `{value}_{n}` probing.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum InitialValue {
    /// 系统按 gen spec 生成.
    #[default]
    Auto,
    /// 用户固定值. 冲突时 probing 为 `{value}_1`, `{value}_2`, ...
    Fixed { value: String },
}

// ─── MockStrategy ──────────────────────────────────────────────────────────

/// Mock 策略: 两维度正交组合.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct MockStrategy {
    /// 维度一: 初始值模式. 默认 `Auto`.
    #[serde(default)]
    pub initial: InitialValue,

    /// 维度二: 生成策略. `None` = 未配置 (resolve 时 infer); `Some` = 用户显式设置.
    ///
    /// 仅 `initial = Auto` 时生效; `Fixed` 模式忽略此字段.
    ///
    /// 字段名 `gen_spec` 避免 `gen` (Rust 2024 保留关键字); serde rename 保 toml/json
    /// wire 兼容 (用户配置仍写 `gen = ...`).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "gen")]
    pub gen_spec: Option<GenSpec>,
}

impl MockStrategy {
    /// 在 resolve 拿到 real value 后调用:
    /// 若 `gen=None` 且 `initial=Auto`, 用 real + `global_prefix` infer 默认 gen spec.
    /// Fixed 模式不需要 gen, 保持 None.
    ///
    /// `global_prefix` 来自 `[redact] global_mock_prefix` (默认空串), 透传给
    /// [`GenSpec::infer_default_for`] 作为 infer 出的 gen_spec.prefix.
    pub fn resolve_against(&mut self, real: &str, global_prefix: &str) {
        if self.gen_spec.is_none() && matches!(self.initial, InitialValue::Auto) {
            self.gen_spec = Some(GenSpec::infer_default_for(real, global_prefix));
        }
    }

    /// 基础校验 (不依赖 real value). 在 `crate::secrets::SecretEntry::validate` 中调用.
    pub fn validate(&self) -> Result<(), String> {
        match &self.initial {
            InitialValue::Fixed { value } => {
                if value.is_empty() {
                    return Err("fixed mock value must not be empty".into());
                }
            }
            InitialValue::Auto => {
                // gen=None 时由 resolve_against 填充, 这里不校验 (兼容 value_file 模式).
                if let Some(gen_spec) = &self.gen_spec {
                    gen_spec.validate()?;
                }
            }
        }
        Ok(())
    }

    /// resolve 后的完整校验 (含 real value 依赖的检查).
    /// 在 [`crate::secrets::SecretEntry::validate_and_resolve`] 的第四步调用.
    pub fn validate_against_real(&self, real: &str) -> Result<(), String> {
        self.validate()?;
        // C5 阈值与 real 长度相关 (信息比率 ≤ ~36%): 见模块头部 "C5" 段落.
        let k = c5_threshold_len(real);
        if let InitialValue::Fixed { value } = &self.initial {
            if value == real {
                return Err("fixed mock value must not equal real secret".into());
            }
            // C5 best-effort: Fixed 值不应含 real 的 ≥k 字符连续子串.
            // 用 char-level windows (而非 byte-level) 以正确处理 multibyte UTF-8 secret
            // (byte windows 在多字节字符上会跨 char boundary, from_utf8 失败导致漏检).
            if contains_kchar_substring(value, real, k) {
                return Err(format!(
                    "fixed mock value contains a ≥{k} char substring of the real secret"
                ));
            }
        }
        // Auto 模式: 若用户设置了 gen.prefix, 校验 prefix 不含 real 的 ≥k 字符子串
        // (否则 mock 开头部分会暴露 real 子串, 违反 C5). prefix == real 的场景也被覆盖
        // (real 是自身的 ≥k 字符子串的前提, contains_kchar_substring 会返回 true).
        if let Some(gen_spec) = &self.gen_spec
            && !gen_spec.prefix.is_empty()
            && contains_kchar_substring(&gen_spec.prefix, real, k)
        {
            return Err(format!(
                "gen prefix contains a ≥{k} char substring of the real secret (C5 violation)"
            ));
        }
        Ok(())
    }
}

/// C5 最小阈值 (短 secret 强保护地板). 设计论据见模块头部 "C5" 段落.
const C5_MIN_THRESHOLD: usize = 4;

/// C5 阈值: mock 不应含 real_secret 的 ≥ `c5_threshold_len(real)` 字符连续子串.
///
/// `k(L) = max(4, ⌈L/3⌉)`, L 为 char 数. 设计论据 (信息比率 / 业界 scanner 阈值 /
/// 内部重试链) 见模块头部 "C5" 段落 (SSOT).
pub fn c5_threshold_len(real: &str) -> usize {
    C5_MIN_THRESHOLD.max(real.chars().count().div_ceil(3))
}

/// `haystack` 是否包含 `needle` 的任一 ≥ `k` 字符连续子串 (char-level, 正确处理 multibyte
/// UTF-8). `windows(k)` 在 needle < `k` 字符时返回空迭代器, 天然 gate 掉短串场景.
fn contains_kchar_substring(haystack: &str, needle: &str, k: usize) -> bool {
    needle
        .chars()
        .collect::<Vec<char>>()
        .windows(k)
        .any(|w| haystack.contains(&w.iter().collect::<String>()))
}

/// C5 断言 helper: mock 不含 real 的 ≥k(L) 字符连续子串 (char-level windows, 正确处理
/// multibyte UTF-8). 供 mock.rs / redact.rs 的 proptest / 单元测试共用, 统一口径.
#[cfg(test)]
pub(crate) fn assert_no_c5_substring(mock: &str, real: &str) {
    let k = c5_threshold_len(real);
    let chars: Vec<char> = real.chars().collect();
    for w in chars.windows(k) {
        let sub: String = w.iter().collect();
        assert!(
            !mock.contains(&sub),
            "mock {mock:?} contains real ≥{k}-char substring {sub:?} (real={real:?})"
        );
    }
}

// ─── 候选生成器 ────────────────────────────────────────────────────────────

/// 计算确定性 seed (C3 前缀缓存友好性的根基).
///
/// 同一 `(real, strategy)` 总产生同一 seed → 同一候选序列 (counter=0,1,2,...).
/// redact 调用此函数获得 seed, 保证同一 secret 在会话全程 mock 稳定.
pub fn deterministic_seed(real: &str, strategy: &MockStrategy) -> u64 {
    crate::util::hash64(&(real, strategy))
}

/// 在给定 `seed + counter` 下生成单个候选 mock.
///
/// 调用方 (redact) 按 probing 协议消费:
/// - counter=0: 首选候选.
/// - counter>0: 前序候选与 IR / allocated 冲突时的后备.
///
/// **Auto 模式**要求 `strategy.gen_spec` 为 `Some` (由 [`MockStrategy::resolve_against`] 填充).
/// **Fixed 模式**: counter=0 返回 `value`, counter>0 返回 `{value}_{counter}`.
///
/// # C5 内部重试链 (Auto 模式)
///
/// Auto 分支内部按 `retry = 0..=[C5_INTERNAL_RETRIES]` 完全确定性地循环重 hash body,
/// 找到第一个满足 C5 (mock 不含 real_secret 的 ≥ [`c5_threshold_len`] 字符子串) 的候选返回.
/// 重试链不破坏 C3 (无副作用, 不消耗外部 counter): 同一 `(real, strategy, seed, counter)`
/// 仍严格产出同一 mock.
///
/// 重试链上限 `C5_INTERNAL_RETRIES` = 10000 是 **safety bound (仅防死循环)**, 非概率目标.
/// 详见模块头部 "C5" 段落 (SSOT).
pub fn gen_candidate(real: &str, strategy: &MockStrategy, seed: u64, counter: u32) -> String {
    match &strategy.initial {
        InitialValue::Fixed { value } => {
            if counter == 0 {
                value.clone()
            } else {
                format!("{value}_{counter}")
            }
        }
        InitialValue::Auto => {
            let gen_spec = strategy
                .gen_spec
                .as_ref()
                .expect("Auto mode requires gen spec; call MockStrategy::resolve_against first");
            let pool: Vec<char> = gen_spec.charset.enabled_chars();
            // validate 应已拒绝空 charset; 这里 defense-in-depth.
            if pool.is_empty() {
                return gen_spec.prefix.clone();
            }
            let k = c5_threshold_len(real);
            // 重试链: 第 retry 次用 hash(seed,counter,retry) 重 hash body.
            // 找到第一个不含 real ≥k 字符子串的候选. 全失败则返回最后一次 (best-effort).
            // 上限是 safety bound (1e-50000 量级失败率, 实质等价于确定性, 见模块头部).
            for retry in 0..=C5_INTERNAL_RETRIES {
                let candidate = gen_one_auto_body(gen_spec, &pool, seed, counter, retry);
                if !contains_kchar_substring(&candidate, real, k) {
                    return candidate;
                }
            }
            // 重试链耗尽 (1e-50000 量级, 实际永不触发), 退化返回最后一次候选.
            // 上层 redact 的 C2/C4 probing 仍能通过外部 counter 推进找到合格候选.
            gen_one_auto_body(gen_spec, &pool, seed, counter, C5_INTERNAL_RETRIES)
        }
    }
}

/// C5 内部重试链上限 (safety bound, 仅防死循环, 非概率目标).
/// 取较大值让 C5 在 Auto 模式下实质等价于确定性契约 (见模块头部 "C5").
const C5_INTERNAL_RETRIES: u32 = 10_000;

/// Auto 模式的单次 body 生成 (给定 `retry` 偏移量). 完全确定性, 无副作用.
fn gen_one_auto_body(
    gen_spec: &GenSpec,
    pool: &[char],
    seed: u64,
    counter: u32,
    retry: u32,
) -> String {
    let (body_min, body_max) = gen_spec.body_length_range();

    // body 长度: min==max 时固定, 否则按 hash 在 [body_min, body_max] 选.
    // `retry` 进入 hash 输入 → 不同 retry 产出不同长度 (当 min!=max) 或不同字符.
    let body_len = if body_min == body_max {
        body_min
    } else {
        let h = crate::util::hash64(&format!("{seed}{counter}{retry}len"));
        body_min + (h % (body_max - body_min + 1) as u64) as usize
    };

    let prefix_len = gen_spec.prefix.chars().count();
    let mut buf = String::with_capacity(prefix_len + body_len);
    buf.push_str(&gen_spec.prefix);
    for i in 0..body_len {
        let h = crate::util::hash64(&format!("{seed}{counter}{retry}{i}"));
        let idx = (h % pool.len() as u64) as usize;
        buf.push(pool[idx]);
    }
    buf
}

// ─── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Charset ──────────────────────────────────────────────────────────

    #[test]
    fn charset_infer_from_pure_lowercase() {
        let cs = Charset::infer_from("abcdef");
        assert!(cs.lowercase);
        assert!(!cs.digits);
        assert!(!cs.uppercase);
        assert!(!cs.underscore);
        assert!(!cs.hyphen);
        assert!(cs.other.is_empty());
    }

    #[test]
    fn charset_infer_from_mixed() {
        let cs = Charset::infer_from("sk-Abc123_X!");
        assert!(cs.digits, "digits");
        assert!(cs.lowercase, "lowercase");
        assert!(cs.uppercase, "uppercase");
        assert!(cs.underscore, "underscore");
        assert!(cs.hyphen, "hyphen");
        assert_eq!(cs.other, vec!['!']);
    }

    #[test]
    fn charset_infer_dedup_other() {
        let cs = Charset::infer_from("a!b!c!");
        assert!(cs.lowercase);
        // `!` 出现 3 次但只收集一次.
        assert_eq!(cs.other, vec!['!']);
    }

    #[test]
    fn charset_infer_empty_real() {
        let cs = Charset::infer_from("");
        assert!(cs.is_empty());
    }

    /// widen 兜底: 退化 real 推断空间 1 → 拓宽到 ≥ 阈值 (机制与不变量见
    /// `GenSpec::infer_default_for` doc; lint 有效范围见 `lint_candidate_space` doc).
    #[test]
    fn infer_default_widens_degenerate_charset() {
        // real = 4 个双引号: infer 出 other=['"'] 单字符, 空间 1^4 = 1.
        // 停在 lowercase+digits: (1+26+10)^4 = 37^4 ≈ 187 万 ≥ 2^20, uppercase 不开
        // (最小拓宽断言 — 防"一刀切全开"回归静默扩大缓存失效面).
        let spec = GenSpec::infer_default_for("\"\"\"\"", "");
        assert!(spec.candidate_space() >= MIN_CANDIDATE_SPACE_WARN);
        assert!(spec.charset.lowercase && spec.charset.digits && !spec.charset.uppercase);
        // widen 只并入标准类, real 的字符仍在池中 (仿真度: charset ⊇ real 字符).
        assert!(spec.charset.enabled_chars().contains(&'"'));
    }

    /// 空间充足的典型 secret 不触发 widen (行为/缓存兼容: 已生成的 mock 不变).
    #[test]
    fn infer_default_no_widen_when_space_sufficient() {
        // 32 位混合 charset API key: 62^32 >> 2^20.
        let real = "sk-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
        let spec = GenSpec::infer_default_for(real, "");
        assert_eq!(spec.charset, Charset::infer_from(real));
    }

    /// 短 real 的固有边界 (n ≤ 3): 全开标准类也达不到阈值 — widen 兜到
    /// "最大可达"即停 (等长约束下空间上限 = charset_size^n, 物理边界).
    #[test]
    fn infer_default_widen_stops_at_physical_limit() {
        let spec = GenSpec::infer_default_for("a", "");
        // 1 字符 body 全开 (62 标准字符) 候选 62 < 2^20: widen 并完全部标准类后停止.
        assert!(spec.charset.lowercase && spec.charset.digits && spec.charset.uppercase);
    }

    /// unicode 退化 real: 4 个相同 CJK 字符 (other=['密'], 多字节按 char 计数 = 1)
    /// 同样走 widen — charset 处理与 ASCII 无关 (enabled_chars 按 char, 非 byte).
    #[test]
    fn infer_default_widens_unicode_degenerate_charset() {
        let spec = GenSpec::infer_default_for("密密密密", "");
        assert!(spec.candidate_space() >= MIN_CANDIDATE_SPACE_WARN);
        assert!(spec.charset.enabled_chars().contains(&'密'));
    }

    #[test]
    fn charset_enabled_chars_order() {
        let cs = Charset {
            digits: true,
            lowercase: false,
            uppercase: true,
            underscore: true,
            hyphen: false,
            other: vec!['@'],
        };
        let chars = cs.enabled_chars();
        // 顺序: digits → uppercase → underscore → other.
        assert_eq!(&chars[..10], "0123456789".chars().collect::<Vec<_>>());
        assert_eq!(&chars[10..36], ('A'..='Z').collect::<Vec<_>>());
        assert_eq!(chars[36], '_');
        assert_eq!(chars[37], '@');
    }

    #[test]
    fn charset_enabled_chars_dedup_other() {
        // other 中有与标准类重复的字符 → 去重.
        let cs = Charset {
            digits: true,
            lowercase: false,
            uppercase: false,
            underscore: false,
            hyphen: false,
            other: vec!['0', '5', '!'], // '0','5' 与 digits 重复.
        };
        let chars = cs.enabled_chars();
        // digits 10 + '!' 1 = 11, '0'/'5' 不重复加入.
        assert_eq!(chars.len(), 11);
        assert!(chars.contains(&'!'));
    }

    #[test]
    fn charset_is_empty() {
        assert!(Charset::default().is_empty());
        assert!(
            !Charset {
                digits: true,
                ..Default::default()
            }
            .is_empty()
        );
    }

    // ─── GenSpec ──────────────────────────────────────────────────────────

    #[test]
    fn genspec_infer_default_for_real() {
        // 默认 (空 global_prefix): prefix 空, length == real 长度.
        let gen_spec = GenSpec::infer_default_for("sk-Abc123", "");
        assert_eq!(gen_spec.prefix, "");
        assert!(gen_spec.charset.lowercase);
        assert!(gen_spec.charset.uppercase);
        assert!(gen_spec.charset.digits);
        assert!(gen_spec.charset.hyphen);
        assert_eq!(gen_spec.length_range, (9, 9)); // "sk-Abc123" = 9 chars.
    }

    #[test]
    fn genspec_infer_default_with_global_prefix() {
        // 配置 global_prefix="sgm_": mock 总长 = prefix(4) + real(9) = 13.
        let gen_spec = GenSpec::infer_default_for("sk-Abc123", "sgm_");
        assert_eq!(gen_spec.prefix, "sgm_");
        assert_eq!(gen_spec.length_range, (13, 13));
    }

    #[test]
    fn genspec_infer_default_empty_real() {
        let gen_spec = GenSpec::infer_default_for("", "");
        assert_eq!(gen_spec.length_range, (0, 0));
        // 空 real: n=0 时空间恒 1 < 阈值, widen 全开标准类 (空 real 在生产路径
        // 被 redact_ir_inner 的 !value.is_empty() 过滤, 此形态仅测试可达).
        assert!(
            gen_spec.charset.lowercase && gen_spec.charset.digits && gen_spec.charset.uppercase
        );
    }

    #[test]
    fn genspec_validate_rejects_zero_length() {
        let gen_spec = GenSpec {
            prefix: "".into(),
            charset: Charset {
                digits: true,
                ..Default::default()
            },
            length_range: (0, 0),
        };
        assert!(gen_spec.validate().is_err());
    }

    #[test]
    fn genspec_validate_rejects_min_gt_max() {
        let gen_spec = GenSpec {
            prefix: "".into(),
            charset: Charset {
                digits: true,
                ..Default::default()
            },
            length_range: (10, 5),
        };
        assert!(gen_spec.validate().is_err());
    }

    #[test]
    fn genspec_validate_rejects_prefix_longer_than_min() {
        let gen_spec = GenSpec {
            prefix: "longprefix".into(),
            charset: Charset {
                digits: true,
                ..Default::default()
            },
            length_range: (5, 10), // min=5 < prefix=10.
        };
        let err = gen_spec.validate().unwrap_err();
        assert!(err.contains("prefix length"), "{err}");
    }

    #[test]
    fn genspec_validate_rejects_empty_charset() {
        let gen_spec = GenSpec {
            prefix: "".into(),
            charset: Charset::default(),
            length_range: (10, 10),
        };
        let err = gen_spec.validate().unwrap_err();
        assert!(err.contains("charset is empty"), "{err}");
    }

    #[test]
    fn genspec_validate_accepts_valid() {
        let gen_spec = GenSpec {
            prefix: "sk-".into(),
            charset: Charset {
                digits: true,
                lowercase: true,
                ..Default::default()
            },
            length_range: (10, 20),
        };
        assert!(gen_spec.validate().is_ok());
    }

    // ─── 候选空间 (candidate_space) ────────────────────────────────────────

    /// 构造仅含 n 个自定义字符的 charset (其余全关).
    fn charset_of(n_chars: &str) -> Charset {
        Charset {
            other: n_chars.chars().collect(),
            ..Default::default()
        }
    }

    #[test]
    fn candidate_space_fixed_small() {
        // charset 2 × 固定长度 4 = 2^4 = 16 (任务书示例的弱配置).
        let gen_spec = GenSpec {
            prefix: "".into(),
            charset: charset_of("ab"),
            length_range: (4, 4),
        };
        assert_eq!(gen_spec.candidate_space(), 16);
    }

    #[test]
    fn candidate_space_range_sum() {
        // charset 2 × 区间 [3,5] = 2^3 + 2^4 + 2^5 = 56.
        let gen_spec = GenSpec {
            prefix: "".into(),
            charset: charset_of("ab"),
            length_range: (3, 5),
        };
        assert_eq!(gen_spec.candidate_space(), 8 + 16 + 32);
    }

    #[test]
    fn candidate_space_subtracts_prefix() {
        // prefix "ab" 固定 2 字符 → body 区间 [2,2], charset 2 → 2^2 = 4.
        let gen_spec = GenSpec {
            prefix: "ab".into(),
            charset: charset_of("xy"),
            length_range: (4, 4),
        };
        assert_eq!(gen_spec.candidate_space(), 4);
        assert_eq!(gen_spec.body_length_range(), (2, 2));
    }

    #[test]
    fn candidate_space_saturates() {
        // charset 36 × 长度 64: 36^64 远超 u64 → 封顶 u64::MAX, 不 panic.
        let gen_spec = GenSpec {
            prefix: "".into(),
            charset: Charset {
                digits: true,
                lowercase: true,
                ..Default::default()
            },
            length_range: (64, 64),
        };
        assert_eq!(gen_spec.candidate_space(), u64::MAX);
        // 极宽区间同样封顶 (早退, 不长循环).
        let wide = GenSpec {
            prefix: "".into(),
            charset: charset_of("ab"),
            length_range: (1, usize::MAX),
        };
        assert_eq!(wide.candidate_space(), u64::MAX);
    }

    #[test]
    fn candidate_space_single_char_charset() {
        // charset 1: 每个长度恰 1 个候选, 空间 = 区间宽度 [4,8] = 5.
        let gen_spec = GenSpec {
            prefix: "".into(),
            charset: charset_of("x"),
            length_range: (4, 8),
        };
        assert_eq!(gen_spec.candidate_space(), 5);
    }

    #[test]
    fn candidate_space_lenient_degenerate_shapes() {
        // 假设声明的字面语义 (validate 已拒绝的形态, 纯算术不 panic):
        // 空 charset → 0.
        let empty_cs = GenSpec {
            prefix: "".into(),
            charset: Charset::default(),
            length_range: (4, 4),
        };
        assert_eq!(empty_cs.candidate_space(), 0);
        // 未配置 (0,0) → 单一空 body 候选 = 1.
        let unconfigured = GenSpec {
            prefix: "".into(),
            charset: charset_of("ab"),
            length_range: (0, 0),
        };
        assert_eq!(unconfigured.candidate_space(), 1);
        // 畸形 min > max → 空集求和 = 0.
        let malformed = GenSpec {
            prefix: "".into(),
            charset: charset_of("ab"),
            length_range: (5, 3),
        };
        assert_eq!(malformed.candidate_space(), 0);
    }

    // ─── 候选空间 lint (lint_candidate_space) ──────────────────────────────

    #[test]
    fn lint_explicit_weak_spec_is_some() {
        // 显式弱配置: charset 2 × len 4 = 16 << 2^20.
        let s = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: Some(GenSpec {
                prefix: "".into(),
                charset: charset_of("ab"),
                length_range: (4, 4),
            }),
        };
        let lint = s.lint_candidate_space().expect("weak spec should lint");
        assert_eq!(lint.space, 16);
        assert_eq!(lint.charset_size, 2);
        assert_eq!(lint.body_length_range, (4, 4));
    }

    #[test]
    fn lint_strong_spec_is_none() {
        // 强配置: charset 62 (alnum+_) × len 12 → 62^12 远超 2^20.
        let s = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: Some(GenSpec {
                prefix: "".into(),
                charset: Charset {
                    digits: true,
                    lowercase: true,
                    uppercase: true,
                    underscore: true,
                    ..Default::default()
                },
                length_range: (12, 12),
            }),
        };
        assert!(s.lint_candidate_space().is_none());
    }

    #[test]
    fn lint_auto_degenerate_real_widened_not_linted() {
        // Auto + 退化 real (widen 后语义): n ≥ 4 的退化 real resolve 后恒不可 lint
        // (widen 兜底; 机制见 GenSpec::infer_default_for, lint 有效范围见
        // lint_candidate_space 语义边界段). n ≤ 3 物理边界除外 (见尾部).
        // "aaaa": infer lowercase (26^4 = 456976 < 2^20) → widen 并入 digits →
        // 36^4 = 1679616 ≥ 2^20 → 停.
        let mut s = MockStrategy::default();
        s.resolve_against("aaaa", "");
        assert!(s.lint_candidate_space().is_none());
        // 全 "other" 字符的退化 real: infer 单字符 '!' (空间 1) → widen 并入
        // lowercase+digits ((1+26+10)^4 = 37^4 ≈ 187 万 ≥ 2^20) → 停, uppercase 未开.
        let mut s = MockStrategy::default();
        s.resolve_against("!!!!", "");
        assert!(s.lint_candidate_space().is_none());
        // **n=3 物理边界**: "abc" 全小写无 other, 全开后 62³ = 238,328 仍 < 2^20 —
        // (65³ ≈ 27.5 万是 n=3 含 other 的理论上界, 见 infer_default_for doc) —
        // Auto 极短 real 在全开兜底后仍 lint (边界语义钉住, 防 widen/阈值漂移).
        let mut s = MockStrategy::default();
        s.resolve_against("abc", "");
        let lint = s
            .lint_candidate_space()
            .expect("n=3 real 全开仍低于阈值, 应 lint");
        assert!(lint.space < MIN_CANDIDATE_SPACE_WARN);
    }

    #[test]
    fn lint_auto_normal_real_is_none() {
        // Auto + 正常 real (多种字符, 足够长) → infer 空间远超 2^20.
        let mut s = MockStrategy::default();
        s.resolve_against("sk-1234567890abcdef", "");
        assert!(s.lint_candidate_space().is_none());
    }

    #[test]
    fn lint_fixed_mode_and_unresolved_auto_are_none() {
        // Fixed 模式: probing 候选 {value}_{counter} 无上界, 不受 gen spec 限制.
        let fixed = MockStrategy {
            initial: InitialValue::Fixed {
                value: "mock-value".into(),
            },
            gen_spec: None,
        };
        assert!(fixed.lint_candidate_space().is_none());
        // Auto 未 resolve (gen None): 空间未知, 不误报.
        let unresolved = MockStrategy::default();
        assert!(unresolved.lint_candidate_space().is_none());
    }

    #[test]
    fn lint_threshold_boundary() {
        // 边界语义: space == 阈值不 lint (< 才 lint); space == 阈值/2 lint.
        let at = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: Some(GenSpec {
                prefix: "".into(),
                charset: charset_of("ab"),
                length_range: (20, 20), // 2^20 = MIN_CANDIDATE_SPACE_WARN.
            }),
        };
        assert_eq!(
            at.gen_spec.as_ref().unwrap().candidate_space(),
            MIN_CANDIDATE_SPACE_WARN
        );
        assert!(at.lint_candidate_space().is_none(), "space == 阈值不 lint");

        let below = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: Some(GenSpec {
                prefix: "".into(),
                charset: charset_of("ab"),
                length_range: (19, 19), // 2^19 = 阈值/2 < 阈值.
            }),
        };
        assert!(
            below.lint_candidate_space().is_some(),
            "space < 阈值要 lint"
        );
    }

    // ─── MockStrategy ─────────────────────────────────────────────────────

    #[test]
    fn mock_strategy_default_is_auto_no_gen() {
        let s = MockStrategy::default();
        assert!(matches!(s.initial, InitialValue::Auto));
        assert!(s.gen_spec.is_none());
    }

    #[test]
    fn mock_strategy_resolve_infers_gen_for_auto() {
        let mut s = MockStrategy::default();
        s.resolve_against("sk-Abc123", "");
        let gen_spec = s.gen_spec.expect("gen should be inferred");
        assert_eq!(gen_spec.length_range, (9, 9));
        assert!(gen_spec.charset.lowercase);
    }

    #[test]
    fn mock_strategy_resolve_does_not_overwrite_user_gen() {
        let user_gen = GenSpec {
            prefix: "custom".into(),
            charset: Charset {
                digits: true,
                ..Default::default()
            },
            length_range: (20, 20),
        };
        let mut s = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: Some(user_gen.clone()),
        };
        s.resolve_against("sk-Abc123", "");
        // 用户设置的 gen 不被覆盖.
        assert_eq!(s.gen_spec.as_ref().unwrap(), &user_gen);
    }

    #[test]
    fn mock_strategy_resolve_skips_fixed_mode() {
        // Fixed 模式不需要 gen.
        let mut s = MockStrategy {
            initial: InitialValue::Fixed {
                value: "my-mock".into(),
            },
            gen_spec: None,
        };
        s.resolve_against("sk-Abc123", "");
        // Fixed 模式 gen 保持 None.
        assert!(s.gen_spec.is_none());
    }

    #[test]
    fn mock_strategy_validate_fixed_empty_rejected() {
        let s = MockStrategy {
            initial: InitialValue::Fixed { value: "".into() },
            gen_spec: None,
        };
        assert!(s.validate().is_err());
    }

    #[test]
    fn mock_strategy_validate_auto_with_bad_gen_rejected() {
        let s = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: Some(GenSpec {
                prefix: "".into(),
                charset: Charset::default(), // 空 charset.
                length_range: (10, 10),
            }),
        };
        assert!(s.validate().is_err());
    }

    #[test]
    fn mock_strategy_validate_against_real_rejects_fixed_equals_real() {
        let s = MockStrategy {
            initial: InitialValue::Fixed {
                value: "secret123".into(),
            },
            gen_spec: None,
        };
        let err = s.validate_against_real("secret123").unwrap_err();
        assert!(err.contains("must not equal"), "{err}");
    }

    #[test]
    fn mock_strategy_validate_against_real_rejects_fixed_with_real_substring() {
        // C5 阈值随 real 长度自适应 (见 c5_threshold_len). 这里覆盖两类场景:
        //
        // 1. 短 real (L≤12, k=4): 任何 ≥4 字符子串触发 C5 违反.
        let real_short = "sk-test123"; // 10 chars → k = max(4, ⌈10/3⌉) = 4
        let s_short = MockStrategy {
            initial: InitialValue::Fixed {
                value: "ask-tzzz".into(), // 含 real 4 字符子串 "sk-t".
            },
            gen_spec: None,
        };
        let err = s_short.validate_against_real(real_short).unwrap_err();
        assert!(err.contains("≥4 char substring"), "{err}");
    }

    #[test]
    fn mock_strategy_validate_against_real_c5_threshold_scales_with_real_len() {
        // C5 阈值随 real 长度自适应: 长 real 时, 4 字符子串不再触发 C5 (信息比率 < 1/3),
        // 需要 ≥⌈L/3⌉ 字符子串才触发. 这条性质是 k(L) = max(4, ⌈L/3⌉) 的核心.
        // 覆盖三个关键长度: L=12 (k=4 短 secret 上界), L=13 (k=5 转折点), L=18 (k=6).

        // L=12 (k=4): 4 字符子串仍触发 C5.
        let real12 = "sk-test-1234"; // 12 chars → k=4
        let s12 = MockStrategy {
            initial: InitialValue::Fixed {
                value: "Xsk-tY".into(), // 含 real 的 4 字符子串 "sk-t".
            },
            gen_spec: None,
        };
        assert!(
            s12.validate_against_real(real12).is_err(),
            "4-char substring must trigger C5 for L=12 (k=4)"
        );

        // L=13 (k=5, 转折点): 4 字符子串不再触发, 5 字符才触发.
        let real13 = "sk-test-12345"; // 13 chars → k=5
        let s13_clean = MockStrategy {
            initial: InitialValue::Fixed {
                value: "Xsk-tY".into(), // 仅 4 字符子串 "sk-t".
            },
            gen_spec: None,
        };
        assert!(
            s13_clean.validate_against_real(real13).is_ok(),
            "4-char substring must NOT trigger C5 for L=13 (k=5)"
        );
        let s13_dirty = MockStrategy {
            initial: InitialValue::Fixed {
                value: "Xsk-teY".into(), // 含 real 的 5 字符子串 "sk-te".
            },
            gen_spec: None,
        };
        let err = s13_dirty.validate_against_real(real13).unwrap_err();
        assert!(err.contains("≥5 char substring"), "{err}");

        // L=18 (k=6): 4 字符不触发, 6 字符才触发.
        let real18 = "sk-test-abcdef1234"; // 18 chars
        let s18_clean = MockStrategy {
            initial: InitialValue::Fixed {
                value: "Xsk-tY".into(),
            },
            gen_spec: None,
        };
        assert!(
            s18_clean.validate_against_real(real18).is_ok(),
            "4-char substring must NOT trigger C5 for L=18 (k=6)"
        );
        let s18_dirty = MockStrategy {
            initial: InitialValue::Fixed {
                value: "Xsk-tesY".into(), // 含 real 的 6 字符子串 "sk-tes".
            },
            gen_spec: None,
        };
        let err = s18_dirty.validate_against_real(real18).unwrap_err();
        assert!(err.contains("≥6 char substring"), "{err}");
    }

    #[test]
    fn mock_strategy_validate_against_real_accepts_clean_fixed() {
        let s = MockStrategy {
            initial: InitialValue::Fixed {
                value: "completely-different".into(),
            },
            gen_spec: None,
        };
        assert!(s.validate_against_real("sk-test-123456").is_ok());
    }

    #[test]
    fn mock_strategy_validate_against_real_catches_multibyte_utf8_substring() {
        // C5 检查必须用 char-level windows (而非 byte-level), 否则 multibyte UTF-8
        // (如中文, 每字符 3 字节) 会让所有 4-byte windows 跨 char boundary → 全部漏检.
        // real = 4 中文字符 + 空格 + 6 ASCII = 11 chars → k = max(4, ⌈11/3⌉) = 4.
        let real = "你好世界 Secret";
        // Fixed value 含 real 的 4 字符子串 "你好世界".
        let s = MockStrategy {
            initial: InitialValue::Fixed {
                value: "prefix-你好世界-suffix".into(),
            },
            gen_spec: None,
        };
        let err = s.validate_against_real(real).unwrap_err();
        assert!(err.contains("≥4 char substring"), "{err}");
    }

    #[test]
    fn mock_strategy_validate_against_real_rejects_auto_prefix_in_real() {
        // Auto 模式: gen.prefix 出现在 real 中 → mock 开头会暴露 real 子串 (C5).
        let real = "sk-test-secret-value";
        let s = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: Some(GenSpec {
                prefix: "sk-test".into(), // 出现在 real 中.
                charset: Charset {
                    digits: true,
                    ..Default::default()
                },
                length_range: (20, 20),
            }),
        };
        let err = s.validate_against_real(real).unwrap_err();
        assert!(err.contains("C5 violation"), "{err}");
    }

    #[test]
    fn mock_strategy_validate_against_real_accepts_auto_prefix_not_in_real() {
        // Auto 模式: gen.prefix 不出现在 real 中 → OK.
        let s = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: Some(GenSpec {
                prefix: "MOCK-".into(),
                charset: Charset {
                    digits: true,
                    ..Default::default()
                },
                length_range: (20, 20),
            }),
        };
        assert!(s.validate_against_real("sk-test-secret-value").is_ok());
    }

    // ─── gen_candidate (Auto 模式) ────────────────────────────────────────

    /// 构造一个 Auto 策略 (测试 helper).
    fn auto_strategy(prefix: &str, charset: Charset, length: usize) -> MockStrategy {
        MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: Some(GenSpec {
                prefix: prefix.into(),
                charset,
                length_range: (length, length),
            }),
        }
    }

    #[test]
    fn gen_candidate_auto_basic_shape() {
        let s = auto_strategy(
            "",
            Charset {
                digits: true,
                ..Default::default()
            },
            10,
        );
        let mock = gen_candidate("real", &s, 42, 0);
        assert_eq!(mock.len(), 10);
        assert!(mock.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn gen_candidate_auto_respects_prefix() {
        let s = auto_strategy(
            "sk-",
            Charset {
                digits: true,
                ..Default::default()
            },
            10,
        );
        let mock = gen_candidate("real", &s, 42, 0);
        assert!(mock.starts_with("sk-"));
        assert_eq!(mock.len(), 10);
        // prefix 后的部分全是 digits.
        assert!(mock["sk-".len()..].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn gen_candidate_auto_respects_charset() {
        let s = auto_strategy(
            "",
            Charset {
                lowercase: true,
                ..Default::default()
            },
            20,
        );
        let mock = gen_candidate("real", &s, 1, 0);
        assert_eq!(mock.len(), 20);
        assert!(mock.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn gen_candidate_auto_respects_other_chars() {
        let s = auto_strategy(
            "",
            Charset {
                other: vec!['!', '@', '#'],
                ..Default::default()
            },
            15,
        );
        let mock = gen_candidate("real", &s, 7, 0);
        assert_eq!(mock.len(), 15);
        assert!(mock.chars().all(|c| "!@#".contains(c)));
    }

    #[test]
    fn gen_candidate_auto_length_range_min() {
        // length_range = (5, 10): 不同 seed 可能产生 5-10 长度.
        let s = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: Some(GenSpec {
                prefix: "".into(),
                charset: Charset {
                    digits: true,
                    ..Default::default()
                },
                length_range: (5, 10),
            }),
        };
        for seed in 0..100u64 {
            let mock = gen_candidate("real", &s, seed, 0);
            assert!(
                mock.len() >= 5 && mock.len() <= 10,
                "len {} not in [5,10] for seed {seed}: {mock}",
                mock.len()
            );
        }
    }

    #[test]
    fn gen_candidate_auto_fixed_length_when_min_eq_max() {
        let s = auto_strategy(
            "",
            Charset {
                digits: true,
                ..Default::default()
            },
            8,
        );
        for seed in 0..50u64 {
            for counter in 0..5u32 {
                let mock = gen_candidate("real", &s, seed, counter);
                assert_eq!(mock.len(), 8, "fixed length violated");
            }
        }
    }

    // ─── gen_candidate (确定性) ────────────────────────────────────────────

    #[test]
    fn gen_candidate_is_deterministic() {
        // 同一 (real, strategy, seed, counter) → 同一 mock.
        let s = auto_strategy(
            "",
            Charset {
                digits: true,
                lowercase: true,
                ..Default::default()
            },
            12,
        );
        let real = "sk-test";
        let seed = deterministic_seed(real, &s);
        let m1 = gen_candidate(real, &s, seed, 0);
        let m2 = gen_candidate(real, &s, seed, 0);
        assert_eq!(m1, m2, "must be deterministic for same input");
    }

    #[test]
    fn gen_candidate_candidate_sequence_stable() {
        // counter=0,1,2,... 产生稳定的候选序列.
        // 相同 strategy 多次调用, 序列相同 (这是"候选序列稳定"的核心, C3 的根基).
        let s = auto_strategy(
            "",
            Charset {
                digits: true,
                ..Default::default()
            },
            8,
        );
        let real = "my-secret";
        let seed = deterministic_seed(real, &s);

        let seq1: Vec<String> = (0..5).map(|c| gen_candidate(real, &s, seed, c)).collect();
        let seq2: Vec<String> = (0..5).map(|c| gen_candidate(real, &s, seed, c)).collect();
        assert_eq!(seq1, seq2, "candidate sequence must be stable");
    }

    #[test]
    fn gen_candidate_different_counter_usually_different() {
        // counter 0,1,2,... 通常产生不同候选 (否则 probing 无意义).
        let s = auto_strategy(
            "",
            Charset {
                digits: true,
                lowercase: true,
                uppercase: true,
                ..Default::default()
            },
            10,
        );
        let seed = 12345u64;
        let candidates: Vec<String> = (0..10)
            .map(|c| gen_candidate("real", &s, seed, c))
            .collect();
        let unique: std::collections::HashSet<_> = candidates.iter().collect();
        // 10 个候选中至少有 8 个不同 (允许少量碰撞, 但不应大量重复).
        assert!(
            unique.len() >= 8,
            "probing sequence too colliding: {} unique out of 10",
            unique.len()
        );
    }

    // ─── gen_candidate (Auto): C5 不含 real ≥k(L) 字符子串 (property-based) ──────
    //
    // 直接对 gen_candidate 做 property-based 覆盖: 现有测试只覆盖 validate_against_real
    // 的 prefix 校验, 或经 redact.rs 的 predict_mock 间接覆盖; 这里直接锁死 Auto 模式
    // body 生成的 C5 行为. 输入 real ∈ [A-Za-z0-9]{4,64} 覆盖短/长 secret.
    //
    // C5 契约、阈值公式与内部重试链的设计论据见模块头部 "C5" 段落 (SSOT).
    // 极低基数 real (如仅 2 个不同字符) 是已知 C5 边界, 不在输入域内
    // (历史 regression: proptest-regressions/redact.txt).
    use proptest::prelude::*;

    /// RED-1 / RED-5 property 测试的 GenSpec 生成器: 随机 prefix / charset 类开关组合 /
    /// `other` 自定义字符 (含多字节 €, 覆盖非 ASCII 维度 — 生成器覆盖度本身是
    /// 契约要求, contracts.md §0.3) / length_range, 保证 `validate()` 通过
    /// (charset 非空, prefix_len ≤ min ≤ max, min > 0; prop_map 尾部
    /// debug_assert 机械守护). 全类开关关闭且 other 为空时回落 digits=true
    /// (避免空 charset, 免 prop_filter 拒绝采样开销).
    fn valid_auto_gen_spec() -> impl Strategy<Value = GenSpec> {
        (
            "[a-zA-Z0-9_]{0,6}",
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            "[@#$%€]{0,3}",
            0usize..24,
            0usize..24,
        )
            .prop_map(
                |(prefix, digits, lower, upper, under, hyph, other, min_pad, span)| {
                    let other: Vec<char> = other.chars().collect();
                    let charset = Charset {
                        digits: digits || !(lower || upper || under || hyph || !other.is_empty()),
                        lowercase: lower,
                        uppercase: upper,
                        underscore: under,
                        hyphen: hyph,
                        other,
                    };
                    let prefix_len = prefix.chars().count();
                    let min = prefix_len + 1 + min_pad; // ≥ prefix_len + 1 > 0
                    let max = min + span;
                    let gen_spec = GenSpec {
                        prefix,
                        charset,
                        length_range: (min, max),
                    };
                    debug_assert!(gen_spec.validate().is_ok());
                    gen_spec
                },
            )
    }

    /// resolve 后 Auto 策略的 gen spec 提取 (三条 RED-1/5 property 共用).
    /// resolve_against 保证 Auto 模式必有 gen spec (None → infer).
    fn resolved_gen(strategy: &MockStrategy) -> &GenSpec {
        strategy
            .gen_spec
            .as_ref()
            .expect("Auto after resolve_against always has gen spec")
    }

    /// RED-1/5 property 共用的前置: Auto 策略构造 + resolve (gen_spec None → infer,
    /// prefix 注入等语义由 resolve_against 统一处理).
    fn resolved_auto_strategy(
        gen_spec: Option<GenSpec>,
        real: &str,
        global_prefix: &str,
    ) -> MockStrategy {
        let mut strategy = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec,
        };
        strategy.resolve_against(real, global_prefix);
        strategy
    }

    proptest! {
        /// 守卫 RED-5: gen_candidate (Auto) body 不含 real ≥k(L) 字符子串 (contracts.md §2).
        #[test]
        fn prop_c5_gen_candidate_auto_body_no_real_substring(
            real in "[A-Za-z0-9]{4,64}",
            seed in any::<u64>(),
        ) {
            let mut strategy = MockStrategy::default();
            strategy.resolve_against(&real, "");
            let mock = gen_candidate(&real, &strategy, seed, 0);
            assert_no_c5_substring(&mock, &real);
        }

        /// 守卫 RED-5: probing 路径 (counter>0 候选) 同样不含 real ≥k(L) 字符子串.
        /// 同 C5 约束, counter>0 候选 (首项与 IR 冲突时的后备)
        /// 同样不应含 real 的 ≥k(L) 字符子串. 这条路径在生产 redact_ir 中由 gen_mock_for_ir
        /// 触发, 本测试直接对 gen_candidate 的多个 counter 取值覆盖.
        #[test]
        fn prop_c5_gen_candidate_probing_no_real_substring(
            real in "[A-Za-z0-9]{4,64}",
            seed in any::<u64>(),
        ) {
            let mut strategy = MockStrategy::default();
            strategy.resolve_against(&real, "");
            for counter in 0u32..8 {
                let mock = gen_candidate(&real, &strategy, seed, counter);
                assert_no_c5_substring(&mock, &real);
            }
        }

        /// 守卫 RED-1: mock 字符全部来自 gen_spec.charset ∪ gen_spec.prefix
        /// (contracts.md §2). gen_spec 双来源覆盖: 显式配置 (Some) 与
        /// resolve_against infer (None → infer_default_for), 两条路径的产出
        /// 都受本性质约束.
        #[test]
        fn prop_mock_matches_gen_spec_charset(
            real in "[A-Za-z0-9]{4,32}",
            gen_spec in proptest::option::of(valid_auto_gen_spec()),
            global_prefix in "(sgm_|mock-)?",
            seed in any::<u64>(),
            counter in 0u32..4,
        ) {
            let strategy = resolved_auto_strategy(gen_spec, &real, &global_prefix);
            let mock = gen_candidate(&real, &strategy, seed, counter);
            let resolved = resolved_gen(&strategy);
            let allowed: std::collections::HashSet<char> = resolved
                .charset
                .enabled_chars()
                .into_iter()
                .chain(resolved.prefix.chars())
                .collect();
            prop_assert!(
                mock.chars().all(|c| allowed.contains(&c)),
                "mock {mock:?} has chars outside charset ∪ prefix (allowed: {allowed:?})"
            );
        }

        /// 守卫 RED-1: mock 总长 (char count) ∈ gen_spec.length_range (contracts.md §2).
        /// 长度语义: length_range 是**含 prefix 的总长** (GenSpec 文档 "char count"),
        /// body 长度区间 = length_range 减 prefix 字符数 (`body_length_range`),
        /// 实现见 `gen_one_auto_body` (prefix 固定 + body 随机).
        #[test]
        fn prop_mock_length_in_range(
            real in "[A-Za-z0-9]{4,32}",
            gen_spec in proptest::option::of(valid_auto_gen_spec()),
            global_prefix in "(sgm_|mock-)?",
            seed in any::<u64>(),
            counter in 0u32..4,
        ) {
            let strategy = resolved_auto_strategy(gen_spec, &real, &global_prefix);
            let mock = gen_candidate(&real, &strategy, seed, counter);
            let (min, max) = resolved_gen(&strategy).length_range;
            let len = mock.chars().count();
            prop_assert!(
                len >= min && len <= max,
                "mock char len {len} not in length_range [{min},{max}]: {mock:?}"
            );
        }

        /// 守卫 RED-5: Auto 模式确定性 — 同 (real, strategy, seed, counter) 两次调用
        /// gen_candidate 结果相等. 内部重试链 (C5_INTERNAL_RETRIES) 是纯函数
        /// (retry 经 hash 进候选, 无随机源 / 无全局状态), 使 C5 实质等价于确定性
        /// 契约 (contracts.md §2). 两次调用之间穿插不同 seed 的干扰调用, 排除
        /// 隐藏可变状态.
        ///
        /// 注: first == second 对恒空输出也平凡成立 — 非平凡性由姊妹 property
        /// `prop_mock_non_empty` / `_matches_gen_spec_charset` / `_length_in_range`
        /// 互补钉住, 勿单独删除姊妹测试.
        #[test]
        fn prop_c5_auto_mode_deterministic(
            real in "[A-Za-z0-9]{4,32}",
            gen_spec in proptest::option::of(valid_auto_gen_spec()),
            global_prefix in "(sgm_|mock-)?",
            seed in any::<u64>(),
            counter in 0u32..4,
        ) {
            let strategy = resolved_auto_strategy(gen_spec, &real, &global_prefix);
            let first = gen_candidate(&real, &strategy, seed, counter);
            // 干扰调用: 不同 seed 的候选穿插其间, 若存在隐藏全局状态会污染第二次结果.
            let _noise = gen_candidate(&real, &strategy, seed ^ 0xdead_beef, counter);
            let second = gen_candidate(&real, &strategy, seed, counter);
            prop_assert_eq!(first, second);
        }
    }

    // ─── gen_candidate (Fixed 模式) ──────────────────────────────────────

    #[test]
    fn gen_candidate_fixed_counter_zero_returns_value() {
        let s = MockStrategy {
            initial: InitialValue::Fixed {
                value: "my-mock-value".into(),
            },
            gen_spec: None,
        };
        assert_eq!(gen_candidate("real", &s, 42, 0), "my-mock-value");
    }

    #[test]
    fn gen_candidate_fixed_counter_positive_adds_suffix() {
        let s = MockStrategy {
            initial: InitialValue::Fixed {
                value: "my-mock".into(),
            },
            gen_spec: None,
        };
        assert_eq!(gen_candidate("real", &s, 42, 1), "my-mock_1");
        assert_eq!(gen_candidate("real", &s, 42, 2), "my-mock_2");
        assert_eq!(gen_candidate("real", &s, 42, 99), "my-mock_99");
    }

    #[test]
    fn gen_candidate_fixed_ignores_seed() {
        // Fixed 模式的候选与 seed 无关 (counter=0 时总是 value 本身).
        let s = MockStrategy {
            initial: InitialValue::Fixed {
                value: "fixed-val".into(),
            },
            gen_spec: None,
        };
        assert_eq!(gen_candidate("real", &s, 0, 0), "fixed-val");
        assert_eq!(gen_candidate("real", &s, 99999, 0), "fixed-val");
    }

    // ─── 端到端: 候选序列 + probing 模拟 ──────────────────────────────────

    #[test]
    fn probing_finds_non_conflicting_candidate() {
        // 模拟 redact 的 probing: 构造一个"首项候选已在上下文中"的场景,
        // 验证 counter 递增能找到不冲突的候选.
        let s = auto_strategy(
            "",
            Charset {
                digits: true,
                ..Default::default()
            },
            8,
        );
        let real = "real-secret";
        let seed = deterministic_seed(real, &s);
        let first = gen_candidate(real, &s, seed, 0);

        // 模拟 IR 已含首项候选 → 需 probing.
        let mut allocated: std::collections::HashSet<String> = std::collections::HashSet::new();
        allocated.insert(first.clone());

        let mut found = None;
        for counter in 0..100 {
            let candidate = gen_candidate(real, &s, seed, counter);
            if !allocated.contains(&candidate) {
                found = Some(candidate);
                break;
            }
        }
        let found = found.expect("probing should find a candidate within 100 tries");
        assert!(!allocated.contains(&found));
        assert_ne!(found, first);
    }

    #[test]
    fn infer_and_generate_roundtrip() {
        // 从 real infer 策略 → resolve → gen_candidate 生成的 mock 长度 == real 长度.
        let real = "sk-Abc123_XY!";
        let mut s = MockStrategy::default();
        s.resolve_against(real, "");
        let seed = deterministic_seed(real, &s);
        let mock = gen_candidate(real, &s, seed, 0);
        assert_eq!(mock.chars().count(), real.chars().count());
        // mock 的字符集应与 real 的字符集一致 (来自 infer).
        let mock_cs = Charset::infer_from(&mock);
        // mock 用到的每个字符类都应在 real 的字符集中出现.
        if mock_cs.digits {
            assert!(s.gen_spec.as_ref().unwrap().charset.digits);
        }
        if mock_cs.uppercase {
            assert!(s.gen_spec.as_ref().unwrap().charset.uppercase);
        }
    }

    // ─── serde roundtrip ─────────────────────────────────────────────────

    #[test]
    fn mock_strategy_serde_roundtrip_auto() {
        let s = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: Some(GenSpec {
                prefix: "sk-".into(),
                charset: Charset {
                    digits: true,
                    lowercase: true,
                    other: vec!['!'],
                    ..Default::default()
                },
                length_range: (15, 20),
            }),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: MockStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn mock_strategy_serde_roundtrip_fixed() {
        let s = MockStrategy {
            initial: InitialValue::Fixed {
                value: "my-fixed-mock".into(),
            },
            gen_spec: None,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: MockStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn mock_strategy_serde_omits_none_gen() {
        // gen=None 时不应出现在 JSON 中 (skip_serializing_if = "Option::is_none").
        let s = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: None,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("gen"), "None gen should be omitted: {json}");
    }

    #[test]
    fn mock_strategy_serde_default_deserializes_from_empty() {
        // 空对象 {} 应反序列化为 Default (向后兼容旧配置无此字段).
        let back: MockStrategy = serde_json::from_str("{}").unwrap();
        assert!(matches!(back.initial, InitialValue::Auto));
        assert!(back.gen_spec.is_none());
    }

    #[test]
    fn initial_value_tagged_serde() {
        // 验证 tag = "kind".
        let auto_json = serde_json::to_string(&InitialValue::Auto).unwrap();
        assert!(auto_json.contains("\"kind\":\"auto\""));
        let fixed_json = serde_json::to_string(&InitialValue::Fixed { value: "x".into() }).unwrap();
        assert!(fixed_json.contains("\"kind\":\"fixed\""));
        assert!(fixed_json.contains("\"value\":\"x\""));

        let back: InitialValue = serde_json::from_str(&auto_json).unwrap();
        assert_eq!(back, InitialValue::Auto);
    }

    #[test]
    fn mock_strategy_serde_toml_roundtrip() {
        // 验证 TOML 序列化 (config 文件用 TOML).
        let s = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: Some(GenSpec {
                prefix: "sk-".into(),
                charset: Charset {
                    digits: true,
                    lowercase: true,
                    ..Default::default()
                },
                length_range: (10, 15),
            }),
        };
        // 用一个 wrapper struct 因为 TOML 顶层必须是 table.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Wrapper {
            mock_strategy: MockStrategy,
        }
        let w = Wrapper { mock_strategy: s };
        let toml_str = toml::to_string(&w).unwrap();
        let back: Wrapper = toml::from_str(&toml_str).unwrap();
        assert_eq!(w.mock_strategy, back.mock_strategy);
    }
}
