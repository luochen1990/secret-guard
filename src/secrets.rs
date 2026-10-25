//! Secret 类型定义 + 校验 + [`DynamicEntry`] 实现 + effective 视图 + 处理策略
//! ([`SecretStrategy`]: redact 默认 / reject (RED-9) / placeholder (RED-10, 批2) /
//! protect 搁置值 fail-fast).
//!
//! # 三层数据模型 (与 [`crate::provider`] 完全对称)
//!
//! [`SecretTable`] (= [`DynamicTable<SecretEntry>`](crate::config::DynamicTable)) 同时持有:
//! - `static_entries`: 来自 `secret-guard.toml` 的只读基线, 启动时加载, 进程内不可变.
//! - `dynamic_entries`: 来自 `secret-guard.state.toml` 的 WebUI 编辑结果, 可 CRUD.
//! - `decisions`: 与 [`crate::provider::ProviderTable`] 共享同一份 [`Decisions`] 实例
//!   (因为两者都写 state.toml).
//!
//! 合并 / CRUD / 持久化等所有通用逻辑都在 [`crate::config::DynamicTable`] 中实现,
//! 本模块只补充 Secret 类型特定的小部分: [`DynamicEntry`] impl + effective 视图
//! 的 masked 映射 (`compute_effective_secret`) + secret 校验工具.
//!
//! # 持久化与并发
//!
//! 见 [`crate::config::DynamicTable`] 的文档.
//!
//! # secret value 的两种来源 (`resolve_value`)
//!
//! 与 [`crate::provider::Provider`] 的 `api_key` / `api_key_file` 对称, `SecretEntry` 也支持
//! 两种 value 配置方式 (互斥, 同时设置会在 `validate()` 报错):
//!
//! | 字段 | 类型 | 适用场景 |
//! |---|---|---|
//! | `value` | `String` (直接值) | 本地 dev / 简单部署 |
//! | `value_file` | `Option<PathBuf>` | 生产部署 / sops-nix / systemd LoadCredential |
//!
//! **与 Provider 的关键差异 (生命周期)**:
//! - Provider 的 `api_key_file` 是**运行时每次请求读文件** (热路径, 读不到 → warn + 空字符串 fallback).
//!   因为 provider 失败只影响转发, 不影响安全性.
//! - Secret 的 `value_file` 是**启动时一次性 resolve** (config 加载阶段读一次, 内容写入 `value`
//!   字段, 清空 `value_file`). 读不到 → **fail-fast 启动失败**. 因为 secret 缺失会让 Redact
//!   静默失效, 进而导致真实 Secret 泄漏到 LLM provider — 这正是 secret-guard 要防止的事故.
//!
//! resolve 后 Redact 核心逻辑零改动 (按 `value` 字段做字节匹配, 无额外 IO).
//! 部署示例 (批量注入) 见 `docs/deployment-nixos.md`.

use serde::{Deserialize, Serialize};

use crate::config::{
    Decisions, DynamicEntry, DynamicState, DynamicTable, EffectiveSource, OverrideMode,
    classify_source, pick_with_inherit,
};
use crate::mock::MockStrategy;

/// 单条 secret 注册项.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// 唯一 id (slug). 同一份表 (static 或 dynamic) 中必须唯一.
    /// 通过 [`validate_id`] 校验合法字符集.
    pub id: String,
    /// 可选的人类可读名称 (用于 Web UI 显示).
    #[serde(default)]
    pub name: Option<String>,
    /// 类别: 影响 mock_secret 的生成策略 (第四步细化).
    #[serde(default)]
    pub category: SecretCategory,
    /// 真实 secret 明文 (服务端使用; 永不通过 API 返回).
    ///
    /// 与 [`SecretEntry::value_file`] 互斥 — 同时设置会在 [`SecretEntry::validate`] 中报错.
    /// 启动时若设置了 `value_file`, [`SecretEntry::resolve_value`] 会把文件内容 (trim 后)
    /// 写入此字段并清空 `value_file`, 之后 redact 热路径只读 `value` (零额外 IO).
    #[serde(default)]
    pub value: String,
    /// 可选: 从文件路径读取 secret 明文. 与 [`SecretEntry::value`] 互斥.
    ///
    /// # 设计意图 (与 [`crate::provider::DirectProvider::api_key_file`] 对称)
    ///
    /// 让 `secret-guard.toml` 本身不含敏感数据, secret 由外部机制 (sops-nix /
    /// systemd LoadCredential / docker secrets / k8s secrets) 解密到独立路径.
    /// 这极大简化了上游 nixos module 的配置 — toml 可直接进 git 或 nix store.
    ///
    /// # 生命周期: 启动时一次性 resolve
    ///
    /// 与 Provider 的 `api_key_file` (每次请求读文件, warn+fallback) 不同, secret 的
    /// `value_file` 在 config 加载时只读一次, 把内容写入 `value` 字段后清空 `value_file`.
    /// 这样 redact 核心逻辑 (按 `value` 做字节匹配) 零改动, 也避免热路径 N×IO.
    ///
    /// 读文件失败 → fail-fast (返回 Err, 由 main 传播为非零退出码). 原因: secret 是 redact 的核心数据,
    /// 静默 fallback 到空值会让 redact 失效, 导致 secret 泄漏到 LLM provider —
    /// 这正是 secret-guard 要防止的事故. fail-fast 让误配在部署时就暴露.
    ///
    /// 文件内容会被 `trim()` (容忍 sops / `echo | tee` 末尾换行符).
    #[serde(default)]
    pub value_file: Option<std::path::PathBuf>,

    /// Mock 策略 (两维度: 初始值 / 生成策略).
    ///
    /// 未配置 (`#[serde(default)]`) → [`MockStrategy::default`] (Auto + 无 gen).
    /// 在 [`SecretEntry::validate_and_resolve`] 的 resolve_value 步骤后, 若仍是 Auto + 无 gen,
    /// 会调用 [`MockStrategy::resolve_against`] 用 real value infer 默认 gen spec.
    ///
    /// redact 路径 (见 [`crate::redact`]) 通过 [`crate::mock::gen_candidate`] 消费此策略.
    #[serde(default)]
    pub mock_strategy: MockStrategy,

    /// per-secret 处理策略 (#305): 该 secret 真值命中请求时的处置方式.
    ///
    /// - `redact` (默认): 替换为 mock — 既有行为, 全部 RED-* 契约逐字不变.
    /// - `reject`: 真值出现于请求 → 整请求拒绝转发 (503, 零上游外发, message 只含
    ///   secret id + reason, SEC-2 同型). **显式策略, 不受 `on_probe_exhausted`
    ///   fail_open/closed 模式影响** (契约 RED-9).
    /// - `placeholder` (批2): 替换为明示假值 `[REDACTED:{id}]`, 响应不还原 +
    ///   蜜罐泄露检测 (响应中出现真值 → WARN + record 打标, 不干预转发).
    ///   契约 RED-10, 实现见 [`crate::redact`] C9 段.
    /// - `protect`: 搁置值 (#305 完结时用户未想清语义, 重启需新 issue), 配置即
    ///   validate 报错 fail-fast, 见 [`SecretEntry::validate`] 的检查.
    ///
    /// 注: `strategy` 不参与 [`crate::redact::init_seed`] 的哈希 — 翻转策略不应
    /// 改变其他 secret 的 mock (C3 前缀缓存友好).
    #[serde(default)]
    pub strategy: SecretStrategy,
}

impl SecretEntry {
    /// 若设置了 `value_file`, 读取文件内容写入 `value` 并清空 `value_file`.
    /// 之后 redact 热路径只读 `value`, 无额外 IO.
    ///
    /// # 语义
    ///
    /// - `value` 非空 + `value_file` None → 不变 (直接值模式)
    /// - `value` 空 + `value_file` Some → 读文件, trim, 写入 `value`, 清空 `value_file`
    /// - 两者都非空 → [`SecretEntry::validate`] 已拒绝 (不会走到这里)
    /// - 两者都空 → 不变 (由 [`validate_value`] 在 validate 阶段拒绝)
    ///
    /// # 错误处理: fail-fast
    ///
    /// 读文件失败返回 `Err`. 调用方 ([`Config::load_or_default`] /
    /// [`DynamicState::load_or_empty`]) 会把错误转成启动失败, 让误配在部署时暴露.
    /// 见 [`SecretEntry::value_file`] 字段文档的"生命周期"段.
    ///
    /// [`Config::load_or_default`]: crate::config::Config::load_or_default
    /// [`DynamicState::load_or_empty`]: crate::config::DynamicState::load_or_empty
    pub fn resolve_value(&mut self) -> Result<(), String> {
        let Some(path) = self.value_file.take() else {
            return Ok(());
        };
        match std::fs::read_to_string(&path) {
            Ok(s) => {
                self.value = s.trim().to_string();
                Ok(())
            }
            Err(e) => Err(format!(
                "failed to read value_file for secret '{}': {} (path: {})",
                self.id,
                e,
                path.display()
            )),
        }
    }

    /// 完整的 entry 入系统校验序列: 结构 validate → resolve_value → 内容 validate_value.
    ///
    /// 所有 entry 进入系统的路径 (static config 加载 / dynamic state 加载 / WebUI upsert)
    /// 都应通过此方法, 保证 "互斥 + 文件可读 + value 内容合法" 三条契约一致执行,
    /// 避免分散在三处的 ad-hoc 调用序列漂移.
    ///
    /// `global_mock_prefix` 来自 `[redact] global_mock_prefix`, 透传给 validate_value
    /// (拒绝 real 含 prefix) 与 resolve_against (注入到 Auto 模式的 gen_spec.prefix).
    ///
    /// # 步骤设计动机
    ///
    /// 1. **结构 validate** ([`DynamicEntry::validate`]): id 格式 + value 与 value_file 互斥
    ///    + mock_strategy 基础校验 (不依赖 real value 的部分, 如 Fixed 非空). 在 resolve 前跑, 能在 value 还空 (value_file 模式) 时识别结构错误.
    /// 2. **resolve_value**: 从 `value_file` 读文件写入 `value` (fail-fast: 读失败 → Err).
    /// 3. **内容 validate** ([`validate_value`]): resolve 后 value 是最终 redact 用的字节,
    ///    必须满足长度 / mock prefix / PUA 约束.
    /// 4. **category↔形状矛盾检测** ([`MockStrategy::category_shape_mismatch`]):
    ///    标注与值形状矛盾时 WARN (PEM 矛盾 = 提醒改标注保持所见/所为一致;
    ///    JWT/公开前缀矛盾 = 提醒改标注可启用结构化 mock). 必须在步骤 5 的
    ///    resolve **之前**跑 — 之后 `gen_spec.is_some()` 恒真 (infer 填充与用户
    ///    显式配置不可区分), 检测会静默失效.
    /// 5. **mock_strategy resolve + validate** ([`MockStrategy::resolve_against`] +
    ///    [`MockStrategy::validate_against_real`]): 用 resolve 后的 real value infer
    ///    gen spec (Auto 模式) 并校验 Fixed 不含 real 子串 (C5 best-effort). 必须在 value
    ///    resolve 后跑, 因为 infer 与 C5 检查都依赖 real value.
    /// 6. **候选空间 gate** ([`MockStrategy::lint_candidate_space`]): gen spec 定型后
    ///    对弱候选空间 (低于 [`crate::mock::MIN_CANDIDATE_SPACE_WARN`]) **fail-fast 拒绝**
    ///    (#383 方案 D, 2026-10-21: 自 WARN 升级 — 从配置期源头消灭 probing 耗尽的
    ///    触发面, 见 contracts.md RED-9). 仅对 redact 策略生效 (reject/placeholder
    ///    不做 mock 生成, 无触发面); Auto 路径经 widen 兜底恒达标, 命中的必是用户
    ///    手动配置的弱 gen_spec. 同 gate 族还有过短 real 的 redact 拒绝
    ///    (`MIN_REDACT_REAL_CHARS`, 物理边界 — Auto widen 救不了).
    ///
    /// # 与 Provider 的差异
    ///
    /// Provider 不需要此序列 — 它的 `api_key` 允许空 (Ollama 等场景), 且 `effective_api_key`
    /// 是运行时每次请求读文件. 见 [`crate::provider::DirectProvider::effective_api_key`].
    pub fn validate_and_resolve(&mut self, global_mock_prefix: &str) -> Result<(), String> {
        self.validate()?;
        self.resolve_value()?;
        validate_value(&self.value, global_mock_prefix)?;
        // ── #383 方案 D gate ①: 过短 real + redact 策略拒绝 ──
        // 在 resolve 之前判 (value 已 resolve): 等长 Auto 推断下 n < MIN_REDACT_REAL_CHARS
        // 时候选空间物理上不可达 2^20 (上界 65^n — 62 标准类 + n 个 real 自带 other 字符,
        // n=3 时 ≈ 27 万), Auto widen 兜底救不了 — 若留给 gate ② 只能得到 "widen charset"
        // 的误导性引导 (Auto 推断结果不可配), 此处给出唯一可行动的引导: 换策略.
        // 只挡 redact (reject/placeholder 不做 mock 生成, 短值合法); chars().count()
        // 非 len() — 与等长约束/mock 长度的字符口径一致 (multibyte 安全).
        if matches!(self.strategy, SecretStrategy::Redact)
            && self.value.chars().count() < MIN_REDACT_REAL_CHARS
        {
            return Err(format!(
                "secret {}: value too short for equal-length redact mock generation \
                 (physical candidate-space boundary; use strategy 'reject' or \
                 'placeholder' instead)",
                self.id
            ));
        }
        // category↔形状矛盾检测 (resolve_against **之前**: 此时 gen_spec.is_some()
        // ⟺ 用户显式配置, infer 填充与用户配置可区分): 标注与值的形状特征矛盾时
        // WARN — PEM 矛盾 = 行为已最优但标注是语义债 (所见非所为), JWT/公开前缀
        // 矛盾 = 静默丢失仿真增强 (暴露映射表/标注错误). 检测面与跳过条件的
        // 完整语义见 `category_shape_mismatch` doc.
        if let Some(mismatch) = self.mock_strategy.category_shape_mismatch(
            &self.value,
            self.category,
            global_mock_prefix,
        ) {
            tracing::warn!(
                secret_id = %self.id,
                category = self.category.as_str(),
                detected = mismatch.detected(),
                suggested_category = mismatch.suggested_category().as_str(),
                "secret category label mismatches the value's detected shape; \
                 relabel for consistency (pem: mock already structured, label is \
                 cosmetic) or to enable structured mock (jwt/public_prefix)"
            );
        }
        // category 透传: shape 推断的语义 hint (PrivateKey PEM 不 gate category —
        // 形状自证; Token/ApiKey gate JWT/公开前缀判定, 见 `infer_shape`).
        self.mock_strategy
            .resolve_against(&self.value, self.category, global_mock_prefix);
        self.mock_strategy.validate_against_real(&self.value)?;
        // ── #383 方案 D gate ②: 弱候选空间 gen_spec 从 WARN 升级为拒绝 ──
        // resolve 之后 gen_spec 已定型 (Auto 路径经 widen 兜底恒 ≥ 阈值 — 此处命中的
        // 必是用户手动配置的弱 gen_spec), 纯读. 所有 entry 进入系统的路径 (static 加载
        // / dynamic 加载 / WebUI upsert) 都经过本方法, 是公共 choke point. 仅对 redact
        // 策略生效 (同 gate ① 的策略边界). Err message 严禁含 secret value 或 mock
        // (SEC 红线) — 只含 id / 数字 / 建议.
        if matches!(self.strategy, SecretStrategy::Redact)
            && let Some(lint) = self.mock_strategy.lint_candidate_space()
        {
            return Err(format!(
                "secret {}: mock gen spec candidate space {} is below the minimum \
                 recommended {} (runtime probing may exhaust and degrade via \
                 on_probe_exhausted); widen charset or length_range, or switch \
                 strategy to reject/placeholder",
                self.id,
                lint.space,
                crate::mock::MIN_CANDIDATE_SPACE_WARN
            ));
        }
        Ok(())
    }
}

/// Secret 类别 (mock 生成器的选择参数, category-aware shape 推断见
/// `crate::mock` 头部). 定义在 mock 模块 (依赖方向 `secrets → mock` 单向),
/// 此处 re-export 维持既有 API (`use crate::secrets::SecretCategory` 不变).
pub use crate::mock::SecretCategory;

/// per-secret 处理策略 (#305): secret 真值命中请求时 redact pipeline 的处置方式.
///
/// 语义总览见 [`SecretEntry::strategy`] 字段文档; reject 行为契约 = contracts.md
/// **RED-9**, placeholder 行为契约 = contracts.md **RED-10** (批2 交付).
/// `protect` 已定义但行为搁置 (#305 完结决策), 由 [`SecretEntry::validate`]
/// fail-fast 拒绝 (防静默失效).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretStrategy {
    /// 默认: 真值替换为 mock (既有 C1-C7 行为).
    #[default]
    Redact,
    /// 请求侧 mock 伪装 + 全响应 mock→placeholder (当初 #305 裁决的语义, 保留作
    /// 重启参考; 已搁置 — #305 完结时用户未想清, 配置即 validate 报错).
    Protect,
    /// 明示假值替换 + 蜜罐泄露检测 (批2, RED-10): 请求侧真值 →
    /// `[REDACTED:{id}]`, 响应不还原; 检测到真值出现于 LLM 响应则 WARN + 打标.
    Placeholder,
    /// 真值出现于请求 → 整请求拒绝转发 (503, 零上游外发).
    Reject,
}

impl SecretStrategy {
    /// 所有变体及其字符串名 — 派生自 `as_str()` (const fn match 是字符串单源,
    /// serde rename 同步由 roundtrip 测试守卫; 定长数组不随新增 variant 自动扩 —
    /// ALL 漏项无自动守卫, 需人工随新增 variant 同步).
    /// 值域 SSOT: validate 的 fail-fast 判定消费此表; 前端 strategy 选择器
    /// 硬编码已实现值 (redact/reject/placeholder), 不从本表派生.
    pub const ALL: [(Self, &'static str); 4] = [
        (Self::Redact, Self::Redact.as_str()),
        (Self::Protect, Self::Protect.as_str()),
        (Self::Placeholder, Self::Placeholder.as_str()),
        (Self::Reject, Self::Reject.as_str()),
    ];

    pub const fn as_str(self) -> &'static str {
        // 穷尽 match: 新增 variant 编译期引导补齐 (本 match 是字符串单源, ALL 派生自它).
        match self {
            Self::Redact => "redact",
            Self::Protect => "protect",
            Self::Placeholder => "placeholder",
            Self::Reject => "reject",
        }
    }
}

/// 校验 secret id (slug). 允许: 字母/数字开头, 长度 1-64, 仅含 `[A-Za-z0-9_-]`.
/// 防止 XSS / 路径冲突 / 路由切段问题.
///
/// 同时被 secret 与 provider 的 id 校验复用 (单一事实来源).
pub fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 64 {
        return Err(format!("id length must be 1..=64, got {}", id.len()));
    }
    let mut chars = id.chars();
    let first = chars.next().expect("non-empty checked above");
    if !first.is_ascii_alphanumeric() {
        return Err(format!("id must start with [A-Za-z0-9], got '{first}'"));
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(format!(
                "id contains illegal character '{c}' (allowed: alphanumeric, '_', '-')"
            ));
        }
    }
    Ok(())
}

/// redact 策略 real 的最小字符数 (#383 方案 D gate ①, 2026-10-21).
///
/// 物理边界推导: 等长 Auto 推断的候选空间上界 = charset_size^n (n = real 字符数,
/// charset ≤ 62 标准类 + n 个 real 自带的 other 字符), n ≤ 3 时最大 65³ ≈ 27.5 万
/// < 2^20 — widen 兜底也救不了, mock probing 耗尽是物理必然而非对抗构造.
/// n ≥ 4 恒可达标 (62⁴ ≈ 1480 万). 另一独立理由: 极短值在 IR 子串匹配中是海量
/// 误命中源 (替换会大面积破坏请求文本). 拒绝时引导 reject/placeholder
/// (不做 mock 生成, 短值合法). 用 `chars().count()` 口径 — 与等长约束/mock 长度
/// 的字符语义一致 (multibyte 安全), 区别于 [`validate_value`] 的字节下限.
const MIN_REDACT_REAL_CHARS: usize = 4;

/// 校验 secret value. 防止用户误配短 / 结构性 / 含 PUA / 与 mock prefix 冲突的 secret
/// (避免 redact 时破坏整个请求 body 或 round-trip identity).
///
/// `global_mock_prefix` 来自 `[redact] global_mock_prefix` (默认空串). 若非空且 real
/// secret 含此 prefix, 则 mock 可能与 real 共享 ≥`k(L)` 字符子串违反 C5, 故拒绝
/// (k(L) 见 [`crate::mock::c5_threshold_len`]). 空串时此检查跳过 (空 prefix 不产生冲突).
pub fn validate_value(value: &str, global_mock_prefix: &str) -> Result<(), String> {
    if value.len() < 3 {
        return Err(format!(
            "secret value too short (min 3 bytes), got {}",
            value.len()
        ));
    }
    // 含 mock prefix → 与 redact 输出冲突, 拒绝. 空 prefix 跳过 ("" 是任意串子串).
    if !global_mock_prefix.is_empty() && value.contains(global_mock_prefix) {
        return Err(format!(
            "secret value must not contain the mock prefix '{global_mock_prefix}' (reserved for redaction)"
        ));
    }
    // PUA 字符与 mock 输出冲突, 拒绝.
    if value
        .chars()
        .any(|c| (0xE000..=0xF8FF).contains(&(c as u32)))
    {
        return Err("secret value must not contain Unicode PUA characters (U+E000..U+F8FF)".into());
    }
    Ok(())
}

/// 对 secret / api_key 做最小信息脱敏:
/// - 空 → 空;
/// - 短 (≤8 字符) → 用相同长度的 `*` 填充, 暴露长度但不暴露内容;
/// - 长 (>8 字符) → 保留首尾各 1 字符 + 中间 `*` (长度等于原值).
///
/// `pub(crate)` 让 web::api / provider / secrets 共用同一份实现 (DRY).
pub(crate) fn mask_value(v: &str) -> String {
    let chars: Vec<char> = v.chars().collect();
    if chars.is_empty() {
        return String::new();
    }
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head = chars[0];
    let tail = chars[chars.len() - 1];
    let stars = "*".repeat(chars.len().saturating_sub(2));
    format!("{head}{stars}{tail}")
}

/// effective 快照 → 非空真值集合 (#257 S0.5 隐私扫描的排除集投影 SSOT:
/// proxy 两条 redact seam 的 `PrivacyScanner::submit` 与 web alerts API 的
/// 视图过滤共用 — 空值跳过的预处理在此一次收口, 消费方不再重复过滤).
pub fn non_empty_values(entries: &[SecretEntry]) -> Vec<String> {
    entries
        .iter()
        .filter(|e| !e.value.is_empty())
        .map(|e| e.value.clone())
        .collect()
}

// ─── DynamicEntry impl: 把 SecretEntry 接入泛型 DynamicTable ──────────────

impl DynamicEntry for SecretEntry {
    fn id(&self) -> &str {
        &self.id
    }

    fn validate(&self) -> Result<(), String> {
        validate_id(&self.id)?;
        // value 与 value_file 互斥: 同时设置语义不明, 几乎肯定是误操作
        // (比如 toml 既填了 value 又忘了删 value_file).
        if !self.value.is_empty() && self.value_file.is_some() {
            return Err(format!(
                "secret {} has both value and value_file set; pick one",
                self.id
            ));
        }
        // value 内容校验 (长度 / PUA) 只在 value 非空时跑 —
        // value_file 模式下 value 要等 resolve_value 才有内容, 那时再由
        // validate_and_resolve 跑完整 validate_value (含 global_mock_prefix 检查).
        // 这与 Provider::validate 不校验 api_key 内容 (允许空) 的模式对称.
        //
        // prefix 检查不在 validate() 做 (它需要 global_mock_prefix 配置, 属 resolve 阶段职责),
        // 由 validate_and_resolve 统一执行 (SSOT).
        if !self.value.is_empty() {
            validate_value(&self.value, "")?;
        }
        // mock_strategy 基础校验 (Fixed 非空 / Auto+gen 配置合法). 依赖 real value 的
        // C5 检查由 validate_against_real 在 resolve 后执行, 不在这里 (兼容 value_file 模式).
        self.mock_strategy.validate()?;
        // strategy 值域 fail-fast (#305): protect 已定义但行为搁置 (#305 完结决策), 接受
        // 该配置会静默按 redact 处理 — 显式报错. 放在本 validate 而非
        // validate_and_resolve 专属步骤: validate_and_resolve 第一步就是 self.validate(),
        // 且 upsert_dynamic (WebUI CRUD 的底层) 独立调用本方法 — 一处检查同时覆盖
        // static 加载 / dynamic 加载 / WebUI upsert 全部入口路径.
        // placeholder 已在批2 交付 (明示假值 + 蜜罐检测, RED-10).
        if matches!(self.strategy, SecretStrategy::Protect) {
            return Err(format!(
                "secret {}: strategy '{}' is not implemented yet (shelved; see #305)",
                self.id,
                self.strategy.as_str()
            ));
        }
        Ok(())
    }

    fn set_state_field(state: &mut DynamicState, entries: Vec<Self>) {
        state.secrets = entries;
    }

    fn get_decision(d: &Decisions, id: &str) -> OverrideMode {
        d.secret(id)
    }

    fn set_decision(d: &mut Decisions, id: &str, mode: OverrideMode) {
        d.set_secret(id, mode);
    }

    /// 持久化投影: infer 填充的 gen_spec (gen_inferred 标记) 剥离 — state.toml
    /// 只含用户声明, 每次加载 fresh infer. 用户显式配置的 gen_spec 保留.
    /// value 的 resolve 态 (value_file 读入的明文) 按既有语义保留落盘
    /// (state.toml 含明文 dynamic value, 见根 AGENTS.md 配置模型).
    /// 语义与动机见 `DynamicEntry::strip_runtime_state` trait doc.
    fn strip_runtime_state(&self) -> Self {
        let mut e = self.clone();
        if e.mock_strategy.gen_inferred {
            e.mock_strategy.gen_spec = None;
            e.mock_strategy.gen_inferred = false;
        }
        e
    }
}

// ─── SecretTable 别名 + 类型特定 effective 视图 ────────────────────────────

/// Secret 表. 在 AppState (crate::state) 中作为共享可变状态.
///
/// 实际类型是 [`DynamicTable<SecretEntry>`](crate::config::DynamicTable),
/// 所有通用方法 (effective_raw / get_effective / upsert_dynamic / ...) 在那里实现;
/// 下面的 `impl DynamicTable<SecretEntry>` 仅补充 Secret 特有的 effective 视图.
pub type SecretTable = DynamicTable<SecretEntry>;

/// Secret 的合并视图项. value 已脱敏 (永不回传真实值).
#[derive(Debug, Clone, Serialize)]
pub struct EffectiveSecret {
    pub id: String,
    pub name: Option<String>,
    pub category: SecretCategory,
    pub value_masked: String,
    pub value_length: usize,
    pub mock_strategy: MockStrategy,
    pub strategy: SecretStrategy,

    pub source: EffectiveSource,
    pub decision: OverrideMode,
    pub static_version: Option<SecretMasked>,
    pub dynamic_version: Option<SecretMasked>,
}

/// 对外返回时屏蔽真实 value. 见 `mask_value` 的脱敏规则.
#[derive(Debug, Clone, Serialize)]
pub struct SecretMasked {
    pub id: String,
    pub name: Option<String>,
    pub category: SecretCategory,
    pub value_masked: String,
    pub value_length: usize,
    pub mock_strategy: MockStrategy,
    pub strategy: SecretStrategy,
}

impl From<SecretEntry> for SecretMasked {
    fn from(e: SecretEntry) -> Self {
        Self {
            value_masked: crate::secrets::mask_value(&e.value),
            value_length: e.value.chars().count(),
            id: e.id,
            name: e.name,
            category: e.category,
            mock_strategy: e.mock_strategy,
            strategy: e.strategy,
        }
    }
}

impl DynamicTable<SecretEntry> {
    /// 返回 effective 视图 (WebUI 列表). value 已脱敏.
    pub fn effective_snapshot(&self) -> Vec<EffectiveSecret> {
        self.effective_triples()
            .into_iter()
            .filter_map(|(s, d, m)| compute_effective_secret(s, d, m))
            .collect()
    }
}

/// 给定 (static_ver, dynamic_ver, mode), 计算 effective secret 的合并视图.
/// 走 `pick_with_inherit` 统一收口 (SecretEntry 的 inherit 是 no-op, 行为与裸
/// pick_effective 等价 — 保持三条 effective 读取路径的收口不变量成立, 见 #157).
fn compute_effective_secret(
    static_ver: Option<SecretEntry>,
    dynamic_ver: Option<SecretEntry>,
    mode: OverrideMode,
) -> Option<EffectiveSecret> {
    let raw = pick_with_inherit(static_ver.clone(), dynamic_ver.clone(), mode)?;
    let source = classify_source(static_ver.is_some(), dynamic_ver.is_some(), mode)
        .expect("pick (with inherit) Some ⇒ classify_source Some");
    let static_masked = static_ver.map(SecretMasked::from);
    let dynamic_masked = dynamic_ver.map(SecretMasked::from);
    Some(EffectiveSecret {
        value_masked: crate::secrets::mask_value(&raw.value),
        value_length: raw.value.chars().count(),
        id: raw.id,
        name: raw.name,
        category: raw.category,
        mock_strategy: raw.mock_strategy,
        strategy: raw.strategy,
        source,
        decision: mode,
        static_version: static_masked,
        dynamic_version: dynamic_masked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EffectiveSource, OverrideMode};
    use std::path::PathBuf;
    use std::sync::Arc;

    use parking_lot::RwLock;

    use crate::config::Decisions;

    fn entry(id: &str, value: &str) -> SecretEntry {
        SecretEntry {
            id: id.into(),
            name: Some(format!("name-{id}")),
            category: SecretCategory::ApiKey,
            value: value.into(),
            value_file: None,
            mock_strategy: MockStrategy::default(),
            strategy: SecretStrategy::default(),
        }
    }

    fn empty_decisions() -> Arc<RwLock<Decisions>> {
        Arc::new(RwLock::new(Decisions::default()))
    }

    fn tempfile_path() -> PathBuf {
        let id = uuid::Uuid::new_v4().to_string();
        let path = PathBuf::from(format!("/tmp/opencode/tmp/test-secrets-{id}.toml"));
        // 确保父目录存在, 否则 atomic_write 的 File::create 会因 ENOENT 失败
        // (测试不应依赖外部预先创建的目录).
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        path
    }

    // ─── 类型特定的校验函数 ─────────────────────────────────────────────

    #[test]
    fn validate_id_accepts_valid_slugs() {
        assert!(validate_id("a").is_ok());
        assert!(validate_id("abc-123_XYZ").is_ok());
        assert!(validate_id(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn validate_id_rejects_invalid() {
        assert!(validate_id("").is_err());
        assert!(validate_id(&"a".repeat(65)).is_err());
        assert!(validate_id("-abc").is_err());
        assert!(validate_id("_abc").is_err());
        assert!(validate_id("has space").is_err());
        assert!(validate_id("slash/here").is_err());
        assert!(validate_id("quote'here").is_err());
        assert!(validate_id("<html>").is_err());
    }

    #[test]
    fn validate_value_rejects_short_pua_and_mock_prefix() {
        // 太短.
        assert!(validate_value("ab", "").is_err());
        // 含 PUA 字符.
        assert!(validate_value("ok\u{E000}value", "").is_err());
        // 合法 (空 global_prefix → 不检查 prefix).
        assert!(validate_value("normal-secret-value", "").is_ok());
        // 配置了 global_prefix 后, 含该 prefix 的 value 被拒绝.
        assert!(validate_value("contains sgm_ in middle", "sgm_").is_err());
        // 不含 prefix 的合法值.
        assert!(validate_value("normal-secret-value", "sgm_").is_ok());
    }

    #[test]
    fn mask_value_hides_full_content() {
        assert_eq!(mask_value(""), "");
        assert_eq!(mask_value("short"), "*****"); // ≤8 → 全 *
        assert_eq!(mask_value("12345678"), "********");
        assert_eq!(mask_value("123456789"), "1*******9"); // >8 → 首尾各 1
        // 任意 >8 长度: head + (n-2) stars + tail.
        let secret = "sk-1234567890abcdef";
        let masked = mask_value(secret);
        assert_eq!(masked.len(), secret.chars().count());
        assert!(masked.starts_with('s'));
        assert!(masked.ends_with('f'));
        // 中间应全是 '*'.
        let middle: String = masked
            .chars()
            .skip(1)
            .take(masked.chars().count() - 2)
            .collect();
        assert!(middle.chars().all(|c| c == '*'));
    }

    #[test]
    fn secret_category_roundtrip_str() {
        for (cat, name) in SecretCategory::ALL {
            // serde 字符串名与 as_str 一致 (as_str 是单源, 双编码面在 serde rename —
            // 漂移会让 WebUI 词表/用户手写 toml 的值被 serde 拒绝, 此处锁死).
            let json = serde_json::to_string(&cat).unwrap();
            assert_eq!(json, format!("{name:?}"));
        }
        // 其他类型转换正确.
        assert_eq!(SecretCategory::default(), SecretCategory::ApiKey);
    }

    // ─── SecretStrategy (#305 批1): serde 兼容 + validate fail-fast ─────────

    #[test]
    fn secret_strategy_defaults_to_redact_for_legacy_config() {
        // 旧配置不带 strategy 字段 → Redact (零行为变化锚, RED-9 向后兼容).
        let e: SecretEntry = toml::from_str(
            r#"
            id = "legacy"
            value = "sk-legacy-secret-value"
        "#,
        )
        .unwrap();
        assert_eq!(e.strategy, SecretStrategy::Redact);
        assert_eq!(SecretStrategy::default(), SecretStrategy::Redact);
    }

    #[test]
    fn secret_strategy_reject_parses_from_toml() {
        let e: SecretEntry = toml::from_str(
            r#"
            id = "r"
            value = "sk-rejectable-secret-value"
            strategy = "reject"
        "#,
        )
        .unwrap();
        assert_eq!(e.strategy, SecretStrategy::Reject);
        // 未知值被 serde 拒绝 (fail-fast, 不静默 fallback).
        assert!(
            toml::from_str::<SecretEntry>(
                r#"
            id = "bad"
            value = "sk-some-secret-value-xx"
            strategy = "bogus"
        "#
            )
            .is_err()
        );
    }

    #[test]
    fn secret_strategy_all_roundtrip_str() {
        for (s, name) in SecretStrategy::ALL {
            // serde 字符串名与 as_str 一致 (as_str 是单源, 双编码面在 serde rename).
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(json, format!("{name:?}"));
        }
    }

    #[test]
    fn validate_rejects_unimplemented_strategy_values() {
        // protect 已定义但行为搁置 (#305 完结决策) → validate fail-fast (#305).
        // 两条入口路径都挡: 直接 validate() (upsert_dynamic 底层独立调用) 与
        // validate_and_resolve() (static/dynamic 加载 + WebUI handler 的 choke point).
        let bad = SecretStrategy::Protect;
        let mut e = entry("unimpl", "sk-unimplemented-strategy");
        e.strategy = bad;
        let err = e.validate().unwrap_err();
        assert!(
            err.contains("not implemented yet"),
            "validate() should reject {bad:?}: {err}"
        );
        assert!(
            err.contains("shelved; see #305"),
            "err should point to the shelving decision: {err}"
        );
        let mut e2 = entry("unimpl", "sk-unimplemented-strategy");
        e2.strategy = bad;
        assert!(
            e2.validate_and_resolve("").is_err(),
            "validate_and_resolve() must also reject {bad:?}"
        );
        // 可用值 (redact / reject / placeholder — 批2 交付, RED-10) 不被 validate
        // 挡 — 行为约束在 redact pipeline.
        for ok in [
            SecretStrategy::Redact,
            SecretStrategy::Reject,
            SecretStrategy::Placeholder,
        ] {
            let mut e = entry("ok-strategy", "sk-usable-strategy-value");
            e.strategy = ok;
            assert!(e.validate().is_ok(), "{ok:?} should pass validate");
        }
    }

    // ─── effective_snapshot: 类型特定的 masked 视图 ─────────────────────
    //
    // 通用合并 / CRUD / 持久化 / decision 行为已在 `crate::config::table_tests`
    // 用 SecretEntry 作为 canonical 类型覆盖. 这里只测 EffectiveSecret 特有的
    // masked 字段映射.

    /// infer 的 gen_spec 不落盘 (persist 剥离): WebUI upsert 路径 (Web 层先
    /// validate_and_resolve 再 upsert_dynamic, 落盘 resolve 态) 与加载后继发
    /// persist 的 state.toml 都只含用户声明 — 每次加载 fresh infer, 且
    /// gen_spec 的存在不再被误读为用户显式配置 (mismatch 检测的接管判据).
    #[test]
    fn upsert_strips_inferred_gen_spec_from_state_toml() {
        let tmp = tempfile_path();
        let t = SecretTable::new(vec![], vec![], empty_decisions(), tmp.clone());
        // 生产同型: Web 层先 resolve (infer 填充 + gen_inferred=true) 再 upsert.
        let mut e = entry("web-created", "sk-A1b2C3d4E5f6G7h8I9j0");
        e.validate_and_resolve("").unwrap();
        assert!(e.mock_strategy.gen_inferred, "resolve must mark inferred");
        assert!(e.mock_strategy.gen_spec.is_some());
        t.upsert_dynamic(e).unwrap();
        // state.toml: 无 gen 段 (infer 剥离), value 明文按既有语义保留.
        let text = std::fs::read_to_string(&tmp).unwrap();
        assert!(
            !text.contains("gen"),
            "inferred gen must not persist: {text}"
        );
        assert!(text.contains("web-created"));
        // 内存态保留 infer 结果 (redact 热路径 / effective view 依赖).
        let mem = t.get_dynamic("web-created").unwrap();
        assert!(mem.mock_strategy.gen_spec.is_some());
        assert!(mem.mock_strategy.gen_inferred);
        // 用户显式 gen 保留落盘 (非 infer).
        let mut explicit = entry("explicit-gen", "some-random-value-123456");
        explicit.mock_strategy = crate::mock::MockStrategy {
            initial: crate::mock::InitialValue::Auto,
            gen_spec: Some(crate::mock::GenSpec {
                prefix: "keep".into(),
                charset: crate::mock::Charset {
                    lowercase: true,
                    ..Default::default()
                },
                length_range: (30, 30),
                shape: crate::mock::SecretShape::Plain,
            }),
            gen_inferred: false,
        };
        explicit.validate_and_resolve("").unwrap();
        assert!(!explicit.mock_strategy.gen_inferred);
        t.upsert_dynamic(explicit).unwrap();
        let text = std::fs::read_to_string(&tmp).unwrap();
        assert!(
            text.contains("keep"),
            "explicit user gen must persist: {text}"
        );
    }

    /// #319: GET DTO 必须暴露 gen 的来源标记 (`gen_inferred`) — WebUI 编辑器
    /// 脏检查的判定源 (未触碰时: inferred → 回传省略 gen 让后端 fresh infer;
    /// 显式 → 原样回传防丢; dynamic override 整条目替换, 省略显式 gen 会使其
    /// 被 infer 结果遮蔽 = 数据丢失).
    #[test]
    fn effective_snapshot_exposes_gen_inferred_flag() {
        let tmp = tempfile_path();
        // inferred: PEM 值 + privatekey → resolve 填充 gen (shape=pem) + 标记.
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEAtc0vLB3n6e5h8xNB7FJ7dX08ZD7kWrvFarcOeSNBjSM=\n-----END OPENSSH PRIVATE KEY-----";
        let mut inferred = entry("inferred-gen", pem);
        inferred.category = SecretCategory::PrivateKey;
        inferred.validate_and_resolve("").unwrap();
        assert!(inferred.mock_strategy.gen_inferred);
        // explicit: 用户手配 gen (gen_inferred=false).
        let mut explicit = entry("explicit-gen", "some-random-value-123456");
        explicit.mock_strategy = crate::mock::MockStrategy {
            initial: crate::mock::InitialValue::Auto,
            gen_spec: Some(crate::mock::GenSpec {
                prefix: "keep".into(),
                charset: crate::mock::Charset {
                    lowercase: true,
                    ..Default::default()
                },
                length_range: (30, 30),
                shape: crate::mock::SecretShape::Plain,
            }),
            gen_inferred: false,
        };
        explicit.validate_and_resolve("").unwrap();
        assert!(!explicit.mock_strategy.gen_inferred);

        let t = SecretTable::new(vec![], vec![inferred, explicit], empty_decisions(), tmp);
        let json = serde_json::to_value(t.effective_snapshot()).unwrap();
        let arr = json.as_array().unwrap();
        let find = |id: &str| {
            arr.iter()
                .find(|e| e["id"] == serde_json::json!(id))
                .unwrap()
        };
        let inf = find("inferred-gen");
        assert_eq!(
            inf["mock_strategy"]["gen_inferred"],
            serde_json::json!(true)
        );
        // shape 一并暴露 (未触碰回传原样 gen 的 "含 shape" 前提).
        assert_eq!(
            inf["mock_strategy"]["gen"]["shape"]["kind"],
            serde_json::json!("pem")
        );
        let exp = find("explicit-gen");
        assert!(
            exp["mock_strategy"].get("gen_inferred").is_none(),
            "explicit 条目的 DTO 不带 gen_inferred (false 省略): {exp}"
        );
        assert_eq!(
            exp["mock_strategy"]["gen"]["prefix"],
            serde_json::json!("keep")
        );
    }

    #[test]
    fn effective_snapshot_includes_provenance_and_masks_value() {
        let tmp = tempfile_path();
        let t = SecretTable::new(
            vec![
                entry("static-only", "static-secret-v"),
                entry("override-id", "static-base-v"),
            ],
            vec![
                entry("dynamic-only", "dynamic-secret-v"),
                entry("override-id", "dynamic-over-v"),
            ],
            empty_decisions(),
            tmp,
        );
        let snap = t.effective_snapshot();
        assert_eq!(snap.len(), 3);

        // 序列化结果中真实 value 不应出现.
        let json = serde_json::to_string(&snap).unwrap();
        assert!(!json.contains("static-secret-v"));
        assert!(!json.contains("dynamic-secret-v"));
        assert!(json.contains("value_masked"));

        let by_id: std::collections::HashMap<String, EffectiveSecret> =
            snap.into_iter().map(|e| (e.id.clone(), e)).collect();

        let s = by_id.get("static-only").unwrap();
        assert_eq!(s.source, EffectiveSource::Static);
        assert!(s.static_version.is_some());
        assert!(s.dynamic_version.is_none());

        let d = by_id.get("dynamic-only").unwrap();
        assert_eq!(d.source, EffectiveSource::Dynamic);
        assert!(d.static_version.is_none());
        // dynamic-only 时, dynamic_version 就是自身.
        assert!(d.dynamic_version.is_some());

        let ov = by_id.get("override-id").unwrap();
        assert_eq!(ov.source, EffectiveSource::DynamicOverride);
        assert!(ov.static_version.is_some());
        assert!(ov.dynamic_version.is_some());
    }

    #[test]
    fn prefer_static_marks_source_correctly() {
        let tmp = tempfile_path();
        let t = SecretTable::new(
            vec![entry("a", "static-v")],
            vec![entry("a", "dynamic-v")],
            empty_decisions(),
            tmp,
        );
        t.set_decision("a", OverrideMode::PreferStatic).unwrap();
        let snap = t.effective_snapshot();
        assert_eq!(snap[0].source, EffectiveSource::StaticPreferred);
        // "static-v" 8 字符, ≤ 8 → 全 *; length 8.
        assert_eq!(snap[0].value_masked, "********");
        assert_eq!(snap[0].value_length, 8);
    }

    // ─── value_file: 从文件路径读取 secret 明文 ─────────────────────────

    /// 辅助: 创建一个临时 secret 文件 (含末尾换行, 模拟 sops / echo | tee 行为).
    fn write_secret_file(content: &str) -> PathBuf {
        let id = uuid::Uuid::new_v4().to_string();
        let path = PathBuf::from(format!("/tmp/opencode/tmp/test-secret-file-{id}.txt"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // 故意加末尾换行 — resolve_value 必须 trim.
        std::fs::write(&path, format!("{content}\n")).unwrap();
        path
    }

    #[test]
    fn resolve_value_reads_from_file_and_trims() {
        let path = write_secret_file("sk-test-secret-value");
        let mut e = SecretEntry {
            id: "x".into(),
            name: None,
            category: SecretCategory::ApiKey,
            value: String::new(),
            value_file: Some(path),
            mock_strategy: crate::mock::MockStrategy::default(),
            strategy: SecretStrategy::default(),
        };
        assert!(e.resolve_value().is_ok());
        assert_eq!(e.value, "sk-test-secret-value"); // 末尾换行被 trim 掉.
        assert!(e.value_file.is_none()); // resolve 后清空 value_file.
    }

    #[test]
    fn resolve_value_no_op_when_value_file_is_none() {
        // 直接值模式: 没有 value_file, resolve 是 no-op, value 保持不变.
        let mut e = SecretEntry {
            id: "x".into(),
            name: None,
            category: SecretCategory::ApiKey,
            value: "direct-value".into(),
            value_file: None,
            mock_strategy: crate::mock::MockStrategy::default(),
            strategy: SecretStrategy::default(),
        };
        assert!(e.resolve_value().is_ok());
        assert_eq!(e.value, "direct-value");
    }

    #[test]
    fn resolve_value_fails_fast_on_unreadable_file() {
        let mut e = SecretEntry {
            id: "x".into(),
            name: None,
            category: SecretCategory::ApiKey,
            value: String::new(),
            value_file: Some(PathBuf::from("/nonexistent/secret-guard-test/no-such-file")),
            mock_strategy: crate::mock::MockStrategy::default(),
            strategy: SecretStrategy::default(),
        };
        let err = e.resolve_value().unwrap_err();
        // 错误信息含 id + path 便于排查.
        assert!(err.contains("x"), "err should mention secret id: {err}");
        assert!(
            err.contains("no-such-file"),
            "err should mention path: {err}"
        );
        // fail-fast: resolve_value 在读文件前就 Option::take 走 value_file (不论成败),
        // value 保持空. 调用方会在错误时整体放弃 entry, 不会继续用.
        assert!(e.value.is_empty());
        assert!(e.value_file.is_none());
    }

    #[test]
    fn validate_rejects_both_value_and_value_file_set() {
        let e = SecretEntry {
            id: "x".into(),
            name: None,
            category: SecretCategory::ApiKey,
            value: "some-direct-value".into(),
            value_file: Some(PathBuf::from("/etc/passwd")),
            mock_strategy: crate::mock::MockStrategy::default(),
            strategy: SecretStrategy::default(),
        };
        let err = e.validate().unwrap_err();
        assert!(
            err.contains("both value and value_file"),
            "err should explain mutual exclusion: {err}"
        );
    }

    #[test]
    fn validate_accepts_value_file_with_empty_value() {
        // value_file 模式: value 留空, validate 应当通过 (value 内容校验推迟到 resolve 后).
        let e = SecretEntry {
            id: "x".into(),
            name: None,
            category: SecretCategory::ApiKey,
            value: String::new(),
            value_file: Some(PathBuf::from("/some/path")),
            mock_strategy: crate::mock::MockStrategy::default(),
            strategy: SecretStrategy::default(),
        };
        assert!(e.validate().is_ok());
    }

    // ─── validate_and_resolve 的弱配置拒绝 (#383 方案 D: 配置期 fail-fast) ────
    //
    // SEC-1 裁决 (issue #383): on_probe_exhausted=fail_open 时被跳过 secret 的 record
    // 含真值回显 WebUI, 与 SEC-1 契约冲突 — 裁决从配置期源头消灭 probing 耗尽的
    // 触发面 (弱 mock 配置直接拒绝), 而非为冲突登记契约例外. 两道 gate 都只对
    // Redact 策略生效 (reject/placeholder 不做 mock 生成, 无触发面 — 引导目标必须
    // 可达); Err message 严禁含 secret value 或 mock (SEC 红线) — 只含 id / 数字 / 建议.

    #[test]
    fn validate_and_resolve_rejects_weak_manual_gen_spec() {
        // 显式弱 mock 策略 (charset 2 × len 4 = 16 候选 << 2^20): validate_and_resolve
        // 拒绝 (语义自 #383 起由 "通过 + WARN" 翻转为 fail-fast Err — 候选空间 lint
        // 是 Err 的信息来源, 见 MockStrategy::lint_candidate_space).
        let mut e = entry("weak-spec", "some-real-secret-value");
        e.mock_strategy = crate::mock::MockStrategy {
            initial: crate::mock::InitialValue::Auto,
            gen_spec: Some(crate::mock::GenSpec {
                prefix: "".into(),
                charset: crate::mock::Charset {
                    other: vec!['a', 'b'],
                    ..Default::default()
                },
                length_range: (4, 4),
                shape: crate::mock::SecretShape::Plain,
            }),
            gen_inferred: false,
        };
        let err = e.validate_and_resolve("").unwrap_err();
        assert!(
            err.contains("weak-spec"),
            "err should mention secret id: {err}"
        );
        assert!(
            err.contains("16") && err.contains(&format!("{}", 1 << 20)),
            "err should carry candidate space vs min recommended: {err}"
        );
        assert!(
            err.contains("reject") && err.contains("placeholder"),
            "err should guide strategy alternatives: {err}"
        );
    }

    #[test]
    fn validate_and_resolve_rejects_short_real_for_redact() {
        // "abc" (3 chars): validate_value (≥3 字节) 通过, 但等长 Auto 推断下候选空间
        // 物理上不可达 2^20 (上界 65³ ≈ 27 万) — 拒绝 + 引导换策略.
        let mut e = entry("short-real", "abc");
        let err = e.validate_and_resolve("").unwrap_err();
        assert!(
            err.contains("short-real"),
            "err should mention secret id: {err}"
        );
        assert!(
            err.contains("reject") && err.contains("placeholder"),
            "err should guide strategy alternatives: {err}"
        );
        assert!(!err.contains("abc"), "SEC 红线: err 严禁含真值: {err}");
        // multibyte: "密码" 2 chars (6 字节, 通过 validate_value 字节下限) — 拒绝判据
        // 是 chars().count() (与等长约束/mock 长度口径一致), 非 len() 字节数.
        let mut m = entry("short-multibyte", "密码");
        assert!(
            m.validate_and_resolve("").is_err(),
            "multibyte 2-char value must be rejected by char count"
        );
        // 边界: 4 chars 恰好放行 (62⁴ ≈ 1480 万 ≥ 2^20, widen 兜底可达标).
        let mut ok = entry("boundary-four", "abcd");
        assert!(ok.validate_and_resolve("").is_ok());
    }

    #[test]
    fn validate_and_resolve_allows_short_real_for_reject_and_placeholder() {
        // 引导目标可达: reject/placeholder 不做 mock 生成 (整请求拒绝 / 固定明示
        // 假值), 无 probing 耗尽触发面 — 短值合法, 不受两道 gate 约束.
        for s in [SecretStrategy::Reject, SecretStrategy::Placeholder] {
            let mut e = entry("short-ok", "abc");
            e.strategy = s;
            assert!(
                e.validate_and_resolve("").is_ok(),
                "{s:?} + short value should pass (guided target must be legal)"
            );
        }
    }

    #[test]
    fn validate_and_resolve_auto_degenerate_real_not_lintable() {
        // Auto + 退化 real "aaaa" (2026-09 widen 后的新语义): infer lowercase (26^4
        // = 456976 < 2^20) → widen 并入 digits → 36^4 ≥ 2^20 → resolve 后恒不可
        // lint (Auto 永不弱配置; lint 有效对象是手动配置的 gen_spec).
        let mut e = SecretEntry {
            id: "degenerate".into(),
            name: None,
            category: SecretCategory::ApiKey,
            value: "aaaa".into(),
            value_file: None,
            mock_strategy: crate::mock::MockStrategy::default(),
            strategy: SecretStrategy::default(),
        };
        assert!(e.validate_and_resolve("").is_ok());
        assert!(
            e.mock_strategy.lint_candidate_space().is_none(),
            "Auto widen 兜底后退化 real 不再产生弱配置 lint"
        );
    }

    #[test]
    fn validate_and_resolve_normal_real_not_lintable() {
        // 正常 real + 默认 Auto 策略: infer 空间充足, lint 不触发.
        let mut e = entry("normal", "sk-1234567890abcdef");
        assert!(e.validate_and_resolve("").is_ok());
        assert!(e.mock_strategy.lint_candidate_space().is_none());
    }

    // ─── SEC-1: EffectiveSecret JSON 永不含真实 value ────────────────────
    //
    // 契约 (docs/design/contracts.md §7 SEC-1): GET /secrets 路径的核心安全保证 —
    // EffectiveSecret (GET 响应 DTO) 序列化为 JSON 后不得包含真实 secret value 的任何
    // 子串. 类型系统层依赖 EffectiveSecret / SecretMasked 用 `value_masked` (经
    // mask_value 脱敏) 替代 `value`; property 层把 "JSON 字符串扫描" 作为防御性第二道
    // 闸 (即便有人未来误加 value 字段, property 也会 fail).
    //
    // 既有 effective_snapshot_includes_provenance_and_masks_value 是固定输入的 example
    // 测试, 不构成 property; 此处补随机化覆盖.

    use proptest::prelude::*;

    proptest! {
        /// #383 方案 D: redact 策略下, 任意手动配置的 gen_spec 经 validate_and_resolve
        /// 通过 ⟹ 候选空间 ≥ 2^20 (弱配置的配置期拒绝 property 化 — 通过即强配置).
        ///
        /// 条件式 (is_ok ⟹ 断言): charset 全关等形态被 GenSpec::validate 拒绝, 属于
        /// 另一条错误路径, 不在本 property 的断言范围.
        #[test]
        fn prop_validated_manual_gen_spec_meets_candidate_space_floor(
            real in "[a-z0-9]{4,24}",
            digits in any::<bool>(),
            lowercase in any::<bool>(),
            uppercase in any::<bool>(),
            body_min in 1usize..8,
            body_extra in 0usize..8,
        ) {
            let mut e = entry("prop-floor", &real);
            e.mock_strategy = crate::mock::MockStrategy {
                initial: crate::mock::InitialValue::Auto,
                gen_spec: Some(crate::mock::GenSpec {
                    prefix: "".into(),
                    charset: crate::mock::Charset {
                        digits,
                        lowercase,
                        uppercase,
                        ..Default::default()
                    },
                    length_range: (body_min, body_min + body_extra),
                    shape: crate::mock::SecretShape::Plain,
                }),
                gen_inferred: false,
            };
            if e.validate_and_resolve("").is_ok() {
                prop_assert!(
                    e.mock_strategy.lint_candidate_space().is_none(),
                    "通过校验的 redact gen_spec 候选空间必须 ≥ 2^20 (弱配置应被拒绝)"
                );
            }
        }

        /// #383 方案 D: 过短 real (恰 3 chars — 通过 validate_value 字节下限, 落在
        /// 等长约束的物理边界): redact 恒被拒且 Err 引导 reject/placeholder 而不含
        /// 真值; 引导目标 (reject/placeholder) 恒通过. 生成器限数字: gate ① 的 Err
        /// 是固定模板 (无数字), 否则随机 3 字母真值可与模板子串巧合 (proptest 实证:
        /// "tea" ⊂ "instead" 触发 SEC 断言假阳性 — 模板本不含真值).
        #[test]
        fn prop_short_real_redact_rejected_other_strategies_pass(
            real in "[0-9]{3}",
            which in 0usize..3,
        ) {
            let strategies = [
                SecretStrategy::Redact,
                SecretStrategy::Reject,
                SecretStrategy::Placeholder,
            ];
            let mut e = entry("prop-short", &real);
            e.strategy = strategies[which];
            match strategies[which] {
                SecretStrategy::Redact => {
                    let err = e.validate_and_resolve("").unwrap_err();
                    prop_assert!(
                        err.contains("reject") && err.contains("placeholder"),
                        "err should guide strategy alternatives: {err}"
                    );
                    prop_assert!(
                        !err.contains(&real),
                        "SEC 红线: err 严禁含真值: {err}"
                    );
                }
                _ => {
                    prop_assert!(e.validate_and_resolve("").is_ok());
                }
            }
        }

        /// SEC-1: 任意 secret value, EffectiveSecret 序列化后的 JSON 字符串不含真实 value.
        ///
        /// 这是 GET /secrets 路径的核心安全保证 — 任何泄露都是 Critical bug.
        /// 验证方式: 把 EffectiveSecret 整体序列化为 JSON, 然后在结果字符串里
        /// 用 `contains` 搜真实 value. mask_value 对 >8 字符输入只保留首尾各 1 字符,
        /// 中间用 `*` 填充, 因此正常情况下真实 value 的中间子串不可能出现在 JSON 里.
        ///
        /// 注意: 这里只校验 effective_snapshot()[0] 本身 (EffectiveSecret struct),
        /// 不含 static_version / dynamic_version 字段 — 这两者已是 SecretMasked (也
        /// 用 mask_value 脱敏). EffectiveSecret 序列化时这两个嵌套字段也会跟着序列化,
        /// 全局扫一次 JSON 字符串即可覆盖.
        #[test]
        fn prop_effective_secret_json_excludes_real_value(
            id in "[a-z][a-z0-9_]{0,8}",
            // ≥4 字节以满足 validate_value 最小 3 字节要求; 同时避开 value_file 模式.
            // 字符集限定为 ASCII 可见非特殊字符, 避免 JSON escape 干扰 contains 匹配
            // (例如真实 value 含 `"` 或 `\` 时, JSON 里会被转义为 `\"` / `\\`,
            // contains(real_value) 会假阴性 — 这里用纯字母数字+斜杠+等号, 这些字符
            // 在 JSON 字符串值中不被转义).
            value in "[A-Za-z0-9/+=]{4,32}"
        ) {
            let s = SecretEntry {
                id: id.clone(),
                name: Some(format!("name-{id}")),
                category: SecretCategory::ApiKey,
                value: value.clone(),
                value_file: None,
                mock_strategy: MockStrategy::default(),
                strategy: SecretStrategy::default(),
            };
            let table = SecretTable::new(
                vec![s],
                vec![],
                empty_decisions(),
                PathBuf::from("/tmp/opencode/tmp/sec1-effective-state.toml"),
            );
            let snap = table.effective_snapshot();
            prop_assert!(!snap.is_empty(), "static entry 应出现在 effective 中");
            let json = serde_json::to_string(&snap[0]).expect("serialize EffectiveSecret");
            // 核心: 真实 value 不得出现在 JSON 任何位置 (字段名 / 字段值都不行).
            prop_assert!(
                !json.contains(value.as_str()),
                "SEC-1 violation: EffectiveSecret JSON contains real value. json={}",
                json
            );
        }
    }
}
