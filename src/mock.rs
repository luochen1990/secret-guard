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
//! # category-aware 形状推断 (结构仿真)
//!
//! `SecretEntry.category` ([`SecretCategory`], 定义于本模块 — 它是 mock 生成器的
//! 选择参数) 参与 Auto 模式的 gen spec 推断, 决定 [`SecretShape`] (结构形状维度):
//!
//! - **PrivateKey (形状自证, 不 gate category)**: real 匹配 PEM 结构 (首行
//!   `-----BEGIN ...-----` / 末行 `-----END ...-----` / 中间全 b64 行) → 合成
//!   结构完整的假 PEM (复用 real 的公开边界行 + 等长随机 b64 body 行). 归类
//!   错误免疫: category 标错时 PEM 形状仍被识别.
//! - **Email (形状自证, 不 gate category, 同 PEM 先例)**: real 匹配 email 语法
//!   (见 `parse_email`) → `local@domain` 结构: domain 复用公开邮箱域白名单成员
//!   ([`EMAIL_DOMAINS`]), local 用名字池组合 (见 `gen_name_like`:
//!   [`FIRST_NAMES`]/[`LAST_NAMES`] + digit pad). gate: local 的 name-like 候选
//!   空间 ≥ [`MIN_CANDIDATE_SPACE_WARN`] — 短 local 物理空间不足时退化 Plain
//!   (仿真与空间不可兼得, 取空间). 存量归类为 other 的 email secret 直接受益.
//! - **Token + JWT 形状** (三段点分 b64url, 每段 ≥10 chars, 总长 ≥32) → 三段
//!   等长随机 b64url, 点分结构保留.
//! - **ApiKey + 公开前缀白名单** (sk-/ghp_/AKIA/AIza/glpat-/hf_/sg_/... 见
//!   [`PUBLIC_KEY_PREFIXES`], 最长命中, body ≥8 chars) → mock 保留公开前缀.
//! - **Phone (gate category)**: category == Phone 且 real 字符域合法 (⊆ digits
//!   与 `+ - ( ) . 空格` 分隔符, `+` 仅首位, digit ≥ 7 — 10^7 > 2^20 是空间
//!   物理边界, 不足退化 Plain) → 分隔符骨架保持 (见 `parse_phone`), digit 位
//!   随机.
//! - **Username (gate category)**: category == Username 且 name-like 候选空间
//!   达标 (real 长度 ≥ 7) → 名字池组合 + digit pad 到等长.
//! - 其余 (含 Password/Cookie/Other) → [`SecretShape::Plain`] 平坦串 (历史行为).
//!
//! **归类错误无害**: 所有增强都有形状 gate (或形状自证), category 标错最多退化
//! 为 Plain (与历史行为一致), 不产生错误行为. 标注与值形状的**矛盾** (PEM 但非
//! privatekey / email 形状但非 email 标注 / JWT 但非 token / 白名单前缀但非
//! apikey) 由 `MockStrategy::category_shape_mismatch` 在配置期 WARN (检测面与
//! 跳过条件见其 doc).
//!
//! **global_prefix 裁决**: `global_mock_prefix` 非空时恒推断 Plain — 用户显式
//! 配置辨识前缀 = 放弃结构仿真 (辨识度与仿真度互斥, 把矛盾交给配置).
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
//! **公开格式子串豁免 (shape-aware, RED-5 精确化)**: [`SecretShape`] 的公开结构段
//! (PublicPrefixed 的白名单前缀 / Pem 的 BEGIN·END 边界行 / Email 的 `@domain`
//! 公开邮箱域段) 是 real 中**信息量为零的公开格式串** (业界约定, 非 secret 内容)
//! — mock 复用它们不泄露任何 secret 信息. C5 检查 (`c5_violated`) 在窗口比较前
//! 剥离 mock 的公开段, 随机部分照常做 ≥k 子串检查. 契约条文见 contracts.md RED-5.
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

// ─── SecretCategory (mock 生成器的选择参数) ────────────────────────────────

/// Secret 类别. Auto 模式 gen spec 推断的语义 hint (参与 [`SecretShape`] 判定,
/// 见模块头部 "category-aware 形状推断" 段).
///
/// 定义于 mock.rs (而非 secrets.rs): 它是 mock 生成策略的输入, 依赖方向
/// `secrets → mock` 保持单向 (secrets.rs re-export 维持既有 API 兼容).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecretCategory {
    /// 密码 (相对短, 任意可打印字符).
    Password,
    /// API key (通常较长, 固定前缀如 sk-/sk-ant-/AKIA).
    #[default]
    ApiKey,
    /// 长 bearer token (JWT 等).
    Token,
    /// Cookie 值.
    Cookie,
    /// 私钥 (PEM 等, 多行).
    PrivateKey,
    /// 电子邮件地址 (`local@domain` 结构; Email 形状推断见 `infer_email`).
    Email,
    /// 电话号码 (分隔符骨架 + digit 位随机, 见 `parse_phone`).
    Phone,
    /// 用户名 (名字池组合 + digit pad, 见 `gen_name_like`).
    Username,
    /// 兜底.
    Other,
}

impl SecretCategory {
    /// 所有变体及其字符串名 — 派生自 `as_str()` (const fn match 是字符串单源).
    /// serde rename 同步由 roundtrip 测试守卫; 定长数组不随新增 variant 自动扩 —
    /// ALL 漏项无自动守卫, 需人工随新增 variant 同步.
    pub const ALL: [(Self, &'static str); 9] = [
        (Self::Password, Self::Password.as_str()),
        (Self::ApiKey, Self::ApiKey.as_str()),
        (Self::Token, Self::Token.as_str()),
        (Self::Cookie, Self::Cookie.as_str()),
        (Self::PrivateKey, Self::PrivateKey.as_str()),
        (Self::Email, Self::Email.as_str()),
        (Self::Phone, Self::Phone.as_str()),
        (Self::Username, Self::Username.as_str()),
        (Self::Other, Self::Other.as_str()),
    ];

    pub const fn as_str(self) -> &'static str {
        // 穷尽 match: 新增 variant 编译期引导补齐 (本 match 是字符串单源, ALL 派生自它).
        match self {
            Self::Password => "password",
            Self::ApiKey => "apikey",
            Self::Token => "token",
            Self::Cookie => "cookie",
            Self::PrivateKey => "privatekey",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Username => "username",
            Self::Other => "other",
        }
    }
}

// ─── SecretShape (结构形状维度) ─────────────────────────────────────────────

/// GenSpec 的结构形状: mock 的分段结构 (category-aware 推断, 见模块头部
/// "category-aware 形状推断" 段). 用户也可经 `mock_strategy.gen.shape` 显式配置.
///
/// **等长不变量**: 所有形状生成的 mock 总字符数 == real 总字符数
/// (infer 出的 `length_range` 是单点区间) — wire 字节量无扰动, 与 Plain 一致.
///
/// **公开格式子串与 C5**: PublicPrefixed 的 `public_prefix`、Pem 的边界行与
/// Email 的 `@domain` 公开邮箱域段是 real 中信息量为零的公开格式串, C5 检查
/// 豁免这些段 (见 `c5_violated` 与模块头部 "公开格式子串豁免" 段).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretShape {
    /// 平坦串: `prefix + 随机 body` (历史唯一形态; 所有形状不匹配场景的兜底).
    #[default]
    Plain,
    /// 公开前缀 + 随机 body: `public_prefix` 来自 [`PUBLIC_KEY_PREFIXES`] 白名单
    /// (精确大小写, 最长命中), C5 检查豁免该前缀段. 推断 gate: category == ApiKey
    /// 且 body (去前缀后) ≥ 8 chars.
    PublicPrefixed {
        /// 公开格式前缀 (白名单精确匹配, 区分大小写).
        public_prefix: String,
    },
    /// JWT 三段点分: 三段等长随机 base64url + `.` 连接. 推断 gate: category ==
    /// Token 且 real 匹配 JWT 形状 (见 `parse_jwt`).
    Jwt {
        /// 三段的 body 长度 (随机字符数, 不含点分隔符).
        seg_lens: Vec<usize>,
    },
    /// PEM 块: 复用 real 的公开边界行 (BEGIN/END) + 每行等长随机 b64 body.
    /// 推断 gate: real 匹配 PEM 结构 (见 `parse_pem`) — **不 gate category**
    /// (形状自证, 归类错误免疫).
    Pem {
        header_line: String,
        footer_line: String,
        /// 每条 body 行的长度 (随机字符数, 不含 `\n`).
        body_line_lens: Vec<usize>,
    },
    /// Email: `local@domain` — local 为 name-like 随机段 (名字池 + digit pad, 见
    /// `gen_name_like`), domain 为白名单公开邮箱域 ([`EMAIL_DOMAINS`], shape 携带,
    /// C5 豁免该段). 推断 gate: 形状自证 (`parse_email`, 不 gate category, 同 PEM
    /// 先例) + 域名放得下 + local 候选空间达标 (见 `infer_email`).
    Email {
        /// 公开邮箱域 (白名单成员, 小写; real 的域在白名单时复用).
        domain: String,
    },
    /// Phone: 分隔符骨架保持 (`#` = digit 占位, 其余字符 literal 复用 real 的
    /// 分隔符), digit 位随机. 推断 gate: category == Phone + 字符域合法 + digit
    /// 数 ≥ 7 (见 `parse_phone`).
    Phone {
        /// digit 占位骨架 (`#` = 随机 digit 位, 其余字符 literal).
        skeleton: String,
    },
    /// Username: 名字池组合 + digit pad 到等长 (见 `gen_name_like`). 推断 gate:
    /// category == Username + name-like 候选空间达标 (real 长度 ≥ 7).
    Username,
}

/// 公开 API key 前缀白名单 (业界格式约定, 精确大小写匹配; 匹配取最长命中 —
/// `sk-ant-` 优先于 `sk-`). 新增前缀改此表: 公开格式是业界共识而非部署特例,
/// 不做配置化 (YAGNI).
pub const PUBLIC_KEY_PREFIXES: &[&str] = &[
    "github_pat_",
    "sk-ant-",
    "glpat-",
    "AKIA",
    "ASIA",
    "AIza",
    "xoxb-",
    "xoxa-",
    "xoxp-",
    "xoxs-",
    "xoxr-",
    "xapp-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "hf_",
    "gsk_",
    "sg_",
    "sk_",
    "gl_",
    "sk-",
];

/// 公开邮箱域名白名单 (业界公共邮箱域, 小写精确匹配). Email 形状的公开段
/// (`@domain`) 由此表供给 — C5 豁免只覆盖白名单成员: 手动配置携带私有域会被
/// `GenSpec::validate` 拒绝 (同 `PUBLIC_KEY_PREFIXES` 哲学 — 防 "固定段夹带
/// 真值并整段豁免 C5" 的绕过面). 新增域名改此表 (公开邮箱域是业界共识).
pub const EMAIL_DOMAINS: &[&str] = &[
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
    "live.com",
    "aol.com",
    "qq.com",
    "163.com",
    "126.com",
    "sina.com",
    "foxmail.com",
    "yeah.net",
    "example.com",
];

/// name-like 段的名字池 (西方名 + 拼音混合, 全小写 ASCII, 长度 2..=9; 供
/// `gen_name_like` / `name_like_space`). 2..3 char 短名 20 个 (设计下限 ≥ 16,
/// 供短 target — 短 email local / username — 的名字挑选与空间计算).
pub const FIRST_NAMES: &[&str] = &[
    // 2..3 char (短名, 20 个):
    "li",
    "bo",
    "yu",
    "qi",
    "he",
    "an",
    "yi",
    "ze",
    "en",
    "ru",
    "wei",
    "mei",
    "tao",
    "hui",
    "jun",
    "xia",
    "lei",
    "yan",
    "tom",
    "max",
    // 4 char (14 个):
    "ling",
    "yuan",
    "chen",
    "jing",
    "ming",
    "feng",
    "john",
    "jane",
    "alex",
    "mary",
    "lily",
    "anna",
    "noah",
    "liam",
    // 5 char (8 个):
    "maria",
    "sarah",
    "david",
    "laura",
    "kevin",
    "emily",
    "chris",
    "james",
    // 6..9 char (9 个):
    "robert",
    "olivia",
    "sophia",
    "michael",
    "jessica",
    "william",
    "matthew",
    "jennifer",
    "christina",
];

/// name-like 段的姓氏池 (拼音 + 西方混合, 全小写 ASCII, 长度 3..=8; 供
/// `gen_name_like` 的 two-part 模式与 `name_like_space`).
pub const LAST_NAMES: &[&str] = &[
    "liu", "sun", "zhu", "lin", "gao", "luo", "han", "wang", "chen", "yang", "zhao", "zhou",
    "feng", "tang", "deng", "zhang", "huang", "zheng", "smith", "brown", "davis", "moore", "white",
    "taylor", "wilson", "thomas", "harris", "martin", "miller", "johnson", "jackson", "anderson",
];

/// username 形态的分隔符集 (`first + sep + last` 的 sep, 见 `gen_name_like`).
pub const USERNAME_SEPS: &[char] = &['_', '.', '-'];

/// email local 段的分隔符集 (固定 `.` — email local 的常见形态是
/// `first.last`, 不引入 `_`/`-` 保持拟真).
pub const EMAIL_LOCAL_SEPS: &[char] = &['.'];

/// real 的公开 API key 前缀 (白名单最长命中). body (去前缀后) < 8 chars 时返回
/// `None` — 短 body 前缀保留意义弱 (仿真增益小) 且 C5 随机窗口空间过窄.
fn find_public_prefix(real: &str) -> Option<&'static str> {
    PUBLIC_KEY_PREFIXES
        .iter()
        .copied()
        .filter(|p| real.starts_with(p))
        .max_by_key(|p| p.len())
        .filter(|p| real.chars().count() >= p.chars().count() + 8)
}

/// real 是否 PEM 块 (手写形状判定, 零依赖): 首行 `-----BEGIN <label>-----` + 末行
/// `-----END <label>-----` + 中间 ≥1 行全为 base64 字符 (`A-Za-z0-9+/=`).
/// 命中返回 parse 出的形状参数 (header/footer 原样复用 — 公开格式串).
///
/// **label 收紧** (C5 豁免前提的结构保证): `<label>` 必须匹配 `[A-Z0-9 ]+`
/// (RFC 7468 标准标签形态, 如 `OPENSSH PRIVATE KEY`). 非标准 label (如含用户
/// 可控内容的 `-----BEGIN hunter2-password-----`) 不识别 — C5 豁免的合法性
/// 前提是"被豁免段是信息量为零的公开格式串", 任意 label 不满足该前提,
/// 保守退化 Plain (等长平坦串, 无豁免). 已知边界: CRLF / 尾随换行的 PEM 因
/// 行尾 `\r` 不匹配 b64 字符集而静默退化 Plain (value_file 的 trim 只去首尾).
fn parse_pem(real: &str) -> Option<SecretShape> {
    let (header, rest) = real.split_once('\n')?;
    let (body, footer) = rest.rsplit_once('\n')?;
    // BEGIN/END label 一致 + 标准形态 (公开格式前提, 见 pem_boundary_label).
    if pem_boundary_label(header, "BEGIN")? != pem_boundary_label(footer, "END")? {
        return None;
    }
    let is_b64_line = |l: &str| {
        !l.is_empty()
            && l.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
    };
    if !body.split('\n').all(is_b64_line) {
        return None;
    }
    Some(SecretShape::Pem {
        header_line: header.to_string(),
        footer_line: footer.to_string(),
        body_line_lens: body.split('\n').map(|l| l.chars().count()).collect(),
    })
}

/// PEM 边界行的标准形态 label (`-----<which> <label>-----`, which ∈ BEGIN|END):
/// 返回 `Some(label)` 当且仅当边界行是**公开格式** — label 匹配 `[A-Z0-9 ]{1,64}`
/// (RFC 7468 标准标签形态, 长度上限挡住 "label 内嵌大写载荷" 的伪 PEM 自伤面).
/// 这是 Pem 形状 C5 豁免的结构前提: 推断路径 (parse_pem) 与手动配置路径
/// (validate) 共用 — 保证被豁免的边界行恒为信息量为零的标准形态, 杜绝
/// "自定义 label 携带真值内容整行豁免"的绕过面.
fn pem_boundary_label<'a>(line: &'a str, which: &str) -> Option<&'a str> {
    let label = line
        .strip_prefix(&format!("-----{which} "))
        .and_then(|s| s.strip_suffix("-----"))?;
    let public_form = !label.is_empty()
        && label.chars().count() <= 64
        && label
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == ' ');
    public_form.then_some(label)
}

/// real 是否 JWT (手写形状判定): 三段点分 base64url (`A-Za-z0-9_-`), 每段
/// ≥ 10 chars, 总长 ≥ 32. 段长下限挡掉版本号 / 主机名等三段点分误判;
/// 与 category == Token 的 gate (infer 调用处) 双重收紧.
fn parse_jwt(real: &str) -> Option<SecretShape> {
    let segs: Vec<&str> = real.split('.').collect();
    if segs.len() != 3 || real.chars().count() < 32 {
        return None;
    }
    let ok = segs.iter().all(|s| {
        s.chars().count() >= 10
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    });
    ok.then(|| SecretShape::Jwt {
        seg_lens: segs.iter().map(|s| s.chars().count()).collect(),
    })
}

/// real 是否 email 地址 (手写语法判定, 零依赖; **语法级检测, 不做空间判定** —
/// 空间 gate 在 `infer_email`): 恰一个 `@`; local 1..=64 chars, 字符 ∈
/// `[a-zA-Z0-9._%+-]`; domain ≥1 个 `.`, 每 label 1..=63 chars ∈ `[a-zA-Z0-9-]`,
/// TLD (最后一个 label) ≥2 chars 且全 alpha. 整串无空白 (local/domain 的字符域
/// 检查已隐含覆盖 — 两者拼回即整串).
///
/// 返回 `(local_len, domain)` — domain 取**小写归一**形态 (email domain 大小写
/// 不敏感; `infer_email` 的白名单匹配依赖归一).
fn parse_email(real: &str) -> Option<(usize, String)> {
    let (local, domain) = real.split_once('@')?;
    if domain.contains('@') {
        return None; // 恰一个 '@' (split_once 已取首个, 尾部再有即非法).
    }
    let local_len = local.chars().count();
    if local_len == 0 || local_len > 64 {
        return None;
    }
    if !local
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-'))
    {
        return None;
    }
    let domain = domain.to_ascii_lowercase();
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for label in &labels {
        let n = label.chars().count();
        if n == 0 || n > 63 {
            return None;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return None;
        }
    }
    let tld = *labels.last().expect("labels non-empty (len ≥ 2 checked)");
    if tld.chars().count() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some((local_len, domain))
}

/// real 是否电话号码形态 (仅在 category == Phone 时由 `infer_shape` 调用):
/// real 非空; 字符域 ⊆ `{0-9, '+', ' ', '-', '(', ')', '.'}`; `+` 仅允许首位;
/// digit 数 ≥ 7 (**空间物理边界**: 10^7 > 2^20, 不足返回 None 退化 Plain).
/// 返回 digit 占位骨架: digit → `#`, 其余字符 (分隔符) → 原字符 literal 复用.
fn parse_phone(real: &str) -> Option<String> {
    if real.is_empty() {
        return None;
    }
    let mut digit_count = 0usize;
    for (i, c) in real.chars().enumerate() {
        match c {
            '0'..='9' => digit_count += 1,
            '+' if i == 0 => {}
            ' ' | '-' | '(' | ')' | '.' => {}
            _ => return None,
        }
    }
    if digit_count < 7 {
        return None;
    }
    Some(
        real.chars()
            .map(|c| if c.is_ascii_digit() { '#' } else { c })
            .collect(),
    )
}

/// name-like 组合的诚实候选空间 (saturating u64):
/// `Σ_{first ∈ FIRST, |f| ≤ target} 10^(target-|f|)`
/// `+ Σ_{(first,sep,last), |f|+1+|l| ≤ target} 10^(target-|f|-1-|l|)`
/// 若无任何 first 放得下 (target < 2, 名字池最短 2 chars): `charset_size^target`
/// (全随机兜底分支).
///
/// 10^pad 与生成一致: pad 恒为 digit (`gen_name_like` 的 `hash % 10`, 拟真
/// "john92" 而非 "johnXz"); 名字项与 charset 无关 (名字池是常量表, 不从 charset
/// 采样 — charset 只喂兜底分支). saturating 求和/求幂: 超大空间封顶 u64::MAX,
/// 不因溢出 panic (ROB).
fn name_like_space(target: usize, seps: &[char], charset_size: u64) -> u64 {
    // 10^e: e ≥ 20 恒饱和 (10^20 ≈ 1e20 > u64::MAX ≈ 1.8e19), 免 as u32 截断.
    let pow10 = |e: usize| -> u64 {
        if e >= 20 {
            u64::MAX
        } else {
            10u64.pow(e as u32)
        }
    };
    let mut total: u64 = 0;
    // first-only: first + digit pad.
    for f in FIRST_NAMES {
        let fl = f.chars().count();
        if fl <= target {
            total = total.saturating_add(pow10(target - fl));
        }
    }
    // two-part: first + sep + last + digit pad (sep ∈ seps, 每组合同空间).
    for f in FIRST_NAMES {
        for l in LAST_NAMES {
            let used = f.chars().count() + 1 + l.chars().count();
            if used > target {
                continue;
            }
            let term = pow10(target - used).saturating_mul(seps.len() as u64);
            total = total.saturating_add(term);
        }
    }
    if total == 0 {
        // 无任何 first 放得下 (target < 2): 全随机兜底分支.
        // u32::try_from 防御 target 超宽 (物理不可达) 的 as-truncation 低估.
        charset_size.saturating_pow(u32::try_from(target).unwrap_or(u32::MAX))
    } else {
        total
    }
}

/// email 形状推断 (形状自证, 不 gate category — 同 `parse_pem` 先例, 存量
/// other 归类的 email secret 直接受益). 语法过 (`parse_email`) 后选 domain:
/// ① real 的 domain (小写归一) ∈ [`EMAIL_DOMAINS`] → 复用 (公开格式段复用);
/// ② 否则从白名单筛放得下的成员 (`len ≤ total - 2`, local ≥ 1), `hash64(real)`
/// 确定性挑一个; ③ 空 (real 过短放不下任何白名单域) → None. domain 定了后
/// `local_len = total - 1 - domain_len`, 再 gate: `name_like_space(local_len,
/// EMAIL_LOCAL_SEPS, 10) ≥ MIN_CANDIDATE_SPACE_WARN` — 不足 → None → Plain
/// (短 local 物理空间不足, 仿真与空间不可兼得, 取空间; 预检 charset_size 用
/// 10 即可: pad 恒 digit, 名字项与 charset 无关).
fn infer_email(real: &str) -> Option<SecretShape> {
    let (real_local_len, real_domain) = parse_email(real)?;
    let total = real.chars().count();
    let (domain, local_len) = if EMAIL_DOMAINS.contains(&real_domain.as_str()) {
        (real_domain, real_local_len)
    } else {
        let fitting: Vec<&str> = EMAIL_DOMAINS
            .iter()
            .copied()
            .filter(|d| d.chars().count() + 2 <= total)
            .collect();
        // fitting 可空 (real 过短放不下任何白名单域, 如 total < 8 = 最短白名单
        // "qq.com" + local 1 + '@') → None (退化 Plain, 其 local 空间也必不足).
        if fitting.is_empty() {
            return None;
        }
        let picked = fitting[(crate::util::hash64(real) % fitting.len() as u64) as usize];
        let local_len = total - 1 - picked.chars().count();
        ((*picked).to_string(), local_len)
    };
    (name_like_space(local_len, EMAIL_LOCAL_SEPS, 10) >= MIN_CANDIDATE_SPACE_WARN)
        .then_some(SecretShape::Email { domain })
}

/// shape 推断 (category + real 形状). `global_prefix` 非空时恒 Plain
/// (用户显式要辨识前缀 = 放弃结构仿真, 见模块头部裁决).
fn infer_shape(real: &str, category: SecretCategory, global_prefix: &str) -> SecretShape {
    if !global_prefix.is_empty() {
        return SecretShape::Plain;
    }
    // PEM / Email 不 gate category: 形状自证, 归类错误免疫.
    if let Some(pem) = parse_pem(real) {
        return pem;
    }
    if let Some(email) = infer_email(real) {
        return email;
    }
    let n = real.chars().count();
    match category {
        SecretCategory::Token => parse_jwt(real).unwrap_or_default(),
        SecretCategory::ApiKey => find_public_prefix(real)
            .map(|p| SecretShape::PublicPrefixed {
                public_prefix: p.to_string(),
            })
            .unwrap_or_default(),
        SecretCategory::Phone => parse_phone(real)
            .map(|skeleton| SecretShape::Phone { skeleton })
            .unwrap_or_default(),
        // Username gate: name-like 候选空间达标 (real ≥ 7 — 短 username 物理空间
        // 不足, 仿真与空间不可兼得, 取空间; 预检 charset_size 用 10, 同 infer_email).
        SecretCategory::Username => {
            if name_like_space(n, USERNAME_SEPS, 10) >= MIN_CANDIDATE_SPACE_WARN {
                SecretShape::Username
            } else {
                SecretShape::Plain
            }
        }
        _ => SecretShape::Plain,
    }
}

// ─── GenSpec ───────────────────────────────────────────────────────────────

/// 生成策略: 固定前缀 + 字符集 + 长度范围 + 结构形状.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GenSpec {
    /// 固定前缀. 默认空串 (不固定任何前缀, 全部随机).
    ///
    /// **仅 [`SecretShape::Plain`] 使用** (等价地, PublicPrefixed 的前缀在
    /// `shape.public_prefix`); 其他形状要求本字段为空 (validate 强制) — 结构
    /// 分段与公开前缀统一由 shape 携带, 避免双通道歧义.
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub charset: Charset,
    /// 闭区间 `[min, max]` (char count, 非 byte count) — **mock 总长** (含结构
    /// 分隔符与公开段). infer 出的形状恒为单点区间 (等长不变量).
    /// `(0, 0)` = 未配置 (由 [`MockStrategy::resolve_against`] 在拿到 real 后 infer).
    #[serde(default)]
    pub length_range: (usize, usize),
    /// 结构形状 (category-aware 推断, 见 [`SecretShape`]). 默认 Plain (兼容旧配置).
    #[serde(default)]
    pub shape: SecretShape,
}

impl GenSpec {
    /// 从 real secret 推断默认 gen spec:
    /// `prefix=global_prefix`, `charset=infer_from(real)` (**+ widen 兜底**),
    /// `length_range=(global_prefix.chars + n, ...)` (mock 总长 = global_prefix + real 等长 body).
    ///
    /// `global_prefix` 来自 `[redact] global_mock_prefix` 配置 (默认空串).
    /// 让 Auto 模式生成的 mock 带可配置的统一前缀, 便于在日志 / WebUI 中视觉辨识.
    /// 非空时恒推断 Plain (辨识度 > 仿真度, 见模块头部 "global_prefix 裁决").
    ///
    /// # category-aware shape (2026-10)
    ///
    /// `category` 参与 `infer_shape` 判定: PrivateKey + PEM / Email 形状自证 /
    /// Token + JWT / ApiKey + 公开前缀 / Phone 骨架 / Username 名字池 → 结构化
    /// shape (等长不变量保持, 仿真度提升); 其余 Plain. charset 推断源是 real 的
    /// **随机部分** (Jwt 去点 / Pem 取 body 行 / PublicPrefixed 去公开前缀 /
    /// Email 取 local 段 / Phone 取 digit 位 / Username 取全串), 结构分隔符不入
    /// pool; Email/Username 额外**强制** charset ⊇ 名字池 + 分隔符 + digits
    /// (名字池生成不从 charset 采样, RED-1 前提), Phone 强制 digits-only 且跳过
    /// widen (骨架仿真的字符域约束, 见函数体注释).
    ///
    /// # Auto widen 兜底 (2026-09, 生成器扩宽发现的老缺陷)
    ///
    /// 退化 real (全同字符, 如 `""""`) 推断出单字符 charset → 等长候选空间 = 1,
    /// 唯一候选 == real 本身 → probing 必拒 → 耗尽 (fail_closed 下 503).
    /// Auto 的产品语义是**开箱即用**, 不应要求用户懂 charset 配置, 故推断后
    /// 候选空间 < [`MIN_CANDIDATE_SPACE_WARN`] 时逐级并入标准类
    /// (lowercase → digits → uppercase), 直到达标或全部并入.
    /// - 与 lint 阈值对齐 ⇒ Auto 模式永不落入弱配置区 (lint 只对手动配置有意义);
    /// - widen 是 (real, category, prefix) 的纯函数 ⇒ C3 确定性保持;
    /// - 空间充足的 secret 不触发 ⇒ 已生成的 mock 不变, 前缀缓存兼容;
    /// - 并入只增不减 (charset ⊇ real 字符) ⇒ 仿真度单调不降;
    /// - 极短 real (n ≤ 3: 全开标准类后 65³ ≈ 27 万仍 < 2^20) 兜到"最大可达"即停 —
    ///   等长约束下空间上限 = charset_size^n, 属物理边界 (n ≥ 4 恒可达标: 62⁴ ≈ 1480 万),
    ///   该形态由配置期 redact 短值 gate 拒绝 (#383 方案 D: validate_and_resolve 对
    ///   redact + n<4 直接 Err 引导换策略), 运行时残余由 fail_closed 兜底.
    pub fn infer_default_for(real: &str, category: SecretCategory, global_prefix: &str) -> Self {
        let n = real.chars().count();
        let shape = infer_shape(real, category, global_prefix);
        // charset 推断源: real 的随机部分 (结构分隔符/公开段不入 pool, 生成器按
        // shape 重新放置结构). Plain 的随机部分就是 real 本身 (历史行为).
        // random_source 同时是 widen 基数 random_n 的来源 — 随机字符数, 与
        // candidate_space / body_length_range 的口径一致 (结构段不计入空间).
        // 已知偏差: Email 域交换 (非白名单域换白名单域) 时 random_n = real local
        // 长度, 与 shape 的 local_len 可不同 (见下方 Email arm) — widen 是
        // charset^random_n 的保守近似, 对 Email/Username 无实质作用 (name-like
        // 生成不从 pool 采样, candidate_space 由 name_like_space 覆写), 强制项
        // 只增不减, 最坏情况是多开 uppercase (装饰性, 不破坏 RED-1/C3).
        let (random_source, prefix) = match &shape {
            SecretShape::Plain => (real.to_string(), global_prefix.to_string()),
            SecretShape::PublicPrefixed { public_prefix } => (
                real.chars()
                    .skip(public_prefix.chars().count())
                    .collect::<String>(),
                String::new(),
            ),
            SecretShape::Jwt { .. } => (real.replace('.', ""), String::new()),
            SecretShape::Pem { .. } => {
                // body 行 concat (去边界行与换行)
                let lines: Vec<&str> = real.split('\n').collect();
                (lines[1..lines.len() - 1].concat(), String::new())
            }
            // Email: local 段 (real 的 '@' 前 — 形状自证 parse_email 已过).
            // 注: local_len (body 长度) 由 shape 的 domain 与 total 决定, 与 real
            // local 长度可不同 (非白名单域换白名单域时), random_source 只喂 charset.
            SecretShape::Email { .. } => (
                real.split_once('@')
                    .map(|(l, _)| l)
                    .unwrap_or("")
                    .to_string(),
                String::new(),
            ),
            // Phone: digit 字符集 (skeleton 展开的 digits = real 的 digit 位).
            SecretShape::Phone { .. } => (
                real.chars()
                    .filter(|c| c.is_ascii_digit())
                    .collect::<String>(),
                String::new(),
            ),
            // Username: real 全串 (随机部分就是整个 body).
            SecretShape::Username => (real.to_string(), String::new()),
        };
        let random_n = random_source.chars().count();
        let prefix_len = prefix.chars().count();
        let mut charset = Charset::infer_from(&random_source);
        // 形状强制字符面 (RED-1): Email/Username 的随机段由名字池常量表 + digit
        // pad 生成 (**不从 charset 采样**), charset 必须 ⊇ 名字池字符 (全小写) +
        // 分隔符 + digits — infer 路径在此强制. Phone 强制 digits-only 且跳过
        // widen (下方): mock 的随机位恒 digit (骨架仿真), 并入字母破坏 digit-only
        // 仿真; widen 的空间兜底对 Phone 无意义 (10^n 是 digit-only 的物理空间,
        // 推断 gate 已保证 digit ≥ 7 → 10^7 > 2^20).
        let mut skip_widen = false;
        match &shape {
            SecretShape::Email { .. } => {
                charset.lowercase = true;
                charset.digits = true;
                if !charset.other.contains(&'.') {
                    charset.other.push('.');
                }
            }
            SecretShape::Username => {
                charset.lowercase = true;
                charset.digits = true;
                for c in ['_', '.', '-'] {
                    if !charset.other.contains(&c) {
                        charset.other.push(c);
                    }
                }
            }
            SecretShape::Phone { .. } => {
                charset = Charset {
                    digits: true,
                    ..Default::default()
                };
                skip_widen = true;
            }
            _ => {}
        }
        // body 候选空间 = charset_size^random_n (等长, 与 candidate_space 的单区间项一致).
        // saturating_pow: 空间封顶 u64::MAX, 溢出不 panic.
        // 注: `random_n as u32` 对 >u32::MAX (≈4.3e9 chars, 需 ≥4GB secret) 截断 — 物理不可达.
        let space_short = |cs: &Charset| {
            (cs.enabled_chars().len() as u64).saturating_pow(random_n as u32)
                < MIN_CANDIDATE_SPACE_WARN
        };
        // 逐级并入: lowercase 可能已被 infer 开启 (如全小写 real) — 第一步 no-op,
        // 由 recheck 驱动向 digits 推进, 自校正无需特判. 强制项 (上方) 只增不减,
        // widen 不会被关掉.
        if !skip_widen {
            if space_short(&charset) {
                charset.lowercase = true;
            }
            if space_short(&charset) {
                charset.digits = true;
            }
            if space_short(&charset) {
                charset.uppercase = true;
            }
        }
        Self {
            prefix,
            charset,
            length_range: (prefix_len + n, prefix_len + n),
            shape,
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
        // shape 一致性: 结构形状 (非 Plain) 下 prefix 字段必须为空 (结构分段与公开
        // 前缀统一由 shape 携带, 拒绝双通道歧义配置), 且 length_range 必须与 shape
        // 的分段结构严格一致 (等长不变量的手动配置形态).
        //
        // 豁免前提的结构保证 (C5): c5_violated 豁免的固定段 (public_prefix /
        // PEM 边界行 / Email domain) 在此强制其"信息量为零的公开格式"属性 —
        // public_prefix 必须 ∈ PUBLIC_KEY_PREFIXES 白名单, header/footer 必须匹配
        // 标准 PEM 标签形态, domain 必须 ∈ EMAIL_DOMAINS 白名单.
        // 推断路径天然满足 (find_public_prefix 白名单产出 / parse_pem 的 label
        // 收紧), 手动配置经此拦截 — 杜绝"自定义固定段携带真值内容并整段豁免
        // C5 检查"的绕过面.
        if !matches!(self.shape, SecretShape::Plain) && !self.prefix.is_empty() {
            return Err(
                "gen.prefix must be empty when shape != plain (structure is carried by \
                 shape; for a plain prefix+body form use shape = plain)"
                    .into(),
            );
        }
        match &self.shape {
            SecretShape::Plain => {}
            SecretShape::PublicPrefixed { public_prefix } => {
                let pp_len = public_prefix.chars().count();
                if public_prefix.is_empty() || pp_len >= min {
                    return Err(format!(
                        "shape.public_prefixed prefix length ({pp_len}) must be in 1..min({min})"
                    ));
                }
                if !PUBLIC_KEY_PREFIXES.contains(&public_prefix.as_str()) {
                    return Err(format!(
                        "shape.public_prefixed prefix must be a member of the public key prefix \
                         whitelist (C5 exemption applies only to well-known format prefixes), got \
                         {pp_len} chars"
                    ));
                }
            }
            SecretShape::Jwt { seg_lens } => {
                if seg_lens.len() != 3 || seg_lens.contains(&0) {
                    return Err("shape.jwt requires exactly 3 non-empty segments".into());
                }
                // saturating 求和: 对抗性手动值 (WebUI upsert 可达的巨大分段) 不
                // panic (debug) / 不回绕 (release).
                let total: usize = seg_lens
                    .iter()
                    .fold(0usize, |a, &b| a.saturating_add(b))
                    .saturating_add(seg_lens.len())
                    .saturating_sub(1);
                if (min, max) != (total, total) {
                    return Err(format!(
                        "shape.jwt segments sum to {total} chars (incl. dots); length_range must \
                         be the single point ({total}, {total})"
                    ));
                }
            }
            SecretShape::Pem {
                header_line,
                footer_line,
                body_line_lens,
            } => {
                if header_line.is_empty() || footer_line.is_empty() {
                    return Err("shape.pem header/footer lines must be non-empty".into());
                }
                match (
                    pem_boundary_label(header_line, "BEGIN"),
                    pem_boundary_label(footer_line, "END"),
                ) {
                    (Some(h), Some(f)) if h == f => {}
                    _ => {
                        return Err(
                            "shape.pem header/footer must match the standard PEM label form \
                             (-----BEGIN/END [A-Z0-9 ]{1,64}-----, labels equal): C5 exemption \
                             applies only to well-known format boundaries"
                                .into(),
                        );
                    }
                }
                if body_line_lens.is_empty() || body_line_lens.contains(&0) {
                    return Err("shape.pem requires at least one non-empty body line".into());
                }
                let total: usize = header_line
                    .chars()
                    .count()
                    .saturating_add(footer_line.chars().count())
                    .saturating_add(1) // header 后换行
                    .saturating_add(
                        body_line_lens
                            .iter()
                            .fold(0usize, |a, &b| a.saturating_add(b)),
                    )
                    .saturating_add(body_line_lens.len()); // 每行后换行
                if (min, max) != (total, total) {
                    return Err(format!(
                        "shape.pem structure sums to {total} chars; length_range must be the \
                         single point ({total}, {total})"
                    ));
                }
            }
            SecretShape::Email { domain } => {
                // C5 豁免前提的结构保证: domain 必须是公开邮箱域白名单成员
                // (私有域携带部署特例内容, 整段豁免 C5 会绕过 RED-5 — 推断路径
                // 天然满足 (EMAIL_DOMAINS 产出), 手动配置经此拦截).
                let domain_len = domain.chars().count();
                if !EMAIL_DOMAINS.contains(&domain.as_str()) {
                    return Err(
                        "shape.email domain must be a member of the public email domain \
                         whitelist (C5 exemption applies only to well-known public domains)"
                            .into(),
                    );
                }
                // 结构总长 = local_len + 1 ('@') + domain_len, local_len ≥ 1 →
                // min ≥ domain_len + 2 (local_len 由 length_range 反推, 单点一致).
                if min < domain_len + 2 {
                    return Err(format!(
                        "shape.email requires a non-empty local part: length_range min({min}) \
                         must be ≥ domain length ({domain_len}) + 2 (local + '@')"
                    ));
                }
                if min != max {
                    return Err(format!(
                        "shape.email structure requires a single-point length_range, got \
                         ({min}, {max}); local length = min - {domain_len} - 1"
                    ));
                }
            }
            SecretShape::Phone { skeleton } => {
                let skeleton_len = skeleton.chars().count();
                if skeleton.is_empty() {
                    return Err("shape.phone skeleton must be non-empty".into());
                }
                if !skeleton
                    .chars()
                    .all(|c| matches!(c, '#' | '+' | ' ' | '-' | '(' | ')' | '.'))
                {
                    return Err(
                        "shape.phone skeleton chars must be a subset of {'#', '+', ' ', '-', \
                         '(', ')', '.'} (digit placeholder + phone separators)"
                            .into(),
                    );
                }
                if !skeleton.contains('#') {
                    return Err(
                        "shape.phone skeleton requires at least one '#' digit placeholder".into(),
                    );
                }
                // charset 必须纯 digits: 随机位从 charset pool 取 (骨架仿真),
                // 并入字母会破坏 digit-only 形态 (与 infer 路径的强制一致).
                if !(self.charset.digits
                    && !self.charset.lowercase
                    && !self.charset.uppercase
                    && !self.charset.underscore
                    && !self.charset.hyphen
                    && self.charset.other.is_empty())
                {
                    return Err(
                        "shape.phone charset must be digits-only (random digits come from \
                         charset; letters would break the digit skeleton simulation)"
                            .into(),
                    );
                }
                if (min, max) != (skeleton_len, skeleton_len) {
                    return Err(format!(
                        "shape.phone skeleton sums to {skeleton_len} chars; length_range must \
                         be the single point ({skeleton_len}, {skeleton_len})"
                    ));
                }
            }
            // Username 无结构字段 (prefix 空已由上方通用规则强制); length_range
            // 区间允许非单点 (生成器按区间 hash 选 target, 同 Plain 的 body 长度选择).
            SecretShape::Username => {}
        }
        Ok(())
    }
}

// ─── 候选空间 lint (拒绝前的信息载体) ──────────────────────────────────────

/// 配置期候选空间 gate 的阈值: gen spec 的候选空间低于此值时,
/// [`MockStrategy::lint_candidate_space`] 返回 `Some` — 由调用方
/// ([`crate::secrets::SecretEntry::validate_and_resolve`], redact 策略) 转为
/// **fail-fast 拒绝** (#383 方案 D, 2026-10-21; 历史形态是 WARN).
///
/// # rationale
///
/// 运行时 mock probing 上限是 `redact::MOCK_PROBE_LIMIT` (生产 2^20, 见
/// `src/redact.rs`): redact 需要为每个 secret 找到**不在 IR 中且未被分配**的 mock,
/// 有效空间还要再扣除 IR 已有内容与已分配 mock — 因此名义候选空间一旦低于探测
/// 上限, 配合对抗性 IR 内容即可让 probing 耗尽 (触发
/// `[redact] on_probe_exhausted` 的 fail-open/fail-closed). 本 gate 把这类弱配置
/// 拒绝在配置写入时 (static 加载 / WebUI upsert), 从源头消灭耗尽触发面
/// (fail_open 形态的 record 真值回显与 SEC-1 冲突 — issue #383 裁决).
///
/// # 与 `redact::MOCK_PROBE_LIMIT` 的关系
///
/// 阈值语义独立成常量, **不引用** `redact::MOCK_PROBE_LIMIT` — mock → redact 是
/// 反向依赖 (依赖方向图见根 AGENTS.md, redact → codec/mock 才是合法方向).
/// 两者数值若需联动, 由人维护同步 (当前同为 2^20).
pub const MIN_CANDIDATE_SPACE_WARN: u64 = 1 << 20;

/// 弱候选空间 lint 的结果 (纯数据; 由调用方转成拒绝 message, 便于单元测试).
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
    /// 平坦两形态 (Plain / PublicPrefixed) 的固定前缀: Plain 用 `gen.prefix`,
    /// PublicPrefixed 用 shape 携带的白名单公开前缀. 其余形状 (Jwt / Pem /
    /// Email / Phone / Username) 无平坦前缀概念 (validate 强制其 prefix 为空).
    /// "哪个前缀生效" 的单一落点.
    fn flat_fixed_prefix(&self) -> &str {
        match &self.shape {
            SecretShape::PublicPrefixed { public_prefix } => public_prefix,
            _ => &self.prefix,
        }
    }

    /// body (随机部分) 的长度闭区间 (saturating). 与 `gen_one_auto_body` 的生成
    /// 语义对齐 — 固定结构段 (prefix / 公开前缀 / PEM 边界行 / 点分隔符 /
    /// Email 的 '@'+domain / Phone 的骨架 literal) 不参与随机选择.
    ///
    /// shape-aware: 平坦两形态按 `length_range - flat_fixed_prefix()` (Plain 即
    /// 历史行为); Jwt / Pem / Email / Phone 的分段长度由 shape 携带 (等长, 单点
    /// 区间 — infer 保证, 手动配置由 validate 强制); Username 的 body 即全串
    /// (prefix 恒空, 区间原样保留 — 生成器按区间 hash 选 target).
    fn body_length_range(&self) -> (usize, usize) {
        match &self.shape {
            SecretShape::Plain | SecretShape::PublicPrefixed { .. } => {
                let prefix_len = self.flat_fixed_prefix().chars().count();
                (
                    self.length_range.0.saturating_sub(prefix_len),
                    self.length_range.1.saturating_sub(prefix_len),
                )
            }
            SecretShape::Jwt { seg_lens } => {
                // saturating: 与 validate 侧的对抗性保证对齐 (巨大手动分段不 panic).
                let total: usize = seg_lens.iter().fold(0usize, |a, &b| a.saturating_add(b));
                (total, total)
            }
            SecretShape::Pem { body_line_lens, .. } => {
                let total: usize = body_line_lens
                    .iter()
                    .fold(0usize, |a, &b| a.saturating_add(b));
                (total, total)
            }
            SecretShape::Email { domain } => {
                // local_len = 总长 (单点, 取 min) - '@' - domain 长.
                let local_len = self
                    .length_range
                    .0
                    .saturating_sub(1 + domain.chars().count());
                (local_len, local_len)
            }
            SecretShape::Phone { skeleton } => {
                // 随机位 = skeleton 的 '#' 占位数 (literal 分隔符不计入).
                let digits = skeleton.chars().filter(|&c| c == '#').count();
                (digits, digits)
            }
            SecretShape::Username => {
                let prefix_len = self.flat_fixed_prefix().chars().count();
                (
                    self.length_range.0.saturating_sub(prefix_len),
                    self.length_range.1.saturating_sub(prefix_len),
                )
            }
        }
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
    ///
    /// # name-like 形状覆写 (Email / Username)
    ///
    /// 随机段由名字池常量表 + digit pad 生成 (**不从 charset 采样**), 诚实空间 =
    /// `name_like_space` 对 body 区间求和 (Email: local_len 单点 + seps =
    /// [`EMAIL_LOCAL_SEPS`]; Username: Σ per len, seps = [`USERNAME_SEPS`]).
    /// Phone 不覆写: 随机位从 charset pool 取, charset 恒 digits-only (validate
    /// 强制) — 既有 `charset^body` 公式即诚实空间.
    pub fn candidate_space(&self) -> u64 {
        let charset_size = self.charset.enabled_chars().len() as u64;
        if charset_size == 0 {
            return 0;
        }
        let (bmin, bmax) = self.body_length_range();
        if bmax < bmin {
            return 0;
        }
        match &self.shape {
            SecretShape::Email { .. } => {
                return name_like_space(bmin, EMAIL_LOCAL_SEPS, charset_size);
            }
            SecretShape::Username => {
                let mut total: u64 = 0;
                for len in bmin..=bmax {
                    total = total.saturating_add(name_like_space(len, USERNAME_SEPS, charset_size));
                    if total == u64::MAX {
                        break; // 早退: 极宽区间防长循环 (同下方饱和早退).
                    }
                }
                return total;
            }
            _ => {}
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
    /// `Some` (弱配置信号). **纯函数不直接打日志/返回错误**, 由调用方处理 —
    /// 生产消费方是 `crate::secrets::SecretEntry::validate_and_resolve`: redact 策略下
    /// 把命中转为 **fail-fast Err** (#383 方案 D, 2026-10-21 自 WARN 升级), 本函数
    /// 是 Err message 的信息来源 (候选空间数字等).
    ///
    /// # 语义边界 (Auto widen 后)
    ///
    /// Auto 推断路径经 [`GenSpec::infer_default_for`] 的 widen 兜底, resolve 后
    /// 空间恒 ≥ 阈值 (极短 real 的物理边界除外) — Auto 场景实际不再触发本 lint;
    /// lint 的有效对象是**用户手动配置**的 gen_spec (`lint_explicit_weak_spec_is_some`).
    /// 极短 real (n ≤ 3) 的 Auto 形态在 validate_and_resolve 被 redact 策略的
    /// 独立短值 gate **更早拒绝** (引导换策略, 而非误导性的 "widen" 建议);
    /// 本函数对其 resolved spec 仍返回 Some (纯函数边界语义, 由
    /// `lint_auto_degenerate_real_widened_not_linted` 尾部钉住).
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
///
/// `PartialEq` / `Eq` / `Hash` 手写**只覆盖声明态** (`initial` + `gen_spec`) —
/// `gen_inferred` 是运行时标记, 参与 equality/seed 会让 "infer 前后" 的同一
/// 策略产生不同 seed (C3 违例) 或假性不等.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MockStrategy {
    /// 维度一: 初始值模式. 默认 `Auto`.
    #[serde(default)]
    pub initial: InitialValue,

    /// 维度二: 生成策略. `None` = 未配置 (resolve 时 infer); `Some` = 已定型
    /// (用户显式配置, 或 resolve 推断填充 — 区分见 `gen_inferred`).
    ///
    /// 仅 `initial = Auto` 时生效; `Fixed` 模式忽略此字段.
    ///
    /// 字段名 `gen_spec` 避免 `gen` (Rust 2024 保留关键字); serde rename 保 toml/json
    /// wire 兼容 (用户配置仍写 `gen = ...`).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "gen")]
    pub gen_spec: Option<GenSpec>,

    /// 运行时标记: `gen_spec` 是否由 [`MockStrategy::resolve_against`] 推断填充
    /// (非用户显式配置). serde 形态: **只写不读** (`skip_deserializing` + false 时
    /// 省略) — `true` 时序列化进 GET DTO (EffectiveSecret/SecretMasked), WebUI
    /// 编辑器的脏检查以此区分 "gen 是 infer 结果 → 回传省略 gen 让后端 fresh
    /// infer" 与 "用户显式 → 原样回传防丢" (#319); 永不反序列化 ⇒ 经 wire
    /// (static/state toml / WebUI 请求) 进入的 `gen_spec` 恒为用户显式, 该
    /// 不变量不可被客户端伪造. 持久化层 (`DynamicTable::persist_dynamic` 经
    /// [`crate::config::DynamicEntry::strip_runtime_state`]) 依此把 infer 的
    /// gen_spec (连同标记) 从 state.toml 剥离 — 落盘只含用户声明, 每次加载
    /// fresh infer (避免 stale spec 固化, 也避免 "gen_spec 存在" 被误读为
    /// 用户显式配置).
    ///
    /// 不参与 `PartialEq` / `Eq` / `Hash` (见 struct 级手写 impl 说明).
    #[serde(skip_deserializing, skip_serializing_if = "std::ops::Not::not")]
    pub gen_inferred: bool,
}

impl PartialEq for MockStrategy {
    fn eq(&self, other: &Self) -> bool {
        self.initial == other.initial && self.gen_spec == other.gen_spec
    }
}

impl Eq for MockStrategy {}

impl std::hash::Hash for MockStrategy {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.initial.hash(state);
        self.gen_spec.hash(state);
    }
}

/// category 标注与值形状的矛盾 (配置期 WARN 的检测结果, 纯数据; 语义与检测面
/// 见 [`MockStrategy::category_shape_mismatch`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CategoryShapeMismatch {
    /// 值是 PEM 但标注非 privatekey — 行为已按 PEM 结构化 (不受标注影响),
    /// 提醒改标注保持所见 (WebUI category) 与所为 (mock 形状) 一致.
    PemButNotPrivatekey,
    /// 值是 email 形状但标注非 email — 行为已按 Email 结构化 (email 检测不
    /// gate category, 形状自证; local 空间达标时), 标注是纯语义债, 提醒改标注
    /// 保持所见与所为一致 (同 PEM 先例 — 空间不足时行为仍 Plain, 改标注不改变
    /// 行为, cosmetic).
    EmailButNotEmailCategory,
    /// 值是 JWT 形状但标注非 token — 退化 plain, 改标 token 可启用结构化 mock.
    JwtButNotToken,
    /// 值命中公开前缀白名单但标注非 apikey — 退化 plain, 改标 apikey 可启用
    /// 前缀保留.
    PublicPrefixButNotApiKey,
}

impl CategoryShapeMismatch {
    /// 检测到的形状名 (WARN 结构化字段用, 非 secret 内容).
    pub fn detected(&self) -> &'static str {
        match self {
            Self::PemButNotPrivatekey => "pem",
            Self::EmailButNotEmailCategory => "email",
            Self::JwtButNotToken => "jwt",
            Self::PublicPrefixButNotApiKey => "public_prefix",
        }
    }

    /// 建议标注 (WARN 行动建议用).
    pub fn suggested_category(&self) -> SecretCategory {
        match self {
            Self::PemButNotPrivatekey => SecretCategory::PrivateKey,
            Self::EmailButNotEmailCategory => SecretCategory::Email,
            Self::JwtButNotToken => SecretCategory::Token,
            Self::PublicPrefixButNotApiKey => SecretCategory::ApiKey,
        }
    }
}

impl MockStrategy {
    /// 在 resolve 拿到 real value 后调用:
    /// 若 `gen=None` 且 `initial=Auto`, 用 real + category + `global_prefix` infer
    /// 默认 gen spec (category-aware shape, 见 [`GenSpec::infer_default_for`]).
    /// Fixed 模式不需要 gen, 保持 None.
    ///
    /// `global_prefix` 来自 `[redact] global_mock_prefix` (默认空串), 透传给
    /// [`GenSpec::infer_default_for`] 作为 infer 出的 gen_spec.prefix.
    pub fn resolve_against(&mut self, real: &str, category: SecretCategory, global_prefix: &str) {
        if self.gen_spec.is_none() && matches!(self.initial, InitialValue::Auto) {
            self.gen_spec = Some(GenSpec::infer_default_for(real, category, global_prefix));
            self.gen_inferred = true;
        }
    }

    /// category 标注与值形状的矛盾检测 (配置期 WARN 的纯数据源, 与
    /// [`MockStrategy::lint_candidate_space`] 同型: 纯函数不直接打日志, 由调用方
    /// WARN — 便于单元测试). 严禁携带 secret value / mock 明文 (SEC 红线).
    ///
    /// # 检测面 (只报"矛盾", 不报"常态")
    ///
    /// - `PemButNotPrivatekey`: 值是 PEM 但标注非 privatekey — **行为已按 PEM
    ///   结构化** (PEM 检测不 gate category, 形状自证), 标注是纯语义债, 提醒改
    ///   标注保持 WebUI 所见与实际行为一致.
    /// - `EmailButNotEmailCategory`: 值是 email 形状 (语法级 `parse_email`, 不
    ///   预判空间 gate) 但标注非 email — 行为已按 Email 结构化 (email 检测同样
    ///   不 gate category), 标注是纯语义债 (同 PEM; local 空间不足时行为仍
    ///   Plain, 改标注不改变行为).
    /// - `JwtButNotToken` / `PublicPrefixButNotApiKey`: 值的形状需要标注佐证才
    ///   能启用结构化 mock (JWT/公开前缀 gate category), 标注不符 → **静默退化
    ///   plain, 丢失仿真增强** — 提醒改标注可启用 (暴露映射表/手工标注错误).
    ///
    /// 反向不检测 (设计内常态, warn 即噪音): 标注 token/privatekey/apikey 但值
    /// 无对应形状 (大量 token 是随机串 / WireGuard 私钥是单行 base64 / 绝大多数
    /// api key 无已知前缀), 平坦串即正确行为.
    ///
    /// # 跳过条件 (用户已接管, 矛盾无行动价值)
    ///
    /// - `initial = Fixed` 或用户显式配置了 `gen_spec` (含 shape; 判据 =
    ///   `gen_spec.is_some() && !gen_inferred` — infer 填充不算接管): mock 形态
    ///   由用户配置决定, 标注不参与行为.
    /// - `global_prefix` 非空: 用户显式选辨识度 = 放弃全部结构仿真 (恒推断
    ///   plain), "改标注可启用"不成立.
    ///
    /// # 调用时机
    ///
    /// 推荐在 [`MockStrategy::resolve_against`] **之前**调用 (如
    /// `crate::secrets::SecretEntry::validate_and_resolve` 第四步): 此时
    /// `gen_spec.is_some()` ⟺ 用户显式配置. `gen_inferred` 标记使其在之后
    /// (含同一 entry 重复 validate_and_resolve 的场景) 调用仍精确. real 须已
    /// resolve (value_file 已读入).
    pub fn category_shape_mismatch(
        &self,
        real: &str,
        category: SecretCategory,
        global_prefix: &str,
    ) -> Option<CategoryShapeMismatch> {
        if !matches!(self.initial, InitialValue::Auto)
            || (self.gen_spec.is_some() && !self.gen_inferred)
        {
            return None;
        }
        if !global_prefix.is_empty() {
            return None;
        }
        if parse_pem(real).is_some() && category != SecretCategory::PrivateKey {
            return Some(CategoryShapeMismatch::PemButNotPrivatekey);
        }
        if parse_email(real).is_some() && category != SecretCategory::Email {
            return Some(CategoryShapeMismatch::EmailButNotEmailCategory);
        }
        if category != SecretCategory::Token && parse_jwt(real).is_some() {
            return Some(CategoryShapeMismatch::JwtButNotToken);
        }
        if category != SecretCategory::ApiKey && find_public_prefix(real).is_some() {
            return Some(CategoryShapeMismatch::PublicPrefixButNotApiKey);
        }
        None
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

/// mock 候选的 C5 检查 (shape-aware, RED-5 "公开格式子串豁免"):
/// PublicPrefixed 剥离公开前缀段 / Pem 剥离边界行 / Email 剥离 `@domain` 公开
/// 邮箱域段后, 对**随机部分**做 ≥k 窗口检查 (real 整体作 needle — 随机部分撞上
/// real 任意窗口仍算违反, 重试链兜底). Plain / Jwt 无豁免段, 全串检查 (Jwt 的点
/// 分隔符是单字符, 低于任何 k ≥ 4 阈值, 天然不构成豁免需求); Phone / Username
/// 同理全串检查 — phone 的骨架分隔符是单字符 literal (< k), username 的名字池
/// 是常量表 (非 real 派生). 已知边界 (best-effort): phone 的**连续分隔符链**
/// (病态 real 如长 `-` 串) 使 literal 段自身 ≥k 且不可变, C5 重试链无解时按
/// 既有 safety-bound 语义返回最后候选.
fn c5_violated(candidate: &str, real: &str, shape: &SecretShape, k: usize) -> bool {
    match shape {
        SecretShape::Plain
        | SecretShape::Jwt { .. }
        | SecretShape::Phone { .. }
        | SecretShape::Username => contains_kchar_substring(candidate, real, k),
        SecretShape::PublicPrefixed { public_prefix } => {
            let stripped = candidate
                .strip_prefix(public_prefix.as_str())
                .unwrap_or(candidate);
            contains_kchar_substring(stripped, real, k)
        }
        SecretShape::Email { domain } => {
            // 剥离 @domain 公开段 (白名单成员, 信息量为零; strip 失败 — 手动畸形
            // domain 不匹配候选尾部 — 时全串检查, fail-safe).
            let stripped = candidate
                .strip_suffix(domain.as_str())
                .and_then(|s| s.strip_suffix('@'))
                .unwrap_or(candidate);
            contains_kchar_substring(stripped, real, k)
        }
        SecretShape::Pem {
            header_line,
            footer_line,
            ..
        } => {
            let mut s = candidate;
            if let Some(rest) = s
                .strip_prefix(header_line)
                .and_then(|r| r.strip_prefix('\n'))
            {
                s = rest;
            }
            if let Some(rest) = s
                .strip_suffix(footer_line)
                .and_then(|r| r.strip_suffix('\n'))
            {
                s = rest;
            }
            contains_kchar_substring(s, real, k)
        }
    }
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
            // 找到第一个不含 real ≥k 字符子串的候选 (shape-aware 豁免公开结构段,
            // 见 `c5_violated`). 全失败则返回最后一次 (best-effort).
            // 上限是 safety bound (1e-50000 量级失败率, 实质等价于确定性, 见模块头部).
            for retry in 0..=C5_INTERNAL_RETRIES {
                let candidate = gen_one_auto_body(gen_spec, &pool, seed, counter, retry);
                if !c5_violated(&candidate, real, &gen_spec.shape, k) {
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

/// name-like 随机段生成 (email local 与 username 共用): 名字池常量表
/// ([`FIRST_NAMES`]/[`LAST_NAMES`]) 组合 + digit pad 到恰好 `target` 长.
/// 完全确定性于 `(target, seps, seed, counter, retry, pool)`, 无副作用 (C3).
///
/// 模式选择: two-part (`first + sep + last + pad`) / first-only (`first + pad`)
/// / 全随机兜底 (target < 2, 无任何 first 放得下 — 名字池物理不可用, 从 `pool`
/// 取随机字符). two-part 在大 target (≥ 8) 下概率优先 (拟真: 长 username 通常
/// 是姓名组合), 小 target 均匀二选一; 所选 first 配不出 last 时退化 first-only.
///
/// 随机流纪律 (与 `gen_one_auto_body` 一致): pad digit 与兜底字符取自
/// `{seed}{counter}{retry}{i}` hash 流 (i 从 0 起), **名字/sep 挑选不消耗流
/// 索引** (结构段不消耗流索引). pad 恒为 digit (`hash % 10` → '0'..='9', 拟真
/// "john92" 而非 "johnXz" — 与 `name_like_space` 的 10^pad 口径一致).
///
/// # 前提 (调用方保证)
///
/// `pool` 非空 (`gen_one_auto_body` 入口已防御空 pool); infer 路径的 charset 恒
/// ⊇ {lowercase, digits, sep 字符} (`infer_default_for` 强制) — 名字池字符
/// (全小写 ASCII) 与 digit pad 都 ⊆ charset (RED-1; 名字池不从 charset 采样,
/// 合规性由该强制保证, 手动配置同理需覆盖此面).
fn gen_name_like(
    target: usize,
    seps: &[char],
    seed: u64,
    counter: u32,
    retry: u32,
    pool: &[char],
) -> String {
    // fitting 子集 (长度放得下, 顺序取 const 表序).
    let firsts: Vec<&str> = FIRST_NAMES
        .iter()
        .copied()
        .filter(|f| f.chars().count() <= target)
        .collect();
    if firsts.is_empty() {
        // 全随机兜底 (target < 2): 从 charset pool 取 (pool 非空由调用方保证).
        return (0..target)
            .map(|i| {
                let h = crate::util::hash64(&format!("{seed}{counter}{retry}{i}"));
                pool[(h % pool.len() as u64) as usize]
            })
            .collect();
    }
    // 模式选择: two-part 可行时按 hash 二选一 (大 target 偏向 two-part).
    let mode_h = crate::util::hash64(&format!("{seed}{counter}{retry}mode"));
    let want_two_part = if target >= 8 {
        mode_h % 4 != 0
    } else {
        mode_h % 2 == 0
    };
    // 名字挑选: hash 独立 tag (不消耗 pad 的流索引). 嵌套 fn (非闭包) — 显式
    // lifetime 让 `items` 的 'static 元素引用传播到输出.
    fn pick<'a>(seed: u64, counter: u32, retry: u32, tag: &str, items: &[&'a str]) -> &'a str {
        let h = crate::util::hash64(&format!("{seed}{counter}{retry}{tag}"));
        items[(h % items.len() as u64) as usize]
    }
    // pad digit: hash % 10 → '0'..='9' (恒 digit, 不依赖 pool).
    let digit_at = |i: usize| -> char {
        let h = crate::util::hash64(&format!("{seed}{counter}{retry}{i}"));
        (b'0' + (h % 10) as u8) as char
    };
    let first = pick(seed, counter, retry, "first", &firsts);
    if want_two_part && !seps.is_empty() {
        let lasts: Vec<&str> = LAST_NAMES
            .iter()
            .copied()
            .filter(|l| first.chars().count() + 1 + l.chars().count() <= target)
            .collect();
        if !lasts.is_empty() {
            let last = pick(seed, counter, retry, "last", &lasts);
            let sep_h = crate::util::hash64(&format!("{seed}{counter}{retry}sep"));
            let sep = seps[(sep_h % seps.len() as u64) as usize];
            let pad_len = target - first.chars().count() - 1 - last.chars().count();
            let mut out = String::with_capacity(target);
            out.push_str(first);
            out.push(sep);
            out.push_str(last);
            out.extend((0..pad_len).map(digit_at));
            return out;
        }
    }
    // first-only.
    let pad_len = target - first.chars().count();
    let mut out = String::with_capacity(target);
    out.push_str(first);
    out.extend((0..pad_len).map(digit_at));
    out
}

/// Auto 模式的单次 body 生成 (给定 `retry` 偏移量). 完全确定性, 无副作用.
///
/// shape-aware: 随机字符流由同一个 hash 序列驱动 (`{seed}{counter}{retry}{i}`,
/// i 全局递增 — 结构段不消耗流索引, 保证各形状共享同一确定性生成语义), 再按
/// shape 的结构放置 (点分隔符 / PEM 边界行与换行 / 公开前缀 / email 的
/// `@domain` / phone 的骨架 literal / username 的 name-like 名字池组合).
fn gen_one_auto_body(
    gen_spec: &GenSpec,
    pool: &[char],
    seed: u64,
    counter: u32,
    retry: u32,
) -> String {
    // 随机字符流: 取流中第 offset..offset+len 个字符 (hash 索引连续, 段间无缝).
    let random_chars = |offset: usize, len: usize| -> String {
        (offset..offset + len)
            .map(|i| {
                let h = crate::util::hash64(&format!("{seed}{counter}{retry}{i}"));
                pool[(h % pool.len() as u64) as usize]
            })
            .collect()
    };

    match &gen_spec.shape {
        SecretShape::Plain | SecretShape::PublicPrefixed { .. } => {
            // 平坦两形态同构: 固定前缀 (flat_fixed_prefix 单源) + 随机 body
            // (body 长度按 length_range - 前缀长).
            let fixed_prefix = gen_spec.flat_fixed_prefix();
            let (body_min, body_max) = gen_spec.body_length_range();
            let body_len = if body_min == body_max {
                body_min
            } else {
                let h = crate::util::hash64(&format!("{seed}{counter}{retry}len"));
                body_min + (h % (body_max - body_min + 1) as u64) as usize
            };
            let mut buf = String::with_capacity(fixed_prefix.chars().count() + body_len);
            buf.push_str(fixed_prefix);
            buf.push_str(&random_chars(0, body_len));
            buf
        }
        SecretShape::Jwt { seg_lens } => seg_lens
            .iter()
            .scan(0usize, |offset, &len| {
                let seg = random_chars(*offset, len);
                *offset += len;
                Some(seg)
            })
            .collect::<Vec<_>>()
            .join("."),
        SecretShape::Pem {
            header_line,
            footer_line,
            body_line_lens,
        } => {
            let mut buf = String::with_capacity(gen_spec.length_range.0);
            buf.push_str(header_line);
            buf.push('\n');
            let mut offset = 0usize;
            for (i, &line_len) in body_line_lens.iter().enumerate() {
                if i > 0 {
                    buf.push('\n');
                }
                buf.push_str(&random_chars(offset, line_len));
                offset += line_len;
            }
            buf.push('\n');
            buf.push_str(footer_line);
            buf
        }
        SecretShape::Email { domain } => {
            // local = name-like 生成, 输出 local + '@' + domain (domain 公开段
            // 白名单复用; local_len = 总长 (单点) - '@' - domain 长).
            let domain_len = domain.chars().count();
            let local_len = gen_spec.length_range.0.saturating_sub(1 + domain_len);
            let local = gen_name_like(local_len, EMAIL_LOCAL_SEPS, seed, counter, retry, pool);
            format!("{local}@{domain}")
        }
        SecretShape::Phone { skeleton } => {
            // '#' → 随机 digit (流 offset 只在 '#' 位递增), 其余字符 literal
            // 复用 real 的分隔符骨架.
            let mut buf = String::with_capacity(skeleton.chars().count());
            let mut offset = 0usize;
            for c in skeleton.chars() {
                if c == '#' {
                    buf.push_str(&random_chars(offset, 1));
                    offset += 1;
                } else {
                    buf.push(c);
                }
            }
            buf
        }
        SecretShape::Username => {
            // 区间非单点 (手动配置) 时 hash 选 target 长度 (同 Plain 的 body
            // 长度选择逻辑); infer 出恒单点.
            let (min, max) = gen_spec.body_length_range();
            let target = if min == max {
                min
            } else {
                let h = crate::util::hash64(&format!("{seed}{counter}{retry}len"));
                min + (h % (max - min + 1) as u64) as usize
            };
            gen_name_like(target, USERNAME_SEPS, seed, counter, retry, pool)
        }
    }
}

// ─── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
        let spec = GenSpec::infer_default_for("\"\"\"\"", SecretCategory::default(), "");
        assert!(spec.candidate_space() >= MIN_CANDIDATE_SPACE_WARN);
        assert!(spec.charset.lowercase && spec.charset.digits && !spec.charset.uppercase);
        // widen 只并入标准类, real 的字符仍在池中 (仿真度: charset ⊇ real 字符).
        assert!(spec.charset.enabled_chars().contains(&'"'));
    }

    /// 空间充足的典型 secret 不触发 widen (行为/缓存兼容: 已生成的 mock 不变).
    #[test]
    fn infer_default_no_widen_when_space_sufficient() {
        // 32 位混合 charset API key: 62^29 >> 2^20. ApiKey + sk- 公开前缀 →
        // PublicPrefixed shape (category-aware), charset 推断源是 body (去 sk-).
        let real = "sk-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
        let spec = GenSpec::infer_default_for(real, SecretCategory::default(), "");
        assert_eq!(
            spec.shape,
            SecretShape::PublicPrefixed {
                public_prefix: "sk-".into()
            }
        );
        assert_eq!(
            spec.charset,
            Charset::infer_from("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6")
        );
        // 等长不变量: mock 总长 (含公开前缀) == real 总长.
        assert_eq!(
            spec.length_range,
            (real.chars().count(), real.chars().count())
        );
        // 同一 real 归为 Other (归类错误场景): 退化为 Plain, charset 推断源回到 real.
        let plain = GenSpec::infer_default_for(real, SecretCategory::Other, "");
        assert_eq!(plain.shape, SecretShape::Plain);
        assert_eq!(plain.charset, Charset::infer_from(real));
    }

    /// 短 real 的固有边界 (n ≤ 3): 全开标准类也达不到阈值 — widen 兜到
    /// "最大可达"即停 (等长约束下空间上限 = charset_size^n, 物理边界).
    #[test]
    fn infer_default_widen_stops_at_physical_limit() {
        let spec = GenSpec::infer_default_for("a", SecretCategory::default(), "");
        // 1 字符 body 全开 (62 标准字符) 候选 62 < 2^20: widen 并完全部标准类后停止.
        assert!(spec.charset.lowercase && spec.charset.digits && spec.charset.uppercase);
    }

    /// unicode 退化 real: 4 个相同 CJK 字符 (other=['密'], 多字节按 char 计数 = 1)
    /// 同样走 widen — charset 处理与 ASCII 无关 (enabled_chars 按 char, 非 byte).
    #[test]
    fn infer_default_widens_unicode_degenerate_charset() {
        let spec = GenSpec::infer_default_for("密密密密", SecretCategory::default(), "");
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
        let gen_spec = GenSpec::infer_default_for("sk-Abc123", SecretCategory::default(), "");
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
        let gen_spec = GenSpec::infer_default_for("sk-Abc123", SecretCategory::default(), "sgm_");
        assert_eq!(gen_spec.prefix, "sgm_");
        assert_eq!(gen_spec.length_range, (13, 13));
    }

    #[test]
    fn genspec_infer_default_empty_real() {
        let gen_spec = GenSpec::infer_default_for("", SecretCategory::default(), "");
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
            shape: SecretShape::Plain,
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
            shape: SecretShape::Plain,
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
            shape: SecretShape::Plain,
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
            shape: SecretShape::Plain,
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
            shape: SecretShape::Plain,
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
            shape: SecretShape::Plain,
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
            shape: SecretShape::Plain,
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
            shape: SecretShape::Plain,
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
            shape: SecretShape::Plain,
        };
        assert_eq!(gen_spec.candidate_space(), u64::MAX);
        // 极宽区间同样封顶 (早退, 不长循环).
        let wide = GenSpec {
            prefix: "".into(),
            charset: charset_of("ab"),
            length_range: (1, usize::MAX),
            shape: SecretShape::Plain,
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
            shape: SecretShape::Plain,
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
            shape: SecretShape::Plain,
        };
        assert_eq!(empty_cs.candidate_space(), 0);
        // 未配置 (0,0) → 单一空 body 候选 = 1.
        let unconfigured = GenSpec {
            prefix: "".into(),
            charset: charset_of("ab"),
            length_range: (0, 0),
            shape: SecretShape::Plain,
        };
        assert_eq!(unconfigured.candidate_space(), 1);
        // 畸形 min > max → 空集求和 = 0.
        let malformed = GenSpec {
            prefix: "".into(),
            charset: charset_of("ab"),
            length_range: (5, 3),
            shape: SecretShape::Plain,
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
                shape: SecretShape::Plain,
            }),
            gen_inferred: false,
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
                shape: SecretShape::Plain,
            }),
            gen_inferred: false,
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
        s.resolve_against("aaaa", SecretCategory::default(), "");
        assert!(s.lint_candidate_space().is_none());
        // 全 "other" 字符的退化 real: infer 单字符 '!' (空间 1) → widen 并入
        // lowercase+digits ((1+26+10)^4 = 37^4 ≈ 187 万 ≥ 2^20) → 停, uppercase 未开.
        let mut s = MockStrategy::default();
        s.resolve_against("!!!!", SecretCategory::default(), "");
        assert!(s.lint_candidate_space().is_none());
        // **n=3 物理边界**: "abc" 全小写无 other, 全开后 62³ = 238,328 仍 < 2^20 —
        // (65³ ≈ 27.5 万是 n=3 含 other 的理论上界, 见 infer_default_for doc) —
        // Auto 极短 real 在全开兜底后仍 lint (边界语义钉住, 防 widen/阈值漂移).
        let mut s = MockStrategy::default();
        s.resolve_against("abc", SecretCategory::default(), "");
        let lint = s
            .lint_candidate_space()
            .expect("n=3 real 全开仍低于阈值, 应 lint");
        assert!(lint.space < MIN_CANDIDATE_SPACE_WARN);
    }

    #[test]
    fn lint_auto_normal_real_is_none() {
        // Auto + 正常 real (多种字符, 足够长) → infer 空间远超 2^20.
        let mut s = MockStrategy::default();
        s.resolve_against("sk-1234567890abcdef", SecretCategory::default(), "");
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
            gen_inferred: false,
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
                shape: SecretShape::Plain,
            }),
            gen_inferred: false,
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
                shape: SecretShape::Plain,
            }),
            gen_inferred: false,
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
        s.resolve_against("sk-Abc123", SecretCategory::default(), "");
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
            shape: SecretShape::Plain,
        };
        let mut s = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: Some(user_gen.clone()),
            gen_inferred: false,
        };
        s.resolve_against("sk-Abc123", SecretCategory::default(), "");
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
            gen_inferred: false,
        };
        s.resolve_against("sk-Abc123", SecretCategory::default(), "");
        // Fixed 模式 gen 保持 None.
        assert!(s.gen_spec.is_none());
    }

    #[test]
    fn mock_strategy_validate_fixed_empty_rejected() {
        let s = MockStrategy {
            initial: InitialValue::Fixed { value: "".into() },
            gen_spec: None,
            gen_inferred: false,
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
                shape: SecretShape::Plain,
            }),
            gen_inferred: false,
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
            gen_inferred: false,
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
            gen_inferred: false,
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
            gen_inferred: false,
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
            gen_inferred: false,
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
            gen_inferred: false,
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
            gen_inferred: false,
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
            gen_inferred: false,
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
            gen_inferred: false,
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
            gen_inferred: false,
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
                shape: SecretShape::Plain,
            }),
            gen_inferred: false,
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
                shape: SecretShape::Plain,
            }),
            gen_inferred: false,
        };
        assert!(s.validate_against_real("sk-test-secret-value").is_ok());
    }

    // ─── category-aware shape (结构仿真) ─────────────────────────────────

    /// 测试用 PEM 样本 (OpenSSH format 形状: BEGIN/END 边界 + 2 行 b64 body).
    const TEST_PEM: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEAtc0vLB3n6e5h8xNB7FJ7dX08ZD7kWrvFarcOeSNBjSM=\n-----END OPENSSH PRIVATE KEY-----";
    /// 测试用 JWT 样本 (三段 b64url, 段长 36/27/43).
    const TEST_JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    /// resolve 辅助: Auto + 无用户 gen → infer (生产路径同型).
    fn resolved(real: &str, category: SecretCategory) -> MockStrategy {
        let mut s = MockStrategy::default();
        s.resolve_against(real, category, "");
        s
    }

    /// validate 组测试共用的 GenSpec 构造: 空前缀 + lowercase/digits charset +
    /// 指定 shape/length_range.
    fn shape_spec(shape: SecretShape, len: (usize, usize)) -> GenSpec {
        GenSpec {
            prefix: String::new(),
            charset: Charset {
                lowercase: true,
                digits: true,
                ..Default::default()
            },
            length_range: len,
            shape,
        }
    }

    #[test]
    fn gen_inferred_wire_is_serialize_only() {
        // #319: GET DTO 需要区分 "gen 是 infer 结果" (WebUI 未触碰回传省略 →
        // 后端 fresh infer) 与 "用户显式" (原样回传防丢) — 序列化必须带标记.
        let s = resolved(TEST_PEM, SecretCategory::PrivateKey);
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["gen_inferred"], serde_json::json!(true));
        // 只写不读: 反序列化忽略该字段 (恒 false) — 经 wire (toml / WebUI 请求)
        // 供给的 gen_spec 恒为用户显式, "infer 态" 不可被客户端伪造 (免 sanitize 点).
        let rt: MockStrategy = serde_json::from_value(json).unwrap();
        assert!(!rt.gen_inferred);
        assert_eq!(
            rt.gen_spec, s.gen_spec,
            "gen_spec 本身 wire round-trip 不变"
        );
        // false 时省略 — 显式配置 / 声明态的 DTO 不多带字段 (state.toml 持久化
        // 投影 strip 后同形态, 落盘零扰动).
        let explicit = MockStrategy::default();
        assert!(
            serde_json::to_value(&explicit)
                .unwrap()
                .get("gen_inferred")
                .is_none()
        );
    }

    #[test]
    fn shape_infer_pem_not_gated_by_category() {
        // 归类错误免疫: PEM 形状自证, 任意 category (含 Other/ApiKey) 都推断 Pem.
        for cat in SecretCategory::ALL.iter().map(|(c, _)| *c) {
            let s = resolved(TEST_PEM, cat);
            assert!(
                matches!(&s.gen_spec.as_ref().unwrap().shape, SecretShape::Pem { .. }),
                "category {cat:?} should still infer Pem"
            );
        }
    }

    #[test]
    fn shape_infer_jwt_gated_by_token_category() {
        assert!(matches!(
            resolved(TEST_JWT, SecretCategory::Token)
                .gen_spec
                .unwrap()
                .shape,
            SecretShape::Jwt { .. }
        ));
        // 非 Token 归类 (映射错误场景) → Plain (归类错误无害).
        for cat in [
            SecretCategory::ApiKey,
            SecretCategory::Other,
            SecretCategory::PrivateKey,
        ] {
            assert_eq!(
                resolved(TEST_JWT, cat).gen_spec.unwrap().shape,
                SecretShape::Plain
            );
        }
    }

    #[test]
    fn shape_infer_public_prefix_gated_by_apikey_and_body_length() {
        let real = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
        assert!(matches!(
            resolved(real, SecretCategory::ApiKey).gen_spec.unwrap().shape,
            SecretShape::PublicPrefixed { public_prefix } if public_prefix == "ghp_"
        ));
        // 非 ApiKey → Plain.
        assert_eq!(
            resolved(real, SecretCategory::Token)
                .gen_spec
                .unwrap()
                .shape,
            SecretShape::Plain
        );
        // body < 8 chars → Plain (前缀保留意义弱).
        assert_eq!(
            resolved("ghp_Ab12", SecretCategory::ApiKey)
                .gen_spec
                .unwrap()
                .shape,
            SecretShape::Plain
        );
    }

    #[test]
    fn shape_infer_global_prefix_forces_plain() {
        // 用户显式辨识前缀 = 放弃结构仿真 (模块头部 "global_prefix 裁决").
        let mut s = MockStrategy::default();
        s.resolve_against(TEST_PEM, SecretCategory::PrivateKey, "sgm_");
        assert_eq!(s.gen_spec.unwrap().shape, SecretShape::Plain);
    }

    // ─── category-aware shape: email / phone / username (issue #410) ──────

    #[test]
    fn shape_infer_email_not_gated_by_category() {
        // 形状自证 (同 PEM 先例): 任意 category (含存量 Other 归类) 都推断 Email.
        let real = "zhang.wei@gmail.com";
        for cat in SecretCategory::ALL.iter().map(|(c, _)| *c) {
            let s = resolved(real, cat);
            assert!(
                matches!(
                    &s.gen_spec.as_ref().unwrap().shape,
                    SecretShape::Email { domain } if domain == "gmail.com"
                ),
                "category {cat:?} should still infer Email (whitelisted domain reused)"
            );
        }
        // 非白名单域: 确定性挑一个放得下的白名单成员 (白名单不含私有域,
        // 挑中的必然 ≠ real 的域).
        let s = resolved("jennifer.liu@corp.example.internal", SecretCategory::Email);
        match &s.gen_spec.unwrap().shape {
            SecretShape::Email { domain } => {
                assert!(
                    EMAIL_DOMAINS.contains(&domain.as_str()),
                    "picked domain {domain:?} must be a whitelisted member"
                );
            }
            other => panic!("expected Email shape, got {other:?}"),
        }
    }

    #[test]
    fn shape_infer_space_fallbacks_to_plain() {
        // ① email real 但 local 极短 (name 空间不足) → Plain.
        assert_eq!(
            resolved("ab@163.com", SecretCategory::Email)
                .gen_spec
                .unwrap()
                .shape,
            SecretShape::Plain
        );
        // ② category=Phone 但 digit 数 < 7 (空间物理边界) → Plain.
        assert_eq!(
            resolved("123456", SecretCategory::Phone)
                .gen_spec
                .unwrap()
                .shape,
            SecretShape::Plain
        );
        // ③ category=Username 但 real 长 4 (name 空间不足) → Plain.
        assert_eq!(
            resolved("abcd", SecretCategory::Username)
                .gen_spec
                .unwrap()
                .shape,
            SecretShape::Plain
        );
    }

    #[test]
    fn email_mock_is_structured_and_equal_length() {
        // 白名单域 (复用) + 非白名单域 (确定性挑白名单成员); email 检测不 gate
        // category — 存量 Other 归类同样受益 (第二个样本).
        for (real, cat) in [
            ("zhang.wei@gmail.com", SecretCategory::Email),
            ("jennifer.liu@corp.example.internal", SecretCategory::Other),
        ] {
            let s = resolved(real, cat);
            let mock = gen_candidate(real, &s, 7, 0);
            // 等长不变量.
            assert_eq!(mock.chars().count(), real.chars().count(), "real={real}");
            // 恰一个 '@', domain ∈ EMAIL_DOMAINS, local 非空.
            let parts: Vec<&str> = mock.split('@').collect();
            assert_eq!(parts.len(), 2, "exactly one '@': {mock}");
            assert!(!parts[0].is_empty(), "non-empty local: {mock}");
            assert!(
                EMAIL_DOMAINS.contains(&parts[1]),
                "domain {:?} must be whitelisted (mock={mock})",
                parts[1]
            );
            // shape-aware C5: domain 公开段豁免后 local 随机段无 real ≥k 子串.
            let shape = s.gen_spec.clone().unwrap().shape;
            assert!(!c5_violated(&mock, real, &shape, c5_threshold_len(real)));
            assert_ne!(mock, real);
        }
    }

    #[test]
    fn email_mock_c5_exemption_covers_domain_only() {
        // real local=3 → infer 的空间 gate 会退化 Plain; 此处手动配置 Email shape
        // 专测 C5 豁免机制本身 (空间 gate 与 C5 豁免正交 — 同
        // pem_mock_c5_exemption_covers_boundary_lines_only 的构造法).
        let real = "foo@gmail.com";
        let s = MockStrategy {
            gen_spec: Some(GenSpec {
                prefix: String::new(),
                charset: Charset {
                    lowercase: true,
                    digits: true,
                    other: vec!['.'],
                    ..Default::default()
                },
                // real 总长 13 (local 3 + '@' + "gmail.com" 9).
                length_range: (13, 13),
                shape: SecretShape::Email {
                    domain: "gmail.com".into(),
                },
            }),
            ..Default::default()
        };
        let shape = s.gen_spec.as_ref().unwrap().shape.clone();
        let mock = gen_candidate(real, &s, 7, 0);
        // domain 段复用 "gmail.com" 不触发 C5; local 非空且等长.
        assert!(mock.ends_with("@gmail.com"), "mock={mock}");
        assert_eq!(mock.chars().count(), real.chars().count());
        let k = c5_threshold_len(real);
        assert!(!c5_violated(&mock, real, &shape, k));
        // local 段不含 real 的 ≥k 子串 (豁免只覆盖 domain, local 照常检查).
        let local = mock.strip_suffix("@gmail.com").unwrap();
        assert!(!contains_kchar_substring(local, real, k));
        // 反例: local 夹带 real 的 ≥k 子串 ("gmail" 是 real 的 5-char 子串,
        // k = max(4, ⌈13/3⌉) = 5) → 判定违反 (豁免不能掩护 local).
        let evil = "xgmail@gmail.com";
        assert!(c5_violated(evil, real, &shape, k));
    }

    #[test]
    fn phone_mock_preserves_skeleton_and_equal_length() {
        let real = "+86 138-0013-8000";
        let s = resolved(real, SecretCategory::Phone);
        let shape = s.gen_spec.clone().unwrap().shape;
        // 骨架 = real 的逐字符映射 (digit → '#', 分隔符 literal).
        assert!(matches!(&shape, SecretShape::Phone { skeleton }
            if skeleton == "+## ###-####-####"));
        let mock = gen_candidate(real, &s, 7, 0);
        // 等长 + literal 位置与 real 完全一致, digit 位保持 digit.
        assert_eq!(mock.chars().count(), real.chars().count());
        for (i, (m, r)) in mock.chars().zip(real.chars()).enumerate() {
            if r.is_ascii_digit() {
                assert!(m.is_ascii_digit(), "digit pos {i} must stay digit: {mock}");
            } else {
                assert_eq!(m, r, "literal pos {i} must be preserved: {mock}");
            }
        }
        assert_ne!(mock, real);
        // infer 路径 charset 恒 digits-only (RED-1: 随机位 ⊆ charset).
        let spec = s.gen_spec.as_ref().unwrap();
        let pool = spec.charset.enabled_chars();
        assert!(pool.iter().all(|c| c.is_ascii_digit()), "pool={pool:?}");
        assert!(!c5_violated(&mock, real, &shape, c5_threshold_len(real)));
    }

    #[test]
    fn username_mock_is_name_like_and_equal_length() {
        // ≥ 7: name-like 候选空间达标 (2-char 名 × 10^5 项 ≥ 2^20).
        for real in ["chenjing8", "wei12345", "li66666"] {
            let s = resolved(real, SecretCategory::Username);
            let shape = s.gen_spec.clone().unwrap().shape;
            assert!(matches!(shape, SecretShape::Username), "real={real}");
            let mock = gen_candidate(real, &s, 7, 0);
            assert_eq!(mock.chars().count(), real.chars().count());
            // name-like: 以名字池成员开头 (first-only 与 two-part 都以 first 起头;
            // target ≥ 7 时名字池恒可用, 不走全随机兜底分支).
            assert!(
                FIRST_NAMES.iter().any(|f| mock.starts_with(f)),
                "mock {mock:?} is not name-like (no FIRST_NAMES prefix)"
            );
            // 全串字符域 = 名字池 (小写) ∪ seps ∪ digit pad (RED-1 的 infer 强制面).
            assert!(mock.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-')
            }));
            assert!(!c5_violated(&mock, real, &shape, c5_threshold_len(real)));
        }
    }

    #[test]
    fn pem_mock_is_structured_and_equal_length() {
        let s = resolved(TEST_PEM, SecretCategory::PrivateKey);
        let mock = gen_candidate(TEST_PEM, &s, 7, 0);
        // 等长不变量.
        assert_eq!(mock.chars().count(), TEST_PEM.chars().count());
        let mock_lines: Vec<&str> = mock.split('\n').collect();
        let real_lines: Vec<&str> = TEST_PEM.split('\n').collect();
        assert_eq!(mock_lines.len(), real_lines.len());
        // 公开边界行原样复用 (仿真: LLM 看到的是合法形状的 key).
        assert_eq!(mock_lines[0], real_lines[0]);
        assert_eq!(*mock_lines.last().unwrap(), *real_lines.last().unwrap());
        // body 行: b64 字符 + 行长与 real 对应行一致.
        for (m, r) in mock_lines[1..mock_lines.len() - 1]
            .iter()
            .zip(&real_lines[1..real_lines.len() - 1])
        {
            assert_eq!(m.chars().count(), r.chars().count());
            assert!(
                m.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
            );
        }
        // mock != real (随机 body 事实上不同).
        assert_ne!(mock, TEST_PEM);
        // shape-aware C5: 公开段豁免后随机部分无 real ≥k 子串.
        let shape = s.gen_spec.unwrap().shape;
        assert!(!c5_violated(
            &mock,
            TEST_PEM,
            &shape,
            c5_threshold_len(TEST_PEM)
        ));
    }

    #[test]
    fn pem_mock_c5_exemption_covers_boundary_lines_only() {
        // 豁免只覆盖公开边界行: 把 real 的长 b64 body 行放进候选 → 仍判定违反.
        let s = resolved(TEST_PEM, SecretCategory::PrivateKey);
        let shape = s.gen_spec.clone().unwrap().shape;
        let k = c5_threshold_len(TEST_PEM);
        let real_lines: Vec<&str> = TEST_PEM.split('\n').collect();
        let body_line = real_lines[1]; // 64 chars b64, 是 real 的 ≥k 子串
        let evil = format!("-----BEGIN X-----\n{body_line}\n-----END X-----");
        assert!(c5_violated(&evil, TEST_PEM, &shape, k));
    }

    #[test]
    fn jwt_mock_is_three_segment_and_equal_length() {
        let s = resolved(TEST_JWT, SecretCategory::Token);
        let mock = gen_candidate(TEST_JWT, &s, 7, 0);
        assert_eq!(mock.chars().count(), TEST_JWT.chars().count());
        let m_segs: Vec<&str> = mock.split('.').collect();
        let r_segs: Vec<&str> = TEST_JWT.split('.').collect();
        assert_eq!(m_segs.len(), 3);
        for (m, r) in m_segs.iter().zip(&r_segs) {
            assert_eq!(m.chars().count(), r.chars().count());
            assert!(
                m.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
            );
        }
        assert_ne!(mock, TEST_JWT);
    }

    #[test]
    fn public_prefixed_mock_keeps_prefix_and_equal_length() {
        let real = "AKIAIOSFODNN7EXAMPLE";
        let s = resolved(real, SecretCategory::ApiKey);
        let mock = gen_candidate(real, &s, 7, 0);
        assert_eq!(mock.chars().count(), real.chars().count());
        assert!(mock.starts_with("AKIA"));
        assert_ne!(mock, real);
        // shape-aware C5: 豁免 AKIA 段后随机 body 无 real ≥k 子串.
        let shape = s.gen_spec.unwrap().shape;
        assert!(!c5_violated(&mock, real, &shape, c5_threshold_len(real)));
    }

    #[test]
    fn find_public_prefix_longest_match_wins() {
        // sk-ant- (Anthropic) 优先于 sk- (OpenAI 系), 防前缀截断.
        let real = "sk-ant-api03-ABCDEFGHIJKLMNOP";
        let s = resolved(real, SecretCategory::ApiKey);
        assert!(matches!(
            s.gen_spec.unwrap().shape,
            SecretShape::PublicPrefixed { public_prefix } if public_prefix == "sk-ant-"
        ));
    }

    #[test]
    fn validate_rejects_prefix_with_structural_shape() {
        // 结构形状下 prefix 字段必须为空 (双通道歧义拒绝).
        let spec = GenSpec {
            prefix: "sgm_".into(),
            ..shape_spec(
                SecretShape::Jwt {
                    seg_lens: vec![10, 9, 9],
                },
                (30, 30),
            )
        };
        let err = spec.validate().unwrap_err();
        assert!(err.contains("gen.prefix must be empty"), "{err}");
    }

    #[test]
    fn validate_jwt_length_range_must_match_segments() {
        // 结构总长 10+9+9+2 = 30.
        let mk = |len: (usize, usize)| {
            shape_spec(
                SecretShape::Jwt {
                    seg_lens: vec![10, 9, 9],
                },
                len,
            )
        };
        assert!(mk((30, 30)).validate().is_ok());
        let err = mk((29, 30)).validate().unwrap_err();
        assert!(err.contains("single point (30, 30)"), "{err}");
    }

    #[test]
    fn validate_pem_structure_must_match_length_range() {
        let header = "-----BEGIN X-----";
        let footer = "-----END X-----";
        let total = header.chars().count() + 1 + 8 + 1 + footer.chars().count();
        let mk = |len: (usize, usize)| {
            shape_spec(
                SecretShape::Pem {
                    header_line: header.into(),
                    footer_line: footer.into(),
                    body_line_lens: vec![8],
                },
                len,
            )
        };
        assert!(mk((total, total)).validate().is_ok());
        assert!(mk((total + 1, total + 1)).validate().is_err());
    }

    #[test]
    fn validate_email_domain_must_be_whitelisted_and_single_point() {
        // 合法: 白名单域 + 单点长度 (local = 14 - 1 - 10 = 3 ≥ 1).
        let mk = |domain: &str, len: (usize, usize)| {
            shape_spec(
                SecretShape::Email {
                    domain: domain.into(),
                },
                len,
            )
        };
        assert!(mk("gmail.com", (14, 14)).validate().is_ok());
        // 私有域 (携带部署特例内容) → 拒绝 (C5 豁免前提的结构保证).
        let err = mk("corp.example.internal", (34, 34))
            .validate()
            .unwrap_err();
        assert!(err.contains("whitelist"), "{err}");
        // 非单点区间 → 拒绝.
        let err = mk("gmail.com", (14, 15)).validate().unwrap_err();
        assert!(err.contains("single-point"), "{err}");
        // local 为空 (min < domain_len + 2) → 拒绝.
        let err = mk("protonmail.com", (14, 14)).validate().unwrap_err();
        assert!(err.contains("non-empty local"), "{err}");
    }

    #[test]
    fn validate_phone_skeleton_and_digits_only_charset() {
        // 合法: 骨架 + digits-only charset + 单点长度 (charset 需显式 digits-only,
        // shape_spec 默认 lowercase+digits 不满足 — 单独构造).
        let mk = |skeleton: &str, charset: Charset| GenSpec {
            prefix: String::new(),
            charset,
            length_range: (skeleton.chars().count(), skeleton.chars().count()),
            shape: SecretShape::Phone {
                skeleton: skeleton.into(),
            },
        };
        let digits_only = Charset {
            digits: true,
            ..Default::default()
        };
        assert!(
            mk("+## ###-####-####", digits_only.clone())
                .validate()
                .is_ok()
        );
        // 骨架含非法字符 (字母) → 拒绝.
        let err = mk("+## ab#-####-####", digits_only.clone())
            .validate()
            .unwrap_err();
        assert!(err.contains("subset of"), "{err}");
        // 骨架无 '#' (纯 literal, 无随机位) → 拒绝.
        let err = mk("+--", digits_only.clone()).validate().unwrap_err();
        assert!(err.contains("at least one '#'"), "{err}");
        // 骨架空 → 拒绝 (通用 length_range>0 检查先行拦截 — 单点 (0,0) 不合法;
        // skeleton 非空检查是纵深防御).
        let err = mk("", digits_only.clone()).validate().unwrap_err();
        assert!(err.contains("length_range must be > 0"), "{err}");
        // charset 非纯 digits (含字母) → 拒绝 (破坏 digit 骨架仿真).
        let with_lower = Charset {
            digits: true,
            lowercase: true,
            ..Default::default()
        };
        let err = mk("+## ###-####-####", with_lower).validate().unwrap_err();
        assert!(err.contains("digits-only"), "{err}");
        // 长度与骨架不一致 → 拒绝.
        let bad_len = GenSpec {
            prefix: String::new(),
            charset: digits_only,
            length_range: (18, 18),
            shape: SecretShape::Phone {
                skeleton: "+## ###-####-####".into(), // 17 chars ≠ 18.
            },
        };
        let err = bad_len.validate().unwrap_err();
        assert!(err.contains("single point (17, 17)"), "{err}");
    }

    #[test]
    fn validate_username_accepts_range_lengths() {
        // Username 无结构字段: 区间允许非单点 (生成器按区间 hash 选 target).
        assert!(
            shape_spec(SecretShape::Username, (8, 16))
                .validate()
                .is_ok()
        );
        assert!(
            shape_spec(SecretShape::Username, (10, 10))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn username_mock_manual_range_length_within_bounds() {
        // 手动配置 (区间非单点): 生成 target ∈ 区间 (同 Plain 的 body 长度选择
        // 逻辑), 等长不变量在区间语义下保持 (mock 长 ∈ [min, max]).
        let s = MockStrategy {
            gen_spec: Some(GenSpec {
                prefix: String::new(),
                charset: Charset {
                    lowercase: true,
                    digits: true,
                    other: vec!['_', '.', '-'],
                    ..Default::default()
                },
                length_range: (7, 12),
                shape: SecretShape::Username,
            }),
            ..Default::default()
        };
        for seed in 0..50u64 {
            let mock = gen_candidate("some-user", &s, seed, 0);
            let len = mock.chars().count();
            assert!(
                (7..=12).contains(&len),
                "mock len {len} not in [7,12]: {mock}"
            );
        }
    }

    /// ALL 完整性 (新变体登记): 9 项 + 新变体的 as_str / serde 名一致. 运行时
    /// as_str↔ALL↔serde 三方一致的全量守卫在 secrets.rs
    /// `secret_category_roundtrip_str` (迭代 ALL, 自动覆盖新变体), 此处钉住
    /// 新变体的存在性与字符串名 (ALL 漏项无编译期守卫).
    #[test]
    fn secret_category_all_covers_email_phone_username() {
        assert_eq!(SecretCategory::ALL.len(), 9);
        let names: Vec<&str> = SecretCategory::ALL.iter().map(|(_, s)| *s).collect();
        for name in ["email", "phone", "username"] {
            assert!(names.contains(&name), "ALL missing {name}");
        }
        // serde lowercase 名 (用户手写 toml / WebUI 词表的 wire 面).
        assert_eq!(
            serde_json::to_string(&SecretCategory::Email).unwrap(),
            "\"email\""
        );
        assert_eq!(
            serde_json::to_string(&SecretCategory::Phone).unwrap(),
            "\"phone\""
        );
        assert_eq!(
            serde_json::to_string(&SecretCategory::Username).unwrap(),
            "\"username\""
        );
    }

    // ─── 豁免前提的结构保证 (C5 信任面) ──────────────────────────────────

    #[test]
    fn validate_rejects_public_prefix_outside_whitelist() {
        // 手动配置的 public_prefix 必须是公开格式白名单成员: 任意自定义串 (如
        // 真值子串) 携带真实内容, 整段豁免 C5 会绕过 RED-5 — validate 拦截.
        let spec = shape_spec(
            SecretShape::PublicPrefixed {
                public_prefix: "ZebraSecret12345".into(), // 真值的 16 字符逐字子串
            },
            (40, 40),
        );
        let err = spec.validate().unwrap_err();
        assert!(err.contains("whitelist"), "{err}");
        // 白名单成员 (同长度) 通过.
        let ok = shape_spec(
            SecretShape::PublicPrefixed {
                public_prefix: "github_pat_".into(),
            },
            (40, 40),
        );
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn parse_pem_rejects_non_standard_label() {
        // 非标准 label (用户可控内容, 如 `-----BEGIN hunter2-password-----`) 不
        // 识别为 PEM — 豁免前提是"信息量为零的公开格式串", 任意 label 不满足.
        let evil = "-----BEGIN hunter2-password-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END hunter2-password-----";
        for cat in SecretCategory::ALL.iter().map(|(c, _)| *c) {
            // 断言 "不识别为 PEM" (非 == Plain: category-aware 推断下非 PEM 串可
            // 得其他形状, 如长串 + Username 标注 → Username — 与本测试意图正交).
            assert!(
                !matches!(
                    resolved(evil, cat).gen_spec.unwrap().shape,
                    SecretShape::Pem { .. }
                ),
                "non-standard label must not infer Pem (category {cat:?})"
            );
        }
        // 标准 label 形态 ([A-Z0-9 ]+, RFC 7468) 正常识别.
        let std = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----";
        assert!(matches!(
            resolved(std, SecretCategory::PrivateKey)
                .gen_spec
                .unwrap()
                .shape,
            SecretShape::Pem { .. }
        ));
    }

    #[test]
    fn parse_pem_rejects_mismatched_and_oversized_labels() {
        // BEGIN/END label 不一致 → 退化 Plain (RFC 7468 要求成对; 拒绝即无豁免,
        // fail-safe).
        let mismatched = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END RSA PRIVATE KEY-----";
        assert_eq!(
            resolved(mismatched, SecretCategory::PrivateKey)
                .gen_spec
                .unwrap()
                .shape,
            SecretShape::Plain
        );
        // label > 64 chars (标准形态上限) → 退化 Plain — 挡 "label 内嵌大写载荷"
        // 的伪 PEM 自伤面.
        let long_label = "A".repeat(65);
        let oversized = format!(
            "-----BEGIN {long_label}-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END {long_label}-----"
        );
        assert_eq!(
            resolved(&oversized, SecretCategory::PrivateKey)
                .gen_spec
                .unwrap()
                .shape,
            SecretShape::Plain
        );
        // validate 手动路径同款收紧: label 一致但超长 → Err.
        let spec = shape_spec(
            SecretShape::Pem {
                header_line: format!("-----BEGIN {long_label}-----"),
                footer_line: format!("-----END {long_label}-----"),
                body_line_lens: vec![8],
            },
            (200, 200),
        );
        let err = spec.validate().unwrap_err();
        assert!(err.contains("standard PEM label form"), "{err}");
    }

    #[test]
    fn validate_rejects_non_standard_pem_boundary() {
        // 手动配置的 header/footer 同样必须匹配标准 PEM 标签形态.
        let spec = shape_spec(
            SecretShape::Pem {
                header_line: "-----BEGIN hunter2-password-----".into(),
                footer_line: "-----END hunter2-password-----".into(),
                body_line_lens: vec![10],
            },
            (60, 60),
        );
        let err = spec.validate().unwrap_err();
        assert!(err.contains("standard PEM label form"), "{err}");
    }

    // ─── gen_inferred 运行时标记 (持久化剥离 + seed 不变性) ──────────────

    #[test]
    fn gen_inferred_excluded_from_equality_and_seed() {
        // 同一策略 infer 前后 (gen_spec None → Some + gen_inferred=true) 的
        // 声明态不同, 但 "同一声明态 ± gen_inferred" 的 eq/hash 必须一致 —
        // gen_inferred 参与 Hash 会让 resolve 前后的 seed 漂移 (C3 违例).
        let mut a = MockStrategy::default();
        a.resolve_against("sk-1234567890abcdef", SecretCategory::ApiKey, "");
        assert!(a.gen_inferred);
        let mut b = a.clone();
        b.gen_inferred = false;
        assert_eq!(a, b, "gen_inferred must not affect equality");
        assert_eq!(
            crate::util::hash64(&a),
            crate::util::hash64(&b),
            "gen_inferred must not affect hash/seed"
        );
        // serde round-trip 后标记恒 false (只写不读: 序列化携带, 反序列化忽略, #319).
        let json = serde_json::to_string(&a).unwrap();
        let back: MockStrategy = serde_json::from_str(&json).unwrap();
        assert!(!back.gen_inferred);
        assert_eq!(back.gen_spec, a.gen_spec, "gen_spec itself round-trips");
    }

    // ─── category↔形状矛盾检测 (category_shape_mismatch) ────────────────

    #[test]
    fn mismatch_detects_all_four_contradictions() {
        let s = MockStrategy::default();
        // PEM + 非 privatekey 标注 → 行为已按 PEM (不受标注影响), 提醒改标注.
        assert_eq!(
            s.category_shape_mismatch(TEST_PEM, SecretCategory::ApiKey, ""),
            Some(CategoryShapeMismatch::PemButNotPrivatekey)
        );
        // email 形状 + 非 email 标注 → 行为已按 Email 结构化 (形状自证), 纯语义债.
        assert_eq!(
            s.category_shape_mismatch("zhang.wei@gmail.com", SecretCategory::Other, ""),
            Some(CategoryShapeMismatch::EmailButNotEmailCategory)
        );
        // JWT + 非 token 标注 → 静默丢失增强, 提醒改标注可启用.
        assert_eq!(
            s.category_shape_mismatch(TEST_JWT, SecretCategory::Other, ""),
            Some(CategoryShapeMismatch::JwtButNotToken)
        );
        // 白名单前缀 + 非 apikey 标注 → 同上.
        let m = s
            .category_shape_mismatch("AKIAIOSFODNN7EXAMPLE", SecretCategory::Token, "")
            .unwrap();
        assert_eq!(m, CategoryShapeMismatch::PublicPrefixButNotApiKey);
        // WARN 文案数据源映射的正确性 (写错只会产生误导性 WARN, 类型不挡).
        assert_eq!(m.detected(), "public_prefix");
        assert_eq!(m.suggested_category(), SecretCategory::ApiKey);
        assert_eq!(CategoryShapeMismatch::PemButNotPrivatekey.detected(), "pem");
        assert_eq!(
            CategoryShapeMismatch::PemButNotPrivatekey.suggested_category(),
            SecretCategory::PrivateKey
        );
        assert_eq!(
            CategoryShapeMismatch::EmailButNotEmailCategory.detected(),
            "email"
        );
        assert_eq!(
            CategoryShapeMismatch::EmailButNotEmailCategory.suggested_category(),
            SecretCategory::Email
        );
        assert_eq!(CategoryShapeMismatch::JwtButNotToken.detected(), "jwt");
        assert_eq!(
            CategoryShapeMismatch::JwtButNotToken.suggested_category(),
            SecretCategory::Token
        );
        // 标注匹配 → 无矛盾.
        assert_eq!(
            s.category_shape_mismatch(TEST_PEM, SecretCategory::PrivateKey, ""),
            None
        );
        assert_eq!(
            s.category_shape_mismatch("zhang.wei@gmail.com", SecretCategory::Email, ""),
            None
        );
        assert_eq!(
            s.category_shape_mismatch(TEST_JWT, SecretCategory::Token, ""),
            None
        );
        assert_eq!(
            s.category_shape_mismatch("AKIAIOSFODNN7EXAMPLE", SecretCategory::ApiKey, ""),
            None
        );
    }

    #[test]
    fn mismatch_silent_for_design_normal_cases() {
        // 反向不检测 (设计内常态, warn 即噪音): 标注 token/privatekey/apikey 但
        // 值无对应形状 — 平坦串即正确行为 (随机串 token / 单行 b64 私钥 /
        // 无前缀 api key).
        let s = MockStrategy::default();
        assert_eq!(
            s.category_shape_mismatch("random-access-token-xyz", SecretCategory::PrivateKey, ""),
            None
        );
        assert_eq!(
            s.category_shape_mismatch("plain-password-value", SecretCategory::Token, ""),
            None
        );
        assert_eq!(
            s.category_shape_mismatch("no-known-prefix-key", SecretCategory::ApiKey, ""),
            None
        );
    }

    #[test]
    fn mismatch_skipped_when_user_took_over() {
        // Fixed / 用户显式 gen_spec / global_prefix 非空 = 用户接管, 矛盾无行动
        // 价值, 不检测.
        let fixed = MockStrategy {
            initial: InitialValue::Fixed {
                value: "mock-x".into(),
            },
            gen_spec: None,
            gen_inferred: false,
        };
        assert_eq!(
            fixed.category_shape_mismatch(TEST_PEM, SecretCategory::ApiKey, ""),
            None
        );
        // 用户显式 gen (gen_inferred = false): mock 形态由用户配置决定, 跳过.
        let explicit = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: resolved("whatever-value-here", SecretCategory::Other)
                .gen_spec
                .clone(),
            gen_inferred: false,
        };
        assert_eq!(
            explicit.category_shape_mismatch(TEST_JWT, SecretCategory::Other, ""),
            None
        );
        // resolve 推断填充的 gen (gen_inferred = true) 不算接管 — 同一 entry
        // 重复 validate_and_resolve (加载后再编辑等场景) 检测仍有效.
        let mut inferred = MockStrategy::default();
        inferred.resolve_against("whatever-value-here", SecretCategory::Other, "");
        assert_eq!(
            inferred.category_shape_mismatch(TEST_JWT, SecretCategory::Other, ""),
            Some(CategoryShapeMismatch::JwtButNotToken)
        );
        assert_eq!(
            MockStrategy::default().category_shape_mismatch(
                TEST_PEM,
                SecretCategory::ApiKey,
                "sgm_"
            ),
            None
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// 等长不变量 (全 category × 全形状): infer 出的 gen spec 生成的 mock
        /// 总字符数 == real 总字符数 — 结构化形状与 Plain 同守 wire 字节量无扰动.
        #[test]
        fn prop_category_shape_mock_equal_length(
            category in 0usize..9,
            body in "[a-zA-Z0-9+/=_-]{1,64}",
            name in "[a-z]{2,12}",
            phone in "[0-9]{1,16}",
            kind in 0usize..7,
        ) {
            let cat = SecretCategory::ALL[category].0;
            // kind 定向构造七类形态: 0 PEM / 1 JWT / 2 公开前缀 / 3 普通串 /
            // 4 email / 5 phone / 6 username. 短样本 (name/phone 过短) 空间不足
            // 时退化 Plain — 等长断言仍成立 (gate 语义由
            // shape_infer_space_fallbacks_to_plain 专项钉住).
            let real = match kind {
                0 => format!("-----BEGIN X-----\n{body}\n-----END X-----"),
                1 => format!("{body}.{body}.{body}"),
                2 => format!("sk-{body}"),
                4 => format!("{name}.{name}@gmail.com"),
                5 => format!("+86 {phone}"),
                6 => name.clone(),
                _ => body.clone(),
            };
            // 跳过 validate_value 会拒绝的过短样本 (< 3 bytes) — infer 本身不校验,
            // 但保持与生产入口一致的前置 (validate_and_resolve 先 validate_value).
            if real.len() < 3 { return Ok(()); }
            let s = resolved(&real, cat);
            let mock = gen_candidate(&real, &s, 42, 0);
            prop_assert_eq!(mock.chars().count(), real.chars().count());
            // shape-aware C5 恒成立 (重试链兑现, 公开段豁免).
            let shape = s.gen_spec.unwrap().shape;
            prop_assert!(!c5_violated(&mock, &real, &shape, c5_threshold_len(&real)));
        }

        /// 守卫 RED-1 (shape-aware charset 合规, #356 子项5): 结构化形状
        /// (jwt / pem / public_prefixed / email / phone / username) 下 mock 的
        /// 字符域 = **随机段字符全部来自 gen_spec.charset** (用户显式配置面 —
        /// infer 的 charset 被覆盖) ∪ **结构段字符来自 shape 携带的固定结构**
        /// (jwt 点分隔 / PEM 边界行与换行 / 公开前缀 / email 的 '@'+domain /
        /// phone 的骨架 literal). 既有 `prop_mock_matches_gen_spec_charset` 经
        /// `valid_auto_gen_spec` 硬编码 shape: Plain (:2737 注释声明有意收窄 —
        /// RED-5 公开段豁免与 charset 断言口径冲突), 非 Plain 形状的 charset
        /// 合规性此前零覆盖; 等长 + C5 已由 `prop_category_shape_mock_equal_length`
        /// 互补覆盖, 本 property 补 charset 半面.
        ///
        /// 构造: real 定向构造七类形状 (同上) → resolve (infer 携带 shape 结构与
        /// length_range, 保证分段单点一致) → **显式覆盖 charset** (模拟用户
        /// "选形状 + 自选字符集" 的真实配置面; email/username 强制并入名字池
        /// 必需字符, phone 固定 digits-only — 合法配置面, 见函数体) → gen_candidate.
        #[test]
        fn prop_shape_mock_charset_compliance(
            kind in 0usize..7,
            body in "[a-zA-Z0-9+/=_-]{8,64}",
            name in "[a-z]{7,12}",
            phone in "[0-9]{5,16}",
            digits in any::<bool>(),
            lower in any::<bool>(),
            upper in any::<bool>(),
            under in any::<bool>(),
            hyph in any::<bool>(),
            other in "[@#$%€]{0,3}",
            seed in any::<u64>(),
            counter in 0u32..4,
        ) {
            let cat = match kind {
                0 => SecretCategory::PrivateKey,
                1 => SecretCategory::Token,
                2 => SecretCategory::ApiKey,
                4 => SecretCategory::Email,
                5 => SecretCategory::Phone,
                6 => SecretCategory::Username,
                _ => SecretCategory::Other,
            };
            // name ≥ 7 / phone ≥ 5 (总 digit ≥ 7) 保证 email/phone/username 三形态
            // 的 shape 推断稳定命中 (空间达标), 专测形状分支的 charset 合规.
            let real = match kind {
                0 => format!("-----BEGIN X-----\n{body}\n-----END X-----"),
                1 => format!("{body}.{body}.{body}"),
                2 => format!("sk-{body}"),
                4 => format!("{name}.{name}@gmail.com"),
                5 => format!("+86 {phone}"),
                6 => name.clone(),
                _ => body.clone(),
            };
            let mut s = MockStrategy::default();
            s.resolve_against(&real, cat, "");
            let spec = s.gen_spec.as_mut().expect("Auto after resolve has gen spec");
            // 显式覆盖 charset (空 charset 防御: 全关 + other 空时回落 digits,
            // 同 valid_auto_gen_spec 的处理). 三新形状强制并入形状必需字符 —
            // 同 infer_default_for 的强制 (RED-1 前提: 名字池/digit pad ⊆ charset
            // 是生成器的合规前提, 此处模拟合法手动配置面); phone 固定 digits-only
            // (validate 强制纯 digits).
            let other_chars: Vec<char> = other.chars().collect();
            let force_other = |cs: &mut Charset, seps: &[char]| {
                for &c in seps {
                    if !cs.other.contains(&c) {
                        cs.other.push(c);
                    }
                }
            };
            spec.charset = match kind {
                4 => {
                    // email local: 名字池 (小写) + '.' sep + digit pad.
                    let mut cs = Charset {
                        lowercase: true,
                        digits: true,
                        ..Default::default()
                    };
                    force_other(&mut cs, EMAIL_LOCAL_SEPS);
                    cs
                }
                5 => Charset {
                    digits: true,
                    ..Default::default()
                },
                6 => {
                    // username: 名字池 + seps + digit pad.
                    let mut cs = Charset {
                        lowercase: true,
                        digits: true,
                        ..Default::default()
                    };
                    force_other(&mut cs, USERNAME_SEPS);
                    cs
                }
                _ => Charset {
                    digits: digits || !(lower || upper || under || hyph || !other_chars.is_empty()),
                    lowercase: lower,
                    uppercase: upper,
                    underscore: under,
                    hyphen: hyph,
                    other: other_chars,
                },
            };
            let pool: std::collections::HashSet<char> =
                spec.charset.enabled_chars().into_iter().collect();
            // 结构字符: flat_fixed_prefix (Plain=gen prefix / PublicPrefixed=公开前缀)
            // + shape 分隔符/边界行/公开段.
            let mut allowed: std::collections::HashSet<char> =
                spec.flat_fixed_prefix().chars().collect();
            match &spec.shape {
                SecretShape::Plain => {}
                SecretShape::PublicPrefixed { .. } => {}
                SecretShape::Jwt { .. } => {
                    allowed.insert('.');
                }
                SecretShape::Pem {
                    header_line,
                    footer_line,
                    ..
                } => {
                    allowed.extend(header_line.chars());
                    allowed.extend(footer_line.chars());
                    allowed.insert('\n');
                }
                SecretShape::Email { domain } => {
                    allowed.insert('@');
                    allowed.extend(domain.chars());
                }
                SecretShape::Phone { skeleton } => {
                    allowed.extend(skeleton.chars().filter(|&c| c != '#'));
                }
                SecretShape::Username => {}
            }
            allowed.extend(pool);
            let mock = gen_candidate(&real, &s, seed, counter);
            prop_assert!(
                mock.chars().all(|c| allowed.contains(&c)),
                "shape mock {mock:?} has chars outside charset ∪ structure (allowed: {allowed:?})"
            );
        }
    }

    /// 构造一个 Auto 策略 (测试 helper).
    fn auto_strategy(prefix: &str, charset: Charset, length: usize) -> MockStrategy {
        MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: Some(GenSpec {
                prefix: prefix.into(),
                charset,
                length_range: (length, length),
                shape: SecretShape::Plain,
            }),
            gen_inferred: false,
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
                shape: SecretShape::Plain,
            }),
            gen_inferred: false,
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
                        shape: SecretShape::Plain,
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
    ///
    /// category 固定 Other (域收窄 Plain): default ApiKey 会让白名单前缀 real
    /// (AKIA/AIza 开头) 推断 PublicPrefixed, 与无豁免的 `assert_no_c5_substring`
    /// 口径冲突 (RED-5 公开段豁免语义) — 豁免路径由 shape 专项测试覆盖.
    fn resolved_auto_strategy(
        gen_spec: Option<GenSpec>,
        real: &str,
        global_prefix: &str,
    ) -> MockStrategy {
        let mut strategy = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec,
            gen_inferred: false,
        };
        strategy.resolve_against(real, SecretCategory::Other, global_prefix);
        strategy
    }

    proptest! {
        /// 守卫 RED-5: gen_candidate (Auto) body 不含 real ≥k(L) 字符子串 (contracts.md §2).
        #[test]
        fn prop_c5_gen_candidate_auto_body_no_real_substring(
            real in "[A-Za-z0-9]{4,64}",
            seed in any::<u64>(),
        ) {
            // category = Other: 域收窄 Plain (resolve_against 的 PublicPrefixed
            // 豁免与无豁免断言口径冲突, 见 resolved_auto_strategy 注释).
            let mut strategy = MockStrategy::default();
            strategy.resolve_against(&real, SecretCategory::Other, "");
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
            // category = Other: 域收窄 Plain (同上).
            let mut strategy = MockStrategy::default();
            strategy.resolve_against(&real, SecretCategory::Other, "");
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
            gen_inferred: false,
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
            gen_inferred: false,
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
            gen_inferred: false,
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
        s.resolve_against(real, SecretCategory::default(), "");
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
                shape: SecretShape::Plain,
            }),
            gen_inferred: false,
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
            gen_inferred: false,
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
            gen_inferred: false,
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
                shape: SecretShape::Plain,
            }),
            gen_inferred: false,
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
