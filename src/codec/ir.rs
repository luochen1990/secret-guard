//! 协议无关 IR 类型: 请求 / 响应 / 流事件.
//!
//! # 设计原则
//!
//! - **Superset IR**: 承载 OpenAI 和 Anthropic 都能表达的字段;
//!   单 protocol 独有的字段 (如 Anthropic `top_k`) 也在 IR 中, 但对端 writer 直接 drop.
//! - **first-class 字段优先于 `extra`**: 任何**需要跨协议保留**的字段都必须是 IR first-class 字段,
//!   而不是放在 `extra` (extra 在跨协议翻译时会被清空, 防止源协议独有的字段泄漏到对端).
//! - **同协议 round-trip 语义等价**: 同协议的 reader→writer 链应该让 body **语义等价**
//!   (字段顺序可能不同; 空文本块 / 空 content 等价性可能轻微变化, 但对 LLM 而言无差异).
//!   不追求严格 byte-exact (字段顺序 / 空字符串归一化可能让 wire 字节略变).

use serde_json::{Map, Value, json};

// ─── 请求侧 ────────────────────────────────────────────────────────────────

/// 协议无关的 chat completion 请求.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IrRequest {
    /// system / developer 角色的消息 (OpenAI: `messages[].role=="system"` 提升;
    /// Anthropic: 顶层 `system` 字段). 跨协议时这些块要折叠到顶层 system 或反之.
    pub system: Vec<IrBlock>,
    /// 主体对话消息 (不含 system 角色).
    pub messages: Vec<IrMessage>,
    /// 工具定义.
    pub tools: Vec<IrTool>,
    /// wire 形态元数据: 原始 wire 是否含 tools 字段 (即便为空数组).
    /// 同协议 round-trip 时填充, 跨协议翻译前清空.
    /// 区分 "tools: []" (显式空) 与缺失 tools 字段.
    pub tools_present: bool,
    /// wire 形态元数据: Anthropic 顶层 `system` 字段原始形态 (string / array).
    /// 区分 `"system": "x"` 与 `"system": [{"type":"text","text":"x"}]` — 单 Text block
    /// 的 array 形态若被折叠启发式改写成 string, 破坏 FWD-1 字面等式 (#269).
    /// 仅 Anthropic codec 填充; 跨协议翻译前清空.
    pub system_form: Option<SystemForm>,
    /// 最大输出 token 数. OpenAI 可选, Anthropic 必填.
    pub max_tokens: Option<u32>,
    /// wire 形态元数据: `max_tokens` 值的来源字段名 (OpenAI 双读别名, #283).
    /// - `None`: 缺失 / 跨协议路径 / 内部构造 (writer 写默认 `max_tokens`)
    /// - `Some(MaxTokensForm::MaxTokens)`: 原始 wire 用 `max_tokens`
    /// - `Some(MaxTokensForm::MaxCompletionTokens)`: 原始 wire 用
    ///   `max_completion_tokens` (o-series reasoning 模型字段; 官方 OpenAI 对
    ///   o-series 拒收 `max_tokens`, 字段名改写即 400)
    ///
    /// 仅 OpenAI codec 填充 (Responses/Anthropic 单字段无名可记); 跨协议翻译前清空
    /// (egress 恒写 `max_tokens`, o-series 检测待裁决 — known-limitations codec 节).
    pub max_tokens_form: Option<MaxTokensForm>,
    /// 采样温度. JSON 数字是 f64, 用 f64 避免 0.7→0.699999988 的精度损失.
    pub temperature: Option<f64>,
    /// nucleus sampling 截止. 两个协议都有.
    pub top_p: Option<f64>,
    /// top-k sampling 截止. **仅 Anthropic 有**; OpenAI writer drop.
    pub top_k: Option<u32>,
    /// 停止序列 (归一化为 `Vec<String>`). 空数组表示无 stop 序列 (但仍可能原始 wire 显式存在).
    pub stop: Vec<String>,
    /// wire 形态元数据: 原始 wire 中 `stop` 字段是否存在及其形态.
    /// - `None`: 缺失 / 跨协议路径 (writer 不输出 stop 字段)
    /// - `Some(StopForm::String)`: 原始是单字符串 (writer 输出 `"stop":"..."`)
    /// - `Some(StopForm::Array)`: 原始是数组 (writer 输出 `"stop":[...]`, 即便空数组也输出)
    ///
    /// 仅同协议 round-trip 时填充, 用于 wire 形态保真 (L7).
    /// 跨协议翻译前由 caller 清空.
    pub stop_form: Option<StopForm>,
    /// 工具选择策略.
    pub tool_choice: Option<IrToolChoice>,
    /// 终端用户标识. OpenAI: 顶层 `user`; Anthropic: `metadata.user_id`.
    pub user: Option<String>,
    /// 是否允许并行工具调用.
    /// OpenAI: 顶层 `parallel_tool_calls` (默认 true);
    /// Anthropic: `tool_choice.disable_parallel_tool_use` (默认 false, 注意取反).
    pub parallel_tool_calls: Option<bool>,
    /// 是否流式响应.
    pub stream: bool,
    /// reasoning (深度思考) 配置 (roadmap A1, 跨协议 first-class). None = 请求无
    /// reasoning 配置. 同协议路径不消费本字段 (extra 原样回写), 跨协议 seam 上
    /// extra 被清空后由它驱动翻译. 详见 [`IrReasoning`] 头部注释.
    pub reasoning: Option<IrReasoning>,
    /// 模型 id (从原始请求透传, 写入 egress 请求).
    pub model: String,
    /// 未建模字段的逃生舱. 同协议 round-trip 时透传; 跨协议时清空 (防泄漏).
    pub extra: serde_json::Map<String, Value>,
}

impl IrRequest {
    /// 清空所有 wire_fidelity 元数据 (跨协议翻译前调用, SSOT).
    ///
    /// wire_fidelity 字段记录的是 **ingress 协议的 wire 形态** (如字段是 string 还是 array),
    /// 跨协议翻译时 ingress 形态对 egress 协议无意义, 必须清空, 否则会污染 egress wire.
    /// 集中在此避免新增字段时漏清.
    pub fn clear_wire_fidelity(&mut self) {
        self.stop_form = None;
        self.tools_present = false;
        self.system_form = None;
        self.max_tokens_form = None;
        // 顶层 system blocks 的 extra 同样清空 (#269 评审补充): Anthropic 顶层
        // system 数组的 block 可携带 cache_control, 跨协议时不得泄漏进 egress wire.
        clear_block_extras(&mut self.system);
        for m in &mut self.messages {
            m.content_form = None;
            m.reasoning_content_form = None;
            // block/message 级 extra (#269): 与顶层 extra 同契约 — 同协议透传,
            // 跨协议清空 (防止 Anthropic 独有字段如 cache_control 泄漏进 egress wire).
            m.extra.clear();
            clear_block_extras(&mut m.content);
        }
        for t in &mut self.tools {
            t.extra.clear();
        }
    }
}

/// 递归清空 block 的 extra 字段 (含 ToolResult.content 嵌套块).
///
/// 与 [`IrRequest::clear_wire_fidelity`] 同属 SSOT 清空点: 新增带 extra 的
/// IrBlock variant 时只需改这里.
fn clear_block_extras(blocks: &mut [IrBlock]) {
    for b in blocks {
        match b {
            IrBlock::Text { extra, .. }
            | IrBlock::ToolUse { extra, .. }
            | IrBlock::ToolResult { extra, .. }
            | IrBlock::Image { extra, .. }
            | IrBlock::Reasoning { extra, .. }
            | IrBlock::ReasoningContent { extra, .. } => extra.clear(),
        }
        if let IrBlock::ToolResult { content, .. } = b {
            clear_block_extras(content);
        }
    }
}

/// 单条对话消息.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IrMessage {
    pub role: IrRole,
    pub content: Vec<IrBlock>,
    /// wire 形态元数据: 消息级未建模字段的逃生舱 (如 Anthropic 消息级
    /// `output_config` / provider 扩展). 同协议 round-trip 时原样回写
    /// (#269, L4); 跨协议翻译前由 `clear_wire_fidelity` 清空 (防泄漏, 与
    /// 顶层 `extra` 契约同型). 空 Map = 无.
    ///
    /// 注意: 此字段在 `MessageRef`/`resolve_message` 中**不保留** (MessageRef 只存
    /// role + block hash, 同 `contains_user_text` 的既有限制) — 影响面仅 WebUI
    /// timeline 重建 (非 egress 路径), egress wire 序列化走原始 `ir.messages`.
    pub extra: serde_json::Map<String, Value>,
    /// wire 形态元数据: 原始 wire 中 `content` 是 string 还是 array 还是 null.
    /// - `None`: 跨协议路径 / 内部构造 (writer 用协议默认形态)
    /// - `Some(ContentForm::String)`: 原始是裸 string (Anthropic 单文本消息常见)
    /// - `Some(ContentForm::Array)`: 原始是 array of blocks
    /// - `Some(ContentForm::Null)`: 原始是 null (assistant 调用工具时)
    ///
    /// 仅同协议 round-trip 时填充, 用于 wire 形态保真 (L1).
    /// 跨协议翻译前由 caller 清空.
    pub content_form: Option<ContentForm>,
    /// wire 形态元数据: assistant 消息的 `reasoning_content` 字段是否显式存在
    /// (空串 / null 两种 "无信息量但显式存在" 的形态). #176 FWD-1 保真:
    /// 区分 `"reasoning_content": ""` / `null` 与字段缺席, writer 据此写回.
    /// 非 assistant 消息恒 None; 跨协议翻译前清空.
    pub reasoning_content_form: Option<ReasoningContentForm>,
    /// 这条消息是否代表用户的**主动文本输入** (而非工具结果的隐式 user 角色).
    ///
    /// 背景: IR 把 OpenAI `role:"tool"` 和 Anthropic `role:"user"+tool_result` 都归一化
    /// 为 `IrRole::User`, 导致无法从 `role` 单一维度区分 "用户真在说话" vs "工具结果
    /// 借 user 角色承载". 此字段补充丢失的维度, 由 reader 入口 (同时看到原始 wire role
    /// 和解析后的 content blocks) 集中判定:
    ///   - `role == User` 且 content 含非空 Text block → true
    ///   - 其他 (tool_result-only user / assistant / system) → false
    ///
    /// 用途: DAG 的 round_role 判定 (sidebar 分组: 用户轮 vs 工具轮).
    /// 不参与 wire 序列化 (writer 忽略此字段).
    ///
    /// 注意: 此字段在 `MessageRef`/`resolve_message` 中**不保留** (MessageRef 只存 role +
    /// block hash). round_role 在 push_messages 时一次性消耗原始 msgs 的此字段, 之后
    /// resolve_message 重建的 IrMessage 此字段会 reset 为 false (Default).
    pub contains_user_text: bool,
}

/// content blocks 是否含非空 Text block.
/// secret 在 IR 各位置的命中计数 (redact 审计的治理归因维度, 采集于替换前的
/// 只读遍历 — `redact.rs::count_hit_locations`).
///
/// 归属论证: 描述的是 **IR 结构位置** (system / tools / messages / 协议边缘),
/// 与 `contains_user_text` 同族; redact (域 A 改写) 与 usage (域 B 审计) 都可
/// 依赖本模块, 不引入横向边.
///
/// 分类语义 (治理行动映射):
/// - `system`: system prompt 污染 → 通常是工具/环境配置把 secret 注入了系统提示词;
/// - `tools`: 工具定义 (name/description/schema) → MCP server 或工具注册时硬编码;
/// - `user`: 真用户输入 (`contains_user_text` 判定) → 用户/agent 把 secret 粘进了消息;
/// - `history`: 其余 messages (assistant 历史 / tool_result 回传) → 前序轮次已泄或工具回显;
/// - `other`: stop 序列 / user 字段 / extra — 罕见的协议边缘位置.
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct HitLocations {
    pub system: u64,
    pub tools: u64,
    pub user: u64,
    pub history: u64,
    pub other: u64,
}

impl HitLocations {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// 非零分类的 (名称, 计数) 迭代 (持久化展开与 UI 渲染共用; 固定序保证确定性).
    pub fn non_zero(&self) -> impl Iterator<Item = (&'static str, u64)> {
        [
            ("system", self.system),
            ("tools", self.tools),
            ("user", self.user),
            ("history", self.history),
            ("other", self.other),
        ]
        .into_iter()
        .filter(|(_, n)| *n > 0)
    }
}

/// 用于 reader 入口判定 `contains_user_text`.
pub fn blocks_has_text(blocks: &[IrBlock]) -> bool {
    blocks
        .iter()
        .any(|b| matches!(b, IrBlock::Text { text, .. } if !text.is_empty()))
}

/// wire 中 message content 的原始形态. 用于同协议 round-trip 时保留 wire 形态.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentForm {
    /// 裸字符串: `"content": "hello"`
    String,
    /// 数组: `"content": [{"type":"text","text":"hello"}]`
    Array,
    /// null: `"content": null (assistant 调用工具时)
    Null,
}

/// wire 中 assistant 消息 `reasoning_content` 字段的形态 (L1 保真, #176).
///
/// - `Some(Empty)`: wire 显式 `"reasoning_content": ""` (reader 视为无信息量不建
///   ReasoningContent block, 但 writer 必须写回空串 — 区分 "显式空" 与 "缺席")
/// - `Some(Null)`: wire 显式 `"reasoning_content": null`
/// - `None`: 字段缺席 (或跨协议路径, clear_wire_fidelity 后)
///
/// 非 string / 非 null 的异常形态归 `None` (writer 按缺席输出, ROB-1 降级).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasoningContentForm {
    Empty,
    Null,
}

impl ReasoningContentForm {
    /// 从 wire 字段值推断形态 (与 [`ContentForm::classify`] / [`StopForm::classify`]
    /// 同签名). 仅识别 "显式存在但无信息量" 的两形态: 空串 / null;
    /// 非空 string (正常路径, 由 block 承载) / 缺失 / 异常类型 → None.
    pub fn classify(value: Option<&Value>) -> Option<Self> {
        match value {
            Some(Value::String(s)) if s.is_empty() => Some(Self::Empty),
            Some(Value::Null) => Some(Self::Null),
            _ => None,
        }
    }

    /// 形态 → wire 值 (与 `classify` 读写字面对称).
    pub fn to_value(self) -> Value {
        match self {
            Self::Empty => Value::String(String::new()),
            Self::Null => Value::Null,
        }
    }
}

impl ContentForm {
    /// 从 wire 字段值推断 content 形态. 缺失 / 非预期类型 → None (writer 用协议默认).
    /// 用于 reader 在解析 message content / tool_result content 时记录原始形态 (L1 保真).
    pub fn classify(value: Option<&Value>) -> Option<Self> {
        match value {
            Some(Value::String(_)) => Some(Self::String),
            Some(Value::Array(_)) => Some(Self::Array),
            Some(Value::Null) => Some(Self::Null),
            _ => None,
        }
    }
}

/// wire 中 stop 字段的原始形态. 用于同协议 round-trip 时保留 wire 形态.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopForm {
    /// 单字符串: `"stop": "abc"`
    String,
    /// 数组: `"stop": ["abc"]`
    Array,
}

impl StopForm {
    /// 从 wire `stop` 字段值推断形态. 缺失 / 非预期类型 → None.
    pub fn classify(value: Option<&Value>) -> Option<Self> {
        match value {
            Some(Value::String(_)) => Some(Self::String),
            Some(Value::Array(_)) => Some(Self::Array),
            _ => None,
        }
    }
}

/// wire 中 max_tokens 值的来源字段名 (OpenAI 双读别名). 用于同协议 round-trip 时
/// 保留字段名 (`max_tokens` / `max_completion_tokens`, #283) — o-series 上游对
/// 字段名敏感, 改写即 400. 与 `StopForm` 不同, 形态由**键名**区分 (值恒为数字),
/// 故无 `classify` (按值推断) — 由 OpenAI reader 双读处内联记录.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxTokensForm {
    /// `"max_tokens": N`
    MaxTokens,
    /// `"max_completion_tokens": N` (o-series reasoning 模型字段)
    MaxCompletionTokens,
}

/// wire 中 Anthropic 顶层 `system` 字段的原始形态 (L1 同型保真, #269).
///
/// 背景: writer 曾对单 Text block 一律折叠为 string 形态 — ingress 为 array 形态
/// (claude code 实测, block 可携带 `cache_control`) 时写回会改变形态, 破坏 FWD-1
/// 字面等式. 与 [`StopForm`] / [`ContentForm`] 同型: 同协议 round-trip 填充,
/// 跨协议翻译前清空.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemForm {
    /// 单字符串: `"system": "abc"`
    String,
    /// 数组: `"system": [{"type":"text",...}]` (含单 block — 形态保真优先于折叠启发式)
    Array,
}

/// reasoning (深度思考) 配置的协议无关表示 (roadmap A1, 批次 1).
///
/// 归一化三协议的两种 API 风格: "档位 (effort)" vs "精确预算 (budget_tokens)":
/// - OpenAI Chat: `reasoning_effort: "minimal"|"low"|...` (档位)
/// - OpenAI Responses: `reasoning: {effort: "..."}` (档位)
/// - Anthropic: `thinking: {type, budget_tokens?}` (精确预算 / adaptive / disabled)
///
/// **与 extra 的共存纪律** (roadmap §2.4): 三协议 reader 均**不**把对应 wire 字段
/// (`reasoning_effort` / `thinking` / `reasoning`) 从 `collect_extra` 排除 — 原始
/// 对象 (含 `display` / `summary` 等未建模子字段) 留在 extra: 同协议 round-trip
/// 由 extra 原样回写 (writer 检测到 extra 有对应 key 时跳过 first-class 注入,
/// 避免双写), 未知档位值 (enum 建不出) 也靠 extra 兜底不丢 (ROB); 跨协议 seam
/// (`cross_proto_forward`) extra 被清空, 本字段驱动翻译.
///
/// 本字段是**语义字段**而非 wire 形态元数据: `clear_wire_fidelity` **不清空**它 —
/// 这正是跨协议保留 reasoning 语义的机制 (对照: `stop_form` 等只服务同协议保真).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrReasoning {
    /// 关闭 reasoning (Anthropic `thinking: {type: "disabled"}`).
    /// OpenAI 系无对应字段 (writer 不写), lossy-by-target.
    Disabled,
    /// 档位模式 (OpenAI `reasoning_effort` / Responses `reasoning.effort`).
    Effort(IrReasoningEffort),
    /// 精确预算模式 (Anthropic `thinking: {type: "enabled", budget_tokens: N}`).
    Budget(u32),
    /// 自适应 (Anthropic `thinking: {type: "adaptive"}`).
    /// OpenAI 系无对应档位 (writer 投影到 Medium).
    Adaptive,
}

/// reasoning 档位 (OpenAI effort 枚举, 6 档).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrReasoningEffort {
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
    Max,
}

/// effort ↔ budget 双向投影表 (绝对值, roadmap A1 裁决: 简单优先, 不随 max_tokens
/// 自适应 — 真实场景出现 "max_tokens 很大但 reasoning 不够用" 再切 ratio 公式).
/// **表序 == [`IrReasoningEffort`] 判别式序** (`budget_tokens` 按 `self as usize`
/// 直查) — 重排变体声明序会静默错位 (由 `effort_budget_table_values_locked` 拦截).
const EFFORT_BUDGETS: [u32; 6] = [1024, 2048, 4096, 8192, 16384, 32768];

impl IrReasoningEffort {
    /// wire 字符串形态 (OpenAI effort 枚举名, 全小写单词无分隔符).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Xhigh => "xhigh",
            Self::Max => "max",
        }
    }

    /// wire 字符串 → enum. 未知档位返回 None (ROB-1: 不 panic; same-proto 由
    /// extra 兜底保真, 跨协议按无配置处理).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "minimal" => Some(Self::Minimal),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "xhigh" => Some(Self::Xhigh),
            "max" => Some(Self::Max),
            _ => None,
        }
    }

    /// effort → budget 投影 (表 SSOT, 与 [`Self::nearest_budget`] 互为逆).
    pub fn budget_tokens(self) -> u32 {
        EFFORT_BUDGETS[self as usize]
    }

    /// budget → effort 反查 (nearest: `|表值 − budget|` 最小的档位; 等距平局取
    /// 较高档, 如 1536 距 1024/2048 等距 → Low). 精确预算 (连续) 投影到 6 档
    /// 离散枚举必损精度 — 本函数是 o/r writer 对 `Budget(n)` 的统一降维规则,
    /// 表值精确命中时无损 (`nearest_budget(e.budget_tokens()) == e`).
    pub fn nearest_budget(budget: u32) -> Self {
        let mut best = 0usize;
        let mut best_dist = u64::MAX;
        for (i, table) in EFFORT_BUDGETS.iter().enumerate() {
            // u64 距离避免 u32 溢出 (budget 很大时).
            let dist = (*table as u64).abs_diff(budget as u64);
            // 等距平局取较高档 (i 更大): `<=` 使后面的等距候选胜出.
            if dist <= best_dist {
                best = i;
                best_dist = dist;
            }
        }
        match best {
            0 => Self::Minimal,
            1 => Self::Low,
            2 => Self::Medium,
            3 => Self::High,
            4 => Self::Xhigh,
            _ => Self::Max,
        }
    }
}

impl IrReasoning {
    /// 投影到 OpenAI 系 (o/r) effort 档位:
    /// - `Effort(e)` → e; `Budget(n)` → nearest 档; `Adaptive` → Medium (无档位
    ///   对应, 取中档默认);
    /// - `Disabled` → None (OpenAI 系无 "关闭" 字段, writer 不写 — lossy-by-target).
    pub fn to_effort(self) -> Option<IrReasoningEffort> {
        match self {
            Self::Disabled => None,
            Self::Effort(e) => Some(e),
            Self::Budget(n) => Some(IrReasoningEffort::nearest_budget(n)),
            Self::Adaptive => Some(IrReasoningEffort::Medium),
        }
    }
}

impl SystemForm {
    /// 从 wire `system` 字段值推断形态. 缺失 / 非预期类型 → None.
    pub fn classify(value: Option<&Value>) -> Option<Self> {
        match value {
            Some(Value::String(_)) => Some(Self::String),
            Some(Value::Array(_)) => Some(Self::Array),
            _ => None,
        }
    }
}

/// 消息角色. 注意: `System` 角色的消息虽然出现在 [`IrMessage`] 里时,
/// reader 会**提升**到 [`IrRequest::system`], 但 IrMessage 仍可承载 (内部一致性).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum IrRole {
    System,
    #[default]
    User,
    Assistant,
    Tool,
}

/// 消息内容块 (chat completion 中所有协议都支持 block-based content).
impl IrBlock {
    /// 该 block 的 wire 级 `extra` (L5, #269; T7 扩至 thinking 族 — 全部六个
    /// wire 来源 variant 携带).
    pub fn block_extra(&self) -> Option<&serde_json::Map<String, Value>> {
        match self {
            IrBlock::Text { extra, .. }
            | IrBlock::ToolUse { extra, .. }
            | IrBlock::ToolResult { extra, .. }
            | IrBlock::Image { extra, .. }
            | IrBlock::Reasoning { extra, .. }
            | IrBlock::ReasoningContent { extra, .. } => Some(extra),
        }
    }
}

///
/// # block 级 `extra` (#269, L5; T7 扩至 thinking 族)
///
/// 全部六个 wire 来源 variant (Text / ToolUse / ToolResult / Image / Reasoning /
/// ReasoningContent) 均携带 `extra: Map<String, Value>` — 该 block 上未建模字段
/// 的逃生舱 (典型: Anthropic block 级 `cache_control` 缓存断点, claude code
/// 每请求 2-4 个; 扩展思考场景官方推荐断点恰在 thinking block — T7 补齐).
/// 同协议 round-trip 时 reader 收集 / writer 原样回写; 跨协议翻译前由
/// `clear_wire_fidelity` 清空 (与顶层 `IrRequest.extra` 契约同型).
/// 注意: sg-thinking envelope **不携带** extra — 打包点在 writer = 跨协议 seam
/// 之后 (extra 已被清空, 恒空 Map), 解包侧的 extra 由 reader 从 wire item 现收.
#[derive(Debug, Clone, PartialEq)]
pub enum IrBlock {
    /// 文本块.
    Text {
        text: String,
        /// 未建模字段 (如 `cache_control`). 空 Map = 无.
        extra: serde_json::Map<String, Value>,
    },
    /// 工具调用 (assistant 发起).
    /// `id` 必须 verbatim 透传, 否则下一轮 tool_result 引用断裂.
    ToolUse {
        id: String,
        name: String,
        input: Value,
        /// 未建模字段. 空 Map = 无.
        extra: serde_json::Map<String, Value>,
    },
    /// 工具结果 (user 回复 assistant 的 ToolUse).
    /// OpenAI 用独立 `role:"tool"` 消息承载; Anthropic 用 user 消息内的 tool_result 块.
    ToolResult {
        tool_use_id: String,
        content: Vec<IrBlock>,
        /// wire 保真 (#269): `None` = 字段缺席 (API 语义 false); `Some(true/false)` =
        /// 显式形态, writer 按原样回写 (显式 false 不能静默省略 — 破坏 FWD-1 字面等式).
        is_error: Option<bool>,
        /// wire 形态元数据: Anthropic tool_result.content 可能是 string 或 array.
        /// OpenAI 的 tool message content 永远是 string, 此字段 None.
        /// 同协议 round-trip 时填充, 跨协议翻译前清空.
        content_form: Option<ContentForm>,
        /// 未建模字段 (如 `cache_control`). 空 Map = 无.
        extra: serde_json::Map<String, Value>,
    },
    /// 图片块. 跨协议唯一无歧义形式是 Base64; URL 引用也保留.
    Image {
        source: IrImageSource,
        /// 未建模字段 (如 `cache_control`). 空 Map = 无.
        extra: serde_json::Map<String, Value>,
    },
    /// 推理块 (Responses API 的 `reasoning` output item).
    ///
    /// `summary` 文本数组可被 Redact 扫描是否有 secret 子串 (叶子);
    /// `encrypted_content` 是 provider opaque blob (密文, **不进 redact 扫描** —
    /// 见 [`ThinkingOpaque`] 的安全链注记), 同协议 round-trip 与 a⇄r 跨协议
    /// envelope 搬运均完整保留 (T7, 修复 "reasoning chain 断裂" 已知限制).
    Reasoning {
        summary: Vec<String>,
        /// Responses reasoning item 的 `encrypted_content` (provider opaque).
        /// None = wire 缺席。跨协议到 Anthropic 时被 envelope 打包进 signature。
        opaque: Option<String>,
        /// 未建模字段 (L5, T7 — 与 Text 等四臂同型; reasoning item 的 id 等未知
        /// 字段逃生舱)。跨协议经 `clear_wire_fidelity` 清空。
        extra: serde_json::Map<String, Value>,
    },
    /// 思考原文块 (OpenAI Chat 兼容 provider 的 `reasoning_content` 字段 / Anthropic
    /// `thinking` / `redacted_thinking` block, 思考型模型的思考阶段原文).
    ///
    /// 与 [`IrBlock::Reasoning`] 的区别: 后者是 Responses API 的**摘要列表**
    /// (`summary_text[]`), 本块是思考**原文连续文本** (非流式 message 字段 /
    /// 流式 ReasoningDelta 累积). 两者语义不同, 不合并 (#176).
    ///
    /// Redact 覆盖: `text` 是 IR 字符串叶子 (secret 可能泄漏进思考流)。
    /// `opaque` 是签名/密文**非明文**, 不进扫描; 其跨协议搬运的安全性由
    /// envelope 的打包/解包位置保证 (writer 侧打包 = post-redact, reader 侧
    /// 解包 = pre-redact — 解包文本以叶子身份进入扫描, 见 `codec/thinking.rs`).
    /// 跨协议: a→r 经 envelope 搬进 encrypted_content; o-origin (opaque=None)
    /// 到 a 丢弃 + WARN (o 无 opaque 容器, 不发明 wire 形态)。
    ReasoningContent {
        text: String,
        /// provider opaque: Anthropic thinking.signature / redacted_thinking.data。
        /// `RedactedData` 形态时 `text` 恒空 (redacted_thinking 无原文)。
        opaque: Option<ThinkingOpaque>,
        /// 未建模字段 (L5, T7 — 典型: thinking block 的 `cache_control` 缓存断点,
        /// 扩展思考场景官方推荐断点恰在此)。跨协议经 `clear_wire_fidelity` 清空。
        extra: serde_json::Map<String, Value>,
    },
}

/// Anthropic thinking 族 block 的 provider opaque 容器 (T7)。
///
/// **安全链注记**: signature / data 是 Anthropic 的加密签名/密文, **不是明文** —
/// 不进 redact 的字符串叶子扫描 (`redact.rs::StringLeafOps`)。secret-guard 只
/// **搬运**不合成 (旧 "无法合法合成 signature" 裁决只否定合成, 不否定搬运 —
/// cc-switch 的 envelope passthrough 是第三条路)。
/// 跨协议 a⇄r 搬运经 `sg-thinking-v1:` envelope (base64 明文 JSON), 打包点在
/// writer (post-redact / post-restore), 解包点在 reader (pre-redact / pre-restore)
/// — 保证 envelope 内文本要么已脱敏 (请求方向), 要么本就该交付客户端 (响应方向)。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ThinkingOpaque {
    /// `thinking.signature` (加密签名; 覆盖 thinking 文本 — redact mock 文本后
    /// signature 可能失配, 属 "安全优先于签名有效性" 的已接受折衷, 见
    /// known-limitations)。
    Signature(String),
    /// `redacted_thinking.data` (纯密文无原文, 承载块 `text` 恒空)。
    RedactedData(String),
}

/// 图片来源 (跨协议中立的图片表达).
#[derive(Debug, Clone, PartialEq)]
pub enum IrImageSource {
    /// 内联 base64 字节 + 真实 MIME type ("image/png" 等).
    Base64 { media_type: String, data: String },
    /// 远程图片 URL (OpenAI `image_url.url` https://...; Anthropic `source.url`).
    Url(String),
}

/// 工具定义.
#[derive(Debug, Clone, PartialEq)]
pub struct IrTool {
    pub name: String,
    pub description: Option<String>,
    /// JSON Schema 描述工具参数.
    pub input_schema: Value,
    /// wire 形态元数据: 工具级未建模字段的逃生舱 (如 Anthropic 工具上的
    /// `cache_control` / `defer_loading` / `type`). 同协议 round-trip 原样回写
    /// (#269, claude code 常把缓存断点放在最后一个工具定义上); 跨协议翻译前
    /// 由 `clear_wire_fidelity` 清空. 空 Map = 无.
    pub extra: serde_json::Map<String, Value>,
}

/// 工具选择策略. 取并集: 每个协议都能表达这 4 种.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrToolChoice {
    /// 模型自主决定是否调用工具 (默认).
    Auto,
    /// 模型必须不调用工具 (仅生成文本).
    None,
    /// 模型必须调用某个工具 (任意).
    /// OpenAI `"required"`; Anthropic `{type:"any"}`.
    Required,
    /// 模型必须调用指定名称的工具.
    /// OpenAI `{type:"function",function:{name}}`; Anthropic `{type:"tool",name}`.
    Tool { name: String },
}

// ─── 响应侧 (非流式) ───────────────────────────────────────────────────────

/// 协议无关的非流式 chat completion 响应.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IrResponse {
    /// assistant 回复的内容块.
    pub content: Vec<IrBlock>,
    /// 终止原因. 同协议时 verbatim 透传; 跨协议时 enum→enum 映射.
    pub stop_reason: Option<IrStopReason>,
    /// 命中的停止序列 (若有). 跨协议保留.
    pub stop_sequence: Option<String>,
    /// token 用量统计.
    pub usage: IrUsage,
    /// wire 形态元数据: 上游响应是否**显式携带** usage 对象 (usage-stats 采集用).
    ///
    /// 区分 "无回显" (`false`, 如 OpenAI 流式未开 `include_usage` / 非 2xx /
    /// parse 失败) 与 "显式零回显" (`true` + 全零, wire 有 `"usage": {全零}`) —
    /// 用量统计的 P-3 原则 (缺失显式) 依赖此位. reader 在 wire 观测到 usage 对象时
    /// 置 true; 流式侧由 StreamScan 在任一 usage 承载事件到达时置 true.
    /// 不参与 wire 序列化 (writer 忽略; 与 content_form 等元数据同模式).
    pub usage_present: bool,
    /// 上游实际服务的模型名 (响应里携带).
    pub model: Option<String>,
    /// 响应 id (OpenAI `chatcmpl-...`; Anthropic `msg_...`).
    /// 同协议时透传; 跨协议时置 None, 由 ingress writer 合成本地格式 id.
    pub id: Option<String>,
    /// Unix epoch seconds (OpenAI 携带; Anthropic 不带, OpenAI writer 合成).
    pub created: Option<u64>,
}

/// 协议无关的终止原因. typed enum (无 String payload), 防止 foreign token 跨协议泄漏.
///
/// reader 把无法识别的 native token 映射到 [`Self::Other`]; writer 的 match 是穷举的,
/// 编译器强制新协议覆盖每个 variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrStopReason {
    /// 自然结束 (OpenAI `"stop"`; Anthropic `"end_turn"`).
    EndTurn,
    /// 命中 stop sequence (OpenAI `"stop"` + stop_sequence; Anthropic `"stop_sequence"`).
    StopSequence,
    /// 达到 max_tokens (两协议都 `"max_tokens"`).
    MaxTokens,
    /// 模型调用工具 (OpenAI `"tool_calls"`; Anthropic `"tool_use"`).
    ToolUse,
    /// 内容审核拦截 (OpenAI `"content_filter"`; Anthropic 无直接对应, 通过 error 表达).
    Safety,
    /// 模型拒绝 (Anthropic `"refusal"`; OpenAI 无直接对应).
    Refusal,
    /// 兜底: 任何无法识别的 native token. 防止 foreign 字符串泄漏.
    Other,
}

/// token 用量统计. 归一化为 "未缓存 input + 加性 cache 字段".
///
/// # 归一化约定
///
/// - `input_tokens`: **未缓存** input (OpenAI 的 `prompt_tokens` 含 cached 总和, reader
///   必须 `saturating_sub(cached_tokens)`)
/// - `cache_read_input_tokens`: 命中缓存读取的 input (加性, 不重复计入 input_tokens)
/// - `cache_creation_input_tokens`: 写入缓存的 input (加性)
/// - `output_tokens`: 输出 token 数
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IrUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_input_tokens: Option<u64>,
    pub cache_read_input_tokens: Option<u64>,
}

impl IrUsage {
    /// 全零的零值, 用于流式累积的初始值.
    pub fn zero() -> Self {
        Self::default()
    }

    /// 是否所有字段都为零. 用于判断 usage 是否携带有效统计.
    ///
    /// 单一事实来源: 新增字段时只需要更新此方法, 所有 caller 自动生效.
    /// (eg. OpenAI writer 决定是否在 chunk 中附 `usage` 字段;
    /// StreamTranslate post-stop guard 决定是否放行 MessageDelta.)
    pub fn is_zero(&self) -> bool {
        self.input_tokens == 0
            && self.output_tokens == 0
            && self.cache_creation_input_tokens.unwrap_or(0) == 0
            && self.cache_read_input_tokens.unwrap_or(0) == 0
    }

    /// OpenAI 风格的 `prompt_tokens`: 未缓存 input + 命中缓存 + 写入缓存 (饱和加).
    ///
    /// 单一事实来源: IR 归一化约定中 `input_tokens` 仅含未缓存部分, 但 OpenAI wire
    /// 格式的 `prompt_tokens` 含 cached 总和, writer 必须加回.
    /// 集中在此避免多处手算.
    pub fn openai_prompt_tokens(&self) -> u64 {
        self.input_tokens
            .saturating_add(self.cache_read_input_tokens.unwrap_or(0))
            .saturating_add(self.cache_creation_input_tokens.unwrap_or(0))
    }

    /// 序列化为 OpenAI wire 格式的 `usage` 对象.
    ///
    /// 单一事实来源: 非流式响应与流式 MessageDelta 都用同一个 wire 形态,
    /// 集中在此避免两处手写 JSON shape (新增字段时只改此处).
    /// `prompt_tokens` 总和经 [`IrUsage::openai_prompt_tokens`] (SSOT, 禁止手算);
    /// `cache_read` 经 `prompt_tokens_details.cached_tokens` 写回 (#284) — 条件写
    /// 判据与 Anthropic writer 的双 cache 字段一致 (`Some` 即写, 含 `Some(0)`,
    /// 保持 round-trip presence 保真); `cache_creation` 无 OpenAI 对应字段,
    /// 只计入总和.
    pub fn openai_usage_json(&self) -> Value {
        let prompt_tokens = self.openai_prompt_tokens();
        let mut obj = Map::new();
        obj.insert("prompt_tokens".to_string(), json!(prompt_tokens));
        obj.insert("completion_tokens".to_string(), json!(self.output_tokens));
        obj.insert(
            "total_tokens".to_string(),
            json!(prompt_tokens.saturating_add(self.output_tokens)),
        );
        if let Some(cached) = self.cache_read_input_tokens {
            obj.insert(
                "prompt_tokens_details".to_string(),
                json!({ "cached_tokens": cached }),
            );
        }
        Value::Object(obj)
    }
}

// ─── 流式侧 ────────────────────────────────────────────────────────────────

/// 协议无关的流式事件. 取 OpenAI 与 Anthropic 流事件类型的并集.
///
/// reader 把 native SSE 事件解析为 [`IrStreamEvent`]; writer 把 [`IrStreamEvent`] 序列化回 native SSE.
/// [`super::stream::StreamTranslate`] 负责 egress reader ⨯ ingress writer 的组合.
#[derive(Debug, Clone, PartialEq)]
pub enum IrStreamEvent {
    /// 流开始. usage 在 Anthropic 流的 `message_start` 携带 input_tokens;
    /// OpenAI 流的 start chunk 总是 `None` (input 在末尾 include_usage chunk).
    MessageStart {
        usage: Option<IrUsage>,
        id: Option<String>,
        created: Option<u64>,
        model: Option<String>,
    },
    /// 内容块开始.
    BlockStart { index: usize, block: IrBlockMeta },
    /// 内容块增量.
    BlockDelta { index: usize, delta: IrDelta },
    /// 内容块结束.
    BlockStop { index: usize },
    /// 流终止前的元数据 (stop_reason + 最终 usage).
    ///
    /// `usage_present`: wire 是否显式携带 usage 对象 (与 [`IrResponse::usage_present`]
    /// 同语义的流式事件版; reader 产出端设置, writer 忽略). 区分 "message_delta 无
    /// usage 字段" 与 "usage 对象为全零" — StreamScan 据此精确累积 presence
    /// (STR-2: scan ≡ 非流式 parse 的等价性要求).
    MessageDelta {
        stop_reason: Option<IrStopReason>,
        stop_sequence: Option<String>,
        usage: IrUsage,
        usage_present: bool,
    },
    /// 流终止.
    MessageStop,
    /// 流中错误 (上游 SSE `event: error` 或 OpenAI 流内联 `{"error":...}`).
    Error(String),
}

/// 内容块元信息 (BlockStart 携带).
#[derive(Debug, Clone, PartialEq)]
pub enum IrBlockMeta {
    Text,
    ToolUse {
        id: String,
        name: String,
    },
    /// 思考原文块 (流式对应物: [`IrDelta::ReasoningDelta`]). #176.
    ///
    /// 命名配对规律: meta 名 == 折叠 block 名 (Text↔Text / ToolUse↔ToolUse /
    /// 本变体 ↔ [`IrBlock::ReasoningContent`]). 注意 **不是** [`IrBlock::Reasoning`]
    /// (后者是 Responses API 摘要列表语义, 无流式对应物).
    ///
    /// **o-origin 专用** (OpenAI 流 `delta.reasoning_content`): 无 provider opaque
    /// 容器 — Anthropic writer 对本变体跳过 (o 协议无容器可搬, T7 裁决: envelope
    /// 仅 a⇄r)。有容器的 thinking 族流 (a/r-origin) 用 [`Self::Thinking`]。
    ReasoningContent,
    /// thinking 族 block (有合法 opaque 容器: a `thinking`/`redacted_thinking`,
    /// r reasoning item) 的流式起点 (T7)。生产者: a 流式 reader (thinking start)
    /// 与 r 流式 reader (reasoning item added)。折叠目标仍是
    /// [`IrBlock::ReasoningContent`] (StreamScan) — meta 表达的是流式 origin 能力
    /// (a writer 可完整产出 / 可 envelope 搬运), 不是折叠 block 类型; 与
    /// [`Self::ReasoningContent`] 的区分是 writer 能力分派依据。
    Thinking,
    /// `redacted_thinking` 的流式起点 (T7): 纯 opaque 无原文无 delta — Anthropic
    /// 实际流把完整 `data` 放在 content_block_start, 随后直接 content_block_stop。
    RedactedThinking {
        /// provider opaque 密文 (content_block_start 携带的全量 data)。
        data: String,
    },
}

/// 内容块增量 (BlockDelta 携带).
#[derive(Debug, Clone, PartialEq)]
pub enum IrDelta {
    /// 文本增量.
    TextDelta(String),
    /// 工具调用参数的 JSON 片段 (流式 partial JSON).
    InputJsonDelta(String),
    /// 思考原文增量 (OpenAI 兼容流式 `delta.reasoning_content` / Anthropic
    /// `thinking_delta` / Responses reasoning summary delta 归一). #176.
    /// 纯文本流, secret 可能泄漏, 走与 Text 相同的 redact/restore 扫描。
    ReasoningDelta(String),
    /// Anthropic `signature_delta`: thinking block 的**原生**加密签名增量 (T7)。
    /// a-origin 专用 — 同协议 a→a 由 writer **verbatim 写回** (fidelity 锚点,
    /// 绝不 envelope 重打包); 签名非明文, 不进 redact/restore 扫描 (直通)。
    SignatureDelta(String),
    /// Responses reasoning item 的 `encrypted_content` (在 `output_item.done`
    /// 整体到达, T7)。r-origin 专用 — 同协议 r→r writer verbatim 写回 done 族帧;
    /// 跨协议到 a 由 a writer 在 BlockStop 时打包进 envelope signature。
    /// 密文非明文, 不进 redact/restore 扫描 (直通)。
    ReasoningOpaqueDelta(String),
}

/// Responses 流式 reader 追踪的单个 output item 的解码状态 (key = output_index).
///
/// 设计纪律 (与 [`StreamDecodeState::tool_ir_index`] 同): **记录映射而非可重算** —
/// ir_index 分配一经随 BlockStart 发出即成为事件流的一部分, 无法事后从 wire 推回.
#[derive(Debug, Clone)]
pub enum StreamItemState {
    /// message item: 自身不发事件 (BlockStart 延迟到 content_part.added, per part,
    /// 映射在 [`ResponsesDecodeState::part_ir_index`]); 此处仅登记归属,
    /// output_item.done(message) 的兜底关闭据此判定.
    Message,
    /// function_call: BlockStart 已在 output_item.added 发出.
    /// `args_delta_seen`: 是否收到过非空 arguments delta — output_item.done 的
    /// "补发全量 arguments" 兜底判定 (从未流式过 → done item 带全量 → 补一条).
    FunctionCall {
        ir_index: usize,
        args_delta_seen: bool,
    },
    /// reasoning: BlockStart 已在 output_item.added 发出; summary/正文两种 delta
    /// 归一为 ReasoningDelta, BlockStop 在 output_item.done (reasoning 无 part 级事件).
    Reasoning { ir_index: usize },
    /// hosted tool (web_search_call/file_search_call/computer_call/mcp_call/...) 或
    /// 未知类型: 该 item 的整族事件 (added/delta/done) 全部忽略, 不进 IR.
    Dropped,
}

/// Responses 流式 reader 的解码状态 (其余协议 reader 恒为默认值, 零开销).
#[derive(Debug, Clone, Default)]
pub struct ResponsesDecodeState {
    /// 下一可用 IR block index (全局递增, 按 BlockStart 发出顺序 0,1,2,...).
    pub next_ir_index: usize,
    /// 是否已发 MessageStart (`response.created` 只处理首个, 重复/乱序忽略).
    pub started: bool,
    /// 流程中是否出现过 function_call item — `response.completed` 推断 stop_reason
    /// (ToolUse vs EndTurn) 的依据. 单独记录而非查 `items`: output_item.done 会
    /// 消费 `items` 条目, 终止事件到达时表已可能为空.
    pub saw_function_call: bool,
    /// 每个 output item 的状态 (key = output_index).
    pub items: std::collections::BTreeMap<u64, StreamItemState>,
    /// `(output_index, content_index) → ir_index` — message 的 output_text parts.
    /// 条目存在 = part 已开未关 (`content_part.done` 移除条目, 与 BlockStart 在
    /// content_part.added / BlockStop 在 content_part.done 的对称配对一致);
    /// refusal 等被跳过的 part 不登记 — 后续 delta/done 查不到映射自然忽略.
    pub part_ir_index: std::collections::BTreeMap<(u64, u64), usize>,
}

/// reader 端的流式解码状态. 用于 OpenAI flat stream 与 Responses 事件流的 block 边界合成.
///
/// Anthropic 流基本是 1:1 的 (事件自带 block index), reader 仅使用
/// [`Self::dropped_block_starts`] (跳过 block 的配对 stop, #282);
/// Responses reader 只使用 [`Self::responses`] 子状态 (事件映射表见
/// `codec::responses::stream::read_responses_stream_event` 头部).
#[derive(Debug, Clone, Default)]
pub struct StreamDecodeState {
    /// 是否已发 MessageStart.
    pub started: bool,
    /// 文本块是否已开. OpenAI flat stream 需要合成 `BlockStart{Text}`.
    pub text_block_open: bool,
    /// 文本块在 IR 中的 index (OpenAI 流里 text 与 tool_call 的相对顺序不固定,
    /// 由首次出现位置决定 index).
    pub text_index: Option<usize>,
    /// 思考块是否已开 (openai `delta.reasoning_content`, #176).
    /// 与 text_block_open 对称: flat stream 需要合成 `BlockStart{ReasoningContent}`.
    pub reasoning_block_open: bool,
    /// 思考块在 IR 中的 index.
    pub reasoning_index: Option<usize>,
    /// 已开启的 OpenAI tool_call 索引集合 (OpenAI `tool_calls[].index`).
    pub open_tools: std::collections::BTreeSet<usize>,
    /// 每个 OpenAI tool_call index 在 IR 中对应的 block index.
    /// 必须持久化记录, 不能在 finish 时 recompute — 否则 text 后到会导致 index 偏移.
    pub tool_ir_index: std::collections::BTreeMap<usize, usize>,
    /// Anthropic reader: `content_block_start` 未产出 IR BlockStart 的 block index
    /// 集合 (image 等未建模类型, 按 index 记录与类型无关; thinking 族已建模为
    /// BlockStart, T7 后离开本集合). 对应 index 的
    /// `content_block_stop` 查表同步跳过 (remove 语义, stop 后清除), 防止孤儿
    /// BlockStop 进入 IR 事件流 — 同协议 restore 模式下会直通 wire 成未配对的
    /// content_block_stop (#282). 与 translate.rs 的 `skipped_block_starts`
    /// (writer 侧机制) 是两个不同机制. 其余协议 reader 恒空, 零开销.
    pub dropped_block_starts: std::collections::BTreeSet<usize>,
    /// Responses 流式 reader 的解码状态 (其余协议恒为默认值, 零开销).
    pub responses: ResponsesDecodeState,
}

// ─── StreamEncodeState ─────────────────────────────────────────────────────

/// writer 侧流式编码状态 (与 reader 侧 [`StreamDecodeState`] 对称).
///
/// Responses writer 需要累积 block 内容以合成 done 类事件的全量 item
/// (`output_item.done` / `response.completed`); OpenAI / Anthropic writer
/// 不使用 (1 IR 事件 → 0/1 帧, 无需累积).
///
/// 生命周期: 由 caller (`StreamTranslate`) 持有, 跨事件复用, 流结束 (`finish`) 后丢弃.
#[derive(Debug, Clone, Default)]
pub struct StreamEncodeState {
    /// Responses writer 的累积状态 (其余协议保持恒空, 零开销).
    pub responses: ResponsesEncodeState,
    /// Anthropic writer 的累积状态 (T7: thinking 族 block 的 envelope 合成;
    /// 其余协议保持恒空, 零开销).
    pub anthropic: AnthropicEncodeState,
}

/// Anthropic 流式 writer 的 thinking 族 block 累积状态 (T7)。
///
/// Anthropic writer 历史上无状态 (1 IR 事件 → 0/1 帧); T7 引入唯一的累积需求:
/// 跨协议 (r|a)→a 时, 若流中未出现原生 [`IrDelta::SignatureDelta`] (a-origin 真
/// 签名), 须在 BlockStop **合成** envelope signature (`sg-thinking-v1:` 前缀,
/// 内容 = 打包整个 Reasoning block) — 此时需要该 block 的完整 thinking 文本,
/// 只能从 ReasoningDelta 累积。同协议 a→a 原生签名 verbatim 直通, 不触发合成。
///
/// 幂等契约: 与 [`ResponsesEncodeState`] 同型 — BlockStart 的探测重复调用只注册
/// 一次 (only-if-absent), delta/stop 每事件至多调用一次。
#[derive(Debug, Clone, Default)]
pub struct AnthropicEncodeState {
    /// IR block index → thinking 族累积状态 (BlockStart 注册, BlockStop 移除).
    pub thinking: std::collections::BTreeMap<usize, AnthropicThinkingAccum>,
}

/// 单个 thinking 族 block 的累积条目 (T7)。
#[derive(Debug, Clone, Default)]
pub struct AnthropicThinkingAccum {
    /// redacted_thinking (数据在 BlockStart meta 携带; stop 时不再合成 signature)。
    pub redacted: bool,
    /// ReasoningDelta 累积 (envelope 的 summary/正文来源; post-restore 内容)。
    pub text: String,
    /// ReasoningOpaqueDelta 累积 (r-origin encrypted_content, envelope 的 opaque)。
    pub opaque: Option<String>,
    /// 原生 SignatureDelta 的签名值 — **延迟到 BlockStop emit** (Anthropic wire
    /// 规范顺序: signature_delta 是 stop 前最后一个 delta; restore 滑窗的尾部
    /// flush 会在 BlockStop 前补发 thinking_delta, 提前 emit signature 会把
    /// thinking 尾巴挤到 signature 之后, 违反顺序)。
    pub native_signature: Option<String>,
}

/// Responses 流式 writer 追踪的单个 output item 的累积状态 (key = IR block index,
/// 即合成帧的 `output_index` — 一一对应, 跨协议 reasoning 跳过产生的空洞已有先例).
#[derive(Debug, Clone)]
pub struct ResponsesItemAccum {
    /// item 类型 (决定 added/done 族帧与 `response.completed` 重建的全量 item 形态).
    pub kind: ResponsesItemKind,
    /// 确定性合成的 item id (`msg_{n}` / `fc_{n}` / `rs_{n}`, n = 全局 item 序号).
    /// 确定性 (而非随机量) 是幂等契约的一半: 探测重复调用产出相同帧.
    pub item_id: String,
    /// function_call 专属: 客户端回传 `function_call_output` 的关联键 = IR ToolUse id
    /// (round-trip 保真的关键; item.id/call_id 双字段是非流式 `write_response` 先例).
    pub call_id: String,
    /// function_call 专属: 工具名.
    pub name: String,
    /// 内容累积 (BlockDelta 追加, done 族帧与 `response.completed` 读全量):
    /// message 的 output_text / reasoning 的 summary text / function_call 的
    /// arguments JSON 串 — 按 kind 单一字段, 无混合形态.
    pub content: String,
    /// reasoning item 专属 (T7): done 族帧写出的 `encrypted_content`。
    /// `Verbatim` = r-origin ([`IrDelta::ReasoningOpaqueDelta`], 同协议 fidelity
    /// 直通); `Foreign` = a-origin thinking 族 opaque ([`IrDelta::SignatureDelta`] /
    /// RedactedThinking meta), done 时打包 sg-envelope。两者由不同 origin 的
    /// reader 互斥生产; 病态共存时 **Verbatim 优先** (r writer 的 ReasoningOpaqueDelta
    /// 分支覆盖, SignatureDelta 分支不覆盖已有 Verbatim)。
    pub encrypted: Option<ResponsesEncrypted>,
}

/// [`ResponsesItemAccum::encrypted`] 的来源形态 (T7)。
#[derive(Debug, Clone)]
pub enum ResponsesEncrypted {
    /// r-origin `encrypted_content` 原文 (fidelity: 原样写回)。
    Verbatim(String),
    /// a-origin thinking 族 opaque (writer 侧打包 envelope)。
    Foreign(ThinkingOpaque),
}

/// [`ResponsesItemAccum`] 的 item 类型维度 (IR block meta → Responses item 类型).
#[derive(Debug, Clone, Copy)]
pub enum ResponsesItemKind {
    /// message item (IR Text block; content_part 级帧由 writer 合成, content_index 恒 0).
    Message,
    /// function_call item (IR ToolUse block).
    FunctionCall,
    /// reasoning item (IR ReasoningContent block, 以 summary_text 形态合成).
    Reasoning,
}

impl ResponsesItemAccum {
    /// 无 call_id/name 的 item 构造 (message / reasoning).
    pub fn simple(kind: ResponsesItemKind, item_id: String) -> Self {
        Self {
            kind,
            item_id,
            call_id: String::new(),
            name: String::new(),
            content: String::new(),
            encrypted: None,
        }
    }
}

/// Responses 流式 writer 的累积状态 (其余协议 writer 恒为默认值, 零开销).
///
/// # 幂等契约 (translate 层探测调用)
///
/// `StreamTranslate` 的跳过 block 配对过滤会对 **BlockStart** 事件调用两次 writer
/// (第一次探测 `is_empty`, 非空则丢弃帧、随后 emit 时再次调用). 因此 [`Self::items`]
/// 的注册点 (BlockStart 处理) 必须幂等: 同一 index 已存在则不重复注册/不覆盖,
/// `next_item_seq` 不重复递增 — 两次调用返回的帧因 item_id 确定性合成而完全一致.
/// 其余事件类型 (Delta/Stop/Message*) 的探测只发生在 BlockStart, writer 每事件至多
/// 调用一次; 元信息捕获仍取 "首个为准" (仅 None 时写), 对手工重复调用同样安全.
#[derive(Debug, Clone, Default)]
pub struct ResponsesEncodeState {
    /// response 元信息 (MessageStart 捕获, 首个为准). `id`/`created` 缺失时在首次
    /// 合成 response 骨架帧处隐式初始化 (synth id / now) **并写回** — 保证
    /// created 与 completed/failed 帧携带同一 id/created_at (MessageStart 缺席的
    /// 病态流也能宽容闭合).
    pub id: Option<String>,
    pub created: Option<u64>,
    pub model: Option<String>,
    /// 下一全局 item 序号 (`msg_{n}`/`fc_{n}`/`rs_{n}` 的 n, 从 0 递增).
    /// 仅在 BlockStart 注册**新** item 时递增 (幂等: 已注册 index 不递增).
    pub next_item_seq: usize,
    /// 按 IR block index (== output_index) 累积的 items. BlockStop **不移除**条目 —
    /// `response.completed` 的 output 需要全量 items 按 index 升序重建.
    pub items: std::collections::BTreeMap<usize, ResponsesItemAccum>,
    /// MessageDelta 缓存的终止信息 (终止事件合成用; "带信息的 delta 获胜" —
    /// stop_reason 仅 Some 时覆盖, usage 仅 present 或非零时覆盖, 防病态后续
    /// 全零 delta 冲掉真值). `usage_present` 由 terminal 合成消费 (present=false
    /// → usage:null, 2026-09-23 诚实化裁决 — round-trip presence 保真, 不再
    /// 伪造全零对象).
    pub stop_reason: Option<IrStopReason>,
    pub usage: IrUsage,
    pub usage_present: bool,
}

// ─── IrError ───────────────────────────────────────────────────────────────

/// codec 解析失败时返回的错误. 当前仅承载人类可读消息,
/// 由 caller 决定如何转换为 HTTP 响应.
#[derive(Debug, Clone)]
pub struct IrError {
    pub message: String,
}

impl IrError {
    pub fn new<M: Into<String>>(msg: M) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

impl std::fmt::Display for IrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for IrError {}

// ─── Helper: stop sequences 归一化 ─────────────────────────────────────────

/// 把 native stop 字段 (可能是 string 或 array) 归一化为 `Vec<String>`.
///
/// - 空字符串元素丢弃 (无意义的 stop).
/// - 缺失 / null / 其他类型返回空 Vec (== 省略).
pub fn read_stop_sequences(val: Option<&Value>) -> Vec<String> {
    match val {
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_stop_sequences_handles_string_array_empty() {
        assert_eq!(read_stop_sequences(None), Vec::<String>::new());
        assert_eq!(
            read_stop_sequences(Some(&Value::Null)),
            Vec::<String>::new()
        );
        assert_eq!(
            read_stop_sequences(Some(&serde_json::json!("stop1"))),
            vec!["stop1".to_string()]
        );
        assert_eq!(
            read_stop_sequences(Some(&serde_json::json!(["a", "b"]))),
            vec!["a".to_string(), "b".to_string()]
        );
        // 空字符串元素丢弃.
        assert_eq!(
            read_stop_sequences(Some(&serde_json::json!(["", "x", ""]))),
            vec!["x".to_string()]
        );
        // 单个空字符串视为省略.
        assert_eq!(
            read_stop_sequences(Some(&serde_json::json!(""))),
            Vec::<String>::new()
        );
    }

    #[test]
    fn ir_tool_choice_eq() {
        assert_eq!(IrToolChoice::Auto, IrToolChoice::Auto);
        assert_ne!(
            IrToolChoice::Tool { name: "x".into() },
            IrToolChoice::Tool { name: "y".into() }
        );
    }

    // ─── IrReasoning: effort ↔ budget 双向投影 (roadmap A1) ──────────────
    //
    // 投影表是三协议 reader/writer 翻译的 SSOT, 表值与 nearest 语义在此锁定.

    #[test]
    fn effort_budget_table_values_locked() {
        // roadmap A1 绝对值表 (Minimal..Max).
        assert_eq!(IrReasoningEffort::Minimal.budget_tokens(), 1024);
        assert_eq!(IrReasoningEffort::Low.budget_tokens(), 2048);
        assert_eq!(IrReasoningEffort::Medium.budget_tokens(), 4096);
        assert_eq!(IrReasoningEffort::High.budget_tokens(), 8192);
        assert_eq!(IrReasoningEffort::Xhigh.budget_tokens(), 16384);
        assert_eq!(IrReasoningEffort::Max.budget_tokens(), 32768);
    }

    #[test]
    fn nearest_budget_inverts_table_exactly() {
        // 表值精确命中 → 无损 (effort → budget → effort 恒等).
        for e in [
            IrReasoningEffort::Minimal,
            IrReasoningEffort::Low,
            IrReasoningEffort::Medium,
            IrReasoningEffort::High,
            IrReasoningEffort::Xhigh,
            IrReasoningEffort::Max,
        ] {
            assert_eq!(IrReasoningEffort::nearest_budget(e.budget_tokens()), e);
        }
    }

    #[test]
    fn nearest_budget_midpoints_and_ties() {
        // 区间中点归较高档 (平局裁决: 1536 距 1024/2048 等距 → Low).
        assert_eq!(
            IrReasoningEffort::nearest_budget(1536),
            IrReasoningEffort::Low
        );
        assert_eq!(
            IrReasoningEffort::nearest_budget(3072),
            IrReasoningEffort::Medium
        );
        // 边界内采样.
        assert_eq!(
            IrReasoningEffort::nearest_budget(1),
            IrReasoningEffort::Minimal
        );
        assert_eq!(
            IrReasoningEffort::nearest_budget(10000),
            IrReasoningEffort::High
        );
        assert_eq!(
            IrReasoningEffort::nearest_budget(u32::MAX),
            IrReasoningEffort::Max
        );
    }

    #[test]
    fn effort_parse_round_trips_and_rejects_unknown() {
        for e in [
            IrReasoningEffort::Minimal,
            IrReasoningEffort::Low,
            IrReasoningEffort::Medium,
            IrReasoningEffort::High,
            IrReasoningEffort::Xhigh,
            IrReasoningEffort::Max,
        ] {
            assert_eq!(IrReasoningEffort::parse(e.as_str()), Some(e));
        }
        // 未知档位 None (ROB-1), 不 panic.
        assert_eq!(IrReasoningEffort::parse("banana"), None);
        assert_eq!(IrReasoningEffort::parse(""), None);
    }

    #[test]
    fn reasoning_to_effort_projection() {
        use IrReasoning::*;
        assert_eq!(
            Effort(IrReasoningEffort::High).to_effort(),
            Some(IrReasoningEffort::High)
        );
        // Budget → nearest (10000 → High, 距 8192 近).
        assert_eq!(Budget(10000).to_effort(), Some(IrReasoningEffort::High));
        assert_eq!(Budget(0).to_effort(), Some(IrReasoningEffort::Minimal));
        // Adaptive → Medium 默认档; Disabled → None (OpenAI 无关闭字段).
        assert_eq!(Adaptive.to_effort(), Some(IrReasoningEffort::Medium));
        assert_eq!(Disabled.to_effort(), None);
    }

    // ─── IrUsage::is_zero ──────────────────────────────────────────────
    //
    // is_zero 是多个决策点的 SSOT (openai_writer 决定是否附 usage、StreamTranslate
    // post-stop guard 决定是否放行 MessageDelta). 任何字段非零都应返回 false.
    // 新增字段时只需更新 is_zero 方法本身, 这些测试自动覆盖回归.

    #[test]
    fn ir_usage_is_zero_when_all_fields_zero() {
        // 全零 (含 None cache 字段) → true.
        assert!(IrUsage::zero().is_zero());
        assert!(IrUsage::default().is_zero());
    }

    #[test]
    fn ir_usage_is_zero_when_cache_fields_are_none() {
        // 显式 None 的 cache 字段也算零.
        assert!(
            IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            }
            .is_zero()
        );
    }

    #[test]
    fn ir_usage_is_nonzero_when_input_tokens_nonzero() {
        let u = IrUsage {
            input_tokens: 1,
            ..Default::default()
        };
        assert!(!u.is_zero());
    }

    #[test]
    fn ir_usage_is_nonzero_when_output_tokens_nonzero() {
        let u = IrUsage {
            output_tokens: 1,
            ..Default::default()
        };
        assert!(!u.is_zero());
    }

    #[test]
    fn ir_usage_is_nonzero_when_cache_read_input_tokens_nonzero() {
        let u = IrUsage {
            cache_read_input_tokens: Some(1),
            ..Default::default()
        };
        assert!(!u.is_zero());
    }

    #[test]
    fn ir_usage_is_nonzero_when_cache_creation_input_tokens_nonzero() {
        let u = IrUsage {
            cache_creation_input_tokens: Some(1),
            ..Default::default()
        };
        assert!(!u.is_zero());
    }

    // ─── IrUsage::openai_usage_json: cache 归类 (#284) ──────────────────
    //
    // B3b 回归: cache_read 经 prompt_tokens_details.cached_tokens 上 wire;
    // 总和口径由 openai_prompt_tokens SSOT 保证 (对照断言).

    #[test]
    fn openai_usage_json_writes_cached_tokens_details() {
        let u = IrUsage {
            input_tokens: 100,
            output_tokens: 10,
            cache_read_input_tokens: Some(50),
            cache_creation_input_tokens: Some(30),
        };
        let v = u.openai_usage_json();
        assert_eq!(v.get("prompt_tokens"), Some(&json!(180)));
        assert_eq!(
            v.get("prompt_tokens_details")
                .and_then(|d| d.get("cached_tokens")),
            Some(&json!(50)),
            "缺 prompt_tokens_details.cached_tokens (cache_read 不上 wire)"
        );
    }
}
