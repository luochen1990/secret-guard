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

use serde_json::{Value, json};

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
    /// 最大输出 token 数. OpenAI 可选, Anthropic 必填.
    pub max_tokens: Option<u32>,
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
        for m in &mut self.messages {
            m.content_form = None;
            m.reasoning_content_form = None;
            for b in &mut m.content {
                if let IrBlock::ToolResult { content_form, .. } = b {
                    *content_form = None;
                }
            }
        }
    }
}

/// 单条对话消息.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IrMessage {
    pub role: IrRole,
    pub content: Vec<IrBlock>,
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
        .any(|b| matches!(b, IrBlock::Text { text } if !text.is_empty()))
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
#[derive(Debug, Clone, PartialEq)]
pub enum IrBlock {
    /// 文本块.
    Text { text: String },
    /// 工具调用 (assistant 发起).
    /// `id` 必须 verbatim 透传, 否则下一轮 tool_result 引用断裂.
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    /// 工具结果 (user 回复 assistant 的 ToolUse).
    /// OpenAI 用独立 `role:"tool"` 消息承载; Anthropic 用 user 消息内的 tool_result 块.
    ToolResult {
        tool_use_id: String,
        content: Vec<IrBlock>,
        is_error: bool,
        /// wire 形态元数据: Anthropic tool_result.content 可能是 string 或 array.
        /// OpenAI 的 tool message content 永远是 string, 此字段 None.
        /// 同协议 round-trip 时填充, 跨协议翻译前清空.
        content_form: Option<ContentForm>,
    },
    /// 图片块. 跨协议唯一无歧义形式是 Base64; URL 引用也保留.
    Image { source: IrImageSource },
    /// 推理块 (Responses API 的 `reasoning` output item).
    ///
    /// 仅承载 `summary` 文本数组 (可被 Redact 扫描是否有 secret 子串).
    /// `encrypted_content` 是 provider-specific opaque blob, **当前实现不保留**
    /// (同协议 round-trip 也会丢失); 这会破坏依赖 reasoning chain 的链式调用
    /// (如 `previous_response_id` + reasoning context compression). 这是已知限制.
    Reasoning { summary: Vec<String> },
    /// 思考原文块 (OpenAI Chat 兼容 provider 的 `reasoning_content` 字段,
    /// 思考型模型如 glm / deepseek-r1 的思考阶段原文).
    ///
    /// 与 [`IrBlock::Reasoning`] 的区别: 后者是 Responses API 的**摘要列表**
    /// (`summary_text[]`), 本块是思考**原文连续文本** (非流式 message 字段 /
    /// 流式 ReasoningDelta 累积). 两者语义不同, 不合并 (#176).
    ///
    /// Redact 覆盖: `text` 是 IR 字符串叶子 (secret 可能泄漏进思考流).
    /// 跨协议: Anthropic writer 跳过 (thinking block 需要 signature, 无法合法
    /// 合成); Responses writer 跳过 (reasoning item 依赖 encrypted_content).
    ReasoningContent { text: String },
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

    /// 序列化为 OpenAI wire 格式的 `usage` 对象 (`{prompt_tokens, completion_tokens, total_tokens}`).
    ///
    /// 单一事实来源: 非流式响应与流式 MessageDelta 都用同一个 wire 形态,
    /// 集中在此避免两处手写 JSON shape (新增字段如 `prompt_tokens_details` 时只改一处).
    pub fn openai_usage_json(&self) -> Value {
        let prompt_tokens = self.openai_prompt_tokens();
        json!({
            "prompt_tokens": prompt_tokens,
            "completion_tokens": self.output_tokens,
            "total_tokens": prompt_tokens.saturating_add(self.output_tokens),
        })
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
    ReasoningContent,
}

/// 内容块增量 (BlockDelta 携带).
#[derive(Debug, Clone, PartialEq)]
pub enum IrDelta {
    /// 文本增量.
    TextDelta(String),
    /// 工具调用参数的 JSON 片段 (流式 partial JSON).
    InputJsonDelta(String),
    /// 思考原文增量 (OpenAI 兼容流式 `delta.reasoning_content`). #176.
    ReasoningDelta(String),
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
/// Anthropic 流是 1:1 的 (事件自带 block index), 顶层字段在 Anthropic reader 中不使用;
/// Responses reader 只使用 [`Self::responses`] 子状态 (事件映射表见
/// `codec::responses::read_responses_stream_event` 头部).
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
}

/// Responses 流式 writer 的累积状态 (内容由 T3 填充; 本任务只立骨架).
#[derive(Debug, Clone, Default)]
pub struct ResponsesEncodeState {
    // T3 将添加: response 元信息 / items 累积 / 终止缓存
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
}
