# IR 字段建模路线图

> **本文件是 SSOT**: 定义 secret-guard IR 如何建模跨协议字段, 以及 `extra` 字段的职责边界.
> 所有 codec 字段提升 / 新增 / 变更的 PR 必须引用本文件.
>
> **维护纪律**: 每次协议官方文档更新或新增协议时, 必须同步更新本文件的"字段全景表";
> 每次字段提升实施后, 必须更新"实施进度"章节.

## 0. 文档定位与读者

- **读者 scope**: 任何修改 `IrRequest` / `IrResponse` / `IrBlock` 字段的人、考虑"某字段该进 first-class 还是 extra"的人、排定 codec 工作优先级的人。
- **不是读者**: 终端用户 (用户文档在 README); WebUI 开发者 (本文件不涉及展示层); 只读 codec 现有契约的人 (去 `src/codec/AGENTS.md`)。
- **与其它文档的关系**: 本文件是 `src/codec/AGENTS.md` "wire fidelity" 段的**前置依赖** — AGENTS.md 讲当前 IR 的契约, 本文件讲 IR 的演进路线与字段归属判定。
- **可发现性 hook**: 根 `AGENTS.md` 模块概览表的 `codec/` 行 + `src/codec/AGENTS.md` "当前覆盖与搁置"段。改 codec IR 时, 这两处会把你导向本文件。

## 1. 问题陈述

### 1.1 现状

secret-guard 的 IR (中间表示) 有一个 `extra: Map<String, Value>` 字段作为"未建模字段的逃生舱".
当前 extra 承载了 **24 个顶层字段** (基于官方文档对照, 见 §3 字段全景表).

**问题**: 其中至少 12 个字段在跨协议翻译时会**静默丢失** (因为 `cross_proto_forward` 会 `ir.extra.clear()`),
而这些字段在目标协议里其实有语义对应 — 它们不是"协议特有", 而是"跨协议通用但形态各异".
典型例子: `response_format` (OpenAI 顶层 vs Anthropic `output_config.format`)、
`reasoning_effort` (OpenAI 顶层 vs Anthropic `thinking.budget_tokens`).

### 1.2 目标

1. **把跨协议通用字段提升为 IR first-class 字段**, 让它们能精确转换而非静默丢失.
2. **把 `extra` 的职责收敛为"仅承载真正协议特有的字段"**, 并在契约里讲清楚边界.
3. **建立可机械验证的判定准则**, 让未来新增协议字段时有明确的归属决策依据, 不再依赖主观判断.

### 1.3 非目标

- 不追求"100% 字节级 wire fidelity" — 同协议路径已 byte-exact 短路, 跨协议路径接受
  "normalize_json 相等" (见 FWD-1 契约).
- 不覆盖 message 内部 content block 的建模 (IrBlock 的 Text / ToolUse / ToolResult 已有, 不在本次范围).
- 不实现新的 codec 协议 (Gemini / Ollama 等仍是后续工作).

## 2. 判定准则 (机械化, SSOT)

> **这一节是核心** — 任何"某字段该不该 first-class"的讨论都以本节准则为准绳.

### 2.1 一条铁律

来自 Busbar 源码注释 (`crates/busbar/src/ir/mod.rs`, `top_p` 字段附近), 经 5 个独立项目验证 (见 §5 调研结论):

> **如果一个字段在跨协议时应该 TRANSLATE (翻译到目标协议的 native 形态), 它就必须是 first-class typed 字段;
> 否则它会在跨协议 hop 上被静默丢弃.**
>
> **extra 只承载源协议特有、无跨协议映射的字段.**

实现机制: `cross_proto_forward` 在跨协议 seam 上 `ir.extra.clear()`.
所以"放 extra 的字段跨协议时被丢"不是 bug, 是**设计** — extra 的契约就是"same-proto 透传, 跨协议清空".

### 2.2 三步判定流程

对每个待决策字段, 依次回答:

1. **该字段是否在 ≥2 个协议中存在?** (官方文档对照, 见 §3)
   - 是 → 进入步骤 2
   - 否 (仅 1 个协议有) → **归 extra** (协议特有)

2. **该字段在目标协议中是否有语义对应?** (即使形态不同)
   - 是 → **必须 first-class** (跨协议应 translate)
   - 否 → **归 extra** (源特有, 跨协议时该丢)

3. **该字段的归一化方向是否明确?** (数值归一 / 枚举映射 / 形态变换)
   - 明确 → 进入实施 (写 reader/writer + 测试)
   - 不明确 → 暂留 extra, 标记为"待归一化设计", 进 §7 待办清单

### 2.3 典型应用

| 字段 | 步骤1 (≥2 协议) | 步骤2 (语义对应) | 步骤3 (归一化) | 判定 |
|---|---|---|---|---|
| `response_format` | OpenAI Chat + Responses + Anthropic (`output_config.format`) | ✓ | text / json_schema / json_object 三态 enum | **first-class** |
| `reasoning_effort` | OpenAI Chat (`reasoning_effort`) + Responses (`reasoning.effort`) + Anthropic (`thinking.budget_tokens`) | ✓ | effort enum ↔ budget_tokens 数值表 | **first-class** |
| `service_tier` | OpenAI (6 档) + Anthropic (2 档) | ✓ | enum + 降级 (Anthropic 无 flex/scale 时降级 auto) | **first-class** |
| `seed` | 仅 OpenAI Chat (Responses 无此字段, 经官方文档核实) | ✗ | — | **extra** (协议特有) |
| `stream_options` | OpenAI Chat + Responses (Anthropic 用 `stream: bool` 替代) | 部分 (行为等价, 见 §6.A4) | OpenAI 特有结构, Anthropic 默认行为等价 | **first-class** (派生字段, 详见 §6.A4) |
| `audio` | OpenAI 独有 | ✗ | 无 | **extra** (协议特有) |
| `web_search_options` | OpenAI Chat 独有 (hosted tool) | ✗ | 跨协议时本来就应丢弃 (Responses codec 已实现) | **extra** (协议特有) |

### 2.4 边界纪律: first-class 与 provider-specific 共存不合并

> 来自 Vercel AI SDK V4 的设计经验.

把字段提升为 first-class 后, **对应的 provider-specific 形态应在 extra 里保留**, 不要试图消灭.

理由: provider-specific 形态常携带比 first-class 更细的控制 (如 Anthropic `thinking.budget_tokens` 可精确到任意数值,
而 first-class `reasoning_effort` 只有 6 档枚举). writer 应**优先读 provider-specific (extra), 否则 fallback 到 first-class**.

错误做法: 把 `thinking` 提升为 first-class 后, 在 Anthropic reader 里把 `thinking` 从 known 列表删除 → 精细控制丢失.
正确做法: `thinking` 保留在 extra, reader 同时填 first-class (effort enum) + extra (原始 thinking object), writer 优先读 extra.

## 3. 字段全景表 (基于官方文档)

> **数据来源**: OpenAI Chat Completions / Anthropic Messages / OpenAI Responses 三家官方 API reference
> (2026-08-05 抓取, 完整 body parameters 段, 无截断).
> 字段总数: OpenAI Chat 35 / Anthropic 18 / Responses 31.
> 原始提取见 `/tmp/opencode/ir-research/sources/protocol-fields-extracted.md` (此文件为临时调研产物, 不进仓库).

### 3.1 字段分类汇总

按 §2.2 准则判定后, 字段分三类:

- **类别 A — 跨协议通用, 应 first-class** (共 10 项): 在 ≥2 协议有语义对应
- **类别 B — 协议特有, 归 extra** (共 21 项): 仅 1 协议有, 或跨协议时该丢弃
- **当前已 first-class** (共 15 项): IR 现状已正确建模, 不需变动

> **计数口径**: 类别按"语义字段"计数, 合并 same-protocol 的 deprecated 别名 (如 `max_tokens` + `max_completion_tokens` + `max_output_tokens` 算 1 项 first-class); §3.3 表格里同行多字段 (如 `conversation`/`previous_response_id`) 按独立字段计.

### 3.2 类别 A: 跨协议通用字段 (提升目标, 优先级排序)

> 优先级 = 使用频率 (真实数据 + 测试 fixture) × 跨协议损失风险.
> 使用频率数据见 §4, 来源 `/tmp/opencode/ir-research/sources/field-usage-stats.md`.

| # | 语义 | OpenAI Chat | Anthropic | OpenAI Responses | 真实用量 | fixture | 优先级 | 备注 |
|---|---|---|---|---|---:|---:|:-:|---|
| A1 | **reasoning 配置** | `reasoning_effort: enum` | `thinking: {budget_tokens, type, display}` | `reasoning: {effort, ...}` | 94% (thinking) + 2% (effort) | 0 | **P0** | 真实用量最高, Busbar/Vercel/OpenRouter 一致推荐优先; 归一化:`IrReasoning::{Effort, Budget, Dynamic}` typed enum + budget 表 |
| A2 | **response_format / 结构化输出** | `response_format: {type, json_schema?}` | `output_config.format: {schema, type}` | `text.format: {schema, type}` | 0% | 0 | **P1** | 三协议都有, Busbar 注释明确说该字段曾是 "Value→每 writer 修一次 bug" 的重灾区; 归一化:`IrResponseFormat::{Text, JsonSchema, JsonObject}` typed enum |
| A3 | **service_tier** | `service_tier: enum(6档)` | `service_tier: enum(2档)` | 同 Chat | 0% | 0 | **P1** | 两协议都有, 枚举值不对等需要降级映射 (Anthropic 无 flex/scale → auto); 简单 enum |
| A4 | **stream_options.include_usage** | `stream_options: {include_usage}` | (Anthropic 流式默认带 usage) | `stream_options: {include_obfuscation}` | 96% | 0 | **P1** | 真实用量第二高. **归类别 A 但实施形态特殊**: 目标协议 (Anthropic) 无对应字段, 但有"默认行为等价"的对应 — Anthropic 流式天然带 usage. 详见 §6.A4 |
| A5 | **frequency_penalty** | `frequency_penalty: number` | (Anthropic 不支持) | (不支持) | 0% | 0 | P2 | 仅 OpenAI Chat 有, 但跨协议时"明确告警丢弃"比静默丢好. 边界 case, 见 §6.A5 |
| A6 | **presence_penalty** | `presence_penalty: number` | (不支持) | (不支持) | 0% | 0 | P2 | 同 A5 |
| A7 | **logprobs / top_logprobs** | `logprobs: bool` + `top_logprobs: n` | (不支持) | 顶层 `top_logprobs: n` + `include: ["message.output_text.logprobs"]` | 0% | 0 | P2 | 跨协议语义弱对应, OpenAI 内部两协议形态都不同 |
| A8 | **prompt cache 控制** | `prompt_cache_options: {mode, ttl}` | `cache_control: {type, ttl}` | 同 Chat | 0% | 0 | P3 | 两协议都有但语义形态差异大 (block 级 vs request 级), 归一化设计复杂 |
| A9 | **metadata** | `metadata: map(16)` | `metadata: {user_id}` | `metadata: map(16)` | 0% | 0 | P3 | OpenAI 是任意 KV, Anthropic 仅 user_id; 当前 Anthropic 已把 user_id 映射到 IR `user`, OpenAI 的 metadata map 应进 extra |
| A10 | **user / safety_identifier** | `user` (deprecated) / `safety_identifier` | `metadata.user_id` | 同 Chat | 0% | 0 | P3 | `user` 已 first-class, 但 `safety_identifier` 是新名字; 评估是否改 IR 字段名 |

**移到类别 B (经准则核实不满足 ≥2 协议)**:

- `seed`: **仅 OpenAI Chat** (Responses 无此字段, 经官方文档核实) → 归 extra, 不提升
- `n`: **仅 OpenAI Chat** (Anthropic/Responses 均无) → 归 extra

### 3.3 类别 B: 协议特有字段 (归 extra, 不提升)

> 这些字段在跨协议翻译时**应该被丢弃**, extra 是它们的正确归宿.
> 判定依据: 步骤 2 "目标协议无语义对应" 成立.

| 字段 | 协议 | 为什么特有 |
|---|---|---|
| `audio` | OpenAI Chat | 音频输出 (modalities 含 audio 时), Anthropic 无音频 |
| `modalities` | OpenAI Chat | 输出类型选择 (text/audio), Anthropic 无 |
| `prediction` | OpenAI Chat | 静态预测输出加速, Anthropic 无对应 |
| `store` | OpenAI Chat + Responses | OpenAI 的模型蒸馏/evals 存储, Anthropic 无 |
| `verbosity` | OpenAI Chat (顶层) + Responses (`text.verbosity`) | 响应冗长度, Anthropic 用 thinking 部分覆盖但不对应 |
| `moderation` | OpenAI Chat + Responses | OpenAI 内容审核, Anthropic 用独立 API |
| `web_search_options` | OpenAI Chat | hosted tool, Responses codec 已实现丢弃逻辑 |
| `container` | Anthropic | Claude 代码执行容器, OpenAI 用 code_interpreter (不同实现) |
| `inference_geo` | Anthropic | 推理地理区域, OpenAI 用 service_tier 但语义不同 |
| `seed` | OpenAI Chat | beta 确定性采样, Anthropic/Responses 均无 (经官方文档核实) |
| `n` | OpenAI Chat | 候选数, Anthropic/Responses 均无 |
| `background` | Responses | 后台运行, 另两协议无 |
| `conversation` | Responses | 服务端会话状态, secret-guard 是 stateless 代理本来就应丢弃 |
| `previous_response_id` | Responses | 服务端会话状态, 同上 |
| `include` | Responses | 输出包含项, 另两协议用独立字段 |
| `instructions` | Responses | 已映射到 IR `system` (虽 Responses 独有但已有 first-class 对应) |
| `max_tool_calls` | Responses | 内置工具调用上限, 另两协议无 |
| `text` (含 format/verbosity) | Responses | 已被 A2 (format) + 部分 extra 覆盖 |
| `truncation` | Responses | 上下文截断策略, 另两协议无 |
| `context_management` | Responses | 上下文压缩配置, 另两协议无 |
| `prompt` (模板引用) | Responses | prompt 模板系统, 另两协议无 |
| `function_call` | OpenAI Chat (deprecated) | 已被 tools 取代, 不需建模 |
| `functions` | OpenAI Chat (deprecated) | 已被 tools 取代, 不需建模 |

### 3.4 当前已 first-class (无需变动)

`model`, `messages`/`input`, `system`/`instructions`, `tools`, `max_tokens`/`max_completion_tokens`/`max_output_tokens`,
`temperature`, `top_p`, `top_k`, `stop`/`stop_sequences`, `tool_choice`, `parallel_tool_calls`/`disable_parallel_tool_use`,
`user` (部分), `stream`.

共 15 个语义槽位, IR 现状已正确建模.

## 4. 使用频率数据 (优先级依据)

> 来源: 真实运行服务 (10 sessions / 54 records, 100% OpenAI 协议) + 测试 fixture 扫描 (16 个 .rs 文件).
> 完整数据见 `/tmp/opencode/ir-research/sources/field-usage-stats.md`.

### 4.1 真实数据 top (54 records)

| 频次 | 字段 | 占比 | 当前状态 |
|---:|---|---:|---|
| 54 | `messages`, `model` | 100% | 已 first-class |
| 52 | `max_tokens`, `stream` | 96% | 已 first-class |
| 52 | `stream_options` | 96% | **extra** (A4, P1) |
| 51 | `thinking` | 94% | **extra** (A1, P0) |
| 51 | `tool_choice`, `tools` | 94% | 已 first-class |
| 3 | `temperature` | 6% | 已 first-class |
| 1 | `reasoning_effort` | 2% | **extra** (A1, P0) |

### 4.2 fixture 覆盖盲区

测试 fixture 中**完全未出现**的 extra 字段 (26 个):
`seed`, `n`, `frequency_penalty`, `presence_penalty`, `logit_bias`, `top_logprobs`,
`response_format`, `service_tier`, `reasoning_effort`, `thinking`,
`stream_options`, `prompt_cache_options`, `prompt_cache_key`, `cache_control`,
`user`, `metadata`, `top_p`, `stop_sequences`, `parallel_tool_calls`,
`modalities`, `audio`, `prediction`, `store`, `verbosity`, `moderation`, `web_search_options`.

**结论**: 现有测试对 extra 字段几乎零覆盖. 任何字段提升都必须**同时补 property test 生成器**,
否则提升本身无法验证.

### 4.3 数据局限性声明

- 真实数据 100% 是 OpenAI 协议, Anthropic/Responses 实际使用频次**无样本** (低置信).
- 真实数据来自单一用户 (lc), 不能代表所有用户场景.
- fixture 统计基于当前测试集, 测试本身有盲区 (如 thinking 没测不等于不重要, 真实 94% 说明它很重要).

## 5. 前人工作调研结论 (字段建模策略验证)

> 完整调研报告见临时文件 `/tmp/opencode/ir-research/sources/` (不进仓库, 关键结论已合并到本文件).
> 调研覆盖 5 个项目: Busbar / LiteLLM / Vercel AI SDK / new-api / OpenRouter.

### 5.1 核心结论: secret-guard 同源的 Busbar 已经把这件事做完了

secret-guard 的 IR 借鉴自 Busbar, 而 Busbar **本身已经把类别 A 中的多数字段提升为 typed first-class**
(基于调研报告: seed / n / frequency_penalty / presence_penalty / logprobs / top_logprobs / response_format / reasoning_effort / stop 都 first-class,
只有 service_tier 和 stream_options 落 extra; 计数口径与 secret-guard 类别 A 不完全 1:1 对应, 因 Busbar 覆盖更多协议).

> **置信度声明**: 这条结论是高置信 (Busbar 源码直接摘录), 但"Busbar first-class 数量"基于调研报告的归纳,
> 未逐字段核对 Busbar 的 `crates/busbar/src/ir/mod.rs` 原文. 实施批次 1 (reasoning) 时应 webfetch Busbar 源码做最终核对.

更关键: Busbar 的每个 typed 字段都有注释记录"以前是 Value/String, 每个 writer 踩过一次 bug, typing 后消灭该 bug 类".
**这些注释是我们即将走的路的现成地图**.

Busbar `IrResponseFormat` 注释直接原文 (摘自 `crates/busbar/src/ir/mod.rs`):

> "THE SMELL THIS REMOVES: `IrRequest.response_format` used to be an opaque `serde_json::Value`...
> Each writer then re-sniffed that blob and the lazy default was to ECHO it; correct same-protocol,
> but cross-protocol that emits a FOREIGN shape the backend 400s.
> **The identical bug surfaced once per writer (openai → cohere → gemini → responses)** because the field was never canonicalized on the way IN."

### 5.2 五个项目的共识 (多源验证, 注意置信度差异)

> **置信度说明**: Busbar / LiteLLM / Vercel / new-api 是源码级验证 (高置信);
> **OpenRouter 实现闭源**, 共识基于官方文档逆推 (中置信). 下表"共识项目数"列区分源码 vs 文档.

| 设计要点 | 共识项目数 (源码 / 总) | 说明 |
|---|:-:|---|
| typed enum + exhaustive match 是消灭"echo foreign shape" bug 类的根本手段 | 4 源码 / 5 总 (Busbar / Vercel / new-api / OpenRouter) | stop_reason / tool_choice / response_format 都应 typed 化 |
| reasoning 字段必须 first-class 且要同时容纳 effort + budget_tokens 两种风格 | 4 源码 / 5 总 (全部, OpenRouter 文档逆推) | 唯一一个所有项目都做了专门抽象的字段 |
| superset IR 优于 common subset | 3 源码 (Busbar / new-api / OpenRouter 文档) | OpenAI 为 lingua franca 的策略 (LiteLLM/Vercel) 在跨协议时丢字段多 |
| first-class 与 provider-specific 共存不合并 | 1 源码 (Vercel, 但设计纪律强) | 提升后不要消灭 extra 里对应 provider-specific 形态 |

### 5.3 反面教材 (new-api)

new-api 的字段丢失 bug **反复出现**: issue #6614 (frequency/presence_penalty) / #6615 (tool_calls 文本) / #6603 (reasoning_content).
根因: struct field 声明 + N 个转换器手动写 + golden fixture 单一. **我们必须避免**:
- 不能只加 struct field 不写转换逻辑 (会静默丢)
- 不能靠单一 fixture 测试 (要 property-based 生成器覆盖所有 first-class 字段)

## 6. 字段提升设计方案 (按优先级)

> 每个字段的设计包含: IR 字段类型定义、三协议 reader 解析规则、三协议 writer 序列化规则、跨协议归一化语义、
> property test 守卫设计、与 extra 共存策略.
>
> **本节是实施时的契约, PR review 时逐项核对.**

### A1 — reasoning 配置 (P0, 真实用量 94%+2%, 最高优先级)

**归一化设计** (直接抄 Busbar `IrReasoningAsk`):

```rust
/// reasoning 配置的协议无关表示.
/// 归一化三协议的两种 API 风格: "档位 (effort)" vs "精确预算 (budget_tokens)".
#[derive(Debug, Clone, PartialEq)]
pub enum IrReasoning {
    /// 关闭 reasoning (Anthropic `thinking: {type: "disabled"}`)
    Disabled,
    /// 档位模式 (OpenAI `reasoning_effort: "low"|"medium"|...`, Responses `reasoning.effort`)
    Effort(IrReasoningEffort),
    /// 精确预算模式 (Anthropic `thinking: {type: "enabled", budget_tokens: N}`)
    Budget(u32),
    /// 自适应 (Anthropic `thinking: {type: "adaptive"}`)
    Adaptive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrReasoningEffort {
    Minimal, Low, Medium, High, Xhigh, Max,
}
```

**双向投影表** (effort ↔ budget, 抄 Busbar `reasoning_budgets: [u32; 4]`, 扩展到 6 档):

| Effort | budget_tokens 默认 (max_tokens=4096 时) |
|---|---|
| Minimal | 1024 |
| Low | 2048 |
| Medium | 4096 |
| High | 8192 |
| Xhigh | 16384 |
| Max | 32768 |

注: budget_tokens 是绝对值, 与 max_tokens 无关 (Anthropic 要求 budget < max_tokens, writer 需保证).
OpenRouter 用 ratio 公式 (max_tokens × 0.1/0.2/0.5/0.8/0.95), 自适应 max_tokens.
**初版用绝对值表** (简单), 后续如真实场景需要再切 ratio.

**reader 规则**:
- OpenAI Chat: 读 `reasoning_effort: string` → `Effort(IrReasoningEffort::from_str)`
- Responses: 读 `reasoning.effort: string` → 同上; 若 `reasoning.summary` 存在, 暂存 extra
- Anthropic: 读 `thinking: {type, budget_tokens?, display?}` → `Disabled` / `Budget(n)` / `Adaptive`

**writer 规则**:
- OpenAI Chat: 写 `reasoning_effort: "low"|"medium"|...` (Budget 反查表 → nearest effort; Adaptive → 默认 Medium)
- Responses: 写 `reasoning: {effort: ...}` (同上)
- Anthropic: 写 `thinking: {type: "enabled", budget_tokens: N}` (Effort 查表 → budget; Adaptive → `{type:"adaptive"}`)

**property test 守卫**:
- 新增 `arb_ir_reasoning()` 生成器覆盖 4 个 variant (Disabled / Effort / Budget / Adaptive) × 6 个 effort 档位 (Minimal..Max)
- `fwd_property.rs` 加 round-trip test: `normalize(reasoning_effort wire) == normalize(writer(reader(wire)))`
- 跨协议 golden: OpenAI `reasoning_effort: "high"` → Anthropic `thinking: {type:"enabled", budget_tokens: 8192}` → 回 OpenAI 应得 `reasoning_effort: "high"`

**与 extra 共存**: 提升后, Anthropic reader 的 known 列表**仍保留 `thinking`** (拿原始 object 进 extra), 让用户保留 `display` 字段等 first-class 不覆盖的精细控制. writer 优先读 first-class, extra 只用于回写 same-proto round-trip.

**已知限制**: OpenAI `reasoning_effort: "max"` 在 Anthropic 侧 budget 表只到 32768, 可能不够; 真实场景按 ratio 更准, 后续优化.

### A2 — response_format (P1, 三协议都有, Busbar 重灾区)

**归一化设计** (抄 Busbar `IrResponseFormat`):

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum IrResponseFormat {
    /// 默认文本格式 (OpenAI `{type:"text"}`, Anthropic 无显式字段)
    Text,
    /// JSON Schema 结构化输出
    JsonSchema { name: String, schema: Value, strict: Option<bool> },
    /// JSON object 模式 (旧式, 推荐 JsonSchema 替代)
    JsonObject,
}
```

**reader / writer 规则**:
- OpenAI Chat: 读 `response_format: {type, json_schema?}` / 写同
- Responses: 读 `text.format: {type, schema?}` / 写 `text: {format: ...}`
- Anthropic: 读 `output_config.format: {type:"json_schema", schema}` / 写 `output_config: {format: ...}`; `Text` 不写字段 (默认)

**property test**: round-trip OpenAI/Anthropic/Responses 各自 + 跨协议 golden (JsonSchema 三协议应能 round-trip).

**已知限制**: OpenAI 的 `name`/`description`/`strict` 子字段在 Anthropic/Responses 侧可能无对应, 暂存 extra 或 drop.

### A3 — service_tier (P1, 简单 enum)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrServiceTier {
    Auto, Default, Flex, Scale, Priority, Fast,
    // Anthropic 仅支持 Auto / StandardOnly, 映射: StandardOnly → Default
    StandardOnly,
}
```

**降级规则**: 跨协议时若目标协议不支持某档位, 降级到 `Auto` + emit warning (而非静默丢).

### A4 — stream_options (P1, 真实用量 96%, 边界 case)

**特殊性**: OpenAI Chat/Responses 有此字段, Anthropic 无 (用 `stream: bool` 替代).
按 §2.2 严格判定似乎应归 extra (步骤 2 不满足: Anthropic 无语义对应字段).
**但**有一个关键事实让这个字段成为类别 A 的合法成员: Anthropic 流式响应**天然默认带 usage 事件** (`message_delta` 事件总是包含 usage),
即"Anthropic 没有开关字段"等价于"OpenAI `stream_options.include_usage: true`".

**判定**: 类别 A, 但归一化不是"字段翻译"而是"行为等价" —
`include_usage: true` 在 Anthropic 侧的等价物是"什么都不做 (默认行为已满足)".
跨协议时若 OpenAI 客户端发 `include_usage: true` 翻译到 Anthropic, 不丢字段而是确认默认行为匹配.

**实施**: 在 `IrRequest` 加 first-class 派生字段 `expected_usage_in_stream: bool`
(从 OpenAI `stream_options.include_usage` 派生). 该字段不影响 writer 输出 (因 Anthropic 默认就带 usage),
但**让跨协议路径显式记录"客户端期望流末 usage"这个语义**, 让未来如果 Anthropic 改变默认行为时能被测试抓到.

**与 extra 共存**: `stream_options` 原始对象仍进 extra (保留 OpenAI 特有的 `include_obfuscation` 子字段),
reader 同时填 `expected_usage_in_stream` 派生字段.

**为何这是类别 A 而非 extra**: 准则 §2.2 步骤 2 问的是"目标协议是否有语义对应", Anthropic 的"默认带 usage 行为"就是一种语义对应 (虽然没有显式字段). 严格的"必须有字段"判定会漏掉这类行为等价场景. 这是准则的已知边界, A4 是先例案例.

### A5/A6 — frequency_penalty / presence_penalty (P2)

**边界判定**: 仅 OpenAI Chat 有, Anthropic/Responses 都不支持. 按 §2.2 严格判定归 extra.
**但**: Busbar 把它们 first-class 了, 理由是"明确告警丢弃比静默丢好".

**决策**: **暂留 extra**, 加 warning 机制. 跨协议翻译时若 extra 含这两个字段, emit warning 给客户端 (而非静默 clear).
等真实用户场景出现频繁跨协议丢这两个字段时再提升.

### A7 — logprobs (P2, 跨协议语义弱)

仅 OpenAI Chat (`logprobs: bool` + `top_logprobs: n`) 和 Responses (顶层 `top_logprobs` + `include: ["message.output_text.logprobs"]`) 有,
Anthropic 不支持. 形态差异大. **暂留 extra**, 同 A5/A6 加 warning.

### A8 — prompt cache 控制 (P3)

`prompt_cache_options` (OpenAI Chat + Responses) vs `cache_control` (Anthropic) — 两协议都有但语义形态差异大 (request 级 vs block 级), 归一化设计复杂. **暂留 extra**.

### A9 — metadata (P3)

OpenAI `metadata: map(16 KV)` vs Anthropic `metadata: {user_id}` — 同名但语义完全不同. 当前 Anthropic 已把 `user_id` 映射到 IR `user`, OpenAI 的 metadata map 应进 extra. **暂留 extra**.

### A10 — user / safety_identifier (P3)

`user` 已 first-class (Anthropic `metadata.user_id` 映射), 但 OpenAI 新增 `safety_identifier` (替代 `user`). **暂留 extra**, 评估未来是否改 IR 字段名.

### 移到类别 B (不提升)

- **A8 旧编号 seed**: 仅 OpenAI Chat 有 (Responses 无, 经官方文档核实) → 归 extra
- **A9 旧编号 n**: 仅 OpenAI Chat 有 → 归 extra
- **frequency_penalty / presence_penalty** (旧 A5/A6): 仅 OpenAI Chat 有, 但跨协议时加 warning 比静默丢好. 严格按准则归 extra, 配套 warnings 机制实施后告知客户端

## 7. 实施路线图

### 7.1 分批计划 (按优先级 a > b > c)

| 批次 | 字段 | 优先级依据 | 解阻塞 | 预计工作量 |
|---|---|---|---|---|
| **批次 1** | A1 (reasoning) | 真实用量 94%+2% | — | 中 (typed enum + budget 表 + 跨协议 golden) |
| **批次 2** | A2 (response_format) + A3 (service_tier) | Busbar 重灾区 + 简单 enum | L8 partial | 中 (A2 复杂, A3 简单, 合并批) |
| **批次 3** | A4 (stream_options) | 真实用量 96% | L8 partial | 小 (派生字段, 不复杂) |
| **批次 4** | A7 (logprobs) + warnings 机制 | 中优先级, 配套 warnings 基础设施 | — | 中 |
| **批次 5** | 评估 A8-A10 + L8 完成 | 视真实场景 | L8 完成, 管线合并可评估 | — |

### 7.2 每批的 DoD (Definition of Done)

- [ ] IR 字段类型定义 + `derive(Debug, Clone, PartialEq)`
- [ ] 三协议 reader 解析规则 (含 wire 形态元数据保留, 同协议 round-trip 用)
- [ ] 三协议 writer 序列化规则 (含 exhaustive match, 不允许 fallback echo)
- [ ] property test 生成器 (`arb_ir_*`)
- [ ] 同协议 round-trip property test (`fwd_property.rs`) 转正 (删除对应 `#[ignore]`)
- [ ] 跨协议 golden test (至少 OpenAI ⇄ Anthropic 一对)
- [ ] `src/codec/AGENTS.md` "当前覆盖与搁置"清单更新
- [ ] 本文件 §3.2 表格的"优先级"列标注"已实施"
- [ ] `just check` 全绿 (含 consistency-check feature)

### 7.3 与 L8 / 管线合并的关系

- **L8 解阻塞**: 批次 2 的 A2/A3 partial 解 L8 (response 侧的某些字段 round-trip 能转正, 但 L8 完整解决需 A4 也完成).
- **管线合并门槛**: 批次 5 完成后, response 侧 round-trip property test 覆盖率达标, 可重新评估 passthrough/IR 路径合并.

## 8. 待确认事项 (需决策)

> 标注 [CONFUSED] / [GUESS] 的项需要人工 review.

### 8.1 [GUESS] reasoning budget 表用绝对值还是 ratio

- 选项 A (Busbar): 绝对值表 `[1024, 2048, 4096, 8192, 16384, 32768]`, 简单, 但不自适应 max_tokens
- 选项 B (OpenRouter): ratio 公式 `max_tokens × [0.1, 0.2, 0.5, 0.8, 0.95]`, 自适应, 但实现复杂

当前选 A (简单), 如真实场景出现"max_tokens 很大但 reasoning 不够用"再切 B.

### 8.2 [GUESS] warnings 机制的具体形态

Vercel 的 warnings 是 SDK 返回的数组, secret-guard 是网关 — warnings 如何传递给客户端?
选项:
- 写入 response header (如 `X-SG-Warnings: field1,field2`)
- 写入 response body (非标, 破坏透明中继)
- 仅日志记录 (不通知客户端)

倾向选项 1 (header), 但需确认不破坏 FWD-1 透明中继契约 (header 是 secret-guard 加的, 不是上游的).

### 8.3 [CONFUSED] metadata 字段的归一化方向

OpenAI `metadata: map(16 KV)` vs Anthropic `metadata: {user_id}` — 这两个虽然同名但语义完全不同.
是分别建模 (OpenAI metadata 进 extra, Anthropic user_id 已 first-class) 还是统一?
倾向"分别建模", 因强行统一会引入虚假对应.

## 9. 参考文档

### 9.1 调研产出 (临时, 不进仓库)

- `/tmp/opencode/ir-research/sources/protocol-fields-extracted.md` — 三家协议字段清单
- `/tmp/opencode/ir-research/sources/field-usage-stats.md` — 字段使用频率统计
- 前人工作调研报告 (tech-solution-researcher 子任务产出, 已合并关键结论到 §5)

### 9.2 外部参考

- Busbar: https://github.com/GetBusbar/busbar (Apache-2.0, secret-guard IR 同源)
- LiteLLM: https://github.com/BerriAI/litellm
- Vercel AI SDK: https://github.com/vercel/ai
- new-api: https://github.com/songquanpeng/one-api (反面教材)
- OpenRouter: https://openrouter.ai/ (文档, 闭源实现)

### 9.3 本仓库相关文档

- `docs/design/contracts.md` — FWD-1 / FWD-2 契约 (字节级透明中继)
- `src/codec/AGENTS.md` — codec 模块契约 (wire fidelity 现状)
- 根 `AGENTS.md` — 项目级原则 (视图正确性、鲁棒性、术语表)

## 10. 变更日志

| 日期 | 变更 | 作者 |
|---|---|---|
| 2026-08-05 | 初版 (基于三阶段调研: 前人工作 / 字段全景 / 使用统计) | opencode-bot |
