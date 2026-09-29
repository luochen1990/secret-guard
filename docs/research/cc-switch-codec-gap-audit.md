# cc-switch ⇄ secret-guard codec 差距审计报告

> **一句话结论**: secret-guard 的 typed-enum IR 架构在 stop_reason / usage 等维度优于
> cc-switch 的手写镜像矩阵, 但 9 个语义维度里 **7 个存在盲区** — 其中三个是 "已有全部
> 组件、只差胶水" 的便宜修复 (T2 o-series 字段名 / T3 usage cache 细节 / T4 Responses
> incomplete_details), 一个是同协议 redact 流式路径的**孤儿 content_block_stop** wire
> 违例 (T1, 新发现, 比单纯丢 thinking 更严重)。

| | |
|---|---|
| 审计日期 | 2026-09-29 |
| 审计性质 | 逐维度对照审计 (cc-switch 互操作语义知识 × secret-guard codec IR 建模现状), 只读不改码 |
| 证据基线 | cc-switch @ `846de29c`; secret-guard @ `8c8337e` (两侧均为 worktree 实测 HEAD) |
| 姊妹篇 | 架构调研: `docs/research/cc-switch-codec-notes.md` (本文引用其结论不重复论证) |
| 覆盖范围 | 9 维度 = 与 codec IR 建模直接相关的语义项; cc-switch 的 cache_control 断点注入 / prompt_cache_key 注入**不单列维度** — 与 FWD-1 冲突面已在姊妹篇 §4.2-C 论证 (均需裁决), 本审计不重复 |
| 评级体系 | 无 gap / 有意忽略 (有契约依据) / **盲区** (无处理且无裁决依据) / 需裁决 (与 FWD-1 / SEC-10 等契约张力需用户决策) |
| 稳定性提示 | cc-switch 无契约文档, 行号随其版本漂移; secret-guard 行号基于 8c8337e |

## 审计结论 TL;DR

**评级分布**: 盲区 ×7 (维度 1/2/3/4/5/6/9) · 有意忽略 ×1 (维度 7) · 需裁决 ×1 (维度 8,
维度 9 的反向子项另计低优先裁决) · 无 gap ×0。

**最重要的三个盲区**:

1. **同协议 + Redact 流式路径的孤儿 `content_block_stop`** (维度 1 子发现): Anthropic
   流式 reader 丢弃 thinking block 的 BlockStart (anthropic.rs:232) 却无条件透传其
   BlockStop (anthropic.rs:267-273), 而配对过滤只在跨协议模式启用
   (stream/translate.rs:196) — a→a + redact + streaming + thinking 上游时客户端收到
   未配对的 `content_block_stop` (协议违例, anthropic.rs:512-514 的兜底注释只对跨协议
   成立)。叠加: history 中的 thinking block 在 reader 就被丢 (同协议 redact 也丢),
   tool-use + thinking 会话上游大概率 400。
2. **OpenAI writer 恒写 `max_tokens`** (维度 4): reader 双读 `max_completion_tokens`
   (openai.rs:162-167) 但 writer 无字段名保真 (openai.rs:371-373) — o-series 上游 400
   ("Unsupported parameter: max_tokens"), 跨协议与同协议 redact 双杀; 修复是标准
   wire-fidelity form 模式 (~50 LOC)。
3. **伪流式上游 → stream=true 客户端拿到单块 JSON** (维度 9): 判型降级到 buffered 翻译
   后以 `application/json` 返回 (cross_proto.rs:535-538), SDK 流式解析器大概率报错;
   cc-switch 的展开方案 (单 JSON → 完整 SSE 生命周期) 所需组件 secret-guard 全部已有
   (IrResponse + ingress 流式 writer + SSE reassembler), 只差胶水。

## 汇总表

| # | 维度 | secret-guard 现状 | 评级 | 一句话 |
|---|---|---|---|---|
| 1 | thinking signature / reasoning 往返 | **无** (IR 无 signature/encrypted_content; Anthropic thinking reader 层丢弃) | **盲区** | 同协议 redact 也丢 thinking, 流式还产生孤儿 content_block_stop; cc-switch 的 base64 envelope 证明 passthrough 建模可行 |
| 2 | tool 媒体搬运 | **部分** (同协议无损; 跨协议 `blocks_to_text` 静默丢 Image) | **盲区** | tool_result 里的图片无占位标记无 WARN 直接消失, 连 "已知损失" 都未登记 |
| 3 | reasoning effort 档位映射 | **部分** (thinking/effort 落 extra: 同协议保真, 跨协议 clear 全丢) | **盲区** (已规划) | roadmap A1 (P0) 有完整方案未实施; 跨协议时思考档位静默蒸发 |
| 4 | o-series `max_completion_tokens` | **部分** (reader 双读, writer 恒写 `max_tokens`) | **盲区** | o-series 上游拒收 `max_tokens`; 同协议 redact round-trip 连字段名都改了 |
| 5 | stop_reason 双向映射 | **部分** (typed enum 优; Responses writer 半截) | **盲区** | Responses writer 不写 `incomplete_details.reason`, 自己的 reader 把它读回 Other — MaxTokens round-trip 有损 |
| 6 | usage cache 字段归类 | **部分** (IR 建模 + 三 reader 全对齐; OpenAI/Responses writer 丢 details) | **盲区** | `responses_usage_json` 还漏加 cache_creation (内部 SSOT 不一致); o/r ingress 客户端缓存核算失真 |
| 7 | 图片降级 (纯文本模型) | **无** | **有意忽略** | FWD-1 "上游不认可就让它失败, 网关不兜底" 明文裁决; 降级机制同 body_filter 属 body 改写不参考 (姊妹篇 §4.3/§4.2-A 已区分 "名单知识可吸收, 机制不吸收") |
| 8 | billing header 剥离 | **无** (有认知: #269 测试明示该形态, 裁决按原位保留) | **需裁决** | 剥 = 删客户端字节 (撞 FWD-1 + 2026-09-23 cache_control 注入否决先例); 不剥 = 目标侧前缀缓存每轮全 miss (#2350 实证真实成本) |
| 9 | 流/非流互通兜底 | **部分** (有 buffered 降级不崩; 无形态适配) | **盲区** + 需裁决-低 (反向) | stream=true 客户端最终拿到 JSON; 反向 (非流式收 SSE) 原样透传 — cc-switch 双向兜底, secret-guard 单向降级 |

---

## 1. thinking signature / reasoning 跨协议往返

**(a) cc-switch 的做法**

- `reasoning_bridge.rs:1-94`: Messages ↔ Responses 桥的 "opaque reasoning transport" —
  Anthropic 协议没有 Responses `reasoning` item 的字段, 为让 **stateless tool loop
  无损**, 把完整 reasoning item 序列化后 base64 (URL_SAFE_NO_PAD) 藏进
  `thinking.signature` (有 summary 时, :67-71) 或 `redacted_thinking.data` (无
  summary 时, :62-65), 版本前缀 `ccswitch-openai-reasoning-v1:` (:11); 回传时解码
  原样还原 (`openai_reasoning_item_from_anthropic_block`, :82-94)。round-trip 单测
  锁定 (:101-130)。
- 消费点: `transform_responses.rs:21-22` (import), `:2448` (Anthropic block → 还原
  reasoning item), `:2780` (reasoning item → 藏进 block)。
- 关键设计事实: **不合成签名, 只搬运** — signature 对它是不可解构的 opaque 容器。

**(b) secret-guard 现状 — 无**

- IR 无 signature / encrypted_content 概念: `IrBlock::Reasoning { summary: Vec<String> }`
  (ir.rs:391-397), 注释自认 "`encrypted_content` 是 provider-specific opaque blob,
  **当前实现不保留** (同协议 round-trip 也会丢失)"。
- Anthropic 侧: 非流式 `read_block` 对 `thinking` / `redacted_thinking` 返回 None
  (anthropic.rs:776, "不在 MVP") — **reader 层丢弃, 同协议 + Redact 路径同样丢**
  (该路径经 IR 重序列化, proxy/mod.rs:26); 流式 `content_block_start` 对 thinking
  无 BlockStart (anthropic.rs:232)、`thinking_delta`/`signature_delta` 忽略
  (anthropic.rs:258); writer 对 Reasoning/ReasoningContent 返回 None
  (anthropic.rs:985-993, "thinking block 需要 signature, 无法合法合成")。
- Responses 侧: reader 仅取 summary, 忽略 encrypted_content (responses/mod.rs:538-540,
  :835); writer 只重写 summary (responses/mod.rs:359-368)。

**(c) gap 评级: 盲区** — 分三层影响, 严重度递增:

1. **跨协议丢失** (已登记): o/r ⇄ a 任意方向 reasoning 上下文不可达。
2. **同协议 + Redact 请求侧丢失**: Anthropic 客户端 (claude code extended thinking +
   tool use) 回传的 history thinking block 在 reader 就被丢 → 上游 Anthropic 对
   tool-use + thinking 会话要求回传 thinking block, 大概率 400。**未实测** (推断依据:
   Anthropic 官方语义 + cc-switch `thinking_rectifier` 的存在反证此类会话的脆弱性);
   但机制本身 (reader 层 None) 是代码事实。
3. **同协议 + Redact 流式孤儿帧** (本次审计新发现): reader 丢 thinking 的 BlockStart
   却**无条件**产出其 BlockStop (anthropic.rs:267-273 对 `content_block_stop` 不查
   block 类型), 配对过滤 (`skipped_block_starts`) 只在跨协议模式启用且只覆盖
   **writer 侧跳过** (stream/translate.rs:107-110, :141, :196) — 同协议 restore 模式
   下客户端收到未配对的 `content_block_stop` (协议违例; anthropic.rs:512-514 注释
   声称的兜底与同协议行为不符)。

"无法合法合成 signature" 的裁决 rationale (codec/AGENTS.md "支持矩阵" 的
`reasoning_content` 跨协议丢弃 rationale blockquote) 只否定了**合成**,
未否定**搬运已有 signature/blob** — cc-switch 证明了 passthrough 是第三条路。

**(d) 已有条目**: 部分。known-limitations.md codec 节 #176 条目 (ReasoningContent /
OpenAI 思考原文跨协议丢弃) 与 "encrypted_content 同协议 round-trip 也会丢失"
(line 22); codec/AGENTS.md "支持矩阵" ❌ 行 ("Anthropic `thinking` blocks")。**未覆盖**:
同协议 redact 的 thinking 丢失影响、孤儿 BlockStop 违例、passthrough 方案评估。

## 2. tool 媒体搬运

**(a) cc-switch 的做法**

- `tool_media.rs:1-118`: Chat 协议 tool 消息只许文本 → `plan_chat_tool_output_media`
  (:60-88) 把 tool 输出里识别到的媒体块 (Image/File/Audio, 遍历深度 32) 抽出, 原位
  留 `[cc-switch: tool result media moved to the following user message]` 标记
  (:13-14, :62-65); 媒体经 `queue_chat_tool_output_media` (:90-104, 附
  `[cc-switch: media output of tool call {call_id}]` 引导文本) 暂存, 由
  `flush_pending_chat_tool_media` (:106-118) 搬到紧随的**合成 user 消息**;
  ≥8KB base64 整体截断 (:12)。纯共享库, 5 个桥消费 (如 transform_codex_chat.rs:646,
  :705-707, :915)。

**(b) secret-guard 现状 — 部分 (同协议无损, 跨协议静默丢弃)**

- 同协议 (Anthropic→Anthropic redact): `read_block` 保留 tool_result 内 Image
  (anthropic.rs:733 递归 read_block, :744-774 Image 读入), writer 原样写回
  (anthropic.rs:946, :969-983) — 无损。
- 跨协议到 Chat: ToolResult → `role:"tool"` + `content: blocks_to_text(content)`
  (openai.rs:342-359, is_error 时加 `[error] ` 前缀 :350-351); `blocks_to_text`
  (mod.rs:225-234) **只取 Text 块 join('\n'), 其余类型 `_ => None` 静默丢弃** —
  tool_result 里的 Image 无占位标记消失; 纯图片 tool_result → 空字符串。
- 跨协议到 Responses: 同型, `function_call_output` 的 `output` = `blocks_to_text`
  (responses/mod.rs:904-914)。
- 无任何 WARN / 计数 (对比: reasoning 丢弃有 `count_reasoning_blocks` WARN,
  cross_proto.rs:235-241)。

**(c) gap 评级: 盲区**。跨协议 lossy-by-target 本身有先例 (reasoning 丢弃是被接受的
已知损失), 但这里 (i) 连 "已知损失" 的登记都没有; (ii) 无占位标记意味着 LLM 对
"工具返回了图片" 这一事实在另一协议侧完全不可见 (cc-switch 的标记至少保住事实);
(iii) 可搬运性成立 — OpenAI/Responses 的 user 消息都支持图片 (openai.rs:1243-1254
已实现 Image→`image_url`, 含 Base64→data URL)。附带发现: Responses writer 的 user
消息 Image **只支持 Url, Base64 被丢** (responses/mod.rs:884-888, 与 OpenAI writer
两种都支持不对称)。

**(d) 已有条目**: 无 (known-limitations.md / ir-fields-roadmap.md 均未提 tool_result
媒体; 已 grep "媒体/image/tool_result" 核实)。

## 3. reasoning effort 档位映射

**(a) cc-switch 的做法**

- `transform.rs:100-148` `resolve_reasoning_effort`: 优先级 1 = 显式
  `output_config.effort` (low/medium/high/xhigh 1:1; `max` 按模型支持度否则回落
  xhigh; 未知值不注入); 优先级 2 = `thinking.type` + `budget_tokens` fallback
  (`adaptive`→`xhigh`; `enabled`: <4000→low / 4000-15999→medium / ≥16000→high;
  无 budget→high; disabled/缺失→None)。
- 仅对 `supports_reasoning_effort` 模型族注入 (transform.rs:64-85: o-series / gpt-5+ /
  grok-4.5+ / grok-build-*), 消费点 transform.rs:237-241 (写入
  `reasoning_effort`) 与 transform_responses.rs:1843。

**(b) secret-guard 现状 — 部分 (同协议保真, 跨协议无映射)**

- IR 无 effort/budget 概念 (ir.rs:18-68 `IrRequest` 全字段清单无)。
- 三协议的请求侧配置都落 `extra`: Anthropic `thinking` 不在 collect_extra 排除清单
  (anthropic.rs:100-116); OpenAI `reasoning_effort` 不在排除清单 (openai.rs:185-202);
  Responses `reasoning` 不在排除清单 (responses/mod.rs:167-180)。→ 同协议 redact 时
  extra 透传保真; **跨协议 `ir.extra.clear()` 全丢** (cross_proto.rs:111-117)。
- 无模型能力检测 (model 字段仅透传, 无任何 sniffing)。

**(c) gap 评级: 盲区 (已识别未实施)**。跨协议 a→o/r 时 thinking 配置静默蒸发 —
深度思考请求被当普通请求执行, 行为档位改变且用户无感知 (无 WARN)。姊妹篇 4.2-A
已将其列为 "高价值无契约冲突" 吸收项。

**(d) 已有条目**: **有, 且是完整方案** — ir-fields-roadmap.md **A1 (P0)** (§3 表
:121): `IrReasoning::{Disabled, Effort, Budget, Adaptive}` typed enum + effort↔budget
双向投影表 (:286-297, 抄 Busbar 扩到 6 档) + reader/writer 三协议映射 (:302-309) +
round-trip / golden 测试 (:312-314) + "extra 共存" 纪律 (:91-95, :316 — writer 优先
读 first-class, extra 保 same-proto 精细控制)。属路线图第一批 (§批次表) 未实施。

## 4. o-series 模型检测 (max_completion_tokens vs max_tokens)

**(a) cc-switch 的做法**

- `transform.rs:56-62` `is_openai_o_series`: `o` + 数字前缀 (o1/o3/o4-mini...)。
- 写侧切换: `transform.rs:216-222` — `max_tokens` 值存在且目标是 o-series → 写
  `max_completion_tokens`, 否则写 `max_tokens`。

**(b) secret-guard 现状 — 部分**

- reader 双读: `max_tokens` or `max_completion_tokens` → `IrRequest::max_tokens`
  (openai.rs:162-167; 文件头注释 :13 明示 "后者是 o1/o3 reasoning 模型用"); 单测
  `read_request_max_completion_tokens_recognized` (openai.rs:1453-1461)。
- **writer 恒写 `max_tokens`** (openai.rs:371-373), 无模型检测, 无字段名形态保真
  (`IrRequest` 无 max_tokens_form — 对比 stop_form/tools_present/system_form 的
  wire-fidelity 家族)。

**(c) gap 评级: 盲区**。两个影响面:
1. **跨协议 a→o 打到 o-series 上游**: Anthropic 的 `max_tokens` 翻译成 OpenAI
   `max_tokens` → o-series API 拒收 (OpenAI 对 o 系列要求 `max_completion_tokens`,
   报 "Unsupported parameter: `max_tokens`")。注: 对第三方 OpenAI 兼容网关普遍
   双收, 触发面主要是官方/严格上游。
2. **同协议 + Redact**: 客户端发 `max_completion_tokens` → reader 收进 max_tokens →
   writer 写回 `max_tokens` — 字段名被改, 超出 normalize_json 能吸收的范围
   (键名不等), FWD-2 round-trip 等式在此字段上实际已破 (property 生成器未覆盖
   该字段名, 故未红灯)。

**(d) 已有条目**: 无专门条目。roadmap 把三个别名算 "1 项语义字段" (ir-fields-roadmap.md
:112, :170 — "合并 same-protocol 的 deprecated 别名"), 但**写侧别名还原**问题未登记。

## 5. stop_reason / finish 双向映射

**(a) cc-switch 的做法**

- 手写镜像两份 (姊妹篇 §1 已指出漂移风险): `transform_responses.rs:2091-2109`
  `map_responses_stop_reason` (status + has_tool_use + incomplete_reason → Anthropic
  stop_reason; `incomplete` + `max_output_tokens`/`max_tokens`/缺 reason → `max_tokens`;
  其他 → `end_turn`) ↔ `transform_codex_anthropic.rs:121-137`
  `map_anthropic_stop_reason_to_status` (`max_tokens`→`incomplete`+`max_output_tokens`;
  `refusal`→`incomplete`+`content_filter` — 注释: 防 Codex 当成正常空回复;
  `model_context_window_exceeded`→`incomplete`+`max_output_tokens`;
  `pause_turn`→`completed`+WARN)。

**(b) secret-guard 现状 — 部分 (typed enum 架构占优, Responses 写侧半截)**

- IR: `IrStopReason` 7 variants typed enum (ir.rs:484-499), reader 无法识别的 token
  归 `Other` 防泄漏, writer match 穷举由编译器强制 — 架构优于手写镜像。
- 读侧 (三协议全): openai.rs:815-823 (`stop`/`length`/`tool_calls`|`function_call`/
  `content_filter`); anthropic.rs:841-850 (含 `refusal`); responses
  `read_response_status` (mod.rs:724-763): `completed` 按 output 有无 function_call
  推断 ToolUse (2026-09-23 精确化裁决), `incomplete` 按 `incomplete_details.reason`
  精确化 (`max_output_tokens`→MaxTokens / `content_filter`→Safety / 未知→Other)。
- 写侧: OpenAI `write_stop_reason` (openai.rs:1305-1315, Refusal→`stop`) 与 Anthropic
  `write_stop_reason` (anthropic.rs:1045-1055, Safety→`end_turn`) 穷举完整;
  **Responses `write_status_str` (mod.rs:1018-1030) 只写 status 字符串, 不写
  `incomplete_details.reason`** — MaxTokens→`"incomplete"` (裸), Safety/Refusal→
  `"incomplete"` (裸); 流式终止事件同源 (:1016-1017 注释明示 SSOT 共用)。
- 后果: 自己的 reader 对 "incomplete 无 reason" 归 Other (mod.rs:756, 单测 :1324
  明示) → **r-ingress round-trip: MaxTokens → incomplete(无 reason) → 读回 Other**。

**(c) gap 评级: 盲区 (中度)**。补 `incomplete_details: {reason}` 即闭环, 且完全落在
"契约演进原则" 的无需授权类 (2026-09-23 已有 stop_reason 精确化先例裁决 — 根
AGENTS.md "契约演进原则"; known-limitations line 26 的 "Responses 流式方案 T2/T3"
同族)。

**(d) 已有条目**: 部分。known-limitations line 26 登记 "failed→Other→completed 有损"
与 stop_reason 流式/非流式统一, 但 incomplete_details 缺失未登记。

## 6. usage 映射细节 (cache 字段归类)

**(a) cc-switch 的做法**

- Responses→Anthropic: `transform_responses.rs:2142-2216`
  `build_anthropic_usage_from_responses` — 字段解析优先级链 (input_tokens→
  prompt_tokens 兜底; cache_read: 直字段→`input_tokens_details.cached_tokens`→
  `prompt_tokens_details.cached_tokens`; cache_creation: 直字段→`cache_write_tokens`
  嵌套兜底), 空/部分对象降级全零。
- Anthropic→Responses: `transform_codex_anthropic.rs:139-184`
  `build_responses_usage_from_anthropic` — **input_tokens = fresh + cache_read +
  cache_creation 饱和加** (:177-179), details 嵌套写回; 注释明示计费口径
  ("billing parser 减去两个子集再分别计价")。

**(b) secret-guard 现状 — 部分 (IR 读侧全对齐, OpenAI/Responses 写侧丢细节)**

- IR 建模到位: `IrUsage` 4 字段, 归一化约定 "未缓存 input + 加性 cache"
  (ir.rs:501-516)。三 reader 全对齐: OpenAI 减 cached (openai.rs:825-850,
  `prompt_tokens_details.cached_tokens`, creation 恒 None :848); Responses 减
  cached (mod.rs:694-718, :707-711 注释明示); Anthropic 双 cache 字段直读
  (anthropic.rs:852-868)。
- 写侧分叉:
  - Anthropic writer 完整: 双 cache 字段条件写 (anthropic.rs:1058-1069)。
  - **OpenAI writer**: `openai_usage_json` (ir.rs:551-558) 只写
    prompt/completion/total 三数, **不写 `prompt_tokens_details.cached_tokens`**
    (非流式 :492 与流式 :606 共用) — cache_read 在 IR 里却不上 wire。
  - **Responses writer**: `responses_usage_json` (mod.rs:1038-1045) 不写
    `input_tokens_details`, 且 **input_total = input + cache_read, 漏加
    cache_creation** (:1039) — 与同文件 `openai_prompt_tokens` 的两项相加
    (ir.rs:541-545) 内部不一致; Anthropic 上游 cache_creation > 0 时 r-ingress
    客户端看到的 input_tokens 系统性偏小。

**(c) gap 评级: 盲区**。a→o / a→r 方向, 客户端的缓存命中率/成本核算失真 (usage-stats
侧不受影响 — 它读 IR, USAGE-* 走 `RespFinality.echo`); `responses_usage_json` 漏加
是准 bug (违反 IrUsage 自己的加性归一化约定)。

**(d) 已有条目**: 部分。known-limitations line 24 登记 Responses **流式** usage details
丢弃 ("重合成 usage 只含 input/output/total 三数"), 但非流式 writer 的同型缺失 +
cache_creation 漏加未登记。

## 7. 图片降级 (纯文本模型媒体能力)

**(a) cc-switch 的做法**

- `media_sanitizer.rs:11-115`: `[Unsupported Image]` 原位替换; 双路触发 — 预防式
  (provider 配置的模型能力声明, "declaration-driven, never a guess" :15-19 +
  heuristic 开关) 与反应式 (`is_unsupported_image_error` :55-115: 400/415/422/501 +
  "only support(s) text" 自证短语 (#5025 火山方舟, 英文缺三单都列了) / image/vision/
  multimodal/media 字样 + unsupported 词族, 命中后替换 body 同 provider 重试)。

**(b) secret-guard 现状 — 无**

- grep `text.only|unsupported|media` 全 codec/proxy 无命中 (仅测试名
  `cross_proto_round_trip_text_only_messages`); IR Image block 直通, 无媒体能力/
  模型能力概念, 无错误驱动重试机制 (secret-guard 的转发是一次性, 无 cc-switch 式
  per-request 重试循环)。

**(c) gap 评级: 有意忽略**。依据: 根 AGENTS.md "原始形状保持" 段 — "不引入任何主动
添加/改写; 客户端请求上游不认可就让其失败 (直连同样失败, **网关不兜底**)";
姊妹篇 §4.2-A 已区分: 名单**知识**可吸收, 降级**机制**不吸收 (与 body_filter 同属
body 改写)。反应式替换需要 "错误驱动原地改 body
+ 同 provider 重试" 的机制, 与 secret-guard 的一次性透明中继哲学结构性冲突。若用户
真实撞到纯文本网关 4xx, 出路是文档指引而非代码。

**(d) 已有条目**: 无 (亦无需代码条目; 可选加一条 FAQ 性 known-limitations 说明
"纯文本上游 4xx 网关不兜底, 请自建 route 到多模态端点")。

## 8. billing header 剥离

**(a) cc-switch 的做法**

- `transform.rs:18-54` `strip_leading_anthropic_billing_header`: 只剥 system 文本
  **开头首次出现**的 `x-anthropic-billing-header:` 行 (CRLF/LF 全处理), 后续出现
  保留 (防误删用户文本 :23-24)。rationale #2350: Claude Code 动态计费头的 `cch=`
  值每轮变化, 转发到 OpenAI 侧 (`messages` system 或 Responses `instructions`)
  使 prompt 前缀每轮不同, **前缀缓存全失效**。消费点: transform.rs:180, :189
  (Anthropic→Chat 的 system 折叠处)。

**(b) secret-guard 现状 — 无 (有认知, 无处理)**

- 跨协议 a→o: system blocks 经 `blocks_to_text` 原样折叠进 system 消息
  (openai.rs:314 附近); a→r: 同型折叠进 `instructions` (responses/mod.rs:276-280)。
  顶层 system 与 messages[] 内 system 的 billing header 一字不差翻过去。
- 现象已被认知: anthropic.rs 测试 :1266-1294 明示 "claude code 实测形态: 顶层 system
  (array) + messages[0]=system (`x-anthropic-billing-header: probe`)", 但 #269 的
  裁决方向是**按原位保留** (FWD-1; codec/AGENTS.md "wire fidelity" 段的 #269 已知
  边界注记) — 位置保真, 内容不动。
- 同协议路径无此问题: 无 redact 字节透传; 有 redact 时 mock 替换 per-request 稳定
  (C3), system 文本不被改写。

**(c) gap 评级: 需裁决**。张力两侧:
- 剥 = 删除客户端发送的字节 → 撞 FWD-1 "对 wire 的唯一合法修改是 real↔mock 替换"
  的精神, 且有 2026-09-23 `inject_cache_control` 否决先例 (同样是 "缓存友好 vs 形状
  保持" 的权衡, 当时选了形状);
- 不剥 = 跨协议目标侧前缀缓存每轮全 miss, 用户 token 成本上升 — cc-switch #2350
  实证这是真实账单问题, 且 C3 (经济性契约) 的精神是 "不无必要地破坏缓存", 但 C3
  条文只约束 redact 的 mock 稳定性, 不覆盖翻译路径的内容删减。
- 折衷空间: 仅跨协议翻译路径剥 (翻译本已授权改形状, 但 "改形状" ≠ "删内容", 仍是
  内容级修改); 或配置项 opt-in (如 `[redact] strip_billing_header_on_translate`)。

**(d) 已有条目**: 无 (roadmap "暂留 extra" 清单 :197-198 列了 `prompt_cache_key` 等,
但无 billing header 概念)。

## 9. 流/非流互通兜底 (伪流式上游)

**(a) cc-switch 的做法** (双向兜底; 机制与 rationale 详述见姊妹篇 §1 末段, 此处仅留行号锚点)

- **上游对 `stream:true` 返回单 JSON** → 展开为完整 SSE 生命周期:
  `streaming_responses.rs:70-107` `responses_json_to_anthropic_sse` (消费点 :2416)。
- **上游对非流式请求返回 SSE** → 嗅探聚合 (#2234): `handlers.rs:2306-2316`
  `body_looks_like_sse` → 聚合器 (:2430); 三处对称臂 (:577, :1451, :1611)。

**(b) secret-guard 现状 — 部分 (单向降级, 无形态适配)**

- 判型 SSOT = 响应 Content-Type (`helpers::is_sse` / `is_streaming`):
  - 跨协议: cross_proto.rs:270-312 — `stream=true` + 2xx + SSE → 流式翻译扇出;
    **其余 (含上游无视 stream 返回单 JSON) → buffered 翻译 + WARN** (:287-295
    "falling back to buffered translation", best-effort 不让请求失败) → **以
    `Content-Type: application/json` 单块返回** (:535-538) 给要 SSE 的客户端。
  - 同协议 + redact: same_proto.rs:252-265 同型 WARN + buffered。
  - 同协议无 redact: 字节透传 (上游违约字节直通 — FWD-1 铁域, 行为正确)。
- 反向 (非流式请求收到 SSE): buffered → `serde_json::from_slice` 失败 → 原样透传
  SSE 字节 + WARN (cross_proto.rs:454-465, "response body is not a single JSON
  value") — 非流式客户端拿到 SSE 原文。
- 无任何 "把翻译结果重放为客户端期望形态" 的机制。

**(c) gap 评级: 盲区 (前半) + 需裁决-低 (反向子项)**。

- 前半 (stream=true 拿 JSON): "不让请求失败" 的意图实际达成度存疑 — OpenAI /
  Anthropic SDK 的流式解析器对非 SSE body 普遍报错, 客户端侧仍失败 (只是网关侧
  不炸、错误换个形态)。cc-switch 展开方案所需的组件 secret-guard **全部已有**:
  egress reader 已把整块 JSON parse 成 `IrResponse` (cross_proto.rs:407-409), 缺的
  只是 "IrResponse → 事件序列 (MessageStart/BlockStart/全量 Delta/BlockStop/
  MessageDelta/MessageStop) → ingress 流式 writer → SSE" 的重放胶水。契约面无冲突:
  跨协议路径本就是翻译; same-proto redact 路径本就 IR 重序列化 (仅保真语义, 不保
  流形态) — 但行为变化应登记 known-limitations。
- 反向 (非流式收 SSE): 更罕见 (伪流式中转站对非流式请求强行 SSE), `StreamScan`
  (stream/scan.rs, SSE → IrResponse 累积器) 恰好就是所需聚合器; 做不做属低优先
  裁决 (透传至少让客户端能看到原始错误/数据, 聚合则 "修正" 上游违约)。

**(d) 已有条目**: 部分。known-limitations redact 节 line 61-63 从 mock/restore 视角
覆盖了非 SSE 判型 fallback (mock 不还原 / 透传), 但 "**stream=true 客户端最终拿到
JSON 形态错配**" 的客户端影响未登记。

---

## 补齐任务清单 (盲区项按建议优先级)

> 规模为含测试的粗估; "关联" 列指 roadmap / known-limitations 需同步的条目。
> 独立于本清单的裁决请求: 维度 8 (billing header 剥离, T9) 与维度 9 反向子项 (T10)。

| # | 任务 | 改动落点 | 规模 (LOC) | 优先级 | 关联 |
|---|---|---|---|---|---|
| T1 | **修复孤儿 content_block_stop** (维度 1.3): Anthropic 流式 reader 记录 "未产出 BlockStart 的 index" (可放 `StreamDecodeState`), `content_block_stop` 查表跳过; 或同协议模式复用 `skipped_block_starts` 过滤 (来源改为 reader 侧) | `src/codec/anthropic.rs` (read_response_events) + `src/codec/stream/translate.rs` | ~40 | **P0** (wire 违例 bug) | known-limitations codec 节新条目 (同协议 redact + thinking 流式的孤儿帧) |
| T2 | **max_tokens 字段名保真** (维度 4): 新增 `MaxTokensForm` wire-fidelity 元数据 (与 `StopForm` 同型), OpenAI reader 记录 / writer 按原字段名回写 (同协议); 跨协议 o-egress 的 o-series 检测另议 (可抄 cc-switch 前缀嗅探, 或保守双发不兼容 — 需 mini-裁决) | `src/codec/ir.rs` + `src/codec/openai.rs` | ~50-70 | **P0** | roadmap §3 全景表加写侧别名注记; known-limitations codec 节新条目 (同协议 redact 改写字段名) |
| T3 | **usage cache 细节补齐** (维度 6): `responses_usage_json` 修 input_total 漏加 cache_creation + 写 `input_tokens_details.cached_tokens`; `openai_usage_json` 写 `prompt_tokens_details.cached_tokens` (= cache_read) | `src/codec/ir.rs` + `src/codec/responses/mod.rs` | ~25 | **P0** (含准 bug) | known-limitations line 24 扩充至非流式 writer |
| T4 | **Responses writer 补 `incomplete_details.reason`** (维度 5): `write_status_str` 升级为返回 (status, Option<reason>) 或并列 helper; 非流式 `write_response` 与流式终止事件 (stream.rs) 同步; round-trip 测试从 Other 恢复 MaxTokens/Safety | `src/codec/responses/mod.rs` + `src/codec/responses/stream.rs` | ~40 | **P1** | known-limitations line 26 ("Responses 流式方案 T2/T3" 条目) 扩充 |
| T5 | **伪流式上游 → 合成 SSE 生命周期** (维度 9 前半): buffered 判型分支 (cross_proto + same_proto redact) 在 `ir.stream=true` 且翻译成功时, 把 IrResponse 重放为事件序列喂 ingress 流式 writer, 以 `text/event-stream` 返回; 失败路径回落现状 | `src/proxy/cross_proto.rs` + `src/proxy/same_proto.rs` + `src/proxy/fan_out.rs` (新 helper) | ~80-120 | **P1** | known-limitations 新条目 (形态适配行为 + same-proto 无 redact 路径仍透传的边界) |
| T6 | **A1 reasoning 配置跨协议映射** (维度 3): 按 roadmap A1 既有方案实施 (typed enum + 投影表 + golden); 档位表可交叉验证 cc-switch 的 budget 阈值 (4000/16000) 与 adaptive→xhigh | `src/codec/ir.rs` + 三协议 reader/writer (按 roadmap §A1) | ~150 | **P1** (roadmap 已定 P0 批次) | roadmap "实施进度" 章节更新 |
| T7 | **thinking / encrypted_content passthrough 建模** (维度 1.1/1.2): 走 roadmap §2.2 判定 (boundary case, 参照 #176 先例登记); 方案 A = 新 `IrBlock::Thinking { thinking, signature_or_data }` 原样搬运 (cc-switch 证明可行, redact 需扫描 thinking 文本叶子), 方案 B = 至少同协议 redact 路径保真 (reader 收进 block 级 extra) | `docs/design/ir-fields-roadmap.md` (先登记) + `src/codec/ir.rs` + `src/codec/anthropic.rs` + `src/codec/responses/` | ~200-300 | **P2** (功能, 契约级) | roadmap 新 boundary-case 条目; known-limitations #176 条目升级 |
| T8 | **tool_result 媒体丢弃可观测化** (维度 2): 最小 = `blocks_to_text` 丢弃非 Text 块时计数 WARN (对齐 reasoning 丢弃先例) + known-limitations 条目; 完整 = 媒体搬运到下一条 user 消息 + 占位标记 (抄 tool_media 思路, Chat/Responses user content 均可承载); 顺带修 Responses writer Base64 image 丢弃 (:884-888 → data URL) | `src/codec/mod.rs` (blocks_to_text) 或各 writer; 完整版 `src/codec/openai.rs` + `responses/mod.rs` | 最小 ~20 / 完整 ~120 | **P2** (最小) / P3 (完整) | known-limitations codec 节新条目 |
| T9 | **billing header 剥离** (维度 8): **等裁决**。若授权: a→o / a→r 翻译点的 system 折叠处剥头部首现行 + 配置开关 (默认 off); 抄 cc-switch 的 "只剥首次 + 保留后续" 边界 | `src/proxy/cross_proto.rs` (或 codec writer 层) + `src/config.rs` | ~60 | 待裁决 | 裁决后 known-limitations / configuration.md 同步 |
| T10 | **非流式请求收 SSE 的嗅探聚合** (维度 9 反向): JSON parse 失败臂先 `body_looks_like_sse` 嗅探, 命中则用 `StreamScan` 聚合成 IrResponse 再走 writer; 未命中维持透传 | `src/proxy/cross_proto.rs` + `src/codec/stream/scan.rs` 复用 | ~100 | **P3** (罕见场景, 可只登记) | known-limitations (若不做则登记透传行为) |

### 与既有流程的衔接

- T1-T3 是 bug 级修复, 建议各自走 TDD (先红后绿), 不涉契约变更。
- T4 / T6 落在 "契约演进原则" 的无需授权类 (精确化), 但需同步 contracts.md 相关
  property 断言 (FWD-* 的 round-trip 生成器需扩轴: max_completion_tokens 字段名 /
  incomplete_details / cache details)。
- T5 / T7 / T9 触及行为语义或契约边界, 建议先在 PR 描述中引用本报告对应小节作为
  决策依据; T7 必须先过 roadmap §2.2 判定流程。
- 本报告的发现回填后, 应同步更新姊妹篇 §4.2-A 的清单状态 (避免两份文档漂移)。
