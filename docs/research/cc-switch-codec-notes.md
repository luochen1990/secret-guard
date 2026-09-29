# cc-switch 协议转换机制调研笔记: 架构剖析与可参考性评估

> **一句话结论**: 架构上 secret-guard 的 IR 体系优于 cc-switch 的点对点手写矩阵, 不值得抄;
> 但 cc-switch 用大规模用户实战撞出来的**互操作语义知识** (修正器族 + 字段映射表 + 流/非流兜底)
> 值得"抄知识、不抄架构"地吸收。

| | |
|---|---|
| 调研日期 | 2026-09-29 |
| 回答的问题 | cc-switch 本地路由的协议转换怎么做的? secret-guard 能参考什么? |
| 证据基线 | cc-switch @ `846de29c` (GitHub main, 2026-09-29 HEAD, 源码逐文件验证); secret-guard @ `8c8337e` |
| 覆盖范围 | 协议转换架构 / 互操作修正器族 / failover 与熔断; **不覆盖** MCP/Skills/Prompts 等套件管理功能 (与网关无关) |
| 姊妹篇 | 差距审计 (逐维度对照 secret-guard codec 现状): `docs/research/cc-switch-codec-gap-audit.md` |
| 稳定性提示 | cc-switch 无契约文档, 行为以代码为准, 版本迭代快; 引用的行号随其版本漂移 |

---

## 1. 转换架构: 无 IR 的 star 型点对点手写

**没有中间表示**。每个 `(ingress, upstream)` 方向一个独立文件, 全部是
`serde_json::Value → Value` 的 JSON-to-JSON 直接拼装, 共 **32,481 行** (`src-tauri/src/proxy/providers/` 下 15 个文件):

| 文件 | 转换对 | 行数 |
|---|---|---|
| transform_responses.rs + streaming_responses.rs | Anthropic → Responses (双向) | 5,498 + 7,066 |
| transform_codex_anthropic.rs + streaming_codex_anthropic.rs | 同上镜像方向 | 3,055 + 1,218 |
| transform_codex_chat.rs + streaming_codex_chat.rs | Responses ↔ Chat | 5,438 + 1,493 |
| transform.rs + streaming.rs | Anthropic ↔ Chat (OpenRouter, 默认关) | 2,090 + 1,370 |
| transform_gemini.rs + streaming_gemini.rs | Anthropic ↔ Gemini | 2,693 + 1,054 |

关键架构事实:

- **实际矩阵比宣传窄**: 可转换 ingress 只有 Anthropic (Claude) 和 Responses (Codex) 两种;
  Chat 和 Gemini ingress 是**纯透传入口** (无出站转换分支, handlers.rs 直接 forward);
  Responses → Gemini 不支持。
- **请求侧与响应侧各自独立**: 请求侧 dispatch 在 forwarder.rs, 响应侧 dispatch 在
  handlers.rs, 两处各维护一套 if/else, 靠 `api_format` / `should_convert_*` 字符串约定对齐。
  同一格式对的两个方向是独立手写的镜像函数 (如 stop_reason 映射
  `map_responses_stop_reason` 与 `map_anthropic_stop_reason_to_status` 是两份),
  文件头自认 "The direction is exactly the mirror of transform_responses.rs"。
- **类型化结构体是死代码**: `providers/models/` 下的 `AnthropicRequest`/`OpenAIRequest`
  标注 `#![allow(dead_code)]`, 生产路径不引用。
- **防漂移的共享模块** (他们自己在打补丁): `codex_responses_sse.rs` (Responses SSE 输出
  envelope 统一, "a wire fix lands here once instead of being mirrored in both files"),
  `codex_chat_common.rs` (reasoning 字段多供应商兜底提取), `reasoning_bridge.rs`
  (OpenAI reasoning item ↔ Anthropic thinking signature 的 base64 往返编解码),
  `tool_media.rs` + `json_canonical.rs` (全部 transform 共用)。
- **未共享的重复**: Anthropic content block 解析逻辑在 4 个 transform 文件各一份;
  SSE 流式骨架 (async_stream + buffer + take_sse_block + UTF-8 remainder) 在 5 个
  streaming 文件各复制一份。

**流式机制**: 逐 event 状态机, 增量转换 (不缓冲整包)。每个 (upstream → client) 对一个
独立转换器, 状态机负责跨 event 语义重组: tool_use arguments 分片累积、
`pending_message_delta` 延迟到 `[DONE]`、Gemini 快照式 chunk 自行 diff 等。

**流/非流互通兜底** (伪流式中转站场景的实战解法):
- 上游对 `stream:true` 返回单个 JSON → hold 到 EOF, 一次性展开为完整 SSE 生命周期
  (streaming_responses.rs `responses_json_to_anthropic_sse`)。
- 上游对非流式请求返回未标记 Content-Type 的 SSE → 嗅探聚合 (`body_looks_like_sse`)
  后走非流式转换 (handlers.rs 三处对称, 注释标 #2234)。

## 2. 互操作修正器族 (实战价值最高的部分)

统一模式: **错误驱动 → 原地改 body → 同 provider 重试一次** (反应式);
外加少量发送前的主动处理 (预防式)。开关默认: 反应式全开, 主动式 (Optimizer) 默认关。

| 修正器 | 解决的实战问题 | 核心机制 | 触发 |
|---|---|---|---|
| thinking_rectifier | Claude Code 回传 thinking block, 第三方中转/Gemini 校验签名 400 | 删 thinking/redacted_thinking block + 遗留 signature 字段后重试; 按 7 类错误子串匹配识别 | 反应式; 仅 Claude 类 provider; 每请求一次 |
| thinking_budget_rectifier | budget_tokens 不满足 ≥1024 且 < max_tokens | 强制 enabled + budget=32000 + max_tokens 抬到 64000 后重试 | 同上; adaptive 类型不改写 |
| media_sanitizer | 纯文本模型 (GLM/Qwen/DeepSeek 系网关) 收图片 400/415 (#5025) | image block 原位替换 `"[Unsupported Image]"`, 覆盖 Anthropic/Responses/Gemini 三种 wire 形状 | 预防式 (模型能力名单) + 反应式 (错误匹配) 双路 |
| tool_media | Chat 协议 tool 消息只许文本, 跨协议桥媒体无处安放 | 工具输出媒体抽出到紧随的合成 user 消息, 原位留标记; ≥8KB base64 截断 | 纯共享库, 5 个桥消费 |
| xai_sanitize | xAI 严格 serde 对 Codex 私有字段 422 (#6815/#7451, 移植 sub2api) | 确定性字段删除/结构重写 + 回程 SSE 还原 namespace + 整浮点参数改写 | 按上游 api.x.ai 判定 |
| body_filter | `_` 前缀私有字段透传泄露 | 递归删除 (JSON Schema properties 内豁免), **无条件**每请求执行 | 无条件 |

**缓存友好族** (对 token 账单敏感场景的杀手锏):

- `strip_leading_anthropic_billing_header`: Claude Code 在 system 开头塞动态计费头,
  转发到 OpenAI 系后每轮前缀变化, 前缀缓存全失效 (#2350); 只剥头部首次出现。
- `prompt_cache_key` 注入: 按 session 派生稳定 key (Copilot 场景从 metadata 提取),
  注释明言 "Generated per-request UUIDs must never be used here"; Chat 方向按上游
  宿主白名单决定是否可发 (未知网关默认不发, 防未知字段 400)。
- cache_control 断点注入: 4 个位置 (tools 末项/system 末块/最后消息末 block/倒数第二
  user 锚点), 总预算 4, 尊重已有标记; **Codex→Anthropic 桥默认开** (桥接请求无
  cache_control, 不注入则每轮全价, #5071)。
- system 数组合并为单条 system 消息 ("跨轮字节稳定, 不影响前缀缓存")。

## 3. failover: per-request 候选链 + circuit breaker

- **候选链**: 每请求一次选定 (failover 队列序, 忽略"当前 provider"指针), 每家试一次,
  `max_retries+1` 上限 (默认最多 4 家)。Codex Official 永不参与 (跨账号 Authorization)。
- **失败分类** (`categorize_proxy_error`): Retryable = 连接错误/超时 + **401/403/429/5xx
  等全部非黑名单状态码** (rationale: 换家 = 换 key/配额/地域, 值得一试); NonRetryable =
  400/405/406/413/414/415/422/501 (请求自身问题, 换家无用) + 内部错误。2xx 但 body 是
  错误 envelope 也在循环内检测, 可触发 failover; Responses 流式延迟提交直到有效产出
  (buffer 上限 256KB)。
- **熔断器** per `(app, provider)`: 4 连败 Open / 60s 冷却 / HalfOpen 放行 **1 条真实
  流量** (非合成探活) / 2 成功 Closed; 错误率线 0.6@10 请求; 计数是**累计值非滑动窗口**
  (已知缺陷)。纯被动, 无主动探活; DB 健康表仅供 UI 展示不参与路由。
- **流式 failover 边界**: 只在首 chunk 到达前可换家 (首包超时/流提前结束 → 回候选链);
  首 chunk 之后断流只终止不重试。
- **body 处理**: 全内存缓冲 (axum 上限 200MB), 每 attempt 重新序列化发送, 重放平凡。
- **两层切换**: 请求内切换 (per-request 循环 continue) + 全局路由指针切换 (成功后异步
  改 live-state, 只影响后续新请求; inflight 不受影响)。

## 4. 对 secret-guard 的可参考性评估

### 4.1 架构: 不抄 (IR 枢纽全面占优)

| 维度 | cc-switch (star 点对点) | secret-guard (IR 枢纽) |
|---|---|---|
| 新增协议成本 | ~4 个大文件 (2-5k 行) | 1 Reader + 1 Writer (~200 行), 全 pair 自动获得 |
| 双向一致性 | 手写镜像函数, 漂移风险已显形 | round-trip property 机械守卫 |
| 流式翻译 | 5 套独立状态机 + 复制骨架 | StreamTranslate 统一框架 |
| dispatch | 两处 if/else 字符串对齐 | `Protocol::reader()/writer()` 单点 |

cc-switch 的结构是"桌面配置管理器后加网关"的历史包袱, 其共享模块是在给自己的架构
打补丁。secret-guard 无任何理由向此方向退化。

### 4.2 语义知识: 值得吸收 (分四级, 详见差距审计)

- **A. 字段映射/场景清单** (高价值, 无契约冲突): reasoning 跨协议往返 (reasoning_bridge
  base64 技巧)、tool 媒体搬运规则、effort 档位映射、o-series 检测、stop_reason 双向
  映射、usage cache 归类 — 逐项对照 `src/codec/` 补盲区,
  产出见 `docs/research/cc-switch-codec-gap-audit.md`。("已确认纯文本模型名单"仅
  知识可吸收; 其降级机制不吸收 — 同 body_filter 属 body 改写, 见 §4.3 与审计维度 7。)
- **B. 流/非流互通兜底** (中价值): 伪流式中转站场景真实存在, 可对照
  known-limitations 的 Responses 流式损失评估。
- **C. 缓存友好技术** (高价值, **需契约裁决**): ⚠️ 三项均与 FWD-1「原始形状保持」
  存在张力 — 剥 billing 头是**删客户端字节**, cache_key/cache_control 注入是**添加
  客户端未发送内容** (根 AGENTS.md "原始形状保持" 段明文禁止主动添加), 均需用户
  显式授权 (2026-09-23 `inject_cache_control` 否决先例 — 同为 "缓存友好 vs 形状保持"
  权衡, 当时选了形状)。其中 billing header 的裁决论证详见差距审计维度 8; 不剥的代价
  实证: cc-switch #2350 (目标侧前缀缓存每轮全 miss)。
- **D. failover 策略** (选择性): Pool 的"耗尽信号驱动"与 cc-switch 的"错误驱动换家"
  是正交哲学; 可考虑吸收"连接失败/5xx 是否触发 Pool 切换"。熔断器的累计值窗口设计
  不值得抄。

### 4.3 明确不参考

- body_filter 的**无条件**私有字段过滤: 与 FWD-1 同协议 byte-exact 直接冲突,
  secret-guard 哲学是"客户端发什么就送什么, 上游不认可就让它失败"。
- 点对点文件组织 / 双处 dispatch / 镜像函数。
