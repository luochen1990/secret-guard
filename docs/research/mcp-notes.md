# MCP 机制笔记: MCP server 的能力如何进入 LLM 请求

> **一句话结论**: MCP 的连接流量 (initialize / tools/list / tools/call) 发生在 agent 与 server 之间,
> 不在 LLM API 路径上; MCP 的一切能力都被 client "编译"成 LLM 请求里的**普通文本** ——
> tools 数组条目、system prompt 段落、工具往返消息。
> 协议对这些文本的内容与呈现均无约束: **server 决定写什么, client 决定怎么放进请求**。

| | |
|---|---|
| 调研日期 | 2026-09-08 |
| 回答的问题 | agent (如 opencode) 注册了 MCP server 后, 发出的 LLM 请求与没注册时有什么区别? 协议约束在哪里结束? |
| 证据基线 | opencode @ `d6855b6` · modelcontextprotocol/typescript-sdk @ `5119ee7` (均为当日 HEAD, 源码逐条验证) |
| 覆盖范围 | tools / resources / instructions 三条通道 (客户端实现以 opencode 为样例); MCP 的 prompts 能力 (提示词模板) 未覆盖 |
| 稳定性提示 | 协议层结论 (§4 §5) 相对稳定; 客户端实现细节 (§3) 会随版本漂移 |

---

## 1. MCP 在链路中的位置: 与 LLM API 路径分离

MCP 是 **agent ↔ 工具服务器** 的协议, 独立于 agent ↔ LLM 的 API 协议:

```
                ┌──────────────── agent (opencode 等) ────────────────┐
                │                                                      │
   stdio / HTTP │ 直接连接, 不经过 LLM API 路径          LLM API 请求   │
                ▼                                     ▼                │
        ┌──────────────┐                      ┌──────────────┐        │
        │  MCP servers │                      │    LLM 网关   │──────► │ LLM provider
        └──────────────┘                      │  (若有, 抽象) │ ◄───── │ (OpenAI 等)
                                              └──────────────┘        │
```

MCP server 能影响 LLM 请求的**唯一途径**, 是改变请求体内容 —— 而这由 client 负责翻译。
理解 MCP 的关键, 就是理解这套"编译规则" (§3) 和它的约束边界 (§4)。

## 2. 连接生命周期与能力发现

```
client                                MCP server
  │ ── initialize request ──────────────► │  协议版本 / client 能力
  │ ◄─ initialize response ───────────── │  protocolVersion
  │                                      │  capabilities (tools? resources? prompts?)
  │                                      │  serverInfo
  │                                      │  instructions?   ← 可选, 裸 string (§4)
  │ ── notifications/initialized ──────► │
  │                                      │
  │ ── tools/list (分页) ───────────────► │  → 工具清单: name / description / inputSchema
  │ ── resources/list ─────────────────► │  → 资源清单 (若声明该 capability)
  │ ── tools/call ──────────────────────► │  → 执行, 返回 content (§3.4)
```

协议定义了三类能力: **Tools** (可调用工具) / **Resources** (上下文数据) / **Prompts** (提示词模板)。
本文覆盖前两类 + instructions 字段。

## 3. 能力 → LLM 请求的"编译规则"

以下以 opencode 实现为样例 (协议本身不规定这些, 见 §4)。

### 3.1 tools → 请求的 tools 数组 (必然发生)

每个 MCP tool 在 LLM 请求的 `tools` 数组里就是一个**普通 function tool**, 没有任何 MCP 专属标记:

| 字段 | 谁决定 | 内容 |
|---|---|---|
| `name` | client 拼接 | opencode: `sanitize(server) + "_" + sanitize(tool)`, 如 `github_create_issue` (sanitize = `[^a-zA-Z0-9_-]` → `_`) |
| `description` | server | tools/list 返回的原样描述 |
| `parameters` | server | server 的 inputSchema; client 强制 `type: object` + `additionalProperties: false` |

**命名约定因客户端而异, 不是协议标准**: opencode 用单下划线 `<server>_<tool>`,
Claude Code 用 `mcp__<server>__<tool>`。这决定了 §6 的"不可分辨"结论。

实现细节: OpenAI Responses 系 provider 下, client 会给所有 function tool 统一补 `strict: false`,
因为 MCP 来源的 schema 常不满足 OpenAI structured-outputs 约束。

### 3.2 instructions → system prompt 段落 (条件发生, 常被误以为必然)

仅当 server 在 initialize 响应里返回可选的 `instructions` 字段, client 才注入。
opencode 的包装形态:

```
<mcp_instructions>
  <server name="server-id">
    ...(server 提供的任意文本, 仅 trim + 缩进)...
  </server>
</mcp_instructions>
```

"注册 MCP 会在 system prompt 加一段"这个印象, 只在 server 主动提供 instructions 时成立。

### 3.3 resources 能力 → 3 个合成工具 (容易被忽略)

若任一已连接 server 声明 `resources` capability, client 额外合成三个 function tool
(**不来自** server 的 tools/list, 是 client 自己造的):

- `list_mcp_resources` / `list_mcp_resource_templates` / `read_mcp_resource`

即"注册 MCP 后 tools 变多"有两个来源: server 的工具清单 + client 的资源访问合成工具。

### 3.4 工具调用往返 → 消息历史 (动态, 一次调用永久驻留)

```
assistant message ── 带 tool_calls (name + arguments)
tool/user message ── 结果回填, 三种形态:
    ├─ text     → 普通 tool result 文本
    ├─ image    → data:image/...;base64,... 直接进消息历史
    └─ resource → blob 转成 data URL file block (≤10MB 且 mime 白名单内;
                  否则降级为 "[Binary MCP resource omitted: ...]" 占位文本)
```

image / resource 的 base64 data URL 会**持续出现在该会话后续所有请求**里。

### 3.5 变体形态: code mode (实验性)

opencode 开启 `experimentalCodeMode` 时, MCP 工具**根本不进 tools 数组**,
而是把整个工具目录序列化成文本, 嵌进一个 `execute` 工具的 description。
此时 MCP 的影响收敛为"某工具描述里的一大段文本"。

### 3.6 另一种拓扑: provider 侧 hosted MCP

以上均为 **client 侧**拓扑 (agent 直连 MCP server)。还存在 **provider 侧**拓扑:
OpenAI Responses API 提供 hosted MCP 工具类型 (请求里传 `{"type": "mcp", "server_label": ...,
"server_url": ...}`), MCP server 由 **provider 负责连接** —— 能力发现与工具调用都发生在
provider 内部, 请求体里只有 server 的引用 (label + URL, 可含鉴权 header)。
两种拓扑下"谁编译 MCP 能力"完全不同: 前者是 client, 后者是 provider。

## 4. 协议的约束边界: server 决定内容, client 决定形态

MCP 协议对 `instructions` 字段的完整定义 (InitializeResultSchema):

```ts
/**
 * Instructions describing how to use the server and its features.
 * This can be used by clients to improve the LLM's understanding of
 * available tools, resources, etc. It can be thought of like a "hint" to the model.
 * For example, this information MAY be added to the system prompt.
 */
instructions: z.string().optional()
```

两个关键事实:

1. **内容侧零约束**: 裸 `string` —— 无长度上限、无内容/结构要求、无转义规则。
   server 可以自由注入任何文本, 包括伪装成其他来源的指令。
2. **呈现侧零约束**: 协议只说 "MAY be added to the system prompt" (RFC 2119 的 MAY)。
   加不加、放哪、怎么包装、要不要截断/过滤, 全部留给 client 自由裁量。
   `<mcp_instructions>` 这个标签名在协议里**不存在**, 是 opencode 的发明;
   Claude Code 用另一套格式; 也可以有 client 选择只给人类看而不进 prompt。

一句话: **MCP server 是"内容作者", client 是"排版编辑"** —— 协议只约定字段存在性。
这个模式不限于 instructions, 对 §5 的全部通道成立。

## 5. 安全含义: 四条 server 可控的文本通道

MCP server 控制的、最终流入 LLM 请求的文本通道是一族, instructions 只是其中最常被讨论的一条:

| # | 通道 | 协议约束 | 最终落点 |
|---|---|---|---|
| 1 | initialize 的 `instructions` | 裸 string | system prompt (client 自愿注入) |
| 2 | tool 的 name / description / inputSchema | 裸 string / JSON Schema | tools 数组 |
| 3 | tool call 结果 (text / image / resource) | 裸内容 | 消息历史 |
| 4 | resource 内容 | 裸内容 | 消息历史 (经 §3.3 合成工具) |

四条通道同构: **server 决定内容, client 决定形态**, 无一例外。

对抗性观察 (以 opencode 为例): client 对 `instructions` 零消毒 —— 仅 `.trim()` + 缩进。
server 返回的文本里含 `</mcp_instructions>` 或 `</server>` 即可**闭合包装标签**,
把后续文本伪装成"来自包装之外的其他来源"。XML 风格包装在对抗场景下形同虚设。

信任模型: 连接一个 MCP server ≈ 给 system prompt 和消息历史开一个不受约束的写入端口,
安全边界完全落在"你选择连接哪些 server"这一步 —— 这也是 MCP 生态公认的
prompt injection 攻击面。

## 6. 对 LLM API 路径上中介 (如网关) 的含义

若在 agent 与 provider 之间放置观察者 (LLM 网关), 视野如下:

**可见性: MCP 痕迹 100% 在请求体内, 无带外通道。**
§3 的所有影响 (tools 条目、prompt 段落、往返消息、base64 附件) 都随 LLM 请求流经网关,
理论上均可观察、可脱敏、可统计。

**不可分辨性: 无法从 wire 上可靠区分 MCP 工具与客户端内置工具。**
二者同构 (都是普通 function tool, §3.1), 命名约定又因客户端而异且非标准。
任何"按 MCP server 聚合"的统计只能基于命名启发式, 存在误判空间。
同理, 消息历史里的文本也无法区分"来自 MCP server"与"来自用户/客户端"。

**体积: base64 附件的放大效应。**
工具返回的 image / resource 以 data URL 常驻消息历史 (§3.4), 会显著放大
后续每个请求的体积。

## 7. 证据索引

(行号以调研当日快照为准, 便于复查; 客户端代码漂移后以语义为准)

| 结论 | 证据位置 |
|---|---|
| tools 数组合并 MCP 工具 | opencode `packages/opencode/src/session/tools.ts:390` |
| 工具命名 `server_tool` | opencode `packages/opencode/src/mcp/catalog.ts:119` (`toolName`) |
| `<mcp_instructions>` 注入 | opencode `packages/opencode/src/session/system.ts:119-134` |
| instructions 仅 trim 处理 | 同上 (`.split("\n")` + 缩进, 无转义) |
| 3 个资源合成工具 | opencode `packages/opencode/src/session/tools.ts:27-31` (`MCP_RESOURCE_TOOLS`) |
| image → base64 attachment | opencode `packages/opencode/src/session/tools.ts:440` 起 |
| resource blob 10MB 白名单 | 同上 (`MAX_MCP_RESOURCE_BLOB_BYTES` / `SUPPORTED_MCP_RESOURCE_ATTACHMENT_MIMES`) |
| code mode 收敛为描述 | opencode `packages/opencode/src/tool/code-mode.ts` (`describeCatalog`) |
| Responses 系 `strict: false` | opencode `packages/opencode/src/session/llm/request.ts:150` |
| `instructions: string, optional` | mcp ts-sdk `packages/core/src/schemas.ts:565-574` (`InitializeResultSchema`) |
| "MAY be added to the system prompt" | 同上字段 doc 注释 |
| `getInstructions()` 零处理直返 | mcp ts-sdk `packages/client/src/client/client.ts:1384` |
