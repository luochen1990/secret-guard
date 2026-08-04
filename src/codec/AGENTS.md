# codec 模块 — 跨协议翻译契约

> 本文件是 `src/codec/` 目录的导航与契约汇总. 各子模块的源文件头部有更细节的 `//!` 注释.
> 项目级原则 (鲁棒性、视图正确性、术语) 见根目录 `AGENTS.md`.

## 职责

在 OpenAI Chat Completions 与 Anthropic Messages 之间双向翻译, 借鉴 Busbar
(`GetBusbar/busbar`, Apache-2.0) 的 superset IR + Reader/Writer trait 设计,
大幅精简以匹配 secret-guard 的 MVP 范围.

## 支持矩阵

- ✅ OpenAI Chat Completions ⇄ Anthropic Messages 双向 (非流式 + 流式 SSE).
- ✅ OpenAI Responses API 同协议透传 + Redact (非流式; 流式 + Redact 返回 501).
- ✅ OpenAI Responses ⇄ OpenAI Chat Completions 跨协议翻译 (非流式).
- ❌ Responses ⇄ Anthropic 跨协议: 未实现 (返回 501).
- ❌ Responses 流式 SSE 事件翻译 (`read_response_events` / `write_response_event` 返回空/None).
- ❌ 不在 MVP: Bedrock / Gemini / Cohere, reasoning `encrypted_content` (provider-specific opaque),
  Anthropic `thinking` blocks, citations, logprobs, prompt caching, Bedrock eventstream 二进制流.

## 核心抽象

| 抽象 | 位置 | 职责 |
|---|---|---|
| `IrRequest` / `IrResponse` / `IrBlock` / `IrStreamEvent` | `ir.rs` | 协议无关的中间表示 (chat completion 范围) |
| `Reader` trait | `mod.rs` | wire JSON/Bytes → IR (`read_request` / `read_response` / `read_response_events`) |
| `Writer` trait | `mod.rs` | IR → wire (`write_request` / `write_response` / `write_response_event` / `requires_max_tokens` / `emits_sse_done_terminator` / `write_error`) |
| `StreamTranslate` | `stream.rs` | egress SSE → IR 事件流 → ingress SSE (chunk-boundary 处理 + 跨协议翻译 + 同协议 restore 两种模式) |
| `StreamScan` | `stream.rs` | 流式 SSE → IrResponse 累积器 (供 WebUI parsed view) |
| `Protocol` enum | `mod.rs` | codec 当前支持的协议子集 (OpenAI/Anthropic/Responses); `from_native` 是 Gemini/Ollama → None 的单一接入点 |

## 子模块

- `ir.rs` — IR 类型. 设计原则: superset IR (承载双协议都能表达的字段);
  first-class 字段优先于 `extra` (跨协议翻译时 extra 被清空, 防止源协议独有字段泄漏);
  同协议 round-trip **normalize_json 相等** (wire 形态元数据保留, 见下方 "wire fidelity").
- `normalize.rs` — canonical JSON 序列化 (`normalize_json`), 用于 FWD-2 property test
  的字节级断言. 仅测试用, 不进生产路径.
- `openai.rs` — OpenAI Chat Completions 的 Reader/Writer (含流式 fan-out,
  flat stream 一个 chunk 可能产生 0..n 个 IR 事件, 需 state 合成).
- `anthropic.rs` — Anthropic Messages 的 Reader/Writer (流式 1:1 映射).
- `responses.rs` — OpenAI Responses API 的 Reader/Writer (非流式; 流式 SSE 事件翻译未实现).
- `stream.rs` — SSE chunk-boundary 处理 (TCP 切片兼容, CRLF/LF 双兼容, MAX_BUF 溢出 abort).

## wire fidelity (wire 形态元数据)

> 详细设计见 `docs/design/contracts.md` FWD-1/FWD-2 + 本 worktree 的 commit history.

同协议 reader→writer round-trip 在 **`normalize_json` (canonical JSON) 意义下**保留 wire 语义:

```
normalize(v) == normalize(Writer(Reader(v)))
```

`normalize_json` = BTreeMap key 排序 + 紧凑序列化 + 无空白, 吸收字段顺序 / 空白等
无语义差异, 让 round-trip property 可机械验证.

为达到此契约, IR 携带一组 **wire 形态元数据** 字段 (仅同协议路径填充, 跨协议翻译前清空):

| 字段 | 位置 | 作用 |
|---|---|---|
| `IrRequest.stop_form: Option<StopForm>` | ir.rs | stop 字段形态 (String/Array), 区分 `"stop":"x"` vs `"stop":["x"]` |
| `IrRequest.tools_present: bool` | ir.rs | tools 字段是否存在 (区分 `"tools":[]` vs 缺失) |
| `IrMessage.content_form: Option<ContentForm>` | ir.rs | message content 形态 (String/Array/Null) |
| `IrBlock::ToolResult.content_form: Option<ContentForm>` | ir.rs | tool_result 内 content 形态 (Anthropic 特有) |

**清空 SSOT**: `IrRequest::clear_wire_fidelity()` 集中清空所有 wire_fidelity 字段
(含嵌套 ToolResult), 跨协议路径 (`proxy/cross_proto.rs::cross_proto_forward`) 调用之.
新增 wire_fidelity 字段时只需改这一处.

**当前覆盖与搁置**:

- ✅ 已覆盖 (request): content 形态 (L1) / stop 形态 (L7) / tools 显式空 (L6) / tool_use input round-trip / 裸 string content part
- ⏸️ 搁置 (待后续): 多 system messages 合并 (L2) / message-level extra (L4) / block-level 未知 part (L5) / usage 字段位置与计算 (L8, response 路径)

搁置项对应的 proptest 生成器分支已用 `// NOTE` 标注, 实现后恢复即可.
response 路径的 2 个 property 标了 `#[ignore]`, 实现 L8 后启用.

## 关键不变式

1. **同协议 + 无 Redact 不进入 codec** (字节透传), 零回归. 见 `proxy/mod.rs::dispatch`.
2. **同协议 + Redact**: reader → `redact_ir` → writer 重序列化, **normalize_json 相等**
   (wire 形态元数据保留, 语义信息无损; 字段顺序 / 空白等无语义差异由 normalize 吸收).
   恢复流式 UX.
3. **跨协议时 IR 的 `extra` 字段强制清空**, 防止源协议独有字段泄漏到对端.
4. **跨协议路径响应大小受 `MAX_RESP_BODY_RECORD` (32 MiB) 保护**, 防止恶意上游 OOM.
5. **错误响应翻译为 ingress 协议的原生 envelope**, message 截断到 4 KiB 并优先解析上游
   `error.message`.

## 与其它模块的协作

- **`proxy/`**: `dispatch` 根据 ingress/egress 协议是否一致 + 是否有 Redact,
  选择字节透传 / IR 路径 / 跨协议翻译. 详见 `src/proxy/mod.rs` 头部.
- **`redact.rs`**: Redact/Restore 在 IR 层操作, 与 codec 同层, 两者自然组合
  (跨协议翻译 + Redact 在同一 pipeline).
- **`dag.rs`**: DAG 节点存储 IrBlock, codec 的 IR 类型是 DAG 的内容寻址单元.
