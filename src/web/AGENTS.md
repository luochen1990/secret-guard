# web 模块 — JSON API + 单页 WebUI 契约

> 本文件是 `src/web/` 目录的导航与契约汇总. 源文件 (`api.rs` / `mod.rs`) 头部有更细节的注释.
> 项目级原则 (鲁棒性、视图正确性、前端不变量 I1/I2、术语) 见根目录 `AGENTS.md`.

## 职责

- `mod.rs`: `/__sg` 子 router + `/` 根入口 + slash redirect + not_found.
- `api.rs`: `/__sg/api/*` JSON endpoints (records + sessions + nodes/timeline + secrets/providers CRUD).
- `index.html`: 单页 UI (IM 风格: 会话折叠 sidebar + timeline 对话流, 内嵌 CSS + vanilla JS, 零外部依赖).

## 路由

- `GET /` 与 `GET /__sg` —— 单页 HTML (根路径主入口, `/__sg` 向后兼容).
- `GET /__sg/` —— 307 redirect 到 `/__sg` (临时, 避免浏览器永久缓存).
- `/__sg/*` 未匹配子路径 —— 404, **绝不**进入 forward (否则会泄漏内部 URL 到上游).

> 注意: axum 0.8 的 `nest("/__sg", ...)` 默认匹配不带尾斜杠的 `/__sg`. server.rs 显式注册了
> `/__sg/` → `/__sg` 的 redirect.

## API endpoints

```
GET    /__sg/api/records[?offset=N&limit=M]   → {records, total, offset, limit}
GET    /__sg/api/records/{id}[?view=parsed]   → {record, parsed_request?, parsed_response?, parse_error?}
GET    /__sg/api/sessions                     → {sessions, total}  (叶子节点, latest-first)
GET    /__sg/api/nodes/{id}/timeline[?limit=N]→ {records}  (沿 parent 链向上 N 个祖先, oldest-first)
GET    /__sg/api/secrets
POST   /__sg/api/secrets
PUT    /__sg/api/secrets/{id}
DELETE /__sg/api/secrets/{id}
PATCH  /__sg/api/secrets/{id}/decision     body: {"mode": "default|prefer_static|disabled"}

GET    /__sg/api/providers
POST   /__sg/api/providers
PUT    /__sg/api/providers/{id}
DELETE /__sg/api/providers/{id}
PATCH  /__sg/api/providers/{id}/decision
```

所有响应带 `Cache-Control: no-store`, 避免浏览器对自动刷新返回缓存内容.

### Records 分页

`offset` 0-based 从最新算起; `limit` clamp 到 `[1,200]`, 默认 50.

### Records parsed view

`?view=parsed` 返回 `parsed_request` (从 `req_body` 按需用 ingress codec 解析) +
`parsed_response` (直接取自 `record.resp_parsed`, 由 proxy 层的 `StreamScan` 在流过程中
增量累积, 非流式路径在响应完成时一次性计算). Gemini/Ollama 无 codec → `parse_error` + fallback raw.

### Records list 轻量化 + 预览提取

`GET /records` 返回 `RecordSummary` (不含 `req_body` / `resp_body` / `resp_parsed`),
body 字段由 `GET /records/{id}?view=...` 按需拉取. 流式响应的 `resp_body` 在 record 完成后
为空 (不保留原始 SSE 字节), parsed view 通过 `resp_parsed` 提供.

`RecordSummary` 同时携带两个从 `req_body` 一次性提取的轻量字段 (提取后丢弃 body):
- `preview`: sidebar 主标题 (截断到 48 chars). 优先取最后一条 user message (可读性好);
  无 user 时回退到最后一条有文本的 message (tool_result / assistant).
  压缩 marker ("What did we do so far?") 命中时 fallback 到最后一条 assistant 摘要.
  提取失败 fallback 到 method+path.
- `model`: 顶层 `model` 字段 (OpenAI / Anthropic 共有), sidebar 副标题第二行.

提取逻辑在 `web::api::extract_preview_and_model` (协议无关字节级, 不依赖 codec reader).
**假设声明**: 假设 messages 数组中 user 在 assistant 之前; 假设压缩 marker 是固定字符串.
**降级**: 任一假设不成立 → fallback (method+path / 空 model), **永不 panic**.

### Timeline delta messages (issue #27)

> **当前实现**: timeline 用 push 时预存的 `req_body_raw` 截取 delta (非 lazy redact).
> 完整 lazy redact 重建 (derive_redact_map 含 system/tools) 是后续工作, 见 `src/dag.rs` 头部.

timeline 路径的 `RecordSummary` 额外携带 `req_delta_messages` (本轮新增 messages 的 wire JSON,
从 `req_body_raw` 末尾截取). 前端按 role 渲染独立气泡 (system / user / tool_result / assistant),
assistant 作为无源气泡 (前序 response 的历史副本). 根节点额外注入 system prompt (OpenAI reader
提升 system 到 `IrRequest.system`, writer 写回 messages[0]; 截取逻辑在根节点 start>0 时补回).
list 路径 (`GET /records`) 不填此字段 (避免 O(n) 全量 resolve).

**已知限制 (跨协议)**: OpenAI writer 会把 Anthropic 风格的混合 Text+ToolResult user 消息拆成
(1+N) 条 wire messages, 导致 `req_body_raw` 的 messages 数 > IR messages 数.
`extract_delta_messages` 用 `messages.len() - req_delta_count` 切片时, 跨协议路径的 start 偏小,
delta 可能包含前序轮消息. 同协议路径不受影响 (wire 与 IR 1:1). 后续可改为从 `req_delta`
(IR MessageRef) resolve + ingress writer 重新序列化 (与 redact 路径一致).

### Timeline response 传输优化 (issue #28 Phase A)

timeline 返回的 N 个节点中, 只有最末节点 (timeline anchor) 保留 `parsed_response`; 非末轮的设为 None.
理由: 非 leaf 的 response 内容已被下一轮 delta 的 assistant message 完整包含, 传输是冗余.
前端从完整 delta 渲染连续对话流 (含 assistant 气泡), 只有末轮额外渲染 response-pane
(尚未被任何 delta 消费的部分). 后续 Phase B 将进一步在 push 时删除 parent.response (瞬态存储),
用 `consistency-check` feature flag 的 assertion 保证 delta↔response 一致 (见根目录"视图正确性确保机制").

### Sessions / Timeline (会话折叠 WebUI)

- sidebar 一级 (会话) 来自 `GET /api/sessions` (返回叶子节点 + record_count + latest 字段).
- 二级 (轮次列表) 与右侧 timeline 对话流来自 `GET /api/nodes/{id}/timeline?limit=N`
  (沿 parent 链向上取 N 个祖先, oldest-first).
- timeline 惰性加载: 滚到顶时以最老 node 的 parent 为新起点 prepend 更早 N 轮 (保持滚动锚点).
- `timelineReachedTop` 仅在用户实际滚顶触发 `loadOlder` 探测后置位 (而非初次加载时从
  `records.length < limit` 推断), 避免短会话首屏即显示 "已经到顶了".

### ForwardRecord.redactions

`Vec<(mock, secret_id)>` — 从 `redact_ir` 产出的 `RedactionMap` SSOT 派生
(见 `proxy.rs::derive_redactions`). WebUI 的 mock 高亮和 "命中" 筛选都基于此字段,
**永不**在前端重新计算, 避免前后端漂移. 不含真实 secret value, 可安全暴露.

### 安全姿态

- GET 永不返回 secret 的 `value` / provider 的 `api_key` 真实值 (用 `mask_value` 占位).
- 写操作通过同源策略 + 本地监听 (默认 127.0.0.1) 保护.
- 内部错误细节不通过响应体返回, 仅进 tracing.

## WebUI 渲染契约 (`index.html`)

> 前端不变量 I1 (气泡数 == IR messages 长度) 与 I2 (sidebar 条目数 == HTTP 请求数) 见根目录 AGENTS.md.
> 回归守卫: `tests/webui/im-ui.spec.ts`.

### Sidebar 分组渲染 (二级 + 三级小圆点)

- 二级条目 (`.round-item` = 用户轮次, req_delta 含 `role=user`) 显示 preview 文本 + 时间.
- 紧随其后的工具调用轮次 (req_delta 无 user, 仅 assistant+tool_result) 折叠为三级小圆点
  (`.sub-dot`), 横向排列在组首下方.
- 圆点颜色 = tool name 哈希 (FNV-1a 调色板, 与 provider 图标复用), tooltip 显示 tool name + 时间.
- 点击圆点 = `selectRound` (同二级条目).

### 每轮操作按钮 (info + raw)

timeline 每轮 header 含两个按钮:
- `ℹ` info: 弹窗展示传输层元数据 (method/path/status/elapsed/streamed/model/error/redactions 等,
  全部来自 RecordSummary, 无需网络请求).
- `raw`: 弹窗展示原始 req_body / resp_body / req_headers / resp_headers (按需懒拉
  `GET /api/records/{id}`). body 是 LLM 视角 (已 redact, 安全展示); headers 已脱敏
  (auth/cookie 等 = `<redacted>`). 流式响应的 resp_body 为空 (不保留 SSE 字节), 显示提示.

### Response 气泡渲染

一条 response 在数据模型上 = messages 数组中的 **一条 assistant message**. 进入下一轮时
它仍是 messages 中的一项 (不拆分). 前端尊重这个数据模型: text 和 tool_calls/tool_use
渲染在**同一个气泡**内, tool_call/tool_use 段用 `.bubble-tool-call` 子区域做视觉区分
(边框 + 缩进 + monospace). 不拆分为多个独立气泡.

### 其它渲染细节

- 三段式 fingerprint: 自动刷新期间 request-pane 滚动位置 + bubble 展开状态保持.
- 三级展示气泡 (折叠 → 展开 → 弹框全文).
- response 打字框布局 (固定底部, 独立滚动).
- 气泡颜色 + sender icon 分类.
- 气泡间微小间距 (margin-bottom, 避免视觉粘连).
- tool name 推断: `toolNameOfRound` (假设 tool_calls 含 function.name; 降级 fallback 到 `'?'`).
