# web 模块 — JSON API + 单页 WebUI 契约

> 本文件是 `src/web/` 目录的导航与契约汇总. 源文件 (`mod.rs` / `api/` 目录下各子模块) 头部有更细节的注释.
> 项目级原则 (鲁棒性、视图正确性、前端不变量 I1/I2/I3、术语) 见根目录 `AGENTS.md`.

## 职责

- `mod.rs`: WebUI 顶级 router (`/` + `/api/*`) + `/api/{*rest}` 404 兜底 + not_found. (`NO_STORE` 共享常量已上移 `crate::state`, 消费者跨 web/auth 两层.)
- `api/` (目录, 按资源组拆分, 见 #146): `/api/*` JSON endpoints.
  - `mod.rs` — 模块根 + handler re-export (`web::api::<handler>` 路径稳定).
  - `error.rs` — `ApiError` 统一错误类型.
  - `crud.rs` — secrets/providers 共享的 CRUD 泛型流程 (`EffectiveItem` + `CrudTable` + create/update/delete/decision flow, 错误消息经 kind_label 参数化).
  - `records.rs` — `GET /records/{id}` 单条 raw + parsed view (弹窗按需拉).
  - `sessions.rs` — `GET /sessions` + `GET /sessions/{sid}/timeline` + `POST /sync` (session-aware timeline API).
  - `secrets.rs` / `providers.rs` — 各自 CRUD (5 endpoints), handler 是 crud.rs 泛型流程的薄壳.
    providers.rs 另含 `POST /providers/probe` (协议自动探测): base_url 校验后的薄壳,
    探测算法 SSOT 在 `proxy::models::probe_provider_upstream` (与上游模型清单 fetch 同乡);
    以及 `PUT/DELETE /providers/probe` — 存量 id="probe" 条目的管理薄 wrapper
    (固定 id 适配到 update/delete flow, 静态路由 405 阴影的补齐);
    以及 `GET /providers/{id}/models` (模型清单预览, endpoints 弹窗的 Models 按钮):
    存在性校验后的薄壳, 取数算法 SSOT 在 `proxy::models::provider_model_preview`
    (Router 走 advertised_names 本地合成 / Direct+Pool 走 resolve_route + 上游现场 fetch).
  - `apikeys.rs` — API key CRUD (4 endpoints, 无条件挂载, "只认证, 不隔离").
  - `usage.rs` — `GET /usage/summary` 用量汇总查询 (usage-stats §8; 直读 UsageStore
    SQL 聚合, 派生走 `usage::summary::build_summary` 纯函数).
- `dto.rs` (已移至顶层 `src/dto.rs`): WebUI 响应序列化 DTO (SessionView / NodeView / RoundBrief / TimelineRound / TimelineTail / TimelinePage / TimelineDiffData / SyncSnapshot). 构造逻辑留 dag 模块 (持读锁访问私有字段). 中立化理由见 `src/dto.rs` 头部 (dag 域 B 不再反向依赖 web 域 C).
- `index.html`: 单页 UI (IM 风格: 会话折叠 sidebar + timeline 对话流, 内嵌 CSS + vanilla JS, 零外部依赖).

## 路由

> URI 分配的完整规划 (顶级保留字 / 命名空间不相交论证) 见 `docs/design/url-layout.md`.

- `GET /` —— 单页 HTML (唯一 WebUI 入口; 旧 `/__sg` 前缀已移除, 历史 `git log -S "__sg"`).
- `/api/*` 未匹配子路径 —— 404, **绝不**进入 forward (否则会泄漏内部 URL 到上游).
- OIDC 认证路由 (`/login`, `/oauth2/callback`, `/logout`, 公开的 `/api/me`) 由
  `server.rs` 装配 (不在本模块, 仅 auth 启用时挂载).

## API endpoints

```
GET    /api/records/{id}[?view=parsed]   → {record, parsed_request?, parsed_response?, parse_error?}
                                                 (单条 raw + parsed view, WebUI 弹窗按需拉)
GET    /api/sessions                     → {sessions, total}  (叶子节点, latest-first)
GET    /api/sessions/{sid}/timeline[?before=UUID&limit=N]
                                               → TimelinePage {rounds, tail, has_more}
                                                 (session-aware timeline 分页, oldest-first)
POST   /api/sync   body: {selected?, expanded[]}  → {sessions, rounds, timeline?}
                                                 (WebUI 3s 轮询统一入口: sidebar + timeline diff 一次采集)
GET    /api/secrets
POST   /api/secrets
PUT    /api/secrets/{id}
DELETE /api/secrets/{id}            → static 基线存在 (含 override) 一律 409 (#156);
                                       仅 dynamic-only 可删 (204)
PATCH  /api/secrets/{id}/decision     body: {"mode": "default|prefer_static|disabled"}

GET    /api/providers
POST   /api/providers
PUT    /api/providers/{id}
DELETE /api/providers/{id}           → 同 secrets (#156)
PATCH  /api/providers/{id}/decision
POST   /api/providers/probe          body: {base_url, api_key?} →
                                         {probes[4] (openai/anthropic/gemini/ollama,
                                          status: ok|auth_failed|absent|error,
                                          models?, detail?, urls[]),
                                          recommended?, note?, common_uri?}
                                         (协议自动探测; 失败是数据不是 HTTP 错误 — 恒 200,
                                          仅非法 base_url → 400; 算法在 proxy::models.
                                          urls = 该族实际 GET 的完整 URL (不黑盒回显);
                                          common_uri = recommended 族的布局断言
                                          ("/v1"|"" — detect 知识, 保存落盘为
                                          Endpoint.common_uri)
PUT    /api/providers/probe          → 同 PUT /api/providers/{id}, 固定 id="probe"
DELETE /api/providers/probe          → 同 DELETE /api/providers/{id}, 固定 id="probe"
                                          (静态段优先于 {id} 参数段, 该 id 的编辑/删除只能
                                           经此进 — 补齐前存量 "probe" 条目 405 不可管理;
                                           新建该 id 仍被拒绝, 纯防混淆)
POST   /api/providers/{id}/pool-reset → {id, reset} — 清空该 pool 全部成员闹钟
                                          (非 pool 条目 400 / 不存在含 decision-Disabled 404;
                                           只动运行时内存态, 不触碰配置)
GET    /api/providers/{id}/models    → ModelPreview {models[], source: "router-synthesized"|"upstream",
                                          upstream_id?, error?} — 模型清单预览 (endpoints 弹窗
                                          的 Models 按钮): Router 走 advertised_names 本地合成
                                          (与转发路径 GET /{short}/{router}/models 同源同值, 共享
                                          TTL 缓存); Direct/Pool 经 resolve_route 后上游**现场**
                                          fetch (不进缓存 — 与 Direct /models 逐请求透传一致).
                                          失败是数据不是 HTTP 错误 (恒 200, fetch/解析失败落在
                                          error 字段, SEC-2 净化); 仅条目不存在 → 404.
                                          算法 SSOT 在 proxy::models::provider_model_preview.
GET    /api/providers                → pool 条目平级附加 pool_status[] (每成员
                                          {id, active, resume_in_secs} —
                                          PoolStates 只读派生, 非 pool 条目该字段缺席)

GET    /api/api-keys
POST   /api/api-keys
DELETE /api/api-keys/{id}
PATCH  /api/api-keys/{id}/toggle

GET    /api/settings                → {audit_capture: "off"|"errors"|"full"} — 全局设置当前值
PUT    /api/settings                body {audit_capture: 同上三态 string} (兼容旧 bool) → 200 同 shape
                                          (详细日志开关: 开 = 新请求记录完整
                                           req_body_raw / raw_resp_body; 关 = 极致省内存
                                           (timeline 不受影响, B1 blocks 派生)。per-request
                                           原子 (push 快照, 在途请求不受切换影响); 原子
                                           持久化 state.toml; 非法 body 统一 400。语义 SSOT
                                           见 src/state.rs::AuditCapture)
                                           前端入口 (B3): header 工具栏「详细日志」checkbox
                                           (#audit-capture) — 服务端状态的镜像 (GET 初始化
                                           + PUT 乐观更新/失败回滚/在途 disabled), 不入
                                           state 对象 (auto-refresh checkbox 同型, DOM 即状态)
GET    /api/usage/summary[?hours=N]  → UsageSummary {range, pricing_status, totals,
                                                 by_bucket[], by_model[], by_provider[],
                                                 unpriced_models[], zero_priced_models[],
                                                 redactions{by_secret[], recent[]}}
                                                 (模型用量统计: hours 缺省 168 (7d), 0→1,
                                                  上限 min(retention_days×24, 9600);
                                                  ≤14d hour 粒度, 更长 day 折叠;
                                                  usage tab 5s 节流轮询)
```

> **探测假设 (best-effort 已知边界)**: 探测假设 base_url 是裸 origin/base (不带
> 路径前缀), 探测端点 = `{base_url}/v1/models` 等。Azure 风格路径前缀 base
> (如 `https://xx.openai.azure.com/openai`) 的探测 URL 会拼出不存在的端点,
> 大概率全部 `absent` / 无 recommended — 属 best-effort 已知边界, 手选 protocol
> 即可。

所有响应带 `Cache-Control: no-store`, 避免浏览器对自动刷新返回缓存内容.

> **disabled 条目可见性**: `GET /api/secrets` / `GET /api/providers` 的响应各带一个
> `disabled` 数组 (decision=Disabled 的 static 条目, **masked** 视图 —
> `SecretMasked` / `ProviderMasked`, 绝不回明文). effective view 排除它们 (CFG-1),
> 此数组让 WebUI 渲染灰色删除线行并提供 decision 切回入口 (2026-09-13 排查修复).
> 悬空 decision (static 侧已删除的 id) 在启动时被 prune (contracts.md **CFG-6**).

> **POST 的 `generated_id` 明示位** (#164 子项 6): secrets / providers 的 POST 请求
> 不传 `id` (或传空串) 时, 服务端自动生成 UUID v4, 并在 201 响应体额外携带
> `"generated_id": true` (显式传 id 时该字段缺席). 脚本用户可据此感知 id 是服务端
> 生成的; 旧客户端忽略新字段即可, 向后兼容.

> 注: 旧的 `GET /api/records` (扁平分页) + `GET /api/nodes/{id}/timeline` (基于 node_id)
> 已删除, 由 session-aware sync API 替代. 详见 `dag` 模块的 session_rounds /
> timeline_view / timeline_diff / sync_snapshot.

### Records parsed view (单条按需拉取)

`?view=parsed` 返回 `parsed_request` (从 `req_body` 按需用 ingress codec 解析) +
`parsed_response` (直接取自 `record.resp_parsed`, 由 proxy 层的 `StreamScan` 在流过程中
增量累积, 非流式路径在响应完成时一次性计算). Gemini/Ollama 无 codec → `parse_error` + fallback raw.
audit_capture 未保留的请求 (off 档全部 / errors 档成功请求, B2/B3) parsed_request 恒 null + `record.audit_capture_off = true`
(`parse_error` 报 "req_body not captured...") — WebUI 审计溯源弹窗 (`data-audit-node`,
判 `record.audit_capture_off`) 与 raw 弹窗同占位文案.

### Record preview / model 提取 (push 时一次性)

`extract_preview_and_model` (定义在 `crate::derive`, 协议无关字节级, 不依赖 codec reader)
在 push 时从 `req_body` 一次性提取两个轻量字段 (提取后丢弃 body):
- `preview`: sidebar 主标题 (截断到 48 chars). 优先取最后一条 user message (可读性好);
  无 user 时回退到最后一条有文本的 message (tool_result / assistant).
  压缩 marker ("What did we do so far?") 命中时 fallback 到最后一条 assistant 摘要.
  提取失败 (非 JSON / 缺 messages) → preview=None, 前端降级到占位文本:
  sidebar round-item `(no preview)` / sub-dot tooltip `?` / timeline 气泡 `(no content)`;
  session 级条目先试 `path` 字段 (SessionView 携带, TimelineRound 不含).
- `model`: 顶层 `model` 字段 (OpenAI / Anthropic 共有), sidebar 副标题第二行.

**假设声明**: 假设 messages 数组中 user 在 assistant 之前; 假设压缩 marker 是固定字符串.
**降级**: 任一假设不成立 → fallback (preview 占位文本 / 空 model), **永不 panic**.

### session-aware timeline (TimelineRound / TimelineTail / TimelineDiffData)

新模型基于 SessionId (替代旧的基于 node_id 的 timeline). 三条查询路径在 `dag` 模块
(`dag/timeline.rs`):

- `session_rounds(sid)`: sidebar 三级菜单的轻量 round 摘要 (RoundBrief, 不含 delta messages).
- `timeline_view(sid, before, limit)`: timeline 初始加载 + lazy load (向前翻更老).
  返回 `TimelinePage { rounds: Vec<TimelineRound>, tail: TimelineTail, has_more }`.
- `timeline_diff(sid, after, tail_length)`: sync 轮询的 diff.
  返回 `Option<TimelineDiffData { new_rounds, tail }>`, None = 无变化 (304 等价).

**req_delta_messages 实现** (B1): 从 BlockPool 结构化派生 (`derive::extract_delta_messages_from_blocks`)
— `req_delta` (MessageRef, real 视角) resolve → real→mock 替换 (`redactions` 投影重建, 不含真
实 secret 输出) → ingress writer 序列化 + 根节点 system 注入 (system 来自根节点 `system_refs`).
与旧 req_body_raw 末尾切片**逐字节等价**: 常驻 proptest `prop_blocks_derivation_matches_raw`
(生成器矩阵) + consistency-check shadow `assert_delta_view_matches_raw` (渲染点) 双重守卫.
旧实现 (`extract_delta_messages_from_raw`) 保留为 oracle, 生产路径不再调用.
已知限制 (行为保持, 未修复): OpenAI writer 的 ToolResult 拆分场景 (混合 Text+ToolResult 的 user
消息拆为 1+N 条 wire 消息) 下, 尾部对齐使 delta 可能**丢失本轮展开的头部** (伴随的 user text 气泡
与部分 tool 消息), 不会混入前序轮消息; 修复属 DTO-6 ⏳.

**tail (response 抽屉)**: 末轮 (链中最新) 的 response 内容. B1 双态: finalize 后从
`response.message` + 元字段渲染派生 (`derive::response_parsed_from_parts`); 流式进行中
沿用 stored 节流 parsed (前端实时进度). `length` = parsed 序列化字节数 (parsed 为 None
时 fallback 到 raw_resp_body.len()). 前端用它判定是否需要更新抽屉.
非末轮的 response 内容已被下一轮 delta 的 assistant message 包含 (Phase A 决策), 故 tail
只代表"最新尚未被 delta 消费的 response".

### sync API (POST /api/sync, WebUI 3s 轮询统一入口)

`sync_snapshot(expanded, selected)` 在 DAG 层单个 `inner.read()` 锁内一次性采集三部分
(避免新 push 在两次锁之间漂移):

- `sessions: Vec<SessionView>`: 全量会话列表 (sidebar 一级树).
- `rounds: HashMap<SessionId, Vec<RoundBrief>>`: 仅 expanded session 的 round 详情 (sidebar 三级菜单).
- `timeline: Option<TimelineDiffData>`: 仅 selected session 的 diff (None = 无选中 / 无变化).

selected 游标 = `(session_id, latest_round, response_length)`:
- `latest_round`: 前端持有的最后一条 round id (不属于本 session 时视为初始加载, 返回全部).
- `response_length`: 前端持有的末轮 tail 长度 (与当前 tail.length 比对, 不一致则返回新 tail).

### ForwardRecord.redactions

`Vec<(mock, secret_id)>` — 从 `redact_ir` 产出的 `RedactionMap` SSOT 派生
(见 `proxy/recorder.rs::derive_redactions`). WebUI 的 mock 高亮和 "命中" 筛选都基于此字段,
**永不**在前端重新计算, 避免前后端漂移. 不含真实 secret value, 可安全暴露.

### 安全姿态

- GET 永不返回 secret 的 `value` / provider 的 `api_key` 真实值 (用 `mask_value` 占位).
- 写操作由本地监听 (默认 127.0.0.1) + server 层 Host/Origin guard (SEC-7,
  `src/server_host_guard.rs` — 防 DNS rebinding, 未声明域名 Host 一律 403;
  `/api/*` 写另校验 Origin/Sec-Fetch-Site) 保护。"同源策略兜底" 的旧假设已被
  rebinding 攻破, 不再单独依赖.
- 内部错误细节不通过响应体返回, 仅进 tracing.

### API keys (无 auth 依赖)

API key CRUD **无条件挂载** (在 `web::router()`, 不依赖 `auth.enabled`),
遵循"**只认证, 不隔离**"哲学:

- `auth.enabled = false` (单用户模式): store 仍然构造, WebUI 可签发/管理 key.
  数据持久化在 state.toml, 用户可"预先配置好", 等启用 auth 后即可使用.
  注: 此时 forwarding 路径的 `require_api_key` middleware 不挂载, 这些 key
  暂无消费方, 但不影响数据生命周期.
- `auth.enabled = true`: store 同时服务 WebUI 管理 + forwarding middleware 鉴权.
- **不做用户隔离**: 移除 `tenant_id == user_sub` 过滤 — 所有 (登录的) 用户共享
  同一份 key 池. 设计理由见 `src/web/api/apikeys.rs` 头部注释.
- `tenant_id` / `created_by` 字段保留 (兼容已有持久化数据), 统一填 `"admin"` 占位,
  不影响业务逻辑 (lookup 不读 tenant_id).

## WebUI 渲染契约 (`index.html`)

> 前端不变量 I1 (气泡数 == req_delta messages 长度; 空 delta 轮按 round_kind 三态
> 分发: retry → 0 气泡 + 徽章 / no_messages → preview fallback) / I2 (sidebar 条目数
> == HTTP 请求数) / I3 (timeline 轮次 DOM 顺序 == 数据顺序 oldest-first) 见根目录
> AGENTS.md. 回归守卫: `tests/webui/im-ui.spec.ts`. round_kind 派生语义 SSOT =
> contracts.md DTO-9.

### Provider 表单 (构造分野 + 路由编辑器) 与列表 router 行渲染

- **协议词表两套** (2026-09 决策, 见根 AGENTS.md 已知限制段呈现策略): 端点行的
  protocol select 下拉词表 = `GET /api/providers` 的 `webui_protocols` (仅 codec 覆盖族
  openai/anthropic/openai-responses, 代码侧谓词 SSOT = `Protocol::codec_covered()`);
  全量 `protocols`/`shorts` 仅供路由约定表格渲染与 endpoints 弹窗的 short 映射. 存量
  gemini/ollama 条目编辑与 Detect 探测推荐经 `setEndpointProtocolValue` 动态 append
  "(experimental)" 选项 (词表灌入发生在 `addEndpointRow` 物化时 — "populate 先于
  set" 时序由行生命周期天然保证) — 后端能力保留, 只是新建不引导.
- 表单 `#p-kind` 是构造分野的唯一事实来源 (**三构造**: Direct / Router / Pool):
  **Direct** (端点行编辑器 `#p-endpoints-list` + API Key 字段) vs **Router** (路由
  编辑器字段组 `#p-router-fields`) vs **Pool** (成员编辑器 + exhaust 高级配置字段组
  `#p-pool-fields`). 切换只显隐字段组, **不清空已输入内容** — Direct↔Router↔Pool
  来回切不丢数据 (与 #181 的字段保留语义一致)。
- **Direct 端点行编辑器** (multi-endpoint, D1-D3): 每行 = protocol select + base_url
  input + common_uri 徽标 + Detect 按钮 + 行删除; "+ Add endpoint" 增行. 行数据
  SSOT 是 DOM 本身 (同路由编辑器模式): common_uri 暂存存 `row.dataset.commonUri`
  (null 态 = 无该属性), 行序 = 声明序 = fallback 序 (D2). ≥1 行约束在提交侧校验
  (`collectEndpointsFromForm`: 0 行 / protocol 或 base_url 空 / 同 protocol 重复
  三类前置拦截, 文案与 routes/members 同风格). 编辑回填 = `p.endpoints[]` 全量物化,
  保存全量提交 endpoints (无 #157 null 歧义, "保留" 由回填实现). api_key 保持条目级
  一份 (共享凭证, D3).
- **Pool 构造** (spec-pool-provider §10): 成员编辑器 = 有序 Direct provider 下拉
  (行序 = failover 优先级, ↑/↓ 排序, 候选排除编辑对象自身 + 仅 Direct 条目, 悬空
  成员补 "(missing)" 选项); exhaust 三通道 + cooldown 在原生 `<details>` 高级区
  (默认折叠, 显示 "默认策略" 提示), **dirty 追踪** — 未改动不发送 (创建 → 后端
  内置窗口限额默认表 / 编辑 → 回填旧值), 改动过才全量发送 (后端字段级替换)。
  提交语义: Pool 分支全量发 `members` (≥1 条, 每行前端必填拦截)。
- **构造切换的显式取消** (后端 PUT 省略 = 回填旧值的配对语义): 编辑对象是
  router/pool 而表单构造不是时, 分别发 `routes: []` / `members: []` (后端定义的
  "显式退出该构造" wire 语义)。
- **列表 pool 行**: URL 列渲染成员清单 + 运行时状态徽章 (数据 = 响应的
  `pool_status` 服务端派生字段, 前端不重算): ▸ 首个 active 成员 (当前命中,
  列表序解析的前端派生) + dot 两态 (● active / ◐ 耗尽至闹钟 `until HH:MM` 或
  剩余秒 — missing/disabled 成员不进状态机, 徽章恒 active, 由 decision/enabled
  表达); 超过 2 条折叠 + "+N more"。
  actions 附 `reset` 按钮 (`POST /api/providers/{id}/pool-reset` 后刷新)。
  protocol pill 显示成员 egress 去重集合 (每成员的链尾近似; 中间 pool 跳取其首个成员)。disabled pool 行
  纯配置展示 (无运行时数据)。
- **路由编辑器** (#179): 每行一条 `Route` — `model_pattern` (`*` 通配) / `target`
  (下拉: 其余 provider, 排除编辑对象自身防自环; 悬空目标保留 "(missing)" option,
  编辑保存不静默丢指向) / `upstream_model` (可选, 空 = null 透传) / `priority` (整数可负,
  空输入按 0) + 启用 checkbox. **wire 无独立 enabled 字段**: 取消勾选 = 提交
  `priority: null` (路由保留但不参与匹配).
- **提交语义**: Router 分支全量发 `routes` (≥1 条; 每行 model_pattern / target 前端必填
  拦截, 不依赖后端 400). Direct 分支不发 `routes` / `members` — 构造切换的显式取消
  例外见上方 "构造切换的显式取消" 条.
- **Detect 协议探测** (端点行内, per 行): `POST /api/providers/probe` (该行 base_url +
  条目级 api_key 当前值) 手动触发; recommended 只自动填入**该行**的 protocol select
  (建议非命令, 用户可手改 — 词表 = webui_protocols, 透传族动态 append), 另附模型
  chips 预览 (MVP 深度 = 浏览 + 点击复制). 每行结果回显该族全部探测 URL (`GET {url}`
  子行 — 不黑盒, 全 404 时用户可对照调整 base_url); 无推荐时附引导 hint.
  common_uri 知识链 (per 行): detect → `row.dataset.commonUri` 暂存 (badge 以
  `+/v1` / `✓ included` 追加回显在该行 base_url 输入框后, 点击复制 base_url+
  common_uri 整体) → 保存 payload 全量携带 (null = 未探测, 前端编辑回填 effective
  原值实现"保留") → 后端 `Endpoint.common_uri` 落盘 → fetch_model_list fast path.
  base_url 编辑作废该行暂存 (探测结果只对被探测 URL 成立). 表单值变更后旧结果不
  自动清除 (下次点击以当前表单值覆盖); probeEpoch 代数对账沿用 (dialog 重开即
  丢弃在途结果), 行级追加行存活 (isConnected) 与该行 base_url 未变两个落地条件.
- **列表 router 行**: URL 列渲染路由摘要 `model_pattern → target · egress` (禁用路由主文本
  删除线; 超过 2 条折叠为首条 + "+N more", 全量在 td title). egress 是**展示近似** —
  从路由 target 出发 walk 链尾 Direct 的**端点集合** (`chainTailEndpoints`: 中间 router
  取最高优先级启用路由的目标, 防环 seen set, 悬空 → `?`; 链尾多端点时协议并集入
  集合文案 `protocolSetLabel` — 单一 → 该 protocol, 短列表逗号连接, 放不下 →
  `mixed`), 忽略路由 upstream_model 重写对后续跳匹配的影响 (展示无需 per-model
  精确解析). protocol pill 显示路由 egress 的去重集合. egress 标记挂静态教育 tooltip
  (跨协议代价: reasoning_content 丢弃; 流式翻译支持 — codec 覆盖族任意 pair 均可,
  M2 走查的 Responses 非流式例外已随其流式 writer 落地移除).
- **列表 direct 行** (multi-endpoint): 每端点一枚 protocol pill (集合展示, tooltip
  附该端点 base_url); URL cell 显示第一端点 base_url (声明序 = fallback 序) +
  "+N" 角标 (td title 全量 `protocol: base_url` 列表). disabled 行同型展示.

### Endpoints 弹窗 (direct 端点行 + router/pool 入口矩阵 + Models 预览)

- **direct 条目 = per 端点行形态** (multi-endpoint): 每行 = 一个已配置端点 —
  `.ep-row[data-short]` 头行 = 协议名 + short chip + direct 徽章 (同协议透传, 无
  translate/unsupported 形态 — 端点行入口按定义同协议, 连 codec 都不需要) +
  Models 按钮; 次行 = upstream base_url ↤ 入口 URL 双 code 块 + Copy (复制入口
  URL). 行列表尾部附 fallback hint (未配置端点的 ingress fallback 第一端点跨协议
  翻译, codec 覆盖族限定).
- **router/pool 条目 = 5 协议入口矩阵** (M2 走查重设计形态保留): 每协议一张卡
  `.ep-row[data-short]` — 头行 = 协议名 + short chip + 模式徽章 (direct=info 软底 /
  translate=warn 软底 / n/a=inactive) + Models 按钮; 次行 = URL code 块 + Copy 按钮,
  或虚线 "not supported" (unsupported 行无 Models/Copy 按钮 — 不引导不可用动作).
  per-ingress 模式判定 (`ingressMode`) 按**链尾端点集合** (D2 语义): 集合含 ingress →
  direct; 否则 fallback 首端点 — 双方都 codec 覆盖 → translate; 否则 unsupported.
  单端点集合退化为旧单 egress 语义. translate 徽章 tooltip 统一流式语义
  (streaming included, 不再按 pair 分化), 覆盖集 `CODEC_SUPPORTED` 与后端
  `Protocol::codec_covered()` 同步.
- 主题行 `#provider-endpoints-subject` 回显 provider id / name / egress (链尾端点
  集合的协议并集文案, `protocolSetLabel`).
- **Models 预览** (`GET /api/providers/{id}/models`): 每行 Models 按钮惰性展开
  `.ep-models` 面板 — 首次展开 fetch, 结果记 `panel.dataset.loaded` (弹窗生命周期内
  的会话级缓存, 收起再展开不重复请求; fetch 失败**不**记 loaded, 再次展开即重试).
  API 是条目级 (multi-endpoint 后端统一 OpenAI 视角选端点 — preview 现状, 前端
  不补偿; direct 多端点行的面板各自惰性展开, 拉同一清单). 面板渲染复用 Detect
  探测的通用件 (`.probe-models` / `.probe-chip` 点击复制 / `.probe-line(-err)`),
  标题附来源标注: `synthesized from routes` (Router 本地合成) vs `upstream: {id}`
  (Direct/Pool 上游取数 — pool 即当前命中成员). 失败是数据: 面板内错误行, 不是
  HTTP 错误弹窗. 事件委托挂 `#provider-endpoints-body` (rows 动态生成), chip/Copy/
  Models 三类目标分流.

### Sidebar 分组渲染 (二级 + 三级小圆点)

- 二级条目 (`.round-item` = 用户轮次, req_delta 含 `role=user`) 显示 preview 文本 + 时间.
- 紧随其后的工具调用轮次 (req_delta 无 user, 仅 assistant+tool_result) 折叠为三级小圆点
  (`.sub-dot`), 横向排列在组首下方.
- 圆点颜色 = tool name 哈希 (FNV-1a 调色板, 与 provider 图标复用), tooltip 显示 tool name + 时间.
- 点击圆点 = `selectRound` (同二级条目).
- **重试轮** (`round_kind === 'retry'`, 后端 push 时预计算, SSOT): 继承 parent 的
  round_role + preview → 与原轮同型渲染 (用户轮重试仍是组首, 工具轮重试仍是 sub-dot
  — fork 场景祖先链完整, 同型成立; 仅孤儿链 parent 被 LRU 淘汰时, Tool 重试轮作为
  链首走隐式组首 fallback), preview/tooltip 加 `↻` 前缀区分 (消除与原轮的 preview
  歧义). 语义: IR 等价重发, 用户没有发新消息, 见 contracts.md DTO-9 / UI-1.

### 每轮操作按钮 (info + raw)

timeline 每轮 header 含两个按钮:
- `ℹ` info: 弹窗展示传输层元数据. 字段两路来源: 本地即时渲染 (TimelineRound 的
  id/round_role/created_at/redactions + 末轮 TimelineTail 的 status/elapsed/streamed/
  complete/error — 非末轮显示 "(history round)") + 异步懒拉补全 (`GET /api/records/{id}`
  的 method/path/model/upstream_id; model 是 **egress 视角** — 路由改写生效时与
  upstream_model 同值 (改写轮次两行显示相同值), 无改写时 = 客户端原值 — M1 走查
  修复: record DTO 补 model 字段, 弹窗 Model 行不再恒 "(unknown)").
- `raw`: 弹窗展示原始 req_body / resp_body / req_headers / resp_headers (按需懒拉
  `GET /api/records/{id}`). body 是 LLM 视角 (已 redact, 安全展示); headers 已脱敏
  (auth/cookie 等 = `<redacted>`; 名单 = 硬编码黑名单 ∪ `[redact] redacted_headers`,
  SEC-4). 流式响应的 resp_body 为空 (不保留 SSE 字节), 显示提示. audit_capture off
  期间的请求 (`record.audit_capture_off`, B2/B3) req/resp body 区段显示未捕获占位
  (文案 SSOT `NOT_CAPTURED_NOTE`, 判据统一为该结构化字段; 优先级高于 streamed 空态
  提示 — off 下非流式 body 同样未存; headers 照常展示).

### Response 气泡渲染

一条 response 在数据模型上 = messages 数组中的 **一条 assistant message**. 进入下一轮时
它仍是 messages 中的一项 (不拆分). 前端尊重这个数据模型: text 和 tool_calls/tool_use
渲染在**同一个气泡**内, tool_call/tool_use 段用 `.bubble-tool-call` 子区域做视觉区分
(边框 + 缩进 + monospace). 不拆分为多个独立气泡.

思考原文 (`reasoning_content`, #176) 也渲染为 assistant 气泡内的 `.bubble-tool-call`
子区域 (位于 text 段之前), 复用同款视觉区分 — 数据已到前端 JSON
(request 历史 assistant 消息 + parsed response 的 message), 不渲染会静默不可见.

### 气泡内 XML 块渲染 (`renderTextWithXmlBlocks`)

气泡文本 (system/user/tool 纯文本气泡 + assistant 的 reasoning/text 段 + Anthropic
response text block) 中 "开/闭标签各自独占一行" 形态的块级 XML (如
`<system-reminder>` / `<function_results>` / agent 自定义标签) 被渲染为气泡**内部**
带背景色的独立区块 `.xml-block` (层级同 `.bubble-tool-call` 子区域) — **不拆新气泡**,
UI-1 气泡数不变量不受影响. 区块结构: 徽章行 (tag 名 + 开标签属性原文, 信息无损 —
字面标签行不重复展示) + body (内容, mock 高亮照常生效).

- **识别是 best-effort** (ROB 纪律, `xmlBlockSegments`): 行级正则 + 同名标签 depth
  计数 + 未闭合扫描 memo 化 (同 tag 重复形态 O(N), 防主线程冻结; 最坏互异 tag 仍
  O(N²)); 行内标签 / 自闭合 / 未闭合 / 属性含尖括号一律不识别, 降级为纯文本原样
  展示, 永不 panic. 安全性: 只做行级识别, 先分段再 escapeHtml, 无注入面.
- **配色**: per-tag FNV-1a 稳定映射 `.xml-c0..xml-c5` tint class (同 tag 恒同色;
  `XML_TINT_COUNT` 与 CSS 变体类是两处同步的对偶), 颜色全走 CSS `light-dark()`
  跟随主题, 不拼 inline style (主题切换不 stale).
- 回归守卫: `tests/webui/im-ui.spec.ts` "XML 块渲染" 用例 (块化 + mock 块内高亮 +
  自闭合 depth 安全 + 未闭合降级).

### Response 抽屉 (overlay 架构)

Response 是独立的 `.response-drawer`, **悬浮**在 `#detail` 之上 (position:absolute overlay),
而非 flex column 分栏. 抽屉始终展示末轮的 response (尚未被任何 delta 消费的部分).

**架构核心** (消除循环依赖): `#detail` 高度固定 (= wrapH, 不依赖 drawerH).
drawer overlay 不影响 #detail 的滚动空间. 因此:
- `maxScroll = scrollHeight - wrapH` (不依赖 drawerH)
- 所有元素位置 = `offsetTop - scrollTop` 的纯函数
- `drawerH = f(scrollTop)` 是纯函数, 无循环, 无死锁

**两段式高度** (`drawerH = max(段A, 段B)`, 上界 extremeMaxH):
- **段 A — 跟踪选中气泡** (phase 1/2):
  - 气泡在视口下方 → minH (10%).
  - 气泡在视口内 → `wrapH - bubbleBottomY - GAP`, clamp [minH, maxH].
  - 气泡滚出顶部 → clamp 到 maxH (40%).
- **段 B — 遮挡露出的 placeholder** (phase 3/4):
  - `placeholderExposed` = placeholder DOM 在视口内的可见高度.
  - 未露出 (= 0) → 不影响段 A (phase 3 等价).
  - 露出 → drawer 至少覆盖 `placeholderExposed - GAP` (顶部让出 GAP 作呼吸空间),
    平滑到 extremeMaxH (80%).

> **关键不变量**: drawer 遮挡露出的 placeholder 时顶部让出 `DRAWER_GAP` (≈28px) 作呼吸空间
> (WebUI 反馈3: 末轮 request 与 drawer 上边缘的视觉间距). 残余 GAP 截是白底 placeholder 顶部,
> 作为呼吸空间可见 (可接受, 非空白泄漏). 历史 bug: 旧 phase 4 用 `bubbleBottomY <= 0` 作
> 门槛, 末轮选中时 bby 永远 > 0 (因为末轮紧邻 placeholder, maxScroll 不足以让它滚出顶部)
> → phase 2 clamp 封顶在 maxH, placeholder 空白被露出. 修复: 改用 `placeholderExposed`
> (基于 placeholder 实际露出量) 作为段 B 驱动, 与段 A 解耦.

**placeholder**: `#detail` 末尾的 `.drawer-placeholder`.
- 长内容 (contentEnd > wrapH): height = extremeMaxH (80% wrapH), 提供 phase 4 滚动空间.
- 短内容 (contentEnd ≤ wrapH): height = 0, 不进入初始视口, 也不需要 phase 4.

**新 round 到来**: keyed reconciliation 追加新轮次, `#detail` 高度不变, scrollTop 不变 →
drawerH 不变 → 分配比例保持 (用户视野不受内容变化干扰).

> **follow 自动滚动预留 drawer 空间** (WebUI 反馈2/3): `scrollTimelineToBottomForce`
> 的滚动目标是 `contentEnd - wrapH + drawerH + GAP`, 让末轮 request 底部出现在
> **当前 drawer 上边缘之上 GAP 处** (而非贴视口底被 drawer 遮挡). drawerH 取滚动前的
> 当前值 (保留用户当前的 response 视图, 避免跳变). 段 B (`placeholderCover =
> placeholderExposed - GAP`) 与此自洽: 多滚的 drawerH+GAP 进入 placeholder 区时,
> drawer 至少覆盖 drawerH (顶部 GAP 截留作呼吸空间), 高度稳定不暴涨. placeholder 顶部
> 的 GAP 截是白底, 作为末轮 request 与 drawer 之间的呼吸间距可见 (可接受, 非空白泄漏).
> placeholder 仅服务**用户手动滚动** (phase 4 看 response 抽屉). `isNearBottom` 基于
> contentEnd (placeholder 区视为 "在底部", 新 round 到达仍自动滚回).

scroll-nav 的 bottom 同步到 drawerH, 使底部按钮贴合滚动区域底端.

> **不变量**: `#detail` 高度必须固定 (= wrapH), **禁止**改为 `height: wrapH - drawerH`
> 或引入 flex 分栏 — 那会重建循环依赖 (drawerH 影响 detailH 影响 maxScroll 影响 drawerH).

### 选中态高亮 (issue #36)

选中轮次 (来自 sidebar 点击或 timeline header 点击) 持续高亮 (`.tl-round.selected`,
背景色 + 左侧色条), 不是一闪而过的动画. 选中瞬间叠加一次 `.flash` 闪烁动画作为反馈.

### timeline 滚动状态机: follow / pinned (I5 ↔ UI-6)

timeline 有两种滚动状态, 由 **视口距底部距离** 机械推导 (SSOT), 不由 "最近点了什么" 决定:

- **follow** (距末轮底部 ≤ `NEAR_BOTTOM_PX` ≈ 100px): 新 round 到达 → 自动滚到末轮底部
  (`scrollTimelineToBottomForce`, 预留 drawerH+GAP 让末轮 request 完整可见).
  **follow 闭合不变量 (UI-6)**: follow + 短内容 (contentEnd ≤ wrapH) 时,
  `updateResponseDrawerLayout` 自动压缩 drawer 到 `wrapH - contentEnd - GAP` (派生属性,
  让末轮完整可见). 契约 + 失效区间豁免见 contracts.md `prop_follow_invariant_under_new_round`.
- **pinned** (距底 > `NEAR_BOTTOM_PX`): 新 round 到达 → 不滚动, 浮出 `#unread-badge` 显示 "↓ N".

**follow/pinned 视觉指示 (WebUI 反馈1)**: drawer 顶部边缘颜色随状态切换 — follow 时
淡线 (1px `--border`), pinned 时 accent 细条 (3px `--accent` = indigo, + indigo 辉光阴影).
`.pinned` 类由 `updateResponseDrawerLayout` 在每渲染/滚动周期同步 (与 drawer 高度同一周期,
覆盖抽屉从隐藏切到可见等边界). 配色与 unread badge 一致.

**关键解耦 (方案 X)**: `selectedRound` 与 `timelineFollow` 解耦. `selectedRound` 是
"用户最后显式关注的轮次", **不随 follow 自动推进** (避免 Response 抽屉布局连续重算 +
`.flash` 反复触发). 仅 "进入 follow 的显式动作" (点 Session / 点 unread badge / 初次
loadTimeline) 才重置 selected 到最新轮 (`.selected` 持续高亮; 不触发 `.flash` — 因
这些动作用 `scroll:'bottom'` 滚到底, 与 `highlightRound` 的 70% 定位冲突).

**状态机入口**:
- `syncFollowMode()`: 唯一改 `state.timelineFollow` 的入口, 在 scroll 事件 (RAF 合并) +
  新内容追加后调用. pinned → follow 时清零 `unreadCount`.
- `handleNewRounds()`: 新 round 到达时按 follow/pinned 分支处理 (follow 滚底 / pinned 累加未读).
- `jumpToLatest()`: unread badge 点击 = 进入 follow + 重置 selected 到最新轮.

**"↓ 回到底部" vs "跳到最新" (unread badge) 的语义区别**:
- `scrollTimelineToBottom()` (↓ 按钮): 仅滚动视口到最新轮, **不重置** selectedRound.
  进入 follow 由后续 scroll 事件的 syncFollowMode 自然完成.
- `jumpToLatest()` (unread badge): 滚动 + **重置** selectedRound 到最新轮 (`.selected` 持续高亮, 无 flash).

### 其它渲染细节

- 三段式 fingerprint: 自动刷新期间 request-pane 滚动位置 + bubble 展开状态保持.
- 三级展示气泡 (折叠 → 展开 → 弹框全文).
- 悬浮导航按钮 (回到顶部/底部): 固定在对话框窗口右侧, 不随内容滚动 (issue #36).
- 气泡颜色 + sender icon 分类.
- 气泡间微小间距 (margin-bottom, 避免视觉粘连).
- tool round 预览: 直接消费后端预计算的 `round_role` + `preview` 字段 (前端不做 best-effort 推断).

### 主题系统 (双主题 + 自动跟随系统)

视觉语言 = **冷灰蓝中性面 + 靛蓝 (indigo) accent** (2026-08 重设计, 参考 aibox/web/traffic 的
视觉风格; 旧版为 Catppuccin Latte/Mocha). 分层表面 (canvas → shell → surface → inset) /
三级边框 (`--border` / `--border-faint` / `--border-strong`) / 交互态统一走 accent 家族:
hover = `--bg-hover` (indigo 微染), 选中 = `--bg-selected` / `--tint-selected` (+ 左侧
accent 色条); 徽标分两类 — 计数/未读等可扫读徽标用实心 accent, 分类 pill / 状态 badge
用 `--*-soft` 软底 + 同色深字. 排版: Inter 优先 sans 栈 (本机装有则用,
零外部依赖), 13.5px 基准, 数字密集区 `tabular-nums`. 三态切换: auto (跟随 OS
`prefers-color-scheme`) / light / dark, 由 header 工具栏的 `.theme-switch` 三按钮控制,
选择持久化在 `localStorage['sg-theme']`.

- **ThemeResolver** (`<head>` 内联阻塞脚本, 最早执行避免 FOUC): 读 localStorage → 写 `<html data-theme="auto|light|dark">` + `data-effective-theme` (auto 已解析为 light/dark). 监听 OS 偏好变化, auto 模式下实时更新.
- **CSS**: `:root` 声明全部语义变量为 `light-dark(亮值, 暗值)`, 自动随 `color-scheme` 切换. **禁止**在 `input/button/select` 上硬编码 `color-scheme: dark` (会破坏 `light-dark()` 解析, 历史教训); 让它们继承 `:root` 的 color-scheme. 阴影同理: `light-dark()` 只接受颜色, 整段 shadow 用 `--shadow-color` / `--shadow-color-md` 颜色变量在各 box-shadow 处组合.
- **语义层 vs 调色板层**: 组件只引用语义变量 (`--fg/--fg-muted/--fg-faint/--panel/--border/--accent` 等), 不直接引用色相名. 改色相只动 `:root`, 调对比度只动语义映射.
- **对比度**: `--fg` / `--fg-muted` 在对应底色上达 WCAG AA (≥4.5:1); `--fg-faint` 用于 placeholder / disabled / 占位提示 (非阅读重点, 可低于 AA).
- **JS inline-style 例外**: `PROVIDER_PALETTE` 拼进 `style` 属性, 无法用 CSS var 跟随主题, 故 JS 端用单个 2D 数组 `[{light, dark}, ...]` (成对结构防亮/暗漂移), 由 `currentColorScheme()` (读 `data-effective-theme`) 选对应半边. 主题切换时主脚本注册的 `window.__onThemeChange` 回调失效 sidebar fingerprint 后直接 `renderSidebar()` 重画 (因 renderSidebar 的 fingerprint 不含主题, 不失效会短路 → icon 不更新).
