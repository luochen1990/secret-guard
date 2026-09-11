# web 模块 — JSON API + 单页 WebUI 契约

> 本文件是 `src/web/` 目录的导航与契约汇总. 源文件 (`api.rs` / `mod.rs`) 头部有更细节的注释.
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
  - `apikeys.rs` — API key CRUD (4 endpoints, 无条件挂载, "只认证, 不隔离").
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

GET    /api/api-keys
POST   /api/api-keys
DELETE /api/api-keys/{id}
PATCH  /api/api-keys/{id}/toggle

GET    /api/usage/summary[?hours=N]  → UsageSummary {range, pricing_status, totals,
                                                 by_bucket[], by_model[], by_provider[],
                                                 unpriced_models[], zero_priced_models[],
                                                 redactions{by_secret[], recent[]}}
                                                 (模型用量统计: hours 缺省 168 (7d), 0→1,
                                                  上限 min(retention_days×24, 9600);
                                                  ≤14d hour 粒度, 更长 day 折叠;
                                                  usage tab 5s 节流轮询)
```

所有响应带 `Cache-Control: no-store`, 避免浏览器对自动刷新返回缓存内容.

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

**req_delta_messages 实现**: 当前从 `req_body_raw` 末尾切片 (已 redact, LLM 视角, 安全).
不走 BlockPool + codec writer 路径 (会泄露真实 secret, 需在 web 层重建 redactMap — TODO).
已知限制: 跨协议 writer 拆分场景切片 start 偏小, delta 可能含前序轮消息 (同协议不受影响).
详见 `derive.rs::extract_delta_messages_from_raw`.

**tail (response 抽屉)**: 末轮 (链中最新) 的 response 内容. `length` = parsed 序列化字节数
(parsed=None 时 fallback 到 raw_resp_body.len()). 前端用它判定是否需要更新抽屉.
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
- 写操作通过同源策略 + 本地监听 (默认 127.0.0.1) 保护.
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

- 表单 `#p-kind` 是构造分野的唯一事实来源: **Direct** (Protocol / Base URL / API Key
  字段组) vs **Router** (路由编辑器字段组 `#p-router-fields`). 切换只显隐字段组,
  **不清空已输入内容** — Direct↔Router 来回切不丢数据 (与 #181 的字段保留语义一致).
- **路由编辑器** (#179): 每行一条 `Route` — `model_pattern` (`*` 通配) / `target`
  (下拉: 其余 provider, 排除编辑对象自身防自环; 悬空目标保留 "(missing)" option,
  编辑保存不静默丢指向) / `upstream_model` (可选, 空 = null 透传) / `priority` (整数可负,
  空输入按 0) + 启用 checkbox. **wire 无独立 enabled 字段**: 取消勾选 = 提交
  `priority: null` (路由保留但不参与匹配).
- **提交语义**: Router 分支全量发 `routes` (≥1 条; 每行 model_pattern / target 前端必填
  拦截, 不依赖后端 400). Direct 分支不发 `routes` — **唯一例外**: 编辑对象当前是
  Router 时发 `routes: []` ("显式改回实体"; PUT 省略 routes 会被后端回填旧路由停留在
  Router).
- **列表 router 行**: URL 列渲染路由摘要 `model_pattern → target · egress` (禁用路由主文本
  删除线; 超过 2 条折叠为首条 + "+N more", 全量在 td title). egress 是**展示近似** —
  从路由 target 出发 walk 链尾 Direct 的 protocol (中间 router 取最高优先级启用
  路由的目标, 防环 seen set, 悬空 → `?`), 忽略路由 upstream_model 重写对后续跳匹配的影响
  (展示无需 per-model 精确解析). protocol pill 显示路由 egress 的去重集合 (单一 →
  该 protocol, 短列表逗号连接, 放不下 → `mixed`). egress 标记挂静态教育 tooltip
  (跨协议代价: 流式 501 / reasoning_content 丢弃). endpoints 对话框复用同一近似
  (`resolveEgressProtocol`).

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
- `ℹ` info: 弹窗展示传输层元数据 (method/path/status/elapsed/streamed/model/error/redactions 等,
  全部来自 TimelineRound / TimelineTail, 无需网络请求).
- `raw`: 弹窗展示原始 req_body / resp_body / req_headers / resp_headers (按需懒拉
  `GET /api/records/{id}`). body 是 LLM 视角 (已 redact, 安全展示); headers 已脱敏
  (auth/cookie 等 = `<redacted>`). 流式响应的 resp_body 为空 (不保留 SSE 字节), 显示提示.

### Response 气泡渲染

一条 response 在数据模型上 = messages 数组中的 **一条 assistant message**. 进入下一轮时
它仍是 messages 中的一项 (不拆分). 前端尊重这个数据模型: text 和 tool_calls/tool_use
渲染在**同一个气泡**内, tool_call/tool_use 段用 `.bubble-tool-call` 子区域做视觉区分
(边框 + 缩进 + monospace). 不拆分为多个独立气泡.

思考原文 (`reasoning_content`, #176) 也渲染为 assistant 气泡内的 `.bubble-tool-call`
子区域 (位于 text 段之前), 复用同款视觉区分 — 数据已到前端 JSON
(request 历史 assistant 消息 + parsed response 的 message), 不渲染会静默不可见.

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
