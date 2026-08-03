# web 模块 — JSON API + 单页 WebUI 契约

> 本文件是 `src/web/` 目录的导航与契约汇总. 源文件 (`api.rs` / `mod.rs`) 头部有更细节的注释.
> 项目级原则 (鲁棒性、视图正确性、前端不变量 I1/I2/I3、术语) 见根目录 `AGENTS.md`.

## 职责

- `mod.rs`: `/__sg` 子 router + `/` 根入口 + slash redirect + not_found + `NO_STORE` 共享常量.
- `api.rs`: `/__sg/api/*` JSON endpoints (records 单条 view + sessions + sync + sessions/timeline + secrets/providers CRUD).
- `dto.rs`: WebUI 响应序列化 DTO (SessionView / NodeView / RoundBrief / TimelineRound / TimelineTail / TimelinePage / TimelineDiffData / SyncSnapshot). 构造逻辑留 dag.rs (持读锁访问私有字段).
- `index.html`: 单页 UI (IM 风格: 会话折叠 sidebar + timeline 对话流, 内嵌 CSS + vanilla JS, 零外部依赖).

## 路由

- `GET /` 与 `GET /__sg` —— 单页 HTML (根路径主入口, `/__sg` 向后兼容).
- `GET /__sg/` —— 307 redirect 到 `/__sg` (临时, 避免浏览器永久缓存).
- `/__sg/*` 未匹配子路径 —— 404, **绝不**进入 forward (否则会泄漏内部 URL 到上游).

> 注意: axum 0.8 的 `nest("/__sg", ...)` 默认匹配不带尾斜杠的 `/__sg`. server.rs 显式注册了
> `/__sg/` → `/__sg` 的 redirect.

## API endpoints

```
GET    /__sg/api/records/{id}[?view=parsed]   → {record, parsed_request?, parsed_response?, parse_error?}
                                                (单条 raw + parsed view, WebUI 弹窗按需拉)
GET    /__sg/api/sessions                     → {sessions, total}  (叶子节点, latest-first)
GET    /__sg/api/sessions/{sid}/timeline[?before=UUID&limit=N]
                                              → TimelinePage {rounds, tail, has_more}
                                                (session-aware timeline 分页, oldest-first)
POST   /__sg/api/sync   body: {selected?, expanded[]}  → {sessions, rounds, timeline?}
                                                (WebUI 3s 轮询统一入口: sidebar + timeline diff 一次采集)
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

GET    /__sg/api/api-keys
POST   /__sg/api/api-keys
DELETE /__sg/api/api-keys/{id}
PATCH  /__sg/api/api-keys/{id}/toggle
```

所有响应带 `Cache-Control: no-store`, 避免浏览器对自动刷新返回缓存内容.

> 注: 旧的 `GET /api/records` (扁平分页) + `GET /api/nodes/{id}/timeline` (基于 node_id)
> 已删除, 由 session-aware sync API 替代. 详见 `dag.rs` 的 session_rounds /
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
  提取失败 fallback 到 method+path.
- `model`: 顶层 `model` 字段 (OpenAI / Anthropic 共有), sidebar 副标题第二行.

**假设声明**: 假设 messages 数组中 user 在 assistant 之前; 假设压缩 marker 是固定字符串.
**降级**: 任一假设不成立 → fallback (method+path / 空 model), **永不 panic**.

### session-aware timeline (TimelineRound / TimelineTail / TimelineDiffData)

新模型基于 SessionId (替代旧的基于 node_id 的 timeline). 三条查询路径在 `dag.rs`:

- `session_rounds(sid)`: sidebar 三级菜单的轻量 round 摘要 (RoundBrief, 不含 delta messages).
- `timeline_view(sid, before, limit)`: timeline 初始加载 + lazy load (向前翻更老).
  返回 `TimelinePage { rounds: Vec<TimelineRound>, tail: TimelineTail, has_more }`.
- `timeline_diff(sid, after, tail_length)`: sync 轮询的 diff.
  返回 `Option<TimelineDiffData { new_rounds, tail }>`, None = 无变化 (304 等价).

**req_delta_messages 实现**: 当前从 `req_body_raw` 末尾切片 (已 redact, LLM 视角, 安全).
不走 BlockPool + codec writer 路径 (会泄露真实 secret, 需在 web 层重建 redactMap — TODO).
已知限制: 跨协议 writer 拆分场景切片 start 偏小, delta 可能含前序轮消息 (同协议不受影响).
详见 `dag.rs::extract_delta_messages_from_raw`.

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
(见 `proxy.rs::derive_redactions`). WebUI 的 mock 高亮和 "命中" 筛选都基于此字段,
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
  同一份 key 池. 设计理由见 `src/web/api.rs` 的 `/api-keys` 段注释.
- `tenant_id` / `created_by` 字段保留 (兼容已有持久化数据), 统一填 `"admin"` 占位,
  不影响业务逻辑 (lookup 不读 tenant_id).

## WebUI 渲染契约 (`index.html`)

> 前端不变量 I1 (气泡数 == IR messages 长度) / I2 (sidebar 条目数 == HTTP 请求数) /
> I3 (timeline 轮次 DOM 顺序 == 数据顺序 oldest-first) 见根目录 AGENTS.md.
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
  全部来自 TimelineRound / TimelineTail, 无需网络请求).
- `raw`: 弹窗展示原始 req_body / resp_body / req_headers / resp_headers (按需懒拉
  `GET /api/records/{id}`). body 是 LLM 视角 (已 redact, 安全展示); headers 已脱敏
  (auth/cookie 等 = `<redacted>`). 流式响应的 resp_body 为空 (不保留 SSE 字节), 显示提示.

### Response 气泡渲染

一条 response 在数据模型上 = messages 数组中的 **一条 assistant message**. 进入下一轮时
它仍是 messages 中的一项 (不拆分). 前端尊重这个数据模型: text 和 tool_calls/tool_use
渲染在**同一个气泡**内, tool_call/tool_use 段用 `.bubble-tool-call` 子区域做视觉区分
(边框 + 缩进 + monospace). 不拆分为多个独立气泡.

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

**follow/pinned 视觉指示 (WebUI 反馈1)**: drawer 顶部边缘颜色随状态切换 — follow 时淡灰
近不可见 (1px `#ddd`), pinned 时蓝色细条 (3px `#4a6fa5` + 轻微上浮阴影). `.pinned` 类由
`updateResponseDrawerLayout` 在每渲染/滚动周期同步 (与 drawer 高度同一周期, 覆盖抽屉从
隐藏切到可见等边界). 配色与 unread badge 一致.

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
