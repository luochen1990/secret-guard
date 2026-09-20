# secret-guard URL 布局规划 (URI 分配 SSOT)

> 本文档是 secret-guard **全部 URL 路径分配的单一事实来源 (SSOT)**.
> 任何新增路由 / 改动路径前, 先读本文档; 改动后必须同步更新本文档.
> 受众: 所有给 secret-guard 添加路由或消费其 URL 的开发者 (后端 router 装配 /
> 前端 fetch / 测试 / 部署反代配置).
>
> 路由**装配实现**见 `src/server.rs` + `src/web/mod.rs` (后端),
> 路由**可测契约**见 `docs/design/contracts.md` FWD-5 / SEC-6.
> 本文档管 "URL 空间如何划分 + 为什么这样划分"; 那两处管 "如何实现 + 如何验证".

## 设计目标

1. **WebUI URL 干净**: 浏览器地址栏只出现 `/` (无 `/__sg` 这类实现细节前缀).
2. **forward 命名空间不受污染**: 转发路径是产品的核心接口, 任何 WebUI/API 路由
   不得抢占 `/{proto}/{name}` 形态.
3. **内部 URL 绝不外泄**: 未匹配的内部路径 404, 绝不 fallback 到 forward
   (SEC-6 安全契约).
4. **分配规则可预测**: 新增路由时, 从本文档的规则即可确定它该挂在哪,
   不需要 case-by-case 讨论.

## URL 空间总览

| 路径 | 用途 | 挂载点 | 认证 (auth 启用时) |
|---|---|---|---|
| `/` | WebUI 单页 HTML | `web::router()` (`web/mod.rs`) | OIDC login_required |
| `/api/*` | WebUI JSON API (sessions / sync / records / secrets / providers / api-keys / usage / me) | `web::router()` + `server.rs` (`/api/me`) | OIDC login_required (`/api/me` 例外: 公开) |
| `/login`, `/oauth2/callback`, `/logout` | OIDC 认证流程 | `server.rs` `build_router_with_auth_layers` | 公开 (login_required 之外) |
| `/{o\|a\|g\|l\|r}/{name}` | forward, rest = `/` | `server.rs` forward_router | API key (`require_api_key` middleware) |
| `/{o\|a\|g\|l\|r}/{name}/{*rest}` | forward, 含 sub-path | 同上 | 同上 |
| 其他 (未匹配) | 404 (`/api/{*rest}` 走 `web::not_found` 带 body; 纯未匹配路径如 `/foo` 是 axum 默认 404 空 body) | axum 无匹配 + `/api/{*rest}` 兜底 | — |

> `o` = OpenAI (Chat Completions), `a` = Anthropic, `g` = Gemini, `l` = oLLama,
> `r` = Responses (OpenAI Responses API). 简写映射 SSOT: `Protocol::ALL` (`src/provider.rs`).

## 顶级保留字

以下**首段**被内部功能占用. 反之, 新增内部路由只能从这些保留字 (或按下述规则
新增保留字) 中取; **`login` / `logout` / `oauth2` 仅在 `[auth] enabled = true`
时挂载** (单用户模式下: 单段路径无路由匹配 → axum 默认 404; `/login/foo` 等
多段路径落 forward 参数路由后因首段非 proto 简写 → 404):

| 保留字 | 用途 | 挂载条件 |
|---|---|---|
| `api` | WebUI JSON API 根 | 总是 |
| `login` / `logout` / `oauth2` | OIDC 认证流程 | 仅 auth 启用时 |

**当前活跃保留字集合 = `api` + `login` + `logout` + `oauth2`, 共 4 个.**
(退役的 `__sg` 见 "历史" 一节, 不在集合内.)

**新增保留字的规则**: 顶级保留字必须尽量少, 且与 proto 简写集合 (`o/a/g/l/r`)
不相交.

## 命名空间不相交论证 (为什么这样分配是安全的)

forward 路由 (`/{proto}/{name}/...`) 首段必须是 proto 简写, 由
`dispatch` (`src/proxy/mod.rs`) 用 `Protocol::from_short` 校验, 非法值 404.
内部保留字 (`api` / `login` / `logout` / `oauth2`) 都不是 proto 简写, 因此:

1. **静态优先**: axum (matchit) 中静态段 (`/api/sessions`) 优先于参数段
   (`/{proto}/{name}`), 内部路由永远不会被 forward 路由遮蔽.
2. **参数兜底安全**: 未匹配任何静态路由的路径落入 `/{proto}/{name}` 时,
   proto 解析失败 → 404 (不转发), 满足 SEC-6.
   例: `/__sg/foo` (退役前缀) → proto `__sg` 非法 → 404.
3. **provider id 不会遮蔽内部路由**: provider id 出现在第二段, 不与顶级
   保留字竞争; 用户配置名为 `api` 的 provider id 不受影响 (路径是 `/o/api/...`).

> 路由 provider (`routes`, #179) 与实体 provider 共用同一 id 命名空间与同一
> `/{proto}/{name}` 路由 — URL 层零新增保留字; dispatch 在 provider 解析后按请求
> model 匹配路由并跟随 target 链 (ingress 仍由 URL proto 决定). 详见 FWD-5
> (`docs/design/contracts.md`).
>
> **模型列表端点的行为注记 (#196, URL 不变)**: router provider 的模型列表 GET 端点
> (o/a/r 的 `/models` 与 `/v1/models`, g 另含 `/v1beta/models`, l 的 `/api/tags`) 在
> dispatch 内**本地终结** — 响应本地合成 (别名 ∪ 过滤后上游清单), 不透传上游。
> 这是同一 URL 上的行为分派 (按 provider kind), 不是新的 URL 分配; 语义 SSOT 见
> FWD-7 (`docs/design/contracts.md`)。Direct provider 的同端点仍透传。
>
> **多端点注记 (multi-endpoint, URL 不变)**: Direct 条目的 `endpoints` 多协议端点
> 不新增 URL 形态 — egress 由 ingress 经 `select_endpoint` 选定 (精确匹配 → 同协议;
> 无匹配 → 首端点跨协议翻译)。Direct 的 /models GET 同走 dispatch 转发 (按 ingress
> 对应端点透传); router 本地合成拉上游清单时亦按各 ingress 入口选端点 (FWD-7)。

## `/api/*` 子空间分配

本节只管**空间分配** (哪些资源组存在 + 挂载条件); HTTP 方法 / 参数 / 响应 shape
的端点契约见 `src/web/AGENTS.md` (两文档不重复维护方法列表).

| 子路径 | 用途 |
|---|---|
| `/api/records/{id}` | 单条 record raw/parsed view (WebUI 弹窗按需拉) |
| `/api/sessions` [+ `/{sid}/timeline`] | 会话列表 + session-aware timeline 分页 |
| `/api/sync` | WebUI 3s 轮询统一入口 (sidebar + timeline diff) |
| `/api/secrets` [+ `/{id}` [+ `/decision`]] | secret CRUD + OverrideMode |
| `/api/providers` [+ `/{id}` [+ `/decision`]] + `/probe` | provider CRUD + OverrideMode + 协议自动探测 (静态段优先于 `{id}`: POST = 探测; PUT/DELETE `/probe` = 以固定 id="probe" 适配的编辑/删除薄 wrapper, 存量 "probe" 条目由此可管理 — 新建该 id 仍在 upsert 校验层拒绝, 纯防混淆) |
| `/api/providers/{id}/pool-reset` | pool 条目成员闹钟清空 (POST; 两段路径与 `{id}/decision` 同型, 无单段阴影) |
| `/api/providers/{id}/models` | 模型清单预览 (GET; endpoints 弹窗的 Models 按钮 — Router 本地合成 / Direct+Pool 上游现场 fetch, 失败是数据恒 200; 取数算法与转发路径 /models 同乡 `proxy::models`) |
| `/api/api-keys` [+ `/{id}` [+ `/toggle`]] | API key CRUD |
| `/api/usage/summary` | 模型用量统计汇总 (usage-stats, 定价经 models.dev 惰性拉取) |
| `/api/me` | 当前登录用户信息 (公开, 未登录返回 `authenticated:false`; 仅 auth 启用时挂载, 单用户模式无此路由) |
| `/api/{*rest}` (未匹配) | **404 兜底, 绝不 forward** (SEC-6). 兜底在 login_required 之外 — 未登录也能收到 404 (而非 307), 这是有意设计: 兜底作为安全网应在任何认证状态下工作, 404 本身 fail-closed 不泄露内容; 副作用是 404 vs 307 可区分资源组是否存在 (评估为可接受的极低危信息) |

规则: `/api/*` 下新增资源组时, 在 `web::router()` (`src/web/mod.rs`) 注册,
同步更新 `src/web/AGENTS.md` 的 endpoint 表与本表.

## 历史: `/__sg` 前缀的退役 (2026-08)

- 2026-08 之前: WebUI + API 挂在 `/__sg` 下 (`/__sg`, `/__sg/api/*`, `/__sg/login`).
- 2026-08 URL 硬切重构: 全部提升到顶级 (`/`, `/api/*`, `/login`), `/__sg` 前缀
  **彻底移除** (无 redirect 兼容层). 理由: 自用/内测阶段项目, 无外部消费者,
  代码库简洁优先 (兼容性处理 SOP 见根目录 AGENTS.md "处理不兼容变更").
- 退役后行为: `/__sg` (单段) → 404; `/__sg/foo` → 匹配 forward 参数路由 →
  proto `__sg` 非法 → 404. 守卫测试: `legacy_sg_prefix_returns_404` (integration.rs).
- 找回旧实现: `git log -S "__sg"` / `git show <硬切 commit>^`.

## 变更流程 (给后续开发者)

1. **新增内部路由**: 确认首段 ∈ 现有保留字 (`api` 子空间优先); 若需新顶级保留字,
   先更新本文档 "顶级保留字" 一节 (含与 proto 简写不相交的论证), 再动代码.
2. **新增 proto 简写**: 更新 `Protocol::ALL` + 本文档 URL 空间总览的简写映射行.
3. **改 URL**: 同步清单 — 本文档 + `src/web/AGENTS.md` (或对应模块 AGENTS.md) +
   根目录 AGENTS.md 路由表 + README (若用户可见) + contracts.md (若有对应 property).
4. **守卫**: 路由行为由 `tests/integration.rs` 的 SEC-6 proptest
   (`prop_internal_url_404_no_forward`) + FWD-5 properties 守卫, 改动后跑 `just check`.
