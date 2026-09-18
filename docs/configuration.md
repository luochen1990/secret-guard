# secret-guard 配置参考 (用户向)

> **读者**: 使用 / 部署 secret-guard 的最终用户. 回答 "这个字段怎么配 / 默认值是什么 / 配错了会怎样".
> 开发者向的实现契约 (合并算法 / 持久化机制 / 泛型基础设施) 见 `src/config.rs` 头部与根目录 `AGENTS.md`.

secret-guard 通过一个 TOML 文件启动 (默认 `secret-guard.toml`, 可用 `--config` 改路径),
另有一个程序自动写回的状态文件 (`secret-guard.state.toml`, WebUI 编辑结果). 两者分工:

| 文件 | 角色 | 谁写 |
|---|---|---|
| `secret-guard.toml` | 声明式配置 (本文档的主角), 进程内只读, 改动需重启 | 用户手写 |
| `secret-guard.state.toml` | WebUI 编辑结果 + 对声明式条目的覆盖决策, 删除即重置 | 程序自动 |

> ⚠️ `secret-guard.state.toml` 含**明文**敏感数据 (WebUI 创建的 secret、显式写入的 api_key),
> 务必加入 `.gitignore`.

### `secret-guard.state.toml` 布局速查 (手编排障用)

状态文件由程序自动写回, 一般不需要手编; 但排障时 (如条目从 WebUI 消失) 可按此速查
各 section 的职责. **decision 独立成表**是设计而非冗余 — 它是对 `secret-guard.toml`
里 static 条目的"态度", 而条目本身住在一个程序不可写的文件里:

```toml
providers = []            # WebUI fork 出的 dynamic override / dynamic-only 条目 (条目内容层)
secrets = []
api_keys = []             # WebUI 签发的 API key (存 hash)
api_keys_disabled = []    # static API key 被禁用的 label 集合 (态度层, 一维)

[decisions.providers]     # 对 static provider id 的三态决策 (态度层):
"openai-main" = "disabled"   # default (不入表) | prefer_static | disabled

[decisions.secrets]       # 对 static secret id 的三态决策, 同上
```

- 条目**内容**与对条目的**态度**分离存储: disabled 的 static 条目不在上面的
  `providers = []` 数组里 (那里只有 dynamic 层), 它的禁用状态只记录在 `[decisions]` 表.
- decision=disabled 的条目在 WebUI 的 Secrets / Providers 页以**灰色删除线行**显示,
  用行内 decision 下拉可切回 (`default` / `prefer_static`) 恢复.
- 从 `secret-guard.toml` 删除某 id 后, state 里残留的对应 decision 会在**下次启动时
  自动清除** (日志可见 `pruned dangling decision` WARN) — 同 id 日后重新加入不会被
  旧状态静默禁用.
- 整个文件删除即重置: secret-guard 回到 `secret-guard.toml` 声明的纯净状态.

配置文件可以只写需要的部分 — 所有 section 都可缺省, 缺省条目为空、数值取下表默认值.

## 最小可用示例

```toml
[[providers]]
id = "openai-main"
kind = "direct"
protocol = "openai"
base_url = "https://api.openai.com"
api_key = "sk-your-upstream-key"

[[secrets.entries]]
id = "my-github-token"
value = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
```

> **注意嵌套层级**: provider 是平铺的 `[[providers]]`, 而 secret 必须嵌套在
> `[[secrets.entries]]` 下 (两套写法不一致是历史设计), 误写 `[[secrets]]` 会导致启动
> 失败, 报错与提示见文末"常见配置错误"表.

## `[server]` — 监听与转发 (改动需重启)

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `host` | string | `"127.0.0.1"` | 监听地址. 默认只监听本机回环, 防止意外暴露到局域网. |
| `port` | u16 | `8787` | 监听端口. 也可用 `--port` / 环境变量 `SG_PORT` 覆盖. |
| `records_capacity` | usize | `1024` | 内存中保留的转发记录条数上限 (超出按 FIFO 淘汰). |
| `upstream_connect_timeout_secs` | u64 | `15` | 连上游的 TCP+TLS 握手超时 (秒). `0` = 不限时. |
| `upstream_response_header_timeout_secs` | u64 | `60` | 等上游响应头到达的超时 (秒), **流式请求档**: 只对显式 `stream: true` 的请求生效 (流式响应头在首 token 生成后即返回, 60s 覆盖大上下文 prefill). 超时返回 504. `0` = 不限时. |
| `upstream_nonstream_response_header_timeout_secs` | u64 | `300` | 等上游响应头到达的超时 (秒), **非流式请求档**: 对其余所有请求生效 (缺 `stream` 字段也算非流式). 非流式响应头要等**整个响应生成完**才返回, 大上下文 (几十 k token) 下总时长轻松超 60s, 默认放宽到 300s. 超时返回 504. `0` = 不限时. |
| `upstream_stream_idle_timeout_secs` | u64 | `120` | 流式响应两个 chunk 之间的最大空闲 (秒). `0` = 不限时. |
| `allowed_domains` | string[] | `[]` | SEC-7 Host guard 信任域名, **反代 + 域名部署形态用**. 经反向代理以域名 (如 `sg.example.com`) 暴露 secret-guard 时, 反代保留原始 Host (`proxy_set_header Host $host`) 并在此声明该域名 — 命中按名字精确匹配 (大小写不敏感) 且**端口宽松** (反代转发的 Host 形态不可穷举). 未声明的域名形式 Host 一律 403 (防 DNS rebinding: 攻击者的域名进不了这份你手写的名单). 含 `:` 的形态 (host:port / 裸 IPv6)、IP 字面量、`localhost`、空串条目无意义, 启动时 WARN 跳过. 示例: `allowed_domains = ["sg.example.com"]` |

## `[redact]` — 脱敏行为 (改动需重启)

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `global_mock_prefix` | string | `""` | 所有 Auto 模式 mock 的统一前缀 (如 `"sgm_"`), 便于在日志 / WebUI 中一眼认出 mock. 设定后, secret 真值不允许包含该前缀. |
| `on_probe_exhausted` | `"fail_open"` \| `"fail_closed"` | `"fail_closed"` | mock 候选探测耗尽时 (极罕见, 需对抗性构造; 配置期 lint 已前置拦截弱配置) 的策略: `fail_closed` (默认, 降级偏安全) 拒绝转发整个请求 (503), 宁可失败也不泄露; `fail_open` 跳过该 secret 照常转发 (显式 opt-in, 历史行为). |
| `on_unsupported_protocol` | `"fail_open"` \| `"fail_closed"` | `"fail_closed"` | codec 不覆盖的协议 (目前 gemini / ollama) 上配置了 secrets 时的策略: `fail_closed` (默认, 降级偏安全) 拒绝转发整个请求 (503), 停损防泄露 (message 只含协议名 + provider id, 不含 secret); `fail_open` (显式 opt-in, 历史行为) WARN + 放行透传 — secret 会**原样出站**. 只管 secret 安全性: 仅 model 重写降级 (无 secret) 时两模式都维持 WARN 透传. |
| `on_fallback_restore` | `"withhold"` \| `"restore"` | `"withhold"` | codec 无法 parse 上游响应的 fallback 路径上 (body 仍是合法 JSON), 是否把 Mock 还原为 real 发给客户端: `withhold` (默认, 降级偏安全) 保留 Mock 透传 — 失败/降级响应体是最高概率被客户端日志系统 / 错误追踪采集的内容, 把 real 还原进去等于精准投放泄露, 而 Mock 按设计可安全暴露; `restore` (显式 opt-in) 还原 mock → real (本地工具直接可用真 secret, 但 real 可能随客户端日志扩散). 非 JSON body 的 fallback 分支不受此开关影响 (restore 本就无意义, 恒透传 + WARN). |
| `redacted_headers` | string[] | `[]` | 追加进 WebUI record header 脱敏名单的 header 名 (SEC-4). 用于自定义 auth header (如 `x-my-service-key`) — 不在硬编码黑名单内时若不配置, 其值会原样记录到 WebUI record. 条目启动时归一化 (trim + 小写, 空串跳过) 后按小写 header 名**精确匹配** (非子串匹配: 配 `x-my-key` 不波及 `x-my-key-v2`), 与硬编码黑名单并集生效. 默认空 = 行为不变. 示例: `redacted_headers = ["x-my-service-key"]` |

## `[usage]` — 模型用量统计 (改动需重启)

token 用量数据 100% 来自上游响应回显的 `usage` 字段 (零本地估算); 成本按
[models.dev](https://models.dev) 价目表估算 (恒为估算, 无价模型显示 "—").
明细持久化在 state.toml 同目录的 `usage.sqlite3` (SQLite 固定名, usage_events 表每请求一行 + redact_events 审计表; 旧 `<stem>.usage.jsonl` 与 `<stem>.usage.sqlite3` 不迁移, 留在原地可手动删除/改名).

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `true` | 总开关; `false` = 不采集不落盘 (零开销). |
| `retention_days` | u32 | `90` | 明细保留天数; `0` = 永久. 启动时清理过期行. |
| `pricing_url` | string | models.dev api.json | 定价数据源, 可指向自托管镜像. |
| `pricing_refresh_secs` | u64 | `86400` | 定价表刷新间隔 (秒). |
| `pricing_override` | model → price 表 | 空 | 自定义模型定价 (优先于 models.dev), 见下例. |

定价覆盖示例 ($ / 1M tokens; `cache_read` / `cache_write` 可省略 — 回退到
`input` 价 / 1.25×`input`):

```toml
[usage.pricing_override."my-relay/gpt-fork"]
input = 0.5
output = 2.0
```

已知限制: OpenAI 流式请求仅在客户端设置 `stream_options.include_usage = true`
时上游才回显 usage — 此类请求在 Usage 页只计请求数, 无 token 统计 (页面有提示).

## `[[providers]]` — 上游 LLM 端点 (平铺数组)

每个 provider 是**两种构造之一** (#187 sum type): **直连** (Direct, 真实上游端点) 或
**路由** (Router, 按请求 model 分流的路由端点)。由 **`kind` 字段判别** (`"direct"` /
`"router"`, 必填 — 缺失时启动 fail-fast), 对应构造的字段写在同一个 `[[providers]]`
表内。构造不匹配的字段会被**静默忽略** (serde flatten 无法拒绝未知字段): Router 条目
写 base_url/api_key、Direct 条目写 routes 均不生效 — 请勿依赖, 配置以 `kind` 为准。

> **旧字段迁移提示**: 旧版的 `kind = "virtual"` + 顶层 `route_to` / `model_override` 写法
> 已删除 — `virtual` 变体不存在会启动报错, 残留的 `route_to` / `model_override` 字段
> 会触发启动 WARN (#159 静态预检) 且不生效。请改写为 `kind = "router"` +
> `[[providers.routes]]` (见下文)。

**共享字段** (两种构造均可配):

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `id` | string | (必填) | 唯一标识. 1..=64 字符, 以字母/数字开头, 只允许字母数字、`_`、`-`. 出现在转发 URL 中 (`/o/<id>/...`). |
| `kind` | string | (必填) | 构造判别: `"direct"` (直连) 或 `"router"` (路由). |
| `enabled` | bool | `true` | `false` 时转发到该 provider 返回 503. |
| `name` | string | — | 可选的人类可读名称 (仅 WebUI 显示). |

**Direct 构造** (`kind = "direct"`):

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `protocol` | string | (必填) | 上游协议: `openai` / `anthropic` / `gemini` / `ollama` / `openairesponses` (OpenAI Responses API). |
| `base_url` | string | (必填) | 上游 base URL. 必须以 `http://` 或 `https://` 开头, **末尾不带 `/`** (路径由 secret-guard 拼接). 如 `https://api.openai.com`. |
| `api_key` | string | `""` | 上游 API key 明文. 与 `api_key_file` 互斥 (同时设置启动报错). |
| `api_key_file` | path | — | 从文件读 API key (适合 sops-nix / systemd LoadCredential 等外部注入, 让 toml 本身不含敏感数据). 每次请求时读取, 读不到按空 key 处理并打 WARN. 文件内容自动去首尾空白. |

**Router 构造** (`kind = "router"`) — 无 protocol / base_url / api_key 字段:

Router 自身不转发, 按请求 model 匹配 `routes` 路由后链式解析到链尾的 Direct provider.
ingress 协议由请求 URL 决定, egress 协议由链尾实体决定 (不同则自动跨协议翻译) —
因此 Router **没有 protocol 字段** (残留发送会被静默忽略).

路由写在 `[[providers.routes]]` 子表数组 (至少一条, 空表启动报错):

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `model_pattern` | string | (必填) | model 名通配符: 仅 `*` 是元字符 (匹配任意串, 含空串), 其余字符**字面匹配**, 大小写敏感. `"*"` 匹配一切. 非空, ≤64 字符. |
| `target` | string | (必填) | 目标 provider id, 可指向另一 router (链式解析到链尾实体). 悬空目标 (不存在) 写入放行, 请求时 503. 启用路由自环启动报错 (禁用路由不构成环检查的边); 跨条目环在 WebUI 写入时拒绝, 启动时对合并视图环检查 WARN (手改 state.toml 产生的环启动即告警), 请求时返回 503, 不挂起. |
| `upstream_model` | string | — (透传) | **出站 model 重写**: 命中该路由的请求 body 顶层 `model` 字段被替换为该值. 省略 = 透传客户端原 model. 链上多跳重写是 **pipeline** 语义: 改写值参与下一跳 router 的路由匹配, 后者覆盖前者. 非空 / 非纯空白 / ≤128 字符 (清空请省略字段). 代价: 重写生效时该请求放弃字节直传 (上游前缀缓存失效); Gemini/Ollama 无 codec 无法改写: WARN + 原样透传. |
| `priority` | i64 | — (禁用) | 优先级, **越大越优先**. 省略 (null) = 该路由**禁用** (不参与匹配, 也不构成环检查的边). 同优先级按**列表出现顺序**取先者. |

```toml
[[providers]]
id = "anthropic-main"
kind = "direct"
protocol = "anthropic"
base_url = "https://api.anthropic.com"
api_key_file = "/run/credentials/anthropic.key"   # 与 api_key 二选一
```

### 路由 endpoint (routes) — 按请求 model 的路由转发

客户端固定连接路由 endpoint 的 URL (如 `/o/my-model/v1/chat/completions`),
实际打到哪个上游由**请求 body 里的 model 名**决定 — dispatch 在请求 body 收集后
提取顶层 `model`, 按路由匹配转发:

```toml
[[providers]]
id = "openai-main"
kind = "direct"
protocol = "openai"
base_url = "https://api.openai.com"
api_key = "sk-..."

[[providers]]
id = "anthropic-main"
kind = "direct"
protocol = "anthropic"
base_url = "https://api.anthropic.com"
api_key_file = "/run/credentials/anthropic.key"

[[providers]]
id = "my-model"
kind = "router"
[[providers.routes]]
model_pattern = "claude-*"        # claude 系模型走 Anthropic, 并重写为固定版本
target = "anthropic-main"
upstream_model = "claude-sonnet-4"
priority = 100
[[providers.routes]]
model_pattern = "*"               # 兜底: 其余 (含无 model 字段的请求) 走 OpenAI
target = "openai-main"
priority = 0
```

语义要点:
- **路由选择**: 启用 (`priority` 非 null) 且 model_pattern 匹配请求 model 的路由中
  `priority` 最大者; 同优先级按列表出现顺序取先者. 请求 model 取 JSON **顶层**
  string `model` 字段 — 非 JSON / 无该字段 / 非 string / 空 body 视为 `""`
  (只有 `"*"` 类 model_pattern 能命中).
- **model 重写是 pipeline**: 命中路由的 `upstream_model` 改写立即生效 — 链上下一个
  router 按改写后的 model 匹配, 多跳重写后者覆盖前者. 跨模型名切换 (#183) 由路由的
  `upstream_model` 字段承载 (替代已删除的 `model_override`): 命中即把客户端 model
  替换为目标模型, 适配 gpt-4o ↔ claude 等切换. 代价: 重写生效的请求放弃字节直传
  (上游前缀缓存失效), 见字段表.
- **切换只影响新请求** (per-request 解析, body 收集后执行), in-flight 请求按已
  解析目标完成.
- **错误行为** (均 503): 无匹配路由 / 链上目标悬空 / 目标 `enabled = false` /
  成环. 启用路由自环启动即报错 (禁用路由不构成环边), 跨条目环在 WebUI 写入时拒绝;
  启动时对合并视图做环检查, 手改 state.toml 产生的环启动即 WARN (含环路径).
- 目标协议与 URL 协议不同时自动走跨协议翻译 (codec 覆盖族内任意 pair 非流式可翻译,
  其中 OpenAI ⇄ Anthropic 含流式 SSE 翻译; Responses 任一侧的流式仍返回 501,
  与该协议流式翻译未实现一致).
- WebUI timeline / 轮次详情的 "via ..." 角标与 `Upstream` 字段显示每轮实际命中的
  上游 (路由切换后历史轮次仍如实记录各自归属).
- **WebUI 覆盖静态 router 的方式 = PUT 全量 routes**: 调整 `priority` / 禁用某条
  路由 (置 `priority: null`) / 新增路由行, 均通过提交完整的 routes 数组表达;
  省略 `routes` 字段 = 保留旧值, 空数组 `[]` = 改回 Direct 构造.
- 路由 ↔ 实体切换 (#187 sum type / #190 表单构造分野): 对话框顶部 **Kind**
  选择器切换构造, 表单按构造显示对应字段组 (Direct: Protocol/Base URL/API Key;
  Router: Routes 编辑器)。切换到 Direct 需填 Base URL (前置校验); static 基线下的
  鉴权字段会从 static 继承复原。已知限制: **dynamic-only** 条目 Direct →
  Router → Direct 往返会丢失 api_key (Router 构造无处存放, 切回时需重新填写 —
  表单 placeholder 会显示 "(optional)" 而非 "unchanged" 作为提示)。

## `[[secrets.entries]]` — 需要保护的 Secret (嵌套在 `[secrets]` 下)

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `id` | string | (必填) | 唯一标识, 规则同 provider id. |
| `name` | string | — | 可选的人类可读名称 (仅 WebUI 显示). |
| `category` | string | `"apikey"` | 类别: `password` / `apikey` / `token` / `cookie` / `privatekey` / `other`. |
| `value` | string | `""` | secret 明文. 最少 3 字节; 不允许包含 `global_mock_prefix`; 不允许包含 Unicode 私用区字符 (U+E000..U+F8FF). 与 `value_file` 互斥. |
| `value_file` | path | — | 启动时一次性从文件读取 (适合 sops-nix 等外部注入), 读取失败会**拒绝启动** (fail-fast: secret 缺失会让保护静默失效, 必须在部署时暴露). 文件内容自动去首尾空白. |
| `mock_strategy` | table | (见下) | 替身 (mock) 的生成策略. 缺省时自动按真值推断: 等长、同字符集的确定性随机值. |

### `mock_strategy` 子表

```toml
[[secrets.entries]]
id = "my-github-token"
value = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"

[secrets.entries.mock_strategy]
# 维度一: 初始值. 缺省 "auto" (系统生成).
# 固定替身写法:
# initial = { kind = "fixed", value = "ghp_FAKEplaceholder" }

# 维度二: 生成策略 (仅 initial = "auto" 时生效). 缺省按真值推断.
[secrets.entries.mock_strategy.gen]
prefix = "ghp_mock_"                # 固定前缀
length_range = [24, 36]             # [最小, 最大] 字符数 (闭区间)
[secrets.entries.mock_strategy.gen.charset]
lowercase = true
digits = true
# 其他开关: uppercase / underscore / hyphen / other = ['$', '#']
```

约束: `length_range` 两个值都须 > 0 且 min ≤ max; `prefix` 长度不能超过 min; charset 至少
开启一类. 固定替身不能等于真值, 也不能包含真值的长子串 (启动时校验).

候选空间提示: charset 与 body 长度区间 (总长减 prefix) 共同决定候选 mock 的总数
`Σ charset大小^长度`. 候选总数低于 2^20 (运行时探测预算) 时, 配置写入时 (static 加载 /
WebUI 保存) 会打 WARN 提示运行时探测可能耗尽 (此时由 `[redact] on_probe_exhausted`
决定跳过或拒绝) — 收到该 WARN 请加宽 `charset` 或 `length_range`. 例如 charset 仅 2
个字符 × 固定长度 4 只有 16 个候选, 属于高危配置; 缺省 (按真值推断) 的策略对正常长度
的 secret 通常空间充足, 但真值字符种类退化 (如 `"aaaa"` → 单字符 charset) 时同样会触发.

## `[auth]` — 认证 (默认关闭 = 单用户模式)

默认 `enabled = false`: 所有路由无认证, 适合个人本机使用. 需要多用户 / 暴露给
局域网时启用 OIDC 登录 + API key:

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | `true` 时: WebUI 需 OIDC 登录, 转发路径需 API key. |
| `oidc` | table | — | OIDC Provider 配置 (enabled = true 时必填). |
| `api_keys` | array | `[]` | 静态预设 API key (也可在 WebUI 的 API Keys 页签发). |
| `secure_cookie` | bool | `false` | session cookie 是否带 Secure flag. 经反向代理以 HTTPS 暴露时应设 `true` (本地 HTTP dev 必须 `false` — `true` 时浏览器不回传 cookie). |

`[auth.oidc]` 字段:

| 字段 | 类型 | 说明 |
|---|---|---|
| `issuer_url` | string | OIDC issuer (如 `https://sso.example.com/realms/main`). |
| `client_id` | string | OAuth2 client id. |
| `client_secret_file` | path | 可选, client secret 文件路径. |
| `redirect_url` | string | 可选, 回调 URL. 只能换 scheme/host/port, path 固定为 `/oauth2/callback`. 监听地址非浏览器可达时 (如反代域名) 必须配置. |

`[[auth.api_keys]]` 字段: `label` (唯一标识), `key` 或 `key_file` (二选一, 语义同上).

```toml
[auth]
enabled = true

[auth.oidc]
issuer_url = "https://sso.example.com/realms/main"
client_id = "secret-guard"

[[auth.api_keys]]
label = "ci-pipeline"
key = "sg_ci_abc123..."
```

## 命令行参数与环境变量

`secret-guard run` 启动网关. CLI / 环境变量优先于配置文件:

| 参数 | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| `--host` | `SG_HOST` | 回退 `[server] host` (127.0.0.1) | 监听地址. |
| `--port` | `SG_PORT` | 回退 `[server] port` (8787) | 监听端口. |
| `-c, --config` | `SG_CONFIG` | `secret-guard.toml` | 声明式配置文件路径. |
| `--state` | `SG_STATE` | 由 config 路径派生 | 状态文件路径 (`secret-guard.toml` → `secret-guard.state.toml`). |

## 常见配置错误

| 症状 | 原因与解法 |
|---|---|
| ``TOML parse error ... [[providers]] missing field `kind``` | provider 条目缺少构造判别字段 (#187 起必填): 补 `kind = "direct"` (直连上游) 或 `kind = "router"` (路由). 报错行号指向对应 `[[providers]]` 表头. |
| ``TOML parse error ... [[providers]] unknown variant `virtual`, expected `direct` or `router``` | 旧版 `kind = "virtual"` 已删除: 改为 `kind = "router"`, 原 `route_to` 指向改写为一条 `[[providers.routes]]` (`model_pattern = "*"` + `target = ...`), 原 `model_override` 改为路由的 `upstream_model` 字段. |
| 启动 WARN `unknown field route_to` / `unknown field model_override` | 这两个 providers 顶层字段已删除 (#159 静态预检对残留字段告警, 残留不生效): 改写为 `[[providers.routes]]` 子表 (见上文 Router 构造). |
| `TOML parse error ... [[secrets]] invalid type: map, expected a sequence` | secret 必须写 `[[secrets.entries]]`, 不能写 `[[secrets]]`. 报错前会先输出一行 WARN `did you mean [[secrets.entries]]?` 指路. |
| 启动 WARN `unknown field ... did you mean ...?` | 字段拼写错误. 可选字段拼错会被忽略不生效 (仅 WARN 提示), "以为配了实际没配", 须修正; 必填字段 (如 `protocol`) 拼错则 WARN 后再报 `missing field` 启动失败. `[[providers.routes]]` 内的未知字段同样会 WARN (定位含 entry 下标). |
| `base_url must not end with '/'` | 去掉末尾 `/`, 路径由 secret-guard 拼接. |
| `secret value too short (min 3 bytes)` | secret 真值至少 3 字节. |
| `key and key_file are mutually exclusive` / `api_key` 与 `api_key_file` 同时设置 | 二选一, 删掉其中一个. |
| `provider ... must declare at least one route` | Router 构造的 `routes` 为空 — 空路由 router 无法转发任何请求, 启动即拒. 至少配一条 (兜底可用 `model_pattern = "*"`). |
| 请求返回 404 `not_found` | URL 里 provider id 不存在, 或 proto 前缀拼错 (见 README 路由表). |
| 请求返回 503 `unavailable` | provider `enabled = false`, 或路由坏链: message 含 `router provider '...' has no route matching model '...'` (无匹配路由 — 检查 model_pattern 与 priority) / `route target '...' not found` (悬空目标) / `route target '...' is disabled` / `route cycle detected` (手改配置产生的环). |

配置文件缺失时进程仍可启动 (空配置 + 默认值, 但没有任何 provider 可转发, 启动日志有 WARN).
