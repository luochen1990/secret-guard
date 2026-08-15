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

配置文件可以只写需要的部分 — 所有 section 都可缺省, 缺省条目为空、数值取下表默认值.

## 最小可用示例

```toml
[[providers]]
id = "openai-main"
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
| `upstream_response_header_timeout_secs` | u64 | `60` | 等上游响应头到达的超时 (秒), 超时返回 504. `0` = 不限时. |
| `upstream_stream_idle_timeout_secs` | u64 | `120` | 流式响应两个 chunk 之间的最大空闲 (秒). `0` = 不限时. |

## `[redact]` — 脱敏行为 (改动需重启)

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `global_mock_prefix` | string | `""` | 所有 Auto 模式 mock 的统一前缀 (如 `"sgm_"`), 便于在日志 / WebUI 中一眼认出 mock. 设定后, secret 真值不允许包含该前缀. |
| `on_probe_exhausted` | `"fail_open"` \| `"fail_closed"` | `"fail_open"` | mock 候选探测耗尽时 (极罕见, 需对抗性构造) 的策略: `fail_open` 跳过该 secret 照常转发; `fail_closed` 拒绝转发整个请求 (503), 宁可失败也不泄露. |

## `[[providers]]` — 上游 LLM 端点 (平铺数组)

每个 provider 是一个上游服务的完整定义:

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `id` | string | (必填) | 唯一标识. 1..=64 字符, 以字母/数字开头, 只允许字母数字、`_`、`-`. 出现在转发 URL 中 (`/o/<id>/...`). |
| `protocol` | string | (必填) | 上游协议: `openai` / `anthropic` / `gemini` / `ollama` / `openairesponses` (OpenAI Responses API). |
| `base_url` | string | (必填) | 上游 base URL. 必须以 `http://` 或 `https://` 开头, **末尾不带 `/`** (路径由 secret-guard 拼接). 如 `https://api.openai.com`. |
| `api_key` | string | `""` | 上游 API key 明文. 与 `api_key_file` 互斥 (同时设置启动报错). |
| `api_key_file` | path | — | 从文件读 API key (适合 sops-nix / systemd LoadCredential 等外部注入, 让 toml 本身不含敏感数据). 每次请求时读取, 读不到按空 key 处理并打 WARN. 文件内容自动去首尾空白. |
| `enabled` | bool | `true` | `false` 时转发到该 provider 返回 503. |
| `name` | string | — | 可选的人类可读名称 (仅 WebUI 显示). |

```toml
[[providers]]
id = "anthropic-main"
protocol = "anthropic"
base_url = "https://api.anthropic.com"
api_key_file = "/run/credentials/anthropic.key"   # 与 api_key 二选一
```

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

## `[auth]` — 认证 (默认关闭 = 单用户模式)

默认 `enabled = false`: 所有路由无认证, 适合个人本机使用. 需要多用户 / 暴露给
局域网时启用 OIDC 登录 + API key:

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | `true` 时: WebUI 需 OIDC 登录, 转发路径需 API key. |
| `oidc` | table | — | OIDC Provider 配置 (enabled = true 时必填). |
| `api_keys` | array | `[]` | 静态预设 API key (也可在 WebUI 的 API Keys 页签发). |

`[auth.oidc]` 字段:

| 字段 | 类型 | 说明 |
|---|---|---|
| `issuer_url` | string | OIDC issuer (如 `https://sso.example.com/realms/main`). |
| `client_id` | string | OAuth2 client id. |
| `client_secret_file` | path | 可选, client secret 文件路径. |
| `redirect_url` | string | 可选, 回调 URL. 只能换 scheme/host/port, path 固定为 `/__sg/oauth2/callback`. 监听地址非浏览器可达时 (如反代域名) 必须配置. |

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
| `TOML parse error ... [[secrets]] invalid type: map, expected a sequence` | secret 必须写 `[[secrets.entries]]`, 不能写 `[[secrets]]`. 报错前会先输出一行 WARN `did you mean [[secrets.entries]]?` 指路. |
| 启动 WARN `unknown field ... did you mean ...?` | 字段拼写错误. 可选字段拼错会被忽略不生效 (仅 WARN 提示), "以为配了实际没配", 须修正; 必填字段 (如 `protocol`) 拼错则 WARN 后再报 `missing field` 启动失败. |
| `base_url must not end with '/'` | 去掉末尾 `/`, 路径由 secret-guard 拼接. |
| `secret value too short (min 3 bytes)` | secret 真值至少 3 字节. |
| `key and key_file are mutually exclusive` / `api_key` 与 `api_key_file` 同时设置 | 二选一, 删掉其中一个. |
| 请求返回 404 `not_found` | URL 里 provider id 不存在, 或 proto 前缀拼错 (见 README 路由表). |
| 请求返回 503 `unavailable` | provider `enabled = false`. |

配置文件缺失时进程仍可启动 (空配置 + 默认值, 但没有任何 provider 可转发, 启动日志有 WARN).
