Secret Guard
============

防止你的 Agent 不经意间将你的 Secrets (password, private keys, token, cookies) 泄露到 LLM Provider 服务器上.

---

这是一个超轻量级的 LLM Gateway, 它提供的功能是:

1. 在本地起一个 LLM 网关进程, 你可以将 claude-code / opencode / hermes-agent 等软件的 API BASE URL 指向它监听的本地地址
2. 它将原封不动地转发LLM的输入输出, 同时在本地程序中检查其中是否包含你的 Secret, 并将其替换为 Mock Secret.
3. 它会在收到的LLM响应中(包括工具调用中)进行反向替换, 以使得包含 Secret 的工具调用在你的本地仍然能正常运行. 整个过程只对 LLM 透明.
4. 它会在生成 Mock Secret 时, 确保它在会话中的唯一性, 以使得它完全不可能跟其他内容出现同名撞车, 不用担心响应中的内容被错误地替换.
5. 它会精心生成像模像样的 Mock Secret , 以使得从 LLM 的视角看, 它几乎就是一个真 Secret, 不会被 LLM 质疑这个 Secret 的合法性 (比如 LLM 不会因发现 Mock Secret 很假而错误地提示你 "它的长度太短" 之类的问题, 而引入 LLM 响应噪音)

## 快速开始

### 1. 安装

```bash
# Nix (flake, 需配置好 forgejo 的 SSH key):
nix run git+ssh://forgejo@git.lambda.lc:5522/lc-studio/secret-guard -- --help
# 或将 overlay / nixosModule 接入你的 flake 后直接用 pkgs.secret-guard

# Cargo (从源码构建, 需要 rustc >= 1.96):
cargo install --git ssh://forgejo@git.lambda.lc:5522/lc-studio/secret-guard
# 或克隆仓库后: cargo install --path .
```

### 2. 最小配置

在某个目录创建 `secret-guard.toml` (1 个上游 provider + 1 个要保护的 secret 即可跑通):

```toml
[[providers]]
id = "openai-main"
kind = "direct"                         # 直连上游 (路由端点用 "router")
protocol = "openai"
base_url = "https://api.openai.com"
api_key = "sk-your-upstream-key"        # 转发时注入上游的 key

[[secrets.entries]]
id = "my-github-token"
value = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"   # 要保护的 secret (不会发往上游)
```

> 注意层级: secret 写在 `[[secrets.entries]]` 下 (providers 是平铺 `[[providers]]`,
> 两套写法不一致). 全部配置字段见 [docs/configuration.md](docs/configuration.md).

### 3. 启动并发出第一个请求

```bash
secret-guard run --port 18787
curl http://127.0.0.1:18787/o/openai-main/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"My token is ghp_0123456789abcdefghijklmnopqrstuvwxyz, please summarize."}]}'
```

> 本文示例统一用端口 `18787`; 不指定 `--port` 时默认监听 `127.0.0.1:8787`
> (也可用 `[server] port` 或环境变量 `SG_PORT` 修改).

请求中的 secret 已被替换为等长的仿真 Mock Secret 发往上游 (每笔转发完成日志的
`redactions=1` 即替换计数), LLM 全程看不到真值. 浏览器打开 `http://127.0.0.1:18787/`
可在 WebUI 的 Records 页查看这次请求的 LLM 视角 (secret 位置以高亮 mock 呈现).

日常使用时, 把 agent 工具的 `base_url` 指过来即可, 无需手写 curl:

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:18787/o/openai-main/v1", api_key="ignored")
```

> SDK 的 `base_url` 需自带版本路径前缀 (如 `/v1`), secret-guard 只原样透传;
> Anthropic SDK 的 `base_url` 同理配到 `/a/<provider-id>` 即可 (其 SDK 自带 `/v1/messages`).

### 路由约定

URL 形如 `/{proto_short}/{provider_id}/*rest`, 同时编码 **入站协议** 与 **目标 Provider**:

| proto_short | Protocol | SDK 示例 (`base_url`) |
|---|---|---|
| `o` | OpenAI    | `http://127.0.0.1:18787/o/<provider-id>/v1` |
| `a` | Anthropic | `http://127.0.0.1:18787/a/<provider-id>` |
| `g` | Gemini    | `http://127.0.0.1:18787/g/<provider-id>` |
| `l` | oLLama    | `http://127.0.0.1:18787/l/<provider-id>` |
| `r` | Responses (OpenAI Responses API) | `http://127.0.0.1:18787/r/<provider-id>/v1` |

`proto_short` 简写映射来自 `Protocol::ALL`, 详细路由错误语义见 `AGENTS.md`.
注: 表中 URL 是 SDK `base_url` 口径 — OpenAI SDK (Chat Completions 与 Responses 同 SDK)
需自带 `/v1` 前缀; Anthropic SDK 自行拼 `/v1/messages`, 配到 `/a/<provider-id>` 即可;
curl 直连则写完整路径 (见上方示例).

### 日志与排障

每笔转发完成时 stdout 打一行 INFO 摘要 (`forward method=... path=... status=... elapsed_ms=... redactions=N provider=...`),
无需打开 WebUI 即可在命令行确认流量经过 secret-guard; 上游故障 (502/504) 的错误 body 也带可读原因
(如 `upstream error: http://127.0.0.1:29999 (Connection refused)`). 量级大时可用
`RUST_LOG=secret_guard=warn` 调低 (默认 `info`).

### WebUI 入口

浏览器访问根路径 `http://127.0.0.1:18787/` 即可打开 WebUI (端口同上, 默认 8787):
- **Records**: 会话 / 轮次时间线, 查看每次转发的请求与响应 (LLM 视角, 含 Mock Secret).
- **Secrets**: 管理 Secret 注册表.
- **Providers**: 管理 Provider 注册表.
- **API Keys**: 签发 / 禁用转发路径认证用的 API key (启用 `[auth]` 后生效).

### 双层配置

secret-guard 采用双层配置: 声明式文件 `secret-guard.toml` (用户手写, 进程内只读) +
动态状态文件 `secret-guard.state.toml` (WebUI 编辑结果自动落盘, 删除即可重置).
同一实体可同时有 static 与 dynamic 来源, 后者可覆盖前者.

> ⚠️ **敏感数据警示**: `secret-guard.state.toml` 含**明文**敏感数据 — 通过 WebUI 创建的
> dynamic secret 的 `value`、显式提供的 provider `api_key` 都以明文落盘, 其敏感级别与
> `secret-guard.toml` **同级**: 务必加入 `.gitignore`, 误 commit 会把 secret 泄漏进版本历史.

文件分工与各配置段全部字段 / 类型 / 默认值 / 常见错误见
**[docs/configuration.md](docs/configuration.md)**; 合并语义 (`OverrideMode`:
Default / PreferStatic / Disabled) 等开发者向细节见 `AGENTS.md` 与 `src/config.rs` 头部注释.

---

更详尽的开发 / 部署 / 测试流程见 `AGENTS.md`.
