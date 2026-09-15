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

### 路由约定

URL 形如 `/{proto_short}/{provider_id}/*rest`, 同时编码 **入站协议** 与 **目标 Provider**:

| proto_short | Protocol | SDK 示例 (`base_url`) |
|---|---|---|
| `o` | OpenAI    | `http://127.0.0.1:18787/o/<provider-id>` |
| `a` | Anthropic | `http://127.0.0.1:18787/a/<provider-id>` |
| `g` | Gemini    | `http://127.0.0.1:18787/g/<provider-id>` |
| `l` | oLLama    | `http://127.0.0.1:18787/l/<provider-id>` |
| `r` | Responses (OpenAI Responses API) | `http://127.0.0.1:18787/r/<provider-id>` |

`proto_short` 简写映射来自 `Protocol::ALL`, 详细路由错误语义见 `AGENTS.md`.

### 日志与排障

每笔转发完成时 stdout 打一行 INFO 摘要 (`forward method=... path=... status=... elapsed_ms=... redactions=N provider=...`),
无需打开 WebUI 即可在命令行确认流量经过 secret-guard; 上游故障 (502/504) 的错误 body 也带可读原因
(如 `upstream error: http://127.0.0.1:29999 (Connection refused)`). 量级大时可用
`RUST_LOG=secret_guard=warn` 调低 (默认 `info`).

### WebUI 入口

浏览器访问根路径 `http://127.0.0.1:18787/` 即可打开 WebUI:
- **Records**: 会话 / 轮次时间线, 查看每次转发的请求与响应 (LLM 视角, 含 Mock Secret).
- **Secrets**: 管理 Secret 注册表.
- **Providers**: 管理 Provider 注册表.

(向后兼容入口 `/__sg` 仍保留.)

### 双层配置

secret-guard 采用双层配置, 同一份实体可同时有 static 与 dynamic 来源, WebUI 编辑结果落盘到 dynamic 文件:

| 文件 | 角色 | 谁写 | 进 git? |
|---|---|---|---|
| `secret-guard.toml`       | **声明式 (static)**: providers / secrets / server / redact / auth. 进程内只读. | 用户手写 | 推荐 |
| `secret-guard.state.toml` | **动态 (dynamic)**: WebUI 编辑结果 + 对 static 项的 decision. 删除即可重置. | 程序自动 | 强烈推荐 .gitignore |

> ⚠️ **敏感数据警示**: `secret-guard.state.toml` 含**明文**敏感数据 — 通过 WebUI 创建的
> dynamic secret 的 `value`、显式提供的 provider `api_key` 都以明文落盘. 其敏感级别与
> `secret-guard.toml` **同级**: 务必加入 `.gitignore`, 误 commit 会把 secret 泄漏进版本历史.

合并语义 (`OverrideMode`: Default / PreferStatic / Disabled) 与各字段详情见 `AGENTS.md` 与 `src/config.rs` 头部注释.

---

更详尽的开发 / 部署 / 测试流程见 `AGENTS.md`.

