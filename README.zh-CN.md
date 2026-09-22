<p align="center">
  <img src="assets/logo.svg" width="110" alt="Secret Guard logo">
</p>

# Secret Guard

**跑在本地的轻量 LLM 网关: 出站把请求中的 Secret 替换为等长仿真 Mock, 回传响应自动还原为真值 — LLM 全程接触不到你的 Secret, Agent 工具照常工作。**

[文档站](https://secret-guard.lambda.lc/zh-cn/) · [下载](https://secret-guard.lambda.lc/zh-cn/download/) · [快速上手](https://secret-guard.lambda.lc/zh-cn/tutorial-quick-start/) · [协议支持](#协议支持) · [English](./README.md)

## 为什么需要 Secret Guard?

claude-code / opencode / hermes-agent 这类 Agent 工具替你干活的方式, 就是把材料整段塞进提示词 — 代码、配置、终端输出, 连同其中的 password、private key、token、cookies, 全部送到了 LLM Provider 的服务器上。这些数据一旦离开本机就不再受你控制: 可能进入 Provider 日志、用于模型训练、或随一次泄露事件曝光。

而 "不要把 Secret 放进上下文" 在 Agent 工作流里并不现实 — 凭证恰恰是 Agent 替你操作真实系统时要用的东西。Secret Guard 化解的正是这个矛盾: **Agent 继续用你的 Secret 干活, LLM 却永远接触不到真值。**

## 工作原理

接入成本只有一行: 把 Agent 工具的 API base URL 指向本地网关, 流量经它转发到 Provider:

```text
请求出站:  Agent 工具 ──真 Secret──►  secret-guard  ──仿真 Mock──►  LLM Provider
响应回传:  本地工具   ◄──真 Secret──  secret-guard  ◄──Mock 应答──  LLM Provider
                           (Redact / Restore 均发生在本地, 双向透明)
```

- **出站 Redact**: 发往 LLM 的请求中, Secret 被替换为等长、同字符集的仿真 Mock
  (默认策略) — LLM 拿着它照常干活, 浑然不觉。
- **回传 Restore**: LLM 响应回传时 (包括工具调用参数), Mock 被反向还原为真值 — 含 Secret 的 curl 命令落到你机器上时认证照常通过。

一笔真实请求出站前后的样子 (截自真实运行, 仅 token 值为虚构):

```text
Agent 发出的:     GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz
Provider 收到的:  GITHUB_TOKEN=2_9rr_61dr1lmv2wf15aotyyt262l3t9_2pt4uih
```

WebUI 快速导览 — 会话时间线、LLM 视角的请求视图 (Mock 高亮)、响应侧还原后的真值:

![WebUI 演示](assets/demo.gif)

每笔转发都可在 WebUI 的 Records 页核对 (会话时间线 + 请求详情, Secret 位置以高亮
Mock 呈现, 即 LLM 所见):

![WebUI Records 页 — 会话时间线与请求详情 (LLM 所见)](assets/records-detail.webp)

## 快速开始

### 1. 安装

```bash
# 二进制归档 (Linux x86_64 / ARM64, musl 全静态, 附 SHA256 校验) — 见下载页:
#   https://secret-guard.lambda.lc/zh-cn/download/

# Nix (flake):
nix run github:luochen1990/secret-guard -- --help
# 或将 overlay / nixosModule 接入你的 flake 后直接用 pkgs.secret-guard

# Cargo (从源码构建, 需要 rustc >= 1.96):
cargo install --git https://github.com/luochen1990/secret-guard
# 或克隆仓库后: cargo install --path .
```

> NixOS 用户推荐 `services.secret-guard.*` 结构化选项部署 (eval 期校验配置,
> 凭据走文件注入), 见 [docs/deployment-nixos.md](docs/deployment-nixos.md)。

### 2. 最小配置

在某个目录创建 `secret-guard.toml` (1 个上游 provider + 1 个要保护的 secret 即可跑通):

```toml
[[providers]]
id = "openai-main"
kind = "direct"                         # 直连上游 (路由端点用 "router", 套餐池用 "pool")
api_key = "sk-your-upstream-key"        # 条目级凭证, 全端点共享 — 必须写在 [[providers.endpoints]] 之前 (TOML 子表切换)
[[providers.endpoints]]
protocol = "openai"                     # 每协议至多一条端点
base_url = "https://api.openai.com"     # 入站协议无匹配端点时回退首端点

[[secrets.entries]]
id = "my-github-token"
value = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"   # 要保护的 secret (不会发往上游)
```

> 注意层级: secret 写在 `[[secrets.entries]]` 下 (providers 是平铺 `[[providers]]`,
> 两套写法不一致)。全部配置字段见 [docs/configuration.md](docs/configuration.md)。

### 3. 启动并发出第一个请求

```bash
secret-guard run --port 18787
curl http://127.0.0.1:18787/o/openai-main/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"My token is ghp_0123456789abcdefghijklmnopqrstuvwxyz, please summarize."}]}'
```

上游收到的是仿真 Mock — 转发完成日志的 `redactions=1` 即替换计数;
浏览器打开 `http://127.0.0.1:18787/` 可在 Records 页回看这笔请求。

> 示例统一用端口 `18787`; 默认监听 `127.0.0.1:8787`, 可用 `[server] port`
> 或环境变量 `SG_PORT` 修改。

日常使用时, 把 Agent 工具的 `base_url` 指向网关即可, 无需手写 curl:

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:18787/o/openai-main/v1", api_key="ignored")
```

### 路由约定

URL 形如 `/{proto_short}/{provider_id}/*rest`, 同时编码**入站协议**与**目标 Provider**:

| proto_short | 协议 | SDK 示例 (`base_url`) |
|---|---|---|
| `o` | OpenAI | `http://127.0.0.1:18787/o/<provider-id>/v1` |
| `a` | Anthropic | `http://127.0.0.1:18787/a/<provider-id>` |
| `g` | Gemini | `http://127.0.0.1:18787/g/<provider-id>` |
| `l` | Ollama | `http://127.0.0.1:18787/l/<provider-id>` |
| `r` | Responses (OpenAI Responses API) | `http://127.0.0.1:18787/r/<provider-id>/v1` |

> SDK 侧注意: OpenAI SDK 需自带 `/v1` 前缀; Anthropic SDK 自行拼 `/v1/messages`,
> 配到 `/a/<provider-id>` 即可。

### 配置模型: 静态 + 动态双层

- `secret-guard.toml` — 声明式配置, 用户手写, 进程内只读。
- `secret-guard.state.toml` — WebUI 编辑结果自动落盘的动态状态, 删除即可重置; 同一实体
  的 dynamic 来源可覆盖 static。

> ⚠️ **敏感数据警示**: `state.toml` 含**明文**敏感数据 (WebUI 创建的 secret value、
> 显式写入的 provider api_key), 敏感级别与 `secret-guard.toml` 同级: 务必加入
> `.gitignore`, 误 commit 会把 secret 泄漏进版本历史。

### 日志与排障

每笔转发完成时打一行 INFO 摘要 (`forward ... status=... elapsed_ms=... redactions=N
provider=...`), 命令行即可确认流量经过 secret-guard; 上游故障 (502/504) 的错误 body 带
可读原因。日志量大时用 `RUST_LOG=secret_guard=warn` 调低 (默认 `info`)。

## 何以可靠

把生产流量交给一个中间进程, 需要它先证明自己不会帮倒忙。以下性质以 property-based
测试与端到端集成测试固化在仓库中, 每次发版全量验证:

- **透明中继**: 无 Redact 时字节级透传; 有 Redact 时除 real↔mock 替换外语义完全
  不变 (仅字段顺序等无语义的序列化差异) — 行为与直连无异。
- **严格可逆**: 每个 Mock 与真值一一对应, Restore 是 Redact 的精确逆运算 — 含 Secret
  的工具调用不会因替换而损坏。
- **确定性 Mock**: 同一 Secret 的 Mock 跨轮保持稳定, 不破坏 Provider 的前缀缓存 —
  正常会话中命中率与 token 成本不受影响 (mock 意外逃逸并被回传的例外见下)。
- **上下文内不撞车**: Mock 绝不与请求中的其他内容重名, 响应不会被错误替换。
- **多 Provider 路由**: 支持多 Provider 配置 (OpenAI / Anthropic / Gemini / Ollama /
  Responses), 按请求 model 通配符路由到不同上游。
- **套餐池轮换 (Pool)**: 把多份编码订阅套餐 (各含独立凭证) 挂成一个入口, 一份套餐的
  窗口限额用尽自动切换到下一份, 窗口恢复后自动切回 — 全程零人工干预。

## 协议支持

| 协议 | 转发 | Secret Redact | 跨协议翻译 |
|---|---|---|---|
| OpenAI (Chat Completions) | ✅ | ✅ | ✅ ⇄ Anthropic (含流式) / ⇄ Responses (非流式) |
| Anthropic (claude) | ✅ | ✅ | ✅ ⇄ OpenAI (含流式) / ⇄ Responses (非流式) |
| OpenAI Responses | ✅ | ✅ (非流式) | ✅ ⇄ Chat Completions / Anthropic (非流式) |
| Gemini / Ollama | ✅ 字节透传 | 🚧 [Roadmap](#roadmap--贡献) | 🚧 [Roadmap](#roadmap--贡献) |

- Gemini / Ollama 是透明字节透传 (转发本身完整可用); 由于 codec 尚未覆盖, Redact
  不作用于这两族 — 配置了 secrets 时, 它们路径上的请求默认被**拒绝** (503,
  `[redact] on_unsupported_protocol = "fail_closed"`, 错误信息自带出路提示)。
  手写配置文件 / REST API 可创建这两族 provider (适合无 secret 的纯转发场景);
  WebUI 新建表单不引导, 但编辑存量条目与 Detect 探测推荐会以 "(experimental)"
  选项支持。
- **降级偏安全**: Redact 的异常路径 (上游响应无法解析 / 非 2xx) 默认保留 Mock
  透传 — 真值不进失败响应体; `on_fallback_restore = "restore"` 可显式 opt-in
  还原。三个降级开关的完整语义见 [docs/configuration.md](docs/configuration.md)。
- 协议行为由 property-based 测试与模拟上游的集成测试固化; Anthropic / Gemini /
  Ollama 的真实 Provider 实地验证尚未进行 (见 [Roadmap](#roadmap--贡献)) — 首次
  接入建议先在 WebUI Records 页核对一笔真实流量。

## Roadmap & 贡献

以下方向正在推进, 欢迎 issue / PR — 主仓库
[github.com/luochen1990/secret-guard](https://github.com/luochen1990/secret-guard),
完整开发指南见 [AGENTS.md](AGENTS.md):

- **Gemini / Ollama codec**: 补齐这两族的 Redact 与跨协议能力。新增协议只需实现
  Reader + Writer trait (~200 行), 不动 dispatch — 架构见 `src/codec/AGENTS.md`。
- **Responses 流式 SSE 翻译**: Responses + Redact 命中 + `stream=true` 返回 501
  (防止 mock 静默外流); 仅路由 model 重写 (无 Redact) 时流式放行, SSE 字节透传。
- **Responses 参与的跨协议流式**: OpenAI ⇄ Anthropic 流式翻译已支持, Responses
  侧的流式事件翻译待实现; 跨协议翻译中 reasoning content / hosted tools 暂被
  丢弃 (有 WARN)。
- **真实 Provider 实地验证**: 为协议矩阵补真实上游的集成测试 profile。

## 文档

你可能正在找:

- 三分钟跑通第一个受保护请求 → [站点·快速上手](https://secret-guard.lambda.lc/zh-cn/tutorial-quick-start/)
- 全部配置字段 / 类型 / 默认值 → [docs/configuration.md](docs/configuration.md)
- WebUI 各页面用法 → [站点·WebUI 指南](https://secret-guard.lambda.lc/zh-cn/manual-webui/)
- NixOS 部署与凭据注入 → [docs/deployment-nixos.md](docs/deployment-nixos.md)
- 架构设计与数据流契约 → [docs/design/](docs/design/) (contracts.md)
- 开发流程 / 测试策略 / 模块契约 → [AGENTS.md](AGENTS.md)

## License

MIT — 见 [LICENSE](LICENSE)。
