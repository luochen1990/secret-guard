# secret-guard — Agent 工作指南

> 本文件面向 AI 代码助手 (opencode / claude-code 等), 描述本项目的关键约定与开发流程.
> 用户级文档见 `README.md`.

## 项目定位

轻量级 LLM 网关 (本地进程): 透明转发 LLM 请求, 同时检测并替换 body 中的 secret,
防止 agent 不经意把 secret 泄露到 LLM Provider. 响应回传时反向替换, 让本地工具仍能用真 secret.
支持多 provider 配置 (OpenAI / Anthropic / Gemini / Ollama), 通过 URL 路径前缀选择目标.

## 关键技术决策 (SSOT)

- **语言**: Rust 2021 edition (toolchain 1.96, via nixos-unstable, 与 ~/ws/nixos 共享 nixpkgs)
- **Web 框架**: axum 0.8 (不使用 rig.rs / pingora 等高级抽象)
- **HTTP client**: reqwest 0.12 with rustls
- **协议无关**: body 在字节层面流动, 不解析 LLM 协议; secret 改写在字节层面
- **双层配置**: 声明式 `secret-guard.toml` (static, 只读) + 动态 `secret-guard.state.toml`
  (dynamic, WebUI 写回). 见下方"配置模型".
- **测试**: cargo-nextest + proptest (property-based) + mockito (集成测试)

## 路由策略 (核心契约)

URL = `/{proto_short}/{provider_id}/*path`. 同时编码 ingress 协议与目标 provider,
为未来跨协议转换预留钩子 (MVP 仅支持 ingress == egress 的 identity passthrough).

| 路径 | 含义 |
|---|---|
| `/` | Web UI (主入口) |
| `/__sg`, `/__sg/*` | Web UI + JSON API (向后兼容旧入口) |
| `/{o\|a\|g\|l}/{name}` | forward, rest = "/" |
| `/{o\|a\|g\|l}/{name}/{*rest}` | forward, rest 含前导 `/` |
| 其他 | 404 (不再 catch-all 透传) |

`proto_short` 简写映射 (单一事实来源: `Protocol::ALL`):

- `o` = OpenAI
- `a` = Anthropic
- `g` = Gemini
- `l` = oLLama

错误语义:
- 未知 protocol 简写 → 404 `not_found`
- 未知 provider id → 404 `not_found`
- 禁用 provider (`enabled = false`) → 503 `unavailable`
- ingress != egress (跨协议) → 501 `not_implemented` (未来工作)

## 模块概览

```
src/
├── main.rs        # 二进制入口: 解析 CLI, 加载 static + dynamic, 启动 server
├── lib.rs         # 库入口
├── cli.rs         # clap 参数 schema (--config / --state / --host / --port)
├── config.rs      # Config (static) / DynamicState / OverrideMode / Decisions
│                  # + DynamicEntry trait + DynamicTable<T> 泛型 (provider / secret 共用)
│                  # + atomic_write / UpsertKind / DeleteOutcome
├── provider.rs    # Protocol / Provider + DynamicEntry impl + EffectiveProvider 合并视图
├── secrets.rs     # SecretEntry / SecretCategory + DynamicEntry impl + EffectiveSecret + mask_value
├── record.rs      # ForwardRecord / RecordStore / ResponseUpdate
├── redact.rs      # mock_secret + RedactionMap + redact_request + restore_response
├── proxy.rs       # ProxyState + forward/forward_no_rest + fan_out_streaming/buffered
├── server.rs      # build_router + serve (装配 persist_lock + 共享 decisions)
└── web/
    ├── mod.rs     # /__sg 子 router + / 根入口 + slash_redirect + not_found
    ├── api.rs     # JSON endpoints (records + secrets/providers CRUD + PATCH .../decision)
    └── index.html # 单页 UI (内嵌 CSS + vanilla JS, 零外部依赖)
```

> `ProviderTable` 与 `SecretTable` 是 [`DynamicTable<T>`](src/config.rs) 的类型别名,
> 通用合并 / CRUD / 持久化算法都在 config.rs; 各模块只补充类型特定的 EffectiveView
> 映射与 validate 钩子.

## 配置模型 (双层: Static + Dynamic)

secret-guard 把配置拆成两个独立文件, 各自承担不同职责:

| 文件 | 角色 | 谁写 | 进入 git? |
|---|---|---|---|
| `secret-guard.toml`        | **声明式 (static)** 配置: providers / secrets / server. | 用户手写 | ✅ 推荐 |
| `secret-guard.state.toml`  | **动态 (dynamic)** 状态: WebUI 编辑结果 + 对 static 项的 decision. | 程序自动 | ❌ 推荐 .gitignore |

- static 配置在进程内**只读**; WebUI 永不修改它.
- 用户删除 `secret-guard.state.toml` 即可"重置"所有 WebUI 变更, 回到声明式基线.
- 启动时 state 文件不存在是正常情况 (返回空 state).

### 合并语义 (`OverrideMode`)

对每个 static id, WebUI 可设置 per-item 决策 (`decisions` 段持久化到 state.toml):

- `Default` (默认): 若 dynamic 中有同 id override 则用 dynamic, 否则用 static.
- `PreferStatic`: 强制使用 static 原值, 忽略 dynamic override.
- `Disabled`: 从 effective view 中完全排除, 既不用 static 也不用 dynamic.

dynamic-only 的 id (即 static 中不存在的) 总是直接生效, 不受 decision 影响.

### Effective source (4 种, 供 UI 区分)

| `source` 字段 | 含义 |
|---|---|
| `static` | 仅 static 有此 id, 用 static. |
| `dynamic` | 仅 dynamic 有此 id (WebUI 创建的). |
| `dynamic_override` | static + dynamic 都有, decision=Default → 用 dynamic. |
| `static_preferred` | static + dynamic 都有, decision=PreferStatic → 用 static. |

Disabled 项不进入 effective view (UI 看不到, 路由层也拿不到).

### CRUD 操作语义

- **POST** 创建 dynamic-only item. 若 id 与 static 冲突 → 409 (要用 PUT 走 fork 流程).
- **PUT** 编辑: 若 id 在 static 中, 服务端自动 fork 出一份 dynamic override (git-style 心智模型).
- **DELETE** 仅作用于 dynamic: 若有 dynamic 删除之 (override 关系下保留 static + 重置 decision);
  若 id 仅在 static 中 → 409 (提示用 PATCH .../decision + mode=disabled).
- **PATCH `/{id}/decision`** 切换对 static id 的决策. 返回 `{id, resource, decision}` ack.

### API endpoints (WebUI)

```
GET    /__sg/api/records[/{id}]
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

## 关键契约

### mock_secret (`src/redact.rs`)

`mock_secret(full_context, real_secret) -> String` 满足 6 条形式化契约 (C1-C6),
完整定义见 `src/redact.rs` 文件头 doc. 关键不变式:

- **C5**: mock 不含 real_secret 的 ≥4 字符连续子串.
  前提: `SecretTable::upsert` 通过 `validate_value` 拒绝含 `MOCK_PREFIX` ("sgm_") 的 secret.
- **C6**: `restore_response(redact_request(body, secrets).0, map) == body` (round-trip identity).
  property-based 测试在 `src/redact.rs::tests::prop_*` 覆盖.

### fan_out 双路径 (`src/proxy.rs`)

- `fan_out_streaming`: SecretTable 为空时使用, 流式透传, 最佳 UX.
- `fan_out_buffered`: 启用 redact 时使用, 完整累积响应再 restore, 失去流式但保证 C6.
- **客户端响应永远无大小上限**; 只有 record 累积受 `MAX_RESP_BODY_RECORD` (32 MiB) 约束.

### Provider 路由 (`src/proxy.rs`)

`forward` 接收 `Path<ForwardPath> { proto, name, rest }`, 按 URL 解析 ingress 与 provider:
1. `Protocol::from_short(proto)` → ingress 协议 (o/a/g/l)
2. `ProviderTable::get_effective(name)` → 目标 provider (合并 static + dynamic + decision 后的生效值)
3. 协议匹配检查 (MVP: ingress == egress; 跨协议 → 501)
4. `apply_provider_auth` 用 `provider.effective_api_key()` 注入对应协议的 auth header:
   - OpenAI / Ollama → `Authorization: Bearer <key>`
   - Anthropic → `x-api-key: <key>`
   - Gemini → `x-goog-api-key: <key>`
   同时剥离竞争 header (避免客户端误传的对手协议 auth 干扰上游), provider 配置优先于客户端.

#### api_key 的两种来源 (`Provider::effective_api_key`)

`Provider` 同时支持两种 api_key 配置方式 (互斥, 同时设置会在 `validate()` 报错):

| 字段 | 类型 | 适用场景 |
|---|---|---|
| `api_key` | `String` (直接值) | 本地 dev / 简单部署 / 不在乎 toml 含敏感数据 |
| `api_key_file` | `Option<PathBuf>` (从文件读取) | 生产部署 / sops-nix / systemd LoadCredential / k8s secrets |

优先级: 直接值 > 文件 > 空. 文件内容会被 `trim()` (容忍 sops / `echo | tee` 末尾换行符).
读不到文件返回空字符串 — 让 `apply_provider_auth` 跳过 auth 注入, 单 provider 配置错误不会拖垮整个进程.

`api_key_file` 让 secret-guard.toml 本身可以不含敏感数据 — toml 可以直接进 git 或 nix store,
secret 由 sops-nix 解密到 `/run/secrets/...`, secret-guard 在请求时读取.
这极大简化了上游 nixos module 的配置 (不用 `sops.templates` 渲染整个 toml).

### 跨表并发安全 (`src/server.rs` + `src/config.rs`)

`SecretTable` 与 `ProviderTable` (都是 `DynamicTable<T>` 别名) 共享两份同步原语
(server 启动时构造并注入):

- **`Arc<Mutex<()>> persist_lock`**: 串行整个 RMW, 避免两表并发写 state.toml 互相覆盖.
- **`Arc<RwLock<Decisions>> decisions`**: 同一份 per-id 决策 (因为 `[decisions]` 段同时含
  providers + secrets 两个子表, 任何一方修改都要触发 state.toml 重写, 共享同一份内存).

### DynamicTable 持久化 (`src/config.rs`)

- 内存层: `Arc<RwLock<Vec<T>>>` × 2 (static_entries 只读 + dynamic_entries 可变).
- 持久化策略: 先写 state.toml (atomic + fsync), 再更新内存 (失败自动回滚).
- `tmp` 文件名带 UUID, 避免并发 atomic_write 互相覆盖.
- 每次写 dynamic 时 `DynamicState::load_or_empty(state_path)` → 改对应段 → `to_toml` → atomic_write.
  共享 persist_lock 保证读-改-写串行化, 不会丢失 decisions 段.
- 类型钩子: `DynamicEntry` trait 让泛型表知道如何把 entry 写入 state 的对应字段
  (`set_state_field`) 与读写 decisions 的对应子表 (`get_decision` / `set_decision`).
  新增第三种 entry 类型只需 impl 该 trait (~25 行) 即可获得完整 CRUD / 持久化 / decision 通道.


## 部署示例 (NixOS + sops-nix)

`api_key_file` 字段让 secret-guard.toml 可以完全脱敏 — 直接进 nix store, secret
由 sops-nix 解密到独立路径. 推荐两种姿势 (任选其一, 都不需要改 NixOS module):

### 姿势 1: sops.secrets + systemd LoadCredential (推荐, 不修改 sops.secrets owner)

适合 secret 被多个模块共享的场景 (例如 claude-code 模块也用同一个 api_key, 已经
设了 `owner = "lc"`). LoadCredential 让 systemd 在服务启动时把 secret mount 到
`/run/credentials/<service>/<id>`, 自动设 mode=0400 owner=<service User>, 不需要
修改 sops.secrets owner 避免与其他模块冲突.

```nix
systemd.services.secret-guard.serviceConfig.LoadCredential = [
  "zai_key:${config.sops.secrets."llm__zai_coding_plan_api_key".path}"
];

services.secret-guard.configFile = (pkgs.writeText "secret-guard.toml" ''
  [[providers]]
  id = "zai-coding-plan"
  protocol = "openai"
  base_url = "https://open.bigmodel.cn/api/coding/paas/v4"
  api_key_file = "/run/credentials/secret-guard.service/zai_key"
  enabled = true
'');
```

### 姿势 2: sops.secrets + 直接路径 (需要 owner = "secret-guard")

适合 secret 只给 secret-guard 用的场景. 与姿势 1 的唯一差异是 `api_key_file` 直接
指向 sops 解密路径, 而不是经 LoadCredential 转手:

```nix
sops.secrets."zai_api_key" = { owner = "secret-guard"; };

services.secret-guard.configFile = (pkgs.writeText "secret-guard.toml" ''
  [[providers]]
  id = "zai-coding-plan"
  protocol = "openai"
  base_url = "https://open.bigmodel.cn/api/coding/paas/v4"
  api_key_file = "${config.sops.secrets."zai_api_key".path}"
  enabled = true
'');
```

**不推荐**: `sops.templates` 渲染整个 toml 把 api_key 嵌入明文 — toml 无法进 nix
store, 调试不便, 与 nixos 生态主流模式 (hermes-agent / bazarr) 不一致.


## 开发流程

```bash
# 一次性环境
nix develop --impure      # 进入 devShell

# 一键 check (fmt + clippy + machete + nextest + doctest)
just check

# 开发热加载
just dev                  # cargo watch -x run

# 手动测试 — 启动 server (需要先在 secret-guard.toml 配置 [[providers]])
cargo run -- run --port 18787
# state.toml 路径默认从 config 派生: secret-guard.toml → secret-guard.state.toml
# 也可显式指定: cargo run -- run --state /tmp/my-state.toml
# 浏览器: http://127.0.0.1:18787/  (或旧版 /__sg)
# OpenAI SDK 配置: base_url = http://127.0.0.1:18787/o/<provider-id>
```

### 客户端使用示例

OpenAI Python SDK:
```python
from openai import OpenAI
client = OpenAI(
    base_url="http://127.0.0.1:18787/o/openai-main",
    api_key="ignored",  # 由 provider 配置覆盖
)
```

Anthropic Python SDK:
```python
from anthropic import Anthropic
client = Anthropic(
    base_url="http://127.0.0.1:18787/a/anthropic-main",
    api_key="ignored",  # 由 provider 配置覆盖
)
```

## 测试策略

| 层级 | 工具 | 示例 |
|---|---|---|
| 单元 (纯函数) | `#[test]` | `provider::tests::protocol_short_roundtrip` |
| Property-based | `proptest` | `redact::tests::prop_round_trip_identity` |
| 集成 (端到端) | `mockito` + `axum::serve` | `tests/integration.rs::forwards_streaming_sse` |

`mockito::Matcher` 在 1.x 没有 `String` 变体, 用 `Exact` 或 `Json` / `PartialJson`.

集成测试覆盖的关键场景:
- 同协议 identity passthrough (OpenAI / Anthropic / Gemini / Ollama)
- 跨协议请求返回 501 `not_implemented`
- 未知 protocol / provider 返回 404
- 禁用 provider 返回 503
- provider api_key 覆盖客户端 auth header
- root `/` 提供 Web UI
- static provider 在 effective view 与路由中生效
- dynamic override 替换 static 路由目标
- decision=disabled 从 effective view 移除 + 路由 404
- decision=prefer_static 强制使用 static
- PUT 静态 provider 自动 fork dynamic override
- DELETE 静态 provider 返回 409 (必须走 decision 通道)
- DELETE dynamic override 后回到 static 基线
- POST 与 static id 冲突返回 409
- PATCH .../decision 对 dynamic-only id 返回 404

## 已知限制 (MVP)

- **跨协议转换未实现**: `/o/anthropic-main/*` 这类 ingress != egress 的请求返回 501.
  架构已为此预留 (见"后续工作").
- 启用 redact 时, 流式响应降级为 buffered (失去 SSE 流式 UX).
- mock_secret 用 SipHash (Rust `DefaultHasher`), 同 Rust 版本内确定, 但**不保证跨版本稳定**;
  RedactionMap 是 per-request 状态不持久化, 所以无实际影响.
- mock 固定 15 字符 (`sgm_` + 11 char base62), 不模拟 real_secret 的格式/长度.
  LLM 可能识别出"sgm_..." 的规律性 — 未来可考虑 category-aware 的 mock 生成器.
- static config (`secret-guard.toml`) 的 `[server]` 段当前仅在启动时读取一次,
  WebUI 改 host/port 不会生效 (需要重启).
- WebUI 编辑 provider 时 api_key 始终要求重输 (无法保留旧值), 留空则覆盖为空字符串.

## 路径约定

- `/` 命名空间: Web UI 主入口 (新).
- `/__sg` 命名空间: Web UI / API (向后兼容旧入口).
- `/__sg/` (带尾斜杠): 307 redirect 到 `/__sg`.
- `/__sg/{*rest}` 未匹配路径: 返回 404, **绝不**进入 forward (否则会泄漏内部 URL 到上游).
- `/{o|a|g|l}/{id}/*`: 转发到对应 provider.
- 其他所有路径: 404.

## 后续工作 (非 MVP 范围)

- **协议转换** (最重要的预留工作): 实现 `ProtocolCodec` trait, 每个 protocol 提供
  `parse_request(Bytes) -> UnifiedRequest` 与 `serialize_request(UnifiedRequest) -> Bytes`,
  通过统一 IR 桥接不同协议. 当前 URL 设计 `/{ingress}/{egress_provider}/*` 已天然支持:
  ingress != egress 时调用 codec 链 `parse(ingress) → IR → serialize(egress)`.
  候选 IR: OpenAI ChatCompletion (生态最广) 或自研 union type 覆盖各家特有字段.
  关键挑战: SSE 流式响应的 chunk-boundary 转换 (sliding window + UTF-8 char 边界).
  当前 MVP 在此处返回 501 Not Implemented (见 `proxy::dispatch`).
- 流式响应 + redact 的 chunk boundary 处理 (用 sliding window + UTF-8 char 边界检测).
- mock_secret 的 category-aware 生成 (Password/ApiKey/Cookie 等格式感知).
- 配置热加载 (目前 Web UI 改 config 后, 重启才影响 CLI 参数).
- 测试覆盖率自动上报 + fuzzing (cargo-fuzz).
- Web UI 编辑 provider 时保留 api_key (改用 `null` 表示不更新).
