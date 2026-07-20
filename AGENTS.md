# secret-guard — Agent 工作指南

> 本文件面向 AI 代码助手 (opencode / claude-code 等), 描述本项目的关键约定与开发流程.
> 用户级文档见 `README.md`.

## 项目定位

轻量级 LLM 网关 (本地进程): 透明转发 LLM 请求, 同时检测并替换 body 中的 secret,
防止 agent 不经意把 secret 泄露到 LLM Provider. 响应回传时反向替换, 让本地工具仍能用真 secret.

## 关键技术决策 (SSOT)

- **语言**: Rust 2021 edition (toolchain 1.96, via nixpkgs-unstable)
- **Web 框架**: axum 0.8 (不使用 rig.rs / pingora 等高级抽象)
- **HTTP client**: reqwest 0.12 with rustls
- **协议无关**: body 在字节层面流动, 不解析 LLM 协议; secret 改写在字节层面
- **配置**: TOML (`secret-guard.toml`), 通过 atomic rename 持久化
- **测试**: cargo-nextest + proptest (property-based) + mockito (集成测试)

## 模块概览

```
src/
├── main.rs        # 二进制入口: 解析 CLI, 启动 server
├── lib.rs         # 库入口
├── cli.rs         # clap 参数 schema (Option<T> 表示"未指定")
├── config.rs      # Config / ServerConfig / UpstreamConfig / SecretsConfig
├── secrets.rs     # SecretEntry / SecretCategory / SecretTable (共享可变状态)
├── record.rs      # ForwardRecord / RecordStore / ResponseUpdate
├── redact.rs      # mock_secret + RedactionMap + redact_request + restore_response
├── proxy.rs       # ProxyState + forward handler + fan_out_streaming/buffered
├── server.rs      # build_router + serve (含 graceful shutdown)
└── web/
    ├── mod.rs     # /__sg 子 router + slash_redirect + not_found
    ├── api.rs     # JSON endpoints (records + secrets CRUD)
    └── index.html # 单页 UI (内嵌 CSS + vanilla JS, 零外部依赖)
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

### SecretTable 并发 (`src/secrets.rs`)

- `persist_lock` 串行整个 RMW (read-modify-write), 保证并发 upsert/delete 不丢失更新.
- 持久化策略: 先写文件 (atomic + fsync), 再更新内存 (失败自动回滚).
- `tmp` 文件名带 UUID, 避免并发 atomic_write 互相覆盖.

## 开发流程

```bash
# 一次性环境
nix develop --impure      # 进入 devShell

# 一键 check (fmt + clippy + machete + nextest + doctest)
just check

# 开发热加载
just dev                  # cargo watch -x run

# 手动测试
cargo run -- run --port 18787 --upstream http://127.0.0.1:9999
# 浏览器: http://127.0.0.1:18787/__sg
```

## 测试策略

| 层级 | 工具 | 示例 |
|---|---|---|
| 单元 (纯函数) | `#[test]` | `redact::tests::c1_non_empty` |
| Property-based | `proptest` | `redact::tests::prop_round_trip_identity` |
| 集成 (端到端) | `mockito` + `axum::serve` | `tests/integration.rs::forwards_streaming_sse` |

`mockito::Matcher` 在 1.x 没有 `String` 变体, 用 `Exact` 或 `Json` / `PartialJson`.

## 已知限制 (MVP)

- 启用 redact 时, 流式响应降级为 buffered (失去 SSE 流式 UX).
- mock_secret 用 SipHash (Rust `DefaultHasher`), 同 Rust 版本内确定, 但**不保证跨版本稳定**;
  RedactionMap 是 per-request 状态不持久化, 所以无实际影响.
- mock 固定 15 字符 (`sgm_` + 11 char base62), 不模拟 real_secret 的格式/长度.
  LLM 可能识别出"sgm_..." 的规律性 — 未来可考虑 category-aware 的 mock 生成器.
- 配置文件 `secret-guard.toml` 中 `secrets` 段是单一 SSOT, 手动编辑可能被 Web UI 写回覆盖.

## 路径约定

- `/__sg` 命名空间: Web UI / API, 不转发到上游.
- `/__sg/` (带尾斜杠): 307 redirect 到 `/__sg`.
- `/__sg/{*rest}` 未匹配路径: 返回 404, **绝不**进入 catch-all `forward` (否则会泄漏内部 URL 到上游).
- 其他所有路径: 透传到上游.

## 后续工作 (非 MVP 范围)

- 流式响应 + redact 的 chunk boundary 处理 (用 sliding window + UTF-8 char 边界检测).
- mock_secret 的 category-aware 生成 (Password/ApiKey/Cookie 等格式感知).
- 配置热加载 (目前 Web UI 改 config 后, 重启才影响 CLI 参数).
- 测试覆盖率自动上报 + fuzzing (cargo-fuzz).
