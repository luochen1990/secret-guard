# secret-guard — Agent 工作指南

> 本文件面向 AI 代码助手 (opencode / claude-code 等), 描述本项目的**项目级**约定与开发流程.
> 模块级实现契约见各模块目录的 `AGENTS.md` 或源文件头部 `//!` 注释 (指针见"模块概览").
> 用户级文档见 `README.md`.

## 本文档维护约定

- 拆分结构: 领域专题已下沉独立文件, 本文件只留锚点 hook — 已知限制 → `docs/known-limitations.md`; 依赖观察 (多版本快照 + 升级等待队列) → `docs/dependency-watch.md`; 模块依赖方向图 → `docs/design/module-dependency.md`. 新知识先落所属子文件 / 小节, 不在 hook 处展开.
- 登记类区块 (术语表 / 契约编号速查 / 模块概览 / 配置字段维护者注记): 按 key 字母序插入 (Latin 条目在前, CJK 条目按码点在后) — 插入点天然分散, 并发插入互不冲突.
- 叙事类区块 (路由错误语义 / 决策记录): 新条目追加至本节末尾.
- 条目单行化: 一条知识一个 `- ` bullet, 单行书写不折行 — 行级 3-way merge 对不同位置插入天然免疫.
- 锚点冻结: 小节名与编号被 src 代码注释 / tests / docs 引用 ("已知限制 (MVP)" / "后续工作" / "已接受的例外" / "前端不变量" I1-I6 / 契约前缀 / C1-C7), 不改名、不重编号.

## 项目定位

轻量级 LLM 网关 (本地进程): 透明转发 LLM 请求, 同时检测并替换 body 中的 secret,
防止 agent 不经意把 secret 泄露到 LLM Provider. 响应回传时反向替换, 让本地工具仍能用真 secret.
支持多 provider 配置 (OpenAI / Anthropic / Gemini / Ollama / Responses), 通过 URL 路径前缀选择目标.

## 术语表

> 本表是**消除歧义的权威**. 当用户使用"常见异名"列中的口语时, 回应时必须替换为"规范术语"
> 并紧临括注对应关系, 例如: 用户说"把 AI 发的消息居左" → "明白, 我把 role 为 Assistant
> (AI 发的) 的 Bubble 居左". 不要反问"你说的 X 是不是指 Y"——直接纠正, 避免漂移.
> 行序 (登记类): 按规范术语字母序插入 — Latin 条目在前 (case-insensitive), CJK 条目按码点在后.

| 规范术语 | 定义 | 常见异名 | 归属层 |
|---|---|---|---|
| **Bubble** | 前端 timeline 中渲染的单条消息气泡 (= 1 个 IR message) | 气泡、消息块、消息项 | web/index.html |
| **Common URI** | 端点的公共 URI 前缀 — 三段式 `base_url + common_uri + request_uri` 的中段, 两个消费面: ① fetch_model_list (router /models 本地合成拉上游清单); ② 跨协议翻译的出站 URL (`Endpoint::effective_common_uri`, #260 — 显式值直通, 缺省按 base 尾段启发式). 同协议透传不受影响 (转发 rest 原样流过). 值域: `"/v1"` 裸根布局 / `""` 版本前缀已含 (智谱等国产系) / 缺省未探测 (fetch 按 `V1_COMMON_URIS` 顺序懒回退现场推导). 持久化在 `Endpoint.common_uri` (per-endpoint; Detect 探测自动填充, WebUI 端点行 badge 回显), 运行时记忆在 `CacheEntry.common_uri_hit` | common_uri、版本前缀、布局前缀 | provider/proxy |
| **Effective view** | 合并 static + dynamic + decision 后的生效配置 | 生效配置、最终配置、合并视图 | config |
| **Endpoint (端点)** | Direct provider 的一个 `(protocol, base_url, common_uri)` 三元组 (`endpoints` 有序数组, 每协议至多一条 — validate 强制; 多端点共享同一凭证)。数组序 = fallback 序: egress 端点由 ingress 经 `select_endpoint` 选定 — 精确匹配 → 同协议, 无匹配 → 首端点跨协议翻译 (multi-endpoint D2) | 协议端点、端点条目 | provider/proxy |
| **ForwardRecord** | 一次 HTTP 转发的完整记录 (web 层 DTO, 从 DAG Node 派生) | 请求记录、record、转发记录 | web |
| **Ingress / Egress** | 请求进入 / 响应离开 secret-guard 时用的协议 | 入站/出站协议 | proxy/codec |
| **IR** | 协议无关的中间表示 (IrRequest / IrResponse / IrBlock) | 中间表示 | codec |
| **Member (成员)** | Pool 的 `members[]` 指向的一个 Direct provider id (= 一份独立套餐凭证) | 池成员、成员账号 | pool |
| **Mock** | Redact 时替代 Secret 的占位值 (per-secret 稳定, 不含真 secret 子串) | 假值、替身、占位符 | 全局 |
| **MockStrategy** | 每个 Secret 的 Mock 生成策略 (初始值 + 生成策略两维度) | mock 策略、生成策略 | mock/redact |
| **Node** | ConversationDAG 中的一个节点 = 一次 API 调用 | 轮次、round、节点 | dag/web |
| **Pool Provider** | `ProviderKind::Pool` 构造的套餐池端点 (`members` 有序成员列表必填) — 自身不转发, 顺序 failover: 正常全打第一个可用成员, 检测到窗口限额耗尽信号后自动切下一个成员, 耗尽成员按恢复闹钟自动回归; 运行时状态内存态不持久化 (契约 POOL-*) | 套餐轮换、配额池、账号池、用完了切下一个 | provider/proxy/pool |
| **Protocol** | LLM API 的协议族 (OpenAI / Anthropic / Gemini / Ollama / Responses) | 协议、格式 | 全局 |
| **Provider** | 一个 provider 条目 (sum type: Direct 直连实体 \| Router 路由 \| Pool 套餐池, #187 + Pool 延伸) | 上游、后端、模型、服务商 | 全局 |
| **Redact** | 把 request body 中的 Secret 替换为 Mock 的正向操作 | 脱敏、过滤、打码、替换 | 全局 |
| **RedactionMap** | 一次 Redact 产出的 Secret↔Mock 双向映射表 (per-request, 不持久化) | 映射表、redact map | redact |
| **req_delta** | 一个 Node 相对其 parent 新增的 messages | 增量、本轮新增、delta | dag/web |
| **resp_parsed** | 流式响应经 StreamScan 累积的 IR 视图 | 解析结果、响应解析 | web |
| **Restore** | 把 response body 中的 Mock 还原为 Secret 的反向操作 | 还原、反替换、恢复 | 全局 |
| **RoundKind** | 轮次展示类别三态 (Normal 常规 \| Retry IR 等价重发 \| NoMessages 无 messages), push 时从 (split_at, msgs) 预计算, UI-1 渲染分发的 SSOT (contracts.md DTO-9) | 重试标记、轮次类型 | dag/web |
| **Route** | 路由四元组 (`model_pattern` model 通配符 / `target` 目标 / `upstream_model` 重写 / `priority` 优先级) — model_pattern 匹配请求 model 时路由到 target, priority 越大越优先 (None = 禁用) | 规则、路由规则 | provider/proxy |
| **Router Provider** | `ProviderKind::Router` 构造的路由端点 (`routes` 路由列表必填) — 自身不转发, 按请求 model 匹配路由链式解析到链尾实体 provider (per-request, WebUI 即席改路由, #179 多规则化; sum type 化 #187) | 虚拟 endpoint、virtual provider、路由 provider、别名 | provider/proxy |
| **Secret** | 需要从 LLM 视野中隐藏的真实敏感值 (API key / token / 密码等) | 密钥、敏感信息、真实值、真值 | 全局 |
| **Session** | 由 Merkle 前缀哈希聚类的一组 Node 链 | 会话、对话、conversation | dag/web |
| **三通道 (exhaust signal channels)** | 耗尽信号的三条独立匹配线 (HTTP status / body 码 / response header, OR 关系), 判定 SSOT = `pool::detect_exhaustion` | 信号通道、触发线 | pool |
| **闹钟 (alarm)** | 成员耗尽时记录的恢复时刻 (`Exhausted{until}`) — 来自上游精确信号解析 (`resume_at`) 或 `now + cooldown_secs` 兜底 (恒有时刻, 无永久形态) | 恢复时间、冷却时间 | pool |

## 关键技术决策 (SSOT)

- **语言**: Rust 2024 edition (toolchain 1.96, via nixos-unstable, 与 ~/ws/nixos 共享 nixpkgs)
- **Web 框架**: axum 0.8 (不使用 rig.rs / pingora 等高级抽象)
- **HTTP client**: reqwest 0.12 with rustls
- **协议无关**: body 在字节层面流动, secret 改写在 IR 层 (基于 `src/codec/ir`)
- **双层配置**: 声明式 `secret-guard.toml` (static, 只读) + 动态 `secret-guard.state.toml`
  (dynamic, WebUI 写回). 详尽语义见 `src/config.rs` 头部.
- **测试**: cargo-nextest + proptest (property-based) + mockito (集成测试) + Playwright (WebUI)
- **覆盖率**: cargo-llvm-cov (LLVM source-based, 行级精度). 细节见"测试策略".
- **格式化**: treefmt 全仓 (nixfmt / rustfmt / taplo / ruff-format), 配置 SSOT =
  根 `treefmt.toml`; 门禁 = `just check-fmt` (treefmt --fail-on-change). 细节见
  "nix flake 布局 (flake-fhs)" 段.

## 数据流契约 (总览)

> **本节是 normative (尺子), 不是 descriptive (描述现状)**. 定义 secret-guard 数据正确性的理想目标.
> 完整契约 (10 个属性域, ~100 条可测 property) 见 **`docs/design/contracts.md`**.

数据流分三个信任域, 域间有单向承诺:

```
域 A (转发链: client ↔ upstream)  ──字节正确性是根基──►  域 B (派生链: DAG/webapi)
                                                          │
                                                          ▼
                                                   域 C (渲染层: WebUI DOM)
```

**最强契约 FWD-1 (透明中继 byte-exact)**: secret-guard 是客户端与上游之间的字节级透明中继 — **对 wire 的唯一合法修改是 real↔mock 替换**, 除此之外的任何字节差异都是 bug. 两个半段 (请求侧 / 响应侧) 经 normalize (canonical JSON) 后 byte-exact. 这条契约把"难以测的语义等价"转换为"可机械验证的字节相等".

**契约编号速查** (段前缀 → 域, 详见 `docs/design/contracts.md` §0.2; 行序 (登记类): 按前缀字母序插入):

| 前缀 | 域 | 收纳现有契约 | 一句话职责 |
|---|---|---|---|
| `CDAG-*` | B | **DAG INV-1..5** + 新增 | 内容寻址 + Merkle + refcount + 孤儿节点 + session 稳定 |
| `CFG-*` | B | 新增 | 双层配置合并 / CRUD / 持久化 / 并发 |
| `DTO-*` | B | 新增 | WebUI DTO 派生 (redactions / resp_parsed / preview / delta / title) |
| `FWD-*` | A | codec INV-1/2/5, proxy DoD | 透明中继 byte-exact + codec round-trip + HTTP 透传 + 路由 + 鉴权 |
| `POOL-*` | A | 新增 (Pool Provider, 待人工授权) | 套餐池顺序 failover + 三通道耗尽检测 + 闹钟自愈 + 全耗尽本地 503 + 检测旁路 + 默认表语义域 |
| `RED-*` | A | **C1-C7** (redact/mock) | Redact/Restore 可逆双射 + 不泄漏 + 前缀缓存友好 |
| `ROB-*` | 跨 | 鲁棒性原则 | best-effort 永不 panic + 假设声明注释必备 |
| `SEC-*` | 跨 | 新增 | GET 不泄漏 / panic 不泄漏 / headers 脱敏 / 本地监听 / Host·Origin 校验 (SEC-7, 防 DNS rebinding) / 敏感落盘 owner-only (SEC-8) / API nosniff (SEC-9) / 降级偏安全 (SEC-10) |
| `STR-*` | A | codec INV-4 + 新增 | 流式 SSE 边界 + 累积 + 错误降级 + reader 多 tool_call 索引 |
| `UI-*` | C | **I1-I3** + 新增 | 气泡数 / sidebar 条目数 / DOM 顺序 / reconciliation / drawer |
| `USAGE-*` | B | 新增 (usage-stats) | 回显保真 + 聚合一致性 + 成本纯函数 + 缺失显式 + 计入判据 + model SEC 扫描 |
| `VIEW-*` | 跨 | 视图正确性机制 | 先断言后删除 + 派生字段 consistency-check 覆盖 |

**核心纪律** (详见 `docs/design/contracts.md` §0.3 Property 设计原则 + §0.4 冗余覆盖原则 + §0.5 漂移处理流程):
- Property 描述**外部可观察行为**, 不依赖内部实现 (避免过拟合).
- 优先 **byte-exact (normalize 后)** 而非语义等价 (可机械验证, 无需 case-by-case 定义"语义").
- **proptest 生成器覆盖度也作为契约要求** (历史 bug 多次出现 property 存在但生成器太窄致漏测).
- **端到端契约 (FWD-1) 与其分解契约 (FWD-2 / RED-6/7) 必须分别独立形式化、独立可测** (测试原则是不信任其他代码).
- 契约编号一经分配永不变更 (删除作废不重用).
- 代码与契约冲突时, **契约不能擅自修改, 必须经过人工授权** (详见 `docs/design/contracts.md` §0.5).

## 关键不变式与工程纪律

### 模块依赖方向图 (SSOT — 新增依赖前必查)

> 数据流契约 "域 A (转发链) → 域 B (派生链) → 域 C (渲染层)" 单向承诺的实施层 (#145).
> 依赖图 (主干) / 分层要点 / **已接受的例外** 清单 (每条单行 bullet, 按边名字母序, 必附 rationale) 的 SSOT 见 **`docs/design/module-dependency.md`** — 新增 `use crate::...` 前对照该图判断 "新依赖是否扩大偏离"; 只允许**向下**依赖 (指向更低层), 反向 / 新横向依赖需先改该图并在 PR 中说明理由.
> 本锚点被 src 代码注释引用 (`src/dto.rs` 头部 / `src/proxy/models.rs` / `src/proxy/mod.rs` 的 "已接受的例外"), 小节名冻结.

> secret-guard 的核心职责 (转发 + Redact) 必须对任意字节流零失败.
> 围绕核心职责之外、**基于对 LLM 应用层行为模式强假设** 的附加功能
> (preview 提取 / delta 切片 / WebUI 分组渲染 / tool name 推断等) 是"尽力而为"增强,
> 绝不能因假设不成立而让请求失败或进程崩溃.

### 鲁棒性原则 (best-effort, 永不 panic) → ROB-* 契约

对"尝试性解析"功能, 必须同时满足:

1. **鲁棒性处理**: 解析路径用 `Option`/`Result` 传播失败, 缺字段 / 类型不符 / 空数组 / 越界
   都返回 `None` 或空, 由调用方走 fallback (如 preview 为 None 时前端降级到占位文本,
   delta 切片 fallback 到空 `Vec`, tool name fallback 到 `'?'`).
   Rust 侧用 `?` 短路; 前端用 `|| []` / `|| '?'` 兜底.
2. **假设声明注释**: 每个解析点必须在注释中显式写出它对输入的假设
   (如 "假设 messages 数组中 user 在 assistant 之前"), 以及假设不成立时的降级行为.

已实践位置: `derive::extract_preview_and_model` (preview 提取),
`derive::extract_tool_use_name` (工具轮次 preview = tool name 提取),
`derive::extract_delta_messages_from_raw` (delta 切片).
(注: 前端 `toolNameOfRound` 已删除, tool name 提取在后端分两路 — sidebar 主标题由
`extract_preview_and_model` 处理, 工具轮次的 sub-dot preview 由 `extract_tool_use_name`
在 `dag::push_messages` 覆盖, 两者均由 `prop_preview_never_panics` 统一守卫 ROB-1.)

> **例外 — DAG 核心数据结构不用 best-effort**: `dag::BlockPool::intern` 的 collision check
> 用 `assert!` (非 `debug_assert!`), release 也 panic. 理由: collision 属哈希函数 bug,
> 静默覆盖会让两个不同 block 共享 hash 引发难定位的数据损坏, panic 是更优选择. 详见
> **CDAG-6** 契约 (`docs/design/contracts.md` §4).

### 视图正确性确保机制 (View-Correctness Discipline) → VIEW-* 契约

当用视图 / 引用 / 派生字段替代原始数据存储 (典型场景: 内存优化、去重、lazy 派生) 时:

1. **先断言后删除**: 删除原始数据前, 必须用 `assert_eq!(derived_view, original_data)` 断言两者
   相等 (或写专项测试覆盖). **禁止**仅凭"视图逻辑应该对"就删除原始数据.
2. **断言需有 feature flag 守护**: 对热路径断言用 `#[cfg(feature = "consistency-check")]`
   包裹, 避免生产开销但保留 CI 守卫 (项目已有此 feature 先例).
3. **原始数据是核心功能的真相**: secret-guard 的核心职责是转发 + Redact 的字节准确性.
   任何"派生视图更优雅"的诱惑都不能凌驾于数据准确性之上.

已实践位置: `redactions` 字段从 RedactionMap 派生 (`proxy/recorder.rs::assert_redactions_match_map`)、
`preview`/`model` 从 `req_body_raw` 派生 (`proxy/recorder.rs::assert_preview_model_match_source`)、
`resp_parsed` (非流式) 从上游响应字节经 codec reader 派生 (`proxy/recorder.rs::assert_resp_parsed_matches_source_nonstream`)、
`session.title` 从 root node preview 派生 (`dag/mod.rs::assert_session_title_matches_root_preview`)、
`resp_parsed` (流式) 从 StreamScan 累积 (`proxy/fan_out.rs`, Phase A 已删除原始 SSE 字节, 派生与源物理分离, 暂不守卫).
后续 Phase B 删除 parent.response 时必须走此流程.

### C3 前缀缓存友好性 (经济性契约) → RED-3 契约

Redact 不应无必要地改变 request body 的字节内容, 避免破坏 LLM Provider 侧的前缀缓存命中
(前缀缓存是 byte-exact 的, 历史 message 中 mock 字节变化会导致从该 message 起的整个前缀
缓存失效, 增加用户的 token 费用负担). 实现: per-request seed 驱动整个 RedactionMap,
保证同一 policy + 同一上下文 → 同一 mock. 详尽契约 (C1-C7) 见 `src/redact.rs` 头部
与 `src/mock.rs` 头部.

> 例外 (RED-3 裁决, #143): pre-replace IR 已含该 secret 的旧 mock 时 (客户端把 mock
> 回传进历史), mock 允许变化 (probing counter 推进). 理由: 复用旧 mock 会让 restore
> 错替历史中的旧 mock, 破坏 RED-6 round-trip — restore 正确性优先于缓存稳定性.
> 代价是经济性 (前缀缓存失效), 非安全性. 详见 contracts.md RED-3 例外场景裁决.

### Host / Origin 校验 (SEC-7, 防 DNS rebinding + CSRF 纵深)

默认单用户模式 (auth disabled) 下无认证, "同源策略兜底" 的旧假设会被 DNS rebinding
击穿 — 攻击页面的域名 rebind 到 127.0.0.1 后, 浏览器发出的请求对本地 server 是
"同源"的, 可读 `/api/sync`、可写 provider base_url / secret decision。server 层以
最外层 middleware 对**所有**路由做两类校验 (实现 `src/server_host_guard.rs`,
挂载 `src/server.rs`, 失败一律 403):

1. **Host 白名单** (所有请求): Host 的显式 port 必须等于监听 port (无 port 仅当
   监听 80 时合法 — 浏览器默认省略); host 部分放行: loopback IP 字面量
   (127.0.0.0/8, `[::1]`) / 配置 host / `localhost` / 空 host; 配置 host 非
   loopback (`0.0.0.0` / `::` / LAN IP — 本机非环回地址无法枚举) 时放行任意
   **IP 字面量**; **未声明的域名形式 Host 一律拒绝** — 例外:
   `[server] allowed_domains` 显式声明的信任域名按名字精确匹配且**端口宽松**
   (反代 + 域名部署形态, 攻击者的域名进不了这份用户手写的名单; 条目归一化
   trim + 小写, 含 `:` 形态 (host:port/裸 IPv6)/IP 字面量/localhost/空串条目 WARN 跳过)。生产 `serve()` 要求
   host 可解析为 SocketAddr, 域名 host 启动即报错 (仅 Host header 侧有白名单)。
   缺 Host header 放行 (rebinding 必带域名 Host)。
2. **`/api/*` 非安全方法 (POST/PUT/DELETE/PATCH) 的 Origin / Sec-Fetch-Site 校验**:
   带 Origin 则其 host:port 必须在白名单 (`Origin: null` 拒绝;
   `allowed_domains` 声明域名同享且端口宽松); 带
   Sec-Fetch-Site 则必须是 same-origin / same-site / none; 两者都缺放行
   (非浏览器 SDK)。GET/HEAD 等安全方法豁免 (读端泄漏由 SEC-1 守卫)。
   转发路径 (`/{o|a|g|l|r}/...`) 不做 Origin 校验 (SDK 场景, Host 校验已覆盖)。

测试: 单元 (`src/server_host_guard.rs::tests`) + 集成 (`tests/integration.rs`
SEC-7 段); 可测 property 见 `docs/design/contracts.md` **SEC-7**。

### 契约演进原则 (2026-09-23 用户授权)

- **尊重事实** (诚实呈现数据的缺失/来源/粒度 — 如 usage 缺失时不伪造全零对象) 是通用原则, 向此方向演进**无需人工授权**.
- 协议间互译的**精确化** (把粗粒度映射改精确、消除信息损失 — 如 stop_reason 按 output 推断) 同样无需授权 — 契约锁定的断言可能只是之前实现阶段的折衷, 精确化演进不受其阻碍 (同步更新契约正文与 property 断言即可). 政策落点: `docs/design/contracts.md` §0.5.

## 降级偏安全原则 (fail-safe degradation) → SEC-10 契约

secret-guard 在无法维持核心保证 (real secret 不出现在未授权位置) 的降级路径上,
**默认不扩散真实 secret** — 请求侧降级默认拒绝转发 (503), 响应侧降级默认保留 Mock
透传; real 进入更大暴露面 (上游 / 易被日志采集的失败响应体) 必须显式 opt-in.
rationale 是不对称性: 可用性损失可重试恢复, 机密性损失不可逆. 三个开关
(`[redact] on_probe_exhausted` / `on_unsupported_protocol` / `on_fallback_restore`,
2026-09 起默认全部安全侧) 是本原则的配置面; 完整陈述与 property 见
`docs/design/contracts.md` **SEC-10**.

## 前端不变量 (UI Invariants) → UI-1..UI-7 契约

> 以下条目是**跨 web/dag/index.html 的强不变量**, 任何渲染优化或内存重构不得违反.
>
> **编号映射**: AGENTS.md 的 `I*` 是 contracts.md `UI-*` 的前身 (历史编号).
> `I1=UI-1`, `I2=UI-2`, `I3=UI-3`, `I4=UI-6 的 selectedRound 子属性`, `I5=UI-6`, `I6=UI-7`.
> contracts.md 收录并扩展为 UI-1..UI-7, 以 contracts.md 为 SSOT; 此处保留 I* 编号便于历史 grep.
### I1 — 气泡数 == req_delta messages 长度

会话详情页 (timeline) 渲染的 Bubble 数量, 必须等于该 Node 的 req_delta messages
数组长度. 空 delta 轮按 `round_kind` 三态分发 (DTO-9, push 时预计算): `retry`
(IR 等价重发) → 0 气泡 + retry 徽章 (不捏造用户消息); `no_messages` → preview
fallback 单气泡. 任何渲染优化 (折叠、合并、视图派生) 不得改变此等式.

### I2 — sidebar 条目数 == HTTP 请求数

左边栏每个一级条目 (Session) 下, 二级 + 三级条目总数, 必须等于归属该 Session 的 HTTP 请求
数 (即 DAG 中以该 Session 叶子为终点的链上 Node 数).

### I3 — timeline 轮次 DOM 顺序 == 数据顺序 (oldest-first)

会话详情页 (timeline) 中 `.tl-round` 在 DOM 里的出现顺序, 必须与 `state.timelineRecords`
完全一致 — 即 oldest-first (顶部最老, 底部最新, 与对话流时间线方向一致). 实现层面的陷阱
(anchor 从 DOM 末尾 vs 最前起步) 见 `reconcileTimelineRounds` 函数头部注释 (历史教训).

### I4 — `.tl-round.selected` 类 == `state.selectedRound` SSOT

timeline 中带 `.selected` 类的 `.tl-round` 集合, 必须严格等于 `{state.selectedRound}`
(恰好一个 rid 匹配, 其余均不带; `state.selectedRound = null` 时全无). 该一致性由
`updateSelectedRoundClass` 在 `selectRound` 入口显式同步. 历史 bug: 点击 dot/round-item
时只调 `highlightRound` (负责 `.flash` 闪烁动画), 不重建 DOM, 而
`reconcileTimelineRounds` 复用已有节点时也不更新 class, 导致 `.selected` 滞留在旧轮次
与 `.flash` 错位.

### I5 — timeline 滚动状态机: followMode 是视口位置的纯派生 (↔ UI-6)

timeline 的 follow/pinned 状态由**视口距底部距离**机械推导 (纯派生), 不由 "最近点了什么"
显式动作决定; `selectedRound` 与 followMode 解耦 (方案 X: 仅 "进入 follow 的显式动作" —
点 Session / 点 unread badge / 初次 loadTimeline — 才重置 selected 到最新轮).
完整状态机 (NEAR_BOTTOM_PX 阈值 / follow 闭合不变量 / 短内容 drawer 压缩 / 几何失效区间)
的 SSOT 是 contracts.md **UI-6**; 视觉指示 (drawer 边缘配色 / `.pinned` 类) 与前端实现
细节 (syncFollowMode 入口 / handleNewRounds / jumpToLatest) 见 `src/web/AGENTS.md`
"timeline 滚动状态机" 段.

### I6 — sidebar rounds 回填时序 + timeline 并发一致性 (↔ UI-7)

点击 sidebar 会话头 (toggleSession 展开) 后, 三级菜单的 "Loading rounds…" 占位符由
toggleSession 内触发的**主动 sync** 覆盖 (不依赖 3s 轮询 tick; auto-refresh 关闭时
占位符不得无限期停留). timeline 并发一致性由**代数 (gen) 对账**保证:
`state.timelineGen` 只增不减, 换世界者 (loadTimeline / clearTimeline) bump; 一切写
`timelineRecords` / `tail` / `timelineReachedTop` 的在途响应落地前对账, 代数不匹配即
丢弃 timeline 数据 (sidebar 数据照常应用). sync 构造 `selected` 游标前校验
`timelineSession === selectedSession` (loadTimeline 落地对账通过后才认领归属),
不一致发 null 游标, 防止矛盾游标触发后端 "after 不属于本 session → 全链重放" 契约.
详尽形式化见 contracts.md **UI-7**.

**回归守卫**: 这些不变量由 `tests/webui/im-ui.spec.ts` 守卫. 改前端渲染逻辑或后端
delta 切片时, 必须同步跑 `just check-webui`.

## 路由策略 (核心契约)

URL = `/{proto_short}/{provider_id}/*path`. 同时编码 ingress 协议与目标 provider,
为未来跨协议转换预留钩子. **完整 URI 分配规划 (顶级保留字 / 命名空间不相交论证 /
变更流程) 的 SSOT 见 `docs/design/url-layout.md`**, 下列路由改动必须同步该文档.

| 路径 | 含义 |
|---|---|
| `/` | Web UI (主入口) |
| `/api/*` | Web UI JSON API (未匹配子路径 404, 绝不进 forward) |
| `/login`, `/oauth2/callback`, `/logout` | OIDC 认证 (auth 启用时) |
| `/{o\|a\|g\|l\|r}/{name}` | forward, rest = "/" |
| `/{o\|a\|g\|l\|r}/{name}/{*rest}` | forward, rest 为子路径 ({*rest} 捕获不含前导 `/`, 消费方容错处理, 见 `ForwardPath` 注释) |
| 其他 | 404 (不再 catch-all 透传) |

`proto_short` 简写映射的 SSOT 是 `Protocol::ALL` (协议家族清单见术语表 Protocol 行),
文档与代码注释一律引用该常量, 不维护手抄清单.

错误语义 (叙事类 — 新条目追加至本节末尾):
- 未知 protocol 简写 → 404 `not_found`
- 未知 provider id → 404 `not_found`
- 禁用 provider (`enabled = false`) → 503 `unavailable`
- 路由 provider (routes) 坏路由: 无匹配路由 (NoMatch) / 目标缺失 / 目标 disabled / 成环 → 503 `unavailable` (message 只含 id + model 名 + reason 枚举, SEC-2 同型; 解析 per-request — body 收集后按请求 model 匹配路由, 切换只影响新请求 — FWD-5, #179)
- 套餐池 provider (pool) 全耗尽: 全部成员耗尽/missing/disabled → 503 `unavailable`, **本地快速失败 (零上游请求)**, message 只含 pool id + reason 枚举 + 最早恢复剩余秒 (SEC-2 同型); 顺序 failover + 耗尽信号检测的语义见 contracts.md **POOL-*** 与 `src/pool.rs` 头部
- **跨协议 + `stream=true`**: codec 覆盖族 (OpenAI ⇄ Anthropic ⇄ Responses) 任意 pair 走 StreamTranslate 流式翻译 (含 Redact 场景的响应侧 restore; Responses 流式已知损失见 `docs/known-limitations.md`)
- Gemini/Ollama 跨协议 → 501 (codec 未覆盖)

**Direct provider 多协议端点 (multi-endpoint)**: Direct 条目持有有序 `endpoints` 数组
(每协议至多一条, validate 强制), egress 端点由 ingress 经 `DirectProvider::select_endpoint`
选定 — 精确匹配 → 同协议透传, 无匹配 → 首端点跨协议翻译 (fallback, 单端点配置下行为
与演进前一致); 空 endpoints (绕过 validate 的非法配置) → 503。router 链尾与 pool 成员
同型 (解析到链尾/成员 Direct 后按 ingress 选端点)。端点选择 property 与完整语义见
contracts.md **FWD-5** 与 `src/provider.rs` 头部。

**router provider 的模型列表 GET 请求本地终结 (#196)**: `GET /{o|a|g|l|r}/{router}` + 模型列表端点
(o/r/a: `/models` 或 `/v1/models`; g 另含 `/v1beta/models`; l: `/api/tags`) 时, 响应本地合成 =
别名清单 (exact pattern, 路由表序) ∪ 过滤后的上游模型清单 (per-(Direct-provider, 选定端点
egress 协议) 缓存, 各 ingress 入口经 `select_endpoint` 各自选 fetch 端点、各自缓存;
TTL 300s + serve-stale-on-error + single-flight; exact-only router 零上游请求 — N6 gate),
不进转发链 / 不记 DAG (D5); Direct provider 的 /models 透传行为不变 (D6)。
Pool 不进此本地终结分支 (Router 专属) — pool 入口的 /models 经 resolve_route 打到当前
成员, Direct 透传语义 (成员耗尽的 failover 语义对 GET /models 同样生效)。
可测 property 见 `docs/design/contracts.md` **FWD-7**; 实现见 `src/proxy/models.rs` 头部。

详尽的 dispatch 路径选择 (同协议透传 / IR 路径 / 跨协议翻译) 与 fan_out 四路径见
`src/proxy/mod.rs` 头部 (拆分为模块目录, 各子路径实现在 `same_proto.rs` / `cross_proto.rs` /
`fan_out.rs`); 路由相关的可测 property 见 `docs/design/contracts.md` **FWD-5**.

## 模块概览

> 每个模块的**详尽契约**在对应位置. 这里只给一句话职责 + 指针.
> 行序 (登记类): 按模块名字母序插入.

| 模块 | 职责 (一句话) | 详尽契约位置 |
|---|---|---|
| `auth/` (模块目录: mod/oidc/handlers/session/apikey/middleware) | OIDC 登录 (WebUI) + 本地 API key (SDK 转发) + session | `auth/mod.rs` 头部 `//!` |
| `codec/` | 跨协议 IR + Reader/Writer trait + StreamTranslate (OpenAI / Anthropic / Responses) | **`src/codec/AGENTS.md`** + `docs/design/ir-fields-roadmap.md` (IR 字段建模路线图: extra 边界 + 字段提升判定准则 + 实施批次) |
| `config.rs` | 双层配置 schema + `DynamicTable<T>` 泛型 + 持久化 + 静态配置预检审计 (未知 section/字段 → 启动 WARN, #159) | 文件头部 `//!` (覆盖 OverrideMode / CRUD / Effective source / 跨表并发) |
| `dag/` (模块目录: mod/pool/types/view/timeline) | ConversationDAG 内容寻址存储 (BlockPool + Node + Merkle) | `src/dag/mod.rs` 头部 `//!` + `docs/design/conversation-dag.md` |
| `derive.rs` | 从 request body 派生 preview/model/text 的字节级提取 + delta messages 切片 (域 B 派生链, ROB-1 永不 panic) | 文件头部 `//!` (含 "为什么不在 web::api" 归属论证) |
| `dto.rs` | WebUI 响应 DTO 中立类型层 (SessionView/NodeView/.../SyncSnapshot, 域 B → 域 C wire shape; 构造逻辑留 dag) | 文件头部 `//!` (含 "为什么是顶层中立模块" 归属论证) |
| `error.rs` | 统一应用错误类型 `AppError` (转发链 + 鉴权层共用, 不反向依赖) | 文件头部 `//!` (含与 `web::api::ApiError` 分工 + Upstream/UpstreamTimeout message 净化回传契约) |
| `main.rs` / `cli.rs` / `lib.rs` | 二进制入口 + CLI 参数 schema | 文件头部 `//!` |
| `mock.rs` | MockStrategy 两维度 (初始值 + 生成策略) + 确定性 seed + `[redact] global_mock_prefix` 注入 + Auto widen 兜底 (退化 charset 候选空间 < 2^20 时逐级拓宽, Auto 永不弱配置) + GenSpec 候选空间配置期 lint (WARN, 有效对象为手动配置) | 文件头部 `//!` (C3 根基) |
| `pool.rs` | Pool Provider 运行时: 成员状态机 `PoolStates` (顺序 failover pick + 耗尽闹钟 + 配置对齐重建, 内存态不持久化) + 三通道耗尽信号检测器 `detect_exhaustion` (纯函数, ROB) + `PoolWatch` 响应侧旁路检测编排 + 观察面 (member_status / reset) | 文件头部 `//!` (含内置默认信号表语义域 + "提取宽判别严" 设计依据) + contracts.md **POOL-*** |
| `provider.rs` | Provider sum type (Direct 直连·多协议端点 `endpoints` + `select_endpoint` 端点选择 \| Router 路由 \| Pool 套餐池) + Route (model_pattern 通配 / priority / 路由级 upstream_model 重写) + PoolProvider/ExhaustConfig 与内置默认信号表常量 + Effective view + api_key 两来源 (Direct 条目级, 全端点共享) + `resolve_route` 路由链解析 (per-request; Router 跳按请求 model 匹配 + model 重写 pipeline, Pool 跳经 `PoolPicker` 状态机选成员) | 文件头部 `//!` |
| `proxy/` | dispatch 路径选择 + fan_out 四路径 + Provider 鉴权 + router GET /models 本地合成 + provider 协议探测 (拆分为 mod/helpers/auth/models/recorder/same_proto/cross_proto/fan_out 子模块) | `src/proxy/mod.rs` 头部 `//!` |
| `record.rs` | ForwardRecord (web 层 DTO, GET /records/{id} 响应 shape) | 文件头部 `//!` |
| `redact.rs` | RedactionMap + redact/restore pipeline + 形式化契约 C1-C7 | 文件头部 `//!` |
| `secrets.rs` | SecretEntry 实体 + Effective view + value 两来源 | 文件头部 `//!` |
| `server.rs` | router 装配 + 双层状态注入 + graceful shutdown + Host/Origin guard 最外层挂载 | 文件头部 `//!` |
| `server_host_guard.rs` | Host 白名单 + Origin/Sec-Fetch-Site 校验 middleware (SEC-7: 防 DNS rebinding + CSRF 纵深; 白名单语义见文件头) | 文件头部 `//!` |
| `state.rs` | 进程级共享状态 `AppState` (原 ProxyState, 上移见 #145) + HTTP 共享常量 `NO_STORE` | 文件头部 `//!` |
| `usage/` (模块目录: mod/store/pricing/summary) | 模型用量统计 + redact 审计: 上游回显 usage 采集 (UsageCtx, rounds 三态 + status 原始码) + SQLite 持久化 (writer 线程批量事务) + SQL 聚合 (hour 粒度) + models.dev 定价 + summary 派生 (设计 `docs/design/usage-stats.md`, 契约 USAGE-*) | `src/usage/mod.rs` 头部 `//!` |
| `util.rs` | 集中的哈希工具 + 文件权限收紧 (SEC-8) + 字符串截断族 (char boundary 安全, ROB-1) | 文件头部 `//!` |
| `web/` | JSON API (`api/` 目录) + 单页 WebUI | **`src/web/AGENTS.md`** |

> `ProviderTable` 与 `SecretTable` 是 `DynamicTable<T>` (`src/config.rs`) 的类型别名,
> 通用合并 / CRUD / 持久化算法都在 config.rs; 各模块只补充类型特定的 EffectiveView
> 映射与 validate 钩子.

## 配置模型 (双层: Static + Dynamic) — 概览

| 文件 | 角色 | 谁写 | 进入 git? |
|---|---|---|---|
| `secret-guard.toml` | **声明式 (static)** 配置: providers / secrets / server / redact / auth. 进程内只读. | 用户手写 | ✅ 推荐 |
| `secret-guard.state.toml` | **动态 (dynamic)** 状态: WebUI 编辑结果 + 对 static 项的 decision. 删除即可重置. **含明文敏感数据** (dynamic secret value / 显式写入的 api_key), 敏感级别与 static 同级 (#157). | 程序自动 | ❌ 推荐 .gitignore |

合并语义 (OverrideMode: Default / PreferStatic / Disabled)、Effective source 4 种、
CRUD 操作语义、DynamicTable 持久化策略、跨表并发安全的详尽描述见 `src/config.rs` 头部.

> 配置字段表 (全部段的字段 / 类型 / 默认值 / 用户语义) 的唯一维护点是 **`docs/configuration.md`**
> (README 已链接) — 改配置 schema (增删字段 / 改默认值) 只更新该文档, 本文件不再维护字段副本.

Secret / Provider 的两种 value 来源 (`value`/`value_file`、`api_key`/`api_key_file`)
及其 fail-fast vs 热路径差异, 见 `src/secrets.rs` 与 `src/provider.rs` 头部.

### 配置字段维护者注记 (登记类 — 按字段名字母序; 只登记 configuration.md 不载的实现指针 / 事故背景)

> `[server]` / `[redact]` / `[auth]` 段仅在启动时读取一次, WebUI 修改不生效 (restart
> 才生效). 这是为了保持转发核心路径的零运行时配置开销.

- `[auth]` 行为注记: `enabled = true` 时浏览器 WebUI 走 OIDC, SDK 转发走本地 API key (`Authorization: Bearer sg_...`); ApiKeyStore 与 `/api/api-keys` CRUD 无认证也总是可用 ("只认证, 不隔离" 哲学, 见 `src/auth/mod.rs` 头部); `oidc.issuer_url` 启动时 Discovery 拉取端点 (fail-fast); `oidc.client_secret_file` 可缺省 (public client + PKCE 场景); `[[auth.api_keys]]` 启动时 hash 后注入 ApiKeyStore 与 WebUI 签发 key 共用同一池, 静态 key 不可删除只能 disable/enable (`label` 唯一标识; `key`/`key_file` 二选一互斥, 语义同 `src/secrets.rs` 的 `value`/`value_file`).
- `allowed_domains`: Host 白名单完整语义 (端口宽松规则 / 归一化 / WARN 跳过条目) 见本文 "Host / Origin 校验 (SEC-7)" 段.
- `global_mock_prefix`: Auto 模式 mock 统一前缀, 注入每个 secret 的 `gen_spec.prefix`; 详见 `src/redact.rs` C5 契约.
- `host`: 默认 `127.0.0.1` 回环是 SEC-6 契约 (本地监听, 防意外暴露到 LAN/WAN).
- `on_fallback_restore`: 实现指针 `src/proxy/helpers.rs::restore_via_json_leaf_fallback` + `src/config.rs::OnFallbackRestore`; 行为契约 RED-8 / SEC-10 (降级偏安全).
- `on_probe_exhausted`: 实现指针 `src/redact.rs::redact_ir_checked` + `src/config.rs::OnProbeExhausted`; 默认 `fail_closed` 是 SEC-10 2026-09 翻转 (历史 `fail_open` 需显式 opt-in); 配置显式写出便于审计.
- `on_unsupported_protocol`: 实现指针 `src/proxy/same_proto.rs` from_native-None 分支 + `src/config.rs::OnUnsupportedProtocol`; 默认 `fail_closed` 同为 SEC-10 2026-09 翻转.
- `redacted_headers`: 归一化实现 `state.rs::normalize_redacted_headers`; 脱敏名单 = 硬编码黑名单 (`proxy::helpers::is_sensitive_header` 为 SSOT) ∪ 本配置, 请求/响应两侧 record 记录点统一取 `AppState::redacted_headers`.
- TCP keepalive (非配置, 内置): `server.rs::build_upstream_client` 显式钉住 reqwest 0.12.28 默认参数 (idle 15s + interval 15s + retries 3 + Linux TCP_USER_TIMEOUT 30s) — 全局 "活性判官" (亚分钟级 ~45s 判死 → 502). 注: reqwest 0.12.x 默认已开启 keepalive, 钉住是防升级静默漂移 (应用层超时放宽为 3600s 兜底后, keepalive 是死连接的唯一快速检测). 职责分工完整陈述见 contracts.md **FWD-4** "超时职责分工" 段.
- `upstream_connect_timeout_secs`: `0` = 无限 (向后兼容, 不建议); 覆盖 reqwest `connect_timeout`. 建连是唯一量纲自信的阶段, 15s 保持设紧.
- `upstream_nonstream_response_header_timeout_secs`: 非流式档默认 3600s = 防挂兜底量纲 (2026-09-23 裁决: #175 的 300s 在深度思考增长下误杀窗口重新打开; 活性检测归 TCP keepalive); "流式" 判定 SSOT = 显式顶层布尔 `true` 才算流式 (实现 `proxy::helpers::requests_stream` + codec reader, 两处等价).
- `upstream_response_header_timeout_secs`: 流式请求档为 TTFT 语义 (响应头在首 token 后到达), 默认 3600s 防挂兜底 (旧 60s 误杀大上下文 prefill / relay 伪流式); 超时记 504 record.
- `upstream_stream_idle_timeout_secs`: 流式 chunk 空闲档, 2026-09-23 裁决随三档统一 3600s 防挂兜底 (rationale 见 contracts.md FWD-4 "超时职责分工").

## 开发流程

```bash
# 一次性环境
nix develop --impure      # 进入 devShell (工具链全家桶; nix fmt 仅 devShell 内可用)

# 验证链 (命令全集见 justfile / `just --list`, 此处只列高频入口)
just check                # 一键 check: fmt + clippy + machete + doc + nextest + typos + deny-offline
                          #   链内含 check-webui-syntax (index.html 内嵌 JS 语法) 与
                          #   check-contracts (contracts.md property 落地标注 lint, #144);
                          #   doctest 当前禁用 (唯一 doctest 被 ignored, 需要时在 justfile 取消注释)
just ci-merge             # 一键复现 CI P0 门禁全链 (check-features + check 主链 + file-size; "本地全绿 ⇒ CI 必绿" 的锚)
just check --coverage     # check 含覆盖率插桩 (P2 ci-periodic 档内容; 本地按需)
just check-webui          # WebUI 回归测试 (Playwright)

# 开发热加载
just dev                  # cargo watch -x run (重启进程)
just dev-test             # cargo watch -x nextest run (TDD 红绿循环)

# 依赖审查 (devShell 内); 覆盖率报告 (coverage-html / coverage-lcov) 见 "测试策略" 各小节
just audit                # cargo audit (RUSTSec CVE)
just deny                 # cargo deny (license + bans + advisory 二次审查)
just typos                # typos-cli (拼写检查)

# 手动测试 — 启动 server (需要先在 secret-guard.toml 配置 [[providers]])
cargo run -- run --port 18787
# state.toml 路径默认从 config 派生: secret-guard.toml → secret-guard.state.toml
# 浏览器: http://127.0.0.1:18787/
# SDK 接入示例 (OpenAI / Anthropic base_url) 见 README "proto_short" 表;
#   注意 OpenAI SDK 不自动补 /v1 需自带 (…/o/<id>/v1), api_key 任意值 (由 provider 配置覆盖)
```

### CI (Forgejo Actions)

v3.0 三档 (org 分级契约, 见 lc-studio/forgejo-actions README; 命名即门禁):

| 档 | workflow | 触发 | 阻塞 | 内容 |
|---|---|---|---|---|
| P0 | `ci-merge.yml` | PR + master push + 手动 | PR 合入 | check-features + check 主链 (fmt/clippy/machete/doc/测试/typos/deny-offline/check-contracts) + file-size |
| P1 | `ci-deploy.yml` | master push + nightly + 手动 | 部署 | audit (CVE, 阻塞) + bench compare-save + nix build cargoHash (canary 探针, runner 无 nix-daemon 恒失败) (**非超集**偏差, 见 workflow 头声明) |
| P2 | `ci-periodic.yml` | nightly per-SHA 去重 + 手动 (无 push) | 无 | check --coverage + coverage-gate + WebUI Playwright |

跳过/去重机制: 事件去重 (push 仅 master; PR 总是跑 — draft/WIP PR 除外) + 内容去重
(skip-if-passed 共享 action, ff-merge 后同 SHA 不重跑; P2 按 SHA 去重次晚自愈) + PR
并发去旧 (concurrency). WIP 门禁 (#204): draft PR 不触发 CI, 去 WIP 前缀时经 `edited`
事件自动补跑 (机制见 docs/ci.md "WIP 门禁")。

**本地复现锚点**: `just ci-merge` = P0 全链 ("本地全绿 ⇒ CI 阻塞项必绿"); P1/P2 的
本地近似入口见 justfile `ci-deploy` / `ci-periodic` recipe 注释。

> CI 实现细节 (checkout 策略 / 缓存复用 / 并发假设 / 评论写回 / 三档 step 明细与
> 迁移去向表 / 各 step 升级路径) 见 **docs/ci.md**。

## 测试策略

| 层级 | 工具 | 示例 |
|---|---|---|
| 单元 (纯函数) | `#[test]` | `provider::tests::protocol_short_roundtrip` |
| Property-based | `proptest` | `redact::tests::prop_round_trip_identity` |
| 集成 (端到端) | `mockito` + `axum::serve` | `tests/integration.rs::forwards_streaming_sse` |
| WebUI 回归 | Playwright (TypeScript) | `tests/webui/im-ui.spec.ts` (守卫前端不变量 UI-1..UI-7) |
| 性能基线 | criterion | `benches/redact.rs` (redact_ir / StreamingRestorer 3 场景) |
| 覆盖率 | cargo-llvm-cov (LLVM source-based) | `just coverage-html` |

`mockito::Matcher` 在 1.x 没有 `String` 变体, 用 `Exact` 或 `Json` / `PartialJson`.

### TDD 与可选测试 (ignored tests)

> 为"先写测试、后写实现"的 TDD 流程提供不阻塞 CI 的机制. 关键事实: **`#[ignore]` 是
> libtest 的运行期属性, rustc 编译器不认识它** — 因此 ignored 测试**默认就参与每次
> `cargo build --tests` / `cargo nextest run` 的编译**, 编译漂移已被 `just check` 的
> clippy + nextest 编译阶段守住, 无需额外 CI step.

**ignore reason 命名规范** (两种合法形态):
1. `<标识符>: <一句话说明>` — 标识符为可追踪引用 (契约编号 `L8` / `RED-X` / issue 号 `#42`).
2. `待 <功能> ...` — 长期搁置项, 无契约/issue 编号, 必须在 `docs/known-limitations.md` 或
   `## 后续工作` 有对应条目.
现有先例: `L8: usage ...` (形态1)、`待 Gemini codec 实现 ...` (形态2).

**按"被测代码是否已存在"选型**:

| 场景 | 机制 | 适用条件 |
|---|---|---|
| **A: 被测函数已存在, 行为还没对** | `#[ignore = "..."]` | 最常见. 例: `redact_ir` 已实现但某 property 未满足. |
| **B: 被测函数尚未存在** | stub (`todo!()`) + `#[ignore]` | 真正的"测试先行". |
| **B 例外: 涉及新依赖/新模块** | `#[cfg(feature = "todo-X")]` + `[features] todo-X` | stub 若引用未实现的依赖, 会迫使该依赖提前进 Cargo.toml 拖慢默认编译; feature gate 彻底隔离. |

**TDD 循环** (场景 B 为例):
1. 写 stub 函数 (`todo!()`) + 测试, 测试标 `#[ignore = "L8: 待实现 ..."]`
2. `just check` → 绿 (编译通过即可, 运行跳过)
3. 实现真函数, 替换 stub
4. `just test-ignored <测试名子串>` → 看红灯变绿 (如 `just test-ignored openai_response`)
5. 删除 `#[ignore]` 行 + stub → 测试进入常驻集

**日常巡检**: ignored 测试应随对应功能实现而"转正" (删除 `#[ignore]`). 长期未转正的
ignored 测试是"计划但搁置"的信号, 应在 `docs/known-limitations.md` 或 `## 后续工作` 中
有对应条目. ignored 测试默认不运行故不计入覆盖率, 转正后自动纳入.
用 `cargo nextest list --run-ignored=only` 列出当前所有 ignored 测试做走查.

### 覆盖率工具 (`cargo-llvm-cov`)

集成 cargo-nextest. 工具链与 `LLVM_COV` / `LLVM_PROFDATA` 环境变量由 devShell 注入
(nix rust toolchain 不带 llvm-tools-preview 组件, 见 `nix/shells/default.nix`). 所有 coverage 命令
需在 `nix develop` 内执行.

- `just coverage`: 终端摘要表格.
- `just coverage-gate`: 覆盖率门禁 (CI 用, 双阈值).
- `just coverage-html`: HTML 报告 → `coverage/html/index.html`.
- `just coverage-lcov`: LCOV 报告 → `coverage/lcov.info`.

产物默认写到 `target/llvm-cov-target/` 与 `coverage/` (均已 .gitignore).
门禁阈值见 justfile (`COVERAGE_MIN_LINES` / `COVERAGE_MAX_UNCOVERED`).

### `rust-diff-analyzer` (PR diff 拆解 + 文件长度门禁)

区分 diff 中的 prod 代码 vs test 代码, 用于 review 时判断真实膨胀 (测试代码增加不是膨胀,
prod 代码大量增加才需警惕). 工具用 syn AST 解析, 自动识别 `#[cfg(test)]` / `#[test]` /
`tests/` 目录, 不依赖命名约定. 不在 nixpkgs, devShell 用 lazy `cargo install` wrapper
封装 (首次 `just diff-loc` 编译到 `${XDG_CACHE_HOME:-~/.cache}/secret-guard-tools/`, 后续命中).

两处复用 (SSOT):
- `just diff-loc`: 对 `master...HEAD` 跑 human 格式报告 (本地终端用).
- `just check-file-size`: 对每个 .rs 做完整 AST 分类, 只统计 prod 行数 (排除 test),
  双阈值门禁 (WARN 500 软提醒 / MAX 1600 硬阻断). fail-closed: 工具失败时 exit 1 不放行.
- CI: PR 事件的 diff 拆解 + 文件长度门禁都复用此工具 (diff 步 `continue-on-error: true`
  真正非阻塞), 详见 **docs/ci.md**.

### cargo-audit (CVE 监控)

依赖 CVE 扫描 (`cargo audit`). 项目级配置在 `.cargo/audit.toml`, 当前显式忽略项:

- **RUSTSEC-2023-0071** (rsa Marvin Attack): secret-guard 是 OIDC 客户端, 仅走 rsa 公钥
  验证路径, 不持有 RSA 私钥, 不在攻击面. 上游无修复版本. 详尽论证见 `.cargo/audit.toml`.

**走查纪律**: `.cargo/audit.toml` 的 ignore 项每半年走查一次; 上游若已修复, 立即移除忽略项
并升级依赖. 走查触发 = `just audit` 时人工核对 (CI 每 PR 跑, 但 ignore 项不报错, 易遗忘).

### cargo-deny (license + bans + sources 离线门禁; advisories 归 audit)

`cargo audit` 只覆盖 RUSTSec CVE; `cargo-deny` 额外覆盖 license 不兼容 / 重复 crate 多版本 /
禁止依赖 / git 源审计. 项目声明 MIT 且发布到 nixpkgs overlay, license 合规是硬约束 (引入
GPL/AGPL 等 copyleft 会污染下游). 配置在 `deny.toml`, 与 `.cargo/audit.toml` 的 `[advisories.ignore]`
保持同步 (互为冗余兜底).

- **CI 阻塞门禁是纯离线的** (`just deny-offline` = `cargo deny --offline check licenses
  bans sources`, 在 `just check` 链尾随 coverage step 执行, 不设独立 CI step): advisories
  检查需联网拉 advisory DB, 网络抖动会让阻塞门禁随机失败, 故归给 continue-on-error 的
  cargo audit. 本地 `just check` 链尾跑同一命令 (含 typos), 保证本地全绿 ⇒ CI 阻塞项必绿.
  全量检查 (含 advisories) 用 `just deny`.
- **license allow**: MIT / Apache-2.0 / BSD-* / ISC / Zlib / Unicode-* / MPL-2.0 (file-level
  copyleft, 不污染链接产物) / CC0-1.0 / CDLA-Permissive-2.0 (webpki-roots 的 CA 根证书数据协议).
  copyleft (GPL/AGPL/LGPL) 与不明 license 被 deny. 新 license 误报出现时更新 `deny.toml`
  即可 (属正常维护).
- **multiple-versions = warn**: 重复 crate 只警告不阻断 (Rust 生态 duplicate 多为传递依赖
  暂态, 强制 deny 会频繁阻塞). 当前重复清单 (两个口径) / 三类归因 / 消解时点 / 升级等待
  队列的 SSOT 见 **docs/dependency-watch.md** (实时清单以 `cargo tree -d` 与 Cargo.lock 为准).
- **sources**: 只允许 crates.io + 本地 path 源, 禁止私有 registry / git 直链 (难审计).

## 部署

NixOS 部署两代姿势: 结构化选项 (`services.secret-guard` 的 providers/secrets.entries/redact/auth,
未显式设 configFile 时经 `nix/render.nix` 自动生成 toml, eval 期校验 fail-fast) + 手写
configFile (escape hatch, 互斥). 凭据注入 (LoadCredential / sops 直接路径) 与 secret
批量注入方案见 **`docs/deployment-nixos.md`**.

### nix flake 布局 (flake-fhs)

flake outputs 由 [flake-fhs](https://github.com/luochen1990/flake-fhs) 按目录树生成
(`layout.roots = ["/nix"]`, embed 布局), 目录约定:

- `nix/pkgs/<name>.nix` → `packages.<sys>.<name>` (callPackage 注入)
- `nix/modules/<name>.nix` → `nixosModules.<name>` (单文件 module, 无 enable 注入)
- `nix/shells/<name>.nix` → `devShells.<sys>.<name>` (evalContext 注入 pkgs/system)
- `nix/checks/<name>.nix` → `checks.<sys>.<name>` (callPackage; `nix/checks/scope.nix`
  补注 lib — scope 默认的 `pkgs.lib` 不含 `nixosSystem`, 见该文件头)

flake-fhs 不生成的 output 由 flake.nix 手动补: `overlays.default` (SSOT 在
`nix/overlay.nix`, module 内注入与 packages 共用), `packages.default` 别名.
`nixpkgs.config = {}` 显式清零框架默认的 `allowUnfree = true` (license 合规由
deny 体系把关, unfree 应被拒绝). `formatter` output = 裸 `pkgs.treefmt`
(flake-fhs 探测到仓库根 `treefmt.toml` 后自动切换) — 注意 `nix fmt` 仅在
devShell 内可用 (treefmt 调用的 nixfmt/taplo/ruff 需在 PATH; devShell 已备齐).
全仓格式化 SSOT = 根 `treefmt.toml` (覆盖 nix/rust/toml/py; 排除 md/yaml/ts
的理由见其头部), devShell `treefmt` 与 CI `just check-fmt` 读同一份配置;
CI runner VM 未预装 treefmt 时 check-fmt 降级 rust-only (见 justfile).
扫描名单目录之外的散件 (`nix/module.nix` / `nix/render.nix` / `nix/tests/`) 不被
收集 — 测试辅助库因此必须留在 `nix/tests/` (checks 目录内的裸 .nix 会被当 check).
`nix/modules/secret-guard.nix` 是薄组装层 (imports `nix/module.nix` 本体 + overlay
注入), 保持 `nixosModules.secret-guard` 的 "module + overlay" 语义.

- toml 渲染 SSOT: `nix/render.nix` (纯函数, 与 src serde schema 的同步契约见其文件头,
  契约测试 `nix/tests/render.nix` 锁定); 模块接线冒烟 `nix/tests/module-eval.nix`
  (build 期经 `nix/tests/assert-toml.py` 用 python tomllib 对生成的 configFile 做
  TOML 语法 + 结构 round-trip 断言, 与 render.nix 的 eval 期断言互补, 共同锁定
  "模块选项 → configFile 生成" 链路).
  两者经 `just nix-check` 接入验证链 (挂在 `just check` 链尾, recipe 内探测
  nix-daemon — CI runner 架构禁止 nix 求值故自动跳过, serde 漂移门禁由本地纪律承担)
  — src serde schema 变更时本地先红.

> 路径约定见上方"路由策略"表格; `/api/*` 子路由细节 (未匹配 404 no-forward)
> 见 `src/web/AGENTS.md`; 完整 URI 分配规划见 `docs/design/url-layout.md`.

## 已知限制 (MVP)

> 完整清单的 SSOT 已下沉至 **`docs/known-limitations.md`** (按领域小节归位: auth / codec /
> config / dag / deploy / derive / pool / redact / routing / usage; 节内条目单行, 追加至末尾).
> **新增限制条目时同步评估**: README 协议支持矩阵 / Roadmap 与 probe note (`PROBE_NOTE_*`)
> 是否需要联动 (呈现策略详见该文件头部).
> 本段保留同名锚点 — src 代码注释 / tests / docs 中 "根 AGENTS.md '已知限制' 条目" 的
> 引用经此跳转到该文件.

## 后续工作 (非 MVP 范围)

- **更多协议**: Gemini / Ollama / Bedrock / Cohere / OpenAI Responses API.
  新增协议只需实现 Reader + Writer trait (~200 行), 不动 dispatch.
- mock_secret 的 category-aware 默认生成 (Password/ApiKey/Cookie 等格式感知).
- 配置热加载; 测试覆盖率自动上报 + fuzzing (cargo-fuzz).
- **依赖升级**: 多版本共存快照 / 归因 / 升级等待队列的 SSOT 见 **`docs/dependency-watch.md`** —
  滞后是稳态, 触发条件满足时再升; 领取 duplicate 告警或评估升级时读它.

### 已知搁置 (有意识的不做)

- **OIDC JWKS 刷新无退避/negative-cache (#198)**: `OidcBackend::exchange_and_verify`
  遇签名类验签失败时每次都重跑 discovery (对比 #196 的 ModelListCache 有 TTL +
  serve-stale + 30s 退避). 不做的原因: 登录是人工低频操作 + 重试严格有界 (只一次,
  且触发前置是 token exchange 成功, 伪造 token 无法触发放大) + 真实轮换 (月频)
  只有首个请求付代价. 若未来出现 IdP 异常期间的 discovery 压力, 再补"上次刷新
  失败后 X 秒内不重试"的单时间戳退避.
- **redact 性能优化 (Aho-Corasick 多模式匹配)**: `redact_ir` 的 `gen_mock_for_ir` 已
  做 P2-1 优化 (hybrid 延迟预拼接 IR 叶子缓存, 消除 P×L 因子, 详见 `src/redact.rs`
  `gen_mock_for_ir` 头部); `StreamingRestorer::find_safe_end` + `restore_str_inplace`
  仍对每个 mock 朴素 find+replace (K 次扫描). P2-2 曾尝试合并两者扫描 (缓存命中 mock
  列表 + restore 复用), 实测因 `restore_str_inplace` 的 `if s.contains(mock)` 预检查
  已避免无命中 mock 的 replace 开销, 而缓存命中列表需重新扫描 head (与 contains 等价)
  或 clone pair (分配开销), 净收益为负, 已回退. 真正的合并优化需要 Aho-Corasick 单次
  多模式扫描 (消除 K 因子), 当前不是瓶颈, 性能基线已建立 (`just bench`), 等真有性能
  问题再做. 详尽设计见 `benches/redact.rs` 头部.
- **`hash_block` memoize (DAG)**: `serde_json::to_string` 在 `intern` 入口每 ToolUse
  block 重算一次 (历史 message 的 block 在每次 `push_messages` 都被重新 intern).
  未 memoize 因 `IrBlock` 加 `OnceCell<BlockHash>` 破坏 derive + 跨 clone 不共享缓存
  + blast radius 大. 若 profiling 显示为瓶颈, 选项: (1) 手写 `Value` walk+hash 省
  String 分配; (2) `OnceCell` 局部缓存 + 手写 PartialEq. 见 `src/dag/pool.rs::hash_block`.
