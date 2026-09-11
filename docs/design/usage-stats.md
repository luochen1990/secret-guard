# secret-guard 模型用量统计 (Usage Stats) 功能设计

> 状态: Implemented v4 (2026-09-11 存储升级 + rounds/redact 扩展)
> 调研基线: opencode (sst/opencode@50efc05, `cli/cmd/stats.ts` + models.dev 定价),
> claude-code `/cost` `/usage` + ccusage 生态, models.dev 开源模型定价库.
> 关键约束 (用户指定): **充分利用模型回显信息, 尽量避免自己造轮子**.
> v4 变更 (2026-09-11, 人工授权 — contracts.md 变更日志同日条目): 存储层
> JSONL → **SQLite** (rusqlite bundled, WAL, writer 线程批量事务; 内存聚合 +
> 启动重放删除, summary SQL 直查 — 架构净简化); 聚合粒度 day → **hour**
> (≤14 天 hour bucket, 更长 day 折叠; `by_day` → `by_bucket` + `granularity`);
> 新增 **rounds 三态** (round_kind 列, 真值透传自 dag push 判定, retry 可见性);
> `ok: bool` → **status 原始状态码** (429/4xx/5xx 派生分类); 新增 **redact 审计**
> (redact_events 表, B 级精度: 事件明细 + mock, USAGE-7; 请求侧落账). 旧 JSONL
> 不迁移 (留在原地可手动删除). API `days` 参数 → `hours`.
> v4b 变更 (同日治理扩展): redact 审计加治理三问维度 — 位置分类 category/count
> (C 级结构化落地, `codec::ir::HitLocations`), auth 归因 api_key_label
> (AuthenticatedTenant.label), 溯源 node 关联 (悬空容忍). 红线不变: 明文与文本
> 片段永不持久化.
> v3 变更 (实施后走查, 2026-09-03): 实施中修正 — days 查询加硬上限 400
> (ROB: GET 参数防分配 abort); passthrough 降级路径 (secrets 非空 + 无 codec)
> 的 SEC model 扫描补全 (v2 遗漏); PricingCache 退避窗口补齐 serve-stale 形态;
> cache_write 缺价回退 1.25×input 登记; `-YYMMDD` 后缀不剥 (rationale 见 §7).
> v2 变更: 修正 v1 对代码库现状的两处误判 (死字段), 补采集层设计 (M0)、
> usage presence 类型、计入判据、防淘汰方案、定价匹配规则、SEC 边界修正.

## 0. 背景与定位: 为什么用量统计属于网关

secret-guard 是本地 LLM 网关, 所有工具 (opencode / claude-code / cursor / 自研脚本)
的请求都从它过手. 这带来客户端工具不具备的三个计量位势:

1. **跨工具 SSOT**: ccusage 要解析 `~/.claude` 的 JSONL, opencode-stats 要读 SQLite ——
   各家存储格式是私有实现细节, 一改就碎. 网关在 **wire 层**直接消费所有上游回显的
   `usage` 字段, 与工具存储格式零耦合.
2. **真实账单视角**: 客户端工具普遍低估 —— retry (RoundKind::Retry 的 IR 等价重发)、
   多候选、路由切换, 每次都真实消耗上游 token, 但客户端未必知道. 网关看到的就是
   "你实际付了多少".
3. **归因维度天然齐全**: 每个请求已携带 provider (upstream_id)、model、session、
   时间戳 —— 客户端工具要靠猜的归因, 网关直接有.

定位: **只做计量与展示, 不做计费/限额执行** (预算告警是 P2 可选, 限流拦截明确 Out of Scope).

## 1. 参考功能矩阵与取舍

| 功能点 | opencode stats | claude-code / ccusage | 本设计取舍 |
|---|---|---|---|
| 总量 (in/out/cache_read/cache_write) | ✅ | ✅ | ✅ P1 |
| reasoning tokens 独立维度 | ✅ | ✅ (statusline) | ⏸ P2 (需 IrUsage 扩维) |
| 成本估算 | ✅ models.dev | ✅ 内置价表 | ✅ P1, models.dev + override |
| 按 model 分解 | ✅ `--models` | ✅ | ✅ P1 |
| 按天报表 / 柱状图 | ✅ costPerDay | ✅ `daily` | ✅ P1 |
| 按 session | ✅ | ✅ | ✅ P1 (实时 DAG fold) |
| 按 project 过滤 | ✅ | — | ❌ 网关无 project 概念 (session 即粒度) |
| 5h 计费窗口 blocks | — | ✅ | ❌ 订阅制特有, API 网关无此语义 |
| toolUsage 统计 | ✅ | — | ⏸ P2 (req_delta 已有 tool_call, 可后补) |
| 中位数/单 session 均值 | ✅ | — | ⏸ P2 (有明细即易加) |
| statusline 实时条 | ✅ footer | ✅ | ❌ TUI 概念; 对应物 = WebUI 徽章 (P1 部分) |
| 热力图 / 365 天 | — (生态工具有) | ✅ | ⏸ P2+ |
| 预算告警 | — | ✅ spend limits | ⏸ P2 (WebUI 徽章, 不拦截) |

## 2. 核心原则 (对应 "避免造轮子")

- **P-1 零自造计数**: token 数据 100% 来自上游响应回显的 `usage` 字段, 经既有 codec
  reader 归一化为 `IrUsage`. 不引入 tokenizer, 不做任何本地估算 token 数.
- **P-2 零自维护价目表**: 定价 100% 复用 models.dev 开源数据库 (`api.json`,
  `$ / 1M tokens`, 含 input/output/cache_read/cache_write 四价 —— schema 由
  opencode `provider.ts:1546-1550` 消费方式佐证, M3 加快照校验测试锁定).
  secret-guard 只做拉取 + 本地缓存 + 用户 override.
- **P-3 缺失显式**: 无回显 usage 的请求 (非 2xx / parse 失败 / OpenAI 流式未开
  include_usage / 无 codec 协议 / 流式中断) 必须以 `requests_without_usage` 显式计数,
  **不得**伪装成 0 token 参与成本.
- **P-4 成本永远是估算**: 所有 cost 展示带 "estimated" 语义; 无价格匹配时显示
  "—" (null), 不显示 $0.00.
- **P-5 轻量持久 (v4 修订)**: SQLite 明细 (rusqlite bundled, 单文件 WAL) + SQL
  聚合直查, 无内存聚合双份簿记. 引入 SQLite 的触发条件 (v2 时声明过): ad-hoc
  历史查询需求 (redact 审计回查 / 小时粒度) + 免启动重放 — 交换的是
  libsqlite3-sys 一个 C 依赖, license (MIT + public domain) 过审无障碍.

## 3. 现状盘点 (v2 修正: 如实版)

| 资产 | 状态 | 说明 |
|---|---|---|
| `IrUsage` 四维归一化 (input/output/cache_read/cache_write) | ✅ 已实现 | `src/codec/ir.rs`, 各 reader 已从 wire 解析 (OpenAI `prompt_tokens_details.cached_tokens`, Anthropic `cache_*`, Responses `input_tokens` 族) |
| `IrUsage::openai_prompt_tokens` 归一化约定 | ✅ 已实现 | IR `input_tokens` 仅含未缓存部分 —— 成本公式直接可用 |
| 聚合维度字段 | ✅ 已实现 | `CallEvent`: created_at / path / ingress_protocol / model / upstream_id / upstream_model |
| **`ResponseData.usage: IrUsage`** | ⚠️ **死字段** | 定义于 `dag/types.rs:252` 但生产代码全部 5 处 `ResponseData` 构造 (fan_out.rs:184/424, cross_proto.rs:256/363, recorder.rs:293) 均 `..Default::default()`, **从未被填充/读取**. codec 已把 usage 解析进 `IrResponse.usage`, 但 proxy 从未转移 → 采集闭环是本设计的 **M0 工作量**, 不是既有资产 |
| **`ResponseData.model`** (上游回显模型) | ⚠️ **死字段** | 同上, 从未填充. 聚合键主选源需 M0 接线; 接线前 CallEvent.model (请求侧, 已实现) 是唯一现实来源 |
| usage presence ("无回显" 与 "显式零" 区分) | ❌ 不存在 | `IrResponse.usage` 非 Option, reader 对缺失 `unwrap_or_default()` → P-3 在现有类型上不可表达, 见 §5.1 |
| TTL + serve-stale + single-flight 缓存模式 | ✅ 先例 | `src/proxy/models.rs` (#196), 定价缓存照此语义各自实现 (第三处出现再抽象) |
| AppState 聚合纯数据 store 先例 | ✅ 先例 | `state.rs` → `auth::ApiKeyStore` / `proxy::ModelListCache` |
| WebUI 轮询 | ✅ 先例 | 3s sync; usage 页独立 endpoint 同节奏 |

**缺口 = 六层**: presence 类型 → 采集接线 (M0) → DTO 暴露 → 持久化 → 聚合 → 定价与展示.

## 4. 数据流设计

```
上游响应 (wire, 含回显 usage)
  │  (既有 codec reader / StreamScan, 增量: usage_present 位, §5.1)
  ▼
IrResponse { usage, usage_present, model }
  │  (M0: 统一收口 helper, §5.2 —— 5 处构造点全部接线)
  ▼
ResponseData { usage: Option<IrUsage>, model: Option<String> }
  │
  ├─ (a) DAG 实时路径: TimelineRound.usage / SessionView.usage_total ──► 徽章 (P1)
  │
  └─ (b) 持久统计路径: proxy 响应完成点 (与 attach 同点, in-scope 上下文, 不回读 DAG)
        ► UsageStore.record(UsageEvent)   # mpsc channel → 独立 writer 线程批量事务 insert
        ► (b') redact 审计路径 (v4): 请求侧 push 后立即 record_redactions
              (redact 已实际发生, 响应失败也不丢 — USAGE-7)
        ► summary 查询 = SQLite SQL GROUP BY 直查 (hour 粒度, 无内存聚合)
  ▼
GET /api/usage/summary ──► SQLite SQL 聚合 × PricingTable ──► WebUI Usage 页
```

### UsageEvent 明细行 schema (v4: SQLite `usage_events` 表, 每请求一行)

```sql
-- 列即字段; JSON 视图仅示意
-- ts: RFC3339 UTC (retention 按 ts); hour: 本地时区 'YYYY-MM-DDTHH' (聚合键,
--      day 视图 = substr(hour,1,10) 折叠; Rust 侧插入时计算, 避免 SQL 时区体操)
-- status: 原始 HTTP 状态码 (v4 替代 ok:bool; 2xx/429/其余4xx/5xx 分类在
--      summary 派生层完成 — 一列原始事实回答所有 "某类错误多不多" 的问题)
-- round_kind: 0/1/2 = Normal/Retry/NoMessages (真值透传自 dag push_messages
--      判定; retries + no_messages 独立计数, normal = requests - 两者, 派生)
{
  "ts": "2026-09-02T15:04:05.678Z",   // CallEvent.created_at
  "hour": "2026-09-02T23",             // 本地时区 (示例 TZ=UTC+8)
  "provider": "openai-main",           // upstream_id (路由解析后的链尾实体)
  "model": "gpt-5.6-terra",            // 回显 model 优先 (M0 接线后), fallback 请求 model
  "model_req": "gpt-fast",             // 请求侧 model (两者不同 = 命中别名/重写)
  "proto": "o",                        // ingress proto_short
  "status": 200,                       // 原始状态码 (v4)
  "complete": true,                    // resp_complete (流式中断 = false)
  "round_kind": 0,                     // v4 rounds 三态
  "usage": { "i": 70, "o": 10, "cr": 30, "cw": 0 }  // usage 四列 NULL ⇔ 无回显;
                                                    // cr/cw 的 None 按约定 unwrap_or(0) 落盘
                                                    // (USAGE-2 的相等断言按此语义表述)
}
```

### RedactEvent 审计行 schema (v4: `redact_events` 表, 粒度 = 每请求 × 每命中
secret × 每非零位置分类; v4b 治理三问扩展)

```jsonc
{
  "ts": "...", "hour": "...",          // 同上
  "secret_id": "github-token",         // 受控 id (config schema, 无 secret 明文)
  "mock": "sgm_...",                   // 替换值 (C5 保证 + 防御纵深扫描, USAGE-6/7)
  "category": "system",                // v4b 位置分类: system|tools|user|history|other
                                       //   (C 级结构化落地 — 只存位置不存内容;
                                       //    语义: system=提示词污染, tools=工具定义,
                                       //    user=用户输入, history=历史回显, other=边缘)
  "count": 2,                          // 该分类在本请求的出现次数 (聚合侧 SUM)
  "node": "550e8400-...",              // v4b DAG node 关联 (溯源到 mock 化原文;
                                       //   悬空容忍 — restart/淘汰后 404 降级)
  "api_key_label": "ci-runner",        // v4b auth 归因 (单用户模式 null)
  "provider": "openai-main",
  "model_req": "gpt-fast",             // 请求侧 (redact 发生在请求侧, 回显未知)
  "proto": "o"
}
```

精度级别 (用户裁决): A 纯聚合 / **B 事件明细+mock (采纳)** / C B+出现位置
(**v4b 以结构化形态落地**: category+count 列, 无文本片段).
红线: real secret 明文与上下文**文本片段**永不持久化 (片段可能含未声明的敏感
信息; 事后取证走 node 关联的内存态 record, UI 点击 recent 行 view 拉取).

治理工作流闭环: Redactions 视图发现 hits 异常 → 看 categories 判定污染环节
(system=工具配置 / tools=MCP server / user=用户粘贴 / history=前序泄露回显) →
看 api_key_label + node 定位客户端与会话 → 点击 (存活的) record 确认上下文 →
处置 (修工具 + 轮换 secret).

- **SEC 边界 (v2 修正)**: `model` / `model_req` 是**自由 wire 字符串**, 不是受控 id.
  passthrough + fail_open 场景下 secret 理论上可出现在其中 (如中转把路由 key 编码进
  model 名), 一旦发生会**持久化**到磁盘 —— 比内存 DAG 更严重. 防护: record 时对两个
  model 字符串做 active secrets 扫描 (复用 PolicySnapshot 的 contains 判定, O(secrets)
  小扫描), 命中 → 替换 `<redacted:model>` + WARN; 另截断 256 chars. 其余字段为受控
  类型 (数字 / provider id / proto 枚举), 天然无 secret.
- 文件路径: 与 state.toml 同目录派生 (`secret-guard.usage.sqlite3`, 派生规则同
  config → state 路径约定). WAL + synchronous=NORMAL + busy_timeout 5s.
  打开失败 → WARN + 降级 `:memory:` (统计可用, 明细不持久 — best-effort).
- 写失败降级: writer 线程 insert 失败 → WARN 一次 + `dropped` 计数, 查询照常
  (best-effort: 明细可丢, 进程不崩). schema 版本经 PRAGMA user_version 管理.
- retention 清理: 启动时 `DELETE WHERE ts < cutoff` (O(过期行), 非 JSONL 版全文件重写).

## 5. 采集层设计 (M0, v2 新增)

### 5.1 usage presence 类型

- `IrResponse` 增 `usage_present: bool` (wire-fidelity 元数据风格, 同 `content_form`
  先例): reader 在 wire 中**观测到** usage 对象时置 true (非流式: body 含 usage 对象;
  流式: 任一携带 usage 的事件到达). 显式全零回显 (`"usage": {全零}`) 是 present=true.
- `ResponseData.usage` 从死的非 Option `IrUsage` 改为 **`Option<IrUsage>`** (None ⇔
  无回显或无响应). 字段当前零读取点, 改型无 blast radius.
- 关联: codec 路线图 L8 (response 侧 usage 字段位置) 是既有搁置项 —— 本设计只做
  presence 位, 不做 usage 字段位置保真, 不与 L8 冲突.
- OpenAI writer 附不附 usage 字段的判定维持 `is_zero()` 现状不变 (presence 只进
  统计链路, 不进改写链路, 不触碰 FWD-2).

### 5.2 采集接线: 统一收口

- 5 处 `ResponseData` 构造点 (fan_out 流式/非流式, cross_proto ×2, same_proto
  passthrough recorder) 收口到一个 helper (如 `proxy::finalize_response`):
  填 `usage` / `model` (从 in-scope 的 `IrResponse` / StreamScan 终态转移) +
  调 `UsageStore.record`. 单一入口防止未来新增路径漏接.
- **防淘汰 (M4 评审项)**: record 使用转发任务 in-scope 的请求上下文 (created_at /
  provider / model_req / proto 在 push 前就存在于 proxy 局部), **不回读 DAG** ——
  节点被 FIFO 淘汰、甚至 `attach_response` 因 evicted 静默返回, 都不影响 usage 落账.

### 5.3 计入判据 (哪些请求进 UsageEvent) → USAGE-5

- 只记 **POST** 请求: 消耗 token 的生成调用 (chat / responses / embeddings) 全部是
  POST; GET /models 透传 (会建 DAG 节点但零 messages) 被排除; router /models 本地
  终结本就不进 DAG (#196 D5), 两类 /models 语义统一为"不计".
- embeddings 等非 chat 的 POST **计入** (其响应同样回显 usage, 计费语义正确), 在
  契约注释中显式声明.
- dispatch 前置拒绝 (404 未知 provider / 503 禁用 / 501 跨协议流式) 不产生
  UsageEvent (未发生上游转发).

### 5.4 OpenAI 流式 usage 可得性 (覆盖率预期管理)

- OpenAI 流式**默认不回显 usage**, 需客户端设 `stream_options.include_usage: true`.
  网关不得代为注入 (FWD-1: wire 唯一合法修改是 real↔mock 替换; 注入需 §0.5 人工
  授权修约, 不默认做, 列为 P2 可选开关 + 决策点).
- Anthropic 流式无此问题 (message_start / message_delta 携带 usage, reader 已解析).
- P1 缓解: ① `cost_coverage` / `requests_without_usage` 指标让缺口可见; ② WebUI
  Usage 页在 coverage 低时展示提示文案 ("OpenAI 流式请求需客户端开启
  stream_options.include_usage 才能统计 token"); ③ README/AGENTS 已知限制登记.

## 6. 聚合设计

聚合结构 (v4: SQL GROUP BY 直查, 无内存聚合 — 单一事实来源):

```sql
-- 按 (hour, provider, model) 三元组; day 视图 = substr(hour,1,10) 折叠
SELECT hour, provider, model, COUNT(*), SUM(usage_i IS NULL),
       SUM(round_kind = 1), SUM(round_kind = 2),          -- retries / no_messages
       SUM(status = 429), SUM(status BETWEEN 400 AND 499 AND status != 429),
       SUM(status >= 500),                                 -- 429 / 4xx / 5xx (v4)
       SUM(COALESCE(usage_i,0)), SUM(COALESCE(usage_o,0)),
       SUM(COALESCE(usage_cr,0)), SUM(COALESCE(usage_cw,0))
FROM usage_events WHERE hour >= ?1
GROUP BY hour, provider, model ORDER BY hour, provider, model   -- 确定性 (USAGE-3)
```

- **hour 键**: 本地时区 `YYYY-MM-DDTHH` (v4 从 day 升级; 本地工具, 用户直觉是
  "今天/这一小时"). 查询粒度自适应: 窗口 ≤14 天 (336h) hour bucket, 更长 day
  折叠 (payload 控制); 补零连续序列在 summary 派生层生成.
- **model 键**: 回显 model (M0 接线后) 优先, None 时请求 model; `model_req != model`
  的行按回显 model 归并 (它才是计费模型).
- session 级聚合**不做持久化** (SessionId 是内存实例生命周期, 跨 restart 无意义):
  session 用量 = 实时从 DAG fold TimelineRound.usage. **口径漂移声明** (UI 显式表达):
  restart 后 session 徽章从零起算、LRU (session) 淘汰后缩水, 而持久账本累计 —— 两套数字
  语义不同 (session 徽章 = "本次进程内该会话的已渲染轮次", Usage 页 = "持久账本"),
  Usage 页脚注说明.

## 7. 定价设计 (models.dev)

- 数据源: `https://models.dev/api.json` (单文件全量, MIT).
- 缓存: 照抄 #196 ModelListCache 语义 —— 惰性首拉 (首个 usage 查询触发, 不阻塞启动),
  TTL 24h (可配), serve-stale-on-error, 失败退避 30s, single-flight; 成功后写
  `secret-guard.pricing.json` 作离线冷启动兜底.
- **冷启动行为**: 首拉完成前所有 cost = null, 响应携带
  `pricing_status: "loading" | "ok" | "stale" | "offline"`, UI 显示价目表状态;
  并发查询经 single-flight 等待首个结果 (超时 5s 按 offline 返回, 不阻塞).
- **匹配规则** (v2 成文, #202 修订碰撞语义):
  1. 用户 override 全名精确匹配 (键 = 聚合用 model 字符串本身) —— 最高优先;
  2. models.dev `model_id` 精确匹配: 唯一命中 → 取; 多 vendor 同名 → 域名启发
     消歧 —— hint host 的 vendor 集与候选集**交集非空则收缩到交集** (用户
     provider 就部署在该 host 上, 交集外是别家 host 的 vendor), 空 = 无信号,
     不收缩、全池落偏好序; 收缩后在池内按**确定性偏好序**取第一: 无 `-plan` 段
     (套餐/订阅系 vendor) > 名字短 > 字母序. 同 host 多 vendor 碰撞 (如
     open.bigmodel.cn 上 `zhipuai` 与 `zhipuai-coding-plan`) 全部保留候选,
     **不依赖上游 JSON 键序** (#202: 单值 last-wins 曾让套餐 vendor 静默胜出,
     cost 恒 0 且 coverage=1.0). 偏好序是**启发式策略而非正确性保证** (命名漂移
     可击穿, 如不含 plan 段的订阅系命名), 被击穿时零价结果由 `zero_priced_models`
     显式暴露 (见 §8), 用户可用 `pricing_override` 一锤定音;
  3. 剥日期后缀 (`-YYYY-MM-DD$`, 11 chars) 后重复步骤 2
     (`gpt-5.6-terra-2026-07-09` → `gpt-5.6-terra`). 注: `-YYMMDD` 形态
     (如 anthropic 的 `claude-3-5-sonnet-20240620`) 不剥 — 该 dated 形态本身通常
     就是 models.dev 的 model_id, 剥了反而匹配不到;
  4. 均失败 → cost null, 计入 `unpriced_models` 清单 (UI 提示配 override).
- 成本公式 (opencode 语义; IR 归一化后 `input_tokens` 恰为未缓存部分):
  `cost = i×in + cr×cache_read + cw×cache_write + o×out  (÷1M)`
- 缺价字段回退 (P-2 的宽松近似, **有值时永远用真实值**): models.dev 未列
  `cache_read` → 按 `input` 价; 未列 `cache_write` → 按 1.25×`input`
  (Anthropic 质量型写入加价的惯例近似).
- **快照语义决策**: 明细行不存 cost, 查询时按**当前**价目表实时重算. 理由: 价目表
  更新后历史估算随之修正 (本地工具更关心 "现在算要多少钱"), 明细行最小. 代价:
  历史数字随价目表漂移 —— UI 明示 "以当前价目表估算".
- M3 加 models.dev schema 快照校验测试 (字段缺失/改名 → WARN, 不静默丢价).

## 8. API 设计

```
GET /api/usage/summary?hours=168     # hours=0 → 1, 缺省 168 (7d); 上限 = min(retention_days×24, 9600)
→ {
    "range": { "from": "...", "to": "...", "hours": 168, "granularity": "hour" },
                                     // ≤336h hour bucket ('YYYY-MM-DDTHH'), 更长 day 折叠
    "pricing_status": "ok",
    "totals": {
      "requests": 412, "requests_without_usage": 3,
      "retries": 37, "no_messages": 2,        // v4 rounds 三态 (normal = requests - 两者, 派生)
      "rate_limited_429": 12,                 // v4 status 原始码派生分类
      "errors_4xx": 1, "errors_5xx": 3,
      "input": 8_112_334, "output": 210_998,
      "cache_read": 5_004_112, "cache_write": 91_200,
      "cache_hit_rate": 0.86,                 // cr / (i + cr + cw); cache_write 计入
                                                // 分母 (它也是 input 的一部分), 口径注明
      "est_cost_usd": 12.41,                  // 仅含有价行
      "cost_coverage": 0.97                    // 有价且有 usage 请求占比 (P-4 可观测)
    },
    "by_bucket":  [ { "bucket": "2026-09-11T14", ...UsageAgg, "est_cost_usd": ... }, ... ],
    "by_model":   [ { "model": "...", "provider": "...", ...UsageAgg, "est_cost_usd": ... }, ... ],
    "by_provider":[ { "provider": "...", ...UsageAgg, "est_cost_usd": ... }, ... ],
    "unpriced_models": ["my-relay/gpt-fork"],
    "zero_priced_models": ["glm-5.3"],       // 有价但四价全零 (免费档/套餐 vendor,
                                              // 含 override 显式置零); 与 unpriced 分开
                                              // 显式, 防 cost=0 + coverage=1.0 掩盖 (#202)
    "redactions": {                           // v4b 审计视图 (USAGE-7 治理三问), 与 usage 同窗口
      "by_secret": [ { "secret_id": "...", "mock": "...", "hits": 42,
                       "categories": { "system": 30, "user": 12 },   // 位置分布
                       "first_ts": "...", "last_ts": "..." }, ... ],
      "recent":     [ { "ts": "...", "secret_id": "...", "mock": "...", "category": "system",
                         "count": 1, "node": "550e...", "api_key_label": null,
                         "provider": "...", "model_req": "...", "proto": "o" }, ... ]  // ≤100
    }
  }
```

- by_model / by_provider 按 est_cost 降序 (null 视为最小).
- **DTO 载体 (v2 修正)**: timeline 徽章 → `TimelineRound` 增 `usage` (非 NodeView —
  timeline 走 TimelineDiffData); session 徽章 → `SessionView` 增 `usage_total`;
  `RoundBrief` 不加 (sidebar 三级菜单保持轻量). 均走既有 3s sync.
- Usage 页独立轮询: 仅 tab 激活时, 5s 间隔 (summary 载荷比 sync diff 重), range 参数
  前端缓存.

## 9. WebUI 设计

1. **Usage 页** (顶部导航新 tab):
   - 时间范围切换 (24h / 7d / 30d / All = retention 全域);
   - 汇总卡片行: Requests · Input · Output · Cache Read · Cache Write · Cache Hit % ·
     Est. Cost ("~$12.41" 样式, 恒带 "~"; coverage < 100% 角标; pricing_status ≠ ok
     时显示价目表状态); coverage 低 + OpenAI provider 存在时展示 include_usage 提示;
   - 堆叠柱状图 (in / cache_read / cache_write / out 四段): 粒度随窗口自适应
     (≤14d 按小时, 更长按天; 阈值 HOURLY_MAX_HOURS = 336), 纯 SVG/CSS, 不引入
     图表库 (index.html 无构建链, 保持零依赖);
   - By Model 表 (provider 列 / reqs / 四维 token / ~cost / 占比%) + By Provider 表;
   - 页脚: 口径说明 (估算语义 / session 徽章与持久账本口径差异).
2. **timeline round 徽章**: 每轮头部 `70 in / 10 out` (hover title 展开 cache 细分);
   retry 轮正常显示 (网关视角: 重试也是钱).
3. **session header 徽章**: session 标题旁 `Σ 8.1k in / 2.1k out` (进程内口径, 见 §6).

## 10. 配置设计 (static `[usage]` 段, 启动读一次, 同 `[redact]/[auth]` 模式)

| 字段 | 默认 | 说明 |
|---|---|---|
| `enabled` | `true` | 总开关; false 时不采集不落盘 (零开销). 改动需 restart (static 语义, 注明). |
| `pricing_url` | models.dev api.json | 定价源, 可指向自托管镜像. |
| `pricing_refresh_secs` | `86400` | TTL. |
| `retention_days` | `90` | 明细保留天数; 0 = 永久. 启动时清理. |
| `pricing_override` | 空 | `model → {input, output, cache_read, cache_write}` ($/1M). |

## 11. 契约 (新增 `USAGE-*` 域, 挂入 contracts.md)

- **USAGE-1 聚合一致性 (hour 粒度 + rounds 三态)**: ∀窗口. `summary.totals` ==
  窗口内明细行 fold; `by_bucket` / `by_model` / `by_provider` 各自分项之和 == totals;
  `requests == Σ(normal + retry + no_messages)` (完整 SSOT 见 contracts.md USAGE-1).
- **USAGE-2 回显保真**: 存储的 usage == 上游回显经 codec 归一化值 (cr/cw 的 None 按
  `unwrap_or(0)` 语义落盘); presence 位忠实反映 "wire 是否观测到 usage"
  (property: 对 codec round-trip fixture, UsageEvent == (ResponseData.usage, in-scope
  上下文) 的纯函数).
- **USAGE-3 成本纯函数与可复算**: cost(event, price) 确定性纯函数; 同明细 + 同价目表
  ⇒ 同 cost; 无价 ⇒ None. proptest: 逐行算再求和 == fold 后再算 (线性性).
- **USAGE-4 缺失显式**: `requests == Σ(usage 非空行) + requests_without_usage`;
  usage 为空的行对 token / cost 贡献恒为 0.
- **USAGE-5 计入判据 + status 原始事实**: 仅 POST 且实际发生上游转发的请求产生
  UsageEvent; GET /models (透传与本地终结) / dispatch 前置拒绝不产生; status 存原始
  状态码 (429/4xx/5xx 派生分类).
- **SEC 关联**: UsageEvent 序列化前过 model 字符串 secret 扫描 (§4); pricing 缓存与
  JSONL 无 body 内容 —— 入 SEC-* 走查清单.

## 12. 已知限制 (诚实清单)

- **OpenAI 流式未开 `include_usage` 的请求无 token 数** (§5.4): 只计请求数. 这是 P1
  最大的覆盖率缺口, 靠 cost_coverage 指标 + UI 提示管理预期.
- **无回显 usage 的请求无 token 数**: 非 2xx / codec parse 失败 / 流式中断 / 网络错误
  (P-3).
- **Gemini / Ollama (无 codec, passthrough) 完全无 usage**: P1 不支持;
  P2 可做 "仅 usage 字段" 浅提取 (Gemini `usageMetadata` / Ollama `prompt_eval_count`),
  不建全 codec —— "利用回显" 的低成本延伸.
- **reasoning tokens 未建模**: OpenAI `completion_tokens_details.reasoning_tokens` /
  Responses `output_tokens_details.reasoning_tokens` 回显目前被丢弃 (计入 output 总数,
  不单列). P2 扩 `IrUsage.reasoning_output: Option<u64>`.
- **cost 是估算**: models.dev 价格 ≠ 实际合同价; 无价模型显示 "—".
- **历史 cost 随价目表漂移** (§7 快照语义).
- **restart 时在途请求丢失** (append 在响应完成点); 写失败降级丢明细 (§4).
- **shutdown 时 channel 尾批可能丢失** (v4): writer 线程批量 insert, 进程退出时
  已 record 但未落库的事件 (≤ 批量上限 64 条 + 在途批) 随 detached 线程蒸发;
  channel 关闭时 drain-then-exit 兜底大部分, 无 fsync-on-shutdown 钩子 (本地工具
  可接受; JSONL 版逐行 flush 的耐久粒度更细).
- **session 徽章与持久账本口径不同** (§6): 前者进程内, 后者持久.
- **多实例并发写同一 SQLite 未设计** (单用户本地工具假设, 与 #157 TOCTOU 声明同型).

## 13. 里程碑 (v2: 增 M0, 补文档同步义务)

| 批次 | 内容 | 验证 |
|---|---|---|
| **M0 采集闭环** | `usage_present` 位 + `ResponseData.usage/model` 改型接线 + 5 构造点收口 helper (含 record 挂钩) + 计入判据过滤 | USAGE-2/5 单测 + codec fixture 回归 |
| M1 暴露与徽章 | TimelineRound.usage / SessionView.usage_total + timeline / session 徽章 | 单测 + im-ui Playwright |
| M2 持久化与聚合 | `src/usage/` (store + agg + JSONL + mpsc writer) + AppState 挂载 | USAGE-1/4 proptest |
| M3 定价与 API | usage/pricing.rs (models.dev 缓存 + 匹配 + override + schema 快照测试) + `/api/usage/summary` | USAGE-3 proptest + mockito |
| M4 Usage 页 | WebUI tab + SVG 柱状图 + 表格 | Playwright |
| 文档同步 (随各批次) | url-layout.md §`/api/*` 表 · web/AGENTS.md endpoint 表 · 根 AGENTS.md 配置表+依赖图+模块概览 · docs/configuration.md · contracts.md USAGE-* 域 · config.rs 预检审计 (#159) | check-contracts lint |
| P2 | api-key 归因 / reasoning 维度 / Gemini+Ollama 浅提取 / 导出 (JSONL download) / 预算徽章 / include_usage 注入开关 (需 FWD-1 修约决策) | — |

## 14. 开放问题 (默认已选, 用户可推翻)

1. day 键时区 = 本地 (非 UTC) —— 已选本地.
2. cost 快照语义 = 实时重算 (明细不存 cost) —— 已选实时 (§7).
3. retention 默认 90 天 —— 已选.
4. OpenAI 流式 include_usage **不注入** (FWD-1 未修约) —— 已选不注入 + coverage 可见;
   若实际使用中 OpenAI 流式占比高导致覆盖率不可接受, 再提请修约.
5. per-api-key 归因 (auth 启用时按 key 分账) —— P2; 需在 CallEvent 增 key 标识.
6. 实施前建议对本 v2 再走查一轮 (v1 评审暴露过现状误判), 特别是 M0 的 5 处构造点
   收口与 presence 语义在 StreamScan 上的落点.
