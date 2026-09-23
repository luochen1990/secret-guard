# Conversation DAG 设计文档

> Status: **已落地** (核心步骤 1-9 完成, 2026-07-24; 见下方"实施期演进说明")
> Scope: RecordStore → ConversationDag 重构 + lazy redact pipeline

> ## ⚠️ 实施期演进说明 (2026-07-24 增补)
>
> 本文档是**设计决策的历史快照**, 写于重构启动时. 实施过程中若干细节已演进,
> 与下方描述存在偏差. 阅读时以代码 (`src/dag/mod.rs`) 为准; 下表列出关键偏差:
>
> | 主题 | 文档描述 | 实际实施 |
> |---|---|---|
> | API 名 | `push_from_ir` (第 5 节受影响面 / 第 6 节步骤 6) | 命名为 `push_messages` |
> | 数据结构 | `struct ConversationDag { nodes, prefix_index, order, max, blocks }` (第 3 节) | 外层包 `Arc<RwLock<DagInner>>`, 新增 `sessions` 表 + `max_sessions` + `min_sessions`; **`order` 字段移除**, 改用 `sessions.leaf_id` + LRU |
> | 淘汰策略 | FIFO (第 7 节, 假设单会话线性) | 进化为 **LRU session 淘汰 + child_count 级联 GC** (leaf 先删, 递减 parent, 级联到 child_count=0) |
> | 实施进度 | "步骤 5-10 是后续 PR 范围" (第 6 节) | 核心已全量落地 (步骤 1-9 完成, proxy/web/codec 全部接入), 仅 "完整 lazy redact 重建" (步骤 5 的 derive_redact_map 含 system/tools) 待定 |
> | timeline 数据源 | 第 6 节步骤 5 注: "timeline 用 push 时预存 req_body_raw 截取 delta" | B1 起 req_delta_messages 从 BlockPool 派生 (MessageRef resolve → redactions 投影重建 real→mock 替换 → ingress writer, 与旧 raw 切片逐字节等价, contracts.md DTO-5), tail 从 `response.message` + 元字段派生; `req_body_raw` / `raw_resp_body` 仅详细日志开关 audit_capture on 时保留 (B2, 默认 off 存空串 — CFG-7/DTO-10), 不再是 timeline 的内容数据源 (`tail.length` 末级 fallback 除外 — parsed 缺失时读 `raw_resp_body.len()`) |
> | migration 提示 | "config schema ... 需 migration 提示" (第 5 节) | **未实现** TODO: sticky 字段删除未提供运行时 migration 提示, 静默忽略未知字段 |
>
> 下文保留原始设计叙述 (历史价值). 上述偏差点在正文中以 `📌` 内联标注.

## 1. 动机

当前 RecordStore 是扁平的 `VecDeque<ForwardRecord>`, 每条 record 完整存储 req_body /
resp_body / resp_parsed. opencode agent 的一次会话产生 N 条 record (实测 44 条), 它们的
messages 高度重叠 (每次请求都带完整历史), 导致:

- **存储冗余**: 37KB system prompt 被存 44 份
- **WebUI 体验差**: sidebar 列出 44 条几乎相同的记录, 无法识别它们属于同一会话

实证 (100 条真实 record dump):
- 首条 user msg 的 hash 作为 session_key: 100 条 → 7 组, 零误判
- 组内 100% 是严格前缀关系 (线性链), 暂无 fork
- 折叠后 sidebar 项数 100 → 7, 减少 93%

## 2. 核心概念

### 2.1 OriginRecord vs SecureRecord

```
OriginRecord (真实)               SecureRecord (脱敏)
  │                                  │
  │  apply redactMap  ─────────────► │  (发给 LLM)
  │  restore redactMap ◄───────────── │  (LLM 返回)
  │                                  │
  │  apply redactMap  ─────────────► │  (发给 WebUI)
```

- **OriginRecord**: 含真实 secret 的对话内容. 永远只在内存中 (DAG 节点持有).
- **SecureRecord**: secret 被替换为 mock 的脱敏视图. 永远是输出 (给 LLM client / WebUI).
- **redactMap**: Origin ↔ Secure 的双向转换器. 由 `(policy, OriginRecord, seed)` 纯函数派生,
  不作为数据持久化.

### 2.2 record = DAG 节点

一次 API 调用就是对话链上的一个节点:

```
sys ← u1 ← [a1(t1)] ← u2 ← [a2(t2)] ← u3
       Node0  Node1    Node2   Node3
```

- **Node0**: req_delta = `[sys, u1]` (客户端发出的 request 中相对 parent 的增量;
  parent=None 所以全部是 delta)
- **Node1**: req_delta = `[a1, t1]` (a1 是 agent 从 Node0 的 response 复制进 req 的,
  t1 是 client 执行 tool 得到的结果; 都属于客户端发出的 request 内容)

**response 存 LLM 原始返回** (含 mock, 未 restore):
- Node.response = LLM 这次返回的原始内容 (LLM 视角, 含 mock secret)
- restore (mock → real) 是 lazy 的, 只在 proxy → client 实时转发路径上做, **不在 DAG 存储路径上**
- response 独立于 req_delta, 遵循"忠实于原始数据"原则: LLM 返回什么就存什么
- WebUI 读 response 时原样展示 (LLM 视角); 读 req_delta 时 apply redactMap 转 mock (LLM 视角). 两边一致, 审计语义 = "LLM 实际看到了什么"
- 冗余通过 BlockPool 内容寻址自然消化 (相同 block 物理共享, 不同则各自存储, bug 可见)

**DAG 拓扑完全由 req_delta 决定**, response 不参与 parent 查找 / prefix_hash.

### 2.3 内容寻址 + Merkle prefix hash

每个 node 的 identity = `hash(parent.prefix_hash, own_msgs)`.

- **own_hash**: node 自身 msgs 的 hash (不含祖先)
- **prefix_hash**: 从根到本 node 的累积 hash, `hash(parent.prefix_hash 或 0, own_hash)`

新 record 到达时, 计算 messages 的前缀 hash 序列, 查 HashMap 找到最深匹配, 即为 parent:

```
new messages = [m1..mN]
cum[0] = hash(0, h(m1))
cum[k] = hash(cum[k-1], h(m_{k+1}))
倒序查 prefix_index: 找到最大 i 使 cum[i-1] 命中 → parent = matched node, delta = msgs[i..]
```

复杂度 O(N), N = messages 数量, 实测最大 ~352, < 1ms.

### 2.4 Block 池 (内容寻址)

IrBlock 内容寻址入全局池, node 持 BlockHash 引用:

- system prompt (37KB) 跨 50 个 node 只存 1 份
- tool_use input JSON, tool_result content 跨节点共享
- 引用计数 (refcount), FIFO 淘汰 node 时递减, refcount=0 时删 block

### 2.5 lazy redact

node 存 OriginRecord (真实 messages, redact 前). redact 在请求路径上 eager 做, 但:

- node 不存 redactMap, 只存 **redact_seed: u64** (无 Option, 0 表示 passthrough)
- redactMap = derive(policy, OriginRecord, seed), 纯函数, 用完即弃
- WebUI 读取时按需重建 redactMap, apply 到 OriginRecord 得 SecureRecord

### 2.6 C3 契约修正

当前 C3 描述的是实现细节 (per-secret 候选序列稳定性), 泄露了抽象. C3 的本质是经济性契约:

> **C3 前缀缓存友好性**: redact 不应无必要地改变 request body 的字节内容,
> 避免破坏 LLM Provider 侧的前缀缓存命中, 进而增加用户的 token 费用负担.

前缀缓存是 byte-exact 的: 若历史 message 中的 mock 字节变化 (即便只改一个 secret 的 mock),
从该 message 起的整个前缀缓存失效. 多轮对话中前缀很长, 这种失效代价巨大.
因此 mock 的稳定性 (同一 secret 在会话中保持同一 mock) 直接保护缓存命中.

实现手段 (deterministic_seed 的确定性) 保证同一 (real, strategy) 总产生同一候选序列,
这是 C3 的根基, 不随 seed 继承策略变化.

### 2.7 删除 sticky=false

`sticky=false` (每次请求用随机 seed, 候选序列每次不同) **直接违反 C3** (mock 每轮都变,
前缀缓存完全失效). 其声称的收益 ("防 LLM 关联多次请求") 不在 secret-guard 的威胁模型内
(MVP 防的是 secret 泄漏, 不是关联). 因此删除 sticky 维度, 只保留确定性路径.

影响: `MockStrategy.sticky` 字段删除, mock.rs / redact.rs / secrets.rs / config schema /
WebUI 编辑表单相应简化.

### 2.8 seed 语义与继承策略

**seed 链**: `seed → next(seed) → next(next(seed)) → ...`, next() 是纯函数.

**prepare_checker**: 给定 secrets 集合, `seed -> (full_context -> bool)` 检测该 seed 产生的
redactMap 中是否有 mock 出现在 full_context 中 (C2 in-context uniqueness).

**init seed**: `deterministic_seed(real, strategy)`, 只依赖 secret 本身, 与请求无关.
保证同一 secret 在任何会话中候选序列相同 (C3 契约的根基).

**probe 过程**: 从起始 seed 开始, 逐次 check, 选用首个通过的 seed.

**seed 继承策略** (纯性能优化):
- child 继承 parent node 的 seed 作为首次尝试, 而非从 init 重新开始.
- 单调性保证: `child.full_context ⊇ parent.full_context`, 故 parent 中失败的 seed 在 child
  中必然也失败. 从 init 重新 probe 会重复走 parent 已走过的失败路径.
- 继承直接跳过这些已失败的 seed, 平均情况 child probe 零次.
- **最终选中的 seed 与从 init 开始大概率相同** (单调性: parent 通过的 seed 在 child 中大概率
  仍通过), 所以继承策略不影响 C3 (mock 稳定性), 只影响 probe 的 CPU 成本.
- 增量 check (与继承正交): parent.seed 已保证 mock 不在 parent.full_context,
  child 只需扫描增量部分 (child.context - parent.context).

**policy 快照** (Arc COW):
- SecretTable 维护 `Arc<PolicySnapshot>`, push node 时取 Arc 引用存 node
- 用户编辑 secret 时, SecretTable 替换 Arc 指向新版本 (COW), 老版本仍被历史 node 引用
- WebUI 读取时用 node 持有的 policy Arc + redact_seed 重建当时的 redactMap
- FIFO 淘汰 node 时, 老 PolicySnapshot 引用计数归零自动释放

## 3. 数据结构

```rust
// 内容寻址的 IrBlock 池 (全局共享)
struct BlockPool {
    blocks: HashMap<BlockHash, Arc<IrBlock>>,
    refcount: HashMap<BlockHash, usize>,
}

// 内容寻址的 message (role + block 引用列表)
struct MessageRef {
    role: IrRole,
    blocks: Vec<BlockHash>,
}

// DAG 节点 = 一次 API 调用
struct Node {
    id: Uuid,
    parent: Option<Uuid>,
    // 客户端发出的 request 中, 相对 parent 的增量 (OriginRecord, 真实内容)
    // 不含 response — response 独立存储 (忠实于原始数据原则)
    req_delta: Arc<[MessageRef]>,
    own_hash: u64,
    prefix_hash: u64,             // 只基于 req_delta 累积
    event: CallEvent,
    response: RwLock<Option<ResponseData>>,  // LLM 返回, 独立存储
}

// LLM 返回的 response 数据 (message content + 元数据)
struct ResponseData {
    message: Option<MessageRef>,  // assistant message (intern 到 BlockPool)
    usage: IrUsage,
    stop_reason: Option<IrStopReason>,
    stop_sequence: Option<String>,
    id: Option<String>,
    created: Option<u64>,
    model: Option<String>,
    raw_resp_body: String,        // 原始上游 JSON (审计/调试)
    streamed: bool,
    resp_complete: bool,
    error: Option<String>,
    redactions: Vec<(String, String)>, // (mock, secret_id) 投影, WebUI 用
}

struct CallEvent {
    created_at: DateTime<Utc>,
    method: String,
    path: String,
    req_headers: Vec<(String, String)>,
    redact_seed: u64,               // 重建 redactMap 用 (0 = passthrough)
    policy: Arc<PolicySnapshot>,    // 重建 redactMap 用
    req_envelope: serde_json::Value, // 请求侧非 message 字段
    ingress_protocol: Option<codec::Protocol>,
    req_body_raw: String,           // LLM 视角的请求 body 快照 (📌 B2 起 audit_capture off 存空串; timeline 数据源已由 BlockPool 派生取代, 见顶部偏差表)
    preview: Option<Arc<str>>,      // 首条 user msg 截断, list 路径 Arc::clone 免拷贝
    model: Option<Arc<str>>,        // 顶层 model 字段, list 路径 Arc::clone 免拷贝
    redactions: Arc<[(String, String)]>, // (mock, secret_id) 投影, list 路径免拷贝
}

// 注: 响应侧元数据 (resp_status / resp_headers / elapsed_ms) 只存于 ResponseData 的
// RwLock 内 — 这是两级锁 (perf) 的前提: attach_response / update_parsed_response
// 持外层 inner.read() + 内层 node.response.write(), 不再串行化在全局 write lock 上.
// 旧 CallEvent 的这 3 个镜像字段已删除 (SSOT).
// 📌 实施演进: 实际为 ConversationDag { inner: Arc<RwLock<DagInner>> },
//    DagInner 含 nodes/prefix_index/blocks/sessions/max_nodes/max_sessions/min_sessions,
//    无 `order` 字段 (改用 sessions.leaf_id + LRU). 见顶部"实施期演进说明".
struct ConversationDag {
    nodes: HashMap<Uuid, Node>,
    prefix_index: HashMap<u64, Vec<Uuid>>,
    order: VecDeque<Uuid>,
    max: usize,
    blocks: BlockPool,
}
```

## 4. 关键不变式

1. **req_delta 与 response 独立**: request 内容 (客户端发出) 和 response 内容 (LLM 返回)
   是两份独立数据源, 独立存储, 不捏造等式 (忠实于原始数据原则).
2. **Merkle prefix_hash 只基于 req_delta**: response 不参与 parent 查找.
3. **Block refcount 一致**: intern block 时 refcount++, 淘汰 node 时按 req_delta + response
   message 分别递减.
4. **OriginRecord 不可变**: node.req_delta 入 DAG 后永不修改.
5. **redact_seed 可重现**: 给定 (node.req_delta 真实内容, node.policy, node.redact_seed),
   redactMap 完全确定. seed=0 表示 passthrough (无 secret 命中).

## 5. 受影响面

| 模块 | 变更 |
|---|---|
| record.rs | **重写**: ForwardRecord/RecordStore → Node/ConversationDag |
| redact.rs | redact_ir 演化为返回 seed; 保留 restore 路径; RedactionMap 仍存在但临时; C3 契约重述为前缀缓存友好性 |
| mock.rs | **删除 sticky 字段** (sticky=false 违反 C3); 只保留 deterministic 路径 |
| secrets.rs | SecretEntry 删除 mock_strategy.sticky 相关字段 + resolve 逻辑 |
| config schema | toml 中 mock_strategy 不再支持 sticky 字段 (向后不兼容, 需 migration 提示) 📌 |
| proxy.rs | push_from_ir / attach_response 取代 push/update 📌 实际命名为 `push_messages` |
| codec/stream (现 `stream/scan.rs`) | StreamScan snapshot → attach 到 node |
| web/api/{records,sessions}.rs | list 派生 RecordSummary (walk DAG); get_record 按需重建 |
| web/index.html | secret 编辑表单删除 sticky 选项 |
| config.rs | **不动** (records 纯内存, 不持久化) |
| AGENTS.md | 更新 record/redact/mock 相关段落; 新增"忠实于原始数据"原则 |

## 6. 实施顺序

1. BlockPool + MessageRef ✅
2. Node + ConversationDag (push 算法 + full_request_messages walk + FIFO GC) ✅
3. 删除 sticky=false (mock.rs + redact.rs + secrets.rs + config + WebUI) ✅
4. C3 契约重述 (redact.rs 头部注释) ✅
5. lazy redact pipeline (redact_seed 注入 + seed 继承)
6. proxy.rs 适配
7. web/api (records/sessions) 适配
8. codec/stream.rs 适配
9. 测试 (单元 + 集成 + WebUI Playwright)
10. 文档 (AGENTS.md)

> 步骤 1-4 在 PR #15 完成 (DAG 核心模块 + sticky 删除 + C3 重述).
> 步骤 5-10 是后续 PR 范围 (完整 DAG 接入).
>
> 📌 实施演进 (2026-07-24): 步骤 6-9 已全量落地 (proxy/web/codec 全部接入 DAG),
> 仅步骤 5 "完整 lazy redact 重建" 待定.
> 📌 实施演进 (2026-09-24, B1/B2): timeline 数据源已切换 — req_delta_messages 从
> BlockPool 派生 (redactions 投影重建 + ingress writer, 见顶部偏差表), 不再从
> req_body_raw 切片; req_body_raw 仅详细日志 (audit_capture) on 时保留.

## 7. 已知限制: 孤儿节点 (FIFO 淘汰 parent)

> 📌 实施演进: 本节描述的 FIFO 策略已被 **LRU session 淘汰 + child_count 级联 GC**
> 取代, 多会话交替 push 的孤儿风险已缓解. 本节保留作历史背景. 见顶部"实施期演进说明".

当前 FIFO 淘汰策略假设单会话线性使用: 引用者 (child) 永远后于被引用者 (parent) 被 push,
所以 FIFO 淘汰顺序天然安全 (parent 先于 child 被淘汰).

**多会话并发场景的风险**: 若两个独立会话交替 push (A1, B1, A2, B2, ...), FIFO 可能先淘汰 A1,
而 A2 的 parent 是 A1 → A2 的 parent 链断裂 → `full_request_messages(A2)` 返回 None
(`collect_req_delta_refs` 用 `?` 传播). A2 变为 "孤儿节点": 仍在 `nodes` / `order` 中,
WebUI list 会显示, 但无法展开完整 request messages.

**缓解**: 后续接入 WebUI 时, 应在 `NodeView` 增加 `is_orphan: bool` (检查 parent 链完整性),
让 WebUI 标注 "context lost" 或跳过. 当前 MVP 不处理, 因 opencode agent 的典型使用模式是
单会话线性 (实测 100 条 record 全部是严格前缀链).
