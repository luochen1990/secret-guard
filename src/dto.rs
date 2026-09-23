//! WebUI 响应序列化的 DTO 类型 (域 B → 域 C 的 wire shape).
//!
//! # 职责边界
//!
//! 本模块定义 Web API 响应 (`/api/sessions`, `/api/sessions/{sid}/timeline`,
//! `POST /api/sync`) 的 JSON 形态. 这些类型是 **域 B (派生链) → 域 C (渲染层)** 的
//! wire shape: 从 DAG 读取数据后构造, 序列化为前端消费的 JSON.
//!
//! # 为什么是顶层中立模块 (不在 web 也不在 dag)
//!
//! 历史上这些 DTO 先定义在 `crate::dag` (#95 前的 dag.rs), 后移到 `crate::web::dto`
//! (#95), 两次落点都不理想: 前者让存储层耦合 wire shape (违反单一职责), 后者让 dag
//! (域 B) 反向依赖 web (域 C) 展示层路径 — 违反 "域 A → 域 B → 域 C 单向承诺"
//! (见 AGENTS.md 模块依赖方向图). 移到顶层中立模块后, dag 与 web 各自**单向**依赖
//! 本模块, dag 可脱离 web 单独抽出 (dag 是内容寻址通用件, 是最可能被复用的模块之一).
//!
//! # 构造方法留 dag 模块 (不在本模块)
//!
//! 这些 DTO 的**构造逻辑** (从 DAG 内部字段填充) 仍保留在 `dag` 模块的方法 / free
//! function 中 (`node_view` / `session_view` / `build_timeline_round` 等), 因为它们需
//! 持 `DagInner` 读锁访问私有字段 (`Node.event` / `Node.response` / `Session` 等).
//! 移到独立模块会要求暴露 DAG 内部结构, 代价超过收益. 本模块只承载哑数据载体
//! (无行为, 非 web::api 展示层 handler), dag 依赖它是向下的类型层依赖.
//!
//! # 与 `record::ForwardRecord` 的分工
//!
//! [`crate::record::ForwardRecord`] 是另一个 web 层 DTO (GET /records/{id} 响应),
//! 历史上独立维护 "维持 Web API JSON shape 稳定" 的职责. 本模块的 9 个 DTO 与之同源
//! (都是 web 层 wire shape), 仅按 endpoint 分文件: 本模块服务 sessions/timeline/sync,
//! record.rs 服务 records 单条详情. (record.rs 留在顶层是历史落点, 与本模块平级.)

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::codec::ir::{IrRole, IrUsage};
use crate::dag::{RoundKind, SessionId};

/// token 用量的 wire 视图 (usage-stats, docs/design/usage-stats.md).
///
/// 四维与 [`IrUsage`] 一致; cache 两维的 `None` (上游未上报该维度) 按
/// `unwrap_or(0)` 归一 (USAGE-2 相等断言按此语义表述). 纯数字, 天然无 secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct UsageView {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

impl UsageView {
    pub fn from_ir(u: &IrUsage) -> Self {
        Self {
            input: u.input_tokens,
            output: u.output_tokens,
            cache_read: u.cache_read_input_tokens.unwrap_or(0),
            cache_write: u.cache_creation_input_tokens.unwrap_or(0),
        }
    }

    /// 饱和加 (session 总量折叠用).
    pub fn saturating_add(self, other: Self) -> Self {
        Self {
            input: self.input.saturating_add(other.input),
            output: self.output.saturating_add(other.output),
            cache_read: self.cache_read.saturating_add(other.cache_read),
            cache_write: self.cache_write.saturating_add(other.cache_write),
        }
    }
}

/// 会话视图 (sidebar 一级树).
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionView {
    /// 会话稳定标识 (前端选中/展开用, 刷新后不变).
    pub session_id: SessionId,
    /// 叶子节点 id (会话最新一轮). timeline 请求起点.
    pub leaf_id: Uuid,
    /// 根节点 id (会话第一轮 或 fork 点).
    pub root_id: Uuid,
    /// 会话内轮次数 (push 时增量维护, 无需走 parent 链).
    pub record_count: usize,
    /// 会话开始时间 (根节点 created_at).
    pub created_at: DateTime<Utc>,
    /// 最新活动时间 (叶子节点 created_at, LRU 淘汰用).
    pub latest_at: DateTime<Utc>,
    /// preview (叶子节点的最后一条 user msg 截断).
    ///
    /// `Arc<str>`: list_sessions (3s 轮询) 路径共享切片而非 clone 字符串.
    /// serde 透明序列化为 string, 前端无感知.
    pub preview: Option<Arc<str>>,
    /// model (叶子节点). `Arc<str>` 同上.
    pub model: Option<Arc<str>>,
    /// 最新轮次的上游响应状态.
    pub latest_resp_status: u16,
    /// 最新轮次的错误 (若有).
    pub latest_error: Option<String>,
    /// 最新轮次的 redactions. `Arc<[(String,String)]>`: 共享切片而非 clone Vec.
    pub redactions: Arc<[(String, String)]>,
    /// 叶子节点 HTTP path (形如 "/o/<provider_id>/..."), 前端 provider icon 据此解析
    /// protocol 角标 + provider id. 取最近一轮的 provider, 跨 provider 重试场景下
    /// 可能不代表整条会话的 provider.
    pub path: String,
    /// 会话累计用量 (进程内口径: 沿链折叠各轮 ResponseData.usage, usage-stats §6 —
    /// restart 归零 / 轮次被 FIFO 淘汰后缩水, 与 Usage 页的持久账本口径不同).
    pub usage_total: UsageView,
}

/// Node 的轻量只读视图 (供 list / 元数据查询).
///
/// 不含 messages body 与 resp_body / req_body_raw (避免 clone 大量数据);
/// 含 list 场景需要的所有元数据 (preview / model / redactions / 响应状态等).
///
/// `parsed_response`: B1 双态派生 (`derive::parsed_view`) — 流式进行中读 stored
/// 节流快照, finalize 后从 message + 元字段派生.
#[derive(Debug, Clone)]
pub struct NodeView {
    pub id: Uuid,
    pub parent: Option<Uuid>,
    /// CDAG-7: 本节点是否为孤儿 (parent 已被 LRU 淘汰, 链在此截断).
    /// 根节点 (parent = None) 与 parent 存活的正常节点均为 false — 根不是孤儿.
    /// 前端可据此显式降级展示 (孤儿轮次的前缀上下文已缺失), 而非渲染残缺数据;
    /// 注意: 本字段仅在 NodeView 层派生, ForwardRecord / TimelineRound 等 wire DTO
    /// 的传播尚未接通 (后续工作) — 打通前该字段到不了任何 JSON 端点.
    pub is_orphan: bool,
    /// 所属会话的稳定标识 (push 时确定).
    pub session_id: SessionId,
    /// 本轮的主导角色 = req_delta 最后一条 message 的 role.
    /// 语义: "由于谁发了最后一条消息而触发了这次 HTTP 请求".
    /// WebUI 用它决定 sidebar 条目样式 + timeline 气泡渲染.
    pub round_role: IrRole,
    /// 轮次展示类别 (Normal / Retry / NoMessages), 见 dag::types::RoundKind.
    pub round_kind: RoundKind,
    pub req_delta_count: usize,
    pub has_response: bool,
    pub created_at: DateTime<Utc>,
    pub elapsed_ms: u64,
    pub method: String,
    pub path: String,
    pub resp_status: u16,
    pub redact_seed: u64,
    /// WebUI sidebar 标题 (最后一条 user message 截断).
    /// `Arc<str>`: list/timeline 路径共享切片而非 clone (serde 透明序列化).
    pub preview: Option<Arc<str>>,
    /// 请求 body 顶层 model 字段. `Arc<str>` 同上.
    pub model: Option<Arc<str>>,
    /// 实际承载转发的 provider id (路由解析后的链尾实体, #179).
    /// 非路由请求时即 URL 中的 provider id.
    pub upstream_id: Arc<str>,
    /// 实际改写的 model 值 (仅路由规则改写生效时 Some, #183).
    pub upstream_model: Option<Arc<str>>,
    /// 是否流式响应.
    pub streamed: bool,
    /// 响应是否完整 (上游错误 / 客户端断开 → false).
    pub resp_complete: bool,
    /// body 是否被详细日志保留 (三态决策的最终结果: Off 恒 false / Full 恒 true /
    /// Errors = 错误请求 true; **在途未定**按 true — 暂存中的 body 可看).
    /// `ForwardRecord.audit_capture_off` 的派生源; 决策 SSOT 见
    /// `config::AuditCaptureMode::retain`.
    pub audit_retained: bool,
    /// 错误诊断.
    pub error: Option<String>,
    /// (mock, secret_id) 投影. 永不含真实 secret value.
    /// `Arc<[(String,String)]>`: 共享切片而非 clone Vec.
    pub redactions: Arc<[(String, String)]>,
    /// parsed view (ingress codec writer 序列化的 IrResponse, LLM 视角含 mock).
    /// B1 双态: 流式进行中 = stored 节流 parsed; finalize 后 = message + 元字段
    /// 渲染派生 (`derive::response_parsed_from_parts`).
    pub parsed_response: Option<serde_json::Value>,
    /// 本轮 request delta (相对 parent 的增量 messages, 协议无关 wire JSON).
    ///
    /// 只在 timeline 路径填充 (list_page 路径留空, 避免 O(n) 全量 resolve).
    /// 前端用于渲染本轮新增的气泡 (system / user / tool_result 等),
    /// 实现每轮 preview + 完整 delta 展示 (issue #27).
    ///
    /// 每个元素是 message 的 wire JSON (OpenAI / Anthropic 原生格式),
    /// 前端按 role 分发气泡样式, 与 response 气泡区分.
    pub req_delta_messages: Vec<serde_json::Value>,
}

/// Node 的请求侧详情 (GET /records/{id} 按需拉取).
#[derive(Debug, Clone)]
pub struct NodeDetail {
    pub req_headers: Vec<(String, String)>,
    pub req_body_raw: String,
}

// ─── WebUI sync API 数据结构 (session-aware timeline + sync) ───────────────
//
// 替代旧的 NodeView timeline (基于 node_id) + list_records (扁平分页).
// 新模型基于 SessionId: sidebar 折叠会话树 + timeline 按 session 分页 + sync diff.
//
// 三条查询路径:
// - session_rounds(sid): sidebar 三级菜单的轻量 round 摘要.
// - timeline_view(sid, before, limit): timeline 初始加载 + lazy load (向前翻更老).
// - timeline_diff(sid, after, tail_length): sync 轮询的 diff.
// 三者共享 TimelineRound 结构 (含 req_delta_messages).

/// sidebar 三级菜单的轻量 round 摘要 (不含 req_delta_messages, 节省 3s 轮询带宽).
///
/// 字段直接从 `Node.event` 派生 (push 时预计算), 不 walk parent 链, 不 resolve block.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RoundBrief {
    pub id: Uuid,
    pub round_role: IrRole,
    /// 轮次展示类别 (Normal / Retry / NoMessages): sidebar retry 轮加 ↻ 前缀.
    pub round_kind: RoundKind,
    /// `Arc<str>`: 共享 event.preview, 轮询路径零拷贝.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<Arc<str>>,
    pub created_at: DateTime<Utc>,
}

/// timeline 每轮的完整数据 (含 request delta messages 的 wire JSON).
///
/// 与 RoundBrief 的区别: 多了 redactions + req_delta_messages (前端渲染气泡用).
/// `req_delta_messages` B1 起从 BlockPool 结构化派生 (resolve + real→mock 投影替换
///   经 ingress writer 序列化, `derive::extract_delta_messages_from_blocks`), 与旧
/// req_body_raw 末尾切片逐字节等价 (consistency-check shadow 守卫); OpenAI writer
/// 的 ToolResult 拆分场景保持与旧切片一致的尾部对齐 — delta 可能丢失本轮展开的头部
/// (user text 气泡与部分 tool 消息, 不混入前序轮; DTO-6 的错位行为不变).
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimelineRound {
    pub id: Uuid,
    pub round_role: IrRole,
    /// 轮次展示类别: 见 `dag::types::RoundKind` (Retry → 徽章, UI-1).
    pub round_kind: RoundKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<Arc<str>>,
    pub created_at: DateTime<Utc>,
    /// 实际承载转发的 provider id (target 解析后的链尾实体, #179).
    /// 非虚拟请求时即 URL 中的 provider id; 前端用它渲染 "via ..." 归属角标.
    pub upstream_id: Arc<str>,
    /// `Arc<[(String,String)]>`: 共享 event.redactions, 零拷贝.
    /// 每个 tuple = (mock_value, secret_id), **永不**含真实 secret.
    pub redactions: Arc<[(String, String)]>,
    /// 本轮 request delta (相对 parent 的增量 messages, wire JSON).
    /// B1: 从 BlockPool 结构化派生 (`derive::extract_delta_messages_from_blocks`,
    /// 与旧 req_body_raw 切片逐字节等价 — 见 contracts.md DTO-5).
    /// 前端按 role 渲染气泡 (system/user/tool), 与末轮 response 抽屉互补.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub req_delta_messages: Vec<serde_json::Value>,
    /// 本轮上游回显的 token 用量 (round 头部徽章, usage-stats). `None` = 无回显
    /// (非 2xx / parse 失败 / OpenAI 流式未开 include_usage / 无 codec 协议).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageView>,
}

/// timeline 抽屉 (视图级, 当前末轮的 response 内容).
///
/// 仅 timeline_view 的初始加载 / timeline_diff 的更新会推送新 tail;
/// 前端用 length 做 diff 判定 (是否需要更新抽屉内容).
/// 非 timeline 末轮的 response 内容已被下一轮 delta 的 assistant message 包含
/// (Phase A 决策, 详见旧 timeline 实现), 故 tail 只代表"最新尚未被 delta 消费的 response".
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimelineTail {
    pub round_id: Uuid,
    /// response 内容的字节长度 (前端用它判定是否需要更新抽屉).
    /// = parsed 序列化字节数 (parsed 为 None 时 fallback 到 raw_resp_body.len()).
    /// B1: finalize 后 parsed 为派生值 (见下), length 语义不变 (派生序列化字节数).
    pub length: usize,
    pub resp_status: u16,
    pub elapsed_ms: u64,
    pub streamed: bool,
    pub resp_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// parsed view (ingress codec writer 序列化的 IrResponse, LLM 视角含 mock).
    /// B1 双态: 流式进行中 = stored 节流 parsed (StreamScan 快照); finalize 后 =
    /// `response.message` + 元字段渲染派生 (`derive::response_parsed_from_parts`,
    /// stored Value 已在 finalize 时清除).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parsed: Option<serde_json::Value>,
}

/// GET /sessions/{sid}/timeline 的完整响应.
///
/// `rounds`: oldest-first, limit 条 (含末轮).
/// `tail`: 末轮 (rounds 最后一个) 的 response 抽屉数据.
/// `has_more`: 链上还有更老的 node (limit 之外), 前端用于显示 "load more" 提示.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimelinePage {
    pub rounds: Vec<TimelineRound>,
    pub tail: TimelineTail,
    pub has_more: bool,
}

/// sync 的 timeline diff 部分 (POST /api/sync 的 response.timeline).
///
/// `new_rounds`: after 游标之后新增的 round (oldest-first).
/// `tail`: 当前末轮的 response 抽屉 (前端用它 + length 判定是否需要更新).
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimelineDiffData {
    pub new_rounds: Vec<TimelineRound>,
    pub tail: TimelineTail,
}

/// POST /api/sync 的完整快照 (一个 read lock 内采集).
///
/// 三部分:
/// - `sessions`: 所有 session 的 SessionView (sidebar 一级树).
/// - `rounds`: 仅 expanded session 的 RoundBrief 列表 (sidebar 三级菜单).
/// - `timeline`: 仅 selected session 的 diff (timeline 初始加载 / 增量更新).
///
/// 在单个 `inner.read()` 锁内一次性采集, 避免多次 list_sessions / timeline_view
/// 之间数据漂移 (典型: 新 push 在两次读锁之间到达, sessions 与 rounds 不一致).
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncSnapshot {
    pub sessions: Vec<SessionView>,
    pub rounds: HashMap<SessionId, Vec<RoundBrief>>,
    /// None = 无选中 / 无 diff (前端持有的游标已是最新, 304 等价).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline: Option<TimelineDiffData>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ─── UsageView: 饱和加法代数性质 (session 总量折叠的算术根基) ─────────────
    //
    // UsageView.saturating_add 是 session usage_total 折叠 (dag::view 沿链求和) 的
    // 唯一算子, 上游 IrUsage 回显值是外部输入 (恶意/损坏的上游可回 u64 极值), 折叠
    // 必须在任意输入下不 panic 且封顶. 数学背景: 饱和加法 (⊞) 在非负整数上满足
    // 交换律与结合律 — 结合律证明分两case: 三数之和 ≤ MAX 时两侧均不饱和 (退化为
    // 普通加法, 结合); > MAX 时两侧均饱和到 MAX, 相等. 本 block 用极值偏置生成器
    // 锁住这些性质 (生成器覆盖度作为契约要求, contracts.md §0.3).

    /// 极值偏置的 u64 生成器: 混合全域随机与饱和边界 (0 / 1 / MAX 邻域),
    /// 确保极值邻域不靠概率性触达 (全域 any::<u64> 撞中 MAX±64 的概率 ~2^-58).
    fn arb_u64_sat() -> impl Strategy<Value = u64> {
        prop_oneof![
            4 => any::<u64>(),
            1 => Just(0u64),
            1 => Just(1u64),
            2 => (u64::MAX - 64)..=u64::MAX,
        ]
    }

    /// 四维独立的 UsageView 生成器 (每维独立取极值偏置值).
    fn arb_usage_view() -> impl Strategy<Value = UsageView> {
        (arb_u64_sat(), arb_u64_sat(), arb_u64_sat(), arb_u64_sat()).prop_map(
            |(input, output, cache_read, cache_write)| UsageView {
                input,
                output,
                cache_read,
                cache_write,
            },
        )
    }

    /// from_ir 归一契约: cache 两维的 None (上游未上报) 归 0, 其余透传.
    /// 固定值断言 (字段映射是确定性的, 无随机输入空间).
    #[test]
    fn from_ir_normalizes_none_cache_dims_to_zero() {
        let u = UsageView::from_ir(&IrUsage {
            input_tokens: 100,
            output_tokens: 7,
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
        });
        assert_eq!(
            u,
            UsageView {
                input: 100,
                output: 7,
                cache_read: 0,
                cache_write: 0
            },
            "None cache dims must normalize to 0 (USAGE-2 相等断言语义)"
        );
        // 极值透传: u64::MAX 不被 from_ir 截断.
        let extreme = UsageView::from_ir(&IrUsage {
            input_tokens: u64::MAX,
            output_tokens: u64::MAX,
            cache_read_input_tokens: Some(u64::MAX),
            cache_creation_input_tokens: Some(u64::MAX),
        });
        assert_eq!(
            extreme,
            UsageView {
                input: u64::MAX,
                output: u64::MAX,
                cache_read: u64::MAX,
                cache_write: u64::MAX
            },
            "u64::MAX must pass through from_ir unchanged"
        );
    }

    proptest! {
        /// 交换律: a ⊞ b == b ⊞ a (逐维).
        #[test]
        fn prop_saturating_add_commutative(a in arb_usage_view(), b in arb_usage_view()) {
            prop_assert_eq!(a.saturating_add(b), b.saturating_add(a));
        }

        /// 结合律: (a ⊞ b) ⊞ c == a ⊞ (b ⊞ c). 饱和加法在非负整数上满足结合律
        /// (论证见 mod 头部注释), 极值偏置生成器保证饱和分支被实际触达.
        #[test]
        fn prop_saturating_add_associative(
            a in arb_usage_view(), b in arb_usage_view(), c in arb_usage_view(),
        ) {
            let left = a.saturating_add(b).saturating_add(c);
            let right = a.saturating_add(b.saturating_add(c));
            prop_assert_eq!(left, right);
        }

        /// 单位元: a ⊞ 0 == 0 ⊞ a == a (零用量轮次不改变累计值).
        #[test]
        fn prop_saturating_add_identity(a in arb_usage_view()) {
            let zero = UsageView::default();
            prop_assert_eq!(a.saturating_add(zero), a);
            prop_assert_eq!(zero.saturating_add(a), a);
        }

        /// 封顶与支配性: 结果逐维 ≥ max(a,b) (单调不亏)、任一操作数该维为 MAX 时
        /// 结果恰为 MAX (吸收元), 且 "未溢出 == 普通加法精确值, 溢出 == 恰为 MAX"
        /// (饱和只在溢出处介入, 不引入其他偏差). 不 panic 性由测试本身执行到
        /// 断言即证明 (误用 `+` 会在 property 求值时溢出 panic, 走不到 checked 分支).
        #[test]
        fn prop_saturating_add_caps_at_max(a in arb_usage_view(), b in arb_usage_view()) {
            let s = a.saturating_add(b);
            for (x, y, z) in [
                (a.input, b.input, s.input),
                (a.output, b.output, s.output),
                (a.cache_read, b.cache_read, s.cache_read),
                (a.cache_write, b.cache_write, s.cache_write),
            ] {
                prop_assert!(z >= x.max(y), "saturated sum must dominate both operands");
                if x == u64::MAX || y == u64::MAX {
                    prop_assert_eq!(z, u64::MAX, "u64::MAX must be absorbing");
                }
                // 数学和未溢出时必须精确等于普通加法 (饱和只在溢出处介入).
                match x.checked_add(y) {
                    Some(exact) => prop_assert_eq!(z, exact, "no overflow: must equal plain add"),
                    None => prop_assert_eq!(z, u64::MAX, "overflow: must saturate to MAX"),
                }
            }
        }
    }

    /// 极值锚点: MAX ⊞ MAX 每维恰为 MAX, 不 panic. 固定值断言 (极值点是确定的,
    /// proptest 已概率性覆盖, 此处给回归时一眼可读的显式锚).
    #[test]
    fn saturating_add_max_saturated_point() {
        let m = UsageView {
            input: u64::MAX,
            output: u64::MAX,
            cache_read: u64::MAX,
            cache_write: u64::MAX,
        };
        assert_eq!(m.saturating_add(m), m, "MAX ⊞ MAX must saturate to MAX");
        // MAX 维 + 1: 该维封顶在 MAX; 加数其余维为 0 (单位元), MAX 维保持 MAX.
        let one = UsageView {
            input: 1,
            ..Default::default()
        };
        assert_eq!(m.saturating_add(one), m, "MAX-dim + 1 must stay at MAX");
    }
}
