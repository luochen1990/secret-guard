//! 模型用量统计 (usage-stats): 上游回显 usage 的采集 / 聚合 / SQLite 持久化.
//!
//! # 职责边界 (docs/design/usage-stats.md)
//!
//! - [`UsageEvent`]: 一条持久化明细 (每请求一行, SQLite `usage_events` 表).
//! - [`RedactEvent`]: redact 审计明细 (每请求 × 每命中 secret 一行,
//!   `redact_events` 表; B 级精度: ts/secret_id/mock/provider/model, **永不**含
//!   real secret 明文 — USAGE-7).
//! - [`UsageStore`]: SQLite 持久化 + SQL 聚合查询 (writer 线程批量事务 insert,
//!   转发热路径零同步 IO; summary 查询直读 SQL, 无内存聚合双份簿记).
//! - [`UsageCtx`]: proxy 侧的采集上下文 (in-scope 请求元数据 + push 后注入的
//!   `dag::RoundKind` 纯类型, **不回读 DAG** 于响应完成点 — 节点被 FIFO 淘汰不影响落账,
//!   设计 §5.2 防淘汰).
//!
//! # 数据来源 (P-1 零自造计数)
//!
//! token 数 100% 来自上游响应回显的 `usage` 字段 (经 codec reader 归一化的
//! [`crate::codec::ir::IrUsage`]), 不引入 tokenizer / 本地估算.
//!
//! # 计入判据 (USAGE-5)
//!
//! 仅 **POST 且收到上游响应** (任何 status) 的请求产生 UsageEvent:
//! - GET /models 透传 (方法过滤) 与 router /models 本地终结 (无转发) 都不计;
//! - dispatch 前置拒绝 (404/503/501) 与上游 send 失败 (502/504, 无响应) 不计 —
//!   "requests" 语义 = "上游实际返回了响应的 POST 请求数".
//! - `status` 存**原始 HTTP 状态码** (USAGE-5): 2xx/429/其余 4xx/5xx 的分类在
//!   summary 派生层完成 (SSOT: 一列原始事实回答所有 "某类错误多不多" 的问题,
//!   避免 schema 的 per-class flag 蔓延).
//! - RedactEvent 不按 method 过滤: redact 只发生在 body 改写路径 (GET 无 body
//!   天然不命中), 且审计语义 ("secret 差点泄露") 与 method 无关.
//!
//! # 聚合粒度 (USAGE-1)
//!
//! 聚合键 = (**hour**, provider, model); hour 是**本地时区** `YYYY-MM-DDTHH`
//! (本地工具, "今天/这一小时" 的用户直觉, 设计 §6). day 视图 = hour 前缀折叠,
//! 在查询时按窗口大小选择粒度 (≤14 天 hour, 更长 day).
//!
//! # SEC 边界
//!
//! `model` / `model_req` / `mock` 是自由字符串 (非受控 id) — fail_open passthrough
//! 场景下 secret 理论可出现在 model 中; mock 虽由 C5 契约保证不含 secret 子串,
//! 仍做防御纵深扫描. [`UsageCtx`] 落账前对三者做 active secrets 扫描
//! (命中 → `<redacted:...>` 占位 + WARN) 并截断 256 chars; 其余字段为受控类型
//! (数字 / provider id / proto 枚举), 天然无 secret.
//!
//! # 依赖方向
//!
//! 域 B 派生链成员; 仅依赖基础层类型 (codec::ir::IrUsage / secrets::SecretEntry /
//! dag::RoundKind 纯类型 / config 的 UsageConfig+PriceOverride 纯数据 schema —
//! usage→config 是向下合法边, 性质同 provider→config, 非例外; usage→dag 仅引用
//! RoundKind 枚举, 同 dto→dag 的 "纯类型依赖" 先例), 不依赖 proxy / web
//! (被 state 聚合, 组合根先例同 `state.api_keys` / `state.model_lists`).

mod pricing;
mod store;
pub mod summary;

pub use pricing::{
    ModelPrice, PricingCache, PricingStatus, PricingTable, extract_host,
    price_overrides_from_config,
};
pub use store::{Granularity, RedactRecentRow, RedactSecretRow, UsageAgg, UsageStore};
pub use summary::UsageSummary;

use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::codec::ir::IrUsage;
use crate::secrets::SecretEntry;

/// 一条持久化明细 (SQLite `usage_events` 一行). 列映射见 `store.rs::insert_batch`.
///
/// `usage: None` = wire 无回显 (P-3 缺失显式: 请求数进统计, token 不进);
/// 流式中断时为 StreamScan 已累积的部分值 (配 `complete: false`).
#[derive(Debug, Clone)]
pub struct UsageEvent {
    /// 请求时间 (CallEvent.created_at 同源).
    pub ts: chrono::DateTime<chrono::Utc>,
    /// 实际承载转发的 provider id (路由解析后的链尾实体).
    pub provider: String,
    /// 聚合用 model: **回显 model 优先** (计费模型), fallback 请求 model.
    /// 已过 SEC 扫描 + 截断.
    pub model: Option<String>,
    /// 请求侧 model (CallEvent.model 同源; 两者不同 = 命中别名/重写).
    pub model_req: Option<String>,
    /// ingress proto short ("o"/"a"/"g"/"l"/"r").
    pub proto: String,
    /// 上游响应的**原始 HTTP 状态码** (USAGE-5; 计入判据保证恒有响应).
    /// 2xx/429/4xx/5xx 分类在 summary 派生, 不在存储层固化 per-class flag.
    pub status: u16,
    /// 响应是否完整 (流式中断 / parse 失败中断 = false).
    pub complete: bool,
    /// 轮次类别 (M3: rounds 统计; SSOT = dag push_messages 判定, 此处透传真值).
    pub round_kind: crate::dag::RoundKind,
    /// 上游回显的四维用量 (cr/cw 的 None 按 unwrap_or(0) 归一, USAGE-2 语义).
    pub usage: Option<UsageQuanta>,
}

/// redact 审计明细 (SQLite `redact_events` 一行, 粒度 = 每请求 × 每命中
/// secret × 每非零位置分类).
///
/// B 级精度 (usage-stats 设计 §4b) + 治理三问扩展 (USAGE-7): ts / secret_id /
/// mock / provider / model_req / proto 回答 "何时何地泄了什么"; `category` (结构化
/// 位置) 回答 "哪个环节塞进来的"; `node` / `api_key_label` 回答 "谁" (DAG 节点
/// 关联 + auth 归因). **永不**含 real secret 明文与上下文文本片段 (红线):
/// mock 由 C5 契约保证不含 secret 的 ≥k(L) 连续子串, 落账前仍做防御纵深扫描.
#[derive(Debug, Clone)]
pub struct RedactEvent {
    pub ts: chrono::DateTime<chrono::Utc>,
    /// secret 的受控 id (config 层 schema, 天然无 secret 明文).
    pub secret_id: String,
    /// 替换用的 mock 值 (已过 SEC 防御扫描 + 截断).
    pub mock: String,
    /// 位置分类 (`HitLocations::non_zero` 展开的一档; 见该类型文档的治理语义).
    pub category: &'static str,
    /// 该分类在本请求中的出现次数 (聚合侧 SUM).
    pub count: u64,
    /// DAG node id (Uuid 字符串; 悬空容忍 — restart/淘汰后不可回查, UI 降级提示).
    pub node: String,
    /// auth 启用时的 API key label 归因; 单用户模式 (auth 未启用) 为 None.
    pub api_key_label: Option<String>,
    pub provider: String,
    /// 请求侧 model (redact 发生在请求侧, 响应 model 尚未可知).
    pub model_req: Option<String>,
    pub proto: String,
}

/// 一次 redact 的审计采集单元 (per request × per secret, 位置分布聚合形态;
/// [`UsageCtx::record_redactions`] 按 `non_zero()` 展开为 N 条 RedactEvent).
#[derive(Debug, Clone)]
pub struct RedactHit {
    pub secret_id: String,
    pub mock: String,
    pub locations: crate::codec::ir::HitLocations,
}

/// 四维 token 用量的持久化形态 (与 [`crate::dto::UsageView`] 同构, 独立定义避免
/// usage → dto 的 wire-shape 耦合: SQLite 列是存储格式, DTO 是 API 格式).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UsageQuanta {
    pub i: u64,
    pub o: u64,
    pub cr: u64,
    pub cw: u64,
}

impl UsageQuanta {
    pub fn from_ir(u: &IrUsage) -> Self {
        Self {
            i: u.input_tokens,
            o: u.output_tokens,
            cr: u.cache_read_input_tokens.unwrap_or(0),
            cw: u.cache_creation_input_tokens.unwrap_or(0),
        }
    }
}

/// SEC 占位符: 自由字符串命中 secret 时的整体替换值 (USAGE-6/7).
const REDACTED_MODEL: &str = "<redacted:model>";
const REDACTED_MOCK: &str = "<redacted:mock>";

/// SEC 防护: 自由字符串 (model / mock) 过 active secrets 扫描 + 截断.
///
/// 命中任一 secret 明文 → 整体替换为 `placeholder` (无法安全截断: 泄漏位置不定);
/// 否则截断到 256 chars (char boundary 安全). 返回 (结果, 是否命中).
fn sanitize_free_string(value: &str, placeholder: &str, secrets: &[SecretEntry]) -> (String, bool) {
    for s in secrets {
        if !s.value.is_empty() && value.contains(s.value.as_str()) {
            tracing::warn!(
                len = value.len(),
                "usage/redact event string contained an active secret; redacted before persist"
            );
            return (placeholder.to_string(), true);
        }
    }
    let mut out = value.to_string();
    if out.len() > 256 {
        let cut = out
            .char_indices()
            .nth(256)
            .map(|(i, _)| i)
            .unwrap_or(out.len());
        out.truncate(cut);
    }
    (out, false)
}

/// proxy 侧的采集上下文.
///
/// 在转发函数内 (same_proto / cross_proto, push_messages 附近) 一次性构造,
/// 携带 **in-scope 请求元数据** (含 push 后注入的 `round_kind`) 流转到:
/// - redact 落账点 (请求侧, push 后立即 — 审计语义: 响应失败也不丢);
/// - 响应完成点 (fan_out 的 spawn task / buffered 收尾) 的 `record_response`.
///
/// 响应完成点不回读 DAG — 节点被 FIFO 淘汰、`attach_response` 因 evicted 静默
/// 返回, 都不影响 usage 落账 (设计 §5.2 防淘汰).
#[derive(Clone)]
pub struct UsageCtx {
    store: Arc<UsageStore>,
    ts: DateTime<Utc>,
    provider: Arc<str>,
    model_req: Option<String>,
    proto: Arc<str>,
    method: Arc<str>,
    /// push 后由 proxy 注入 (dag.round_kind_of; SSOT 判定在 push_messages).
    round_kind: crate::dag::RoundKind,
    /// 本请求的 DAG node id (push 返回; redact 审计的溯源关联, 悬空容忍).
    node: uuid::Uuid,
    /// auth 启用时的 API key label (归因; 单用户模式 None). 纯数据, 经 proxy 从
    /// request extension 提取注入 (proxy → auth 的纯类型依赖, 见根 AGENTS.md).
    api_key_label: Option<String>,
    /// active secrets 快照 (SEC model/mock 扫描用; 与 CallEvent.policy 同源).
    secrets: Arc<[SecretEntry]>,
}

impl UsageCtx {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<UsageStore>,
        provider: Arc<str>,
        model_req: Option<String>,
        proto: impl Into<Arc<str>>,
        method: impl Into<Arc<str>>,
        round_kind: crate::dag::RoundKind,
        node: uuid::Uuid,
        api_key_label: Option<String>,
        secrets: Arc<[SecretEntry]>,
    ) -> Self {
        Self {
            store,
            ts: Utc::now(),
            provider,
            model_req,
            proto: proto.into(),
            method: method.into(),
            round_kind,
            node,
            api_key_label,
            secrets,
        }
    }

    /// model_req 的 SEC 扫描 (record_redactions / record_response 共用).
    fn sanitized_model_req(&self, secrets: &[SecretEntry]) -> Option<String> {
        self.model_req
            .as_deref()
            .map(|m| sanitize_free_string(m, REDACTED_MODEL, secrets).0)
    }

    /// 请求侧 redact 落账点: 每命中 secret × 每非零位置分类一条 RedactEvent (USAGE-7).
    ///
    /// 在 push_messages 后立即调用 (hits 从 redact_and_derive 的 map 派生, push 前
    /// 捕获); 不过滤 method (redact 只发生在 body 改写路径, 审计语义与 method 无关).
    pub fn record_redactions(&self, hits: &[RedactHit]) {
        if self.store.is_disabled() || hits.is_empty() {
            return;
        }
        let secrets: &[SecretEntry] = &self.secrets;
        let model_req = self.sanitized_model_req(secrets);
        for h in hits {
            // 防御纵深: C5 已保证 mock 不含 secret 子串, 扫描是纵深 (USAGE-7 property).
            let mock = sanitize_free_string(&h.mock, REDACTED_MOCK, secrets).0;
            for (category, count) in h.locations.non_zero() {
                self.store.record_redact(RedactEvent {
                    ts: self.ts,
                    secret_id: h.secret_id.clone(),
                    mock: mock.clone(),
                    category,
                    count,
                    node: self.node.to_string(),
                    api_key_label: self.api_key_label.clone(),
                    provider: self.provider.to_string(),
                    model_req: model_req.clone(),
                    proto: self.proto.to_string(),
                });
            }
        }
    }

    /// 响应完成点调用: 构造 UsageEvent 落账 (SQLite insert).
    ///
    /// 参数为纯数据 (不依赖 proxy 类型): `usage`/`model_echo` 来自 M0 接线的
    /// `ResponseEcho`. USAGE-5 计入判据在此统一执行 (非 POST → no-op);
    /// `model_echo` 优先, fallback `model_req`, 两者均过 SEC 扫描.
    pub fn record_response(
        &self,
        status: u16,
        complete: bool,
        usage: Option<IrUsage>,
        model_echo: Option<String>,
    ) {
        // USAGE-5: 仅 POST 计入 (GET /models 透传等被方法过滤).
        if self.method.as_ref() != "POST" {
            return;
        }
        let secrets: &[SecretEntry] = &self.secrets;
        // 聚合 model: 回显优先, fallback 请求侧; 空串归一为 None.
        let model = model_echo
            .as_deref()
            .or(self.model_req.as_deref())
            .map(|m| sanitize_free_string(m, REDACTED_MODEL, secrets).0)
            .filter(|m| !m.is_empty());
        let model_req = self
            .model_req
            .as_deref()
            .map(|m| sanitize_free_string(m, REDACTED_MODEL, secrets).0);
        let event = UsageEvent {
            ts: self.ts,
            provider: self.provider.to_string(),
            model,
            model_req,
            proto: self.proto.to_string(),
            status,
            complete,
            round_kind: self.round_kind,
            usage: usage.as_ref().map(UsageQuanta::from_ir),
        };
        self.store.record(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::RoundKind;

    fn no_secrets() -> Arc<[SecretEntry]> {
        Arc::from(Vec::<SecretEntry>::new().into_boxed_slice())
    }

    /// UsageCtx 测试构造收口 (node/label 归因用例单独构造).
    fn ctx_with(
        store: &Arc<UsageStore>,
        model_req: Option<&str>,
        method: &str,
        secrets: Arc<[SecretEntry]>,
    ) -> UsageCtx {
        UsageCtx::new(
            store.clone(),
            Arc::from("p"),
            model_req.map(String::from),
            "o",
            method,
            RoundKind::Normal,
            uuid::Uuid::new_v4(),
            None,
            secrets,
        )
    }

    fn entry_with_value(v: &str) -> SecretEntry {
        SecretEntry {
            id: format!("sid-{v}"),
            name: None,
            category: crate::secrets::SecretCategory::ApiKey,
            value: v.to_string(),
            value_file: None,
            mock_strategy: crate::mock::MockStrategy::default(),
        }
    }

    // ─── sanitize_free_string (SEC: SQLite 持久化边界) ───────────────────

    #[test]
    fn sanitize_redacts_model_containing_secret() {
        let secrets = vec![entry_with_value("sk-live-abc123")];
        let (out, hit) =
            sanitize_free_string("relay/sk-live-abc123-fork", REDACTED_MODEL, &secrets);
        assert!(hit);
        assert_eq!(out, REDACTED_MODEL);
        // 不含 secret 的部分不能残留.
        assert!(!out.contains("sk-live-abc123"));
    }

    #[test]
    fn sanitize_keeps_clean_model_and_truncates_at_char_boundary() {
        let secrets = vec![entry_with_value("sk-live-abc123")];
        let (out, hit) = sanitize_free_string("gpt-5.6-terra", REDACTED_MODEL, &secrets);
        assert!(!hit);
        assert_eq!(out, "gpt-5.6-terra");
        // 300 个多字节字符 → 截断到 256 chars 且不出现在字符中间.
        let long: String = "模型".repeat(150); // 300 chars, 900 bytes
        let (trunc, _) = sanitize_free_string(&long, REDACTED_MODEL, &secrets);
        assert_eq!(trunc.chars().count(), 256);
        assert!(trunc.chars().all(|c| c == '模' || c == '型'));
    }

    // ─── UsageCtx::record_response (USAGE-5 计入判据 + model 选择) ──────

    #[test]
    fn record_response_filters_non_post() {
        let store = Arc::new(UsageStore::disabled());
        ctx_with(&store, None, "GET", no_secrets()).record_response(
            200,
            true,
            Some(IrUsage::default()),
            None,
        );
        assert_eq!(
            store.total_events(),
            0,
            "GET must not be recorded (USAGE-5)"
        );
    }

    #[test]
    fn record_response_prefers_echo_model_and_sanitizes() {
        let store = Arc::new(UsageStore::in_memory());
        let ctx = ctx_with(
            &store,
            Some("sk-live-abc123-alias"), // model_req 含 secret
            "POST",
            Arc::from(vec![entry_with_value("sk-live-abc123")].into_boxed_slice()),
        );
        ctx.record_response(
            200,
            true,
            Some(IrUsage {
                input_tokens: 70,
                output_tokens: 10,
                cache_read_input_tokens: Some(30),
                ..Default::default()
            }),
            Some("gpt-echoed".to_string()),
        );
        // in_memory 模式同步直写, 查询立即可见.
        let cells = store.query_cells("", crate::usage::Granularity::Hour);
        assert_eq!(cells.len(), 1);
        let ((_, provider, model), agg) = &cells[0];
        assert_eq!(provider, "p");
        assert_eq!(
            model.as_deref(),
            Some("gpt-echoed"),
            "echo model wins (聚合键是回显 model)"
        );
        assert_eq!(agg.requests, 1);
        assert_eq!(agg.input, 70);
        assert_eq!(agg.cache_read, 30);
        assert_eq!(agg.output, 10);
        assert_eq!(agg.retries, 0, "round_kind=Normal 不计 retry");
        // USAGE-2: 回显保真 (i=70 归一自 prompt 100 - cached 30).
        // round_kind 真值性 (USAGE-1 rounds 维度): Normal 不进 retries/no_messages.
    }

    #[test]
    fn record_response_counts_retry_and_429_dimensions() {
        // M3/M5: rounds 三态 + status 原始列派生分类 (429 独立计数).
        let store = Arc::new(UsageStore::in_memory());
        let mk = |kind: RoundKind, status: u16| {
            UsageCtx::new(
                store.clone(),
                Arc::from("p"),
                Some("m".to_string()),
                "o",
                "POST",
                kind,
                uuid::Uuid::new_v4(),
                None,
                no_secrets(),
            )
            .record_response(status, true, None, None);
        };
        mk(RoundKind::Normal, 200);
        mk(RoundKind::Retry, 429);
        mk(RoundKind::NoMessages, 500);
        let cells = store.query_cells("", crate::usage::Granularity::Hour);
        let agg = &cells[0].1;
        assert_eq!(agg.requests, 3);
        assert_eq!(agg.retries, 1);
        assert_eq!(agg.no_messages, 1);
        assert_eq!(agg.rate_limited_429, 1);
        assert_eq!(agg.errors_5xx, 1);
        assert_eq!(agg.errors_4xx, 0);
    }

    // ─── UsageCtx::record_redactions (USAGE-7 治理三问: 位置/归因/溯源) ────

    fn hit(secret_id: &str, mock: &str, locations: crate::codec::ir::HitLocations) -> RedactHit {
        RedactHit {
            secret_id: secret_id.to_string(),
            mock: mock.to_string(),
            locations,
        }
    }

    fn locs(
        system: u64,
        tools: u64,
        user: u64,
        history: u64,
        other: u64,
    ) -> crate::codec::ir::HitLocations {
        crate::codec::ir::HitLocations {
            system,
            tools,
            user,
            history,
            other,
        }
    }

    #[test]
    fn record_redactions_expands_categories_and_sanitizes_mock() {
        let store = Arc::new(UsageStore::in_memory());
        let ctx = UsageCtx::new(
            store.clone(),
            Arc::from("p1"),
            Some("m-req".to_string()),
            "o",
            "POST",
            RoundKind::Normal,
            uuid::Uuid::new_v4(),
            None,
            Arc::from(vec![entry_with_value("sk-live-abc123")].into_boxed_slice()),
        );
        // sid-1: system 1 + user 2 (展开 2 行); sid-2: mock 含 secret (防御纵深) + user 1.
        ctx.record_redactions(&[
            hit("sid-1", "sgm_clean_mock_111", locs(1, 0, 2, 0, 0)),
            hit("sid-2", "leak-sk-live-abc123-x", locs(0, 0, 1, 0, 0)),
        ]);
        let (by_secret, recent) = store.query_redacts("", 10);
        assert_eq!(by_secret.len(), 2);
        let r1 = by_secret.iter().find(|r| r.secret_id == "sid-1").unwrap();
        assert_eq!(r1.hits, 3);
        assert_eq!(r1.categories.get("system"), Some(&1));
        assert_eq!(r1.categories.get("user"), Some(&2));
        // USAGE-7 SEC: 含 secret 子串的 mock 必须被整体替换 (防御纵深).
        let r2 = by_secret.iter().find(|r| r.secret_id == "sid-2").unwrap();
        assert_eq!(r2.mock, REDACTED_MOCK);
        assert_eq!(recent.len(), 3);
        assert!(!format!("{recent:?}").contains("sk-live-abc123"));
    }

    #[test]
    fn record_redactions_carries_node_and_api_key_label() {
        let store = Arc::new(UsageStore::in_memory());
        let node = uuid::Uuid::new_v4();
        UsageCtx::new(
            store.clone(),
            Arc::from("p"),
            None,
            "o",
            "POST",
            RoundKind::Normal,
            node,
            Some("ci-runner".to_string()),
            no_secrets(),
        )
        .record_redactions(&[hit("sid", "m", locs(0, 1, 0, 0, 0))]);
        let (_, recent) = store.query_redacts("", 10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].node.as_deref(), Some(node.to_string().as_str()));
        assert_eq!(recent[0].api_key_label.as_deref(), Some("ci-runner"));
        assert_eq!(recent[0].category, "tools");
    }

    #[test]
    fn record_redactions_noop_on_disabled_or_zero_locations() {
        let disabled = Arc::new(UsageStore::disabled());
        ctx_with(&disabled, None, "POST", no_secrets()).record_redactions(&[hit(
            "s",
            "m",
            locs(0, 0, 1, 0, 0),
        )]);
        let zero = Arc::new(UsageStore::in_memory());
        ctx_with(&zero, None, "POST", no_secrets()).record_redactions(&[hit(
            "s",
            "m",
            locs(0, 0, 0, 0, 0),
        )]); // 全零 → 零行
        assert!(disabled.query_redacts("", 10).0.is_empty());
        assert!(zero.query_redacts("", 10).0.is_empty());
    }
}
