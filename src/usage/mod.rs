//! 模型用量统计 (usage-stats): 上游回显 usage 的采集 / 聚合 / 持久化.
//!
//! # 职责边界 (docs/design/usage-stats.md)
//!
//! - [`UsageEvent`]: 一条持久化明细 (每请求一行 JSONL, ~180B).
//! - [`UsageStore`]: 内存聚合 (启动重放 JSONL + record 增量) + mpsc → 独立
//!   writer 线程 append (转发热路径零同步 IO).
//! - [`UsageCtx`]: proxy 响应完成点的采集上下文 (in-scope 请求元数据, **不回读
//!   DAG** — 节点被 FIFO 淘汰不影响落账, 设计 §5.2).
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
//!
//! # SEC 边界
//!
//! `model` / `model_req` 是自由 wire 字符串 (非受控 id) — fail_open passthrough
//! 场景下 secret 理论可出现在其中. [`UsageCtx`] 落账前对二者做 active secrets
//! 扫描 (命中 → `<redacted:model>` + WARN) 并截断 256 chars; 其余字段为受控类型
//! (数字 / provider id / proto 枚举), 天然无 secret.
//!
//! # 依赖方向
//!
//! 域 B 派生链成员; 仅依赖基础层类型 (codec::ir::IrUsage / secrets::SecretEntry
//! 纯数据 + chrono/serde), 不依赖 dag / proxy / web (被 state 聚合, 组合根先例同
//! `state.api_keys` / `state.model_lists`).

mod store;

pub use store::{UsageAgg, UsageStore};

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::codec::ir::IrUsage;
use crate::secrets::SecretEntry;

/// 一条持久化明细 (JSONL 一行). 字段命名紧凑 (i/o/cr/cw), ~180B/行.
///
/// `usage: None` = wire 无回显 (P-3 缺失显式: 请求数进统计, token 不进);
/// 流式中断时为 StreamScan 已累积的部分值 (配 `complete: false`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageEvent {
    /// 请求时间 (CallEvent.created_at 同源).
    pub ts: DateTime<Utc>,
    /// 实际承载转发的 provider id (路由解析后的链尾实体).
    pub provider: String,
    /// 聚合用 model: **回显 model 优先** (计费模型), fallback 请求 model.
    /// 已过 SEC 扫描 + 截断.
    pub model: Option<String>,
    /// 请求侧 model (CallEvent.model 同源; 两者不同 = 命中别名/重写).
    pub model_req: Option<String>,
    /// ingress proto short ("o"/"a"/"g"/"l"/"r").
    pub proto: String,
    /// HTTP method (计入判据已保证恒 "POST", 冗余存储供明细审计).
    pub method: String,
    /// resp_status == 2xx.
    pub ok: bool,
    /// 响应是否完整 (流式中断 / parse 失败中断 = false).
    pub complete: bool,
    /// 上游回显的四维用量 (cr/cw 的 None 按 unwrap_or(0) 归一, USAGE-2 语义).
    pub usage: Option<UsageQuanta>,
}

/// 四维 token 用量的持久化形态 (与 [`crate::dto::UsageView`] 同构, 独立定义避免
/// usage → dto 的 wire-shape 耦合: JSONL 是存储格式, DTO 是 API 格式).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
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

/// SEC 防护: model 字符串过 active secrets 扫描 + 截断.
///
/// 命中任一 secret 明文 → 整体替换为占位符 (无法安全截断: 泄漏位置不定);
/// 否则截断到 256 chars (char boundary 安全). 返回 (结果, 是否命中).
fn sanitize_model_string(model: &str, secrets: &[SecretEntry]) -> (String, bool) {
    for s in secrets {
        if !s.value.is_empty() && model.contains(s.value.as_str()) {
            tracing::warn!(
                model_len = model.len(),
                "usage event model string contained an active secret; redacted before persist"
            );
            return ("<redacted:model>".to_string(), true);
        }
    }
    let mut out = model.to_string();
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

/// proxy 响应完成点的采集上下文.
///
/// 在转发函数内 (same_proto / cross_proto, push_messages 附近) 一次性构造,
/// 携带 **in-scope 请求元数据** 流转到响应完成点 (fan_out 的 spawn task /
/// buffered 收尾), 调用 [`Self::record_response`] 落账. 不回读 DAG — DAG 节点
/// 被 FIFO 淘汰、`attach_response` 因 evicted 静默返回, 都不影响 usage 落账
/// (设计 §5.2 防淘汰).
#[derive(Clone)]
pub struct UsageCtx {
    store: Arc<UsageStore>,
    ts: DateTime<Utc>,
    provider: Arc<str>,
    model_req: Option<String>,
    proto: Arc<str>,
    method: Arc<str>,
    /// active secrets 快照 (SEC model 扫描用; 与 CallEvent.policy 同源).
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
        secrets: Arc<[SecretEntry]>,
    ) -> Self {
        Self {
            store,
            ts: Utc::now(),
            provider,
            model_req,
            proto: proto.into(),
            method: method.into(),
            secrets,
        }
    }

    /// 响应完成点调用: 构造 UsageEvent 落账 (聚合 + JSONL append).
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
        let (model, _) = match &model_echo {
            Some(m) => sanitize_model_string(m, secrets),
            None => match &self.model_req {
                Some(m) => sanitize_model_string(m, secrets),
                None => (String::new(), false),
            },
        };
        let model_req = self
            .model_req
            .as_deref()
            .map(|m| sanitize_model_string(m, secrets).0);
        let event = UsageEvent {
            ts: self.ts,
            provider: self.provider.to_string(),
            model: if model.is_empty() { None } else { Some(model) },
            model_req,
            proto: self.proto.to_string(),
            method: self.method.to_string(),
            ok: (200..300).contains(&status),
            complete,
            usage: usage.as_ref().map(UsageQuanta::from_ir),
        };
        self.store.record(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ─── sanitize_model_string (SEC: JSONL 持久化边界) ──────────────────

    #[test]
    fn sanitize_redacts_model_containing_secret() {
        let secrets = vec![entry_with_value("sk-live-abc123")];
        let (out, hit) = sanitize_model_string("relay/sk-live-abc123-fork", &secrets);
        assert!(hit);
        assert_eq!(out, "<redacted:model>");
        // 不含 secret 的部分不能残留.
        assert!(!out.contains("sk-live-abc123"));
    }

    #[test]
    fn sanitize_keeps_clean_model_and_truncates_at_char_boundary() {
        let secrets = vec![entry_with_value("sk-live-abc123")];
        let (out, hit) = sanitize_model_string("gpt-5.6-terra", &secrets);
        assert!(!hit);
        assert_eq!(out, "gpt-5.6-terra");
        // 300 个多字节字符 → 截断到 256 chars 且不出现在字符中间.
        let long: String = "模型".repeat(150); // 300 chars, 900 bytes
        let (trunc, _) = sanitize_model_string(&long, &secrets);
        assert_eq!(trunc.chars().count(), 256);
        assert!(trunc.chars().all(|c| c == '模' || c == '型'));
    }

    // ─── UsageCtx::record_response (USAGE-5 计入判据 + model 选择) ──────

    /// 构造内存态 store (无文件) 的 ctx helper.
    fn ctx_with(method: &str, model_req: Option<&str>, secrets: Vec<SecretEntry>) -> UsageCtx {
        UsageCtx::new(
            Arc::new(UsageStore::disabled()),
            Arc::from("test-provider"),
            model_req.map(String::from),
            "o",
            method,
            Arc::from(secrets.into_boxed_slice()),
        )
    }

    #[test]
    fn record_response_filters_non_post() {
        let store = Arc::new(UsageStore::disabled());
        let ctx = UsageCtx::new(
            store.clone(),
            Arc::from("p"),
            None,
            "o",
            "GET",
            Arc::from(Vec::<SecretEntry>::new().into_boxed_slice()),
        );
        ctx.record_response(200, true, Some(IrUsage::default()), None);
        assert_eq!(store.total_requests(), 0, "GET must not be recorded (USAGE-5)");
    }

    #[test]
    fn record_response_prefers_echo_model_and_sanitizes() {
        let store = Arc::new(UsageStore::for_tests());
        let ctx = UsageCtx::new(
            store.clone(),
            Arc::from("p"),
            Some("sk-live-abc123-alias".to_string()), // model_req 含 secret
            "o",
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
        let events = store.take_events_for_test();
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.model.as_deref(), Some("gpt-echoed"), "echo model wins");
        assert_eq!(
            e.model_req.as_deref(),
            Some("<redacted:model>"),
            "model_req must be sanitized"
        );
        assert_eq!(e.usage.as_ref().unwrap().i, 70);
        assert_eq!(e.usage.as_ref().unwrap().cr, 30);
        assert!(e.ok && e.complete);
    }

    // 防 unused 警告 (helper 在被禁用路径下可能未用).
    #[allow(dead_code)]
    fn _ctx_with_used() {
        let _ = ctx_with("POST", None, vec![]);
    }
}
