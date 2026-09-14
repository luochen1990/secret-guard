//! DAG record 构造 + 视图正确性守卫 + 响应累积器.
//!
//! # 职责边界
//!
//! 汇集转发链中所有与 DAG 记录相关的辅助逻辑:
//! - [`build_call_event`]: 三条转发路径 (same_proto passthrough / same_proto IR /
//!   cross_proto) 共用的 [`CallEvent`] 构造器.
//! - [`record_upstream_failure`]: 错误路径的 incomplete 记录写入.
//! - [`derive_redactions`] / [`parse_request_ir`] / [`redact_and_derive`]: IR 解析
//!   与 redact 派生 (same_proto / cross_proto 共享的前半段).
//! - [`RecordAccumulator`]: fan_out 三路径共享的响应字节累积器 (受
//!   `MAX_RESP_BODY_RECORD` cap 保护).
//! - [`ParsedSync`]: 流式 parsed view 的节流累积器.
//!
//! # 视图正确性守卫 (`consistency-check` feature)
//!
//! 派生字段 (`redactions` / `preview` / `model` / `parsed`) 是 SSOT 的视图. 详见
//! AGENTS.md "视图正确性确保机制". 本模块集中三个守卫函数:
//! [`assert_redactions_match_map`] / [`assert_preview_model_match_source`] /
//! [`assert_resp_parsed_matches_source_nonstream`].

use std::time::Duration;

use axum::http::HeaderMap;
use futures::StreamExt;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::helpers::redact_headers;
use crate::config::OnProbeExhausted;
use crate::dag::{CallEvent, ConversationDag, PolicySnapshot, ResponseData};
use crate::error::AppError;
use crate::provider::Protocol;
use crate::redact::{RedactError, RedactionMap, redact_ir_checked};

/// 流式 parsed view (StreamScan snapshot) 的节流写入间隔.
/// 太短 → DAG 写锁竞争; 太长 → WebUI 看不到流式进度. 500ms 是 UX 与锁竞争的折中.
pub(super) const PARSED_SYNC_INTERVAL: Duration = Duration::from_millis(500);

// ─── usage-stats 采集: 响应回显摘要 (M0 收口) ───────────────────────────────

/// 上游响应的回显摘要 (usage + 实际模型名), usage-stats 采集的单一提取入口.
///
/// 数据源: 非流式 = `reader.read_response` 的 [`crate::codec::ir::IrResponse`];
/// 流式 = StreamScan snapshot (经 [`ParsedSync::finalize`] 一并产出). proxy 全部
/// ResponseData 构造点统一经此结构接线 (单一入口防新增转发路径漏接).
/// 设计: docs/design/usage-stats.md §5.2.
/// 两字段皆 Option — `#[derive(Default)]` 即 "无回显" 占位值 (错误路径 /
/// parse 失败 / 无 codec 协议).
#[derive(Default)]
pub(crate) struct ResponseEcho {
    /// 回显的 token 用量. `None` = wire 无回显 (presence 语义见
    /// `IrResponse::usage_present`); 流式中断时为已累积部分值.
    pub usage: Option<crate::codec::ir::IrUsage>,
    /// 上游回显的实际服务模型名 (别名/路由场景比请求侧 model 更准).
    pub model: Option<String>,
}

impl ResponseEcho {
    /// 从 IrResponse 提取 (usage_present 位决定 usage 的 Option-ness).
    pub(crate) fn from_ir(ir: &crate::codec::ir::IrResponse) -> Self {
        Self {
            usage: ir.usage_present.then(|| ir.usage.clone()),
            model: ir.model.clone(),
        }
    }
}

// ─── 跨语言契约字符串 (前端 index.html 依赖, 见 isClientDisconnect) ─────────
//
// error_kind 字面量是前后端契约 (前端 index.html::isClientDisconnect 硬编码比较).
// 集中为 const, 任何改动一处即可, 避免 fan_out_* 三处各自硬编码导致漂移.

/// 客户端主动断开 (tx.send 失败). 前端 isClientDisconnect 严格相等匹配此串.
pub(super) const ERR_CLIENT_DISCONNECTED: &str = "client disconnected";
/// 上游流式响应中途出错 (reqwest stream Err).
pub(super) const ERR_UPSTREAM_STREAM: &str = "upstream stream error";
/// 上游流式响应 chunk 空闲超时 (chunk 间隔超过配置的 stream_idle_timeout).
pub(super) const ERR_STREAM_IDLE_TIMEOUT: &str = "upstream stream idle timeout";
/// 响应超过 record 累积上限 (MAX_RESP_BODY_RECORD).
pub(super) const ERR_RESP_CAP_EXCEEDED: &str = "response exceeds record cap";

/// 投影 `RedactionMap` + `secrets_snapshot` → `(mock_value, secret_id)` 列表.
///
/// 这是 [`CallEvent::redactions`] 的唯一派生入口. 输出**永不**包含真实 secret 值.
/// 可以直接序列化到 GET API 响应中给 WebUI.
///
/// 匹配规则与去重语义见 [`derive_redact_hits`] 的共享 join (两投影同源,
/// mock↔secret_id 关联一致性由 `redaction_projections_agree_on_mock_secret_pairing`
/// 测试守卫; consistency-check 守卫 [`assert_redactions_match_map`] 只覆盖本投影).
pub(super) fn derive_redactions(
    redaction_map: &RedactionMap,
    secrets_snapshot: &[crate::secrets::SecretEntry],
) -> Vec<(String, String)> {
    derive_redact_hits(redaction_map, secrets_snapshot)
        .into_iter()
        .map(|h| (h.mock, h.secret_id))
        .collect()
}

// ─── same_proto / cross_proto 共享的请求准备 helpers ───────────────────────
//
// same_proto_forward 与 cross_proto_forward 的前半段 (解析 body → reader → IR →
// redact → derive_redactions) 流程步骤高度重合, 抽取为两个小 helper 消除重复,
// 同时保留两路径在 URL / headers / record path 上的差异 (这些差异是语义性的, 不宜强行合并).

/// 解析请求 body 为 JSON 并用 ingress reader 读为 IR (same_proto / cross_proto 共享).
///
/// 失败返回 `BadBody` (JSON 解析失败或 codec reader 拒绝).
/// 解析请求 body → IR; `model_rewrite` 非空时**无条件注入**到 IR 的 model 字段
/// (#183, D3 — 客户端 body 缺 model 亦注入; IrRequest.model 本是必填 String).
/// 这是 model 重写的**唯一注入点** (same_proto IR 路径与 cross_proto 共享, SSOT).
pub(super) fn parse_request_ir(
    req_bytes: &[u8],
    ingress: Protocol,
    reader: &dyn crate::codec::Reader,
    model_rewrite: Option<&str>,
) -> Result<crate::codec::ir::IrRequest, AppError> {
    let body: serde_json::Value = serde_json::from_slice(req_bytes)
        .map_err(|e| AppError::BadBody(format!("invalid JSON in {ingress} request body: {e}")))?;
    let mut ir = reader
        .read_request(&body)
        .map_err(|e| AppError::BadBody(format!("{ingress} request parse failed: {}", e.message)))?;
    if let Some(m) = model_rewrite {
        ir.model = m.to_string();
    }
    Ok(ir)
}

/// `redaction_map.real_to_mock` × `secrets_snapshot` 的共享 join (M-C4).
///
/// 匹配规则: `real_to_mock` 的 key (真实 secret) 与 snapshot 的 `value` 字段
/// first-match. 仅命中的 secret 才进入列表 (eg secret 在表中但本次请求体没有它,
/// 不计入). 同一 secret 多次匹配仍只投影一次 (HashMap 已去重).
///
/// 边角: 若两个 SecretEntry 共享同一 `value` (eg 用户重复配置), `find` 返回首个匹配;
/// 由于 RedactionMap 按 value 去重, 对应只有一个 mock — 这种重复配置语义上就是冗余,
/// WebUI 只展示其中一个 id 是可接受的 (它们指向相同的 secret 内容).
///
/// 本函数是该 join 的**唯一实现** ( [`derive_redactions`] 的 (mock, secret_id)
/// 投影从本函数结果派生 — 两投影对同一 (map, snapshot) 输入的 mock↔secret_id
/// 关联恒一致, 由 `redaction_projections_agree_on_mock_secret_pairing` 守卫).
/// 从 RedactionMap (SSOT) 派生 usage 审计的采集单元: (secret_id, mock, 位置分布);
/// locations 取 map.hits (redact_ir_inner 在替换前采集).
fn derive_redact_hits(
    redaction_map: &RedactionMap,
    secrets_snapshot: &[crate::secrets::SecretEntry],
) -> Vec<crate::usage::RedactHit> {
    redaction_map
        .real_to_mock
        .iter()
        .filter_map(|(real, mock)| {
            let id = secrets_snapshot
                .iter()
                .find(|s| &s.value == real)
                .map(|s| s.id.clone())?;
            let locations = redaction_map.hits.get(real).copied().unwrap_or_default();
            Some(crate::usage::RedactHit {
                secret_id: id,
                mock: mock.clone(),
                locations,
            })
        })
        .collect()
}

/// `redact_and_derive` 的返回类型别名 (避免 clippy::type_complexity 误报).
///
/// 四元组语义: `(redaction_map, redact_seed, redactions, redact_hits)`.
/// Err 是已构造好的客户端错误 (fail_closed 503, 见 [`probe_exhausted_error`]),
/// 调用方用 `?` 直接传播.
type RedactOutcome = Result<
    (
        RedactionMap,
        u64,
        Vec<(String, String)>,
        Vec<crate::usage::RedactHit>,
    ),
    AppError,
>;

/// 对 IR 应用 redact 并派生 CallEvent.redactions (same_proto / cross_proto 共享).
///
/// `mode` 控制 probing 耗尽时的策略:
/// - [`OnProbeExhausted::FailOpen`] (默认): 耗尽时 warn+skip (向后兼容, 永不 Err).
/// - [`OnProbeExhausted::FailClosed`]: 耗尽时返回 `Err(AppError)` (503, 由
///   [`probe_exhausted_error`] 构造), 调用方 `?` 传播拒绝转发.
///
/// 返回 `(redaction_map, redact_seed, redactions, redact_hits)`. redaction_map 非空时 debug 日志记录命中数.
///
/// 注: disabled secret 的明文放行 WARN (#161) 不在此层 — 挂在 dispatch (raw bytes)
/// 以覆盖透传快捷分支, 见 [`crate::redact::warn_disabled_secrets_in_body`].
pub(super) fn redact_and_derive(
    ir: &mut crate::codec::ir::IrRequest,
    secrets_snapshot: &[crate::secrets::SecretEntry],
    mode: OnProbeExhausted,
    log_tag: &str,
) -> RedactOutcome {
    let (redaction_map, redact_seed) = match redact_ir_checked(ir, secrets_snapshot, mode) {
        Ok(ok) => ok,
        // fail_closed 拒绝转发: 503 错误构造收口在此 (两路径共用同一 log_tag,
        // 消除调用方镜像 match 与 tag 字面量的双写漂移面).
        Err(e) => return Err(probe_exhausted_error(&e, log_tag)),
    };
    if !redaction_map.is_empty() {
        debug!(
            redactions = redaction_map.real_to_mock.len(),
            "redacted secrets in {log_tag} IR"
        );
    }
    let redactions = derive_redactions(&redaction_map, secrets_snapshot);
    // usage 审计派生 (USAGE-7 治理归因): (secret_id, mock, 位置分布), 与
    // derive_redactions 同源 (map SSOT) — mock/id 供落账, locations 供分类.
    let redact_hits = derive_redact_hits(&redaction_map, secrets_snapshot);
    // 视图正确性守卫: redactions 是 RedactionMap (SSOT) 的派生视图, 每次派生都断言不变式.
    // 集中在 helper 内部确保 same_proto / cross_proto 两条路径都覆盖.
    #[cfg(feature = "consistency-check")]
    assert_redactions_match_map(&redactions, &redaction_map, secrets_snapshot);
    Ok((redaction_map, redact_seed, redactions, redact_hits))
}

/// fail_closed 拒绝转发时的 WARN + 客户端 503 错误构造 (redact_and_derive 内部使用).
///
/// 该 503 文案是客户端可见错误 body (SEC-2 同型契约面: 变量部分只含 secret id +
/// reason, 不含 secret 明文) — same_proto / cross_proto 两路径经同一
/// `redact_and_derive` 调用点触达, 文案单点维护. `log_tag` 与
/// [`redact_and_derive`] 的同名参数一致 ("same-proto" / "cross-proto"),
/// 仅用于 WARN 日志的路径归因.
fn probe_exhausted_error(e: &RedactError, log_tag: &str) -> AppError {
    warn!(
        secret_id = %e.secret_id,
        reason = ?e.reason,
        "redact probe exhausted in {log_tag} path; refusing to forward (fail_closed)"
    );
    AppError::Unavailable(format!(
        "redact probe exhausted, secret forwarding refused by policy \
             (on_probe_exhausted=fail_closed); check secret mock_strategy config \
             (secret_id hint: {}, reason: {:?})",
        e.secret_id, e.reason
    ))
}

// ─── 视图正确性守卫 (CI 用, 需 `--features consistency-check`) ─────────────

/// 视图正确性守卫 (CI 用, 需 `--features consistency-check`).
///
/// `redactions` 字段是 `RedactionMap` (SSOT) 的派生视图. 本函数断言派生保持
/// RedactionMap 的关键不变式, 防止未来重构破坏派生一致性. 详见 AGENTS.md
/// "视图正确性确保机制" — "redactions 字段从 RedactionMap 派生" 是该机制的已实践位置.
///
/// 不变式:
/// 1. 派生结果的条目数 == RedactionMap 中命中 secrets_snapshot 的 real 数.
/// 2. 派生结果中每个 mock 都能在 RedactionMap 中反向查到同一 real (双向索引自洽).
/// 3. 派生结果中 mock 唯一 (RedactionMap 按 value 去重, 派生也应去重).
#[cfg(feature = "consistency-check")]
pub(super) fn assert_redactions_match_map(
    derived: &[(String, String)],
    redaction_map: &RedactionMap,
    secrets_snapshot: &[crate::secrets::SecretEntry],
) {
    // (1) 条目数: 派生结果应 == real_to_mock 中命中 snapshot 的 real 数.
    let expected = redaction_map
        .real_to_mock
        .keys()
        .filter(|real| secrets_snapshot.iter().any(|s| &s.value == *real))
        .count();
    debug_assert_eq!(
        derived.len(),
        expected,
        "derived redactions count drift from RedactionMap SSOT"
    );
    // (2) 双向索引自洽: 每个 mock 反查 real, 且该 real 命中 snapshot.
    for (mock, _id) in derived {
        let real = redaction_map.mock_to_real.get(mock);
        debug_assert!(
            real.is_some_and(|r| secrets_snapshot.iter().any(|s| s.value == *r)),
            "derived mock {mock:?} not round-tripping through RedactionMap"
        );
    }
    // (3) mock 唯一 (RedactionMap 按 value 去重).
    let mut mocks: Vec<&String> = derived.iter().map(|(m, _)| m).collect();
    mocks.sort();
    mocks.dedup();
    debug_assert_eq!(
        mocks.len(),
        derived.len(),
        "derived redactions have duplicate mocks"
    );
}

/// 视图正确性守卫 (CI 用, 需 `--features consistency-check`).
///
/// `CallEvent.preview` / `CallEvent.model` 的两种提取路径:
/// - codec 路径: 从 IR 提取 (`extract_preview_and_model_from_ir`), req_body_raw 是 IR 的
///   writer 序列化结果.
/// - passthrough 路径: 从 req_body_raw 字符串提取 (`extract_preview_and_model`).
///
/// 本守卫从 req_body_raw 字符串重新提取, 比对存储的 preview/model. 对 passthrough 天然
/// 一致; 对 codec 路径, 它验证 "IR 提取 == 字符串提取" (writer 忠实序列化 messages).
///
/// 捕获的 drift: writer 改变了 messages 顺序/结构导致 IR 提取与字符串提取不一致.
/// 详见 AGENTS.md "视图正确性确保机制".
#[cfg(feature = "consistency-check")]
pub(super) fn assert_preview_model_match_source(event: &CallEvent) {
    let (rederived_preview, rederived_model) =
        crate::derive::extract_preview_and_model(&event.req_body_raw);
    debug_assert_eq!(
        event.model.as_deref(),
        rederived_model.as_deref(),
        "stored model drifts from req_body_raw SSOT"
    );
    // preview 的 "IR 提取 == 字符串提取" 等价性在 Responses ingress 上**不可定义**:
    // 其 wire 形态用 input[] 而非 messages[] (字符串提取器结构上看不见, 恒 None —
    // 与 "Responses 协议的 timeline delta 为空" 已知限制同根), 而 IR 提取可见.
    // 跳过 preview 比对 (model 是顶层字段, 两路径都可见, 仍比对).
    if event.ingress_protocol != Some(crate::codec::Protocol::OpenAIResponses) {
        debug_assert_eq!(
            event.preview.as_deref(),
            rederived_preview.as_deref(),
            "stored preview drifts from req_body_raw SSOT"
        );
    }
}

/// 视图正确性守卫 (CI 用, 需 `--features consistency-check`).
///
/// `ResponseData.parsed` (非流式) 是上游响应字节的派生视图:
/// 用 codec reader 把 resp_bytes 解析为 [`crate::codec::ir::IrResponse`], 再用 codec writer
/// 序列化为 wire JSON 缓存. 本函数断言派生保持一致 — 重新用 reader 解析 source bytes,
/// 与派生时使用的 IR snapshot 比对.
///
/// 捕获的 drift 类型: 未来若 parsed 改为从其他来源 (如 restore 后的 IR / 客户端响应)
/// 派生, 此守卫会立刻失败. 仅在派生成功路径 (reader 解析成功 + 2xx 成功响应) 触发;
/// fallback 路径 (parse 失败原样透传 / 非 2xx 错误响应) 时 parsed_for_record 为 None,
/// 由调用方负责传入 expected = None 跳过断言. 详见 AGENTS.md "视图正确性确保机制".
#[cfg(feature = "consistency-check")]
pub(super) fn assert_resp_parsed_matches_source_nonstream(
    parsed_for_record: Option<&serde_json::Value>,
    source_bytes: &[u8],
    reader: &dyn crate::codec::Reader,
) {
    // 预期: source_bytes 解析失败 → parsed_for_record 应为 None (fallback 路径, 不比对).
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(source_bytes) else {
        debug_assert!(
            parsed_for_record.is_none(),
            "parsed_for_record set but source bytes are not valid JSON"
        );
        return;
    };
    // reader 解析失败 → parsed_for_record 也应为 None.
    let Ok(ir) = reader.read_response(&v) else {
        debug_assert!(
            parsed_for_record.is_none(),
            "parsed_for_record set but reader fails to parse source bytes"
        );
        return;
    };
    // 成功路径: parsed_for_record 必为 Some. (调用方负责保证仅在派生会生成 parsed 的
    // 路径调用本守卫 — 即 2xx 成功响应. 非 2xx 错误响应即便 reader 能解析, 也不派生 parsed.)
    let Some(parsed) = parsed_for_record else {
        debug_assert!(
            false,
            "source parses successfully but parsed_for_record is None"
        );
        return;
    };
    // model 字段 (字符串) 直接比对 — 这是 IrResponse 中最稳定、最易 drift 的字段.
    // 容许 codec 不对称: 部分 writer 把 None model 写成空串 "" (如 OpenAI writer),
    // 部分 reader 又把 "" 读回 Some(""). 双侧都 normalize 为 None 等价, 避免已知 codec
    // 行为被误报为 drift.
    let parsed_model_norm: Option<&str> = parsed
        .get("model")
        .and_then(|m| m.as_str())
        .filter(|s| !s.is_empty());
    let ir_model_norm: Option<&str> = ir.model.as_deref().filter(|s| !s.is_empty());
    debug_assert_eq!(
        parsed_model_norm, ir_model_norm,
        "parsed.model drifts from IrResponse SSOT (after normalizing None == empty string)"
    );
}

/// 写一条 "上游请求失败" 记录 (错误路径专用 helper).
///
/// 同时打转发摘要 (#160): 上游故障是命令行排障的最高价值场景, 错误终态也必须有
/// INFO 摘要行 (与成功路径的 3 个完成点对齐; 此处是 502/504 错误终态的 choke point).
pub(super) fn record_upstream_failure(
    dag: &ConversationDag,
    record_id: Uuid,
    started: std::time::Instant,
    status: u16,
    error: String,
) {
    dag.attach_response(
        record_id,
        ResponseData {
            resp_status: status,
            resp_headers: vec![],
            elapsed_ms: started.elapsed().as_millis() as u64,
            error: Some(error),
            ..Default::default()
        },
    );
    log_forward_summary(dag, record_id);
}

// ─── 转发可观测性: 摘要日志 (#160) + 协议错配 WARN (#162) ───────────────────

/// #162: 2xx 响应被 reader 宽松解析为空 content + 零 usage 的协议错配 WARN
/// (fan_out / cross_proto 响应解析成功分支共享).
///
/// 强烈的 "provider protocol 与上游实际协议错配" 信号 (典型: anthropic provider
/// 指到 OpenAI 端点, reader 对缺字段 unwrap_or_default 降级, 字段全落空).
/// 行为不变 (仍翻译返回), 仅打 WARN. 协议名只作结构化字段 `protocol`
/// (两路径统一字段名, 便于 grep), 不在消息文案里重复插值.
pub(super) fn warn_if_protocol_mismatch(
    record_id: Uuid,
    proto_name: &str,
    ir_resp: &crate::codec::ir::IrResponse,
    is_success: bool,
) {
    if is_success && ir_resp.content.is_empty() && ir_resp.usage.is_zero() {
        warn!(
            %record_id,
            protocol = proto_name,
            "upstream 2xx response parsed to empty content and zero usage; \
              does the upstream actually speak the expected protocol? \
              (check provider protocol vs upstream shape)"
        );
    }
}

/// #158: 响应 parse 失败 fallback 时的 mock-not-restored WARN (共享 helper).
///
/// 本请求做过 redact (map 非空) 且响应走 parse 失败 fallback (原样透传, 无 restore)
/// 时, body 中的 mock 不会被还原 — 客户端拿到假 secret. 记一条 WARN 让该逃逸
/// 可感知 (行为不变: 仍原样透传, best-effort 原则).
///
/// 调用方: fan_out_buffered_ir 的两个 fallback 分支 (reader 拒绝 / 非 JSON) +
/// cross_proto 非流式翻译的对称分支 (#158 补全, AGENTS.md "后续工作" 登记项).
pub(super) fn warn_mock_not_restored(record_id: Uuid, redaction_map: &RedactionMap, detail: &str) {
    if !redaction_map.is_empty() {
        warn!(
            %record_id,
            detail,
            "response parse failed with redactions in flight; \
             mock not restored; client will see mock values"
        );
    }
}

/// 每笔转发完成 (record 最终态写入后) 打一行 INFO 摘要 (#160: 命令行排障).
///
/// 形如 `forward method=POST path=/o/p1/v1/chat/completions status=200
/// elapsed_ms=123 redactions=1 provider=p1 streamed=false complete=true`.
/// 字段全部从 DAG node 派生 (经 [`ConversationDag::forward_summary_fields`],
/// 只读标量不 clone parsed view — 该路径每请求执行一次, 必须轻量).
/// provider id 从 path 第二段解析 (`/{proto}/{provider}/...`, 与 ForwardPath
/// 同构; cross_proto 的 path 带尾部 " [a → b]" 注释, 落在后续段不影响 nth(2)).
///
/// 安全: 字段均来自路由/元数据, 永不含 secret 值 (redactions 只记条数).
///
/// 调用点 (record 终态 choke points): fanout_stream_task (两条流式路径) /
/// fan_out_buffered_ir / cross_proto 正常收尾 / record_upstream_failure
/// (502/504 错误终态) / cross_proto 中途流错误与 cap 分支.
///
/// 流式请求在流结束 (attach_response 最终态) 时打, 而非响应头到达时 —
/// 保证 elapsed_ms 覆盖完整流时长, 且 record 尚未落盘的错误能带上.
pub(super) fn log_forward_summary(dag: &ConversationDag, record_id: Uuid) {
    let Some(f) = dag.forward_summary_fields(record_id) else {
        return;
    };
    let provider = f.path.split('/').nth(2).unwrap_or("?");
    info!(
        %record_id,
        method = %f.method,
        path = %f.path,
        status = f.resp_status,
        elapsed_ms = f.elapsed_ms,
        redactions = f.redactions,
        provider = %provider,
        streamed = f.streamed,
        complete = f.resp_complete,
        error = ?f.error,
        "forward"
    );
}

/// 发送上游请求, 可选地对"响应头到达"加超时保护. 失败时记录到 DAG 并返回 AppError.
///
/// `header_timeout = None` 时退化为普通 `send().await` (向后兼容 / 测试场景).
/// `Some(d)` 时用 `tokio::time::timeout` 包裹 send, 超时记 504 record.
///
/// 错误映射: reqwest 网络错误 → 502 (BAD_GATEWAY); 响应头超时 → 504 (GATEWAY_TIMEOUT).
/// 504 让 WebUI 区分 "上游不可达" vs "上游 hang" 两种运维场景.
///
/// 三个 forward 路径 (passthrough / same_proto / cross_proto) 共用此 helper.
///
/// 注: 这层超时**只约束响应头到达**, 不影响后续流式 body 的总时长
/// (流式 body 的 chunk 空闲超时见 next_chunk 的 idle_timeout).
pub(super) async fn send_upstream_or_fail(
    dag: &ConversationDag,
    record_id: Uuid,
    started: std::time::Instant,
    request_builder: reqwest::RequestBuilder,
    header_timeout: Option<std::time::Duration>,
) -> Result<reqwest::Response, crate::error::AppError> {
    let send_fut = request_builder.send();
    // Result<Response, Either<reqwest::Error, Elapsed>> — 用 nested Result 表达三态.
    let raw: Result<reqwest::Response, Result<reqwest::Error, std::time::Duration>> =
        match header_timeout {
            None => send_fut.await.map_err(Ok),
            Some(d) => match tokio::time::timeout(d, send_fut).await {
                Ok(Ok(r)) => Ok(r),
                Ok(Err(e)) => Err(Ok(e)),
                Err(_elapsed) => Err(Err(d)),
            },
        };
    match raw {
        Ok(r) => Ok(r),
        Err(Ok(e)) => {
            // reqwest 网络错误 (连接拒绝 / DNS / TLS 等) → 502.
            // record 侧保留完整错误串; 客户端 502 body message 用净化后的可读原因
            // (#163: 让 SDK 用户能区分网关故障 vs 上游故障并定位是哪个上游).
            let msg = format!("upstream send error: {e}");
            record_upstream_failure(dag, record_id, started, 502, msg);
            Err(crate::error::AppError::Upstream(upstream_error_brief(&e)))
        }
        Err(Err(d)) => {
            // 响应头超时 → 504.
            let msg = format!("upstream response headers not received within {:?}", d);
            record_upstream_failure(dag, record_id, started, 504, msg);
            Err(crate::error::AppError::UpstreamTimeout(format!(
                "upstream timeout (no response headers within {:?})",
                d
            )))
        }
    }
}

/// 把 reqwest 网络错误净化为一句可安全回传客户端的可读原因 (#163).
///
/// 形如 `upstream error: http://127.0.0.1:29999/v1/chat (tcp connect error:
/// Connection refused (os error 111))`. 信息泄露策略 (SEC 纪律, 见 error.rs 头部):
/// - URL 只保留 `scheme://host:port/path`: **防御性丢弃 userinfo / query / fragment**
///   (上游 URL 的 query 可能携带 api_key 类参数, 即使当前 provider 配置不含也不能赌).
/// - 根因取 error `source()` 链最深层 (如 "tcp connect error: Connection refused"),
///   比首层 Display ("error sending request for url (...)") 更具体且天然不含 URL.
///
/// 与 record 侧 (`record_upstream_failure` 保留完整 `e.to_string()`) 分工: record 是
/// 本地 WebUI 视图可含完整细节; 本函数的产物会进 502 响应 body 回传客户端.
pub(super) fn upstream_error_brief(e: &reqwest::Error) -> String {
    let root = root_error_cause(e);
    match e.url() {
        Some(u) => format!("upstream error: {} ({root})", safe_url_for_client(u)),
        None => format!("upstream error: {root}"),
    }
}

/// 沿 `source()` 链走到底, 取最深层的 Display (最具体的一层, 如 io/TCP 错误).
fn root_error_cause(e: &reqwest::Error) -> String {
    let mut cur: &dyn std::error::Error = e;
    while let Some(next) = cur.source() {
        cur = next;
    }
    cur.to_string()
}

/// URL → `scheme://host:port/path` (丢弃 userinfo / query / fragment).
///
/// 消费方: [`upstream_error_brief`] (502 body) 与 [`safe_url_for_log`]
/// (debug 日志脱敏, SEC-C4).
fn safe_url_for_client(u: &reqwest::Url) -> String {
    let mut s = format!("{}://", u.scheme());
    if let Some(host) = u.host_str() {
        s.push_str(host);
    }
    if let Some(port) = u.port() {
        s.push_str(&format!(":{port}"));
    }
    s.push_str(u.path());
    s
}

/// 字符串 URL 的脱敏入口 (SEC-C4): 剥离 userinfo / query / fragment 后返回
/// 可安全写日志的形态. 复用 [`safe_url_for_client`] 的剥离逻辑.
///
/// 用途: same_proto 两处 `debug!(url = ...)` — 上游 URL 可能携带客户端 query
/// (如 Gemini `?key=...`), 原样打日志会把 secret 泄露到 debug 输出.
/// 解析失败的防御性降级: 至少按首个 `?` 剥掉 query (输入是内部拼接的 URL,
/// 异常形态仅理论可能; 剥 query 保证降级路径也不携带敏感参数).
pub(super) fn safe_url_for_log(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(u) => safe_url_for_client(&u),
        Err(_) => url
            .split_once('?')
            .map(|(head, _)| head)
            .unwrap_or(url)
            .to_string(),
    }
}

/// 从上游 stream 取下一个 chunk, 可选地带空闲超时保护.
///
/// `idle_timeout = None`: 退化为 `stream.next().await` (向后兼容).
/// `Some(d)`: 每个 chunk 等待最多 d, 超时则日志 warn 并返回 `Some(Err(TimedOut))`,
/// 让 caller 走 upstream error 路径标记 record incomplete.
///
/// 返回 `None` = stream 正常结束; `Some(Ok(_))` / `Some(Err(_))` = 有数据或错误.
/// 防御 "上游发了响应头但 body chunk 卡住" 的 hang 形态.
pub(super) async fn next_chunk<S>(
    stream: &mut S,
    idle_timeout: Option<std::time::Duration>,
    record_id: &uuid::Uuid,
) -> Option<Result<bytes::Bytes, std::io::Error>>
where
    S: futures::Stream<Item = reqwest::Result<bytes::Bytes>> + Unpin,
{
    let fut = stream.next();
    match idle_timeout {
        None => fut.await.map(|r| r.map_err(io_err_from_reqwest)),
        Some(d) => match tokio::time::timeout(d, fut).await {
            Ok(inner) => inner.map(|r| r.map_err(io_err_from_reqwest)),
            Err(_elapsed) => {
                tracing::warn!(
                    %record_id,
                    timeout = ?d,
                    "upstream stream chunk idle timeout"
                );
                Some(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    ERR_STREAM_IDLE_TIMEOUT,
                )))
            }
        },
    }
}

/// reqwest::Error → std::io::Error 转换 (stream 循环统一用 io::Error 便于 mpsc 传递).
pub(super) fn io_err_from_reqwest(e: reqwest::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// io::Error → record error label (区分 idle timeout 与其他 stream error).
///
/// 三个 fan_out 路径共用此分类, 保证 client_status 推断 (504 vs 502) 一致.
/// idle timeout (io::ErrorKind::TimedOut) → ERR_STREAM_IDLE_TIMEOUT → 504;
/// 其他 stream error → ERR_UPSTREAM_STREAM → 502.
pub(super) fn stream_err_label(e: &std::io::Error) -> &'static str {
    if e.kind() == std::io::ErrorKind::TimedOut {
        ERR_STREAM_IDLE_TIMEOUT
    } else {
        ERR_UPSTREAM_STREAM
    }
}

/// 构造 [`CallEvent`] (3 个 push 点共用).
///
/// `secrets_snapshot = None` 表示 passthrough 路径 (无机密命中), 用空 policy + seed=0.
/// `secrets_snapshot = Some(s)` 表示 codec 路径, policy 持有真实 secret 列表 (COW Arc).
///
/// `req_text` 是已 redact 的请求 body 快照 (LLM 视角), **按值接收** 直接 move 进
/// `req_body_raw` (WebUI req_body 权威来源) — 调用方不再保留则零拷贝
/// (IR 路径用 `serde_json::to_string` 产 String; passthrough 路径一次
/// `from_utf8_lossy`, 外部输入可能是非法 UTF-8).
/// `ir = Some(&ir)` (codec 路径): preview/model 从已 parse 的 IR 提取 (零重复 JSON parse).
/// `ir = None` (passthrough 路径): 从 req_text 字符串提取 (passthrough 不 parse IR 保持 byte-exact).
/// `upstream_id`: 实际承载转发的 provider id (路由解析后的链尾实体, #179).
/// `upstream_model`: 实际改写的 model 值 (仅 override 实际注入 IR 时 Some; passthrough
/// / 无 codec 降级路径恒 None, #183 D4 — 非 None-ness 即 "本轮被 override" 的信号).
#[allow(clippy::too_many_arguments)]
pub(super) fn build_call_event(
    parts: &axum::http::request::Parts,
    path: &str,
    fwd_headers: &HeaderMap,
    req_text: String,
    ir: Option<&crate::codec::ir::IrRequest>,
    ingress_protocol: Option<crate::codec::Protocol>,
    upstream_id: &str,
    upstream_model: Option<&str>,
    redact_seed: u64,
    secrets_snapshot: Option<&[crate::secrets::SecretEntry]>,
    redactions: Vec<(String, String)>,
) -> CallEvent {
    let (preview, model) = match ir {
        Some(ir) => crate::derive::extract_preview_and_model_from_ir(ir),
        None => crate::derive::extract_preview_and_model(&req_text),
    };
    let policy = match secrets_snapshot {
        Some(s) => std::sync::Arc::new(PolicySnapshot {
            secrets: std::sync::Arc::from(s.to_vec()),
        }),
        None => std::sync::Arc::new(PolicySnapshot::default()),
    };
    let event = CallEvent {
        created_at: chrono::Utc::now(),
        method: parts.method.as_str().to_string(),
        path: path.to_string(),
        req_headers: redact_headers(fwd_headers),
        ingress_protocol,
        redact_seed,
        policy,
        req_body_raw: req_text,
        preview: preview.map(std::sync::Arc::<str>::from),
        model: model.map(std::sync::Arc::<str>::from),
        upstream_id: std::sync::Arc::from(upstream_id),
        upstream_model: upstream_model.map(std::sync::Arc::<str>::from),
        // round_role 占位值 (User); DAG push_messages 内部会根据 delta 的 contains_user_text 修正.
        round_role: crate::codec::ir::IrRole::User,
        // round_kind 占位值 (Normal); push_messages 内按 split_at 修正 (全前缀重复 → Retry).
        round_kind: crate::dag::RoundKind::Normal,
        redactions: std::sync::Arc::from(redactions),
    };
    // 视图正确性守卫: preview/model 应与 req_body_raw (SSOT) 的字符串提取一致.
    // codec 路径从 IR 提取, req_body_raw 是 IR 的 writer 序列化 — 两者应等价 (writer 忠实
    // 序列化 messages). passthrough 路径直接从 req_body_raw 提取, 天然一致.
    #[cfg(feature = "consistency-check")]
    assert_preview_model_match_source(&event);
    event
}

// ─── 响应累积器 (fan_out 三路径共享) ───────────────────────────────────────

/// 上游响应字节的记录累积器 (fan_out_* 三路径共享).
///
/// 职责: 把上游 chunk 流累积到一个 `Vec<u8>`, 受 `MAX_RESP_BODY_RECORD` 上限保护,
/// 并跟踪 overflow / error_kind 状态. 三个 fan_out 函数原本各自复制 ~30 行相同逻辑,
/// 现统一在此. 调用方负责 chunk 的"额外处理"(透传给客户端 channel / StreamTranslate /
/// ParsedSync), 本结构只管 record 累积 + cap 保护.
///
/// # 内存开销 (followup: 改 Vec<Bytes> 分片)
///
/// `acc` 用连续 `Vec<u8>` 而非 `Vec<Bytes>` 分片, 因为 `fan_out_buffered_ir` 路径
/// 必须连续字节做 `serde_json::from_slice` 解析. 副作用: `fan_out_streaming` 的
/// streamed=true && 2xx 路径里, `acc` 只写不读 (body 用 `String::new()`, parsed 来自
/// ParsedSync), 理论上最大 `MAX_RESP_BODY_RECORD` (32 MiB) 是纯浪费. 不改的原因:
/// streamed=true && 非 2xx 路径需读 acc (utf8_view 错误回显); overflow 标志控制
/// ParsedSync 停止 (改结构需联动); consistency-check 守卫 + 多处测试直接访问 acc.len
/// (fan_out.rs ~12 处 + record.rs test ~3 处). blast radius 较大 (~15-20 处), 当前留作
/// followup. 32MiB 在大响应场景才触发, 非热路径.
///
/// # 不变式
///
/// - overflow 一旦置位, 后续 push 静默丢弃 (record 已截断, 不再增长).
/// - error_kind 一旦置位 (非 None), 表示流异常终止 (client disconnect / upstream error / cap).
pub(super) struct RecordAccumulator {
    pub(super) acc: Vec<u8>,
    pub(super) overflow: bool,
    pub(super) error_kind: Option<String>,
}

impl RecordAccumulator {
    pub(super) fn new() -> Self {
        Self {
            acc: Vec::new(),
            overflow: false,
            error_kind: None,
        }
    }

    /// 累积一个 chunk. 超过 `MAX_RESP_BODY_RECORD` 时置 overflow 标志 (后续静默丢弃).
    /// 仅在未 overflow 时累积, 避免无意义的拷贝.
    pub(super) fn push_record(&mut self, b: &[u8], record_id: Uuid) {
        if self.overflow {
            return;
        }
        let remaining = super::MAX_RESP_BODY_RECORD.saturating_sub(self.acc.len());
        if remaining > 0 {
            let take = remaining.min(b.len());
            self.acc.extend_from_slice(&b[..take]);
        }
        if b.len() > remaining {
            warn!(
                %record_id,
                cap = super::MAX_RESP_BODY_RECORD,
                "response too large to record; further chunks discarded"
            );
            self.overflow = true;
        }
    }

    /// 标记流异常终止 (client disconnect / upstream stream error / cap).
    pub(super) fn set_error(&mut self, kind: &str) {
        self.error_kind = Some(kind.to_string());
    }

    /// 是否已正常结束 (无 error_kind).
    pub(super) fn complete(&self) -> bool {
        self.error_kind.is_none()
    }
}

/// 流式 parsed view 累积器 + 节流写入 DAG 的小封装.
///
/// 三条流式扇出路径 (fan_out_streaming / fan_out_streaming_with_restore /
/// fan_out_streaming_cross_proto) 共享同一套节流策略, 避免多处重复 StreamScan +
/// writer + last_sync 的管理逻辑 (同协议路径经 [`Self::new`], 跨协议路径经
/// [`Self::new_cross_proto`] 分离 scan/writer 协议).
pub(super) struct ParsedSync {
    scan: crate::codec::stream::StreamScan,
    writer: Box<dyn crate::codec::Writer>,
    dag: ConversationDag,
    record_id: Uuid,
    last_sync: Option<std::time::Instant>,
}

/// IrResponse "scan 零语义事件" 判定: 事件层的所有字段均未被观测过.
///
/// Responses 协议的 `read_response_events` 未实现 (恒返回空事件), 流式 scan 永远
/// 零事件; OpenAI/Anthropic 正常流的首个事件即携带 model/id 或 block. 零事件时
/// `write_response` 会产出 "合成 id + 空 output + status completed" 的畸形 parsed
/// view (凭空捏造响应元数据, DTO 派生纪律禁止) — 调用方据此降级为 `None`
/// (前端降级占位).
fn scan_decoded_nothing(ir: &crate::codec::ir::IrResponse) -> bool {
    ir.content.is_empty()
        && ir.model.is_none()
        && ir.id.is_none()
        && ir.created.is_none()
        && ir.stop_reason.is_none()
        && ir.stop_sequence.is_none()
        && !ir.usage_present
}

impl ParsedSync {
    pub(super) fn new(
        proto: crate::codec::Protocol,
        dag: ConversationDag,
        record_id: Uuid,
    ) -> Self {
        Self::new_cross_proto(proto, proto, dag, record_id)
    }

    /// 参数化构造: `scan_proto` 解析上游 (egress) SSE 字节, `writer_proto` 序列化
    /// parsed view. 跨协议流式路径两者不同 (scan 用 egress reader, 序列化用
    /// ingress writer — 与非流式 cross_proto 的 resp_parsed 语义一致, WebUI 按
    /// ingress codec 解析); 同协议路径传相同值 (经 [`Self::new`]).
    pub(super) fn new_cross_proto(
        scan_proto: crate::codec::Protocol,
        writer_proto: crate::codec::Protocol,
        dag: ConversationDag,
        record_id: Uuid,
    ) -> Self {
        Self {
            scan: crate::codec::stream::StreamScan::new(scan_proto),
            writer: writer_proto.writer(),
            dag,
            record_id,
            last_sync: None,
        }
    }

    /// 喂入上游 chunk; 按节流间隔把 snapshot 写入 DAG node 的 parsed 字段.
    /// 零语义事件 (如 Responses 流) 不写 — 捏造空响应对象违反派生纪律,
    /// 由 [`Self::finalize`] 统一降级 None.
    pub(super) fn feed(&mut self, b: &[u8]) {
        self.scan.feed(b);
        let due = self
            .last_sync
            .is_none_or(|t| t.elapsed() >= PARSED_SYNC_INTERVAL);
        if due {
            let parsed = self.scan.snapshot();
            if scan_decoded_nothing(&parsed) {
                // 仍记录 last_sync: 零事件流的每次 snapshot 都是空, 无需重试判定.
                self.last_sync = Some(std::time::Instant::now());
                return;
            }
            self.dag
                .update_parsed_response(self.record_id, self.writer.write_response(&parsed));
            self.last_sync = Some(std::time::Instant::now());
        }
    }

    /// 流结束时的最终快照 (parsed view + 回显摘要, usage-stats 采集一并产出).
    /// 零语义事件时 parsed 为 `None` (前端降级占位, 不捏造空响应对象).
    pub(super) fn finalize(self) -> (Option<serde_json::Value>, ResponseEcho) {
        let ir = self.scan.snapshot();
        let echo = ResponseEcho::from_ir(&ir);
        if scan_decoded_nothing(&ir) {
            return (None, echo);
        }
        (Some(self.writer.write_response(&ir)), echo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── M-C4: derive_redactions / derive_redact_hits 投影一致性 ────────────
    //
    // 两投影共享 derive_redact_hits 的单次 join (M-C4 去重后 redactions 从 hits
    // 派生). 本测试锁定关联不变式: 对同一 (map, snapshot) 输入, redactions 的
    // (mock, secret_id) 集合与 hits 的 (mock, secret_id) 集合逐对相等 — 防未来
    // 重构让两投影各自维护 join 再次分叉.

    #[test]
    fn redaction_projections_agree_on_mock_secret_pairing() {
        use crate::redact::RedactionMap;
        use crate::secrets::{SecretCategory, SecretEntry};

        fn entry(id: &str, value: &str) -> SecretEntry {
            SecretEntry {
                id: id.into(),
                name: None,
                category: SecretCategory::ApiKey,
                value: value.into(),
                value_file: None,
                mock_strategy: crate::mock::MockStrategy::default(),
            }
        }

        let mut map = RedactionMap::default();
        // 两条命中映射 + 一条未命中 (snapshot 无对应 secret, 不进任何投影).
        for (real, mock) in [("real-A", "mock-A"), ("real-B", "mock-B")] {
            map.real_to_mock.insert(real.into(), mock.into());
            map.mock_to_real.insert(mock.into(), real.into());
        }
        map.real_to_mock
            .insert("real-NOHIT".into(), "mock-NOHIT".into());
        // 共享 value 边角: sid-A2 与 sid-A 同 value → first-match 语义只投影
        // 一个 id (doc 声明的行为, 防 join 方向被反转为 snapshot-iter 后退化).
        let snapshot = vec![
            entry("sid-A", "real-A"),
            entry("sid-A2", "real-A"),
            entry("sid-B", "real-B"),
        ];

        let redactions = derive_redactions(&map, &snapshot);
        let hits = derive_redact_hits(&map, &snapshot);

        let mut expected: Vec<(String, String)> = hits
            .iter()
            .map(|h| (h.mock.clone(), h.secret_id.clone()))
            .collect();
        expected.sort();
        let mut actual = redactions;
        actual.sort();
        assert_eq!(
            actual, expected,
            "redactions' (mock, secret_id) pairings must equal hits'"
        );
        // 共享 value 去重: 每条映射只投影一次 (first-match), 总数仍为 2 而非 3.
        assert_eq!(actual.len(), 2);
        assert_eq!(hits.len(), 2);
        assert!(
            actual.contains(&("mock-A".into(), "sid-A".to_string())),
            "shared-value first-match must pick the earlier entry: {actual:?}"
        );
        assert!(
            !actual.iter().any(|(_, id)| id == "sid-A2"),
            "duplicate-value entry must be deduplicated away: {actual:?}"
        );
        assert!(
            !actual.iter().any(|(m, _)| m.contains("NOHIT")),
            "unmatched real must not project"
        );
    }

    // ─── stream_err_label: 504/502 分类 SSOT ───────────────────────────────
    //
    // stream_err_label 是 "idle timeout → 504 / 其他 → 502" 判定的 SSOT
    // (fan_out 三路径 + cross_proto 的 client_status 推断共用). 锁定两类分支.

    #[test]
    fn stream_err_label_distinguishes_timeout_from_other_errors() {
        let timed_out = std::io::Error::new(std::io::ErrorKind::TimedOut, "idle");
        assert_eq!(stream_err_label(&timed_out), ERR_STREAM_IDLE_TIMEOUT);
        let other = std::io::Error::other("upstream reset");
        assert_eq!(stream_err_label(&other), ERR_UPSTREAM_STREAM);
    }

    // ─── SEC-C4b: safe_url_for_log 的 query 剥离 ───────────────────────────
    //
    // debug 日志的 URL 脱敏入口 (same_proto 两处消费). 锁定 Ok 路径 (经
    // safe_url_for_client 剥 userinfo/query/fragment) 与解析失败 fallback
    // (至少剥 query) 两个分支.

    #[test]
    fn safe_url_for_log_strips_query_and_fallback_strips_query() {
        // Ok 路径: query (可能带 ?key=...) 与 userinfo 被剥离.
        assert_eq!(
            safe_url_for_log("https://api.example.com/v1/chat?key=leak-me"),
            "https://api.example.com/v1/chat"
        );
        // 解析失败 fallback (空 host 是非法 URL): 仍按首个 '?' 剥 query.
        assert_eq!(
            safe_url_for_log("http://:///path?api_key=leak-me"),
            "http://:///path"
        );
    }

    // ─── #163: 502 message 净化 (payload 进客户端错误 body, 信息泄露 SSOT 纪律) ──
    //
    // 契约 (issue #163): 502 body 的 message 填可读原因 (url host:port + 根因),
    // 且不得带 provider api_key / secret 内容. 单测覆盖净化函数的两个维度
    // (根因提取 + URL 剥离); 端到端 (连接拒绝 → body 文本) 由集成测试
    // upstream_unreachable_502_body_carries_readable_cause 锁定.

    #[test]
    fn safe_url_strips_userinfo_query_fragment() {
        let u: reqwest::Url = "https://user:pass@host.example:8443/pa/th?q=secret#frag"
            .parse()
            .unwrap();
        assert_eq!(
            safe_url_for_client(&u),
            "https://host.example:8443/pa/th",
            "userinfo/query/fragment must be stripped"
        );
    }

    #[test]
    fn safe_url_keeps_scheme_host_port_path() {
        let u: reqwest::Url = "http://127.0.0.1:29999/v1/chat/completions"
            .parse()
            .unwrap();
        assert_eq!(
            safe_url_for_client(&u),
            "http://127.0.0.1:29999/v1/chat/completions"
        );
        // 无显式 port 时不追加 :port (scheme 默认端口).
        let u2: reqwest::Url = "https://api.example.com/v1".parse().unwrap();
        assert_eq!(safe_url_for_client(&u2), "https://api.example.com/v1");
    }

    /// 语义锁定: reqwest::Error 首 layer 的 Display 含 URL 且描述宽泛
    /// ("error sending request for url (...)"), 而根因在 source 链最深层.
    /// 本测试连接死端口构造真实 reqwest 错误 (与生产 502 同型), 断言净化函数
    /// 取的是最深层根因 (含 "connection refused"), 且 URL 部分已剥离 query.
    #[test]
    fn upstream_error_brief_picks_root_cause_and_sanitized_url() {
        use std::error::Error as _;
        // 手工构造三层 source 链: reqwest 错误的 url() 来自 builder, 这里用
        // reqwest 真实错误构造最贴近生产: 连接一个死端口 (与集成测试同型).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let err = rt.block_on(async {
            // bind 后立刻 drop: 保证该端口无 listener (connection refused 确定性触发).
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            drop(l);
            reqwest::get(format!("http://{addr}/v1/chat?key=leak-me"))
                .await
                .expect_err("dead port must produce reqwest error")
        });
        // 根因在 source 链最深层, 且比首层 Display 更具体.
        // (io 错误文案大小写随平台: Linux "Connection refused", 断言用小写不敏感.)
        let first_layer = err.to_string();
        let brief = upstream_error_brief(&err);
        assert!(
            brief.to_lowercase().contains("connection refused"),
            "brief must carry the root cause, got: {brief}"
        );
        // 首 layer 的 Display 形如 "error sending request for url (...)" — 不含根因.
        // (锁定语义: 若未来 reqwest 改变 Display 形态, 此断言提醒重评 root_error_cause.)
        assert!(
            !first_layer.to_lowercase().contains("connection refused"),
            "first-layer Display unexpectedly carries root cause: {first_layer}"
        );
        // query (可能携带 key) 必须被剥离.
        assert!(
            !brief.contains("leak-me"),
            "brief must not carry query string: {brief}"
        );
        assert!(
            brief.contains(&err.url().unwrap().host_str().unwrap().to_string()),
            "brief must name the upstream host for diagnosis: {brief}"
        );
        // source 链不为空 (root_error_cause 确实走了 >1 层).
        assert!(err.source().is_some(), "reqwest error should be layered");
    }

    // ─── MAX_RESP_BODY_RECORD 截断契约 (核心契约: 客户端响应无上限 vs record 有 cap) ─
    //
    // 契约 (proxy//!): "客户端响应永远无大小上限; 只有 record 累积受
    // MAX_RESP_BODY_RECORD (32 MiB) 约束". 一旦回归会静默截断用户响应.

    #[test]
    fn max_resp_body_record_constant_is_32mib() {
        // pin 住常量值, 防止误改 (这是经济性与内存的折中, 32MiB 覆盖绝大多数 LLM 响应).
        assert_eq!(super::super::MAX_RESP_BODY_RECORD, 32 * 1024 * 1024);
        assert_eq!(super::super::MAX_REQ_BODY, 16 * 1024 * 1024);
    }

    #[test]
    fn truncation_banner_string_is_stable() {
        // pin 住 banner 文本, 前端依赖它识别截断状态. 三个 fan_out 共用同一字符串.
        let banner = super::super::TRUNCATED_BANNER;
        assert!(!banner.is_empty());
    }

    #[test]
    fn record_accumulator_caps_and_marks_overflow() {
        let mut acc = RecordAccumulator::new();
        // 推入超 cap 的 chunk: 应截断到 cap 并置 overflow.
        let huge = vec![b'x'; super::super::MAX_RESP_BODY_RECORD + 10];
        acc.push_record(&huge, Uuid::nil());
        assert!(acc.overflow, "overflow must be set when chunk exceeds cap");
        assert_eq!(
            acc.acc.len(),
            super::super::MAX_RESP_BODY_RECORD,
            "acc must be capped at MAX_RESP_BODY_RECORD"
        );
        // 后续 push 被静默丢弃 (overflow 已置位).
        let before = acc.acc.len();
        acc.push_record(b"y", Uuid::nil());
        assert_eq!(acc.acc.len(), before, "post-overflow push must be dropped");
    }

    #[test]
    fn record_accumulator_tracks_error_and_completeness() {
        let mut acc = RecordAccumulator::new();
        assert!(acc.complete(), "fresh accumulator is complete");
        acc.set_error(ERR_CLIENT_DISCONNECTED);
        assert!(!acc.complete(), "after error, not complete");
        assert_eq!(acc.error_kind.as_deref(), Some(ERR_CLIENT_DISCONNECTED));
    }

    // ─── ParsedSync: 零语义事件流降级 None (DTO 派生纪律: 不捏造响应) ──────
    //
    // Responses 的 read_response_events 未实现 (恒返回空事件): map 空 + stream 的
    // Responses 请求放行 SSE 字节透传后 (#183 D5 收窄), ParsedSync 对这类流
    // accumulate 零事件 — write_response 会捏造 "合成 id + 空 output + completed"
    // 的畸形对象. 锁定: 零事件 → parsed None + echo 无回显; 有事件 → Some 照常.

    #[test]
    fn parsed_sync_responses_stream_decodes_to_none() {
        let dag = ConversationDag::new(4, 8, 1);
        let mut ps = ParsedSync::new(
            crate::codec::Protocol::OpenAIResponses,
            dag.clone(),
            Uuid::nil(),
        );
        // Responses 流式 SSE fixture (事件层语义真实, 但 reader 不解任何事件).
        ps.feed(b"event: response.output_text.delta\n");
        ps.feed(b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hi\"}\n\n");
        ps.feed(b"event: response.completed\n");
        ps.feed(b"data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":5}}}\n\n");
        let (parsed, echo) = ps.finalize();
        assert!(
            parsed.is_none(),
            "zero-event scan must degrade to None, got {parsed:?}"
        );
        assert!(
            echo.usage.is_none(),
            "usage must not be fabricated from undecoded events"
        );
        assert!(echo.model.is_none());
        // feed 路径也不得把捏造对象写进 DAG (节点无 parsed 字段或 None).
        // (此 fixture 的 record_id 不存在于 dag, update 被吞 — 单独覆盖见下个测试.)
    }

    #[test]
    fn parsed_sync_feed_zero_events_does_not_write_dag() {
        let dag = ConversationDag::new(4, 8, 1);
        // 先 push 一个节点, 让 update_parsed_response 有真实落点.
        let event = CallEvent {
            created_at: chrono::Utc::now(),
            method: "POST".to_string(),
            path: "/r/x/v1/responses".to_string(),
            req_headers: vec![],
            ingress_protocol: None,
            redact_seed: 0,
            policy: std::sync::Arc::new(PolicySnapshot::default()),
            req_body_raw: String::new(),
            round_role: crate::codec::ir::IrRole::User,
            round_kind: crate::dag::RoundKind::Normal,
            preview: None,
            model: None,
            upstream_id: std::sync::Arc::from("test"),
            redactions: std::sync::Arc::from([]),
            upstream_model: None,
        };
        let id = dag.push_messages(vec![], event);
        let mut ps = ParsedSync::new(crate::codec::Protocol::OpenAIResponses, dag.clone(), id);
        ps.feed(b"data: {\"type\":\"response.created\"}\n\n");
        // 零事件: parsed 绝不能是捏造的 "空 output + completed" 对象
        // (节点可能尚无 ResponseData — 两种形态都合法, Some(捏造对象) 不合法).
        let fabricated = dag
            .get_response(id)
            .and_then(|r| r.parsed)
            .filter(|p| p.get("object").and_then(|o| o.as_str()) == Some("response"));
        assert!(
            fabricated.is_none(),
            "feed must not write a fabricated empty response: {:?}",
            fabricated
        );
    }

    #[test]
    fn parsed_sync_openai_stream_decodes_to_some() {
        let dag = ConversationDag::new(4, 8, 1);
        let mut ps = ParsedSync::new(crate::codec::Protocol::OpenAI, dag, Uuid::nil());
        // OpenAI 流式 chunk (带 model/id), reader 会解码出 MessageStart + 增量.
        ps.feed(b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hi\"}}]}\n\n");
        ps.feed(b"data: [DONE]\n\n");
        let (parsed, echo) = ps.finalize();
        let parsed = parsed.expect("decoded OpenAI stream must yield Some parsed view");
        let content = parsed
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or_default();
        assert_eq!(content, "Hi", "parsed view carries decoded text: {parsed}");
        assert_eq!(echo.model.as_deref(), Some("gpt-4o"));
    }

    // ─── SEC-3: assert/panic 消息不泄漏 secret ───────────────────────────
    //
    // 契约 (docs/design/contracts.md §7 SEC-3): 任何 assert / panic 消息不得包含
    // secret 明文. 视图正确性守卫 (assert_redactions_match_map 等) 在 CI 下用
    // `debug_assert!` 守卫派生视图与 SSOT 的一致性; 这些 assert 的诊断消息由派生数据
    // 构成 (mock / id 等), 不应直接内联 secret value. 本 property 故意制造不一致触发
    // assert, 用 catch_unwind 捕获 panic payload, 断言其字符串表示不含 secret value.
    //
    // 仅在 consistency-check feature 下运行 (assert 函数仅在该 feature 编译).
    #[cfg(feature = "consistency-check")]
    use proptest::prelude::*;

    #[cfg(feature = "consistency-check")]
    proptest! {
        /// SEC-3: assert_redactions_match_map 触发 panic 时, 消息不含 secret.value.
        ///
        /// 触发方式: 构造一个"派生 redactions 条目数 > RedactionMap 命中数"的不一致
        /// (derived 含一条 mock, 但 redaction_map 为空 + snapshot 含 secret), 让断言 (1)
        /// `debug_assert_eq!(derived.len(), expected)` 失败. panic 消息由
        /// `derived.len()` / `expected` (1 位数字) + 固定字面量构成, 不含 secret value.
        ///
        /// 字符集 `[a-zA-Z0-9_\-]{6,40}`: 覆盖真实 secret 形态 (sk-abc / ghp_xxx /
        /// 混合大小写). panic 消息的数字 run 极短 (left=1/right=0, 各 1 位), 固定句式
        /// ("derived redactions count drift ...") 不含随机长字符串, 英文单词子串假阳性
        /// 概率可忽略. 若未来断言消息内联随机值 (如 mock/id), 需重评估字符集.
        #[test]
        fn prop_assert_messages_no_secret(secret in "[a-zA-Z0-9_\\-]{6,40}") {
            use crate::redact::RedactionMap;
            use crate::secrets::{SecretCategory, SecretEntry};

            // 派生 redactions 含一条"假命中" (mock / id 都用固定值, 不内联 secret —
            // 模拟生产派生层只含 mock + secret_id, 永不内联 secret value).
            let derived = vec![(String::from("mock-fake"), String::from("sid-fake"))];

            // 空 RedactionMap + snapshot 含真实 secret: expected = 0 (map 空), 但
            // derived.len() = 1 → 断言 (1) `debug_assert_eq!(derived.len(), expected)` 失败.
            // snapshot 含 secret 模拟生产 (policy 持有 secret value), 但派生层不应泄漏.
            // id 用固定字面量 (不内联 secret), 避免人为把 secret 塞进 snapshot 数据结构.
            let map = RedactionMap::default();
            let snapshot = vec![SecretEntry {
                id: String::from("sid-fake"),
                name: None,
                category: SecretCategory::ApiKey,
                value: secret.clone(),
                value_file: None,
                mock_strategy: crate::mock::MockStrategy::default(),
            }];

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_redactions_match_map(&derived, &map, &snapshot);
            }));
            let payload = result.expect_err(
                "inconsistent derived/map must trigger debug_assert panic under consistency-check"
            );
            // panic payload 通常是 &'static str 或 String; 取其字符串表示.
            // 若 payload 是非字符串类型 (如未来某个 panic!(some_struct)), 拒绝 fallback
            // 到固定字面量 — 那会让断言恒真 (字面量不含 secret), 使 SEC-3 property 空洞
            // 通过, 静默放过安全漏洞. 必须 fail-loud 暴露 payload 类型不可检视的问题.
            let msg = payload
                .downcast_ref::<String>()
                .map(|s| s.as_str())
                .or_else(|| payload.downcast_ref::<&'static str>().copied())
                .unwrap_or_else(|| panic!(
                    "SEC-3 cannot inspect non-string panic payload (type id: {:?}); \
                     refusing to pass vacuously — this would silently hide secret leakage",
                    (*payload).type_id()
                ));
            prop_assert!(
                !msg.contains(secret.as_str()),
                "SEC-3 violation: assert panic message leaks secret. msg={}",
                msg
            );
        }
    }
}
