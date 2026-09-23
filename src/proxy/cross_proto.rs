//! 跨协议转发路径 (ingress != egress): codec 翻译 + redact.
//!
//! # 职责边界
//!
//! ingress 协议 → IR → egress 协议, 上游响应反向翻译. 与 same_proto 的差异:
//! - 流式响应 (2xx + SSE): StreamTranslate 跨协议模式实时翻译 (可选 restore),
//!   经 mpsc 扇出管道回传 (见 `fan_out::fan_out_streaming_cross_proto`).
//! - 应用 redact (在 IR 层, 不与 codec 翻译冲突). redact 场景的流式响应经
//!   StreamRestoreHook 做响应侧 mock→real (与非流式的 `restore_ir_response` 对称).
//! - 上游错误响应 (4xx/5xx) 也通过 codec 翻译为 ingress 协议的原生错误 envelope.
//!
//! # 范围与限制
//!
//! codec 覆盖族内 (openai/anthropic/openairesponses) 任意 pair 的翻译 — 非流式经
//! 通用 IR 路径, 流式经 StreamTranslate — 均已承载 (含 Responses 参与的 pair,
//! 双向各有集成测试锁定).

use std::time::Instant;

use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode};
use bytes::Bytes;
use tracing::{debug, warn};

use crate::dag::ResponseData;
use crate::error::AppError;
use crate::provider::{DirectProvider, Endpoint, Protocol};

use super::auth::ANTHROPIC_VERSION;
use super::auth::apply_provider_auth;
use super::helpers::{
    build_response_headers, is_streaming, redact_headers, sanitize_request_headers, utf8_view,
};
#[cfg(feature = "consistency-check")]
use super::recorder::assert_resp_parsed_matches_source_nonstream;
use super::recorder::{
    build_call_event, parse_request_ir, push_event_and_wire_usage, redact_and_derive,
};

/// 跨协议转发: ingress 协议 → IR → egress 协议, 上游响应反向翻译.
///
/// # 路径选择 (响应侧)
///
/// - `ir.stream == true` + 2xx + Content-Type 是 SSE: 流式翻译扇出
///   (`fan_out_streaming_cross_proto`), redact 场景注入 restore hook.
/// - 其余 (非流式请求 / 非 2xx / 非 SSE): 完整 buffer 后一次性翻译 (非流式语义).
///   流式请求但上游返回非 SSE 时打 WARN (与 same_proto 判型处对称).
/// - 上游错误响应 (4xx/5xx) 也通过 codec 翻译为 ingress 协议的原生错误 envelope.
///
/// # 限制
///
/// - codec 覆盖族内 (openai/anthropic/responses) 任意 pair (流式与非流式) 均可翻译;
///   gemini/ollama 任一侧 → 501 (`Protocol::from_native` 返回 None).
/// - **应用 redact**: 跨协议 + redact 通过 [`crate::redact::redact_ir`] 在 IR 层做替换,
///   不会与 codec 翻译冲突. 响应侧: 非流式经 `restore_ir_response`, 流式经
///   StreamTranslate 的 restore hook (mock→real, RED-7).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn cross_proto_forward(
    state: crate::state::AppState,
    fp: super::ForwardPath,
    parts: axum::http::request::Parts,
    req_bytes: Bytes,
    ingress: Protocol,
    provider: DirectProvider,
    endpoint: Endpoint,
    upstream_id: &str,
    model_rewrite: Option<String>,
    started: Instant,
    secrets_snapshot: Vec<crate::secrets::SecretEntry>,
    pool_watch: Option<crate::pool::PoolWatch>,
) -> Result<Response<Body>, AppError> {
    use crate::codec::Protocol as CodecProtocol;

    // egress 协议 = 选定端点的协议 (multi-endpoint: fallback 时即首端点协议,
    // 与 ingress 不同的语义前提由 dispatch 的 exact=false 保证).
    let egress = endpoint.protocol;

    // 1. 检查 codec 是否支持此协议对.
    let Some(ingress_codec) = CodecProtocol::from_native(ingress) else {
        return Err(AppError::NotImplemented(format!(
            "ingress protocol '{}' is not supported by codec (only openai/anthropic/openairesponses)",
            ingress.name()
        )));
    };
    let Some(egress_codec) = CodecProtocol::from_native(egress) else {
        return Err(AppError::NotImplemented(format!(
            "egress protocol '{}' is not supported by codec (only openai/anthropic/openairesponses)",
            egress.name()
        )));
    };

    let ingress_reader = ingress_codec.reader();
    let ingress_writer = ingress_codec.writer();
    let egress_writer = egress_codec.writer();

    // 2-3. 解析 ingress body → IR (共享 helper).
    let mut ir = parse_request_ir(
        &req_bytes,
        ingress,
        ingress_reader.as_ref(),
        model_rewrite.as_deref(),
    )?;

    // 4. 若 egress 要求 max_tokens 而 IR 缺失, 注入默认值.
    if egress_writer.requires_max_tokens() && ir.max_tokens.is_none() {
        ir.max_tokens = Some(crate::codec::DEFAULT_MAX_TOKENS);
    }

    // 5. 清空 ingress-only 元数据:
    //    - extra: ingress-only 字段会泄漏到 egress, 一并清空. (注: Responses 的
    //      hosted tools 不在 extra — tools 是 modeled 字段被 collect_extra 排除,
    //      丢弃发生在 reader 读取时并在该处 WARN, 见 responses.rs read_request)
    //    - wire_fidelity (stop_form / content_form / tools_present): ingress wire 形态
    ir.extra.clear();
    ir.clear_wire_fidelity();

    // 6. 快照真实 messages (redact 前) 给 DAG.
    let real_messages = ir.messages.clone();

    // 7. redact IR + derive redactions (共享 helper, 内含 consistency-check 守卫).
    //    FailClosed 模式下 probing 耗尽时 redact_and_derive 内部构造 503 并在此
    //    `?` 拒绝转发 (防 secret 泄露).
    let (redaction_map, redact_seed, redactions, redact_hits) = redact_and_derive(
        &mut ir,
        &secrets_snapshot,
        state.on_probe_exhausted,
        "cross-proto",
    )?;

    // 8. IR → egress body. (T5: 请求侧 ReasoningContent blocks 会被 egress writer
    //    丢弃 (#176, 见 count_reasoning_blocks 假设声明) — 计数, WARN 在步骤 11 后
    //    record_id 就位时打.)
    let dropped_req_reasoning = count_reasoning_blocks(&ir.system)
        + ir.messages
            .iter()
            .map(|m| count_reasoning_blocks(&m.content))
            .sum::<usize>();
    let egress_body_value = egress_writer.write_request(&ir);
    let egress_bytes = serde_json::to_vec(&egress_body_value)
        .map_err(|e| AppError::Internal(format!("serialize egress body failed: {e}")))?;

    // 9. 构造上游 URL: 三段式 `base + effective_common_uri + request_uri`
    //    (egress writer 的 request_uri 不含版本前缀; 中段由端点布局决定 —
    //    显式 common_uri 优先, 缺省按 base 尾段启发式, #260: 旧行为硬编码
    //    "/v1" 前缀对版本段已含的上游 (智谱 coding plan / DeepSeek /
    //    opencode zen 等) 拼出双版本段 404).
    let upstream_url = format!(
        "{}{}{}",
        endpoint.base_url,
        endpoint.effective_common_uri(),
        egress_writer.upstream_path()
    );

    // 10. 复制请求 headers + 应用 egress 协议的 auth.
    let mut fwd_headers = sanitize_request_headers(&parts.headers);
    fwd_headers.remove(axum::http::header::CONTENT_TYPE);
    fwd_headers.remove(axum::http::header::CONTENT_LENGTH);
    apply_provider_auth(
        &mut fwd_headers,
        &provider.effective_api_key(upstream_id),
        egress,
    );
    // 跨协议时客户端不会自带 egress 协议的特定 header, 这里仅在缺失时注入默认.
    // 用 entry().or_insert() 而非 insert(), 保留客户端主动设置更新的版本的能力.
    // 版本值收口在 auth::ANTHROPIC_VERSION (与 models.rs 的 fetch 共享, M-C3).
    if egress == Protocol::Anthropic {
        fwd_headers
            .entry("anthropic-version")
            .or_insert_with(|| HeaderValue::from_static(ANTHROPIC_VERSION));
    }

    // 11. push 到 DAG.
    let path_for_record = format!(
        "/{}/{}/{}  [{} → {}]",
        fp.proto,
        fp.name,
        fp.rest.trim_start_matches('/'),
        ingress.name(),
        egress.name()
    );
    // 用 redact 后的 IR 经 ingress writer 重序列化作为 record body (而非原始 req_bytes).
    // 理由与 same_proto_forward 一致: record 应保存 "redact 后的视图" (LLM 看到的版本),
    // 而非客户端原始 body (可能含未 redact 的真实 secret). 这里用 ingress writer 而非
    // egress writer, 让 WebUI 的 parsed view 能用 ingress codec 正确 round-trip 解析.
    // writer 输出恒为合法 UTF-8, 直接产 String 按值 move 进 record (req_body_raw),
    // 消除 to_vec → lossy copy → to_string 拷贝链 (PERF-C2).
    let req_view_value = ingress_writer.write_request(&ir);
    let req_text_for_record = serde_json::to_string(&req_view_value)
        .map_err(|e| AppError::Internal(format!("serialize ingress view body failed: {e}")))?;
    let event = build_call_event(
        &parts,
        &path_for_record,
        &fwd_headers,
        &state.redacted_headers,
        req_text_for_record,
        Some(&ir),
        Some(ingress_codec),
        upstream_id,
        model_rewrite.as_deref(),
        redact_seed,
        Some(&secrets_snapshot),
        redactions,
    );
    let (record_id, usage_ctx) = push_event_and_wire_usage(
        &state,
        &fp,
        &parts,
        upstream_id,
        real_messages,
        event,
        &secrets_snapshot,
        &redact_hits,
    );

    // T5: 跨协议丢弃可观测性 — 计数在丢弃点 (步骤 8 请求历史 / 步骤 15 响应) 已算,
    // record_id 此刻才产生, WARN 延后到这里打 (只记计数, 绝不记内容).
    // reasoning = IrBlock::ReasoningContent (思考原文); hosted tools 的丢弃 WARN
    // 不在此处 — 在 responses.rs reader 丢弃点 (见步骤 5 注释).
    if dropped_req_reasoning > 0 {
        warn!(
            %record_id,
            count = dropped_req_reasoning,
            "dropping reasoning block(s) from request history in cross-protocol translation"
        );
    }

    debug!(
        %record_id,
        method = %parts.method,
        url = %upstream_url,
        ingress = %ingress.name(),
        egress = %egress.name(),
        "cross-proto forwarding"
    );

    // 12. 发送到上游. 响应头超时按流式语义选档 (#175): ir.stream 是 writer 产出的
    //     egress body 真实语义 (该 body 发往上游) — 流式请求走 TTFT 档, 非流式走
    //     整响应档, 与 same_proto 路径同构.
    let upstream_resp = super::recorder::send_upstream_or_fail(
        &state.dag,
        record_id,
        started,
        state
            .upstream
            .request(parts.method, &upstream_url)
            .headers(fwd_headers)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header(axum::http::header::CONTENT_LENGTH, egress_bytes.len())
            .body(egress_bytes),
        state.upstream_timeouts.header_timeout(ir.stream),
    )
    .await?;

    // 13. 判型: 流式请求 + 2xx + SSE → 跨协议流式翻译扇出 (mpsc 管道, 不 buffer);
    //     其余 (非流式请求 / 非 2xx / 非 SSE) 落入下方 buffered 翻译路径.
    //     假设: 上游对 stream=true 的 2xx 响应 Content-Type 是 text/event-stream;
    //     不成立时 (如上游不支持流式返回整 JSON) 走 buffered 翻译 + WARN 降级,
    //     不让请求失败 (best-effort).
    let resp_status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let content_type = super::helpers::response_content_type(&resp_headers);
    let streamed = is_streaming(content_type);
    // 流式翻译管道只会重组 SSE 帧 (空行分帧), 判型用比 is_streaming 更窄的
    // is_sse — is_streaming 额外放行的 application/x-ndjson 进翻译会产出空流,
    // 应落 buffered.
    let sse_upstream = super::helpers::is_sse(content_type);
    // 判型 WARN: 2xx 但非 SSE 才是异常信号 (上游无视流式请求); 非 2xx 是常态
    // 错误流 (4xx/5xx JSON body), 不打 WARN 防噪音. 与 same_proto 判型处 (#158,
    // 按 redact 在飞门控) 差异: 跨协议所有响应都经翻译, 2xx 非流式无论有无
    // redact 都意味着 "客户端要流式却拿到整块", 信号本身值得保留.
    if ir.stream && resp_status.is_success() && !streamed {
        warn!(
            %record_id,
            provider = %upstream_id,
            content_type = %content_type,
            "upstream returned non-SSE content-type for a stream=true cross-proto \
             request; falling back to buffered translation"
        );
    }
    if ir.stream && resp_status.is_success() && sse_upstream {
        return super::fan_out::fan_out_streaming_cross_proto(
            state.dag.clone(),
            record_id,
            started,
            upstream_resp,
            resp_status,
            resp_headers,
            state.redacted_headers.clone(),
            ingress_codec,
            egress_codec,
            redaction_map,
            state.upstream_timeouts.stream_idle,
            usage_ctx,
        )
        .await;
    }

    // 14. 完整 buffer 上游响应 (非流式 / 非 2xx / 非 SSE 判型降级). 受 MAX_RESP_BODY_RECORD 上限保护.
    let resp_bytes: Bytes = {
        let mut acc: Vec<u8> = Vec::new();
        let mut stream = upstream_resp.bytes_stream();
        let mut exceeded = false;
        let mut stream_err: Option<std::io::Error> = None;
        while let Some(chunk) = super::recorder::next_chunk(
            &mut stream,
            state.upstream_timeouts.stream_idle,
            &record_id,
        )
        .await
        {
            match chunk {
                Ok(b) => {
                    if acc.len() + b.len() > super::MAX_RESP_BODY_RECORD {
                        exceeded = true;
                        break;
                    }
                    acc.extend_from_slice(&b);
                }
                Err(e) => {
                    stream_err = Some(e);
                    break;
                }
            }
        }
        // 14.5 Pool 耗尽旁路检测 (T2): 上游原文 (resp_status / resp_headers /
        // 已累积的 acc) 在翻译前检测 — 用原文而非翻译后的 ingress envelope;
        // 只读副本, 翻译 (步骤 15) 与检测互不相干 (FWD-1). 位置在两个早退
        // return (stream_err / cap) **之前**: 流中断时 acc 是部分字节, code
        // 通道 best-effort 降级, status/header 通道不受影响 — 与同协议
        // buffered_ir 路径的 error_kind 场景行为对称。
        if let Some(watch) = &pool_watch {
            watch.detect_and_mark(resp_status, &resp_headers, &acc);
        }
        if let Some(e) = stream_err {
            let err_label = super::recorder::stream_err_label(&e);
            let elapsed = started.elapsed().as_millis() as u64;
            warn!(%record_id, error = %e, err = err_label, "cross-proto upstream stream error mid-flight");
            state.dag.attach_response(
                record_id,
                ResponseData {
                    resp_status: resp_status.as_u16(),
                    resp_headers: redact_headers(&resp_headers, &state.redacted_headers),
                    elapsed_ms: elapsed,
                    error: Some(err_label.to_string()),
                    resp_complete: false,
                    streamed: false,
                    ..Default::default()
                },
            );
            // usage-stats: 响应头已到达但流中断 → 计请求数, 无回显 (USAGE-4).
            usage_ctx.record_response(resp_status.as_u16(), false, None, None);
            // 摘要 (#160): 错误终态也打 (choke point 之一).
            super::recorder::log_forward_summary(&state.dag, record_id);
            // 区分 idle timeout (504) 与其他 stream error (502), 与同协议路径一致.
            // 复用已算出的 err_label (stream_err_label 是 timeout 判定的 SSOT).
            // 客户端 message 只用 err_label (固定字面量) — e 的 to_string 含完整上游
            // URL (io_err_from_reqwest 内嵌), 不能进客户端 body (SEC 纪律, #163).
            return Err(if err_label == super::recorder::ERR_STREAM_IDLE_TIMEOUT {
                AppError::UpstreamTimeout(err_label.to_string())
            } else {
                AppError::Upstream(err_label.to_string())
            });
        }
        if exceeded {
            warn!(%record_id, cap = super::MAX_RESP_BODY_RECORD, "cross-proto upstream response exceeded cap; aborting");
            let msg = format!(
                "upstream response exceeded {} byte cap",
                super::MAX_RESP_BODY_RECORD
            );
            super::recorder::record_upstream_failure(
                &state.dag,
                record_id,
                started,
                502,
                msg.clone(),
            );
            // usage-stats: 响应头已到达但超 cap 中止 → 计请求数, 无回显.
            usage_ctx.record_response(resp_status.as_u16(), false, None, None);
            return Err(AppError::Upstream(msg));
        }
        Bytes::from(acc)
    };

    // 15. 翻译响应: egress JSON → IR → (restore redact) → ingress JSON.
    let egress_reader = egress_codec.reader();
    let ingress_writer = ingress_codec.writer();
    // parsed view: 记录 LLM 视角的 IR (restore 之前, 含 mock). 仅 2xx 成功响应.
    let mut resp_parsed_for_record: Option<serde_json::Value> = None;
    // usage-stats 回显摘要 (restore 前提取, 语义同 fan_out_buffered_ir).
    let mut resp_echo = super::recorder::ResponseEcho::default();
    let (resp_status_out, resp_body_out): (StatusCode, Vec<u8>) = if resp_status.is_success() {
        match serde_json::from_slice::<serde_json::Value>(&resp_bytes) {
            Ok(v) => match egress_reader.read_response(&v) {
                Ok(mut ir_resp) => {
                    // #162: 协议错配 WARN (空 content + 零 usage 启发式, 共享 helper).
                    super::recorder::warn_if_protocol_mismatch(
                        record_id,
                        egress.name(),
                        &ir_resp,
                        resp_status.is_success(),
                    );
                    // T5: 响应侧 ReasoningContent blocks 会被 ingress writer 丢弃
                    // (#176), 计数告警 (同请求侧, 只记计数不记内容).
                    let dropped_resp_reasoning = count_reasoning_blocks(&ir_resp.content);
                    if dropped_resp_reasoning > 0 {
                        warn!(
                            %record_id,
                            count = dropped_resp_reasoning,
                            "dropping reasoning block(s) from response in cross-protocol translation"
                        );
                    }
                    // record 存 LLM 视角 (restore 之前, 含 mock) 的 parsed view.
                    resp_echo = super::recorder::ResponseEcho::from_ir(&ir_resp);
                    resp_parsed_for_record = Some(ingress_writer.write_response(&ir_resp));
                    // restore: mock → real (跨协议 + redact 时, 客户端看到的应该是真 secret).
                    crate::redact::restore_ir_response(&mut ir_resp, &redaction_map);
                    let translated = ingress_writer.write_response(&ir_resp);
                    let body = serde_json::to_vec(&translated).unwrap_or_default();
                    (resp_status, body)
                }
                Err(e) => {
                    warn!(%record_id, error = %e.message, "failed to parse upstream response as {}; passing through verbatim", egress.name());
                    // RED-8 / SEC-10: reader 拒绝但 body 仍是合法 JSON — 共享兜底
                    // 决策序列 (helpers SSOT, 与 fan_out_buffered_ir 对称;
                    // on_fallback_restore: withhold 保留 Mock / restore 兜底还原).
                    let mut v = v;
                    (
                        resp_status,
                        super::helpers::restore_via_json_leaf_fallback(
                            record_id,
                            &mut v,
                            &resp_bytes,
                            "codec reader rejected response",
                            &redaction_map,
                            state.on_fallback_restore,
                        ),
                    )
                }
            },
            Err(e) => {
                // 非 JSON body: 叶子级兜底以单 JSON Value 为前提, 对同一字节再 parse
                // 必然同样失败 — 不再尝试, 直接透传 (已知限制). 此前完全静默 —
                // 补 WARN (已知限制条目明说要补的 mock-not-restored 信号;
                // 无 redaction 在途时只是普通透传, 不打).
                super::helpers::warn_mock_not_restored(
                    record_id,
                    &format!("response body is not a single JSON value ({e})"),
                    &redaction_map,
                );
                (resp_status, resp_bytes.to_vec())
            }
        }
    } else {
        // 错误响应: 截断 + 解析上游 error.message 防止泄漏内部细节.
        let friendly = serde_json::from_slice::<serde_json::Value>(&resp_bytes)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| raw_error_snippet(&resp_bytes));
        let kind = http_status_to_error_kind(resp_status.as_u16());
        let envelope = ingress_writer.write_error(resp_status.as_u16(), kind, &friendly);
        let body = serde_json::to_vec(&envelope).unwrap_or_default();
        (resp_status, body)
    };

    // 16. attach 响应到 DAG.
    let elapsed = started.elapsed().as_millis() as u64;
    // 视图正确性守卫: resp_parsed (非流式) 是 resp_bytes (SSOT) 经 egress reader 的派生视图.
    // 仅在 2xx 成功响应时触发 — 非 2xx 错误响应即便 reader 能解析也不派生 parsed
    // (走 envelope 翻译路径), 守卫对 None 比对会误报.
    #[cfg(feature = "consistency-check")]
    if resp_status.is_success() {
        assert_resp_parsed_matches_source_nonstream(
            resp_parsed_for_record.as_ref(),
            &resp_bytes,
            egress_reader.as_ref(),
        );
    }
    state.dag.attach_response(
        record_id,
        ResponseData {
            resp_status: resp_status_out.as_u16(),
            resp_headers: redact_headers(&resp_headers, &state.redacted_headers),
            // 视角语义注意: 与 fan_out_buffered_ir ("LLM 视角, 含 mock") 不同, 这里
            // raw_resp_body 沿用 master 起的客户端视角 (翻译 + restore 后的出站字节) —
            // DAG OriginRecord 本就按真值存储, 无安全边界问题, 仅为两条路径语义
            // 不一致的显式声明 (WebUI raw view 在 cross-proto 下展示真 secret).
            raw_resp_body: utf8_view(&resp_body_out),
            parsed: resp_parsed_for_record,
            elapsed_ms: elapsed,
            // 判型结果 (上游响应是否 SSE-shaped) — 客户端实际收到的是 buffered 翻译
            // (非流式回传), 但 record 的 streamed 语义与 same_proto 家族一致: 记录
            // 上游响应形态 (非 2xx SSE 错误体落在此路径时为 true).
            streamed,
            resp_complete: true,
            usage: resp_echo.usage.clone(),
            model: resp_echo.model.clone(),
            ..Default::default()
        },
    );
    // usage-stats 落账 (USAGE-5 计入判据在 ctx 内统一执行).
    usage_ctx.record_response(
        resp_status_out.as_u16(),
        true,
        resp_echo.usage,
        resp_echo.model,
    );
    // record 最终态写入后打摘要 (#160).
    super::recorder::log_forward_summary(&state.dag, record_id);

    // 17. 构造响应.
    let mut resp = Response::new(Body::from(resp_body_out));
    *resp.status_mut() = resp_status_out;
    let mut out_headers = build_response_headers(&resp_headers);
    out_headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    out_headers.remove(axum::http::header::CONTENT_LENGTH);
    *resp.headers_mut() = out_headers;
    Ok(resp)
}

/// 把 HTTP status 映射为 protocol-agnostic error kind 字符串.
fn http_status_to_error_kind(status: u16) -> &'static str {
    match status {
        400 => "invalid_request_error",
        401 => "authentication_error",
        403 => "permission_denied",
        404 => "not_found_error",
        429 => "rate_limit_error",
        500..=599 => "api_error",
        _ => "internal_error",
    }
}

/// 错误响应 body 解析不出 `error.message` 时的回退 message: 原始字节按 UTF-8
/// 尽力解释 (非法 UTF-8 → 空串), 截断到 [`super::MAX_ERROR_MSG_LEN`] 字节.
///
/// 契约 (ROB-1): 截断切点必须落在 char boundary — 上游 body 是任意字节, 多字节
/// 字符上直切字节偏移会 panic, 掐断整个连接.
fn raw_error_snippet(resp_bytes: &[u8]) -> String {
    let raw = std::str::from_utf8(resp_bytes).unwrap_or("");
    crate::util::truncate_str_on_char_boundary(raw, super::MAX_ERROR_MSG_LEN).to_string()
}

/// 统计 block 切片中 [`IrBlock::ReasoningContent`] (思考原文, #176) 的数量,
/// 递归含 ToolResult.content (writer 的 block 写出对任何位置统一跳过, 计数同构).
/// 请求侧调用点: `ir.system` + 各 `ir.messages[].content`; 响应侧: `ir_resp.content`.
///
/// # 假设声明 (计数 ⇒ 实际丢弃)
///
/// 跨协议时 egress/ingress writer 对 ReasoningContent 返回 None (Anthropic thinking
/// block 需要 signature / Responses reasoning item 依赖 encrypted_content, 均无法从
/// 思考原文合法合成). 当前支持矩阵下会**生产**此 block 的 ingress 只有 OpenAI
/// (assistant 历史回传 / 响应的 `reasoning_content` 字段), 其跨协议目标
/// (anthropic / responses writer) 均丢弃 — count > 0 ⇒ 实际丢弃. OpenAI writer 虽
/// 保留 (assistant message / response), 但 anthropic / responses ingress 不生产此
/// block, 不构成误报; 新增协议 reader 时需复核此假设 (届时应把 "egress 是否丢弃"
/// 提为 Writer capability 而非在本模块硬编码).
fn count_reasoning_blocks(blocks: &[crate::codec::ir::IrBlock]) -> usize {
    blocks
        .iter()
        .map(|b| match b {
            crate::codec::ir::IrBlock::ReasoningContent { .. } => 1,
            crate::codec::ir::IrBlock::ToolResult { content, .. } => {
                count_reasoning_blocks(content)
            }
            _ => 0,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::{count_reasoning_blocks, http_status_to_error_kind, raw_error_snippet};
    use crate::codec::ir::IrBlock;

    /// ROB-1: 错误响应 body 含多字节字符且超过 MAX_ERROR_MSG_LEN 时, 截断切点
    /// 会落在字符中间 — 不得 panic (历史 bug: 字节偏移直切 `raw[..cap]`).
    ///
    /// 构造: "错" (3 bytes/char) × 2000 = 6000 bytes; 4096 = 3×1365 + 1, 切点
    /// 4096 落在第 1366 个字符 (span 4095..4098) 内部.
    #[test]
    fn raw_error_snippet_truncates_multibyte_on_char_boundary() {
        let body = "错".repeat(2000);
        let s = raw_error_snippet(body.as_bytes());
        // 不 panic 且是合法 UTF-8 (类型即保证); 截断发生在 char boundary.
        assert!(s.len() < body.len(), "必须发生截断");
        assert_eq!(
            s.len(),
            3 * 1365,
            "4096 floor 到最近的 char boundary = 4095"
        );
        assert!(s.chars().all(|c| c == '错'), "不得出现残缺字符");
        // 未超限时原样保留 (含 ASCII 快速路径).
        assert_eq!(raw_error_snippet(b"short error"), "short error");
        // 非法 UTF-8 → 空串 (与既有行为一致).
        assert_eq!(raw_error_snippet(&[0xff, 0xfe]), "");
    }

    /// 覆盖所有 match 分支, 确保 status → kind 映射完整且稳定.
    /// (错误 kind 字符串暴露给客户端 envelope, 改动属契约性变更, 测试守卫之.)
    #[test]
    fn http_status_to_error_kind_covers_all_branches() {
        let cases: &[(u16, &str)] = &[
            (400, "invalid_request_error"),
            (401, "authentication_error"),
            (403, "permission_denied"),
            (404, "not_found_error"),
            (429, "rate_limit_error"),
            (500, "api_error"),
            (502, "api_error"),
            (599, "api_error"),
            // fallthrough 分支: 未在表中列出的 status 统一归为 internal_error.
            (200, "internal_error"),
            (302, "internal_error"),
            (600, "internal_error"),
        ];
        for (status, expected) in cases {
            assert_eq!(
                http_status_to_error_kind(*status),
                *expected,
                "status {status}"
            );
        }
    }

    // ─── T5 纯函数: 跨协议丢弃计数 ────────────────────────────────────────

    /// count_reasoning_blocks: 只计 ReasoningContent (思考原文), 不计 Reasoning
    /// (Responses summary) / Text 等其他 variant; 递归 ToolResult.content.
    #[test]
    fn count_reasoning_blocks_counts_only_reasoning_content_recursively() {
        let blocks = vec![
            IrBlock::Text {
                text: "user text".into(),
            },
            IrBlock::ReasoningContent {
                text: "thinking...".into(),
            },
            IrBlock::Reasoning {
                summary: vec!["summary 不是思考原文".into()],
            },
            IrBlock::ToolResult {
                tool_use_id: "tu_1".into(),
                content: vec![
                    IrBlock::Text { text: "ok".into() },
                    IrBlock::ReasoningContent {
                        text: "nested thinking".into(),
                    },
                ],
                is_error: false,
                content_form: None,
            },
            IrBlock::ReasoningContent {
                text: "trailing".into(),
            },
        ];
        // 顶层 2 个 + ToolResult 嵌套 1 个 = 3; Reasoning(summary) 不计.
        assert_eq!(count_reasoning_blocks(&blocks), 3);
        assert_eq!(count_reasoning_blocks(&[]), 0);
    }
}
