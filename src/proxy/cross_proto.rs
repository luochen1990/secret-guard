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
//! 只支持 OpenAI ⇄ Anthropic 双向流式/非流式. Responses (ingress 或 egress) 的
//! 流式仍返回 501 — 其 `read_response_events` 未实现, 放行会翻译出空流
//! (同 same_proto 路径的 Responses 流式 501, #183 D5).

use std::time::Instant;

use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode};
use bytes::Bytes;
use tracing::{debug, warn};

use crate::dag::ResponseData;
use crate::error::AppError;
use crate::provider::{DirectProvider, Protocol};

use super::auth::ANTHROPIC_VERSION;
use super::auth::apply_provider_auth;
use super::helpers::{
    build_response_headers, is_streaming, redact_headers, sanitize_request_headers, utf8_view,
};
#[cfg(feature = "consistency-check")]
use super::recorder::assert_resp_parsed_matches_source_nonstream;
use super::recorder::{build_call_event, parse_request_ir, redact_and_derive};

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
/// - 只支持 OpenAI ⇄ Anthropic 双向 (其他组合返回 501).
/// - **Responses (ingress 或 egress) + stream=true → 501**: Responses 流式 SSE
///   事件翻译未实现 (`read_response_events` 返回空), 放行会静默产出空流.
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
    upstream_id: &str,
    model_rewrite: Option<String>,
    started: Instant,
    secrets_snapshot: Vec<crate::secrets::SecretEntry>,
) -> Result<Response<Body>, AppError> {
    use crate::codec::Protocol as CodecProtocol;

    // 1. 检查 codec 是否支持此协议对.
    let Some(ingress_codec) = CodecProtocol::from_native(ingress) else {
        return Err(AppError::NotImplemented(format!(
            "ingress protocol '{}' is not supported by codec (only openai/anthropic)",
            ingress.name()
        )));
    };
    let Some(egress_codec) = CodecProtocol::from_native(provider.protocol) else {
        return Err(AppError::NotImplemented(format!(
            "egress protocol '{}' is not supported by codec (only openai/anthropic)",
            provider.protocol.name()
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

    // 4. 流式: OpenAI ⇄ Anthropic 已接入 (StreamTranslate 跨协议模式 + 流式扇出);
    //    Responses (ingress 或 egress) 仍 501 — 其 read_response_events 未实现
    //    (返回空), 放行会静默翻译出空流. 文案与 same_proto 路径的 Responses 流式
    //    501 同风格 (#183 D5).
    if ir.stream
        && (ingress_codec == CodecProtocol::OpenAIResponses
            || egress_codec == CodecProtocol::OpenAIResponses)
    {
        return Err(AppError::NotImplemented(format!(
            "streaming cross-protocol ({ingress} → {}) is not yet supported \
             (Responses SSE event translation unimplemented); disable stream=true \
             in the client request",
            provider.protocol.name()
        )));
    }

    // 5. 若 egress 要求 max_tokens 而 IR 缺失, 注入默认值.
    if egress_writer.requires_max_tokens() && ir.max_tokens.is_none() {
        ir.max_tokens = Some(crate::codec::DEFAULT_MAX_TOKENS);
    }

    // 6. 清空 ingress-only 元数据:
    //    - extra: ingress-only 字段会泄漏到 egress
    //    - wire_fidelity (stop_form / content_form / tools_present): ingress wire 形态
    ir.extra.clear();
    ir.clear_wire_fidelity();

    // 7. 快照真实 messages (redact 前) 给 DAG.
    let real_messages = ir.messages.clone();

    // 8. redact IR + derive redactions (共享 helper, 内含 consistency-check 守卫).
    //    FailClosed 模式下 probing 耗尽时 redact_and_derive 内部构造 503 并在此
    //    `?` 拒绝转发 (防 secret 泄露).
    let (redaction_map, redact_seed, redactions, redact_hits) = redact_and_derive(
        &mut ir,
        &secrets_snapshot,
        state.on_probe_exhausted,
        "cross-proto",
    )?;

    // 9. IR → egress body.
    let egress_body_value = egress_writer.write_request(&ir);
    let egress_bytes = serde_json::to_vec(&egress_body_value)
        .map_err(|e| AppError::Internal(format!("serialize egress body failed: {e}")))?;

    // 10. 构造上游 URL (egress writer 的固定 path).
    let upstream_url = format!("{}{}", provider.base_url, egress_writer.upstream_path());

    // 11. 复制请求 headers + 应用 egress 协议的 auth.
    let mut fwd_headers = sanitize_request_headers(&parts.headers);
    fwd_headers.remove(axum::http::header::CONTENT_TYPE);
    fwd_headers.remove(axum::http::header::CONTENT_LENGTH);
    apply_provider_auth(
        &mut fwd_headers,
        &provider.effective_api_key(upstream_id),
        provider.protocol,
    );
    // 跨协议时客户端不会自带 egress 协议的特定 header, 这里仅在缺失时注入默认.
    // 用 entry().or_insert() 而非 insert(), 保留客户端主动设置更新的版本的能力.
    // 版本值收口在 auth::ANTHROPIC_VERSION (与 models.rs 的 fetch 共享, M-C3).
    if provider.protocol == Protocol::Anthropic {
        fwd_headers
            .entry("anthropic-version")
            .or_insert_with(|| HeaderValue::from_static(ANTHROPIC_VERSION));
    }

    // 12. push 到 DAG.
    let path_for_record = format!(
        "/{}/{}/{}  [{} → {}]",
        fp.proto,
        fp.name,
        fp.rest.trim_start_matches('/'),
        ingress.name(),
        provider.protocol.name()
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
        req_text_for_record,
        Some(&ir),
        Some(ingress_codec),
        upstream_id,
        model_rewrite.as_deref(),
        redact_seed,
        Some(&secrets_snapshot),
        redactions,
    );
    // usage-stats 采集上下文 + redact 审计落账 (helpers SSOT: 请求侧, redact 已
    // 实际发生, 即使响应失败也不丢 — USAGE-7).
    let model_req = event.model.as_ref().map(|m| m.to_string());
    let record_id = state.dag.push_messages(real_messages, event);
    let usage_ctx = super::helpers::usage_ctx_and_record_redactions(
        &state,
        super::helpers::UsageWire {
            fp: &fp,
            method: &parts.method,
            upstream_id,
            model_req,
            secrets: &secrets_snapshot,
            record_id,
            hits: &redact_hits,
            api_key_label: super::helpers::auth_label(&parts),
        },
    );

    debug!(
        %record_id,
        method = %parts.method,
        url = %upstream_url,
        ingress = %ingress.name(),
        egress = %provider.protocol.name(),
        "cross-proto forwarding"
    );

    // 13. 发送到上游. 响应头超时按流式语义选档 (#175): ir.stream 是 writer 产出的
    //     egress body 真实语义 (该 body 发往上游) — 流式请求走 TTFT 档, 非流式走
    //     整响应档, 与 same_proto 路径同构.
    let upstream_resp = match super::recorder::send_upstream_or_fail(
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
    .await
    {
        Ok(r) => r,
        Err(e) => return Err(e),
    };

    // 14. 判型: 流式请求 + 2xx + SSE → 跨协议流式翻译扇出 (mpsc 管道, 不 buffer);
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
            ingress_codec,
            egress_codec,
            redaction_map,
            state.upstream_timeouts.stream_idle,
            usage_ctx,
        )
        .await;
    }

    // 15. 完整 buffer 上游响应 (非流式 / 非 2xx / 非 SSE 判型降级). 受 MAX_RESP_BODY_RECORD 上限保护.
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
        if let Some(e) = stream_err {
            let err_label = super::recorder::stream_err_label(&e);
            let elapsed = started.elapsed().as_millis() as u64;
            warn!(%record_id, error = %e, err = err_label, "cross-proto upstream stream error mid-flight");
            state.dag.attach_response(
                record_id,
                ResponseData {
                    resp_status: resp_status.as_u16(),
                    resp_headers: redact_headers(&resp_headers),
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

    // 16. 翻译响应: egress JSON → IR → (restore redact) → ingress JSON.
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
                        provider.protocol.name(),
                        &ir_resp,
                        resp_status.is_success(),
                    );
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
                    warn!(%record_id, error = %e.message, "failed to parse upstream response as {}; passing through verbatim", provider.protocol.name());
                    // #158 补全: parse 失败 fallback + redact 在飞 → mock 不被 restore,
                    // 客户端拿到假 secret. 与 same_proto 路径 (fan_out_buffered_ir) 对称的
                    // 可感知 WARN (行为不变: 仍原样透传).
                    super::recorder::warn_mock_not_restored(
                        record_id,
                        &redaction_map,
                        &format!(
                            "cross-proto codec reader ({}) rejected response: {}",
                            provider.protocol.name(),
                            e.message
                        ),
                    );
                    (resp_status, resp_bytes.to_vec())
                }
            },
            Err(e) => {
                // #158 补全: 非 JSON body (如 SSE-shaped body 判型降级到此处) 同样
                // 无法 restore, 对称 WARN.
                super::recorder::warn_mock_not_restored(
                    record_id,
                    &redaction_map,
                    &format!(
                        "cross-proto response body is not a single JSON value ({e}); \
                         likely SSE-shaped body under a non-SSE content-type"
                    ),
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
            .unwrap_or_else(|| {
                let raw = std::str::from_utf8(&resp_bytes).unwrap_or("");
                let cap = raw.len().min(super::MAX_ERROR_MSG_LEN);
                raw[..cap].to_string()
            });
        let kind = http_status_to_error_kind(resp_status.as_u16());
        let envelope = ingress_writer.write_error(resp_status.as_u16(), kind, &friendly);
        let body = serde_json::to_vec(&envelope).unwrap_or_default();
        (resp_status, body)
    };

    // 17. attach 响应到 DAG.
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
            resp_headers: redact_headers(&resp_headers),
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

    // 18. 构造响应.
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

#[cfg(test)]
mod tests {
    use super::http_status_to_error_kind;

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
}
