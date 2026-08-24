//! 跨协议转发路径 (ingress != egress): codec 翻译 + redact.
//!
//! # 职责边界
//!
//! ingress 协议 → IR → egress 协议, 上游响应反向翻译. 与 same_proto 的差异:
//! - 强制非流式 (上游 stream=false; 客户端若 stream=true 返回 501).
//! - 应用 redact (在 IR 层, 不与 codec 翻译冲突).
//! - 响应直接翻译 (无 restore, mock 不在响应中出现).
//! - 上游错误响应 (4xx/5xx) 也通过 codec 翻译为 ingress 协议的原生错误 envelope.
//!
//! # MVP 范围与限制
//!
//! 只支持 OpenAI ⇄ Anthropic 双向 (其他组合返回 501). StreamTranslate 跨协议翻译
//! 已实现但未接入 dispatch (跨协议 + stream=true → 501).

use std::time::Instant;

use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode};
use bytes::Bytes;
use tracing::{debug, warn};

use crate::dag::ResponseData;
use crate::error::AppError;
use crate::provider::{Protocol, Provider};

use super::auth::apply_provider_auth;
use super::helpers::{build_response_headers, redact_headers, sanitize_request_headers, utf8_view};
#[cfg(feature = "consistency-check")]
use super::recorder::assert_resp_parsed_matches_source_nonstream;
use super::recorder::{build_call_event, parse_request_ir, redact_and_derive};

/// 跨协议转发: ingress 协议 → IR → egress 协议, 上游响应反向翻译.
///
/// # MVP 限制
///
/// - 只支持 OpenAI ⇄ Anthropic 双向 (其他组合返回 501).
/// - **强制非流式**: 上游 stream=false (即便客户端请求 stream=true). 客户端若 stream=true,
///   目前返回 501 (`streaming cross-protocol not yet supported`).
/// - **应用 redact**: 跨协议 + redact 通过 [`crate::redact::redact_ir`] 在 IR 层做替换,
///   不会与 codec 翻译冲突. 跨协议路径响应直接翻译 (无 restore, mock 不在响应中出现).
/// - 上游错误响应 (4xx/5xx) 也通过 codec 翻译为 ingress 协议的原生错误 envelope.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn cross_proto_forward(
    state: crate::state::AppState,
    fp: super::ForwardPath,
    parts: axum::http::request::Parts,
    req_bytes: Bytes,
    ingress: Protocol,
    provider: Provider,
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
    let mut ir = parse_request_ir(&req_bytes, ingress, ingress_reader.as_ref())?;

    // 4. MVP 限制: 跨协议时不支持流式 (StreamTranslate 尚未接入 dispatch).
    if ir.stream {
        return Err(AppError::NotImplemented(format!(
            "streaming cross-protocol ({ingress} → {}) is not yet supported; \
             disable stream=true in the client request",
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
    //    FailClosed 模式下 probing 耗尽 → 直接 503 拒绝转发 (防 secret 泄露).
    let (redaction_map, redact_seed, redactions) = match redact_and_derive(
        &mut ir,
        &secrets_snapshot,
        state.on_probe_exhausted,
        "cross-proto",
    ) {
        Ok(out) => out,
        Err(e) => {
            warn!(
                secret_id = %e.secret_id,
                reason = ?e.reason,
                "redact probe exhausted in cross-proto path; refusing to forward (fail_closed)"
            );
            return Err(AppError::Unavailable(format!(
                "redact probe exhausted, secret forwarding refused by policy \
                     (on_probe_exhausted=fail_closed); check secret mock_strategy config \
                     (secret_id hint: {}, reason: {:?})",
                e.secret_id, e.reason
            )));
        }
    };

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
        &provider.effective_api_key(),
        provider.protocol,
    );
    // 跨协议时客户端不会自带 egress 协议的特定 header, 这里仅在缺失时注入默认.
    // 用 entry().or_insert() 而非 insert(), 保留客户端主动设置更新的版本的能力.
    if provider.protocol == Protocol::Anthropic {
        fwd_headers
            .entry("anthropic-version")
            .or_insert_with(|| HeaderValue::from_static("2023-06-01"));
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
    let req_view_value = ingress_writer.write_request(&ir);
    let req_view_bytes = serde_json::to_vec(&req_view_value)
        .map_err(|e| AppError::Internal(format!("serialize ingress view body failed: {e}")))?;
    let req_text_for_record = utf8_view(&req_view_bytes);
    let event = build_call_event(
        &parts,
        &path_for_record,
        &fwd_headers,
        &req_text_for_record,
        Some(&ir),
        Some(ingress_codec),
        &provider.id,
        redact_seed,
        Some(&secrets_snapshot),
        redactions,
    );
    let record_id = state.dag.push_messages(real_messages, event);

    debug!(
        %record_id,
        method = %parts.method,
        url = %upstream_url,
        ingress = %ingress.name(),
        egress = %provider.protocol.name(),
        "cross-proto forwarding"
    );

    // 13. 发送到上游. 响应头超时按流式语义选档 (#175): 上面的 501 门已保证
    //     此处 ir.stream == false (跨协议强制非流式), 故实际恒走非流式档 —
    //     egress body 由 writer 写出 stream=false, 响应头确实要等整响应生成完,
    //     量纲与非流式档一致. 写 ir.stream 而非硬编码 false, 未来接入跨协议流式
    //     翻译时此处自动选对流式档.
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

    // 14. 完整 buffer 上游响应 (跨协议 MVP 不支持流式). 受 MAX_RESP_BODY_RECORD 上限保护.
    let resp_status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
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
            return Err(AppError::Upstream(msg));
        }
        Bytes::from(acc)
    };

    // 15. 翻译响应: egress JSON → IR → (restore redact) → ingress JSON.
    let egress_reader = egress_codec.reader();
    let ingress_writer = ingress_codec.writer();
    // parsed view: 记录 LLM 视角的 IR (restore 之前, 含 mock). 仅 2xx 成功响应.
    let mut resp_parsed_for_record: Option<serde_json::Value> = None;
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
                    resp_parsed_for_record = Some(ingress_writer.write_response(&ir_resp));
                    // restore: mock → real (跨协议 + redact 时, 客户端看到的应该是真 secret).
                    crate::redact::restore_ir_response(&mut ir_resp, &redaction_map);
                    let translated = ingress_writer.write_response(&ir_resp);
                    let body = serde_json::to_vec(&translated).unwrap_or_default();
                    (resp_status, body)
                }
                Err(e) => {
                    warn!(%record_id, error = %e.message, "failed to parse upstream response as {}; passing through verbatim", provider.protocol.name());
                    (resp_status, resp_bytes.to_vec())
                }
            },
            Err(_) => (resp_status, resp_bytes.to_vec()),
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
            resp_headers: redact_headers(&resp_headers),
            raw_resp_body: utf8_view(&resp_body_out),
            parsed: resp_parsed_for_record,
            elapsed_ms: elapsed,
            streamed: false,
            resp_complete: true,
            ..Default::default()
        },
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
