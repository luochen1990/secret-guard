//! 同协议转发路径 (ingress == egress).
//!
//! # 职责边界
//!
//! 同协议下按 SecretTable 是否空再分两路:
//!
//! - [`same_proto_forward`] (SecretTable 非空): IR 路径 (reader → redact_ir → writer).
//!   非流式响应走 buffered + restore_ir_response; 流式响应走 StreamTranslate 同协议
//!   restore 模式 (恢复流式 UX, 但失去 byte-exact).
//! - [`same_proto_passthrough`] (SecretTable 空): 字节透传 (零回归, 最热路径).
//!
//! **同协议 + 无 redact 保持 byte-exact + 流式 UX 零回归**; 同协议 + redact + 非流式
//! 仅 normalize_json 相等 (IR re-serialize 改变字段顺序/空白), 语义信息通过 wire 形态
//! 元数据保留.

use std::time::Instant;

use axum::body::Body;
use axum::http::Response;
use bytes::Bytes;
use tracing::{debug, warn};

use crate::error::AppError;
use crate::provider::{Protocol, Provider};

use super::auth::apply_provider_auth;
use super::helpers::{
    build_upstream_url, is_streaming, requests_stream, sanitize_request_headers, utf8_view,
};
use super::recorder::{build_call_event, parse_request_ir, redact_and_derive};

/// 同协议转发: 字节透传 (无 redact) 或 IR 路径 (启用 redact).
///
/// **同协议 + 无 redact**: 字节透传, 保留流式 UX. 这条路径零回归.
/// **同协议 + redact**: 走 IR (reader → redact_ir → writer).
///   非流式响应: buffered + restore_ir_response.
///   流式响应: 用 StreamTranslate 同协议 + restore 模式, 恢复流式 UX.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn same_proto_forward(
    state: crate::state::AppState,
    fp: super::ForwardPath,
    parts: axum::http::request::Parts,
    req_bytes: Bytes,
    ingress: Protocol,
    provider: Provider,
    started: Instant,
    secrets_snapshot: Vec<crate::secrets::SecretEntry>,
) -> Result<Response<Body>, AppError> {
    if secrets_snapshot.is_empty() {
        // 字节透传: 不进入 codec, 不做 redact. 这是最热路径 (多数 provider 无 secret).
        return same_proto_passthrough(state, fp, parts, req_bytes, ingress, provider, started)
            .await;
    }

    // IR 路径 (启用 redact).
    use crate::codec::Protocol as CodecProtocol;
    let Some(codec_proto) = CodecProtocol::from_native(ingress) else {
        // codec 不支持此协议 (Gemini/Ollama), 但同协议 + SecretTable 非空时本应做 redact.
        // 降级到字节透传: secret 原样转发到上游 (静默失效风险). 用 warn 让运维注意到.
        // 安全: 只记 protocol + provider id, 永不记 secret 值.
        warn!(
            "secrets configured for {} provider '{}', but codec does not cover {}; \
             secrets will be forwarded unredacted to upstream",
            ingress.name(),
            provider.id,
            ingress.name()
        );
        return same_proto_passthrough(state, fp, parts, req_bytes, ingress, provider, started)
            .await;
    };

    let reader = codec_proto.reader();
    let writer = codec_proto.writer();

    // 1-2. 解析请求 body → IR (共享 helper).
    let mut ir = parse_request_ir(&req_bytes, ingress, reader.as_ref())?;

    // Responses 协议 + Redact + 流式: 当前 codec 的 read_response_events 未实现
    // (Responses 流式 SSE 事件翻译是 MVP 范围外). 若放行会静默产生空流.
    // 显式返回 501, 与跨协议流式一致.
    if ir.stream && ingress == Protocol::OpenAIResponses {
        return Err(AppError::NotImplemented(format!(
            "streaming + redact for {} protocol is not yet supported (Responses SSE event \
             translation unimplemented); either disable stream=true in the client request \
             or remove secrets from this provider's config",
            ingress.name()
        )));
    }

    // 3. 快照真实 messages (redact 前) 给 DAG (DAG 存 OriginRecord 视角真实内容,
    //    WebUI 查询时 lazy apply redactMap).
    let real_messages = ir.messages.clone();

    // 4. redact IR + derive redactions (共享 helper).
    //    流式响应里的 TextDelta / InputJsonDelta 都会经 StreamingRestorer 做 sliding-window
    //    restore (在 StreamTranslate::new_same_proto_restore 中), 不再需要 warn.
    //    FailClosed 模式下 probing 耗尽 → 直接 503 拒绝转发 (防 secret 泄露).
    let (redaction_map, redact_seed, redactions) = match redact_and_derive(
        &mut ir,
        &secrets_snapshot,
        state.on_probe_exhausted,
        "same-proto",
    ) {
        Ok(out) => out,
        Err(e) => {
            warn!(
                secret_id = %e.secret_id,
                reason = ?e.reason,
                "redact probe exhausted in same-proto path; refusing to forward (fail_closed)"
            );
            return Err(AppError::Unavailable(format!(
                "redact probe exhausted, secret forwarding refused by policy \
                     (on_probe_exhausted=fail_closed); check secret mock_strategy config \
                     (secret_id hint: {}, reason: {:?})",
                e.secret_id, e.reason
            )));
        }
    };

    // 5. IR → 请求 body (同协议 writer 重序列化).
    let new_body = writer.write_request(&ir);
    let req_bytes_to_send = serde_json::to_vec(&new_body)
        .map_err(|e| AppError::Internal(format!("serialize redacted body failed: {e}")))?;
    let req_text_for_record = utf8_view(&req_bytes_to_send);

    // 6. 构造上游 URL.
    let query = parts
        .uri
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let upstream_url = build_upstream_url(&provider.base_url, &format!("{}{query}", fp.rest));

    // 7. 复制请求 headers + 应用 auth. 删除客户端的 content-type/length (重新计算).
    let mut fwd_headers = sanitize_request_headers(&parts.headers);
    fwd_headers.remove(axum::http::header::CONTENT_TYPE);
    fwd_headers.remove(axum::http::header::CONTENT_LENGTH);
    apply_provider_auth(&mut fwd_headers, &provider.effective_api_key(), ingress);

    // 8. push 到 DAG (真实 messages + CallEvent 元数据).
    let path_for_record = format!(
        "/{}/{}/{}",
        fp.proto,
        fp.name,
        fp.rest.trim_start_matches('/')
    );
    let event = build_call_event(
        &parts,
        &path_for_record,
        &fwd_headers,
        &req_text_for_record,
        Some(&ir),
        Some(codec_proto),
        redact_seed,
        Some(&secrets_snapshot),
        redactions,
    );
    let record_id = state.dag.push_messages(real_messages, event);

    debug!(%record_id, method = %parts.method, url = %upstream_url, "forwarding redacted same-proto request");

    // 9. 发送到上游. 响应头超时按**出站 body 的流式语义**选档 (#175): IR 的
    //    stream 字段是 writer 产出的 egress body 真实语义 (该 body 发往上游),
    //    比原始 req_bytes 检测更贴近被超时保护的实体.
    let upstream_resp = match super::recorder::send_upstream_or_fail(
        &state.dag,
        record_id,
        started,
        state
            .upstream
            .request(parts.method, &upstream_url)
            .headers(fwd_headers)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header(axum::http::header::CONTENT_LENGTH, req_bytes_to_send.len())
            .body(req_bytes_to_send),
        state.upstream_timeouts.header_timeout(ir.stream),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return Err(e),
    };

    // 10. 收集响应元数据.
    let resp_status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let content_type = resp_headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let streamed = is_streaming(&content_type);
    // #158: 本应走流式 restore (请求声明 stream=true 且本请求有 redact) 但上游
    // Content-Type 非 text/event-stream 时, 下方会落入 fan_out_buffered_ir 的
    // parse-失败 fallback — mock 不被 restore, 客户端拿到假 secret. 该 fallback
    // 内的 WARN 是逃逸点日志; 此处补充上游侧信号 (实际收到的 content-type).
    if ir.stream && !streamed && !redaction_map.is_empty() {
        warn!(
            %record_id,
            provider = %provider.id,
            content_type = %content_type,
            "upstream returned non-SSE content-type for a stream=true request; \
             falling back to buffered path"
        );
    }

    debug!(%record_id, status = %resp_status, streamed, "upstream responded");

    // 11. 响应处理:
    //     - 流式 + redact: StreamTranslate 同协议模式, per-event restore (恢复流式 UX).
    //     - 非流式 + redact: buffered + restore_ir_response.
    if streamed && resp_status.is_success() {
        super::fan_out::fan_out_streaming_with_restore(
            state.dag.clone(),
            record_id,
            started,
            upstream_resp,
            resp_status,
            resp_headers,
            codec_proto,
            redaction_map,
            state.upstream_timeouts.stream_idle,
        )
        .await
    } else {
        super::fan_out::fan_out_buffered_ir(
            state.dag.clone(),
            record_id,
            started,
            upstream_resp,
            resp_status,
            resp_headers,
            streamed,
            codec_proto,
            redaction_map,
            state.upstream_timeouts.stream_idle,
        )
        .await
    }
}

/// 同协议字节透传路径 (无 redact 时使用). 这条路径是项目最初的核心契约,
/// 必须保持 byte-exact + 流式 UX 零回归.
#[allow(clippy::too_many_arguments)]
async fn same_proto_passthrough(
    state: crate::state::AppState,
    fp: super::ForwardPath,
    parts: axum::http::request::Parts,
    req_bytes: Bytes,
    ingress: Protocol,
    provider: Provider,
    started: Instant,
) -> Result<Response<Body>, AppError> {
    let req_text_for_record = utf8_view(&req_bytes);
    let query = parts
        .uri
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let upstream_url = build_upstream_url(&provider.base_url, &format!("{}{query}", fp.rest));

    let mut fwd_headers = sanitize_request_headers(&parts.headers);
    apply_provider_auth(&mut fwd_headers, &provider.effective_api_key(), ingress);

    let path_for_record = format!(
        "/{}/{}/{}",
        fp.proto,
        fp.name,
        fp.rest.trim_start_matches('/')
    );
    // passthrough 路径无 IR 解析 (字节透传). DAG node 存空 messages (孤立节点) +
    // req_body_raw (原始字节) 作为 WebUI req_body 权威来源. Gemini/Ollama 无 codec
    // 协议也走此路径 (parsed view 不可用, 与旧行为一致).
    let event = build_call_event(
        &parts,
        &path_for_record,
        &fwd_headers,
        &req_text_for_record,
        None,
        crate::codec::Protocol::from_native(ingress),
        0,
        None,
        vec![],
    );
    let record_id = state.dag.push_messages(vec![], event);

    debug!(%record_id, method = %parts.method, url = %upstream_url, "forwarding (passthrough)");

    // 响应头超时按请求 body 的流式语义选档 (#175): passthrough 无 codec 解析,
    // 用 requests_stream 对原始字节做顶层 "stream" 检测 (保守判定: 只有显式
    // stream=true 才用流式短超时, rationale 见该函数 doc).
    let stream_requested = requests_stream(&req_bytes);
    let upstream_resp = match super::recorder::send_upstream_or_fail(
        &state.dag,
        record_id,
        started,
        state
            .upstream
            .request(parts.method, &upstream_url)
            .headers(fwd_headers)
            .body(req_bytes),
        state.upstream_timeouts.header_timeout(stream_requested),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return Err(e),
    };

    let resp_status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let content_type = resp_headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let streamed = is_streaming(&content_type);

    debug!(%record_id, status = %resp_status, streamed, "upstream responded");

    super::fan_out::fan_out_streaming(
        state.dag.clone(),
        record_id,
        started,
        upstream_resp,
        resp_status,
        resp_headers,
        streamed,
        crate::codec::Protocol::from_native(ingress),
        state.upstream_timeouts.stream_idle,
    )
    .await
}
