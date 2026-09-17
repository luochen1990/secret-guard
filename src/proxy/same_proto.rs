//! 同协议转发路径 (ingress == egress).
//!
//! # 职责边界
//!
//! 同协议下按 "SecretTable 非空 **或 model 改写生效 (路由规则)**" 分两路 (#183 判据):
//!
//! - [`same_proto_forward`] (有 secret 或 override): IR 路径 (reader → [model 注入] →
//!   redact_ir → writer). 请求侧经 IR 改写 (FWD-1 修订授权: model 重写 / redact).
//!   响应侧按 redaction map 分流 — map 非空才需要 restore: 流式 2xx 走 StreamTranslate
//!   同协议 restore 模式 (Responses 流式除外: 501, 事件翻译未实现), 其余走 buffered_ir;
//!   **map 为空 (override-only / secret 未命中) 响应保持字节透传** (fan_out_streaming,
//!   byte-exact + 流式 UX; parsed view 按协议累积 — Responses 的 SSE 事件未实现,
//!   降级 None, 见 ParsedSync::finalize).
//! - [`same_proto_passthrough`] (无 secret 且无改写): 字节透传 (零回归, 最热路径).
//!
//! codec 不覆盖的协议 (Gemini/Ollama) 走 [`same_proto_forward`] 时受
//! `[redact] on_unsupported_protocol` 停损开关管约 (fail_closed + secrets → 503):
//! 详见函数内 from_native-None 分支.
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
use crate::provider::{DirectProvider, Protocol};

use super::auth::apply_provider_auth;
use super::helpers::{
    build_upstream_url, is_streaming, requests_stream, sanitize_request_headers, utf8_view,
};
use super::recorder::{
    build_call_event, parse_request_ir, push_event_and_wire_usage, redact_and_derive,
    safe_url_for_log,
};

/// 同协议转发: 字节透传 (无 redact 且无 override) 或 IR 路径 (有 redact 或 override).
///
/// **同协议 + 无 redact 无改写**: 字节透传, 保留流式 UX. 这条路径零回归.
/// **同协议 + redact / model 改写 (路由规则, #183)**: 请求侧走 IR (reader → model 注入 →
///   redact_ir → writer); 响应侧仅 redaction map 非空时需要 restore
///   (流式 2xx: StreamTranslate restore 模式; 其余: buffered_ir), map 为空时响应
///   字节透传 (byte-exact 不受 override 影响).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn same_proto_forward(
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
    // 字节直传仅当 "无 secret 且无 model 改写" (#183): 改写需要作用在
    // egress IR 的 model 字段上, 强制走 IR 路径 (FWD-1 修订的契约代价).
    if secrets_snapshot.is_empty() && model_rewrite.is_none() {
        // 字节透传: 不进入 codec, 不做 redact. 这是最热路径 (多数 provider 无 secret).
        // secrets_snapshot 此分支前提即为空, 传空.
        return same_proto_passthrough(
            state,
            fp,
            parts,
            req_bytes,
            ingress,
            provider,
            upstream_id,
            started,
            &[],
        )
        .await;
    }

    // IR 路径 (启用 redact / model 改写).
    use crate::codec::Protocol as CodecProtocol;
    let Some(codec_proto) = CodecProtocol::from_native(ingress) else {
        // codec 不支持此协议 (Gemini/Ollama), 但同协议 + SecretTable 非空时本应做 redact.
        // `[redact] on_unsupported_protocol` 停损开关 (SEC-10 降级偏安全, 与
        // on_probe_exhausted 同型):
        // - FailClosed (默认, 2026-09 自 FailOpen 翻转) + 配置了 secrets: 拒绝转发
        //   (503) — secret 原样出站是安全降级的底线, 默认停损. 仅管 secret 安全性:
        //   仅 model 改写降级 (无 secret) 时不触发, 维持 WARN 透传.
        // - FailOpen (显式 opt-in, 历史行为): 降级到字节透传, secret 原样转发到上游
        //   (静默失效风险), 用 warn 让运维注意到.
        // 安全: 只记 protocol + provider id, 永不记 secret 值 (SEC-2).
        if state.on_unsupported_protocol == crate::config::OnUnsupportedProtocol::FailClosed
            && !secrets_snapshot.is_empty()
        {
            warn!(
                "secrets configured for {} provider '{}', but codec does not cover {}; \
                 refusing to forward (on_unsupported_protocol=fail_closed)",
                ingress.name(),
                upstream_id,
                ingress.name()
            );
            return Err(AppError::Unavailable(format!(
                "provider '{upstream_id}' uses protocol {} which the redaction codec does \
                 not cover, and secrets are configured for it; forwarding refused by \
                 policy (on_unsupported_protocol=fail_closed); use a codec-covered \
                 protocol path (o/a/r), remove this provider's secret dependency, or \
                 set on_unsupported_protocol = \"fail_open\" to forward unredacted",
                ingress.name()
            )));
        }
        // #183 D2: model 改写同型降级 — 无 codec 无法改写 model, WARN + 原样透传
        // (两模式下都如此 — 重写不涉及 secret 安全性).
        warn!(
            "secrets or a model rewrite (route) configured for {} provider '{}', but \
             codec does not cover {}; requests will be forwarded as-is (secrets unredacted / \
             model not rewritten)",
            ingress.name(),
            upstream_id,
            ingress.name()
        );
        // 降级透传, 但 secrets_snapshot 必须传入 — UsageCtx 的 SEC model 扫描
        // (USAGE-6) 恰防 "fail_open passthrough 把 secret 持久化进 SQLite".
        return same_proto_passthrough(
            state,
            fp,
            parts,
            req_bytes,
            ingress,
            provider,
            upstream_id,
            started,
            &secrets_snapshot,
        )
        .await;
    };

    let reader = codec_proto.reader();
    let writer = codec_proto.writer();

    // 1-2. 解析请求 body → IR (共享 helper; route 的 upstream_model 改写值在此注入, SSOT).
    let mut ir = parse_request_ir(
        &req_bytes,
        ingress,
        reader.as_ref(),
        model_rewrite.as_deref(),
    )?;

    // 3. 快照真实 messages (redact 前) 给 DAG — 仅用于内容寻址 / parent 增量计算
    //    (req_delta 切片). WebUI 读的是 redact 后的 req_body_raw (LLM 视角), 永不
    //    触碰这份真实快照 (见 src/web/AGENTS.md "req_delta_messages 实现" 段).
    let real_messages = ir.messages.clone();

    // 4. redact IR + derive redactions (共享 helper; FailClosed 模式下 probing 耗尽
    //    时 redact_and_derive 内部构造 503 并在此 `?` 拒绝转发, 防止 secret 泄露).
    //    流式响应里的 TextDelta / InputJsonDelta 都会经 StreamingRestorer 做 sliding-window
    //    restore (在 StreamTranslate::new_same_proto_restore 中), 不再需要 warn.
    let (redaction_map, redact_seed, redactions, redact_hits) = redact_and_derive(
        &mut ir,
        &secrets_snapshot,
        state.on_probe_exhausted,
        "same-proto",
    )?;

    // Responses 协议 + 流式 + **Redact 命中** (map 非空): 响应需要 restore, 而
    // Responses 的 read_response_events 未实现 (SSE 事件层翻译是 MVP 范围外),
    // 放行会让 mock 静默流到客户端. 显式返回 501, 与跨协议流式一致.
    // 两档语义 (#183 D5 收窄): model 重写-only (map 空) 时**不拦** — 重写只作用于
    // 请求半段, 响应无需任何 restore, 走 fan_out_streaming SSE 字节透传
    // (byte-exact; resp_parsed 因 Responses 事件未解码降级 None, 前端占位).
    if ir.stream && ingress == Protocol::OpenAIResponses && !redaction_map.is_empty() {
        return Err(AppError::NotImplemented(format!(
            "streaming for {} protocol is not yet supported while redaction is active \
             (Responses SSE event translation unimplemented); remove stream=true from \
             the client request, or remove the secrets matched by this request to \
             stream (model rewrite alone no longer blocks streaming)",
            ingress.name()
        )));
    }

    // 5. IR → 请求 body (同协议 writer 重序列化). writer 输出恒为合法 UTF-8,
    //    直接产 String 按值 move 进 record (req_body_raw); 出站仅一次
    //    clone().into_bytes() (消除 to_vec → lossy copy → to_string 三段拷贝链).
    let new_body = writer.write_request(&ir);
    let req_text_for_record = serde_json::to_string(&new_body)
        .map_err(|e| AppError::Internal(format!("serialize redacted body failed: {e}")))?;
    let req_bytes_to_send = req_text_for_record.clone().into_bytes();

    // 6. 构造上游 URL + record path (同协议两路径共享 helper).
    let (upstream_url, path_for_record) = same_proto_upstream_url_and_path(&provider, &fp, &parts);

    // 7. 复制请求 headers + 应用 auth. 删除客户端的 content-type/length (重新计算).
    let mut fwd_headers = sanitize_request_headers(&parts.headers);
    fwd_headers.remove(axum::http::header::CONTENT_TYPE);
    fwd_headers.remove(axum::http::header::CONTENT_LENGTH);
    apply_provider_auth(
        &mut fwd_headers,
        &provider.effective_api_key(upstream_id),
        ingress,
    );

    // 8. push 到 DAG (真实 messages + CallEvent 元数据).
    let event = build_call_event(
        &parts,
        &path_for_record,
        &fwd_headers,
        &state.redacted_headers,
        req_text_for_record,
        Some(&ir),
        Some(codec_proto),
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

    // url 脱敏 (SEC-C4): query 可能携带客户端 key (如 Gemini ?key=...).
    debug!(%record_id, method = %parts.method, url = %safe_url_for_log(&upstream_url), "forwarding redacted same-proto request");

    // 9. 发送到上游. 响应头超时按**出站 body 的流式语义**选档 (#175): IR 的
    //    stream 字段是 writer 产出的 egress body 真实语义 (该 body 发往上游),
    //    比原始 req_bytes 检测更贴近被超时保护的实体.
    let upstream_resp = super::recorder::send_upstream_or_fail(
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
    .await?;

    // 10. 收集响应元数据.
    let resp_status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let content_type = super::helpers::response_content_type(&resp_headers).to_string();
    let streamed = is_streaming(&content_type);
    // #158: 本应走流式 restore (请求声明 stream=true 且本请求有 redact) 但上游
    // Content-Type 非 text/event-stream 时, 下方会落入 fan_out_buffered_ir 的
    // parse-失败 fallback — mock 不被 restore, 客户端拿到假 secret. 该 fallback
    // 内的 WARN 是逃逸点日志; 此处补充上游侧信号 (实际收到的 content-type).
    if ir.stream && !streamed && !redaction_map.is_empty() {
        warn!(
            %record_id,
            provider = %upstream_id,
            content_type = %content_type,
            "upstream returned non-SSE content-type for a stream=true request; \
             falling back to buffered path"
        );
    }

    debug!(%record_id, status = %resp_status, streamed, "upstream responded");

    // 11. 响应处理 — 仅 redaction map 非空才需要 restore (#183: override 只改写
    //     **请求半段** 的 model, 响应半段不受 FWD-1 修订授权):
    //     - map 非空 + 流式 2xx: StreamTranslate 同协议 restore 模式 (per-event restore).
    //     - map 非空 + 其余: buffered_ir (parse 失败 fallback 透传, 见 #158).
    //     - map 空 (override-only / secret 未命中): 字节透传 fan_out_streaming —
    //       响应 byte-exact + 流式 UX, parsed view 照常累积/计算.
    if !redaction_map.is_empty() {
        if streamed && resp_status.is_success() {
            super::fan_out::fan_out_streaming_with_restore(
                state.dag.clone(),
                record_id,
                started,
                upstream_resp,
                resp_status,
                resp_headers,
                state.redacted_headers.clone(),
                codec_proto,
                redaction_map,
                state.upstream_timeouts.stream_idle,
                usage_ctx.clone(),
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
                state.redacted_headers.clone(),
                streamed,
                codec_proto,
                redaction_map,
                state.on_fallback_restore,
                state.upstream_timeouts.stream_idle,
                usage_ctx.clone(),
            )
            .await
        }
    } else {
        super::fan_out::fan_out_streaming(
            state.dag.clone(),
            record_id,
            started,
            upstream_resp,
            resp_status,
            resp_headers,
            state.redacted_headers.clone(),
            streamed,
            Some(codec_proto),
            state.upstream_timeouts.stream_idle,
            usage_ctx,
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
    provider: DirectProvider,
    upstream_id: &str,
    started: Instant,
    secrets_snapshot: &[crate::secrets::SecretEntry],
) -> Result<Response<Body>, AppError> {
    let req_text_for_record = utf8_view(&req_bytes);
    let (upstream_url, path_for_record) = same_proto_upstream_url_and_path(&provider, &fp, &parts);

    let mut fwd_headers = sanitize_request_headers(&parts.headers);
    apply_provider_auth(
        &mut fwd_headers,
        &provider.effective_api_key(upstream_id),
        ingress,
    );

    // passthrough 路径无 IR 解析 (字节透传). DAG node 存空 messages (孤立节点) +
    // req_body_raw (原始字节) 作为 WebUI req_body 权威来源. Gemini/Ollama 无 codec
    // 协议也走此路径 (parsed view 不可用, 与旧行为一致).
    let event = build_call_event(
        &parts,
        &path_for_record,
        &fwd_headers,
        &state.redacted_headers,
        req_text_for_record,
        None,
        crate::codec::Protocol::from_native(ingress),
        upstream_id,
        None, // passthrough 未改写 model (override 配置了也到此为止, 见 D2 降级)
        0,
        None,
        vec![],
    );
    // usage 接线 (SSOT helper, 接线契约见其函数 doc). secrets_snapshot: 入口 1
    // (无 secret) 为空; 入口 2 (secrets 非空但无 codec 降级透传) 为全量快照 —
    // USAGE-6 的 SEC 扫描恰防后者的 model 字符串泄漏.
    let (record_id, usage_ctx) = push_event_and_wire_usage(
        &state,
        &fp,
        &parts,
        upstream_id,
        vec![],
        event,
        secrets_snapshot,
        &[],
    );

    debug!(%record_id, method = %parts.method, url = %safe_url_for_log(&upstream_url), "forwarding (passthrough)");

    // 响应头超时按请求 body 的流式语义选档 (#175): passthrough 无 codec 解析,
    // 用 requests_stream 对原始字节做顶层 "stream" 检测 (保守判定: 只有显式
    // stream=true 才用流式短超时, rationale 见该函数 doc).
    let stream_requested = requests_stream(&req_bytes);
    let upstream_resp = super::recorder::send_upstream_or_fail(
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
    .await?;

    let resp_status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let content_type = super::helpers::response_content_type(&resp_headers).to_string();
    let streamed = is_streaming(&content_type);

    debug!(%record_id, status = %resp_status, streamed, "upstream responded");

    super::fan_out::fan_out_streaming(
        state.dag.clone(),
        record_id,
        started,
        upstream_resp,
        resp_status,
        resp_headers,
        state.redacted_headers.clone(),
        streamed,
        crate::codec::Protocol::from_native(ingress),
        state.upstream_timeouts.stream_idle,
        usage_ctx,
    )
    .await
}

/// 同协议两路径 (forward / passthrough) 共享的上游 URL + record path 构造.
///
/// - `upstream_url`: base_url + rest + query (query 可能携带客户端 key, 如 Gemini
///   `?key=...`; 落日志前经 `safe_url_for_log` 脱敏, SEC-C4).
/// - `path_for_record`: 还原 ingress 侧的完整路径形态 `/{proto}/{name}/{rest}`.
///
/// 刻意不合入 cross_proto: 其 URL 用 egress writer 的固定 `upstream_path()`,
/// record path 带 `[a → b]` 协议尾注 (语义不同).
fn same_proto_upstream_url_and_path(
    provider: &DirectProvider,
    fp: &super::ForwardPath,
    parts: &axum::http::request::Parts,
) -> (String, String) {
    let query = parts
        .uri
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let upstream_url = build_upstream_url(&provider.base_url, &format!("{}{query}", fp.rest));
    let path_for_record = format!(
        "/{}/{}/{}",
        fp.proto,
        fp.name,
        fp.rest.trim_start_matches('/')
    );
    (upstream_url, path_for_record)
}
