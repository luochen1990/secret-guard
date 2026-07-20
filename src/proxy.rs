//! 透明反向代理 handler.
//!
//! # 契约 / DoD
//! 1. **协议无关**: 任意 HTTP 方法 / 路径透传, body 视为字节流.
//! 2. **零字段损失**: 上游响应的所有 header / 状态码 / body 原样回传 (除 hop-by-hop).
//! 3. **流式友好**: 上游若返回 SSE / chunked, 也以流式方式回传给客户端.
//! 4. **可观测**: 每次请求都生成 [`ForwardRecord`], 包括错误路径下的 incomplete 标记.
//! 5. **可插拔**: 后续 secret 改写只需在 "请求 body 收集后" 与 "响应 chunk 流出前" 两处插入 hook.
//!
//! # 路由策略
//! URL = `/{proto_short}/{provider_id}/*path`, 由 [`ForwardPath`] 解析:
//! - `proto_short` 决定 ingress 协议 (o/a/g/l).
//! - `provider_id` 决定目标 provider (含 egress 协议).
//! - 若 ingress == egress: identity passthrough, 透传到 `provider.base_url + path`.
//! - 若 ingress != egress: 返回 501 (跨协议转换为未来工作).
//! - 若 provider 不存在 / 被禁用: 返回 404 / 503.
//!
//! # 流式响应处理
//! 用 mpsc channel 做扇出: 一个后台 task 读取上游 chunk, 同时写一份给客户端 channel
//! 一份累积给记录. 顺序上**先 send 后 acc**, 让客户端反向压力能尽早传到上游.
//! 流结束 / 客户端断开 / 上游错误 都触发记录更新 (带 incomplete 标记).

use std::time::Instant;

use axum::{
    body::{to_bytes, Body},
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, Response, StatusCode},
    response::IntoResponse,
};
use bytes::Bytes;
use futures::StreamExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, warn};

use crate::provider::{Protocol, ProviderTable};
use crate::record::{ForwardRecord, RecordStore, ResponseUpdate};
use crate::redact::{redact_request, restore_response, RedactionMap};
use crate::secrets::SecretTable;

/// 进程级共享状态, 在 router 与 handler 间共享.
#[derive(Clone, Debug)]
pub struct ProxyState {
    pub upstream: reqwest::Client,
    pub providers: ProviderTable,
    pub records: RecordStore,
    pub secrets: SecretTable,
}

/// axum 路径参数: `/{proto}/{name}/{*rest}`.
///
/// `rest` 由 axum 的 catch-all 语法 (`{*rest}`) 提供, 含前导 `/`, 例如 `/v1/chat`.
/// 若 URL 只到 `/{proto}/{name}` 则走 [`forward_no_rest`] 单独路由.
#[derive(serde::Deserialize, Debug)]
pub struct ForwardPath {
    pub proto: String,
    pub name: String,
    pub rest: String,
}

/// hop-by-hop 或在反代语义下不应原样转发的 header (RFC 7230 §6.1 + 反代常识).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// 请求 body 在内存中收集的上限 (16 MiB).
const MAX_REQ_BODY: usize = 16 * 1024 * 1024;

/// 单条响应 body 累积记录的上限 (32 MiB).
const MAX_RESP_BODY_RECORD: usize = 32 * 1024 * 1024;

/// 主 handler: 路径 `/{proto}/{name}/{*rest}`, 解析后透传到对应 provider.
///
/// 路径段语义:
/// - `proto` = ingress 协议的单字母简写 (o/a/g/l).
/// - `name` = 目标 provider id.
/// - `rest` = 上游 path (含前导 `/`), query string 单独从 uri 拼回.
///
/// MVP: 仅支持 ingress == provider.protocol (identity passthrough);
/// 跨协议请求返回 501 Not Implemented.
pub async fn forward(
    State(state): State<ProxyState>,
    Path(fp): Path<ForwardPath>,
    req: Request<Body>,
) -> Result<Response<Body>, AppError> {
    dispatch(state, fp, req).await
}

/// 路径只到 `/{proto}/{name}` (没有 rest 段) 的薄包装: 等价于 rest = "/".
pub async fn forward_no_rest(
    State(state): State<ProxyState>,
    Path((proto, name)): Path<(String, String)>,
    req: Request<Body>,
) -> Result<Response<Body>, AppError> {
    let fp = ForwardPath {
        proto,
        name,
        rest: "/".to_string(),
    };
    dispatch(state, fp, req).await
}

async fn dispatch(
    state: ProxyState,
    fp: ForwardPath,
    req: Request<Body>,
) -> Result<Response<Body>, AppError> {
    let started = Instant::now();
    let (parts, body) = req.into_parts();

    // 1. 解析 ingress 协议.
    let ingress = Protocol::from_short(&fp.proto).ok_or_else(|| {
        AppError::NotFound(format!(
            "unknown protocol '/{}' (expected one of: o/a/g/l)",
            fp.proto
        ))
    })?;

    // 2. 查找 effective provider (合并 static + dynamic + decision 后的生效值).
    let provider = state
        .providers
        .get_effective(&fp.name)
        .ok_or_else(|| AppError::NotFound(format!("unknown provider '/{}'", fp.name)))?;
    if !provider.enabled {
        return Err(AppError::Unavailable(format!(
            "provider '{}' is disabled",
            provider.id
        )));
    }

    // 3. 收集请求 body (跨协议和同协议都需要).
    let req_bytes = to_bytes(body, MAX_REQ_BODY)
        .await
        .map_err(|e| AppError::BadBody(e.to_string()))?;

    // 4. 协议匹配: 同协议走 identity passthrough; 跨协议走 codec 翻译.
    if ingress != provider.protocol {
        return cross_proto_forward(state, fp, parts, req_bytes, ingress, provider, started).await;
    }

    // 5. redact 请求 body (若 effective SecretTable 非空).
    let secrets_snapshot = state.secrets.effective_raw();
    let (req_text_for_record, redaction_map): (String, RedactionMap) =
        if secrets_snapshot.is_empty() {
            (utf8_view(&req_bytes), RedactionMap::default())
        } else {
            let original = utf8_view(&req_bytes);
            let (redacted, map) = redact_request(&original, &secrets_snapshot);
            if !map.is_empty() {
                debug!(
                    redactions = map.real_to_mock.len(),
                    "redacted secrets in request body"
                );
            }
            (redacted, map)
        };
    let req_bytes_to_send = req_text_for_record.clone().into_bytes();

    // 6. 构造上游 URL: provider.base_url + rest + ?query.
    let query = parts
        .uri
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let upstream_url = build_upstream_url(&provider.base_url, &format!("{}{query}", fp.rest));

    // 7. 复制请求 headers (剥离 hop-by-hop + Connection 列出的字段 + Host + Content-Length).
    //    若 provider 配了 api_key (直接值或从 api_key_file 读取), 用它覆盖
    //    Authorization / x-api-key, 避免客户端漏传或泄露.
    let mut fwd_headers = sanitize_request_headers(&parts.headers);
    apply_provider_auth(&mut fwd_headers, &provider.effective_api_key(), ingress);

    // 8. 记录请求快照 (LLM 视角的改写后版本).
    let path_for_record = format!(
        "/{}/{}/{}",
        fp.proto,
        fp.name,
        fp.rest.trim_start_matches('/')
    );
    let req_snapshot = ForwardRecord::new(
        parts.method.as_str().to_string(),
        path_for_record,
        redact_headers(&fwd_headers),
        req_text_for_record,
    );
    let record_id = state.records.push(req_snapshot);

    debug!(%record_id, method = %parts.method, url = %upstream_url, "forwarding request");

    // 9. 发送到上游 (失败时也写回 record, 标记 incomplete).
    let upstream_resp = match state
        .upstream
        .request(parts.method, &upstream_url)
        .headers(fwd_headers)
        .body(req_bytes_to_send)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let elapsed = started.elapsed().as_millis() as u64;
            warn!(%record_id, error = %e, "upstream send failed");
            state.records.update_response_full(
                record_id,
                ResponseUpdate {
                    resp_status: 502,
                    resp_headers: vec![],
                    resp_body: String::new(),
                    elapsed_ms: elapsed,
                    streamed: false,
                    resp_complete: false,
                    error: Some(format!("upstream send error: {e}")),
                },
            );
            return Err(AppError::Upstream(e.to_string()));
        }
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

    debug!(%record_id, status = %resp_status, streamed, "upstream responded");

    // 11. 处理响应: 若启用 redact, 走 buffered (完整累积再 restore);
    //     否则保持流式透传 (最佳 UX).
    if redaction_map.is_empty() {
        fan_out_streaming(
            state.records.clone(),
            record_id,
            started,
            upstream_resp,
            resp_status,
            resp_headers,
            streamed,
        )
        .await
    } else {
        fan_out_buffered(BufferedParams {
            records: state.records.clone(),
            record_id,
            started,
            upstream_resp,
            resp_status,
            resp_headers,
            streamed,
            redaction_map,
        })
        .await
    }
}

/// 若 provider 配置了 api_key, 注入对应的 auth header.
///
/// 协议约定 (尊重各 provider 官方 SDK 的默认 header):
/// - OpenAI / Ollama: `Authorization: Bearer <key>` (OpenAI 标准; Ollama 1.17+ 也支持).
/// - Anthropic: `x-api-key: <key>`.
/// - Gemini: `x-goog-api-key: <key>` (Google API 官方约定; 不用 Bearer 避免与 OAuth 流程混淆).
///
/// 若客户端已自带对应 header, provider 的 api_key 覆盖之 — provider 配置优先.
/// 同步剥离客户端可能误传的竞争 header (如用 OpenAI ingress 时清除 `x-api-key`,
/// 防止上游误识别).
fn apply_provider_auth(headers: &mut HeaderMap, api_key: &str, ingress: Protocol) {
    let key = api_key.trim();
    if key.is_empty() {
        return;
    }
    // 目标 header 名 + 客户端可能误传的竞争 header 名 (统一剥离) + value 构造.
    // OpenAI/Ollama 用 `Bearer <key>` 格式; Anthropic/Gemini 用裸 key.
    let (target, competitors, value_str): (&'static str, &[&'static str], String) = match ingress {
        Protocol::OpenAI | Protocol::Ollama => (
            "authorization",
            &["x-api-key", "x-goog-api-key"][..],
            format!("Bearer {key}"),
        ),
        Protocol::Anthropic => (
            "x-api-key",
            &["authorization", "x-goog-api-key"][..],
            key.to_string(),
        ),
        Protocol::Gemini => (
            "x-goog-api-key",
            &["authorization", "x-api-key"][..],
            key.to_string(),
        ),
    };
    for c in competitors {
        headers.remove(*c);
    }
    match HeaderValue::from_str(&value_str) {
        Ok(v) => {
            headers.insert(target, v);
        }
        Err(e) => {
            // api_key 含非法 HTTP header 字符 (控制字符 / 非 ASCII 等).
            // 这通常是配置错误, 记 warn 让运维注意到; 不插入 header 让上游自行拒绝.
            warn!(
                error = %e,
                target,
                "provider api_key contains illegal header chars; skipping auth injection"
            );
        }
    }
}

/// 跨协议转发: ingress 协议 → IR → egress 协议, 上游响应反向翻译.
///
/// # MVP 范围与限制
///
/// - 只支持 OpenAI ⇄ Anthropic 双向 (其他组合返回 501).
/// - **强制非流式**: 上游 stream=false (即便客户端请求 stream=true). 客户端若 stream=true,
///   目前返回 501 (`streaming cross-protocol not yet supported`).
/// - **不应用 redact**: 跨协议时 redact map 强制为空 (因为 codec 是结构化翻译, 不能与字节级
///   redact 共存). 若 SecretTable 非空, secrets 不会被替换为 mock — 这是已知限制,
///   未来在 IR 阶段做结构化 redact 才能修复.
/// - 上游错误响应 (4xx/5xx) 也通过 codec 翻译为 ingress 协议的原生错误 envelope.
async fn cross_proto_forward(
    state: ProxyState,
    fp: ForwardPath,
    parts: axum::http::request::Parts,
    req_bytes: Bytes,
    ingress: Protocol,
    provider: crate::provider::Provider,
    started: Instant,
) -> Result<Response<Body>, AppError> {
    use crate::codec::Protocol as CodecProtocol;
    // trait methods 通过 CodecProtocol::reader/writer 返回的 Box<dyn Reader/Writer> 调用,
    // 不需要显式 use trait (Rust 自动识别 method 调用).

    // 0. 跨协议路径当前不应用 redact (redact 是字节级; codec 是结构化翻译).
    //    必须显式 warn 提示 operator, 避免误以为有 secret 保护.
    if !state.secrets.effective_raw().is_empty() {
        warn!(
            "cross-protocol request bypasses secret redaction; \
             secrets in body will reach upstream verbatim \
             (ingress={}, egress={})",
            ingress.name(),
            provider.protocol.name()
        );
    }

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
    let egress_writer = egress_codec.writer();

    // 2. 解析 ingress body 为 JSON.
    let ingress_body: serde_json::Value = serde_json::from_slice(&req_bytes)
        .map_err(|e| AppError::BadBody(format!("invalid JSON in {ingress} request body: {e}")))?;

    // 3. ingress JSON → IR.
    let mut ir = ingress_reader
        .read_request(&ingress_body)
        .map_err(|e| AppError::BadBody(format!("{ingress} request parse failed: {}", e.message)))?;

    // 4. MVP 限制: 跨协议时不支持流式.
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

    // 6. 清空 extra (跨协议时 extra 字段会泄漏 ingress-only 的内容, 必须丢弃).
    ir.extra.clear();

    // 7. IR → egress body.
    let egress_body_value = egress_writer.write_request(&ir);
    let egress_bytes = serde_json::to_vec(&egress_body_value)
        .map_err(|e| AppError::Internal(format!("serialize egress body failed: {e}")))?;

    // 8. 构造上游 URL (egress writer 的固定 path).
    let upstream_url = format!("{}{}", provider.base_url, egress_writer.upstream_path());

    // 9. 复制请求 headers + 应用 egress 协议的 auth (注意: 用 provider.protocol, 不是 ingress).
    let mut fwd_headers = sanitize_request_headers(&parts.headers);
    // 删除客户端可能传的 content-type / content-length, 后面会用我们计算的新值.
    fwd_headers.remove(axum::http::header::CONTENT_TYPE);
    fwd_headers.remove(axum::http::header::CONTENT_LENGTH);
    apply_provider_auth(&mut fwd_headers, &provider.effective_api_key(), provider.protocol);
    // 跨协议时客户端不会自带 egress 协议的特定 header, 这里仅在缺失时注入默认.
    // 用 entry().or_insert() 而非 insert(), 保留客户端主动设置更新的版本的能力.
    if provider.protocol == Protocol::Anthropic {
        fwd_headers
            .entry("anthropic-version")
            .or_insert_with(|| HeaderValue::from_static("2023-06-01"));
    }

    // 10. 记录请求快照 (用于 Web UI).
    let path_for_record = format!(
        "/{}/{}/{}  [{} → {}]",
        fp.proto,
        fp.name,
        fp.rest.trim_start_matches('/'),
        ingress.name(),
        provider.protocol.name()
    );
    let req_text_for_record = utf8_view(&req_bytes);
    let req_snapshot = ForwardRecord::new(
        parts.method.as_str().to_string(),
        path_for_record,
        redact_headers(&fwd_headers),
        req_text_for_record,
    );
    let record_id = state.records.push(req_snapshot);

    debug!(
        %record_id,
        method = %parts.method,
        url = %upstream_url,
        ingress = %ingress.name(),
        egress = %provider.protocol.name(),
        "cross-proto forwarding"
    );

    // 11. 发送到上游.
    let upstream_resp = match state
        .upstream
        .request(parts.method, &upstream_url)
        .headers(fwd_headers)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::CONTENT_LENGTH, egress_bytes.len())
        .body(egress_bytes)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let elapsed = started.elapsed().as_millis() as u64;
            warn!(%record_id, error = %e, "cross-proto upstream send failed");
            state.records.update_response_full(
                record_id,
                ResponseUpdate {
                    resp_status: 502,
                    resp_headers: vec![],
                    resp_body: String::new(),
                    elapsed_ms: elapsed,
                    streamed: false,
                    resp_complete: false,
                    error: Some(format!("upstream send error: {e}")),
                },
            );
            return Err(AppError::Upstream(e.to_string()));
        }
    };

    // 12. 完整 buffer 上游响应 (跨协议 MVP 不支持流式). 受 MAX_RESP_BODY_RECORD 上限保护,
    //     防止恶意/故障上游 OOM.
    let resp_status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_bytes: Bytes = {
        let mut acc: Vec<u8> = Vec::new();
        let mut stream = upstream_resp.bytes_stream();
        let mut exceeded = false;
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(b) => {
                    if acc.len() + b.len() > MAX_RESP_BODY_RECORD {
                        exceeded = true;
                        break;
                    }
                    acc.extend_from_slice(&b);
                }
                Err(e) => {
                    let elapsed = started.elapsed().as_millis() as u64;
                    warn!(%record_id, error = %e, "cross-proto upstream stream error mid-flight");
                    state.records.update_response_full(
                        record_id,
                        ResponseUpdate {
                            resp_status: resp_status.as_u16(),
                            resp_headers: redact_headers(&resp_headers),
                            resp_body: String::new(),
                            elapsed_ms: elapsed,
                            streamed: false,
                            resp_complete: false,
                            error: Some(format!("upstream stream error: {e}")),
                        },
                    );
                    return Err(AppError::Upstream(e.to_string()));
                }
            }
        }
        if exceeded {
            let elapsed = started.elapsed().as_millis() as u64;
            warn!(
                %record_id,
                cap = MAX_RESP_BODY_RECORD,
                "cross-proto upstream response exceeded cap; aborting"
            );
            state.records.update_response_full(
                record_id,
                ResponseUpdate {
                    resp_status: 502,
                    resp_headers: vec![],
                    resp_body: String::new(),
                    elapsed_ms: elapsed,
                    streamed: false,
                    resp_complete: false,
                    error: Some(format!(
                        "upstream response exceeded {MAX_RESP_BODY_RECORD} byte cap"
                    )),
                },
            );
            return Err(AppError::Upstream(format!(
                "upstream response exceeded {MAX_RESP_BODY_RECORD} byte cap"
            )));
        }
        Bytes::from(acc)
    };

    // 13. 翻译响应: egress JSON → IR → ingress JSON.
    let egress_reader = egress_codec.reader();
    let ingress_writer = ingress_codec.writer();
    let (resp_status_out, resp_body_out) = translate_cross_proto_response(
        egress_reader.as_ref(),
        ingress_writer.as_ref(),
        resp_status,
        &resp_bytes,
        provider.protocol.name(),
        record_id,
    );

    // 14. 记录响应.
    let elapsed = started.elapsed().as_millis() as u64;
    state.records.update_response_full(
        record_id,
        ResponseUpdate {
            resp_status: resp_status_out.as_u16(),
            resp_headers: redact_headers(&resp_headers),
            resp_body: utf8_view(&resp_body_out),
            elapsed_ms: elapsed,
            streamed: false,
            resp_complete: true,
            error: None,
        },
    );

    // 15. 构造响应: 强制 content-type 为 application/json (codec 总是产出 JSON).
    let mut resp = Response::new(Body::from(resp_body_out));
    *resp.status_mut() = resp_status_out;
    let mut out_headers = build_response_headers(&resp_headers);
    out_headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    out_headers.remove(axum::http::header::CONTENT_LENGTH); // axum 会自动重算
    *resp.headers_mut() = out_headers;
    Ok(resp)
}

/// 把上游 egress 响应翻译为 ingress 响应.
///
/// 成功响应 (2xx): 通过 codec IR 翻译 body; 解析失败则原样透传 (记 warn).
/// 错误响应 (非 2xx): 用 codec 的 write_error 翻译 envelope, 截断 message 到 4 KiB
/// 并优先解析上游 error.message 字段作为友好提示 (避免泄漏内部细节).
fn translate_cross_proto_response(
    egress_reader: &dyn crate::codec::Reader,
    ingress_writer: &dyn crate::codec::Writer,
    resp_status: StatusCode,
    resp_bytes: &[u8],
    egress_proto_name: &str,
    record_id: uuid::Uuid,
) -> (StatusCode, Vec<u8>) {
    if resp_status.is_success() {
        match serde_json::from_slice::<serde_json::Value>(resp_bytes) {
            Ok(v) => match egress_reader.read_response(&v) {
                Ok(ir_resp) => {
                    let translated = ingress_writer.write_response(&ir_resp);
                    let body = serde_json::to_vec(&translated).unwrap_or_default();
                    (resp_status, body)
                }
                Err(e) => {
                    warn!(
                        %record_id,
                        error = %e.message,
                        "failed to parse upstream response as {}; passing through verbatim",
                        egress_proto_name
                    );
                    (resp_status, resp_bytes.to_vec())
                }
            },
            Err(_) => {
                // 非 JSON 响应 (eg. HTML 错误页): 原样返回.
                (resp_status, resp_bytes.to_vec())
            }
        }
    } else {
        // 错误响应: 截断 + 解析上游 error.message 防止泄漏内部细节.
        let friendly = serde_json::from_slice::<serde_json::Value>(resp_bytes)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| {
                let raw = std::str::from_utf8(resp_bytes).unwrap_or("");
                let cap = raw.len().min(4096);
                raw[..cap].to_string()
            });
        let kind = http_status_to_error_kind(resp_status.as_u16());
        let envelope = ingress_writer.write_error(resp_status.as_u16(), kind, &friendly);
        let body = serde_json::to_vec(&envelope).unwrap_or_default();
        (resp_status, body)
    }
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

/// 流式扇出: 一份给客户端 (流式), 一份累积给记录.
/// 在未启用 redact 时使用, 保持最佳 UX.
async fn fan_out_streaming(
    records: RecordStore,
    record_id: uuid::Uuid,
    started: Instant,
    upstream_resp: reqwest::Response,
    resp_status: StatusCode,
    resp_headers: HeaderMap,
    streamed: bool,
) -> Result<Response<Body>, AppError> {
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(32);
    let resp_headers_for_record = resp_headers.clone();
    let status_u16 = resp_status.as_u16();

    tokio::spawn(async move {
        let mut stream = upstream_resp.bytes_stream();
        let mut acc: Vec<u8> = Vec::new();
        let mut overflow = false;
        let mut error_kind: Option<String> = None;
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(b) => {
                    if tx.send(Ok(b.clone())).await.is_err() {
                        error_kind = Some("client disconnected".into());
                        break;
                    }
                    if !overflow {
                        let remaining = MAX_RESP_BODY_RECORD.saturating_sub(acc.len());
                        if remaining > 0 {
                            let take = remaining.min(b.len());
                            acc.extend_from_slice(&b[..take]);
                        }
                        if b.len() > remaining {
                            warn!(
                                %record_id,
                                cap = MAX_RESP_BODY_RECORD,
                                "response too large to record; further chunks discarded"
                            );
                            overflow = true;
                        }
                    }
                }
                Err(e) => {
                    warn!(%record_id, error = %e, "upstream stream error mid-flight");
                    let io_err = std::io::Error::other(e.to_string());
                    let _ = tx.send(Err(io_err)).await;
                    error_kind = Some("upstream stream error".into());
                    break;
                }
            }
        }
        let elapsed = started.elapsed().as_millis() as u64;
        let body = if overflow {
            "<truncated: exceeded record cap>".to_string()
        } else {
            utf8_view(&acc)
        };
        records.update_response_full(
            record_id,
            ResponseUpdate {
                resp_status: status_u16,
                resp_headers: redact_headers(&resp_headers_for_record),
                resp_body: body,
                elapsed_ms: elapsed,
                streamed,
                resp_complete: error_kind.is_none(),
                error: error_kind,
            },
        );
    });

    let body = Body::from_stream(ReceiverStream::new(rx));
    let mut resp = Response::new(body);
    *resp.status_mut() = resp_status;
    *resp.headers_mut() = build_response_headers(&resp_headers);
    Ok(resp)
}

/// 缓冲扇出的参数包. 避免 `fan_out_buffered` 参数过多.
struct BufferedParams {
    records: RecordStore,
    record_id: uuid::Uuid,
    started: Instant,
    upstream_resp: reqwest::Response,
    resp_status: StatusCode,
    resp_headers: HeaderMap,
    streamed: bool,
    redaction_map: RedactionMap,
}

/// 缓冲扇出: 完整累积响应, restore mock → real, 一次性返回给客户端.
/// 失去流式 UX, 但保证 mock→real 映射正确.
async fn fan_out_buffered(p: BufferedParams) -> Result<Response<Body>, AppError> {
    let BufferedParams {
        records,
        record_id,
        started,
        upstream_resp,
        resp_status,
        resp_headers,
        streamed,
        redaction_map,
    } = p;
    let resp_headers_for_record = resp_headers.clone();
    let status_u16 = resp_status.as_u16();
    let cap = MAX_RESP_BODY_RECORD;

    let mut stream = upstream_resp.bytes_stream();
    let mut acc: Vec<u8> = Vec::new();
    let mut error_kind: Option<String> = None;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(b) => {
                if acc.len() + b.len() > cap {
                    let remaining = cap.saturating_sub(acc.len());
                    if remaining > 0 {
                        acc.extend_from_slice(&b[..remaining]);
                    }
                    error_kind = Some("response exceeds record cap".into());
                    break;
                }
                acc.extend_from_slice(&b);
            }
            Err(e) => {
                error_kind = Some(format!("upstream stream error: {e}"));
                break;
            }
        }
    }

    // record 存储的是 LLM 视角 (含 mock); 客户端拿到的是 restore 后的版本.
    let acc_text = utf8_view(&acc);
    let elapsed = started.elapsed().as_millis() as u64;
    records.update_response_full(
        record_id,
        ResponseUpdate {
            resp_status: status_u16,
            resp_headers: redact_headers(&resp_headers_for_record),
            resp_body: acc_text.clone(),
            elapsed_ms: elapsed,
            streamed,
            resp_complete: error_kind.is_none(),
            error: error_kind,
        },
    );

    // restore mock → real 给客户端.
    let client_text = restore_response(&acc_text, &redaction_map);
    let client_bytes = client_text.into_bytes();
    let mut resp = Response::new(Body::from(client_bytes));
    *resp.status_mut() = resp_status;
    *resp.headers_mut() = build_response_headers(&resp_headers);
    Ok(resp)
}

// ─── Error ────────────────────────────────────────────────────────────────

/// 应用错误: 自动转换为合适的 HTTP 状态, 响应体永远是合法 JSON.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("invalid request body: {0}")]
    BadBody(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("service unavailable: {0}")]
    Unavailable(String),
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("internal: {0}")]
    Internal(String),
}

#[derive(serde::Serialize)]
struct ErrorBody {
    error: &'static str,
    /// 人类可读的额外说明 (不泄露内部细节, 仅描述协议 / 路由层面的常见错误).
    message: Option<String>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response<Body> {
        // 内部错误细节仅记录到日志, 不回写到响应 (避免信息泄露 — reqwest::Error 等通常
        // 含完整上游 URL, 直接返回给客户端会暴露内部拓扑).
        // 因此 Upstream / BadBody / Internal 的 message 字段用 None (客户端只看到 kind);
        // NotFound / Unavailable / NotImplemented 的 message 描述协议/路由层面的问题,
        // 信息量对客户端排查有用且不含敏感字段, 原样返回.
        let (status, kind, message) = match &self {
            AppError::BadBody(_) => (StatusCode::BAD_REQUEST, "bad_request", None),
            AppError::Upstream(_) => (StatusCode::BAD_GATEWAY, "upstream_error", None),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, "not_found", Some(m.clone())),
            AppError::Unavailable(m) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                Some(m.clone()),
            ),
            AppError::NotImplemented(m) => (
                StatusCode::NOT_IMPLEMENTED,
                "not_implemented",
                Some(m.clone()),
            ),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal", None),
        };
        error!(error = %self, kind, "proxy error");
        let body = serde_json::to_vec(&ErrorBody {
            error: kind,
            message,
        })
        .unwrap_or_else(|_| b"{\"error\":\"internal\"}".to_vec());
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = status;
        resp.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        resp
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

fn build_upstream_url(base: &str, path_and_query: &str) -> String {
    let base = base.trim_end_matches('/');
    if path_and_query.starts_with('/') {
        format!("{base}{path_and_query}")
    } else {
        format!("{base}/{path_and_query}")
    }
}

/// 是否在 `Connection` header 列表中? (RFC 7230 §6.1: 这些也是 hop-by-hop.)
fn connection_listed(name: &str, src: &HeaderMap) -> bool {
    let target = name.to_lowercase();
    src.get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case(&target)))
        .unwrap_or(false)
}

fn is_hop_by_hop(name: &str) -> bool {
    let lower = name.to_lowercase();
    HOP_BY_HOP.iter().any(|h| *h == lower)
}

fn sanitize_request_headers(src: &HeaderMap) -> HeaderMap {
    filter_headers(src, |name| {
        is_hop_by_hop(name)
            || connection_listed(name, src)
            || matches!(name, "host" | "content-length")
    })
}

fn build_response_headers(src: &HeaderMap) -> HeaderMap {
    filter_headers(src, |name| {
        is_hop_by_hop(name) || connection_listed(name, src) || name == "content-length"
    })
}

fn filter_headers(src: &HeaderMap, drop_fn: impl Fn(&str) -> bool) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(src.len());
    for (name, value) in src.iter() {
        let name_str = name.as_str().to_lowercase();
        if drop_fn(&name_str) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

fn is_streaming(content_type: &str) -> bool {
    let ct = content_type.split(';').next().unwrap_or("").trim();
    ct.eq_ignore_ascii_case("text/event-stream") || ct.eq_ignore_ascii_case("application/x-ndjson")
}

fn utf8_view(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// 敏感 header 脱敏 (仅用于记录存储, 不影响转发).
fn redact_headers(src: &HeaderMap) -> Vec<(String, String)> {
    src.iter()
        .map(|(name, value)| {
            let name_str = name.as_str().to_lowercase();
            let v = if is_sensitive_header(&name_str) {
                "<redacted>".to_string()
            } else {
                value.to_str().unwrap_or("<binary>").to_string()
            };
            (name_str, v)
        })
        .collect()
}

/// 判断 header 是否敏感: 黑名单关键词匹配 (覆盖各 LLM provider 常见字段).
fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "x-api-key"
            | "api-key"
            | "x-anthropic-api-key"
            | "openai-organization"
            | "openai-project"
            | "x-goog-api-key"
            | "x-amz-security-token"
            | "cookie"
            | "set-cookie"
            | "proxy-authorization"
    ) || name.contains("token")
        || name.contains("secret")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_upstream_url_handles_trailing_slash() {
        assert_eq!(
            build_upstream_url("https://api.example.com/", "/v1/messages"),
            "https://api.example.com/v1/messages"
        );
        assert_eq!(
            build_upstream_url("https://api.example.com", "/v1/messages?foo=bar"),
            "https://api.example.com/v1/messages?foo=bar"
        );
    }

    #[test]
    fn build_upstream_url_handles_empty_rest() {
        // 路径只到 /{proto}/{name} 时 rest = "/".
        assert_eq!(
            build_upstream_url("https://api.example.com", "/?q=1"),
            "https://api.example.com/?q=1"
        );
    }

    #[test]
    fn sanitize_strips_hop_by_hop_and_host() {
        let mut src = HeaderMap::new();
        src.insert("host", "example.com".parse().unwrap());
        src.insert("content-length", "123".parse().unwrap());
        src.insert("connection", "keep-alive".parse().unwrap());
        src.insert("x-api-key", "secret".parse().unwrap());
        let out = sanitize_request_headers(&src);
        assert!(out.get("host").is_none());
        assert!(out.get("content-length").is_none());
        assert!(out.get("connection").is_none());
        assert_eq!(out.get("x-api-key").unwrap(), "secret");
    }

    #[test]
    fn sanitize_strips_connection_listed_custom_headers() {
        let mut src = HeaderMap::new();
        src.insert("connection", "x-custom, foo".parse().unwrap());
        src.insert("x-custom", "leak".parse().unwrap());
        src.insert("foo", "bar".parse().unwrap());
        src.insert("baz", "kept".parse().unwrap());
        let out = sanitize_request_headers(&src);
        assert!(
            out.get("x-custom").is_none(),
            "Connection-listed header must be stripped"
        );
        assert!(out.get("foo").is_none());
        assert_eq!(out.get("baz").unwrap(), "kept");
    }

    #[test]
    fn redact_headers_masks_secrets() {
        let mut src = HeaderMap::new();
        src.insert("authorization", "Bearer xxx".parse().unwrap());
        src.insert("x-api-key", "key".parse().unwrap());
        src.insert("x-goog-api-key", "gkey".parse().unwrap());
        src.insert("x-custom-token", "tok".parse().unwrap());
        src.insert("x-custom", "value".parse().unwrap());
        let v = redact_headers(&src);
        let m: std::collections::HashMap<_, _> = v.into_iter().collect();
        assert_eq!(m.get("authorization").unwrap(), "<redacted>");
        assert_eq!(m.get("x-api-key").unwrap(), "<redacted>");
        assert_eq!(m.get("x-goog-api-key").unwrap(), "<redacted>");
        assert_eq!(m.get("x-custom-token").unwrap(), "<redacted>");
        assert_eq!(m.get("x-custom").unwrap(), "value");
    }

    #[test]
    fn is_streaming_detects_sse_strictly() {
        assert!(is_streaming("text/event-stream"));
        assert!(is_streaming("text/event-stream; charset=utf-8"));
        assert!(is_streaming("application/x-ndjson"));
        assert!(!is_streaming("application/json"));
        assert!(!is_streaming("application/octet-stream"));
        assert!(!is_streaming("video/xyz-stream"));
    }

    #[test]
    fn utf8_view_handles_invalid_utf8() {
        let bad = &[0xFF, 0xFE, 0x00];
        let s = utf8_view(bad);
        assert!(s.contains('\u{FFFD}'));
    }

    #[test]
    fn apply_provider_auth_openai_uses_bearer() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer client-token".parse().unwrap());
        apply_provider_auth(&mut h, "sk-server-side", Protocol::OpenAI);
        assert_eq!(h.get("authorization").unwrap(), "Bearer sk-server-side");
    }

    #[test]
    fn apply_provider_auth_anthropic_uses_x_api_key() {
        let mut h = HeaderMap::new();
        h.insert("x-api-key", "client-key".parse().unwrap());
        apply_provider_auth(&mut h, "sk-ant-server", Protocol::Anthropic);
        assert_eq!(h.get("x-api-key").unwrap(), "sk-ant-server");
    }

    #[test]
    fn apply_provider_auth_gemini_uses_x_goog_api_key() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer client-tok".parse().unwrap());
        apply_provider_auth(&mut h, "ya29.server", Protocol::Gemini);
        // Gemini 用 x-goog-api-key, 不用 Authorization Bearer.
        assert_eq!(h.get("x-goog-api-key").unwrap(), "ya29.server");
        assert!(
            h.get("authorization").is_none(),
            "must clear competing header"
        );
    }

    #[test]
    fn apply_provider_auth_strips_competing_headers() {
        // 客户端误传了竞争对手协议的 header, 应被剥离.
        let mut h = HeaderMap::new();
        h.insert("x-api-key", "client-anthropic".parse().unwrap());
        h.insert("x-goog-api-key", "client-gemini".parse().unwrap());
        apply_provider_auth(&mut h, "sk-server", Protocol::OpenAI);
        assert_eq!(h.get("authorization").unwrap(), "Bearer sk-server");
        assert!(h.get("x-api-key").is_none());
        assert!(h.get("x-goog-api-key").is_none());
    }

    #[test]
    fn apply_provider_auth_skips_empty_key() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer keep-me".parse().unwrap());
        apply_provider_auth(&mut h, "   ", Protocol::OpenAI);
        assert_eq!(h.get("authorization").unwrap(), "Bearer keep-me");
    }
}
