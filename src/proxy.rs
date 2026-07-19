//! 透明反向代理 handler.
//!
//! # 契约 / DoD
//! 1. **协议无关**: 任意 HTTP 方法 / 路径透传, body 视为字节流.
//! 2. **零字段损失**: 上游响应的所有 header / 状态码 / body 原样回传 (除 hop-by-hop).
//! 3. **流式友好**: 上游若返回 SSE / chunked, 也以流式方式回传给客户端.
//! 4. **可观测**: 每次请求都生成 [`ForwardRecord`], 包括错误路径下的 incomplete 标记.
//! 5. **可插拔**: 后续 secret 改写只需在 "请求 body 收集后" 与 "响应 chunk 流出前" 两处插入 hook.
//!
//! # 流式响应处理
//! 用 mpsc channel 做扇出: 一个后台 task 读取上游 chunk, 同时写一份给客户端 channel
//! 一份累积给记录. 顺序上**先 send 后 acc**, 让客户端反向压力能尽早传到上游.
//! 流结束 / 客户端断开 / 上游错误 都触发记录更新 (带 incomplete 标记).

use std::time::Instant;

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Response, StatusCode},
    response::IntoResponse,
};
use bytes::Bytes;
use futures::StreamExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, warn};

use crate::record::{ForwardRecord, RecordStore, ResponseUpdate};

/// 进程级共享状态, 在 router 与 handler 间共享.
#[derive(Clone, Debug)]
pub struct ProxyState {
    pub upstream: reqwest::Client,
    pub upstream_base: String,
    pub records: RecordStore,
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

/// 主 handler: 接收任意方法 / 任意路径的请求, 透明转发到上游.
pub async fn forward(
    State(state): State<ProxyState>,
    req: Request<Body>,
) -> Result<Response<Body>, AppError> {
    let started = Instant::now();
    let (parts, body) = req.into_parts();

    // 1. 收集请求 body (为后续 secret 改写与记录做准备).
    let req_bytes = to_bytes(body, MAX_REQ_BODY)
        .await
        .map_err(|e| AppError::BadBody(e.to_string()))?;

    // 2. 构造上游 URL.
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let upstream_url = build_upstream_url(&state.upstream_base, path_and_query);

    // 3. 复制请求 headers (剥离 hop-by-hop + Connection 列出的字段 + Host + Content-Length).
    let fwd_headers = sanitize_request_headers(&parts.headers);

    // 4. 记录请求快照 (UI 友好, 敏感 header 脱敏).
    let req_snapshot = ForwardRecord::new(
        parts.method.as_str().to_string(),
        parts.uri.path().to_string(),
        redact_headers(&fwd_headers),
        utf8_view(&req_bytes),
    );
    let record_id = state.records.push(req_snapshot);

    debug!(%record_id, method = %parts.method, url = %upstream_url, "forwarding request");

    // 5. 发送到上游 (失败时也写回 record, 标记 incomplete).
    let upstream_resp = match state
        .upstream
        .request(parts.method, &upstream_url)
        .headers(fwd_headers)
        .body(req_bytes)
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

    // 6. 收集响应元数据.
    let resp_status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let content_type = resp_headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let streamed = is_streaming(&content_type);

    debug!(%record_id, status = %resp_status, streamed, "upstream responded");

    // 7. 扇出响应: 一份给客户端 (流式), 一份累积给记录.
    fan_out_response(
        state.records.clone(),
        record_id,
        started,
        upstream_resp,
        resp_status,
        resp_headers,
        streamed,
    )
    .await
}

/// 把上游响应扇出给客户端 + 记录存储.
async fn fan_out_response(
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

    // 后台 task: 读上游 chunk -> 先 send (反向压力) -> 再累积给记录.
    tokio::spawn(async move {
        let mut stream = upstream_resp.bytes_stream();
        let mut acc: Vec<u8> = Vec::new();
        let mut overflow = false;
        let mut error_kind: Option<String> = None;
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(b) => {
                    // 先 send: 若 channel 关闭 (客户端断开), 提前退出.
                    if tx.send(Ok(b.clone())).await.is_err() {
                        error_kind = Some("client disconnected".into());
                        break;
                    }
                    // 后 acc: 累积给记录 (受 MAX_RESP_BODY_RECORD 限制).
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
        // 流结束: 更新记录. 标记完整性.
        let elapsed = started.elapsed().as_millis() as u64;
        let body = if overflow {
            "<truncated: exceeded record cap>".to_string()
        } else {
            utf8_view(&acc)
        };
        let complete = error_kind.is_none();
        records.update_response_full(
            record_id,
            ResponseUpdate {
                resp_status: status_u16,
                resp_headers: redact_headers(&resp_headers_for_record),
                resp_body: body,
                elapsed_ms: elapsed,
                streamed,
                resp_complete: complete,
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

// ─── Error ────────────────────────────────────────────────────────────────

/// 应用错误: 自动转换为合适的 HTTP 状态, 响应体永远是合法 JSON.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("invalid request body: {0}")]
    BadBody(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("internal: {0}")]
    Internal(String),
}

#[derive(serde::Serialize)]
struct ErrorBody {
    error: &'static str,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response<Body> {
        let (status, kind) = match &self {
            AppError::BadBody(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            AppError::Upstream(_) => (StatusCode::BAD_GATEWAY, "upstream_error"),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        // 内部错误细节仅记录到日志, 不回写到响应 (避免信息泄露 + 避免 JSON 注入).
        error!(error = %self, kind, "proxy error");
        let body = serde_json::to_vec(&ErrorBody { error: kind })
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
}
