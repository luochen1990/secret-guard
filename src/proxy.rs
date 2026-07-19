//! 透明反向代理 handler.
//!
//! # 契约 / DoD
//! 1. **协议无关**: 任意 HTTP 方法 / 路径透传, body 视为字节流.
//! 2. **零字段损失**: 上游响应的所有 header / 状态码 / body 原样回传 (除 hop-by-hop).
//! 3. **流式友好**: 上游若返回 SSE / chunked, 也以流式方式回传给客户端.
//! 4. **可观测**: 每次请求都生成 [`ForwardRecord`] 供 Web UI 消费.
//! 5. **可插拔**: 后续 secret 改写只需在 "请求 body 收集后" 与 "响应 chunk 流出前" 两处插入 hook.
//!
//! # 流式响应的处理策略
//! 用 mpsc channel 做扇出: 一个后台 task 读取上游 chunk, 同时写一份给客户端 channel
//! 一份累积给记录. 流结束或客户端断开时, 更新 [`RecordStore`] 中的响应快照.
//! 这种方式的好处是: 客户端体验 (流式) 与记录完整性 (全文快照) 同时满足, 且无需缓冲整个响应再返回.

use std::time::Instant;

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Response, StatusCode},
    response::IntoResponse,
};
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, warn};

use crate::record::{ForwardRecord, RecordStore};

/// 进程级共享状态, 在 router 与 handler 间以 `Arc` 语义共享.
#[derive(Clone, Debug)]
pub struct ProxyState {
    pub upstream: reqwest::Client,
    pub upstream_base: String,
    pub records: RecordStore,
}

impl ProxyState {
    pub fn new(upstream: reqwest::Client, upstream_base: String, records: RecordStore) -> Self {
        Self {
            upstream,
            upstream_base,
            records,
        }
    }
}

/// hop-by-hop 或在反代语义下不应原样转发的 header.
/// 参考 RFC 7230 §6.1 + 反代常识.
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
/// LLM 请求几乎不会超过此体积 (主要体积来自 tool output 嵌入).
const MAX_REQ_BODY: usize = 16 * 1024 * 1024;

/// 单条响应 body 累积记录的上限 (32 MiB).
/// 流式响应通常远小于此; 超出时仅丢弃记录, 不影响转发.
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

    // 3. 复制请求 headers (剥离 hop-by-hop + Host + Content-Length).
    let fwd_headers = sanitize_request_headers(&parts.headers);

    // 4. 记录请求快照.
    let req_snapshot = ForwardRecord::new(
        parts.method.as_str().to_string(),
        parts.uri.path().to_string(),
        redact_headers(&fwd_headers),
        utf8_view(&req_bytes),
    );
    let record_id = state.records.push(req_snapshot);

    debug!(%record_id, method = %parts.method, url = %upstream_url, "forwarding request");

    // 5. 发送到上游.
    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .map_err(|e| AppError::Internal(format!("invalid method: {e}")))?;
    let upstream_resp = state
        .upstream
        .request(method, &upstream_url)
        .headers(fwd_headers)
        .body(req_bytes)
        .send()
        .await
        .map_err(|e| AppError::Upstream(e.to_string()))?;

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
        state,
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
    state: ProxyState,
    record_id: uuid::Uuid,
    started: Instant,
    upstream_resp: reqwest::Response,
    resp_status: StatusCode,
    resp_headers: HeaderMap,
    streamed: bool,
) -> Result<Response<Body>, AppError> {
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(32);

    let records = state.records.clone();
    let resp_headers_for_record = resp_headers.clone();
    let status_u16 = resp_status.as_u16();

    // 后台 task: 读上游 chunk -> 写客户端 channel + 累积给记录.
    tokio::spawn(async move {
        let mut stream = upstream_resp.bytes_stream();
        let mut acc: Vec<u8> = Vec::new();
        let mut overflow = false;
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(b) => {
                    if !overflow {
                        if acc.len() + b.len() <= MAX_RESP_BODY_RECORD {
                            acc.extend_from_slice(&b);
                        } else {
                            warn!(
                                %record_id,
                                cap = MAX_RESP_BODY_RECORD,
                                "response too large to record; further chunks discarded"
                            );
                            overflow = true;
                        }
                    }
                    if tx.send(Ok(b)).await.is_err() {
                        // 客户端断开
                        break;
                    }
                }
                Err(e) => {
                    let io_err = std::io::Error::other(e.to_string());
                    let _ = tx.send(Err(io_err)).await;
                    break;
                }
            }
        }
        // 流结束: 更新记录.
        let elapsed = started.elapsed().as_millis() as u64;
        let body = if overflow {
            "<truncated: exceeded record cap>".to_string()
        } else {
            utf8_view(&acc)
        };
        records.update_response(
            record_id,
            status_u16,
            redact_headers(&resp_headers_for_record),
            body,
            elapsed,
            streamed,
        );
    });

    // 把 receiver 流转换为 axum body.
    let body = Body::from_stream(ReceiverStream::new(rx));
    let mut resp = Response::new(body);
    *resp.status_mut() = resp_status;
    *resp.headers_mut() = build_response_headers(&resp_headers);
    Ok(resp)
}

// ─── Error ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("invalid request body: {0}")]
    BadBody(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response<Body> {
        let (code, msg) = match &self {
            AppError::BadBody(m) => (400u16, m.clone()),
            AppError::Upstream(m) => (502, m.clone()),
            AppError::Internal(m) => (500, m.clone()),
        };
        error!(error = %self, "proxy error");
        let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut resp = Response::new(Body::from(format!("{{\"error\":\"{msg}\"}}")));
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

fn sanitize_request_headers(src: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(src.len());
    for (name, value) in src.iter() {
        let name_str = name.as_str().to_lowercase();
        if HOP_BY_HOP.contains(&name_str.as_str()) {
            continue;
        }
        if matches!(name_str.as_str(), "host" | "content-length") {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

fn build_response_headers(src: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(src.len());
    for (name, value) in src.iter() {
        let name_str = name.as_str().to_lowercase();
        if HOP_BY_HOP.contains(&name_str.as_str()) {
            continue;
        }
        // body 可能被改写, 长度不可信; 由 hyper 自动重新计算
        if name_str == "content-length" {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

fn is_streaming(content_type: &str) -> bool {
    content_type.contains("text/event-stream") || content_type.contains("stream")
}

fn utf8_view(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// 敏感 header 脱敏 (仅用于记录存储, 不影响转发).
fn redact_headers(src: &HeaderMap) -> Vec<(String, String)> {
    src.iter()
        .map(|(name, value)| {
            let name_str = name.as_str().to_lowercase();
            let v = if matches!(
                name_str.as_str(),
                "authorization"
                    | "x-api-key"
                    | "api-key"
                    | "cookie"
                    | "set-cookie"
                    | "proxy-authorization"
            ) {
                "<redacted>".to_string()
            } else {
                value.to_str().unwrap_or("<binary>").to_string()
            };
            (name_str, v)
        })
        .collect()
}

// 引入 futures::StreamExt 以使用 .next()
use futures::StreamExt;

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
    fn sanitize_strips_hop_by_hop() {
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
    fn redact_headers_masks_secrets() {
        let mut src = HeaderMap::new();
        src.insert("authorization", "Bearer xxx".parse().unwrap());
        src.insert("x-api-key", "key".parse().unwrap());
        src.insert("x-custom", "value".parse().unwrap());
        let v = redact_headers(&src);
        let m: std::collections::HashMap<_, _> = v.into_iter().collect();
        assert_eq!(m.get("authorization").unwrap(), "<redacted>");
        assert_eq!(m.get("x-api-key").unwrap(), "<redacted>");
        assert_eq!(m.get("x-custom").unwrap(), "value");
    }

    #[test]
    fn is_streaming_detects_sse() {
        assert!(is_streaming("text/event-stream"));
        assert!(is_streaming("application/x-ndjson; stream"));
        assert!(!is_streaming("application/json"));
    }

    #[test]
    fn utf8_view_handles_invalid_utf8() {
        let bad = &[0xFF, 0xFE, 0x00];
        let s = utf8_view(bad);
        assert!(s.contains('\u{FFFD}'));
    }
}
