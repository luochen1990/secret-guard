//! 端到端集成测试: 启动 secret-guard + mock 上游, 验证透传功能.
//!
//! 测试覆盖:
//! - 非流式响应: 完整 JSON body 透传
//! - 流式响应: SSE chunks 透传
//! - 请求 header 透传 (Authorization 等敏感字段保留)
//! - 转发记录被持久化

use std::time::Duration;

use axum::{
    body::Body,
    http::StatusCode,
};
use http_body_util::BodyExt;
use secret_guard::{proxy::ProxyState, record::RecordStore, server};
use tokio::net::TcpListener;

/// 在随机端口启动一个 mock 上游, 返回其 base URL 与 `MockServer`.
async fn spawn_mock_upstream() -> mockito::ServerGuard {
    mockito::Server::new_async().await
}

/// 在随机端口启动 secret-guard, 返回其 base URL.
async fn spawn_proxy(upstream_base: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream = reqwest::Client::new();
    let records = RecordStore::new(64);
    let state = ProxyState::new(upstream, upstream_base, records);
    let app = server::build_router(server::AppState::new(state));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn proxy_request(
    proxy_url: &str,
    method: &str,
    path: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, String, reqwest::header::HeaderMap) {
    let mut builder = reqwest::Client::new()
        .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), format!("{proxy_url}{path}"));
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let resp = builder.body(body.to_string()).send().await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let text = resp.text().await.unwrap();
    (status, text, headers)
}

#[tokio::test]
async fn forwards_non_streaming_json() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"msg_1","content":"hello"}"#)
        .create_async()
        .await;

    let proxy_url = spawn_proxy(upstream.url()).await;
    let (status, body, headers) = proxy_request(
        &proxy_url,
        "POST",
        "/v1/messages",
        r#"{"model":"claude-3"}"#,
        &[("x-api-key", "test-key"), ("anthropic-version", "2023-06-01")],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("msg_1"));
    assert_eq!(
        headers.get("content-type").unwrap(),
        "application/json"
    );
}

#[tokio::test]
async fn forwards_streaming_sse() {
    let mut upstream = spawn_mock_upstream().await;
    let sse_body = concat!(
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n"
    );
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;

    let proxy_url = spawn_proxy(upstream.url()).await;
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/v1/messages"))
        .header("x-api-key", "test-key")
        .body(r#"{"model":"claude-3","stream":true}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let text = resp.text().await.unwrap();
    assert!(text.contains("content_block_delta"));
    assert!(text.contains("message_stop"));
}

#[tokio::test]
async fn propagates_request_headers_upstream() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .match_header("x-api-key", "secret-key")
        .match_header("anthropic-version", "2023-06-01")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let proxy_url = spawn_proxy(upstream.url()).await;
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/v1/messages",
        "{}",
        &[("x-api-key", "secret-key"), ("anthropic-version", "2023-06-01")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn records_request_and_response_snapshots() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"ok":true}"#)
        .create_async()
        .await;

    // 共享 RecordStore: 在 proxy 与 test 间用同一句柄.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_client = reqwest::Client::new();
    let records = RecordStore::new(64);
    let records_handle = records.clone();
    let state = ProxyState::new(upstream_client, upstream.url().to_string(), records);
    let app = server::build_router(server::AppState::new(state));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let _ = proxy_request(
        &format!("http://{addr}"),
        "POST",
        "/v1/messages",
        r#"{"q":"hi"}"#,
        &[],
    )
    .await;

    // 后台 task 可能稍晚写回响应, 给 200ms 余量.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let list = records_handle.list();
    assert_eq!(list.len(), 1, "exactly one record expected");
    let r = &list[0];
    assert_eq!(r.method, "POST");
    assert_eq!(r.path, "/v1/messages");
    assert!(r.req_body.contains("\"q\":\"hi\""));
    assert_eq!(r.resp_status, 200);
    assert!(r.resp_body.contains("\"ok\":true"));
}

#[tokio::test]
async fn returns_502_on_upstream_failure() {
    // 用一个未监听的端口作为 upstream, 必然连接失败.
    let dummy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_addr = dummy_listener.local_addr().unwrap();
    drop(dummy_listener);

    let proxy_url = spawn_proxy(format!("http://{bad_addr}")).await;
    let (status, body, _) =
        proxy_request(&proxy_url, "POST", "/v1/messages", "{}", &[]).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(body.contains("error"));
}

#[tokio::test]
async fn get_method_is_forwarded() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("GET", "/healthz")
        .with_status(200)
        .with_body("ok")
        .create_async()
        .await;

    let proxy_url = spawn_proxy(upstream.url()).await;
    let (status, body, _) = proxy_request(&proxy_url, "GET", "/healthz", "", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

/// 工具函数: 把 axum Body 完整读为 bytes (备用).
#[allow(dead_code)]
async fn read_body_full(body: Body) -> Vec<u8> {
    body.collect().await.unwrap().to_bytes().to_vec()
}

// http_body_util 是 dev 依赖, 显式声明避免 cargo machete 误报.
#[allow(unused_imports)]
use http_body_util as _http_body_util_marker;
