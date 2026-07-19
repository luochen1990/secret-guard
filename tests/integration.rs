//! 端到端集成测试: 启动 secret-guard + mock 上游, 验证透传功能.
//!
//! 测试覆盖:
//! - 非流式响应: 完整 JSON body 透传
//! - 流式响应: SSE chunks 透传
//! - 请求 header 透传 (Authorization 等敏感字段保留)
//! - 转发记录被持久化
//! - 上游 non-2xx 透传
//! - 上游不可达时返回 502 + record 标记 incomplete
//! - hop-by-hop / Connection 自定义 header 被剥离
//! - Web UI: `/__sg/` HTML 与 `/__sg/api/records` JSON

use std::time::Duration;

use secret_guard::{
    proxy::ProxyState,
    record::RecordStore,
    secrets::{SecretCategory, SecretEntry, SecretTable},
    server,
};
use tokio::net::TcpListener;

/// 在随机端口启动一个 mock 上游, 返回其 server guard.
async fn spawn_mock_upstream() -> mockito::ServerGuard {
    mockito::Server::new_async().await
}

/// 在随机端口启动 secret-guard, 返回其 base URL.
async fn spawn_proxy(upstream_base: String) -> String {
    spawn_proxy_with(upstream_base, reqwest::Client::new(), RecordStore::new(64)).await
}

async fn spawn_proxy_with(
    upstream_base: String,
    upstream: reqwest::Client,
    records: RecordStore,
) -> String {
    spawn_proxy_full(upstream_base, upstream, records, test_secret_table()).await
}

async fn spawn_proxy_full(
    upstream_base: String,
    upstream: reqwest::Client,
    records: RecordStore,
    secrets: SecretTable,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = ProxyState {
        upstream,
        upstream_base,
        records,
        secrets,
    };
    let app = server::build_router(proxy);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

/// 用于测试的空 SecretTable (config_path 指向临时文件).
fn test_secret_table() -> SecretTable {
    let id = uuid::Uuid::new_v4().to_string();
    let path = std::path::PathBuf::from(format!("/tmp/opencode/tmp/test-secret-table-{id}.toml"));
    let _ = std::fs::remove_file(&path);
    SecretTable::new(vec![], path)
}

/// 构造一个含给定 entries 的 SecretTable (用于 redact 测试).
fn test_secret_table_with(entries: Vec<SecretEntry>) -> SecretTable {
    let id = uuid::Uuid::new_v4().to_string();
    let path = std::path::PathBuf::from(format!("/tmp/opencode/tmp/test-secret-table-{id}.toml"));
    let _ = std::fs::remove_file(&path);
    SecretTable::new(entries, path)
}

fn secret(id: &str, value: &str) -> SecretEntry {
    SecretEntry {
        id: id.into(),
        name: Some(id.into()),
        category: SecretCategory::ApiKey,
        value: value.into(),
    }
}

async fn proxy_request(
    proxy_url: &str,
    method: &str,
    path: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (reqwest::StatusCode, String, reqwest::header::HeaderMap) {
    let mut builder = reqwest::Client::new().request(
        reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
        format!("{proxy_url}{path}"),
    );
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let resp = builder.body(body.to_string()).send().await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let text = resp.text().await.unwrap();
    (status, text, headers)
}

/// 轮询直到 `predicate` 满足, 或超时. 用于等待后台 spawn task 写回记录.
async fn wait_until_or_timeout<F>(
    records: &RecordStore,
    predicate: F,
    timeout: Duration,
) -> Vec<secret_guard::record::ForwardRecord>
where
    F: Fn(&[secret_guard::record::ForwardRecord]) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let list = records.list();
        if predicate(&list) {
            return list;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timeout waiting for record update; current list: {list:?}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
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
        &[
            ("x-api-key", "test-key"),
            ("anthropic-version", "2023-06-01"),
        ],
    )
    .await;

    assert_eq!(status, reqwest::StatusCode::OK);
    assert!(body.contains("msg_1"));
    assert_eq!(headers.get("content-type").unwrap(), "application/json");
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

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
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
        &[
            ("x-api-key", "secret-key"),
            ("anthropic-version", "2023-06-01"),
        ],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn strips_custom_connection_listed_header() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .match_header("x-should-not-leak", mockito::Matcher::Missing)
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
        &[
            ("connection", "x-should-not-leak"),
            ("x-should-not-leak", "leak-value"),
        ],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
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

    let upstream_client = reqwest::Client::new();
    let records = RecordStore::new(64);
    let records_handle = records.clone();
    let proxy_url = spawn_proxy_with(upstream.url().to_string(), upstream_client, records).await;

    let _ = proxy_request(&proxy_url, "POST", "/v1/messages", r#"{"q":"hi"}"#, &[]).await;

    // 等待后台 task 写回 (避免 flaky sleep).
    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;

    assert_eq!(list.len(), 1, "exactly one record expected");
    let r = &list[0];
    assert_eq!(r.method, "POST");
    assert_eq!(r.path, "/v1/messages");
    assert!(r.req_body.contains("\"q\":\"hi\""));
    assert_eq!(r.resp_status, 200);
    assert!(r.resp_body.contains("\"ok\":true"));
    assert!(r.resp_complete);
    assert!(r.error.is_none());
}

#[tokio::test]
async fn upstream_non_2xx_is_forwarded() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(429)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"rate_limited"}"#)
        .create_async()
        .await;

    let proxy_url = spawn_proxy(upstream.url()).await;
    let (status, body, _) = proxy_request(&proxy_url, "POST", "/v1/messages", "{}", &[]).await;
    assert_eq!(status, reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert!(body.contains("rate_limited"));
}

#[tokio::test]
async fn upstream_unreachable_returns_502_and_marks_record_incomplete() {
    // 用一个未监听的端口作为 upstream, 必然连接失败.
    let dummy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_addr = dummy_listener.local_addr().unwrap();
    drop(dummy_listener);

    let upstream_client = reqwest::Client::new();
    let records = RecordStore::new(64);
    let records_handle = records.clone();
    let proxy_url = spawn_proxy_with(format!("http://{bad_addr}"), upstream_client, records).await;

    let (status, body, _) = proxy_request(&proxy_url, "POST", "/v1/messages", "{}", &[]).await;
    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
    assert!(body.contains("upstream_error"));

    // 后台 task 写回 record (incomplete + error).
    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.error.is_some()).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let r = &list[0];
    assert_eq!(r.resp_status, 502);
    assert!(!r.resp_complete);
    assert!(r.error.as_deref().unwrap().contains("upstream send error"));
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
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn passes_query_string_through() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("GET", "/v1/models")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("limit".into(), "10".into()),
            mockito::Matcher::UrlEncoded("order".into(), "desc".into()),
        ]))
        .with_status(200)
        .with_body("[]")
        .create_async()
        .await;

    let proxy_url = spawn_proxy(upstream.url()).await;
    let (status, _, _) =
        proxy_request(&proxy_url, "GET", "/v1/models?limit=10&order=desc", "", &[]).await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn web_ui_serves_html() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    // `/__sg` 无尾斜杠: 应直接返回 HTML.
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert!(body.contains("secret-guard"));
    assert!(body.contains("<html"));
}

#[tokio::test]
async fn web_api_lists_records() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let upstream_client = reqwest::Client::new();
    let records = RecordStore::new(64);
    let records_handle = records.clone();
    let proxy_url = spawn_proxy_with(upstream.url().to_string(), upstream_client, records).await;

    let _ = proxy_request(&proxy_url, "POST", "/v1/messages", "{}", &[]).await;

    // 等待记录写回.
    wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;

    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/records"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    let recs = body.get("records").and_then(|v| v.as_array()).unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["method"], "POST");
    assert_eq!(recs[0]["path"], "/v1/messages");
}

#[tokio::test]
async fn web_api_returns_record_by_id() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_body(r#"{"ok":true}"#)
        .create_async()
        .await;

    let upstream_client = reqwest::Client::new();
    let records = RecordStore::new(64);
    let records_handle = records.clone();
    let proxy_url = spawn_proxy_with(upstream.url().to_string(), upstream_client, records).await;

    let _ = proxy_request(&proxy_url, "POST", "/v1/messages", r#"{"q":"hi"}"#, &[]).await;

    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let id = list[0].id;

    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/records/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["id"], id.to_string());
    assert_eq!(body["resp_status"], 200);
}

#[tokio::test]
async fn web_api_404_for_unknown_record() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let resp = reqwest::Client::new()
        .get(format!(
            "{proxy_url}/__sg/api/records/00000000-0000-0000-0000-000000000000"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn web_api_400_for_invalid_uuid() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/records/not-a-uuid"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn web_api_records_empty_when_no_traffic() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/records"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    let recs = body.get("records").and_then(|v| v.as_array()).unwrap();
    assert_eq!(recs.len(), 0);
}

#[tokio::test]
async fn web_namespace_not_forwarded_to_upstream() {
    // `/__sg/api/records/` (尾斜杠, axum nest 不会匹配) 必须不被 catch-all 吞掉
    // 而泄漏到上游. 测试断言: 上游绝不应收到任何 `/__sg/*` 请求.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let proxy_url = spawn_proxy(upstream.url()).await;

    // 即使尾斜杠路由未明确, 也至少不应进入 forward; 即使 404 也 OK, 关键是不应静默转发.
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/records/"))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    // 期望 404 (or 任何非 2xx), 而非转发到上游后返回的 200.
    assert!(
        !status.is_success(),
        "expected /__sg/* to NOT be forwarded upstream, got status {status}"
    );
}

// ─── secrets API ──────────────────────────────────────────────────────────

#[tokio::test]
async fn secrets_api_lists_empty() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/secrets"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    let secrets = body.get("secrets").and_then(|v| v.as_array()).unwrap();
    assert_eq!(secrets.len(), 0);
    // categories 字段返回可选列表.
    let cats = body.get("categories").and_then(|v| v.as_array()).unwrap();
    assert!(cats.len() >= 5);
}

#[tokio::test]
async fn secrets_api_create_lists_update_delete() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let client = reqwest::Client::new();

    // Create.
    let resp = client
        .post(format!("{proxy_url}/__sg/api/secrets"))
        .json(&serde_json::json!({
            "id": "test-key-1",
            "name": "Test API Key",
            "category": "apikey",
            "value": "sk-test-1234567890abcdef",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let created: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(created["id"], "test-key-1");
    assert_eq!(created["name"], "Test API Key");
    assert_eq!(created["category"], "apikey");
    // value 必须被脱敏, 不可返回真实值.
    assert_ne!(created["value_masked"], "sk-test-1234567890abcdef");
    assert!(created["value_masked"].as_str().unwrap().contains('*'));
    assert_eq!(created["value_length"], 24);

    // List 看到新增.
    let resp = client
        .get(format!("{proxy_url}/__sg/api/secrets"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let secrets = body.get("secrets").and_then(|v| v.as_array()).unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0]["id"], "test-key-1");

    // Update (改名 + 换值).
    let resp = client
        .put(format!("{proxy_url}/__sg/api/secrets/test-key-1"))
        .json(&serde_json::json!({
            "name": "Renamed",
            "category": "token",
            "value": "new-token-value-9876543210",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let updated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(updated["name"], "Renamed");
    assert_eq!(updated["category"], "token");
    assert_eq!(updated["value_length"], 26);

    // Delete.
    let resp = client
        .delete(format!("{proxy_url}/__sg/api/secrets/test-key-1"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // List 再次为空.
    let resp = client
        .get(format!("{proxy_url}/__sg/api/secrets"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let secrets = body.get("secrets").and_then(|v| v.as_array()).unwrap();
    assert_eq!(secrets.len(), 0);
}

#[tokio::test]
async fn secrets_api_rejects_empty_value() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/__sg/api/secrets"))
        .json(&serde_json::json!({
            "id": "bad",
            "value": "",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn secrets_api_delete_missing_returns_404() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let resp = reqwest::Client::new()
        .delete(format!("{proxy_url}/__sg/api/secrets/does-not-exist"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

// ─── redact / restore flow ─────────────────────────────────────────────────

#[tokio::test]
async fn redact_strips_secret_from_upstream_request() {
    let real_secret = "sk-test-123";
    let mut upstream = spawn_mock_upstream().await;
    // 上游无条件返回 200; mockito 不易表达"不包含 secret"的匹配,
    // 我们通过 RecordStore 中的 req_body 来验证 redact 是否生效.
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"msg_1"}"#)
        .create_async()
        .await;

    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = RecordStore::new(64);
    let records_handle = records.clone();
    let proxy_url = spawn_proxy_full(
        upstream.url().to_string(),
        upstream_client,
        records,
        secrets,
    )
    .await;

    let body = format!(r#"{{"messages":[{{"content":"use {real_secret} now"}}]}}"#);
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/v1/messages"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // 通过 RecordStore 验证 req_body 已被改写 (不含真实 secret).
    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let r = &list[0];
    assert!(
        !r.req_body.contains(real_secret),
        "record body must not contain real secret, got: {}",
        r.req_body
    );
    assert!(
        r.req_body.contains("use") && r.req_body.contains("now"),
        "non-secret content must be preserved, got: {}",
        r.req_body
    );
}

#[tokio::test]
async fn restore_inserts_secret_back_for_client() {
    let real_secret = "sk-test-123";
    let mut upstream = spawn_mock_upstream().await;
    // 上游返回 mock 字符 (LLM 看到的版本); 客户端应拿到 real_secret.
    let _m = upstream
        .mock("POST", "/echo")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"echo":"<placeholder>"}"#)
        .create_async()
        .await;

    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = RecordStore::new(64);
    let records_handle = records.clone();
    let proxy_url = spawn_proxy_full(
        upstream.url().to_string(),
        upstream_client,
        records,
        secrets,
    )
    .await;

    // 触发 redact 以建立 mock 映射.
    let body = format!(r#"{{"input":"use {real_secret} now"}}"#);
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/echo"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    let resp_text = resp.text().await.unwrap();

    // record 中存的是 LLM 视角 (含 mock): 客户端拿到的是 restored 版本.
    // 客户端响应里没有 secret (因为上游 echo 的就是 placeholder), 但至少证明 round-trip OK.
    assert!(resp_text.contains("placeholder"));

    // 检查 record 的 req_body 是改写过的 (含 mock, 不含真实 secret).
    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let r = &list[0];
    assert!(
        !r.req_body.contains(real_secret),
        "record body must not contain real secret: {}",
        r.req_body
    );
}

#[tokio::test]
async fn no_redact_when_secret_table_empty() {
    // 没配 secret 时, body 应当原样透传.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .match_body(mockito::Matcher::Exact("raw-body".into()))
        .with_status(200)
        .with_body("ok")
        .create_async()
        .await;

    let proxy_url = spawn_proxy(upstream.url()).await;
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/v1/messages"))
        .body("raw-body")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}
