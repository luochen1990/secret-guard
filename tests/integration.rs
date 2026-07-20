//! 端到端集成测试: 启动 secret-guard + mock 上游, 验证透传功能.
//!
//! 测试覆盖:
//! - 多 provider 路由 (`/{proto}/{name}/*`).
//! - 同协议 identity passthrough (OpenAI / Anthropic / Gemini / Ollama).
//! - 跨协议请求返回 501.
//! - 未知 provider / 禁用 provider 返回 404 / 503.
//! - 未知 protocol 简写返回 404.
//! - 流式 SSE / 非流式 JSON 透传.
//! - 请求 header 透传; provider api_key 覆盖客户端 auth.
//! - 转发记录被持久化.
//! - 上游不可达时返回 502 + record 标记 incomplete.
//! - Web UI: `/` 根路径 + `/__sg/` HTML; `/__sg/api/*` JSON.

use std::time::Duration;

use secret_guard::{
    provider::{Protocol, Provider, ProviderTable},
    proxy::ProxyState,
    record::RecordStore,
    secrets::{SecretCategory, SecretEntry, SecretTable},
    server,
};
use tokio::net::TcpListener;

async fn spawn_mock_upstream() -> mockito::ServerGuard {
    mockito::Server::new_async().await
}

/// 启动 secret-guard, 单 provider (默认 OpenAI 协议, base_url = mock 上游).
async fn spawn_proxy_with_provider(_upstream_base: String, provider: Provider) -> String {
    spawn_proxy_full(
        vec![provider],
        reqwest::Client::new(),
        RecordStore::new(64),
        test_secret_table(),
    )
    .await
}

/// 启动 secret-guard, 默认 OpenAI provider 指向 mock 上游.
async fn spawn_proxy(upstream_base: String) -> String {
    let provider = openai_provider("oa-main", &upstream_base);
    spawn_proxy_with_provider(upstream_base, provider).await
}

fn openai_provider(id: &str, base_url: &str) -> Provider {
    Provider {
        id: id.into(),
        protocol: Protocol::OpenAI,
        base_url: base_url.into(),
        api_key: "sk-test-key".into(),
        enabled: true,
        name: Some(id.into()),
    }
}

fn provider_with(id: &str, proto: Protocol, base_url: &str) -> Provider {
    Provider {
        id: id.into(),
        protocol: proto,
        base_url: base_url.into(),
        api_key: String::new(),
        enabled: true,
        name: Some(id.into()),
    }
}
#[allow(clippy::too_many_arguments)]
async fn spawn_proxy_full(
    providers: Vec<Provider>,
    upstream: reqwest::Client,
    records: RecordStore,
    secrets: SecretTable,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let cfg_path = std::path::PathBuf::from(format!("/tmp/opencode/tmp/test-sg-cfg-{id}.toml"));
    let _ = std::fs::remove_file(&cfg_path);
    let provider_table = ProviderTable::new(providers, cfg_path);
    let proxy = ProxyState {
        upstream,
        providers: provider_table,
        records,
        secrets,
    };
    let app = server::build_router(proxy);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

fn test_secret_table() -> SecretTable {
    test_secret_table_with(vec![])
}

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

// ─── 基础转发 ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn forwards_non_streaming_json() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"chatcmpl-1","choices":[]}"#)
        .create_async()
        .await;

    let proxy_url = spawn_proxy(upstream.url()).await;
    let (status, body, headers) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        r#"{"model":"gpt-4"}"#,
        &[],
    )
    .await;

    assert_eq!(status, reqwest::StatusCode::OK);
    assert!(body.contains("chatcmpl-1"));
    assert_eq!(headers.get("content-type").unwrap(), "application/json");
}

#[tokio::test]
async fn forwards_streaming_sse() {
    let mut upstream = spawn_mock_upstream().await;
    let sse_body = concat!(
        "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;

    let proxy_url = spawn_proxy(upstream.url()).await;
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .body(r#"{"model":"gpt-4","stream":true}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let text = resp.text().await.unwrap();
    assert!(text.contains("\"delta\""));
    assert!(text.contains("[DONE]"));
}

#[tokio::test]
async fn provider_api_key_overrides_client_auth() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .match_header("authorization", "Bearer sk-test-key")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let proxy_url = spawn_proxy(upstream.url()).await;
    // 客户端发了个错误的 token; 服务端应使用 provider 配置的 api_key.
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        "{}",
        &[("authorization", "Bearer WRONG-TOKEN")],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn anthropic_provider_uses_x_api_key() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .match_header("x-api-key", "sk-ant-test")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let provider = Provider {
        id: "an-main".into(),
        protocol: Protocol::Anthropic,
        base_url: upstream.url(),
        api_key: "sk-ant-test".into(),
        enabled: true,
        name: None,
    };
    let proxy_url = spawn_proxy_with_provider(upstream.url(), provider).await;
    let (status, _, _) =
        proxy_request(&proxy_url, "POST", "/a/an-main/v1/messages", "{}", &[]).await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn strips_custom_connection_listed_header() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .match_header("x-should-not-leak", mockito::Matcher::Missing)
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let proxy_url = spawn_proxy(upstream.url()).await;
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
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
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"ok":true}"#)
        .create_async()
        .await;

    let upstream_client = reqwest::Client::new();
    let records = RecordStore::new(64);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        upstream_client,
        records,
        test_secret_table(),
    )
    .await;

    let _ = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        r#"{"q":"hi"}"#,
        &[],
    )
    .await;

    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;

    assert_eq!(list.len(), 1, "exactly one record expected");
    let r = &list[0];
    assert_eq!(r.method, "POST");
    assert_eq!(r.path, "/o/oa-main/v1/chat/completions");
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
        .mock("POST", "/v1/chat/completions")
        .with_status(429)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"rate_limited"}"#)
        .create_async()
        .await;

    let proxy_url = spawn_proxy(upstream.url()).await;
    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert!(body.contains("rate_limited"));
}

#[tokio::test]
async fn upstream_unreachable_returns_502_and_marks_record_incomplete() {
    let dummy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_addr = dummy_listener.local_addr().unwrap();
    drop(dummy_listener);

    let upstream_client = reqwest::Client::new();
    let records = RecordStore::new(64);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &format!("http://{bad_addr}"));
    let proxy_url = spawn_proxy_full(
        vec![provider],
        upstream_client,
        records,
        test_secret_table(),
    )
    .await;

    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
    assert!(body.contains("upstream_error"));

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
    let (status, body, _) = proxy_request(&proxy_url, "GET", "/o/oa-main/healthz", "", &[]).await;
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
    let (status, _, _) = proxy_request(
        &proxy_url,
        "GET",
        "/o/oa-main/v1/models?limit=10&order=desc",
        "",
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

// ─── 路由错误语义 ───────────────────────────────────────────────────────────

#[tokio::test]
async fn unknown_protocol_returns_404() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let (status, body, _) = proxy_request(&proxy_url, "POST", "/x/foo/v1/chat", "{}", &[]).await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
    assert!(body.contains("not_found"));
}

#[tokio::test]
async fn unknown_provider_returns_404() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/does-not-exist/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
    assert!(body.contains("not_found"));
}

#[tokio::test]
async fn disabled_provider_returns_503() {
    let mut upstream = spawn_mock_upstream().await;
    // 即使上游能响应, 也不应该被调用.
    let _m = upstream
        .mock("POST", mockito::Matcher::Any)
        .with_status(200)
        .with_body("should-not-happen")
        .create_async()
        .await;

    let provider = Provider {
        enabled: false,
        ..openai_provider("oa-disabled", &upstream.url())
    };
    let proxy_url = spawn_proxy_with_provider(upstream.url(), provider).await;
    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-disabled/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("unavailable"));
}

#[tokio::test]
async fn cross_protocol_returns_501() {
    // provider 协议是 Anthropic, 但客户端用 /o/ (OpenAI 入口) 访问.
    let upstream = spawn_mock_upstream().await;
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(upstream.url(), provider).await;
    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::NOT_IMPLEMENTED);
    assert!(body.contains("not_implemented"));
    assert!(body.contains("cross-protocol"));
}

#[tokio::test]
async fn no_rest_segment_routes_to_root() {
    // /o/{name} 应当等价于 /o/{name}/ → 上游收到 GET /.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("GET", "/")
        .with_status(200)
        .with_body("root")
        .create_async()
        .await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let (status, body, _) = proxy_request(&proxy_url, "GET", "/o/oa-main", "", &[]).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body, "root");
}

#[tokio::test]
async fn unmatched_path_returns_404() {
    // 单段路径不匹配 `/{proto}/{name}` 路由, 应当 404 (不被 catch-all 转发).
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/just-one-segment"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

// ─── Web UI / API ──────────────────────────────────────────────────────────

#[tokio::test]
async fn root_serves_web_ui() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert!(body.contains("secret-guard"));
    assert!(body.contains("<html"));
}

#[tokio::test]
async fn web_ui_legacy_path_still_works() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert!(resp.text().await.unwrap().contains("secret-guard"));
}

#[tokio::test]
async fn web_api_lists_records() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let upstream_client = reqwest::Client::new();
    let records = RecordStore::new(64);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        upstream_client,
        records,
        test_secret_table(),
    )
    .await;

    let _ = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        "{}",
        &[],
    )
    .await;

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
    assert_eq!(recs[0]["path"], "/o/oa-main/v1/chat/completions");
}

#[tokio::test]
async fn web_api_returns_record_by_id() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_body(r#"{"ok":true}"#)
        .create_async()
        .await;

    let upstream_client = reqwest::Client::new();
    let records = RecordStore::new(64);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        upstream_client,
        records,
        test_secret_table(),
    )
    .await;

    let _ = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        r#"{"q":"hi"}"#,
        &[],
    )
    .await;

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
async fn web_namespace_not_forwarded_to_upstream() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let proxy_url = spawn_proxy(upstream.url()).await;

    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/records/"))
        .send()
        .await
        .unwrap();
    let status = resp.status();
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
    let cats = body.get("categories").and_then(|v| v.as_array()).unwrap();
    assert!(cats.len() >= 5);
}

#[tokio::test]
async fn secrets_api_create_lists_update_delete() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let client = reqwest::Client::new();

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
    assert_ne!(created["value_masked"], "sk-test-1234567890abcdef");

    let resp = client
        .get(format!("{proxy_url}/__sg/api/secrets"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let secrets = body.get("secrets").and_then(|v| v.as_array()).unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0]["id"], "test-key-1");

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

    let resp = client
        .delete(format!("{proxy_url}/__sg/api/secrets/test-key-1"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
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

// ─── providers API ─────────────────────────────────────────────────────────

#[tokio::test]
async fn providers_api_lists_existing() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/providers"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    let providers = body.get("providers").and_then(|v| v.as_array()).unwrap();
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0]["id"], "oa-main");
    assert_eq!(providers[0]["protocol"], "openai");
    assert_eq!(providers[0]["api_key_masked"], "s*********y"); // "sk-test-key" (11 chars)
    assert!(body.get("protocols").unwrap().as_array().unwrap().len() >= 4);
    assert!(body.get("shorts").unwrap().as_array().unwrap().len() >= 4);
}

#[tokio::test]
async fn providers_api_create_update_delete() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let client = reqwest::Client::new();

    // 创建新 Anthropic provider.
    let resp = client
        .post(format!("{proxy_url}/__sg/api/providers"))
        .json(&serde_json::json!({
            "id": "an-main",
            "name": "Anthropic Main",
            "protocol": "anthropic",
            "base_url": "https://api.anthropic.com",
            "api_key": "sk-ant-test-12345",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let created: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(created["id"], "an-main");
    assert_eq!(created["protocol"], "anthropic");
    assert_ne!(created["api_key_masked"], "sk-ant-test-12345");
    assert_eq!(created["api_key_length"], 17); // "sk-ant-test-12345"

    // List 看到 2 条.
    let resp = client
        .get(format!("{proxy_url}/__sg/api/providers"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let providers = body.get("providers").and_then(|v| v.as_array()).unwrap();
    assert_eq!(providers.len(), 2);

    // Update: 改 base_url.
    let resp = client
        .put(format!("{proxy_url}/__sg/api/providers/an-main"))
        .json(&serde_json::json!({
            "protocol": "anthropic",
            "base_url": "https://api.anthropic.com/v2",
            "api_key": "sk-ant-new",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let updated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(updated["base_url"], "https://api.anthropic.com/v2");

    // Delete.
    let resp = client
        .delete(format!("{proxy_url}/__sg/api/providers/an-main"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // 剩 1 条.
    let resp = client
        .get(format!("{proxy_url}/__sg/api/providers"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let providers = body.get("providers").and_then(|v| v.as_array()).unwrap();
    assert_eq!(providers.len(), 1);
}

#[tokio::test]
async fn providers_api_rejects_bad_base_url() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(upstream.url()).await;
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/__sg/api/providers"))
        .json(&serde_json::json!({
            "id": "bad",
            "protocol": "openai",
            "base_url": "not-a-url",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

// ─── redact / restore flow ─────────────────────────────────────────────────

#[tokio::test]
async fn redact_strips_secret_from_upstream_request() {
    let real_secret = "sk-test-123";
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"chatcmpl-1"}"#)
        .create_async()
        .await;

    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = RecordStore::new(64);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(r#"{{"messages":[{{"content":"use {real_secret} now"}}]}}"#);
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

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
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(r#"{{"input":"use {real_secret} now"}}"#);
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/echo"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    let resp_text = resp.text().await.unwrap();
    assert!(resp_text.contains("placeholder"));

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
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .match_body(mockito::Matcher::Exact("raw-body".into()))
        .with_status(200)
        .with_body("ok")
        .create_async()
        .await;

    let proxy_url = spawn_proxy(upstream.url()).await;
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .body("raw-body")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}
