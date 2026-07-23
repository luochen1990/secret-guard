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
    dag::ConversationDag,
    provider::{Protocol, Provider, ProviderTable},
    proxy::ProxyState,
    record::ForwardRecord,
    secrets::{SecretCategory, SecretEntry, SecretTable},
    server,
};
use tokio::net::TcpListener;

/// 生成唯一的 state.toml 临时路径, 并确保父目录存在
/// (atomic_write 不创建目录, 集成测试的 CRUD 会触发持久化).
fn tmp_state_path(label: &str) -> std::path::PathBuf {
    let id = uuid::Uuid::new_v4().to_string();
    let path = std::path::PathBuf::from(format!("/tmp/opencode/tmp/test-{label}-{id}.toml"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    path
}

async fn spawn_mock_upstream() -> mockito::ServerGuard {
    mockito::Server::new_async().await
}

/// 启动 secret-guard, 单 provider (默认 OpenAI 协议, base_url = mock 上游).
async fn spawn_proxy_with_provider(provider: Provider) -> String {
    spawn_proxy_full(
        vec![provider],
        reqwest::Client::new(),
        ConversationDag::new(64),
        test_secret_table(),
    )
    .await
}

/// 启动 secret-guard, 默认 OpenAI provider 指向 mock 上游.
async fn spawn_proxy(upstream_base: &str) -> String {
    let provider = openai_provider("oa-main", upstream_base);
    spawn_proxy_with_provider(provider).await
}

fn openai_provider(id: &str, base_url: &str) -> Provider {
    Provider {
        id: id.into(),
        protocol: Protocol::OpenAI,
        base_url: base_url.into(),
        api_key: "sk-test-key".into(),
        api_key_file: None,
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
        api_key_file: None,
        enabled: true,
        name: Some(id.into()),
    }
}
#[allow(clippy::too_many_arguments)]
async fn spawn_proxy_full(
    providers: Vec<Provider>,
    upstream: reqwest::Client,
    records: ConversationDag,
    secrets: SecretTable,
) -> String {
    spawn_proxy_static_dynamic(vec![], providers, upstream, records, secrets).await
}

/// 显式同时指定 static + dynamic 两层.
/// 旧 helper (`spawn_proxy_full`) 把所有传入视为 dynamic, 仍保持向后兼容.
#[allow(clippy::too_many_arguments)]
async fn spawn_proxy_static_dynamic(
    static_providers: Vec<Provider>,
    dynamic_providers: Vec<Provider>,
    upstream: reqwest::Client,
    records: ConversationDag,
    secrets: SecretTable,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state_path = tmp_state_path("sg-state");

    // 共享 decisions + persist_lock, 模拟生产环境的双表协同.
    let decisions = std::sync::Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    let persist_lock = std::sync::Arc::new(parking_lot::Mutex::new(()));

    let provider_table = ProviderTable::with_persist_lock(
        static_providers,
        dynamic_providers,
        decisions.clone(),
        state_path.clone(),
        persist_lock.clone(),
    );

    // SecretTable 由调用方构造 (内部已带独立的 decisions + persist_lock).
    // 测试场景下 secrets 与 providers 不共享 state 文件, 不影响测试结论.
    let _ = (decisions, persist_lock, state_path);
    let proxy = ProxyState {
        upstream,
        providers: provider_table,
        dag: records,
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
    let path = tmp_state_path("secret-table");
    let decisions = std::sync::Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    // 旧测试语义: 把传入 entries 视为 dynamic (供 redact 流程使用).
    SecretTable::new(vec![], entries, decisions, path)
}

fn secret(id: &str, value: &str) -> SecretEntry {
    let mut e = SecretEntry {
        id: id.into(),
        name: Some(id.into()),
        category: SecretCategory::ApiKey,
        value: value.into(),
        value_file: None,
        mock_strategy: secret_guard::mock::MockStrategy::default(),
    };
    // 模拟生产 validate_and_resolve 路径: 让 Auto 模式的 gen spec 被 infer.
    e.mock_strategy.resolve_against(&e.value);
    e
}

/// 预测 redact 对给定 real_secret 生成的首个 mock (counter=0).
///
/// 与生产 [`secret_guard::redact::redact_ir`] 路径一致:
/// [`secret_guard::mock::deterministic_seed`] + counter=0.
/// 用于集成测试中 mockito 上游响应 fixture (需要预知 mock 值才能构造"LLM echo 了 mock"的场景).
fn predict_mock(real: &str) -> String {
    use secret_guard::mock::{deterministic_seed, gen_candidate};
    let entry = secret("predict", real);
    let seed = deterministic_seed(&entry.value, &entry.mock_strategy);
    gen_candidate(&entry.value, &entry.mock_strategy, seed, 0)
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

/// 从 DAG 派生 `Vec<ForwardRecord>` (newest first), 供断言检查.
///
/// 等价于旧 `RecordStore::list()` 的语义: walk 所有 node, 拼接元数据 + 请求 + 响应字段.
/// 集成测试用此 helper 把 DAG 视为"扁平 record 列表"做断言 (DAG 的会话折叠等高级特性
/// 不在集成测试的关注范围).
fn dag_list_forward_records(dag: &ConversationDag) -> Vec<ForwardRecord> {
    dag.list_node_ids_newest_first()
        .into_iter()
        .filter_map(|id| {
            let view = dag.get_node(id)?;
            let detail = dag.get_node_detail(id)?;
            let resp = dag.get_response(id);
            Some(ForwardRecord {
                id: view.id,
                created_at: view.created_at,
                method: view.method,
                path: view.path,
                req_headers: detail.req_headers,
                req_body: detail.req_body_raw,
                resp_status: view.resp_status,
                resp_headers: resp
                    .as_ref()
                    .map(|r| r.resp_headers.clone())
                    .unwrap_or_default(),
                resp_body: resp
                    .as_ref()
                    .map(|r| r.raw_resp_body.clone())
                    .unwrap_or_default(),
                resp_parsed: resp.as_ref().and_then(|r| r.parsed.clone()),
                elapsed_ms: view.elapsed_ms,
                streamed: view.streamed,
                resp_complete: view.resp_complete,
                error: view.error,
                redactions: view.redactions,
            })
        })
        .collect()
}

async fn wait_until_or_timeout<F>(
    records: &ConversationDag,
    predicate: F,
    timeout: Duration,
) -> Vec<ForwardRecord>
where
    F: Fn(&[ForwardRecord]) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let list = dag_list_forward_records(records);
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

    let proxy_url = spawn_proxy(&upstream.url()).await;
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

    let proxy_url = spawn_proxy(&upstream.url()).await;
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
async fn streaming_parsed_view_accumulates_text() {
    // 验证流式响应完成后, parsed view (resp_parsed) 包含累积的完整文本,
    // 而非原始 SSE 字节. 这是本次改动的核心契约.
    let mut upstream = spawn_mock_upstream().await;
    let sse_body = concat!(
        r#"data: {"id":"x","created":0,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"两者"},"finish_reason":null}]}"#,
        "\n\n",
        r#"data: {"id":"x","created":0,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"都可以"},"finish_reason":null}]}"#,
        "\n\n",
        r#"data: {"id":"x","created":0,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"工作"},"finish_reason":"stop"}]}"#,
        "\n\n",
        "data: [DONE]\n\n",
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;

    let proxy_url = spawn_proxy(&upstream.url()).await;
    let _ = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        r#"{"model":"gpt-4","stream":true,"messages":[{"role":"user","content":"hi"}]}"#,
        &[],
    )
    .await;

    // 等 record 完成.
    let records = wait_for_record_count(&format!("{proxy_url}/__sg/api/records"), 1).await;
    assert!(records[0].streamed, "should be streamed");
    assert!(records[0].resp_complete, "should be complete");

    // 拉 parsed view, 验证累积文本.
    let client = reqwest::Client::new();
    let env: serde_json::Value = client
        .get(format!(
            "{proxy_url}/__sg/api/records/{}?view=parsed",
            records[0].id
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let parsed_resp = env["parsed_response"]
        .as_object()
        .expect("parsed_response should exist");
    // OpenAI shape: choices[0].message.content
    let choices = parsed_resp["choices"]
        .as_array()
        .expect("choices should be array");
    let content = choices[0]["message"]["content"]
        .as_str()
        .expect("content should be string");
    assert_eq!(
        content, "两者都可以工作",
        "parsed view should contain accumulated text, got: {content}"
    );
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

    let proxy_url = spawn_proxy(&upstream.url()).await;
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
async fn provider_api_key_file_reads_secret_from_path() {
    // 端到端验证: provider.api_key_file 指向一个文件, secret-guard 应当在转发时读取其内容
    // (含 trim) 并注入 Authorization header. 这是 sops-nix 等外部 secret manager 集成的关键.
    let key_file = std::env::temp_dir().join(format!(
        "secret-guard-test-api-key-{}.txt",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&key_file, "sk-from-file\n").unwrap(); // 末尾换行应被 trim 掉

    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .match_header("authorization", "Bearer sk-from-file")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let provider = Provider {
        id: "oa-file".into(),
        protocol: Protocol::OpenAI,
        base_url: upstream.url(),
        api_key: String::new(),
        api_key_file: Some(key_file.clone()),
        enabled: true,
        name: None,
    };
    let proxy_url = spawn_proxy_with_provider(provider).await;

    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-file/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);

    std::fs::remove_file(&key_file).ok();
}

#[tokio::test]
async fn provider_api_key_file_missing_falls_through_to_no_auth() {
    // api_key_file 指向不存在的文件时, effective_api_key 返回空 → apply_provider_auth 跳过.
    // 这种"软失败"避免单个 provider 配置错误拖垮整个进程 (用户应该看到 401/403 from upstream).
    let mut upstream = spawn_mock_upstream().await;
    // mock 不约束 Authorization header (因为 secret-guard 不会注入任何 auth).
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let provider = Provider {
        id: "oa-broken".into(),
        protocol: Protocol::OpenAI,
        base_url: upstream.url(),
        api_key: String::new(),
        api_key_file: Some(std::path::PathBuf::from("/nonexistent/secret-guard-test")),
        enabled: true,
        name: None,
    };
    let proxy_url = spawn_proxy_with_provider(provider).await;

    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-broken/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    // secret-guard 不报错, 转发到上游; 上游 mock 接受了 (实际生产中上游会 401).
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
        api_key_file: None,
        enabled: true,
        name: None,
    };
    let proxy_url = spawn_proxy_with_provider(provider).await;
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

    let proxy_url = spawn_proxy(&upstream.url()).await;
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
    let records = ConversationDag::new(64);
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

    let proxy_url = spawn_proxy(&upstream.url()).await;
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
    let records = ConversationDag::new(64);
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

    let proxy_url = spawn_proxy(&upstream.url()).await;
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

    let proxy_url = spawn_proxy(&upstream.url()).await;
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
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let (status, body, _) = proxy_request(&proxy_url, "POST", "/x/foo/v1/chat", "{}", &[]).await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
    assert!(body.contains("not_found"));
}

#[tokio::test]
async fn unknown_provider_returns_404() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
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
    let proxy_url = spawn_proxy_with_provider(provider).await;
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
async fn cross_protocol_translates_system_prompt_to_anthropic_top_level() {
    // OpenAI messages[].role=="system" 应翻译为 Anthropic 顶层 system 字段.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({"system": "You are a helpful assistant."}),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"msg_x","type":"message","role":"assistant","content":[{"type":"text","text":"OK"}],"model":"claude","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}"#,
        )
        .create_async()
        .await;
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let body = r#"{"model":"gpt-4o","messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"Hi"}]}"#;
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        body,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn cross_protocol_anthropic_requires_max_tokens_injected() {
    // OpenAI 客户端不带 max_tokens, 跨协议到 Anthropic 时应注入默认值 4096.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({"max_tokens": 4096}),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"msg_x","type":"message","role":"assistant","content":[{"type":"text","text":"OK"}],"model":"claude","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}"#,
        )
        .create_async()
        .await;
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}"#;
    let (status, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        body,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn cross_protocol_translates_tools_and_tool_use_round_trip() {
    // OpenAI tools/tool_calls/tool messages → Anthropic tools/tool_use/tool_result 完整往返.
    // 仅断言关键字段 (tools 名, tool_use 块, tool_result 关联), 不强求完整 body 等价
    // (因为 IR 统一把 string content 升级为 array of text blocks).
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({
                "tools": [{"name": "get_weather"}],
                "messages": [
                    {"role": "user"},
                    {"role": "assistant", "content": [{"type": "tool_use", "id": "call_1", "name": "get_weather", "input": {"city": "SF"}}]},
                    {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "call_1"}]}
                ]
            }),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"msg_x","type":"message","role":"assistant","content":[{"type":"text","text":"It's sunny in SF"}],"model":"claude","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}"#,
        )
        .create_async()
        .await;
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"weather?"},{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"SF\"}"}}]},{"role":"tool","tool_call_id":"call_1","content":"Sunny"}],"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}}]}"#;
    let (status, resp_body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        body,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {resp_body}");
    assert!(resp_body.contains("It's sunny in SF"), "got: {resp_body}");
}

#[tokio::test]
async fn cross_protocol_translates_upstream_error_to_ingress_envelope() {
    // 上游错误响应应通过 codec 翻译为 ingress 协议 envelope (不泄漏内部细节).
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(429)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":{"type":"rate_limit_error","message":"Too many requests"}}"#)
        .create_async()
        .await;
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}"#;
    let (status, resp_body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        body,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::TOO_MANY_REQUESTS);
    // OpenAI 风格 envelope.
    assert!(
        resp_body.contains("\"type\":\"rate_limit_error\""),
        "got: {resp_body}"
    );
    assert!(resp_body.contains("Too many requests"), "got: {resp_body}");
}

#[tokio::test]
async fn same_proto_streaming_with_redact_restores_mock_in_sse_chunks() {
    // 同协议 + redact + 流式响应: 用 StreamTranslate restore 模式.
    // 上游 SSE chunk 含 mock → 客户端拿到的是 real_secret (restore 生效).
    // 用 mock_with_salt(real, 0) 预测首次 mock (gen_mock_for_ir 在 allocated 为空时返回 salt=0 mock).
    let real_secret = "sk-test-123";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    let sse_body = format!(
        concat!(
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"leaked {mock} in chunk\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":3,\"completion_tokens\":1,\"total_tokens\":4}}}}\n\n",
            "data: [DONE]\n\n",
        ),
        mock = expected_mock,
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(
        r#"{{"model":"gpt-4o","stream":true,"messages":[{{"role":"user","content":"use {real_secret} now"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    assert_eq!(status, reqwest::StatusCode::OK);
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .cloned()
        .unwrap();
    assert!(
        ct.to_str().unwrap().contains("text/event-stream"),
        "should be SSE"
    );
    let text = resp.text().await.unwrap();
    // 客户端应该看到 real_secret (mock 被 restore).
    assert!(
        text.contains(real_secret),
        "client should see real_secret restored in stream; got: {text}"
    );
    // 客户端不应该看到 mock 前缀.
    assert!(
        !text.contains(&expected_mock),
        "client should NOT see mock {expected_mock}; got: {text}"
    );

    // record 里应该不含 real_secret (LLM 视角的请求体已被 redact).
    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let r = &list[0];
    assert!(
        !r.req_body.contains(real_secret),
        "record should not contain real secret"
    );
}

#[tokio::test]
async fn same_proto_streaming_with_redact_preserves_include_usage_chunk() {
    // 回归: 同协议 + redact + 流式响应 + 上游支持 stream_options.include_usage.
    //
    // OpenAI `stream_options.include_usage: true` 模式下, 流末尾会有一个独立 chunk:
    //   `choices: []` (空数组) + 顶层 `usage`.
    // 此前 reader 把空数组当成 "无 choice" 直接 return, 丢失 usage; writer 也忽略
    // MessageDelta 的 usage 字段. 两者叠加导致客户端 (如 opencode) 拿到 0 tokens.
    //
    // 该测试覆盖整条链路: 上游发出独立的 usage chunk → reader 识别 → writer 写回.
    let real_secret = "sk-test-123";
    let mut upstream = spawn_mock_upstream().await;
    // 上游 SSE: 1) role chunk  2) text delta  3) finish_reason chunk (无 usage)
    //           4) 独立 usage chunk (choices=[], 顶层 usage)  5) [DONE]
    let sse_body =
        format!(
            concat!(
                "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\"}},\"finish_reason\":null}}]}}\n\n",
                "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"uses {real_secret}\"}},\"finish_reason\":null}}]}}\n\n",
                "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n",
                "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{{\"prompt_tokens\":42,\"completion_tokens\":7,\"total_tokens\":49}}}}\n\n",
                "data: [DONE]\n\n",
            ),
            real_secret = real_secret,
        );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64);
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"x"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let text = resp.text().await.unwrap();
    // 关键断言: usage 必须透传给客户端 (修复前丢失, 导致 opencode 显示 "0 tokens").
    assert!(
        text.contains("\"prompt_tokens\":42"),
        "client must see usage.prompt_tokens=42; got: {text}"
    );
    assert!(
        text.contains("\"completion_tokens\":7"),
        "client must see usage.completion_tokens=7; got: {text}"
    );
}

#[tokio::test]
async fn streaming_redact_restores_mock_split_across_sse_chunks() {
    // 跨 SSE chunk 的 mock 也应被 sliding-window restore.
    // 场景: LLM 在响应里 echo 出 mock, mock 恰好被 TCP 切到两个 chunk 中间.
    let real_secret = "sk-test-123";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    // 把 mock 切成连续两半 (mock 本身在文本中是连续的, 只是跨了 chunk 边界):
    //   chunk1 content = "leaked " + mock[..8]
    //   chunk2 content = mock[8..] + " end"
    let split = 8;
    let mock_prefix = &expected_mock[..split];
    let mock_suffix = &expected_mock[split..];
    let sse_body = format!(
        concat!(
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"leaked {mp}\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{ms} end\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":3,\"completion_tokens\":1,\"total_tokens\":4}}}}\n\n",
            "data: [DONE]\n\n",
        ),
        mp = mock_prefix,
        ms = mock_suffix,
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64);
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(
        r#"{{"model":"gpt-4o","stream":true,"messages":[{{"role":"user","content":"use {real_secret} now"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let text = resp.text().await.unwrap();
    // 客户端应该看到完整的 real_secret (跨 chunk mock 被 sliding-window restore).
    assert!(
        text.contains(real_secret),
        "client should see real_secret restored from cross-chunk mock; got: {text}"
    );
    // 客户端不应看到任何 mock 残段.
    assert!(
        !text.contains(mock_prefix),
        "client should NOT see mock prefix {mock_prefix}; got: {text}"
    );
    assert!(
        !text.contains(mock_suffix),
        "client should NOT see mock suffix {mock_suffix}; got: {text}"
    );
}

#[tokio::test]
async fn streaming_redact_restores_input_json_delta_in_tool_use() {
    // 流式 tool_use 的 InputJsonDelta 中含 mock 也应被 restore.
    // 上游 SSE 流里 arguments delta 含 mock, 客户端最终拼接应看到 real_secret.
    let real_secret = "sk-test-123";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    let sse_body = format!(
        concat!(
            // 第 1 chunk: assistant role + tool_call 开始.
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"tool_calls\":[{{\"index\":0,\"id\":\"call_x\",\"type\":\"function\",\"function\":{{\"name\":\"run\",\"arguments\":\"\"}}}}]}},\"finish_reason\":null}}]}}\n\n",
            // 第 2 chunk: arguments delta 含完整 mock.
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"arguments\":\"{{\\\"cmd\\\":\\\"echo {mock}\\\"}}\"}}}}]}},\"finish_reason\":null}}]}}\n\n",
            // 第 3 chunk: finish.
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"tool_calls\"}}],\"usage\":{{\"prompt_tokens\":3,\"completion_tokens\":1,\"total_tokens\":4}}}}\n\n",
            "data: [DONE]\n\n",
        ),
        mock = expected_mock,
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64);
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(
        r#"{{"model":"gpt-4o","stream":true,"tools":[{{"type":"function","function":{{"name":"run","description":"x","parameters":{{"type":"object","properties":{{"cmd":{{"type":"string"}}}}}}}}}}],"messages":[{{"role":"user","content":"use {real_secret}"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "status mismatch, body: {text}"
    );
    // 客户端应看到 real_secret 在 tool_call arguments 中.
    assert!(
        text.contains(real_secret),
        "client should see real_secret in tool args; got: {text}"
    );
    assert!(
        !text.contains(&expected_mock),
        "client should NOT see mock in tool args; got: {text}"
    );
}

#[tokio::test]
async fn streaming_redact_restores_when_upstream_skips_block_stop() {
    // 上游协议异常: 漏发 content_block_stop / finish_reason chunk, 直接发 message_stop / [DONE].
    // StreamTranslate 应在 MessageStop 时 flush_all_restorers, 把残留 mock tail 还原为 real.
    let real_secret = "sk-test-123";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    // 上游 SSE: 只发 role + 一个 content + message_stop, 没发 content_block_stop.
    // OpenAI 风格: content chunk 后直接 data: [DONE], 跳过 finish_reason chunk.
    let sse_body = format!(
        concat!(
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\"}},\"finish_reason\":null}}]}}\n\n",
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"leaked {mock}\"}},\"finish_reason\":null}}]}}\n\n",
            "data: [DONE]\n\n",
        ),
        mock = expected_mock,
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse_body)
        .create_async()
        .await;
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64);
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(
        r#"{{"model":"gpt-4o","stream":true,"messages":[{{"role":"user","content":"use {real_secret}"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let text = resp.text().await.unwrap();
    // 即使上游漏发 finish_reason / BlockStop, 客户端也应看到 real_secret.
    assert!(
        text.contains(real_secret),
        "client should see real_secret via finish() flush; got: {text}"
    );
    assert!(
        !text.contains(&expected_mock),
        "client should NOT see mock; got: {text}"
    );
}

#[tokio::test]
async fn cross_protocol_with_redact_round_trips_through_ir_translation() {
    // 跨协议 + redact + restore: 客户端发 OpenAI (含 secret) → codec 翻译为 Anthropic
    // (含 mock) → 上游响应含 mock → codec 翻译回 OpenAI + restore mock 为 real_secret.
    let real_secret = "sk-test-123";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    // 上游响应里含 mock (假设 LLM echo 了它在请求里看到的 mock).
    let upstream_body = format!(
        r#"{{"id":"msg_x","type":"message","role":"assistant","content":[{{"type":"text","text":"echo {expected_mock}"}}],"model":"claude","stop_reason":"end_turn","stop_sequence":null,"usage":{{"input_tokens":1,"output_tokens":1}}}}"#
    );
    let _m = upstream
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(upstream_body)
        .create_async()
        .await;
    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64);
    let records_handle = records.clone();
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(
        r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"use {real_secret} now"}}]}}"#
    );
    let (status, resp_body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        &body,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {resp_body}");
    // 客户端应看到 real_secret (跨协议翻译 + restore).
    assert!(
        resp_body.contains(real_secret),
        "client should see real_secret (cross-proto + restore); got: {resp_body}"
    );
    assert!(
        !resp_body.contains(&expected_mock),
        "client should NOT see mock; got: {resp_body}"
    );

    // record body 绝不能含真实 secret (cross-proto 路径也必须 redact 后再保存).
    // 这是 pre-existing bug 的回归测试: 早期 cross_proto_forward 直接存原始 req_bytes,
    // 会在 record 里泄漏 secret. 现在改用 ingress writer 重序列化 redact 后的 IR.
    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let r = &list[0];
    assert!(
        !r.req_body.contains(real_secret),
        "cross-proto record body must NOT contain real secret; got: {}",
        r.req_body
    );
    assert!(
        r.req_body.contains(&expected_mock),
        "cross-proto record body should contain mock (redacted view); got: {}",
        r.req_body
    );
    // parsed view 应当可用 (record body 是 ingress writer 重序列化的 OpenAI JSON).
    assert_eq!(
        r.redactions.len(),
        1,
        "expected 1 redaction, got: {:?}",
        r.redactions
    );
    assert_eq!(r.redactions[0].1, "api-key");
}

#[tokio::test]
async fn cross_protocol_translates_openai_ingress_to_anthropic_upstream() {
    // OpenAI ingress → Anthropic upstream (端到端跨协议翻译).
    let mut upstream = spawn_mock_upstream().await;
    // mock 上游: 期待收到 Anthropic 格式的 /v1/messages 请求.
    let _m = upstream
        .mock("POST", "/v1/messages")
        .match_header("anthropic-version", "2023-06-01")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"msg_01test","type":"message","role":"assistant","content":[{"type":"text","text":"Hi from Claude"}],"model":"claude-3-5-sonnet","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":5}}"#,
        )
        .create_async()
        .await;
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    // OpenAI ingress 客户端发 OpenAI 格式.
    let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#;
    let (status, resp_body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        body,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {resp_body}");
    // 响应应该是 OpenAI 格式.
    assert!(
        resp_body.contains("\"object\":\"chat.completion\""),
        "got: {resp_body}"
    );
    assert!(resp_body.contains("Hi from Claude"), "got: {resp_body}");
    assert!(resp_body.contains("\"prompt_tokens\""), "got: {resp_body}");
    assert!(
        resp_body.contains("\"finish_reason\":\"stop\""),
        "got: {resp_body}"
    );
}

#[tokio::test]
async fn cross_protocol_translates_anthropic_ingress_to_openai_upstream() {
    // 反向: Anthropic ingress → OpenAI upstream.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"chatcmpl-test","object":"chat.completion","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Hi from GPT"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":4,"total_tokens":16}}"#,
        )
        .create_async()
        .await;
    let provider = provider_with("oa-main", Protocol::OpenAI, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let body =
        r#"{"model":"claude","messages":[{"role":"user","content":"Hello"}],"max_tokens":50}"#;
    let (status, resp_body, _) =
        proxy_request(&proxy_url, "POST", "/a/oa-main/v1/messages", body, &[]).await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {resp_body}");
    // 响应应该是 Anthropic 格式.
    assert!(
        resp_body.contains("\"type\":\"message\""),
        "got: {resp_body}"
    );
    assert!(resp_body.contains("Hi from GPT"), "got: {resp_body}");
    assert!(
        resp_body.contains("\"stop_reason\":\"end_turn\""),
        "got: {resp_body}"
    );
    assert!(
        resp_body.contains("\"input_tokens\":12"),
        "got: {resp_body}"
    );
}

#[tokio::test]
async fn cross_protocol_streaming_returns_501() {
    // MVP: 跨协议 + stream=true 应返回 501 (尚未支持).
    let upstream = spawn_mock_upstream().await;
    let provider = provider_with("an-main", Protocol::Anthropic, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}],"stream":true}"#;
    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/an-main/v1/chat/completions",
        body,
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::NOT_IMPLEMENTED);
    assert!(body.contains("streaming cross-protocol"));
}

#[tokio::test]
async fn cross_protocol_unknown_pair_returns_501() {
    // Gemini/Ollama 在 codec 中尚未支持, 跨协议到这些仍应返回 501.
    let upstream = spawn_mock_upstream().await;
    let provider = provider_with("gem-main", Protocol::Gemini, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let (status, body, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/gem-main/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::NOT_IMPLEMENTED);
    assert!(body.contains("not supported by codec"));
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
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let (status, body, _) = proxy_request(&proxy_url, "GET", "/o/oa-main", "", &[]).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body, "root");
}

#[tokio::test]
async fn unmatched_path_returns_404() {
    // 单段路径不匹配 `/{proto}/{name}` 路由, 应当 404 (不被 catch-all 转发).
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
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
    let proxy_url = spawn_proxy(&upstream.url()).await;
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
    let proxy_url = spawn_proxy(&upstream.url()).await;
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
    let records = ConversationDag::new(64);
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
    let records = ConversationDag::new(64);
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
    // 新 envelope: {record, parsed_request, parsed_response, parse_error}.
    // 默认 view=raw, parsed_* 全为 null.
    assert_eq!(body["record"]["id"], id.to_string());
    assert_eq!(body["record"]["resp_status"], 200);
    assert!(body.get("parsed_request").is_some());
    assert!(body["parsed_request"].is_null());
}

#[tokio::test]
async fn web_api_404_for_unknown_record() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
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
async fn web_api_records_list_has_pagination_envelope() {
    // 验证新 ListRecordsResponse shape: {records, total, offset, limit}.
    // 默认 limit=50, offset=0.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let _ = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        r#"{"q":"hi"}"#,
        &[],
    )
    .await;
    // 等 1 条记录.
    let _ = wait_for_record_count(&format!("{proxy_url}/__sg/api/records"), 1).await;

    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/records"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["total"], 1);
    assert_eq!(body["offset"], 0);
    assert_eq!(body["limit"], 50);
    assert_eq!(body["records"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn web_api_records_list_respects_offset_limit() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", mockito::Matcher::Any)
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    // 发 3 条请求 → 3 条记录.
    for _ in 0..3 {
        let _ = proxy_request(
            &proxy_url,
            "POST",
            "/o/oa-main/v1/chat/completions",
            r#"{"q":"hi"}"#,
            &[],
        )
        .await;
    }
    let _ = wait_for_record_count(&format!("{proxy_url}/__sg/api/records"), 3).await;

    // 取第一页 (offset=0, limit=2): total=3, len=2.
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/records?offset=0&limit=2"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["total"], 3);
    assert_eq!(body["offset"], 0);
    assert_eq!(body["limit"], 2);
    assert_eq!(body["records"].as_array().unwrap().len(), 2);

    // 取第二页 (offset=2, limit=2): 只剩 1 条.
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/records?offset=2&limit=2"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["total"], 3);
    assert_eq!(body["records"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn web_api_records_list_filter_hits_returns_only_redacted() {
    // 构造混合场景: 2 条命中 secret (redactions 非空) + 2 条 passthrough (redactions 空).
    // filter=hits 应只返回 2 条命中, total=2; filter=all 仍 total=4.
    let real_secret = "sk-filter-test-789";
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("{}")
        .create_async()
        .await;

    let entries = vec![secret("hit-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64);
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let hit_body = format!(r#"{{"messages":[{{"content":"use {real_secret}"}}]}}"#);
    let plain_body = r#"{"messages":[{"content":"plain"}]}"#;
    // 交错发送: plain, hit, plain, hit. 顺序不重要 (list 倒序), 但要保证两类都有.
    for body in [plain_body, &hit_body, plain_body, &hit_body] {
        let _ = reqwest::Client::new()
            .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
    }
    let _ = wait_for_record_count(&format!("{proxy_url}/__sg/api/records"), 4).await;

    // filter=all: total=4.
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/records?filter=all"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["total"], 4, "filter=all should see all 4 records");
    assert_eq!(body["filter"], "all");
    assert_eq!(body["records"].as_array().unwrap().len(), 4);

    // filter=hits: total=2, 只含带 redactions 的记录.
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/records?filter=hits"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["total"], 2, "filter=hits should see only 2 redacted");
    assert_eq!(body["filter"], "hits");
    let recs = body["records"].as_array().unwrap();
    assert_eq!(recs.len(), 2);
    for r in recs {
        let reds = r["redactions"].as_array().unwrap();
        assert!(
            !reds.is_empty(),
            "hits filter must not return plain records"
        );
        assert_eq!(reds[0][1], "hit-key");
    }

    // 默认 (省略 filter) 应等价于 filter=all.
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/records"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["total"], 4);
    assert_eq!(body["filter"], "all");
}

#[tokio::test]
async fn web_api_records_view_parsed_openai_returns_structured() {
    // view=parsed 应当用 OpenAI codec 把 req_body 解析成结构化 JSON.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"id":"chatcmpl-1","choices":[{"message":{"role":"assistant","content":"hello"}}]}"#,
        )
        .create_async()
        .await;

    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64);
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
        r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#,
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

    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/records/{id}?view=parsed"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["record"]["id"], id.to_string());
    assert!(
        body["parse_error"].is_null(),
        "unexpected parse_error: {}",
        body["parse_error"]
    );
    let parsed_req = &body["parsed_request"];
    assert!(!parsed_req.is_null(), "parsed_request should not be null");
    assert!(
        parsed_req.get("messages").is_some(),
        "parsed_request should have messages"
    );
    let parsed_resp = &body["parsed_response"];
    assert!(!parsed_resp.is_null(), "parsed_response should not be null");
    assert!(
        parsed_resp.get("choices").is_some(),
        "parsed_response should have choices"
    );
}

#[tokio::test]
async fn web_api_records_view_parsed_gemini_returns_error() {
    // Gemini 不在 codec 支持范围, view=parsed 应当返回 parse_error.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", mockito::Matcher::Any)
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let provider = provider_with("gem-main", Protocol::Gemini, &upstream.url());
    let proxy_url = spawn_proxy_with_provider(provider).await;
    let _ = proxy_request(
        &proxy_url,
        "POST",
        "/g/gem-main/v1/generateContent",
        r#"{"q":"hi"}"#,
        &[],
    )
    .await;
    let records = wait_for_record_count(&format!("{proxy_url}/__sg/api/records"), 1).await;
    let id = records[0].id;

    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/records/{id}?view=parsed"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["record"]["id"], id.to_string());
    assert!(body["parsed_request"].is_null());
    let err = body["parse_error"].as_str().unwrap();
    assert!(
        err.contains("gemini") || err.contains("protocol"),
        "parse_error should mention gemini/protocol, got: {err}"
    );
}

#[tokio::test]
async fn web_api_400_for_invalid_uuid() {
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
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

    let proxy_url = spawn_proxy(&upstream.url()).await;

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
    let proxy_url = spawn_proxy(&upstream.url()).await;
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
    let proxy_url = spawn_proxy(&upstream.url()).await;
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
    let proxy_url = spawn_proxy(&upstream.url()).await;
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
    let proxy_url = spawn_proxy(&upstream.url()).await;
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
    let proxy_url = spawn_proxy(&upstream.url()).await;
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
    let proxy_url = spawn_proxy(&upstream.url()).await;
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
    let proxy_url = spawn_proxy(&upstream.url()).await;
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
    let records = ConversationDag::new(64);
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
async fn redact_populates_record_redactions_field() {
    // 验证 ForwardRecord.redactions 在 same_proto + redact 路径被正确填充.
    // 这是 WebUI 渲染 "本次请求命中哪些 secret" 的权威数据源.
    let real_secret = "sk-redact-me-456";
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"chatcmpl-1"}"#)
        .create_async()
        .await;

    let entries = vec![secret("my-api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    // 请求体含 real_secret → codec + redact_ir 会命中.
    let body = format!(r#"{{"messages":[{{"content":"use {real_secret}"}}]}}"#);
    let _ = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();

    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    let r = &list[0];
    // redactions 应当有 1 条: (mock_value, "my-api-key").
    assert_eq!(
        r.redactions.len(),
        1,
        "expected 1 redaction, got: {:?}",
        r.redactions
    );
    assert_eq!(r.redactions[0].1, "my-api-key", "secret id mismatch");
    assert!(
        !r.redactions[0].0.is_empty() && r.redactions[0].0 != "my-api-key-value",
        "mock should be non-empty and differ from real, got: {}",
        r.redactions[0].0
    );
    // 关键: redactions 中绝不能出现真实 secret.
    assert!(
        !r.redactions.iter().any(|(m, _)| m.contains(real_secret)),
        "redactions must not leak real secret"
    );
    // 记录的 req_body 中也应当看不到真实 secret (mock 替换后).
    assert!(!r.req_body.contains(real_secret));
}

#[tokio::test]
async fn passthrough_path_leaves_redactions_empty() {
    // 无 secret 配置 → passthrough 路径 → redactions 应当为空 vec.
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(
        vec![provider],
        upstream_client,
        records,
        test_secret_table(), // 空 secrets 表
    )
    .await;

    let _ = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        r#"{"q":"no-secret-here"}"#,
        &[],
    )
    .await;

    let list = wait_until_or_timeout(
        &records_handle,
        |l| l.first().map(|r| r.resp_complete).unwrap_or(false),
        Duration::from_secs(2),
    )
    .await;
    assert!(
        list[0].redactions.is_empty(),
        "passthrough path should leave redactions empty, got: {:?}",
        list[0].redactions
    );
}

#[tokio::test]
async fn restore_inserts_secret_back_for_client() {
    // IR-based redact round-trip: 请求里 secret → mock → LLM, 响应里 mock → secret → client.
    // 用 mock_with_salt(real, 0) 预测首次 mock, 让上游响应直接含 mock, 验证 restore 生效.
    let real_secret = "sk-test-123";
    let expected_mock = predict_mock(real_secret);
    let mut upstream = spawn_mock_upstream().await;
    let upstream_body = format!(
        r#"{{"id":"chatcmpl-x","object":"chat.completion","created":1700000000,"model":"gpt-4o","choices":[{{"index":0,"message":{{"role":"assistant","content":"echo {expected_mock}"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}}}"#
    );
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(upstream_body)
        .create_async()
        .await;

    let entries = vec![secret("api-key", real_secret)];
    let secrets = test_secret_table_with(entries);
    let upstream_client = reqwest::Client::new();
    let records = ConversationDag::new(64);
    let records_handle = records.clone();
    let provider = openai_provider("oa-main", &upstream.url());
    let proxy_url = spawn_proxy_full(vec![provider], upstream_client, records, secrets).await;

    let body = format!(
        r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"use {real_secret} now"}}]}}"#
    );
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    let resp_text = resp.text().await.unwrap();
    // 客户端应看到 real_secret (mock 已被 restore).
    assert!(
        resp_text.contains(real_secret),
        "client should see real_secret restored; got: {resp_text}"
    );
    assert!(
        !resp_text.contains(&expected_mock),
        "client should NOT see mock; got: {resp_text}"
    );

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

    let proxy_url = spawn_proxy(&upstream.url()).await;
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/o/oa-main/v1/chat/completions"))
        .body("raw-body")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

// ─── static + dynamic 合并 (新设计核心) ────────────────────────────────────

/// spawn proxy, 接受 static_providers (来自声明式 config) + dynamic providers (WebUI 写过).
async fn spawn_with_static_and_dynamic(
    static_providers: Vec<Provider>,
    dynamic_providers: Vec<Provider>,
) -> String {
    spawn_proxy_static_dynamic(
        static_providers,
        dynamic_providers,
        reqwest::Client::new(),
        ConversationDag::new(64),
        test_secret_table(),
    )
    .await
}

#[tokio::test]
async fn static_provider_is_listed_with_static_source() {
    let upstream = spawn_mock_upstream().await;
    let s = openai_provider("static-p", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;

    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{proxy_url}/__sg/api/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = body.get("providers").unwrap().as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], "static-p");
    assert_eq!(arr[0]["source"], "static");
    assert_eq!(arr[0]["decision"], "default");
    assert!(arr[0]["static_version"].is_object());
    assert!(arr[0]["dynamic_version"].is_null());
}

#[tokio::test]
async fn static_provider_routes_correctly() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_body("static-routed")
        .create_async()
        .await;
    let s = openai_provider("static-p", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;

    let resp = proxy_request(
        &proxy_url,
        "POST",
        "/o/static-p/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(resp.0, reqwest::StatusCode::OK);
    assert_eq!(resp.1, "static-routed");
}

#[tokio::test]
async fn dynamic_override_replaces_static_in_routing() {
    let mut upstream_static = spawn_mock_upstream().await;
    let _m_static = upstream_static
        .mock("POST", "/v1/chat/completions")
        .with_body("from-static-upstream")
        .create_async()
        .await;
    let mut upstream_dyn = spawn_mock_upstream().await;
    let _m_dyn = upstream_dyn
        .mock("POST", "/v1/chat/completions")
        .with_body("from-dynamic-upstream")
        .create_async()
        .await;

    let static_p = openai_provider("shared-id", &upstream_static.url());
    let mut dynamic_p = openai_provider("shared-id", &upstream_dyn.url());
    dynamic_p.api_key = "dynamic-key".into();
    let proxy_url = spawn_with_static_and_dynamic(vec![static_p], vec![dynamic_p]).await;

    let resp = proxy_request(
        &proxy_url,
        "POST",
        "/o/shared-id/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(resp.1, "from-dynamic-upstream", "dynamic 应覆盖 static");
}

#[tokio::test]
async fn decision_disabled_drops_static_provider() {
    let upstream = spawn_mock_upstream().await;
    let s = openai_provider("static-disabled", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;
    let client = reqwest::Client::new();

    // 切到 disabled.
    let resp = client
        .patch(format!(
            "{proxy_url}/__sg/api/providers/static-disabled/decision"
        ))
        .json(&serde_json::json!({"mode": "disabled"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // List 不再包含.
    let body: serde_json::Value = client
        .get(format!("{proxy_url}/__sg/api/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = body.get("providers").unwrap().as_array().unwrap();
    assert!(arr.is_empty(), "disabled 应从 effective view 中消失");

    // 路由也 404.
    let resp = proxy_request(
        &proxy_url,
        "POST",
        "/o/static-disabled/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(resp.0, reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn decision_prefer_static_beats_dynamic_override() {
    let mut upstream_static = spawn_mock_upstream().await;
    let _m_static = upstream_static
        .mock("POST", "/v1/chat/completions")
        .with_body("static-wins")
        .create_async()
        .await;
    let mut upstream_dyn = spawn_mock_upstream().await;
    let _m_dyn = upstream_dyn
        .mock("POST", "/v1/chat/completions")
        .with_body("dynamic-loses")
        .create_async()
        .await;

    let static_p = openai_provider("both", &upstream_static.url());
    let dynamic_p = openai_provider("both", &upstream_dyn.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![static_p], vec![dynamic_p]).await;
    let client = reqwest::Client::new();

    let resp = client
        .patch(format!("{proxy_url}/__sg/api/providers/both/decision"))
        .json(&serde_json::json!({"mode": "prefer_static"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let resp = proxy_request(&proxy_url, "POST", "/o/both/v1/chat/completions", "{}", &[]).await;
    assert_eq!(resp.1, "static-wins");
}

#[tokio::test]
async fn put_static_provider_forks_dynamic_override() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_body("ok")
        .create_async()
        .await;
    let s = openai_provider("static-p", "https://invalid-static.example");
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;
    let client = reqwest::Client::new();

    // 用 PUT 编辑 static provider → 服务端自动 fork 出 dynamic.
    let resp = client
        .put(format!("{proxy_url}/__sg/api/providers/static-p"))
        .json(&serde_json::json!({
            "protocol": "openai",
            "base_url": upstream.url(),
            "api_key": "forked-key",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let updated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(updated["source"], "dynamic_override");
    assert_eq!(updated["base_url"], upstream.url());
    assert!(updated["static_version"].is_object());
    assert!(updated["dynamic_version"].is_object());

    // 路由应走 dynamic (指向 mock), 而不是 static (指向 invalid URL).
    let resp = proxy_request(
        &proxy_url,
        "POST",
        "/o/static-p/v1/chat/completions",
        "{}",
        &[],
    )
    .await;
    assert_eq!(resp.0, reqwest::StatusCode::OK);
    assert_eq!(resp.1, "ok");
}

#[tokio::test]
async fn delete_static_only_provider_is_rejected() {
    let upstream = spawn_mock_upstream().await;
    let s = openai_provider("static-p", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;
    let client = reqwest::Client::new();

    let resp = client
        .delete(format!("{proxy_url}/__sg/api/providers/static-p"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CONFLICT,
        "static 永不可删, 必须走 decision=disabled"
    );
}

#[tokio::test]
async fn delete_dynamic_override_keeps_static_baseline() {
    let mut upstream = spawn_mock_upstream().await;
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_body("static-back")
        .create_async()
        .await;

    let static_p = openai_provider("p", &upstream.url());
    let mut dynamic_p = openai_provider("p", "https://dynamic-invalid.example");
    dynamic_p.api_key = "override-key".into();
    let proxy_url = spawn_with_static_and_dynamic(vec![static_p], vec![dynamic_p]).await;
    let client = reqwest::Client::new();

    // 删除 dynamic override → 回到 static.
    let resp = client
        .delete(format!("{proxy_url}/__sg/api/providers/p"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // List 显示 source 回到 static.
    let body: serde_json::Value = client
        .get(format!("{proxy_url}/__sg/api/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = body.get("providers").unwrap().as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["source"], "static");

    // 路由走 static (mock), 返回 ok.
    let resp = proxy_request(&proxy_url, "POST", "/o/p/v1/chat/completions", "{}", &[]).await;
    assert_eq!(resp.0, reqwest::StatusCode::OK);
    assert_eq!(resp.1, "static-back");
}

#[tokio::test]
async fn create_post_rejects_conflict_with_static_id() {
    let upstream = spawn_mock_upstream().await;
    let s = openai_provider("static-p", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{proxy_url}/__sg/api/providers"))
        .json(&serde_json::json!({
            "id": "static-p",
            "protocol": "openai",
            "base_url": "https://other.example",
            "api_key": "x",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
}

#[tokio::test]
async fn decision_endpoint_rejects_non_static_id() {
    let upstream = spawn_mock_upstream().await;
    let d = openai_provider("dynamic-only", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![], vec![d]).await;
    let client = reqwest::Client::new();

    let resp = client
        .patch(format!(
            "{proxy_url}/__sg/api/providers/dynamic-only/decision"
        ))
        .json(&serde_json::json!({"mode": "disabled"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "decision 只对 static id 有意义"
    );
}

#[tokio::test]
async fn secret_decision_disabled_drops_from_redaction() {
    // static secret + decision=disabled → redact 流程不应再使用它.
    let mut upstream = spawn_mock_upstream().await;
    let real_secret = "static-secret-value";
    let _m = upstream
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_body("ok")
        .create_async()
        .await;

    let provider = openai_provider("oa-main", &upstream.url());
    // 把 secret 放入 static 层.
    let decisions = std::sync::Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    let secret_path = tmp_state_path("static-secret");
    let static_secrets = vec![secret("static-s", real_secret)];
    let secrets = SecretTable::new(static_secrets, vec![], decisions, secret_path);

    let proxy_url = spawn_proxy_static_dynamic(
        vec![provider],
        vec![],
        reqwest::Client::new(),
        ConversationDag::new(64),
        secrets,
    )
    .await;
    let client = reqwest::Client::new();

    // 禁用 static-s.
    let resp = client
        .patch(format!("{proxy_url}/__sg/api/secrets/static-s/decision"))
        .json(&serde_json::json!({"mode": "disabled"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // 发请求带 secret → 应当原样转发 (redact 不再发生).
    let (_, _, _) = proxy_request(
        &proxy_url,
        "POST",
        "/o/oa-main/v1/chat/completions",
        &format!("{{\"prompt\": \"{real_secret}\"}}"),
        &[],
    )
    .await;

    // 等记录写入, 验证 body 仍含 secret.
    let records = wait_for_record_count(&format!("{proxy_url}/__sg/api/records"), 1).await;
    // list 不返回 req_body, 需通过 detail API 拉取.
    let detail: serde_json::Value = client
        .get(format!("{proxy_url}/__sg/api/records/{}", records[0].id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let body = detail["record"]["req_body"].as_str().unwrap_or("");
    assert!(
        body.contains(real_secret),
        "disabled secret 应当不被 redact, body={body}"
    );
}

/// 辅助: 当测试未持有 ConversationDag handle 时, 通过 records API 轮询直到出现 count 条记录.
/// list API 返回的轻量 record 摘要 (不含 req_body / resp_body / resp_parsed).
/// 测试只需检查 metadata 字段, body 由 GET /records/{id}?view=... 按需拉.
#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct RecordSummary {
    id: uuid::Uuid,
    method: String,
    path: String,
    resp_status: u16,
    elapsed_ms: u64,
    streamed: bool,
    resp_complete: bool,
    error: Option<String>,
    #[serde(default)]
    redactions: Vec<(String, String)>,
    #[serde(default)]
    preview: Option<String>,
    #[serde(default)]
    model: Option<String>,
}

async fn wait_for_record_count(url: &str, count: usize) -> Vec<RecordSummary> {
    let client = reqwest::Client::new();
    for _ in 0..50 {
        let body: serde_json::Value = client.get(url).send().await.unwrap().json().await.unwrap();
        let arr = body.get("records").unwrap().as_array().unwrap();
        if arr.len() >= count {
            return arr
                .iter()
                .map(|v| serde_json::from_value(v.clone()).unwrap())
                .collect();
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("timeout waiting for {count} records at {url}");
}

// ─── 额外覆盖 (针对 Code Review C1 / M2 / M4 的回归) ─────────────────────

#[tokio::test]
async fn decision_can_reenable_after_disabled() {
    // disable → default 必须能切回, 否则用户永久锁死.
    let upstream = spawn_mock_upstream().await;
    let s = openai_provider("static-p", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;
    let client = reqwest::Client::new();

    // 1. disable.
    let resp = client
        .patch(format!("{proxy_url}/__sg/api/providers/static-p/decision"))
        .json(&serde_json::json!({"mode": "disabled"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // 2. 切回 default — 此时 effective_snapshot 看不到 static-p, 但 has_static 应当返回 true.
    let resp = client
        .patch(format!("{proxy_url}/__sg/api/providers/static-p/decision"))
        .json(&serde_json::json!({"mode": "default"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "Disabled 状态下也必须能切回 Default, 否则用户被永久锁死"
    );

    // 3. 重新出现在 list 中.
    let body: serde_json::Value = client
        .get(format!("{proxy_url}/__sg/api/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = body.get("providers").unwrap().as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], "static-p");
}

#[tokio::test]
async fn delete_disabled_static_id_returns_409() {
    // 用户先 disable 了 static id, 再尝试 DELETE 应当返回 409 (而不是 404).
    let upstream = spawn_mock_upstream().await;
    let s = openai_provider("static-p", &upstream.url());
    let proxy_url = spawn_with_static_and_dynamic(vec![s], vec![]).await;
    let client = reqwest::Client::new();

    client
        .patch(format!("{proxy_url}/__sg/api/providers/static-p/decision"))
        .json(&serde_json::json!({"mode": "disabled"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .delete(format!("{proxy_url}/__sg/api/providers/static-p"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CONFLICT,
        "disabled 状态下的 static id DELETE 应当 409, 而非 404"
    );
}

#[tokio::test]
async fn cross_table_shared_state_no_lost_update() {
    // 真正共享 persist_lock + decisions + state_path: 并发 POST provider + POST secret,
    // 期望两者最终都出现在同一份 state.toml 中.
    use secret_guard::config::Decisions;
    use secret_guard::provider::ProviderTable;
    use secret_guard::secrets::SecretTable;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state_path = tmp_state_path("shared-state");

    let decisions = std::sync::Arc::new(parking_lot::RwLock::new(Decisions::default()));
    let persist_lock = std::sync::Arc::new(parking_lot::Mutex::new(()));

    let provider_table = ProviderTable::with_persist_lock(
        vec![],
        vec![],
        decisions.clone(),
        state_path.clone(),
        persist_lock.clone(),
    );
    let secret_table =
        SecretTable::with_persist_lock(vec![], vec![], decisions, state_path.clone(), persist_lock);
    let proxy = ProxyState {
        upstream: reqwest::Client::new(),
        providers: provider_table,
        dag: ConversationDag::new(64),
        secrets: secret_table,
    };
    let app = server::build_router(proxy);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let url = format!("http://{addr}");

    // 并发发起两个 POST. client 可以 clone (Arc-backed, 共享连接池).
    let client = reqwest::Client::new();
    let c1 = client.clone();
    let c2 = client.clone();
    let url1 = url.clone();
    let url2 = url.clone();
    let (r1, r2) = tokio::join!(
        async move {
            c1.post(format!("{url1}/__sg/api/providers"))
                .json(&serde_json::json!({
                    "id": "p-concurrent",
                    "protocol": "openai",
                    "base_url": "https://api.openai.com",
                    "api_key": "k",
                }))
                .send()
                .await
                .unwrap()
        },
        async move {
            c2.post(format!("{url2}/__sg/api/secrets"))
                .json(&serde_json::json!({
                    "id": "s-concurrent",
                    "value": "some-secret-value",
                }))
                .send()
                .await
                .unwrap()
        }
    );
    assert_eq!(r1.status(), reqwest::StatusCode::CREATED);
    assert_eq!(r2.status(), reqwest::StatusCode::CREATED);

    // state.toml 应当同时包含新 provider 和新 secret.
    let state = secret_guard::config::DynamicState::load_or_empty(&state_path).unwrap();
    assert_eq!(state.providers.len(), 1);
    assert_eq!(state.secrets.len(), 1);
    assert_eq!(state.providers[0].id, "p-concurrent");
    assert_eq!(state.secrets[0].id, "s-concurrent");
}

#[tokio::test]
async fn validate_value_rejects_mock_prefix() {
    // 集成层验证 C5 前提: 含 sgm_ 的 secret 应被拒绝.
    let upstream = spawn_mock_upstream().await;
    let proxy_url = spawn_proxy(&upstream.url()).await;
    let resp = reqwest::Client::new()
        .post(format!("{proxy_url}/__sg/api/secrets"))
        .json(&serde_json::json!({
            "id": "bad",
            "value": "sgm_abc12345",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}
