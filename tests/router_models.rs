//! #196: router provider 原生 GET /models 的集成测试.
//!
//! 覆盖 (对应 contracts.md FWD-7, brief §3.2):
//! - default-plan 主验收: 别名(路由表序) + 过滤后上游模型(walk 序 × 上游序) 有序合并;
//! - 缓存: 同 server 连续两次查询, 每个 upstream mock 恰命中 1 次;
//! - exact-only router: 零上游请求 + 响应只含别名 (N6);
//! - 上游 fetch 500: 响应仍 200 仅别名; 再次查询仍 200 (best-effort, ROB);
//! - Direct provider 回归: /models 透传 byte-exact, 不进缓存;
//! - 嵌套 router + 链上 disabled target 不贡献;
//! - Anthropic ingress 的响应 shape;
//! - D5: /models 查询不产生 DAG session.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use secret_guard::provider::{
    DirectProvider, Endpoint, PoolProvider, Protocol, Provider, ProviderKind, ProviderTable, Route,
    RouterProvider,
};
use secret_guard::proxy::ModelListCache;
use secret_guard::server;
use secret_guard::state::AppState;
use tokio::net::TcpListener;

// ─── helpers (参考 tests/integration.rs 的既有形态, 仅保留本文件所需子集) ────

fn tmp_state_path(label: &str) -> std::path::PathBuf {
    let id = uuid::Uuid::new_v4().to_string();
    let path = std::path::PathBuf::from(format!("/tmp/opencode/tmp/test-rm-{label}-{id}.toml"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    path
}

fn test_api_key_store() -> secret_guard::auth::ApiKeyStore {
    secret_guard::auth::ApiKeyStore::new(
        &[],
        std::path::Path::new("."),
        vec![],
        std::collections::HashSet::new(),
        tmp_state_path("api-keys"),
        Arc::new(parking_lot::Mutex::new(())),
    )
}

fn test_secret_table() -> secret_guard::secrets::SecretTable {
    let decisions = Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    secret_guard::secrets::SecretTable::new(vec![], vec![], decisions, tmp_state_path("secrets"))
}

fn openai_provider(id: &str, base_url: &str) -> Provider {
    Provider {
        id: id.into(),
        enabled: true,
        name: Some(id.into()),
        kind: ProviderKind::Direct(DirectProvider {
            endpoints: vec![Endpoint {
                protocol: Protocol::OpenAI,
                base_url: base_url.into(),
                common_uri: None,
            }],
            api_key: String::new(),
            api_key_file: None,
        }),
    }
}

fn anthropic_provider(id: &str, base_url: &str) -> Provider {
    Provider {
        kind: ProviderKind::Direct(DirectProvider {
            endpoints: vec![Endpoint {
                protocol: Protocol::Anthropic,
                base_url: base_url.into(),
                common_uri: None,
            }],
            api_key: String::new(),
            api_key_file: None,
        }),
        ..openai_provider(id, base_url)
    }
}

/// 多端点 provider (multi-endpoint, FWD-7 缓存键控测试用): endpoints 按传入序
/// (数组序 = fallback 序, 第一项 = 默认端点, D2).
fn multi_endpoint_provider(id: &str, endpoints: &[(Protocol, String)]) -> Provider {
    Provider {
        id: id.into(),
        enabled: true,
        name: Some(id.into()),
        kind: ProviderKind::Direct(DirectProvider {
            endpoints: endpoints
                .iter()
                .map(|(protocol, base_url)| Endpoint {
                    protocol: *protocol,
                    base_url: base_url.clone(),
                    common_uri: None,
                })
                .collect(),
            api_key: String::new(),
            api_key_file: None,
        }),
    }
}

fn route(pattern: &str, target: &str, priority: i64) -> Route {
    Route {
        model_pattern: pattern.into(),
        target: target.into(),
        upstream_model: None,
        priority: Some(priority),
    }
}

fn rewrite_route(pattern: &str, target: &str, model: &str, priority: i64) -> Route {
    Route {
        upstream_model: Some(model.into()),
        ..route(pattern, target, priority)
    }
}

fn router_provider(id: &str, routes: Vec<Route>) -> Provider {
    Provider {
        id: id.into(),
        enabled: true,
        name: Some(id.into()),
        kind: ProviderKind::Router(RouterProvider { routes }),
    }
}

fn pool_provider(id: &str, members: Vec<String>) -> Provider {
    Provider {
        id: id.into(),
        enabled: true,
        name: Some(id.into()),
        kind: ProviderKind::Pool(PoolProvider {
            members,
            exhaust: Default::default(),
            cooldown_secs: 60,
        }),
    }
}

/// 启动 secret-guard (providers 视为 dynamic 层), 返回 proxy url.
async fn spawn(providers: Vec<Provider>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state_path = tmp_state_path("state");
    let decisions = Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    let persist_lock = Arc::new(parking_lot::Mutex::new(()));
    let provider_table =
        ProviderTable::with_persist_lock(providers, vec![], decisions, state_path, persist_lock);
    let redact = secret_guard::config::RedactConfig::default();
    let proxy = AppState {
        pools: secret_guard::pool::PoolStates::new(),
        upstream: reqwest::Client::new(),
        providers: provider_table,
        dag: secret_guard::dag::ConversationDag::new(64, 500, 1),
        secrets: test_secret_table(),
        api_keys: test_api_key_store(),
        auth_enabled: false,
        global_mock_prefix: Arc::from(""),
        // [redact] 三 gate 镜像生产默认 (SEC-10); 本 harness 不触降级路径.
        on_probe_exhausted: redact.on_probe_exhausted,
        on_unsupported_protocol: redact.on_unsupported_protocol,
        on_fallback_restore: redact.on_fallback_restore,
        // SEC-4: 镜像生产装配 (normalize 后入 state); 本 harness 无自定义名单.
        redacted_headers: secret_guard::state::normalize_redacted_headers(&redact.redacted_headers),
        upstream_timeouts: secret_guard::config::UpstreamTimeouts::default(),
        model_lists: Arc::new(ModelListCache::new()),
        usage: std::sync::Arc::new(secret_guard::usage::UsageStore::in_memory()),
        pricing: std::sync::Arc::new(secret_guard::usage::PricingCache::for_tests()),
    };
    let app = server::build_router(
        proxy,
        secret_guard::server_host_guard::HostGuard::new("127.0.0.1", addr.port()),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

async fn get(proxy_url: &str, path: &str) -> (reqwest::StatusCode, String) {
    let resp = reqwest::Client::new()
        .get(format!("{proxy_url}{path}"))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.text().await.unwrap())
}

/// 从响应 JSON 提取 `data[].id` (OpenAI / Anthropic shape).
fn model_ids(body: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    v["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap().to_string())
        .collect()
}

async fn spawn_mock_upstream() -> mockito::ServerGuard {
    mockito::Server::new_async().await
}

// ─── 主验收用例 (default-plan 推演示例, brief §3.2 原样落地) ────────────────

/// 路由: ultra/flash/vision (exact + rewrite, prio 30) → glm-main;
/// glm-* (prio 20) → glm-main; * (prio 10) → glm-fallback.
/// 期望: [ultra, flash, vision, glm-4.7, glm-4.8-flash, glm-4.6v, glm-4.9, qwen-3]
/// (glm-4.7-air 被过滤: 匹配 glm-* 落 main, main 无它).
/// 同 server 连续两次查询, 每个 upstream mock 恰命中 1 次 (TTL 缓存).
/// D5: 查询不产生 DAG session.
#[tokio::test]
async fn router_models_default_plan_merge() {
    let mut main = spawn_mock_upstream().await;
    let mut fallback = spawn_mock_upstream().await;
    let main_mock = main
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"object":"list","data":[
                {"id":"glm-4.7"},{"id":"glm-4.8-flash"},{"id":"glm-4.6v"},{"id":"glm-4.9"}
            ]}"#,
        )
        .expect(1)
        .create_async()
        .await;
    let fallback_mock = fallback
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"object":"list","data":[{"id":"qwen-3"},{"id":"glm-4.7-air"}]}"#)
        .expect(1)
        .create_async()
        .await;

    let providers = vec![
        openai_provider("glm-main", &main.url()),
        openai_provider("glm-fallback", &fallback.url()),
        router_provider(
            "default-plan",
            vec![
                rewrite_route("ultra", "glm-main", "glm-4.7", 30),
                rewrite_route("flash", "glm-main", "glm-4.8-flash", 30),
                rewrite_route("vision", "glm-main", "glm-4.6v", 30),
                route("glm-*", "glm-main", 20),
                route("*", "glm-fallback", 10),
            ],
        ),
    ];
    let proxy = spawn(providers).await;

    let expected = [
        "ultra",
        "flash",
        "vision",
        "glm-4.7",
        "glm-4.8-flash",
        "glm-4.6v",
        "glm-4.9",
        "qwen-3",
    ];
    for _ in 0..2 {
        let (status, body) = get(&proxy, "/o/default-plan/v1/models").await;
        assert_eq!(status, 200, "body: {body}");
        let ids = model_ids(&body);
        assert_eq!(
            ids, expected,
            "default-plan 合并序 (别名 → walk 序 × 上游序, 遮蔽过滤): {body}"
        );
        // N5: owned_by 统一 "router", 不泄漏内部 provider id.
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(
            v["data"]
                .as_array()
                .unwrap()
                .iter()
                .all(|m| m["owned_by"] == "router")
        );
    }
    // 缓存: 两次查询, 每个 upstream 恰命中 1 次.
    main_mock.assert_async().await;
    fallback_mock.assert_async().await;

    // D5: /models 查询不产生 DAG session.
    let (status, body) = get(&proxy, "/api/sessions").await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["total"], 0,
        "router /models 本地终结 + cache-fill fetch 都不进 DAG (D5): {body}"
    );
}

// ─── N6: exact-only router 零上游请求 ───────────────────────────────────────

#[tokio::test]
async fn router_models_exact_only_skips_upstream() {
    let mut upstream = spawn_mock_upstream().await;
    let mock = upstream
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_body(r#"{"data":[{"id":"should-not-appear"}]}"#)
        // expect(0): exact-only router 必须零 fetch (N6 gate).
        .expect(0)
        .create_async()
        .await;

    let providers = vec![
        openai_provider("direct-a", &upstream.url()),
        router_provider("exact-only", vec![route("foo", "direct-a", 30)]),
    ];
    let proxy = spawn(providers).await;

    // 两个 ingress 路径形态都拦截 ("/models" 与 "/v1/models"), 都零 fetch;
    // query 参数忽略 (Anthropic ?limit= 之类不影响拦截判定)。
    for path in [
        "/o/exact-only/v1/models",
        "/o/exact-only/models",
        "/o/exact-only/v1/models?limit=1",
    ] {
        let (status, body) = get(&proxy, path).await;
        assert_eq!(
            status, 200,
            "exact-only 不再 503 (GET 无 body 不再 NoMatch): {body}"
        );
        assert_eq!(model_ids(&body), ["foo"], "只含别名: {body}");
    }
    mock.assert_async().await;
}

// ─── 上游 fetch 失败: best-effort, 永不 fail 查询 (ROB) + 失败退避 (M1) ──────

/// 失败退避语义 (M1): 首次 fetch 500 → 响应仍 200 仅别名 (best-effort);
/// 退避窗口 (prod 30s) 内的后续查询**立即**返回, 不再重试 (mockito 恰命中 1 次),
/// 不被 dead upstream 逐查询阻塞. 窗口过后允许重试的行为由单测覆盖
/// (`model_list_cache_failure_backoff_blocks_retry_within_window`, cfg(test) 短退避).
#[tokio::test]
async fn router_models_upstream_error_serves_aliases_only() {
    let mut upstream = spawn_mock_upstream().await;
    let mock = upstream
        .mock("GET", "/v1/models")
        .with_status(500)
        .with_body("internal error")
        // 首查触发一次 fetch; 退避窗口内的第二次查询不再 fetch.
        .expect(1)
        .create_async()
        .await;

    let providers = vec![
        openai_provider("direct-a", &upstream.url()),
        router_provider(
            "with-wildcard",
            vec![route("foo", "direct-a", 30), route("*", "direct-a", 10)],
        ),
    ];
    let proxy = spawn(providers).await;

    for i in 0..2 {
        let (status, body) = get(&proxy, "/o/with-wildcard/v1/models").await;
        assert_eq!(
            status,
            200,
            "上游 500 不 fail 查询 (第 {} 次): {body}",
            i + 1
        );
        assert_eq!(
            model_ids(&body),
            ["foo"],
            "fetch 失败 → 无数据降级, 仅别名 (第 {} 次): {body}",
            i + 1
        );
    }
    mock.assert_async().await;
}

// ─── Direct provider 回归: /models 透传不变 (byte-exact, 不进缓存) ──────────

#[tokio::test]
async fn direct_provider_models_passthrough_byte_exact() {
    let mut upstream = spawn_mock_upstream().await;
    let raw_body =
        r#"{"object":"list","data":[{"id":"x","object":"model","owned_by":"org","created":123}]}"#;
    let mock = upstream
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(raw_body)
        // Direct 不缓存: 每次查询都透传上游.
        .expect(2)
        .create_async()
        .await;

    let proxy = spawn(vec![openai_provider("direct-a", &upstream.url())]).await;

    for _ in 0..2 {
        let (status, body) = get(&proxy, "/o/direct-a/v1/models").await;
        assert_eq!(status, 200);
        assert_eq!(body, raw_body, "Direct /models 必须上游字节原样透传 (D6)");
    }
    mock.assert_async().await;
}

// ─── 嵌套 router + 链上 disabled target 不贡献 ──────────────────────────────

#[tokio::test]
async fn nested_router_disabled_target_not_contributing() {
    let mut up_a = spawn_mock_upstream().await;
    let mut up_b = spawn_mock_upstream().await;
    let mock_a = up_a
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_body(r#"{"data":[{"id":"a1"}]}"#)
        .expect(1)
        .create_async()
        .await;
    let mock_b = up_b
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_body(r#"{"data":[{"id":"b1"}]}"#)
        // disabled target 不被 fetch.
        .expect(0)
        .create_async()
        .await;

    let providers = vec![
        openai_provider("a", &up_a.url()),
        // enabled=false: top 的 x-* 路由指向它, 但它不贡献 (不 fetch, 不广告).
        Provider {
            enabled: false,
            ..openai_provider("b", &up_b.url())
        },
        router_provider("mid", vec![route("*", "a", 0)]),
        router_provider(
            "top",
            vec![
                // exact → disabled target: D2 过滤 (不可解析).
                route("dead", "b", 40),
                route("t-*", "mid", 20),
                route("x-*", "b", 30),
                route("*", "mid", 10),
            ],
        ),
    ];
    let proxy = spawn(providers).await;

    let (status, body) = get(&proxy, "/o/top/v1/models").await;
    assert_eq!(status, 200, "body: {body}");
    // "dead" 被 D2 过滤 (disabled target 不可解析); a1 经 *→mid 链解析进 a 的清单;
    // b 从未被 fetch / 广告.
    assert_eq!(
        model_ids(&body),
        ["a1"],
        "嵌套链贡献 a1, disabled b 不贡献: {body}"
    );
    mock_a.assert_async().await;
    mock_b.assert_async().await;
}

// ─── Anthropic ingress 的响应 shape ────────────────────────────────────────

#[tokio::test]
async fn router_models_anthropic_ingress_shape() {
    let mut upstream = spawn_mock_upstream().await;
    // match_header: 锁定对 Anthropic 上游的 fetch 带 anthropic-version (M1 回归,
    // 缺失会被真实 Anthropic API 400 拒绝 → 该 provider 永无贡献).
    let _mock = upstream
        .mock("GET", "/v1/models")
        .match_header("anthropic-version", "2023-06-01")
        .with_status(200)
        .with_body(r#"{"data":[{"id":"claude-1"},{"id":"claude-2"}]}"#)
        .create_async()
        .await;

    let providers = vec![
        anthropic_provider("anthropic-main", &upstream.url()),
        router_provider(
            "r",
            vec![
                route("alias", "anthropic-main", 30),
                route("*", "anthropic-main", 10),
            ],
        ),
    ];
    let proxy = spawn(providers).await;

    let (status, body) = get(&proxy, "/a/r/v1/models").await;
    assert_eq!(status, 200, "body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let data = v["data"].as_array().unwrap();
    assert_eq!(data.len(), 3);
    assert_eq!(data[0]["type"], "model");
    assert_eq!(data[0]["id"], "alias");
    assert_eq!(data[0]["display_name"], "alias");
    assert_eq!(data[0]["created_at"], "1970-01-01T00:00:00Z");
    assert_eq!(data[1]["id"], "claude-1");
    assert_eq!(v["has_more"], false);
}

// ─── single-flight: 并发查询不 stampede 上游 (M2, N4) ───────────────────────

/// 起一个"慢上游" axum server: GET /v1/models 先 sleep `delay` 再返回固定清单,
/// 每次请求对 `counter` +1 (命中计数).
async fn spawn_slow_models_upstream(
    delay: std::time::Duration,
    counter: Arc<AtomicUsize>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counter_for_handler = counter.clone();
    let app = axum::Router::new().route(
        "/v1/models",
        axum::routing::get(move || {
            let counter = counter_for_handler.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(delay).await;
                (
                    [("content-type", "application/json")],
                    r#"{"data":[{"id":"slow-1"}]}"#,
                )
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

/// M2: single-flight — 两个并发 /models 查询, 首个 fetch 进行中到达第二个时,
/// 上游**恰被命中 1 次** (等锁者随后读新鲜缓存), 两响应一致. 若退化成 stampede
/// (并发各自 fetch), 计数会 ≥ 2, 本测试红.
#[tokio::test]
async fn router_models_single_flight_under_concurrency() {
    let hits = Arc::new(AtomicUsize::new(0));
    let base =
        spawn_slow_models_upstream(std::time::Duration::from_millis(200), hits.clone()).await;

    let providers = vec![
        openai_provider("slow", &base),
        router_provider("sf-router", vec![route("*", "slow", 10)]),
    ];
    let proxy = spawn(providers).await;

    let (first, second) = tokio::join!(
        get(&proxy, "/o/sf-router/v1/models"),
        get(&proxy, "/o/sf-router/v1/models"),
    );
    for (label, (status, body)) in [("first", first), ("second", second)] {
        assert_eq!(status, 200, "{label}: {body}");
        assert_eq!(model_ids(&body), ["slow-1"], "{label} 响应一致: {body}");
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "single-flight: 并发查询对同一上游恰发起一次 fetch"
    );
}

// ─── GET /api/providers/{id}/models (endpoints 弹窗的模型清单预览) ──────────
//
// 覆盖: Direct 现场 fetch (不进缓存) / Router 本地合成 (与转发路径同源同值,
// 共享 TTL 缓存) / Pool 命中当前成员 / 失败是数据 (恒 200) / 未知 id 404.

async fn preview(proxy_url: &str, id: &str) -> (reqwest::StatusCode, serde_json::Value) {
    let (status, body) = get(proxy_url, &format!("/api/providers/{id}/models")).await;
    (status, serde_json::from_str(&body).unwrap())
}

#[tokio::test]
async fn preview_models_direct_upstream_fresh_fetch() {
    let mut upstream = spawn_mock_upstream().await;
    let mock = upstream
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_body(r#"{"data":[{"id":"m-1"},{"id":"m-2"}]}"#)
        // 现场语义: 不进缓存 — 与 Direct /models 逐请求透传一致, 每次预览都 fetch.
        .expect(2)
        .create_async()
        .await;
    let proxy = spawn(vec![openai_provider("direct-a", &upstream.url())]).await;

    for _ in 0..2 {
        let (status, v) = preview(&proxy, "direct-a").await;
        assert_eq!(status, 200, "{v}");
        assert_eq!(v["source"], "upstream");
        assert_eq!(v["upstream_id"], "direct-a");
        assert!(v["error"].is_null(), "{v}");
        assert_eq!(v["models"], serde_json::json!(["m-1", "m-2"]));
    }
    mock.assert_async().await;
}

#[tokio::test]
async fn preview_models_router_synthesized_matches_forward_path() {
    let mut upstream = spawn_mock_upstream().await;
    let mock = upstream
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_body(r#"{"data":[{"id":"g-1"},{"id":"g-2"}]}"#)
        .expect(1) // 预览共享 TTL 缓存: 两次预览 + 一次转发路径, 上游恰 1 次.
        .create_async()
        .await;
    let proxy = spawn(vec![
        openai_provider("up-a", &upstream.url()),
        router_provider(
            "plan",
            vec![route("alias", "up-a", 30), route("*", "up-a", 10)],
        ),
    ])
    .await;

    for _ in 0..2 {
        let (status, v) = preview(&proxy, "plan").await;
        assert_eq!(status, 200, "{v}");
        assert_eq!(v["source"], "router-synthesized");
        assert!(
            v["upstream_id"].is_null(),
            "合成清单横跨多上游, 无单一取数 id: {v}"
        );
        assert!(v["error"].is_null(), "{v}");
        assert_eq!(
            v["models"],
            serde_json::json!(["alias", "g-1", "g-2"]),
            "别名在前 + 上游合并段 (与 FWD-7 同序)"
        );
    }
    // 同源同值: 预览与转发路径的 GET /models 完全一致.
    let (_, body) = get(&proxy, "/o/plan/v1/models").await;
    assert_eq!(model_ids(&body), ["alias", "g-1", "g-2"], "{body}");
    mock.assert_async().await;
}

#[tokio::test]
async fn preview_models_pool_hits_current_member() {
    let mut up1 = spawn_mock_upstream().await;
    let mut up2 = spawn_mock_upstream().await;
    let _m1 = up1
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_body(r#"{"data":[{"id":"one"}]}"#)
        .create_async()
        .await;
    // 零 failover 守卫: 列表序优先级下第二成员必须零调用 (expect(0) + 显式 assert).
    let m2 = up2
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_body(r#"{"data":[{"id":"two"}]}"#)
        .expect(0)
        .create_async()
        .await;
    let proxy = spawn(vec![
        openai_provider("mem-1", &up1.url()),
        openai_provider("mem-2", &up2.url()),
        pool_provider("plan-pool", vec!["mem-1".into(), "mem-2".into()]),
    ])
    .await;

    let (status, v) = preview(&proxy, "plan-pool").await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["source"], "upstream");
    assert_eq!(v["upstream_id"], "mem-1", "pool 预览打当前命中成员");
    assert_eq!(v["models"], serde_json::json!(["one"]));
    m2.assert_async().await;
}

#[tokio::test]
async fn preview_models_fetch_failure_is_data_not_http_error() {
    let mut upstream = spawn_mock_upstream().await;
    upstream
        .mock("GET", "/v1/models")
        .with_status(500)
        .with_body("internal error")
        .create_async()
        .await;
    let proxy = spawn(vec![openai_provider("dead", &upstream.url())]).await;

    let (status, v) = preview(&proxy, "dead").await;
    assert_eq!(status, 200, "失败是数据不是 HTTP 错误 (probe 同姿态): {v}");
    assert_eq!(v["models"], serde_json::json!([]));
    let err = v["error"].as_str().expect("error 字段必有值");
    assert!(err.contains("500"), "错误串含状态详情: {err}");
}

#[tokio::test]
async fn preview_models_pool_unresolvable_is_data() {
    // 悬空成员 (ghost 不存在) → AllMembersExhausted (无闹钟形态), 落在 error 字段.
    let proxy = spawn(vec![pool_provider("broken-pool", vec!["ghost".into()])]).await;

    let (status, v) = preview(&proxy, "broken-pool").await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["models"], serde_json::json!([]));
    let err = v["error"].as_str().expect("error 字段必有值");
    assert!(
        err.contains("broken-pool") && err.contains("no available member"),
        "错误串含 pool id + reason (SEC-2 同型): {err}"
    );
}

#[tokio::test]
async fn preview_models_unknown_provider_404() {
    let proxy = spawn(vec![]).await;
    let (status, body) = get(&proxy, "/api/providers/ghost/models").await;
    assert_eq!(status, 404, "body: {body}");
}

/// multi-endpoint ROB: 空 endpoints (手改 state.toml 绕过 validate 的非法配置)
/// → 数据化错误 (error 字段), 不 panic / 不 5xx — 与 dispatch 的 503 同源假设.
#[tokio::test]
async fn preview_models_empty_endpoints_is_data_not_panic() {
    let broken = Provider {
        id: "no-endpoints".into(),
        enabled: true,
        name: None,
        kind: ProviderKind::Direct(DirectProvider {
            endpoints: vec![],
            api_key: String::new(),
            api_key_file: None,
        }),
    };
    let proxy = spawn(vec![broken]).await;
    let (status, v) = preview(&proxy, "no-endpoints").await;
    assert_eq!(status, 200, "失败是数据不是 HTTP 错误: {v}");
    assert_eq!(v["models"], serde_json::json!([]));
    let err = v["error"].as_str().expect("error 字段必有值");
    assert!(err.contains("no endpoints"), "reason 明确: {err}");
    assert_eq!(v["upstream_id"], "no-endpoints");
}

// ─── multi-endpoint: FWD-7 缓存键控 (id, egress) + fetch 端点选择 ───────────

/// 双端点 provider 挂 wildcard router — /o 与 /a 入口各自 fetch 各自端点并
/// **独立缓存** (条目键 = (provider id, 选定端点 egress 协议), FWD-7):
/// - 每个 ingress 的首次查询触发各自端点的 fetch (各自恰 1 次), TTL 内重复
///   查询零新请求 (N4 复用);
/// - 两入口的清单互不串台 (/o 只见 gpt-*, /a 只见 claude-*) — 旧裸 id 键控下
///   /a 首查会命中 /o 的条目 (anthropic 上游零 fetch, 清单串台), 本测试为红;
/// - anthropic 端点的 fetch 带 anthropic-version header (match_header 锁定) —
///   fetch 走选定端点的 egress 方言 (与 dispatch 转发路径同一 `select_endpoint`
///   语义: 广告的模型必须真能被该入口的服务端点提供).
#[tokio::test]
async fn router_models_multi_endpoint_cache_per_ingress() {
    let mut openai_upstream = spawn_mock_upstream().await;
    let mut anthropic_upstream = spawn_mock_upstream().await;
    let o_mock = openai_upstream
        .mock("GET", "/v1/models")
        .with_status(200)
        .with_body(r#"{"data":[{"id":"gpt-4o"},{"id":"gpt-4o-mini"}]}"#)
        // (dual, openai) 生命周期内恰 1 次: /o 首查 fetch, 复查走缓存.
        .expect(1)
        .create_async()
        .await;
    let a_mock = anthropic_upstream
        .mock("GET", "/v1/models")
        // egress 方言锚: fetch 按选定端点 (anthropic) 的协议出站.
        .match_header("anthropic-version", "2023-06-01")
        .with_status(200)
        .with_body(r#"{"data":[{"id":"claude-3-5-sonnet"},{"id":"claude-3-haiku"}]}"#)
        // (dual, anthropic) 独立条目恰 1 次: /a 首查 fetch, 复查走缓存.
        .expect(1)
        .create_async()
        .await;

    let providers = vec![
        multi_endpoint_provider(
            "dual",
            &[
                (Protocol::OpenAI, openai_upstream.url()),
                (Protocol::Anthropic, anthropic_upstream.url()),
            ],
        ),
        // wildcard 路由开 N6 gate (fetch + merge); 别名段为空 (无 exact pattern).
        router_provider("r", vec![route("*", "dual", 10)]),
    ];
    let proxy = spawn(providers).await;

    // /o 入口 ×2: 首查 fetch openai 端点, 二查零新请求; 清单 = openai 端点的模型.
    for i in 0..2 {
        let (status, body) = get(&proxy, "/o/r/v1/models").await;
        assert_eq!(status, 200, "第 {} 次查询: {body}", i + 1);
        assert_eq!(
            model_ids(&body),
            ["gpt-4o", "gpt-4o-mini"],
            "/o 入口清单来自 openai 端点 (第 {} 次): {body}",
            i + 1
        );
    }
    // /a 入口 ×2: 首查 fetch anthropic 端点 (独立缓存条目), 二查零新请求;
    // 清单 = anthropic 端点的模型 (Anthropic 响应 shape, data[].id 同构).
    for i in 0..2 {
        let (status, body) = get(&proxy, "/a/r/v1/models").await;
        assert_eq!(status, 200, "第 {} 次查询: {body}", i + 1);
        assert_eq!(
            model_ids(&body),
            ["claude-3-5-sonnet", "claude-3-haiku"],
            "/a 入口清单来自 anthropic 端点 (第 {} 次): {body}",
            i + 1
        );
    }
    o_mock.assert_async().await;
    a_mock.assert_async().await;
}
