//! Pool provider (套餐池) failover 集成测试 (spec §11-T2).
//!
//! 覆盖响应侧耗尽检测的三条挂载路径 (旁路, FWD-1: 检测绝不改响应字节):
//! - same_proto passthrough / IR map 空 → `fan_out_streaming` (spawn task);
//! - same_proto IR + redact 命中 (map 非空) + 非 2xx → `fan_out_buffered_ir`;
//! - cross_proto 非 2xx → buffer 后翻译前.
//!
//! 时间推进: 闹钟回归用短 cooldown (1s) + 无恢复来源形态驱动, 不 sleep 真实长时长.
//! 异步时序: `fan_out_streaming` 路径的检测在 spawn task 内完成 (客户端收到响应 ≠
//! 状态已 mark), 涉及切换的断言一律经 [`until_status`] 轮询 + 相对基线计数,
//! 不依赖内部时序.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use secret_guard::{
    dag::ConversationDag,
    provider::{
        DirectProvider, Endpoint, ExhaustConfig, PoolProvider, Protocol, Provider, ProviderKind,
        ProviderTable,
    },
    secrets::{SecretCategory, SecretEntry, SecretTable},
    server,
    state::AppState,
};
use tokio::net::TcpListener;

// ─── harness (镜像 tests/integration.rs 的测试构造 SSOT) ─────────────────────

fn tmp_state_path(label: &str) -> std::path::PathBuf {
    let id = uuid::Uuid::new_v4().to_string();
    let path =
        std::path::PathBuf::from(format!("/tmp/opencode/tmp/pool-failover-{label}-{id}.toml"));
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

fn base_app_state(
    upstream: reqwest::Client,
    providers: ProviderTable,
    dag: ConversationDag,
    secrets: SecretTable,
) -> AppState {
    let redact = secret_guard::config::RedactConfig::default();
    AppState {
        pools: secret_guard::pool::PoolStates::new(),
        upstream,
        providers,
        dag,
        secrets,
        api_keys: test_api_key_store(),
        auth_enabled: false,
        global_mock_prefix: Arc::from(""),
        on_probe_exhausted: redact.on_probe_exhausted,
        on_unsupported_protocol: redact.on_unsupported_protocol,
        on_fallback_restore: redact.on_fallback_restore,
        redacted_headers: secret_guard::state::normalize_redacted_headers(&redact.redacted_headers),
        upstream_timeouts: secret_guard::config::UpstreamTimeouts::default(),
        model_lists: Arc::new(secret_guard::proxy::ModelListCache::new()),
        usage: Arc::new(secret_guard::usage::UsageStore::in_memory()),
        pricing: Arc::new(secret_guard::usage::PricingCache::for_tests()),
        // B2: 详细日志开关 (存量行为守卫, 默认 on; 需要开启的测试用 struct-update 覆盖).
        audit_capture: secret_guard::state::AuditCapture::for_tests(true),
    }
}

async fn spawn_proxy(providers: Vec<Provider>, secrets: SecretTable) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let decisions = Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    let persist_lock = Arc::new(parking_lot::Mutex::new(()));
    let provider_table = ProviderTable::with_persist_lock(
        providers,
        vec![],
        decisions,
        tmp_state_path("sg-state"),
        persist_lock,
    );
    let state = base_app_state(
        reqwest::Client::new(),
        provider_table,
        ConversationDag::new(64, 500, 1),
        secrets,
    );
    let app = server::build_router(
        state,
        secret_guard::server_host_guard::HostGuard::new("127.0.0.1", addr.port()),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

// ─── provider / secret / mock 构造 helpers ───────────────────────────────────

fn direct_provider(id: &str, proto: Protocol, base_url: &str) -> Provider {
    Provider {
        id: id.into(),
        enabled: true,
        name: Some(id.into()),
        kind: ProviderKind::Direct(DirectProvider {
            endpoints: vec![Endpoint {
                protocol: proto,
                base_url: base_url.into(),
                common_uri: None,
            }],
            api_key: "sk-test".into(),
            api_key_file: None,
        }),
    }
}

fn pool_provider(id: &str, members: &[&str], cooldown_secs: u64) -> Provider {
    Provider {
        id: id.into(),
        enabled: true,
        name: Some(id.into()),
        kind: ProviderKind::Pool(PoolProvider {
            members: members.iter().map(|s| s.to_string()).collect(),
            exhaust: ExhaustConfig::default(),
            cooldown_secs,
        }),
    }
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
    e.mock_strategy.resolve_against(&e.value, "");
    e
}

fn secret_table_with(entries: Vec<SecretEntry>) -> SecretTable {
    let decisions = Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    SecretTable::new(vec![], entries, decisions, tmp_state_path("secret-table"))
}

// ─── mockito 计数 mock (1.7 的 Mock 无 hits() 查询 — 闭包自计数) ─────────────

/// 请求计数器 (match_request 闭包递增; 语义 = 该 mock 被选中响应的次数).
type Hits = Arc<AtomicUsize>;

fn new_hits() -> Hits {
    Arc::new(AtomicUsize::new(0))
}

fn hits(c: &Hits) -> usize {
    c.load(Ordering::SeqCst)
}

/// 挂一个带计数的 JSON 响应 mock (any path — 单成员单 mock, path 无判别意义,
/// 用 Any 消除对上游 path 拼接的假设; match_request 与 method/path 是 AND 语义).
async fn counted_json_response(
    server: &mut mockito::ServerGuard,
    counter: &Hits,
    status: u16,
    body: impl AsRef<[u8]>,
    extra_headers: &[(&str, &str)],
) {
    let c = counter.clone();
    let mut mock = server
        .mock("POST", mockito::Matcher::Any)
        .match_request(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            true
        })
        .with_status(status as usize)
        .with_header("content-type", "application/json");
    for (k, v) in extra_headers {
        mock = mock.with_header(*k, v);
    }
    mock.with_body(body).create_async().await;
}

/// 成员 mock 规格 ([`two_member_pool`] 的参数形态).
struct MemberSpec {
    status: u16,
    body: String,
    /// 额外响应 headers (如 Claude 订阅限流 header).
    headers: &'static [(&'static str, &'static str)],
}

fn resp(status: u16, body: impl Into<String>) -> MemberSpec {
    MemberSpec {
        status,
        body: body.into(),
        headers: &[],
    }
}

fn resp_with_headers(
    status: u16,
    body: impl Into<String>,
    headers: &'static [(&'static str, &'static str)],
) -> MemberSpec {
    MemberSpec {
        status,
        body: body.into(),
        headers,
    }
}

/// 双成员 pool 测试拓扑: 两个 mockito 上游 + `[m1, m2]` pool + 同协议 Direct
/// 成员 (判别约定: m1/m2 各自 mock 的响应 status 即流量来源标记). 拓扑陈述
/// 一次, 测试正文只剩 spec 差异.
///
/// 返回 (proxy_url, m1 计数, m2 计数, 两上游 server) — mockito ServerGuard
/// drop 会关 server, 测试须持有 server 绑定到函数末尾 (`_servers`).
async fn two_member_pool(
    pool_id: &str,
    proto: Protocol,
    cooldown_secs: u64,
    m1: MemberSpec,
    m2: MemberSpec,
    secrets: Vec<SecretEntry>,
) -> (
    String,
    Hits,
    Hits,
    mockito::ServerGuard,
    mockito::ServerGuard,
) {
    let (mut s1, mut s2) = (
        mockito::Server::new_async().await,
        mockito::Server::new_async().await,
    );
    let (h1, h2) = (new_hits(), new_hits());
    counted_json_response(&mut s1, &h1, m1.status, m1.body, m1.headers).await;
    counted_json_response(&mut s2, &h2, m2.status, m2.body, m2.headers).await;
    let proxy = spawn_proxy(
        vec![
            pool_provider(pool_id, &["m1", "m2"], cooldown_secs),
            direct_provider("m1", proto, &s1.url()),
            direct_provider("m2", proto, &s2.url()),
        ],
        secret_table_with(secrets),
    )
    .await;
    (proxy, h1, h2, s1, s2)
}

// ─── 请求 helpers ────────────────────────────────────────────────────────────

const CHAT_BODY: &str = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#;

/// OpenAI 形态 chat 请求 (ingress /o/{pool}/v1/chat/completions).
async fn chat(proxy: &str, pool: &str, body: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{proxy}/o/{pool}/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap()
}

/// 反复发请求直到响应 status 等于 `want` (pool 检测在流式 spawn task 内异步完成 —
/// 客户端收到 429 ≠ 状态已 mark, 紧随的请求可能仍打旧成员; 轮询上限 5s 防死循环,
/// 超时 panic 报告最后状态).
async fn until_status(
    proxy: &str,
    pool: &str,
    body: &str,
    want: reqwest::StatusCode,
) -> reqwest::Response {
    let mut last = None;
    for _ in 0..100 {
        let resp = chat(proxy, pool, body).await;
        if resp.status() == want {
            return resp;
        }
        last = Some(resp.status());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("request never got {want} within 5s (last: {last:?})");
}

/// 成功响应 body (OpenAI 形态, 健康成员的回包).
const OK_BODY: &str = r#"{"id":"cmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

/// 智谱窗口耗尽 body (动态 next_flush_time — 未来 1h, 保证解析成功且闹钟不响).
fn zhipu_exhaust_body() -> String {
    let t = chrono::Local::now() + chrono::Duration::seconds(3600);
    format!(
        r#"{{"error":{{"code":"1308","message":"Insufficient balance in coding plan"}},"next_flush_time":"{}"}}"#,
        t.to_rfc3339()
    )
}

/// 纯 code 通道形态 (无 next_flush_time / Retry-After → resume 走 cooldown 兜底).
const PLAIN_EXHAUST_BODY: &str = r#"{"error":{"code":"1308","message":"quota exceeded"}}"#;

/// Claude 订阅撞窗 body (rate_limit_error 不在默认码表 — 检测只走 header 通道).
const CLAUDE_EXHAUST_BODY: &str =
    r#"{"type":"error","error":{"type":"rate_limit_error","message":"Usage limit reached"}}"#;

/// Claude 订阅撞窗的专属响应 header (Anthropic Pro/Max OAuth 流量).
const CLAUDE_BLOCKED_HEADER: &[(&str, &str)] =
    &[("anthropic-ratelimit-unified-5h-status", "blocked")];

// ─── §11-T2: 智谱形态 (code 通道 + next_flush_time) ──────────────────────────

/// 智谱形态: 成员1 上游 429 + `error.code="1308"` + next_flush_time → 后续请求
/// failover 到成员2 (双上游计数断言), 触发请求原样透传 429 (SDK 重试落到
/// 新成员, sg 不内部重发).
#[tokio::test]
async fn zhipu_window_exhaust_switches_to_second_member() {
    let (proxy, m1_hits, m2_hits, _s1, _s2) = two_member_pool(
        "glm-pool",
        Protocol::OpenAI,
        60,
        resp(429, zhipu_exhaust_body()),
        resp(200, OK_BODY),
        vec![],
    )
    .await;

    // 请求1: 打到 m1, 429 原样透传 (spec: 触发切换的请求不内部重发).
    let resp1 = chat(&proxy, "glm-pool", CHAT_BODY).await;
    assert_eq!(resp1.status(), 429);
    assert_eq!(hits(&m1_hits), 1, "first request must hit member 1");

    // 检测异步 (spawn task): 轮询直到请求落到 m2 (200).
    let _ = until_status(&proxy, "glm-pool", CHAT_BODY, reqwest::StatusCode::OK).await;
    assert_eq!(
        hits(&m2_hits),
        1,
        "after exhaust signal, traffic must fail over to member 2"
    );
}

/// 闹钟回归: 成员1 429 (无恢复来源 → now+cooldown 兜底, cooldown=1s) → 切到 m2;
/// cooldown 过后成员1 回归**列表头** (前缀缓存友好) — 判别设计: m1 恒 429 /
/// m2 恒 200 (响应 status 即来源标记), 回归 = 闹钟后的单发请求恰好打到 m1
/// (再收 429 并重挂闹钟), 其后请求回落 m2.
#[tokio::test]
async fn exhausted_member_returns_to_head_after_cooldown_alarm() {
    let (proxy, m1_hits, m2_hits, _s1, _s2) = two_member_pool(
        "glm-pool",
        Protocol::OpenAI,
        1, // cooldown=1s: 短闹钟驱动回归, 不 sleep 真实长时长
        resp(429, PLAIN_EXHAUST_BODY),
        resp(200, OK_BODY),
        vec![],
    )
    .await;

    // 请求1: m1 429 → mark (resume = now + 1s).
    let resp1 = chat(&proxy, "glm-pool", CHAT_BODY).await;
    assert_eq!(resp1.status(), 429);
    assert_eq!(hits(&m1_hits), 1);

    // 闹钟期内: 流量切到 m2 (200 只可能来自 m2 — m1 恒 429).
    let _ = until_status(&proxy, "glm-pool", CHAT_BODY, reqwest::StatusCode::OK).await;
    let m2_hits_after_switch = hits(&m2_hits);
    assert!(
        m2_hits_after_switch >= 1,
        "during cooldown, traffic goes to member 2"
    );
    // 相对基线: until_status 轮询期间的探测请求可能反复命中 m1 (检测异步窗口),
    // 回归断言按相对计数, 不依赖轮询从未打到 m1 的时序假设.
    let m1_base = hits(&m1_hits);

    // 闹钟过期 (cooldown=1s + 检测/轮询余量): 成员1 回归列表头 — 单发请求
    // 恰好打到 m1 (再收 429, m1 计数 +1; 若未回归则会打 m2 收 200, 断言失败).
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let resp = chat(&proxy, "glm-pool", CHAT_BODY).await;
    assert_eq!(
        resp.status(),
        429,
        "recovered member 1 returns to the pool head"
    );
    assert_eq!(
        hits(&m1_hits),
        m1_base + 1,
        "the post-alarm request must hit member 1 (head of the list)"
    );

    // m1 重挂闹钟 → 其后请求回落 m2.
    let _ = until_status(&proxy, "glm-pool", CHAT_BODY, reqwest::StatusCode::OK).await;
    assert!(
        hits(&m2_hits) > m2_hits_after_switch,
        "after member 1 re-exhausts, traffic returns to member 2"
    );
}

// ─── §11-T2: Claude 订阅 header 形态 (header 通道) ───────────────────────────

/// Claude Pro/Max 订阅撞窗: 429 + `anthropic-ratelimit-unified-5h-status: blocked`
/// 专属 header → 切换.
#[tokio::test]
async fn claude_subscription_header_exhaust_switches_member() {
    let (proxy, m1_hits, m2_hits, _s1, _s2) = two_member_pool(
        "claude-pool",
        Protocol::OpenAI,
        60,
        resp_with_headers(429, CLAUDE_EXHAUST_BODY, CLAUDE_BLOCKED_HEADER),
        resp(200, OK_BODY),
        vec![],
    )
    .await;

    let resp1 = chat(&proxy, "claude-pool", CHAT_BODY).await;
    assert_eq!(resp1.status(), 429);
    assert_eq!(hits(&m1_hits), 1);

    let _ = until_status(&proxy, "claude-pool", CHAT_BODY, reqwest::StatusCode::OK).await;
    assert_eq!(
        hits(&m2_hits),
        1,
        "claude header signal must trigger failover"
    );
}

// ─── §11-T2: 全部耗尽 → 本地 503 快速失败 ────────────────────────────────────

/// 两个成员都收到耗尽信号后, 后续请求本地 503 (SEC-2 净化 message: 含 pool id,
/// 不含上游 body 原文), **无上游请求发出** (上游计数冻结).
#[tokio::test]
async fn all_members_exhausted_returns_local_503_without_upstream_request() {
    let (proxy, m1_hits, m2_hits, _s1, _s2) = two_member_pool(
        "glm-pool",
        Protocol::OpenAI,
        60,
        resp(429, PLAIN_EXHAUST_BODY),
        resp(429, PLAIN_EXHAUST_BODY),
        vec![],
    )
    .await;

    // 轮询直到两个成员都被标记 → 本地 503 (快速失败).
    let resp = until_status(
        &proxy,
        "glm-pool",
        CHAT_BODY,
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("glm-pool"),
        "503 body must name the pool id (SEC-2 sanitized): {body}"
    );
    assert!(
        !body.contains("quota exceeded"),
        "503 body must not echo upstream body text (SEC-2): {body}"
    );

    // 本地快速失败: 再发请求 → 仍 503 且上游计数冻结 (无出站请求).
    let hits_before = (hits(&m1_hits), hits(&m2_hits));
    for _ in 0..3 {
        let resp = chat(&proxy, "glm-pool", CHAT_BODY).await;
        assert_eq!(resp.status(), 503);
    }
    assert_eq!(
        (hits(&m1_hits), hits(&m2_hits)),
        hits_before,
        "local fast-fail must not send any upstream request"
    );
}

// ─── §11-T2: 流式请求收到 429 ────────────────────────────────────────────────

/// stream=true 请求收到 429 (上游拒绝时不是 SSE, body 已缓冲) → 同样触发切换.
#[tokio::test]
async fn streaming_request_receiving_429_triggers_switch() {
    let (proxy, m1_hits, m2_hits, _s1, _s2) = two_member_pool(
        "glm-pool",
        Protocol::OpenAI,
        60,
        resp(429, PLAIN_EXHAUST_BODY),
        resp(200, OK_BODY),
        vec![],
    )
    .await;

    let stream_body =
        r#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hello"}]}"#;
    let resp1 = chat(&proxy, "glm-pool", stream_body).await;
    assert_eq!(
        resp1.status(),
        429,
        "stream=true request must still see the 429"
    );
    assert_eq!(hits(&m1_hits), 1);

    let _ = until_status(&proxy, "glm-pool", stream_body, reqwest::StatusCode::OK).await;
    assert_eq!(
        hits(&m2_hits),
        1,
        "429 on a stream=true request must trigger failover"
    );
}

// ─── §11-T2: FWD-1 — 检测不改响应字节 ────────────────────────────────────────

/// 检测是旁路: 客户端收到的 429 body 与上游返回**逐字节一致** (含 JSON 精确形态).
#[tokio::test]
async fn detection_does_not_alter_response_bytes() {
    // 刻意用非常规空白/键序形态, 锁定字节级 (而非语义级) 一致. r##: body 含 `}"` +
    // Rust 1.97 的 `r#{..}#` bracketed raw string 歧义, 双井号消解.
    let upstream_body = r##"{"error" : {"code":"1308","message":"quota exceeded"} ,"next_flush_time":"2099-01-01 00:00:00"}"##;
    let (proxy, _m1_hits, _m2_hits, _s1, _s2) = two_member_pool(
        "glm-pool",
        Protocol::OpenAI,
        60,
        resp(429, upstream_body),
        resp(200, OK_BODY),
        vec![],
    )
    .await;

    let resp = chat(&proxy, "glm-pool", CHAT_BODY).await;
    assert_eq!(resp.status(), 429);
    let bytes = resp.bytes().await.unwrap();
    assert_eq!(
        &bytes[..],
        upstream_body.as_bytes(),
        "client 429 body must be byte-identical to upstream (FWD-1)"
    );
}

// ─── 挂载点覆盖: same_proto IR (redact 命中, map 非空 → fan_out_buffered_ir) ──

/// 请求 body 含 secret → redact 命中 (map 非空) → 非 2xx 响应走 buffered_ir
/// 路径, 检测同样生效 (切换).
#[tokio::test]
async fn exhaust_detection_covers_ir_redact_path() {
    let body_with_secret =
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"key is sk-live-abc123 ok"}]}"#;
    let (proxy, m1_hits, m2_hits, _s1, _s2) = two_member_pool(
        "glm-pool",
        Protocol::OpenAI,
        60,
        resp(429, PLAIN_EXHAUST_BODY),
        resp(200, OK_BODY),
        vec![secret("s1", "sk-live-abc123")],
    )
    .await;

    let resp1 = chat(&proxy, "glm-pool", body_with_secret).await;
    assert_eq!(resp1.status(), 429);
    assert_eq!(hits(&m1_hits), 1);

    let _ = until_status(
        &proxy,
        "glm-pool",
        body_with_secret,
        reqwest::StatusCode::OK,
    )
    .await;
    assert_eq!(
        hits(&m2_hits),
        1,
        "buffered_ir path must detect exhaust and fail over"
    );
}

// ─── 挂载点覆盖: cross_proto (跨协议非 2xx → buffer 后检测) ──────────────────

/// ingress OpenAI / 成员 anthropic → 跨协议路径. 成员1 429 + Claude 订阅
/// header → 检测 (上游原文) → 切换; 客户端收到的 429 是翻译后的 OpenAI
/// envelope (跨协议本来就会翻译 — 与检测无关).
#[tokio::test]
async fn exhaust_detection_covers_cross_proto_path() {
    let (proxy, m1_hits, m2_hits, _s1, _s2) = two_member_pool(
        "claude-pool",
        Protocol::Anthropic, // 成员协议 ≠ ingress OpenAI → 跨协议
        60,
        resp_with_headers(429, CLAUDE_EXHAUST_BODY, CLAUDE_BLOCKED_HEADER),
        resp(
            200,
            r#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-3","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}}"#,
        ),
        vec![],
    )
    .await;

    // ingress /o/... (OpenAI) → egress anthropic: 跨协议.
    let resp1 = chat(&proxy, "claude-pool", CHAT_BODY).await;
    assert_eq!(
        resp1.status(),
        429,
        "translated error envelope keeps upstream status"
    );
    let body1 = resp1.text().await.unwrap();
    assert!(
        body1.contains("rate_limit_error"),
        "cross-proto 429 is translated to an OpenAI-shaped envelope: {body1}"
    );
    assert_eq!(hits(&m1_hits), 1);

    let _ = until_status(&proxy, "claude-pool", CHAT_BODY, reqwest::StatusCode::OK).await;
    assert_eq!(
        hits(&m2_hits),
        1,
        "cross-proto path must detect exhaust and fail over"
    );
}
