//! OIDC 认证流程集成测试: 起本地 mock IdP server, 覆盖 `auth/oidc.rs` +
//! `auth/handlers.rs` 的完整 OIDC 流程 (discovery / token exchange / id_token 验证 /
//! login_start / oauth_callback / logout / me).
//!
//! # 为什么不用 mockito
//!
//! OIDC 流程涉及 3 个 endpoint 协作 (discovery + token + jwks), 且 discovery 返回的
//! metadata 里 URL 字段必须指向同一个 server 的实际端口. mockito 适合单 endpoint mock,
//! 多 endpoint 协作 + URL 自引用场景用 axum 直接起 server 更自然.
//!
//! # 为什么用 openidconnect 自己的 signing API 签 id_token
//!
//! 手拼 RS256 JWT 容易踩编码坑 (base64url-no-pad / 字段顺序 / 签名输入是
//! base64(header).base64(payload) 而非原文). openidconnect 内部生成 id_token 字节级
//! 兼容自己的 verifier, 故 mock IdP 直接用 `CoreRsaPrivateSigningKey` + `CoreIdToken::new`
//! 签 token, 把 `as_verification_key()` 派生的公钥放 JWKS, 全链路保证一致.
//!
//! # 覆盖契约
//!
//! - **RED-CRYPTO-1**: id_token 签名链路 (RS256 + JWKS 公钥验签) round-trip.
//! - **RED-CRYPTO-2**: nonce 精确匹配 (login 时生成, id_token 的 nonce claim 必须相等).
//! - **FWD-AUTH-1**: OidcBackend discover + exchange_and_verify happy path.
//! - **FWD-AUTH-2**: handlers login_start / oauth_callback / logout / me.
//! - **FWD-AUTH-3**: oauth_callback happy path 完整端到端 round-trip — mock IdP 实现
//!   /authorize (记录 nonce + code_challenge) 与 code-绑定 /token (真实执行 PKCE
//!   S256 比对 + 用 stored nonce 签发 id_token), 测试经 sg.sid cookie 逐步驱动
//!   login → authorize → callback → /api/me 全链 (PKCE 负对照见
//!   `oauth_callback_rejects_pkce_verification_failure`).
//! - **SEC-AUTH-1**: CSRF state mismatch / id_token 缺失 / 签名错误 均正确拒绝.
//! - **SEC-AUTH-3**: IdP 轮换签名密钥后, 运行中的 secret-guard 无需重启仍能完成 OIDC
//!   登录 (验签失败 → 刷新 JWKS → 有界重验一次). #198: rauthy 月度自动轮换后,
//!   新 kid 的 id_token 在启动时抓取的 JWKS 快照中查无此 key, 登录永久 500.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use axum::Router;
use axum::extract::{Query, State as AxumState};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
// PKCE S256 比对 (BASE64URL_NOPAD(SHA256(verifier))) — 与 oauth2 crate 的
// `PkceCodeChallenge::from_code_verifier_sha256` 同一编码 (见 handle_token 的
// AuthorizeCode 分支).
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
    CoreRsaPrivateSigningKey,
};
use openidconnect::{
    Audience, EmptyAdditionalClaims, EndUserEmail, EndUserName, IssuerUrl, JsonWebKeyId,
    LocalizedClaim, Nonce, StandardClaims, SubjectIdentifier,
};
use parking_lot::Mutex;
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::LineEnding;
// rand 0.10 无 rand::rngs::OsRng; rsa 0.9 钉死 rand_core 0.6 trait bounds,
// 其 re-export 的 OsRng 是唯一零新增依赖来源 (多版本共存归因见 AGENTS.md cargo-deny 段).
use rsa::rand_core::OsRng;
use secret_guard::auth::handlers::{AuthState, login_start, logout, me, oauth_callback};
use secret_guard::auth::oidc::{OidcBackend, OidcCredentials, OidcError};
use secret_guard::auth::{ApiKeyStore, build_session_layer};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

// AuthnBackend + PrivateSigningKey traits 在 scope: 前者调 get_user, 后者调
// as_verification_key (派生 JWKS 公钥).
use axum_login::AuthnBackend;
use openidconnect::PrivateSigningKey;

// ─── mock IdP 核心: 密钥 + 签名工具 ─────────────────────────────────────

/// 一次性生成密钥组 (主 + 野 + 轮换代), 启动时 ~150ms.
///
/// 主密钥的公钥进 JWKS (供客户端验签), 野密钥不公布 (用于 WrongSignature 测试).
/// 两个都用 openidconnect 自己的 `CoreRsaPrivateSigningKey::from_pem` 包装,
/// 这样后续签 id_token 用 openidconnect 的 API, 字节级兼容其 verifier.
///
/// # 关键: 主/野密钥共用同一个 `kid`
///
/// WrongSignature 测试的目标是验证"签名比较失败" (CryptoError "bad signature"), 而非
/// "JWKS 找不到 kid" (NoMatchingKey). 若两把密钥用不同 kid, openidconnect 在 JWKS
/// 按 kid 查不到野密钥的公钥, 直接报 NoMatchingKey 跳过签名比较 — 测试就无法
/// 守卫 RSA 签名验证逻辑本身. 让两把密钥共用 kid, openidconnect 会用 JWKS 里
/// 主密钥的公钥去验证野密钥签的 token, 命中签名 mismatch, 真正走完整验签路径.
///
/// # 轮换代密钥 (`rotated_key` + `rotated_jwks_json`)
///
/// `rotate_keys()` (SEC-AUTH-3, #198) 切换到的**新一代**密钥 (kid 不同), 其公钥
/// 独立序列化为 `rotated_jwks_json` (只含新代公钥 — "旧 key 立即下线"是比真实
/// IdP 新旧并存宽限期更严格的轮换形态). 预生成在静态 IdpKeys 里, 每个测试的
/// rotate 只是指针切换, 无重复 RSA 生成开销.
struct IdpKeys {
    signing_key: CoreRsaPrivateSigningKey,
    rogue_key: CoreRsaPrivateSigningKey,
    rotated_key: CoreRsaPrivateSigningKey,
    /// 只含轮换代公钥的 JWKS (预序列化).
    rotated_jwks_json: String,
    /// 只含初始主密钥公钥的 JWKS (预序列化).
    initial_jwks_json: String,
}

/// 主/野密钥共用的 key id (强制 WrongSignature 走签名比较而非 NoMatchingKey).
const SHARED_KID: &str = "test-key-1";

/// 轮换代密钥的 key id (与 SHARED_KID 不同, 模拟 IdP 换发新 kid).
const ROTATED_KID: &str = "test-key-rotated";

fn generate_keys() -> IdpKeys {
    let mut rng = OsRng;
    let main_priv = RsaPrivateKey::new(&mut rng, 2048).expect("gen main rsa key");
    let rogue_priv = RsaPrivateKey::new(&mut rng, 2048).expect("gen rogue rsa key");
    let rotated_priv = RsaPrivateKey::new(&mut rng, 2048).expect("gen rotated rsa key");

    let main_pem = main_priv
        .to_pkcs1_pem(LineEnding::LF)
        .expect("main to pkcs1 pem");
    let rogue_pem = rogue_priv
        .to_pkcs1_pem(LineEnding::LF)
        .expect("rogue to pkcs1 pem");
    let rotated_pem = rotated_priv
        .to_pkcs1_pem(LineEnding::LF)
        .expect("rotated to pkcs1 pem");

    // 主/野密钥故意共用 kid — 详见 IdpKeys 文档.
    let kid = JsonWebKeyId::new(SHARED_KID.to_string());
    let signing_key =
        CoreRsaPrivateSigningKey::from_pem(&main_pem, Some(kid.clone())).expect("main from pem");
    let rogue_key =
        CoreRsaPrivateSigningKey::from_pem(&rogue_pem, Some(kid)).expect("rogue from pem");
    let rotated_key = CoreRsaPrivateSigningKey::from_pem(
        &rotated_pem,
        Some(JsonWebKeyId::new(ROTATED_KID.to_string())),
    )
    .expect("rotated from pem");

    let initial_jwks_json = serde_json::to_string(&CoreJsonWebKeySet::new(vec![
        signing_key.as_verification_key(),
    ]))
    .expect("serialize initial jwks");
    let rotated_jwks_json = serde_json::to_string(&CoreJsonWebKeySet::new(vec![
        rotated_key.as_verification_key(),
    ]))
    .expect("serialize rotated jwks");

    IdpKeys {
        signing_key,
        rogue_key,
        rotated_key,
        rotated_jwks_json,
        initial_jwks_json,
    }
}

/// 用 openidconnect 自己的 API 签一个合法 RS256 id_token.
///
/// 关键不变量 (openidconnect 字符串精确校验, 必须三方一致):
/// - `issuer` == 客户端 discover 时传的 issuer
/// - `client_id` == 客户端 discover 时传的 client_id
/// - `nonce` == 客户端 authorize_url 生成并存 session 的 nonce
fn sign_id_token(
    signing_key: &CoreRsaPrivateSigningKey,
    issuer: &str,
    client_id: &str,
    nonce: &str,
    sub: &str,
    email: Option<&str>,
    name: Option<&str>,
) -> String {
    let mut standard = StandardClaims::new(SubjectIdentifier::new(sub.to_string()));
    if let Some(e) = email {
        standard = standard.set_email(Some(EndUserEmail::new(e.to_string())));
        standard = standard.set_email_verified(Some(true));
    }
    if let Some(n) = name {
        standard = standard.set_name(Some(LocalizedClaim::from(EndUserName::new(n.to_string()))));
    }

    let claims = CoreIdTokenClaims::new(
        IssuerUrl::new(issuer.to_string()).expect("issuer url"),
        vec![Audience::new(client_id.to_string())],
        chrono::Utc::now() + chrono::Duration::seconds(3600),
        chrono::Utc::now(),
        standard,
        EmptyAdditionalClaims {},
    )
    .set_nonce(Some(Nonce::new(nonce.to_string())));

    CoreIdToken::new(
        claims,
        signing_key,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .expect("sign id token")
    .to_string()
}

// ─── mock IdP 状态 + server ────────────────────────────────────────────

/// /token 端点返回什么. 测试用 `set_token_policy` 注入, mock server 取出后构造响应.
#[derive(Clone)]
enum TokenPolicy {
    /// Happy path: 签合法 id_token, nonce 用登录时生成的值.
    Happy { nonce: String },
    /// 合法 token response 但 **不含** id_token 字段.
    NoIdToken,
    /// 合法 id_token 但 nonce claim 错误.
    WrongNonce { wrong_nonce: String },
    /// 合法 id_token 但用**另一把** (不公布 JWKS 的) 私钥签名.
    WrongSignature { nonce: String },
    /// HTTP 错误响应 (任意 status + body).
    Error { status: u16, body: String },
    /// code-绑定路径 (完整 OIDC flow 端到端用): 从 form body 取 `code` 查 /authorize
    /// 时签发的记录, 真实执行 PKCE S256 比对 (`BASE64URL_NOPAD(SHA256(code_verifier))`
    /// == 记录的 code_challenge) + redirect_uri 一致性校验, 用记录的 **nonce**
    /// (authorize 时经 query 到达 IdP 的) 签发 id_token — 无需测试读取 server-side
    /// session 即可闭合 nonce round-trip.
    AuthorizeCode,
}

/// /authorize 签发的 authorization code 对应的请求记录 (code-绑定 token 签发数据源).
///
/// state 不入 record: 它只在 authorize 应答里原样 echo 回 redirect_uri (见
/// `handle_authorize`), /token 请求不携带 state, 无消费点 (存了就是 dead field).
#[derive(Clone)]
struct AuthorizeRecord {
    /// authorize 请求 query 里的 nonce — id_token 的 nonce claim 来源
    /// (RED-CRYPTO-2 round-trip 的 IdP 侧起点).
    nonce: String,
    /// authorize 请求 query 里的 code_challenge (S256) — token 交换时 PKCE
    /// 验证的比对基准.
    code_challenge: String,
    /// authorize 请求 query 里的 redirect_uri — token 交换时一致性校验
    /// (RFC 6749 §4.1.3).
    redirect_uri: String,
}

/// mock IdP 的共享状态 (跨多 handler 协作).
#[derive(Clone)]
struct IdpState {
    /// IdP 的 issuer URL (= server origin, 三处复用保证字符串相等).
    issuer: String,
    /// 客户端预期的 client_id (id_token aud claim 用).
    client_id: String,
    /// 静态密钥组 (跨所有测试共享): 初始主密钥 + 野密钥 + 轮换代密钥 + 两代 JWKS.
    keys: &'static IdpKeys,
    /// 当前活跃的是哪一代签名密钥 (false = 初始主密钥, true = 轮换代).
    /// per-instance 状态: 不同测试 spawn 的 mock IdP 互不影响轮换进度.
    rotated: Arc<Mutex<bool>>,
    /// discovery 端点故障开关 (true = /.well-known/openid-configuration 返回 500).
    /// 模拟 IdP 半故障 (token 端点正常但 discovery 不可用), 测试 JWKS 刷新失败路径.
    discovery_broken: Arc<Mutex<bool>>,
    /// 下一次 /token 请求的策略. 一次性 (取出即清, 防串扰).
    token_policy: Arc<Mutex<Option<TokenPolicy>>>,
    /// 所有收到的 /token 请求 body (PKCE verifier 断言用).
    token_requests: Arc<Mutex<Vec<String>>>,
    /// /authorize 签发的 code → 请求记录 (TokenPolicy::AuthorizeCode 的 PKCE 验证
    /// + stored-nonce 签发数据源).
    authorize_codes: Arc<Mutex<HashMap<String, AuthorizeRecord>>>,
}

/// 已启动的 mock IdP handle (测试用).
struct MockIdp {
    state: IdpState,
}

impl MockIdp {
    fn set_token_policy(&self, policy: TokenPolicy) {
        *self.state.token_policy.lock() = Some(policy);
    }

    /// 模拟 IdP 轮换签名密钥 (OIDC Core #RotateSigKeys): 切换到新一代密钥
    /// (kid `test-key-rotated`), JWKS 替换为只含新代公钥.
    ///
    /// 之后所有 id_token 都用新密钥签 (与真实 IdP 行为一致: 轮换后新签发的 token
    /// 全部用新 key). 客户端若仍持旧 JWKS 快照 → NoMatchingKey → #198.
    fn rotate_keys(&self) {
        *self.state.rotated.lock() = true;
    }

    /// 使 discovery 端点返回 500 (token 端点不受影响 — 模拟 IdP 半故障).
    fn break_discovery(&self) {
        *self.state.discovery_broken.lock() = true;
    }

    /// 恢复 discovery 端点正常响应 (与 break_discovery 对称).
    fn fix_discovery(&self) {
        *self.state.discovery_broken.lock() = false;
    }

    /// 取出所有收到的 /token 请求 body (PKCE verifier round-trip 断言用).
    fn token_requests(&self) -> Vec<String> {
        self.state.token_requests.lock().clone()
    }

    /// 篡改所有已签发 code 的 code_challenge (PKCE 负对照: 让 token 交换时
    /// S256(session 里的 verifier) 必不匹配 → /token 400 → callback 登录失败,
    /// 证明 AuthorizeCode 路径的 PKCE 比对是真实门禁而非摆设).
    fn tamper_all_code_challenges(&self) {
        for record in self.state.authorize_codes.lock().values_mut() {
            record.code_challenge = "tampered-challenge-will-not-match".to_string();
        }
    }

    fn issuer(&self) -> &str {
        &self.state.issuer
    }

    fn client_id(&self) -> &str {
        &self.state.client_id
    }
}

impl IdpState {
    /// 当前活跃签名密钥 + 其对应的 JWKS JSON (SSOT: "JWKS 公布的 == 活跃签名密钥
    /// 的公钥" 这一 mock 保真度不变量由本方法唯一维护, /token 与 /jwks 共用).
    fn active_signing(&self) -> (&CoreRsaPrivateSigningKey, &str) {
        if *self.rotated.lock() {
            (&self.keys.rotated_key, &self.keys.rotated_jwks_json)
        } else {
            (&self.keys.signing_key, &self.keys.initial_jwks_json)
        }
    }

    /// 用指定密钥签 id_token (issuer/client_id 来自本 state; 测试用户恒为
    /// user-42 / alice@example.com / Alice — 多处测试断言的 claims SSOT).
    fn id_token_for(&self, key: &CoreRsaPrivateSigningKey, nonce: &str) -> String {
        sign_id_token(
            key,
            &self.issuer,
            &self.client_id,
            nonce,
            "user-42",
            Some("alice@example.com"),
            Some("Alice"),
        )
    }
}

/// 启动 mock IdP server (返回控制 handle).
///
/// IdP endpoint 布局:
/// - `GET /.well-known/openid-configuration`: discovery metadata (issuer == self origin;
///   `break_discovery` 后返回 500, 模拟 IdP 半故障).
/// - `GET /jwks`: JWKS 公钥 (初始主密钥; `rotate_keys` 后只含轮换代公钥).
/// - `POST /token`: token exchange (按 token_policy 返回).
/// - `GET /authorize`: 完整授权端点 (校验参数 + 签发 code + 302 回 redirect_uri,
///   见 `handle_authorize`; 既有测试不访问它, 行为不受影响).
async fn spawn_mock_idp() -> MockIdp {
    // 跨测试共享 RSA 密钥组 (避免每个测试重复 ~150ms 生成 3 把密钥的开销, ~19 个
    // 测试 → 省数秒).
    // 安全性: 密钥仅用于测试签 id_token, 不持有任何真实凭证; 共享不影响测试隔离性
    // (每个测试的 nonce/state/code 仍独立生成, 验签只关心公钥-签名匹配而非密钥独占).
    static SHARED_KEYS: OnceLock<IdpKeys> = OnceLock::new();
    let keys: &'static IdpKeys = SHARED_KEYS.get_or_init(generate_keys);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let issuer = format!("http://{addr}");

    let state = IdpState {
        issuer: issuer.clone(),
        client_id: "test-client".to_string(),
        keys,
        rotated: Arc::new(Mutex::new(false)),
        discovery_broken: Arc::new(Mutex::new(false)),
        token_policy: Arc::new(Mutex::new(None)),
        token_requests: Arc::new(Mutex::new(vec![])),
        authorize_codes: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get({
                let state = state.clone();
                let iss = issuer.clone();
                move || async move {
                    if *state.discovery_broken.lock() {
                        let mut resp = idp_json_response(r#"{"error":"discovery broken by test"}"#);
                        *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        return resp;
                    }
                    discovery_response(&iss)
                }
            }),
        )
        .route(
            "/jwks",
            get({
                let state = state.clone();
                move || {
                    let (_, jwks) = state.active_signing();
                    let jwks = jwks.to_string();
                    std::future::ready(idp_json_response(&jwks))
                }
            }),
        )
        .route("/token", post(handle_token).with_state(state.clone()))
        .route(
            "/authorize",
            get(handle_authorize).with_state(state.clone()),
        );

    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    MockIdp { state }
}

/// 构造 discovery metadata JSON (最小必填字段集).
///
/// 关键不变量: `issuer` 字段必须逐字符等于 server 的真实 origin (openidconnect
/// 字符串精确校验, 不做 URL 规范化).
fn discovery_response(issuer: &str) -> Response {
    let metadata = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    });
    idp_json_response(&metadata.to_string())
}

/// application/json 响应. openidconnect 严格要求 discovery/jwks 的 Content-Type.
fn idp_json_response(body: &str) -> Response {
    let mut resp = Response::new(body.to_string().into());
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// /token handler: 取出当前策略, 用 IdpState 的 key 签 id_token, 构造响应.
async fn handle_token(AxumState(state): AxumState<IdpState>, body: String) -> Response {
    // clone 留档: AuthorizeCode 分支还要解析 form body (code / code_verifier /
    // redirect_uri), 既有断言 (PKCE verifier round-trip) 也读原始 body.
    state.token_requests.lock().push(body.clone());

    let policy = state
        .token_policy
        .lock()
        .take()
        .unwrap_or(TokenPolicy::Error {
            status: 500,
            body: r#"{"error":"test setup: token_policy not set"}"#.to_string(),
        });

    match policy {
        TokenPolicy::Happy { nonce } => {
            // 活跃密钥按代数选择 (SSOT: IdpState::active_signing): rotate_keys 后用
            // 新代密钥签, 模拟真实 IdP 轮换后所有新 token 都用新 key 签发.
            let (active, _) = state.active_signing();
            let id_token = state.id_token_for(active, &nonce);
            token_response_with_id_token(id_token)
        }
        TokenPolicy::NoIdToken => token_response_no_id_token(),
        TokenPolicy::WrongNonce { wrong_nonce } => {
            // nonce 故意错: 用 wrong_nonce 当 id_token 的 nonce claim, 但客户端
            // 会用真实 nonce 验证 → InvalidNonce. 签名用活跃密钥 (mock 语义: 除
            // rogue 例外, IdP 恒用活跃密钥签名), 保证失败发生在 nonce 层.
            let (active, _) = state.active_signing();
            let id_token = state.id_token_for(active, &wrong_nonce);
            token_response_with_id_token(id_token)
        }
        TokenPolicy::WrongSignature { nonce } => {
            // 用 rogue_key 签 (不公布 JWKS), 客户端验签必失败.
            let id_token = state.id_token_for(&state.keys.rogue_key, &nonce);
            token_response_with_id_token(id_token)
        }
        TokenPolicy::Error { status, body } => {
            // 测试构造 TokenPolicy::Error 时必须用合法 HTTP status; 不合法说明
            // 测试 setup 有错, 直接 panic 而非 fallback 掩盖.
            let mut resp = Response::new(body.into());
            *resp.status_mut() =
                StatusCode::from_u16(status).expect("TokenPolicy::Error: valid u16 status");
            resp
        }
        TokenPolicy::AuthorizeCode => {
            // 完整 OIDC flow 的 token 端点语义 (RFC 6749 + RFC 7636):
            // 1. 解析 urlencoded form body (openidconnect AuthType::RequestBody —
            //    client_id / code / code_verifier / redirect_uri 都在 form).
            let form: HashMap<String, String> =
                openidconnect::url::form_urlencoded::parse(body.as_bytes())
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
            // 2. code 必须是 /authorize 签发过的, 且 single-use — 兑换即移除
            //    (RFC 6749 §4.1.2 的一次性语义).
            let code = form.get("code").cloned().unwrap_or_default();
            let Some(record) = state.authorize_codes.lock().remove(&code) else {
                return idp_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "unknown authorization code",
                );
            };
            // 3. redirect_uri 必须与 authorize 时一致 (RFC 6749 §4.1.3).
            if form.get("redirect_uri").map(String::as_str) != Some(record.redirect_uri.as_str()) {
                return idp_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "redirect_uri mismatch",
                );
            }
            // 4. PKCE S256 验证 (RFC 7636 §4.6): verifier 是 secret-guard 从
            //    server-side session 取出送来的 — 比对通过即证明 session 里的
            //    verifier 与 authorize 时的 challenge 同源 (PKCE round-trip 成立).
            //    编码与 oauth2 的 from_code_verifier_sha256 逐字节一致.
            let verifier = form.get("code_verifier").cloned().unwrap_or_default();
            let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            if computed != record.code_challenge {
                return idp_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "PKCE verification failed",
                );
            }
            // 5. 用 authorize 时记录的 nonce 签发 (nonce 经 authorize query 到达 IdP,
            //    客户端将用 session 里的同一 nonce 验证 — RED-CRYPTO-2 round-trip).
            let (active, _) = state.active_signing();
            let id_token = state.id_token_for(active, &record.nonce);
            token_response_with_id_token(id_token)
        }
    }
}

fn token_response_with_id_token(id_token: String) -> Response {
    let body = json!({
        "access_token": "mock-access-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
    });
    idp_json_response(&body.to_string())
}

fn token_response_no_id_token() -> Response {
    let body = json!({
        "access_token": "mock-access-token",
        "token_type": "Bearer",
        "expires_in": 3600
    });
    idp_json_response(&body.to_string())
}

/// /authorize handler: 完整 OIDC 授权端点 (供 happy path 端到端测试).
///
/// 校验必填参数 (client_id / redirect_uri / state / nonce / code_challenge /
/// `code_challenge_method == S256` / `response_type == code`), 签发一次性 code 并把
/// (nonce, code_challenge, redirect_uri) 记入 `authorize_codes`, 302 回
/// `{redirect_uri}?code=...&state=...` (state 原样 echo — secret-guard 侧的 CSRF
/// 校验由此被真实驱动).
///
/// 假设声明 (ROB 风格): redirect_uri 无既有 query (测试内恒真 — sg 的 callback URL
/// 不带 query), 故直接 `?` 拼接; code (uuid v4 hex) 与 state (openidconnect 用
/// base64url-nopad 生成) 均为 URL-safe 字符, 无需 percent-encode. 假设不成立时
/// 产生畸形 Location → 测试断言失败 (fail loudly, 不静默).
async fn handle_authorize(
    AxumState(state): AxumState<IdpState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let bad_request =
        |what: &str| idp_error_response(StatusCode::BAD_REQUEST, "invalid_request", what);

    let (Some(client_id), Some(redirect_uri), Some(state_param), Some(nonce), Some(code_challenge)) = (
        params.get("client_id"),
        params.get("redirect_uri"),
        params.get("state"),
        params.get("nonce"),
        params.get("code_challenge"),
    ) else {
        return bad_request("missing client_id/redirect_uri/state/nonce/code_challenge");
    };
    if client_id != &state.client_id {
        return bad_request("unknown client_id");
    }
    if params.get("response_type").map(String::as_str) != Some("code") {
        return bad_request("only response_type=code is supported");
    }
    // 只接受 S256 (plain challenge 会让 PKCE 形同虚设; openidconnect 恒发 S256).
    if params.get("code_challenge_method").map(String::as_str) != Some("S256") {
        return bad_request("only S256 code_challenge_method is supported");
    }

    let code = uuid::Uuid::new_v4().to_string();
    state.authorize_codes.lock().insert(
        code.clone(),
        AuthorizeRecord {
            nonce: nonce.clone(),
            code_challenge: code_challenge.clone(),
            redirect_uri: redirect_uri.clone(),
        },
    );

    // 302 Found: 真实 IdP 授权端点的重定向语义 (Redirect::to 是 303, 此处显式用
    // FOUND 更贴近 wire 形态).
    let location = format!("{redirect_uri}?code={code}&state={state_param}");
    (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
}

/// /token 与 /authorize 的错误响应 (OAuth2 wire 形态, RFC 6749 §5.2: 结构化
/// error + error_description 字段).
fn idp_error_response(status: StatusCode, error: &str, description: &str) -> Response {
    let mut resp =
        idp_json_response(&json!({ "error": error, "error_description": description }).to_string());
    *resp.status_mut() = status;
    resp
}

// ─── client router (secret-guard 侧 handlers 装配) ─────────────────────

/// 装配最小 client router: 只有 OIDC auth 路由 (无 forwarding / proxy).
///
/// 与 `server.rs::build_router_with_auth_layers` 的差异: 不挂 AppState /
/// forwarding 路由, 只保留 OIDC session + handlers, 让测试聚焦 auth 行为.
///
/// # 端口隔离
///
/// 每次 `build_test_router` 都 `TcpListener::bind("127.0.0.1:0")` 让 OS 分配
/// 空闲端口, 多个测试并行跑不会冲突. ApiKeyStore 的 state_path 也用 UUID 唯一化
/// (避免跨测试 state 持久化文件污染).
/// 构造空 ApiKeyStore (无 static key + 无 dynamic entry). 用 UUID 唯一化的临时
/// state_path 满足构造签名 (测试不触发 CRUD 持久化, 路径仅占位, 且跨测试不互扰).
fn empty_api_key_store(prefix: &str) -> ApiKeyStore {
    let tmp_state = std::env::temp_dir().join(format!("{prefix}-{}.toml", uuid::Uuid::new_v4()));
    ApiKeyStore::new(
        &[],
        std::path::Path::new("."),
        vec![],
        std::collections::HashSet::new(),
        tmp_state,
        std::sync::Arc::new(parking_lot::Mutex::new(())),
    )
}

async fn build_test_router(backend: OidcBackend) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");

    let api_keys = empty_api_key_store("sg-auth-oidc-test");
    let auth_state = AuthState {
        backend: backend.clone(),
        api_keys,
    };

    use axum_login::AuthManagerLayerBuilder;
    let auth_routes: Router = Router::new()
        .route("/login", get(login_start).post(login_start))
        .route("/oauth2/callback", get(oauth_callback))
        .route("/logout", post(logout))
        .route("/api/me", get(me))
        .layer(axum::Extension(auth_state));

    let session_layer = build_session_layer(false); // 测试走 HTTP, Secure flag 须关
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();

    let app = Router::new().merge(auth_routes).layer(auth_layer);

    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    base
}

// ─── 测试用例 ──────────────────────────────────────────────────────────

/// 启动 mock IdP + 用它 discover 出 OidcBackend (exchange_and_verify_* 测试共用).
///
/// redirect_url 用占位值 (这些测试不触发真实 callback).
async fn spawn_idp_with_backend() -> (MockIdp, OidcBackend) {
    let idp = spawn_mock_idp().await;
    let backend = OidcBackend::discover(
        idp.issuer(),
        idp.client_id(),
        None,
        "http://127.0.0.1:1/oauth2/callback",
    )
    .await
    .expect("discover");
    (idp, backend)
}

/// 启动完整 client stack: mock IdP + OidcBackend + client router (handler 测试共用).
///
/// 返回 (MockIdp 控制柄, client base URL).
async fn spawn_idp_with_client() -> (MockIdp, String) {
    let (idp, backend) = spawn_idp_with_backend().await;
    let base = build_test_router(backend).await;
    (idp, base)
}

/// 从一组 authorize_url 生成的 (pkce_verifier, nonce, csrf_state) 构造 OidcCredentials.
///
/// 默认假设 CSRF state 匹配 (old == new), 这是绝大多数测试的默认情形.
/// `exchange_and_verify_csrf_mismatch` 显式覆写 new_state 来违反契约.
fn creds_from_parts(pkce_verifier: String, nonce: String, csrf_state: String) -> OidcCredentials {
    OidcCredentials {
        code: "fake-auth-code".to_string(),
        pkce_verifier,
        nonce,
        old_state: csrf_state.clone(),
        new_state: csrf_state,
    }
}

/// Happy 登录前置样板: 生成 authorize 凭证 (真实 nonce/state, 与生产 login_start
/// 路径一致) + 预设 Happy token 策略. 其他 policy 的测试保持显式编排.
fn happy_login_attempt(idp: &MockIdp, backend: &OidcBackend) -> OidcCredentials {
    let parts = backend.authorize_url();
    idp.set_token_policy(TokenPolicy::Happy {
        nonce: parts.nonce.clone(),
    });
    creds_from_parts(parts.pkce_verifier, parts.nonce, parts.csrf_state)
}

#[tokio::test]
async fn discover_happy_path() {
    let (idp, backend) = spawn_idp_with_backend().await;
    // discover 成功即证明: metadata 解析 + issuer 字符串校验 + JWKS 拉取全部通过.
    // 进一步用 authorize_url 验证 client typestate 完整可用.
    let parts = backend.authorize_url();
    assert!(
        parts.auth_url.as_str().starts_with(idp.issuer()),
        "auth_url should point to IdP"
    );
    assert!(!parts.pkce_verifier.is_empty());
    assert!(!parts.nonce.is_empty());
    assert!(!parts.csrf_state.is_empty());
}

#[tokio::test]
async fn discover_invalid_issuer_url_format() {
    // issuer URL 格式非法 (openidconnect::IssuerUrl::new 校验).
    let err = OidcBackend::discover("not-a-url", "client", None, "http://127.0.0.1:1/cb")
        .await
        .unwrap_err();
    assert!(err.contains("invalid issuer_url"), "got: {err}");
}

#[tokio::test]
async fn discover_unreachable() {
    // 用一个几乎肯定空闲的端口 (1), 让 discovery HTTP 请求失败.
    let err = OidcBackend::discover(
        "http://127.0.0.1:1",
        "client",
        None,
        "http://127.0.0.1:1/cb",
    )
    .await
    .unwrap_err();
    assert!(
        err.contains("discovery failed") || err.contains("OIDC"),
        "got: {err}"
    );
}

#[tokio::test]
async fn discover_missing_token_endpoint() {
    // 起 IdP 但 discovery metadata 故意省略 token_endpoint → secret-guard 显式报错
    // (而非依赖 openidconnect 内部 EndpointMaybeSet typestate).
    //
    // 注: openidconnect::discover_async 会先拉 metadata 再拉 jwks_uri, 故 jwks 路由必须
    // 返回 200 (空 JWKS 即可); 错误会在 secret-guard 自己的 `no token_endpoint` 校验触发.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let issuer = format!("http://{addr}");
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get({
                let iss = issuer.clone();
                move || async move {
                    let metadata = json!({
                        "issuer": iss,
                        "authorization_endpoint": format!("{iss}/authorize"),
                        // 故意省略 token_endpoint
                        "jwks_uri": format!("{iss}/jwks"),
                        "response_types_supported": ["code"],
                        "subject_types_supported": ["public"],
                        "id_token_signing_alg_values_supported": ["RS256"]
                    });
                    idp_json_response(&metadata.to_string())
                }
            }),
        )
        .route(
            "/jwks",
            get(|| async move { idp_json_response(r#"{"keys":[]}"#) }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    let err = OidcBackend::discover(&issuer, "cid", None, &format!("{issuer}/cb"))
        .await
        .unwrap_err();
    assert!(err.contains("no token_endpoint"), "got: {err}");
}

#[tokio::test]
async fn exchange_and_verify_happy() {
    let (idp, backend) = spawn_idp_with_backend().await;

    // authorize_url 生成一组真实 nonce + state (与生产 login_start 路径一致).
    let parts = backend.authorize_url();
    // 保留 verifier 副本, exchange 后断言它确实被发给 IdP (PKCE round-trip).
    let verifier_sent = parts.pkce_verifier.clone();

    // 预设 token response 策略: 用真实 nonce 签 id_token.
    idp.set_token_policy(TokenPolicy::Happy {
        nonce: parts.nonce.clone(),
    });

    let creds = creds_from_parts(parts.pkce_verifier, parts.nonce, parts.csrf_state);

    let user = backend
        .exchange_and_verify(creds)
        .await
        .expect("exchange should succeed");

    // 守卫 RED-CRYPTO-1 (签名 round-trip) + RED-CRYPTO-2 (nonce 匹配) + claims 提取.
    assert_eq!(user.sub, "user-42");
    assert_eq!(user.email.as_deref(), Some("alice@example.com"));
    assert_eq!(user.name.as_deref(), Some("Alice"));

    // 守卫 PKCE verifier round-trip: secret-guard 确实把 authorize_url 生成的 verifier
    // 经 /token form body 发给 IdP (而非放 query string 或前端可见位置).
    let token_reqs = idp.token_requests();
    assert_eq!(token_reqs.len(), 1, "exactly one /token request expected");
    assert!(
        token_reqs[0].contains(&verifier_sent),
        "/token body should carry PKCE verifier; got: {}",
        token_reqs[0]
    );

    // 同时验证: get_user 缓存命中 (authenticate 写入, 后续请求恢复).
    // OidcBackend 内部 Arc<RwLock<HashMap>>, clone 是 Arc 引用拷贝, 共享同一份缓存.
    let cached = backend
        .get_user(&user.sub)
        .await
        .expect("get_user")
        .expect("user should be cached");
    assert_eq!(cached.sub, "user-42");
}

#[tokio::test]
async fn exchange_and_verify_csrf_mismatch() {
    // SEC-AUTH-1: CSRF state 不匹配必须拒绝 (防 CSRF 攻击).
    let (_idp, backend) = spawn_idp_with_backend().await;

    let parts = backend.authorize_url();
    // 显式构造不匹配的 CSRF state (违反 old == new 契约), 突出本测试的意图.
    let creds = OidcCredentials {
        code: "x".into(),
        pkce_verifier: parts.pkce_verifier,
        nonce: parts.nonce,
        old_state: parts.csrf_state,
        new_state: "different-state".to_string(),
    };

    let err = backend.exchange_and_verify(creds).await.unwrap_err();
    assert!(matches!(err, OidcError::CsrfMismatch), "got: {err:?}");
}

#[tokio::test]
async fn exchange_and_verify_token_http_error() {
    // token endpoint 返回 4xx → TokenExchange 错误 (不要泄漏内部 IdP 细节).
    let (idp, backend) = spawn_idp_with_backend().await;

    let parts = backend.authorize_url();
    idp.set_token_policy(TokenPolicy::Error {
        status: 400,
        body: r#"{"error":"invalid_grant"}"#.to_string(),
    });

    let creds = creds_from_parts(parts.pkce_verifier, parts.nonce, parts.csrf_state);

    let err = backend.exchange_and_verify(creds).await.unwrap_err();
    match err {
        OidcError::TokenExchange(msg) => {
            // openidconnect 包装 oauth2 的错误, message 含 "Server returned error response"
            // 或具体 status. 不验细节 (依赖库版本), 只确认错误类别.
            assert!(!msg.is_empty(), "TokenExchange error message empty");
        }
        other => panic!("expected TokenExchange, got: {other:?}"),
    }
}

#[tokio::test]
async fn exchange_and_verify_no_id_token() {
    // token response 合法但不含 id_token → NoIdToken (OIDC 要求 id_token).
    let (idp, backend) = spawn_idp_with_backend().await;

    let parts = backend.authorize_url();
    idp.set_token_policy(TokenPolicy::NoIdToken);

    let creds = creds_from_parts(parts.pkce_verifier, parts.nonce, parts.csrf_state);

    let err = backend.exchange_and_verify(creds).await.unwrap_err();
    assert!(matches!(err, OidcError::NoIdToken), "got: {err:?}");
}

#[tokio::test]
async fn exchange_and_verify_wrong_signature() {
    // RED-CRYPTO-1 反向: id_token 用 JWKS 未公布的私钥签名 → 验签必失败.
    //
    // 修复 JWKS 轮换 (#198) 后, 此测试兼守卫有界重试的下界: rogue_key 与主密钥
    // 共用 kid → CryptoError "bad signature" (SignatureVerification 类) → 触发一次 JWKS
    // 刷新 + 重验 → 仍失败 → 最终必须仍报 IdTokenVerification (刷新不得掩盖
    // 真正的验签失败, 也不得因刷新重验而放行坏签名).
    let (idp, backend) = spawn_idp_with_backend().await;

    let parts = backend.authorize_url();
    idp.set_token_policy(TokenPolicy::WrongSignature {
        nonce: parts.nonce.clone(),
    });

    let creds = creds_from_parts(parts.pkce_verifier, parts.nonce, parts.csrf_state);

    let err = backend.exchange_and_verify(creds).await.unwrap_err();
    match err {
        OidcError::IdTokenVerification(msg) => {
            // 共用 kid 设计下 (见 IdpKeys 文档) 恒为 CryptoError "bad signature"
            // (走完整签名比较), 不耦合 openidconnect 错误文案.
            assert!(!msg.is_empty());
        }
        other => panic!("expected IdTokenVerification, got: {other:?}"),
    }
}

#[tokio::test]
async fn exchange_and_verify_wrong_nonce() {
    // RED-CRYPTO-2 反向: id_token nonce claim 不匹配 → InvalidNonce (防重放).
    let (idp, backend) = spawn_idp_with_backend().await;

    let parts = backend.authorize_url();
    idp.set_token_policy(TokenPolicy::WrongNonce {
        wrong_nonce: "totally-different-nonce".to_string(),
    });

    let creds = creds_from_parts(parts.pkce_verifier, parts.nonce, parts.csrf_state);

    let err = backend.exchange_and_verify(creds).await.unwrap_err();
    // openidconnect 在 nonce 不匹配时报 ClaimsVerificationError, 我们的代码包成
    // IdTokenVerification. 仅断言 variant (不耦合 openidconnect 错误文案, 它跨版本
    // 可能变).
    assert!(
        matches!(err, OidcError::IdTokenVerification(_)),
        "expected IdTokenVerification, got: {err:?}"
    );
}

#[tokio::test]
async fn exchange_and_verify_survives_jwks_rotation() {
    // SEC-AUTH-3 (#198): IdP 轮换签名密钥后, 运行中的 secret-guard 无需重启仍能完成
    // OIDC 登录. 场景复现 (2026-09-02 线上事故): rauthy 月度自动轮换签名 key, 新签
    // 发 id_token 的 kid 不在启动时抓取的 JWKS 快照里 → NoMatchingKey → 登录永久
    // 500, 直到进程重启. 期望: 验签失败触发 JWKS 刷新 (重跑 discovery) + 有界重验
    // 一次 → 登录成功.
    let (idp, backend) = spawn_idp_with_backend().await;

    // backend 已持旧一代 JWKS 快照 (只含 kid test-key-1); IdP 轮换到新代
    // (kid test-key-rotated, JWKS 只含新代公钥), 新 token 全部用新 key 签.
    idp.rotate_keys();

    let creds = happy_login_attempt(&idp, &backend);
    let user = backend
        .exchange_and_verify(creds)
        .await
        .expect("login should survive JWKS key rotation without restart");
    assert_eq!(user.sub, "user-42");
}

#[tokio::test]
async fn exchange_and_verify_rotation_refresh_failure_returns_original_error() {
    // SEC-AUTH-3 边界 (#198): 签名验证失败 + JWKS 刷新也失败 (IdP discovery 故障,
    // token 端点正常) 时, 必须返回**原始**验签错误 (刷新失败不掩盖真实验签失败,
    // 也不引入新错误类别), 且旧 client 保持可用 — IdP 恢复后的下一次登录 (再次
    // 触发刷新) 能自愈, 无需重启进程.
    let (idp, backend) = spawn_idp_with_backend().await;
    idp.rotate_keys();

    // 第一轮: 轮换后的 token (新 kid) 验签失败 → 触发刷新 → discovery 500 → 刷新失败.
    let creds = happy_login_attempt(&idp, &backend);
    idp.break_discovery();
    let err = backend.exchange_and_verify(creds).await.unwrap_err();
    assert!(
        matches!(err, OidcError::IdTokenVerification(_)),
        "refresh failure must not mask the original verification error, got: {err:?}"
    );

    // 第二轮: IdP 恢复 → 同一进程的下一次登录自愈 (再次触发刷新并成功).
    idp.fix_discovery();
    let creds = happy_login_attempt(&idp, &backend);
    let user = backend
        .exchange_and_verify(creds)
        .await
        .expect("login should self-heal after IdP recovery without restart");
    assert_eq!(user.sub, "user-42");
}

// ─── handlers 端到端测试 (login_start / oauth_callback / logout / me) ───
//
// oauth_callback happy path 在此端到端覆盖 (无需 mocking AuthSession):
// - nonce 虽存 server-side session, 但它经 authorize URL query 传给 IdP — mock IdP
//   的 /authorize 把它记入 AuthorizeRecord, code-绑定的 /token (AuthorizeCode) 再用
//   stored nonce 签 id_token, 全链 nonce round-trip 由此闭合;
// - PKCE verifier 经 token exchange form body 到达 IdP, /token 真实执行
//   S256(verifier) == authorize 记录的 code_challenge 比对 (RFC 7636 §4.6);
// - 测试用禁用 redirect 的 reqwest client + 手动回传 sg.sid cookie 驱动 4 步
//   浏览器 flow (login → authorize → callback → /api/me), 见
//   `oauth_callback_happy_path_full_round_trip` 与 PKCE 负对照
//   `oauth_callback_rejects_pkce_verification_failure`.
// 下方另有各错误路径 (IdP error 参数 / 缺 session 凭证) 与 logout / me 测试.

/// 装配一个 reqwest client, **禁用自动 redirect** (手动跟 redirect 以断言 Location).
///
/// 注: 不用 reqwest 的 `cookie_store` feature (主依赖 reqwest 没开, 加 dev-dep 会
/// 因 feature unification 影响生产构建). 测试若需跨请求共享 session, 手动从
/// Set-Cookie 提取并回传 Cookie header (见 `extract_session_cookie`).
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build http client")
}

/// 从响应的 Set-Cookie 头集合中提取 sg.sid 的完整 cookie 字符串 (用于后续请求回传).
///
/// tower-sessions 写回的 cookie 形如 `sg.sid=...; HttpOnly; SameSite=Lax; Path=/`.
/// 遍历所有 Set-Cookie 头 (middleware 链可能附加其他 cookie 如 CSRF token),
/// 取出 sg.sid 的 pair 部分 (到第一个 `;`), 后续请求作为 `Cookie: sg.sid=...` 回传.
fn extract_session_cookie(resp: &reqwest::Response) -> Option<String> {
    for set_cookie in resp.headers().get_all(header::SET_COOKIE) {
        let Ok(val) = set_cookie.to_str() else {
            continue;
        };
        let cookie_pair = val.split(';').next().unwrap_or("").trim();
        if cookie_pair.starts_with("sg.sid=") {
            return Some(cookie_pair.to_string());
        }
    }
    None
}

#[tokio::test]
async fn login_start_redirects_to_idp_with_pkce_in_session() {
    // 守卫: login_start 必须重定向到 IdP authorize URL, 并通过 Set-Cookie 写回 session
    // (含 PKCE verifier + nonce + state, 这些绝不能放 query string).
    let (idp, base) = spawn_idp_with_client().await;
    let client = http_client();
    let resp = client.get(format!("{base}/login")).send().await.unwrap();

    // 1. 必须 302 redirect 到 IdP.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .expect("Location header")
        .to_str()
        .unwrap();
    assert!(
        location.starts_with(idp.issuer()),
        "should redirect to IdP, got: {location}"
    );
    // authorize URL 必须含 state + scope.
    assert!(location.contains("state="), "state in query: {location}");
    assert!(
        location.contains("scope=openid"),
        "scope in query: {location}"
    );

    // 2. Set-Cookie 必须写回 session id (HttpOnly + name=sg.sid, 见 session.rs).
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie must be present (session was modified)");
    let cookie_str = set_cookie.to_str().unwrap();
    assert!(cookie_str.contains("sg.sid="), "cookie name: {cookie_str}");
    assert!(
        cookie_str.to_ascii_lowercase().contains("httponly"),
        "HttpOnly red line: {cookie_str}"
    );

    // 注: login_start 是 redirect (非 error_response), 不挂 NO_STORE header.
    // NO_STORE 红线只在 error_response 守卫 (见 handlers::tests 的对应测试).
}

#[tokio::test]
async fn login_start_sanitizes_next_url() {
    // SEC-AUTH-2: next 参数必须是站内相对路径, 防 open redirect.
    // 合法 next: 存入 session (后续 callback 重定向用).
    // 非法 next: 清除旧值, 不影响流程.
    let (idp, base) = spawn_idp_with_client().await;
    let client = http_client();

    // 合法 next: 仍正常 redirect 到 IdP (next 已存入 session).
    let resp = client
        .get(format!("{base}/login?next=/api/records"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // 非法 next (//evil.com): 不阻断流程, 仍 redirect 到 IdP (next 被丢弃, 不进 session).
    // 守卫的是 "next 不会被用作 redirect 目标除非合法", 此处验证非法 next 不抛错.
    let resp2 = client
        .get(format!("{base}/login?next=//evil.com"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::SEE_OTHER,
        "illegal next should not abort login flow"
    );
    let loc = resp2
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        loc.starts_with(idp.issuer()),
        "should still go to IdP, got: {loc}"
    );
}

#[tokio::test]
async fn oauth_callback_rejects_idp_error_param() {
    // IdP 在 callback 里返回 error (用户拒绝授权等): 必须返回 401 + JSON envelope.
    let (_idp, base) = spawn_idp_with_client().await;
    let client = http_client();

    // 先 login 一次拿 cookie (建立 session). 提取 Set-Cookie 用于后续 callback 回传.
    let login_resp = client.get(format!("{base}/login")).send().await.unwrap();
    assert_eq!(
        login_resp.status(),
        StatusCode::SEE_OTHER,
        "login should succeed before testing callback"
    );
    let session_cookie =
        extract_session_cookie(&login_resp).expect("login should set sg.sid cookie");

    // 模拟 IdP 回调时带 error 参数 (回传 session cookie 让 handler 能读 session).
    // 注: CallbackQuery 的 code/state 字段必填 (即使 IdP 返回 error 也要传, axum Query
    // 反序列化要求), 故这里随便填 dummy 值 — handler 会先检查 error 字段短路返回 401.
    let resp = client
        .get(format!(
            "{base}/oauth2/callback?code=dummy&state=dummy&error=access_denied&error_description=user+cancelled"
        ))
        .header(header::COOKIE, session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(
        body["error"],
        "OIDC provider error: access_denied (user cancelled)"
    );
}

#[tokio::test]
async fn oauth_callback_rejects_missing_session_credentials() {
    // 不先 login 直接访问 callback: session 缺 PKCE verifier / nonce / state → 400.
    let (_idp, base) = spawn_idp_with_client().await;
    let client = http_client();

    // 不 login, 直接 callback. session 是空的 (无 cookie 回传).
    let resp = client
        .get(format!("{base}/oauth2/callback?code=fake&state=anything"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap();
    let err_msg = body["error"].as_str().unwrap();
    assert!(
        err_msg.contains("missing") && err_msg.contains("session"),
        "should mention missing session, got: {err_msg}"
    );
}

#[tokio::test]
async fn oauth_callback_happy_path_full_round_trip() {
    // FWD-AUTH-3: 完整 OIDC 登录 flow 端到端 — 生产同构装配 (build_router_with_auth)
    // + mock IdP 完整授权端点 (handle_authorize + TokenPolicy::AuthorizeCode).
    // 逐步驱动浏览器 flow (sg.sid cookie 串起 server-side session), 断言每一跳:
    //   1. /login → 303 IdP authorize URL (PKCE challenge + state + nonce 在 query;
    //      verifier 留在 session)
    //   2. IdP /authorize → 302 回 sg callback (code + state echo)
    //   3. /oauth2/callback → server 从 session 取 verifier/nonce → token exchange
    //      (IdP 真实验 PKCE S256 + 用 authorize 时记录的 nonce 签 id_token) →
    //      验签 + nonce 匹配 → 登录成功 303 "/"
    //   4. /api/me → 200 + 已登录用户 claims
    let (idp, base) = spawn_full_auth_router(false).await;
    idp.set_token_policy(TokenPolicy::AuthorizeCode);
    let client = http_client();

    // Step 1: /login — 303 到 IdP authorize URL.
    let resp = client.get(format!("{base}/login")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let authorize_url = resp
        .headers()
        .get(header::LOCATION)
        .expect("Location header")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        authorize_url.starts_with(idp.issuer()),
        "authorize URL should be on IdP: {authorize_url}"
    );
    assert!(
        authorize_url.contains("code_challenge="),
        "PKCE challenge in authorize query: {authorize_url}"
    );
    assert!(
        authorize_url.contains("nonce="),
        "nonce in authorize query: {authorize_url}"
    );
    assert!(
        authorize_url.contains("state="),
        "CSRF state in authorize query: {authorize_url}"
    );
    let mut session_cookie = extract_session_cookie(&resp).expect("login should set sg.sid cookie");

    // Step 2: IdP /authorize — 记录 (nonce, code_challenge, redirect_uri), 302 回
    // sg 的 callback URL (redirect_uri 与 discovery 配置一致 → 指回本 server).
    let resp = client.get(&authorize_url).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let callback_url = resp
        .headers()
        .get(header::LOCATION)
        .expect("Location header")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        callback_url.starts_with(&base),
        "authorize should redirect back to sg callback: {callback_url}"
    );
    assert!(
        callback_url.contains("code=") && callback_url.contains("state="),
        "authorization code + state in callback: {callback_url}"
    );

    // Step 3: /oauth2/callback (带 session cookie) — 登录成功 → 303 到 "/"
    // (next 缺省). 注: axum-login 的 login() 在首次登录时 cycle session id (防
    // session fixation, tower-sessions cycle_id 会删除旧 id 并签发新 sg.sid) —
    // 后续请求必须用新 cookie. 断言 id 确实轮换, 守卫该防护不静默回归.
    let resp = client
        .get(&callback_url)
        .header(header::COOKIE, &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "callback should redirect on success"
    );
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(loc, "/", "callback success should redirect to / (no next)");
    let cycled = extract_session_cookie(&resp)
        .expect("callback should re-set sg.sid (login writes session)");
    assert_ne!(
        cycled, session_cookie,
        "login() must cycle session id (session fixation mitigation)"
    );
    session_cookie = cycled;

    // Step 4: /api/me (轮换后的 cookie) — 200 + 完整用户 claims (sub/email/name
    // 来自 id_token, me handler 的响应 shape).
    let resp = client
        .get(format!("{base}/api/me"))
        .header(header::COOKIE, &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(body["authenticated"], true);
    assert_eq!(body["sub"], "user-42");
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["name"], "Alice");
}

#[tokio::test]
async fn oauth_callback_rejects_pkce_verification_failure() {
    // PKCE 负对照 (FWD-AUTH-3 的反向): IdP 侧记录的 code_challenge 被篡改后,
    // S256(server session 里的 verifier) 必不匹配 → /token 400 → exchange 失败 →
    // callback 500 + 用户未登录. 证明 happy path 里的 PKCE 比对是真实门禁而非摆设.
    let (idp, base) = spawn_full_auth_router(false).await;
    idp.set_token_policy(TokenPolicy::AuthorizeCode);
    let client = http_client();

    // Step 1-2: 与 happy path 相同 — login 拿 session cookie, authorize 拿 code.
    let resp = client.get(format!("{base}/login")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let authorize_url = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let mut session_cookie = extract_session_cookie(&resp).expect("login should set sg.sid cookie");

    let resp = client.get(&authorize_url).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let callback_url = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // 篡改 IdP 侧的 authorize 记录: PKCE 比对基准不再对应 session 里的 verifier.
    idp.tamper_all_code_challenges();

    // Step 3: callback → IdP PKCE 验证失败 (400) → TokenExchange 错误 → 500 envelope.
    let resp = client
        .get(&callback_url)
        .header(header::COOKIE, &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "PKCE failure should surface as 500 (token exchange failed)"
    );
    // 先取 Set-Cookie 再消费 body (bytes() 会 move resp).
    if let Some(refreshed) = extract_session_cookie(&resp) {
        session_cookie = refreshed;
    }
    let body: serde_json::Value = serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap();
    let err = body["error"].as_str().unwrap();
    assert!(
        err.contains("token exchange"),
        "should surface token exchange failure, got: {err}"
    );

    // Step 4: 登录未发生 — /api/me 仍 authenticated=false.
    let resp = client
        .get(format!("{base}/api/me"))
        .header(header::COOKIE, &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(body["authenticated"], false);
}

#[tokio::test]
async fn me_returns_unauthenticated_when_not_logged_in() {
    // 未登录访问 /api/me: 返回 authenticated=false (不报 401, 因为 me 是公开路由).
    let (_idp, base) = spawn_idp_with_client().await;
    let client = http_client();

    let resp = client.get(format!("{base}/api/me")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(body["authenticated"], false);
}

#[tokio::test]
async fn logout_clears_session_and_redirects() {
    // logout handler: 调 auth_session.logout() + redirect 到 /login.
    // 即使未登录, logout 也不报错 (幂等, 调 logout on empty session 是 no-op).
    let (_idp, base) = spawn_idp_with_client().await;
    let client = http_client();

    let resp = client.post(format!("{base}/logout")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(loc, "/login", "logout should redirect to login");
}

// ─── server.rs auth 装配冒烟测试 ─────────────────────────────────────────
//
// 背景: axum 对重复路由注册是**运行期 panic** (matchit insert error), 不是编译期
// 错误. `build_router_with_auth_layers` 把 webui_public (`/login` 等) 与
// `web::router()` (`/`, `/api/*`) merge 到同一 Router, 是重复路由风险最集中的
// 形态 — 例如未来有人在 web::router() 里加 `/api/me` 或 `/login`, 只会在 auth
// 启用的生产启动时 panic, CI (默认走单用户 build_router) 全绿也无法发现.
// 本测试用真实的 server::build_router_with_auth 做装配冒烟, 把该风险挡在 CI.

/// 构造与生产 `serve()` 同构的完整 auth Router 并 spawn 到随机端口.
///
/// 与 `build_test_router` 的差异: 这里走真实的 `server::build_router_with_auth`
/// (含 web::router() + forward 路由 + /api/{*rest} 兜底), 而非仅 OIDC handlers
/// 的迷你装配. AppState 字段全用最小占位值 (冒烟只关心路由装配与认证跳转,
/// 不关心转发逻辑). 双表共享同一 decisions + persist_lock, 与 server.rs 装配一致.
///
/// 先 bind listener 拿到实际 port, 再用该 port 构造 redirect_url 做 discovery —
/// mock IdP /authorize 的 302 因此指回本 server 的真实 callback URL, 测试可原样
/// 跟随 (与生产 redirect_url 形态一致).
async fn spawn_full_auth_router(secure_cookie: bool) -> (MockIdp, String) {
    let idp = spawn_mock_idp().await;

    let api_keys = empty_api_key_store("sg-auth-smoke");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let redirect_url = format!("http://{addr}/oauth2/callback");
    let backend = OidcBackend::discover(idp.issuer(), idp.client_id(), None, &redirect_url)
        .await
        .expect("discover");

    let decisions = std::sync::Arc::new(parking_lot::RwLock::new(
        secret_guard::config::Decisions::default(),
    ));
    let persist_lock = std::sync::Arc::new(parking_lot::Mutex::new(()));
    let state_path =
        std::env::temp_dir().join(format!("sg-auth-smoke-prov-{}.toml", uuid::Uuid::new_v4()));
    let providers = secret_guard::provider::ProviderTable::with_persist_lock(
        vec![],
        vec![],
        decisions.clone(),
        state_path,
        persist_lock.clone(),
    );
    let secrets_state_path =
        std::env::temp_dir().join(format!("sg-auth-smoke-sec-{}.toml", uuid::Uuid::new_v4()));
    let secrets = secret_guard::secrets::SecretTable::with_persist_lock(
        vec![],
        vec![],
        decisions,
        secrets_state_path,
        persist_lock,
    );
    let redact = secret_guard::config::RedactConfig::default();
    let state = secret_guard::state::AppState {
        upstream: reqwest::Client::new(),
        providers,
        dag: secret_guard::dag::ConversationDag::new(8, 8, 1),
        secrets,
        api_keys: api_keys.clone(),
        auth_enabled: true,
        global_mock_prefix: std::sync::Arc::from(""),
        // [redact] 三 gate 镜像生产默认 (SEC-10); 本 harness 不触降级路径.
        on_probe_exhausted: redact.on_probe_exhausted,
        on_unsupported_protocol: redact.on_unsupported_protocol,
        on_fallback_restore: redact.on_fallback_restore,
        // SEC-4: 镜像生产装配 (normalize 后入 state); 本 harness 无自定义名单.
        redacted_headers: secret_guard::state::normalize_redacted_headers(&redact.redacted_headers),
        upstream_timeouts: secret_guard::config::UpstreamTimeouts::default(),
        model_lists: std::sync::Arc::new(secret_guard::proxy::ModelListCache::new()),
        usage: std::sync::Arc::new(secret_guard::usage::UsageStore::in_memory()),
        pricing: std::sync::Arc::new(secret_guard::usage::PricingCache::for_tests()),
    };

    // 与生产 serve() 同构: 先 bind listener 拿到实际 port, 再用该 port 构造
    // Host guard (SEC-7) 装配 Router.
    let app = secret_guard::server::build_router_with_auth(
        state,
        secret_guard::server::AuthStack {
            backend,
            api_keys,
            secure_cookie, // 由调用方决定 — false: HTTP 测试; true: 接线 e2e
        },
        secret_guard::server_host_guard::HostGuard::new("127.0.0.1", addr.port()),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (idp, format!("http://{addr}"))
}

#[tokio::test]
async fn full_auth_router_assembly_smoke() {
    // 冒烟: 真实 auth 装配 (build_router_with_auth) 不 panic + 关键路由行为正确.
    // 1. 装配本身不 panic (重复路由会在 serve/bind 时 panic, 这里直接暴露).
    let (_idp, base) = spawn_full_auth_router(false).await;
    let client = http_client();

    // 2. 未登录访问受保护 `/` → 307 到 /login (login_required guard 生效;
    //    axum-login 的 guard 用 Redirect::temporary = 307).
    let resp = client.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        loc.starts_with("/login"),
        "guard should redirect to /login, got {loc}"
    );

    // 3. 未登录访问受保护 `/api/sync` → 同样 307 (web::router() 全量在 guard 内).
    let resp = client
        .post(format!("{base}/api/sync"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

    // 4. 公开路由 `/api/me` 不被 guard 拦截 (返回 200 + authenticated:false,
    //    而非 307) — 守卫 webui_public 与 webui_protected 的分界.
    let resp = client.get(format!("{base}/api/me")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn full_auth_router_secure_cookie_wiring_e2e() {
    // [auth] secure_cookie 接线端到端: AuthConfig.secure_cookie → AuthStack →
    // build_session_layer(secure) 的这条 wire 若在未来重构中断裂 (如 AuthStack
    // 丢字段), 配置会静默失效 — 本测试用 secure_cookie=true 的生产同构装配
    // 断言 /login 的 Set-Cookie 携带 Secure 属性, 锁定接线不静默回归.
    let (_idp, base) = spawn_full_auth_router(true).await;
    let client = http_client();

    let resp = client.get(format!("{base}/login")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie must be present after session modification")
        .to_str()
        .unwrap();
    assert!(set_cookie.contains("sg.sid="), "cookie name: {set_cookie}");
    // 属性断言按 ";" 切分跳过 name=value 段后精确比对 (与 session.rs 单测的
    // cookie_attrs 同尺子) — 朴素 contains 会误匹配随机 session id 值的子串.
    let attrs: Vec<String> = set_cookie
        .split(';')
        .skip(1)
        .map(|a| a.trim().to_ascii_lowercase())
        .collect();
    assert!(
        attrs.iter().any(|a| a == "secure"),
        "secure_cookie=true must set Secure flag, got: {set_cookie}"
    );
    assert!(
        attrs.iter().any(|a| a == "httponly"),
        "HttpOnly red line independent of secure_cookie, got: {set_cookie}"
    );
}
