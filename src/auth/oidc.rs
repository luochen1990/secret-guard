//! OIDC 认证后端: 桥接 openidconnect::CoreClient + axum-login.
//!
//! # 流程
//!
//! 1. `/login`: 生成 PKCE challenge + verifier + nonce + CSRF state, 存 server-side
//!    session, redirect 到 IdP authorize URL.
//! 2. IdP 回调 `/oauth2/callback?code=X&state=Y`: 从 session 取 verifier + nonce,
//!    exchange code → token, 验证 ID token (签名 + nonce), 提取 sub/email/name.
//! 3. axum-login 的 `auth_session.login(&user)` 把 User 存入 session.
//! 4. 后续请求: axum-login middleware 从 session 恢复 User, 注入 AuthSession extractor.
//!
//! # 关键不变式
//!
//! - PKCE verifier + nonce **必须存服务端 session**, 绝不放 cookie (安全红线).
//! - ID token 必须验证签名 (JWKS) + nonce (防重放).
//! - CoreClient 在启动时通过 OIDC Discovery 初始化, 进程内共享 (Clone, 内部 Arc).
//!
//! # 类型状态 (typestate)
//!
//! `from_provider_metadata().set_redirect_uri()` 返回的 CoreClient 带 typestate:
//! `HasAuthUrl = EndpointSet`, `HasTokenUrl = EndpointMaybeSet` (token URL 来自 discovery,
//! 可能缺失). 为避免把完整泛型签名写到字段类型里, 本模块用 `OidcClient` 类型别名固定.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use axum_login::{AuthUser, AuthnBackend, UserId};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointSet, IssuerUrl,
    Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// 类型别名: from_provider_metadata + set_token_uri + set_redirect_uri 后的 CoreClient.
///
/// 显式设置 token_uri 让 HasTokenUrl = EndpointSet (所有 IdP 都有 token endpoint).
/// 这样 exchange_code 在编译期保证可用.
type OidcClient = CoreClient<
    EndpointSet,                   // HasAuthUrl
    openidconnect::EndpointNotSet, // HasDeviceAuthUrl
    openidconnect::EndpointNotSet, // HasIntrospectionUrl
    openidconnect::EndpointNotSet, // HasRevocationUrl
    EndpointSet,                   // HasTokenUrl
    EndpointMaybeSet,              // HasUserInfoUrl
>;

/// OIDC 用户身份 (存入 session, 序列化为 JSON).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    /// OIDC subject (唯一标识). M1 中也作为 tenant_id.
    pub sub: String,
    /// email (需 IdP 返回 email scope).
    pub email: Option<String>,
    /// 显示名.
    pub name: Option<String>,
    /// session_auth_hash 的种子 (sub 的字节), 用于 session 完整性校验.
    auth_hash: Vec<u8>,
}

impl AuthUser for User {
    type Id = String;

    fn id(&self) -> Self::Id {
        self.sub.clone()
    }

    fn session_auth_hash(&self) -> &[u8] {
        &self.auth_hash
    }
}

impl User {
    fn from_claims(sub: &str, email: Option<&str>, name: Option<&str>) -> Self {
        Self {
            sub: sub.to_string(),
            email: email.map(|s| s.to_string()),
            name: name.map(|s| s.to_string()),
            auth_hash: sub.as_bytes().to_vec(),
        }
    }
}

/// OIDC 认证后端 (实现 axum-login 的 AuthnBackend trait).
///
/// 持有 CoreClient + 内存用户缓存 (sub → User).
/// 用户缓存在 authenticate 成功时写入, 供 get_user 在后续请求中恢复完整 User
/// (含 email/name). 进程重启后缓存清空, 但 session 也同步失效, 用户需重登.
#[derive(Clone)]
pub struct OidcBackend {
    client: OidcClient,
    http_client: reqwest::Client,
    /// 内存用户缓存: OIDC sub → User (含 email/name).
    users: Arc<RwLock<HashMap<String, User>>>,
}

/// 登录时从 session 取出的临时凭证 (PKCE + nonce + CSRF state).
#[derive(Clone, Deserialize)]
pub struct OidcCredentials {
    /// IdP 返回的 authorization code.
    pub code: String,
    /// PKCE verifier (login 时生成的 secret).
    pub pkce_verifier: String,
    /// Nonce (login 时生成, 用于 ID token 验证).
    pub nonce: String,
    /// login 时存的 CSRF state.
    pub old_state: String,
    /// callback query 中的 state.
    pub new_state: String,
}

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("CSRF state mismatch")]
    CsrfMismatch,
    #[error("missing ID token in token response")]
    NoIdToken,
    #[error("OIDC token exchange failed: {0}")]
    TokenExchange(String),
    #[error("ID token verification failed: {0}")]
    IdTokenVerification(String),
}

impl std::fmt::Debug for OidcBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcBackend").finish_non_exhaustive()
    }
}

/// login 时生成的授权 URL + 需要存入 session 的 verifier/nonce/state.
pub struct AuthUrlParts {
    /// 重定向到 IdP 的 URL.
    pub auth_url: openidconnect::url::Url,
    /// PKCE verifier (secret, 必须存 server-side session).
    pub pkce_verifier: String,
    /// Nonce (必须存 server-side session).
    pub nonce: String,
    /// CSRF state token.
    pub csrf_state: String,
}

impl OidcBackend {
    /// 通过 OIDC Discovery 初始化 CoreClient.
    ///
    /// 启动时调用一次 (异步). 失败则 fail-fast (返回 Err).
    pub async fn discover(
        issuer_url: &str,
        client_id: &str,
        client_secret: Option<String>,
        redirect_url: &str,
    ) -> Result<Self, String> {
        let issuer = IssuerUrl::new(issuer_url.to_string())
            .map_err(|e| format!("invalid issuer_url '{issuer_url}': {e}"))?;
        let redirect = RedirectUrl::new(redirect_url.to_string())
            .map_err(|e| format!("invalid redirect_url '{redirect_url}': {e}"))?;

        // HTTP client: 禁止 redirect 防 SSRF (openidconnect 官方建议).
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("build OIDC http client: {e}"))?;

        let metadata = CoreProviderMetadata::discover_async(issuer, &http_client)
            .await
            .map_err(|e| format!("OIDC discovery failed for '{issuer_url}': {e}"))?;

        // 显式提取 token endpoint 并 set_token_uri, 让 typestate 变为 EndpointSet
        // (保证 exchange_code 编译期可用).
        let token_endpoint = metadata
            .token_endpoint()
            .cloned()
            .ok_or_else(|| format!("OIDC discovery '{issuer_url}': no token_endpoint found"))?;

        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(client_id.to_string()),
            client_secret.map(ClientSecret::new),
        )
        .set_token_uri(token_endpoint)
        .set_redirect_uri(redirect);

        Ok(Self {
            client,
            http_client,
            users: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// 生成授权 URL + PKCE verifier + nonce + CSRF state.
    /// 返回的 verifier/nonce/state 必须由调用方存入 server-side session.
    pub fn authorize_url(&self) -> AuthUrlParts {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (auth_url, csrf_state, nonce) = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        AuthUrlParts {
            auth_url,
            pkce_verifier: pkce_verifier.secret().clone(),
            nonce: nonce.secret().clone(),
            csrf_state: csrf_state.secret().clone(),
        }
    }

    /// 从 IdP callback 交换 token 并验证 ID token, 返回 User.
    ///
    /// 步骤:
    /// 1. CSRF 校验 (old_state == new_state).
    /// 2. exchange code + PKCE verifier → token response (async).
    /// 3. 验证 ID token 签名 + nonce.
    /// 4. 提取 sub/email/name → User.
    pub async fn exchange_and_verify(&self, creds: OidcCredentials) -> Result<User, OidcError> {
        // 1. CSRF 校验.
        if creds.old_state != creds.new_state {
            return Err(OidcError::CsrfMismatch);
        }

        // 2. exchange code + PKCE verifier → token (async, 不阻塞 tokio worker).
        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(creds.code))
            .set_pkce_verifier(PkceCodeVerifier::new(creds.pkce_verifier))
            .request_async(&self.http_client)
            .await
            .map_err(|e| OidcError::TokenExchange(e.to_string()))?;

        // 3. 验证 ID token + nonce.
        let id_token = token_response.id_token().ok_or(OidcError::NoIdToken)?;
        let claims = id_token
            .claims(&self.client.id_token_verifier(), &Nonce::new(creds.nonce))
            .map_err(|e| OidcError::IdTokenVerification(e.to_string()))?;

        // 4. 提取 user 信息 + 缓存 (供 get_user 恢复完整 User).
        let user = User::from_claims(
            claims.subject().as_str(),
            claims.email().map(|e| e.as_str()),
            claims.name().and_then(|n| n.get(None)).map(|n| n.as_str()),
        );
        self.users.write().insert(user.sub.clone(), user.clone());
        Ok(user)
    }
}

impl AuthnBackend for OidcBackend {
    type User = User;
    type Credentials = OidcCredentials;
    type Error = OidcError;

    fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send {
        let fut = self.exchange_and_verify(creds);
        async move { fut.await.map(Some) }
    }

    fn get_user(
        &self,
        user_id: &UserId<Self>,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send {
        // 从内存缓存恢复完整 User (含 email/name).
        // 缓存未命中 (进程重启后) 返回 None → session 自动失效 → 用户重登.
        let user = self.users.read().get(user_id).cloned();
        async move { Ok(user) }
    }
}

/// 构造 axum-login 的 Backend type alias (供 router 装配用).
pub type AuthSession = axum_login::AuthSession<OidcBackend>;
