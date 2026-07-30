//! Provider 鉴权注入 (`apply_provider_auth`).
//!
//! # 职责边界
//!
//! 把 provider 配置的 api_key 注入对应协议的 auth header. 与 codec / redact 正交
//! (只动 header, 不动 body). 被 same_proto / cross_proto 共用.
//!
//! # 协议约定 (尊重各 provider 官方 SDK 的默认 header)
//!
//! - OpenAI / Ollama: `Authorization: Bearer <key>` (OpenAI 标准; Ollama 1.17+ 也支持).
//! - Anthropic: `x-api-key: <key>`.
//! - Gemini: `x-goog-api-key: <key>` (Google API 官方约定; 不用 Bearer 避免与 OAuth 流程混淆).
//!
//! provider 的 api_key 覆盖客户端自带 header — provider 配置优先. 同步剥离客户端
//! 可能误传的竞争 header (如用 OpenAI ingress 时清除 `x-api-key`, 防止上游误识别).

use axum::http::{HeaderMap, HeaderValue};
use tracing::warn;

use crate::provider::Protocol;

/// 若 provider 配置了 api_key, 注入对应的 auth header.
///
/// 空 key (含纯空白) 跳过注入 (保留客户端原有 header). 非法 HTTP header 字符的 key
/// 记 warn 让运维注意到, 不插入 header 让上游自行拒绝 (永不 panic, 永不阻塞转发).
pub(super) fn apply_provider_auth(headers: &mut HeaderMap, api_key: &str, ingress: Protocol) {
    let key = api_key.trim();
    if key.is_empty() {
        return;
    }
    // 目标 header 名 + 客户端可能误传的竞争 header 名 (统一剥离) + value 构造.
    // OpenAI/Ollama 用 `Bearer <key>` 格式; Anthropic/Gemini 用裸 key.
    let (target, competitors, value_str): (&'static str, &[&'static str], String) = match ingress {
        Protocol::OpenAI | Protocol::Ollama => (
            "authorization",
            &["x-api-key", "x-goog-api-key"][..],
            format!("Bearer {key}"),
        ),
        Protocol::Anthropic => (
            "x-api-key",
            &["authorization", "x-goog-api-key"][..],
            key.to_string(),
        ),
        Protocol::Gemini => (
            "x-goog-api-key",
            &["authorization", "x-api-key"][..],
            key.to_string(),
        ),
    };
    for c in competitors {
        headers.remove(*c);
    }
    match HeaderValue::from_str(&value_str) {
        Ok(v) => {
            headers.insert(target, v);
        }
        Err(e) => {
            // api_key 含非法 HTTP header 字符 (控制字符 / 非 ASCII 等).
            // 这通常是配置错误, 记 warn 让运维注意到; 不插入 header 让上游自行拒绝.
            warn!(
                error = %e,
                target,
                "provider api_key contains illegal header chars; skipping auth injection"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_provider_auth_openai_uses_bearer() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer client-token".parse().unwrap());
        apply_provider_auth(&mut h, "sk-server-side", Protocol::OpenAI);
        assert_eq!(h.get("authorization").unwrap(), "Bearer sk-server-side");
    }

    #[test]
    fn apply_provider_auth_anthropic_uses_x_api_key() {
        let mut h = HeaderMap::new();
        h.insert("x-api-key", "client-key".parse().unwrap());
        apply_provider_auth(&mut h, "sk-ant-server", Protocol::Anthropic);
        assert_eq!(h.get("x-api-key").unwrap(), "sk-ant-server");
    }

    #[test]
    fn apply_provider_auth_gemini_uses_x_goog_api_key() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer client-tok".parse().unwrap());
        apply_provider_auth(&mut h, "ya29.server", Protocol::Gemini);
        // Gemini 用 x-goog-api-key, 不用 Authorization Bearer.
        assert_eq!(h.get("x-goog-api-key").unwrap(), "ya29.server");
        assert!(
            h.get("authorization").is_none(),
            "must clear competing header"
        );
    }

    #[test]
    fn apply_provider_auth_strips_competing_headers() {
        // 客户端误传了竞争对手协议的 header, 应被剥离.
        let mut h = HeaderMap::new();
        h.insert("x-api-key", "client-anthropic".parse().unwrap());
        h.insert("x-goog-api-key", "client-gemini".parse().unwrap());
        apply_provider_auth(&mut h, "sk-server", Protocol::OpenAI);
        assert_eq!(h.get("authorization").unwrap(), "Bearer sk-server");
        assert!(h.get("x-api-key").is_none());
        assert!(h.get("x-goog-api-key").is_none());
    }

    #[test]
    fn apply_provider_auth_skips_empty_key() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer keep-me".parse().unwrap());
        apply_provider_auth(&mut h, "   ", Protocol::OpenAI);
        assert_eq!(h.get("authorization").unwrap(), "Bearer keep-me");
    }
}
