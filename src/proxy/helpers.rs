//! HTTP header / URL / 字符串处理工具 (转发链共享, 无业务语义).
//!
//! # 职责边界
//!
//! 纯函数工具集: hop-by-hop header 过滤、上游 URL 拼接、content-type 流式判定、
//! 字节→字符串的 lossy 投影、敏感 header 脱敏. 这些函数无状态、无副作用,
//! 被 same_proto / cross_proto / fan_out 等转发子模块共用.
//!
//! # 归属判断
//!
//! 历史上内联在单文件 `proxy.rs` 的 `// ─── Helpers ───` 段. 拆分为模块目录后
//! 抽到独立文件, 让转发主路径 (same_proto / cross_proto) 聚焦于协议语义.

use axum::http::HeaderMap;

/// hop-by-hop 或在反代语义下不应原样转发的 header (RFC 7230 §6.1 + 反代常识).
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

/// 拼接上游 URL: base 去尾斜杠 + path_and_query (后者需含前导 `/`).
pub(super) fn build_upstream_url(base: &str, path_and_query: &str) -> String {
    let base = base.trim_end_matches('/');
    if path_and_query.starts_with('/') {
        format!("{base}{path_and_query}")
    } else {
        format!("{base}/{path_and_query}")
    }
}

/// 是否在 `Connection` header 列表中? (RFC 7230 §6.1: 这些也是 hop-by-hop.)
fn connection_listed(name: &str, src: &HeaderMap) -> bool {
    let target = name.to_lowercase();
    src.get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case(&target)))
        .unwrap_or(false)
}

fn is_hop_by_hop(name: &str) -> bool {
    let lower = name.to_lowercase();
    HOP_BY_HOP.iter().any(|h| *h == lower)
}

/// 请求 header 清洗: 剥离 hop-by-hop / Connection-listed / host / content-length.
pub(super) fn sanitize_request_headers(src: &HeaderMap) -> HeaderMap {
    filter_headers(src, |name| {
        is_hop_by_hop(name)
            || connection_listed(name, src)
            || matches!(name, "host" | "content-length")
    })
}

/// 响应 header 清洗: 剥离 hop-by-hop / Connection-listed / content-length
/// (content-length 由新 body 决定, 旧值无效).
pub(super) fn build_response_headers(src: &HeaderMap) -> HeaderMap {
    filter_headers(src, |name| {
        is_hop_by_hop(name) || connection_listed(name, src) || name == "content-length"
    })
}

fn filter_headers(src: &HeaderMap, drop_fn: impl Fn(&str) -> bool) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(src.len());
    for (name, value) in src.iter() {
        let name_str = name.as_str().to_lowercase();
        if drop_fn(&name_str) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// content-type 是否表示流式响应 (SSE / NDJSON)?
pub(super) fn is_streaming(content_type: &str) -> bool {
    let ct = content_type.split(';').next().unwrap_or("").trim();
    ct.eq_ignore_ascii_case("text/event-stream") || ct.eq_ignore_ascii_case("application/x-ndjson")
}

/// 把字节投影为 String (非法 UTF-8 用 U+FFFD 替换, 不失败).
pub(super) fn utf8_view(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// 敏感 header 脱敏 (仅用于记录存储, 不影响转发).
///
/// 返回 `(lowercase_name, value_or_redacted)` 列表. 敏感 header 的 value 替换为
/// `<redacted>`, 非法 ASCII value 替换为 `<binary>`, 其余原样保留.
///
/// # 名单边界 (用户自定义 auth header)
///
/// 脱敏名单是**硬编码黑名单** (见 [`is_sensitive_header`]): 主流 LLM provider 的
/// 标准 auth header (**显式枚举, 非 glob 前缀匹配**) 加上含 `token` /
/// `secret` 子串的关键词匹配. 完整名单以 [`is_sensitive_header`] 为 SSOT.
///
/// **未在名单内的 header 会原样记录到 WebUI DAG record**. 用户若使用自定义 auth header
/// (如 `x-my-service-key`), 需在 [`is_sensitive_header`] 追加 (后续工作: 暴露为
/// `[redact] redacted_headers` 配置项; 当前硬编码, 见 AGENTS.md "已知限制").
pub(super) fn redact_headers(src: &HeaderMap) -> Vec<(String, String)> {
    src.iter()
        .map(|(name, value)| {
            let name_str = name.as_str().to_lowercase();
            let v = if is_sensitive_header(&name_str) {
                "<redacted>".to_string()
            } else {
                value.to_str().unwrap_or("<binary>").to_string()
            };
            (name_str, v)
        })
        .collect()
}

/// 判断 header 是否敏感: 黑名单关键词匹配 (覆盖各 LLM provider 常见字段).
///
/// "key" 关键词不纳入匹配 (过于宽泛会误伤 `x-request-key-hash` 等正常 header).
/// 已知 key 类敏感 header (`api-key` / `x-api-key` / `x-goog-api-key` /
/// `x-anthropic-api-key`) 由显式黑名单覆盖.
fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "x-api-key"
            | "api-key"
            | "x-anthropic-api-key"
            | "openai-organization"
            | "openai-project"
            | "x-goog-api-key"
            | "x-amz-security-token"
            | "cookie"
            | "set-cookie"
            | "proxy-authorization"
    ) || name.contains("token")
        || name.contains("secret")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderName;

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
    fn build_upstream_url_handles_empty_rest() {
        // 路径只到 /{proto}/{name} 时 rest = "/".
        assert_eq!(
            build_upstream_url("https://api.example.com", "/?q=1"),
            "https://api.example.com/?q=1"
        );
    }

    #[test]
    fn sanitize_strips_hop_by_hop_and_host() {
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
    fn sanitize_strips_connection_listed_custom_headers() {
        let mut src = HeaderMap::new();
        src.insert("connection", "x-custom, foo".parse().unwrap());
        src.insert("x-custom", "leak".parse().unwrap());
        src.insert("foo", "bar".parse().unwrap());
        src.insert("baz", "kept".parse().unwrap());
        let out = sanitize_request_headers(&src);
        assert!(
            out.get("x-custom").is_none(),
            "Connection-listed header must be stripped"
        );
        assert!(out.get("foo").is_none());
        assert_eq!(out.get("baz").unwrap(), "kept");
    }

    #[test]
    fn redact_headers_masks_secrets() {
        let mut src = HeaderMap::new();
        src.insert("authorization", "Bearer xxx".parse().unwrap());
        src.insert("x-api-key", "key".parse().unwrap());
        src.insert("x-goog-api-key", "gkey".parse().unwrap());
        src.insert("x-custom-token", "tok".parse().unwrap());
        src.insert("x-custom", "value".parse().unwrap());
        let v = redact_headers(&src);
        let m: std::collections::HashMap<_, _> = v.into_iter().collect();
        assert_eq!(m.get("authorization").unwrap(), "<redacted>");
        assert_eq!(m.get("x-api-key").unwrap(), "<redacted>");
        assert_eq!(m.get("x-goog-api-key").unwrap(), "<redacted>");
        assert_eq!(m.get("x-custom-token").unwrap(), "<redacted>");
        assert_eq!(m.get("x-custom").unwrap(), "value");
    }

    #[test]
    fn is_streaming_detects_sse_strictly() {
        assert!(is_streaming("text/event-stream"));
        assert!(is_streaming("text/event-stream; charset=utf-8"));
        assert!(is_streaming("application/x-ndjson"));
        assert!(!is_streaming("application/json"));
        assert!(!is_streaming("application/octet-stream"));
        assert!(!is_streaming("video/xyz-stream"));
    }

    #[test]
    fn utf8_view_handles_invalid_utf8() {
        let bad = &[0xFF, 0xFE, 0x00];
        let s = utf8_view(bad);
        assert!(s.contains('\u{FFFD}'));
    }

    // ─── SEC-4: 含关键词的 header 必须被脱敏 ─────────────────────────────
    //
    // 契约 (docs/design/contracts.md §7 SEC-4): record 存储的 HTTP headers 中,
    // 含 "token" / "secret" 关键词的自定义 header 必须被脱敏为 `<redacted>`.
    //
    // "key" 关键词不纳入匹配 (契约 §7 SEC-4 注): 过于宽泛会误伤 `x-request-key-hash`
    // 等正常 header. 已知 key 类敏感 header (`api-key` / `x-api-key` / `x-goog-api-key` /
    // `x-anthropic-api-key`) 由显式黑名单覆盖 (见 is_sensitive_header).

    use proptest::prelude::*;

    proptest! {
        /// SEC-4: 任意含 "token" / "secret" 关键词的 header 名, redact_headers 输出值为
        /// `<redacted>`.
        ///
        /// `is_sensitive_header` 用 `name.contains("token") || name.contains("secret")`
        /// 做关键词匹配 (case-insensitive, 因为 redact_headers 在调用前会 to_lowercase).
        /// 本 property 随机化 prefix / suffix / keyword 三个维度, 覆盖任意位置含关键词
        /// 的自定义 header (如 `x-my-token`, `token-foo`, `x-secret-bar`).
        ///
        /// "key" 关键词不在匹配范围 (契约 §7 SEC-4 注: 过宽误伤正常 header), 已知 key
        /// 类敏感 header 由显式黑名单覆盖 (见 mod 级注释).
        ///
        /// 字符集 [a-z0-9-]: HTTP header name 合法字符 (token 字符), 且避免大写干扰
        /// contains 匹配 (redact_headers 已 lowercase, 但 prop 中我们也用 lowercase
        /// 生成, 保证一致性).
        #[test]
        fn prop_custom_token_headers_redacted(
            prefix in "[a-z]{0,8}",
            keyword in prop::sample::select(vec!["token", "secret"]),
            suffix in "[a-z0-9-]{0,8}",
            value in "[A-Za-z0-9]{1,32}"
        ) {
            let header_name = format!("{prefix}{keyword}{suffix}");
            let mut src = HeaderMap::new();
            src.insert(
                HeaderName::from_bytes(header_name.as_bytes())
                    .expect("header name bytes must be valid"),
                value.parse().expect("value must be valid HeaderValue"),
            );
            let redacted = redact_headers(&src);
            prop_assert_eq!(redacted.len(), 1, "exactly one header expected");
            // redact_headers 把 name to_lowercase, value 替换为 <redacted> (若是敏感 header).
            prop_assert_eq!(
                &redacted[0].1, "<redacted>",
                "SEC-4 violation: header '{}' contains keyword '{}' but was not redacted",
                header_name, keyword
            );
        }
    }
}
