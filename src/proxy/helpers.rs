//! HTTP header / URL / 字符串处理工具 + 转发链共享的轻量语义判定点.
//!
//! # 职责边界
//!
//! 两类内容, 均无状态、无副作用, 被 same_proto / cross_proto / fan_out 等转发
//! 子模块共用:
//! - 纯工具: hop-by-hop header 过滤、上游 URL 拼接、content-type 流式判定、
//!   字节→字符串的 lossy 投影、敏感 header 脱敏 (SEC-4).
//! - 转发链语义判定/编排点 (字节级 body 顶层字段扫描, 不建 IR): `requests_stream`
//!   (FWD-4 流式档位判定)、`request_model` (路由规则匹配输入)、
//!   `usage_ctx_and_record_redactions` + `auth_label` (USAGE-7 采集上下文构造 +
//!   redact 审计落账).
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
///
/// 前置条件: `name` 已小写 (由 [`filter_headers`] 统一归一后传入). 比较端
/// `eq_ignore_ascii_case` 本就大小写不敏感, 无需预先 `to_lowercase`.
fn connection_listed(name: &str, src: &HeaderMap) -> bool {
    src.get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case(name)))
        .unwrap_or(false)
}

/// 前置条件: `name` 已小写 (由 [`filter_headers`] 统一归一后传入),
/// 与全小写的 `HOP_BY_HOP` 直接比较, 无需 `to_lowercase` 再分配.
/// debug_assert 把前置条件变为可执行契约 (混合大小写输入会静默失配).
fn is_hop_by_hop(name: &str) -> bool {
    debug_assert!(!name.chars().any(|c| c.is_ascii_uppercase()));
    HOP_BY_HOP.contains(&name)
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

/// content-type 是否表示流式响应 (SSE / NDJSON)? 子集关系以代码表达:
/// `is_streaming ≡ is_sse ∨ ndjson` — 两判型不会各自漂移.
pub(super) fn is_streaming(content_type: &str) -> bool {
    is_sse(content_type) || media_type(content_type).eq_ignore_ascii_case("application/x-ndjson")
}

/// content-type 是否为 SSE (text/event-stream)? 比 [`is_streaming`] 更窄 —
/// StreamTranslate 管道只会重组 SSE 帧 (空行分帧), ndjson 进翻译会产出空流,
/// 流式翻译分支的判型用本函数.
pub(super) fn is_sse(content_type: &str) -> bool {
    media_type(content_type).eq_ignore_ascii_case("text/event-stream")
}

/// 剥离 content-type 的参数 (`; charset=...`) 取裸 media type (小写比较由调用方做).
fn media_type(content_type: &str) -> &str {
    content_type.split(';').next().unwrap_or("").trim()
}

/// 从响应 headers 提取 content-type (缺失 / 非法 UTF-8 → 空串, 调用方判型自然落
/// 非流式分支). same_proto / cross_proto 判型处的共享入口.
pub(super) fn response_content_type(headers: &HeaderMap) -> &str {
    headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// 提取 JSON body **顶层** 指定 key 的值 (`requests_stream` / `request_model` 的
/// 共用机制层).
///
/// # 实现 (流式解析 + ROB-1 永不 panic)
///
/// 用 `serde_json::Deserializer::from_slice(...).deserialize_map` 流式逐 key 扫描:
/// 命中 key 取 `T` 值, 其余 value 全部用 `IgnoredAny` 流式跳过 (不构建 Value 树 —
/// 大上下文 body 可达 16 MiB, 全量 `Value` 解析在转发热路径上是纯浪费; 真正需要
/// IR 的路径由 codec reader 解析, 不经过本函数).
///
/// serde 约束 (两个旧 visitor 各写一遍, 收口于此): **找到目标 key 后不提前
/// return**, 继续把剩余 key 消费完 — serde_json 要求 MapAccess 驱动到输入耗尽,
/// 提前 return 会被判为 "trailing comma" 错误 (实测, 见 tests).
///
/// 降级语义 (调用方各自包装): 重复 key 后者覆盖 (与 serde_json Value 的 dup-key
/// 行为一致); 值类型不符 `T` / 非 JSON / 顶层非 object / 截断 body → serde error
/// → `None`.
fn top_level_field<T: serde::de::DeserializeOwned>(body: &[u8], key: &str) -> Option<T> {
    use serde::de::IgnoredAny;
    // MapAccess visitor: 顶层逐 key 扫描, 命中 key 取 T 值, 其余跳过.
    // 顶层非 object 时 serde 直接走 error 路径 (→ None).
    struct TopKeysVisitor<'a, T> {
        key: &'a str,
        marker: std::marker::PhantomData<T>,
    }
    impl<'de, T: serde::de::DeserializeOwned> serde::de::Visitor<'de> for TopKeysVisitor<'_, T> {
        type Value = Option<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut hit = None;
            while let Some(k) = map.next_key::<std::borrow::Cow<'_, str>>()? {
                if k == self.key {
                    // 重复 key: 后者覆盖; 类型不符 → error → 整体 None.
                    hit = Some(map.next_value::<T>()?);
                } else {
                    let _ = map.next_value::<IgnoredAny>()?; // 跳过 (流式, 不入树)
                }
            }
            Ok(hit)
        }
    }
    use serde::Deserializer as _;
    let mut de = serde_json::Deserializer::from_slice(body);
    de.deserialize_map(TopKeysVisitor {
        key,
        marker: std::marker::PhantomData,
    })
    .unwrap_or(None)
}

/// 检测请求 body 是否为显式流式请求 (顶层 `"stream": true`, FWD-4 契约).
///
/// # 语义 (保守判定, #175)
///
/// 只把**显式 `stream: true`** 认作流式; 其余一律按非流式处理:
/// - 缺 `stream` 字段: OpenAI / Anthropic / Responses 均默认非流式 — 按非流式.
/// - `stream: false` / 非布尔 (字符串 "true" 等不合规写法): 按非流式.
/// - 非 JSON body / 顶层非对象 (GET 类空 body 等): 按非流式.
/// - `stream` 不是第一个字段: 字段顺序无关, 顶层任意位置的 `stream` 都识别.
///
/// # 已知盲区 (假设声明, ROB-*)
///
/// 本函数只看 body, 对 Gemini (`alt=sse` query param 触发流式, body 无 stream
/// 字段) 和 Ollama (`/api/chat` 缺字段默认流式) 的真实流式请求会误判为非流式 →
/// 落非流式档. 方向保守 (见下节 rationale, 只是 hang 检测变慢, 不误杀), 可接受;
/// 这两条 passthrough 协议无 codec IR, 没有更精确的信号源.
///
/// # 为什么保守方向是"缺省算非流式"
///
/// 超时选错档的两种代价不对称: 非流式大上下文请求 (响应头要等整个响应生成完,
/// 74k token 可轻松超 60s) 被流式短超时误杀 = **合法请求结构性失败** (#175 事故);
/// 反方向 (流式请求吃到非流式长超时) 只是 hang 的流式请求晚一点超时 (且仍有
/// `stream_idle` 超时兜底). 故缺字段 / 解析失败一律落到非流式长超时档.
///
/// # 与 codec reader 的等价性 (语义 SSOT)
///
/// "显式顶层布尔 true 才算流式" 这一语义有两处实现: 本函数 (passthrough 路径,
/// 字节级扫描) 与 codec reader 的 `stream` 解析 (IR 路径, `obj.get("stream")
/// .and_then(as_bool).unwrap_or(false)`). 两者必须保持语义等价 — 本函数的单测
/// 与 reader 行为对齐 (非布尔 / 缺字段均非流式).
///
/// # 实现 (委托 [`top_level_field`])
///
/// 字节级流式扫描的机制细节 (IgnoredAny 跳过 / 不提前 return / 降级路径) 见
/// [`top_level_field`] doc; 本函数只包装降级默认值 (`None` / 非显式 true →
/// 非流式, best-effort, 见 ROB-* 契约).
pub(super) fn requests_stream(body: &[u8]) -> bool {
    top_level_field::<bool>(body, "stream") == Some(true)
}

/// 提取请求 body **顶层** `model` 字段 (string) — 路由规则的匹配输入
/// (`resolve_route` 的 request_model 来源).
///
/// # 语义 (best-effort, ROB-1 永不 panic)
///
/// - 只扫**顶层** key: `messages` 等嵌套结构里的 model 字段**不误取** (value 用
///   `IgnoredAny` 流式跳过, 不下降);
/// - 非 JSON / 顶层非 object / 无 model 字段 / model 非 string / 空 body (GET) →
///   空串 `""` (调用方语义: 空 model 只匹配 `"*"` 类 pattern);
/// - 字段顺序无关 (顶层任意位置).
///
/// # 实现 (委托 [`top_level_field`])
///
/// 字节级流式扫描的机制细节 (IgnoredAny 跳过 / 不提前 return / 降级路径) 见
/// [`top_level_field`] doc; 本函数只包装降级默认值 (`None` → `""`).
pub(super) fn request_model(body: &[u8]) -> String {
    top_level_field::<String>(body, "model").unwrap_or_default()
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
/// 脱敏名单 = **硬编码黑名单** (见 [`is_sensitive_header`]: 主流 LLM provider 的
/// 标准 auth header — 显式枚举, 非 glob 前缀匹配 — 加上含 `token` / `secret`
/// 子串的关键词匹配) **∪ `extra` 追加名单** (来自 `[redact] redacted_headers`,
/// 经 `state::normalize_redacted_headers` 归一化后存入
/// `AppState::redacted_headers`, 启动时读取一次). `extra` 条目按 lowercase
/// header 名**精确匹配** (调用方保证已 trim + lowercase — 匹配端不做归一化).
/// 默认空 `extra` = 仅黑名单生效, 行为不变.
pub(super) fn redact_headers(src: &HeaderMap, extra: &[String]) -> Vec<(String, String)> {
    src.iter()
        .map(|(name, value)| {
            let name_str = name.as_str().to_lowercase();
            let v = if is_sensitive_header(&name_str) || extra.contains(&name_str) {
                "<redacted>".to_string()
            } else {
                value.to_str().unwrap_or("<binary>").to_string()
            };
            (name_str, v)
        })
        .collect()
}

/// 判断 header 是否敏感: 黑名单关键词匹配 (覆盖各 LLM provider 常见字段).
/// 用户自定义 auth header 经 `[redact] redacted_headers` 配置追加 (并集语义,
/// 见 [`redact_headers`] — 匹配在调用方做, 本函数只管硬编码黑名单).
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

// ─── parse-失败 fallback 可观测性 (#158 + RED-8, fan_out / cross_proto 共享) ──

/// 上游响应 parse 失败 (codec reader 拒绝 / 非 JSON) 但 JSON 叶子级兜底 restore
/// **成功**还原了 mock (RED-8). 客户端拿到的是真 secret, 但 body 经过了非 codec 的
/// 改写路径 (重序列化), 记 WARN 保持可观测 (风格仿照 #158 的 mock-not-restored).
pub(super) fn warn_mocks_restored_via_json_leaf_fallback(record_id: uuid::Uuid) {
    tracing::warn!(
        %record_id,
        "response parse failed with redactions in flight; \
         mocks restored via JSON leaf fallback (response was not parseable by codec)"
    );
}

/// 上游响应 parse 失败且 JSON 叶子级兜底也失败 → mock 逃逸到客户端 (#158).
/// 仅当本请求做过 redact (`map` 非空) 时打 — 无 redaction 在途的 parse 失败只是
/// 普通透传, 无 mock 可逃.
pub(super) fn warn_mock_not_restored(
    record_id: uuid::Uuid,
    detail: &str,
    map: &crate::redact::RedactionMap,
) {
    if !map.is_empty() {
        tracing::warn!(
            %record_id,
            detail,
            "response parse failed with redactions in flight; \
             mock not restored; client will see mock values"
        );
    }
}

/// RED-8 reader 拒绝分支的共享兜底决策序列 (fan_out_buffered_ir / cross_proto_forward
/// 的 SSOT): 在外层**已 parse** 的 `v` 上尝试 JSON 叶子级 restore (零二次 parse) —
/// 成功 → restored WARN + 重序列化字节; 未命中/无 redaction → mock-not-restored WARN
/// + 原字节透传 (FWD-1: 未命中绝不重序列化).
///
/// `mode` = `[redact] on_fallback_restore` (SEC-10 降级偏安全):
/// - `Withhold` (默认): **不尝试 restore**, 保留 Mock 透传 + mock-not-restored
///   WARN (detail 追加 opt-in 提示). 失败/降级响应体是最高概率被客户端日志系统
///   采集的内容, 把 real 还原进去等于精准投放泄露; Mock 按 RED-5 设计可安全暴露.
/// - `Restore` (显式 opt-in, RED-8 行为): JSON 叶子级 restore 兜底如上.
pub(super) fn restore_via_json_leaf_fallback(
    record_id: uuid::Uuid,
    v: &mut serde_json::Value,
    original: &[u8],
    reject_detail: &str,
    map: &crate::redact::RedactionMap,
    mode: crate::config::OnFallbackRestore,
) -> Vec<u8> {
    match mode {
        crate::config::OnFallbackRestore::Withhold => {
            warn_mock_not_restored(
                record_id,
                &format!(
                    "{reject_detail}; set [redact] on_fallback_restore = \"restore\" to opt in"
                ),
                map,
            );
            original.to_vec()
        }
        crate::config::OnFallbackRestore::Restore => {
            if crate::redact::restore_json_value_fallback(v, map) {
                warn_mocks_restored_via_json_leaf_fallback(record_id);
                serde_json::to_vec(v).unwrap_or_else(|_| original.to_vec())
            } else {
                warn_mock_not_restored(record_id, reject_detail, map);
                original.to_vec()
            }
        }
    }
}

// ─── usage-stats 采集上下文构造 ─────────────────────────────────────────────

/// usage 接线参数 (usage_ctx_and_record_redactions 的收口 — 避免 10 参签名).
pub(super) struct UsageWire<'a> {
    pub fp: &'a super::ForwardPath,
    pub method: &'a axum::http::Method,
    pub upstream_id: &'a str,
    /// 请求侧 model (CallEvent.model 是 SSOT).
    pub model_req: Option<String>,
    pub secrets: &'a [crate::secrets::SecretEntry],
    /// push_messages 返回的 node id.
    pub record_id: uuid::Uuid,
    /// redact 审计采集单元 (redact_and_derive 产出, push 前捕获).
    pub hits: &'a [crate::usage::RedactHit],
    /// auth 启用时的 API key label 归因 (单用户模式 None).
    pub api_key_label: Option<String>,
}

/// 从 request parts 提取 auth 归因 (require_api_key middleware 注入的 Extension;
/// auth 未启用时 middleware 不挂载 → None). proxy → auth 是纯类型依赖
/// (AuthenticatedTenant 数据形态), 见根 AGENTS.md 依赖图例外条目.
pub(super) fn auth_label(parts: &axum::http::request::Parts) -> Option<String> {
    parts
        .extensions
        .get::<crate::auth::AuthenticatedTenant>()
        .map(|t| t.label.clone())
}

/// 构造 [`crate::usage::UsageCtx`] 并**立即落账 redact 审计事件** (USAGE-7 请求侧
/// 落账点, 仅由 recorder::push_event_and_wire_usage 调用 — 三转发路径的接线 SSOT
/// 在该函数). 未来新增转发路径不会漏带 SEC 扫描快照与审计接线.
/// `record_id` 用于回读刚 push 节点的 RoundKind (与 attach_response 同型的
/// 安全窗口, 详见 `dag::round_kind_of`).
pub(super) fn usage_ctx_and_record_redactions(
    state: &crate::state::AppState,
    wire: UsageWire<'_>,
) -> crate::usage::UsageCtx {
    let UsageWire {
        fp,
        method,
        upstream_id,
        model_req,
        secrets,
        record_id,
        hits,
        api_key_label,
    } = wire;
    let round_kind = state
        .dag
        .round_kind_of(record_id)
        .unwrap_or(crate::dag::RoundKind::Normal);
    let ctx = crate::usage::UsageCtx::new(
        state.usage.clone(),
        std::sync::Arc::from(upstream_id),
        model_req,
        fp.proto.clone(),
        method.as_str(),
        round_kind,
        record_id,
        api_key_label,
        std::sync::Arc::from(secrets.to_vec().into_boxed_slice()),
    );
    ctx.record_redactions(hits);
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderName;
    use proptest::prelude::*;

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
        // 默认 (extra 空): 仅硬编码黑名单生效, 行为与配置项引入前一致.
        let v = redact_headers(&src, &[]);
        let m: std::collections::HashMap<_, _> = v.into_iter().collect();
        assert_eq!(m.get("authorization").unwrap(), "<redacted>");
        assert_eq!(m.get("x-api-key").unwrap(), "<redacted>");
        assert_eq!(m.get("x-goog-api-key").unwrap(), "<redacted>");
        assert_eq!(m.get("x-custom-token").unwrap(), "<redacted>");
        assert_eq!(m.get("x-custom").unwrap(), "value");
    }

    // ─── SEC-4: [redact] redacted_headers 追加名单 (并集语义) ──────────────
    //
    // 契约 (docs/design/contracts.md §7 SEC-4): extra 条目按 lowercase header 名
    // 精确匹配, 命中即脱敏; 匹配端不做归一化 (trim/lowercase 由装配点
    // state::normalize_redacted_headers 集中完成 — 条目假定已规范).

    #[test]
    fn redact_headers_extra_config_hits_custom_header() {
        // 自定义 auth header (不含 token/secret 关键词, 不在黑名单): 配置进 extra
        // 后必须脱敏; 未配置的同类 header 仍原样记录.
        let mut src = HeaderMap::new();
        src.insert("x-my-service-key", "hunter2".parse().unwrap());
        src.insert("x-other-key", "plain".parse().unwrap());
        let extra = vec!["x-my-service-key".to_string()];
        let m: std::collections::HashMap<_, _> = redact_headers(&src, &extra).into_iter().collect();
        assert_eq!(m.get("x-my-service-key").unwrap(), "<redacted>");
        assert_eq!(m.get("x-other-key").unwrap(), "plain");
    }

    #[test]
    fn redact_headers_extra_is_exact_match_not_substring() {
        // 精确匹配语义: extra 含 "x-my-key" 不波及 "x-my-key-v2" / "prefix-x-my-key".
        let mut src = HeaderMap::new();
        src.insert("x-my-key", "a".parse().unwrap());
        src.insert("x-my-key-v2", "b".parse().unwrap());
        src.insert("prefix-x-my-key", "c".parse().unwrap());
        let extra = vec!["x-my-key".to_string()];
        let m: std::collections::HashMap<_, _> = redact_headers(&src, &extra).into_iter().collect();
        assert_eq!(m.get("x-my-key").unwrap(), "<redacted>");
        assert_eq!(m.get("x-my-key-v2").unwrap(), "b");
        assert_eq!(m.get("prefix-x-my-key").unwrap(), "c");
    }

    #[test]
    fn redact_headers_extra_is_exact_match_assumes_normalized_entries() {
        // 假设声明 (集中式预处理的对应面): extra 条目假定已归一化 — 混大小写条目
        // 不命中 lowercase header 名. 归一化职责在 state::normalize_redacted_headers
        // (有专项测试), 本测试锁定匹配端不悄悄做归一化 (避免双重处理的语义漂移).
        let mut src = HeaderMap::new();
        src.insert("x-my-service-key", "hunter2".parse().unwrap());
        let extra = vec!["X-My-Service-Key".to_string()];
        let m: std::collections::HashMap<_, _> = redact_headers(&src, &extra).into_iter().collect();
        assert_eq!(
            m.get("x-my-service-key").unwrap(),
            "hunter2",
            "non-normalized extra entry must NOT match (normalization is upstream's job)"
        );
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

    // ─── FWD-4: requests_stream 显式 stream 检测 (#175) ────────────────────
    //
    // 契约 (docs/design/contracts.md FWD-4): 只有显式顶层 "stream": true 才按流式
    // 选响应头超时; 其余 (含缺字段 / 非布尔 / 非 JSON / 顶层非对象) 一律非流式.
    // 保守方向 rationale 见 requests_stream doc.

    #[test]
    fn requests_stream_only_explicit_true_is_streaming() {
        // 显式 true (字段位置无关).
        assert!(requests_stream(br#"{"stream":true}"#));
        assert!(requests_stream(
            br#"{"model":"gpt-4","stream":true,"messages":[]}"#
        ));
        // 显式 false / 缺字段 (OpenAI/Anthropic/Responses 默认非流式).
        assert!(!requests_stream(br#"{"stream":false}"#));
        assert!(!requests_stream(br#"{"model":"gpt-4","messages":[]}"#));
        assert!(!requests_stream(br#"{}"#));
        // 嵌套的 stream 不算 (只看顶层).
        assert!(!requests_stream(br#"{"metadata":{"stream":true}}"#));
    }

    #[test]
    fn requests_stream_malformed_bodies_fall_back_to_nonstream() {
        // ROB-1: 任何解析异常 → false (非流式 = 长超时, 保守方向见 doc).
        assert!(!requests_stream(b"")); // 空 body (GET / 非聊天端点)
        assert!(!requests_stream(b"not json at all"));
        assert!(!requests_stream(b"[1,2,3]")); // 顶层非对象
        assert!(!requests_stream(br#"{"stream":"true"}"#)); // 非布尔
        assert!(!requests_stream(br#"{"stream":"#)); // 截断 JSON
    }

    // ─── request_model: 路由规则匹配输入的顶层 model 提取 ──────────────────
    //
    // 语义: 只取顶层 string `model`; 嵌套不误取; 一切异常形态 (非 JSON / 顶层
    // 非对象 / 缺字段 / 非字符串 / 空 body) 降级 "" (best-effort, ROB-1).

    #[test]
    fn request_model_extracts_top_level_string() {
        assert_eq!(request_model(br#"{"model":"gpt-4o"}"#), "gpt-4o");
        // 字段位置无关 (顶层任意位置).
        assert_eq!(
            request_model(br#"{"stream":false,"model":"claude-3","messages":[]}"#),
            "claude-3"
        );
        // 重复 key: 后者覆盖 (与 serde_json Value 的 dup-key 行为一致).
        assert_eq!(
            request_model(br#"{"model":"a","model":"b"}"#),
            "b",
            "duplicate top-level model: last wins"
        );
    }

    #[test]
    fn request_model_missing_field_returns_empty() {
        assert_eq!(request_model(br#"{"messages":[{"role":"user"}]}"#), "");
        assert_eq!(request_model(br#"{}"#), "");
    }

    #[test]
    fn request_model_nested_model_not_picked_up() {
        // messages 里嵌套的 model 字段不能误取 (只扫顶层 key).
        assert_eq!(
            request_model(
                br#"{"messages":[{"role":"user","content":"hi"},{"model":"nested-model"}]}"#
            ),
            "",
            "nested model must not leak to routing"
        );
        // 顶层存在时嵌套值不干扰.
        assert_eq!(
            request_model(br#"{"model":"top","metadata":{"model":"nested"}}"#),
            "top"
        );
    }

    #[test]
    fn request_model_malformed_bodies_fall_back_to_empty() {
        assert_eq!(request_model(b""), ""); // 空 body (GET / 非聊天端点)
        assert_eq!(request_model(b"not json at all"), "");
        assert_eq!(request_model(b"[1,2,3]"), ""); // 顶层非对象
        assert_eq!(request_model(br#"{"model":123}"#), ""); // 非字符串
        assert_eq!(request_model(br#"{"model":null}"#), "");
        assert_eq!(request_model(br#"{"model":"#), ""); // 截断 JSON
    }

    /// FWD-4 property: 任意 JSON 值塞进顶层 `stream` 字段, `requests_stream` 只有
    /// 在该值**是布尔 true** 时返回 true — 所有其他形态 (含畸形) 一律非流式.
    ///
    /// 生成器覆盖: null / bool / 数字 / 字符串 / 数组 / 对象 / 截断字符串, 加上
    /// stream 字段出现在对象头部/尾部两种位置 (字段顺序无关性).
    #[test]
    fn prop_requests_stream_strict_bool_gate() {
        proptest!(|(stream_value in arb_stream_value_forms(), stream_first in proptest::bool::ANY)| {
            let body = if stream_first {
                format!(r#"{{"stream":{stream_value},"model":"m"}}"#)
            } else {
                format!(r#"{{"model":"m","stream":{stream_value}}}"#)
            };
            let expected = stream_value == "true";
            prop_assert_eq!(
                requests_stream(body.as_bytes()),
                expected,
                "body: {}",
                body
            );
        });
    }

    /// 生成 `stream` 字段值的各种形态: 合法 JSON 值 (标量/数组/对象) + "语义上是
    /// true 的非布尔写法" (字符串 "true" / 1) + 截断输入. 覆盖 requests_stream
    /// 的全部降级路径.
    fn arb_stream_value_forms() -> impl proptest::strategy::Strategy<Value = String> {
        proptest::sample::select(vec![
            "true",
            "false",
            "null",
            "0",
            "1",
            "-1",
            "3.14",
            "\"true\"",
            "\"false\"",
            "[true]",
            "{\"deep\":true}",
            "{\"stream\": 12.4", // 截断 JSON (流式解析中途断掉, 尾值残缺)
            "{\"stream\": \"st", // 截断字符串值
        ])
        .prop_map(str::to_string)
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
            let redacted = redact_headers(&src, &[]);
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
