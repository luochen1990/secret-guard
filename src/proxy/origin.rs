//! Origin 发现探测 (`POST /api/providers/probe-origin` 的核心, issue #332).
//!
//! # 职责边界
//!
//! 本模块是**全景探测的 SSOT** (#332 融合, 2026-10-19: master 侧 origin 先行
//! 实现吸收了 PR #344 侧 `probe_provider_upstream` 的全景职责 — 后者已删除,
//! `POST /api/providers/probe` 收敛为 verify 单协议校验, 见 `super::models`):
//! 用户只给 origin (如 `https://api.xiaomimimo.com`, 深路径 URL 也可 — 归一化
//! 只剥已知面尾段, 余下整体作为探测基准), 对每个协议族枚举**面候选**
//! (face = origin + uri, 如 `/anthropic`), 并行探测所有候选, 输出固定 5 行
//! 发现矩阵 (openai / anthropic / gemini / ollama / responses — responses 无
//! 独立候选, 镜像 openai 行). ok 行携带快速添加所需的端点知识 (映射目标是
//! 运行时三段式拼接逐字节一致 — 物化端点的 verify/fetch 必然复现被探测 URL):
//! **v1 族** (openai/responses) 的面路径兼任 `common_uri` 布局断言
//! (`""`/`"/v1"`/深面前缀), `base_url` = origin; **anthropic/ollama** 面路径是
//! base 段 (`base_url` = origin + uri, common_uri null); **gemini** 的
//! `/v1beta` 是运行时自拼版本段, 折叠进 models_path (面恒 `""`,
//! `base_url` = origin, common_uri null). handler 薄壳在
//! `web/api/providers.rs` (origin 校验 + 归一化 + extra_faces 解析后调
//! [`probe_origin_upstream`]).
//!
//! 拆分为 sibling 模块而非续写在 models.rs: file-size 硬门禁
//! (FILE_MAX_PROD_LINES = 1600, models.rs prod 已 ~1270). 判定件 (parse/classify/
//! fetch 防御/headers) 复用 `super::models` 的 pub(super) 件, 不另造轮子.
//!
//! # 证据梯 (tier ladder, 高 tier 命中即止)
//!
//! 每族候选按梯判定, 候选间按 tier 序合并 (models > auth > absent > error,
//! 同 tier 先到先得 — 候选序 = extras 前插后的探测序):
//!
//! 1. **models 证据** (tier1): GET `{face}{models_path}` 2xx + shape 解析成功
//!    (openai/anthropic 共用 data[].id 且靠 `classify_v1_family` 判别字段分家,
//!    gemini/ollama 各自 shape — 全部复用 models.rs 的解析件) → `ok` + `models`.
//! 2. **auth 证据** (tier2): 同 GET 返回 401|403 → `ok` (面存在, key 问题),
//!    detail 提示换 key.
//! 3. **存在性证据** (tier3): tier1/2 全阴 (该族所有候选 404|405) 且候选 uri
//!    非空时, 对每个非空候选 POST 该族的 chat 端点 (固定 probe body, json
//!    content-type): 主探测 ∈ {400,401,403,405,422} (非-404 的 4xx 路由存在集)
//!    **且**对照 GET `{face}/…/__sg_nonexistent__{8hex}__` 严格 404 → `ok` +
//!    `existence`; 其余 (主探测 404/2xx/5xx/连接失败, 或对照非 404) → 无信号.
//! 4. 全阴 → `absent`.
//!
//! **对照探测的必要性 (wildcard / soft-404 宿主)**: 只看主探测状态码会把
//! "任何路径都返回同一状态" 的宿主误判为面存在. 实测校准 (curl, 2026-10-18):
//!
//! - `https://api.xiaomimimo.com`: GET `/v1/models` → 401 (openai 面存在, 无 key);
//!   GET `/models` `/anthropic/v1/models` `/anthropic/models` `/v1beta/models`
//!   `/api/tags` → 404; POST `/anthropic/v1/messages` `{"model":"probe",
//!   "max_tokens":1,"messages":[]}` → **401** `Invalid API Key` (带 key 时为 400,
//!   即 wire 契约示例的 detail 形态); 对照 GET `/anthropic/v1/__sg_nonexistent__
//!   deadbeef01__` → **404** (openresty) → 对照成立, anthropic 面 = ok/existence.
//! - `https://open.bigmodel.cn` (根路径是 SPA **软 200 宿主**): GET `/v1/models` →
//!   **200 + HTML** (非 JSON); GET `/models` `/v1beta/models` → 200 HTML;
//!   GET `/api/tags` → 200 + JSON soft-404 `{"code":500,"msg":"404 NOT_FOUND"}`;
//!   POST `/v1/chat/completions` → **405** (nginx 静态路由拒 POST) 但对照 GET
//!   `/v1/__sg_nonexistent__…__` → **200** → 无信号 → absent. 两个校准结论:
//!   ① 非-404 4xx (含 405) 单独不足以判存在, 对照必须严格 404;
//!   ② **2xx + shape 解析失败 → absent (而非 error)** — SPA 软 200 是 origin 扫描
//!   的常态 (对照旧 base_url 全景探测的判定语义把它判 Error: 那里假设宿主是
//!   API 站点, 200-垃圾是异常; origin 扫描面对任意站点, 200-非模型清单 = 该 URL
//!   不是模型端点, 属否定证据). `error` 保留给传输层失败 (连接失败/超时/超大
//!   body) 与 5xx.
//! - bigmodel `/api/**` 真实面 (如 `/api/coding/paas/v4`): auth 中间件**先于路由**
//!   — GET/POST 一律 401 (含对照路径, 同状态) → 存在性梯无信号; 该场景由
//!   extra_faces (前端预置知识库) + tier2 的 401 auth 证据覆盖, 不依赖 tier3.
//!
//! # tier3 POST 路径与面候选的版本语义
//!
//! openai 的默认候选 (`/v1`) **自带版本前缀** — chat 端点 =
//! `{face}/chat/completions` / `{face}/models:generateContent` (再拼 `/v1` 会双写;
//! GLM 实测端点形态 `open.bigmodel.cn/api/coding/paas/v4` + `/chat/completions`
//! 佐证); anthropic 面 (`/anthropic` 类站点前缀) 的 API 路径 `/v1/messages` 不在
//! 面内 — POST `{face}/v1/messages` (MiMo 实测). 对照路径同理取主探测同子树:
//! anthropic = `{face}/v1/__sg_…__`, 其余 = `{face}/__sg_…__`. 空 URI 候选 ("")
//! 不做 tier3 (origin 根的 POST 语义太杂).
//!
//! # 纪律
//!
//! 探测失败是**数据不是 HTTP 错误** (ROB-*, 恒 200, 永不 panic); detail 经
//! `upstream_error_brief` 姿态净化, 绝不含 api_key; 同族候选与跨族全部并行
//! (`futures::join_all`, 并行一波 join 的形态), tier3 是
//! 第二波 (wave1 join 后条件再 join); 相同 URL 跨族去重只发一次 (openai 候选
//! `""` 与 anthropic 候选 `""` 的 GET `{origin}/v1/models` 共享结果 — tier3 POST
//! URL 按族后缀天然不撞, 免去去重).

use std::collections::HashMap;

use axum::http::{HeaderValue, StatusCode};
use futures::future::join_all;
use serde::Serialize;

use super::helpers::build_upstream_url;
use super::models::{
    V1Family, classify_v1_family, fetch_status_and_body, parse_json_value, parse_model_ids,
    parse_model_ids_from_value, post_status_and_body, probe_headers, status_detail,
};
use crate::provider::Protocol;

// ─── wire DTO (契约冻结, 逐字段对齐前端) ────────────────────────────────

/// origin 发现探测响应. 探测失败是数据不是 HTTP 错误 — handler 恒 200.
#[derive(Debug, Serialize)]
pub(crate) struct OriginProbeResponse {
    /// 归一化后的 canonical origin (探测实际发起的基准).
    pub origin: String,
    /// origin 输入尾部被剥离的已知面段 (`"/anthropic"` / `"/v1"` / `"/v1beta"` /
    /// `"/api/anthropic"`); null = 未剥离.
    pub typed_face_stripped: Option<String>,
    /// 固定 5 行, 顺序: openai, anthropic, gemini, ollama, responses (前端渲染依赖).
    pub faces: Vec<OriginFaceOutcome>,
}

/// 单协议族的发现结果 (wire 行).
#[derive(Debug, Serialize)]
pub(crate) struct OriginFaceOutcome {
    pub protocol: &'static str,
    /// status=ok 时 = 命中面的 uri (`""` = origin 根, 版本前缀已含布局); 其余 null.
    pub uri: Option<String>,
    /// status=ok 时 = 快速添加预填的端点 base_url (#332 融合): **v1 族行
    /// (openai/responses) = origin** — 面路径经 [`Self::common_uri`] 承载为
    /// 布局断言 (base 座回退 origin, 与 `Endpoint` 三段式的语义一致); 其余族
    /// (anthropic/gemini/ollama — 面路径是 base 段而非 common_uri) = origin +
    /// uri. 其余 status null.
    pub base_url: Option<String>,
    pub status: OriginFaceStatus,
    /// 仅 status=ok: `models` (tier1) | `auth` (tier2) | `existence` (tier3).
    pub evidence: Option<OriginFaceEvidence>,
    /// 仅 tier1 ok 有 (可为空数组); 其余 null.
    pub models: Option<Vec<String>>,
    /// 人读证据/净化错误摘要: tier2/3 ok 与 error 必有; tier1 ok 与 absent 为 null
    /// (responses 镜像行恒有 — 追加共用注记). 绝不含 api_key.
    pub detail: Option<String>,
    /// 仅 v1 族 (openai/responses) 的 ok 行非 null: = 命中面 uri, 作为快速添加
    /// 直填 `Endpoint.common_uri` 的布局断言 (`"/v1"` 裸根 / `""` 版本前缀已含 /
    /// 深面如 `/api/coding/paas/v4`); 其余 (非 ok / anthropic·gemini·ollama —
    /// 无 common_uri 概念, base_url 已含面段) null. 与 `verify_endpoint_upstream`
    /// ok outcome 的 common_uri 同源语义 (PR #344 per-outcome 证据的融合落点).
    pub common_uri: Option<String>,
}

/// faces 行的 wire 协议名. 注意 responses 行 = `"responses"` (契约冻结) 而非
/// `Protocol::name()` 的 `"openai-responses"` — 其余 4 名与 Protocol::name 重合.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OriginFaceStatus {
    Ok,
    Absent,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OriginFaceEvidence {
    Models,
    Auth,
    Existence,
}

impl OriginFaceOutcome {
    /// status=ok 行: uri/base_url/common_uri 绑定命中面 (base_url 与 common_uri
    /// 的族别分派见字段注释), evidence/models/detail 由 tier 分派. `cu_layout` =
    /// 该族面路径是否兼任 common_uri (仅 openai 族 — responses 镜像其行;
    /// anthropic 面路径是 base 段, 见 `family_outcome` 的分派注释).
    fn ok(
        protocol: &'static str,
        origin: &str,
        uri: &str,
        cu_layout: bool,
        evidence: OriginFaceEvidence,
        models: Option<Vec<String>>,
        detail: Option<String>,
    ) -> Self {
        Self {
            protocol,
            uri: Some(uri.to_string()),
            base_url: Some(if cu_layout {
                origin.to_string()
            } else {
                face_base(origin, uri)
            }),
            status: OriginFaceStatus::Ok,
            evidence: Some(evidence),
            models,
            detail,
            common_uri: cu_layout.then(|| uri.to_string()),
        }
    }

    /// status=error 行 (detail 必有) / status=absent 行 (detail 必 null):
    /// 两者 uri/base_url/evidence/models/common_uri 均为 null.
    fn not_ok(protocol: &'static str, status: OriginFaceStatus, detail: Option<String>) -> Self {
        debug_assert_eq!(
            (status == OriginFaceStatus::Error),
            detail.is_some(),
            "error 行 detail 必有, absent 行 detail 必 null"
        );
        Self {
            protocol,
            uri: None,
            base_url: None,
            status,
            evidence: None,
            models: None,
            detail,
            common_uri: None,
        }
    }
}

// ─── origin 归一化 ─────────────────────────────────────────────────────

/// 单段已知面尾段 (剥离规则 ①: 最后 path 段精确匹配).
const STRIP_TAIL_SEGMENTS: [&str; 3] = ["anthropic", "v1", "v1beta"];
/// 双段后缀 (剥离规则 ②, 优先于 ①: 路径以 `/api/anthropic` 结尾整体剥离).
const STRIP_SUFFIX: &str = "/api/anthropic";

/// origin 输入归一化: 剥离尾部的已知面段得到 canonical origin (URL 结构分解后
/// 按**整段**匹配, 不做朴素字符串切 — host/query 中的同名词不受影响).
///
/// 前置条件: 调用方 (handler) 已对**原始输入**跑过 `validate_base_url` (http(s)
/// 前缀 / 非尾部 `/`). 本函数额外拒绝 query/fragment (origin 是面根定位符,
/// query 会经 build_upstream_url 的纯拼接内嵌进每个探测 URL 中段).
///
/// 返回 (canonical_origin, 被剥离段). 假设: 剥离只做一次 (多段面尾不递归);
/// 大小写敏感 (`V1` 不剥 — 已知面尾段都是小写约定).
pub(crate) fn normalize_origin(input: &str) -> Result<(String, Option<String>), String> {
    if input.contains('?') || input.contains('#') {
        return Err("origin must not contain a query string or fragment".to_string());
    }
    // scheme://authority/path 分解 (authority 以首个 '/' 结束 — userinfo 与 IPv6
    // 字面量的 ':' 不参与; path 不含前导 '/').
    let (prefix, path) = match input.split_once("://") {
        Some((scheme, rest)) => match rest.split_once('/') {
            Some((authority, path)) => (format!("{scheme}://{authority}"), path),
            // host-only URL (无 path): 无可剥离段.
            None => return Ok((input.to_string(), None)),
        },
        // validate_base_url 已挡掉无 scheme 输入; 到此为防御性兜底 (ROB).
        None => return Err("origin must start with http:// or https://".to_string()),
    };
    if path.is_empty() {
        // "scheme://host/" 形态被 validate_base_url 的尾部 '/' 规则挡住, 防御兜底.
        return Ok((prefix, None));
    }
    // 剥离匹配在带前导 '/' 的完整 path 上做: 双段后缀整体剥离优先 ("/api/anthropic"
    // 含 path 恰为该后缀的形态), 否则单段规则在最后一个 '/' 处切分 (避免中间段
    // 残留尾斜杠, "foo/anthropic" → head "foo" 而非 "foo/").
    let full = format!("/{path}");
    let (head, stripped) = if let Some(head) = full.strip_suffix(STRIP_SUFFIX) {
        (head.to_string(), STRIP_SUFFIX.to_string())
    } else {
        let (head, last) = match path.rfind('/') {
            Some(i) => (&path[..i], &path[i + 1..]),
            None => ("", path),
        };
        if STRIP_TAIL_SEGMENTS.contains(&last) {
            (head.to_string(), format!("/{last}"))
        } else {
            return Ok((input.to_string(), None));
        }
    };
    let canonical = match head.as_str() {
        "" => prefix,
        h if h.starts_with('/') => format!("{prefix}{h}"),
        h => format!("{prefix}/{h}"),
    };
    Ok((canonical, Some(stripped)))
}

// ─── extra_faces 解析 ──────────────────────────────────────────────────

/// extra_face 条目解析 (handler 侧逐条调用): `protocol` 词表 = `Protocol` 的
/// serde 枚举名 + `"responses"` 别名 (与响应 faces 行的 wire 名对齐); `uri` 必须
/// `/` 开头. 校验失败 (未知 protocol / uri 非 `/` 开头, 含空串) → None =
/// 该条丢弃不报错 (best-effort, ROB — 前端预置知识库的脏数据不该让探测 4xx).
pub(crate) fn parse_extra_face(protocol: &str, uri: &str) -> Option<(Protocol, String)> {
    let proto = Protocol::from_name(protocol)
        .or((protocol == "responses").then_some(Protocol::OpenAIResponses))?;
    if !uri.starts_with('/') {
        return None;
    }
    Some((proto, uri.to_string()))
}

// ─── 探测族矩阵 ────────────────────────────────────────────────────────

/// 探测族 (responses 无独立族, 镜像 openai — 见模块头部).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Family {
    OpenAI,
    Anthropic,
    Gemini,
    Ollama,
}

impl Family {
    /// 全部探测族, 顺序 = faces 行前 4 行 (契约冻结).
    const ALL: [Family; 4] = [
        Family::OpenAI,
        Family::Anthropic,
        Family::Gemini,
        Family::Ollama,
    ];

    fn protocol(self) -> Protocol {
        match self {
            Family::OpenAI => Protocol::OpenAI,
            Family::Anthropic => Protocol::Anthropic,
            Family::Gemini => Protocol::Gemini,
            Family::Ollama => Protocol::Ollama,
        }
    }

    fn name(self) -> &'static str {
        self.protocol().name()
    }

    /// tier1 模型清单端点 (相对 face 拼接): openai 族 `/models` (面 `/v1` 兼任
    /// common_uri 布局), anthropic `/v1/models` (API 路径自带 `/v1`).
    /// gemini 的 `/v1beta` 是**运行时自拼版本段** (fetch/verify 恒
    /// `GET {base}/v1beta/models`, `models.rs` 硬编码) — 折叠进 models_path
    /// 而非面候选: 命中行的 base 座 = origin, 快速添加物化的端点与运行时
    /// 拼接逐字节一致 (不折叠会物化出 `{origin}/v1beta` base → 运行时
    /// 双 `/v1beta` 404).
    fn models_path(self) -> &'static str {
        match self {
            Family::OpenAI => "/models",
            Family::Anthropic => "/v1/models",
            Family::Gemini => "/v1beta/models",
            Family::Ollama => "/api/tags",
        }
    }

    /// tier1 默认面候选 (数组序 = 探测优先序; extra_faces 前插后去重).
    fn default_faces(self) -> &'static [&'static str] {
        match self {
            Family::OpenAI => &["/v1", ""],
            Family::Anthropic => &["/anthropic", ""],
            Family::Gemini => &[""],
            Family::Ollama => &[""],
        }
    }

    /// tier3 存在性主探测 (POST 路径相对 face 拼接, 固定 probe body).
    /// 版本语义见模块头部: openai 的面已含版本前缀, 不再拼 `/v1`; gemini 的
    /// `/v1beta` 同为运行时自拼版本段 (随 models_path 折叠, 不在面内).
    fn existence_post(self) -> (&'static str, &'static str) {
        match self {
            Family::OpenAI => ("/chat/completions", r#"{"model":"probe","messages":[]}"#),
            Family::Anthropic => (
                "/v1/messages",
                r#"{"model":"probe","max_tokens":1,"messages":[]}"#,
            ),
            Family::Gemini => ("/v1beta/models:generateContent", "{}"),
            Family::Ollama => ("/api/chat", "{}"),
        }
    }

    /// tier3 对照路径 (主探测同子树, 见模块头部; `{nonce}` = 8 hex).
    fn control_path(self, nonce: &str) -> String {
        match self {
            Family::Anthropic => format!("/v1/__sg_nonexistent__{nonce}__"),
            _ => format!("/__sg_nonexistent__{nonce}__"),
        }
    }

    /// 该族的 v1 家族归属 (openai/anthropic 共用 data[].id 端点时的判别方向;
    /// gemini/ollama 无家族判别).
    fn v1_family(self) -> Option<V1Family> {
        match self {
            Family::OpenAI => Some(V1Family::OpenAI),
            Family::Anthropic => Some(V1Family::Anthropic),
            _ => None,
        }
    }
}

/// extra_face 的 `(Protocol, uri)` 归族 (responses → openai: 共用面, 见镜像语义).
fn family_of(protocol: Protocol) -> Family {
    match protocol {
        Protocol::OpenAI | Protocol::OpenAIResponses => Family::OpenAI,
        Protocol::Anthropic => Family::Anthropic,
        Protocol::Gemini => Family::Gemini,
        Protocol::Ollama => Family::Ollama,
    }
}

/// 族候选组装: extra_faces (给定序) 前插 + 默认候选殿后, 去重保序.
fn family_faces(family: Family, extra_faces: &[(Protocol, String)]) -> Vec<String> {
    let mut out: Vec<String> = extra_faces
        .iter()
        .filter(|(p, _)| family_of(*p) == family)
        .map(|(_, uri)| uri.clone())
        .collect();
    for default in family.default_faces() {
        let default = default.to_string();
        if !out.contains(&default) {
            out.push(default);
        }
    }
    out
}

// ─── 判定 ──────────────────────────────────────────────────────────────

/// 单候选 tier1/2 判定的中间形态 (族内合并前).
#[derive(Debug)]
enum CandKind {
    Models(Vec<String>),
    Auth(u16),
    Absent,
    Error(String),
}

impl CandKind {
    /// tier 序: models(3) > auth(2) > absent(1) > error(0) — 合并取高, 同级先到
    /// 先得 (候选探测序).
    fn rank(&self) -> u8 {
        match self {
            CandKind::Models(_) => 3,
            CandKind::Auth(_) => 2,
            CandKind::Absent => 1,
            CandKind::Error(_) => 0,
        }
    }
}

/// tier1/2 单候选判定 (GET `{face}{models_path}` 的结果 → 候选结论).
///
/// 与 `models::judge_single_endpoint` (verify 路径) 的**有意**差异: 2xx +
/// shape 解析失败 → Absent (SPA 软 200 宿主校准, 见模块头部; base_url 探测的
/// Error 语义假设宿主是 API 站点, origin 扫描不成立). 传输层失败 (Err) 与
/// 5xx/其他非 2xx 仍为 Error.
fn judge_models_get(family: Family, res: &Result<(StatusCode, Vec<u8>), String>) -> CandKind {
    match res {
        Err(reason) => CandKind::Error(reason.clone()),
        Ok((status, body)) if status.is_success() => {
            let shape = match family.v1_family() {
                // v1 族: 单次 parse, 条目解析与家族判别共用同一棵 Value 树
                // (单次 parse 双消费的手法); 非本族 shape / 解析失败均落 None.
                Some(mine) => parse_json_value(body).ok().and_then(|value| {
                    let models = parse_model_ids_from_value(Protocol::OpenAI, &value).ok()?;
                    (classify_v1_family(&value) == mine).then_some(models)
                }),
                None => parse_model_ids(family.protocol(), body).ok(),
            };
            match shape {
                Some(models) => CandKind::Models(models),
                None => CandKind::Absent,
            }
        }
        Ok((status, _)) => match status.as_u16() {
            401 | 403 => CandKind::Auth(status.as_u16()),
            404 | 405 => CandKind::Absent,
            _ => CandKind::Error(status_detail(*status)),
        },
    }
}

/// tier3 路由存在集: 非-404 的 4xx (契约枚举 400/401/403/405/422 — 5xx 与 2xx
/// 不构成存在证据, 见模块头部 bigmodel 405-on-SPA 校准).
fn route_exists(status: StatusCode) -> bool {
    matches!(status.as_u16(), 400 | 401 | 403 | 405 | 422)
}

/// tier3 存在性命中: 主探测状态在路由存在集内 **且** 对照严格 404 (wildcard /
/// soft-404 宿主的对照反证, 见模块头部).
fn existence_hit(
    main: &Result<(StatusCode, Vec<u8>), String>,
    control: &Result<(StatusCode, Vec<u8>), String>,
) -> Option<u16> {
    let (main_status, _) = main.as_ref().ok()?;
    if !route_exists(*main_status) {
        return None;
    }
    match control {
        Ok((c, _)) if c.as_u16() == 404 => Some(main_status.as_u16()),
        _ => None,
    }
}

// ─── 编排 ──────────────────────────────────────────────────────────────

/// tier3 主探测 job (wave 2a 的工作单元; URL 按族后缀天然互异 — 见模块尾部纪律).
struct ExistenceJob {
    family: Family,
    /// 命中面的候选 uri (detail 回显 + 行 uri).
    uri: String,
    /// 主探测 POST URL.
    post_url: String,
    /// 主探测 origin 相对路径 (detail 回显, 形如 `/anthropic/v1/messages`).
    post_path: String,
    body: &'static str,
}

/// wave1 后的族结论 + tier3 所需上下文.
struct FamilyWave1 {
    family: Family,
    kind: CandKind,
    /// 胜出候选 uri (Models/Auth 时的命中面).
    uri: String,
    /// 全部候选 (tier3 遍历用).
    faces: Vec<String>,
}

/// 对任意 origin 并行探测 5 行发现矩阵 (#332). 永不 Err / 永不 panic (ROB-*):
/// 探测失败落在对应 faces 行的 `status=error` + detail (净化串, 不含 api_key).
///
/// `origin` 必须是归一化后的 canonical origin (handler 侧 [`normalize_origin`]);
/// `typed_face_stripped` 原样回显; `extra_faces` 已过 [`parse_extra_face`] 校验.
pub(crate) async fn probe_origin_upstream(
    client: &reqwest::Client,
    origin: &str,
    typed_face_stripped: Option<String>,
    api_key: &str,
    extra_faces: &[(Protocol, String)],
) -> OriginProbeResponse {
    let headers = probe_headers(api_key);

    // ── wave 1: 全族全部 tier1 GET 候选并行 (URL 跨族去重共享) ──
    let faces_by_family: Vec<(Family, Vec<String>)> = Family::ALL
        .iter()
        .map(|f| (*f, family_faces(*f, extra_faces)))
        .collect();
    let all_urls = faces_by_family
        .iter()
        .flat_map(|(f, uris)| {
            uris.iter()
                .map(|uri| face_url(origin, uri, f.models_path()))
        })
        .collect::<Vec<_>>();
    let (unique_urls, url_index) = dedup_index(all_urls.iter().map(String::as_str));
    let fetched = join_all(
        unique_urls
            .iter()
            .map(|url| fetch_status_and_body(client, url, headers.clone())),
    )
    .await;

    // 族内合并 (tier 序取最优, 同级先到先得). result_of 的 key 全部来自
    // url_index 的键集合, 查询必然命中 (不变式, expect 不可达).
    let result_of = |url: &str| &fetched[*url_index.get(url).expect("url from index keys")];
    let wave1: Vec<FamilyWave1> = faces_by_family
        .into_iter()
        .map(|(family, faces)| {
            let mut best: Option<(CandKind, String)> = None;
            for uri in &faces {
                let url = face_url(origin, uri, family.models_path());
                let kind = judge_models_get(family, result_of(&url));
                if best.as_ref().is_none_or(|(b, _)| kind.rank() > b.rank()) {
                    best = Some((kind, uri.clone()));
                }
            }
            let (kind, uri) = best.expect("family_faces 恒非空 (default 至少一条)");
            FamilyWave1 {
                family,
                kind,
                uri,
                faces,
            }
        })
        .collect();

    // ── wave 2a: tier1/2 全阴 (absent) 的族 × 非空候选 → 存在性主探测 POST ──
    let nonce = nonce8();
    let jobs: Vec<ExistenceJob> = wave1
        .iter()
        .filter(|w| matches!(w.kind, CandKind::Absent))
        .flat_map(|w| {
            w.faces
                .iter()
                .filter(|uri| !uri.is_empty())
                .map(move |uri| {
                    let (post_path, body) = w.family.existence_post();
                    ExistenceJob {
                        family: w.family,
                        uri: uri.clone(),
                        post_url: face_url(origin, uri, post_path),
                        post_path: format!("{uri}{post_path}"),
                        body,
                    }
                })
        })
        .collect();
    let posts = join_all(jobs.iter().map(|job| {
        let mut h = headers.clone();
        h.insert("content-type", HeaderValue::from_static("application/json"));
        post_status_and_body(client, &job.post_url, h, job.body)
    }))
    .await;

    // ── wave 2b: 主探测命中路由存在集的 job → 对照 GET (URL 去重: openai 与
    // gemini 的对照路径同形, 同 uri 时共享) ──
    let control_urls = jobs
        .iter()
        .enumerate()
        .filter(|(i, _)| posts[*i].as_ref().is_ok_and(|(s, _)| route_exists(*s)))
        .map(|(_, job)| face_url(origin, &job.uri, &job.family.control_path(&nonce)))
        .collect::<Vec<_>>();
    let (unique_controls, control_index) = dedup_index(control_urls.iter().map(String::as_str));
    let controls = join_all(
        unique_controls
            .iter()
            .map(|url| fetch_status_and_body(client, url, headers.clone())),
    )
    .await;

    // tier3 命中合并: 同族首个命中候选胜出 (候选探测序). 值 = (命中面 uri,
    // 主探测 origin 相对路径, 主探测状态码) — detail 回显需要. 对照仅对
    // 路由存在集内的主探测预取过 (wave 2b 的 filter), 其余 job 无对照可查.
    let mut existence: HashMap<Family, (String, String, u16)> = HashMap::new();
    for (i, job) in jobs.iter().enumerate() {
        if existence.contains_key(&job.family) {
            continue;
        }
        // 对照仅对路由存在集内的主探测预取过 (wave 2b 的 filter ⇔ main Ok ∧
        // route_exists, posts 两波之间不变) — 索引成员资格即"对照可查"判据;
        // 存在性判定 (存在集 ∩ 对照严格 404) 全部收口在 existence_hit 单点.
        let control_url = face_url(origin, &job.uri, &job.family.control_path(&nonce));
        let Some(ci) = control_index.get(control_url.as_str()) else {
            continue; // 对照未预取: 主探测不构成存在证据
        };
        if let Some(main_status) = existence_hit(&posts[i], &controls[*ci]) {
            existence.insert(
                job.family,
                (job.uri.clone(), job.post_path.clone(), main_status),
            );
        }
    }

    // ── 行组装: 前 4 行按族, responses 镜像 openai ──
    let mut faces = wave1
        .iter()
        .map(|w| family_outcome(w, origin, &existence))
        .collect::<Vec<_>>();
    let mirrored = mirror_responses(&faces[0]);
    faces.push(mirrored);
    OriginProbeResponse {
        origin: origin.to_string(),
        typed_face_stripped,
        faces,
    }
}

/// wave1 结论 (+ tier3 命中) → wire 行. existence 值 = (命中面 uri, 主探测
/// origin 相对路径, 主探测状态码).
fn family_outcome(
    w: &FamilyWave1,
    origin: &str,
    existence: &HashMap<Family, (String, String, u16)>,
) -> OriginFaceOutcome {
    // 端点知识映射分派: 仅 **openai 族**的面路径兼任 common_uri (base 座回退
    // origin — 面前缀就是 `{cu}/models` 的 cu); anthropic 族虽与 openai 共用
    // v1/models 判形 (`v1_family`), 其面路径 (`/anthropic` 类) 是 base 段而非
    // common_uri (anthropic 的请求路径自带 `/v1` 版本段), 走 origin + uri 形态.
    let cu_layout = w.family == Family::OpenAI;
    match &w.kind {
        CandKind::Models(models) => OriginFaceOutcome::ok(
            w.family.name(),
            origin,
            &w.uri,
            cu_layout,
            OriginFaceEvidence::Models,
            Some(models.clone()),
            None,
        ),
        CandKind::Auth(code) => OriginFaceOutcome::ok(
            w.family.name(),
            origin,
            &w.uri,
            cu_layout,
            OriginFaceEvidence::Auth,
            None,
            Some(auth_detail(*code)),
        ),
        CandKind::Error(reason) => OriginFaceOutcome::not_ok(
            w.family.name(),
            OriginFaceStatus::Error,
            Some(reason.clone()),
        ),
        CandKind::Absent => match existence.get(&w.family) {
            Some((uri, post_path, main_status)) => OriginFaceOutcome::ok(
                w.family.name(),
                origin,
                uri,
                cu_layout,
                OriginFaceEvidence::Existence,
                None,
                Some(existence_detail(post_path, *main_status)),
            ),
            None => OriginFaceOutcome::not_ok(w.family.name(), OriginFaceStatus::Absent, None),
        },
    }
}

/// tier3 存在性 detail (契约示例形态: `路由存在 (POST /anthropic/v1/messages →
/// 400; 对照路径 404)` — 路径为 origin 相对, 对照恒为 404 才命中).
fn existence_detail(post_path: &str, main_status: u16) -> String {
    format!("路由存在 (POST {post_path} → {main_status}; 对照路径 404)")
}

/// tier2 auth detail 文案 (提示换 key; 状态码来自上游).
fn auth_detail(code: u16) -> String {
    format!("面存在但鉴权失败 (upstream returned {code}), 请检查或更换 api_key")
}

/// responses 镜像行: 状态/uri/base_url/evidence/models 复制 openai 行, detail
/// 追加共用注记 (openai detail 为 null 时注记独立成句).
fn mirror_responses(openai: &OriginFaceOutcome) -> OriginFaceOutcome {
    let note = match openai.uri.as_deref() {
        Some(u) if !u.is_empty() => format!("与 OpenAI 共用 {u}, 探测无法区分"),
        Some(_) => "与 OpenAI 共用根路径, 探测无法区分".to_string(),
        None => "与 OpenAI 共用探测路径, 探测无法区分".to_string(),
    };
    let detail = match &openai.detail {
        Some(d) => format!("{d}; {note}"),
        None => note,
    };
    OriginFaceOutcome {
        protocol: "responses",
        uri: openai.uri.clone(),
        base_url: openai.base_url.clone(),
        status: openai.status,
        evidence: openai.evidence,
        models: openai.models.clone(),
        detail: Some(detail),
        common_uri: openai.common_uri.clone(),
    }
}

// ─── 小工具 ────────────────────────────────────────────────────────────

/// face 相对路径拼接的 URL (`build_upstream_url(origin, uri + path)`): uri 为 ""
/// 时即 origin 根 (版本前缀已含布局).
fn face_url(origin: &str, uri: &str, path: &str) -> String {
    build_upstream_url(origin, &format!("{uri}{path}"))
}

/// face 的 base_url 回显 (`uri=""` → origin 本身, 不拼尾斜杠 — build_upstream_url
/// 对空 path 会拼出 "origin/").
fn face_base(origin: &str, uri: &str) -> String {
    if uri.is_empty() {
        origin.to_string()
    } else {
        build_upstream_url(origin, uri)
    }
}

/// URL 去重 (保序): 返回 (去重列表, 原 URL → 去重后索引).
fn dedup_index<'a>(urls: impl Iterator<Item = &'a str>) -> (Vec<String>, HashMap<String, usize>) {
    let mut list = Vec::new();
    let mut index = HashMap::new();
    for url in urls {
        if !index.contains_key(url) {
            index.insert(url.to_string(), list.len());
            list.push(url.to_string());
        }
    }
    (list, index)
}

/// 对照路径随机后缀 (8 hex): 避免与真实路由/缓存碰撞 (测试用 regex matcher 匹配).
fn nonce8() -> String {
    uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(8)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── 测试构造器 ─────────────────────────────────────────────────────

    /// GET mock (全显式挂载 — 不留 mockito 未匹配的隐式行为, 仓库测试纪律).
    async fn mget(
        server: &mut mockito::ServerGuard,
        path: &str,
        status: u16,
        body: &str,
        expect: usize,
    ) -> mockito::Mock {
        server
            .mock("GET", path)
            .with_status(status as usize)
            .with_body(body)
            .expect(expect)
            .create_async()
            .await
    }

    /// tier3 主探测 POST mock: 钉 json content-type (tier3 语义的一部分).
    async fn mpost(
        server: &mut mockito::ServerGuard,
        path: &str,
        status: u16,
        expect: usize,
    ) -> mockito::Mock {
        server
            .mock("POST", path)
            .match_header("content-type", "application/json")
            .with_status(status as usize)
            .expect(expect)
            .create_async()
            .await
    }

    /// tier3 对照 GET mock: 路径含 8-hex 随机 nonce, 用锚定 regex 匹配
    /// (mockito Regex 是子串语义, ^…$ 锚定防误配).
    async fn mcontrol(
        server: &mut mockito::ServerGuard,
        prefix: &str,
        status: u16,
        expect: usize,
    ) -> mockito::Mock {
        server
            .mock(
                "GET",
                mockito::Matcher::Regex(format!(r"^{prefix}__sg_nonexistent__[0-9a-f]{{8}}__$")),
            )
            .with_status(status as usize)
            .expect(expect)
            .create_async()
            .await
    }

    /// 探测 wrapper: origin = server url (canonical 形态), stripped = None.
    async fn probe(
        server: &mockito::ServerGuard,
        api_key: &str,
        extras: &[(Protocol, String)],
    ) -> OriginProbeResponse {
        probe_origin_upstream(
            &reqwest::Client::new(),
            &server.url(),
            None,
            api_key,
            extras,
        )
        .await
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    /// 默认 wave1 的 5 个唯一 GET URL (跨族去重后): /v1/models 共享于 openai("/v1")
    /// 与 anthropic(""), /models 共享于 openai("") 与 gemini("").
    async fn mock_default_model_gets(
        server: &mut mockito::ServerGuard,
        v1_models: (u16, &str),
        bare_models: (u16, &str),
        anthropic_models: (u16, &str),
        v1beta: (u16, &str),
    ) {
        mget(server, "/v1/models", v1_models.0, v1_models.1, 1).await;
        mget(server, "/models", bare_models.0, bare_models.1, 1).await;
        mget(
            server,
            "/anthropic/v1/models",
            anthropic_models.0,
            anthropic_models.1,
            1,
        )
        .await;
        mget(server, "/v1beta/models", v1beta.0, v1beta.1, 1).await;
    }

    // ─── ① MiMo 形状回归 (issue #332 的回归钉) ──────────────────────────

    /// MiMo 实测形状 (2026-10-18 curl 校准): openai 面 GET /v1/models 200
    /// (openai shape); anthropic 面 /anthropic/v1/models 404 + POST
    /// /anthropic/v1/messages 400 (带 key 形态; 实测无 key 为 401, 同属路由
    /// 存在集) + 对照 404 → anthropic 行 ok/existence. responses 镜像 openai.
    #[tokio::test]
    async fn probe_origin_mimo_shape_regression() {
        let mut server = mockito::Server::new_async().await;
        mock_default_model_gets(
            &mut server,
            (
                200,
                r#"{"object":"list","data":[{"id":"mimo-1","object":"model"}]}"#,
            ),
            (404, ""),
            (404, ""),
            (404, ""),
        )
        .await;
        mget(&mut server, "/api/tags", 404, "", 1).await;
        let post = mpost(&mut server, "/anthropic/v1/messages", 400, 1).await;
        let control = mcontrol(&mut server, "/anthropic/v1/", 404, 1).await;
        mpost(&mut server, "/v1beta/models:generateContent", 404, 1).await;
        let openai_never = mpost(&mut server, "/v1/chat/completions", 404, 0).await;

        let resp = probe(&server, "", &[]).await;

        // 固定 5 行顺序 (契约).
        let names: Vec<&str> = resp.faces.iter().map(|f| f.protocol).collect();
        assert_eq!(
            names,
            ["openai", "anthropic", "gemini", "ollama", "responses"]
        );
        assert_eq!(resp.origin, server.url());
        assert_eq!(resp.typed_face_stripped, None);

        let oa = &resp.faces[0];
        assert_eq!(oa.status, OriginFaceStatus::Ok);
        assert_eq!(oa.evidence, Some(OriginFaceEvidence::Models));
        assert_eq!(oa.uri.as_deref(), Some("/v1"));
        // v1 族 (#332 融合): base_url = origin, 面路径经 common_uri 承载布局.
        assert_eq!(oa.base_url.as_deref(), Some(server.url().as_str()));
        assert_eq!(oa.common_uri.as_deref(), Some("/v1"));
        assert_eq!(oa.models.as_ref().unwrap(), &strs(&["mimo-1"]));
        assert!(oa.detail.is_none());

        let an = &resp.faces[1];
        assert_eq!(an.status, OriginFaceStatus::Ok);
        assert_eq!(an.evidence, Some(OriginFaceEvidence::Existence));
        assert_eq!(an.uri.as_deref(), Some("/anthropic"));
        let an_base = format!("{}/anthropic", server.url());
        assert_eq!(an.base_url.as_deref(), Some(an_base.as_str()));
        assert_eq!(an.common_uri, None, "anthropic 面路径是 base 段, 非 cu");
        assert!(an.models.is_none());
        assert_eq!(
            an.detail.as_deref(),
            Some("路由存在 (POST /anthropic/v1/messages → 400; 对照路径 404)")
        );

        for i in [2, 3] {
            let f = &resp.faces[i];
            assert_eq!(f.status, OriginFaceStatus::Absent, "faces[{i}]");
            assert!(
                f.uri.is_none()
                    && f.base_url.is_none()
                    && f.common_uri.is_none()
                    && f.models.is_none()
            );
            assert!(f.detail.is_none());
        }

        let r = &resp.faces[4];
        assert_eq!(r.status, OriginFaceStatus::Ok);
        assert_eq!(r.evidence, Some(OriginFaceEvidence::Models));
        assert_eq!(r.uri.as_deref(), Some("/v1"));
        assert_eq!(r.base_url.as_deref(), Some(server.url().as_str()));
        assert_eq!(r.common_uri.as_deref(), Some("/v1"));
        assert_eq!(r.models.as_ref().unwrap(), &strs(&["mimo-1"]));
        assert_eq!(
            r.detail.as_deref(),
            Some("与 OpenAI 共用 /v1, 探测无法区分")
        );

        post.assert_async().await;
        control.assert_async().await;
        openai_never.assert_async().await;
    }

    // ─── ② tier1 happy (各族) ───────────────────────────────────────────

    /// 四族各自 tier1 命中: openai 走 bare 布局 (uri "", 智谱形状), anthropic
    /// 走 /anthropic 面 (type/display_name 判别), gemini/ollama 各自 shape;
    /// 全 ok ⇒ 零 tier3 POST (负断言钉死).
    #[tokio::test]
    async fn probe_origin_tier1_happy_all_families() {
        let mut server = mockito::Server::new_async().await;
        mock_default_model_gets(
            &mut server,
            (404, ""),
            (
                200,
                r#"{"object":"list","data":[{"id":"glm-4.6","object":"model","owned_by":"z-ai"}]}"#,
            ),
            (
                200,
                r#"{"data":[{"type":"model","id":"claude-3-5","display_name":"Claude"}]}"#,
            ),
            (200, r#"{"models":[{"name":"models/gem-1"}]}"#),
        )
        .await;
        mget(
            &mut server,
            "/api/tags",
            200,
            r#"{"models":[{"name":"llama3:latest"}]}"#,
            1,
        )
        .await;
        let p1 = mpost(&mut server, "/v1/chat/completions", 404, 0).await;
        let p2 = mpost(&mut server, "/anthropic/v1/messages", 400, 0).await;
        let p3 = mpost(&mut server, "/v1beta/models:generateContent", 404, 0).await;

        let resp = probe(&server, "", &[]).await;

        let oa = &resp.faces[0];
        assert_eq!(oa.status, OriginFaceStatus::Ok);
        assert_eq!(oa.evidence, Some(OriginFaceEvidence::Models));
        assert_eq!(oa.uri.as_deref(), Some(""), "bare 布局: 版本前缀已含");
        assert_eq!(oa.base_url.as_deref(), Some(server.url().as_str()));
        assert_eq!(
            oa.common_uri.as_deref(),
            Some(""),
            "bare 布局断言: cu \"\" = 版本前缀已含"
        );
        assert_eq!(oa.models.as_ref().unwrap(), &strs(&["glm-4.6"]));

        let an = &resp.faces[1];
        assert_eq!(an.status, OriginFaceStatus::Ok);
        assert_eq!(an.uri.as_deref(), Some("/anthropic"));
        assert_eq!(
            an.base_url.as_deref(),
            Some(format!("{}/anthropic", server.url()).as_str()),
            "anthropic 面路径是 base 段 (运行时 base + /v1/messages 复现被探测面)"
        );
        assert_eq!(an.common_uri, None);
        assert_eq!(an.models.as_ref().unwrap(), &strs(&["claude-3-5"]));

        let g = &resp.faces[2];
        assert_eq!(g.status, OriginFaceStatus::Ok);
        assert_eq!(
            g.uri.as_deref(),
            Some(""),
            "gemini /v1beta 折叠进 models_path"
        );
        assert_eq!(
            g.base_url.as_deref(),
            Some(server.url().as_str()),
            "gemini base 座 = origin (/v1beta 是运行时自拼版本段, fetch/verify 恒 GET {{base}}/v1beta/models — 物化端点与被探测 URL 逐字节一致)"
        );
        assert_eq!(g.common_uri, None, "gemini 无 common_uri 概念");
        assert_eq!(g.models.as_ref().unwrap(), &strs(&["gem-1"]));

        let o = &resp.faces[3];
        assert_eq!(o.status, OriginFaceStatus::Ok);
        assert_eq!(o.uri.as_deref(), Some(""));
        assert_eq!(o.common_uri, None, "ollama 无 common_uri 概念");
        assert_eq!(o.models.as_ref().unwrap(), &strs(&["llama3:latest"]));

        let r = &resp.faces[4];
        assert_eq!(r.status, OriginFaceStatus::Ok);
        assert_eq!(
            r.detail.as_deref(),
            Some("与 OpenAI 共用根路径, 探测无法区分")
        );

        p1.assert_async().await;
        p2.assert_async().await;
        p3.assert_async().await;
    }

    // ─── ③ tier2 auth (401) ─────────────────────────────────────────────

    /// /v1/models 401: openai ("/v1" 候选) 与 anthropic ("" 候选 — 同一 URL,
    /// 跨族去重只发一次, expect(1) 钉死) 双 ok/auth, detail 提示换 key;
    /// responses 镜像 openai 行 + 注记拼接.
    #[tokio::test]
    async fn probe_origin_tier2_auth_401() {
        let mut server = mockito::Server::new_async().await;
        mock_default_model_gets(&mut server, (401, ""), (404, ""), (404, ""), (404, "")).await;
        mget(&mut server, "/api/tags", 404, "", 1).await;
        mpost(&mut server, "/v1/chat/completions", 404, 1).await;
        mpost(&mut server, "/v1beta/models:generateContent", 404, 1).await;
        // anthropic 族: /anthropic/v1/models 404 + /v1/models 401 → Auth 命中
        // (tier2 > absent), 不进 tier3.
        let an_never = mpost(&mut server, "/anthropic/v1/messages", 400, 0).await;

        let resp = probe(&server, "sk-bad", &[]).await;

        let oa = &resp.faces[0];
        assert_eq!(oa.status, OriginFaceStatus::Ok);
        assert_eq!(oa.evidence, Some(OriginFaceEvidence::Auth));
        assert_eq!(oa.uri.as_deref(), Some("/v1"));
        assert!(oa.models.is_none());
        let d = oa.detail.as_deref().unwrap();
        assert!(
            d.contains("401") && d.contains("api_key"),
            "auth detail: {d}"
        );

        let an = &resp.faces[1];
        assert_eq!(an.status, OriginFaceStatus::Ok);
        assert_eq!(an.evidence, Some(OriginFaceEvidence::Auth));
        assert_eq!(
            an.uri.as_deref(),
            Some(""),
            "anthropic 的 '' 候选 = /v1/models"
        );

        assert_eq!(resp.faces[2].status, OriginFaceStatus::Absent);
        assert_eq!(resp.faces[3].status, OriginFaceStatus::Absent);

        let r = &resp.faces[4];
        assert_eq!(r.status, OriginFaceStatus::Ok);
        assert_eq!(r.evidence, Some(OriginFaceEvidence::Auth));
        let rd = r.detail.as_deref().unwrap();
        assert!(rd.contains("401") && rd.contains("api_key"), "{rd}");
        assert!(rd.ends_with("与 OpenAI 共用 /v1, 探测无法区分"), "{rd}");

        an_never.assert_async().await;
    }

    // ─── ③b 融合不变式 (probe ✓ ⇒ verify ✓) ───────────────────────────

    /// 回归钉 (验收 review major-1): 发现矩阵 ok 行物化的端点三元组, 经
    /// `verify_endpoint_upstream` 必须**复现被探测 URL** (probe ✓ ⇒ verify ✓,
    /// 同 URL 各 GET 一次 — mockito expect 2). gemini 的 `/v1beta` 曾是面候选
    /// (base 座 = origin+/v1beta), 而 verify/fetch 恒自拼 `/v1beta` → 双版本段
    /// 404; 折叠进 models_path 后 base 座 = origin. v1 族 (cu 布局断言) 与
    /// anthropic (base 段) 同型断言各一条, 锁死三族分派不变式.
    #[tokio::test]
    async fn probe_origin_ok_rows_materialize_to_verify_consistent_endpoints() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        // 三族 ok: openai 裸根 (GET /models, cu "") / anthropic 面 (GET
        // /anthropic/v1/models, base=origin+/anthropic) / gemini (GET
        // /v1beta/models, base=origin). 每个端点被 probe 与 verify 各 GET 一次.
        mget(&mut server, "/v1/models", 404, "", 1).await;
        mget(&mut server, "/models", 200, r#"{"data":[{"id":"oa"}]}"#, 2).await;
        mget(
            &mut server,
            "/anthropic/v1/models",
            200,
            r#"{"data":[{"id":"an","type":"model"}]}"#,
            2,
        )
        .await;
        mget(
            &mut server,
            "/v1beta/models",
            200,
            r#"{"models":[{"name":"gem"}]}"#,
            2,
        )
        .await;
        mget(&mut server, "/api/tags", 404, "", 1).await;
        mpost(&mut server, "/v1/chat/completions", 404, 0).await;
        mpost(&mut server, "/anthropic/v1/messages", 404, 0).await;
        mpost(&mut server, "/v1beta/models:generateContent", 404, 0).await;

        let resp = probe(&server, "", &[]).await;

        let cases = [
            (&resp.faces[0], Protocol::OpenAI, format!("{base}/models")),
            (
                &resp.faces[1],
                Protocol::Anthropic,
                format!("{base}/anthropic/v1/models"),
            ),
            (
                &resp.faces[2],
                Protocol::Gemini,
                format!("{base}/v1beta/models"),
            ),
        ];
        for (face, proto, probed_url) in cases {
            assert_eq!(face.status, OriginFaceStatus::Ok, "{}", face.protocol);
            let v = super::super::models::verify_endpoint_upstream(
                &reqwest::Client::new(),
                face.base_url.as_deref().unwrap_or_default(),
                face.common_uri.as_deref(),
                proto,
                "",
            )
            .await;
            let o = &v.probes[0];
            assert_eq!(
                o.status,
                super::super::models::ProbeStatus::Ok,
                "{}: verify 必须复现被探测 URL — urls {:?} vs probed {probed_url}",
                face.protocol,
                o.urls
            );
            assert_eq!(o.urls, vec![probed_url], "{}", face.protocol);
        }
    }

    // ─── ④ wildcard 宿主 (主探测与对照同状态) ──────────────────────────

    /// POST 主探测 400 且对照也 400 → wildcard/soft-404 宿主, 无信号 →
    /// absent (tier3 命中必须配对照 404).
    #[tokio::test]
    async fn probe_origin_wildcard_same_status_no_signal() {
        let mut server = mockito::Server::new_async().await;
        mock_default_model_gets(&mut server, (404, ""), (404, ""), (404, ""), (404, "")).await;
        mget(&mut server, "/api/tags", 404, "", 1).await;
        mpost(&mut server, "/v1/chat/completions", 404, 1).await;
        mpost(&mut server, "/anthropic/v1/messages", 400, 1).await;
        mcontrol(&mut server, "/anthropic/v1/", 400, 1).await;
        mpost(&mut server, "/v1beta/models:generateContent", 404, 1).await;

        let resp = probe(&server, "", &[]).await;

        for i in 0..4 {
            let f = &resp.faces[i];
            assert_eq!(f.status, OriginFaceStatus::Absent, "faces[{i}]");
            assert!(f.uri.is_none() && f.base_url.is_none());
            assert!(f.detail.is_none(), "absent 行 detail 必 null");
        }
        assert_eq!(resp.faces[4].status, OriginFaceStatus::Absent);
        assert_eq!(
            resp.faces[4].detail.as_deref(),
            Some("与 OpenAI 共用探测路径, 探测无法区分")
        );
    }

    // ─── ⑤ 归一化 (输入 …/anthropic → typed_face_stripped + 按剥离 origin 探测) ──

    #[tokio::test]
    async fn probe_origin_normalization_strips_typed_face() {
        let mut server = mockito::Server::new_async().await;
        mock_default_model_gets(
            &mut server,
            (
                200,
                r#"{"object":"list","data":[{"id":"mimo-1","object":"model"}]}"#,
            ),
            (404, ""),
            (404, ""),
            (404, ""),
        )
        .await;
        mget(&mut server, "/api/tags", 404, "", 1).await;
        mpost(&mut server, "/anthropic/v1/messages", 400, 1).await;
        mcontrol(&mut server, "/anthropic/v1/", 404, 1).await;
        mpost(&mut server, "/v1beta/models:generateContent", 404, 1).await;

        // handler 同款链路: 校验(略) → 归一化 → 探测.
        let raw = format!("{}/anthropic", server.url());
        let (origin, stripped) = normalize_origin(&raw).unwrap();
        let resp = probe_origin_upstream(&reqwest::Client::new(), &origin, stripped, "", &[]).await;

        assert_eq!(resp.origin, server.url(), "canonical origin = 剥离后");
        assert_eq!(resp.typed_face_stripped.as_deref(), Some("/anthropic"));
        // 探测按剥离 origin: /v1/models 直接命中 (不是 /anthropic/v1/models).
        assert_eq!(resp.faces[0].status, OriginFaceStatus::Ok);
        assert_eq!(resp.faces[0].uri.as_deref(), Some("/v1"));
        // 剥离的 /anthropic 作为 anthropic 族候选被重新探测 → tier3 existence.
        assert_eq!(resp.faces[1].evidence, Some(OriginFaceEvidence::Existence));
    }

    // ─── ⑥ extra_faces (GLM 形状) ──────────────────────────────────────

    /// GLM coding plan 形状: extra face /api/coding/paas/v4 (openai 族, 前插
    /// 优先探测) GET /models 200 → openai ok. 附 "responses" 别名 extra 归
    /// openai 族 (共用面语义) — 其候选参与探测但不改胜者 (404).
    #[tokio::test]
    async fn probe_origin_extra_faces_glm_shape() {
        let mut server = mockito::Server::new_async().await;
        mget(
            &mut server,
            "/api/coding/paas/v4/models",
            200,
            r#"{"object":"list","data":[{"id":"glm-4.6","object":"model"}]}"#,
            1,
        )
        .await;
        mget(&mut server, "/resp/face/models", 404, "", 1).await;
        mock_default_model_gets(&mut server, (404, ""), (404, ""), (404, ""), (404, "")).await;
        mget(&mut server, "/api/tags", 404, "", 1).await;
        mpost(&mut server, "/anthropic/v1/messages", 404, 1).await;
        mpost(&mut server, "/v1beta/models:generateContent", 404, 1).await;
        let oa_never = mpost(&mut server, "/v1/chat/completions", 404, 0).await;

        let extras = vec![
            (Protocol::OpenAI, "/api/coding/paas/v4".to_string()),
            (Protocol::OpenAIResponses, "/resp/face".to_string()),
        ];
        let resp = probe(&server, "", &extras).await;

        let oa = &resp.faces[0];
        assert_eq!(oa.status, OriginFaceStatus::Ok);
        assert_eq!(oa.uri.as_deref(), Some("/api/coding/paas/v4"));
        // v1 族深面 (#332 融合): base 座 = origin, 深面前缀作为 cu 布局断言.
        assert_eq!(oa.base_url.as_deref(), Some(server.url().as_str()));
        assert_eq!(oa.common_uri.as_deref(), Some("/api/coding/paas/v4"));
        assert_eq!(oa.models.as_ref().unwrap(), &strs(&["glm-4.6"]));

        let r = &resp.faces[4];
        assert_eq!(r.uri.as_deref(), Some("/api/coding/paas/v4"));
        assert_eq!(r.common_uri.as_deref(), Some("/api/coding/paas/v4"));
        assert_eq!(r.models.as_ref().unwrap(), &strs(&["glm-4.6"]));
        assert_eq!(
            r.detail.as_deref(),
            Some("与 OpenAI 共用 /api/coding/paas/v4, 探测无法区分")
        );

        oa_never.assert_async().await;
    }

    // ─── ⑦ 连接失败 → error 行 (含 SEC 不泄漏 + responses 镜像) ────────

    /// 死 origin (conn refused): 四族全 error (detail 净化含 "request failed"),
    /// tier3 不发起 (error ≠ absent); 序列化响应不含 api_key (SEC);
    /// responses 镜像 error + 注记拼接.
    #[tokio::test]
    async fn probe_origin_connection_failure_error_rows() {
        let api_key = "sk-origin-leaky-key-4321";
        let resp = probe_origin_upstream(
            &reqwest::Client::new(),
            "http://127.0.0.1:9",
            None,
            api_key,
            &[],
        )
        .await;

        for i in 0..4 {
            let f = &resp.faces[i];
            assert_eq!(f.status, OriginFaceStatus::Error, "faces[{i}]");
            assert!(
                f.uri.is_none()
                    && f.base_url.is_none()
                    && f.common_uri.is_none()
                    && f.models.is_none()
            );
            let d = f.detail.as_deref().unwrap();
            assert!(d.contains("request failed"), "faces[{i}] detail: {d}");
        }
        let r = &resp.faces[4];
        assert_eq!(r.status, OriginFaceStatus::Error);
        let rd = r.detail.as_deref().unwrap();
        assert!(rd.contains("request failed"), "{rd}");
        assert!(rd.ends_with("与 OpenAI 共用探测路径, 探测无法区分"), "{rd}");

        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            !json.contains(api_key),
            "probe-origin response must not leak api_key: {json}"
        );
    }

    // ─── ⑧ 空 api_key 畅通 (ollama 本地) ───────────────────────────────

    /// api_key 为空: 全部 auth header 跳过 (ollama 本地场景), anthropic-version
    /// 恒加; /api/tags 200 → ollama ok/models.
    #[tokio::test]
    async fn probe_origin_empty_key_ollama_local() {
        let mut server = mockito::Server::new_async().await;
        let tags = server
            .mock("GET", "/api/tags")
            .match_header("authorization", mockito::Matcher::Missing)
            .match_header("x-api-key", mockito::Matcher::Missing)
            .match_header("x-goog-api-key", mockito::Matcher::Missing)
            .match_header("anthropic-version", super::super::auth::ANTHROPIC_VERSION)
            .with_status(200)
            .with_body(r#"{"models":[{"name":"llama3"}]}"#)
            .expect(1)
            .create_async()
            .await;
        mock_default_model_gets(&mut server, (404, ""), (404, ""), (404, ""), (404, "")).await;
        // tier3 (openai/anthropic/gemini absent, ollama ok): 全 404 → 无信号.
        mpost(&mut server, "/v1/chat/completions", 404, 1).await;
        mpost(&mut server, "/anthropic/v1/messages", 404, 1).await;
        mpost(&mut server, "/v1beta/models:generateContent", 404, 1).await;

        let resp = probe(&server, "", &[]).await;
        let o = &resp.faces[3];
        assert_eq!(o.status, OriginFaceStatus::Ok);
        assert_eq!(o.evidence, Some(OriginFaceEvidence::Models));
        assert_eq!(o.models.as_ref().unwrap(), &strs(&["llama3"]));
        tags.assert_async().await;
    }

    // ─── 纯函数: normalize_origin 矩阵 ──────────────────────────────────

    #[test]
    fn normalize_origin_matrix() {
        let norm = |s: &str| normalize_origin(s).unwrap();
        // host-only / 多段路径: 原样返回.
        assert_eq!(
            norm("https://api.xiaomimimo.com"),
            ("https://api.xiaomimimo.com".into(), None)
        );
        assert_eq!(
            norm("http://127.0.0.1:18787"),
            ("http://127.0.0.1:18787".into(), None)
        );
        assert_eq!(
            norm("https://host/foo/bar"),
            ("https://host/foo/bar".into(), None)
        );
        // 单段已知面尾段剥离.
        assert_eq!(
            norm("https://api.xiaomimimo.com/anthropic"),
            (
                "https://api.xiaomimimo.com".into(),
                Some("/anthropic".into())
            )
        );
        assert_eq!(
            norm("https://api.openai.com/v1"),
            ("https://api.openai.com".into(), Some("/v1".into()))
        );
        assert_eq!(
            norm("https://host/v1beta"),
            ("https://host".into(), Some("/v1beta".into()))
        );
        assert_eq!(
            norm("https://host/foo/anthropic"),
            ("https://host/foo".into(), Some("/anthropic".into()))
        );
        // 双段后缀整体剥离 (优先于单段规则).
        assert_eq!(
            norm("https://ark.cn.volces.com/api/anthropic"),
            (
                "https://ark.cn.volces.com".into(),
                Some("/api/anthropic".into())
            )
        );
        // 剥离只做一次 (不递归).
        assert_eq!(
            norm("https://host/v1/v1"),
            ("https://host/v1".into(), Some("/v1".into()))
        );
        // 大小写敏感 (V1 不剥).
        assert_eq!(norm("https://host/V1"), ("https://host/V1".into(), None));
        // query / fragment → Err.
        assert!(normalize_origin("https://host?x=1").is_err());
        assert!(normalize_origin("https://host/p#frag").is_err());
    }

    // ─── 纯函数: parse_extra_face 规则 ──────────────────────────────────

    #[test]
    fn parse_extra_face_rules() {
        assert_eq!(
            parse_extra_face("openai", "/v1"),
            Some((Protocol::OpenAI, "/v1".to_string()))
        );
        assert_eq!(
            parse_extra_face("anthropic", "/api/anthropic"),
            Some((Protocol::Anthropic, "/api/anthropic".to_string()))
        );
        // "responses" 别名 (与响应 faces 行 wire 名对齐) 与 serde 枚举名等价.
        assert_eq!(
            parse_extra_face("responses", "/r"),
            Some((Protocol::OpenAIResponses, "/r".to_string()))
        );
        assert_eq!(
            parse_extra_face("openai-responses", "/r"),
            Some((Protocol::OpenAIResponses, "/r".to_string()))
        );
        // 未知 protocol / uri 非 '/' 开头 (含空串) → 丢弃.
        assert_eq!(parse_extra_face("bedrock", "/x"), None);
        assert_eq!(parse_extra_face("openai", "no-slash"), None);
        assert_eq!(parse_extra_face("openai", ""), None);
    }
}
