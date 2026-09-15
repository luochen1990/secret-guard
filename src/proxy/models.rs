//! Router provider 的模型列表合成 (GET /models, #196) + Provider 协议探测
//! (probe 端点).
//!
//! # 职责边界
//!
//! 对 router provider (`ProviderKind::Router`) 的**模型列表类 GET 请求**本地合成响应,
//! 不进转发链: `advertise(M) ⟺ 别名(M) ∨ (resolve_route(M)=(T,E) ∧ E ∈ cached(T))`.
//! Direct provider 的 /models 透传行为完全不受影响 (D6).
//!
//! # 冻结语义 (issue #196, N1-N6 / D1-D6)
//!
//! - **N1 合并过滤**: 上游模型 M 被广告 ⟺ `resolve_route(router, M)` 解析到 (T, E)
//!   且 E ∈ cached(T) 的清单 (E = model_rewrite ∨ M; **广告名是 M** — 客户端可寻址名).
//! - **N2 列表序**: 别名 (exact pattern, 路由表序, 去重) 在前 ∪ 过滤后上游模型在后
//!   (上游段 = provider walk 序 × 上游响应数组序; §3.2 验收用例锁定 — 故缓存条目
//!   用 Vec 保序而非 BTreeSet).
//! - **N3 缓存**: per-Direct-provider (`{models, fetched_at}`), union 查询时现算, 不做
//!   flat union 缓存.
//! - **N4**: TTL 300s 常量 (不进配置); serve-stale-on-error (刷新失败保留旧数据);
//!   single-flight (`snapshot_refreshing` 持锁串行 refresh, 等锁者随后读新鲜缓存);
//!   懒加载 (首个查询触发 fetch); **失败退避** (fetch 失败后 30s 窗口内的过期/
//!   从未成功条目不再重试 — 查询立即 serve stale / 无贡献, 不阻塞不占锁重试,
//!   防 dead target 逐查询阻塞 × 全局锁串行的可用性放大).
//! - **N5**: 所有条目 `owned_by: "router"` (统一, 不泄漏内部 provider id).
//! - **N6 顶层 wildcard gate**: 被查询 router 的**启用**路由中存在含 `*` 的
//!   model_pattern 才 fetch+merge, 否则只返回别名 (零上游请求). gate 只看顶层 —
//!   exact-only 顶层 ⇒ 准入名 ⊆ 别名集 ⇒ merge 贡献 ≡ ∅.
//! - **D1**: wildcard pattern 本身不列入响应 (其覆盖的真实模型名经 merge 自然出现).
//! - **D2**: 别名悬挂过滤 — exact pattern 经 `resolve_route` 校验可解析才广告
//!   (advertised ⇒ resolvable).
//! - **D5**: DAG 不记录 /models 响应, 也不记录上游 cache-fill fetch (非 LLM 调用).
//!
//! # 端点判定 (按 ingress 协议)
//!
//! - o / r / a: `rest ∈ {"/models", "/v1/models"}`
//! - g: `rest ∈ {"/models", "/v1/models", "/v1beta/models"}`
//! - l: `rest == "/api/tags"`
//!
//! query 参数忽略 (rest 不含 query string). 非 GET / 非匹配路径由 dispatch 落回原
//! 转发流程, 行为零变化.
//!
//! # 上游 fetch (ROB-*, best-effort 永不 fail 查询)
//!
//! 按目标 provider **自身 protocol** (非 ingress 协议) 请求:
//! - OpenAI / Responses / Anthropic: `GET {base_url}/v1/models`, shape `{data:[{id}]}`
//! - Gemini: `GET {base_url}/v1beta/models`, shape `{models:[{name:"models/X"}]}`
//!   (剥 `models/` 前缀)
//! - Ollama: `GET {base_url}/api/tags`, shape `{models:[{name}]}`
//!
//! headers 复用 `apply_provider_auth`; 整体 10s 超时. 失败 / 超时 / 缺字段 /
//! 非 2xx → 该 provider 跳过并 `warn!` (只含 provider id + reason, 永不含
//! key/secret), 绝不 fail 整个 /models 查询.
//!
//! # 锁纪律
//!
//! walk (可达集快照, 触碰 ProviderTable 读锁) 与 api_key 预解析
//! (`effective_api_key`: api_key_file 路径是同步文件读) 都必须在持有缓存 Mutex
//! **之前**完成 — `snapshot_refreshing` 持锁跨 await 期间不得再取 ProviderTable
//! 读锁 (锁序: 先快照后加缓存锁), 也不得执行同步文件 IO (阻塞所有 router 的
//! /models 查询, #196 review L2).
//!
//! # 归属 (组合根先例)
//!
//! `ModelListCache` 是纯数据 store (无 proxy 行为依赖), 经 `crate::proxy` re-export
//! 给 `crate::state::AppState` 聚合持有 — 组合根先例同 `api_keys` (state 聚合各
//! feature 模块的 store 类型), 详见 `src/state.rs` 字段注释.
//!
//! # Provider 协议探测 (`probe_provider_upstream`)
//!
//! `POST /api/providers/probe` 的核心 (handler 薄壳在 `web/api/providers.rs`,
//! base_url 合法性校验在 handler 侧): 对任意 base_url 并行探测 3 个候选端点,
//! 输出固定 4 项 outcome (顺序 openai / anthropic / gemini / ollama) + 推荐.
//! 判定规则:
//! - `/v1/models` 一路判两族 (openai + anthropic 共用端点, 靠 data 条目的判别
//!   字段分家, 见 `classify_v1_family`); 401|403 → 双 auth_failed, 404|405 →
//!   双 absent, 其余失败 (连接/超时/超大 body/非法 JSON/其他非 2xx) → 双 error.
//! - `/v1beta/models` (gemini) / `/api/tags` (ollama) 独立判定: 2xx + shape
//!   解析成功 → ok; 401|403 → auth_failed; 404|405 → absent; 其余 → error.
//! - 探测失败是**数据不是 HTTP 错误** (handler 对探测结果恒 200).
//! - 推荐序: openai (ollama 双命中附 note) > anthropic > gemini (no-codec
//!   note) > ollama (同 note); 无任何 ok → recommended null.
//!
//! 依赖方向: web/api/providers → 本模块 已在根 AGENTS.md "已接受的例外" 登记
//! (probe 端点复用上游探测基建; 行为借用 — 探测执行出站 HTTP, 非纯数据/
//! 纯函数, handler 只是薄壳无独立实现).

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use serde::Serialize;
use serde_json::json;

use crate::provider::{DirectProvider, Protocol, Provider, ProviderKind, ProviderTable};
use crate::state::AppState;

/// 缓存 TTL (N4: 300s 常量, 不进配置).
///
/// test 构建用 500ms 让单测可覆盖 "TTL 过期后重取" 与 "serve-stale-on-error" 路径
/// (集成测试链接的是非 cfg(test) 的 lib, 仍是 300s — 缓存命中断言依赖它; 测试 TTL
/// 留足余量防 CI 调度延迟把 TTL 内的断言窗口拖过期).
#[cfg(not(test))]
const MODEL_LIST_TTL: Duration = Duration::from_secs(300);
#[cfg(test)]
const MODEL_LIST_TTL: Duration = Duration::from_millis(500);

/// 上游模型列表 fetch 的整体超时 (brief §2.2 冻结常量: **整体** 覆盖 send + body
/// 读取全程 — `send()` 在响应头到达即完成, body 停滞若无超时会**永久持有缓存锁**,
/// 连带所有 router 的 /models 查询挂起, 见 `snapshot_refreshing` 锁语义).
/// test 构建用 500ms 让 "上游停滞超时" 路径可在单测覆盖.
#[cfg(not(test))]
const MODEL_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const MODEL_FETCH_TIMEOUT: Duration = Duration::from_millis(500);

/// fetch 失败后的退避窗口 (M1): 窗口内的过期/从未成功条目不再重试 — 查询立即
/// serve stale (或无贡献), 不阻塞不占锁重试. 防 dead target 逐查询阻塞
/// (每次 ≤ MODEL_FETCH_TIMEOUT) × 全局缓存锁串行的可用性放大.
/// test 构建用 300ms 让退避路径可在单测覆盖.
#[cfg(not(test))]
const MODEL_FETCH_BACKOFF: Duration = Duration::from_secs(30);
#[cfg(test)]
const MODEL_FETCH_BACKOFF: Duration = Duration::from_millis(300);

/// 上游 /models 响应 body 的累积上限 (防御性: 模型清单正常是 KB 量级, 破损上游
/// 不应能借 /models 查询撑爆内存; 超限按该 provider fetch 失败处理).
const MAX_MODELS_BODY: usize = 4 * 1024 * 1024;

/// 可达 Direct 目标: id + 构造快照 + 锁外预解析的 api_key (`advertised_names`
/// 组装, 供 `snapshot_refreshing` 消费). 命名结构体防 id/api_key 位置错换.
struct FetchTarget {
    id: String,
    direct: DirectProvider,
    api_key: String,
}

/// per-Direct-provider 的上游模型清单缓存 (AppState 持有 Arc, 所有 router 共享).
///
/// single-flight: `snapshot_refreshing` 持有内部 Mutex 串行执行过期项 refresh,
/// 并发查询等锁者获得锁后直接读新鲜缓存, 不 stampede 上游.
#[derive(Debug, Default)]
pub struct ModelListCache {
    inner: tokio::sync::Mutex<HashMap<String, CacheEntry>>,
}

/// 单个 provider 的缓存项. `models` 保持**上游响应数组序** (N2 合并段顺序的
/// 一半; §3.2 验收用例锁定, 故是 Vec 而非 BTreeSet — 排序会重排上游序).
///
/// 两个时间字段分工 (M1): `fetched_at` 记**成功**时间 (TTL 起点; `None` = 从未
/// 成功 — serve-stale 无数据, 该 provider 无贡献); `last_attempt` 记**尝试**
/// 时间 (成功或失败, 失败退避窗口 `MODEL_FETCH_BACKOFF` 的起点). 条目只在首次
/// 尝试后存在 — 无条目 = 从未尝试 = 懒加载必须试, 无退避约束.
#[derive(Debug, Clone)]
struct CacheEntry {
    models: Vec<String>,
    fetched_at: Option<Instant>,
    last_attempt: Instant,
}

impl ModelListCache {
    pub fn new() -> Self {
        Self {
            inner: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// 返回 per-provider 缓存清单, 顺带刷新过期项 (single-flight).
    ///
    /// - `targets` 必须是**先行完成**的可达 Direct 快照, 且每项的 api_key 已在锁外
    ///   预解析 (锁纪律见模块头部; warn-once 语义在 `effective_api_key` 内, 与调用
    ///   点无关);
    /// - 刷新判定 (M1): 条目缺席 → 懒加载必须试; `fetched_at` 在 TTL 内 → 复用;
    ///   过期/从未成功 **且** 距 `last_attempt` 超过退避窗口 → 重试. 退避窗口内的
    ///   查询**立即** serve stale (或无贡献), 不 fetch — 不阻塞、不占锁重试, 防
    ///   dead target 逐查询阻塞 (≤MODEL_FETCH_TIMEOUT × 全局锁串行放大);
    /// - 成功 → 覆写 (models, Some(now), now); 失败 → 只推进 `last_attempt`
    ///   (serve-stale 保留旧数据; 从未成功则登记空贡献条目) + warn (只含
    ///   provider id + reason).
    async fn snapshot_refreshing(
        &self,
        client: &reqwest::Client,
        targets: &[FetchTarget],
    ) -> HashMap<String, Vec<String>> {
        let mut map = self.inner.lock().await;
        let mut out = HashMap::new();
        for FetchTarget {
            id,
            direct,
            api_key,
        } in targets
        {
            let needs_refresh = match map.get(id) {
                // 无条目 = 从未尝试 (懒加载首查), 必须试.
                None => true,
                Some(e) => {
                    let stale = e.fetched_at.is_none_or(|t| t.elapsed() >= MODEL_LIST_TTL);
                    stale && e.last_attempt.elapsed() >= MODEL_FETCH_BACKOFF
                }
            };
            if needs_refresh {
                match fetch_model_list(client, api_key, direct).await {
                    Ok(models) => {
                        tracing::debug!(
                            provider_id = %id,
                            count = models.len(),
                            "model list refreshed"
                        );
                        let now = Instant::now();
                        map.insert(
                            id.clone(),
                            CacheEntry {
                                models,
                                fetched_at: Some(now),
                                last_attempt: now,
                            },
                        );
                    }
                    Err(reason) => {
                        // serve-stale-on-error (N4) + 失败退避 (M1): 保留旧数据/旧成功
                        // 时间, 只推进 last_attempt (退避窗口起点). warn 不含
                        // key/secret (SEC 纪律).
                        tracing::warn!(
                            provider_id = %id,
                            reason = %reason,
                            "model list fetch failed; serving stale entry if any"
                        );
                        // 存在则推进 last_attempt; 缺席则插入空贡献条目 (退避记账,
                        // 旧数据/旧成功时间在 Some 路径下原样保留).
                        let now = Instant::now();
                        map.entry(id.clone())
                            .and_modify(|e| e.last_attempt = now)
                            .or_insert_with(|| CacheEntry {
                                models: Vec::new(),
                                fetched_at: None,
                                last_attempt: now,
                            });
                    }
                }
            }
            // 只有曾成功过的条目才有贡献 (从未成功 → 不出现在快照).
            if let Some(entry) = map.get(id)
                && entry.fetched_at.is_some()
            {
                out.insert(id.clone(), entry.models.clone());
            }
        }
        out
    }
}

/// rest 路径是否命中 ingress 协议的模型列表端点 (见模块头部端点判定表).
///
/// rest 形态容错: axum 0.8 `{*rest}` 捕获不含前导 `/` (实测, 见 `ForwardPath` 注释),
/// 此处统一剥掉前导 `/` 后匹配 — 两种形态 (`"/v1/models"` / `"v1/models"`) 都接受.
pub(super) fn is_model_list_path(ingress: Protocol, rest: &str) -> bool {
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    match ingress {
        Protocol::OpenAI | Protocol::Anthropic | Protocol::OpenAIResponses => {
            matches!(rest, "models" | "v1/models")
        }
        Protocol::Gemini => matches!(rest, "models" | "v1/models" | "v1beta/models"),
        Protocol::Ollama => rest == "api/tags",
    }
}

/// N6 gate: 被查询 router 的启用路由中是否存在含 `*` 的 model_pattern.
/// 只看顶层 (不 walk 链), exact-only ⇒ 零 fetch.
fn needs_upstream_merge(entry: &Provider) -> bool {
    match &entry.kind {
        ProviderKind::Router(router) => router
            .routes
            .iter()
            .any(|route| route.priority.is_some() && route.model_pattern.contains('*')),
        ProviderKind::Direct(_) => false,
    }
}

/// N2 别名段: 启用路由中不含 `*` 的 model_pattern, 路由表序 + 去重;
/// D2: 经 `resolve_route(entry, P)` 校验可解析才收录 (advertised ⇒ resolvable).
fn alias_names(table: &ProviderTable, entry: &Provider) -> Vec<String> {
    let ProviderKind::Router(router) = &entry.kind else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for route in &router.routes {
        if route.priority.is_none() || route.model_pattern.contains('*') {
            continue; // 禁用路由不广告; wildcard pattern 不是别名 (D1)
        }
        // 去重短路: 重复 pattern 不再重复 resolve.
        if seen.insert(route.model_pattern.clone())
            && table
                .resolve_route(entry.clone(), &route.model_pattern)
                .is_ok()
        {
            out.push(route.model_pattern.clone());
        }
    }
    out
}

/// 可达集 walk: 从 router 出发沿**所有启用路由**的 target 递归 (get_effective;
/// visited-set 防环; 不依赖请求 model), 收集链尾 Direct provider (id + 构造快照).
/// 悬空 / disabled 的 target 分支直接跳过 (不贡献, 也不下钻).
///
/// 顺序 = DFS preorder 按路由表序 (首达序), 决定 N2 合并段的 provider 序.
fn walk_reachable_directs(
    table: &ProviderTable,
    entry: &Provider,
) -> Vec<(String, DirectProvider)> {
    fn visit(
        table: &ProviderTable,
        provider: &Provider,
        visited: &mut HashSet<String>,
        out: &mut Vec<(String, DirectProvider)>,
    ) {
        let ProviderKind::Router(router) = &provider.kind else {
            return;
        };
        for route in &router.routes {
            if route.priority.is_none() {
                continue;
            }
            let Some(next) = table.get_effective(&route.target) else {
                continue; // 悬空 / decision-disabled: 分支终止
            };
            if !next.enabled || !visited.insert(next.id.clone()) {
                continue; // entry-level disabled (不贡献也不下钻) / 已访问 (防环)
            }
            match next.kind {
                ProviderKind::Direct(direct) => out.push((next.id, direct)),
                ProviderKind::Router(_) => visit(table, &next, visited, out),
            }
        }
    }
    let mut visited = HashSet::from([entry.id.clone()]);
    let mut out = Vec::new();
    visit(table, entry, &mut visited, &mut out);
    out
}

/// 缓存快照 → 合并候选序: 按 walk 序 × 各 provider 清单的上游序拼接, 去重
/// (先出现者占位). 过滤 (N1) 由调用方在消费时执行.
fn union_from_cache<'a>(
    ids: impl Iterator<Item = &'a str>,
    cached: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for id in ids {
        for model in cached.get(id).into_iter().flatten() {
            if seen.insert(model.clone()) {
                out.push(model.clone());
            }
        }
    }
    out
}

/// N1 单点判定: `advertise(M) ⟺ resolve_route(M)=(T,E) ∧ E ∈ cached(T)`
/// (E = model_rewrite ∨ M; 解析失败 — NoMatch / 悬空 / disabled / 环 — 不广告).
fn n1_accepts(
    table: &ProviderTable,
    entry: &Provider,
    model: &str,
    cached: &HashMap<String, Vec<String>>,
) -> bool {
    match table.resolve_route(entry.clone(), model) {
        Ok(resolved) => {
            let egress = resolved.model_rewrite.unwrap_or_else(|| model.to_string());
            cached
                .get(&resolved.id)
                .is_some_and(|list| list.iter().any(|m| m == &egress))
        }
        Err(_) => false,
    }
}

/// 完整广告序 (别名段 + 合并段): FWD-7 的可测核心.
///
/// N6 gate 短路在 alias_names 之后、walk 之前 — exact-only router 零上游请求.
pub(super) async fn advertised_names(state: &AppState, entry: &Provider) -> Vec<String> {
    let aliases = alias_names(&state.providers, entry);
    if !needs_upstream_merge(entry) {
        return aliases;
    }
    // 锁纪律 (模块头部): 快照 + api_key 预解析均在缓存锁外.
    // 代价: api_key_file 配置的 provider 每次 /models 查询读一次文件 (锁外,
    // 通常 <1ms — 旧形态仅在 refresh 时读, 频率被 TTL/退避压低).
    let targets = walk_reachable_directs(&state.providers, entry)
        .into_iter()
        .map(|(id, direct)| FetchTarget {
            api_key: direct.effective_api_key(&id),
            id,
            direct,
        })
        .collect::<Vec<_>>();
    let cached = state
        .model_lists
        .snapshot_refreshing(&state.upstream, &targets)
        .await;
    let seen: HashSet<String> = aliases.iter().cloned().collect();
    let mut out = aliases;
    for model in union_from_cache(targets.iter().map(|t| t.id.as_str()), &cached) {
        // N2 去重: union 内部已去重, contains 只需挡与别名同名的上游模型.
        if !seen.contains(&model) && n1_accepts(&state.providers, entry, &model, &cached) {
            out.push(model);
        }
    }
    out
}

/// dispatch 拦截入口: 合成 ingress 协议 shape 的 200 响应
/// (content-type: application/json + NO_STORE). 永不失败 (ROB).
pub(super) async fn handle_router_models(
    state: &AppState,
    ingress: Protocol,
    entry: Provider,
) -> Response<Body> {
    let names = advertised_names(state, &entry).await;
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json");
    for (name, value) in crate::state::NO_STORE {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from(build_models_body(ingress, &names)))
        .expect("static response parts are valid")
}

/// 按 provider 自身 protocol fetch 模型清单 (best-effort, 错误消息只含 id + reason,
/// 永不含 key/secret — reqwest 错误经 `upstream_error_brief` 净化, 剥 userinfo/query).
///
/// `api_key` 由调用方在缓存锁外预解析传入 (见模块头部锁纪律).
async fn fetch_model_list(
    client: &reqwest::Client,
    api_key: &str,
    direct: &DirectProvider,
) -> Result<Vec<String>, String> {
    let path = match direct.protocol {
        Protocol::OpenAI | Protocol::OpenAIResponses | Protocol::Anthropic => "/v1/models",
        Protocol::Gemini => "/v1beta/models",
        Protocol::Ollama => "/api/tags",
    };
    let url = super::helpers::build_upstream_url(&direct.base_url, path);
    let mut headers = HeaderMap::new();
    super::auth::apply_provider_auth(&mut headers, api_key, direct.protocol);
    if direct.protocol == Protocol::Anthropic {
        headers.insert(
            "anthropic-version",
            HeaderValue::from_static(super::auth::ANTHROPIC_VERSION),
        );
    }
    let (status, body) = fetch_status_and_body(client, &url, headers).await?;
    if !status.is_success() {
        return Err(status_detail(status));
    }
    parse_model_ids(direct.protocol, &body)
}

/// GET 上游 + 有界累积 body, **整体**超时覆盖全程 (send → 状态行 → body 读毕).
///
/// `fetch_model_list` (router /models 缓存填充) 与 `probe_provider_upstream`
/// (协议探测) 的共享防御层: 停滞上游超时掐断 (防 fetch 永久持有缓存锁 / 探测
/// 挂起), 破损上游有界累积 (防撑爆内存, 见 MAX_MODELS_BODY), 错误串经
/// `upstream_error_brief` 净化 (不含 key/secret). 成功返回 (status, body) —
/// status 判定留给调用方 (缓存填充看 is_success, 探测要分 401/404 桶).
///
/// 重构自 fetch_model_list 的两处**有意**行为差异 (提取时声明, 非回归):
/// ① 非 2xx 的 body 也读毕再判错 (探测侧 status 桶判定需要 body 一致路径;
///    上限仍是 MAX_MODELS_BODY; 推论: 非 2xx + 超大 body 时错误串是
///    "response body exceeds ..." 而非 "upstream returned NNN" — 仅日志面差异);
/// ② 非 2xx 错误串统一为纯数字 code (`upstream returned 404`, 契约示例形态)
///    — 旧形态含 reason phrase。
async fn fetch_status_and_body(
    client: &reqwest::Client,
    url: &str,
    headers: HeaderMap,
) -> Result<(StatusCode, Vec<u8>), String> {
    let request = async {
        let mut resp = client.get(url).headers(headers).send().await.map_err(|e| {
            format!(
                "request failed: {}",
                super::recorder::upstream_error_brief(&e)
            )
        })?;
        // 有界累积 (超限按失败处理 — 见 MAX_MODELS_BODY 注释).
        let mut buf = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| {
            format!(
                "body read failed: {}",
                super::recorder::upstream_error_brief(&e)
            )
        })? {
            buf.extend_from_slice(&chunk);
            if buf.len() > MAX_MODELS_BODY {
                return Err(format!("response body exceeds {} bytes", MAX_MODELS_BODY));
            }
        }
        Ok((resp.status(), buf))
    };
    tokio::time::timeout(MODEL_FETCH_TIMEOUT, request)
        .await
        .map_err(|_| "timeout".to_string())?
}

/// 尝试性解析上游 /models 响应 (ROB-*: 非法 JSON / 缺数组字段 → Err;
/// 条目缺 id/name 的元素跳过; 去重保序).
fn parse_model_ids(protocol: Protocol, body: &[u8]) -> Result<Vec<String>, String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;
    // (数组字段, 条目字段, 条目名前缀): 三族协议 shape 的全部差异收敛于此表.
    // OpenAI/Responses/Anthropic 共用 data[].id; Gemini/Ollama 共用 models[].name,
    // 前者 name 带 "models/" 前缀需剥掉. strip 为空串时 strip_prefix 恒 Some (无操作),
    // 三族共用同一条解析链. 新协议 (Bedrock/Cohere 等) 只加一行表项.
    let (array_field, item_field, strip) = match protocol {
        Protocol::OpenAI | Protocol::OpenAIResponses | Protocol::Anthropic => ("data", "id", ""),
        Protocol::Gemini => ("models", "name", "models/"),
        Protocol::Ollama => ("models", "name", ""),
    };
    let names: Vec<String> = value
        .get(array_field)
        .and_then(|d| d.as_array())
        .ok_or_else(|| format!("missing `{array_field}` array"))?
        .iter()
        .filter_map(|m| m.get(item_field).and_then(|i| i.as_str()))
        .map(|n| n.strip_prefix(strip).unwrap_or(n).to_string())
        .collect();
    // 去重保序 (上游响应数组序是 N2 合并序的一半).
    let mut seen = HashSet::new();
    Ok(names
        .into_iter()
        .filter(|n| seen.insert(n.clone()))
        .collect())
}

/// 按 ingress 协议构造响应 body (N5: owned_by 统一 "router"; Anthropic 时间戳用
/// epoch 常量; Gemini 补 `models/` 前缀).
fn build_models_body(ingress: Protocol, names: &[String]) -> String {
    match ingress {
        Protocol::OpenAI | Protocol::OpenAIResponses => json!({
            "object": "list",
            "data": names
                .iter()
                .map(|n| json!({
                    "id": n,
                    "object": "model",
                    "owned_by": "router",
                    "created": 0,
                }))
                .collect::<Vec<_>>(),
        }),
        Protocol::Anthropic => json!({
            "data": names
                .iter()
                .map(|n| json!({
                    "type": "model",
                    "id": n,
                    "display_name": n,
                    "created_at": "1970-01-01T00:00:00Z",
                }))
                .collect::<Vec<_>>(),
            "first_id": null,
            "has_more": false,
            "last_id": null,
        }),
        Protocol::Gemini => json!({
            "models": names
                .iter()
                .map(|n| json!({ "name": format!("models/{n}") }))
                .collect::<Vec<_>>(),
        }),
        Protocol::Ollama => json!({
            "models": names
                .iter()
                .map(|n| json!({ "name": n }))
                .collect::<Vec<_>>(),
        }),
    }
    .to_string()
}

// ─── Provider 协议探测 (POST /api/providers/probe 的核心) ─────────────

/// 双命中 (openai + ollama 同时 ok) 时的推荐理由 (wire 文案冻结于接口契约).
const PROBE_NOTE_DUAL_OLLAMA: &str = "Ollama native endpoint also detected. The OpenAI-compatible endpoint is recommended because secret redaction requires a codec-covered protocol (OpenAI/Anthropic/Responses).";
/// 无 codec 协议 (gemini / ollama) 被推荐时的理由 (同上, 冻结文案).
const PROBE_NOTE_NO_CODEC: &str = "No codec for this protocol: secret redaction is unavailable, and requests hitting secrets are rejected by default (on_unsupported_protocol = fail_closed).";

/// 单个协议的探测结果 (wire DTO).
#[derive(Debug, Serialize)]
pub(crate) struct ProbeOutcome {
    /// 协议名 (= `Protocol::name`, 与 `Protocol::ALL` 同步).
    pub protocol: &'static str,
    pub status: ProbeStatus,
    /// `status == ok` 时必有 (可为空数组 — data 空数组也是合法 shape); 其余 null.
    pub models: Option<Vec<String>>,
    /// `status == ok` 时 null; 其余必有 (上游 status / 家族判别 / 净化后的错误串).
    pub detail: Option<String>,
}

impl ProbeOutcome {
    /// ok 轮次: models 必有 (可为空数组), detail 必 null (字段不变量的类型化).
    fn ok(protocol: &'static str, models: Vec<String>) -> Self {
        Self {
            protocol,
            status: ProbeStatus::Ok,
            models: Some(models),
            detail: None,
        }
    }

    /// 非 ok 轮次 (auth_failed / absent / error): models 必 null, detail 必有.
    fn non_ok(protocol: &'static str, status: ProbeStatus, detail: String) -> Self {
        debug_assert!(status != ProbeStatus::Ok);
        Self {
            protocol,
            status,
            models: None,
            detail: Some(detail),
        }
    }
}

/// 探测状态 (wire 枚举, snake_case — 冻结契约).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProbeStatus {
    /// 2xx + shape 匹配 (models 必有).
    Ok,
    /// 401 | 403 — 端点存在但鉴权失败.
    AuthFailed,
    /// 404 | 405, 或 /v1/models 的 shape 指向家族另一员 — 端点不属于该协议.
    Absent,
    /// 连接失败 / 超时 / 非法 JSON / 超大 body / 其他非 2xx (detail 必有).
    Error,
}

/// 探测响应 (wire DTO). 探测失败是**数据不是 HTTP 错误** — handler 对本结构恒 200.
#[derive(Debug, Serialize)]
pub(crate) struct ProbeResponse {
    /// 固定 4 项, 顺序: openai, anthropic, gemini, ollama.
    pub probes: Vec<ProbeOutcome>,
    /// 无任何 ok 时 null.
    pub recommended: Option<&'static str>,
    /// 推荐理由, 可为 null.
    pub note: Option<&'static str>,
}

/// 探测请求的统一 headers (三路 GET 共用).
///
/// **不走 `apply_provider_auth`**: 它按单一已知协议剥离竞争 auth header (转发
/// 路径的正确防御 — 防上游误识别), 而探测时协议未知, 三个候选协议的 auth
/// header (`authorization: Bearer` / `x-api-key` / `x-goog-api-key`) 必须
/// **并发携带**, 由上游按自己的方言取用. `anthropic-version` 恒加 (Anthropic
/// 上游缺失此 header 会 400, 对其他协议无害). api_key 为空 (含纯空白) 时全部
/// auth header 跳过 (Ollama 等本地无 auth 场景); 含非法 header 字符时 warn 后
/// 跳过该项 (同 `apply_provider_auth` 纪律: 永不 panic, 让上游自行拒绝).
fn probe_headers(api_key: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "anthropic-version",
        HeaderValue::from_static(super::auth::ANTHROPIC_VERSION),
    );
    let key = api_key.trim();
    if key.is_empty() {
        return headers;
    }
    for (name, value) in [
        ("authorization", format!("Bearer {key}")),
        ("x-api-key", key.to_string()),
        ("x-goog-api-key", key.to_string()),
    ] {
        match HeaderValue::from_str(&value) {
            Ok(v) => {
                headers.insert(name, v);
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    name,
                    "probe api_key contains illegal header chars; skipping auth header"
                );
            }
        }
    }
    headers
}

/// /v1/models 的家族归属 (openai 与 anthropic 共用该端点, 靠 shape 判别字段分家).
enum V1Family {
    OpenAI,
    Anthropic,
}

/// /v1/models 200 响应的家族判别: 扫描 `data` 数组, **首个含判别字段的条目**决定 —
/// 有 `object` 字段 → OpenAI (条目形如 `{"id","object":"model",...}`); 有
/// `display_name` 或 `type` → Anthropic (`{"type":"model","id","display_name"}`).
/// 同一条目两者兼有时 `object` 优先 (判别字段是 OpenAI 家族更显式的指纹).
/// 全部条目无判别字段 (含 data 空) → OpenAI (该端点的历史默认方言).
///
/// 假设: 判别只看字段名存在性, 不看字段值. 降级: body 已由调用方经
/// `parse_model_ids` 验证, 此处再 parse 失败 (理论不可达) → OpenAI (ROB-*).
fn classify_v1_family(body: &[u8]) -> V1Family {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return V1Family::OpenAI;
    };
    let Some(entries) = value.get("data").and_then(|d| d.as_array()) else {
        return V1Family::OpenAI;
    };
    for entry in entries {
        if entry.get("object").is_some() {
            return V1Family::OpenAI;
        }
        if entry.get("display_name").is_some() || entry.get("type").is_some() {
            return V1Family::Anthropic;
        }
    }
    V1Family::OpenAI
}

/// 非 2xx status → 探测状态桶: 401|403 → auth_failed, 404|405 → absent,
/// 其余 → error. (2xx 由调用方在 shape 判定分支处理, 不进本函数.)
fn status_probe_bucket(status: StatusCode) -> ProbeStatus {
    if matches!(status.as_u16(), 401 | 403) {
        ProbeStatus::AuthFailed
    } else if matches!(status.as_u16(), 404 | 405) {
        ProbeStatus::Absent
    } else {
        ProbeStatus::Error
    }
}

/// detail 文案: 只含数字 status code (契约示例形态 "upstream returned 401"),
/// 不含 reason phrase (无信息量且冗长).
fn status_detail(status: StatusCode) -> String {
    format!("upstream returned {}", status.as_u16())
}

/// 单端点判定 (gemini: /v1beta/models; ollama: /api/tags): 2xx + shape 解析成功
/// → ok (models 必有); 401|403 → auth_failed; 404|405 → absent; 其余 (连接失败/
/// 超时/超大 body/非法 JSON/其他非 2xx) → error (detail 必有).
fn judge_single_endpoint(
    protocol: Protocol,
    res: &Result<(StatusCode, Vec<u8>), String>,
) -> ProbeOutcome {
    let name = protocol.name();
    match res {
        Err(reason) => ProbeOutcome::non_ok(name, ProbeStatus::Error, reason.clone()),
        Ok((status, body)) if status.is_success() => match parse_model_ids(protocol, body) {
            Ok(models) => ProbeOutcome::ok(name, models),
            Err(reason) => ProbeOutcome::non_ok(name, ProbeStatus::Error, reason),
        },
        Ok((status, _)) => {
            ProbeOutcome::non_ok(name, status_probe_bucket(*status), status_detail(*status))
        }
    }
}

/// /v1/models 端点判定 → (openai, anthropic) 一对 outcome.
///
/// 两家族共用端点与 `data[].id` 解析 (parse_model_ids(OpenAI) == (Anthropic)):
/// parse 失败 (非法 JSON / 缺 data) → 双 error; 成功后按 `classify_v1_family`
/// 分家 — 赢家 ok (带 models), 输家 absent (detail 指明家族归属).
fn judge_v1_pair(res: &Result<(StatusCode, Vec<u8>), String>) -> (ProbeOutcome, ProbeOutcome) {
    let (openai, anthropic) = (Protocol::OpenAI.name(), Protocol::Anthropic.name());
    // 两族共担同一命运 (error / auth_failed / absent) 的对称二元组构造.
    let both = |status: ProbeStatus, detail: String| {
        (
            ProbeOutcome::non_ok(openai, status, detail.clone()),
            ProbeOutcome::non_ok(anthropic, status, detail),
        )
    };
    match res {
        Err(reason) => both(ProbeStatus::Error, reason.clone()),
        Ok((status, body)) if status.is_success() => {
            match parse_model_ids(Protocol::OpenAI, body) {
                Err(reason) => both(ProbeStatus::Error, reason),
                Ok(models) => match classify_v1_family(body) {
                    V1Family::OpenAI => (
                        ProbeOutcome::ok(openai, models),
                        ProbeOutcome::non_ok(
                            anthropic,
                            ProbeStatus::Absent,
                            "endpoint speaks OpenAI family shape".to_string(),
                        ),
                    ),
                    V1Family::Anthropic => (
                        ProbeOutcome::non_ok(
                            openai,
                            ProbeStatus::Absent,
                            "endpoint speaks Anthropic family shape".to_string(),
                        ),
                        ProbeOutcome::ok(anthropic, models),
                    ),
                },
            }
        }
        Ok((status, _)) => both(status_probe_bucket(*status), status_detail(*status)),
    }
}

/// 推荐序 (模块头部 "探测" 段): openai (ollama 双命中附 note) > anthropic >
/// gemini (no-codec note) > ollama (同 note); 无任何 ok → (null, null).
/// 按协议名查 ok 状态, 与 probes 的排列顺序解耦 (顺序本身是冻结的 wire 契约,
/// 不应再成为推荐逻辑的隐式输入).
fn recommend(probes: &[ProbeOutcome]) -> (Option<&'static str>, Option<&'static str>) {
    let ok = |name: &str| {
        probes
            .iter()
            .any(|p| p.protocol == name && p.status == ProbeStatus::Ok)
    };
    if ok(Protocol::OpenAI.name()) {
        if ok(Protocol::Ollama.name()) {
            (Some(Protocol::OpenAI.name()), Some(PROBE_NOTE_DUAL_OLLAMA))
        } else {
            (Some(Protocol::OpenAI.name()), None)
        }
    } else if ok(Protocol::Anthropic.name()) {
        (Some(Protocol::Anthropic.name()), None)
    } else if ok(Protocol::Gemini.name()) {
        (Some(Protocol::Gemini.name()), Some(PROBE_NOTE_NO_CODEC))
    } else if ok(Protocol::Ollama.name()) {
        (Some(Protocol::Ollama.name()), Some(PROBE_NOTE_NO_CODEC))
    } else {
        (None, None)
    }
}

/// 对 base_url 并行探测 4 族协议端点 (base_url 合法性已由 handler 侧校验 —
/// 集中式预处理; 此处不做重复校验, 非法 URL 的最坏结果是全 error outcome).
///
/// 并行 3 个 GET (`tokio::join!`): `/v1/models` (判 openai/anthropic 两族),
/// `/v1beta/models` (gemini), `/api/tags` (ollama). 每路复用
/// `fetch_status_and_body` 防御 (整体超时 + 有界 body + 错误串净化 — detail
/// 不含 api_key).
///
/// 永不 Err / 永不 panic (ROB-*): 探测失败是数据不是 HTTP 错误.
pub(crate) async fn probe_provider_upstream(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
) -> ProbeResponse {
    let headers = probe_headers(api_key);
    // URL 先绑定再借用 (join! 的 future 存活到 .await 完成, 临时值撑不到).
    let (v1_url, gemini_url, ollama_url) = (
        super::helpers::build_upstream_url(base_url, "/v1/models"),
        super::helpers::build_upstream_url(base_url, "/v1beta/models"),
        super::helpers::build_upstream_url(base_url, "/api/tags"),
    );
    let (v1, gemini, ollama) = tokio::join!(
        fetch_status_and_body(client, &v1_url, headers.clone()),
        fetch_status_and_body(client, &gemini_url, headers.clone()),
        fetch_status_and_body(client, &ollama_url, headers),
    );
    let (openai, anthropic) = judge_v1_pair(&v1);
    let gemini = judge_single_endpoint(Protocol::Gemini, &gemini);
    let ollama = judge_single_endpoint(Protocol::Ollama, &ollama);
    let probes = vec![openai, anthropic, gemini, ollama];
    let (recommended, note) = recommend(&probes);
    ProbeResponse {
        probes,
        recommended,
        note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use parking_lot::{Mutex, RwLock};

    use crate::config::Decisions;
    use crate::provider::Route;

    // ─── 测试构造器 ─────────────────────────────────────────────────────

    fn tmp_path(label: &str) -> std::path::PathBuf {
        let id = uuid::Uuid::new_v4().to_string();
        let path =
            std::path::PathBuf::from(format!("/tmp/opencode/tmp/test-models-{label}-{id}.toml"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        path
    }

    fn direct(id: &str, base_url: &str) -> Provider {
        Provider {
            id: id.into(),
            enabled: true,
            name: None,
            kind: ProviderKind::Direct(direct_proto(Protocol::OpenAI, base_url)),
        }
    }

    fn disabled_direct(id: &str, base_url: &str) -> Provider {
        Provider {
            enabled: false,
            ..direct(id, base_url)
        }
    }

    fn direct_proto(protocol: Protocol, base_url: &str) -> DirectProvider {
        DirectProvider {
            protocol,
            base_url: base_url.to_string(),
            api_key: String::new(),
            api_key_file: None,
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

    fn router(id: &str, routes: Vec<Route>) -> Provider {
        Provider {
            id: id.into(),
            enabled: true,
            name: None,
            kind: ProviderKind::Router(crate::provider::RouterProvider { routes }),
        }
    }

    fn table(providers: Vec<Provider>) -> ProviderTable {
        let decisions = Arc::new(RwLock::new(Decisions::default()));
        ProviderTable::new(providers, vec![], decisions, tmp_path("table"))
    }

    fn cached(pairs: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(id, models)| {
                (
                    (*id).to_string(),
                    models.iter().map(|m| (*m).to_string()).collect::<Vec<_>>(),
                )
            })
            .collect()
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    // ─── 端点判定 ───────────────────────────────────────────────────────

    #[test]
    fn is_model_list_path_matrix() {
        // 两种 rest 形态都必须接受 (axum 0.8 不含前导 '/', 见函数注释; 手写调用
        // 可能带前导 '/').
        for p in ["models", "v1/models", "/models", "/v1/models"] {
            for ingress in [
                Protocol::OpenAI,
                Protocol::Anthropic,
                Protocol::Gemini,
                Protocol::OpenAIResponses,
            ] {
                assert!(is_model_list_path(ingress, p), "{ingress} {p}");
            }
            assert!(
                !is_model_list_path(Protocol::Ollama, p),
                "ollama 只认 /api/tags: {p}"
            );
        }
        for p in ["v1beta/models", "/v1beta/models"] {
            assert!(is_model_list_path(Protocol::Gemini, p));
            assert!(!is_model_list_path(Protocol::OpenAI, p));
        }
        for p in ["api/tags", "/api/tags"] {
            assert!(is_model_list_path(Protocol::Ollama, p));
            assert!(!is_model_list_path(Protocol::OpenAI, p));
        }
        // 非模型列表路径不拦截.
        assert!(!is_model_list_path(Protocol::OpenAI, ""));
        assert!(!is_model_list_path(Protocol::OpenAI, "/"));
        assert!(!is_model_list_path(Protocol::OpenAI, "v1/chat/completions"));
        assert!(!is_model_list_path(Protocol::OpenAI, "v1/models/"));
    }

    // ─── N6 gate ────────────────────────────────────────────────────────

    #[test]
    fn gate_exact_only_disables_merge() {
        // exact-only = 全部启用路由均不含 '*' (此处故意不用 glm-* 一类前缀通配).
        let t = router("r", vec![route("ultra", "a", 30), route("flash", "a", 20)]);
        assert!(!needs_upstream_merge(&t), "含 * 的启用路由才开 gate");
    }

    #[test]
    fn gate_wildcard_enables_merge() {
        let t = router("r", vec![route("ultra", "a", 30), route("*", "b", 10)]);
        assert!(needs_upstream_merge(&t));
    }

    #[test]
    fn gate_disabled_wildcard_does_not_count() {
        // priority None = 禁用路由, 不构成 gate (N6 看启用路由).
        let disabled = Route {
            priority: None,
            ..route("*", "a", 0)
        };
        let t = router("r", vec![route("ultra", "a", 30), disabled]);
        assert!(!needs_upstream_merge(&t));
    }

    #[test]
    fn gate_direct_provider_is_false() {
        let d = direct("d", "http://up");
        assert!(!needs_upstream_merge(&d));
    }

    // ─── 别名派生 (N2 + D2) ────────────────────────────────────────────

    #[test]
    fn alias_names_order_dedup_skip_disabled_and_wildcard() {
        let disabled_route = Route {
            priority: None,
            ..route("off", "a", 0)
        };
        let t = table(vec![
            direct("a", "http://a"),
            router(
                "r",
                vec![
                    route("x", "a", 30),
                    route("y", "a", 30),
                    route("y-dup", "a", 5),
                    disabled_route,               // 禁用路由: 不广告
                    route("glm-*", "a", 20),      // wildcard: 不是别名 (D1)
                    route("dead", "missing", 30), // 悬空: D2 过滤
                ],
            ),
        ]);
        let r = t.get_effective("r").unwrap();
        assert_eq!(alias_names(&t, &r), strs(&["x", "y", "y-dup"]));
    }

    #[test]
    fn alias_names_dedup_repeated_pattern() {
        let t = table(vec![
            direct("a", "http://a"),
            router(
                "r",
                vec![
                    route("x", "a", 30),
                    route("x", "a", 20),
                    route("x", "a", 10),
                ],
            ),
        ]);
        let r = t.get_effective("r").unwrap();
        assert_eq!(alias_names(&t, &r), strs(&["x"]), "重复 pattern 去重");
    }

    #[test]
    fn alias_names_requires_full_chain_resolvable() {
        // exact → 二级 router 无匹配路由 (NoMatch) ⇒ 不广告 (D2 在链深度上也成立).
        let t = table(vec![
            direct("a", "http://a"),
            router("mid", vec![route("other", "a", 0)]),
            router("top", vec![route("foo", "mid", 30)]),
        ]);
        let top = t.get_effective("top").unwrap();
        assert_eq!(alias_names(&t, &top), Vec::<String>::new());
    }

    // ─── 可达集 walk ────────────────────────────────────────────────────

    #[test]
    fn walk_collects_nested_directs_skips_disabled_and_dangling() {
        let t = table(vec![
            direct("a1", "http://a1"),
            disabled_direct("b", "http://b"),
            router("mid", vec![route("*", "a1", 0)]),
            router(
                "top",
                vec![
                    route("t-*", "mid", 20),
                    route("x-*", "b", 30),       // disabled target: 不贡献
                    route("d-*", "missing", 30), // 悬空: 不贡献
                ],
            ),
        ]);
        let top = t.get_effective("top").unwrap();
        let targets = walk_reachable_directs(&t, &top);
        let ids: Vec<&str> = targets.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["a1"], "只有嵌套链尾 direct 可达");
    }

    #[test]
    fn walk_terminates_on_cycle() {
        // top → mid → top (启用路由成环, 手改 state.toml 的漏网形态) + 链尾 direct.
        let t = table(vec![
            direct("a", "http://a"),
            router("mid", vec![route("*", "a", 0), route("t-*", "top", 10)]),
            router("top", vec![route("t-*", "mid", 20)]),
        ]);
        let top = t.get_effective("top").unwrap();
        let targets = walk_reachable_directs(&t, &top);
        let ids: Vec<&str> = targets.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["a"]);
    }

    // ─── 合并候选序 ─────────────────────────────────────────────────────

    #[test]
    fn union_preserves_walk_then_upstream_order_with_dedup() {
        let ids = ["main", "fallback"];
        let c = cached(&[
            ("main", &["glm-4.7", "glm-4.8"]),
            ("fallback", &["glm-4.8", "qwen-3"]),
        ]);
        assert_eq!(
            union_from_cache(ids.into_iter(), &c),
            strs(&["glm-4.7", "glm-4.8", "qwen-3"])
        );
        // 无缓存的 provider 无贡献.
        let empty = cached(&[]);
        assert_eq!(
            union_from_cache(ids.into_iter(), &empty),
            Vec::<String>::new()
        );
    }

    // ─── N1 过滤三边界 (brief §3.1) ─────────────────────────────────────

    /// default-plan 的核心推演: 遮蔽 (fallback 有 glm-4.7-air, 但 glm-* 送 main 且
    /// main 无它 → 过滤) + NoMatch 兜底 (qwen-3 仅 `*` 命中 → 广告).
    #[test]
    fn n1_shadowing_and_fallback_boundaries() {
        let t = table(vec![
            direct("main", "http://m"),
            direct("fallback", "http://f"),
            router(
                "r",
                vec![route("glm-*", "main", 20), route("*", "fallback", 10)],
            ),
        ]);
        let r = t.get_effective("r").unwrap();
        let c = cached(&[
            ("main", &["glm-4.7"]),
            ("fallback", &["qwen-3", "glm-4.7-air"]),
        ]);
        // 遮蔽: glm-4.7-air 匹配 glm-* (更高 priority) → main 无它 → 过滤.
        assert!(!n1_accepts(&t, &r, "glm-4.7-air", &c));
        // NoMatch 兜底: qwen-3 仅 * 命中 → fallback 有它 → 广告.
        assert!(n1_accepts(&t, &r, "qwen-3", &c));
        // 常规: glm-4.7 → main 有它 → 广告.
        assert!(n1_accepts(&t, &r, "glm-4.7", &c));
        // 无 * 兜底的 router: union 里的未匹配名一律过滤.
        let t2 = table(vec![
            direct("main", "http://m"),
            router("r2", vec![route("glm-*", "main", 20)]),
        ]);
        let r2 = t2.get_effective("r2").unwrap();
        let c2 = cached(&[("main", &["glm-4.7"])]);
        assert!(!n1_accepts(&t2, &r2, "qwen-3", &c2), "NoMatch → 过滤");
    }

    /// 重写边界: 广告判定看 egress E (rewrite 值) 是否在目标清单, 不看 M 本身.
    #[test]
    fn n1_rewrite_judges_egress_model_not_client_model() {
        let t = table(vec![
            direct("main", "http://m"),
            direct("fallback", "http://f"),
            router(
                "r",
                vec![
                    rewrite_route("glm-4.8*", "main", "glm-4.8-air", 20),
                    route("*", "fallback", 10),
                ],
            ),
        ]);
        let r = t.get_effective("r").unwrap();
        // main 有 M (glm-4.8-flash) 但没有 E (glm-4.8-air) → 过滤.
        let c = cached(&[("main", &["glm-4.8-flash"]), ("fallback", &[])]);
        assert!(!n1_accepts(&t, &r, "glm-4.8-flash", &c));
        // main 有 E → 广告 (即便 E ≠ M).
        let c2 = cached(&[("main", &["glm-4.8-air"]), ("fallback", &[])]);
        assert!(n1_accepts(&t, &r, "glm-4.8-flash", &c2));
    }

    /// N1: 解析失败 (悬空 target) 的候选不广告.
    #[test]
    fn n1_broken_chain_not_advertised() {
        let t = table(vec![router("r", vec![route("*", "missing", 10)])]);
        let r = t.get_effective("r").unwrap();
        let c = cached(&[]);
        assert!(!n1_accepts(&t, &r, "anything", &c));
    }

    // ─── 上游解析 / 响应构造 ────────────────────────────────────────────

    #[test]
    fn parse_model_ids_per_protocol_shapes() {
        assert_eq!(
            parse_model_ids(
                Protocol::OpenAI,
                br#"{"data":[{"id":"a"},{"id":"b"},{"nope":1}]}"#
            )
            .unwrap(),
            strs(&["a", "b"])
        );
        assert_eq!(
            parse_model_ids(Protocol::Anthropic, br#"{"data":[{"id":"c"}]}"#).unwrap(),
            strs(&["c"])
        );
        // Gemini: name 带 models/ 前缀, 剥掉.
        assert_eq!(
            parse_model_ids(
                Protocol::Gemini,
                br#"{"models":[{"name":"models/gem-1"},{"name":"models/gem-2"}]}"#
            )
            .unwrap(),
            strs(&["gem-1", "gem-2"])
        );
        // Ollama: /api/tags shape.
        assert_eq!(
            parse_model_ids(Protocol::Ollama, br#"{"models":[{"name":"llama-1"}]}"#).unwrap(),
            strs(&["llama-1"])
        );
        // 去重保序.
        assert_eq!(
            parse_model_ids(Protocol::OpenAI, br#"{"data":[{"id":"a"},{"id":"a"}]}"#).unwrap(),
            strs(&["a"])
        );
        // 畸形: 非 JSON / 缺数组字段 → Err.
        assert!(parse_model_ids(Protocol::OpenAI, b"{").is_err());
        assert!(parse_model_ids(Protocol::OpenAI, br#"{"data":"nope"}"#).is_err());
        assert!(parse_model_ids(Protocol::Ollama, br#"{"data":[{"id":"x"}]}"#).is_err());
    }

    #[test]
    fn build_models_body_shapes() {
        let names = strs(&["m1", "m2"]);
        for ingress in [Protocol::OpenAI, Protocol::OpenAIResponses] {
            let v: serde_json::Value =
                serde_json::from_str(&build_models_body(ingress, &names)).unwrap();
            assert_eq!(v["object"], "list");
            assert_eq!(v["data"][0]["id"], "m1");
            assert_eq!(v["data"][1]["id"], "m2");
            assert_eq!(v["data"][0]["object"], "model");
            assert_eq!(v["data"][0]["owned_by"], "router", "N5");
            assert_eq!(v["data"][0]["created"], 0);
        }
        let v: serde_json::Value =
            serde_json::from_str(&build_models_body(Protocol::Anthropic, &names)).unwrap();
        assert_eq!(v["data"][0]["type"], "model");
        assert_eq!(v["data"][0]["id"], "m1");
        assert_eq!(v["data"][0]["display_name"], "m1");
        assert_eq!(v["data"][0]["created_at"], "1970-01-01T00:00:00Z");
        assert_eq!(v["has_more"], false);
        let v: serde_json::Value =
            serde_json::from_str(&build_models_body(Protocol::Gemini, &names)).unwrap();
        assert_eq!(v["models"][0]["name"], "models/m1");
        let v: serde_json::Value =
            serde_json::from_str(&build_models_body(Protocol::Ollama, &names)).unwrap();
        assert_eq!(v["models"][0]["name"], "m1");
    }

    // ─── 缓存: TTL 过期重取 + serve-stale-on-error (N4) ────────────────

    #[tokio::test]
    async fn model_list_cache_stale_on_error_and_refresh_after_ttl() {
        let mut server = mockito::Server::new_async().await;
        let ok_mock = server
            .mock("GET", "/v1/models")
            .with_status(200)
            .with_body(r#"{"data":[{"id":"m1"}]}"#)
            .create_async()
            .await;
        let targets = vec![FetchTarget {
            id: "p1".to_string(),
            direct: direct_proto(Protocol::OpenAI, &server.url()),
            api_key: String::new(), // direct_proto 无 key 配置, 预解析恒为空串
        }];
        let cache = ModelListCache::new();
        let client = reqwest::Client::new();

        // 首查: 懒加载 fetch → m1.
        let s1 = cache.snapshot_refreshing(&client, &targets).await;
        assert_eq!(s1.get("p1").unwrap(), &strs(&["m1"]));

        // TTL 内: 直接复用缓存 (零新请求, mock expect 1 锁定).
        let s2 = cache.snapshot_refreshing(&client, &targets).await;
        assert_eq!(s2.get("p1").unwrap(), &strs(&["m1"]));
        ok_mock.assert_async().await;

        // TTL 过期 + 上游 500: serve-stale — 保留旧数据, 不 fail.
        tokio::time::sleep(MODEL_LIST_TTL + Duration::from_millis(200)).await;
        ok_mock.remove_async().await;
        let err_mock = server
            .mock("GET", "/v1/models")
            .with_status(500)
            .create_async()
            .await;
        let s3 = cache.snapshot_refreshing(&client, &targets).await;
        assert_eq!(
            s3.get("p1").unwrap(),
            &strs(&["m1"]),
            "刷新失败必须保留旧缓存 (serve-stale-on-error)"
        );
        err_mock.assert_async().await;

        // M1 失败退避: 失败后的退避窗口内再查 — 立即 serve stale, 不重试
        // (err_mock 仍只命中 1 次, 不被 dead upstream 逐查询阻塞).
        let s3b = cache.snapshot_refreshing(&client, &targets).await;
        assert_eq!(
            s3b.get("p1").unwrap(),
            &strs(&["m1"]),
            "退避窗口内立即 serve stale"
        );
        err_mock.assert_async().await;

        // 上游恢复: 退避窗口过后重新 fetch 覆盖 (sleep 同时盖过 TTL 与退避窗口).
        tokio::time::sleep(MODEL_LIST_TTL + Duration::from_millis(200)).await;
        err_mock.remove_async().await;
        server
            .mock("GET", "/v1/models")
            .with_status(200)
            .with_body(r#"{"data":[{"id":"m2"}]}"#)
            .expect(1)
            .create_async()
            .await;
        let s4 = cache.snapshot_refreshing(&client, &targets).await;
        assert_eq!(s4.get("p1").unwrap(), &strs(&["m2"]));
    }

    /// M1 失败退避 (从未成功路径): 首次 fetch 失败 → 无贡献; 退避窗口内的后续查询
    /// **立即**返回 (不再 fetch, 上游恰命中 1 次); 窗口过后允许重试, 上游恢复则
    /// 拿到数据. 防 dead target 逐查询阻塞 (每次 ≤10s fetch × 全局锁串行放大).
    #[tokio::test]
    async fn model_list_cache_failure_backoff_blocks_retry_within_window() {
        let mut server = mockito::Server::new_async().await;
        let err_mock = server
            .mock("GET", "/v1/models")
            .with_status(500)
            .expect(1)
            .create_async()
            .await;
        let targets = vec![FetchTarget {
            id: "p1".to_string(),
            direct: direct_proto(Protocol::OpenAI, &server.url()),
            api_key: String::new(), // direct_proto 无 key 配置, 预解析恒为空串
        }];
        let cache = ModelListCache::new();
        let client = reqwest::Client::new();

        // 首查: 尝试失败 → 无贡献.
        let s1 = cache.snapshot_refreshing(&client, &targets).await;
        assert!(!s1.contains_key("p1"), "从未成功 → 无贡献");

        // 退避窗口内: 立即返回, 不重试 (expect 1 锁定).
        let s2 = cache.snapshot_refreshing(&client, &targets).await;
        assert!(!s2.contains_key("p1"), "退避窗口内仍无贡献");
        err_mock.assert_async().await;

        // 窗口过后: 允许重试; 上游恢复 → 拿到数据.
        tokio::time::sleep(MODEL_FETCH_BACKOFF + Duration::from_millis(150)).await;
        err_mock.remove_async().await;
        server
            .mock("GET", "/v1/models")
            .with_status(200)
            .with_body(r#"{"data":[{"id":"r1"}]}"#)
            .expect(1)
            .create_async()
            .await;
        let s3 = cache.snapshot_refreshing(&client, &targets).await;
        assert_eq!(s3.get("p1").unwrap(), &strs(&["r1"]));
    }

    // ─── fetch: 超时与超大 body 的降级路径 ─────────────────────────────

    /// H1 回归: 上游 accept 后不发任何字节 (响应头都不发), 整体超时必须掐断 —
    /// 否则 fetch 会永久持有 `snapshot_refreshing` 的缓存锁, 连带所有 router 的
    /// /models 查询挂起。
    #[tokio::test]
    async fn fetch_model_list_times_out_on_stalled_upstream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // 收连接但永不响应也永不关闭 (停滞上游).
        tokio::spawn(async move {
            let (_conn, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let direct = direct_proto(Protocol::OpenAI, &format!("http://{addr}"));
        let err = fetch_model_list(&reqwest::Client::new(), "", &direct)
            .await
            .unwrap_err();
        assert_eq!(err, "timeout", "停滞上游必须被整体超时掐断");
    }

    /// 超大 body 上限: 超过 MAX_MODELS_BODY 的响应按该 provider fetch 失败处理
    /// (不让破损上游借 /models 查询撑爆内存).
    #[tokio::test]
    async fn fetch_model_list_rejects_oversized_body() {
        let mut server = mockito::Server::new_async().await;
        let huge = "x".repeat(MAX_MODELS_BODY + 1);
        server
            .mock("GET", "/v1/models")
            .with_status(200)
            .with_body(huge)
            .create_async()
            .await;
        let direct = direct_proto(Protocol::OpenAI, &server.url());
        let err = fetch_model_list(&reqwest::Client::new(), "", &direct)
            .await
            .unwrap_err();
        assert!(err.contains("exceeds"), "超限 body 必须按失败处理: {err}");
    }

    /// M1 回归: Anthropic 上游的 fetch 必须带 anthropic-version header (缺失会被
    /// 真实 Anthropic API 400 拒绝, mockito 用 match_header 锁定).
    #[tokio::test]
    async fn fetch_model_list_anthropic_sends_version_header() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/models")
            .match_header("anthropic-version", super::super::auth::ANTHROPIC_VERSION)
            .with_status(200)
            .with_body(r#"{"data":[{"id":"c1"}]}"#)
            .expect(1)
            .create_async()
            .await;
        let mut direct = direct_proto(Protocol::Anthropic, &server.url());
        direct.api_key = "sk-ant-test".into();
        // key = direct.api_key 直配值 (预解析结果).
        let models = fetch_model_list(&reqwest::Client::new(), "sk-ant-test", &direct)
            .await
            .unwrap();
        assert_eq!(models, strs(&["c1"]));
        mock.assert_async().await;
    }

    // ─── 完整 pipeline: exact-only gate 短路 (N6) ──────────────────────

    /// 构造完整 AppState (仅单测用; direct 的 base_url 指向不可达端口 — 若 gate
    /// 失效发生 fetch, 结果仍应只含别名: merge 贡献 ≡ ∅ 且 fetch 失败被吞).
    fn unit_app_state(providers: Vec<Provider>) -> AppState {
        let decisions = Arc::new(RwLock::new(Decisions::default()));
        let redact = crate::config::RedactConfig::default();
        AppState {
            upstream: reqwest::Client::new(),
            providers: ProviderTable::new(
                providers,
                vec![],
                decisions.clone(),
                tmp_path("providers"),
            ),
            dag: crate::dag::ConversationDag::new(8, 8, 1),
            secrets: crate::secrets::SecretTable::new(
                vec![],
                vec![],
                decisions,
                tmp_path("secrets"),
            ),
            api_keys: crate::auth::ApiKeyStore::new(
                &[],
                std::path::Path::new("."),
                vec![],
                std::collections::HashSet::new(),
                tmp_path("api-keys"),
                Arc::new(Mutex::new(())),
            ),
            auth_enabled: false,
            global_mock_prefix: Arc::from(""),
            // [redact] 三 gate 镜像生产默认 (SEC-10); 本 harness 不触降级路径.
            on_probe_exhausted: redact.on_probe_exhausted,
            on_unsupported_protocol: redact.on_unsupported_protocol,
            on_fallback_restore: redact.on_fallback_restore,
            // redacted_headers 镜像生产装配 (normalize 后入 state); 本 harness 无自定义名单.
            redacted_headers: crate::state::normalize_redacted_headers(&redact.redacted_headers),
            upstream_timeouts: crate::config::UpstreamTimeouts::default(),
            model_lists: Arc::new(ModelListCache::new()),
            usage: std::sync::Arc::new(crate::usage::UsageStore::in_memory()),
            pricing: std::sync::Arc::new(crate::usage::PricingCache::for_tests()),
        }
    }

    #[tokio::test]
    async fn advertised_names_exact_only_returns_aliases_without_merge() {
        let state = unit_app_state(vec![
            direct("a", "http://127.0.0.1:9"),
            router("r", vec![route("ultra", "a", 30), route("flash", "a", 20)]),
        ]);
        let r = state.providers.get_effective("r").unwrap();
        assert_eq!(
            advertised_names(&state, &r).await,
            strs(&["ultra", "flash"]),
            "exact-only: 只返回别名, 不 fetch (N6)"
        );
    }

    // ─── Provider 协议探测 ─────────────────────────────────────────────

    /// 三端点探测 mock: (v1/models, v1beta/models, api/tags) 各挂一个
    /// (status, body) — 全部显式挂载, 不留 mockito 未匹配的隐式行为.
    async fn probe_upstream(
        v1: (u16, &str),
        v1beta: (u16, &str),
        tags: (u16, &str),
    ) -> mockito::ServerGuard {
        let mut server = mockito::Server::new_async().await;
        for (path, (status, body)) in [
            ("/v1/models", v1),
            ("/v1beta/models", v1beta),
            ("/api/tags", tags),
        ] {
            server
                .mock("GET", path)
                .with_status(status as usize)
                .with_body(body)
                .create_async()
                .await;
        }
        server
    }

    async fn probe(server: &mockito::ServerGuard, api_key: &str) -> ProbeResponse {
        probe_provider_upstream(&reqwest::Client::new(), &server.url(), api_key).await
    }

    #[tokio::test]
    async fn probe_openai_shape_happy() {
        let server = probe_upstream(
            (
                200,
                r#"{"object":"list","data":[{"id":"gpt-4o","object":"model","owned_by":"x"}]}"#,
            ),
            (404, ""),
            (404, ""),
        )
        .await;
        let resp = probe(&server, "").await;
        let names: Vec<&str> = resp.probes.iter().map(|p| p.protocol).collect();
        assert_eq!(names, ["openai", "anthropic", "gemini", "ollama"]);
        let oa = &resp.probes[0];
        assert_eq!(oa.status, ProbeStatus::Ok);
        assert_eq!(oa.models.as_ref().unwrap(), &strs(&["gpt-4o"]));
        assert!(oa.detail.is_none());
        let an = &resp.probes[1];
        assert_eq!(an.status, ProbeStatus::Absent);
        assert_eq!(
            an.detail.as_deref(),
            Some("endpoint speaks OpenAI family shape")
        );
        assert_eq!(resp.probes[2].status, ProbeStatus::Absent, "404 → absent");
        assert_eq!(resp.probes[3].status, ProbeStatus::Absent);
        assert_eq!(resp.recommended, Some("openai"));
        assert!(resp.note.is_none());
    }

    /// 判别字段分家: display_name/type 指向 Anthropic 家族 (object 字段缺席).
    #[tokio::test]
    async fn probe_anthropic_shape_happy() {
        let server = probe_upstream(
            (
                200,
                r#"{"data":[{"type":"model","id":"claude-3-5","display_name":"Claude 3.5"}]}"#,
            ),
            (404, ""),
            (404, ""),
        )
        .await;
        let resp = probe(&server, "").await;
        let an = &resp.probes[1];
        assert_eq!(an.status, ProbeStatus::Ok);
        assert_eq!(an.models.as_ref().unwrap(), &strs(&["claude-3-5"]));
        assert!(an.detail.is_none());
        let oa = &resp.probes[0];
        assert_eq!(oa.status, ProbeStatus::Absent);
        assert_eq!(
            oa.detail.as_deref(),
            Some("endpoint speaks Anthropic family shape")
        );
        assert_eq!(resp.recommended, Some("anthropic"));
        assert!(resp.note.is_none());
    }

    #[tokio::test]
    async fn probe_gemini_happy() {
        let server = probe_upstream(
            (404, ""),
            (
                200,
                r#"{"models":[{"name":"models/gem-1"},{"name":"models/gem-2"}]}"#,
            ),
            (404, ""),
        )
        .await;
        let resp = probe(&server, "").await;
        let g = &resp.probes[2];
        assert_eq!(g.status, ProbeStatus::Ok);
        assert_eq!(g.models.as_ref().unwrap(), &strs(&["gem-1", "gem-2"]));
        assert_eq!(resp.recommended, Some("gemini"));
        // note 断言用冻结文案字面量 (与 detail 的字面量断言风格统一): 断言常量
        // 自身是同义反复, 文案漂移时恒绿, 起不到契约冻结作用.
        assert_eq!(
            resp.note,
            Some(
                "No codec for this protocol: secret redaction is unavailable, and requests hitting secrets are rejected by default (on_unsupported_protocol = fail_closed)."
            )
        );
    }

    #[tokio::test]
    async fn probe_ollama_happy() {
        let server = probe_upstream(
            (404, ""),
            (404, ""),
            (200, r#"{"models":[{"name":"llama3:latest"}]}"#),
        )
        .await;
        let resp = probe(&server, "").await;
        let o = &resp.probes[3];
        assert_eq!(o.status, ProbeStatus::Ok);
        assert_eq!(o.models.as_ref().unwrap(), &strs(&["llama3:latest"]));
        assert_eq!(resp.recommended, Some("ollama"));
        assert_eq!(
            resp.note,
            Some(
                "No codec for this protocol: secret redaction is unavailable, and requests hitting secrets are rejected by default (on_unsupported_protocol = fail_closed)."
            )
        );
    }

    /// 双命中 (openai + ollama): 推荐 openai 并附双命中 note.
    #[tokio::test]
    async fn probe_openai_ollama_dual_hit_recommends_openai() {
        let server = probe_upstream(
            (200, r#"{"data":[{"id":"gpt-4o","object":"model"}]}"#),
            (404, ""),
            (200, r#"{"models":[{"name":"llama3:latest"}]}"#),
        )
        .await;
        let resp = probe(&server, "").await;
        assert_eq!(resp.probes[0].status, ProbeStatus::Ok);
        assert_eq!(resp.probes[3].status, ProbeStatus::Ok);
        assert_eq!(resp.recommended, Some("openai"));
        assert_eq!(
            resp.note,
            Some(
                "Ollama native endpoint also detected. The OpenAI-compatible endpoint is recommended because secret redaction requires a codec-covered protocol (OpenAI/Anthropic/Responses)."
            )
        );
    }

    /// /v1/models 401: openai 与 anthropic 双 auth_failed (端点共用, 鉴权同源);
    /// 其余两族 absent → 无任何 ok → recommended null.
    #[tokio::test]
    async fn probe_v1_models_401_both_auth_failed() {
        let server = probe_upstream((401, ""), (404, ""), (404, "")).await;
        let resp = probe(&server, "").await;
        for i in [0, 1] {
            assert_eq!(resp.probes[i].status, ProbeStatus::AuthFailed);
            assert_eq!(
                resp.probes[i].detail.as_deref(),
                Some("upstream returned 401")
            );
        }
        assert_eq!(resp.recommended, None);
        assert_eq!(resp.note, None);
    }

    /// data 无判别字段 / data 空: 默认 OpenAI 家族 (models 可为空).
    #[tokio::test]
    async fn probe_v1_models_no_discriminator_defaults_openai() {
        let server = probe_upstream((200, r#"{"data":[{"id":"m1"}]}"#), (404, ""), (404, "")).await;
        let resp = probe(&server, "").await;
        assert_eq!(resp.probes[0].status, ProbeStatus::Ok);
        assert_eq!(resp.probes[0].models.as_ref().unwrap(), &strs(&["m1"]));
        assert_eq!(resp.probes[1].status, ProbeStatus::Absent);

        let server = probe_upstream((200, r#"{"data":[]}"#), (404, ""), (404, "")).await;
        let resp = probe(&server, "").await;
        assert_eq!(
            resp.probes[0].status,
            ProbeStatus::Ok,
            "data 空也是合法 shape"
        );
        assert_eq!(
            resp.probes[0].models.as_ref().unwrap(),
            &Vec::<String>::new()
        );
        assert_eq!(resp.probes[1].status, ProbeStatus::Absent);
    }

    /// 判别优先级: 同一条目兼有 object + display_name → object 优先 (OpenAI).
    #[tokio::test]
    async fn probe_v1_models_object_field_wins_over_display_name() {
        let server = probe_upstream(
            (
                200,
                r#"{"data":[{"id":"hybrid","object":"model","display_name":"Hybrid"}]}"#,
            ),
            (404, ""),
            (404, ""),
        )
        .await;
        let resp = probe(&server, "").await;
        assert_eq!(resp.probes[0].status, ProbeStatus::Ok, "object 字段优先");
        assert_eq!(resp.probes[1].status, ProbeStatus::Absent);
    }

    /// 跨条目扫描: 首条目无判别字段, 后续条目有 type → Anthropic (扫描越过
    /// 无判别字段的条目, 与 classify_v1_family 头部声明的规则一致).
    #[tokio::test]
    async fn probe_v1_models_scan_skips_undiscriminated_entries() {
        let server = probe_upstream(
            (
                200,
                r#"{"data":[{"id":"opaque"},{"type":"model","id":"claude-x","display_name":"X"}]}"#,
            ),
            (404, ""),
            (404, ""),
        )
        .await;
        let resp = probe(&server, "").await;
        assert_eq!(resp.probes[1].status, ProbeStatus::Ok);
        assert_eq!(
            resp.probes[1].models.as_ref().unwrap(),
            &strs(&["opaque", "claude-x"])
        );
        assert_eq!(resp.probes[0].status, ProbeStatus::Absent);
    }

    /// 200 但非法 JSON (gemini 路径) → error (detail 含 invalid JSON).
    #[tokio::test]
    async fn probe_gemini_invalid_json_errors() {
        let server = probe_upstream((404, ""), (200, "not-json{{"), (404, "")).await;
        let resp = probe(&server, "").await;
        assert_eq!(resp.probes[2].status, ProbeStatus::Error);
        let detail = resp.probes[2].detail.as_deref().unwrap();
        assert!(detail.contains("invalid JSON"), "detail: {detail}");
        assert_eq!(resp.recommended, None);
    }

    /// 超大 body (超出 MAX_MODELS_BODY) → error, 不撑爆内存.
    #[tokio::test]
    async fn probe_oversized_body_errors() {
        let huge = "x".repeat(MAX_MODELS_BODY + 1);
        let server = probe_upstream((200, &huge), (200, &huge), (200, &huge)).await;
        let resp = probe(&server, "").await;
        for p in &resp.probes {
            assert_eq!(p.status, ProbeStatus::Error);
            assert!(
                p.detail.as_deref().unwrap().contains("exceeds"),
                "detail: {:?}",
                p.detail
            );
        }
        assert_eq!(resp.recommended, None);
    }

    /// 死连接 (TcpListener 收连接但永不响应): 3 路探测全部被整体超时掐断 → error,
    /// 不挂起. 同时守卫 SEC: 响应体序列化后不含 api_key 子串 (错误串经净化).
    #[tokio::test]
    async fn probe_dead_upstream_times_out_without_key_leak() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // 收连接 (3 路并行) 并持有 socket 但永不响应 — 停滞上游.
            let mut held = Vec::new();
            while let Ok((conn, _)) = listener.accept().await {
                held.push(conn);
            }
        });
        let api_key = "sk-probe-leaky-key-9876";
        let resp =
            probe_provider_upstream(&reqwest::Client::new(), &format!("http://{addr}"), api_key)
                .await;
        for p in &resp.probes {
            assert_eq!(p.status, ProbeStatus::Error);
            assert!(
                p.detail.as_deref().unwrap().contains("timeout"),
                "detail: {:?}",
                p.detail
            );
        }
        assert_eq!(resp.recommended, None);
        // SEC: 序列化响应不含 api_key 子串 (detail 走 upstream_error_brief 净化).
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            !json.contains(api_key),
            "probe response must not leak api_key: {json}"
        );
    }

    /// api_key 非空时三路并发携带三种 auth header + anthropic-version
    /// (协议未知, 不预剥离 — 见 probe_headers 注释).
    #[tokio::test]
    async fn probe_sends_all_auth_headers_when_keyed() {
        let mut server = mockito::Server::new_async().await;
        let key = "sk-probe-key";
        let mock = server
            .mock("GET", "/v1/models")
            .match_header(
                "authorization",
                mockito::Matcher::Exact(format!("Bearer {key}")),
            )
            .match_header("x-api-key", key)
            .match_header("x-goog-api-key", key)
            .match_header("anthropic-version", super::super::auth::ANTHROPIC_VERSION)
            .with_status(200)
            .with_body(r#"{"data":[{"id":"m"}]}"#)
            .expect(1)
            .create_async()
            .await;
        for path in ["/v1beta/models", "/api/tags"] {
            server
                .mock("GET", path)
                .with_status(404)
                .create_async()
                .await;
        }
        let resp = probe(&server, key).await;
        assert_eq!(resp.probes[0].status, ProbeStatus::Ok);
        mock.assert_async().await;
    }

    /// api_key 为空: 全部 auth header 跳过 (Ollama 等本地无 auth 场景),
    /// anthropic-version 仍恒加.
    #[tokio::test]
    async fn probe_skips_auth_headers_when_key_empty() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
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
        for path in ["/v1/models", "/v1beta/models"] {
            server
                .mock("GET", path)
                .with_status(404)
                .create_async()
                .await;
        }
        let resp = probe(&server, "").await;
        assert_eq!(resp.probes[3].status, ProbeStatus::Ok);
        mock.assert_async().await;
    }
}
