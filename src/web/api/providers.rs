//! providers CRUD: `GET/POST/PUT/DELETE /providers[/{id}]` + `PATCH /{id}/decision`
//! + `POST /providers/probe` (协议自动探测) + `PUT/DELETE /providers/probe`
//!   (存量 id="probe" 条目的管理薄 wrapper, 见 [`update_provider_probe`])
//! + `POST /providers/{id}/pool-reset` (套餐池成员闹钟清空).
//!
//! 从 api.rs 单文件拆出 (见 #146 残留 1). CRUD 流程骨架在 [`super::crud`]
//! (泛型, 与 secrets 共享), 本文件只承载 provider 特有的 entry 构造 / api_key
//! 保留逻辑 / 列表附加字段 (protocols/shorts/pool 运行时状态). probe 是薄壳:
//! 校验 base_url 后调 `crate::proxy::probe_provider_upstream` (探测算法 SSOT 在
//! proxy 层, 与上游模型清单 fetch 同乡).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::config::DynamicEntry;
use crate::config::OverrideMode;
use crate::pool::MemberStatusView;
use crate::provider::{
    EffectiveProvider, EffectiveProviderKind, ExhaustConfig, Protocol, Provider, ProviderMasked,
};
use crate::state::{AppState, NO_STORE};

use super::crud::{Created, DecisionRequest, decision_flow};
use super::crud::{create_flow, delete_flow, update_flow};
use super::error::ApiError;

/// list 响应的单个条目: [`EffectiveProvider`] + pool 条目的**运行时观察面**
/// (平级附加字段, 非 EffectiveProvider 本体 — static/dynamic 版本走
/// [`ProviderMasked`], 无运行时语义, 不附着)。非 pool 条目该字段缺席
/// (`skip_serializing_if`, 向后兼容 — 旧客户端 shape 不变)。GET 不泄漏原则
/// 天然满足: 只有成员 id 与时刻/秒数, 无敏感值 (SEC-1)。
#[derive(Serialize)]
pub(crate) struct ProviderListItem {
    #[serde(flatten)]
    effective: EffectiveProvider,
    #[serde(skip_serializing_if = "Option::is_none")]
    pool_status: Option<Vec<MemberStatusView>>,
}

pub async fn list_providers(State(state): State<AppState>) -> impl IntoResponse {
    let providers: Vec<ProviderListItem> = state
        .providers
        .effective_snapshot()
        .into_iter()
        .map(|p| {
            // pool 条目附加每成员运行时状态 (核心价值: 用户要看 "现在打到哪份
            // 套餐/谁耗尽了")。member_status 只读无副作用 (GET 语义, 见其 doc)。
            let pool_status = match &p.kind {
                EffectiveProviderKind::Pool { members, .. } => {
                    Some(state.pools.member_status(&p.id, members))
                }
                _ => None,
            };
            ProviderListItem {
                effective: p,
                pool_status,
            }
        })
        .collect();
    // decision=Disabled 的条目不在 effective view (CFG-1), 单独附上 masked 视图,
    // 让前端能渲染灰行 + 提供切回入口 (SEC: 必须经 ProviderMasked 脱敏, 不回明文).
    let disabled: Vec<ProviderMasked> = state
        .providers
        .disabled_statics()
        .into_iter()
        .map(ProviderMasked::from)
        .collect();
    let protocols: Vec<&'static str> = Protocol::ALL.iter().map(|(_, n, _)| *n).collect();
    let shorts: Vec<&'static str> = Protocol::ALL.iter().map(|(_, _, s)| *s).collect();
    // WebUI 新建 provider 表单的协议词表: 仅 codec 覆盖族 (Gemini/Ollama 无 codec,
    // Redact 不可用且默认 fail_closed — 不在表单里引导普通用户创建; 手写配置
    // 文件/API 仍可用, 存量条目编辑时前端 append "experimental" 选项).
    let webui_protocols: Vec<&'static str> = Protocol::ALL
        .iter()
        .filter(|(p, _, _)| p.codec_covered())
        .map(|(_, n, _)| *n)
        .collect();
    let decisions: Vec<&'static str> = OverrideMode::ALL.iter().map(|(_, s)| *s).collect();
    (
        NO_STORE,
        Json(ListProvidersResponse {
            providers,
            disabled,
            protocols,
            shorts,
            webui_protocols,
            decisions,
        }),
    )
}

pub async fn create_provider(
    State(state): State<AppState>,
    Json(payload): Json<UpsertProviderRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let created: Created<EffectiveProvider> = create_flow(
        &state.providers,
        "provider",
        || payload.into_provider(),
        // #179: upsert 后路由边 (启用路由的 target) 成环 → 400 (自环已由
        // Provider::validate 拒绝, 这里覆盖跨条目环; 悬空目标放行 — 创建顺序
        // 无关, 运行时 503 兜底).
        //
        // id="probe" 保留字 (**仅挡新建**, 纯防混淆): 该 id 与探测端点共用
        // /api/providers/probe — PUT/DELETE 该 URL 的语义是 "管理同名条目",
        // 新建会让 "探测" 与 "编辑" 挤在同一 URL 上, 拒绝以免混淆. 存量条目
        // (保留字校验上线前创建 / 手写 toml) 不受影响: 经该端点补齐的
        // PUT/DELETE wrapper (update_provider_probe) 完全可管理.
        |entry| {
            if entry.id == "probe" {
                return Err(ApiError::validation(
                    "provider id 'probe' is reserved (conflicts with the /api/providers/probe endpoint)",
                ));
            }
            validate_provider_upsert(&state.providers, entry)
        },
    )?;
    Ok((StatusCode::CREATED, NO_STORE, Json(created)))
}

pub async fn update_provider(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(mut payload): Json<UpsertProviderRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let ev = update_flow(
        &state.providers,
        "provider",
        &id,
        || {
            // api_key / api_key_file / routes / members 缺省时保留旧值 (避免 WebUI
            // 编辑表单留空意外清空既有配置). 语义: payload None = 保留; Some = 显式覆盖
            // (static 基线下空串的清空语义有已知限制, 见下方 api_key 字段注释).
            //
            // #157 关键: 鉴权字段只从 **dynamic 原始条目** (get_dynamic) 回填,
            // 不用 get_effective — 旧值若是 static 来源, 把已 resolve 的明文搬进
            // override 会让明文落盘 state.toml; 现在改为 override 不记录该字段
            // (None), effective 解析时由 `Provider::inherit_from_static` 回落
            // static (转发仍带旧 key, 行为不变).
            //
            // routes / members / exhaust / cooldown 回填则**可以**走 get_effective
            // 兜底 (与 #190 protocol 回填同模式): 均非敏感, 无明文落盘顾虑 —
            // static 条目的 PUT 即首次 override 场景也能 "省略 = 保留".
            //
            // 假设: 本地单用户场景, get_dynamic 与 upsert_dynamic 之间无并发修改.
            // 多用户/并发编辑场景下存在 TOCTOU (旧值可能过期), 但仅导致配置不一致, 无安全影响.
            //
            // 限制: 若 payload 显式提供 api_key (或 api_key_file), 另一字段仍从旧值保留,
            // 可能触发互斥校验报错 (例如旧值有 api_key, 新传 api_key_file). WebUI 不暴露
            // api_key_file 输入, 仅 SDK 直接调用可能触发, 影响低.
            //
            // 构造意图哨兵: payload 显式非空 members / routes = 显式 Pool / Router
            // 构造决策 — 此时**不回填对方构造的字段** (旧值属于另一构造; 回填会
            // 把服务端自己制造的数据伪装成调用方的 "双显式" 而 400, 错误归因错位)。
            // 省略旧构造字段 + 显式发新构造字段 = 构造切换 (router↔pool 两个方向),
            // 与 Direct 意图 PUT 的静默停留行为对齐。
            let explicit_pool = payload.members.as_ref().is_some_and(|m| !m.is_empty());
            let explicit_router = payload.routes.as_ref().is_some_and(|rs| !rs.is_empty());
            if let Some(old) = state.providers.get_dynamic(&id) {
                // "保留旧值" 回填, 按旧值的构造分派 (sum type 同构, #187):
                // Direct 旧值 → 鉴权字段回填; Router 旧值 → routes 回填;
                // Pool 旧值 → members/exhaust/cooldown_secs 三字段回填 (均非
                // 敏感, 无 #157 明文落盘顾虑)。显式清空/切换由 WebUI 发空数组
                // (routes=[] / members=[]) 表达 (见下方字段注释)。
                match &old.kind {
                    crate::provider::ProviderKind::Direct(d) => {
                        if payload.api_key.is_none() {
                            payload.api_key = Some(d.api_key.clone());
                        }
                        if payload.api_key_file.is_none() {
                            payload.api_key_file = d
                                .api_key_file
                                .as_ref()
                                .map(|p| p.to_string_lossy().into_owned());
                        }
                    }
                    // 哨兵语义 (explicit_pool / explicit_router) 见 helper doc.
                    crate::provider::ProviderKind::Router(r) => {
                        payload.backfill_routes(&r.routes, explicit_pool);
                    }
                    crate::provider::ProviderKind::Pool(p) => {
                        payload.backfill_pool(p, explicit_router);
                    }
                }
            }
            // routes 回填兜底 + protocol 回填 + pool 三字段回填兜底共用**一次**
            // effective 快照 (单次取锁 + merge, 也消除两次快照间的漂移窗口)。
            // 各分支按 kind 变体互斥分派: effective 是 Router 时只有 routes 分支
            // 可能命中, 是 Direct 时只有 protocol 分支可能命中, 是 Pool 时只有
            // pool 分支可能命中。
            //
            // routes 回填兜底: dynamic 无旧条目 (PUT 即首次 override) 时触发;
            // rationale (非敏感, "省略 = 保留") 见上方闭包注释。
            //
            // protocol 回填 (#190 保留语义): 从 **effective** 的 Direct 负载回填 —
            // 覆盖 static-only 条目 (get_dynamic 无旧值的场景)。非敏感字段, 无
            // #157 明文落盘顾虑。回填只服务 Direct 意图 — Router 构造不消费
            // protocol (无此字段), 回填了也会被 into_provider 忽略, 故无需按
            // router 意图守卫; effective 为 Router 时无 Direct 负载可挖 → 不回填,
            // 也不报错。
            //
            // pool 回填兜底 (T3, 同 routes rationale): static pool 条目的 PUT 即
            // 首次 override 场景; exhaust/cooldown 逐字段回填 — 即便 payload
            // 显式发了新 members 也保留未触及字段 (partial PUT, 防 "改个成员把
            // 自定义 exhaust 静默重置回默认表")。显式退出 Pool 构造由 members=[]
            // 表达; 哨兵语义同 dynamic 层 (helper doc)。
            match state.providers.get_effective(&id).map(|e| e.kind) {
                Some(crate::provider::ProviderKind::Router(r)) => {
                    payload.backfill_routes(&r.routes, explicit_pool);
                }
                Some(crate::provider::ProviderKind::Direct(d)) if payload.protocol.is_none() => {
                    payload.protocol = Some(d.protocol);
                }
                Some(crate::provider::ProviderKind::Pool(p)) => {
                    payload.backfill_pool(&p, explicit_router);
                }
                _ => {}
            }
            payload.into_provider()
        },
        |entry| validate_provider_upsert(&state.providers, entry),
    )?;
    Ok((StatusCode::OK, NO_STORE, Json(ev)))
}

/// upsert 钩子 (#179): 类型校验收口到语义 SSOT `Provider::validate` (crud 钩子在
/// id 生成/填充后运行, 正是其正确位置 — into_provider 只做字段变换), 再叠加
/// web 特有的跨条目环检查. 消息只含 provider id.
///
/// id="probe" 保留字检查**不在此** (create/update 共用本钩子, 在这拒绝会连
/// 存量条目的合法编辑一起挡掉): 仅挡新建, 收在 create_provider 的闭包里.
fn validate_provider_upsert(
    table: &crate::provider::ProviderTable,
    entry: &Provider,
) -> Result<(), ApiError> {
    entry.validate().map_err(ApiError::validation)?;
    if table.would_cycle(entry) {
        return Err(ApiError::validation(format!(
            "provider '{}' routes would create a cycle",
            entry.id
        )));
    }
    Ok(())
}

pub async fn delete_provider(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    delete_flow(&state.providers, "provider", &id)?;
    Ok((StatusCode::NO_CONTENT, NO_STORE, ""))
}

/// `PUT /api/providers/probe`: 以固定 id="probe" 适配到 [`update_provider`]
/// 的薄 wrapper (不复制 flow 逻辑, 纯参数适配).
///
/// 存在理由: matchit 静态段优先于 `{id}` 参数段, `PUT /api/providers/{id}`
/// 永远接不到 id="probe" 的请求 — 没有本 wrapper 时存量 "probe" 条目
/// (保留字校验上线前创建 / 手写 toml) 经 API 不可编辑 (405). 补齐后该 id
/// 条目与其他条目同等可管理; 新建仍被拒 (纯防混淆, 见 create_provider).
pub async fn update_provider_probe(
    State(state): State<AppState>,
    Json(payload): Json<UpsertProviderRequest>,
) -> Result<impl IntoResponse, ApiError> {
    update_provider(State(state), Path("probe".to_string()), Json(payload)).await
}

/// `DELETE /api/providers/probe`: [`update_provider_probe`] 的删除侧薄 wrapper
/// (语义与存在理由同彼, 405 补齐).
pub async fn delete_provider_probe(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    delete_provider(State(state), Path("probe".to_string())).await
}

/// 切换对 static id 的 per-item 决策. 同 [`super::secrets::set_secret_decision`].
pub async fn set_provider_decision(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<DecisionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let mode = payload.into_mode()?;
    let ack = decision_flow(&state.providers, "provider", id, mode)?;
    Ok((StatusCode::OK, NO_STORE, Json(ack)))
}

/// `POST /api/providers/{id}/pool-reset`: 清空该 pool 全部成员闹钟 (用户动作:
/// 知道续费了/换窗了, 想立即恢复探测 — 不等闹钟自然到期)。
///
/// - 条目不存在 (含 decision=Disabled — effective 视图排除, 与 update_flow 的
///   存在性口径一致) → 404; 非 Pool 构造 → 400。
/// - reset 幂等且只动运行时内存态 (`PoolStates::reset`), 不触碰配置/落盘。
/// - ack 是轻量确认; 前端随后刷新列表取新的成员状态 (GET 派生)。
pub async fn pool_reset(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let Some(entry) = state.providers.get_effective(&id) else {
        return Err(ApiError::not_found(format!("provider {id} not found")));
    };
    let crate::provider::ProviderKind::Pool(_) = entry.kind else {
        return Err(ApiError::validation(format!(
            "provider '{id}' is not a pool provider"
        )));
    };
    state.pools.reset(&id);
    Ok((
        StatusCode::OK,
        NO_STORE,
        Json(PoolResetAck { id, reset: true }),
    ))
}

/// [`pool_reset`] 的 ack 响应 (轻量 — 状态明细走随后的 GET /api/providers)。
#[derive(Serialize)]
struct PoolResetAck {
    id: String,
    reset: bool,
}

/// `POST /api/providers/probe` 的请求 body.
#[derive(Debug, Deserialize)]
pub(crate) struct ProbeRequest {
    /// 待探测的上游 base URL (http(s), 规则同 provider 配置的 validate_base_url).
    pub base_url: String,
    /// 可选 api_key (空串 = 无 auth 探测, Ollama 等本地场景; serde default).
    #[serde(default)]
    pub api_key: String,
}

/// `POST /api/providers/probe`: 对任意 base_url 探测 4 族协议端点 (薄壳 —
/// 校验 base_url 后调 `crate::proxy::probe_provider_upstream`, 判定/推荐算法
/// SSOT 在 proxy 层).
///
/// 探测失败是**数据不是 HTTP 错误**: 恒 200 (结果落在 status=error 的 outcome),
/// 仅 base_url 非法 (复用 [`crate::provider::validate_base_url`] 同一规则) → 400.
/// 响应不含 api_key (探测 detail 经 `upstream_error_brief` 净化).
pub async fn probe_provider(
    State(state): State<AppState>,
    Json(payload): Json<ProbeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    crate::provider::validate_base_url(&payload.base_url).map_err(ApiError::validation)?;
    let response =
        crate::proxy::probe_provider_upstream(&state.upstream, &payload.base_url, &payload.api_key)
            .await;
    Ok((StatusCode::OK, NO_STORE, Json(response)))
}

#[derive(Serialize)]
pub(crate) struct ListProvidersResponse {
    pub providers: Vec<ProviderListItem>,
    /// decision=Disabled 的 static 条目 (masked). effective view 排除它们 (CFG-1),
    /// 此数组让前端可见并提供 decision 切回入口.
    pub disabled: Vec<ProviderMasked>,
    pub protocols: Vec<&'static str>,
    pub shorts: Vec<&'static str>,
    /// WebUI 新建 provider 表单展示的协议词表 (仅 codec 覆盖族, 见 `list_providers`).
    /// `protocols`/`shorts` 保持全量 — 前端路由约定表格与存量条目编辑仍需全量.
    pub webui_protocols: Vec<&'static str>,
    pub decisions: Vec<&'static str>,
}

/// 创建/更新 provider 的请求 body.
#[derive(Debug, Deserialize)]
pub(crate) struct UpsertProviderRequest {
    pub id: Option<String>,
    pub name: Option<String>,
    /// 协议. **仅 Direct 构造必填**: 缺失 → 400. Router 构造不存在 protocol
    /// (ingress 由 per-request URL 决定, egress 由 per-route 链尾决定 — 无可
    /// 陈述的事实, 见 `RouterProvider`); 请求里残留发送时被忽略, 不报错.
    /// PUT 省略时若 effective 是 Direct → 回填其 protocol ("保留" 语义, 同
    /// api_key; 注意 partial PUT 仍需完整 Direct 字段 — base_url 不回填,
    /// 缺失 400).
    #[serde(default)]
    pub protocol: Option<Protocol>,
    /// 上游 base URL. 实体 provider 必填 (http(s) + 无末尾 `/`); 路由 provider
    /// (routes 非空) 忽略, 可省略/为空 (#179).
    #[serde(default)]
    pub base_url: String,
    /// API key 明文值. 语义因 endpoint 而异:
    /// - POST (create): 省略 (None) 或空串 = 不设置 (适用 Ollama 等本地无 auth 场景).
    /// - PUT (update): 省略 (None) = 保留旧值 — override **不记录**该字段 (不落盘明文,
    ///   #157), effective 解析由 `inherit_from_static` 回落 static / dynamic 旧值.
    ///   具体值 = 显式覆盖 (新值落盘 state.toml, 属预期).
    ///
    /// 已知限制: static 基线下显式空串 `""` 无法清空 key (会被继承回落 static),
    /// 停用走 decision=disabled. 详见根 AGENTS.md "#157 已知限制" 条目.
    ///
    /// WebUI 编辑表单依赖此语义: 用户留空 input 时前端发 null, 不破坏既有 key.
    /// 与 `api_key_file` 互斥 (同时设置会在 `validate()` 报错).
    #[serde(default)]
    pub api_key: Option<String>,
    /// 从文件路径读取 api_key. PUT 时若省略 (None) 则保留旧值 (同 `api_key` 的
    /// "不记录 + 回落" 语义). 与 `api_key` 互斥. WebUI 创建 dynamic-only provider
    /// 时可用, 但通常只在 static config (sops 注入) 用.
    #[serde(default)]
    pub api_key_file: Option<String>,
    /// 路由列表 (#179 多规则化 / #187 sum type). 直接复用 [`Route`] 的
    /// 序列化 (model_pattern / target / upstream_model / priority). 三态语义:
    /// - 省略 (None): 保留旧值 (PUT) — 优先从 dynamic 旧条目回填, 无则从
    ///   effective 回填 (routes 非敏感, 无 #157 落盘顾虑); 两者皆非 Router 时不
    ///   回填 → Direct 构造.
    /// - 空数组 `[]`: 显式 **退出 Router 构造** (改回实体 provider — 与旧
    ///   route_to "" 的 "改回实体" 语义同构).
    /// - 非空数组: **Router 构造** (悬空目标放行, 运行时 503).
    ///
    /// 路由的 enabled 开关由 `priority: null` 表达 (wire 无独立 enabled 字段)。
    /// 成环 (含自环) 在 validate/upsert 钩子拒绝 (400).
    #[serde(default)]
    pub routes: Option<Vec<crate::provider::Route>>,
    /// Pool 成员列表 (T3; 三态语义与 `routes` 先例逐字同构):
    /// - 省略 (None): 保留旧值 (PUT) — 优先从 dynamic 旧条目回填, 无则从
    ///   effective 回填 (非敏感, 无 #157 落盘顾虑); 两者皆非 Pool 时不回填 →
    ///   Direct/Router 构造.
    /// - 空数组 `[]`: 显式**退出 Pool 构造** (与 routes=[] 的 "改回实体" 语义
    ///   同构 — 编辑 pool 条目切到 Direct/Router 时 WebUI 发空数组取消旧构造).
    /// - 非空数组: **Pool 构造** (悬空/重复成员放行 — 运行时 pick 永久标记 +
    ///   failover; 自环/非法 id 在 validate 拒绝).
    ///
    /// **构造切换**: 显式非空 `members` + 省略 `routes` = router→pool 切换
    /// (构造意图哨兵抑制对方构造字段的回填, 见 update_provider); 反向同理。
    /// 调用方**真实**同时显式非空 members 与 routes → 400 (sum type 单构造,
    /// 双显式是调用方错误). Direct/Router 构造下残留发送被静默忽略.
    #[serde(default)]
    pub members: Option<Vec<String>>,
    /// 耗尽信号配置 (三通道 OR). 省略 (None) = 保留旧值 (PUT) / 内置窗口限额
    /// 默认表 (POST 创建); 显式值 = 整体替换 (**字段级替换**语义, 见
    /// [`ExhaustConfig`] — 空通道 = 显式关闭). 仅 Pool 构造消费, 其余构造残留
    /// 发送被忽略. 畸形 header 规则在 validate 钩子 WARN (不拒绝).
    #[serde(default)]
    pub exhaust: Option<ExhaustConfig>,
    /// 兜底闹钟时长 (秒). 三态语义同 `exhaust` (None = 保留旧值 / 默认 60).
    #[serde(default)]
    pub cooldown_secs: Option<u64>,
    #[serde(default = "crate::provider::default_true")]
    pub enabled: bool,
}

impl UpsertProviderRequest {
    /// routes 回填: None = 保留旧值。`explicit_pool` (payload 显式非空 members =
    /// Pool 构造意图) 哨兵抑制回填 — 省略式构造切换 (router→pool) 不被旧 routes
    /// 补成 "双显式 400" (错误归因错位, 见 update_provider 闭包注释)。
    /// dynamic / effective 两层回填共用 (同语义不变量的结构保证, 两层调用点
    /// 不再各自内联判卫)。
    fn backfill_routes(&mut self, routes: &[crate::provider::Route], explicit_pool: bool) {
        if self.routes.is_none() && !explicit_pool {
            self.routes = Some(routes.to_vec());
        }
    }

    /// Pool 三字段回填: None = 保留旧值。members 受 `explicit_router` 哨兵
    /// (省略式 pool→router 切换不回填 members, 同 [`Self::backfill_routes`]);
    /// exhaust/cooldown 属 Pool 构造, 对方构造不消费, 恒回填无害。dynamic /
    /// effective 两层共用。
    fn backfill_pool(&mut self, p: &crate::provider::PoolProvider, explicit_router: bool) {
        if self.members.is_none() && !explicit_router {
            self.members = Some(p.members.clone());
        }
        if self.exhaust.is_none() {
            self.exhaust = Some(p.exhaust.clone());
        }
        if self.cooldown_secs.is_none() {
            self.cooldown_secs = Some(p.cooldown_secs);
        }
    }

    fn into_provider(self) -> Result<Provider, ApiError> {
        if let Some(id) = &self.id
            && !id.is_empty()
            && let Err(e) = crate::secrets::validate_id(id)
        {
            return Err(ApiError::validation(e));
        }
        // 结构校验 (base_url / 路由字段 / 自环 / api_key 互斥) 收口在 crud 钩子的
        // `Provider::validate` (见 validate_provider_upsert), 此处只做字段变换。
        // 构造判别 (sum type, 单构造): 显式非空 members → Pool; 显式非空 routes
        // → Router; 双显式 = 调用方错误 (400); 其余 → Direct (protocol 必填)。
        // 空数组 = 显式取消该构造 (routes=[] / members=[] 同构语义, 见字段注释),
        // 落到 Direct/Router 判定。构造不消费的字段残留发送被静默忽略 (同
        // protocol 在 Router 下的先例)。
        let kind = match (
            self.members.filter(|m| !m.is_empty()),
            self.routes.filter(|rs| !rs.is_empty()),
        ) {
            (Some(_), Some(_)) => {
                return Err(ApiError::validation(
                    "cannot specify both 'members' (pool) and 'routes' (router) — pick one construct",
                ));
            }
            (Some(members), None) => {
                crate::provider::ProviderKind::Pool(crate::provider::PoolProvider {
                    members,
                    // 缺省 = 内置窗口限额默认表 (ExhaustConfig::default) / 60s —
                    // update 路径的 "保留旧值" 已在上游回填, 到这里的 None 只剩
                    // 创建/切换构造场景, 取默认即正确语义.
                    exhaust: self.exhaust.unwrap_or_default(),
                    cooldown_secs: self
                        .cooldown_secs
                        .unwrap_or_else(crate::provider::default_pool_cooldown_secs),
                })
            }
            (None, Some(routes)) => {
                crate::provider::ProviderKind::Router(crate::provider::RouterProvider { routes })
            }
            (None, None) => {
                let protocol = self.protocol.ok_or_else(|| {
                    ApiError::validation("protocol is required for direct providers")
                })?;
                crate::provider::ProviderKind::Direct(crate::provider::DirectProvider {
                    protocol,
                    base_url: self.base_url,
                    api_key: self.api_key.unwrap_or_default(),
                    api_key_file: self.api_key_file.map(std::path::PathBuf::from),
                })
            }
        };
        Ok(Provider {
            id: self.id.unwrap_or_default(),
            enabled: self.enabled,
            name: self.name.filter(|s| !s.trim().is_empty()),
            kind,
        })
    }
}
