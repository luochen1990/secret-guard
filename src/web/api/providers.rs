//! providers CRUD: `GET/POST/PUT/DELETE /providers[/{id}]` + `PATCH /{id}/decision`
//! + `POST /providers/probe` (协议自动探测) + `PUT/DELETE /providers/probe`
//!   (存量 id="probe" 条目的管理薄 wrapper, 见 [`update_provider_probe`]).
//!
//! 从 api.rs 单文件拆出 (见 #146 残留 1). CRUD 流程骨架在 [`super::crud`]
//! (泛型, 与 secrets 共享), 本文件只承载 provider 特有的 entry 构造 / api_key
//! 保留逻辑 / 列表附加字段 (protocols/shorts). probe 是薄壳: 校验 base_url 后
//! 调 `crate::proxy::probe_provider_upstream` (探测算法 SSOT 在 proxy 层, 与
//! 上游模型清单 fetch 同乡).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::config::DynamicEntry;
use crate::config::OverrideMode;
use crate::provider::{EffectiveProvider, Protocol, Provider, ProviderMasked};
use crate::state::{AppState, NO_STORE};

use super::crud::{Created, DecisionRequest, decision_flow};
use super::crud::{create_flow, delete_flow, update_flow};
use super::error::ApiError;

pub async fn list_providers(State(state): State<AppState>) -> impl IntoResponse {
    let providers: Vec<EffectiveProvider> = state.providers.effective_snapshot();
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
            // api_key / api_key_file / routes 缺省时保留旧值 (避免 WebUI 编辑表单
            // 留空意外清空既有配置). 语义: payload None = 保留; Some = 显式覆盖
            // (static 基线下空串的清空语义有已知限制, 见下方 api_key 字段注释).
            //
            // #157 关键: 鉴权字段只从 **dynamic 原始条目** (get_dynamic) 回填,
            // 不用 get_effective — 旧值若是 static 来源, 把已 resolve 的明文搬进
            // override 会让明文落盘 state.toml; 现在改为 override 不记录该字段
            // (None), effective 解析时由 `Provider::inherit_from_static` 回落
            // static (转发仍带旧 key, 行为不变).
            //
            // routes 回填则**可以**走 get_effective 兜底 (与 #190 protocol 回填
            // 同模式): routes 非敏感, 无明文落盘顾虑 — static router 条目的
            // PUT 即首次 override 场景也能 "省略 = 保留".
            //
            // 假设: 本地单用户场景, get_dynamic 与 upsert_dynamic 之间无并发修改.
            // 多用户/并发编辑场景下存在 TOCTOU (旧值可能过期), 但仅导致配置不一致, 无安全影响.
            //
            // 限制: 若 payload 显式提供 api_key (或 api_key_file), 另一字段仍从旧值保留,
            // 可能触发互斥校验报错 (例如旧值有 api_key, 新传 api_key_file). WebUI 不暴露
            // api_key_file 输入, 仅 SDK 直接调用可能触发, 影响低.
            if let Some(old) = state.providers.get_dynamic(&id) {
                // "保留旧值" 回填, 按旧值的构造分派 (sum type 同构, #187):
                // Direct 旧值 → 鉴权字段回填; Router 旧值 → routes 回填.
                // 显式清空/切换由 WebUI 发空 routes 数组 / 完整字段表达 (见下方字段注释).
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
                    crate::provider::ProviderKind::Router(r) => {
                        // payload 省略 (None) = 保留旧路由; 显式发空数组 = 改回
                        // Direct 意图. 守卫对象是 payload 的显式新值 (客户端发新
                        // 路由时不被旧值覆盖).
                        if payload.routes.is_none() {
                            payload.routes = Some(r.routes.clone());
                        }
                    }
                }
            }
            // routes 回填兜底 + protocol 回填共用**一次** effective 快照 (单次取锁
            // + merge, 也消除两次快照间的漂移窗口). 两分支按 kind 变体互斥分派:
            // effective 是 Router 时只有 routes 分支可能命中, 是 Direct 时只有
            // protocol 分支可能命中.
            //
            // routes 回填兜底: dynamic 无旧条目 (PUT 即首次 override) 时触发;
            // rationale (非敏感, "省略 = 保留") 见上方闭包注释.
            //
            // protocol 回填 (#190 保留语义): 从 **effective** 的 Direct 负载回填 —
            // 覆盖 static-only 条目 (get_dynamic 无旧值的场景)。非敏感字段, 无
            // #157 明文落盘顾虑。回填只服务 Direct 意图 — Router 构造不消费
            // protocol (无此字段), 回填了也会被 into_provider 忽略, 故无需按
            // router 意图守卫; effective 为 Router 时无 Direct 负载可挖 → 不回填,
            // 也不报错。
            match state.providers.get_effective(&id).map(|e| e.kind) {
                Some(crate::provider::ProviderKind::Router(r)) if payload.routes.is_none() => {
                    payload.routes = Some(r.routes);
                }
                Some(crate::provider::ProviderKind::Direct(d)) if payload.protocol.is_none() => {
                    payload.protocol = Some(d.protocol);
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
    pub providers: Vec<EffectiveProvider>,
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
    /// - 空数组 `[]`: 显式 **Direct 构造** (改回实体 provider — 与旧 route_to ""
    ///   的 "改回实体" 语义同构).
    /// - 非空数组: **Router 构造** (悬空目标放行, 运行时 503).
    ///
    /// 路由的 enabled 开关由 `priority: null` 表达 (wire 无独立 enabled 字段)。
    /// 成环 (含自环) 在 validate/upsert 钩子拒绝 (400).
    #[serde(default)]
    pub routes: Option<Vec<crate::provider::Route>>,
    #[serde(default = "crate::provider::default_true")]
    pub enabled: bool,
}

impl UpsertProviderRequest {
    fn into_provider(self) -> Result<Provider, ApiError> {
        if let Some(id) = &self.id
            && !id.is_empty()
            && let Err(e) = crate::secrets::validate_id(id)
        {
            return Err(ApiError::validation(e));
        }
        // 结构校验 (base_url / 路由字段 / 自环 / api_key 互斥) 收口在 crud 钩子的
        // `Provider::validate` (见 validate_provider_upsert), 此处只做字段变换:
        // 空数组 routes = 显式改回实体 ("路由 → 实体", 与旧 route_to "" 语义同构).
        // Router 构造不消费 protocol (无此字段) — 残留发送被静默忽略.
        let kind = match self.routes.filter(|rs| !rs.is_empty()) {
            Some(routes) => {
                crate::provider::ProviderKind::Router(crate::provider::RouterProvider { routes })
            }
            None => {
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
