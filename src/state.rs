//! 进程级共享状态 [`AppState`] + HTTP 层共享常量.
//!
//! # 职责边界
//!
//! `AppState` (历史上名 `ProxyState`, 定义在 `proxy/mod.rs`) 是**整个进程**的共享状态:
//! router 与全部 handler (forwarding 转发链 / WebUI JSON API / auth) 通过 axum 的
//! `State` 槽位共享它. 它定义在转发层模块内是历史落点 — 实质是进程级 AppState,
//! 让 web / auth (展示与鉴权层) 反向依赖 proxy (转发层) 违反 "域 A → 域 B → 域 C
//! 单向承诺" (#145 偏差 3). 上移为顶层模块后, proxy / web / auth 各自**单向**依赖之.
//!
//! # 字段语义
//!
//! 各字段的来源与语义注释见结构体定义; 装配点在 `server.rs::serve`
//! (双层配置 → 两张表 + ApiKeyStore + DAG + 超时快照 → AppState).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;

use crate::auth::ApiKeyStore;
use crate::config::{OnFallbackRestore, OnProbeExhausted, OnUnsupportedProtocol};
use crate::dag::ConversationDag;
use crate::provider::ProviderTable;
use crate::secrets::SecretTable;

/// 进程级共享状态, 在 router 与 handler 间共享.
#[derive(Clone, Debug)]
pub struct AppState {
    pub upstream: reqwest::Client,
    pub providers: ProviderTable,
    pub dag: ConversationDag,
    pub secrets: SecretTable,
    /// API key 存储 (server.rs 无条件构造, 与 auth.enabled 无关 — 单用户模式下
    /// WebUI 仍可签发/管理 key). 设计详见 `src/web/api/apikeys.rs` 头部注释.
    pub api_keys: ApiKeyStore,
    /// 服务端认证是否启用 (来自 static config `[auth] enabled`). 与 ApiKeyStore
    /// 的"无条件构造"正交: store 总存在, 但 forwarding 路径的 require_api_key
    /// middleware 仅在 auth_enabled = true 时挂载. WebUI 用此标志区分 key 的
    /// "启用中 / 已禁用 / 认证未启用" 三态 (见 src/web/api/apikeys.rs::list_api_keys).
    pub auth_enabled: bool,
    /// 来自 `[redact] global_mock_prefix` (默认空串). WebUI secret upsert 时
    /// 透传给 validate_and_resolve, 用于校验 value 不含此 prefix + 注入 Auto gen_spec.prefix.
    pub global_mock_prefix: Arc<str>,
    /// 来自 `[redact] on_probe_exhausted` (默认 FailClosed, SEC-10 降级偏安全).
    /// 控制 redact probing 耗尽时是 fail-closed (返回 503 拒绝转发) 还是
    /// fail-open (显式 opt-in, skip + 原样转发).
    pub on_probe_exhausted: OnProbeExhausted,
    /// 来自 `[redact] on_unsupported_protocol` (默认 FailClosed, SEC-10). 控制
    /// codec 不覆盖的协议 (gemini/ollama) 上配置了 secrets 时是 fail-closed
    /// (返回 503 拒绝转发) 还是 fail-open (显式 opt-in, WARN + 透传放行).
    /// 仅管 secret 安全性 — 仅 model 重写降级 (无 secret) 时两模式都维持 WARN
    /// 透传. 消费点 `proxy::same_proto`.
    pub on_unsupported_protocol: OnUnsupportedProtocol,
    /// 来自 `[redact] on_fallback_restore` (默认 Withhold, SEC-10). 控制 codec
    /// 无法 parse 上游响应的 fallback 路径 (reader 拒绝但 body 仍是合法 JSON)
    /// 上, 是否把 Mock 还原为 real 发给客户端: Withhold (默认) 保留 Mock 透传
    /// (降级偏安全 — 失败响应体高概率进入客户端日志系统, Mock 按设计可安全
    /// 暴露); Restore (显式 opt-in) 恢复 RED-8 行为 (本地工具直接可用, 但 real
    /// 可能随日志扩散). 消费点 `proxy::helpers::restore_via_json_leaf_fallback`
    /// (fan_out / cross_proto 的 reader-拒绝臂共享). 非 JSON 分支不受影响.
    pub on_fallback_restore: OnFallbackRestore,
    /// 来自 `[redact] redacted_headers` (默认空), 经 [`normalize_redacted_headers`]
    /// 归一化 (trim + lowercase, 空串条目跳过) 的追加脱敏名单. 消费点
    /// `proxy::helpers::redact_headers` — 与硬编码黑名单并集生效 (SEC-4),
    /// 请求/响应两侧所有 record 记录点统一取本字段.
    pub redacted_headers: Arc<[String]>,
    /// 来自 `[server] upstream_*_timeout_secs` 的上游超时配置.
    /// forward 路径用它给 send().await / stream chunk 加超时保护.
    pub upstream_timeouts: crate::config::UpstreamTimeouts,
    /// Router provider GET /models 的上游模型清单缓存 (#196, FWD-7):
    /// per-Direct-provider, TTL 300s + serve-stale-on-error + single-flight,
    /// 语义 SSOT 见 `src/proxy/models.rs` 头部. 类型是纯数据 store (无 proxy
    /// 行为依赖), 经 `crate::proxy` re-export 在此聚合 — 组合根先例同
    /// `api_keys` (state 聚合各 feature 模块的 store 类型).
    pub model_lists: Arc<crate::proxy::ModelListCache>,
    /// 模型用量统计 + redact 审计 store (usage-stats, docs/design/usage-stats.md):
    /// SQLite 持久化 (writer 线程批量事务 insert) + SQL 聚合查询 (无内存双份簿记).
    /// `enabled = false` 时是 no-op store (record 零开销). 纯数据 store,
    /// 聚合先例同 `api_keys` / `model_lists`.
    pub usage: Arc<crate::usage::UsageStore>,
    /// models.dev 定价缓存 (usage-stats §7): 惰性首拉 + TTL + serve-stale +
    /// single-flight; 只被 /api/usage 查询路径触碰, 不在转发链上.
    pub pricing: Arc<crate::usage::PricingCache>,
    /// Pool provider (套餐池) 的进程级成员状态机: 顺序 failover pick + 耗尽
    /// 闹钟 (内存态, 不持久化 — 真相在上游, 重启重新探测). 纯数据 + 派生层
    /// store, 聚合先例同 `api_keys` / `model_lists` (state 聚合各 feature 模块
    /// 的 store 类型); 消费点: proxy dispatch (`resolve_route` 注入 pick) /
    /// 响应侧耗尽检测 (T2) / web 观察面 (`list_providers` 的成员状态 +
    /// `pool-reset`, T3)。契约见 `src/pool.rs` 头部。
    pub pools: crate::pool::PoolStates,
    /// 详细日志 (audit capture) 运行时开关: push 路径 per-request 读一次快照
    /// (建议值 `CallEvent.audit_captured`), WebUI 经 `PUT /api/settings` 即时切换.
    /// 语义与持久化见 [`AuditCapture`] 文档; 装配点 `server.rs::serve`.
    pub audit_capture: AuditCapture,
}

// ─── AuditCapture 开关 (详细日志) ───────────────────────────────────────────

/// 详细日志 (audit capture) 的运行时开关 + state.toml 持久化.
///
/// # 职责边界
///
/// - 读 (`enabled`): 转发链 push 路径 per-request 调用一次, 决定本请求是否
///   存储 `req_body_raw` / `raw_resp_body`. 决策快照进 `CallEvent.audit_captured`,
///   响应侧 attach 沿用快照 (不重读本开关) — 保证 per-request 原子性:
///   请求在途时切换开关不产生 "req 空 + resp 存了" 的半捕获撕裂.
/// - 写 (`set_enabled`): WebUI `PUT /api/settings`. RMW 持久化 state.toml
///   (与 provider/secret/apikey 表共享 `persist_lock`, 防并发互覆) +
///   更新内存 AtomicBool. 遵循 "先持久化, 再更新内存" 契约: 持久化失败时
///   内存保持旧值 (与 `DynamicTable::set_decision` 同型).
///
/// # Ordering 说明
///
/// 读用 `Relaxed`: 开关无跨字段的同步语义依赖 (每请求独立读取, 切换仅需
/// "尽快对新请求可见", 单变量 load/store 在任何 Ordering 下都满足).
#[derive(Clone, Debug)]
pub struct AuditCapture {
    enabled: Arc<AtomicBool>,
    state_path: Arc<PathBuf>,
    persist_lock: Arc<Mutex<()>>,
}

impl AuditCapture {
    /// 构造: `initial` 来自启动时加载的 `DynamicState.audit_capture`.
    pub fn new(initial: bool, state_path: PathBuf, persist_lock: Arc<Mutex<()>>) -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(initial)),
            state_path: Arc::new(state_path),
            persist_lock,
        }
    }

    /// 当前开关状态 (转发链 push 路径 per-request 读一次).
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// 切换开关: RMW 持久化 state.toml + 更新内存 (先持久化再更新, 见类型文档).
    /// 返回落库后的实际值.
    pub fn set_enabled(&self, v: bool) -> anyhow::Result<()> {
        let _guard = self.persist_lock.lock();
        // 持久化 RMW: 与 set_decision 同型 — 只为改一个字段, secret 早已
        // validate 过, 用空 prefix 跳过 re-validate.
        let mut state = crate::config::DynamicState::load_or_empty(&self.state_path, "")?;
        state.audit_capture = v;
        let text = state.to_toml()?;
        crate::config::atomic_write(&self.state_path, &text)?;
        self.enabled.store(v, Ordering::Relaxed);
        Ok(())
    }
}

// ─── HTTP 层共享常量 ────────────────────────────────────────────────────────

/// 共享的响应安全 header 组 (axum 的 `[(name, value); N]` 接受 `(&str, &str)`).
///
/// - `cache-control: no-store, ...` — WebUI/API 响应是动态数据, 不经任何缓存.
/// - `x-content-type-options: nosniff` (SEC-S1) — 阻止浏览器 MIME sniffing:
///   JSON/文本端点即使被注入也不得被重新解释为脚本/HTML (纵深防御, 对
///   `escapeHtml` 纪律的兜底).
///
/// 仅用于 WebUI / JSON API / auth 响应 — **转发链响应绝不带** (FWD-1: 网关对
/// wire 的唯一合法修改是 real↔mock 替换, 不追加 header).
///
/// 历史上定义在 `web::api` (资源组 CRUD 模块) → `web::mod` (web 层共享常量), 但消费者
/// 跨层: web::api (本模块所有 endpoint) + `crate::auth::handlers` (OIDC login/logout/me).
/// 让 auth 反向依赖 web 违反层间单向承诺 (鉴权层是更低层基础设施), 故落位顶层
/// HTTP 常量小模块, web / auth 各自单向取用 (#145 偏差 3).
pub const NO_STORE: [(&str, &str); 2] = [
    ("cache-control", "no-store, no-cache, must-revalidate"),
    ("x-content-type-options", "nosniff"),
];

// ─── [redact] redacted_headers 归一化 (SEC-4) ────────────────────────────────

/// 归一化 `[redact] redacted_headers` 配置: 每条 trim + lowercase, 归一化后为
/// 空串的条目跳过. 产物供 [`AppState::redacted_headers`] 持有, 与
/// `redact_headers` 的 lowercase header 名做**精确匹配** — 匹配端不做归一化
/// (集中式预处理: 配置的所有脏形态在装配点一次收口).
pub fn normalize_redacted_headers(raw: &[String]) -> Arc<[String]> {
    raw.iter()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_trims_lowercases_and_skips_empty() {
        let raw = vec![
            "  X-My-Service-Key ".to_string(), // trim + lowercase
            "x-other".to_string(),             // 已规范, 原样保留
            "   ".to_string(),                 // 纯空白 → 跳过
            String::new(),                     // 空串 → 跳过
        ];
        let out = normalize_redacted_headers(&raw);
        assert_eq!(
            out.iter().as_slice(),
            ["x-my-service-key".to_string(), "x-other".to_string()].as_slice()
        );
    }

    #[test]
    fn normalize_empty_input_yields_empty_list() {
        // 默认配置 (空名单) 归一化后仍为空 — 默认行为不变的契约前提.
        assert!(normalize_redacted_headers(&[]).is_empty());
    }

    // ─── AuditCapture: 持久化 round-trip + 内存契约 ───────────────────────

    fn tmp_path(label: &str) -> PathBuf {
        // 专属子目录 (而非 /tmp/opencode/tmp 直下): rollback 测试会把**父目录**
        // 设为只读 — 必须只影响本测试自己的目录, 不干扰并发的其他测试.
        let dir = PathBuf::from(format!(
            "/tmp/opencode/tmp/test-audit-capture-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("state.toml")
    }

    #[test]
    fn audit_capture_set_enabled_persists_and_round_trips() {
        // 契约: set_enabled 持久化到 state.toml, 重启路径 (load_or_empty → new)
        // 读回同一状态 — "重启恢复" 的单元层覆盖 (集成层见 tests/integration.rs).
        let path = tmp_path("roundtrip");
        let sw = AuditCapture::new(false, path.clone(), Arc::new(Mutex::new(())));
        assert!(!sw.enabled(), "initial false");

        sw.set_enabled(true).unwrap();
        assert!(sw.enabled(), "memory updated after persist");

        // "重启": 从磁盘重新加载 DynamicState 构造新开关.
        let state = crate::config::DynamicState::load_or_empty(&path, "").unwrap();
        let sw2 = AuditCapture::new(state.audit_capture, path.clone(), Arc::new(Mutex::new(())));
        assert!(sw2.enabled(), "state survives restart path");

        // 关回去也持久化.
        sw2.set_enabled(false).unwrap();
        let state3 = crate::config::DynamicState::load_or_empty(&path, "").unwrap();
        assert!(!state3.audit_capture);
    }

    #[test]
    fn audit_capture_set_enabled_failure_keeps_old_memory() {
        // 契约 (先持久化再更新内存): 持久化失败时内存保持旧值 — 与
        // DynamicTable::set_decision 的回滚语义同型.
        let path = tmp_path("rollback");
        // 预写一个合法 state, 让 load_or_empty 成功、atomic_write 失败 (目录只读).
        crate::config::atomic_write(&path, "").unwrap();
        let dir = path.parent().unwrap().to_path_buf();
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o500))
            .unwrap();

        let sw = AuditCapture::new(false, path, Arc::new(Mutex::new(())));
        let err = sw
            .set_enabled(true)
            .expect_err("persist into read-only dir must fail");
        assert!(!err.to_string().is_empty());
        // 核心断言: 内存未变 (回滚生效).
        assert!(!sw.enabled(), "memory must roll back on persist failure");

        // 恢复权限 (Drop 语义手动补齐, tmp 目录复用 /tmp/opencode/tmp).
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
    }

    #[test]
    fn audit_capture_old_state_toml_without_field_defaults_false() {
        // 契约: 旧版 state.toml 无 audit_capture 字段 → serde default false
        // (升级兼容: 不存在 "缺字段启动失败" 或意外开启).
        let path = tmp_path("legacy");
        std::fs::write(&path, "api_keys_disabled = []\n").unwrap();
        let state = crate::config::DynamicState::load_or_empty(&path, "").unwrap();
        assert!(!state.audit_capture);
    }
}
