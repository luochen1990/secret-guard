//! [`UsageStore`]: usage / redact 明细的 SQLite 持久化 + SQL 聚合查询.
//!
//! # 持久化语义 (P-5 修订: SQLite, 2026-09)
//!
//! - 存储是单个 SQLite 文件 (`usage.sqlite3` 固定名, 落 state.toml 同目录 —
//!   SSOT: `server.rs::state_dir_artifact`; 不能挂 config 同目录: 部署形态
//!   config 常在只读位置如 /nix/store, 且 store 文件名含内容 hash 做 stem
//!   会随 rebuild 换库. WAL 模式 + NORMAL 同步 — 本地单进程下崩溃安全与
//!   性能的常规平衡点.
//! - **热路径零同步 IO**: `record` / `record_redact` 经 std mpsc 交给独立 writer
//!   线程, 批量事务 insert (非阻塞 drain 攒批, channel 排空即 flush — 无定时
//!   驻留窗口, 上限 64 条/批; 设计 §4, 不在 tokio worker 上做 DB IO).
//! - **无内存聚合双份簿记**: summary 查询直接 SQL `GROUP BY` (读连接与写连接
//!   共享同一 `Arc<Mutex<Connection>>`, 单文件单连接 — WAL 下读写交错由 Mutex
//!   串行化, WebUI 5s 节流轮询的频率下无竞争压力). 这是相对 JSONL 版的**架构
//!   净简化**: 不再有 "启动重放重建内存 cells" 的第二份事实.
//! - 写失败 best-effort: WARN 一次 + `dropped` 计数, 查询照常 (ROB-*).
//! - retention: 启动时 `DELETE WHERE ts < cutoff` (O(过期行) 而非 JSONL 版的
//!   全文件重写).
//! - 文件打开失败不致命: WARN + 降级 `:memory:` (统计可用, 明细不持久 —
//!   usage 是增强功能, 不能阻塞网关启动).
//!
//! # Schema (user_version = 1)
//!
//! `usage_events`: 每请求一行 (ts=RFC3339 UTC 字典序==时间序; hour=本地时区
//! `'YYYY-MM-DDTHH'` 聚合键, 插入时 Rust 侧计算 — 避免 SQL 时区体操, day 视图
//! = `substr(hour,1,10)` 折叠). `status` 存原始状态码 (2xx/429/4xx/5xx 分类在
//! 查询 SQL 里派生, 不落 per-class flag). `round_kind` 0/1/2 = Normal/Retry/
//! NoMessages (声明序).
//!
//! `redact_events`: 每请求 × 每命中 secret 一行 (USAGE-7, 详见 `RedactEvent`).
//!
//! # 聚合结构
//!
//! `Vec<((hour|day, provider, model), UsageAgg)>` — SQL GROUP BY 的行形态,
//! by_bucket / by_model / by_provider 视图在 summary 派生层折叠. day 为**本地
//! 时区**日期 (本地工具, "今天" 的用户直觉, 设计 §6).

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

use parking_lot::Mutex;
use rusqlite::Connection;
use tracing::{info, warn};

use crate::config::UsageConfig;
use crate::dag::RoundKind;

use super::{RedactEvent, UsageEvent};

/// 攒批上限 (条) — writer 线程非阻塞 drain 到此值即收尾落库. 无超时参数:
/// recv 阻塞等首条, channel 空时批次已 flush, 不存在 "攒着不写" 的窗口.
const BATCH_MAX: usize = 64;

/// schema 版本 (PRAGMA user_version; 未来 schema 演进时递增并写迁移).
const SCHEMA_VERSION: i32 = 1;

/// 按 (hour|day, provider, model) 三元组的聚合计数 (SQL GROUP BY 的行形态).
/// Serialize: summary DTO 经 `#[serde(flatten)]` 内嵌 (wire 键 == 字段名).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct UsageAgg {
    pub requests: u64,
    /// usage == None 的请求数 (P-3 缺失显式; 对 token / cost 贡献恒 0).
    pub requests_without_usage: u64,
    /// RoundKind::Retry 的轮数 (IR 等价重发 — "重试也是钱" 的浪费可见性).
    pub retries: u64,
    /// RoundKind::NoMessages 的轮数 (normal = requests - retries - no_messages,
    /// 派生不落列).
    pub no_messages: u64,
    /// status == 429 的请求数 (限流 — 通常触发客户端重试, 与 retries 联动看).
    pub rate_limited_429: u64,
    /// 其余 4xx (除 429).
    pub errors_4xx: u64,
    /// 5xx.
    pub errors_5xx: u64,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

/// 聚合键: (bucket, provider, model). bucket 是本地时区 hour (`YYYY-MM-DDTHH`)
/// 或 day (`YYYY-MM-DD`, 长窗口折叠). pub: summary 派生层复用.
pub type AggKey = (String, String, Option<String>);

/// 查询粒度: 短窗口 (≤ [`super::summary`] 阈值) 按小时, 长窗口按天折叠.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granularity {
    Hour,
    Day,
}

/// redact 按 (secret_id, mock) 的聚合行.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RedactSecretRow {
    pub secret_id: String,
    pub mock: String,
    pub hits: u64,
    /// 位置分类分布 (category → 计数; SQL json_group_object 聚合, 治理归因:
    /// "哪个环节把 secret 塞进来", 语义见 `codec::ir::HitLocations`).
    pub categories: std::collections::BTreeMap<String, u64>,
    /// 首次 / 最近命中 (RFC3339 UTC; 同 secret 多 mock 行各自统计).
    pub first_ts: String,
    pub last_ts: String,
}

/// redact 最近事件明细行 (倒序, limit 由查询侧定).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RedactRecentRow {
    pub ts: String,
    pub secret_id: String,
    pub mock: String,
    pub category: String,
    /// 该分类在本请求中的出现次数.
    pub count: u64,
    /// DAG node id (悬空容忍: restart/淘汰后 GET /records/{node} 404, UI 降级提示).
    pub node: Option<String>,
    /// auth 归因 (API key label; 单用户模式 null).
    pub api_key_label: Option<String>,
    pub provider: String,
    pub model_req: Option<String>,
    pub proto: String,
}

/// writer 线程的命令 (单 channel 双事件类型 + flush 屏障).
enum Command {
    Usage(UsageEvent),
    Redact(RedactEvent),
    /// 同步屏障: 处理完此前所有命令后 ack (`flush_for_test` / 未来 graceful
    /// shutdown 复用; 生产热路径不使用).
    Flush(Sender<()>),
}

/// usage / redact 统计的进程级 store (AppState 聚合, 组合根先例同 `api_keys`).
#[derive(Debug)]
pub struct UsageStore {
    enabled: bool,
    /// 配置的 retention (API 层的 hours 上限用; 0 = 永久 = 无上限).
    retention_days: u32,
    /// 读写共享的单连接 (WAL + Mutex 串行化; writer 线程持同 Arc 批量写).
    conn: Option<Arc<Mutex<Connection>>>,
    /// writer 线程发送端 (enabled 且线程成功 spawn 时 Some; drop 时线程随
    /// channel 关闭退出并 flush 尾批). 热路径 `record` 只 `send` (非阻塞).
    writer: Option<Sender<Command>>,
    /// writer 线程写失败计数 (可观测, UI 不展示仅日志).
    dropped: Arc<AtomicU64>,
}

impl UsageStore {
    /// 未启用 (零开销 no-op; record / 查询直接返回空).
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            retention_days: 0,
            conn: None,
            writer: None,
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// 纯内存 store (`:memory:`, 不持久) — 单测 / AppState 测试 fixture /
    /// 文件打开失败时的降级目标. 与生产同代码路径 (schema + 同步 insert,
    /// 不起 writer 线程 — 测试断言无需 flush 等待).
    pub fn in_memory() -> Self {
        let conn = Connection::open_in_memory().expect(":memory: sqlite cannot fail");
        init_schema(&conn);
        Self {
            enabled: true,
            retention_days: 0,
            conn: Some(Arc::new(Mutex::new(conn))),
            writer: None,
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// 生产构造: 打开 (或创建) SQLite 文件 + retention 清理 + 起 writer 线程.
    ///
    /// 文件打开 / 线程 spawn 失败不致命 (WARN + 降级 `:memory:`, 明细不持久 —
    /// best-effort): usage 统计是增强功能, 不能阻塞网关启动.
    pub fn open(config: &UsageConfig, db_path: &Path) -> Self {
        if !config.enabled {
            return Self::disabled();
        }
        let conn = match open_file_db(db_path) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    path = %db_path.display(),
                    error = %e,
                    "usage sqlite not writable; stats run in-memory only"
                );
                let mut this = Self::in_memory();
                this.retention_days = config.retention_days;
                return this;
            }
        };
        let n_expired = apply_retention(&conn, config);
        if n_expired > 0 {
            info!(path = %db_path.display(), n_expired, "usage sqlite: expired rows deleted (retention)");
        }
        info!(path = %db_path.display(), "usage stats store ready");
        let conn = Arc::new(Mutex::new(conn));
        // writer 线程 spawn 失败 (资源耗尽): WARN + 降级同步直写模式
        // (writer=None 时 record 在调用线程 insert — 慢但不丢, 见 `record`).
        let dropped = Arc::new(AtomicU64::new(0));
        let (tx, rx) = std::sync::mpsc::channel::<Command>();
        let writer = match std::thread::Builder::new()
            .name("usage-sqlite".into())
            .spawn({
                let conn = Arc::clone(&conn);
                let dropped = Arc::clone(&dropped);
                move || writer_loop(conn, rx, dropped)
            }) {
            Ok(_) => Some(tx),
            Err(e) => {
                warn!(error = %e, "usage sqlite writer thread spawn failed; falling back to synchronous inserts");
                None
            }
        };
        Self {
            enabled: true,
            retention_days: config.retention_days,
            conn: Some(conn),
            writer,
            dropped,
        }
    }

    pub fn is_disabled(&self) -> bool {
        !self.enabled
    }

    /// 记录一条 usage 事件: writer 线程批量 / 无 writer 时同步直写 (SSOT 同一
    /// `insert_batch`, 分叉仅在调度时机).
    pub fn record(&self, event: UsageEvent) {
        if !self.enabled {
            return;
        }
        self.dispatch(Command::Usage(event));
    }

    /// 记录 redact 审计事件 (同 `record` 的调度语义).
    pub fn record_redact(&self, event: RedactEvent) {
        if !self.enabled {
            return;
        }
        self.dispatch(Command::Redact(event));
    }

    fn dispatch(&self, cmd: Command) {
        if let Some(tx) = &self.writer {
            if tx.send(cmd).is_err() {
                // writer 线程已退出 (仅 drop 场景); 计数即可, 不刷日志 (shutdown 噪音).
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        } else if let Some(conn) = &self.conn {
            // 同步直写降级路径 (writer spawn 失败 / 测试 in_memory 模式).
            match cmd {
                Command::Usage(ev) => {
                    insert_usages(&mut conn.lock(), &[ev]);
                }
                Command::Redact(re) => {
                    insert_redacts(&mut conn.lock(), &[re]);
                }
                Command::Flush(ack) => {
                    let _ = ack.send(());
                }
            }
        }
    }

    /// 同步屏障: writer 线程处理完此前所有命令后返回 (测试断言用).
    pub fn flush_for_test(&self) {
        if let Some(tx) = &self.writer {
            let (ack_tx, ack_rx) = std::sync::mpsc::channel();
            if tx.send(Command::Flush(ack_tx)).is_ok() {
                let _ = ack_rx.recv_timeout(Duration::from_secs(5));
            }
        }
    }

    /// 聚合查询: 窗口 (bucket >= cutoff) 内按 (bucket, provider, model) 分组.
    ///
    /// `gran` 决定 bucket 是 hour 还是 day (SQL GROUP BY / ORDER BY 确定性 —
    /// USAGE-3 要求同两次查询 f64 求和顺序一致).
    pub fn query_cells(&self, cutoff: &str, gran: Granularity) -> Vec<(AggKey, UsageAgg)> {
        let Some(conn) = &self.conn else {
            return Vec::new();
        };
        let conn = conn.lock();
        // day 粒度 = hour 前缀折叠 (GROUP BY / ORDER BY 可引用 SELECT 别名 bucket).
        let key_expr = match gran {
            Granularity::Hour => "hour",
            Granularity::Day => "substr(hour, 1, 10)",
        };
        let sql = format!(
            "SELECT {key_expr} AS bucket, provider, model, \
             COUNT(*), \
             SUM(usage_i IS NULL), \
             SUM(round_kind = 1), SUM(round_kind = 2), \
             SUM(status = 429), \
             SUM(status BETWEEN 400 AND 499 AND status != 429), \
             SUM(status >= 500), \
             SUM(COALESCE(usage_i, 0)), SUM(COALESCE(usage_o, 0)), \
             SUM(COALESCE(usage_cr, 0)), SUM(COALESCE(usage_cw, 0)) \
             FROM usage_events WHERE hour >= ?1 \
             GROUP BY bucket, provider, model \
             ORDER BY bucket, provider, model"
        );
        // 注: WHERE 恒用原始 hour 列比较 (SQLite WHERE 不能引用 SELECT 别名);
        // day 粒度时 cutoff 是 day 前缀, `hour >= day_cutoff` 的字典序包含该天
        // 起的全部 hour (hour 前 10 字符即 day), 语义等价且走 idx_usage_hour.
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "usage sqlite query failed");
                return Vec::new();
            }
        };
        let rows = stmt.query_map([cutoff], |row| {
            // SQLite INTEGER 是 i64; 计数/求和恒非负, cast 到 u64 (饱和语义: i64::MAX
            // as u64 仍是巨值, 本地工具量级下不可达).
            let n = |idx: usize| -> rusqlite::Result<u64> { Ok(row.get::<_, i64>(idx)? as u64) };
            Ok((
                (
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ),
                UsageAgg {
                    requests: n(3)?,
                    requests_without_usage: n(4)?,
                    retries: n(5)?,
                    no_messages: n(6)?,
                    rate_limited_429: n(7)?,
                    errors_4xx: n(8)?,
                    errors_5xx: n(9)?,
                    input: n(10)?,
                    output: n(11)?,
                    cache_read: n(12)?,
                    cache_write: n(13)?,
                },
            ))
        });
        match rows {
            Ok(iter) => iter.filter_map(Result::ok).collect(),
            Err(e) => {
                warn!(error = %e, "usage sqlite query rows failed");
                Vec::new()
            }
        }
    }

    /// redact 审计查询: 按 (secret_id, mock) 聚合 + 最近事件明细 (倒序, ≤ limit).
    pub fn query_redacts(
        &self,
        cutoff: &str,
        limit: usize,
    ) -> (Vec<RedactSecretRow>, Vec<RedactRecentRow>) {
        let Some(conn) = &self.conn else {
            return (Vec::new(), Vec::new());
        };
        let conn = conn.lock();
        // 两层聚合: 内层 per (secret, mock, category) 计数, 外层折回 (secret, mock)
        // 并用 json_group_object (SQLite JSON1, bundled 版内置) 组装 categories
        // 分布 — Rust 侧解析回 Map, wire 上是 JSON object 而非字符串.
        let by_secret = conn
            .prepare(
                "SELECT secret_id, mock, SUM(cnt), MIN(first_ts), MAX(last_ts), \
                        json_group_object(category, cnt) \
                 FROM (SELECT secret_id, mock, category, \
                              SUM(count) AS cnt, MIN(ts) AS first_ts, MAX(ts) AS last_ts \
                       FROM redact_events WHERE hour >= ?1 \
                       GROUP BY secret_id, mock, category) \
                 GROUP BY secret_id, mock \
                 ORDER BY SUM(cnt) DESC, secret_id, mock",
            )
            .and_then(|mut s| {
                s.query_map([cutoff], |row| {
                    let categories_json: String = row.get(5)?;
                    Ok(RedactSecretRow {
                        secret_id: row.get(0)?,
                        mock: row.get(1)?,
                        hits: row.get::<_, i64>(2)? as u64,
                        first_ts: row.get(3)?,
                        last_ts: row.get(4)?,
                        categories: serde_json::from_str(&categories_json).unwrap_or_default(),
                    })
                })
                .map(|iter| iter.filter_map(Result::ok).collect())
            })
            .unwrap_or_else(|e| {
                warn!(error = %e, "redact sqlite query failed");
                Vec::new()
            });
        let recent = conn
            .prepare(
                "SELECT ts, secret_id, mock, category, count, node, api_key_label, \
                        provider, model_req, proto \
                 FROM redact_events WHERE hour >= ?1 \
                 ORDER BY id DESC LIMIT ?2",
            )
            .and_then(|mut s| {
                s.query_map(rusqlite::params![cutoff, limit as i64], |row| {
                    Ok(RedactRecentRow {
                        ts: row.get(0)?,
                        secret_id: row.get(1)?,
                        mock: row.get(2)?,
                        category: row.get(3)?,
                        count: row.get::<_, i64>(4)? as u64,
                        node: row.get(5)?,
                        api_key_label: row.get(6)?,
                        provider: row.get(7)?,
                        model_req: row.get(8)?,
                        proto: row.get(9)?,
                    })
                })
                .map(|iter| iter.filter_map(Result::ok).collect())
            })
            .unwrap_or_else(|e| {
                warn!(error = %e, "redact sqlite recent query failed");
                Vec::new()
            });
        (by_secret, recent)
    }

    /// 配置的 retention 天数 (API 的 hours 查询上限; 0 = 无上限).
    pub fn retention_days(&self) -> u32 {
        self.retention_days
    }

    /// usage 明细累计行数 (测试 + 轻量可观测; 重放恢复断言用).
    pub fn total_events(&self) -> u64 {
        let Some(conn) = &self.conn else {
            return 0;
        };
        conn.lock()
            .query_row("SELECT COUNT(*) FROM usage_events", [], |r| {
                r.get::<_, i64>(0)
            })
            .map(|n| n as u64)
            .unwrap_or(0)
    }
}

// ─── 内部: schema / insert / writer ────────────────────────────────────────

/// 打开文件库: WAL + busy_timeout + synchronous=NORMAL (本地单进程的常规平衡).
fn open_file_db(path: &Path) -> rusqlite::Result<Connection> {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.busy_timeout(Duration::from_millis(5000))?;
    init_schema(&conn);
    Ok(conn)
}

/// 建表 (幂等) + 版本标记. schema 演进策略: 新版本二进制打开旧库 → 建新表
/// (IF NOT EXISTS 幂等) + 版本号前进; 旧版本二进制打开新库 (user_version 更大)
/// → WARN 继续跑 (best-effort: 明细是可放弃的数据, 用户可删库重建).
fn init_schema(conn: &Connection) {
    let sql = "\
        CREATE TABLE IF NOT EXISTS usage_events (\
            id INTEGER PRIMARY KEY, \
            ts TEXT NOT NULL, \
            hour TEXT NOT NULL, \
            provider TEXT NOT NULL, \
            model TEXT, \
            model_req TEXT, \
            proto TEXT NOT NULL, \
            status INTEGER NOT NULL, \
            complete INTEGER NOT NULL, \
            round_kind INTEGER NOT NULL, \
            usage_i INTEGER, usage_o INTEGER, usage_cr INTEGER, usage_cw INTEGER);\
        CREATE INDEX IF NOT EXISTS idx_usage_hour ON usage_events(hour);\
        CREATE TABLE IF NOT EXISTS redact_events (\
            id INTEGER PRIMARY KEY, \
            ts TEXT NOT NULL, \
            hour TEXT NOT NULL, \
            secret_id TEXT NOT NULL, \
            mock TEXT NOT NULL, \
            category TEXT NOT NULL, \
            count INTEGER NOT NULL, \
            node TEXT NOT NULL, \
            api_key_label TEXT, \
            provider TEXT NOT NULL, \
            model_req TEXT, \
            proto TEXT NOT NULL);\
        CREATE INDEX IF NOT EXISTS idx_redact_hour ON redact_events(hour);\
        CREATE INDEX IF NOT EXISTS idx_redact_secret ON redact_events(secret_id);";
    if let Err(e) = conn.execute_batch(sql) {
        warn!(error = %e, "usage sqlite schema init failed");
        return;
    }
    // 版本守卫: 只允许前进 (v0 空库 → v1), 遇到更新版本只 WARN 不回写 —
    // 防旧二进制静默破坏新库的迁移判据.
    match conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)) {
        Ok(v) if v > SCHEMA_VERSION as i64 => {
            warn!(
                found = v,
                supported = SCHEMA_VERSION,
                "usage sqlite schema is newer than this binary; continuing best-effort (delete the db file to reset)"
            );
        }
        _ => {
            if let Err(e) = conn.pragma_update(None, "user_version", SCHEMA_VERSION) {
                warn!(error = %e, "usage sqlite user_version set failed");
            }
        }
    }
}

/// retention 清理 (ts 字典序比较; RFC3339 UTC 字符串序 == 时间序). 返回删除行数.
fn apply_retention(conn: &Connection, config: &UsageConfig) -> u64 {
    let Some(cutoff) = (config.retention_days > 0).then(|| {
        (chrono::Utc::now() - chrono::Duration::days(config.retention_days as i64)).to_rfc3339()
    }) else {
        return 0;
    };
    let n = (|| -> rusqlite::Result<u64> {
        let n1 = conn.execute(
            "DELETE FROM usage_events WHERE ts < ?1",
            rusqlite::params![cutoff],
        )? as u64;
        let n2 = conn.execute(
            "DELETE FROM redact_events WHERE ts < ?1",
            rusqlite::params![cutoff],
        )? as u64;
        Ok(n1 + n2)
    })();
    n.unwrap_or_else(|e| {
        warn!(error = %e, "usage sqlite retention cleanup failed");
        0
    })
}

/// 本地时区 hour 聚合键 (`YYYY-MM-DDTHH`, 设计 §6: 本地工具的用户直觉).
fn hour_key(ts: &chrono::DateTime<chrono::Utc>) -> String {
    ts.with_timezone(&chrono::Local)
        .format("%Y-%m-%dT%H")
        .to_string()
}

/// RoundKind → 存储编码 (声明序: Normal=0 / Retry=1 / NoMessages=2).
fn round_kind_code(kind: &RoundKind) -> u8 {
    match kind {
        RoundKind::Normal => 0,
        RoundKind::Retry => 1,
        RoundKind::NoMessages => 2,
    }
}

/// 事务骨架 (SSOT): begin → prepare → 循环 execute(bind) → commit.
///
/// 知识点单点化: stmt 必须出块 drop 后 tx 才能 commit (rusqlite 借用规则);
/// 错误处理 (WARN + 计数落点) 只写一次. 事件类型差异 (SQL + 参数绑定) 留在调用方.
fn insert_batch<T>(
    conn: &mut Connection,
    label: &str,
    sql: &str,
    events: &[T],
    bind: impl Fn(&mut rusqlite::Statement<'_>, &T) -> rusqlite::Result<usize>,
) -> usize {
    let mut ok = 0;
    let tx = match conn.transaction() {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, count = events.len(), "{label} sqlite insert begin failed; events dropped");
            return 0;
        }
    };
    {
        let mut stmt = match tx.prepare(sql) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "{label} sqlite insert prepare failed; events dropped");
                return 0;
            }
        };
        for ev in events {
            match bind(&mut stmt, ev) {
                Ok(_) => ok += 1,
                Err(e) => warn!(error = %e, "{label} sqlite insert row failed; event dropped"),
            }
        }
    }
    match tx.commit() {
        Ok(()) => ok,
        Err(e) => {
            warn!(error = %e, "{label} sqlite insert commit failed; events dropped");
            0
        }
    }
}

const INSERT_USAGE_SQL: &str = "\
    INSERT INTO usage_events \
    (ts, hour, provider, model, model_req, proto, status, complete, round_kind, \
     usage_i, usage_o, usage_cr, usage_cw) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";

/// 批量 insert usage 事件 (单事务; 调用方持有连接锁). 返回成功行数 (dropped 计数用).
fn insert_usages(conn: &mut Connection, events: &[UsageEvent]) -> usize {
    insert_batch(conn, "usage", INSERT_USAGE_SQL, events, |stmt, ev| {
        let (i, o, cr, cw) = match &ev.usage {
            Some(q) => (
                Some(q.i as i64),
                Some(q.o as i64),
                Some(q.cr as i64),
                Some(q.cw as i64),
            ),
            None => (None, None, None, None),
        };
        stmt.execute(rusqlite::params![
            ev.ts.to_rfc3339(),
            hour_key(&ev.ts),
            ev.provider,
            ev.model,
            ev.model_req,
            ev.proto,
            ev.status,
            ev.complete,
            round_kind_code(&ev.round_kind),
            i,
            o,
            cr,
            cw,
        ])
    })
}

const INSERT_REDACT_SQL: &str = "\
    INSERT INTO redact_events \
    (ts, hour, secret_id, mock, category, count, node, api_key_label, provider, model_req, proto) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";

/// 批量 insert redact 事件 (单事务; 调用方持有连接锁). 返回成功行数.
fn insert_redacts(conn: &mut Connection, events: &[RedactEvent]) -> usize {
    insert_batch(conn, "redact", INSERT_REDACT_SQL, events, |stmt, ev| {
        stmt.execute(rusqlite::params![
            ev.ts.to_rfc3339(),
            hour_key(&ev.ts),
            ev.secret_id,
            ev.mock,
            ev.category,
            ev.count as i64,
            ev.node,
            ev.api_key_label,
            ev.provider,
            ev.model_req,
            ev.proto,
        ])
    })
}

/// writer 线程的攒批缓冲 (usages + redacts + Flush acks 三向量收口;
/// acks 不计入 BATCH_MAX — Flush 是屏障不是事件).
struct Batch {
    usages: Vec<UsageEvent>,
    redacts: Vec<RedactEvent>,
    acks: Vec<Sender<()>>,
}

impl Batch {
    fn new() -> Self {
        Self {
            usages: Vec::new(),
            redacts: Vec::new(),
            acks: Vec::new(),
        }
    }

    fn push(&mut self, cmd: Command) {
        match cmd {
            Command::Usage(ev) => self.usages.push(ev),
            Command::Redact(re) => self.redacts.push(re),
            Command::Flush(ack) => self.acks.push(ack),
        }
    }

    fn event_count(&self) -> usize {
        self.usages.len() + self.redacts.len()
    }

    /// 成对落库 (close 分支与主路径共用), 返回 (期望数, 成功数).
    fn write(&mut self, conn: &mut Connection) -> (u64, u64) {
        let expected = self.event_count() as u64;
        if expected == 0 {
            return (0, 0);
        }
        let ok = insert_usages(conn, &self.usages) + insert_redacts(conn, &self.redacts);
        (expected, ok as u64)
    }

    fn ack_all(&mut self) {
        for ack in std::mem::take(&mut self.acks) {
            let _ = ack.send(());
        }
    }
}

/// writer 线程主体: recv 阻塞等首条 → 非阻塞 drain 攒批 (上限 BATCH_MAX, Flush
/// 屏障立即收尾) → 单事务 insert; Flush 命令在批次落库后 ack.
fn writer_loop(conn: Arc<Mutex<Connection>>, rx: Receiver<Command>, dropped: Arc<AtomicU64>) {
    let mut warned = false;
    loop {
        let mut batch = Batch::new();
        match rx.recv() {
            Ok(cmd) => batch.push(cmd),
            Err(_) => {
                // channel 关闭 (进程 shutdown): drain 队列内残余后收尾 — 尽量
                // 少丢已 record 未落库的尾部事件 (无 fsync 保证, 尽力而为).
                while let Ok(cmd) = rx.try_recv() {
                    batch.push(cmd);
                }
                batch.write(&mut conn.lock());
                return;
            }
        }
        while batch.event_count() < BATCH_MAX {
            match rx.try_recv() {
                Ok(cmd @ Command::Flush(_)) => {
                    batch.push(cmd);
                    break;
                }
                Ok(cmd) => batch.push(cmd),
                Err(_) => break,
            }
        }
        let (expected, ok) = batch.write(&mut conn.lock());
        let failed = expected - ok;
        if failed > 0 {
            let total = dropped.fetch_add(failed, Ordering::Relaxed) + failed;
            if !warned {
                warn!(
                    total_dropped = total,
                    "usage sqlite write failed; events being dropped (counted, not logged per-event)"
                );
                warned = true;
            }
        } else {
            warned = false;
        }
        batch.ack_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::RoundKind;
    use crate::usage::UsageQuanta;

    fn ev(
        hour_offset: i64,
        provider: &str,
        model: Option<&str>,
        usage: Option<UsageQuanta>,
    ) -> UsageEvent {
        UsageEvent {
            ts: chrono::Utc::now() - chrono::Duration::hours(hour_offset),
            provider: provider.to_string(),
            model: model.map(String::from),
            model_req: None,
            proto: "o".to_string(),
            status: 200,
            complete: true,
            round_kind: RoundKind::Normal,
            usage,
        }
    }

    fn quanta(i: u64, o: u64) -> Option<UsageQuanta> {
        Some(UsageQuanta { i, o, cr: 0, cw: 0 })
    }

    fn tmp_db(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sg-usage-{tag}-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("usage.sqlite3");
        let _ = std::fs::remove_file(&p);
        // WAL 侧车文件也清掉 (上次 run 残留).
        let _ = std::fs::remove_file(dir.join("usage.sqlite3-wal"));
        let _ = std::fs::remove_file(dir.join("usage.sqlite3-shm"));
        p
    }

    fn cfg(retention: u32) -> UsageConfig {
        UsageConfig {
            enabled: true,
            retention_days: retention,
            ..Default::default()
        }
    }

    // ─── USAGE-1 聚合一致性: record → SQL 查询 ────────────────────────────

    #[test]
    fn record_accumulates_per_key_and_counts_missing_usage() {
        let s = UsageStore::in_memory();
        s.record(ev(0, "p1", Some("m1"), quanta(10, 5)));
        s.record(ev(0, "p1", Some("m1"), quanta(20, 5)));
        s.record(ev(0, "p1", Some("m1"), None));
        s.record(ev(0, "p2", None, quanta(1, 1)));
        let cells = s.query_cells("", Granularity::Hour);
        let m1 = cells
            .iter()
            .find(|((_, p, m), _)| p == "p1" && m.as_deref() == Some("m1"))
            .expect("m1 cell");
        // USAGE-4: requests == 有 usage 行 + without_usage.
        assert_eq!(m1.1.requests, 3);
        assert_eq!(m1.1.requests_without_usage, 1);
        assert_eq!(m1.1.input, 30);
        assert_eq!(m1.1.output, 10);
        assert_eq!(s.total_events(), 4);
    }

    #[test]
    fn disabled_store_is_noop() {
        let s = UsageStore::disabled();
        s.record(ev(0, "p", None, quanta(1, 1)));
        assert_eq!(s.total_events(), 0);
        assert!(s.query_cells("", Granularity::Hour).is_empty());
    }

    // ─── 小时粒度 + day 折叠 (USAGE-1 hour 升级) ──────────────────────────

    /// 固定基准时刻构造事件 (抗 DST: Utc::now() 在 fall-back 时区的特定窗口
    /// 会让相隔 1 real-hour 的事件落到同一本地 hour 标签, 固定 UTC 基准规避 flaky).
    fn ev_at(base: chrono::DateTime<chrono::Utc>, hour_offset: i64, provider: &str) -> UsageEvent {
        let mut e = ev(hour_offset, provider, Some("m"), quanta(1, 1));
        e.ts = base - chrono::Duration::hours(hour_offset);
        e
    }

    #[test]
    fn hour_granularity_separates_buckets_within_one_day() {
        let s = UsageStore::in_memory();
        // 固定 UTC 基准 (2026-09-11T12:34Z): 间隔整小时 → 本地 hour 标签恒分离.
        let base = chrono::DateTime::parse_from_rfc3339("2026-09-11T12:34:56Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let e_now = ev_at(base, 0, "p");
        let mut e_prev = ev_at(base, 1, "p");
        e_prev.usage = quanta(2, 2);
        let mut e_26h = ev_at(base, 26, "p");
        e_26h.usage = quanta(4, 4);
        s.record(e_now);
        s.record(e_prev);
        s.record(e_26h);
        let hours = s.query_cells("", Granularity::Hour);
        assert_eq!(hours.len(), 3, "3 distinct hour buckets");
        // day 折叠: 昨天 1 天 + 今天 1 天 = 2 bucket, 各自求和.
        let days = s.query_cells("", Granularity::Day);
        assert_eq!(days.len(), 2);
        let total_req: u64 = days.iter().map(|(_, a)| a.requests).sum();
        assert_eq!(total_req, 3);
        let today = days.iter().max_by(|a, b| a.0.0.cmp(&b.0.0)).unwrap();
        assert_eq!(today.1.requests, 2);
        assert_eq!(today.1.input, 3);
    }

    // ─── USAGE-1 持久一致性: SQLite 重开恢复 ──────────────────────────────

    #[test]
    fn open_reuses_existing_db_and_restores_aggregation() {
        let path = tmp_db("reopen");
        let s = UsageStore::open(&cfg(90), &path);
        s.record(ev(0, "p1", Some("m1"), quanta(100, 50)));
        s.record(ev(0, "p1", Some("m1"), None));
        s.flush_for_test();
        drop(s); // 进程退出等价: writer 线程随 channel 关闭退出.
        // 重开: 聚合应从 SQLite 恢复 (SQL 直查, 无重放概念 — 明细即真相).
        let s2 = UsageStore::open(&cfg(90), &path);
        assert_eq!(s2.total_events(), 2);
        let cells = s2.query_cells("", Granularity::Hour);
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0].1.requests, 2);
        assert_eq!(cells[0].1.requests_without_usage, 1);
        assert_eq!(cells[0].1.input, 100);
        let _ = std::fs::remove_file(&path);
    }

    // ─── retention (USAGE-5) ──────────────────────────────────────────────

    #[test]
    fn open_drops_expired_by_retention() {
        let path = tmp_db("ret");
        let s = UsageStore::open(&cfg(1), &path);
        s.record(ev(48, "p", None, quanta(1, 1))); // 48h 前 → 过期
        s.record(ev(1, "p", None, quanta(2, 2))); // 1h 前 → 保留
        s.flush_for_test();
        drop(s);
        let s2 = UsageStore::open(&cfg(1), &path);
        assert_eq!(s2.total_events(), 1, "expired row must be deleted");
        let cells = s2.query_cells("", Granularity::Hour);
        assert_eq!(cells[0].1.input, 2);
        let _ = std::fs::remove_file(&path);
    }

    // ─── UsageQuanta::from_ir (USAGE-2: cr/cw None 归一) ─────────────────

    #[test]
    fn quanta_from_ir_normalizes_none_cache_fields() {
        let q = UsageQuanta::from_ir(&crate::codec::ir::IrUsage {
            input_tokens: 5,
            output_tokens: 6,
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
        });
        assert_eq!(
            q,
            UsageQuanta {
                i: 5,
                o: 6,
                cr: 0,
                cw: 0
            }
        );
    }
    // ─── 损坏 DB 文件 → :memory: 降级 (ROB: 不阻塞网关启动) ─────────────

    #[test]
    fn open_corrupted_file_degrades_to_in_memory() {
        let path = tmp_db("corrupt");
        std::fs::write(&path, b"this is definitely not a sqlite database").unwrap();
        let s = UsageStore::open(&cfg(90), &path);
        // 降级后统计照常 (空), record 可写入, 查询不 panic.
        assert_eq!(s.total_events(), 0);
        s.record(ev(0, "p", None, quanta(1, 1)));
        assert_eq!(s.total_events(), 1);
        let _ = std::fs::remove_file(&path);
    }
}
