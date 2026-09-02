//! [`UsageStore`]: usage 明细的内存聚合 + JSONL 持久化 (append-only).
//!
//! # 持久化语义 (P-5 轻量持久)
//!
//! - 每完成一个请求 append 一行 JSONL (`secret-guard.usage.jsonl`, 与 static
//!   config 同目录派生, 规则同 state.toml 的 `<stem>.<suffix>` 约定).
//! - 热路径零同步 IO: `record` 更新内存聚合 (parking_lot RwLock, O(1)) 后经
//!   std mpsc 交给独立 writer 线程 append (设计 §4, 评审 m4 的决策: 不在
//!   tokio worker 上做文件 IO).
//! - 写失败 best-effort: WARN + `dropped` 计数, 内存聚合照常 (ROB-*).
//! - 启动重放: 逐行 parse, 非法行跳过 + WARN (崩溃残行); 按 retention 过滤,
//!   有过期行则原子重写 (临时文件 + rename).
//!
//! # 聚合结构
//!
//! `HashMap<(day, provider, model), UsageAgg>` — day 为**本地时区**日期
//! (本地工具, "今天" 的用户直觉, 设计 §6). by_day / by_model / by_provider
//! 视图在查询时从 cells 派生 (M3 API 层), 不冗余存储二级索引.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
use parking_lot::Mutex;
use parking_lot::RwLock;
use tracing::{info, warn};

use crate::config::UsageConfig;

use super::UsageEvent;

/// 按 (day, provider, model) 三元组的聚合计数.
/// Serialize: summary DTO 经 `#[serde(flatten)]` 内嵌 (wire 键 == 字段名).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct UsageAgg {
    pub requests: u64,
    /// usage == None 的请求数 (P-3 缺失显式; 对 token / cost 贡献恒 0).
    pub requests_without_usage: u64,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

impl UsageAgg {
    fn apply(&mut self, ev: &UsageEvent) {
        self.requests += 1;
        match &ev.usage {
            Some(u) => {
                self.input = self.input.saturating_add(u.i);
                self.output = self.output.saturating_add(u.o);
                self.cache_read = self.cache_read.saturating_add(u.cr);
                self.cache_write = self.cache_write.saturating_add(u.cw);
            }
            None => self.requests_without_usage += 1,
        }
    }
}

/// 聚合键: (day, provider, model). day 是本地时区 "YYYY-MM-DD".
/// pub: summary 派生层复用 (AggKey 是 store 与 API 层共享的 cells 形状).
pub type AggKey = (String, String, Option<String>);

#[derive(Debug)]
struct AggInner {
    cells: HashMap<AggKey, UsageAgg>,
    total_requests: u64,
}

/// usage 统计的进程级 store (AppState 聚合, 组合根先例同 `api_keys`).
#[derive(Debug)]
pub struct UsageStore {
    enabled: bool,
    /// 配置的 retention (API 层的 days 上限用; 0 = 永久 = 无上限).
    retention_days: u32,
    inner: RwLock<AggInner>,
    /// JSONL writer 线程的发送端 (enabled 且文件可开时 Some; drop 时线程随 channel
    /// 关闭退出). 热路径 `record` 只 `send` (非阻塞).
    writer: Option<std::sync::mpsc::Sender<UsageEvent>>,
    /// writer 线程写失败计数 (可观测, UI 不展示仅日志).
    dropped: Arc<AtomicU64>,
    /// 测试断言用的事件镜像 (仅 cfg(test) 编译, 生产零开销).
    #[cfg(test)]
    events_log: Mutex<Vec<UsageEvent>>,
}

impl UsageStore {
    /// 未启用 (零开销 no-op; record 直接返回).
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            retention_days: 0,
            inner: RwLock::new(AggInner {
                cells: HashMap::new(),
                total_requests: 0,
            }),
            writer: None,
            dropped: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            events_log: Mutex::new(Vec::new()),
        }
    }

    /// 纯内存 store (无文件 IO) — 单测 / AppState 测试 fixture / open() 的构造基座.
    pub fn in_memory() -> Self {
        Self {
            enabled: true,
            retention_days: 0,
            inner: RwLock::new(AggInner {
                cells: HashMap::new(),
                total_requests: 0,
            }),
            writer: None,
            dropped: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            events_log: Mutex::new(Vec::new()),
        }
    }

    /// 生产构造: 重放既有 JSONL (retention 过滤 + 原子清理) + 起 writer 线程.
    ///
    /// 文件打开失败不致命 (WARN + 降级为纯内存聚合, 明细不持久 — best-effort):
    /// usage 统计是增强功能, 不能阻塞网关启动.
    pub fn open(config: &UsageConfig, jsonl_path: &Path) -> Self {
        if !config.enabled {
            return Self::disabled();
        }
        let mut this = Self::in_memory();
        this.retention_days = config.retention_days;
        // 1. 重放 (文件不存在 = 首次启动, 空开始).
        let (retained, expired, invalid) = match std::fs::File::open(jsonl_path) {
            Ok(f) => replay_lines(std::io::BufReader::new(f), retention_cutoff(config)),
            Err(_) => (Vec::new(), 0u64, 0u64),
        };
        if invalid > 0 {
            warn!(path = %jsonl_path.display(), invalid, "usage jsonl: skipped malformed lines (crash residue?)");
        }
        if expired > 0 {
            info!(path = %jsonl_path.display(), expired, "usage jsonl: expired lines dropped (retention)");
        }
        {
            let mut g = this.inner.write();
            for ev in &retained {
                let key = agg_key(ev);
                g.cells.entry(key).or_default().apply(ev);
                g.total_requests += 1;
            }
        }
        // 2. 有过期/残行 → 原子重写为仅保留行 (读侧清理, 不阻塞启动).
        if expired > 0 || invalid > 0 {
            rewrite_atomic(jsonl_path, &retained);
        }
        // 3. writer 线程 (append 模式打开; 失败 → 降级纯内存).
        if let Some(dir) = jsonl_path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(jsonl_path)
        {
            Ok(file) => {
                let (tx, rx) = std::sync::mpsc::channel::<UsageEvent>();
                let dropped = Arc::clone(&this.dropped);
                // spawn 失败 (资源耗尽) 与文件打开失败同型降级: WARN + 纯内存,
                // 不阻塞网关启动 (ROB: usage 是增强功能).
                match std::thread::Builder::new()
                    .name("usage-jsonl".into())
                    .spawn(move || writer_loop(file, rx, dropped))
                {
                    Ok(_) => this.writer = Some(tx),
                    Err(e) => {
                        warn!(error = %e, "usage jsonl writer thread spawn failed; in-memory only")
                    }
                }
            }
            Err(e) => {
                warn!(path = %jsonl_path.display(), error = %e, "usage jsonl not writable; stats run in-memory only");
            }
        }
        info!(
            path = %jsonl_path.display(),
            events = retained.len(),
            "usage stats store ready"
        );
        this
    }

    /// 记录一条事件: 更新内存聚合 + 交 writer 线程 append.
    pub fn record(&self, event: UsageEvent) {
        if !self.enabled {
            return;
        }
        {
            let mut g = self.inner.write();
            let key = agg_key(&event);
            g.cells.entry(key).or_default().apply(&event);
            g.total_requests += 1;
        }
        #[cfg(test)]
        self.events_log.lock().push(event.clone());
        if let Some(tx) = &self.writer
            && tx.send(event).is_err()
        {
            // writer 线程已退出 (仅 drop 场景); 计数即可, 不刷日志 (shutdown 噪音).
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 聚合 cells 的快照 (M3 API 层派生 by_day / by_model / by_provider 视图).
    pub fn snapshot_cells(&self) -> Vec<(AggKey, UsageAgg)> {
        self.inner
            .read()
            .cells
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    /// 累计请求数 (测试 + 轻量可观测).
    pub fn total_requests(&self) -> u64 {
        self.inner.read().total_requests
    }

    /// 配置的 retention 天数 (API 的 days 查询上限; 0 = 无上限).
    pub fn retention_days(&self) -> u32 {
        self.retention_days
    }

    #[cfg(test)]
    pub fn take_events_for_test(&self) -> Vec<UsageEvent> {
        std::mem::take(&mut self.events_log.lock())
    }
}

/// 聚合键: day = ts 的本地时区日期 (设计 §6).
fn agg_key(ev: &UsageEvent) -> AggKey {
    let day = ev
        .ts
        .with_timezone(&chrono::Local)
        .format("%Y-%m-%d")
        .to_string();
    (day, ev.provider.clone(), ev.model.clone())
}

/// retention 截止时刻; 0 = 永久保留 (None).
fn retention_cutoff(config: &UsageConfig) -> Option<chrono::DateTime<chrono::Utc>> {
    (config.retention_days > 0)
        .then(|| chrono::Utc::now() - chrono::Duration::days(config.retention_days as i64))
}

/// 逐行重放: (保留行, 过期行数, 非法行数). ROB: 非法行跳过不 panic.
fn replay_lines<R: BufRead>(
    reader: R,
    cutoff: Option<chrono::DateTime<chrono::Utc>>,
) -> (Vec<UsageEvent>, u64, u64) {
    let mut retained = Vec::new();
    let mut expired = 0u64;
    let mut invalid = 0u64;
    for line in reader.lines() {
        let Ok(line) = line else {
            invalid += 1;
            continue;
        };
        match serde_json::from_str::<UsageEvent>(&line) {
            Ok(ev) => match cutoff {
                Some(c) if ev.ts < c => expired += 1,
                _ => retained.push(ev),
            },
            Err(_) => invalid += 1,
        }
    }
    (retained, expired, invalid)
}

/// 原子重写 JSONL (临时文件 + rename; best-effort, 失败仅 WARN).
fn rewrite_atomic(path: &Path, events: &[UsageEvent]) {
    let tmp = path.with_extension("jsonl.tmp");
    let write = || -> std::io::Result<()> {
        let mut f = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
        for ev in events {
            serde_json::to_writer(&mut f, ev)?;
            f.write_all(b"\n")?;
        }
        f.flush()?;
        std::fs::rename(&tmp, path)
    };
    if let Err(e) = write() {
        warn!(path = %path.display(), error = %e, "usage jsonl rewrite failed (kept as-is)");
    }
}

/// writer 线程主体: 逐行 append + flush (每行 flush — 本地低频, 简单优先).
fn writer_loop(
    file: std::fs::File,
    rx: std::sync::mpsc::Receiver<UsageEvent>,
    dropped: Arc<AtomicU64>,
) {
    let mut out = std::io::BufWriter::new(file);
    let mut warned = false;
    for ev in rx {
        let ok = (|| -> Result<(), Box<dyn std::error::Error>> {
            serde_json::to_writer(&mut out, &ev)?;
            out.write_all(b"\n")?;
            out.flush()?;
            Ok(())
        })()
        .is_ok();
        if !ok {
            // 状态变化时 WARN 一次 (磁盘满等持续性故障不刷屏; 恢复后重置, 再失败再报).
            if !warned {
                warn!(
                    "usage jsonl write failed; events being dropped (counted, not logged per-event)"
                );
                warned = true;
            }
            dropped.fetch_add(1, Ordering::Relaxed);
        } else {
            warned = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::ir::IrUsage;
    use crate::usage::UsageQuanta;

    fn ev(
        day_offset_h: i64,
        provider: &str,
        model: Option<&str>,
        usage: Option<UsageQuanta>,
    ) -> UsageEvent {
        UsageEvent {
            ts: chrono::Utc::now() - chrono::Duration::hours(day_offset_h),
            provider: provider.to_string(),
            model: model.map(String::from),
            model_req: None,
            proto: "o".to_string(),
            method: "POST".to_string(),
            ok: true,
            complete: true,
            usage,
        }
    }

    fn quanta(i: u64, o: u64) -> Option<UsageQuanta> {
        Some(UsageQuanta { i, o, cr: 0, cw: 0 })
    }

    // ─── USAGE-1 聚合一致性: record 路径 ────────────────────────────────

    #[test]
    fn record_accumulates_per_key_and_counts_missing_usage() {
        let s = UsageStore::in_memory();
        s.record(ev(0, "p1", Some("m1"), quanta(10, 5)));
        s.record(ev(0, "p1", Some("m1"), quanta(20, 5)));
        s.record(ev(0, "p1", Some("m1"), None));
        s.record(ev(0, "p2", None, quanta(1, 1)));
        let cells = s.snapshot_cells();
        let m1 = cells
            .iter()
            .find(|((_, p, m), _)| p == "p1" && m.as_deref() == Some("m1"))
            .expect("m1 cell");
        // USAGE-4: requests == 有 usage 行 + without_usage.
        assert_eq!(m1.1.requests, 3);
        assert_eq!(m1.1.requests_without_usage, 1);
        assert_eq!(m1.1.input, 30);
        assert_eq!(m1.1.output, 10);
        assert_eq!(s.total_requests(), 4);
    }

    #[test]
    fn disabled_store_is_noop() {
        let s = UsageStore::disabled();
        s.record(ev(0, "p", None, quanta(1, 1)));
        assert_eq!(s.total_requests(), 0);
        assert!(s.snapshot_cells().is_empty());
    }

    // ─── USAGE-2 + 持久化: JSONL round-trip ────────────────────────────

    #[test]
    fn open_replays_jsonl_and_folds_aggregation() {
        let dir = std::env::temp_dir().join(format!("sg-usage-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("usage.jsonl");
        let _ = std::fs::remove_file(&path);
        // 预置两行合法 + 一行残行.
        let e1 = ev(0, "p1", Some("m1"), quanta(100, 50));
        let e2 = ev(0, "p1", Some("m1"), None);
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "{}", serde_json::to_string(&e1).unwrap()).unwrap();
            writeln!(f, "{{broken json").unwrap();
            writeln!(f, "{}", serde_json::to_string(&e2).unwrap()).unwrap();
        }
        let cfg = UsageConfig {
            enabled: true,
            retention_days: 90,
            ..Default::default()
        };
        let s = UsageStore::open(&cfg, &path);
        // 重放: 2 条合法计入; 残行被清理 (文件重写为 2 行).
        assert_eq!(s.total_requests(), 2);
        let agg: u64 = s.snapshot_cells().iter().map(|(_, a)| a.requests).sum();
        assert_eq!(agg, 2);
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 2, "malformed line must be cleaned");
        assert!(!content.contains("broken"));
        // record 后文件追加 (writer 线程异步, 轮询).
        s.record(ev(0, "p2", None, quanta(1, 1)));
        let mut appended = false;
        for _ in 0..200 {
            std::thread::sleep(std::time::Duration::from_millis(5));
            if std::fs::read_to_string(&path).unwrap().lines().count() == 3 {
                appended = true;
                break;
            }
        }
        assert!(appended, "recorded event must be appended to jsonl");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_drops_expired_by_retention() {
        let dir = std::env::temp_dir().join(format!("sg-usage-ret-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("usage.jsonl");
        let _ = std::fs::remove_file(&path);
        // retention_days=1: 48h 前的过期, 1h 前的保留.
        let old = ev(48, "p", None, quanta(1, 1));
        let fresh = ev(1, "p", None, quanta(2, 2));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "{}", serde_json::to_string(&old).unwrap()).unwrap();
            writeln!(f, "{}", serde_json::to_string(&fresh).unwrap()).unwrap();
        }
        let cfg = UsageConfig {
            enabled: true,
            retention_days: 1,
            ..Default::default()
        };
        let s = UsageStore::open(&cfg, &path);
        assert_eq!(s.total_requests(), 1, "expired line must be dropped");
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 1);
        let _ = std::fs::remove_file(&path);
    }

    // ─── UsageQuanta::from_ir (USAGE-2: cr/cw None 归一) ───────────────

    #[test]
    fn quanta_from_ir_normalizes_none_cache_fields() {
        let q = UsageQuanta::from_ir(&IrUsage {
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
}
