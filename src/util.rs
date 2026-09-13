//! 集中的哈希工具函数 + 文件权限收紧工具 (SEC-8).
//!
//! 设计目标: 项目中多处需要把数据映射到稳定的 u64 (mock seed / DAG 内容寻址 /
//! Merkle 前缀哈希 / redact seed 链). 统一入口确保算法一致 (Rust `DefaultHasher`,
//! 即 SipHash 1-3), 任何算法变更只需改这一处.
//!
//! DAG 不跨进程, 不要求加密强度, 因此使用标准库 `DefaultHasher` 而非 blake3:
//! 同一 Rust 版本内确定即可 (跨版本稳定性不保证, 但本项目无此需求).
//!
//! 多字段哈希: 对需要"按字段顺序哈希、不加长度前缀"的场景, 传入 tuple 引用即可,
//! Rust tuple 的 [`Hash`] 实现只按字段顺序逐个哈希, 不插入分隔符. 例如
//! `hash64(&(parent, own))` 等价于手动 `parent.hash(); own.hash(); finish()`.
//!
//! 注意: `[T]` / `Vec<T>` 的 [`Hash`] 实现会**先哈希长度再哈希元素**, 与裸循环
//! 逐元素哈希的字节序列不同. 若需保留"逐元素无长度前缀"语义 (如 `redact::init_seed`
//! 与 `dag::hash_block`), 仍需直接在调用方用增量 hasher; 已在对应位置注明.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;

/// 计算单个值的 SipHash (DefaultHasher) u64 摘要.
///
/// `t: &T` 形式让调用方传引用即可, 避免消耗所有权. 支持 `?Sized` 以接受 `str` / 切片
/// 等动态大小类型.
pub fn hash64<T: Hash + ?Sized>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

/// 以 owner-only (0600) 权限创建 (或截断) 文件 (SEC-8), 返回可写句柄.
///
/// 与 `File::create` 同语义 (write + create + truncate), 但 unix 下显式 0600 —
/// 供敏感落盘工件 (state.toml / pricing.json) 的**创建时即收紧**路径; umask 只能
/// 收紧不能放宽 (0600 无 group/other 位可被清). 非 unix 无 POSIX mode, 见下方
/// cfg 对.
#[cfg(unix)]
pub fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

/// 非 unix 平台: 无 POSIX mode 概念, 等价 `File::create`.
#[cfg(not(unix))]
pub fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::create(path)
}

/// 将**已存在**的普通文件权限收紧为 owner-only (0600), best-effort (SEC-8).
///
/// 调用方: 敏感落盘工件 (state.toml / usage.sqlite3 / pricing.json) 的启动加载点
/// + 无 mode 控制的写路径.
///
/// 新建敏感文件的首选路径仍是创建时即 0600 ([`create_owner_only`] / sqlite 之外
/// 的写路径); 本函数负责收尾两种残留形态:
/// 1. 旧版本创建的过宽文件 (启动收紧);
/// 2. 无 mode 参数的创建器 (写后收紧, 如 sqlite `Connection::open`).
///
/// 语义: 文件不存在 / 非普通文件 (设备 / 目录 — 如测试 fixture 的 `/dev/null`)
/// 静默跳过; group/other 位已全清 (含 0400 / 0000 等**更严**形态) 跳过 — 只把
/// "他人可读"收进来, 不动用户刻意更紧的配置; chmod 失败仅 WARN 不传播 (敏感
/// 文件权限是纵深防御, 不应让网关启动失败).
#[cfg(unix)]
pub fn tighten_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(md) = std::fs::metadata(path) else {
        return;
    };
    if !md.is_file() {
        return; // /dev/null 等测试 fixture 与设备文件绝不能 chmod
    }
    let mut perms = md.permissions();
    if perms.mode() & 0o077 == 0 {
        return; // 已 owner-only (或更严), 不放宽用户刻意的 0400/0000
    }
    perms.set_mode(0o600);
    if let Err(e) = std::fs::set_permissions(path, perms) {
        tracing::warn!(path = %path.display(), error = %e, "chmod 0600 failed (non-fatal)");
    }
}

/// 非 unix 平台无 POSIX mode 概念, no-op (与调用点的 cfg 无关, 保持调用方简洁).
#[cfg(not(unix))]
pub fn tighten_file_permissions(_path: &Path) {}
