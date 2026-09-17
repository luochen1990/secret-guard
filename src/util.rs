//! 集中的哈希工具函数 + 文件权限收紧工具 (SEC-8) + 字符串截断族.
//!
//! 设计目标: 项目中多处需要把数据映射到稳定的 u64 (mock seed / DAG 内容寻址 /
//! Merkle 前缀哈希 / redact seed 链). 统一入口确保算法一致 (Rust `DefaultHasher`,
//! 即 SipHash 1-3), 任何算法变更只需改这一处.
//!
//! DAG 不跨进程, 不要求加密强度, 因此使用标准库 `DefaultHasher` 而非 blake3:
//! 同一 Rust 版本内确定即可 (跨版本稳定性不保证, 但本项目无此需求).
//!
//! 多字段哈希: 对需要"按字段顺序哈希、不加长度前缀"的场景, 传入 tuple 引用即可,
//! Rust tuple 的 [`Hash`] 实现只按字段顺序逐元素哈希, 不插入分隔符. 例如
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

// ─── 字符串截断族 (char boundary 安全, ROB-1) ─────────────────────────────
//
// 两个核心变体对应两种**不可互换**的上限量纲, 调用点按既有语义对号入座:
//   - 字节上限 (防日志/回显洪水, 如 4 KiB 错误 body 回放) → truncate_str_on_char_boundary
//   - 字符上限 (UI 展示预算, 如 preview 48 chars / model 回显 64 chars)  → truncate_chars 族
// 强行统一量纲会改变各调用点行为, 故保持两个入口.

/// 截断 `s` 到最多 `max_bytes` **字节**, 切点回退到不大于 `max_bytes` 的最近
/// char boundary.
///
/// 契约: (1) 输入是任意合法 `&str` (可含多字节字符), 永不 panic — 直接字节偏移
/// 切片在多字节字符内会 panic, 本函数是其安全替代; (2) 返回值是 `s` 的前缀且
/// 字节数 ≤ `max_bytes`, 并是满足两者约束的最长前缀 (floor 语义, 非 round);
/// (3) 任何路径都零分配 (借用切片; 未超限时即 `s` 本身).
/// 消费点: 跨协议错误响应 message 回放 (proxy::cross_proto, 字节上限 4 KiB).
pub fn truncate_str_on_char_boundary(s: &str, max_bytes: usize) -> &str {
    // end = s.len() 恒为 boundary (未超限时循环零次, 原样返回).
    let mut end = max_bytes.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// 截断 `s` 到最多 `max_chars` 个**字符** (整体字符, 借用切片, 零分配).
///
/// 契约: (1) 永不 panic (char_indices 定位的是字符起点, 天然 boundary);
/// (2) 返回值是 `s` 的前缀且字符数 ≤ `max_chars`; (3) 未超限时返回 `s` 本身.
/// 消费点: usage 自由字符串清洗 (256 chars 上限).
pub fn truncate_chars(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// [`truncate_chars`] 的回显变体: 截断发生时追加 `…`, 让接收端可感知截断.
///
/// 消费点: preview 截断 (derive, 前后端 SSOT 均按 chars 计) / model 名回显
/// (provider NoMatch 503 + 路由日志, 防洪水且截断可见).
pub fn truncate_chars_with_ellipsis(s: &str, max_chars: usize) -> String {
    let truncated = truncate_chars(s, max_chars);
    if truncated.len() < s.len() {
        format!("{truncated}…")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ─── truncate_str_on_char_boundary ──────────────────────────────────────

    #[test]
    fn truncate_str_multibyte_floors_to_char_boundary() {
        // 4096 落在 "错" (3 bytes) 字符内部 → floor 到 4095 (ROB-1 复现锚点).
        let s = "错".repeat(2000);
        let t = truncate_str_on_char_boundary(&s, 4096);
        assert_eq!(t.len(), 4095);
        assert!(s.starts_with(t));
        // 4-byte 字符 (emoji): 上限落在其内部同样 floor.
        let e = "😀".repeat(100); // 400 bytes
        let t = truncate_str_on_char_boundary(&e, 399);
        assert_eq!(t.len(), 396); // 399 → floor 到 99 个 emoji.
        // 上限小于首字符字节数 → 空串 (最差边界).
        assert_eq!(truncate_str_on_char_boundary(&e, 2), "");
        // 未超限 → 原样返回.
        assert_eq!(truncate_str_on_char_boundary("短", 4096), "短");
    }

    /// 生成含多字节字符混合的字符串 (ASCII / 中文 / emoji 随机混搭) — 纯 ASCII
    /// 生成器测不出 char boundary 问题 (历史 bug 正是生成器太窄的教训).
    fn arb_mixed_utf8() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop::sample::select(vec!["a", "z", "0", "中", "文", "😀", "é"]),
            0..256,
        )
        .prop_map(|cs| cs.concat())
    }

    /// 契约 property: 前缀 + 字节上限 + floor 最大化 (不 panic 由运行本身守卫).
    #[test]
    fn prop_truncate_str_prefix_bounded_and_maximal() {
        proptest!(|(s in arb_mixed_utf8(), cap in 0usize..300)| {
            let t = truncate_str_on_char_boundary(&s, cap);
            // 前缀.
            prop_assert!(s.starts_with(t));
            // 字节上限.
            prop_assert!(t.len() <= cap);
            // floor 最大化: 除非整个 s 都放得下, 否则再放一个字符必然超限.
            if t.len() < s.len() {
                let next_len = s[t.len()..].chars().next().unwrap().len_utf8();
                prop_assert!(t.len() + next_len > cap);
            } else {
                prop_assert!(s.len() <= cap);
            }
        });
    }

    // ─── truncate_chars / truncate_chars_with_ellipsis ─────────────────────

    #[test]
    fn truncate_chars_and_ellipsis_semantics() {
        let s = "你好世界"; // 4 chars, 12 bytes
        assert_eq!(truncate_chars(s, 10), s); // 未超限原样.
        assert_eq!(truncate_chars(s, 2), "你好");
        assert_eq!(truncate_chars_with_ellipsis(s, 10), s); // 未截断不加后缀.
        assert_eq!(truncate_chars_with_ellipsis(s, 2), "你好…");
        assert_eq!(truncate_chars_with_ellipsis("", 5), "");
    }

    /// 契约 property: chars 上限 + 前缀 + 未超限恒等.
    #[test]
    fn prop_truncate_chars_prefix_and_count() {
        proptest!(|(s in arb_mixed_utf8(), cap in 0usize..300)| {
            let t = truncate_chars(&s, cap);
            prop_assert!(s.starts_with(t));
            prop_assert!(t.chars().count() <= cap);
            if s.chars().count() <= cap {
                prop_assert_eq!(t, s.as_str());
            } else {
                // 恰等性: 发生截断时恰为 cap 个字符 (chars 维度的最大化).
                prop_assert_eq!(t.chars().count(), cap);
            }
            // ellipsis 变体与核心的一致性: 只多一个 '…' 或完全相等.
            let e = truncate_chars_with_ellipsis(&s, cap);
            if t.len() < s.len() {
                prop_assert_eq!(e, format!("{t}…"));
            } else {
                prop_assert_eq!(e, s);
            }
        });
    }
}
