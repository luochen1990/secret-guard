//! 集中的哈希工具函数.
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

/// 计算单个值的 SipHash (DefaultHasher) u64 摘要.
///
/// `t: &T` 形式让调用方传引用即可, 避免消耗所有权. 支持 `?Sized` 以接受 `str` / 切片
/// 等动态大小类型.
pub fn hash64<T: Hash + ?Sized>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}
