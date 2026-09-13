//! Secret redaction (请求) 与 restoration (响应) 逻辑, 基于 [`crate::codec::ir`] IR.
//!
//! # 设计哲学
//!
//! redact 是 secret-guard 的核心功能: 在请求里把真 secret 替换为 mock (假 secret),
//! 让 LLM 看不到真值; 响应回来时反向 restore, 让本地 agent 看到真值.
//!
//! 历史上 redact 是字节级 find-and-replace. 现在升级为 **IR 变换** (基于 [`crate::codec::ir`]),
//! 与 codec 模块同层, 两者能自然组合 (跨协议翻译 + redact 在同一层 pipeline).
//!
//! # 形式化契约 (mock 生成 + redact pipeline)
//!
//! mock 生成由 [`crate::mock`] 模块负责 (三维度策略), 本模块负责 IR 扫描 + 替换 + restore.
//! 核心契约:
//!
//! - **C1 非空性**: 每个 mock 非空, 满足其 [`crate::mock::GenSpec`] 的 prefix/charset/length.
//! - **C2 上下文唯一性 (in-context uniqueness)**:
//!   `gen_mock_for_ir(ir, secret, allocated)` 返回的 mock 一定**不在** `ir` 中出现
//!   (traverse IR 检查) 且不在 `allocated` 集合中 (C4 保证).
//! - **C3 前缀缓存友好性**: redact 不应无必要地改变 request body 的字节内容, 避免破坏
//!   LLM Provider 侧的前缀缓存命中. 实现手段: per-request seed (单一标量) 驱动整个
//!   redactMap 的 mock 生成. 同一 policy + 同一 messages 上下文 → 同一 seed → 同一
//!   redactMap → mock 在会话全程稳定 (见 [`redact_ir`] 的 seed 语义).
//!
//!   **例外 (RED-2↔RED-3 张力裁决, #143)**: pre-replace IR 已含该 secret 的旧 mock 时
//!   (客户端经上游 parse 失败 fallback 路径把 mock 回传进历史), probing counter 推进
//!   → mock 实质必然变化 (碰撞概率可忽略). 若复用旧 mock, restore 会把历史中自然出现
//!   的旧 mock 错替成 real, 破坏 C6 round-trip — C2 保护 restore 正确性优先于 C3 缓存
//!   稳定性. 代价是 token 缓存费用 (经济性), 非 secret 泄漏. 详见 contracts.md RED-3
//!   例外场景裁决与 `prop_mock_changes_when_ir_contains_old_mock_exception`.
//!
//!   **权衡**: policy 变动 (添加/删除/编辑任一 secret) 会改变 init_seed → 所有 secret 的
//!   mock 全部变化 → 整个会话的前缀缓存失效. 这是 per-request seed 模型 (vs 旧 per-secret
//!   seed) 的代价, 换取了 lazy redact 重建的极简 (node 只存单标量 seed). secret 编辑是
//!   罕见操作, 不在多轮对话热路径上, 实际影响可忽略.
//! - **C4 单射性**: 在一次 [`redact_ir`] 调用内, 不同 secret 总映射到不同 mock
//!   (因为每次 gen_mock_for_ir 都检查 allocated 集合). 极端弱配置下探测可能耗尽,
//!   此时 [`redact_ir`] **跳过该 secret** (原样发往上游) 而非 panic, 优先保进程存活.
//!   [`RedactionMap::insert`] 的 C4 违反 (defense-in-depth) 同样降级跳过, 永不 panic.
//!   **可配置 fail-closed**: [`redact_ir_checked`] 配合 [`crate::config::OnProbeExhausted::FailClosed`]
//!   时, probing 耗尽或 insert collision 都返回 `Err`, 让调用方拒绝转发 (防 secret 泄露).
//! - **C5 不含 real_secret 子串** (实质确定性契约, 阈值随 L 自适应):
//!   - 阈值 `k(L) = max(4, ⌈L/3⌉)` (见 [`crate::mock::c5_threshold_len`]); Auto 模式由
//!     [`crate::mock::gen_candidate`] 内部重试链保证兑现.
//!   - Fixed 模式 / 用户 prefix 由 [`crate::mock::MockStrategy::validate_against_real`] 在
//!     upsert 时检查 (char-level windows, 正确处理 multibyte UTF-8 secret).
//!   - 前提: `SecretTable::upsert` 通过 `validate_value` 拒绝含 `global_mock_prefix` 的 secret
//!     (见 [`crate::secrets::validate_value`]; prefix 为空时此检查跳过).
//!   - 设计较详 (信息比率 / 业界 scanner 阈值 / 重试链) 与历史 regression 见
//!     [`crate::mock`] 模块头部 "C5" 段落 (SSOT) 与 `proptest-regressions/redact.txt`.
//! - **C6 可逆性 (restorability)**: round-trip identity —
//!   `restore_ir_response(&mut <redacted IrResponse>, &redact_ir(&mut <IrRequest>, secrets).0)`
//!   后 IR 语义等价于原 IR. (`redact_ir` 原地变异 IrRequest, 返回 `(RedactionMap, seed)`,
//!   `.0` 取 RedactionMap.)
//! - **C7 流式可逆性 (streaming restorability)**:
//!   [`StreamingRestorer`] 在任意 chunk 切分下保证 round-trip identity —
//!   `concat(push(c_1), push(c_2), ..., push(c_n), flush().1)` 严格等于
//!   `content.replace(mock, real)`. UTF-8 安全 (多字节字符不在 char boundary 中间切).
//!
//! # 扫描覆盖范围
//!
//! [`redact_ir`] 扫描以下字段:
//! - `IrRequest::system` (system prompt blocks)
//! - `IrRequest::messages[].content[]` (所有 block 递归, 含 ToolUse input JSON 字符串叶子)
//! - `IrRequest::tools[].{name, description, input_schema}` (工具元数据)
//! - `IrRequest::stop` (stop sequences)
//! - `IrRequest::user` (user id)
//! - `IrRequest.extra` (未建模字段, JSON 字符串叶子)
//!
//! **不扫描**: `IrRequest::model` (模型名不应该是 secret), `IrRequest.tools[].input_schema` 的非字符串叶子
//! (eg JSON Schema 的 type / properties 结构).
//!
//! # 流式 trade-off
//!
//! - **Text block / Text delta**: 必 redact. 流式响应通过 [`StreamingRestorer`] 做 sliding-window
//!   restore (尾部缓冲 N 字节, N = max mock len - 1), 避免跨 chunk mock 丢失 round-trip.
//! - **InputJsonDelta (流式 tool 参数片段)**: 同样走 [`StreamingRestorer`], 与 text 同算法.
//!   per-block 独立状态, 跨 block 互不干扰.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::codec::ir::{IrBlock, IrRequest, IrResponse, IrTool};
use crate::config::OnProbeExhausted;
use crate::secrets::SecretEntry;

/// redact pipeline 内部错误. **永不**携带真实 secret 明文, 只记 secret id 与可诊断元数据.
///
/// # 设计动机
///
/// redact 是 secret-guard 的核心安全路径. 弱配置 (eg Auto 模式, charset 仅 digits,
/// length_range=(1,1), 仅 10 个候选值) 加上对抗性 IR 可能耗尽 mock 候选. 历史上以
/// `panic!` 报错, 消息含真实 secret 明文 (`secret.value`), 既能被恶意请求触发 DoS
/// 又把 secret 泄露到 stderr/日志. 改为 `Result` 后, 调用方 ([`redact_ir`]) 在 Err 时
/// 用 `warn!` (只记 secret id) 并**跳过该 secret 的本轮 redact** (该 secret 原样发往
/// 上游), 显著优于崩溃整个进程 (崩溃会让所有在途请求失败).
#[derive(Debug)]
pub struct RedactError {
    /// 触发错误的 secret id (来自 [`SecretEntry::id`]), 不含 value.
    pub secret_id: String,
    /// 可读的失败原因 (不含 secret 值).
    pub reason: RedactReason,
}

/// redact 失败的具体原因 (不含敏感数据).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactReason {
    /// mock probing 耗尽 (eg 配置的 charset/length 仅产生极少候选, 全部已在 IR 或 allocated 中).
    ProbingExhausted,
    /// 内部一致性错误 (C4 单射性违反, 仅在防御性检查触发).
    MockCollision,
}

/// 改写映射: real ↔ mock 双向索引.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionMap {
    /// real_secret → mock_secret.
    pub real_to_mock: HashMap<String, String>,
    /// mock_secret → real_secret.
    pub mock_to_real: HashMap<String, String>,
    /// real_secret → 位置分类命中计数 (redact 审计, USAGE-7 治理归因:
    /// "哪个环节把 secret 塞进来"). 键是 real 明文 — 仅内存态, 持久化侧
    /// 由 usage 层翻译为 (secret_id, category) 行, 明文永不落盘.
    /// 形态 [`crate::codec::ir::HitLocations`] (IR 位置语义归 codec 域,
    /// redact 与 usage 均可依赖, 无横向边).
    pub hits: HashMap<String, crate::codec::ir::HitLocations>,
}

impl RedactionMap {
    pub fn is_empty(&self) -> bool {
        self.real_to_mock.is_empty()
    }

    /// 插入映射. 若 mock 已映射到**不同** real (C4 单射性违反), 返回 `RedactError`
    /// (defense-in-depth; C4 保证正常路径不会触发).
    ///
    /// **安全**: `RedactError` 只携带 `secret_id` 与 `reason` (不含 mock 值也不含 real 明文).
    /// 旧实现用 `assert!` 把 `{existing:?}` 与 `{real:?}` (真实 secret 明文) 写入 panic
    /// 消息, 既是 DoS 面又是泄密面. collision 路径的 `secret_id` 由调用方传入, 让
    /// `redact_ir` 的降级 `warn!` 日志能定位到具体 secret (旧实现在 collision 时填空串,
    /// 仅探测耗尽路径有 secret_id, 两者不对称).
    pub fn insert(
        &mut self,
        real: String,
        mock: String,
        secret_id: &str,
    ) -> Result<(), RedactError> {
        if let Some(existing) = self.mock_to_real.get(&mock)
            && existing != &real
        {
            return Err(RedactError {
                secret_id: secret_id.to_string(),
                reason: RedactReason::MockCollision,
            });
        }
        self.mock_to_real.insert(mock.clone(), real.clone());
        self.real_to_mock.insert(real, mock);
        Ok(())
    }

    pub fn mock_for(&self, real: &str) -> Option<&str> {
        self.real_to_mock.get(real).map(|s| s.as_str())
    }

    pub fn real_for(&self, mock: &str) -> Option<&str> {
        self.mock_to_real.get(mock).map(|s| s.as_str())
    }
}

// ─── 内部算法 ──────────────────────────────────────────────────────────────

/// 计算 policy 的 init seed (per-request seed 链的起点).
///
/// 对同一 policy (相同 secrets 集合 + 策略) 总产生同一 init seed →
/// 同一候选序列起点 (C3 前缀缓存友好性的根基).
pub fn init_seed(secrets: &[SecretEntry]) -> u64 {
    // 此处保留直接增量 hasher (未走 crate::util::hash64): 原实现逐元素 hash
    // (value, mock_strategy) 不带长度前缀; 若改用 hash64(&Vec) 会引入 len 字节,
    // 改变历史 seed 值 (违反"保持算法不变"). 语义上仍是 SipHash.
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for s in secrets {
        s.value.hash(&mut h);
        s.mock_strategy.hash(&mut h);
    }
    if h.finish() == 0 {
        // 避免与 passthrough sentinel (0) 冲突.
        1
    } else {
        h.finish()
    }
}

/// 在给定 per-request `seed` 下, 为单个 secret 生成候选 mock (不做唯一性检查).
///
/// counter 是 per-secret 的 probing 计数器: 0 是首选, 冲突时递增.
fn candidate_for(secret: &SecretEntry, seed: u64, counter: u32) -> String {
    crate::mock::gen_candidate(&secret.value, &secret.mock_strategy, seed, counter)
}

/// 生成一个在当前 IR 中**未出现**且**未分配过**的 mock.
///
/// 探测上限: 超过此 counter 即判定 IR 对抗性, 返回 Err (降级跳过).
///
/// 生产用 2^20 (~1M): 对任何合法 charset/length 都有充裕候选空间, 真实命中耗尽
/// 极不可能. 测试用更小的值 (512) 以便 `redact_ir_skips_secret_*` 耗尽测试能在毫秒级
/// 触发 (而非真的循环 1M 次, 覆盖率插桩下会放大数百倍拖垮 CI). 512 对合法多 secret
/// 场景 (如 c4_injectivity 的 100 secret) 仍有充裕探测空间, 不会误触发降级.
#[cfg(not(test))]
const MOCK_PROBE_LIMIT: u32 = 1 << 20;
#[cfg(test)]
const MOCK_PROBE_LIMIT: u32 = 512;

/// per-request seed 模型: 所有 secret 共享同一 seed. counter 是 per-secret 的 probing.
///
/// 返回 `Err(RedactError)` 当探测耗尽 (`MOCK_PROBE_LIMIT` 次仍未找到唯一 mock). 旧实现用 `panic!`,
/// 消息含 `secret.value` (真实 secret 明文) 与 `secret.mock_strategy`, 可被弱配置 +
/// 对抗性 IR 触发, 既 DoS 又泄密. 改为 `Result` 后由 [`redact_ir`] 决策降级策略.
///
/// **性能 (hybrid 延迟缓存)**: counter=0 走零拷贝遍历 ([`ir_request_contains`]); 首次后续
/// probing (counter=1) 时构造叶子缓存 ([`collect_ir_str_leaves`], 一次性收集 IR 字符串
/// 叶子引用, counter≥2 复用同一实例). 这把历史 O(K×P×L×n) (每次 probing 递归 match
/// IrBlock 结构) 在 P≥2 场景降为 O(K×(L+P×n)) —— 结构遍历 L 只发生 1 次. secret 不跨
/// 叶子边界, 缓存按叶子独立 contains 即正确. 详细 benchmark 见 `benches/redact.rs`.
fn gen_mock_for_ir(
    ir: &IrRequest,
    secret: &SecretEntry,
    seed: u64,
    allocated: &HashSet<String>,
) -> Result<String, RedactError> {
    let mut counter: u32 = 0;
    // 延迟预拼接缓存: 首次 probing 冲突 (counter≥1) 时才构造, 避免常见 P=1 场景的开销.
    let mut ir_leaves_cache: Option<Vec<&str>> = None;
    loop {
        let candidate = candidate_for(secret, seed, counter);
        // 空候选必须短路: ir_request_contains 内部对空 needle 返回 false (对齐),
        // 但缓存路径 `leaf.contains("")` 返回 true (Rust std 行为); 弱配置 (eg 空
        // global_mock_prefix + pool.is_empty() 时 gen_candidate 返回空 prefix) 会触发.
        let in_ir = if candidate.is_empty() {
            false
        } else if counter == 0 {
            // 首次 probing: 零拷贝遍历 IR 结构.
            ir_request_contains(ir, &candidate)
        } else {
            // 后续 probing: 复用预拼接缓存 (首次后续构造).
            ir_leaves_cache
                .get_or_insert_with(|| collect_ir_str_leaves(ir))
                .iter()
                .any(|leaf| leaf.contains(&candidate))
        };
        if !in_ir && !allocated.contains(&candidate) {
            return Ok(candidate);
        }
        counter += 1;
        if counter > MOCK_PROBE_LIMIT {
            return Err(RedactError {
                secret_id: secret.id.clone(),
                reason: RedactReason::ProbingExhausted,
            });
        }
    }
}

// ─── 公开 API: IR 级 redact / restore ─────────────────────────────────────

/// 在 [`IrRequest`] 中查找所有 secret 并替换为 mock.
///
/// per-request seed 模型: 所有 secret 共享一个 seed (整个 redactMap 的候选序列起点)。
/// counter 是 per-secret 的 probing 计数器。返回 `(RedactionMap, seed)`:
/// - seed = 0 表示无 secret 命中 (passthrough), DAG node 存 0.
/// - seed ≠ 0 = init_seed(secrets), DAG node 存它用于 lazy 重建.
///
/// C2 (in-context uniqueness): gen_mock_for_ir 检查 pre-replace IR.
/// C4 (injectivity): allocated 集合保证 mock 互不冲突.
///
/// # Probing 耗尽降级 (FailOpen, 历史行为)
///
/// 弱配置 (charset/length 仅产生极少候选) + 对抗性 IR 可能让 mock probing 耗尽,
/// 此函数会 **warn + 跳过该 secret** (原样转发到上游), 优先保进程存活. 这与 secret-guard
/// 核心使命 (防泄露) 相悖; 若需严格拒绝转发, 用 [`redact_ir_checked`] 配合
/// [`OnProbeExhausted::FailClosed`].
pub fn redact_ir(ir: &mut IrRequest, secrets: &[SecretEntry]) -> (RedactionMap, u64) {
    // 历史行为: FailOpen. 遇 Err 仍降级跳过 (与旧实现语义完全一致, 向后兼容).
    match redact_ir_inner(ir, secrets, OnProbeExhausted::FailOpen) {
        Ok(out) => out,
        // FailOpen 模式下 inner 永不返回 Err (内部已 warn+skip). 此分支防御性 unreachable.
        Err(e) => {
            warn!(
                secret_id = %e.secret_id,
                reason = ?e.reason,
                "redact_ir (fail_open) returned error unexpectedly; skipping this secret"
            );
            let seed = if secrets.is_empty() {
                0
            } else {
                init_seed(secrets)
            };
            (RedactionMap::default(), seed)
        }
    }
}

/// 在 [`IrRequest`] 中 redact, 按 `mode` 决定 probing 耗尽时的策略.
///
/// - [`OnProbeExhausted::FailOpen`]: 与 [`redact_ir`] 行为一致 (warn + skip, 向后兼容).
/// - [`OnProbeExhausted::FailClosed`]: 任一 secret probing 耗尽或 insert collision 时
///   立即返回 `Err(RedactError)`, 调用方应拒绝转发该请求 (eg 返回 503), 防止 secret 泄露.
///
/// **FailClosed 的副作用语义**: 返回 Err 前, IR 可能已被部分 redact (在耗尽前的成功 secret
/// 已被改写). 调用方必须丢弃这个 IR 副本, 不能部分转发. 当前 proxy 层实现是直接返回
/// 错误响应, 不使用部分 redact 的 IR.
pub fn redact_ir_checked(
    ir: &mut IrRequest,
    secrets: &[SecretEntry],
    mode: OnProbeExhausted,
) -> Result<(RedactionMap, u64), RedactError> {
    redact_ir_inner(ir, secrets, mode)
}

/// redact 内部共享实现. `mode` 控制 probing 耗尽时的策略.
///
/// FailOpen 模式下永不返回 Err (内部 warn+skip, 与旧 `redact_ir` 语义一致).
/// FailClosed 模式下首次遇到 probing 耗尽或 insert collision 即返回 Err.
fn redact_ir_inner(
    ir: &mut IrRequest,
    secrets: &[SecretEntry],
    mode: OnProbeExhausted,
) -> Result<(RedactionMap, u64), RedactError> {
    let mut map = RedactionMap::default();
    if secrets.is_empty() {
        return Ok((map, 0));
    }

    let mut sorted: Vec<&SecretEntry> = secrets.iter().filter(|e| !e.value.is_empty()).collect();
    sorted.sort_by_key(|e| std::cmp::Reverse(e.value.len()));
    sorted.dedup_by(|a, b| a.value == b.value);

    let mut allocated: HashSet<String> = HashSet::new();
    let seed = init_seed(secrets);
    let mut hit_any = false;

    for secret in sorted {
        if !ir_request_contains(ir, &secret.value) {
            continue;
        }
        hit_any = true;
        // 位置统计 (替换前, 只读): 仅对命中的 secret 执行, 与替换遍历同阶
        // (USAGE-7 治理归因 — 哪个环节把 secret 塞进来).
        let locations = count_hit_locations(ir, &secret.value);
        match gen_mock_for_ir(ir, secret, seed, &allocated) {
            Ok(mock) => {
                // 先 insert 到 map (防御性 C4 检查); 成功后再改写 IR + allocated,
                // 确保 map 与 IR 状态一致 (避免改写了 IR 但 map 缺失映射, 导致 restore 失败).
                match map.insert(secret.value.clone(), mock.clone(), &secret.id) {
                    Ok(()) => {
                        ir_request_replace_all(ir, &secret.value, &mock);
                        allocated.insert(mock);
                        map.hits.insert(secret.value.clone(), locations);
                    }
                    Err(e) => {
                        // insert 的 collision 在防御性检查中触发时, 同样降级跳过 (不 panic).
                        // 不改写 IR: secret 原样发往上游 (与探测耗尽的降级语义一致).
                        match mode {
                            OnProbeExhausted::FailOpen => {
                                warn!(
                                    secret_id = %e.secret_id,
                                    reason = ?e.reason,
                                    "redact insert failed; skipping this secret (forwarded unredacted)"
                                );
                            }
                            OnProbeExhausted::FailClosed => {
                                // FailClosed: 拒绝转发, 返回错误信号. 不 warn (caller 决定日志策略).
                                return Err(e);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                // 探测耗尽: 弱配置 (eg charset/length 仅产生极少候选) + 对抗性 IR.
                match mode {
                    OnProbeExhausted::FailOpen => {
                        // 降级: 跳过该 secret (原样发往上游), 不替换. 优于崩溃整个进程.
                        // 安全: 只记 secret id 与 reason, 永不记 secret value.
                        warn!(
                            secret_id = %e.secret_id,
                            reason = ?e.reason,
                            "mock probing exhausted; skipping this secret (forwarded unredacted). \
                             consider widening charset or length_range for this secret, or set \
                             [redact] on_probe_exhausted = \"fail_closed\" to refuse forwarding"
                        );
                    }
                    OnProbeExhausted::FailClosed => {
                        // FailClosed: 拒绝转发. 不 warn (caller 决定日志策略), 直接返回错误.
                        return Err(e);
                    }
                }
            }
        }
    }

    let final_seed = if hit_any { seed } else { 0 };
    Ok((map, final_seed))
}

/// 在 [`IrResponse`] 中反向替换 mock 为真实 secret.
///
/// 非流式响应的 restore 路径. 遍历结构由 [`StringLeafOps for IrResponse`] 提供,
/// 与 `ir_request_contains` / `ir_request_replace_all` 自动对齐.
pub fn restore_ir_response(ir: &mut IrResponse, map: &RedactionMap) {
    if map.is_empty() {
        return;
    }
    ir.for_each_str_leaf_mut(&mut |s| restore_str(s, map));
}

/// disabled secret 明文放行检测 (#161): 对每个 decision=Disabled 的 secret, 检查其
/// value 字节是否出现在原始请求 body 中; 命中的逐条 WARN (含 secret id).
///
/// 背景: decision=Disabled 的语义是 "关闭对该 secret 的保护 (明文直通上游)", 但这些
/// secret 不进入 [`redact_ir`] 的输入 (effective_raw 已排除), 转发链此前对此完全
/// 静默. 本函数补上 "命中才告警" 的可观测性 — 与 issue #161 要求一致:
/// - **挂载层级 (dispatch, 覆盖全路径)**: 对 raw 请求字节扫描而非解析后的 IR —
///   这样同协议透传快捷分支 (effective secrets 全部 disabled 时 `secrets_snapshot`
///   为空, 不进 codec) 也能告警. 该分支恰是 #161 最核心的场景 ("唯一的 secret 被
///   disable 后每个请求都明文放行且零日志").
/// - **精确度说明**: 字节包含检查对 JSON 转义 (value 含 `"`/控制字符时 wire 上
///   形如 `\uXXXX`) 会漏检 — 漏检仅少打一条告警, 无安全影响, 可接受.
/// - **安全**: 日志只含 secret id, 永不含 secret value (SEC 纪律, 同其他 redact warn).
/// - **成本**: 仅当存在 disabled secret 时才扫描 (每 disabled secret 一次子串搜索);
///   disabled 是罕见配置, 常态零开销. 搜索用 [`memchr::memmem::find`] (均摊 O(n)),
///   替代朴素 O(n·m) 窗口比较 — 大 body (数 MiB) × 每 disabled secret 数十万次
///   窗口比较在 memmem 下消失. 每 needle 单次搜索, one-shot 自由函数即可 (无需
///   Finder 句柄 — 它为跨多次搜索复用而生); secret 可经 WebUI 动态增删, 不引入
///   跨请求缓存 (失效复杂度不值得, 同 [`redact_ir`] 对 secrets 快照的 per-request
///   语义).
///
/// 返回命中数 (供测试断言; 调用方无需使用返回值).
pub fn warn_disabled_secrets_in_body(body: &[u8], disabled: &[SecretEntry]) -> usize {
    let mut hits = 0;
    for secret in disabled {
        if secret.value.is_empty() {
            continue;
        }
        if memchr::memmem::find(body, secret.value.as_bytes()).is_none() {
            continue;
        }
        hits += 1;
        warn!(
            secret_id = %secret.id,
            "secret forwarded in plaintext (decision=disabled): protection for this \
             secret is turned off, its real value is sent to the upstream provider"
        );
    }
    hits
}

// ─── StreamingRestorer: sliding window restore ──────────────────────────────

// DeltaKind 已上移到 `codec::stream` (StreamRestoreHook 接口倒置的一部分, 见
// #145 偏差 2: codec 不再 import redact, restore 能力由调用方注入). 这里 re-export
// 保持 `redact::DeltaKind` 既有路径兼容 (redact 依赖 codec 是既定向下依赖).
pub use crate::codec::stream::DeltaKind;

/// Sliding-window mock→real restorer for streaming `IrStreamEvent`s.
///
/// # 为什么需要 sliding window
///
/// 流式响应里 mock (如 `MOCKABC123`) 可能跨多个 chunk:
/// ```text
/// event 1 TextDelta: "the secret is MOCKAB"
/// event 2 TextDelta: "C123 end"
/// ```
/// 单 event 不含完整 mock, 直接 `restore_str_inplace` 找不到匹配.
/// [`StreamingRestorer`] 在尾部缓冲一定字节, 凑齐完整 mock 再 emit, 保证 round-trip identity.
///
/// # 算法
///
/// 1. push(content) → 与当前 buffer 拼接.
/// 2. 在 combined 中扫描所有 mock, 取最大 `mock_end_byte_offset`.
/// 3. `safe_end = max(mock_end_max, combined.len().saturating_sub(hold))`,
///    `hold = max_mock_len - 1` (防御 mock 跨 chunk).
/// 4. emit `combined[..safe_end]` (restore 后); 保留 `combined[safe_end..]` 进 buffer.
/// 5. [`Self::flush`] 在流/Block 结束时清空 buffer, 对剩余部分做 best-effort restore.
///
/// # Invariant
///
/// - `buffer.len() ≤ hold + 3` (push 后必然 trim; +3 是 UTF-8 char boundary 回退上限).
/// - `max_mock_len` 在构造时锁定 (proxy/ 保证 redact snapshot 期间 RedactionMap 不变).
/// - 一个 restorer 对应单个 block index, 期间 delta kind 不变 (text 或 input_json 二选一).
///
/// # Scope / Out of scope
///
/// - 处理 [`IrDelta::TextDelta`](crate::codec::ir::IrDelta::TextDelta) 和
///   [`IrDelta::InputJsonDelta`](crate::codec::ir::IrDelta::InputJsonDelta) (内容字节流).
/// - 不处理 `MessageDelta.stop_sequence` / `IrStreamEvent::Error`
///   (单 event 完整, 直接 `restore_str_inplace`).
#[derive(Debug)]
pub struct StreamingRestorer {
    map: RedactionMap,
    /// 尾部 hold 字节数 = max_mock_len - 1 (防御跨 chunk mock).
    hold: usize,
    /// 当前未 emit 的尾部 buffer.
    buffer: String,
    /// 最后一次 push 的 delta 类型. flush 时按此类型包装返回.
    /// 默认 Text (一个 block 的第一个 push 之前不会有 flush).
    last_kind: DeltaKind,
}

impl StreamingRestorer {
    /// 构造. `map` 为空时所有 push 直接透传 (zero overhead).
    pub fn new(map: RedactionMap) -> Self {
        let max_mock_len = map.mock_to_real.keys().map(|m| m.len()).max().unwrap_or(0);
        Self {
            map,
            hold: max_mock_len.saturating_sub(1),
            buffer: String::new(),
            last_kind: DeltaKind::Text,
        }
    }

    /// 喂入一段 content delta (TextDelta / InputJsonDelta 的字符串部分).
    ///
    /// 返回可以安全 emit 的部分 (mock 已替换为 real).
    /// 末尾 hold 字节保留在 buffer 等下一个 chunk 凑齐.
    pub fn push(&mut self, content: String) -> String {
        if self.map.is_empty() {
            return content;
        }
        let mut combined = std::mem::take(&mut self.buffer);
        combined.push_str(&content);
        let safe_end = self.find_safe_end(&combined);
        // split_off(safe_end) 把 combined 切成 [...safe_end) + [safe_end...).
        // self.buffer 持有 tail, combined 持有 head; 避免 clone + truncate.
        self.buffer = combined.split_off(safe_end);
        restore_str_inplace(&mut combined, &self.map);
        combined
    }

    /// 设置下次 flush 时使用的 delta kind (text / input_json).
    /// 由 StreamTranslate 在每次 BlockDelta 时同步, 确保 flush 返回正确类型.
    pub fn set_kind(&mut self, kind: DeltaKind) {
        self.last_kind = kind;
    }

    /// Block 结束 (BlockStop) 时调用. 若上游异常未发 BlockStop,
    /// 由 caller (StreamTranslate) 在 MessageStop / finish() 时主动调用以避免 mock 尾部泄漏.
    /// 返回 (delta_kind, restored_content).
    pub fn flush(&mut self) -> (DeltaKind, String) {
        let kind = self.last_kind;
        if self.buffer.is_empty() {
            return (kind, String::new());
        }
        let mut remaining = std::mem::take(&mut self.buffer);
        // buffer 非空蕴含 map 非空 (push 在 map 为空时直接返回 content, 从不写 buffer).
        restore_str_inplace(&mut remaining, &self.map);
        (kind, remaining)
    }

    /// 找出 combined 中可以安全 emit 的末尾 offset.
    ///
    /// 规则: max(最后一个 mock 末尾, len - hold).
    /// 保证 mock 不会跨 emit / buffer 边界.
    ///
    /// 特殊: 当 len ≤ hold 时返回 0 (全部 hold), 避免短 chunk 提前 emit mock 前缀.
    ///
    /// UTF-8 安全: 返回值必然落在 char boundary 上 (回退到最近的 boundary).
    /// buffer 不变式从 `≤ hold` 放宽到 `≤ hold + 3` (UTF-8 char 最多 4 字节).
    fn find_safe_end(&self, combined: &str) -> usize {
        let len = combined.len();
        if self.hold == 0 {
            return len;
        }
        if len <= self.hold {
            return 0;
        }
        let mut max_mock_end = 0usize;
        for mock in self.map.mock_to_real.keys() {
            if mock.len() > len {
                continue;
            }
            let mut start = 0usize;
            while let Some(off) = combined[start..].find(mock) {
                let abs = start + off;
                let end = abs + mock.len();
                if end > max_mock_end {
                    max_mock_end = end;
                }
                start = abs + 1;
            }
        }
        let safe_end_lower_by_hold = len - self.hold;
        let mut safe_end = std::cmp::max(max_mock_end, safe_end_lower_by_hold);
        // 回退到最近的 char boundary (mock 全是 ASCII, mock_end 必然在 boundary 上;
        // len - hold 可能在多字节 char 中间, 回退最多 3 字节).
        while safe_end > 0 && !combined.is_char_boundary(safe_end) {
            safe_end -= 1;
        }
        safe_end
    }
}

// ─── StreamingRestorerSet: per-block restorer 集合 (codec StreamRestoreHook 实现) ──
//
// 接口倒置 (#145 偏差 2) 后, StreamTranslate 通过 `codec::stream::StreamRestoreHook`
// trait 消费 restore 能力, 不再直接依赖本模块的类型. 本类型是 hook 的生产实现:
// 持有 per-block-index 的独立 StreamingRestorer (block 间 mock 边界互不干扰),
// 由 proxy/fan_out.rs 注入到 StreamTranslate::new_same_proto_restore.
//
// 历史: per-index HashMap + 时序编排原在 StreamTranslate 内 (restorers 字段),
// hook 化后状态与编排随实现下沉到本模块, StreamTranslate 只驱动事件流.

/// 按 block index 分片的 [`StreamingRestorer`] 集合, 实现
/// [`crate::codec::stream::StreamRestoreHook`].
///
/// 每个 block index 惰性创建独立 restorer (首次 BlockDelta 时), BlockStop 时移除.
pub struct StreamingRestorerSet {
    map: RedactionMap,
    restorers: HashMap<usize, StreamingRestorer>,
}

impl StreamingRestorerSet {
    /// 构造. `map` 为空时所有 push 直接透传 (StreamingRestorer 空短路, 零开销).
    pub fn new(map: RedactionMap) -> Self {
        Self {
            map,
            restorers: HashMap::new(),
        }
    }
}

impl crate::codec::stream::StreamRestoreHook for StreamingRestorerSet {
    fn restore_delta(&mut self, index: usize, kind: DeltaKind, s: String) -> String {
        let r = self
            .restorers
            .entry(index)
            .or_insert_with(|| StreamingRestorer::new(self.map.clone()));
        r.set_kind(kind);
        r.push(s)
    }

    fn flush_delta(&mut self, index: usize) -> (DeltaKind, String) {
        match self.restorers.remove(&index) {
            Some(mut r) => r.flush(),
            // 未见过该 block (eg BlockStop 无前置 BlockDelta): 无残余, 默认 kind.
            None => (DeltaKind::Text, String::new()),
        }
    }

    fn flush_all(&mut self) -> Vec<(usize, DeltaKind, String)> {
        let mut indices: Vec<usize> = self.restorers.keys().copied().collect();
        // index 升序 emit, 避免违反客户端对 delta 时序的隐含假设
        // (eg OpenAI tool_call arguments partial JSON parser 假设按 index 顺序到达).
        indices.sort_unstable();
        // 空 tail 过滤由消费方 (codec::stream::tail_events) 单点执行.
        indices
            .into_iter()
            .map(|i| {
                let (kind, tail) = self.flush_delta(i);
                (i, kind, tail)
            })
            .collect()
    }

    fn restore_inline(&mut self, s: &mut String) {
        restore_str_inplace(s, &self.map);
    }
}

/// [`restore_str`] 的纯函数版本 (in-place), 复用同一段 find-and-replace 逻辑.
pub(crate) fn restore_str_inplace(s: &mut String, map: &RedactionMap) {
    if map.is_empty() || s.is_empty() {
        return;
    }
    for (mock, real) in &map.mock_to_real {
        if s.contains(mock) {
            *s = s.replace(mock, real);
        }
    }
}

// ─── IR traverse helpers (StringLeafOps trait) ──────────────────────────────
//
// 三类操作 (contains / replace / restore) 对 IR 的遍历结构完全相同, 仅叶子上的动作不同.
// 历史上用三套平行的 block_* / tool_* / value_* / image_source_* 函数复制, 新增 IrBlock
// variant 需同步改 9+ 处. 这里用 StringLeafOps trait 把遍历结构与叶子动作解耦:
// 新增 variant 只需在 impl StringLeafOps for IrBlock 改一处, 三类操作自动对齐.

/// 把"遍历 IR 所有可含 secret 的字符串叶子"这一结构抽象为 trait,
/// 让 contains / replace / restore 三类操作复用同一份遍历代码.
///
/// 叶子定义 (与原 block_contains / value_contains 扫描范围严格一致):
/// - `IrBlock::Text.text`
/// - `IrBlock::ToolUse.{id, name}` + `input` 的 JSON 字符串叶子
/// - `IrBlock::ToolResult.tool_use_id` + `content[]` 递归
/// - `IrBlock::Image.source` (仅 Url 变体)
/// - `IrTool.{name, description?}` + `input_schema` 的 JSON 字符串叶子
/// - `IrRequest.{stop[], user?, extra 字符串叶子}`
/// - `IrResponse.{stop_sequence?, content[]}`
///
/// 设计: 两方法 (不可变 / 可变), 叶子回调为 `FnMut` 允许捕获外部状态 (found 标志 / map).
/// 字符串叶子遍历/替换 trait (crate 内可见, 供 codec test 复用).
///
/// redact 在 IR 字符串叶子做 real↔mock 替换; 该 trait 抽象"找到所有字符串叶子"的逻辑,
/// 让 IrRequest / IrBlock / Value 等不同容器共享同一套遍历代码.
///
/// **走查责任 (SSOT 并行实现)**: [`collect_ir_str_leaves`] / [`collect_block_leaves`] /
/// [`collect_value_leaves`] (P2-1 性能优化缓存构造器) 因 trait `&str` 生命周期不可外提
/// 而内联了相同遍历逻辑. 新增 IrBlock variant / IrTool 字段时, 本 trait impl 与这三
/// 函数两处都要改; 一致性由 `tests::collect_leaves_matches_for_each_str_leaf` 守卫.
pub(crate) trait StringLeafOps {
    /// 遍历所有字符串叶子 (不可变借用).
    fn for_each_str_leaf(&self, f: &mut impl FnMut(&str));
    /// 遍历所有字符串叶子 (可变借用, 用于 replace / restore).
    fn for_each_str_leaf_mut(&mut self, f: &mut impl FnMut(&mut String));
}

impl StringLeafOps for serde_json::Value {
    fn for_each_str_leaf(&self, f: &mut impl FnMut(&str)) {
        match self {
            serde_json::Value::String(s) => f(s),
            serde_json::Value::Array(arr) => {
                for e in arr {
                    e.for_each_str_leaf(f);
                }
            }
            serde_json::Value::Object(obj) => {
                for e in obj.values() {
                    e.for_each_str_leaf(f);
                }
            }
            _ => {}
        }
    }

    fn for_each_str_leaf_mut(&mut self, f: &mut impl FnMut(&mut String)) {
        match self {
            serde_json::Value::String(s) => f(s),
            serde_json::Value::Array(arr) => {
                for e in arr.iter_mut() {
                    e.for_each_str_leaf_mut(f);
                }
            }
            serde_json::Value::Object(obj) => {
                for e in obj.values_mut() {
                    e.for_each_str_leaf_mut(f);
                }
            }
            _ => {}
        }
    }
}

impl StringLeafOps for IrBlock {
    fn for_each_str_leaf(&self, f: &mut impl FnMut(&str)) {
        match self {
            IrBlock::Text { text } => f(text),
            IrBlock::ToolUse { id, name, input } => {
                f(id);
                f(name);
                input.for_each_str_leaf(f);
            }
            IrBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } => {
                f(tool_use_id);
                for c in content {
                    c.for_each_str_leaf(f);
                }
            }
            IrBlock::Image { source } => {
                if let crate::codec::ir::IrImageSource::Url(u) = source {
                    f(u);
                }
            }
            IrBlock::Reasoning { summary } => {
                for s in summary {
                    f(s);
                }
            }
            IrBlock::ReasoningContent { text } => f(text),
        }
    }

    fn for_each_str_leaf_mut(&mut self, f: &mut impl FnMut(&mut String)) {
        match self {
            IrBlock::Text { text } => f(text),
            IrBlock::ToolUse { id, name, input } => {
                f(id);
                f(name);
                input.for_each_str_leaf_mut(f);
            }
            IrBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } => {
                f(tool_use_id);
                for c in content.iter_mut() {
                    c.for_each_str_leaf_mut(f);
                }
            }
            IrBlock::Image { source } => {
                if let crate::codec::ir::IrImageSource::Url(u) = source {
                    f(u);
                }
            }
            IrBlock::Reasoning { summary } => {
                for s in summary {
                    f(s);
                }
            }
            IrBlock::ReasoningContent { text } => f(text),
        }
    }
}

impl StringLeafOps for IrTool {
    fn for_each_str_leaf(&self, f: &mut impl FnMut(&str)) {
        let IrTool {
            name,
            description,
            input_schema,
        } = self;
        f(name);
        if let Some(d) = description {
            f(d);
        }
        input_schema.for_each_str_leaf(f);
    }

    fn for_each_str_leaf_mut(&mut self, f: &mut impl FnMut(&mut String)) {
        let IrTool {
            name,
            description,
            input_schema,
        } = self;
        f(name);
        if let Some(d) = description {
            f(d);
        }
        input_schema.for_each_str_leaf_mut(f);
    }
}

impl StringLeafOps for IrRequest {
    fn for_each_str_leaf(&self, f: &mut impl FnMut(&str)) {
        for block in &self.system {
            block.for_each_str_leaf(f);
        }
        for msg in &self.messages {
            for block in &msg.content {
                block.for_each_str_leaf(f);
            }
        }
        for tool in &self.tools {
            tool.for_each_str_leaf(f);
        }
        for s in &self.stop {
            f(s);
        }
        if let Some(u) = &self.user {
            f(u);
        }
        // extra 是 Map<String, Value>, 遍历所有 Value 的字符串叶子
        // (与原 value_contains(&Value::Object(extra.clone())) 等价, 避免 clone).
        for v in self.extra.values() {
            v.for_each_str_leaf(f);
        }
    }

    fn for_each_str_leaf_mut(&mut self, f: &mut impl FnMut(&mut String)) {
        for block in &mut self.system {
            block.for_each_str_leaf_mut(f);
        }
        for msg in &mut self.messages {
            for block in &mut msg.content {
                block.for_each_str_leaf_mut(f);
            }
        }
        for tool in &mut self.tools {
            tool.for_each_str_leaf_mut(f);
        }
        for s in &mut self.stop {
            f(s);
        }
        if let Some(u) = &mut self.user {
            f(u);
        }
        for v in self.extra.values_mut() {
            v.for_each_str_leaf_mut(f);
        }
    }
}

impl StringLeafOps for IrResponse {
    fn for_each_str_leaf(&self, f: &mut impl FnMut(&str)) {
        if let Some(s) = &self.stop_sequence {
            f(s);
        }
        for block in &self.content {
            block.for_each_str_leaf(f);
        }
    }

    fn for_each_str_leaf_mut(&mut self, f: &mut impl FnMut(&mut String)) {
        if let Some(s) = &mut self.stop_sequence {
            f(s);
        }
        for block in &mut self.content {
            block.for_each_str_leaf_mut(f);
        }
    }
}

/// 一次性收集 IR 所有字符串叶子为 `Vec<&str>` (零拷贝, 只持有叶子引用).
///
/// **用途 (P2-1)**: [`gen_mock_for_ir`] 在首次 probing 冲突 (P≥2) 时构造此缓存,
/// 后续 probing 复用, 避免每次都递归 match IrBlock 结构.
///
/// **零拷贝**: 返回叶子引用而非拼接 String, 避免 K=1 P=1 场景下大 body 的拷贝退化.
///
/// **为何不复用 `for_each_str_leaf`**: trait 签名 `fn for_each_str_leaf(&self, f: &mut
/// impl FnMut(&str))` 的 `&str` 生命周期省略绑 `&self`, 但把 `&str` 收集到外部 `Vec`
/// 时编译器无法传播该生命周期 (E0521). 故此处内联遍历逻辑.
///
/// **SSOT 警告**: 此函数 + [`collect_block_leaves`] + [`collect_value_leaves`] 与
/// [`StringLeafOps`] (for IrRequest/IrBlock/Value) 是**并行实现**, 叶子集合必须完全
/// 一致 (漏收一个叶子 = secret 泄漏, 多收一个 = 性能退化). 新增 IrBlock variant /
/// IrTool 字段时, `impl StringLeafOps` 与这三个 collect 函数两处都要改. 一致性由
/// `tests::collect_leaves_matches_for_each_str_leaf` 测试机械守卫.
fn collect_ir_str_leaves(ir: &IrRequest) -> Vec<&str> {
    let mut leaves: Vec<&str> = Vec::new();
    for block in &ir.system {
        collect_block_leaves(block, &mut leaves);
    }
    for msg in &ir.messages {
        for block in &msg.content {
            collect_block_leaves(block, &mut leaves);
        }
    }
    for tool in &ir.tools {
        leaves.push(&tool.name);
        if let Some(d) = &tool.description {
            leaves.push(d);
        }
        collect_value_leaves(&tool.input_schema, &mut leaves);
    }
    for s in &ir.stop {
        leaves.push(s);
    }
    if let Some(u) = &ir.user {
        leaves.push(u);
    }
    for v in ir.extra.values() {
        collect_value_leaves(v, &mut leaves);
    }
    leaves
}

/// [`collect_ir_str_leaves`] 的 IrBlock 递归辅助.
fn collect_block_leaves<'a>(block: &'a IrBlock, leaves: &mut Vec<&'a str>) {
    match block {
        IrBlock::Text { text } => leaves.push(text),
        IrBlock::ToolUse { id, name, input } => {
            leaves.push(id);
            leaves.push(name);
            collect_value_leaves(input, leaves);
        }
        IrBlock::ToolResult {
            tool_use_id,
            content,
            ..
        } => {
            leaves.push(tool_use_id);
            for c in content {
                collect_block_leaves(c, leaves);
            }
        }
        IrBlock::Image { source } => {
            if let crate::codec::ir::IrImageSource::Url(u) = source {
                leaves.push(u);
            }
        }
        IrBlock::Reasoning { summary } => {
            for s in summary {
                leaves.push(s);
            }
        }
        IrBlock::ReasoningContent { text } => leaves.push(text),
    }
}

/// [`collect_ir_str_leaves`] 的 serde_json::Value 递归辅助.
fn collect_value_leaves<'a>(value: &'a serde_json::Value, leaves: &mut Vec<&'a str>) {
    match value {
        serde_json::Value::String(s) => leaves.push(s),
        serde_json::Value::Array(arr) => {
            for e in arr {
                collect_value_leaves(e, leaves);
            }
        }
        serde_json::Value::Object(obj) => {
            for e in obj.values() {
                collect_value_leaves(e, leaves);
            }
        }
        _ => {}
    }
}

/// IR 中是否出现 needle (在字符串字段中).
///
/// 扫描范围: system blocks / messages.blocks / tools (name+description+input_schema) /
/// `IrBlock::ToolUse.{id, name, input}` / `IrBlock::ToolResult.content` (递归) /
/// stop sequences / user / extra (JSON 字符串叶子).
///
/// **性能角色 (P2-1)**: [`redact_ir`] 入口的 secret 命中检查 + `gen_mock_for_ir`
/// 首次 probing (counter=0) 均用此函数 (零拷贝遍历). 仅当首次 probing 冲突 (P≥2) 时,
/// `gen_mock_for_ir` 才切换到 `collect_ir_str_leaves` 缓存路径.
fn ir_request_contains(ir: &IrRequest, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut found = false;
    ir.for_each_str_leaf(&mut |s| {
        if s.contains(needle) {
            found = true;
        }
    });
    found
}

/// IR 中所有字符串字段把 `from` 全部替换为 `to`.
fn ir_request_replace_all(ir: &mut IrRequest, from: &str, to: &str) {
    if from.is_empty() {
        return;
    }
    ir.for_each_str_leaf_mut(&mut |s| replace_in_place(s, from, to));
}

// ─── 位置统计 (redact 审计, USAGE-7 治理归因) ──────────────────────────────

/// 只读统计 needle 在单个字符串叶子的出现次数.
fn str_occurrences(s: &str, needle: &str) -> u64 {
    if needle.is_empty() {
        return 0;
    }
    s.matches(needle).count() as u64
}

/// 只读统计 needle 在 [`StringLeafOps`] 结构的全部字符串叶子出现次数
/// (复用既有只读遍历; 与替换路径 (`for_each_str_leaf_mut`) 覆盖同一叶子集).
fn leaf_hits(x: &impl StringLeafOps, needle: &str) -> u64 {
    let mut n = 0;
    x.for_each_str_leaf(&mut |s| n += str_occurrences(s, needle));
    n
}

/// 统计 needle (real secret) 在 IR 各位置类别的出现次数, redact 替换前调用.
///
/// 调用前提: `ir_request_contains` 已命中 (本函数不再短路, 直接全量遍历).
/// 分类语义见 [`HitLocations`]: system / tools / user (contains_user_text) /
/// history (其余 messages) / other (stop / user 字段 / extra).
fn count_hit_locations(ir: &IrRequest, needle: &str) -> crate::codec::ir::HitLocations {
    let mut h = crate::codec::ir::HitLocations {
        system: ir.system.iter().map(|b| leaf_hits(b, needle)).sum(),
        tools: ir.tools.iter().map(|t| leaf_hits(t, needle)).sum(),
        ..Default::default()
    };
    for msg in &ir.messages {
        let n: u64 = msg.content.iter().map(|b| leaf_hits(b, needle)).sum();
        if n > 0 {
            if msg.contains_user_text {
                h.user += n;
            } else {
                h.history += n;
            }
        }
    }
    // other: 协议边缘位置 (stop / user 字段 / extra), 罕见但替换路径覆盖, 审计同步覆盖.
    let mut other: u64 = ir.stop.iter().map(|s| str_occurrences(s, needle)).sum();
    if let Some(u) = &ir.user {
        other += str_occurrences(u, needle);
    }
    for v in ir.extra.values() {
        other += leaf_hits(v, needle);
    }
    h.other = other;
    h
}

/// 在 s 中替换所有 from 出现为 to.
fn replace_in_place(s: &mut String, from: &str, to: &str) {
    if from.is_empty() || !s.contains(from) {
        return;
    }
    *s = s.replace(from, to);
}

/// 在 s 中把所有 mock 替换为 real (反向 redact).
fn restore_str(s: &mut String, map: &RedactionMap) {
    restore_str_inplace(s, map);
}

// ─── 测试工具 ──────────────────────────────────────────────────────────────

#[cfg(test)]
fn sample_ir_with_text(text: &str) -> IrRequest {
    use crate::codec::ir::{IrMessage, IrRole};
    IrRequest {
        system: vec![],
        messages: vec![IrMessage {
            role: IrRole::User,
            content: vec![IrBlock::Text {
                text: text.to_string(),
            }],
            ..Default::default()
        }],
        tools: vec![],
        max_tokens: Some(100),
        model: "test-model".to_string(),
        ..Default::default()
    }
}

#[cfg(test)]
fn sample_ir_response_with_text(text: &str) -> IrResponse {
    IrResponse {
        content: vec![IrBlock::Text {
            text: text.to_string(),
        }],
        ..Default::default()
    }
}

#[cfg(test)]
use crate::secrets::SecretCategory;

#[cfg(test)]
fn entry(value: &str) -> SecretEntry {
    let mut e = SecretEntry {
        id: format!("id-{value}"),
        name: None,
        category: SecretCategory::ApiKey,
        value: value.into(),
        value_file: None,
        mock_strategy: crate::mock::MockStrategy::default(),
    };
    // 测试 helper 模拟生产路径: validate_and_resolve 会调用 resolve_against,
    // 让 Auto 模式的 gen spec 被 infer 出来 (否则 gen_candidate 会 panic).
    // 测试默认场景: 空 global_prefix (Auto 模式 mock 无前缀).
    e.mock_strategy.resolve_against(&e.value, "");
    e
}

/// 预测 redact 对给定 real_secret 生成的首个 mock (counter=0).
///
/// 复用 entry() helper (空 global_prefix) + init_seed + gen_candidate,
/// 与生产 [`redact_ir`] 路径的首次候选一致. 集中"如何预测 mock"知识, 供多个测试复用.
#[cfg(test)]
fn predict_mock(real: &str) -> String {
    let e = entry(real);
    let seed = init_seed(std::slice::from_ref(&e));
    crate::mock::gen_candidate(real, &e.mock_strategy, seed, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::ir::{IrMessage, IrResponse, IrRole};
    use pretty_assertions::assert_eq;

    /// 构造一个"探测必耗尽"的 SecretEntry: Auto + digits-only + length_range=(1,1)
    /// → 仅 10 个候选 "0".."9". 配合 [`EXHAUSTING_IR_TEXT_TEMPLATE`] (含全部 10 个候选)
    /// 即可稳定触发 gen_mock_for_ir 的耗尽降级路径 (warn, 不 panic).
    ///
    /// 用于两条 SEC-3 测试: 行为回归 (不 panic) + proptest (warn 日志不泄漏 secret).
    fn exhausted_secret_entry(secret: &str) -> SecretEntry {
        use crate::mock::{Charset, GenSpec, InitialValue, MockStrategy};
        let mut e = SecretEntry {
            id: "weak-secret".into(),
            name: None,
            category: SecretCategory::ApiKey,
            value: secret.into(),
            value_file: None,
            mock_strategy: MockStrategy {
                initial: InitialValue::Auto,
                gen_spec: Some(GenSpec {
                    prefix: String::new(),
                    charset: Charset {
                        digits: true,
                        ..Default::default()
                    },
                    length_range: (1, 1), // 仅 10 个可能值
                }),
            },
        };
        e.mock_strategy.resolve_against(secret, "");
        e
    }

    /// 含全部 10 个数字候选 ("0".."9") 的 IR 文本模板. 用 `format!("{secret}")`
    /// 在末尾追加真实 secret, 确保 redact_ir 实际尝试生成 mock (而非因 IR 无命中而跳过).
    const EXHAUSTING_IR_TEXT_TEMPLATE: &str = "0 1 2 3 4 5 6 7 8 9 filler ";

    // ─── 契约单元测试 ──────────────────────────────────────────────────────

    #[test]
    fn c1_non_empty() {
        // Auto 模式 (空 global_prefix) 生成的 mock 非空, 仅含 infer 自 real 的字符集.
        let ir = sample_ir_with_text("ctx");
        let mut ir_mut = ir.clone();
        let _ = redact_ir(&mut ir_mut, &[entry("sk-test-123")]);
        let m = predict_mock("sk-test-123");
        assert!(!m.is_empty());
        // 空 prefix + real "sk-test-123" → mock 与 real 等长 (11 chars), charset 来自 real.
        assert_eq!(m.chars().count(), 11);
    }

    #[test]
    fn c2_in_context_uniqueness() {
        // gen_mock_for_ir 生成的 mock 必须不出现在当前 IR 中.
        // 构造 IR 里含一个占位字符串, gen 出的 mock 应该避开它.
        let ir = sample_ir_with_text("placeholder-string-that-must-be-avoided");
        let allocated = HashSet::new();
        let entry = entry("real-secret");
        let seed = init_seed(std::slice::from_ref(&entry));
        let m = gen_mock_for_ir(&ir, &entry, seed, &allocated).expect("probing must succeed");
        assert!(
            !ir_request_contains(&ir, &m),
            "gen mock must avoid existing IR content; got {m}"
        );
        assert_ne!(m, "placeholder-string-that-must-be-avoided");
    }

    /// #161: disabled secret 明文放行检测 — 命中才告警 (返回命中数), 未命中零输出.
    /// 覆盖: value 出现 → hit; value 不出现 → 0; 空 value → 0 (防御).
    #[test]
    fn warn_disabled_secrets_hits_only_when_value_present() {
        let body = b"hello sk-live-qwerty987654 world";
        let hit = entry("sk-live-qwerty987654");
        let miss = entry("totally-absent-secret");
        let mut empty_val = entry("");
        empty_val.id = "empty".into();
        assert_eq!(
            warn_disabled_secrets_in_body(body, std::slice::from_ref(&hit)),
            1
        );
        assert_eq!(
            warn_disabled_secrets_in_body(body, std::slice::from_ref(&miss)),
            0
        );
        // 同一 body 多个 disabled secret: 各自独立检测.
        assert_eq!(
            warn_disabled_secrets_in_body(body, &[hit, miss, empty_val]),
            1
        );
        assert_eq!(warn_disabled_secrets_in_body(body, &[]), 0);
        // 空 body: 永不命中.
        assert_eq!(
            warn_disabled_secrets_in_body(b"", &[entry("sk-live-qwerty987654")]),
            0
        );
    }

    /// #161 (SEC): 命中告警的日志内容只含 secret id + "forwarded in plaintext",
    /// 永不含 secret value 本身. 复用 SEC-3 的捕获模式 (线程局部 dispatcher).
    /// 注: entry() helper 的 id 是 "id-{value}" (为方便断言), 会携带 value — 测试
    /// 用真实场景的独立 slug id (生产 id 由 validate_id 保证不含 value).
    #[test]
    fn warn_disabled_secrets_log_contains_id_not_value() {
        let secret_value = "sk-live-qwerty987654";
        let mut disabled = entry(secret_value);
        disabled.id = "prod-like-slug".into();

        let sink: std::sync::Arc<std::sync::Mutex<Vec<u8>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        tracing::dispatcher::with_default(
            &tracing::dispatcher::Dispatch::new(
                tracing_subscriber::fmt()
                    .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
                    .with_writer(CapturingMakeWriter { sink: sink.clone() })
                    .with_timer(())
                    .with_ansi(false)
                    .finish(),
            ),
            || {
                let _ = warn_disabled_secrets_in_body(
                    format!("ctx contains {secret_value}").as_bytes(),
                    std::slice::from_ref(&disabled),
                );
            },
        );
        let buf = sink.lock().expect("sink poisoned").clone();
        let log = String::from_utf8(buf).expect("captured tracing output must be valid UTF-8");
        assert!(log.contains("forwarded in plaintext"), "log: {log}");
        assert!(
            log.contains("prod-like-slug"),
            "log must carry secret_id: {log}"
        );
        assert!(
            !log.contains(secret_value),
            "log leaked secret value: {log}"
        );
    }

    /// 守卫 collect_ir_str_leaves 与 StringLeafOps::for_each_str_leaf 收集相同叶子集合.
    ///
    /// P2-1 优化引入了 collect_ir_str_leaves (+ collect_block_leaves + collect_value_leaves)
    /// 作为 StringLeafOps 的并行实现 (因 trait &str 生命周期不可外提). 漏收一个叶子会
    /// 导致 secret 泄漏 (redact 跳过该叶子中的 secret), 多收会导致性能退化. 本测试构造
    /// 覆盖全部 IrBlock variant + IrTool + IrRequest 各字段的 IR, 断言两份遍历产出相同
    /// 叶子序列, 把 SSOT 一致性从文档纪律升级为机械保证.
    #[test]
    fn collect_leaves_matches_for_each_str_leaf() {
        use crate::codec::ir::{IrImageSource, IrTool};
        let ir = IrRequest {
            system: vec![IrBlock::Text {
                text: "system-prompt".to_string(),
            }],
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![
                    IrBlock::Text {
                        text: "msg-text".to_string(),
                    },
                    IrBlock::ToolUse {
                        id: "tu-id".to_string(),
                        name: "tu-name".to_string(),
                        input: serde_json::json!({"key": "tu-input-val", "n": 42}),
                    },
                    IrBlock::ToolResult {
                        tool_use_id: "tr-id".to_string(),
                        content: vec![IrBlock::Text {
                            text: "tr-content".to_string(),
                        }],
                        is_error: false,
                        content_form: None,
                    },
                    IrBlock::Image {
                        source: IrImageSource::Url("img-url".to_string()),
                    },
                    IrBlock::Reasoning {
                        summary: vec!["reasoning-summary".to_string()],
                    },
                    IrBlock::ReasoningContent {
                        text: "reasoning-content".to_string(),
                    },
                ],
                ..Default::default()
            }],
            tools: vec![IrTool {
                name: "tool-name".to_string(),
                description: Some("tool-desc".to_string()),
                input_schema: serde_json::json!({"type": "object", "title": "schema-title"}),
            }],
            stop: vec!["stop1".to_string()],
            user: Some("user-id".to_string()),
            extra: {
                let mut m = serde_json::Map::new();
                m.insert(
                    "extra-key".to_string(),
                    serde_json::Value::String("extra-val".to_string()),
                );
                m
            },
            ..Default::default()
        };
        // for_each_str_leaf 收集 (用 String 避免 &str 生命周期外提问题, E0521).
        let mut for_each_leaves: Vec<String> = Vec::new();
        ir.for_each_str_leaf(&mut |s| for_each_leaves.push(s.to_string()));
        // collect_ir_str_leaves 收集.
        let collect_leaves: Vec<String> = collect_ir_str_leaves(&ir)
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(
            for_each_leaves, collect_leaves,
            "collect_ir_str_leaves must gather exactly the same leaves as for_each_str_leaf; \
             divergence means a secret in the missed leaf would leak unredacted"
        );
    }

    #[test]
    fn c3_determinism() {
        // gen_candidate 在同一 (real, strategy, seed, counter) 下确定.
        for secret in ["short", "sk-test-123", "a-much-longer-secret-value-XYZ"] {
            let m1 = predict_mock(secret);
            let m2 = predict_mock(secret);
            assert_eq!(m1, m2, "same input must produce same mock for '{secret}'");
        }
    }

    // C3 端到端幂等性.
    //
    // 现有 c3_determinism 只覆盖纯函数层 (predict_mock = init_seed + gen_candidate),
    // 未覆盖生产入口 redact_ir. C3 的本质是 "同一 policy + 同一 IR 上下文 → 同一
    // RedactionMap" (前缀缓存友好性的根基, 见模块头部 C3 契约). redact_ir 内部走
    // candidate_for → mock::gen_candidate (生产路径, 非 legacy), 还涉及 sorted 排序 +
    // allocated probing, 这些环节任一引入非确定性都会破坏 C3. 本测试用端到端双调用 +
    // 全 map 比对锁死该不变量.
    //
    // 场景: 2 个 secret, 分别命中 system prompt 与 user text block (覆盖多条扫描路径),
    // 断言两次 redact_ir 的 (RedactionMap, seed) 完全相等.
    #[test]
    fn c3_redact_ir_end_to_end_idempotent() {
        use crate::codec::ir::IrRequest;
        // 构造一个含 system + user text 的 IR, 让两个 secret 各命中一条扫描路径.
        let build_ir = || IrRequest {
            system: vec![IrBlock::Text {
                text: "system context mentions sk-sys-secret here".to_string(),
            }],
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text {
                    text: "user msg embeds sk-user-secret-xyz".to_string(),
                }],
                ..Default::default()
            }],
            ..sample_ir_with_text("")
        };
        let secrets = vec![entry("sk-sys-secret"), entry("sk-user-secret-xyz")];

        let (map1, seed1) = redact_ir(&mut build_ir(), &secrets);
        let (map2, seed2) = redact_ir(&mut build_ir(), &secrets);

        // seed 必须相等 (per-request seed 链起点稳定, C3 根基).
        assert_eq!(seed1, seed2, "init_seed must be stable for same policy");
        // 整个 RedactionMap 必须相等: real→mock 与 mock→real 双向索引逐条一致.
        // 这要求 sorted 顺序 + probing counter 序列 + gen_candidate 全部可复现.
        assert_eq!(
            map1, map2,
            "redact_ir must produce identical RedactionMap for identical (ir, secrets)"
        );
        // 确保测试确实命中了两个 secret (否则 map 为空会让等式平凡成立).
        assert_eq!(
            map1.real_to_mock.len(),
            2,
            "test setup must hit both secrets; got map {:?}",
            map1.real_to_mock
        );
    }

    #[test]
    fn c4_injectivity_within_redact() {
        // 100 个不同 secret, 在同一 redact_ir 内应映射到 100 个不同 mock.
        let secrets: Vec<SecretEntry> = (0..100)
            .map(|i| entry(&format!("secret-value-{i:03}")))
            .collect();
        let body_text = secrets
            .iter()
            .map(|e| e.value.clone())
            .collect::<Vec<_>>()
            .join(" ");
        let mut ir = sample_ir_with_text(&body_text);
        let (map, _) = redact_ir(&mut ir, &secrets);
        let mocks: HashSet<_> = map.real_to_mock.values().cloned().collect();
        assert_eq!(mocks.len(), 100, "all 100 mocks must be distinct");
    }

    #[test]
    fn c5_no_substring_of_real_secret() {
        // C5: mock 不应含 real_secret 的任何 ≥k(L) 字符连续子串 (阈值随 L 自适应).
        // 空 global_prefix 下, mock 由 hash 驱动 + gen_candidate 内部重试链保证兑现.
        for real in ["sk-test-123", "super-secret-xyz", "ABCDEFGH", "abcdefgh"] {
            let m = predict_mock(real);
            crate::mock::assert_no_c5_substring(&m, real);
        }
    }

    #[test]
    fn c6_round_trip_identity() {
        let text = "auth=sk-test-123; user=alice; token=ABCDEF-1234567890";
        let secrets = vec![entry("sk-test-123"), entry("ABCDEF-1234567890")];
        let mut ir = sample_ir_with_text(text);
        let (map, _) = redact_ir(&mut ir, &secrets);
        // 验证 redact 确实替换了.
        let redacted_text = match &ir.messages[0].content[0] {
            IrBlock::Text { text } => text.clone(),
            _ => panic!("expected Text"),
        };
        assert!(!redacted_text.contains("sk-test-123"));
        assert!(!redacted_text.contains("ABCDEF-1234567890"));
        // restore_ir_response 端到端验证.
        let mut restored_ir = sample_ir_response_with_text(&redacted_text);
        restore_ir_response(&mut restored_ir, &map);
        let restored_text = match &restored_ir.content[0] {
            IrBlock::Text { text } => text.clone(),
            _ => panic!("expected Text"),
        };
        assert_eq!(restored_text, text, "round-trip must restore original text");
    }

    /// 结构性回归守卫: 每种 IrBlock variant 的字符串叶子都必须被 StringLeafOps 覆盖.
    ///
    /// 这是 StringLeafOps trait 重构的配套测试: 新增 IrBlock variant 时, 若忘记在
    /// `for_each_str_leaf` / `for_each_str_leaf_mut` 的 match 中处理, 此测试会失败.
    /// 每种 variant 构造一个含 marker 的实例, 验证 contains 能找到, replace 能改掉.
    #[test]
    fn string_leaf_ops_covers_all_ir_block_variants() {
        use crate::codec::ir::{IrBlock, IrImageSource};
        use serde_json::json;

        // marker 作为 "secret", 注入到每种 variant 的至少一个字符串叶子.
        let marker = "LEAFMARKER";
        let blocks: Vec<IrBlock> = vec![
            IrBlock::Text {
                text: format!("prefix-{marker}-suffix"),
            },
            IrBlock::ToolUse {
                id: format!("call-{marker}"),
                name: "tool".into(),
                input: json!({"key": format!("val-{marker}")}),
            },
            IrBlock::ToolResult {
                tool_use_id: format!("call-{marker}"),
                content: vec![IrBlock::Text {
                    text: format!("nested-{marker}"),
                }],
                is_error: false,
                content_form: None,
            },
            IrBlock::Image {
                source: IrImageSource::Url(format!("https://example.com/{marker}.png")),
            },
            // Base64 image source: 不含 secret (与非 Url 变体的扫描语义一致), 跳过 marker 注入.
            IrBlock::Image {
                source: IrImageSource::Base64 {
                    media_type: "image/png".into(),
                    data: "iVBOR".into(),
                },
            },
        ];

        for (i, block) in blocks.iter().take(4).enumerate() {
            // 不可变遍历: marker 必须被发现 (前 4 个 block 含 marker).
            let mut found = false;
            block.for_each_str_leaf(&mut |s| {
                if s.contains(marker) {
                    found = true;
                }
            });
            assert!(found, "block #{i} leaf not visited by for_each_str_leaf");

            // 可变遍历: replace marker → REPLACED.
            let mut b = block.clone();
            b.for_each_str_leaf_mut(&mut |s| {
                if s.contains(marker) {
                    *s = s.replace(marker, "REPLACED");
                }
            });
            let mut still_has = false;
            b.for_each_str_leaf(&mut |s| {
                if s.contains(marker) {
                    still_has = true;
                }
            });
            assert!(!still_has, "block #{i} still contains marker after replace");
        }
    }

    // ─── 行为测试 ──────────────────────────────────────────────────────────

    #[test]
    fn mock_length_matches_real_when_no_prefix() {
        // 空 global_prefix 下, infer 的 mock 长度 == real 长度 (见 GenSpec::infer_default_for).
        for real in ["abcd", "sk-test", "-leading-dash", "longer-secret-value"] {
            let m = predict_mock(real);
            assert_eq!(
                m.chars().count(),
                real.chars().count(),
                "mock '{m}' length must equal real '{real}' (no global prefix)"
            );
        }
    }

    #[test]
    fn redact_ir_skips_secret_when_probing_exhausted_instead_of_panicking() {
        // 弱配置回归: Auto 模式 + charset.digits + length_range=(1,1) 仅产生 10 个候选 ("0".."9").
        // 旧实现在 IR 已含全部 10 个候选时会 panic, 消息含真实 secret 明文 (DoS + 泄密).
        // 现在应降级跳过该 secret (原样保留 real), 不 panic.
        let real_secret = "super-secret-value-DO-NOT-LEAK";
        let weak_entry = exhausted_secret_entry(real_secret);

        // IR 含全部 10 个数字候选 → gen_mock_for_ir 必然耗尽.
        let ir_text = format!("{EXHAUSTING_IR_TEXT_TEMPLATE}also contains {real_secret}");
        let mut ir = sample_ir_with_text(&ir_text);
        let (map, _) = redact_ir(&mut ir, std::slice::from_ref(&weak_entry));

        // 不 panic 即通过. 进一步断言: 该 secret 被跳过 (map 为空, real 原样保留).
        assert!(
            map.is_empty(),
            "exhausted secret should be skipped, not mapped; got map with {} entries",
            map.real_to_mock.len()
        );
        let redacted_text = match &ir.messages[0].content[0] {
            IrBlock::Text { text } => text.as_str(),
            _ => panic!("expected Text block"),
        };
        assert!(
            redacted_text.contains(real_secret),
            "real secret must be preserved verbatim when probing exhausts (skip, not crash)"
        );
    }

    #[test]
    fn redaction_map_insert_collision_returns_err_without_leaking_secret() {
        // C4 违反 (defense-in-depth) 应返回 Err 而非 panic, 且 Err 不含 real secret 明文.
        let mut map = RedactionMap::default();
        let real_a = "secret-AAAAAAA";
        let real_b = "secret-BBBBBBB";
        let same_mock = "MOCK-COLLISION";
        map.insert(real_a.to_string(), same_mock.to_string(), "id-a")
            .unwrap();
        let err = map
            .insert(real_b.to_string(), same_mock.to_string(), "id-b")
            .expect_err("collision must return Err");
        // Err 的 Debug / Display 不得含任一 real secret 明文.
        let err_dbg = format!("{err:?}");
        assert!(!err_dbg.contains(real_a), "Err leaks real_a: {err_dbg}");
        assert!(!err_dbg.contains(real_b), "Err leaks real_b: {err_dbg}");
        assert_eq!(err.reason, RedactReason::MockCollision);
        // collision 路径的 secret_id 由调用方传入 (旧实现填空串).
        assert_eq!(err.secret_id, "id-b");
    }

    // ─── redact_ir_checked: fail_open / fail_closed 模式 ──────────────────

    #[test]
    fn redact_ir_checked_fail_open_skips_exhausted_secret() {
        // FailOpen 模式: 与历史 redact_ir 行为一致 (warn + skip, 不 panic, 不 Err).
        // 弱配置 (digits-only + length=1) + IR 含全部 10 个候选 → probing 必耗尽.
        let real_secret = "super-secret-value-DO-NOT-LEAK";
        let weak_entry = exhausted_secret_entry(real_secret);
        let ir_text = format!("{EXHAUSTING_IR_TEXT_TEMPLATE}also contains {real_secret}");
        let mut ir = sample_ir_with_text(&ir_text);

        let result = redact_ir_checked(
            &mut ir,
            std::slice::from_ref(&weak_entry),
            crate::config::OnProbeExhausted::FailOpen,
        );
        // FailOpen 永不 Err (与旧 redact_ir 语义一致).
        let (map, _) = result.expect("FailOpen must not return Err on exhaustion");
        assert!(map.is_empty(), "exhausted secret should be skipped");

        // IR 仍保留 real secret (未替换, 原样转发 — 这是 fail_open 的语义代价).
        let text = match &ir.messages[0].content[0] {
            IrBlock::Text { text } => text.as_str(),
            _ => panic!("expected Text block"),
        };
        assert!(
            text.contains(real_secret),
            "FailOpen: real secret preserved (forwarded unredacted); this is the documented trade-off"
        );
    }

    #[test]
    fn redact_ir_checked_fail_closed_returns_err_on_exhaustion() {
        // FailClosed 模式: probing 耗尽时返回 Err, 让调用方拒绝转发 (防 secret 泄露).
        let real_secret = "super-secret-value-DO-NOT-LEAK";
        let weak_entry = exhausted_secret_entry(real_secret);
        let ir_text = format!("{EXHAUSTING_IR_TEXT_TEMPLATE}also contains {real_secret}");
        let mut ir = sample_ir_with_text(&ir_text);

        let err = redact_ir_checked(
            &mut ir,
            std::slice::from_ref(&weak_entry),
            crate::config::OnProbeExhausted::FailClosed,
        )
        .expect_err("FailClosed must return Err on probing exhaustion");
        assert_eq!(err.reason, RedactReason::ProbingExhausted);
        assert_eq!(err.secret_id, "weak-secret");
        // SEC-2: Err 不得含 real secret 明文.
        let err_dbg = format!("{err:?}");
        assert!(
            !err_dbg.contains(real_secret),
            "FailClosed Err must not leak real secret: {err_dbg}"
        );
    }

    #[test]
    fn redact_ir_checked_fail_closed_returns_err_on_insert_collision() {
        // FailClosed 模式: insert collision (C4 defense-in-depth) 也应返回 Err.
        // 构造一个必然 collision 的场景: 两个 secret 映射到同一个 mock.
        // 实际生产中 C4 由 allocated 集合保证, collision 路径只在防御性检查触发.
        // 这里用 RedactionMap::insert 直接验证 reason 分类正确.
        let mut map = RedactionMap::default();
        map.insert("real-a".to_string(), "same-mock".to_string(), "id-a")
            .unwrap();
        let err = map
            .insert("real-b".to_string(), "same-mock".to_string(), "id-b")
            .expect_err("collision must return Err");
        assert_eq!(err.reason, RedactReason::MockCollision);
        // FailClosed 路径在 redact_ir_inner 内会把这个 Err 直接传播 (不 warn+skip).
    }

    #[test]
    fn redact_ir_checked_fail_closed_succeeds_when_probing_succeeds() {
        // 正常路径: FailClosed 模式下, probing 成功时与 FailOpen 行为一致 (返回 Ok + map).
        let mut ir = sample_ir_with_text("my key is sk-test-123 ok");
        let secrets = vec![entry("sk-test-123")];
        let (map, seed) = redact_ir_checked(
            &mut ir,
            &secrets,
            crate::config::OnProbeExhausted::FailClosed,
        )
        .expect("FailClosed must succeed when probing succeeds");
        assert_eq!(map.real_to_mock.len(), 1);
        assert_ne!(seed, 0, "seed must be non-zero when a secret was hit");
        // IR 中 real secret 已被替换为 mock.
        let text = match &ir.messages[0].content[0] {
            IrBlock::Text { text } => text.as_str(),
            _ => panic!("expected Text block"),
        };
        assert!(!text.contains("sk-test-123"));
        assert!(text.contains(map.mock_for("sk-test-123").unwrap()));
    }

    #[test]
    fn redact_ir_checked_fail_closed_no_secrets_returns_empty_map() {
        // 边界: 无 secret 时, 两种模式都返回 Ok + 空 map (passthrough).
        let mut ir = sample_ir_with_text("hello");
        let (map, seed) =
            redact_ir_checked(&mut ir, &[], crate::config::OnProbeExhausted::FailClosed)
                .expect("no secrets → Ok with empty map");
        assert!(map.is_empty());
        assert_eq!(seed, 0);
    }

    #[test]
    fn redact_ir_legacy_remains_fail_open_after_refactor() {
        // 回归守卫: 旧 redact_ir 公开 API 必须保持 FailOpen 行为 (向后兼容).
        // 重构后 redact_ir 内部调 redact_ir_inner(FailOpen), 此测试守卫这层不变性.
        let real_secret = "legacy-fail-open-secret";
        let weak_entry = exhausted_secret_entry(real_secret);
        let ir_text = format!("{EXHAUSTING_IR_TEXT_TEMPLATE}also contains {real_secret}");
        let mut ir = sample_ir_with_text(&ir_text);

        // 旧 API: 返回 (map, seed) 而非 Result; 耗尽时 skip (不 panic).
        let (map, _seed) = redact_ir(&mut ir, std::slice::from_ref(&weak_entry));
        assert!(map.is_empty(), "legacy redact_ir must remain fail_open");
    }

    #[test]
    fn redact_ir_replaces_secret_in_text_block() {
        let mut ir = sample_ir_with_text("my key is sk-test-123 ok");
        let secrets = vec![entry("sk-test-123")];
        let (map, _) = redact_ir(&mut ir, &secrets);
        assert_eq!(map.real_to_mock.len(), 1);
        let mock = map.mock_for("sk-test-123").unwrap();
        let redacted_text = match &ir.messages[0].content[0] {
            IrBlock::Text { text } => text.clone(),
            _ => panic!("expected Text block"),
        };
        assert!(redacted_text.contains(mock));
        assert!(!redacted_text.contains("sk-test-123"));
    }

    #[test]
    fn redaction_map_lookup_misses_return_none() {
        // mock_for / real_for 的 miss 路径 (key 不存在 → None). 现有测试都用 .unwrap(),
        // 未覆盖 None 分支. 这两个是 pub 查询接口, miss 必须返回 None 而非 panic.
        let mut ir = sample_ir_with_text("my key is sk-test-123 ok");
        let secrets = vec![entry("sk-test-123")];
        let (map, _) = redact_ir(&mut ir, &secrets);
        // 命中.
        assert!(map.mock_for("sk-test-123").is_some());
        // miss: 未 redact 过的 real.
        assert!(map.mock_for("never-redacted").is_none());
        // miss: 空字符串.
        assert!(map.mock_for("").is_none());
        // real_for miss: 任意非 mock 字符串.
        let real_mock = map.mock_for("sk-test-123").unwrap();
        assert!(map.real_for(real_mock).is_some());
        assert!(map.real_for("not-a-mock-value").is_none());
        assert!(map.real_for("").is_none());
    }

    #[test]
    fn redact_ir_replaces_secret_in_tool_use_input() {
        use serde_json::json;
        let mut ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::ToolUse {
                    id: "call_1".to_string(),
                    name: "search".to_string(),
                    input: json!({"api_key": "sk-secret-value", "other": "text"}),
                }],
                ..Default::default()
            }],
            ..sample_ir_with_text("")
        };
        let (map, _) = redact_ir(&mut ir, &[entry("sk-secret-value")]);
        assert_eq!(map.real_to_mock.len(), 1);
        // input 里的 secret 应被替换.
        match &ir.messages[0].content[0] {
            IrBlock::ToolUse { input, .. } => {
                let s = serde_json::to_string(input).unwrap();
                assert!(!s.contains("sk-secret-value"));
                assert!(s.contains(map.mock_for("sk-secret-value").unwrap()));
            }
            _ => panic!("expected ToolUse"),
        }
    }

    #[test]
    fn redact_ir_replaces_secret_in_tool_result_recursively() {
        let mut ir = IrRequest {
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::ToolResult {
                    tool_use_id: "call_1".to_string(),
                    content: vec![IrBlock::Text {
                        text: "result with sk-secret".to_string(),
                    }],
                    is_error: false,
                    content_form: None,
                }],
                ..Default::default()
            }],
            ..sample_ir_with_text("")
        };
        let (map, _) = redact_ir(&mut ir, &[entry("sk-secret")]);
        assert_eq!(map.real_to_mock.len(), 1);
        match &ir.messages[0].content[0] {
            IrBlock::ToolResult { content, .. } => match &content[0] {
                IrBlock::Text { text } => assert!(!text.contains("sk-secret")),
                _ => panic!("expected Text"),
            },
            _ => panic!("expected ToolResult"),
        }
    }

    #[test]
    fn redact_ir_replaces_secret_in_system_prompt() {
        use crate::codec::ir::IrRequest;
        let mut ir = IrRequest {
            system: vec![IrBlock::Text {
                text: "system with sk-secret".to_string(),
            }],
            ..sample_ir_with_text("")
        };
        let _ = redact_ir(&mut ir, &[entry("sk-secret")]);
        match &ir.system[0] {
            IrBlock::Text { text } => assert!(!text.contains("sk-secret")),
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn redact_ir_longer_secret_wins_overlapping() {
        // 长度倒序: 先替换 AAAAA, 替换后 IR 中无 AAAAA 残留,
        // AAA 在剩余 IR 中找不到, 不进 map.
        let mut ir = sample_ir_with_text("found AAAAA in body");
        let secrets = vec![entry("AAA"), entry("AAAAA")];
        let (map, _) = redact_ir(&mut ir, &secrets);
        assert!(
            !map.real_to_mock.contains_key("AAA"),
            "AAA should not be in map; map = {:?}",
            map.real_to_mock
        );
        assert!(map.real_to_mock.contains_key("AAAAA"));
    }

    #[test]
    fn redact_ir_skips_secret_not_in_ir() {
        let mut ir = sample_ir_with_text("hello world");
        let secrets = vec![entry("not-present")];
        let (map, _) = redact_ir(&mut ir, &secrets);
        assert!(map.is_empty());
    }

    #[test]
    fn redact_ir_dedupes_identical_values() {
        let mut ir = sample_ir_with_text("token: XYZ123");
        // 两个 entry 共享同一 value "XYZ123" 但 id 不同. redact_ir 按 value 去重,
        // 只生成一个 mock (与 map.real_to_mock 的 key 去重语义一致).
        let mut e1 = entry("XYZ123");
        e1.id = "id-1".into();
        let mut e2 = entry("XYZ123");
        e2.id = "id-2".into();
        let secrets = vec![e1, e2];
        let (map, _) = redact_ir(&mut ir, &secrets);
        assert_eq!(map.real_to_mock.len(), 1);
    }

    #[test]
    fn redact_ir_no_secrets_returns_empty_map() {
        let mut ir = sample_ir_with_text("hello");
        let (map, _) = redact_ir(&mut ir, &[]);
        assert!(map.is_empty());
    }

    // ─── restore_ir_response / restore_ir_stream_event ───────────────────

    #[test]
    fn restore_ir_response_swaps_mock_back_to_real() {
        let mut ir = IrResponse {
            content: vec![IrBlock::Text {
                text: "result MOCKABCDEF12345 end".to_string(),
            }],
            ..Default::default()
        };
        let mut map = RedactionMap::default();
        map.insert(
            "sk-real-secret".to_string(),
            "MOCKABCDEF12345".to_string(),
            "id-test",
        )
        .unwrap();
        restore_ir_response(&mut ir, &map);
        match &ir.content[0] {
            IrBlock::Text { text } => {
                assert!(text.contains("sk-real-secret"));
                assert!(!text.contains("MOCKABCDEF12345"));
            }
            _ => panic!("expected Text"),
        }
    }

    // ─── StreamingRestorer ───────────────────────────────────────────────

    use super::StreamingRestorer;

    fn map_with(real: &str, mock: &str) -> RedactionMap {
        let mut m = RedactionMap::default();
        m.insert(real.to_string(), mock.to_string(), "id-test")
            .unwrap();
        m
    }

    #[test]
    fn restorer_round_trip_on_single_chunk_with_full_mock() {
        let mut r = StreamingRestorer::new(map_with("real-secret", "MOCKABCDEFGHIJK"));
        let content = "the secret is MOCKABCDEFGHIJK padding-padding-padding".to_string();
        let mut emitted = r.push(content.clone());
        emitted.push_str(&r.flush().1);
        assert_eq!(emitted, "the secret is real-secret padding-padding-padding");
    }

    #[test]
    fn restorer_round_trip_on_mock_split_across_chunks() {
        // 核心 contract 的具体落地 (chunk 边界落在 mock 中间).
        // 详细 byte-offset 推理由 prop_streaming_restorer_round_trip 覆盖所有 chunk_size.
        let mut r = StreamingRestorer::new(map_with("real-secret", "MOCKABCDEFGHIJK"));
        let out1 = r.push("the secret is MOCKAB".to_string());
        let out2 = r.push("CDEFGHIJK done".to_string());
        let (_, tail) = r.flush();
        assert_eq!(out1 + &out2 + &tail, "the secret is real-secret done");
    }

    #[test]
    fn restorer_empty_map_is_passthrough() {
        let mut r = StreamingRestorer::new(RedactionMap::default());
        let out = r.push("anything".to_string());
        assert_eq!(out, "anything");
        let (_, tail) = r.flush();
        assert_eq!(tail, "");
    }

    #[test]
    fn restorer_preserves_delta_kind_on_flush() {
        // input_json delta 也应正确 restore, flush 时保留 InputJson kind.
        use super::DeltaKind;
        let mut r = StreamingRestorer::new(map_with("real-token", "MOCKABCDEFGHIJK"));
        r.set_kind(DeltaKind::InputJson);
        // 喂一段长度 ≤ hold 的不完整 mock, 全部进 buffer, push 返回空.
        let out = r.push("MOCKA".to_string()); // 5 字节 < hold=14
        assert!(
            out.is_empty(),
            "push should return empty when all held: {out}"
        );
        let (kind, tail) = r.flush();
        // kind 正确包装为 InputJsonDelta.
        let delta = kind.to_ir_delta(tail.clone());
        assert!(
            matches!(delta, crate::codec::ir::IrDelta::InputJsonDelta(_)),
            "flush should wrap tail as InputJsonDelta"
        );
        // flush 时 best-effort restore, 因 mock 不完整, tail 仍含原始 mock 残段.
        assert!(
            tail.contains("MOCKA"),
            "tail should contain raw mock remnant, got: {tail}"
        );
    }

    #[test]
    fn restorer_round_trip_on_multiple_mocks_in_one_chunk() {
        let mut map = RedactionMap::default();
        map.insert("r1".to_string(), "MOCK11111111111".to_string(), "id-r1")
            .unwrap();
        map.insert("r2".to_string(), "MOCK22222222222".to_string(), "id-r2")
            .unwrap();
        let mut r = StreamingRestorer::new(map);
        let out = r.push("a MOCK11111111111 b MOCK22222222222 c".to_string());
        let (_, tail) = r.flush();
        assert_eq!(out + &tail, "a r1 b r2 c");
    }

    #[test]
    fn restorer_caps_buffer_at_hold_when_no_mock_in_chunk() {
        // 无 mock 时尾部仍 hold (防下个 chunk 携带 mock 前缀).
        // buffer ≤ hold + 3 (UTF-8 char boundary 回退最多 3 字节, 见 find_safe_end).
        let mut r = StreamingRestorer::new(map_with("r", "MOCKABCDEFGHIJK")); // hold = 14
        let chunk = "hello world, this is a long chunk";
        let out = r.push(chunk.to_string());
        let (_, tail) = r.flush();
        assert_eq!(out + &tail, chunk);
        assert!(tail.len() <= 14 + 3, "buffer ≤ hold+3: got {}", tail.len());
    }

    // ─── property-based 测试 (proptest) ─────────────────────────────────────
    use proptest::prelude::*;

    // ─── RED-6/7 响应侧测试辅助 (response-side redact/restore fixtures) ─────
    //
    // 背景: `redact_ir` 只接受 `IrRequest` (请求侧 redact), 响应侧只有 `restore_ir_response`.
    // 因此响应侧 round-trip 的测试模型是:
    //   1. 在一个含 real secret 文本的 IrRequest 上 `redact_ir` → 得到 RedactionMap.
    //   2. 构造一个"含 mock 文本的 IrResponse" (模拟上游 LLM 回响 redacted request).
    //   3. `restore_ir_response(&mut resp, &map)` → 还原为含 real 的 response.
    //   4. 断言 restore 后的 response 字符串叶子 == 含 real 的预期 response.
    //
    // 这里集中"把一组 secrets 变成 (map, real↔mock 对)"的知识, 供多个 response 侧 property 复用.
    // 复用 [`sample_ir_with_text`] (含 real secret 文本) 触发 `redact_ir` 命中, 保证 map 非空.

    /// 对给定的 secrets 列表, 跑一次 `redact_ir` (在含 real secret 文本的 IrRequest 上),
    /// 返回 `(RedactionMap, real↔mock 对列表)`. pairs 仅含成功映射到 mock 的 secret (跳过降级的).
    ///
    /// # 假设
    /// - `secrets` 中任两个互不为子串 (否则 redact 时先替换较长者可能让较短者的文本消失,
    ///   导致 `pairs.len() < secrets.len()`). 调用方需保证 (测试用 `SECRET_{:03}` /
    ///   `[A-Z]{4,12}` 等模板均满足).
    fn redact_secrets_for_response(
        secrets: &[SecretEntry],
    ) -> (RedactionMap, Vec<(String, String)>) {
        // 构造含 real secret 的请求文本 (用空格分隔的 filler, 确保 ir_request_contains 命中每个 secret).
        let body = secrets
            .iter()
            .map(|s| s.value.as_str())
            .collect::<Vec<_>>()
            .join(" prefix ");
        let mut ir = sample_ir_with_text(&body);
        let (map, _) = redact_ir(&mut ir, secrets);
        let pairs: Vec<(String, String)> = secrets
            .iter()
            .filter_map(|s| {
                map.mock_for(&s.value)
                    .map(|m| (s.value.clone(), m.to_string()))
            })
            .collect();
        (map, pairs)
    }

    /// 构造一个含 mock 文本的 IrResponse (Text block), 模拟上游对 redacted request 的回响.
    fn mock_response_with_text(text: &str) -> IrResponse {
        IrResponse {
            content: vec![IrBlock::Text {
                text: text.to_string(),
            }],
            ..Default::default()
        }
    }

    /// 构造一个含 ToolUse 的 IrResponse, 其 input JSON 含 mock 文本.
    /// 模拟上游 LLM 决定调用工具, 把 redacted request 中的 mock 原样回传到 tool input.
    fn mock_response_with_tool_use(id: &str, name: &str, input_mock: &str) -> IrResponse {
        IrResponse {
            content: vec![IrBlock::ToolUse {
                id: id.to_string(),
                name: name.to_string(),
                input: serde_json::json!({ "token": input_mock }),
            }],
            ..Default::default()
        }
    }

    /// 收集 IrResponse 所有字符串叶子 (用于断言 "restore 后无 real 子串" 等).
    fn collect_response_str_leaves(resp: &IrResponse) -> Vec<String> {
        let mut leaves = Vec::new();
        resp.for_each_str_leaf(&mut |s: &str| leaves.push(s.to_string()));
        leaves
    }

    /// 把 full 切成 chunk_size 字节片喂给 r, 返回 emit + flush 拼接结果.
    /// boundary_align=true 时把 chunk 末尾对齐到 char boundary (UTF-8 测试用).
    fn push_chunked(
        r: &mut StreamingRestorer,
        full: &str,
        chunk_size: usize,
        boundary_align: bool,
    ) -> String {
        let bytes = full.as_bytes();
        let mut emitted = String::new();
        let mut i = 0;
        while i < bytes.len() {
            let mut end = (i + chunk_size).min(bytes.len());
            if boundary_align {
                while end < bytes.len() && !full.is_char_boundary(end) {
                    end += 1;
                }
            }
            let piece = std::str::from_utf8(&bytes[i..end]).unwrap().to_string();
            emitted.push_str(&r.push(piece));
            i = end;
        }
        emitted.push_str(&r.flush().1);
        emitted
    }

    // ─── C5 wide secret generator (PR-D) ────────────────────────────────────
    //
    // 背景: prop_c5_redact_mock_no_real_substring_end_to_end 历史用
    // `"[A-Za-z0-9]{4,32}"` 单一 ASCII 字符集. AGENTS.md "Property 设计原则"
    // 明确要求 "proptest 生成器覆盖度也作为契约要求" (历史 bug 多次出现 property 存在
    // 但生成器太窄致漏测). 这里把 secret 与 filler 维度同时扩宽, 守卫 redact_ir 在
    // 多字节 / 含 ASCII 转义字符 / 长 secret 等真实场景下的 C5 行为.

    /// C5 property 用的宽字符 secret 生成器.
    ///
    /// 4 个分支权重均衡, 每个分支确保: (a) charset 基数足够高避免 trivially 成立,
    /// (b) 含 mock generator 会在 charset 内取样的字符 (Charset::infer_from 把 real
    /// 中出现的字符收集到 mock pool 的 other[], 从而有概率偶发命中 real 子串).
    ///
    /// 覆盖维度:
    ///   1. ASCII alphanumeric (baseline, 含历史 regression "AaaaaAaA" 低基数边界).
    ///   2. ASCII 转义字符 (`"` / `\` / `\n` / `\t`): 拓宽 mock pool 字符集到含
    ///      控制字符, 守卫 byte-level substring scan 与 c5_threshold_len 在
    ///      非 alphanumeric 字符下的正确性.
    ///   3. CJK / emoji / 混合 unicode: 多字节 UTF-8, 考验 char-level windows 的
    ///      C5 检查 (byte-level 会跨 char boundary 漏检).
    ///   4. 长 secret (60-200 chars): 模拟长 API key / cookie. 长 secret 下
    ///      k(L)=⌈L/3⌉ 变大 (L=200 → k=67), 高基数 charset 下 C5 子串匹配概率
    ///      仍极低 ((1/62)^67 ≈ 10^-120, retry chain 永远 retry=0 成功), 但 k(L)
    ///      阈值本身随 L 上升是独立的覆盖维度 (短 secret k=4 与长 secret k=67 的
    ///      windows 数与子串分布形态完全不同).
    ///
    /// 边界约束:
    ///   - 长 secret 上限 200 chars: 已覆盖 k(L)=67 阈值场景 (k(L) at L=500 仅升至
    ///     167, 不增加 C5 行为覆盖维度, 徒增 proptest case 预算). reviewer 数学验证:
    ///     62^67 ≈ 10^-120, L=200 时 retry chain 实际永远 retry=0, 无 noise 风险.
    ///   - 不生成与 global_mock_prefix 直接重叠的 secret: 生产路径必经
    ///     `validate_against_real` 拦截, 该路径由 mock.rs 单元测试覆盖, 不在端到端
    ///     redact_ir property 范围内. unicode 混合已能覆盖 mock-charset 内含 real
    ///     字符的相似性场景.
    fn arb_secret_for_c5() -> BoxedStrategy<String> {
        prop_oneof![
            // 1. ASCII alphanumeric baseline (与历史生成器兼容, 但扩宽长度上界到 64).
            "[A-Za-z0-9]{4,64}",
            // 2. ASCII 转义字符 + alphanumeric: `"` / `\` / `\n` / `\t`.
            //    拓宽 mock pool (Charset::infer_from 把这些纳入 other[]),
            //    长度 4-32, 避免过长 secret 拖慢 proptest.
            "[A-Za-z0-9\"\\\\\\n\\t]{4,32}",
            // 3. CJK + emoji + ASCII 混合: 多字节 UTF-8 考验 char-level C5 检查.
            //    CJK 区 [\x{4e00}-\x{9fff}] + emoji [\x{1f300}-\x{1f6ff}] + ASCII.
            "[A-Za-z0-9\\x{4e00}-\\x{9fff}\\x{1f300}-\\x{1f6ff}]{4,32}",
            // 4. 长 secret: 高基数 ASCII alphanumeric, 长度 60-200.
            //    触发 k(L) = ⌈L/3⌉ 大阈值场景 (L=200 → k=67).
            "[A-Za-z0-9]{60,200}",
        ]
        .boxed()
    }

    /// C5 property 用的宽字符 filler 生成器.
    ///
    /// 与 secret 维度相近的字符集 (ASCII + CJK), 让 filler 可能在 IR 中引入额外
    /// 相似子串, 考验 ir_request_contains 的 byte-level scan 在多字节上下文中的正确性.
    fn arb_filler_for_c5() -> BoxedStrategy<String> {
        prop_oneof!["[a-z0-9 ]{0,40}", "[A-Za-z0-9 \\x{4e00}-\\x{9fff}]{0,40}",].boxed()
    }

    /// RED-4 单射性测试的 secret 对生成器: 50% 宽池 / 50% 窄池.
    ///
    /// 窄池 `[ab]{6,10}` = **相似对压力测试**: 2 字符池下 s1/s2 高度相似 (子串对
    /// 如 "ababab" ⊂ "abababab"、共享长前缀对的生成率显著升高), 考验长度倒序替换
    /// 的 span 消费语义与 C2 (mock 不在 pre-replace IR 中, IR 是高重复 ab 模式).
    /// 注意 charset 推断是**字符类**级 (`Charset::infer_from`: real ∈ [ab] →
    /// lowercase=true → enabled_chars 展开为全 26 小写), mock 候选空间是 26^L 而非
    /// 2^L — probing 耗尽无忧 (counter 只在 C2/C4 冲突时递进, C5 由 gen_candidate
    /// 内部重试链消化不消耗 counter; test 档 MOCK_PROBE_LIMIT 512 内全撞概率可忽略).
    /// 子串对 **不排除**: IR 形态 "{s1} {s2}" 下短者的出现 span [0, len(s1)) 与长者
    /// 的替换 span [len(s1)+1, ..) 恒不相交 (secret 不含空格, 无法跨界), 两者恒各有
    /// 一次幸存的独立出现 → 恒双双进 map. 长度倒序替换的覆盖语义
    /// (redact_ir_longer_secret_wins_overlapping) 要求短者出现完全包含在长者内部,
    /// 本 IR 形态不可能满足.
    fn arb_secret_pair_for_injectivity() -> impl Strategy<Value = (String, String)> {
        prop_oneof![
            // 宽池基线 (历史生成器): 26 字符池, 碰撞罕见.
            ("[a-z]{4,12}", "[a-z]{4,12}"),
            // 窄池: 2 字符池, 高碰撞压力.
            ("[ab]{6,10}", "[ab]{6,10}"),
        ]
    }

    proptest! {
        /// 守卫 RED-4: 不同 secret → 不同 mock (单射性, contracts.md §2).
        #[test]
        fn prop_distinct_secrets_distinct_mocks(
            (s1, s2) in arb_secret_pair_for_injectivity()
        ) {
            prop_assume!(s1 != s2);
            // 在同一个空 IR 上, 两个 secret 应映射到不同 mock.
            let mut ir = sample_ir_with_text(&format!("{s1} {s2}"));
            let (map, _) = redact_ir(&mut ir, &[entry(&s1), entry(&s2)]);
            let m1 = map.mock_for(&s1).unwrap();
            let m2 = map.mock_for(&s2).unwrap();
            prop_assert!(m1 != m2, "mocks for distinct secrets collided: {} == {}", m1, m2);
        }

        /// 守卫 RED-2: gen 出的 mock 不在 pre-replace IR 中 (上下文唯一性, contracts.md §2).
        /// 真正的 C2: gen_mock_for_ir 生成的 mock 在生成那一刻不在 IR 中.
        #[test]
        fn prop_mock_not_in_pre_redact_ir(
            secret in "[a-z0-9]{4,16}",
            filler in "[a-z0-9 ]{0,100}"
        ) {
            let body = format!("{filler} {secret} {filler}");
            let ir = sample_ir_with_text(&body);
            // gen_mock_for_ir 内部: 候选 mock 不在 ir 中.
            let allocated = HashSet::new();
            let entry = entry(&secret);
            let seed = init_seed(std::slice::from_ref(&entry));
            let m = gen_mock_for_ir(&ir, &entry, seed, &allocated).expect("probing must succeed");
            prop_assert!(!ir_request_contains(&ir, &m),
                "mock must not appear in pre-redact IR: mock={}", m);
        }

        /// 守卫 RED-6: text block 中 secret 的 redact+restore round-trip identity (可逆双射, contracts.md §2).
        #[test]
        fn prop_round_trip_identity(
            body_prefix in "[a-z0-9 ,.!?'\"\n]{0,100}",
            secret in "[A-Z]{4,12}",
            body_suffix in "[a-z0-9 ,.!?'\"\n]{0,100}"
        ) {
            let body = format!("{body_prefix}{secret}{body_suffix}");
            let mut ir = sample_ir_with_text(&body);
            let original_text = body.clone();
            let (map, _) = redact_ir(&mut ir, &[entry(&secret)]);
            // 取 redact 后的 text.
            let redacted_text = match &ir.messages[0].content[0] {
                IrBlock::Text { text } => text.clone(),
                _ => panic!("expected Text"),
            };
            // restore.
            let mut restored = redacted_text;
            for (mock, real) in &map.mock_to_real {
                if restored.contains(mock) {
                    restored = restored.replace(mock, real);
                }
            }
            prop_assert_eq!(restored, original_text);
        }

        /// 守卫 RED-6: secret 分布在 system prompt / user text / tool_result 嵌套
        /// text (两层 ToolResult 嵌套) 的**全位置** round-trip identity
        /// (可逆双射, contracts.md §2; 转正 tool_result + system 两个位置维度).
        ///
        /// 区别于 `prop_round_trip_identity` (单 text block + 手写字符串 replace):
        /// 本 property 用固定骨架 IR 把 secret 同时注入多个结构位置 (system text /
        /// user text / tool_use_id / tool_result 两层嵌套 text), secret 内容与前后缀
        /// 随机化. restore 侧复用生产 `restore_str` (per-leaf 替换) + `StringLeafOps`
        /// 的 IrRequest 叶子遍历 — 若 **restore 侧** (IrBlock 遍历或替换) 对任一位置
        /// 遗漏, redact 改写过的 mock 会残留在该位置, 整 IR 相等断言即失败.
        /// (redact 侧 `ir_request_replace_all` 与本遍历共享 StringLeafOps for IrBlock,
        /// 两者**同时**遗漏的对称故障不被本断言捕获 — 那是 StringLeafOps 自身单点
        /// 的责任, 由 `collect_leaves_matches_for_each_str_leaf` 等守卫.)
        #[test]
        fn prop_round_trip_identity_all_positions(
            body_prefix in "[a-z0-9 ,.!?'\"\n]{0,60}",
            secret in "[A-Z]{4,12}",
            body_suffix in "[a-z0-9 ,.!?'\"\n]{0,60}"
        ) {
            let mut ir = IrRequest {
                system: vec![IrBlock::Text {
                    text: format!("sys-pre {secret} {body_suffix}"),
                }],
                messages: vec![
                    IrMessage {
                        role: IrRole::User,
                        content: vec![IrBlock::Text {
                            text: format!("{body_prefix} {secret} {body_suffix}"),
                        }],
                        ..Default::default()
                    },
                    IrMessage {
                        role: IrRole::User,
                        content: vec![IrBlock::ToolResult {
                            // tool_use_id 也是字符串叶子 (secret 可经工具调用 id 泄漏).
                            tool_use_id: format!("call-{secret}"),
                            content: vec![
                                IrBlock::Text {
                                    text: format!("outer-result {secret} {body_suffix}"),
                                },
                                IrBlock::ToolResult {
                                    tool_use_id: "call-nested".to_string(),
                                    content: vec![IrBlock::Text {
                                        text: format!("nested-result {body_prefix} {secret}"),
                                    }],
                                    is_error: false,
                                    content_form: None,
                                },
                            ],
                            is_error: false,
                            content_form: None,
                        }],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            };
            let original = ir.clone();
            let (map, _) = redact_ir(&mut ir, &[entry(&secret)]);
            // restore: 与生产 restore_ir_response 相同的叶子遍历 + 替换.
            ir.for_each_str_leaf_mut(&mut |s| restore_str(s, &map));
            prop_assert_eq!(ir, original);
        }

        /// 守卫 RED-1: mock 非空 (mock 非空性, contracts.md §2).
        #[test]
        fn prop_mock_non_empty(
            secret in "[A-Za-z0-9-]{4,20}"
        ) {
            let m = predict_mock(&secret);
            prop_assert!(!m.is_empty());
        }

        /// 守卫 RED-5: mock 不含 real_secret 的 ≥k(L) 字符子串 (实质确定性, contracts.md §2).
        /// C5 契约与重试链的设计论据见
        /// `mock.rs` 模块头部 "C5" 段落 (SSOT).
        #[test]
        fn prop_no_real_substring(
            secret in "[A-Za-z0-9]{4,32}"
        ) {
            let m = predict_mock(&secret);
            crate::mock::assert_no_c5_substring(&m, &secret);
        }

        /// 守卫 RED-5: multibyte secret (中文/emoji) 同 C5 约束, char-level windows.
        /// 与 `prop_no_real_substring` 同语义, 补 multibyte 输入覆盖 (helper 内统一处理).
        #[test]
        fn prop_no_real_substring_multibyte(
            secret in "[\\x{4e00}-\\x{9fff}\\x{1f300}-\\x{1f6ff}a-zA-Z0-9]{4,32}"
        ) {
            let m = predict_mock(&secret);
            crate::mock::assert_no_c5_substring(&m, &secret);
        }

        /// 守卫 RED-6: 多 secret (1..10) 同时出现的 round-trip identity (可逆双射).
        #[test]
        fn prop_multi_secret_round_trip(
            n in 1usize..10,
            prefix in "[a-z]{0,30}",
            suffix in "[a-z]{0,30}"
        ) {
            let secrets: Vec<SecretEntry> = (0..n)
                .map(|i| entry(&format!("SECRET_{:03}", i)))
                .collect();
            let body = format!(
                "{prefix}{}{suffix}",
                secrets.iter().map(|s| s.value.as_str()).collect::<Vec<_>>().join(" /// ")
            );
            let mut ir = sample_ir_with_text(&body);
            let original = body.clone();
            let (map, _) = redact_ir(&mut ir, &secrets);
            let mut redacted_text = match &ir.messages[0].content[0] {
                IrBlock::Text { text } => text.clone(),
                _ => panic!("expected Text"),
            };
            for (mock, real) in &map.mock_to_real {
                if redacted_text.contains(mock) {
                    redacted_text = redacted_text.replace(mock, real);
                }
            }
            prop_assert_eq!(redacted_text, original);
        }

        /// 守卫 RED-6: 同一 secret 多次出现, round-trip 仍为 identity.
        #[test]
        fn prop_repeated_secret_round_trip(
            secret in "[A-Z]{4,8}",
            repeat in 1usize..5,
            filler in "[a-z ]{0,30}"
        ) {
            let body = std::iter::repeat_n(secret.clone(), repeat)
                .collect::<Vec<_>>()
                .join(&filler);
            let mut ir = sample_ir_with_text(&body);
            let original = body.clone();
            let (map, _) = redact_ir(&mut ir, &[entry(&secret)]);
            let mut redacted_text = match &ir.messages[0].content[0] {
                IrBlock::Text { text } => text.clone(),
                _ => panic!("expected Text"),
            };
            for (mock, real) in &map.mock_to_real {
                if redacted_text.contains(mock) {
                    redacted_text = redacted_text.replace(mock, real);
                }
            }
            prop_assert_eq!(redacted_text, original);
        }

        /// 守卫 RED-4: N 个不同 secret → N 个不同 mock (单射性加强版).
        #[test]
        fn prop_redact_produces_distinct_mocks(
            n in 2usize..20
        ) {
            let secrets: Vec<SecretEntry> = (0..n)
                .map(|i| entry(&format!("secret-{:03}", i)))
                .collect();
            let body = secrets.iter().map(|e| e.value.clone()).collect::<Vec<_>>().join(" ");
            let mut ir = sample_ir_with_text(&body);
            let (map, _) = redact_ir(&mut ir, &secrets);
            let mocks: HashSet<_> = map.real_to_mock.values().collect();
            prop_assert_eq!(mocks.len(), n);
        }

        /// 守卫 RED-7: StreamingRestorer 任意 chunk_size 切分下 round-trip identity (流式可逆性, contracts.md §2).
        /// 把含 mock 的文本切成任意 chunk_size, 拼接 emit + flush 必须严格等于
        /// (prefix + real + suffix).
        #[test]
        fn prop_streaming_restorer_round_trip(
            prefix in "[a-z ]{0,50}",
            suffix in "[a-z ]{0,50}",
            chunk_size in 1usize..30,
        ) {
            let real = "SECRETVALUE";
            let mock = "MOCKABCDEFGHIJK"; // 15 字节, 与 real 等价映射
            let map = map_with(real, mock);

            let full = format!("{prefix}{mock}{suffix}");
            let mut r = StreamingRestorer::new(map);
            let emitted = push_chunked(&mut r, &full, chunk_size, false);

            let expected = format!("{prefix}{real}{suffix}");
            prop_assert_eq!(emitted, expected);
        }

        /// 守卫 RED-7: 多字节 UTF-8 字符不在 char boundary 中间切 (流式可逆性 round-trip).
        /// mock 仍是 ASCII, 但 prefix/suffix 含多字节 UTF-8.
        #[test]
        fn prop_streaming_restorer_round_trip_utf8(
            prefix in "[\\x{4e00}-\\x{9fff}]{0,30}",  // 中文
            suffix in "[\\x{4e00}-\\x{9fff}]{0,30}",
            chunk_size in 1usize..=50,
        ) {
            let real = "SECRETVALUE";
            let mock = "MOCKABCDEFGHIJK";
            let map = map_with(real, mock);

            let full = format!("{prefix}{mock}{suffix}");
            let mut r = StreamingRestorer::new(map);
            let emitted = push_chunked(&mut r, &full, chunk_size, true);

            let expected = format!("{prefix}{real}{suffix}");
            prop_assert_eq!(emitted, expected);
        }

        /// 守卫 RED-7: 多 mock 同段文本的 round-trip identity (per-block isolated).
        /// 覆盖 mock self-overlap / nested mock 等边缘情况.
        #[test]
        fn prop_streaming_restorer_round_trip_multi_mock(
            filler in "[a-z ]{0,30}",
            chunk_size in 1usize..=50,
        ) {
            let real1 = "R1";
            let real2 = "R2";
            let mock1 = "MOCK11111111111"; // 15 字节
            let mock2 = "MOCK22222222222";
            let mut map = RedactionMap::default();
            map.insert(real1.to_string(), mock1.to_string(), "id-r1")
                .unwrap();
            map.insert(real2.to_string(), mock2.to_string(), "id-r2")
                .unwrap();

            // full 含两个 mock + filler (可能相邻 / 嵌套 / 被 filler 分隔).
            let full = format!("{filler}{mock1}{filler}{mock2}{filler}");
            let mut r = StreamingRestorer::new(map);
            let emitted = push_chunked(&mut r, &full, chunk_size, false);

            let expected = format!("{filler}{real1}{filler}{real2}{filler}");
            prop_assert_eq!(emitted, expected);
        }

        /// 守卫 RED-3: redact_ir 幂等 (同一 IR+policy → 同一 RedactionMap, 确定性, contracts.md §2).
        /// property 版: 对任意 (prefix, suffix, secret) 组合,
        /// 同一 IR + 同一 policy 的两次 redact_ir 调用必须产出逐字段相等的
        /// RedactionMap 与相等的 seed. 现有 c3_determinism 只覆盖纯函数层
        /// (predict_mock), prop_distinct_secrets_distinct_mocks 只比对 mock 是否两两
        /// 不同, 两者都未锁死 "整张 map 可复现" 这一 C3 核心不变量.
        #[test]
        fn prop_c3_redact_ir_idempotent(
            secret in "[A-Za-z0-9]{4,16}",
            filler in "[a-z0-9 ]{0,60}",
        ) {
            let body = format!("{filler} {secret} {filler}");
            let secrets = vec![entry(&secret)];
            // 两次独立 redact_ir: 重建 IR 以避免前一次原地变异影响.
            let (map1, seed1) = redact_ir(&mut sample_ir_with_text(&body), &secrets);
            let (map2, seed2) = redact_ir(&mut sample_ir_with_text(&body), &secrets);
            prop_assert_eq!(seed1, seed2, "init_seed must be stable");
            // 防平凡: secret 必须命中进 map (在全 map 比对前检查, 避免 prop_assert_eq! 消费 map1).
            prop_assert!(map1.mock_for(&secret).is_some(), "secret must be redacted");
            prop_assert_eq!(
                map1, map2,
                "redact_ir must produce identical RedactionMap for identical (ir, secrets)"
            );
        }

        /// 守卫 RED-3: 跨轮次 mock 稳定性 (前缀缓存友好性的核心声明, contracts.md §2, #143).
        ///
        /// 场景: 同一 policy 下客户端会话推进 — round2 IR = round1 历史 messages (原样
        /// 保留 real 原文, 客户端本地历史不回传 mock) + 新增 assistant/user 轮.
        /// 断言 secret 的 mock 跨轮字节不变: 上游看到的历史轮 (已含 round1 mock) 字节
        /// 稳定, LLM Provider 侧 byte-exact 前缀缓存才能跨轮命中.
        ///
        /// 现有 `prop_c3_redact_ir_idempotent` 只测同一 IR 重复调用的确定性, 未覆盖
        /// "IR 内容增长" 这一真实多轮形态 — 本 property 补齐 (与契约 property 同名).
        ///
        /// 生成器 charset 论证 (counter=0 候选必命中, 断言才精确):
        /// secret `[A-Z]{6,20}` → mock charset 推断为纯大写且等长 (见
        /// `mock_length_matches_real_when_no_prefix`), filler 全小写; C5 (RED-5) 保证
        /// mock ≠ secret, 故 mock (全大写) 不可能出现在 IR 文本 (小写 + secret) 中.
        #[test]
        fn prop_same_policy_same_messages_same_mock(
            secret in "[A-Z]{6,20}",
            r1_filler in "[a-z ]{0,40}",
            r2_reply in "[a-z ]{0,40}",
        ) {
            // round1: 单条 user 消息含 real secret.
            let body1 = format!("{r1_filler} key={secret} end");
            let secrets = vec![entry(&secret)];
            let (map1, seed1) = redact_ir(&mut sample_ir_with_text(&body1), &secrets);
            let mock1 = map1
                .mock_for(&secret)
                .expect("round1: secret 在 IR 中, 必须命中")
                .to_string();

            // round2: 历史前缀保留 (real 原文) + 追加 assistant 回复 + 新 user 轮.
            // messages 严格增长, 全部文本不含任何旧 mock (正常路径: 客户端不回传 mock).
            let mut ir2 = sample_ir_with_text(&body1);
            ir2.messages.push(IrMessage {
                role: IrRole::Assistant,
                content: vec![IrBlock::Text {
                    text: format!("ok {r2_reply}"),
                }],
                ..Default::default()
            });
            ir2.messages.push(IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text {
                    text: format!("again {secret} please"),
                }],
                ..Default::default()
            });
            let (map2, seed2) = redact_ir(&mut ir2, &secrets);
            let mock2 = map2
                .mock_for(&secret)
                .expect("round2: secret 仍在 IR 中, 必须命中")
                .to_string();

            prop_assert_eq!(seed1, seed2, "init_seed 只依赖 policy, 不依赖 IR");
            prop_assert_eq!(
                mock2,
                mock1,
                "RED-3: 同一 policy + 历史不含旧 mock 时, IR 前缀增长不得改变 secret 的 mock \
                 (上游前缀缓存从该 message 起的命中依赖此稳定性)"
            );
        }

        /// 守卫 RED-3 (多 secret 变体): 跨轮 mock 稳定性在多 secret 交互下仍成立
        /// (contracts.md §2, #143). 单 secret 版 (上方) 覆盖核心声明, 本变体补真实
        /// 配置形态 — 多 secret 同轮出现时, probing 的 allocated 集合 + 长度倒序
        /// 处理顺序交互下, 全部 mock 跨轮仍字节稳定.
        ///
        /// 稳定性论证 (归纳, 不依赖 counter=0 命中, 故 s1/s2 无需等长): mock 候选均为
        /// 大写字符串, "候选是否在 IR 中" 仅取决于叶子上大写 run 的内容; 历史叶子的大写
        /// run = {s1, s2} (real), 新增轮只引入小写 + 已有 real (不产生新大写 run);
        /// 逐 secret 归纳: 每一步 probing 看到的 IR 大写内容与 round1 完全一致 →
        /// counter 路径一致 → 全部 mock 稳定. (probing 本身会拒绝撞上 IR 的候选,
        /// 包括 mock 恰为另一 secret 的情形, 两侧同轮同拒.)
        #[test]
        fn prop_same_policy_same_messages_same_mock_multi_secret(
            s1 in "[A-Z]{6,20}",
            s2 in "[A-Z]{6,20}",
            r1_filler in "[a-z ]{0,40}",
            r2_reply in "[a-z ]{0,40}",
        ) {
            prop_assume!(s1 != s2, "需要两个不同 secret");
            let secrets = vec![entry(&s1), entry(&s2)];
            let body1 = format!("{r1_filler} {s1} mid {s2} end");
            let (map1, _) = redact_ir(&mut sample_ir_with_text(&body1), &secrets);
            let mock1_s1 = map1
                .mock_for(&s1)
                .expect("round1: s1 在 IR 中, 必须命中")
                .to_string();
            let mock1_s2 = map1
                .mock_for(&s2)
                .expect("round1: s2 在 IR 中, 必须命中")
                .to_string();
            // sanity (RED-4): 两 mock 互异.
            prop_assert_ne!(&mock1_s1, &mock1_s2);

            // round2: 历史保留 + assistant 回复 (纯小写) + 新 user 轮 (real + 小写).
            let mut ir2 = sample_ir_with_text(&body1);
            ir2.messages.push(IrMessage {
                role: IrRole::Assistant,
                content: vec![IrBlock::Text {
                    text: format!("ok {r2_reply}"),
                }],
                ..Default::default()
            });
            ir2.messages.push(IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text {
                    text: format!("use {s1} and {s2} again"),
                }],
                ..Default::default()
            });
            let (map2, _) = redact_ir(&mut ir2, &secrets);
            let mock2_s1 = map2
                .mock_for(&s1)
                .expect("round2: s1 仍在 IR 中, 必须命中")
                .to_string();
            let mock2_s2 = map2
                .mock_for(&s2)
                .expect("round2: s2 仍在 IR 中, 必须命中")
                .to_string();

            prop_assert_eq!(
                mock2_s1, mock1_s1,
                "RED-3 多 secret: s1 的 mock 跨轮必须字节稳定"
            );
            prop_assert_eq!(
                mock2_s2, mock1_s2,
                "RED-3 多 secret: s2 的 mock 跨轮必须字节稳定"
            );
        }

        /// 守卫 RED-3: policy 变动使 init_seed 与全部 mock 失效 (per-request seed 模型的
        /// 已知代价, contracts.md §2, #143). 与契约 property 同名.
        ///
        /// 场景: 向 policy 添加一个不在 IR 中的新 secret — 该 secret 不产生任何替换,
        /// 但 init_seed 是整个 policy 集合的 hash → 已有 secret 的 mock 也随之全部变化
        /// (历史轮字节改变, 前缀缓存整体失效). 这不是 bug 而是模型代价, 本 property 锁定.
        #[test]
        fn prop_policy_change_invalidates_all_mocks(
            s1 in "[A-Z]{6,20}",
            s2 in "[A-Z]{6,20}",
            filler in "[a-z ]{0,40}",
        ) {
            prop_assume!(s1 != s2, "需要两个不同 secret 构成 policy 变动");
            let body = format!("{filler} key={s1} end");
            let (map_a, seed_a) = redact_ir(&mut sample_ir_with_text(&body), &[entry(&s1)]);
            let mock_a = map_a
                .mock_for(&s1)
                .expect("s1 在 IR 中, 必须命中")
                .to_string();
            // policy 变动: 追加 s2 (不在 IR 中, 不产生替换, 只改变 seed).
            let (map_b, seed_b) =
                redact_ir(&mut sample_ir_with_text(&body), &[entry(&s1), entry(&s2)]);

            prop_assert_ne!(
                seed_a, seed_b,
                "policy 集合变化必须改变 init_seed (per-request seed 模型)"
            );
            let mock_b = map_b
                .mock_for(&s1)
                .expect("s1 仍在 IR 中, 必须命中 (未被 redact = secret 泄漏, 须显式失败)")
                .to_string();
            prop_assert_ne!(
                mock_b,
                mock_a,
                "policy 变动后既有 secret 的 mock 必然变化 (前缀缓存整体失效是已知代价)"
            );
        }

        /// 守卫 RED-3 例外裁决 (#143, contracts.md §2 RED-3 "例外场景"):
        /// pre-replace IR 已含该 secret 的旧 mock 时, mock **允许且必然**变化.
        ///
        /// 触发路径 (现实可达): 流式/非流式上游响应 parse 失败 → fallback 透传含 mock 的
        /// 字节 (根 AGENTS.md "已知限制") → 客户端把 mock 回传进历史 → 下一轮 IR 含旧 mock.
        ///
        /// 裁决理由: 若复用旧 mock, restore 会把历史中自然出现的旧 mock 错替成 real,
        /// 破坏 RED-6 round-trip — RED-2 (in-context uniqueness) 保护 restore 正确性
        /// 优先于 RED-3 缓存稳定性. 代价是 token 缓存费用 (经济性), 非 secret 泄漏.
        ///
        /// 不变量 (例外下仍须成立):
        /// 1. mock 必然变化 (旧 mock 在 IR 中 → probing counter 推进; charset 论证同上,
        ///    round1 的 mock1 即 counter=0 候选, round2 该候选撞车 → 必为 counter≥1 候选);
        /// 2. RED-2: 新 mock 不在 pre-replace IR 中;
        /// 3. RED-6: redact→restore round-trip 恒等, 且历史中的旧 mock 不被触碰 (不在本轮 map);
        /// 4. 例外路径本身确定 (同输入同输出, counter 推进是确定性的, 非随机).
        #[test]
        fn prop_mock_changes_when_ir_contains_old_mock_exception(
            secret in "[A-Z]{6,20}",
            extra in "[a-z ]{0,40}",
        ) {
            // round1: 正常路径拿首选 mock (counter=0 候选, charset 论证保证).
            let secrets = vec![entry(&secret)];
            let body1 = format!("key={secret} end");
            let (map1, _) = redact_ir(&mut sample_ir_with_text(&body1), &secrets);
            let mock1 = map1
                .mock_for(&secret)
                .expect("round1: secret 在 IR 中, 必须命中")
                .to_string();

            // round2 (例外场景): 历史文本被污染 (含旧 mock1), 新一轮 user 消息仍含 real.
            let body2 = format!("hist echo {mock1} {extra} new key={secret} end");
            let mut ir2 = sample_ir_with_text(&body2);
            let (map2, _) = redact_ir(&mut ir2, &secrets);
            let mock2 = map2
                .mock_for(&secret)
                .expect("round2: real 仍命中, 必须被 redact")
                .to_string();

            // 不变量 1: mock 必然变化 (例外核心).
            prop_assert_ne!(
                &mock1, &mock2,
                "RED-3 例外: IR 含旧 mock 时, counter 推进使 mock 必然变化"
            );
            // 不变量 2 (RED-2): 新 mock 不在 pre-replace IR 中 (body2 即 redact 前文本).
            prop_assert!(
                !body2.contains(mock2.as_str()),
                "RED-2 仍成立: 新 mock 不得出现在 pre-replace IR"
            );
            // 不变量 3 (RED-6): redact 后 real 已替换, 历史旧 mock 原样保留;
            // replace 回 real 后与 body2 恒等 (charset 论证保证 replace 无错位).
            let text2 = match &ir2.messages[0].content[0] {
                IrBlock::Text { text } => text.clone(),
                _ => panic!("expected Text"),
            };
            prop_assert!(!text2.contains(secret.as_str()), "real 已被替换");
            prop_assert!(
                text2.contains(mock1.as_str()),
                "历史中的旧 mock 不被本轮 redact/restore 触碰 (不在 map 中)"
            );
            prop_assert_eq!(
                &text2.replace(&mock2, &secret),
                &body2,
                "RED-6 round-trip 恒等 (mock1 保留是 round-trip 的一部分)"
            );
            // 不变量 4: 例外路径确定 (同输入必产同 mock2).
            let (map2b, _) = redact_ir(&mut sample_ir_with_text(&body2), &secrets);
            let mock2b = map2b
                .mock_for(&secret)
                .expect("同 round2: secret 在 IR 中, 必须命中")
                .to_string();
            prop_assert_eq!(
                mock2b,
                mock2,
                "例外路径仍确定性 (counter 推进可复现, 非随机)"
            );
        }

        /// 守卫 RED-5: redact_ir 生产路径产出的 mock 不含 real 子串 (端到端 probing 路径).
        /// property 版, 端到端: redact_ir 产出的 mock 不含 real 的任何
        /// ≥k(L) 字符连续子串. 现有 prop_no_real_substring 用 predict_mock (纯函数) 验证,
        /// 但生产路径在 mock 已出现在 IR 时会 probing 到 counter>0 候选, 该路径下的 C5
        /// 行为未被覆盖. 本测试走完整 redact_ir, 覆盖 probing 路径.
        ///
        /// 生成器覆盖度 (PR-D 扩宽, 详见 `arb_secret_for_c5` / `arb_filler_for_c5` 头注释):
        /// secret 维度覆盖 ASCII alphanumeric / JSON 元字符 / CJK+emoji 混合 / 长 secret,
        /// 不再仅是历史 `"[A-Za-z0-9]{4,32}"` 的窄覆盖.
        ///
        /// C5 契约细节 (阈值公式 / 重试链 / 历史边界) 见 `mock.rs` 模块头部 "C5" 段落 (SSOT).
        #[test]
        fn prop_c5_redact_mock_no_real_substring_end_to_end(
            secret in arb_secret_for_c5(),
            filler in arb_filler_for_c5(),
        ) {
            let body = format!("{filler} {secret} {filler}");
            let mut ir = sample_ir_with_text(&body);
            let (map, _) = redact_ir(&mut ir, &[entry(&secret)]);
            let mock = map.mock_for(&secret).expect("secret must be redacted");
            crate::mock::assert_no_c5_substring(mock, &secret);
        }

        /// SEC-2: 任意触发 RedactError 的场景, error 的 Debug 输出 (`{:?}`) 不含 secret 明文.
        ///
        /// 契约 (docs/design/contracts.md §7 SEC-2): RedactError struct 类型系统级保证
        /// 只携带 `secret_id` + `reason` (无 value 字段). 本 property 是防御性第二道闸 —
        /// 即便未来有人误加 value 字段或 debug 实现泄露, property 也会 fail.
        ///
        /// 触发路径: 手动构造 MockCollision (C4 单射性违反的防御性分支). 既有
        /// redaction_map_insert_collision_returns_err_without_leaking_secret 是固定输入
        /// example 测试, 不构成 property.
        ///
        /// 字符集 [A-Z]{4,12}: 纯 ASCII 大写字母, 不含 JSON/Debug 转义字符,
        /// 避免 `contains(secret)` 因 escape 序列假阴性.
        #[test]
        fn prop_redact_error_debug_no_secret_leak(
            secret_a in "[A-Z]{4,12}",
            secret_b in "[A-Z]{4,12}"
        ) {
            prop_assume!(secret_a != secret_b, "需要两个不同 secret 才能触发 collision");
            // 手动构造 C4 单射性违反: 同一 mock 映射到两个不同 real.
            // secret_id 用占位 "id-a" / "id-b" (与生产路径语义一致: 由调用方传入).
            let mut map = RedactionMap::default();
            map.insert(secret_a.clone(), "mock-x".into(), "id-a")
                .expect("首次插入应成功");
            // 第二次插入同一 mock + 不同 real → MockCollision.
            let err = map
                .insert(secret_b.clone(), "mock-x".into(), "id-b")
                .expect_err("collision must return Err (not panic)");
            prop_assert_eq!(err.reason, RedactReason::MockCollision);
            let debug = format!("{:?}", err);
            // 核心: error debug 不得包含任一 secret 的明文.
            prop_assert!(
                !debug.contains(secret_a.as_str()) && !debug.contains(secret_b.as_str()),
                "SEC-2 violation: RedactError Debug leaks secret. debug={}",
                debug
            );
        }

        // ─── 响应侧 RED-6/7 property (C6/C7 响应半边) ───────────────────────
        //
        // 契约 (docs/design/contracts.md §2 RED-6/7): redact 在请求侧, restore 在响应侧.
        // 此前 proptest 只覆盖请求侧 round-trip, 响应侧仅 1 个固定样例
        // (`restore_ir_response_swaps_mock_back_to_real`). 以下 property 补齐响应侧
        // 的可逆性 / 不泄漏 / 工具调用 input / C4 单射性等覆盖盲区.

        /// 守卫 RED-6 响应半边: IrResponse 中含 mock 的 Text, 经 restore_ir_response 后
        /// 必须等价于"含 real secret 的原始 response". 这里直接断言叶子文本相等
        /// (响应侧 round-trip 不经过 reader/writer 重序列化, 无需 normalize_json).
        #[test]
        fn prop_response_round_trip_identity(
            body_prefix in "[a-z0-9 ,.!?'\"\n]{0,80}",
            secret in "[A-Z]{4,12}",
            body_suffix in "[a-z0-9 ,.!?'\"\n]{0,80}",
            tail in "[a-z0-9 ,.!?'\"\n]{0,30}",
        ) {
            let (map, pairs) = redact_secrets_for_response(&[entry(&secret)]);
            prop_assert!(!pairs.is_empty(), "secret 必须被 redact 映射");
            let (real, mock) = &pairs[0];
            // 构造"上游回响": response 文本含 mock (模拟 LLM 看到 redacted request 后原样回传).
            let redacted_text = format!("{body_prefix}{mock}{body_suffix}");
            let mut resp = mock_response_with_text(&format!("{redacted_text}{tail}"));
            let expected = format!("{body_prefix}{real}{body_suffix}{tail}");
            restore_ir_response(&mut resp, &map);
            // 比对唯一 Text 叶子.
            let restored_text = match &resp.content[0] {
                IrBlock::Text { text } => text.clone(),
                _ => panic!("expected Text"),
            };
            prop_assert_eq!(restored_text, expected);
        }

        /// 守卫 RED-6 响应半边 (round-trip 完整性): restore 后的 IrResponse 任何字符串叶子
        /// 不应残留 mock (restore 把 mock 全部替换为 real, 这是 round-trip identity 的必要条件).
        /// 与 C5 (mock 不含 real 子串, request 侧 redact 时的不变量) 无关 — 本 property
        /// 验证的是 restore 行为本身, 而非 mock 生成质量.
        #[test]
        fn prop_response_no_mock_residual_after_restore(
            secret in "[A-Za-z0-9]{4,32}",
            filler in "[a-z0-9 ]{0,60}",
        ) {
            let (map, pairs) = redact_secrets_for_response(&[entry(&secret)]);
            prop_assert!(!pairs.is_empty(), "secret 必须被 redact 映射");
            let (_real, mock) = &pairs[0];
            let redacted_text = format!("{filler} {mock} {filler}");
            let mut resp = mock_response_with_text(&redacted_text);
            restore_ir_response(&mut resp, &map);
            // restore 后, 任何叶子不应再含 mock (mock 已全部被替换为 real).
            let leaves = collect_response_str_leaves(&resp);
            for leaf in &leaves {
                prop_assert!(
                    !leaf.contains(mock.as_str()),
                    "restore 后仍残留 mock='{}' 在叶子 '{}'",
                    mock, leaf
                );
            }
        }

        /// 守卫 RED-6 多 secret 响应半边: 多个 secret 同时出现时, response 的 round-trip
        /// 仍为 identity (多 mock 互不干扰, restore 全部命中).
        #[test]
        fn prop_response_multi_secret_round_trip(
            n in 1usize..=5,
            prefix in "[a-z]{0,20}",
            suffix in "[a-z]{0,20}",
        ) {
            let secrets: Vec<SecretEntry> = (0..n).map(|i| entry(&format!("SECRET_{:03}", i))).collect();
            let (map, pairs) = redact_secrets_for_response(&secrets);
            prop_assert_eq!(pairs.len(), n, "全部 secret 应被映射");
            // 构造含所有 mock 的响应文本 (用分隔符确保 mock 不互相粘连导致 replace 歧义).
            let mocks_joined = pairs
                .iter()
                .map(|(_, m)| m.as_str())
                .collect::<Vec<_>>()
                .join(" /// ");
            let redacted_text = format!("{prefix}{mocks_joined}{suffix}");
            let mut resp = mock_response_with_text(&redacted_text);
            let reals_joined = pairs
                .iter()
                .map(|(r, _)| r.as_str())
                .collect::<Vec<_>>()
                .join(" /// ");
            let expected = format!("{prefix}{reals_joined}{suffix}");
            restore_ir_response(&mut resp, &map);
            let restored_text = match &resp.content[0] {
                IrBlock::Text { text } => text.clone(),
                _ => panic!("expected Text"),
            };
            prop_assert_eq!(restored_text, expected);
        }

        /// 守卫 RED-6 工具调用半边: ToolUse.input 的 JSON 字符串叶子含 mock 时,
        /// restore_ir_response 必须把 mock 还原为 real (AGENTS.md 强调的工具调用场景).
        /// 这是响应侧最关键的 property — LLM 调用工具时会把 redacted request 中的 mock
        /// 复制到 tool input, restore 必须正确还原, 否则本地工具拿不到真 secret.
        #[test]
        fn prop_response_tool_use_input_restored(
            secret in "[A-Z]{4,12}",
            tool_name in "[a-z_]{3,12}",
        ) {
            let (map, pairs) = redact_secrets_for_response(&[entry(&secret)]);
            prop_assert!(!pairs.is_empty(), "secret 必须被 redact 映射");
            let (real, mock) = &pairs[0];
            // 构造含 mock 的 ToolUse 响应 (模拟 LLM 把 mock 复制进 tool input).
            let mut resp = mock_response_with_tool_use("call_1", &tool_name, mock);
            restore_ir_response(&mut resp, &map);
            // 验证 ToolUse.input.token 已还原为 real.
            match &resp.content[0] {
                IrBlock::ToolUse { id, name, input } => {
                    prop_assert_eq!(id, "call_1");
                    prop_assert_eq!(name, &tool_name);
                    let token = input
                        .get("token")
                        .and_then(|v| v.as_str())
                        .expect("input.token 应为 string");
                    prop_assert_eq!(token, real, "ToolUse.input.token 必须 restore 回 real");
                    prop_assert!(
                        !token.contains(mock.as_str()),
                        "restore 后 tool input 不应残留 mock"
                    );
                }
                _ => panic!("expected ToolUse"),
            }
        }

        /// 守卫 RED-4 (C4 单射) 响应半边: 含全部 mock 的响应 restore 后, 每个 mock 都被
        /// 还原为对应的 real (mock↔real 双射成立). 严格断言: 把 restored 文本按与构造时
        /// 相同的分隔符 split, 与预期 real 列表逐位 prop_assert_eq!, 避免弱 `contains` 检查
        /// 在 real 互为子串时的假阳性.
        #[test]
        fn prop_response_mock_never_in_real(
            n in 2usize..=6,
        ) {
            let secrets: Vec<SecretEntry> = (0..n).map(|i| entry(&format!("REAL_{:03}", i))).collect();
            let (map, pairs) = redact_secrets_for_response(&secrets);
            prop_assert_eq!(pairs.len(), n, "全部 secret 应被映射");
            let mocks: HashSet<&String> = pairs.iter().map(|(_, m)| m).collect();
            prop_assert_eq!(mocks.len(), n, "C4 单射违反: 不同 real 映射到相同 mock");
            // 构造含全部 mock 的响应, 用 " | " 分隔 (确保 mock 之间互不粘连).
            let sep = " | ";
            let mocks_text = pairs
                .iter()
                .map(|(_, m)| m.as_str())
                .collect::<Vec<_>>()
                .join(sep);
            let mut resp = mock_response_with_text(&mocks_text);
            restore_ir_response(&mut resp, &map);
            let restored = match &resp.content[0] {
                IrBlock::Text { text } => text.clone(),
                _ => panic!("expected Text"),
            };
            // 严格双射断言: split restored, 与预期 real 列表逐位相等.
            // (弱 contains 检查在 real 互为子串时会假阳性, split 逐位比对才真正验证双射.)
            let expected_reals: Vec<&str> = pairs.iter().map(|(r, _)| r.as_str()).collect();
            let actual: Vec<&str> = restored.split(sep).collect();
            prop_assert_eq!(actual, expected_reals, "restore 后 real 顺序/内容与预期不符");
        }
    } // end proptest! block (C3/C4/C2/C5/SEC-2 + RED-6/7 response-side)

    // ─── SEC-3: tracing log 不输出 secret 明文 ──────────────────────────
    //
    // 契约 (docs/design/contracts.md §7 SEC-3): 任何 tracing log 消息不得包含
    // secret 明文. redact_ir 在探测耗尽 (gen_mock_for_ir 返回 Err) 时降级跳过该
    // secret 并 `warn!(secret_id, reason, ...)`. 该 warn 的字段只用 secret_id +
    // reason, 永不内联 secret value. 本 property 触发该 warn 路径, 捕获 tracing
    // 输出, 断言不含 secret value.
    //
    // 捕获方式: 用 tracing::dispatcher::with_default 安装一个线程局部的 fmt
    // subscriber, 其 MakeWriter 写入 Mutex<Vec<u8>> sink. 不引入新 dev-dependency
    // (tracing + tracing-subscriber 已在 Cargo.toml).

    /// 可观察的 MakeWriter: 把所有 tracing 事件 fmt 输出收集到共享的 Mutex<Vec<u8>>.
    ///
    /// 设计: 用 Arc<Mutex<Vec<u8>>> 作为 sink, MakeWriter clone Arc 后返回 Writer
    /// (持有 Arc 的 clone + 写入 sink). fmt layer 会对每个事件调用 make_writer.
    struct CapturingMakeWriter {
        sink: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingMakeWriter {
        type Writer = CapturingWriter;
        fn make_writer(&'a self) -> Self::Writer {
            CapturingWriter {
                sink: self.sink.clone(),
            }
        }
    }

    struct CapturingWriter {
        sink: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl std::io::Write for CapturingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.sink.lock().expect("sink poisoned").write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// 触发探测耗尽路径 (redact_ir 发出 warn), 捕获 tracing 输出.
    ///
    /// 弱配置 (Auto + digits-only + length_range=(1,1)) 仅产生 10 个候选 ("0".."9"),
    /// 当 IR 已含全部 10 个候选时 gen_mock_for_ir 必然耗尽 → warn! 路径.
    ///
    /// **时间戳关闭 (SEC-3 测试正确性根基)**: 默认 fmt subscriber 会在每行注入 RFC3339
    /// 时间戳 (含 6 位微秒数字 run, 如 `...373719Z`). 这与纯数字 secret 生成器
    /// `[0-9]{6,24}` 冲突 — 当 6 位 secret 恰好等于当前微秒值时, `log.contains(secret)`
    /// 假阳性 fail. 用 `.with_timer(())` 关闭时间戳注入, 使捕获的 log 不含任何数字 run,
    /// 让本测试只断言我们控制的字段 (secret_id / reason) 而非 wall-clock 噪声.
    fn captured_log_with_exhausted_secret(secret: &str) -> String {
        let weak_entry = exhausted_secret_entry(secret);

        // IR 含全部 10 个数字候选 → gen_mock_for_ir 必然耗尽.
        let ir_text = format!("{EXHAUSTING_IR_TEXT_TEMPLATE}{secret}");
        let mut ir = sample_ir_with_text(&ir_text);

        // 共享 sink: subscriber 写入, 测试读取.
        let sink: std::sync::Arc<std::sync::Mutex<Vec<u8>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        // with_default 设置线程局部 dispatcher, 闭包内的 redact_ir 发出的 warn 被
        // 我们的 capturing subscriber 捕获 (与全局 subscriber 隔离, 不污染其他测试).
        // with_timer(()) 关闭默认时间戳 (见函数级注释).
        tracing::dispatcher::with_default(
            &tracing::dispatcher::Dispatch::new(
                tracing_subscriber::fmt()
                    .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
                    .with_writer(CapturingMakeWriter { sink: sink.clone() })
                    .with_timer(())
                    .with_ansi(false)
                    .finish(),
            ),
            || {
                let _ = redact_ir(&mut ir, std::slice::from_ref(&weak_entry));
            },
        );
        let buf = sink.lock().expect("sink poisoned").clone();
        String::from_utf8(buf).expect("captured tracing output must be valid UTF-8")
    }

    proptest! {
        /// SEC-3: 探测耗尽路径触发的 tracing warn 输出不含 secret value.
        ///
        /// 字符集 `[a-zA-Z0-9_\-]{6,40}`: 覆盖真实 secret 形态 (sk-abc / ghp_xxx /
        /// 混合大小写). 时间戳已由 `captured_log_with_exhausted_secret` 内的
        /// `.with_timer(())` 关闭, 故 log 中无 wall-clock 数字 run; warn 消息字段
        /// (secret_id "weak-secret" + reason + 固定句式) 不含随机长字符串,
        /// 英文单词子串假阳性概率可忽略. 若引入会内联随机值的 warn 字段, 需重评估.
        #[test]
        fn prop_log_messages_no_secret(secret in "[a-zA-Z0-9_\\-]{6,40}") {
            let log = captured_log_with_exhausted_secret(&secret);
            // sanity: warn 必须实际触发 (log 非空), 否则本 property 退化为空洞断言.
            // 探测耗尽路径已由 ir_text 含全部 10 个数字候选保证触发, log 应含 warn 行.
            prop_assert!(
                !log.is_empty(),
                "sanity: warn must fire (probing exhausted path); empty log means path not hit. \
                 this would make the SEC-3 property vacuously true."
            );
            // 核心: 即便 warn 触发 (log 非空), 也不得包含 secret 明文.
            // warn 字段只有 secret_id ("weak-secret") + reason, 永不内联 value.
            prop_assert!(
                !log.contains(secret.as_str()),
                "SEC-3 violation: tracing log leaks secret. log={}",
                log
            );
        }
    }
}

// ─── count_hit_locations (USAGE-7 位置统计) ────────────────────────────────

#[cfg(test)]
mod hit_location_tests {
    use super::*;
    use crate::codec::ir::{IrBlock, IrMessage, IrRole, IrTool};

    fn msg(role: IrRole, text: &str, user_text: bool) -> IrMessage {
        IrMessage {
            role,
            content: vec![IrBlock::Text {
                text: text.to_string(),
            }],
            contains_user_text: user_text,
            ..Default::default()
        }
    }

    #[test]
    fn hit_locations_classifies_system_tools_user_history_other() {
        let needle = "sk-secret";
        let ir = IrRequest {
            system: vec![IrBlock::Text {
                text: format!("preamble {needle} here"),
            }],
            messages: vec![
                msg(IrRole::User, &format!("user pasted {needle}"), true),
                msg(
                    IrRole::Assistant,
                    &format!("assistant echoed {needle} {needle}"),
                    false,
                ),
                msg(IrRole::User, "tool result echoes sk-secret", false),
            ],
            tools: vec![IrTool {
                name: format!("tool_{needle}"),
                description: None,
                input_schema: serde_json::Value::Null,
            }],
            stop: vec![format!("stop-{needle}")],
            ..Default::default()
        };
        let h = count_hit_locations(&ir, needle);
        assert_eq!(h.system, 1);
        assert_eq!(h.tools, 1);
        assert_eq!(h.user, 1);
        // assistant 2 次 + tool_result 借 user 角色承载 1 次 (contains_user_text=false → history).
        assert_eq!(h.history, 3);
        assert_eq!(h.other, 1, "stop 序列入 other");
        assert_eq!(h.non_zero().count(), 5);
    }

    #[test]
    fn hit_locations_matches_actual_replacement_total() {
        // 一致性: map.hits 的分类总和 == replace 前的 needle 总出现数
        // (统计与替换遍历覆盖同一叶子集, StringLeafOps 单一实现保证).
        let needle = "sk-xyz";
        let mut ir = sample_ir_with_text(&format!("a {needle} b {needle} c"));
        let (map, _) = redact_ir(&mut ir, &[secret_entry("sid", needle)]);
        let total: u64 = map
            .hits
            .values()
            .map(|h| h.system + h.tools + h.user + h.history + h.other)
            .sum();
        assert_eq!(total, 2, "两处命中都计入位置统计");
        // sample_ir_with_text 的 fixture 未设 contains_user_text (Default false)
        // → 该位置的命中归 history; user/history 的分类判定由上方显式 fixture 测试覆盖.
        assert!(map.hits.values().all(|h| h.history == 2));
    }

    fn secret_entry(id: &str, value: &str) -> crate::secrets::SecretEntry {
        let mut e = crate::secrets::SecretEntry {
            id: id.to_string(),
            name: None,
            category: crate::secrets::SecretCategory::ApiKey,
            value: value.to_string(),
            value_file: None,
            mock_strategy: crate::mock::MockStrategy::default(),
        };
        e.mock_strategy.resolve_against(&e.value, "");
        e
    }
}
