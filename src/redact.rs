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
//!   **权衡**: policy 变动 (添加/删除/编辑任一 secret) 会改变 init_seed → 所有 secret 的
//!   mock 全部变化 → 整个会话的前缀缓存失效. 这是 per-request seed 模型 (vs 旧 per-secret
//!   seed) 的代价, 换取了 lazy redact 重建的极简 (node 只存单标量 seed). secret 编辑是
//!   罕见操作, 不在多轮对话热路径上, 实际影响可忽略.
//! - **C4 单射性**: 在一次 [`redact_ir`] 调用内, 不同 secret 总映射到不同 mock
//!   (因为每次 gen_mock_for_ir 都检查 allocated 集合). 极端弱配置下探测可能耗尽,
//!   此时 [`redact_ir`] **跳过该 secret** (原样发往上游) 而非 panic, 优先保进程存活.
//!   [`RedactionMap::insert`] 的 C4 违反 (defense-in-depth) 同样降级跳过, 永不 panic.
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

use crate::codec::ir::{IrBlock, IrDelta, IrRequest, IrResponse, IrTool};
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
}

impl RedactionMap {
    pub fn is_empty(&self) -> bool {
        self.real_to_mock.is_empty()
    }

    /// 插入映射. 若 mock 已映射到**不同** real (C4 单射性违反), 返回 `RedactError`
    /// (defense-in-depth; C4 保证正常路径不会触发).
    ///
    /// **安全**: `RedactError` 只携带 `reason` (不含 mock 值也不含 real 明文).
    /// 旧实现用 `assert!` 把 `{existing:?}` 与 `{real:?}` (真实 secret 明文) 写入 panic
    /// 消息, 既是 DoS 面又是泄密面.
    pub fn insert(&mut self, real: String, mock: String) -> Result<(), RedactError> {
        if let Some(existing) = self.mock_to_real.get(&mock)
            && existing != &real
        {
            return Err(RedactError {
                secret_id: String::new(),
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
fn gen_mock_for_ir(
    ir: &IrRequest,
    secret: &SecretEntry,
    seed: u64,
    allocated: &HashSet<String>,
) -> Result<String, RedactError> {
    let mut counter: u32 = 0;
    loop {
        let candidate = candidate_for(secret, seed, counter);
        if !ir_request_contains(ir, &candidate) && !allocated.contains(&candidate) {
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
pub fn redact_ir(ir: &mut IrRequest, secrets: &[SecretEntry]) -> (RedactionMap, u64) {
    let mut map = RedactionMap::default();
    if secrets.is_empty() {
        return (map, 0);
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
        match gen_mock_for_ir(ir, secret, seed, &allocated) {
            Ok(mock) => {
                // 先 insert 到 map (防御性 C4 检查); 成功后再改写 IR + allocated,
                // 确保 map 与 IR 状态一致 (避免改写了 IR 但 map 缺失映射, 导致 restore 失败).
                match map.insert(secret.value.clone(), mock.clone()) {
                    Ok(()) => {
                        ir_request_replace_all(ir, &secret.value, &mock);
                        allocated.insert(mock);
                    }
                    Err(e) => {
                        // insert 的 collision 在防御性检查中触发时, 同样降级跳过 (不 panic).
                        // 不改写 IR: secret 原样发往上游 (与探测耗尽的降级语义一致).
                        warn!(
                            secret_id = %e.secret_id,
                            reason = ?e.reason,
                            "redact insert failed; skipping this secret (forwarded unredacted)"
                        );
                    }
                }
            }
            Err(e) => {
                // 探测耗尽: 弱配置 (eg charset/length 仅产生极少候选) + 对抗性 IR.
                // 降级: 跳过该 secret (原样发往上游), 不替换. 优于崩溃整个进程.
                // 安全: 只记 secret id 与 reason, 永不记 secret value.
                warn!(
                    secret_id = %e.secret_id,
                    reason = ?e.reason,
                    "mock probing exhausted; skipping this secret (forwarded unredacted). \
                     consider widening charset or length_range for this secret"
                );
            }
        }
    }

    let final_seed = if hit_any { seed } else { 0 };
    (map, final_seed)
}

/// 在 [`IrResponse`] 中反向替换 mock 为真实 secret.
///
/// 非流式响应的 restore 路径. 遍历结构由 [`StringLeafOps for IrResponse`] 提供,
/// 与 `ir_request_contains` / `ir_request_replace_all` 自动对齐 (新增 IrBlock variant 只改一处).
pub fn restore_ir_response(ir: &mut IrResponse, map: &RedactionMap) {
    if map.is_empty() {
        return;
    }
    ir.for_each_str_leaf_mut(&mut |s| restore_str(s, map));
}

// ─── StreamingRestorer: sliding window restore ──────────────────────────────

/// Block delta 类型标识, 让 [`StreamingRestorer`] 在 flush 时能恢复正确的 IrDelta variant.
///
/// 一个 block 的生命周期内 (BlockStart .. BlockStop) delta 类型固定不变,
/// restorer 每次 push 都更新 last_kind, flush 时按 last_kind 包装返回.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaKind {
    Text,
    InputJson,
}

impl DeltaKind {
    pub fn to_ir_delta(self, s: String) -> IrDelta {
        match self {
            DeltaKind::Text => IrDelta::TextDelta(s),
            DeltaKind::InputJson => IrDelta::InputJsonDelta(s),
        }
    }
}

/// Sliding-window mock→real restorer for streaming [`IrStreamEvent`]s.
///
/// # 为什么需要 sliding window
///
/// 流式响应里 mock (如 `MOCKABC123`) 可能跨多个 chunk:
/// ```text
/// event 1 TextDelta: "the secret is MOCKAB"
/// event 2 TextDelta: "C123 end"
/// ```
/// 单 event 不含完整 mock, 直接 [`restore_str_inplace`] 找不到匹配.
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
/// - `max_mock_len` 在构造时锁定 (proxy.rs 保证 redact snapshot 期间 RedactionMap 不变).
/// - 一个 restorer 对应单个 block index, 期间 delta kind 不变 (text 或 input_json 二选一).
///
/// # Scope / Out of scope
///
/// - 处理 [`IrDelta::TextDelta`] 和 [`IrDelta::InputJsonDelta`] (内容字节流).
/// - 不处理 [`IrStreamEvent::MessageDelta::stop_sequence`] / [`IrStreamEvent::Error`]
///   (单 event 完整, 直接 [`restore_str_inplace`]).
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
trait StringLeafOps {
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

/// IR 中是否出现 needle (在字符串字段中).
///
/// 扫描范围: system blocks / messages.blocks / tools (name+description+input_schema) /
/// IrBlock::ToolUse.{id, name, input} / IrBlock::ToolResult.content (递归) /
/// stop sequences / user / extra (JSON 字符串叶子).
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
        use crate::mock::{Charset, GenSpec, InitialValue, MockStrategy};

        let weak_strategy = MockStrategy {
            initial: InitialValue::Auto,
            gen_spec: Some(GenSpec {
                prefix: String::new(),
                charset: Charset {
                    digits: true,
                    lowercase: false,
                    uppercase: false,
                    underscore: false,
                    hyphen: false,
                    other: vec![],
                },
                length_range: (1, 1), // 仅 10 个可能值
            }),
        };
        let real_secret = "super-secret-value-DO-NOT-LEAK";
        let mut weak_entry = SecretEntry {
            id: "weak-secret".into(),
            name: None,
            category: SecretCategory::ApiKey,
            value: real_secret.into(),
            value_file: None,
            mock_strategy: weak_strategy,
        };
        weak_entry.mock_strategy.resolve_against(real_secret, "");

        // IR 含全部 10 个数字候选 → gen_mock_for_ir 必然耗尽.
        let ir_text = "0 1 2 3 4 5 6 7 8 9 also contains super-secret-value-DO-NOT-LEAK";
        let mut ir = sample_ir_with_text(ir_text);
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
        map.insert(real_a.to_string(), same_mock.to_string())
            .unwrap();
        let err = map
            .insert(real_b.to_string(), same_mock.to_string())
            .expect_err("collision must return Err");
        // Err 的 Debug / Display 不得含任一 real secret 明文.
        let err_dbg = format!("{err:?}");
        assert!(!err_dbg.contains(real_a), "Err leaks real_a: {err_dbg}");
        assert!(!err_dbg.contains(real_b), "Err leaks real_b: {err_dbg}");
        assert_eq!(err.reason, RedactReason::MockCollision);
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
        map.insert("sk-real-secret".to_string(), "MOCKABCDEF12345".to_string())
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
        m.insert(real.to_string(), mock.to_string()).unwrap();
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
        map.insert("r1".to_string(), "MOCK11111111111".to_string())
            .unwrap();
        map.insert("r2".to_string(), "MOCK22222222222".to_string())
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

    proptest! {
        /// C3 + C4: 不同 secret 总产生不同 mock.
        #[test]
        fn prop_distinct_secrets_distinct_mocks(
            s1 in "[a-z]{4,12}",
            s2 in "[a-z]{4,12}"
        ) {
            prop_assume!(s1 != s2);
            // 在同一个空 IR 上, 两个 secret 应映射到不同 mock.
            let mut ir = sample_ir_with_text(&format!("{s1} {s2}"));
            let (map, _) = redact_ir(&mut ir, &[entry(&s1), entry(&s2)]);
            let m1 = map.mock_for(&s1).unwrap();
            let m2 = map.mock_for(&s2).unwrap();
            prop_assert!(m1 != m2, "mocks for distinct secrets collided: {} == {}", m1, m2);
        }

        /// C2: mock 不在 IR 中 (redact 后的 IR 不含 mock 作为子串 — wait, 它含, 因为替换进去了).
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

        /// C6: round-trip 是 identity (redact + restore).
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

        /// C1: mock 非空. 字符集由 infer 自 real (此处含字母数字与连字符).
        #[test]
        fn prop_mock_non_empty(
            secret in "[A-Za-z0-9-]{4,20}"
        ) {
            let m = predict_mock(&secret);
            prop_assert!(!m.is_empty());
        }

        /// C5: mock 不含 real_secret 的 ≥k(L) 字符子串 (阈值随 L 自适应, 见
        /// [`crate::mock::c5_threshold_len`]). C5 契约与重试链的设计论据见
        /// `mock.rs` 模块头部 "C5" 段落 (SSOT).
        #[test]
        fn prop_no_real_substring(
            secret in "[A-Za-z0-9]{4,32}"
        ) {
            let m = predict_mock(&secret);
            crate::mock::assert_no_c5_substring(&m, &secret);
        }

        /// C5 multibyte: secret 含中文 / emoji / 多字节 UTF-8. 与 `prop_no_real_substring`
        /// 同语义, 补 multibyte 输入覆盖 (char-level windows 在 helper 内统一处理).
        #[test]
        fn prop_no_real_substring_multibyte(
            secret in "[\\x{4e00}-\\x{9fff}\\x{1f300}-\\x{1f6ff}a-zA-Z0-9]{4,32}"
        ) {
            let m = predict_mock(&secret);
            crate::mock::assert_no_c5_substring(&m, &secret);
        }

        /// C6 多 secret round-trip: N 个 secret 同时出现在 IR, restore 后严格等于原 IR.
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

        /// C6 同一 secret 多次出现: round-trip 仍为 identity.
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

        /// C4 加强版: N 个不同 secret → N 个不同 mock.
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

        /// StreamingRestorer 核心 contract: 把含 mock 的文本切成任意 chunk_size, 拼接
        /// emit + flush 必须严格等于 (prefix + real + suffix).
        #[test]
        fn prop_streaming_restorer_round_trip(
            prefix in "[a-z ]{0,50}",
            suffix in "[a-z ]{0,50}",
            chunk_size in 1usize..30,
        ) {
            let real = "SECRETVALUE";
            let mock = "MOCKABCDEFGHIJK"; // 15 字节, 与 real 等价映射
            let mut map = RedactionMap::default();
            map.insert(real.to_string(), mock.to_string()).unwrap();

            let full = format!("{prefix}{mock}{suffix}");
            let mut r = StreamingRestorer::new(map);
            let emitted = push_chunked(&mut r, &full, chunk_size, false);

            let expected = format!("{prefix}{real}{suffix}");
            prop_assert_eq!(emitted, expected);
        }

        /// UTF-8 safety: 多字节字符 (中文 / emoji) 不应在 char boundary 中间被切.
        /// mock 仍是 ASCII, 但 prefix/suffix 含多字节 UTF-8.
        #[test]
        fn prop_streaming_restorer_round_trip_utf8(
            prefix in "[\\x{4e00}-\\x{9fff}]{0,30}",  // 中文
            suffix in "[\\x{4e00}-\\x{9fff}]{0,30}",
            chunk_size in 1usize..=50,
        ) {
            let real = "SECRETVALUE";
            let mock = "MOCKABCDEFGHIJK";
            let mut map = RedactionMap::default();
            map.insert(real.to_string(), mock.to_string()).unwrap();

            let full = format!("{prefix}{mock}{suffix}");
            let mut r = StreamingRestorer::new(map);
            let emitted = push_chunked(&mut r, &full, chunk_size, true);

            let expected = format!("{prefix}{real}{suffix}");
            prop_assert_eq!(emitted, expected);
        }

        /// Multi-mock 场景: 多个 mock 同时出现在 content 中, 任意 chunk 切分下都正确 round-trip.
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
            map.insert(real1.to_string(), mock1.to_string()).unwrap();
            map.insert(real2.to_string(), mock2.to_string()).unwrap();

            // full 含两个 mock + filler (可能相邻 / 嵌套 / 被 filler 分隔).
            let full = format!("{filler}{mock1}{filler}{mock2}{filler}");
            let mut r = StreamingRestorer::new(map);
            let emitted = push_chunked(&mut r, &full, chunk_size, false);

            let expected = format!("{filler}{real1}{filler}{real2}{filler}");
            prop_assert_eq!(emitted, expected);
        }

        /// C3 端到端幂等性 (property 版): 对任意 (prefix, suffix, secret) 组合,
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

        /// C5 生产路径 (property 版, 端到端): redact_ir 产出的 mock 不含 real 的任何
        /// ≥k(L) 字符连续子串. 现有 prop_no_real_substring 用 predict_mock (纯函数) 验证,
        /// 但生产路径在 mock 已出现在 IR 时会 probing 到 counter>0 候选, 该路径下的 C5
        /// 行为未被覆盖. 本测试走完整 redact_ir, 覆盖 probing 路径.
        ///
        /// C5 契约细节 (阈值公式 / 重试链 / 历史边界) 见 `mock.rs` 模块头部 "C5" 段落 (SSOT).
        #[test]
        fn prop_c5_redact_mock_no_real_substring_end_to_end(
            secret in "[A-Za-z0-9]{4,32}",
            filler in "[a-z0-9 ]{0,40}",
        ) {
            let body = format!("{filler} {secret} {filler}");
            let mut ir = sample_ir_with_text(&body);
            let (map, _) = redact_ir(&mut ir, &[entry(&secret)]);
            let mock = map.mock_for(&secret).expect("secret must be redacted");
            crate::mock::assert_no_c5_substring(mock, &secret);
        }
    }
}
