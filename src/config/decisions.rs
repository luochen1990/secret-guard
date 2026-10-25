//! Per-id override decisions — 双层配置的合并判据子系统.
//!
//! 从 `config/mod.rs` 拆出 (2026-10-19, file-size 门禁 1600 行驱动; 内容零变更).
//! 三位一体: [`OverrideMode`] (判据枚举) + [`Decisions`] (state.toml `[decisions]`
//! 段的存储容器, provider/secret 两子表) + [`prune_dangling_decisions`] (启动时
//! 悬空清理, 契约 CFG-6). 经 `config` 模块 re-export, 既有 `crate::config::*`
//! 路径不变.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// 对 static id 的 per-item 决策. 仅对 static 中已存在的 id 生效.
///
/// 序列化为 snake_case 字符串 (`default`/`prefer_static`/`disabled`), 便于在 TOML / JSON 中读写.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideMode {
    /// 默认: 若 dynamic 有同 id override 则用 dynamic, 否则用 static.
    #[default]
    Default,
    /// 强制使用 static 原值, 忽略可能存在的 dynamic override.
    PreferStatic,
    /// 完全禁用: 从 effective view 中排除 (既不用 static 也不用 dynamic).
    Disabled,
}

impl OverrideMode {
    /// 所有变体及其字符串名 — 派生自 `as_str()` (const fn match 是字符串单源;
    /// serde rename 同步由 roundtrip 测试守卫). 定长数组不随新增 variant 自动扩 —
    /// ALL 漏项无自动守卫, 需人工随新增 variant 同步.
    pub const ALL: [(Self, &'static str); 3] = [
        (Self::Default, Self::Default.as_str()),
        (Self::PreferStatic, Self::PreferStatic.as_str()),
        (Self::Disabled, Self::Disabled.as_str()),
    ];

    pub const fn as_str(self) -> &'static str {
        // 穷尽 match: 新增 variant 编译期引导补齐 (本 match 是字符串单源, ALL 派生自它).
        match self {
            Self::Default => "default",
            Self::PreferStatic => "prefer_static",
            Self::Disabled => "disabled",
        }
    }

    /// 按 name 解析 mode. 命名为 `parse` 而非 `from_str`, 避免与 `std::str::FromStr` 冲突.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|(_, n)| *n == s).map(|(m, _)| m)
    }
}

/// `Decisions` 的存储容器: 两张独立的 id→mode 表 (provider / secret).
///
/// 序列化为 TOML 时形如:
///
/// ```toml
/// [decisions.providers]
/// "openai-main" = "disabled"
///
/// [decisions.secrets]
/// "pwd" = "prefer_static"
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decisions {
    #[serde(default)]
    pub providers: HashMap<String, OverrideMode>,
    #[serde(default)]
    pub secrets: HashMap<String, OverrideMode>,
}

impl Decisions {
    /// 读取 provider id 的决策 (默认 `Default`).
    pub fn provider(&self, id: &str) -> OverrideMode {
        self.providers.get(id).copied().unwrap_or_default()
    }

    /// 读取 secret id 的决策 (默认 `Default`).
    pub fn secret(&self, id: &str) -> OverrideMode {
        self.secrets.get(id).copied().unwrap_or_default()
    }

    /// 设置 provider id 的决策. 若 mode == Default 则移除条目 (保持文件精简).
    pub fn set_provider(&mut self, id: &str, mode: OverrideMode) {
        match mode {
            OverrideMode::Default => {
                self.providers.remove(id);
            }
            other => {
                self.providers.insert(id.to_string(), other);
            }
        }
    }

    /// 设置 secret id 的决策.
    pub fn set_secret(&mut self, id: &str, mode: OverrideMode) {
        match mode {
            OverrideMode::Default => {
                self.secrets.remove(id);
            }
            other => {
                self.secrets.insert(id.to_string(), other);
            }
        }
    }
}

/// 清理悬空 decision: 不在对应 static 层的 id (契约 CFG-6).
///
/// 背景: static config 删除/重命名某 id 后, state.toml 的 `[decisions]` 段仍残留该
/// id 的 mode。若同 id 日后重新进入 static (临时下线再恢复是常见运维路径), 会
/// **静默**继承旧 decision (如 disabled → 条目从 WebUI 消失且无任何提示)。
/// 启动时调用本函数清除悬空条目, 保证 "decision 只作用于当前 static 层存在的 id"。
///
/// 纯函数 (不碰文件/锁): 持久化与 WARN 由调用方 (server.rs 装配层) 收口 —
/// Decisions 跨 provider/secret 两子表, 只有装配层能同时看到两张表的 static ids。
///
/// 返回被清理的 `("provider"|"secret", id)` 列表; 空列表 = 无悬空 (调用方免写盘)。
pub fn prune_dangling_decisions(
    d: &mut Decisions,
    static_provider_ids: &std::collections::HashSet<String>,
    static_secret_ids: &std::collections::HashSet<String>,
) -> Vec<(&'static str, String)> {
    let mut pruned = Vec::new();
    d.providers.retain(|id, _| {
        let keep = static_provider_ids.contains(id);
        if !keep {
            pruned.push(("provider", id.clone()));
        }
        keep
    });
    d.secrets.retain(|id, _| {
        let keep = static_secret_ids.contains(id);
        if !keep {
            pruned.push(("secret", id.clone()));
        }
        keep
    });
    pruned
}
