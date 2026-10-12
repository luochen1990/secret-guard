/// Playwright 配置: 内置管理 mock upstream + secret-guard 生命周期.
///
/// webServer 配置让 Playwright 在测试前自动启动两个进程 (mock + sg),
/// 测试结束后自动清理, 无需外部脚本.
///
/// 运行方式:
///   nix develop --impure        # 进入 devShell (shellHook 自动 symlink playwright 到 node_modules)
///   just check-webui            # 跑 WebUI 回归测试
///
/// 或直接调用 (在 tests/webui/ 目录, devShell 内):
///   playwright test             # headless
///   playwright test --headed    # 调试
///   playwright show-report      # 看报告
import { defineConfig } from "@playwright/test";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import { TEST_SECRET_VALUE } from "./fixtures";

// Playwright 加载 config 时 cwd = config 所在目录 (tests/webui).
// 不用 import.meta.url (在 CJS 模式下不可用, 在 ESM 模式下又要求 package.json type:module).
const ROOT = path.resolve(process.cwd(), "..", ".."); // 项目根 (tests/webui 的上两级).
const MOCK_PORT = 19999;
const SG_PORT = 18790;
const SG_URL = `http://127.0.0.1:${SG_PORT}/`;
// secret-guard 二进制检索: 候选 = target 下三个常见产物位, **存在者中选 mtime 最新**.
//   - release: 非插桩、最快, WebUI server 响应最稳 (本地 cargo build --release).
//   - debug:   本地开发常态 (cargo build / nextest run).
//   - llvm-cov-target/debug: CI 兜底 — `just check --coverage` 走 cargo llvm-cov nextest,
//     产物只落此子目录.
// 选择策略是 "mtime 最新" 而非固定优先序 (#314 review 发现): P0/P2 CI 共享持久卷
// CARGO_TARGET_DIR, P0 的 nextest 会在卷内留下 debug/ 产物 — 固定序 (release >
// debug > llvm-cov) 下 P2 nightly 会压过自己刚编译的 llvm-cov 插桩产物, WebUI 打在
// 旧代码上 (改动前就存在的潜伏缺陷, freshness 门卫只是把它显性化为误拦). "选最新"
// 让 P2 天然命中本档产物, 本地也命中最近编译的那个 — 与下方 freshness 门卫语义配套
// (哪个新鲜测哪个). CARGO_TARGET_DIR: CI 用持久卷
// (/var/lib/forgejo-runner/cache/cargo-target), 本地默认 target/.
const CARGO_TARGET_DIR = process.env.CARGO_TARGET_DIR || path.join(ROOT, "target");

/**
 * 返回 mtime 最新的存在候选; 都不存在则抛错列出所有候选.
 * statSync+try 一体 (非 existsSync 预检): 消除 "存在性检查后、stat 前候选消失" 的
 * TOCTOU 裸栈, 消失的候选按不存在处理.
 */
function resolveSgBin(): string {
  const candidates = [
    path.join(CARGO_TARGET_DIR, "release", "secret-guard"),
    path.join(CARGO_TARGET_DIR, "debug", "secret-guard"),
    path.join(CARGO_TARGET_DIR, "llvm-cov-target", "debug", "secret-guard"),
  ];
  const found: { path: string; mtime: number }[] = [];
  for (const p of candidates) {
    // { throwIfNoEntry: false } 不抛 ENOENT, 返回 undefined.
    const st = fs.statSync(p, { throwIfNoEntry: false });
    if (st) found.push({ path: p, mtime: st.mtimeMs });
  }
  if (found.length === 0) {
    throw new Error(
      `secret-guard binary not found in any candidate:\n${candidates.map((p) => `  - ${p}`).join("\n")}\n` +
        `Run 'cargo build' or 'cargo llvm-cov nextest' first.`
    );
  }
  // mtime 相等时保留先者 (= release, 非插桩) — 同新鲜度下偏向更接近生产的产物.
  return found.reduce((a, b) => (b.mtime > a.mtime ? b : a)).path;
}

const SG_BIN = resolveSgBin();
const BIN_MTIME = fs.statSync(SG_BIN).mtimeMs;
// 打印命中路径 + mtime 到 stderr, 让 CI log 直接可见命中了哪个候选、产物多新.
// 动机: WebUI step 的 continue-on-error 会静默吞错, 若解析到非预期产物 (如陈旧 binary)
// 未来复现, 维护者翻 CI log 第一行即可定位, 而非反推. console.error 走 stderr,
// Playwright 不解析 config 加载期的输出, 无副作用.
console.error(`[playwright.config] secret-guard binary: ${SG_BIN} (mtime ${new Date(BIN_MTIME).toISOString()})`);

// ─── freshness 门卫 (#314): 被测 binary 必须不旧于源输入 ──────────────────────
//
// 问题 (事故: PR #311 冲突解决时 14 个假阳性失败): spec 文件从工作区直接读
// (永远最新), 被测服务却是 target/ 里的陈旧 binary (rebase / 改 src 后未重编)
// → 新测试打旧服务 → 大面积假阳性, 且无任何"binary 过旧"提示.
//
// 判定: binary mtime < freshness 输入集的 max mtime → throw fail-fast.
// 输入集 = 一切影响 Rust binary 内容的源输入:
//   - src/ 全树 (含 include_str! 内嵌进 binary 的 src/web/index.html —
//     改前端也必须重编 Rust 才生效, 事故盲点之一)
//   - Cargo.toml / Cargo.lock / rust-toolchain.toml (依赖与工具链变更)
// 保守方向 (只多拦不漏拦): "binary 早于某输入" ⇔ 该输入的修改未进入 binary,
// 测试结果必然无意义; 故 walk 不筛后缀 (简单且同方向), 与降级偏安全
// (contracts.md SEC-10) 同构 — 宁可多编, 不可假阳性.
//
// 声明的盲区 (可接受近似, 维护者无需处理):
//   - `touch -t` 手动回拨 mtime (自找的场景)
//   - toolchain 同版本号内容变更 (nixpkgs 滚动更新, mtime 不变)
//   - walk 中消失的文件 (编辑器原子 rename 的 TOCTOU 窗口) 被 try/catch 跳过 —
//     已删除的文件不可能影响 binary 内容, 跳过安全; broken symlink 同理
//
// CI (P2 ci-periodic) 零成本: checkout (输入 mtime=t₀) → coverage 编译
// (llvm-cov 产物 mtime=t₁>t₀, 且按"选最新"策略必命中) → just check-webui →
// 门卫比较 t₁>t₀ 通过, 不触发任何额外编译.
//
// 拦截路径的行为钉子: `just check-webui-freshness` (justfile, 挂 check 链,
// 用假 binary + 隔离 CARGO_TARGET_DIR 构造场景, 秒级).
const FRESHNESS_INPUTS = ["src", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"];

/**
 * 返回 freshness 输入集中 mtime 最新的文件; 输入全缺失 (仓库结构变更?) 时抛错 fail-closed.
 * statSync 统一判型 (follow symlink — 正常 symlink 的目标 mtime 被采集, 保守方向);
 * walk 中消失的文件 (TOCTOU) 静默跳过, 理由见盲区声明.
 */
function newestFreshnessInput(): { file: string; mtime: number } {
  let best: { file: string; mtime: number } | null = null;
  const consider = (p: string, mtime: number) => {
    if (best === null || mtime > best.mtime) best = { file: p, mtime };
  };
  const walk = (p: string) => {
    try {
      const st = fs.statSync(p); // follow symlink; 消失 (TOCTOU/broken) → catch 跳过
      if (st.isDirectory()) {
        for (const ent of fs.readdirSync(p)) walk(path.join(p, ent));
      } else {
        consider(p, st.mtimeMs);
      }
    } catch {
      return; // 消失的文件/目录 (TOCTOU) — 已删除者不可能影响 binary 内容, 跳过安全
    }
  };
  for (const rel of FRESHNESS_INPUTS) walk(path.join(ROOT, rel));
  if (best === null) {
    throw new Error(`freshness 门卫: 输入集全部缺失 (${FRESHNESS_INPUTS.join(", ")}) — 仓库结构变了?`);
  }
  return best;
}

{
  const newest = newestFreshnessInput();
  if (BIN_MTIME < newest.mtime) {
    // 按命中候选给对应的重编指引 (llvm-cov 判定在前: 其路径含 /debug/ 但不含
    // /release/, 唯一目录名; release 判定用 path.sep 边界防误命中任意 release 段).
    const rebuildHint = SG_BIN.includes("llvm-cov-target")
      ? "just check --coverage"
      : SG_BIN.includes(`${path.sep}release${path.sep}`)
        ? "cargo build --release --locked"
        : "cargo build --locked";
    throw new Error(
      `[playwright.config] secret-guard binary 陈旧 (freshness 门卫, #314):\n` +
        `  binary:  ${SG_BIN} (mtime ${new Date(BIN_MTIME).toISOString()})\n` +
        `  较新输入: ${newest.file} (mtime ${new Date(newest.mtime).toISOString()})\n` +
        `WebUI 测试会打在旧代码上 → 假阳性. 先重编再跑:\n` +
        `  ${rebuildHint}`
    );
  }
}

// 孤儿进程清理不在本文件做 (Playwright 多次 require config + globalSetup 在 webServer
// 之后执行, 时机都不对). 改由 justfile _kill-orphans recipe 在 `playwright test` 之前
// 清理 — 详见 justfile check-webui recipe.

// 每次跑测试用 mkdtempSync 唯一临时目录存放 config/state, 彻底隔离.
//
// 历史 bug (commit 68a5468): 固定 state 路径 (/tmp/sg-ui-test.state.toml) 导致同一
// worktree 反复跑测试时 state 持久累积, 旧 session 用相同 marker 被测试 `.first()`
// 误匹配 (I1 守卫期望 1 气泡却收到 N 个). 改为唯一目录后, 正常流程 (playwright 杀
// webServer 子进程 → 下次新进程) 每次都是干净 state.
//
// 三道防线 (缺一不可):
//   1. mkdtempSync 唯一 state 路径 (本段) — state 文件隔离
//   2. justfile _kill-orphans recipe 在 playwright test 之前清孤儿 (见 justfile) — 端口可用
//   3. reuseExistingServer:false (见 webServer 段) — 强制自起新进程, 不复用孤儿
// 早期方案缺第二、第三道, 用 reuseExistingServer:true 容忍孤儿但被孤儿持有的旧 state 污染.
// 注: 直接 `cd tests/webui && playwright test` 跳过 justfile 时第二道失效, 端口被占会 fail,
// 这是设计取舍 (justfile 是项目 SSOT 调用入口).
const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "sg-webui-"));
const SG_CONFIG = path.join(TMP_DIR, "sg.toml");
const SG_STATE = path.join(TMP_DIR, "sg.state.toml");

// 进程退出时清理临时目录 (best-effort: 仅正常退出生效; 异常信号由系统 tmp 清理兜底).
process.on("exit", () => {
  try {
    fs.rmSync(TMP_DIR, { recursive: true, force: true });
  } catch {
    // best-effort, 不阻塞退出.
  }
});

// 测试前的 setup: 用 Node fs 直接写配置 (避免 shell heredoc 的两层 quoting 歧义).
// 模块加载时执行一次, webServer 启动时配置文件已就绪.
fs.writeFileSync(
  SG_CONFIG,
  `[[providers]]
id = "mock-openai"
kind = "direct"
endpoints = [ { protocol = "openai", base_url = "http://127.0.0.1:${MOCK_PORT}" } ]
enabled = true

# 透传族存量条目 (webui_protocols 词表外): 编辑场景用例的种子.
[[providers]]
id = "mock-gemini"
kind = "direct"
endpoints = [ { protocol = "gemini", base_url = "http://127.0.0.1:${MOCK_PORT}" } ]
enabled = true

# router 条目: endpoints 弹窗矩阵形态 (5 协议入口 × direct/translate/unsupported
# 三态) 用例的种子 — multi-endpoint 后 direct 条目的弹窗改为 per 端点行形态, 矩阵
# 只剩 router/pool 宿主. 链尾 = mock-openai (openai 单端点), 三态断言与旧
# direct 种子时代完全一致.
[[providers]]
id = "mock-router"
kind = "router"
enabled = true

[[providers.routes]]
model_pattern = "*"
target = "mock-openai"
priority = 0

[[secrets.entries]]
id = "test-key"
value = "${TEST_SECRET_VALUE}"
category = "apikey"

# #257 S0.5: 隐私旁路扫描 batch 档 (面板出现 + 登记预填用例依赖; 告警含疑似
# 明文 value — 本地测试信任域). test-key 是已登记值, 会被排除规则/视图过滤
# 双层跳过, 不污染其他用例的 secrets tab 断言.
[privacy_scan]
mode = "batch"
`
);

export default defineConfig({
  testDir: ".",
  testMatch: "im-ui.spec.ts",

  // 单线程跑 (避免多 worker 同时操作同一份 state.toml).
  workers: 1,

  // 视口固定 (保证 layout 稳定 + request-pane 内容足够多触发滚动).
  // 不指定 launchOptions.executablePath: nixpkgs playwright-test wrapper 已经
  // 通过 PLAYWRIGHT_BROWSERS_PATH 环境变量指向系统 chromium, Playwright 自动解析.
  use: {
    baseURL: SG_URL,
    browserName: "chromium",
    viewport: { width: 1280, height: 600 },
    // 默认截图配置 (失败时自动截图).
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },

  // webServer: Playwright 自动管理生命周期 (启动→等待就绪→测试后清理).
  // reuseExistingServer:false 强制自起新进程 — 三道防线之 #3, 详见上方 mkdtempSync 段.
  webServer: [
    {
      // 1. 启动 mock upstream (零依赖 Python 脚本, 配置文件已由 fs.writeFileSync 生成).
      command: `python3 ${path.join(ROOT, "tests", "webui", "mock_upstream.py")}`,
      port: MOCK_PORT,
      timeout: 10_000,
      reuseExistingServer: false,
      env: { MOCK_PORT: String(MOCK_PORT) },
    },
    {
      // 2. 启动 secret-guard (在 mock 就绪后).
      command: `${SG_BIN} run --config ${SG_CONFIG} --state ${SG_STATE} --port ${SG_PORT}`,
      url: `${SG_URL}api/providers`,
      timeout: 15_000,
      reuseExistingServer: false,
    },
  ],
});
