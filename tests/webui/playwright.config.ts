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

// Playwright 加载 config 时 cwd = config 所在目录 (tests/webui).
// 不用 import.meta.url (在 CJS 模式下不可用, 在 ESM 模式下又要求 package.json type:module).
const ROOT = path.resolve(process.cwd(), "..", ".."); // 项目根 (tests/webui 的上两级).
const MOCK_PORT = 19999;
const SG_PORT = 18790;
const SG_URL = `http://127.0.0.1:${SG_PORT}/`;
// secret-guard 二进制检索 (按优先级): release > debug > llvm-cov-target/debug.
//   - release: 非插桩、最快, WebUI server 响应最稳 (本地 cargo build --release).
//   - debug:   本地开发常态 (cargo build / nextest run).
//   - llvm-cov-target/debug: CI 兜底 — `just check --coverage` 走 cargo llvm-cov nextest,
//     产物只落此子目录; CI 在本 step 之前无 release/debug 编译, 故此候选必须存在
//     (历史 bug: 只查 release/debug 两处, CI 永远找不到 binary).
// CARGO_TARGET_DIR: CI 用持久卷 (/var/lib/forgejo-runner/cache/cargo-target), 本地默认 target/.
const CARGO_TARGET_DIR = process.env.CARGO_TARGET_DIR || path.join(ROOT, "target");

/**
 * 返回第一个存在的 secret-guard binary 路径; 都不存在则抛错列出所有候选.
 */
function resolveSgBin(): string {
  const candidates = [
    path.join(CARGO_TARGET_DIR, "release", "secret-guard"),
    path.join(CARGO_TARGET_DIR, "debug", "secret-guard"),
    path.join(CARGO_TARGET_DIR, "llvm-cov-target", "debug", "secret-guard"),
  ];
  const found = candidates.find((p) => fs.existsSync(p));
  if (found) return found;
  throw new Error(
    `secret-guard binary not found in any candidate:\n${candidates.map((p) => `  - ${p}`).join("\n")}\n` +
      `Run 'cargo build' or 'cargo llvm-cov nextest' first.`
  );
}

const SG_BIN = resolveSgBin();
// 打印命中路径到 stderr, 让 CI log 直接可见命中了哪个候选.
// 动机: WebUI step 的 continue-on-error 会静默吞错, 若解析到非预期产物 (如陈旧 binary)
// 未来复现, 维护者翻 CI log 第一行即可定位, 而非反推. console.error 走 stderr,
// Playwright 不解析 config 加载期的输出, 无副作用.
console.error(`[playwright.config] secret-guard binary: ${SG_BIN}`);

// 临时配置文件路径 (绝对路径, webServer 的 cwd 是 testDir).
const SG_CONFIG = "/tmp/sg-ui-test.toml";
const SG_STATE = "/tmp/sg-ui-test.state.toml";

// 测试前的 setup: 用 Node fs 直接写配置 (避免 shell heredoc 的两层 quoting 歧义).
// 模块加载时执行一次, webServer 启动时配置文件已就绪.
fs.writeFileSync(
  SG_CONFIG,
  `[[providers]]
id = "mock-openai"
protocol = "openai"
base_url = "http://127.0.0.1:${MOCK_PORT}"
enabled = true

[[secrets.entries]]
id = "test-key"
value = "sk-test-secret-1234567890"
category = "apikey"
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

  // webServer: Playwright 自动启动并等待就绪.
  // reuseExistingServer: true 允许复用外部已起的 server (本地开发友好).
  webServer: [
    {
      // 1. 启动 mock upstream (零依赖 Python 脚本, 配置文件已由 fs.writeFileSync 生成).
      command: `python3 ${path.join(ROOT, "tests", "webui", "mock_upstream.py")}`,
      port: MOCK_PORT,
      timeout: 10_000,
      reuseExistingServer: true,
      env: { MOCK_PORT: String(MOCK_PORT) },
    },
    {
      // 2. 启动 secret-guard (在 mock 就绪后).
      command: `${SG_BIN} run --config ${SG_CONFIG} --state ${SG_STATE} --port ${SG_PORT}`,
      url: `${SG_URL}__sg/api/providers`,
      timeout: 15_000,
      reuseExistingServer: true,
    },
  ],
});
