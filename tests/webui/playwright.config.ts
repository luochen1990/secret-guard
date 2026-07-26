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
// secret-guard 二进制: 优先 release, 其次 debug.
// CARGO_TARGET_DIR 支持: CI 用持久卷 (/var/lib/forgejo-runner/cache/cargo-target),
// 本地开发默认 target/. 优先 release (CI 跑过 --coverage 用 debug 子目录).
const CARGO_TARGET_DIR = process.env.CARGO_TARGET_DIR || path.join(ROOT, "target");
const releaseBin = path.join(CARGO_TARGET_DIR, "release", "secret-guard");
const debugBin = path.join(CARGO_TARGET_DIR, "debug", "secret-guard");
const SG_BIN = fs.existsSync(releaseBin) ? releaseBin : debugBin;

if (!fs.existsSync(SG_BIN)) {
  throw new Error(
    `secret-guard binary not found at ${releaseBin} or ${debugBin}. Run 'cargo build --release' first.`
  );
}

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
