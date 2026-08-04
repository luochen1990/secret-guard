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

// 每次跑测试用 mkdtempSync 唯一临时目录存放 config/state, 彻底隔离.
//
// 历史 bug: 固定 state 路径 (/tmp/sg-ui-test.state.toml) 导致同一 worktree 反复跑测试时
// state 持久累积, 旧 session 用相同 marker 被测试 `.first()` 误匹配 (I1 守卫期望 1 气泡
// 却收到 N 个). 改为唯一目录后, 正常流程 (playwright 杀 webServer 子进程 → 下次新进程)
// 每次都是干净 state. (reuseExistingServer 的权衡见 webServer 段.)
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

  // webServer: Playwright 自动管理生命周期 (启动→等待就绪→测试后清理).
  // reuseExistingServer:true 容忍 CI runner VM 上残留孤儿进程占用端口 (false 会直接失败);
  // 正常路径下每次用新 TMP_DIR (见上) 隔离 state, 仅孤儿复用 (罕见) 可能读到旧 state.
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
