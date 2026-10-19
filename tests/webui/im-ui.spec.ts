/**
 * IM 风格 WebUI 回归测试 for secret-guard (会话折叠 + timeline 版本, session-aware sync API).
 *
 * 适配会话两级树 sidebar (session-item → round-item) + timeline 右侧对话流.
 * 每条 sendChat 创建一个独立的单轮次会话 (无父上下文 → 各自成为 root+leaf).
 *
 * 后端 API (session-aware sync):
 *   - POST /api/sync           统一轮询 (sidebar sessions + expanded rounds + timeline diff).
 *   - GET  /api/sessions/{sid}/timeline?before=&limit=  初始加载 + lazy load.
 *   - GET  /api/records/{id}   单条 record view (meta/raw/parsed, 轮次详情弹窗按需拉).
 *
 * 前端行为 (相对旧版的差异, 影响测试编写):
 *   - toggleSession 不再设置 state.selectedRound; 仅点击 round-item / sub-dot / timeline
 *     header 才会显式 selectRound. 故依赖 ".tl-round.selected" 的测试需先显式选一轮.
 *   - sidebar 三级菜单用 round_role (后端预计算) 判定: 'user' → round-item, 其他 → sub-dot.
 *     round_role 基于 IrMessage.contains_user_text 字段 (而非 IR 归一化后的 role):
 *     tool-call 循环 (delta 无用户文本输入) 的 round_role=Tool → 折叠为 sub-dot.
 *   - timeline round 的 resp_status / elapsed_ms 等字段移到 TimelineTail, 由
 *     updateLastRoundHeader() 从 state.tail 填充末轮 header.
 *
 * 覆盖原始 7 项需求 (在新的会话/timeline 结构下):
 *   1. 滚动重置修复: 自动刷新期间 timeline 内 scrollTop + bubble 展开状态保持.
 *   2. 三级展示气泡: 折叠 → 展开 → 弹框全文.
 *   3. response 打字框: 固定底部 + 独立滚动 + 不参与 request 滚动.
 *   4. timeline 选中会话初始滚到底.
 *   5. 气泡颜色 + sender icon 分类.
 *   6. sidebar (session-item) preview 提取 (首条 user msg).
 *   7. sidebar model 字段显示.
 *
 * 显式不变量守卫 (AGENTS.md "前端不变量"):
 *   I1: timeline 气泡数 == 该 Node 的 IR messages 数组长度 (参数化 N=1/3/5).
 *   I2: sidebar (round-item + sub-dot) 总数 == 该 Session 的 HTTP 请求数 (M=3).
 *   I3: timeline 轮次 DOM 顺序 == state.timelineRecords (oldest-first, M=3).
 *
 * 错误状态渲染: 上游 502/429 时 WebUI 不崩溃 + record 显示错误状态.
 *
 * SSE 失效通知消费 (rt-push T3 / UI-8): poke → 200ms debounce → sync; SSE 断开
 * 退化为兜底轮询; #164-3 弹窗暂停语义覆盖 poke 路径 (文件尾 describe).
 *
 * 所有测试共享一个 browser context, 按声明顺序执行 (workers=1).
 */
import { test, expect, type Locator, type Page } from "@playwright/test";
import * as http from "http";
import { TEST_SECRET_VALUE } from "./fixtures";

const SG_API = "/api";
const FORWARD_URL = "/o/mock-openai/v1/chat/completions";

// ─── 辅助: 通过 HTTP API 发 chat 请求生成 record ────────────────────────

async function sendChat(
  page: Page,
  messages: Array<Record<string, unknown>>,
  opts: { model?: string; stream?: boolean } = {}
): Promise<void> {
  const body = JSON.stringify({
    model: opts.model ?? "test-model-abc",
    messages,
    stream: opts.stream ?? false,
  });
  await page.request.post(FORWARD_URL, {
    data: body,
    headers: { "Content-Type": "application/json" },
    timeout: 10_000,
  });
}

/**
 * 开/关详细日志 (B2 `PUT /api/settings`)。依赖 raw body 捕获的用例在 sendChat 前
 * 开启 (quant#307 起默认 latest — 会话头部请求有 raw; 未捕获占位断言的用例需显式 off)。
 */
async function setAuditCapture(page: Page, on: boolean | string): Promise<void> {
  // `on` 接受 bool (旧调用点, 服务端兼容反序列化) 或三态 string
  // ("off"/"latest"/"full"; 旧 "errors" 由服务端迁移 latest, 测试不再使用).
  const r = await page.request.put(`${SG_API}/settings`, {
    data: { audit_capture: on },
    headers: { "Content-Type": "application/json" },
    timeout: 10_000,
  });
  if (!r.ok()) throw new Error(`setAuditCapture(${on}) failed: HTTP ${r.status()}`);
}

// 测试间状态卫生: 任何用例改档位后, afterEach 恢复生产默认 latest (quant#307).
// workers=1 共享同一 server 进程, 档位泄漏到后续用例会让 "未捕获占位" 类断言失败.
// server 不可达时静默 (此时测试自身已失败, 卫生钩子不叠加噪音).
test.afterEach(async ({ page }) => {
  await setAuditCapture(page, "latest").catch(() => {});
});

// SSE 静音 route (file-level 默认, rt-push T3): 前端 bootstrap 会订阅
// GET /api/events (SSE 长连接). 默认拦截的两个理由:
//   1. 长连接持续 inflight 会让 page.waitForLoadState("networkidle") (各 describe
//      的 beforeEach 都在用) 永不满足 — "0 inflight 500ms" 的空闲判据被钉死.
//   2. 既有用例的时序假设建立在 3s 兜底轮询节奏上 (findSessionLeafByPreview 的
//      轮询回填 / #164-3 的 "2 个 3s 周期"); 静音后连接立即关闭 → sseHealthy 恒
//      false → 兜底间隔恒 3s, 与 SSE 引入前的行为逐字一致 (零回归面).
// 静音形态: 200 + text/event-stream 一次性 body "retry: 900000\n\n" — 只设重连
// 间隔不投递事件 (SSE 规范: 空 data 的 blank line 不 dispatch), 连接随即关闭 →
// EventSource 15min 内不重连, 每页恰好一次请求. SSE 专项用例在 test 体内
// page.unroute 本默认后自装受控 route (见文件尾 "SSE 失效通知" describe).
test.beforeEach(async ({ page }) => {
  await page.route("**/api/events", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "text/event-stream",
      body: "retry: 900000\n\n",
    });
  });
});

/**
 * 等待 sidebar 出现包含指定 preview 子串的会话 (session-item), 返回其 session_id.
 *
 * 用 Playwright locator 的 auto-retrying polling (不 reload 全页),
 * 依赖 WebUI 自身的 3s 自动刷新拉到新会话. 单测间状态隔离:
 * 每个测试用唯一 marker 子串, 不依赖其他测试创建的会话.
 */
async function findSessionLeafByPreview(page: Page, previewSubstr: string): Promise<string> {
  const item = page.locator(".session-item", { hasText: previewSubstr }).first();
  await item.waitFor({ state: "visible", timeout: 5000 });
  const sid = await item.getAttribute("data-sid");
  if (!sid) throw new Error(`session with preview '${previewSubstr}' has no data-sid`);
  return sid;
}

/**
 * 点击会话展开 + 加载 timeline.
 *
 * 注: 新版 toggleSession 只展开 + loadTimeline, 不显式 selectRound (state.selectedRound
 * 仍为 null). 需要选中态的测试用 selectLastRoundAfterToggle.
 */
async function clickSessionByLeaf(page: Page, sid: string): Promise<void> {
  await page.locator(`.session-item[data-sid="${sid}"]`).click();
  await page.waitForSelector("#detail .request-pane", { timeout: 3000 });
}

/**
 * 打开轮次详情弹窗并切到完整数据 tab (quant#305: 原 raw 弹窗内容的新位置).
 * 断言 raw 内容的用例统一走此 helper — 弹窗结构若再变只改一处.
 */
async function openRoundDetailTab(page: Page): Promise<Locator> {
  await page.locator("#detail .tl-actions button[data-action='detail']").click();
  const dlg = page.locator("dialog.round-dialog");
  await expect(dlg).toBeVisible();
  await dlg.locator(".dialog-tab[data-tab='detail']").click();
  return dlg;
}

/**
 * 在 clickSessionByLeaf 之后显式选中末轮 (模拟用户点最新一轮 header).
 *
 * 用途: 新版 toggleSession 不再设置 state.selectedRound. 需要断言
 * ".tl-round.selected" 的测试 (UI-6 系列 / 需求 4) 必须先调用本函数建立选中态.
 *
 * 等价于用户在打开会话后点最新一轮 header, 与旧版 "点 session 即选中叶子" 的
 * 复合动作行为一致.
 */
async function selectLastRoundAfterToggle(page: Page): Promise<string> {
  const lastRound = page.locator("#detail > .tl-round").last();
  await lastRound.waitFor({ state: "attached", timeout: 3000 });
  const rid = await lastRound.getAttribute("data-rid");
  if (!rid) throw new Error("末轮 .tl-round 缺 data-rid");
  await lastRound.locator(".tl-round-header").click();
  // 等 .selected 类迁移到该轮 (updateSelectedRoundClass 同步触发).
  await expect(
    page.locator(`#detail .tl-round.selected[data-rid="${rid}"]`)
  ).toHaveCount(1);
  return rid;
}

/**
 * 辅助: 构造 3 轮长内容会话, 用于 drawer 回归测试 (bug #3 系列).
 *
 * 每轮首条 user 含 marker (供 findSessionLeafByPreview 匹配) + 超长内容 (3000 'x'),
 * 触发 placeholder 渲染 (placeholderH = extremeMaxH = 80% wrapH). 3 轮累积让 timeline
 * 总内容超过 wrapH, 提供足够的滚动空间观察 phase 切换.
 *
 * @param roundIdx 选中轮次索引 (0=最老/最顶, 2=最新/最底). 末轮紧邻 placeholder,
 *                 中间轮/首轮能滚出视口顶部. 不同选择覆盖不同 phase 路径.
 */
async function setupLongChatSelectRound(page: Page, marker: string, roundIdx: number): Promise<void> {
  const longUser = "x".repeat(3000);
  const reply = "r".repeat(2000);
  await sendChat(page, [
    { role: "user", content: `${marker} ${longUser}` },
    { role: "assistant", content: reply },
  ]);
  await sendChat(page, [
    { role: "user", content: `${marker} ${longUser}` },
    { role: "assistant", content: reply },
    { role: "user", content: `${longUser} second` },
    { role: "assistant", content: reply },
  ]);
  await sendChat(page, [
    { role: "user", content: `${marker} ${longUser}` },
    { role: "assistant", content: reply },
    { role: "user", content: `${longUser} second` },
    { role: "assistant", content: reply },
    { role: "user", content: `${longUser} third` },
    { role: "assistant", content: reply },
  ]);
  const leaf = await findSessionLeafByPreview(page, marker);
  await clickSessionByLeaf(page, leaf);
  await page.waitForTimeout(500);
  await page.locator("#detail .tl-round").nth(roundIdx).locator(".tl-round-header").click();
  await page.waitForTimeout(1000);
}

// ─── 测试用例 ────────────────────────────────────────────────────────────

/**
 * 挂 alert 自动 accept 处理器 (alert 阻塞页面 JS, 不处理会冻结), 并记录消息
 * 供断言 "失败 alert 确实弹出" (证明 fetch 走了失败分支, 而非静默成功).
 * #181/#190 两个表单相关 describe 共用.
 */
function autoAcceptAlerts(page: Page): string[] {
  const alerts: string[] = [];
  page.on("dialog", async (d) => {
    alerts.push(d.message());
    await d.accept();
  });
  return alerts;
}

// 打开新建 provider 表单 (provider 相关 describe 共用, #332 起两 describe 复用).
async function openNewProviderForm(page: Page): Promise<void> {
  await page.locator("button", { hasText: "+ new provider" }).click();
  await expect(page.locator("#provider-form")).toBeVisible();
}

// provider 表单端点行 (multi-endpoint) 快捷定位: 默认第 0 行 (Detect 用例的
// 探测目标 / 新建表单的首行).
function endpointRow(page: Page, n = 0): Locator {
  return page.locator(".endpoint-row").nth(n);
}

// 手动 "添加协议" 产生端点行 (#332 创建流程: 新建表单不预置空白协议行 —
// 协议行来自检测结果快速添加或手动添加).
async function addManualEndpoint(page: Page): Promise<Locator> {
  await page.locator("#p-endpoint-add").click();
  return endpointRow(page, await page.locator(".endpoint-row").count() - 1);
}

test.describe("IM 风格 WebUI 回归 (会话折叠版)", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(500);
  });

  test("需求 6+7: sidebar 会话显示首条 user msg 作为 preview, model 名在 line2", async ({
    page,
  }) => {
    await sendChat(page, [
      { role: "system", content: "system prompt" },
      { role: "user", content: "Hello unique-preview-text-12345" },
    ]);
    // locator 自动 polling 直到 sidebar 出现该会话 (依赖 WebUI 3s 自动刷新).
    const leaf = await findSessionLeafByPreview(page, "Hello unique-preview-text-12345");
    expect(leaf).toBeTruthy();

    // session-item line2 应包含 model 名.
    const metas = await page.locator(".session-item .ri-line2").allTextContents();
    expect(metas.some((m) => m.includes("test-model-abc"))).toBe(true);
  });

  test("sidebar 会话 provider icon: 含协议角标 SVG + provider id 首字母", async ({
    page,
  }) => {
    // 回归守卫: 会话折叠重构曾丢失协议角标 + provider id (退化为 session_id 哈希随机色 + 空角标).
    // mock-openai provider 的 path 前缀是 /o/mock-openai, 首字母应为 'm', 角标应为 OpenAI 六瓣花.
    await sendChat(page, [{ role: "user", content: "provider-icon-marker" }]);
    const item = page
      .locator(".session-item", { hasText: "provider-icon-marker" })
      .first();
    await item.waitFor({ state: "visible", timeout: 5000 });

    const icon = item.locator(".pv-icon").first();
    // 首字母 = provider id 的首字母.
    const letter = ((await icon.textContent()) ?? "").trim().charAt(0);
    expect(letter).toBe("m");
    // 协议角标 SVG 必须存在 (空角标 = bug).
    await expect(icon.locator("svg")).toHaveCount(1);
  });

  test("需求 2+5: sender icon 分类 + 气泡颜色", async ({ page }) => {
    // IM 风格: 每轮 request-pane 只渲染本轮的 user bubble (最后一条 user msg).
    // 不再回显完整 messages 历史, 因此 timeline 内只有 user 气泡.
    await sendChat(page, [
      { role: "system", content: "sys" },
      { role: "user", content: "sender-icon-marker" },
    ]);

    const leaf = await findSessionLeafByPreview(page, "sender-icon-marker");
    await clickSessionByLeaf(page, leaf);
    await page.waitForTimeout(500);

    // sender icons (timeline 内): 单 user 气泡.
    const senderClasses = await page
      .locator("#detail .sender-icon")
      .evaluateAll((els) => els.map((e) => e.className.replace("sender-icon ", "")));
    expect(senderClasses).toContain("s-user");

    // bubble 颜色 class.
    const bubbleClasses = await page
      .locator("#detail .chat-bubble")
      .evaluateAll((els) => els.map((e) => e.className));
    expect(bubbleClasses.some((c) => c.includes("bubble-user"))).toBe(true);
  });

  test("XML 块渲染: 气泡内块级 XML → 带背景色独立区块; 未闭合降级纯文本", async ({
    page,
  }) => {
    // 会话 1: 同轮 delta 含 user + assistant 两条 XML 消息 (一次覆盖两条气泡渲染路径;
    // user 块体内含 static secret, 验证 mock 高亮在块内照常生效).
    await sendChat(page, [
      {
        role: "user",
        content:
          `xmlblk-user before\n<system-reminder>\nhidden context ${TEST_SECRET_VALUE}\n</system-reminder>\nafter text`,
      },
      { role: "assistant", content: "<agent-note>\nagent xml body\n</agent-note>" },
    ]);
    // 会话 2: 未闭合标签 → 不识别, 保持纯文本 (best-effort 降级契约).
    await sendChat(page, [
      { role: "user", content: "xmlblk-unclosed\n<foo>\nnever closed" },
    ]);
    // 会话 3: 块内自闭合行 (<note/>) 不得虚增同名 depth 计数 (否则合法块整体降级).
    await sendChat(page, [
      { role: "user", content: "xmlblk-selfclose\n<note>\n<note/>\ninner line\n</note>" },
    ]);

    // 会话 1: user 气泡内 1 个 xml 块, 标签字面行不重复出现, 前后文本保留.
    const sid1 = await findSessionLeafByPreview(page, "xmlblk-user");
    await clickSessionByLeaf(page, sid1);
    const block = page.locator("#detail .request-pane .chat-bubble.bubble-user .xml-block");
    await expect(block).toHaveCount(1);
    // data-tag 是块的语义锚点 (与徽章文本同源, 属性断言更稳).
    await expect(block).toHaveAttribute("data-tag", "system-reminder");
    // per-tag tint class 稳定附带 + 背景色生效 (区块契约): 两条互补断言落同一块上
    // (兜底 --xml-bg 不透明, bg 检查证明不了 tint 已挂; class 检查证明不了 CSS 接线对).
    await expect(block).toHaveClass(/xml-c\d/);
    const bg = await block.evaluate((el) => getComputedStyle(el).backgroundColor);
    expect(bg).not.toBe("rgba(0, 0, 0, 0)");
    await expect(block.locator(".xml-block-body")).toContainText("hidden context");
    // mock 高亮在块内生效 (secret 已被 redact 为 mock 并包 mark).
    await expect(block.locator(".xml-block-body mark.secret-hit")).toHaveCount(1);
    const userBubble = page.locator("#detail .request-pane .chat-bubble.bubble-user");
    const userText = (await userBubble.textContent()) ?? "";
    expect(userText).toContain("before");
    expect(userText).toContain("after text");
    expect(userText).not.toContain("<system-reminder>");

    // 会话 1 assistant 气泡: XML 块走 assistantBubbleHtml 路径, 同样区块化.
    const agentBlock = page.locator("#detail .request-pane .chat-bubble.bubble-assistant .xml-block");
    await expect(agentBlock).toHaveCount(1);
    await expect(agentBlock).toHaveAttribute("data-tag", "agent-note");
    await expect(agentBlock.locator(".xml-block-body")).toContainText("agent xml body");

    // 会话 2: 未闭合 <foo> 不产生块, 字面标签保留.
    const sid2 = await findSessionLeafByPreview(page, "xmlblk-unclosed");
    await clickSessionByLeaf(page, sid2);
    await expect(page.locator("#detail .request-pane .xml-block")).toHaveCount(0);
    const rawText = (await page.locator("#detail .request-pane .chat-bubble.bubble-user").textContent()) ?? "";
    expect(rawText).toContain("<foo>");

    // 会话 3: 块内自闭合行不影响识别 (若 <note/> 虚增 depth, 单个 </note> 无法归零
    // → 块整体降级, toHaveCount(1) 即红; body 断言守住块内容正常渲染).
    const sid3 = await findSessionLeafByPreview(page, "xmlblk-selfclose");
    await clickSessionByLeaf(page, sid3);
    const noteBlock = page.locator("#detail .request-pane .xml-block");
    await expect(noteBlock).toHaveCount(1);
    await expect(noteBlock.locator(".xml-block-body")).toContainText("inner line");
  });

  test("需求 2 (IM 风格): 每轮渲染本轮 delta, 不重复历史", async ({ page }) => {
    // 多轮对话 (累积 messages 数组): 旧版会每轮重复显示前序历史气泡.
    // 修复后 (issue #27): 每轮 request-pane 渲染本轮 req_delta 的所有非 assistant messages.
    //   - 根节点: system + user (2 个气泡, system 可见)
    //   - 非根节点: 只渲染本轮新增 (user / tool_result 等), 不回显完整历史
    const longSys = "You are a helpful assistant designed to test the secret-guard webui. ".repeat(50);
    await sendChat(page, [
      { role: "system", content: longSys },
      { role: "user", content: "three-tier-test-marker" },
    ]);

    const leaf = await findSessionLeafByPreview(page, "three-tier-test-marker");
    await clickSessionByLeaf(page, leaf);
    await page.waitForTimeout(500);

    // 根节点: 1 个 user 气泡 + 1 个 system 气泡 (system prompt 现在可见).
    await expect(page.locator("#detail .request-pane .chat-bubble.bubble-user")).toHaveCount(1);
    await expect(page.locator("#detail .request-pane .chat-bubble.bubble-system")).toHaveCount(1);
    // user 气泡应包含 preview 文本.
    const userText = await page.locator("#detail .chat-bubble.bubble-user").textContent();
    expect(userText).toContain("three-tier-test-marker");
  });

  test("需求 3: response 抽屉固定底部 + 独立滚动", async ({ page }) => {
    await sendChat(page, [{ role: "user", content: "give me a long response" }]);

    const leaf = await findSessionLeafByPreview(page, "give me a long response");
    await clickSessionByLeaf(page, leaf);
    await page.waitForTimeout(500);

    // timeline 有 request-pane; response 在独立抽屉 (.response-drawer, issue #36).
    await expect(page.locator("#detail .request-pane")).toHaveCount(1);
    const drawer = page.locator("#detail-wrap .response-drawer");
    await expect(drawer).toHaveCount(1);
    await expect(drawer).not.toHaveAttribute("hidden", "");

    // 抽屉应该有可见高度 (相对窗口 10%~80%).
    const respH = await drawer.evaluate((el) => el.clientHeight);
    expect(respH).toBeGreaterThan(100);

    // response 内容应该非空.
    const respText = await drawer.locator(".resp-body").textContent();
    expect(respText!.length).toBeGreaterThan(10);

    // 滚动 #detail (timeline 容器) 不应该影响抽屉的 scrollTop (抽屉是兄弟元素, 独立滚动).
    await page
      .locator("#detail")
      .evaluate((el) => (el.scrollTop = 50));
    await page.waitForTimeout(200);
    const respScroll = await drawer.locator(".resp-body").evaluate((el) => el.scrollTop);
    expect(respScroll).toBe(0);
  });

  test("需求 1 (B1/B2 根治): 自动刷新期间 scrollTop 保持 (IM 风格)", async ({
    page,
  }) => {
    // 多轮对话: 累积 messages 数组 (DAG 通过 prefix-hash 自动把连续请求链成同一会话).
    // IM 风格: 每轮 request-pane 只渲染本轮的 preview (单 user 气泡),
    // 但 response-pane 渲染完整 assistant 回复. 多轮累积 → timeline 可滚动.
    // 注: 用长 system + 长 assistant 回复累积, 保证 timeline 总高度 > 视口 (避免 skip).
    //   折叠态 max-height 4.5em (~70px), 故需 ~6+ 气泡叠加才超视口.
    const longSys = "You are a coding assistant. ".repeat(40);
    const longReply = "2+2 equals 4 and here is a detailed explanation. ".repeat(20);
    // 轮 1: [sys, user1] → 助手回复. mock 看 *首条* user msg: user1 含 "long response" → 长回复.
    await sendChat(page, [
      { role: "system", content: longSys },
      { role: "user", content: "first long response question" },
      { role: "assistant", content: "1+1 equals 2." },
    ]);
    // 轮 2: [sys, user1, asst1, user2] → prefix 匹配轮 1 的 [sys,user1] → 成为轮 1 的 child.
    await sendChat(page, [
      { role: "system", content: longSys },
      { role: "user", content: "first long response question" },
      { role: "assistant", content: "1+1 equals 2." },
      { role: "user", content: "What about 2+2?" },
      { role: "assistant", content: longReply },
      { role: "user", content: "final-long-response-marker" },
    ]);

    // session title = 第一轮的首条 user msg (issue #36: 取最早 round, 非 leaf).
    const leaf = await findSessionLeafByPreview(page, "first long response question");
    await clickSessionByLeaf(page, leaf);
    await page.waitForTimeout(500);

    // 设置 #detail (timeline 容器) scrollTop 到中间.
    const canScroll = await page
      .locator("#detail")
      .evaluate((el) => el.scrollHeight > el.clientHeight);
    if (!canScroll) {
      test.skip(true, "content fits viewport");
      return; // test.skip 会抛, 这行仅为 type-check 之后的 narrowing.
    }

    const expected = await page.locator("#detail").evaluate(
      (el) => {
        el.scrollTop = Math.floor((el.scrollHeight - el.clientHeight) / 2);
        return el.scrollTop;
      }
    );
    expect(expected).toBeGreaterThan(0);

    // 等 2 轮自动刷新 (间隔 3s).
    await page.waitForTimeout(7000);

    // 验证 scrollTop 保持.
    const actual = await page
      .locator("#detail")
      .evaluate((el) => el.scrollTop);
    expect(Math.abs(actual - expected)).toBeLessThan(10);
  });

  test("需求 4: 选中会话时 timeline 初始滚到底", async ({ page }) => {
    // 多轮对话: 累积 messages 数组 (DAG 通过 prefix-hash 自动把连续请求链成同一会话).
    // session title = 第一轮首条 user msg (issue #36).
    // 注: 用长 system + 长 assistant 回复累积, 保证 timeline 总高度 > 视口 (避免 skip).
    const longSys = "You are a coding assistant. ".repeat(40);
    const longReply = "2+2 equals 4 and here is a detailed explanation. ".repeat(20);
    await sendChat(page, [
      { role: "system", content: longSys },
      { role: "user", content: "first long response question" },
      { role: "assistant", content: "1+1 equals 2." },
    ]);
    await sendChat(page, [
      { role: "system", content: longSys },
      { role: "user", content: "first long response question" },
      { role: "assistant", content: "1+1 equals 2." },
      { role: "user", content: "What about 2+2?" },
      { role: "assistant", content: longReply },
      { role: "user", content: "final-long-response-marker" },
    ]);

    const leaf = await findSessionLeafByPreview(page, "first long response question");
    // 点击会话条目 → toggleSession → loadTimeline → scrollTimelineToBottomForce.
    // 契约: "用户点会话条目" = IM 风格看最新消息, 应滚到底 (非 highlightRound 的 70% 定位).
    // 历史回归: DOM 倒序 bug 期间此契约被 highlightRound 的副作用巧合满足; 顺序修正后
    // 暴露了 selectRound 对已缓存会话只 highlight 不滚到底的不一致, 现由 loadTimeline
    // 末尾的 scrollTimelineToBottomForce 修复.
    await clickSessionByLeaf(page, leaf);
    // 等 loadTimeline 完成 + 浏览器 layout 稳定 (updateResponseDrawerLayout 同步触发).
    await page.waitForSelector("#detail .tl-round", { timeout: 3000 });
    await page.waitForTimeout(300);

    // 距 "内容底部" (末轮 .tl-round 底部) 的距离. 用 contentEnd 而非 scrollHeight:
    // #detail 末尾的 .drawer-placeholder 是给手动滚动 phase 4 的缓冲区 (长内容时高 =
    // extremeMaxH = 80% wrapH), 不计入 "内容". scrollTimelineToBottomForce 的契约是滚到
    // contentEnd (末轮紧贴视口底), 不滚入 placeholder (否则 placeholder 进入视口 → drawer
    // 段 B 扩展到 80% 遮挡末轮, WebUI bug #3). 与实现 isNearBottom / UI-6 系列测试的
    // distFromBottom 基准一致 (见下文 UI-6 describe 块内同名 helper).
    const { contentEnd, scrollTop, clientHeight } = await page
      .locator("#detail")
      .evaluate((el) => {
        const rounds = el.querySelectorAll(":scope > .tl-round");
        let end = el.scrollHeight; // fallback: 无 round 时用 scrollHeight.
        if (rounds.length > 0) {
          const last = rounds[rounds.length - 1] as HTMLElement;
          end = last.offsetTop + last.offsetHeight;
        }
        return { contentEnd: end, scrollTop: el.scrollTop, clientHeight: el.clientHeight };
      });
    if (contentEnd <= clientHeight) {
      test.skip(true, "content fits viewport");
      return;
    }

    // 距末轮底部应该 < 20px (选中会话 = IM 风格滚到最新一轮, 不滚入 placeholder 缓冲).
    const distanceToBottom = contentEnd - scrollTop - clientHeight;
    expect(distanceToBottom).toBeLessThan(20);
  });

  // ─── Bug 复现测试 (PR26 引入的渲染问题) ────────────────────────────────────
  //
  // 以下测试复现用户报告的 3 个 bug, 用 "先写测试" 方式锁定期望行为:
  //   Bug 1: tool-call 循环中 user msg 气泡重复 (同一气泡出现多次).
  //   Bug 2: Tool Call (response) 和 Tool Result (下一轮 req) 混在一个气泡.
  //   Bug 3: 压缩后的会话看不到 system prompt / 完整上下文.
  //
  // 复现策略: 通过 sendChat 模拟多轮累积请求, 触发真实渲染路径.

  /**
   * 模拟 agent tool-call 循环: 用户问一次, agent 多轮 tool_call + tool_result.
   *
   * 三轮请求 (累积 messages 数组, DAG 通过 prefix hash 链成同一会话):
   *   轮1: [sys, u1] → LLM 返回 tool_call(ls)
   *   轮2: [sys, u1, a1(tool_call), tool1(result)] → LLM 返回 tool_call(cat)
   *   轮3: [sys, u1, a1(tc), tool1, a2(tc), tool2] → LLM 返回最终文本
   */
  test("Bug 1 验证: tool-call 循环 delta 内容不同 (preview 可同)", async ({
    page,
  }) => {
    await sendChat(page, [
      { role: "system", content: "sys-bug1-test" },
      { role: "user", content: "bug1-list-files-marker" },
    ]);
    await sendChat(page, [
      { role: "system", content: "sys-bug1-test" },
      { role: "user", content: "bug1-list-files-marker" },
      { role: "assistant", content: null, tool_calls: [{ id: "c1", type: "function", function: { name: "ls", arguments: "{}" } }] },
      { role: "tool", tool_call_id: "c1", content: "file1\nfile2" },
    ]);
    await sendChat(page, [
      { role: "system", content: "sys-bug1-test" },
      { role: "user", content: "bug1-list-files-marker" },
      { role: "assistant", content: null, tool_calls: [{ id: "c1", type: "function", function: { name: "ls", arguments: "{}" } }] },
      { role: "tool", tool_call_id: "c1", content: "file1\nfile2" },
      { role: "assistant", content: null, tool_calls: [{ id: "c2", type: "function", function: { name: "cat", arguments: '{"f":"file1"}' } }] },
      { role: "tool", tool_call_id: "c2", content: "hello world" },
    ]);

    const sid = await findSessionLeafByPreview(page, "bug1-list-files-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    // 分组渲染 (session-aware sync API + IR round_role):
    //   注: round_role 基于 contains_user_text 字段判定 (而非 IR 归一化后的 role),
    //   tool-call 循环轮次 (delta 仅含 assistant tool_call + tool result, 无 user 文本)
    //   round_role=Tool → 折叠为 sub-dot.
    //   3 次 HTTP 请求 → 1 个 .round-item (用户首轮), 2 个 .sub-dot (后续 tool 循环).
    await expect(page.locator(".round-item")).toHaveCount(1);
    await expect(page.locator(".sub-dot")).toHaveCount(2);
    // delta 内容验证: tool_result 气泡 + assistant tool_call 气泡应存在.
    expect(await page.locator("#detail .chat-bubble[data-role='tool']").count()).toBeGreaterThan(0);
    expect(await page.locator("#detail .chat-bubble.bubble-assistant").count()).toBeGreaterThan(0);
  });

  test("Bug 2 复现: response 的 tool_call 与 req 的 tool_result 应分开渲染", async ({
    page,
  }) => {
    // 单轮 tool-call 场景: 请求含 tool_result, response 返回文本.
    await sendChat(page, [
      { role: "system", content: "sys-bug2" },
      { role: "user", content: "bug2-weather-marker" },
      {
        role: "assistant",
        content: null,
        tool_calls: [
          {
            id: "w1",
            type: "function",
            function: { name: "get_weather", arguments: '{"city":"SF"}' },
          },
        ],
      },
      { role: "tool", tool_call_id: "w1", content: "Sunny, 72F" },
    ]);

    // preview = 最后一条 user (优先 user).
    const sid = await findSessionLeafByPreview(page, "bug2-weather-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    // 期望 (修复后): request-pane 应显示 tool_result 气泡 (role=tool),
    // response-pane 应显示 LLM 文本回复.
    // 当前 bug: request-pane 只渲染 user preview, tool_result 完全不显示.

    // 1. 应有 tool 气泡 (tool_result 在 request 侧).
    const toolBubbles = page.locator("#detail .chat-bubble.bubble-tool, #detail .chat-bubble[data-role='tool']");
    const toolCount = await toolBubbles.count();
    expect(toolCount, "tool_result 应渲染为独立气泡").toBeGreaterThan(0);

    // 2. tool 气泡应包含 "Sunny" (tool_result 的内容).
    if (toolCount > 0) {
      const toolText = await toolBubbles.first().textContent();
      expect(toolText).toContain("Sunny");
    }

    // 3. tool_result 气泡的 chat-row 应靠右 (客户端发送: user + tool_result 都在右侧;
    //    assistant 在左侧). 检查 flex-direction 为 row-reverse.
    const toolRow = page.locator("#detail .chat-row.row-tool").first();
    if (await toolRow.count() > 0) {
      const fd = await toolRow.evaluate((el) => getComputedStyle(el).flexDirection);
      expect(fd, "tool_result (客户端发送) 应靠右 row-reverse").toBe("row-reverse");
    }
  });

  test("Bug 3 复现: 压缩后应能看到 system prompt + 完整上下文", async ({ page }) => {
    // 模拟 opencode 压缩: 最后一条 user = "What did we do so far?".
    // 修复后: 应能看到 system prompt 气泡 + 压缩摘要气泡.
    await sendChat(page, [
      { role: "system", content: "sys-compress-bug3-marker You are a helpful coding assistant." },
      { role: "user", content: "earlier question" },
      { role: "assistant", content: "earlier answer" },
      { role: "user", content: "What did we do so far?" },
      { role: "assistant", content: "## 目标\n实现 secret-guard" },
    ]);

    // preview = last assistant (压缩 marker fallback).
    const sid = await findSessionLeafByPreview(page, "secret-guard");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    // 期望 (修复后): timeline 应显示 system 气泡.
    // 当前 bug: 只渲染 preview (48 chars 截断), system prompt 完全不展示.
    const systemBubbles = page.locator("#detail .chat-bubble.bubble-system, #detail .chat-bubble[data-role='system']");
    const systemCount = await systemBubbles.count();
    expect(systemCount, "system prompt 应渲染为气泡").toBeGreaterThan(0);

    // system 气泡内容应包含 marker 文本.
    if (systemCount > 0) {
      const sysText = await systemBubbles.first().textContent();
      expect(sysText).toContain("sys-compress-bug3-marker");
    }
  });

  // ─── Phase A: response 传输优化 + delta 含 assistant ──────────────────────
  //
  // 验证 issue #28 Phase A 的核心不变量:
  //   1. 多轮 timeline 中, 只有末轮有 response-pane (非末轮 response 已在 delta 中).
  //   2. delta 里的 assistant message 渲染为无源气泡 (不再跳过).
  test("Phase A: 多轮 timeline 只有末轮有 response, delta 含 assistant 气泡", async ({
    page,
  }) => {
    // 两轮对话 (累积 messages, DAG prefix hash 链成同一会话).
    await sendChat(page, [
      { role: "user", content: "phaseA-round1-marker" },
    ]);
    await sendChat(page, [
      { role: "user", content: "phaseA-round1-marker" },
      { role: "assistant", content: "phaseA-assistant-round1" },
      { role: "user", content: "phaseA-round2-marker" },
    ]);

    // 找到该会话 (session title = 第一轮首条 user msg, issue #36).
    const sid = await findSessionLeafByPreview(page, "phaseA-round1-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    // 应有 2 个 tl-round.
    await expect(page.locator("#detail .tl-round")).toHaveCount(2);

    // response 在独立抽屉里 (issue #36), 不再内嵌轮次. 抽屉恰好 1 个.
    await expect(page.locator("#detail .response-pane")).toHaveCount(0);
    await expect(page.locator("#detail-wrap .response-drawer")).toHaveCount(1);

    // delta 里的 assistant 气泡 (轮1的 response 被轮2 delta 引用).
    const assistantBubbles = page.locator(
      "#detail .request-pane .chat-bubble.bubble-assistant"
    );
    const asstCount = await assistantBubbles.count();
    expect(asstCount, "delta 应含 assistant 气泡").toBeGreaterThan(0);

    // assistant 气泡应包含轮1的 response 内容.
    if (asstCount > 0) {
      const asstText = await assistantBubbles.first().textContent();
      expect(asstText).toContain("phaseA-assistant-round1");
    }
  });

  // ─── sidebar round-item 渲染 + 选中态迁移 ──────────────────────────────────
  //
  // 历史 "三级圆点" 测试基于旧 isUserRound (wire 层 role==='user') 判定: OpenAI tool-call
  // 循环中 role:"tool" 的轮次被判为非 user → 折叠为 .sub-dot. 但 session-aware sync API
  // 改用后端预计算的 round_role (= req_delta 最后一条 message 的 IR role), 而 OpenAI ingress
  // 把 role:"tool" 在 IR 层归一化为 IrRole::User (ToolResult 块) → 故 OpenAI tool-call 循环
  // 每一轮的 round_role 都是 'user' → 全部 .round-item (无 .sub-dot).
  //
  // .sub-dot 仅在 round_role !== 'user' 时出现 (如纯 system/assistant 结尾的轮次, 极罕见),
  // 故本测试改为: 验证 sub-dot 渲染 (1 round-item + 2 sub-dot) + 点击迁移 .selected.
  test("sidebar: tool-call 循环折叠为 sub-dot + 点击迁移 .selected", async ({
    page,
  }) => {
    // 轮1: 用户提问 → LLM 返回 tool_call(ls).
    await sendChat(page, [
      { role: "user", content: "dots-user-question-marker" },
    ]);
    // 轮2: agent tool_call(ls) + tool_result → LLM 返回 tool_call(cat).
    await sendChat(page, [
      { role: "user", content: "dots-user-question-marker" },
      { role: "assistant", content: null, tool_calls: [{ id: "d1", type: "function", function: { name: "ls", arguments: "{}" } }] },
      { role: "tool", tool_call_id: "d1", content: "file_a" },
    ]);
    // 轮3: agent tool_call(cat) + tool_result → LLM 返回最终文本.
    await sendChat(page, [
      { role: "user", content: "dots-user-question-marker" },
      { role: "assistant", content: null, tool_calls: [{ id: "d1", type: "function", function: { name: "ls", arguments: "{}" } }] },
      { role: "tool", tool_call_id: "d1", content: "file_a" },
      { role: "assistant", content: null, tool_calls: [{ id: "d2", type: "function", function: { name: "cat", arguments: '{"f":"a"}' } }] },
      { role: "tool", tool_call_id: "d2", content: "content_a" },
    ]);

    const sid = await findSessionLeafByPreview(page, "dots-user-question-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    // round_role 基于 contains_user_text (而非 IR 归一化 role):
    //   轮1 delta=[user] → round_role=User → round-item.
    //   轮2/轮3 delta=[assistant tool_call, tool result] → round_role=Tool → sub-dot.
    // 1 个 .round-item (用户首轮), 2 个 .sub-dot (后续 tool 循环).
    await expect(page.locator(".round-item")).toHaveCount(1);
    await expect(page.locator(".sub-dot")).toHaveCount(2);

    // 点击 sub-dot 应选中对应轮次: sidebar active + timeline .selected 必须一致.
    // 历史 bug (UI-4): 点击后 .flash 动画到了新轮, 但 .selected 滞留在旧轮 (闪烁与高亮错位).
    // 这里覆盖到 timeline 侧的 .selected, 修复前会失败.
    const roundList = page.locator(`.round-list[data-sid="${sid}"]`);
    const dot1Rid = await roundList.locator(".sub-dot").nth(1).getAttribute("data-rid");
    expect(dot1Rid).toBeTruthy();
    await roundList.locator(".sub-dot").nth(1).click();
    await page.waitForTimeout(500);
    await expect(page.locator(".sub-dot.active")).toHaveCount(1);
    await expect(page.locator(`.sub-dot.active[data-rid="${dot1Rid}"]`)).toHaveCount(1);
    // timeline 侧: 仅一个 .selected, 且 data-rid 与所点击的 sub-dot 一致.
    await expect(page.locator("#detail .tl-round.selected")).toHaveCount(1);
    await expect(page.locator(`#detail .tl-round.selected[data-rid="${dot1Rid}"]`)).toHaveCount(1);

    // 再点另一个 sub-dot, .selected 必须迁移到新轮次 (不留旧选中).
    const dot0Rid = await roundList.locator(".sub-dot").nth(0).getAttribute("data-rid");
    expect(dot0Rid).toBeTruthy();
    await roundList.locator(".sub-dot").nth(0).click();
    await page.waitForTimeout(500);
    await expect(page.locator(".sub-dot.active")).toHaveCount(1);
    await expect(page.locator(`.sub-dot.active[data-rid="${dot0Rid}"]`)).toHaveCount(1);
    await expect(page.locator("#detail .tl-round.selected")).toHaveCount(1);
    await expect(page.locator(`#detail .tl-round.selected[data-rid="${dot0Rid}"]`)).toHaveCount(1);
  });

  // ─── "已经到顶了" 提示已移除 (issue #36) ──────────────────────────────────
  //
  // 验证: 该提示始终无法正确判断显示条件, 直接去掉. 现在页面不应有任何 tl-top-hint 元素.
  test("issue #36: \"已经到顶了\" 提示已移除", async ({ page }) => {
    await sendChat(page, [{ role: "user", content: "top-hint-removed-marker" }]);
    const sid = await findSessionLeafByPreview(page, "top-hint-removed-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    // 不应有任何 tl-top-hint 元素 (提示已完全移除).
    await expect(page.locator(".tl-top-hint")).toHaveCount(0);
  });

  // ─── 轮次详情弹窗 (quant#305: i/raw 合并 + 概览/完整数据 双 tab) ──────────
  //
  // 验证 (UI-9):
  //   1. 每轮 header 只剩一个详情按钮 (原 i / raw 两入口合并).
  //   2. 打开默认落在概览 tab: 元数据小字段 (model 等), 不含大数据.
  //   3. 概览只发 view=meta 小请求; 完整数据 tab 首次激活才拉完整 record,
  //      反复切换不重复拉取.
  //   4. 完整数据 tab = 原 raw 弹窗内容 (headers + bodies).

  test("轮次详情弹窗: i/raw 合并入口 + 概览默认 + 完整数据按需 (quant#305)", async ({ page }) => {
    // 显式开启 full 捕获 — 本用例断言 req_body 内容 (默认 latest 对单轮会话
    // 头部也有 raw, 但显式 full 免受默认档演进影响).
    await setAuditCapture(page, true);
    // 网络审计: 记录弹窗发起的 /api/records/{id} 请求的 view 档位 (无参数 = raw).
    const recordViews: string[] = [];
    page.on("request", (req) => {
      const m = req.url().match(/\/api\/records\/[0-9a-f-]+(?:\?view=(\w+))?$/);
      if (m) recordViews.push(m[1] || "raw");
    });
    await sendChat(page, [{ role: "user", content: "round-detail-tabs-marker" }]);
    const sid = await findSessionLeafByPreview(page, "round-detail-tabs-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    // 合并入口: 仅一个 detail 按钮, 原独立 info / raw 按钮不再存在.
    await expect(page.locator("#detail .tl-actions button[data-action='detail']")).toHaveCount(1);
    await expect(page.locator("#detail .tl-actions button[data-action='info']")).toHaveCount(0);
    await expect(page.locator("#detail .tl-actions button[data-action='raw']")).toHaveCount(0);

    // 打开 → 概览 tab 默认激活, 完整数据 pane 隐藏.
    await page.locator("#detail .tl-actions button[data-action='detail']").click();
    const dlg = page.locator("dialog.round-dialog");
    await expect(dlg).toBeVisible();
    await expect(dlg.locator(".dialog-tab.active[data-tab='overview']")).toHaveCount(1);
    await expect(dlg.locator(".tab-pane[data-pane='overview']")).toBeVisible();
    await expect(dlg.locator(".tab-pane[data-pane='detail']")).toBeHidden();

    // 概览补全: meta 请求到达后 Model 行是请求的 model 值 (sendChat 默认
    // test-model-abc). M1 走查回归: 历史 "Model 恒 (unknown)" 缺陷同判.
    await expect(dlg).toContainText("test-model-abc", { timeout: 5000 });
    // 概览不含大数据: 请求 body marker 不出现在概览 pane (只会在完整数据 tab).
    const overviewText = await dlg.locator(".tab-pane[data-pane='overview']").textContent();
    expect(overviewText, "概览 tab 不应包含请求 body 大数据").not.toContain("round-detail-tabs-marker");
    // 概览期间网络: 只有 view=meta 小请求 (拉完整 record = 违反 UI-9 按需约束).
    expect(recordViews, "概览阶段只应发 view=meta 请求").toEqual(["meta"]);

    // 切到完整数据 tab → 懒拉完整 record, 原 raw 弹窗内容 (headers + bodies).
    await dlg.locator(".dialog-tab[data-tab='detail']").click();
    await expect(dlg.locator(".tab-pane[data-pane='detail']")).toBeVisible();
    await expect(dlg.locator(".tab-pane[data-pane='overview']")).toBeHidden();
    // 懒拉是异步的: 用 auto-retry 断言等加载完成 (而非立即读 Loading… 占位).
    await expect(dlg.locator(".tab-pane[data-pane='detail']")).toContainText("Request Body", { timeout: 5000 });
    const detailText = await dlg.locator(".tab-pane[data-pane='detail']").textContent();
    expect(detailText).toContain("Request Body");
    expect(detailText).toContain("Response Body");
    expect(detailText).toContain("Request Headers");
    // req_body 应含发送的 marker.
    expect(detailText).toContain("round-detail-tabs-marker");
    expect(recordViews).toEqual(["meta", "raw"]);

    // 反复切换不重复拉取 (rawLoadedFor 复用; 仍只有一次完整拉取).
    await dlg.locator(".dialog-tab[data-tab='overview']").click();
    await dlg.locator(".dialog-tab[data-tab='detail']").click();
    await expect(dlg.locator(".tab-pane[data-pane='detail']")).toBeVisible();
    expect(recordViews, "已加载的完整数据 pane 复用, 不重复拉取").toEqual(["meta", "raw"]);
    // 关闭.
    await dlg.locator(".dialog-close").click();
  });

  // 失败轮 "感叹号" 路径 (quant#305): 轮次 header 的 ERR 状态文本 (status-err)
  // 可点击 → 打开轮次详情概览, 失败状态 (502) 与 method/path 等元数据可见.
  test("失败轮 ERR 状态点击 → 轮次详情概览 (quant#305 感叹号路径)", async ({ page }) => {
    await sendChat(page, [{ role: "user", content: "err-detail-marker trigger-502" }]);
    const sid = await findSessionLeafByPreview(page, "err-detail-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    // timeline 轮次 header 的 status (statusClass: resp_status>=400 → status-err).
    const roundStatus = page.locator("#detail .tl-round-header .status-err").first();
    await expect(roundStatus).toHaveText("502");

    // 点击 ERR → 轮次详情弹窗打开且落在概览 tab.
    await roundStatus.click();
    const dlg = page.locator("dialog.round-dialog");
    await expect(dlg).toBeVisible();
    await expect(dlg.locator(".dialog-tab.active[data-tab='overview']")).toHaveCount(1);
    // 概览展示失败轮自身的元数据: meta 补全后的状态行 (502) 与 method.
    await expect(dlg).toContainText("502", { timeout: 5000 });
    await expect(dlg).toContainText("POST", { timeout: 5000 });
    await dlg.locator(".dialog-close").click();
  });

  // meta 拉取失败路径: 概览的 meta 依赖字段不得停留 "(loading…)" 占位 —
  // 必须转为失败文案 (关闭重开可重试), 否则用户面对 "永久加载中" 的误导.
  test("meta 拉取失败: 概览 meta 依赖字段显示失败文案 (不留永久 loading)", async ({ page }) => {
    await sendChat(page, [{ role: "user", content: "meta-fail-marker" }]);
    const sid = await findSessionLeafByPreview(page, "meta-fail-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    // 拦截 meta 请求 → 网络错误 (仅 meta 档, 完整数据档不受影响).
    await page.route("**/api/records/*?view=meta", (route) => route.abort());
    await page.locator("#detail .tl-actions button[data-action='detail']").click();
    const dlg = page.locator("dialog.round-dialog");
    await expect(dlg).toBeVisible();
    // Method 行从 "(loading…)" 转为失败文案 (raw.failedLoad).
    await expect(dlg.locator(".tab-pane[data-pane='overview']")).toContainText(
      "Failed to load record.",
      { timeout: 5000 }
    );
    // 本地字段照常 (role/kind 等不受 meta 失败影响).
    await expect(dlg.locator(".tab-pane[data-pane='overview']")).toContainText("user");
    await page.unroute("**/api/records/*?view=meta");
    await dlg.locator(".dialog-close").click();
  });

  test("response 单气泡: text + tool_calls 在同一气泡内 (子区域区分)", async ({ page }) => {
    // mock upstream 对 "single-bubble" marker 返回 text + tool_calls 混合 response.
    // 验证: text 和 tool_call 在同一个气泡里 (.bubble-tool-call 子区域), 不拆分为多个气泡.
    await sendChat(page, [{ role: "user", content: "single-bubble-marker" }]);
    const sid = await findSessionLeafByPreview(page, "single-bubble-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    // response 抽屉内应只有 1 个 assistant 气泡 (text + tool_call 合并). (issue #36: 抽屉在 #detail-wrap)
    const respBubbles = page.locator("#detail-wrap .response-drawer .chat-bubble");
    await expect(respBubbles).toHaveCount(1);

    // 气泡内应有 .bubble-tool-call 子区域 (tool_call 装饰).
    const toolCallAreas = respBubbles.locator(".bubble-tool-call");
    await expect(toolCallAreas).toHaveCount(1);

    // 子区域应含 tool_call 格式化文本.
    const toolCallText = await toolCallAreas.textContent();
    expect(toolCallText).toContain("lookup");

    // 气泡整体应同时含 text 和 tool_call 内容.
    const fullText = await respBubbles.textContent();
    expect(fullText).toContain("Let me check");
    expect(fullText).toContain("tool_call");
  });

  // ─── I1 显式不变量守卫: timeline 气泡数 == 该轮 IR messages 数 ─────────────
  //
  // AGENTS.md 前端不变量 I1:
  //   "会话详情页 (timeline) 渲染的 Bubble 数量, 必须等于该 Node 对应 HTTP 请求的
  //    IR messages 数组长度."
  //
  // 策略: 发送 N 条 messages (无 system, 避免根节点 system 注入的边界) 作为根节点单轮
  // 会话. 根节点 req_delta = 完整 messages (start=0, 无 system 注入), 故 timeline
  // request-pane 内 bubble 数应严格等于 N. 失败信息直接指向 "I1 违反".
  //
  // 参数化 N ∈ {1, 3, 5}:
  //   N=1: 单 user message (最常见路径).
  //   N=3: user + assistant + user (含 assistant 无源气泡, 验证 assistant 也算 1 个气泡).
  //   N=5: 更长上下文 (确保不是凑巧 1 个).
  for (const N of [1, 3, 5]) {
    test(`I1 守卫: timeline 气泡数 == messages 数组长度 (N=${N})`, async ({ page }) => {
      // 构造 N 条 messages: 交替 user/assistant.
      // 不使用 system 角色 (system 会在根节点被特殊注入, 干扰纯计数语义).
      // N 取奇数 {1,3,5} → 末条天然是 user.
      // marker 放在**末条** user:
      //   node event.preview = 最后一条 user msg (issue #27),
      //   session 标题 = 根 node 的 preview (issue #36),
      //   故 sidebar 会话条目显示的文本 = 末条 user = marker → 可定位会话.
      const marker = `i1-guard-n${N}-marker`;
      const messages: Array<Record<string, unknown>> = [];
      for (let i = 0; i < N; i++) {
        const role = i % 2 === 0 ? "user" : "assistant";
        // 末条 user 用 marker; 其它条目用 role+index 文本避免与 marker 冲突.
        const content = i === N - 1 ? marker : `${role}-msg-${i}`;
        messages.push({ role, content });
      }

      await sendChat(page, messages);

      const sid = await findSessionLeafByPreview(page, marker);
      await clickSessionByLeaf(page, sid);

      // I1 断言: request-pane 内气泡数 == messages 数组长度.
      // (assistant tool_calls 合并进单气泡; 这里 assistant 仅含 content, 1:1 映射.)
      // 用 expect.toHaveCount 做条件等待 (替代固定 sleep): 气泡 DOM 在 timeline 渲染时
      // 已全部创建, toHaveCount 会 auto-retry 到达到 N 个或超时.
      await expect(
        page.locator("#detail .request-pane .chat-bubble"),
        `I1 违反: 发送 ${N} 条 messages, 期望 ${N} 个气泡`
      ).toHaveCount(N);
    });
  }

  // ─── UI-1 retry 守卫: 相同请求重发不捏造用户消息 ─────────────────────────
  //
  // UI-1 精确化 (2026-08-26): 空 delta 轮的渲染语义按 round_kind 分发:
  //   round_kind=retry (客户端字节级重发, 用户没有发新消息) → retry 徽章, 0 消息气泡.
  //
  // 历史 bug: 前端 fallback 把空 delta 渲染为 preview user 气泡 → N 次重发在 timeline
  // 上呈现为 "用户把同一句话说了 N 遍" — 捏造事实. 重试合并到同会话的语义保留
  // (用户裁决), 仅修展示.
  test("UI-1 retry 守卫: 相同请求重发 → 1 会话 2 轮, 仅 1 个 user 气泡 + retry 徽章", async ({
    page,
  }) => {
    const marker = "ui1-retry-guard-marker";
    const messages = [{ role: "user", content: marker }];

    // 两次字节级相同的请求: 第二次全前缀命中 (split_at == len, delta 空)
    // → 同一 session 延续 (重试合并), round_kind=retry.
    await sendChat(page, messages);
    await sendChat(page, messages);

    const sid = await findSessionLeafByPreview(page, marker);
    await clickSessionByLeaf(page, sid);

    // 轮次数 == 2: 重试不拆 session (每次真实转发都是可审计的一轮, I2 语义).
    await expect(page.locator("#detail .tl-round")).toHaveCount(2);

    // 消息气泡仅 1 个: 重试轮渲染徽章而非捏造用户消息 (UI-1 核心断言).
    await expect(page.locator("#detail .request-pane .chat-bubble")).toHaveCount(1);

    // retry 徽章恰好 1 个 (第二轮), 文本含 "retry".
    const badge = page.locator("#detail .retry-badge");
    await expect(badge).toHaveCount(1);
    await expect(badge).toContainText("retry");

    // sidebar: 同 session 2 个条目 (I2), retry 轮带 ↻ 前缀 (消除与原轮的 preview 歧义).
    const roundList = page.locator(`.round-list[data-sid="${sid}"]`);
    await expect(roundList.locator(".round-item")).toHaveCount(2);
    await expect(roundList.locator(".round-item", { hasText: "↻" })).toHaveCount(1);

    // 选中 retry 轮 (末轮): 0 气泡是常态输入, 布局应优雅降级 (选中态迁移 + 无异常,
    // drawer 不因 selectedBubbleBottomVp=null 崩溃) — UI-1 retry 变体守卫.
    await selectLastRoundAfterToggle(page);
    await expect(page.locator("#detail .tl-round.selected .retry-badge")).toHaveCount(1);

    // header userCount 过滤 retry: 2 轮但只有 1 条真实用户消息 (retry 不是新用户输入).
    // (renderTimeline 写 #detail > .detail-header: "Timeline (N rounds, M user)".)
    await expect(page.locator("#detail > .detail-header")).toContainText("Timeline (2 rounds, 1 user)");
  });

  // ─── I2 显式不变量守卫: sidebar (round-item + sub-dot) 总数 == HTTP 请求数 ──
  //
  // AGENTS.md 前端不变量 I2:
  //   "左边栏每个一级条目 (Session) 下, 二级 + 三级条目总数, 必须等于归属该 Session 的
  //    HTTP 请求数 (即 DAG 中以该 Session 叶子为终点的链上 Node 数)."
  //
  // 策略: 单会话多轮 (M 次 HTTP 请求链成同一 Session). 每轮 req_delta 含 user → 全部
  // 作为二级条目 (.round-item), 无三级 (.sub-dot). 故 round-item 数 == M == HTTP 请求数.
  test("I2 守卫: sidebar round-item + sub-dot 总数 == HTTP 请求数 (M=3)", async ({
    page,
  }) => {
    // 三次累积请求 (prefix hash 链成同一会话):
    //   轮1: [u1]                          → delta=[u1],            user round
    //   轮2: [u1, a1, u2]                  → delta=[a1, u2],        user round (含 u2)
    //   轮3: [u1, a1, u2, a2, u3]          → delta=[a2, u3],        user round (含 u3)
    const M = 3;
    const u1 = "i2-guard-root-marker";
    await sendChat(page, [{ role: "user", content: u1 }]);
    await sendChat(page, [
      { role: "user", content: u1 },
      { role: "assistant", content: "i2-reply-1" },
      { role: "user", content: "i2-guard-round2" },
    ]);
    await sendChat(page, [
      { role: "user", content: u1 },
      { role: "assistant", content: "i2-reply-1" },
      { role: "user", content: "i2-guard-round2" },
      { role: "assistant", content: "i2-reply-2" },
      { role: "user", content: "i2-guard-round3" },
    ]);

    // session-item preview = 根 node 的 preview (issue #36) = 根轮最后一条 user msg
    // (issue #27). 轮1 只有 [u1], 首末 user 都是 u1 → preview = u1 → 可定位会话.
    const sid = await findSessionLeafByPreview(page, u1);
    await clickSessionByLeaf(page, sid);

    // 该 session 的 round-list 内 round-item + sub-dot 总数应 == HTTP 请求数 M.
    // sid 是 uuid 字符集 [-0-9a-f], 全部为 CSS 标识符安全字符, 无需 CSS.escape 转义.
    // 先用 expect.toHaveCount 做条件等待 (替代固定 sleep): renderRounds 异步填充 round-list,
    // 每轮都含 user → 全部是 round-item (无 sub-dot). 等 round-item 数稳定到 M.
    const roundList = page.locator(`.round-list[data-sid="${sid}"]`);
    await expect(
      roundList.locator(".round-item"),
      `I2: round-list 未渲染出 ${M} 个 round-item`
    ).toHaveCount(M);

    // I2 总数断言 (round-item + sub-dot == HTTP 请求数 M).
    const roundItems = await roundList.locator(".round-item").count();
    const subDots = await roundList.locator(".sub-dot").count();
    const total = roundItems + subDots;
    expect(
      total,
      `I2 违反: 发送 ${M} 次 HTTP 请求, 但 sidebar round-item(${roundItems}) + sub-dot(${subDots}) = ${total}`
    ).toBe(M);
  });

  // ─── I3 显式不变量守卫: timeline 轮次 DOM 顺序 == 数据顺序 (oldest-first) ──
  //
  // AGENTS.md 前端不变量 I3:
  //   "DOM 中 .tl-round 的顺序必须与 state.timelineRecords 完全一致 (oldest-first,
  //    顶部最老, 底部最新)."
  //
  // 策略: 单会话 3 轮 (同 I2 的累积上下文模式, 每轮 delta 含独特 user marker).
  //   - 每轮的 user marker 出现在该轮的 request-pane 内 (assistant 气泡来自前轮 response).
  //   - 验证 #detail > .tl-round 序列里, 各轮 user marker 按 [r1, r2, r3] 的发送顺序出现.
  // 覆盖: 初次 loadTimeline → renderTimeline → reconcile (append 路径).
  //   未覆盖 prepend (loadOlder) / replace (会话切换) / 乱序自愈 — 留作后续.
  test("I3 守卫: timeline 轮次 DOM 顺序 == 数据顺序 (oldest-first)", async ({ page }) => {
    const u1 = "i3-guard-root-marker";
    // 轮1: [u1]
    await sendChat(page, [{ role: "user", content: u1 }]);
    // 轮2: delta=[a1, u2], user marker = u2
    await sendChat(page, [
      { role: "user", content: u1 },
      { role: "assistant", content: "i3-reply-1" },
      { role: "user", content: "i3-round2-marker" },
    ]);
    // 轮3: delta=[a2, u3], user marker = u3
    await sendChat(page, [
      { role: "user", content: u1 },
      { role: "assistant", content: "i3-reply-1" },
      { role: "user", content: "i3-round2-marker" },
      { role: "assistant", content: "i3-reply-2" },
      { role: "user", content: "i3-round3-marker" },
    ]);

    const sid = await findSessionLeafByPreview(page, u1);
    await clickSessionByLeaf(page, sid);

    // 等 timeline 渲染出 3 轮 (条件等待, 替代固定 sleep).
    await expect(page.locator("#detail > .tl-round")).toHaveCount(3);

    // 收集每轮的 user 文本 (按 DOM 顺序).
    // 每轮 request-pane 内的 user 气泡 (bubble-user) 含该轮的 user marker.
    // 注意: 轮1 的 user 气泡 = u1 (会话标题 marker), 轮2 = i3-round2-marker, 轮3 = i3-round3-marker.
    const roundEls = await page.locator("#detail > .tl-round").all();
    expect(roundEls.length, "应有 3 个 .tl-round").toBe(3);

    const domOrderUsers: string[] = [];
    for (const el of roundEls) {
      // 每轮取最后一条 user 气泡的文本 (本轮新增的 user, 历史轮次的 user 也可能在 delta 里,
      // 但本测试每轮 delta 只新增最后一条 user — 见上面累积构造).
      const userBubbles = el.locator(".request-pane .bubble-user");
      const count = await userBubbles.count();
      if (count === 0) {
        domOrderUsers.push("<no-user>");
        continue;
      }
      const lastUserText = await userBubbles.last().textContent();
      domOrderUsers.push((lastUserText || "").trim());
    }

    // I3 断言: DOM 顺序应与发送顺序一致 [u1, round2-marker, round3-marker].
    const expected = [u1, "i3-round2-marker", "i3-round3-marker"];
    expect(
      domOrderUsers,
      `I3 违反: timeline DOM 轮次顺序错乱. 期望 (oldest-first) ${JSON.stringify(expected)}, 实际 ${JSON.stringify(domOrderUsers)}`
    ).toEqual(expected);
  });

  // ─── 错误状态渲染: 上游 502/429 时 WebUI 不崩溃 + record 可见 ──────────────
  //
  // mock_upstream.py 对 "trigger-502" / "trigger-429" marker 返回相应错误码.
  // 验证: (a) WebUI 不崩溃, record 出现在 sidebar 且 status 文本为错误码 (status-err class);
  //       (b) 选中会话后 timeline 轮次 header 也有错误状态标记;
  //       (c) 错误后页面仍可交互 — 再发一个正常请求, 正常 record 能渲染.
  test("错误状态渲染: 上游 502 时 sidebar 显示 502 状态 + 页面不崩溃", async ({
    page,
  }) => {
    // 发送触发 502 的请求 (sendChat 不检查响应状态, 返回 response 对象).
    await sendChat(page, [{ role: "user", content: "err-502-guard-marker trigger-502" }]);

    // sidebar 会话应出现, 且 status 文本为 "502" (sessionStatusText: latest_resp_status>=400 → 该数字).
    const item = page
      .locator(".session-item", { hasText: "err-502-guard-marker" })
      .first();
    await item.waitFor({ state: "visible", timeout: 5000 });
    // session 状态 span (class status-err) 应含 "502".
    const statusSpan = item.locator(".status-err").first();
    await expect(statusSpan).toHaveText("502");

    // 选中会话 → timeline 加载, 页面不崩溃 (request-pane 出现).
    const sid = await item.getAttribute("data-sid");
    expect(sid).toBeTruthy();
    await page.locator(`.session-item[data-sid="${sid}"]`).click();
    await page.waitForSelector("#detail .request-pane", { timeout: 3000 });

    // timeline 轮次 header 的 status 也应是 502 (statusClass: resp_status>=400 → status-err).
    // 用 expect.toHaveText 做条件等待 (替代固定 sleep): 等渲染完成.
    const roundStatus = page.locator("#detail .tl-round .status-err").first();
    await expect(roundStatus).toHaveText("502");

    // 页面仍可交互: 再发一个正常请求, 验证新 record 正常渲染.
    await sendChat(page, [{ role: "user", content: "err-502-recovery-marker" }]);
    const recoveryItem = page
      .locator(".session-item", { hasText: "err-502-recovery-marker" })
      .first();
    await recoveryItem.waitFor({ state: "visible", timeout: 5000 });
    // 正常请求的 status 应是 200 (status-ok).
    await expect(recoveryItem.locator(".status-ok").first()).toHaveText("200");
  });

  test("错误状态渲染: 上游 429 时 sidebar 显示 429 状态", async ({ page }) => {
    await sendChat(page, [{ role: "user", content: "err-429-guard-marker trigger-429" }]);
    const item = page
      .locator(".session-item", { hasText: "err-429-guard-marker" })
      .first();
    await item.waitFor({ state: "visible", timeout: 5000 });
    await expect(item.locator(".status-err").first()).toHaveText("429");
  });

  // ─── Drawer 相位回归 (bug: phase 4 过早触发 + phase 1 跳变) ──────────────
  //
  // DRAWER_GAP 与 src/web/index.html 生产常量同值, 此处为测试内部 SSOT (供 drawer 相位 +
  // UI-6 follow/pinned 测试共用, 避免散落多 test 各声明).
  const DRAWER_GAP = 28;

  test("drawer phase 3 holds maxH before content enters drawer zone", async ({ page }) => {
    // bug #1 回归: 向下滚, 气泡滚出顶部后 drawer 应保持 maxH (40%),
    // 直到末轮底部真正进入抽屉遮挡区域才开始 phase 4 渐进扩展.
    //
    // 注: 本测试只对长内容有意义 (contentEnd > wrapH 才能真正滚出顶). UI-6 闭合不变量
    // 修复后, 短内容场景的 placeholder 行为有变化 (follow 路径撑 placeholder), 故显式
    // skip 短内容 (与 UI-6 其它 pinned 测试一致用 contentScrollRange 作 skip 条件).
    const reply = "This is a long response for testing the typing box. ".repeat(15);
    const sys = "You are a coding assistant. ".repeat(5);
    // 3 轮长内容会话
    await sendChat(page, [{ role: "system", content: sys }, { role: "user", content: "phase3-hold-marker" }, { role: "assistant", content: reply }]);
    await sendChat(page, [{ role: "system", content: sys }, { role: "user", content: "phase3-hold-marker" }, { role: "assistant", content: reply }, { role: "user", content: "second" }, { role: "assistant", content: reply }]);
    await sendChat(page, [{ role: "system", content: sys }, { role: "user", content: "phase3-hold-marker" }, { role: "assistant", content: reply }, { role: "user", content: "second" }, { role: "assistant", content: reply }, { role: "user", content: "third" }, { role: "assistant", content: reply }]);
    const leaf = await findSessionLeafByPreview(page, "phase3-hold-marker");
    await clickSessionByLeaf(page, leaf);
    await page.waitForTimeout(500);
    // 短内容 (bubble 折叠后 contentEnd ≤ wrapH) 跳过: phase 3 的 drawer 行为只在长内容下有意义.
    const scrollRange = await contentScrollRange(page);
    test.skip(scrollRange <= 200, "content too short (bubble collapsed) to test phase 3");
    // 选中 round 1 (最靠上, 向下滚能把它推出视口)
    const round1 = page.locator("#detail .tl-round").first();
    await round1.locator(".tl-round-header").click();
    await page.waitForTimeout(1200);

    // 持续向下滚, 在气泡离开视口后检查 drawer 是否保持 ≤ maxH + 2px 容差
    const detail = page.locator("#detail");
    let breached = false;
    for (let i = 0; i < 40; i++) {
      await page.mouse.wheel(0, 20);
      await page.waitForTimeout(60);
      const m = await page.evaluate(() => {
        const d = document.getElementById('detail')!;
        const w = document.getElementById('detail-wrap')!;
        const wrapTop = w.getBoundingClientRect().top;
        const selRound = document.querySelector('#detail .tl-round.selected');
        let bby: number | null = null;
        if (selRound) {
          const bubbles = selRound.querySelectorAll('.request-pane .chat-bubble');
          if (bubbles.length > 0) bby = bubbles[bubbles.length - 1].getBoundingClientRect().bottom - wrapTop;
        }
        return {
          scrollTop: d.scrollTop,
          drawerPct: document.getElementById('response-drawer')!.offsetHeight / w.clientHeight,
          bubbleBottomY: bby,
        };
      });
      // 气泡已离开视口 (bby <= 0) 且 scrollTop 还在 phase 3 区间 → drawer 应 ≤ 42% (maxH + 2px)
      if (m.bubbleBottomY !== null && m.bubbleBottomY <= 0 && m.drawerPct > 0.42) {
        breached = true;
        break;
      }
    }
    expect(breached).toBe(false);
  });

  test("drawer phase 1 stays at minH (no jump to defaultH)", async ({ page }) => {
    // bug #2 回归: 向上滚到选中气泡离开视口底部后, drawer 应保持 minH (10%),
    // 不跳回 defaultH (30%).
    const reply = "This is a long response for testing the typing box. ".repeat(15);
    const sys = "You are a coding assistant. ".repeat(5);
    await sendChat(page, [{ role: "system", content: sys }, { role: "user", content: "phase1-jump-marker" }, { role: "assistant", content: reply }]);
    await sendChat(page, [{ role: "system", content: sys }, { role: "user", content: "phase1-jump-marker" }, { role: "assistant", content: reply }, { role: "user", content: "second" }, { role: "assistant", content: reply }]);
    await sendChat(page, [{ role: "system", content: sys }, { role: "user", content: "phase1-jump-marker" }, { role: "assistant", content: reply }, { role: "user", content: "second" }, { role: "assistant", content: reply }, { role: "user", content: "third" }, { role: "assistant", content: reply }]);
    const leaf = await findSessionLeafByPreview(page, "phase1-jump-marker");
    await clickSessionByLeaf(page, leaf);
    await page.waitForTimeout(500);
    // 选中 round 2 (中间, 向上滚到顶能把它推出视口底部)
    const round2 = page.locator("#detail .tl-round").nth(1);
    await round2.locator(".tl-round-header").click();
    await page.waitForTimeout(1200);

    // 向上滚到顶
    for (let i = 0; i < 30; i++) {
      await page.mouse.wheel(0, -30);
      await page.waitForTimeout(50);
    }
    await page.waitForTimeout(300);

    const m = await page.evaluate(() => {
      const w = document.getElementById('detail-wrap')!;
      const wrapTop = w.getBoundingClientRect().top;
      const wrapH = w.clientHeight;
      const selRound = document.querySelector('#detail .tl-round.selected');
      let bby: number | null = null;
      if (selRound) {
        const bubbles = selRound.querySelectorAll('.request-pane .chat-bubble');
        if (bubbles.length > 0) bby = bubbles[bubbles.length - 1].getBoundingClientRect().bottom - wrapTop;
      }
      return {
        drawerPct: document.getElementById('response-drawer')!.offsetHeight / wrapH,
        bubbleBottomY: bby,
        wrapH,
      };
    });

    // 气泡在视口下方 (phase 1) → drawer 应 ≈ minH (10%), 不跳回 defaultH (30%)
    if (m.bubbleBottomY !== null && m.bubbleBottomY >= m.wrapH) {
      expect(m.drawerPct).toBeLessThanOrEqual(0.12);
    }
  });

  test("drawer covers placeholder when scrolling to bottom (last round selected)", async ({
    page,
  }) => {
    // bug #3 回归: 末轮选中时 bubbleBottomY 永远 > 0 (末轮紧邻 placeholder,
    // maxScroll 不足以让末轮气泡滚出顶部), 旧 phase 4 门槛 (bby<=0) 永远不满足,
    // drawer 被 phase 2 的 clamp 封顶在 maxH (40%), placeholder 大片空白被露出.
    //
    // 修复: phase 4 改用 placeholderExposed (placeholder DOM 在视口内的可见高度)
    // 作为驱动, 与 bubbleBottomY 解耦. 滚到底时 drawer 必须扩展到 ≥ placeholder
    // 露出高度, 完全遮挡 placeholder.
    await setupLongChatSelectRound(page, "bug3-marker", 2 /* 末轮 */);

    // 滚到最底 (maxScroll), 等待 scroll 事件的 RAF 回调触发 layout 更新, 再采样
    const m = await page.evaluate(async () => {
      const d = document.getElementById("detail")!;
      const w = document.getElementById("detail-wrap")!;
      const wrapH = w.clientHeight;
      const drawer = document.getElementById("response-drawer")!;
      const ph = document.querySelector("#detail > .drawer-placeholder") as HTMLElement;
      // 滚到底
      d.scrollTop = d.scrollHeight - d.clientHeight;
      // 等待 scroll 事件 + RAF 触发 updateResponseDrawerLayout (异步); 双 RAF 确保 layout 已应用
      const nextFrame = () => new Promise<void>((r) => requestAnimationFrame(() => r()));
      await nextFrame();
      await nextFrame();
      // placeholder DOM 在视口内的可见高度
      const phTop = ph?.offsetTop ?? 0;
      const phH = ph?.offsetHeight ?? 0;
      const viewportBottom = d.scrollTop + wrapH;
      const placeholderExposed = Math.max(0, Math.min(phH, viewportBottom - phTop));
      return {
        wrapH,
        scrollTop: d.scrollTop,
        maxScroll: d.scrollHeight - d.clientHeight,
        drawerH: drawer.offsetHeight,
        drawerPct: drawer.offsetHeight / wrapH,
        placeholderH: phH,
        placeholderExposed,
      };
    });

    // 必须能滚 (内容足够长, placeholder 存在)
    expect(m.placeholderH).toBeGreaterThan(0);
    expect(m.maxScroll).toBeGreaterThan(100);
    // drawer 覆盖 placeholder, 但顶部让出 DRAWER_GAP (~28px) 作呼吸空间 (WebUI 反馈3:
    // 末轮 request 与 drawer 上边缘的视觉间距). 即 drawerH >= placeholderExposed - GAP - 容差(4px).
    // 残余 GAP 截是白底 placeholder 顶部, 作为呼吸空间可见 (可接受, 非空白泄漏).
    expect(m.drawerH).toBeGreaterThanOrEqual(m.placeholderExposed - DRAWER_GAP - 4);
    // 滚到底时 drawer 应接近 extremeMaxH (80%), 而非被封顶在 maxH (40%)
    expect(m.drawerPct).toBeGreaterThan(0.7);
  });

  test("drawer phase 4 transitions smoothly (no sudden jump 40% → 80%)", async ({
    page,
  }) => {
    // bug #3 伴生回归 (中间轮场景): 选中**非末轮**时, 旧 phase 4 门槛 (bby<=0) 能被
    // 满足 (中间轮气泡可滚出顶部), 但 phase4Start = contentEnd - wrapH + maxH 比对应
    // placeholder 实际露出的 scrollTop 晚 maxH 距离. 这导致:
    //   - placeholder 已开始露出, drawer 仍 = maxH (phase 3 平台)
    //   - 到 phase4Start 时 drawer 才开始扩大, 但用户感知是 "滞后 + 突然加速"
    //   - 极端情况下若 phase4Range 很小, 视觉上就是 "40% → 80% 跳变"
    //
    // 修复后: placeholderExposed 从 0 开始线性增长, drawer 立即跟随, 无滞后无跳变.
    //
    // 选中间轮 (roundIdx=1) 让旧 phase 4 路径真正可触发, 测试才有区分性
    // (末轮场景旧 phase 4 根本进不去, 无法检验 "平滑过渡").
    await setupLongChatSelectRound(page, "bug3-smooth-marker", 1 /* 中间轮 */);

    // 以固定步长采样整条曲线, 双 RAF 确保每次采样前 layout 已应用
    const samples = await page.evaluate(async () => {
      const d = document.getElementById("detail")!;
      const w = document.getElementById("detail-wrap")!;
      const wrapH = w.clientHeight;
      const drawer = document.getElementById("response-drawer")!;
      const maxScroll = d.scrollHeight - d.clientHeight;
      const out: Array<{ st: number; drawerPct: number }> = [];
      const nextFrame = () =>
        new Promise<void>((r) => requestAnimationFrame(() => r()));
      for (let st = 0; st <= maxScroll; st += 20) {
        d.scrollTop = st;
        await nextFrame();
        await nextFrame();
        out.push({ st, drawerPct: drawer.offsetHeight / wrapH });
      }
      return out;
    });

    expect(samples.length).toBeGreaterThan(5);
    // 相邻样本 (20px scrollTop 步长) 的 drawerPct 跳变应 ≤ 8%.
    // 修复前的滞后 + 突变会在某一步出现大跳变 (远超 8%), 修复后全程平滑.
    // 注: 阈值留足余量 — phase 2 clamp 段斜率约 3.8% (20px / 530px), 加测量噪声.
    let maxJump = 0;
    let maxJumpAt = -1;
    for (let i = 1; i < samples.length; i++) {
      const jump = Math.abs(samples[i].drawerPct - samples[i - 1].drawerPct);
      if (jump > maxJump) {
        maxJump = jump;
        maxJumpAt = i;
      }
    }
    // 诊断信息: 失败时打印最大跳变位置, 便于定位 phase 边界
    if (maxJump >= 0.08) {
      const prev = samples[maxJumpAt - 1];
      const curr = samples[maxJumpAt];
      console.error(
        `max jump ${maxJump.toFixed(3)} at sample ${maxJumpAt}: st=${prev.st}→${curr.st}, drawer ${(prev.drawerPct * 100).toFixed(1)}%→${(curr.drawerPct * 100).toFixed(1)}%`
      );
    }
    expect(maxJump).toBeLessThan(0.08);
  });

  // ─── UI-4 / UI-5 property 补全 ───────────────────────────────────────
  //
  // 守卫 contracts.md 中标 ⏳ 的 property, 补齐 keyed reconciliation + drawer 的不变量.

  test("UI-5 prop_detail_height_fixed: #detail height 不随 drawerH 变化", async ({
    page,
  }) => {
    // #detail-wrap 占满 wrap (height=100%), #detail flex:1. drawer 是 overlay
    // (position:absolute), 不影响 #detail 高度. 滚动 #detail 到不同位置,
    // drawer 高度会变 (phase 切换), 但 #detail height 应恒等于 wrapH.
    await setupLongChatSelectRound(page, "ui5-height-marker", 2 /* 末轮 */);

    const measurements = await page.evaluate(async () => {
      const d = document.getElementById("detail")!;
      const w = document.getElementById("detail-wrap")!;
      const drawer = document.getElementById("response-drawer")!;
      const wrapH = w.clientHeight;
      const maxScroll = d.scrollHeight - d.clientHeight;
      const out: Array<{ st: number; detailH: number; drawerH: number }> = [];
      const nextFrame = () =>
        new Promise<void>((r) => requestAnimationFrame(() => r()));
      // 采样: 顶 / 中 / 底 三处 (drawer 处于不同 phase).
      for (const ratio of [0, 0.5, 1]) {
        d.scrollTop = Math.floor(ratio * maxScroll);
        await nextFrame();
        await nextFrame();
        out.push({
          st: d.scrollTop,
          detailH: d.clientHeight,
          drawerH: drawer.offsetHeight,
        });
      }
      return { wrapH, out };
    });

    // 核心断言: detailH 恒等于 wrapH, 不随 drawerH 变化.
    for (const m of measurements.out) {
      expect(m.detailH).toBe(measurements.wrapH);
    }
    // 同时验证 drawerH 确实在变 (否则上面断言无区分性, 假绿).
    const drawerHeights = measurements.out.map((m) => m.drawerH);
    const drawerRange = Math.max(...drawerHeights) - Math.min(...drawerHeights);
    expect(drawerRange).toBeGreaterThan(10);
  });

  test("UI-4 prop_reconcile_preserves_bubble_expand_state: 展开气泡跨刷新保留", async ({
    page,
  }) => {
    // 自动刷新 (3s 间隔) 触发 reconcileTimelineRounds. keyed reconciliation
    // 按 data-rid 匹配新旧 .tl-round, 公共节点的 DOM 完全保留, 包括 .expanded class.
    //
    // 触发链: 选中末轮 → 气泡默认 collapsed → 手动点 toggle 进 expanded →
    // 等一次自动刷新 → 断言 .expanded class 仍在.
    await setupLongChatSelectRound(page, "ui4-expand-marker", 2 /* 末轮 */);

    // 找一个 .chat-bubble.collapsed (长内容才会被折叠, setupLongChatSelectRound 的
    // 3000 字符 'x' 内容足够触发). 切到 expanded.
    // 用 .chat-bubble 作 selector (无 collapsed 限定), 后续操作不会因 class 切换而失联.
    const bubble = page.locator("#detail .chat-bubble").first();
    await bubble.waitFor({ state: "visible", timeout: 3000 });
    // 先确认它初始是 collapsed (即长内容, 有 toggle 按钮).
    await expect(bubble).toHaveClass(/collapsed/);
    // 直接改 class (不点击): 测试目标是 reconcile 保留 expanded, 而非 toggle 点击 UX.
    await bubble.evaluate((el) => {
      el.classList.replace("collapsed", "expanded");
    });
    await expect(bubble).toHaveClass(/expanded/);

    // 等 2 轮自动刷新 (间隔 3s, 保守等 7s).
    await page.waitForTimeout(7000);

    // 断言: 气泡仍是 expanded (reconcile 没把它打回 collapsed).
    await expect(bubble).toHaveClass(/expanded/);
  });

  test("UI-4 prop_reconcile_correct_for_all_change_modes: 切换会话 (完全不同) 后再切回 (replace) 保持 DOM", async ({
    page,
  }) => {
    // 覆盖 keyed reconciliation 的 "完全不同" 变动模式:
    // 切到另一个会话 → timelineRecords 完全替换 → 旧 .tl-round 全部移除, 新的全部插入.
    // 再切回原会话 → 又一次完全替换. 这两步都应正确渲染, 不残留旧 DOM.
    //
    // append 模式已由 I3 守卫, replace 模式已由 "需求 4" 间接覆盖, 这里补 "完全不同".
    //
    // 准备两个独立会话 (各自单轮, prefix hash 不同 → 不同 session).
    const markerA = "reconcile-abort-A-9f3c7e1d";
    const markerB = "reconcile-abort-B-2a8b4c6f";
    await sendChat(page, [
      { role: "user", content: markerA },
      { role: "assistant", content: "reply from session A" },
    ]);
    await sendChat(page, [
      { role: "user", content: markerB },
      { role: "assistant", content: "reply from session B" },
    ]);

    const sidA = await findSessionLeafByPreview(page, markerA);
    const sidB = await findSessionLeafByPreview(page, markerB);

    // 切到 A, 验证内容正确.
    await clickSessionByLeaf(page, sidA);
    await expect(page.locator("#detail .request-pane")).toContainText(markerA);
    const roundsInA = await page.locator("#detail .tl-round").count();

    // 切到 B (完全不同模式): A 的 DOM 应全部被替换为 B 的.
    // 注: clickSessionByLeaf 等待条件是 .request-pane 出现, 但切前 A 也有 request-pane,
    // 故等待会立即返回. 用 expect.poll 轮询直到 B 的 marker 真正出现.
    await clickSessionByLeaf(page, sidB);
    await expect
      .poll(async () => {
        const text = await page.locator("#detail .request-pane").textContent();
        return text ?? "";
      })
      .toContain(markerB);
    // A 的 marker 不应残留.
    await expect(page.locator("#detail")).not.toContainText(markerA);

    // 切回 A (再次完全不同): B 应被清掉, A 重新渲染.
    //
    // session-aware sync API 下, toggleSession 对已展开 session 会折叠 (不重 load timeline).
    // 故 "切回 A" 的等价动作: 折叠 A (A 已展开) → 再展开 A (loadTimeline(A) 重新拉).
    // 两次点击 A 的 session-item: 第一次折叠 (expandedSessions.delete), 第二次展开
    // (expandedSessions.add + loadTimeline).
    const sessionA = page.locator(`.session-item[data-sid="${sidA}"]`);
    await sessionA.click();  // 折叠 A (A 当前是 expanded).
    await sessionA.click();  // 展开 A → loadTimeline(A) 重新渲染.
    await expect
      .poll(async () => {
        const text = await page.locator("#detail .request-pane").textContent();
        return text ?? "";
      })
      .toContain(markerA);
    await expect(page.locator("#detail")).not.toContainText(markerB);
    // 轮次数应与首次切到 A 时一致.
    const roundsInAAgain = await page.locator("#detail .tl-round").count();
    expect(roundsInAAgain).toBe(roundsInA);
  });

  // ─── UI-6: timeline 滚动状态机 (follow / pinned) ──────────────────────────
  //
  // AGENTS.md 前端不变量 UI-6:
  //   followMode 是 "视口距底部距离" 的纯派生 (SSOT), 不由 "最近点了什么" 决定.
  //   - follow (距底 ≤ NEAR_BOTTOM_PX): 新 round 到达 → 主动滚到底.
  //   - pinned (距底 >  NEAR_BOTTOM_PX): 新 round 到达 → 不滚动, 浮出 unread badge.
  //
  //   selectedRound 与 followMode 解耦 (方案 X):
  //   - selectedRound 始终是 "用户最后显式关注的轮次", 不随 follow 自动推进.
  //   - 仅 "进入 follow 的显式动作" (点 Session / 点 unread badge) 才重置 selected 到最新轮.

  // UI-6 测试共享的长内容模板 (确保 timeline 总高度 > 视口, follow/pinned 有意义).
  const LONG_SYS = "You are a coding assistant with detailed context. ".repeat(20);
  const LONG_USER = (s: string) => `${s} ${"x".repeat(1500)}`;
  const REPLY = "r".repeat(1500);

  /**
   * 构造累积 N 轮的长内容会话, 返回 session_id (用于 clickSessionByLeaf).
   * 每轮发送完整的累积上下文 (DAG prefix hash 链成同一会话), 第 i 轮的 user 标记为 `round{i}`.
   * marker 作为根轮首条 user msg, 决定 session 标题.
   */
  async function setupLongMultiroundSession(page: Page, marker: string, rounds = 3): Promise<string> {
    for (let i = 1; i <= rounds; i++) {
      const messages: Array<Record<string, unknown>> = [
        { role: "system", content: LONG_SYS },
        { role: "user", content: LONG_USER(marker) },
        { role: "assistant", content: REPLY },
      ];
      for (let j = 2; j <= i; j++) {
        messages.push({ role: "user", content: LONG_USER(`round${j}`) });
        messages.push({ role: "assistant", content: REPLY });
      }
      await sendChat(page, messages);
    }
    return findSessionLeafByPreview(page, marker);
  }

  /** 向已存在的累积会话追加第 N 轮 (N > 当前轮数). */
  async function appendRound(page: Page, marker: string, n: number): Promise<void> {
    const messages: Array<Record<string, unknown>> = [
      { role: "system", content: LONG_SYS },
      { role: "user", content: LONG_USER(marker) },
      { role: "assistant", content: REPLY },
    ];
    for (let j = 2; j <= n; j++) {
      messages.push({ role: "user", content: LONG_USER(`round${j}`) });
      messages.push({ role: "assistant", content: REPLY });
    }
    await sendChat(page, messages);
  }

  /** 等待 timeline 渲染出 N 轮 .tl-round (条件等待). */
  async function waitForRounds(page: Page, n: number): Promise<void> {
    await expect(page.locator("#detail > .tl-round")).toHaveCount(n, { timeout: 5000 });
  }

  /** 进入指定 session 的 timeline 并等到 N 轮渲染完成. */
  async function openTimeline(page: Page, sid: string, rounds: number): Promise<void> {
    await clickSessionByLeaf(page, sid);
    await waitForRounds(page, rounds);
    await page.waitForTimeout(500);
  }

  /** 计算当前 #detail 视口距 "内容底部" (末轮 .tl-round 底部) 的距离 (px).
   *
   * 基于 contentEnd 而非 scrollHeight: #detail 末尾的 .drawer-placeholder 是滚动缓冲
   * (给手动滚动 phase 4 用), 不计入 "内容". 与实现 isNearBottom 的判定基准一致
   * (WebUI bug #3: follow 自动滚动滚到 contentEnd, 不滚入 placeholder).
   * placeholder 区 (滚过 contentEnd) 返回负值 → 视为 "在底部". */
  function distFromBottom(page: Page): Promise<number> {
    return page.locator("#detail").evaluate((el) => {
      // 找末轮 .tl-round (DOM 中最后一个, 不含 placeholder / header).
      const rounds = el.querySelectorAll(":scope > .tl-round");
      let contentEnd = el.scrollHeight; // fallback: 无 round 时用 scrollHeight.
      if (rounds.length > 0) {
        const last = rounds[rounds.length - 1] as HTMLElement;
        contentEnd = last.offsetTop + last.offsetHeight;
      }
      return contentEnd - el.scrollTop - el.clientHeight;
    });
  }

  test("UI-6: 点 Session → follow (滚到底), 无 unread badge", async ({ page }) => {
    // 注: session-aware sync API 下, toggleSession 只 loadTimeline + 滚到底 (follow),
    // 不再显式 selectRound (selectedRound 保持 null). 这是相对旧版的行为变化:
    // 旧版 toggleSession 末尾调 selectRound(leaf, scroll:'bottom') 会设置 selectedRound.
    // 新版认为 "selected" 应是用户显式关注某轮的语义, 进入会话不自动选.
    // 本测试守卫 follow + badge 行为 (与 selected 无关), 不再断言 .selected 位置.
    const sid = await setupLongMultiroundSession(page, "ui5-follow-init-marker");
    await openTimeline(page, sid, 3);

    // follow 状态: 距底 < NEAR_BOTTOM_PX (100px).
    expect(await distFromBottom(page), "初始进入应在底部附近 (follow)").toBeLessThan(100);

    // 无 unread badge (follow 状态 + 0 未读).
    await expect(page.locator("#unread-badge")).toBeHidden();
  });

  /** 把 #detail 滚动到 "内容中部" (pinned 状态), 返回设置后的 scrollTop.
   *
   * 基于末轮 .tl-round 的 contentEnd (不含 .drawer-placeholder 缓冲), 取内容可滚动
   * 范围 [0, contentEnd - clientHeight] 的中点. WebUI bug #3 后 follow/scrollToBottom
   * 基于 contentEnd (placeholder 不计入内容), 故 pinned 模拟也须基于 contentEnd,
   * 否则中点可能落入 placeholder 区. 内容不足以滚动时 (contentEnd <= clientHeight)
   * 返回 0 (顶部). */
  async function scrollToContentMiddle(page: Page): Promise<number> {
    return page.locator("#detail").evaluate((el) => {
      const rounds = el.querySelectorAll(":scope > .tl-round");
      let contentEnd = el.scrollHeight;
      if (rounds.length > 0) {
        const last = rounds[rounds.length - 1] as HTMLElement;
        contentEnd = last.offsetTop + last.offsetHeight;
      }
      const maxContentScroll = Math.max(0, contentEnd - el.clientHeight);
      el.scrollTop = Math.floor(maxContentScroll / 2);
      return el.scrollTop;
    });
  }

  /** 检查 timeline 内容是否足够长 (可滚动). pinned/follow 的滚动语义仅在内容
   *  超出视口时有意义; WebUI bug #3 后短内容无 placeholder, 不进入 pinned.
   *  返回 contentEnd - clientHeight (可滚动距离), <= 0 表示内容不足. */
  async function contentScrollRange(page: Page): Promise<number> {
    return page.locator("#detail").evaluate((el) => {
      const rounds = el.querySelectorAll(":scope > .tl-round");
      let contentEnd = 0;
      if (rounds.length > 0) {
        const last = rounds[rounds.length - 1] as HTMLElement;
        contentEnd = last.offsetTop + last.offsetHeight;
      }
      return contentEnd - el.clientHeight;
    });
  }

  test("UI-6: 手动向上滚 → pinned (距底部 > NEAR_BOTTOM_PX)", async ({ page }) => {
    const sid = await setupLongMultiroundSession(page, "ui5-scroll-up-marker");
    await openTimeline(page, sid, 3);

    // 内容不足以滚动时 skip (pinned 语义仅在长内容下有意义).
    // WebUI bug #3 后 follow/scrollToBottom 基于 contentEnd (不含 placeholder 缓冲),
    // 短内容 (contentEnd <= wrapH) 无 placeholder, 永远 follow, pinned 不可测.
    const scrollRange = await contentScrollRange(page);
    test.skip(scrollRange <= 200, "content too short to test pinned");

    // 向上滚 (滚到内容中部, 距底 > 100px).
    await scrollToContentMiddle(page);
    // 等 scroll 事件 + RAF 触发 syncFollowMode.
    await page.waitForTimeout(300);

    expect(await distFromBottom(page), "向上滚后应距底 > 100px (pinned)").toBeGreaterThan(100);

    // unread badge 仍隐藏 (无新消息, unreadCount=0).
    await expect(page.locator("#unread-badge")).toBeHidden();
  });

  test("UI-6: pinned 状态下新 round 到达 → unread badge 显示 + selected 不变", async ({ page }) => {
    const marker = "ui5-pinned-new-round-marker";
    const sid = await setupLongMultiroundSession(page, marker);
    await openTimeline(page, sid, 3);
    // 注: toggleSession 不再自动 selectRound. 显式选中末轮以建立 selected 态
    // (等价于旧版 toggleSession 末尾的 selectRound(leaf) 副作用).
    const selectedBefore = await selectLastRoundAfterToggle(page);

    // 内容不足以滚动时 skip (pinned 语义仅在长内容下有意义, 见上测试注释).
    const scrollRange = await contentScrollRange(page);
    test.skip(scrollRange <= 200, "content too short to test pinned");

    // 向上滚到内容中部 (pinned), 记录 scrollTop.
    const pinnedScrollTop = await scrollToContentMiddle(page);
    await page.waitForTimeout(300);

    // 发起第 4 轮 (累积上下文, 同一 session).
    await appendRound(page, marker, 4);

    // 等待自动刷新拉到新 round (3s 间隔 + 余量). 用条件等待替代固定 sleep.
    await waitForRounds(page, 4);

    // pinned 状态: scrollTop 应基本不变 (用户没被推走).
    const scrollTopAfter = await page.locator("#detail").evaluate((el) => el.scrollTop);
    expect(
      Math.abs(scrollTopAfter - pinnedScrollTop),
      "pinned 状态下新 round 不应推动 scrollTop"
    ).toBeLessThan(30);

    // unread badge 应显示, 文本含 "1".
    const badge = page.locator("#unread-badge");
    await expect(badge).toBeVisible();
    await expect(badge).toHaveText("↓ 1");

    // selected 不变 (selectedBefore 仍是 DOM 中存在的 .selected).
    const selectedAfter = await page
      .locator("#detail .tl-round.selected")
      .getAttribute("data-rid");
    expect(selectedAfter, "pinned 期间新 round 到达, selected 不应变").toBe(selectedBefore);
  });

  test("UI-6: 点 unread badge → follow + selected 重置到最新轮 + badge 消失", async ({ page }) => {
    const marker = "ui5-badge-click-marker";
    const sid = await setupLongMultiroundSession(page, marker);
    await openTimeline(page, sid, 3);

    // 内容不足以滚动时 skip (pinned 语义仅在长内容下有意义, 见上测试注释).
    const scrollRange = await contentScrollRange(page);
    test.skip(scrollRange <= 200, "content too short to test pinned");

    // 向上滚到 pinned (内容中部).
    await scrollToContentMiddle(page);
    await page.waitForTimeout(300);

    // 发第 4 轮触发 unread.
    await appendRound(page, marker, 4);
    await waitForRounds(page, 4);
    const badge = page.locator("#unread-badge");
    await expect(badge).toBeVisible();

    // 点 badge → jumpToLatest.
    await badge.click();
    await page.waitForTimeout(500);

    // follow 状态: 距底 < 100px.
    expect(await distFromBottom(page), "点 badge 后应在底部附近 (follow)").toBeLessThan(100);

    // selected 应在最新轮 (第 4 轮 = DOM 末尾).
    const selectedRid = await page
      .locator("#detail .tl-round.selected")
      .getAttribute("data-rid");
    const lastRid = await page
      .locator("#detail > .tl-round")
      .last()
      .getAttribute("data-rid");
    expect(selectedRid, "点 badge 后 selected 重置到最新轮").toBe(lastRid);

    // badge 应隐藏 (unread 清零).
    await expect(badge).toBeHidden();
  });

  test("UI-6: follow 状态下新 round 到达 → 自动滚到底, 无 badge", async ({ page }) => {
    const marker = "ui5-follow-new-round-marker";
    const sid = await setupLongMultiroundSession(page, marker);
    await openTimeline(page, sid, 3);

    // 确认初始在 follow (距底 < 100).
    expect(await distFromBottom(page), "初始应 follow").toBeLessThan(100);

    // 发第 4 轮 (follow 状态).
    await appendRound(page, marker, 4);
    await waitForRounds(page, 4);
    // waitForRounds 已确保 refreshTimelineTail 运行 (= scrollTimelineToBottomForce 已调用).
    // 仅等 RAF + layout 稳定, 不需等下一个自动刷新周期.
    await page.waitForTimeout(500);

    // follow 状态: 仍在底部附近.
    expect(await distFromBottom(page), "follow 期间新 round 到达, 应自动滚到底").toBeLessThan(100);

    // 无 badge.
    await expect(page.locator("#unread-badge")).toBeHidden();
  });

  test("UI-6: pinned 期间点历史轮 → selected 停在该轮; 新 round 到达时 selected 不变", async ({ page }) => {
    const marker = "ui5-selected-stable-marker";
    const sid = await setupLongMultiroundSession(page, marker);
    await openTimeline(page, sid, 3);

    // 点第 1 轮 (历史轮, 最老). 这会触发 selectRound(scroll:'highlight') → pinned.
    const round1 = page.locator("#detail > .tl-round").first();
    const round1Rid = await round1.getAttribute("data-rid");
    expect(round1Rid).toBeTruthy();
    await round1.locator(".tl-round-header").click();
    await page.waitForTimeout(1200); // 等 highlightRound smooth 动画完成.

    // selected 应在第 1 轮.
    await expect(page.locator(`#detail .tl-round.selected[data-rid="${round1Rid}"]`)).toHaveCount(1);

    // 发第 4 轮 (新 round 到达).
    await appendRound(page, marker, 4);
    await waitForRounds(page, 4);

    // selected 仍在第 1 轮 (不随新 round 跑).
    await expect(
      page.locator(`#detail .tl-round.selected[data-rid="${round1Rid}"]`),
      "新 round 到达后, selected 应仍在第 1 轮 (方案 X 解耦)"
    ).toHaveCount(1);
    // 最新轮 (第 4) 不带 selected.
    const lastRid = await page
      .locator("#detail > .tl-round")
      .last()
      .getAttribute("data-rid");
    expect(lastRid, "最新轮应有 data-rid").toBeTruthy();
    expect(lastRid, "最新轮不应是第 1 轮").not.toBe(round1Rid);
    await expect(
      page.locator(`#detail .tl-round.selected[data-rid="${lastRid}"]`)
    ).toHaveCount(0);
  });

  test("UI-6: 点 ↓ 回到底部 → follow 但 selected 不重置 (区别于 unread badge)", async ({
    page,
  }) => {
    // 方案 X 的核心区别: scrollTimelineToBottom (↓ 按钮) 仅滚视口, 不重置 selected;
    // jumpToLatest (unread badge) 才重置 selected 到最新轮. 本测试守卫此区别.
    const marker = "ui6-scroll-bottom-no-reset-marker";
    const sid = await setupLongMultiroundSession(page, marker);
    await openTimeline(page, sid, 3);

    // 点第 1 轮 (历史轮). selected = round1, 视口滚到该轮 (pinned).
    const round1 = page.locator("#detail > .tl-round").first();
    const round1Rid = await round1.getAttribute("data-rid");
    expect(round1Rid).toBeTruthy();
    await round1.locator(".tl-round-header").click();
    await page.waitForTimeout(1200); // 等 highlightRound smooth 动画完成.
    await expect(page.locator(`#detail .tl-round.selected[data-rid="${round1Rid}"]`)).toHaveCount(1);

    // 点 ↓ 按钮 (scrollTimelineToBottom, smooth 滚到底, 非 jumpToLatest).
    await page.locator("#scroll-bottom-btn").click();
    await page.waitForTimeout(800); // 等 smooth 动画 + RAF.

    // follow: 距底 < 100.
    expect(await distFromBottom(page), "点 ↓ 后应在底部附近 (follow)").toBeLessThan(100);
    // selected 仍在 round1 (方案 X: ↓ 不重置 selected).
    await expect(
      page.locator(`#detail .tl-round.selected[data-rid="${round1Rid}"]`),
      "点 ↓ 后 selected 应仍在 round1 (不重置)"
    ).toHaveCount(1);
    // 最新轮 (第 3) 不带 selected (与 jumpToLatest 的语义区别).
    const lastRid = await page.locator("#detail > .tl-round").last().getAttribute("data-rid");
    expect(lastRid).not.toBe(round1Rid);
    await expect(page.locator(`#detail .tl-round.selected[data-rid="${lastRid}"]`)).toHaveCount(0);
    // 无 unread badge (follow 状态 + 0 未读).
    await expect(page.locator("#unread-badge")).toBeHidden();
  });

  // ─── UI-6 后续修复: follow 下末轮 request 完整可见 + pinned 视觉指示 ──────
  //
  // WebUI 反馈 1/2/3:
  //   反馈2: follow 时 scrollTimelineToBottomForce 预留 drawerH+GAP, 末轮 request
  //          气泡底部出现在 drawer 上边缘之上 GAP 处 (完整可见, 不被遮挡).
  //   反馈3: DRAWER_GAP 8→28px, 末轮 request 与 drawer 之间留呼吸空间.
  //   反馈1: pinned 时 drawer 上边缘露蓝细边 (.pinned 类); follow 时淡灰近不可见.
  test("UI-6: follow 时末轮 request 完整可见 (不被 drawer 遮挡)", async ({ page }) => {
    const marker = "ui6-follow-visible-marker";
    const sid = await setupLongMultiroundSession(page, marker, 3);
    await openTimeline(page, sid, 3);

    // 末轮 .tl-round 的底部应 ≤ drawer 上边缘 (末轮 request 完整可见, 不被遮挡).
    // 即: lastRoundBottom <= drawerTop (在 wrap 坐标系).
    const visible = await page.evaluate(() => {
      const rounds = document.querySelectorAll("#detail > .tl-round");
      const last = rounds[rounds.length - 1] as HTMLElement;
      const drawer = document.getElementById("response-drawer")!;
      const wrap = document.getElementById("detail-wrap")!;
      const wrapRect = wrap.getBoundingClientRect();
      const lastRect = last.getBoundingClientRect();
      const drawerRect = drawer.getBoundingClientRect();
      return {
        lastRoundBottom: lastRect.bottom - wrapRect.top,
        drawerTop: drawerRect.top - wrapRect.top,
        gap: (drawerRect.top - wrapRect.top) - (lastRect.bottom - wrapRect.top),
      };
    });
    // 末轮底部 ≤ drawer 上边缘 (完整可见).
    expect(visible.lastRoundBottom, "末轮 request 底部应在 drawer 上边缘之上").toBeLessThanOrEqual(visible.drawerTop);
    // GAP ≥ DRAWER_GAP - 容差(4px 亚像素): follow 预留 ~28px 呼吸空间 (WebUI 反馈3).
    // 弱断言 (>=0) 无法守卫 bottomScrollTarget 的 drawerH+GAP 预留逻辑, 故用接近 GAP 的下界.
    expect(visible.gap, "末轮底部到 drawer 上边缘应有 ~DRAWER_GAP 呼吸间距").toBeGreaterThanOrEqual(DRAWER_GAP - 4);
  });

  test("UI-6: pinned 时 drawer 有 .pinned 类, follow 时无 (视觉区分)", async ({ page }) => {
    const marker = "ui6-pinned-class-marker";
    const sid = await setupLongMultiroundSession(page, marker, 3);
    await openTimeline(page, sid, 3);

    const scrollRange = await contentScrollRange(page);
    test.skip(scrollRange <= 200, "content too short to test pinned");

    // follow 时 drawer 无 .pinned 类 (淡灰近不可见).
    await expect(page.locator("#response-drawer")).not.toHaveClass(/pinned/);

    // 向上滚到内容中部 (pinned).
    await scrollToContentMiddle(page);
    await page.waitForTimeout(300); // 等 RAF 合并的 syncFollowMode.

    // pinned 时 drawer 有 .pinned 类 (蓝细边).
    await expect(page.locator("#response-drawer"), "pinned 时 drawer 应有 .pinned 类").toHaveClass(/pinned/);

    // 点 ↓ 回到 follow.
    await page.locator("#scroll-bottom-btn").click();
    await page.waitForTimeout(600); // 等 smooth + RAF.

    // follow 时 .pinned 类移除.
    await expect(page.locator("#response-drawer"), "回到 follow 时 .pinned 应移除").not.toHaveClass(/pinned/);
  });

  // ─── UI-6 follow 闭合不变量 (prop_follow_invariant_under_new_round) ──
  // 守卫 follow 状态在新 round 插入下不被翻转 + 末轮不被 drawer 遮挡.
  // 与 prop_follow_new_round_auto_scroll 互补: 后者只断言长内容稳态结果,
  // 本组覆盖短内容历史 bug 路径 (placeholder=0 → maxScroll clamp → 末轮被遮挡).
  // 契约详尽定义 + 多维断言语义见 contracts.md UI-6.

  /** 采集 follow 闭合不变量的多维状态. 返回 wrap 坐标系的几何 + 视觉类.
   * `distFromContentEnd`: 视口底相对 contentEnd 的距离 (contentEnd - scrollTop - clientHeight).
   *   负值 = 视口底已越过 contentEnd (仍 ≤ NEAR_BOTTOM_PX 视为 follow); 与 isNearBottom 一致. */
  async function followClosureState(page: Page): Promise<{
    lastRoundBottom: number; // 末轮底部在 wrap 坐标系的 y
    drawerTop: number;       // drawer 顶部在 wrap 坐标系的 y
    drawerHasPinned: boolean;
    distFromContentEnd: number;
  }> {
    return page.evaluate(() => {
      const detail = document.getElementById("detail")!;
      const wrap = document.getElementById("detail-wrap")!;
      const drawer = document.getElementById("response-drawer")!;
      const wrapRect = wrap.getBoundingClientRect();
      const rounds = detail.querySelectorAll(":scope > .tl-round");
      let contentEnd = 0;
      let lastRoundBottom = 0;
      if (rounds.length > 0) {
        const last = rounds[rounds.length - 1] as HTMLElement;
        contentEnd = last.offsetTop + last.offsetHeight;
        lastRoundBottom = last.getBoundingClientRect().bottom - wrapRect.top;
      }
      const drawerTop = drawer.getBoundingClientRect().top - wrapRect.top;
      return {
        lastRoundBottom,
        drawerTop,
        drawerHasPinned: drawer.classList.contains("pinned"),
        distFromContentEnd: contentEnd - detail.scrollTop - detail.clientHeight,
      };
    });
  }

  test("UI-6: follow 状态在新 round 插入下不变 (短内容 + drawer 遮挡 → 压缩 drawer)", async ({ page }) => {
    // 复现路径: 第 1 轮短内容 (contentEnd 远 < wrapH), 追加第 2 轮让 contentEnd 落在
    // [wrapH - GAP - minH, wrapH - 0.05*wrapH] 区间 (Case A: drawer 压缩后末轮完整可见).
    // 历史 bug: placeholder=0 不提供滚动空间, maxScroll=0, target 被 clamp 到 0,
    // 末轮被 drawer 遮挡. 修复: follow + 短内容时 updateResponseDrawerLayout 压缩 drawer.
    const marker = "ui6-follow-invariant-cross-marker";
    await page.goto("/");
    // 锁定视口 (避免 CI runner 字体渲染差异让 contentEnd 漂移到失效区间 B2).
    // wrapH=530, 失效区间为 contentEnd > wrapH - GAP - minH = 530 - 28 - 53 = 449.
    // 目标 contentEnd 区间: [310, 449] (Case A, drawer 压缩到 reserveH ≥ minH).
    await page.setViewportSize({ width: 1280, height: 600 });

    // 第 1 轮: 短 (1 user + 1 assistant), follow.
    await sendChat(page, [
      { role: "user", content: `${marker} first` },
      { role: "assistant", content: "ok1" },
    ]);
    const sid = await findSessionLeafByPreview(page, marker);
    await openTimeline(page, sid, 1);
    expect(await distFromBottom(page), "初始应 follow").toBeLessThan(100);

    // 第 2 轮: 8 条 messages (含 r2 的 6 条), 折叠后 contentEnd 落在目标区间.
    await sendChat(page, [
      { role: "user", content: `${marker} first` },
      { role: "assistant", content: "ok1" },
      { role: "user", content: "r2-q1" },
      { role: "assistant", content: "r2-a1" },
      { role: "user", content: "r2-q2" },
      { role: "assistant", content: "r2-a2" },
      { role: "user", content: "r2-q3" },
      { role: "assistant", content: "r2-a3" },
    ]);
    await waitForRounds(page, 2);
    await page.waitForTimeout(800); // 等 syncFollowMode + RAF

    // 先 probe 几何状态, 确认走了压缩路径 (drawerH < defaultH) 且未落入失效区间.
    const probe = await page.evaluate(() => {
      const detail = document.getElementById("detail")!;
      const wrap = document.getElementById("detail-wrap")!;
      const drawer = document.getElementById("response-drawer")!;
      const rounds = detail.querySelectorAll(":scope > .tl-round");
      const last = rounds[rounds.length - 1] as HTMLElement;
      return {
        wrapH: wrap.clientHeight,
        contentEnd: last.offsetTop + last.offsetHeight,
        drawerH: drawer.hidden ? 0 : drawer.offsetHeight,
        defaultH: wrap.clientHeight * 0.30,
        minH: wrap.clientHeight * 0.10,
      };
    });
    // 确认走了压缩路径: 短内容 + drawerH < defaultH (30% wrapH) ⇒ 修复生效.
    expect(probe.contentEnd, "场景应为短内容").toBeLessThanOrEqual(probe.wrapH);
    expect(probe.drawerH, "follow + 短内容应触发 drawer 压缩 (< defaultH)").toBeLessThan(probe.defaultH);

    const s = await followClosureState(page);

    // 多维断言: 末轮不被遮挡.
    expect(
      s.lastRoundBottom,
      "follow 下末轮 request 底部应在 drawer 上边缘之上 (不被遮挡)"
    ).toBeLessThanOrEqual(s.drawerTop);

    // 状态机视觉指示: follow 时 drawer 不带 .pinned 类.
    expect(
      s.drawerHasPinned,
      "follow 状态下 drawer 不应有 .pinned 类 (状态机未被翻转)"
    ).toBe(false);

    // 结果一致性: 距 contentEnd ≤ NEAR_BOTTOM_PX.
    expect(
      s.distFromContentEnd,
      "follow 下视口距 contentEnd 应 ≤ NEAR_BOTTOM_PX"
    ).toBeLessThanOrEqual(100);
  });

  test("UI-6: follow 状态在新 round 插入下不变 (长内容稳态对照)", async ({ page }) => {
    // 对照组: 长内容稳态 (3→4 轮), 守卫修复不破坏既有路径.
    // 与 prop_follow_new_round_auto_scroll 的区别: 多了"末轮不被遮挡" + ".pinned 类"
    // 两个机制闭合维度的断言.
    const marker = "ui6-follow-invariant-steady-marker";
    const sid = await setupLongMultiroundSession(page, marker, 3);
    await openTimeline(page, sid, 3);

    expect(await distFromBottom(page), "初始应 follow").toBeLessThan(100);

    await appendRound(page, marker, 4);
    await waitForRounds(page, 4);
    await page.waitForTimeout(500);

    const s = await followClosureState(page);

    expect(
      s.lastRoundBottom,
      "follow 下末轮 request 底部应在 drawer 上边缘之上 (不被遮挡)"
    ).toBeLessThanOrEqual(s.drawerTop);
    expect(s.drawerHasPinned, "follow 状态下 drawer 不应有 .pinned 类").toBe(false);
    expect(s.distFromContentEnd, "follow 下视口距 contentEnd 应 ≤ NEAR_BOTTOM_PX").toBeLessThanOrEqual(100);
  });

  // Bug #2 (选中历史 round 连续扩展) 的前端路径 selectRound path 2 (loadUntilRound
  // 循环 loadOlder) 需要构造 > TIMELINE_PAGE 的长会话, 留作后续 e2e 覆盖.
  // 后端 timeline_view 的连续区间语义由 dag.rs 既有测试覆盖.

  // ─── API key CRUD 回归 (auth 关闭场景) ────────────────────────────────────
  //
  // 历史 bug: /api/api-keys CRUD 路由仅在 auth.enabled = true 时挂载, 导致
  // 单用户模式下点 "+ new API key" → POST 返回 405, alert "Failed: HTTP 405".
  // 修复: 路由无条件挂载 (web::router), 移除 OIDC guard + tenant_id 隔离.
  //
  // 守卫: 在 playwright config 的默认 (auth 关闭) 配置下, 完整跑一遍
  // create → reveal → list → toggle → delete, 验证无 4xx 错误.
  test("API key CRUD: auth 关闭场景下可签发/列表/切换/删除", async ({ page, request }) => {
    // 用唯一 marker, 测试间隔离 (即使前次失败残留也能区分).
    const label = `crud-test-${Date.now()}`;

    // 1. 签发: POST /api/api-keys, 期望 201 + 返回明文 key (仅此一次).
    const createRes = await request.post(`${SG_API}/api-keys`, {
      data: { label },
    });
    expect(createRes.status(), "POST 应返回 201, 非 405 (历史 bug)").toBe(201);
    const issued = await createRes.json();
    expect(issued.key).toMatch(/^sg_/);
    expect(issued.id).toBeTruthy();

    // 2. 列表: GET /api/api-keys 应包含刚签发的 key (动态, source=dynamic, enabled).
    //    同时验证响应携带 auth_enabled=false (本测试运行在 auth 关闭场景).
    const listRes = await request.get(`${SG_API}/api-keys`);
    expect(listRes.status()).toBe(200);
    const listJson = await listRes.json();
    expect(listJson.auth_enabled, "auth 关闭场景下 auth_enabled 应为 false").toBe(false);
    const listed = listJson.keys as Array<Record<string, unknown>>;
    const found = listed.find((k) => k.id === issued.id);
    expect(found, "新建 key 应出现在列表中").toBeTruthy();
    expect(found!.disabled).toBe(false);
    expect(found!.source).toBe("dynamic");

    // 3. UI 侧也验证 (覆盖前端 renderApiKeys + dialog 流程).
    // 切到 API Keys tab, 验证列表渲染出新 key 的 label.
    await page.locator('a.tab[data-tab="apikeys"]').click();
    await expect(
      page.locator("#apikeys-body"),
      "UI 列表应渲染新建 key 的 label"
    ).toContainText(label);
    // auth 关闭场景: 所有 key 都应显示 inactive badge (第三态), 而非 enabled.
    await expect(
      page.locator("#apikeys-body .badge-inactive").first(),
      "auth 关闭时 key 应显示 inactive 徽章"
    ).toBeVisible();
    // 同时验证 auth-disabled 提示文本可见.
    await expect(
      page.locator("#apikeys-auth-warn"),
      "auth 关闭时 warning 提示应可见"
    ).toBeVisible();

    // 4. 切换 disabled: PATCH, 期望返回 disabled=true.
    const toggleRes = await request.patch(
      `${SG_API}/api-keys/${issued.id}/toggle`,
      { data: { disabled: true } }
    );
    expect(toggleRes.status()).toBe(200);
    const toggled = await toggleRes.json();
    expect(toggled.disabled).toBe(true);

    // 5. 删除: DELETE, 期望 204.
    const delRes = await request.delete(`${SG_API}/api-keys/${issued.id}`);
    expect(delRes.status(), "DELETE 应返回 204").toBe(204);

    // 6. 再次列表, 验证 key 已消失 (自清理, 不污染其他测试).
    const listRes2 = await request.get(`${SG_API}/api-keys`);
    const listed2 = (await listRes2.json()).keys as Array<Record<string, unknown>>;
    expect(listed2.find((k) => k.id === issued.id)).toBeUndefined();
  });

  // ─── UI-7: sidebar rounds 回填时序 + timeline 并发一致性 (gen) ─────────────
  //
  // 历史 bug: toggleSession 只 loadTimeline (右侧), 不为 sidebar 三级菜单发任何请求;
  // rounds 回填只能等 3s 轮询 tick 的 sync() → "Loading rounds…" 卡 0~3s,
  // 关闭 auto-refresh 时无限期. 修复: toggleSession 主动触发 sidebar-only sync.
  //
  // 同时引入 timeline 代际 (gen) 机制, 消除两类并发交错:
  //   ① 矛盾游标: sync 出发时 records 归属 ≠ selectedSession (点击后 loadTimeline
  //      在途) → 旧实现发出自相矛盾的游标, 后端按 "after 不属于本 session" 契约
  //      返回全链 new_rounds, append 进旧 records → 跨会话脏数据.
  //   ② 过气响应: sync 出发时合法, 响应落地前用户切了会话 → 旧 records 被
  //      loadTimeline 替换后, 迟到的 diff 仍 append 上去.
  // gen 不变量: 一个响应能写 timelineRecords, 当且仅当它描述的世界与当前世界同代.

  test("UI-7: 点击会话后 sidebar rounds 立即回填 (不等 3s 轮询)", async ({ page }) => {
    // 关闭 auto-refresh: 若修复缺失, rounds 只能靠 tick 回填 → 本测试必超时失败.
    // 注: uncheck 在 findSessionLeafByPreview 之后 — 后者依赖 auto-refresh 拉新会话.
    await sendChat(page, [{ role: "user", content: "ui7-immediate-rounds-marker" }]);
    const leaf = await findSessionLeafByPreview(page, "ui7-immediate-rounds-marker");
    await page.locator("#auto").uncheck();

    // clickSessionByLeaf 等 #detail .request-pane 出现 (loadTimeline 完成),
    // 但那是右侧; 这里专测 sidebar: round-list 应在该等待窗口内就有条目.
    await page.locator(`.session-item[data-sid="${leaf}"]`).click();
    // 断言: 1s 内 (无 tick 可依赖) sidebar 三级出现非 loading 的实际条目.
    // 旧实现: "Loading rounds…" 停留至手动 refresh (无限期) → timeout 失败.
    const wrap = page.locator(`.round-list[data-sid="${leaf}"]`);
    await expect(
      wrap.locator(".round-item"),
      "auto-refresh 关闭时, 点击后 sidebar rounds 应立即回填"
    ).toHaveCount(1, { timeout: 1000 });
    await expect(wrap.locator(".empty")).toHaveCount(0);
  });

  test("UI-7: 点击会话后 sync 不发矛盾游标 (timelineGen 守卫)", async ({ page }) => {
    // 守卫形态①: 点击 B 的瞬间 (loadTimeline(B) 在途), 主动触发 sync.
    // 旧实现: selected.session_id=B 但 latest_round 还是 A 的叶子 → 后端契约返回
    // 全链 new_rounds → push 进 A 的 records. 修复: timelineSession !== selectedSession
    // 时 selected 游标发 null (后端 timeline=null, 纯 sidebar 回填).
    await sendChat(page, [{ role: "user", content: "ui7-cursor-guard-a" }]);
    await sendChat(page, [{ role: "user", content: "ui7-cursor-guard-b" }]);
    const sidA = await findSessionLeafByPreview(page, "ui7-cursor-guard-a");
    const sidB = await findSessionLeafByPreview(page, "ui7-cursor-guard-b");

    // 1. 打开 A, 等 timeline 落地 (records 归属 = A, gen=g).
    await clickSessionByLeaf(page, sidA);
    const before = await page.evaluate(() => ({
      records: state.timelineRecords.map((r) => r.id),
      gen: state.timelineGen,
    }));

    // 2. 点击 B (loadTimeline(B) 在途, ~14ms 窗口), 立即 (同一帧序列) 主动 sync.
    //    注意不 await loadTimeline — toggleSession 内部已完成 renderSidebar + 发起
    //    fetch; 我们在 fetch resolve 前抢进 sync, 精确复现形态①.
    await page.evaluate((sid) => {
      document.querySelector(`.session-item[data-sid="${sid}"]`).click();
      window.sync();
    }, sidB);
    // 等 B 的 timeline 落地并认领归属 (loadTimeline 对账通过 → timelineSession=sidB).
    await expect
      .poll(() => page.evaluate(() => state.timelineSession), { timeout: 2000 })
      .toBe(sidB);

    const after = await page.evaluate(() => ({
      records: state.timelineRecords.map((r) => r.id),
      session: state.timelineSession,
      selected: state.selectedSession,
      gen: state.timelineGen,
    }));
    // 世界已换到 B: gen 已 bump, records 归属 B.
    expect(after.gen).toBeGreaterThan(before.gen);
    expect(after.session).toBe(sidB);
    expect(after.selected).toBe(sidB);
    // 核心断言: records 是 B 的全量 (恰好 1 轮), 无 A 的 round 混入.
    // 注: pre-fix 构建上若 loadTimeline(B) 先于矛盾游标的 sync 落地, 脏数据会被
    // 随后的全量替换冲掉 (顺序依赖, 约一半概率 false-pass) — 本测试对形态①的
    // 确定性检测力来自上方 gen/session 字段断言 (pre-fix 必挂: 无 bump 机制).
    // records 断言在顺序有利时提供行为级佐证.
    expect(after.records.length).toBe(1);
  });

  test("UI-7: 在途 sync 的迟到 diff 不污染已切换的 timeline (gen 对账)", async ({ page }) => {
    // 守卫形态②: sync 带着完全合法的 A 游标出发 → 用户点 B → B 的 timeline 落地 →
    // A 的 diff 才回来. 旧实现: diff.push 到 B 的 records 上. 修复: sync 落地前
    // 对账 gen, 不匹配则丢弃 timeline 段 (sidebar 段照常应用).
    //
    // 检测力设计: A 打开 (游标=A1) 后再给 A 发一轮 A2, 然后出发 sync — 服务端
    // 对该游标算出 new_rounds=[A2], 响应体真实携带非空 timeline 段. pre-fix 构建
    // 上放行后 A2 会 append 进 B 的 records (records.length=2, 行为级红灯).
    await sendChat(page, [{ role: "user", content: "ui7-stale-drop-a" }]);
    await sendChat(page, [{ role: "user", content: "ui7-stale-drop-b" }]);
    const sidA = await findSessionLeafByPreview(page, "ui7-stale-drop-a");
    const sidB = await findSessionLeafByPreview(page, "ui7-stale-drop-b");

    await clickSessionByLeaf(page, sidA);
    const genA = await page.evaluate(() => state.timelineGen);

    // 挂起 sync (Node 侧 pending 队列): route handler 收到响应后挂起, Node 侧逐个
    // 放行. fulfilled 计数器提供正面等待信号 (放行 → fulfill 完成).
    const pending: Array<() => void> = [];
    let fulfilled = 0;
    await page.route("**/api/sync", async (route) => {
      const resp = await route.fetch();
      await new Promise<void>(r => pending.push(r));
      await route.fulfill({ response: resp });
      fulfilled++;
    });
    try {
      // 关闭 auto-refresh; 给 A 再发一轮 A2 (使其后出发的 sync 游标落后一轮,
      // 响应携带 new_rounds=[A2]); 手动 refresh 触发 sync (出发时世界 = A, 游标合法).
      await page.locator("#auto").uncheck();
      await sendChat(page, [
        { role: "user", content: "ui7-stale-drop-a" },
        { role: "assistant", content: "ok" },
        { role: "user", content: "ui7-stale-drop-a round2" },
      ]);
      await page.locator("button.refresh").click();
      // 等 refresh 的 sync 进入挂起队列 (A 游标, 响应含 A2 diff).
      await expect
        .poll(() => pending.length, { timeout: 2000 })
        .toBeGreaterThan(0);

      // 立刻点 B (换世界, gen bump), 等 B timeline 落地 + 主动 sync 也入队
      // (null 游标, 无 timeline 段, 放行无害).
      await clickSessionByLeaf(page, sidB);
      await expect
        .poll(() => pending.length, { timeout: 2000 })
        .toBeGreaterThanOrEqual(2);
      const mid = await page.evaluate(() => ({
        gen: state.timelineGen,
        records: state.timelineRecords.length,
      }));
      expect(mid.gen).toBeGreaterThan(genA);
      expect(mid.records).toBe(1);

      // 放行全部挂起的 sync (含携带 A2 diff 的迟到响应).
      for (const release of pending.splice(0)) release();
      // 正面等待: 放行的响应全部 fulfill 完成 (fetch resolve + sync 落地链路).
      await expect
        .poll(() => fulfilled, { timeout: 2000 })
        .toBeGreaterThanOrEqual(2);

      // B 的 records 不被 A 的 diff 污染: 仍恰好 B 的 1 轮 (pre-fix: A2 append → 2).
      const after = await page.evaluate(() => ({
        records: state.timelineRecords.map((r) => r.id),
        gen: state.timelineGen,
      }));
      expect(after.records.length).toBe(1);
    } finally {
      // 清理: 释放残余挂起 + 移除 route 拦截, 避免影响后续测试.
      for (const release of pending.splice(0)) release();
      await page.unroute("**/api/sync");
    }
  });
});

// ─── WebUI 打磨批次回归 (#161 + #164-1/2/3) ─────────────────────────────
//
// 覆盖四个新交互:
//   1. (#161) secrets 表 decision 下拉选 Disabled → confirm 弹窗; 取消回滚 / 确认生效
//      且 PATCH 响应含 warning.
//   2. (#164-1) raw 弹窗 Response Body 区段带 "(LLM view, ...)" 标注.
//   3. (#164-2) info 弹窗 Time 字段格式化为本地时间 (title 保留原始 UTC RFC3339).
//   4. (#164-3) 数据未变化时 3s auto-refresh 不重建表格 DOM (tr 引用保持 isConnected).
test.describe("WebUI 打磨 (#161 + #164)", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(500);
  });

  // 本 describe 的 #161 用例会把 test-key 切到 disabled; 断言中途失败时跳过测试体内的
  // 清理, disabled 残留会让后续依赖 test-key 参与 redaction 的用例连环假失败
  // (workers=1 共享同一 server state). afterEach 幂等还原 (default 对已 default 的
  // secret 是 no-op).
  test.afterEach(async ({ request }) => {
    await request.patch(`${SG_API}/secrets/test-key/decision`, {
      data: { mode: "default" },
    });
  });

  test("#161: secret decision→Disabled 有 confirm; 取消回滚 / 确认后带 warning", async ({
    page,
  }) => {
    // config 的 static secret id = "test-key" → secrets 表应渲染 decision 下拉.
    await page.locator('a.tab[data-tab="secrets"]').click();
    const sel = page.locator('select.decision-select[data-id="test-key"]');
    await expect(sel).toBeVisible();

    // 选 Disabled → confirm 出现, 文案含 "plaintext".
    let confirmShown = "";
    page.once("dialog", async (d) => {
      confirmShown = d.message();
      await d.dismiss(); // 先测取消路径.
    });
    await sel.selectOption("disabled");
    await page.waitForTimeout(200);
    expect(confirmShown).toContain("plaintext");

    // 取消后: 下拉显式还原为 default (renderedHtml 短路下 refresh 不会重建 DOM,
    // 复原来自 change handler 的 restoreDecisionSelect).
    await expect(page.locator('select.decision-select[data-id="test-key"]')).toHaveValue(
      "default"
    );

    // 再测确认路径: confirm accept → PATCH 生效 (条目转灰显 disabled 行, 2e2a921).
    let sawConfirm = false;
    const confirmHandler = async (d: import("@playwright/test").Dialog) => {
      sawConfirm = true;
      await d.accept();
      page.off("dialog", confirmHandler);
    };
    page.on("dialog", confirmHandler);
    await page.locator('select.decision-select[data-id="test-key"]').selectOption("disabled");
    await page.waitForTimeout(600);
    expect(sawConfirm).toBe(true);
    // disabled 后条目不再从表格消失 — 2e2a921 起 disabled static 条目保留灰显行
    // (decision 下拉恒 disabled, 可切回 default/prefer_static 复活, 见
    // renderDisabledSecretRow); 断言改为: 行灰显 + 下拉值 = disabled.
    await expect(
      page.locator('select.decision-select[data-id="test-key"]')
    ).toHaveValue("disabled");
    await expect(
      page.locator('tr.row-disabled[data-id="test-key"]')
    ).toBeVisible();
    // 还原由 afterEach 幂等执行 (断言失败中断时也能恢复).
  });

  test("#164-1: 完整数据 tab Response Body 带 (LLM view) 标注", async ({ page }) => {
    // 显式开启 full 捕获 — 标注分支只在捕获开启 (resp_body 有内容) 时出现.
    await setAuditCapture(page, true);
    await sendChat(page, [{ role: "user", content: "raw-llm-view-marker" }]);
    const sid = await findSessionLeafByPreview(page, "raw-llm-view-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    const dlg = await openRoundDetailTab(page);
    await page.waitForTimeout(500);
    const rawText = await dlg.textContent();
    // 非流式响应: Response Body 区段应带 LLM view 标注 (含 mock 视角提示).
    expect(rawText).toContain("Response Body (LLM view");
    await dlg.locator(".dialog-close").click();
  });

  test("#164-2: 概览 tab Time 为本地时间, title 保留 UTC RFC3339", async ({ page }) => {
    await sendChat(page, [{ role: "user", content: "info-time-marker" }]);
    const sid = await findSessionLeafByPreview(page, "info-time-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    await page.locator("#detail .tl-actions button[data-action='detail']").click();
    await page.waitForTimeout(300);
    const timeCell = page.locator("dialog.round-dialog .info-table tr", {
      has: page.locator("td.info-key", { hasText: "Time" }),
    }).locator("td.info-val");

    // 显示值不再是原始 UTC RFC3339 (无 "T..Z" 形态), 而是本地时间.
    const shown = await timeCell.textContent();
    expect(shown).toBeTruthy();
    expect(shown).not.toMatch(/T\d{2}:\d{2}:\d{2}.*Z$/);
    // title 保留原始 UTC RFC3339 (开发者向).
    const title = await timeCell.getAttribute("title");
    expect(title).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    await page.locator("dialog.round-dialog .dialog-close").click();
  });

  test("#164-3: 数据静止时 auto-refresh 不重建表格 DOM", async ({ page }) => {
    await page.locator('a.tab[data-tab="secrets"]').click();
    const row = page.locator("#secrets-body tr").first();
    await row.waitFor({ state: "attached" });

    // 给首行打标签, 等 2 个 auto-refresh 周期 (3s × 2 + 余量) 后检查标签是否仍在
    // 文档中. 数据未变化 (无人改配置) → renderedHtml 短路 → tbody 不重建 → 标签元素
    // 保持连接. (elementHandle.isConnected 在本 Playwright 版本不可序列化, 用 evaluate.)
    const stillConnected = await row.evaluate((el) => {
      el.setAttribute("data-refresh-probe", "1");
      return new Promise<boolean>((resolve) => {
        setTimeout(() => resolve(el.isConnected), 7000);
      });
    });
    expect(stillConnected, "数据静止时 tr 引用不应被刷新打断").toBe(true);
  });
});

// ─── B3: 详细日志开关 (audit capture) + 未捕获占位 ────────────────────────
//
// B2 契约: audit_capture 三态 (off/latest/full, 默认 latest — quant#307) — 未保留
// body 的请求 req_body/resp_body 为空, record DTO 带 audit_capture_off=true; UI 三态
// 下拉在 header 工具栏 (#audit-capture select, GET/PUT /api/settings). 覆盖:
//   1. 三态切换 + 初始化同步 (GET → select 镜像服务端值; 默认 latest)
//   2. off 时 raw 弹窗占位 (优先级高于 streamed 空态 — 非流式请求也占位)
//   3. off 时 usage 审计溯源弹窗占位 (parsed view, 判据与 raw 弹窗同字段)
test.describe("B3: 详细日志开关 (audit capture)", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
  });

  test("三态切换 + 初始化同步反馈", async ({ page }) => {
    // 暂停 3s 自动刷新 (sync 成功会清空 #status) — 切换反馈是一次性文本,
    // 否则断言与轮询 tick 存在负载相关的清空竞态 (CI 慢机 ~3% flake).
    await page.locator("#auto").uncheck();
    // 初始 latest 的保证: grep 单跑 = state 全新 (mkdtemp) 默认 latest; 全量跑 =
    // 文件级 afterEach 卫生钩子恢复 latest. 两种场景下 select 都镜像服务端 latest.
    const sel = page.locator("#audit-capture");
    await expect(sel).toHaveValue("latest");
    // 切 full → PUT 成功 → 状态更新 + #status 轻反馈 (全值域巡回).
    await sel.selectOption("full");
    await expect(sel).toHaveValue("full");
    await expect(page.locator("#status")).toContainText("Audit log: Full");
    await sel.selectOption("off");
    await expect(sel).toHaveValue("off");
    await expect(page.locator("#status")).toContainText("Audit log: Off");
    await sel.selectOption("latest");
    await expect(sel).toHaveValue("latest");
    await expect(page.locator("#status")).toContainText("Audit log: Latest only");
  });

  test("audit_capture off 时完整数据 tab 显示未捕获占位", async ({ page }) => {
    // 显式 off + 非流式请求 — 占位优先于 streamed 空态: 非流式下旧 UI 会显示
    // "(empty)", B3 起必须显示未捕获占位. (quant#307 起默认 latest, off 需显式设置.)
    await setAuditCapture(page, false);
    await sendChat(page, [{ role: "user", content: "audit-off-marker" }]);
    const sid = await findSessionLeafByPreview(page, "audit-off-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    const dlg = await openRoundDetailTab(page);
    // 未捕获占位在完整数据 tab (原 raw 弹窗语义, quant#305 合并).
    await page.waitForTimeout(500); // 等待懒拉 record.
    const rawText = await dlg.textContent();
    // req + resp 两个 body 区段均占位 (headers 照常展示).
    expect(rawText).toContain("not retained by the audit log");
    expect(rawText).toContain("Request Headers");
    // 占位分支不携带 "LLM view" 标注 (那是捕获开启时的语义).
    expect(rawText).not.toContain("LLM view");
    await dlg.locator(".dialog-close").click();
  });

  test("audit_capture off 时 usage 审计溯源弹窗同样占位", async ({ page }) => {
    // 审计弹窗 (data-audit-node) 消费 parsed view (?view=parsed) — 判据与 raw
    // 弹窗统一为 record.audit_capture_off (见 index.html 注释), 本用例守卫该分支.
    // (quant#307 起默认 latest — off 需显式设置, 否则头部请求有 raw 不占位.)
    await setAuditCapture(page, false);
    await sendChat(page, [
      { role: "user", content: `audit-off-recent-marker secret=${TEST_SECRET_VALUE}` },
    ]);
    await page.locator('a.tab[data-tab="usage"]').click();
    // 等 redact recent 落库 (store writer 批量事务, poll 表格出现数据行).
    await expect
      .poll(
        async () =>
          page.locator("#redact-recent-body tr:not(:has(td.empty))").count(),
        { timeout: 15_000 }
      )
      .toBeGreaterThan(0);
    // 点行内 view → 弹窗显示占位 (而非 dump 空 record 的 JSON).
    await page.locator("#redact-recent-body button[data-audit-node]").first().click();
    const auditBody = page.locator("#audit-record-body");
    await expect(auditBody).toContainText("not retained by the audit log");
    await expect(auditBody).not.toContainText('"req_body"');
    // 关闭 (form method=dialog 的 submit 按钮).
    await page.locator("#audit-record-dialog form button.btn").click();
  });
});

// ─── #319: 编辑 secret 的 mock strategy 脏检查 ────────────────────────────
//
// 表单没有 shape 字段 — 编辑已有 secret 时从表单收集 gen 会丢 shape, 且把 infer
// 结果以 "用户显式" (gen_inferred=false) 落盘: ① PEM/JWT 的结构化仿真退化为
// 平坦串; ② infer 逻辑升级不再生效 (冻结); ③ category↔shape mismatch 检测停用.
//
// 修复契约 (判定矩阵, SSOT = index.html collectMockStrategyFromForm 头注释):
//   未触碰 mock 高级区 + 原 gen 是 infer 结果 → PUT body mock_strategy === null
//     (后端 fresh infer — shape 恢复 / infer 升级可生效 / mismatch 复活);
//   未触碰 + 原 gen 是用户显式 → 原样回传 (含 shape; dynamic override 是整条目
//     替换, 省略会让 static/此前的显式配置被 infer 遮蔽 = 数据丢失);
//   触碰过 (任一输入) → 按表单收集 (shape 退化 plain 是已接受的限制, 方向 B 不做).
const TEST_PEM_VALUE = [
  "-----BEGIN OPENSSH PRIVATE KEY-----",
  "b3BlbnNzaC1rZXktdjEAAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn",
  "NhAAAAAwEAAQAAAQEAtc0vLB3n6e5h8xNB7FJ7dX08ZD7kWrvFarcOeSNBjSM=",
  "-----END OPENSSH PRIVATE KEY-----",
].join("\n");

test.describe("WebUI secret mock strategy 脏检查 (#319)", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(500);
  });

  // dynamic-only 条目 DELETE = 204; 幂等清理 (失败不阻断, 已删时 404 无害).
  test.afterEach(async ({ request }) => {
    for (const id of ["gen-rt-inferred", "gen-rt-explicit"]) {
      await request.delete(`${SG_API}/secrets/${id}`);
    }
  });

  /** 经 UI 编辑 secret (改 name + 重输 value), 捕获 PUT body 后放行. */
  async function editSecretViaUi(page: Page, id: string, value: string): Promise<any> {
    let captured: any = null;
    await page.route(`**/api/secrets/${id}`, async (route) => {
      if (route.request().method() === "PUT") {
        captured = route.request().postDataJSON();
      }
      await route.continue();
    });
    await page.locator('a.tab[data-tab="secrets"]').click();
    const row = page.locator(`#secrets-body tr[data-id="${id}"]`);
    await expect(row).toBeVisible();
    await row.locator('button[data-action="edit"]').click();
    const dlg = page.locator("#secret-form");
    await expect(dlg).toBeVisible();
    await page.locator("#f-name").fill("renamed");
    await page.locator("#f-value").fill(value);
    await page.locator('#secret-form-el button[value="save"]').click();
    await expect(dlg).not.toBeVisible();
    expect(captured, "PUT 必须已发出").toBeTruthy();
    return captured;
  }

  test("#319: 未触碰 + infer gen → mock_strategy 省略 (fresh infer, shape 恢复)", async ({
    page,
    request,
  }) => {
    // PEM 值 + privatekey → 后端 infer shape=pem (gen_inferred=true 进 DTO).
    const r = await request.post(`${SG_API}/secrets`, {
      data: { id: "gen-rt-inferred", name: "orig", category: "privatekey", value: TEST_PEM_VALUE },
    });
    expect(r.ok()).toBe(true);

    const payload = await editSecretViaUi(page, "gen-rt-inferred", TEST_PEM_VALUE);
    // 核心: 只改 name 未触碰 mock 区 → 不回传表单收集的 gen (冻结修复点).
    expect(payload.mock_strategy).toBeNull();

    // 保存后仍是 infer 态: DTO gen_inferred=true + shape=pem, 列表 shape 徽标保持
    // (修复前: gen_inferred 消失 + shape 退化 plain → 徽标消失).
    const after = await (await request.get(`${SG_API}/secrets`)).json();
    const entry = after.secrets.find((s: any) => s.id === "gen-rt-inferred");
    expect(entry.mock_strategy.gen_inferred).toBe(true);
    expect(entry.mock_strategy.gen.shape.kind).toBe("pem");
    await expect(
      page.locator('#secrets-body tr[data-id="gen-rt-inferred"] .pill.shape-pem')
    ).toBeVisible();
  });

  test("#319: 未触碰 + 显式 gen → 原样回传 (含 shape, 防丢)", async ({ page, request }) => {
    // 用户显式配置 gen (prefix) — dynamic override 整条目替换语义下, 未触碰时
    // 省略 gen 会让显式配置被 infer 遮蔽 (数据丢失), 必须原样回传.
    const value = "explicit-gen-roundtrip-secret-value";
    const r = await request.post(`${SG_API}/secrets`, {
      data: {
        id: "gen-rt-explicit",
        name: "orig",
        category: "apikey",
        value,
        mock_strategy: {
          initial: { kind: "auto" },
          gen: { prefix: "keep-", charset: { lowercase: true }, length_range: [40, 40] },
        },
      },
    });
    expect(r.ok()).toBe(true);
    // 前置健全性: 显式条目的 DTO 不带 gen_inferred (false 省略).
    const pre = (await (await request.get(`${SG_API}/secrets`)).json()).secrets.find(
      (s: any) => s.id === "gen-rt-explicit"
    );
    expect(pre.mock_strategy.gen_inferred).toBeUndefined();

    const payload = await editSecretViaUi(page, "gen-rt-explicit", value);
    expect(payload.mock_strategy).not.toBeNull();
    expect(payload.mock_strategy.gen.prefix).toBe("keep-");
    // 原样回传含 shape (内部 tag 形态 {"kind":"plain"}).
    expect(payload.mock_strategy.gen.shape.kind).toBe("plain");
  });

  test("#319: 触碰 mock 高级区 → 按表单收集 (用户显式落盘)", async ({ page, request }) => {
    await request.post(`${SG_API}/secrets`, {
      data: { id: "gen-rt-inferred", name: "orig", category: "apikey", value: "touch-mock-area-secret-value-123" },
    });
    const value = "touch-mock-area-secret-value-123";

    let captured: any = null;
    await page.route(`**/api/secrets/gen-rt-inferred`, async (route) => {
      if (route.request().method() === "PUT") captured = route.request().postDataJSON();
      await route.continue();
    });
    await page.locator('a.tab[data-tab="secrets"]').click();
    const row = page.locator('#secrets-body tr[data-id="gen-rt-inferred"]');
    await expect(row).toBeVisible();
    await row.locator('button[data-action="edit"]').click();
    const dlg = page.locator("#secret-form");
    await expect(dlg).toBeVisible();
    // 触碰: 改 prefix 字段 (input 事件 → 脏标记置位).
    await page.locator("#f-ms-prefix").fill("x-");
    await page.locator("#f-name").fill("renamed");
    await page.locator("#f-value").fill(value);
    await page.locator('#secret-form-el button[value="save"]').click();
    await expect(dlg).not.toBeVisible();

    // 触碰过 → 按表单收集 (prefilled 字段 + 用户改动, 显式落盘).
    expect(captured.mock_strategy).not.toBeNull();
    expect(captured.mock_strategy.gen.prefix).toBe("x-");
  });
});

// ─── #181: 表单提交失败时对话框保持打开 + 字段保留 ────────────────────────
//
// bindFormSubmit (secret/provider 两个表单共用) 的 listener 是 async:
// 同步段跑到 `await fetch()` 即挂起, 事件派发完成后浏览器执行 method="dialog" 的
// 默认 action (关闭对话框) — 此刻响应尚未到达. 失败 alert 弹出时表单已不存在,
// 用户已填字段全部丢失 (重开表单被 openXxxForm 重置).
//
// 修复契约: save 分支进门无条件 preventDefault; 对话框关闭只发生在成功路径的
// 显式 dlg.close() (对齐 apikey 表单的既有正确写法). 可用性原则: 可逆性 —
// 失败 → 改正 → 直接重试, 无需重填.
//
// 覆盖四条路径: 409 冲突 (provider+secret) / 网络错误 (catch 分支) /
// builder 校验 (#180 分支回归) / 成功路径 (对话框正常关闭, 守护修复不破坏正向流).
test.describe("WebUI 表单失败保持 (#181)", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(500);
  });

  test("#181: provider 表单 409 冲突时对话框保持打开 + 字段保留", async ({ page }) => {
    await page.locator('a.tab[data-tab="providers"]').click();
    // 等表格渲染 (refreshProviders 完成 → state.providerWebuiProtocols 已填充,
    // 否则端点行的 protocol 下拉为空, selectOption 会失败).
    await expect(page.locator("#providers-body tr").first()).toBeVisible();

    await page.locator("button", { hasText: "+ new provider" }).click();
    const dlg = page.locator("#provider-form");
    await expect(dlg).toBeVisible();
    // 已存在的 static id (playwright.config.ts 预置) → POST 409.
    // 端点行 (multi-endpoint): 手动添加一行 (#332: 新建不预置空白行), 填第 0 行.
    await addManualEndpoint(page);
    await page.locator("#p-id").fill("mock-openai");
    await page.locator("#p-name").fill("my precious name");
    await endpointRow(page).locator(".ep-protocol").selectOption("openai");
    await endpointRow(page).locator(".ep-base-url").fill("http://127.0.0.1:19999/v1");
    await page.locator("#p-api-key").fill("sk-user-typed-key-123");

    const alerts = autoAcceptAlerts(page);
    await page.locator('#provider-form-el button[value="save"]').click();

    // 核心断言: 修复前对话框在点击瞬间被默认 action 关闭 (fetch 仍在途).
    await expect(dlg, "409 后对话框应保持打开").toBeVisible();
    await expect(page.locator("#p-id")).toHaveValue("mock-openai");
    await expect(page.locator("#p-name")).toHaveValue("my precious name");
    await expect(endpointRow(page).locator(".ep-base-url")).toHaveValue("http://127.0.0.1:19999/v1");
    await expect(page.locator("#p-api-key")).toHaveValue("sk-user-typed-key-123");
    // 失败 alert 确实弹出 (含 409 冲突语义).
    await expect
      .poll(() => alerts.length, { timeout: 3000 })
      .toBeGreaterThan(0);
    expect(alerts[0]).toContain("already exists");
    // alert 之后对话框仍打开 (防 "alert 后再关" 类回归).
    await expect(dlg).toBeVisible();

    // 清理: Cancel 关闭 (依赖默认 action, 不走 preventDefault 分支).
    await page.locator('#provider-form-el button[value="cancel"]').click();
    await expect(dlg).not.toBeVisible();
  });

  test("#181: secret 表单 409 冲突时对话框保持打开 + 字段保留", async ({ page }) => {
    await page.locator('a.tab[data-tab="secrets"]').click();
    await expect(page.locator("#secrets-body tr").first()).toBeVisible();

    await page.locator("button", { hasText: "+ new dynamic secret" }).click();
    const dlg = page.locator("#secret-form");
    await expect(dlg).toBeVisible();
    // 已存在的 static id (test-key) → POST 409.
    await page.locator("#f-id").fill("test-key");
    await page.locator("#f-name").fill("my secret name");
    await page.locator("#f-value").fill("some-typed-secret-value");

    const alerts = autoAcceptAlerts(page);
    await page.locator('#secret-form-el button[value="save"]').click();

    await expect(dlg, "409 后对话框应保持打开").toBeVisible();
    await expect(page.locator("#f-id")).toHaveValue("test-key");
    await expect(page.locator("#f-name")).toHaveValue("my secret name");
    // value 字段是敏感输入, 失败后也必须保留 (用户改 id 重试, 不应重敲 value).
    await expect(page.locator("#f-value")).toHaveValue("some-typed-secret-value");
    await expect
      .poll(() => alerts.length, { timeout: 3000 })
      .toBeGreaterThan(0);
    expect(alerts[0]).toContain("already exists");
    // alert 之后对话框仍打开 (防 "alert 后再关" 类回归).
    await expect(dlg).toBeVisible();

    await page.locator('#secret-form-el button[value="cancel"]').click();
    await expect(dlg).not.toBeVisible();
  });

  test("#181: 网络错误 (fetch reject) 时对话框保持打开 (catch 分支)", async ({ page }) => {
    await page.locator('a.tab[data-tab="providers"]').click();
    await expect(page.locator("#providers-body tr").first()).toBeVisible();

    // 模拟后端不可达: 拦截 POST /api/providers 直接 abort.
    await page.route("**/api/providers", async (route) => {
      if (route.request().method() === "POST") await route.abort("failed");
      else await route.continue();
    });

    await page.locator("button", { hasText: "+ new provider" }).click();
    const dlg = page.locator("#provider-form");
    await expect(dlg).toBeVisible();
    await page.locator("#p-id").fill("net-err-provider");
    await addManualEndpoint(page);
    await endpointRow(page).locator(".ep-protocol").selectOption("openai");
    await endpointRow(page).locator(".ep-base-url").fill("http://127.0.0.1:19999/v1");

    const alerts = autoAcceptAlerts(page);
    await page.locator('#provider-form-el button[value="save"]').click();

    await expect(dlg, "网络错误后对话框应保持打开").toBeVisible();
    await expect(page.locator("#p-id")).toHaveValue("net-err-provider");
    await expect
      .poll(() => alerts.length, { timeout: 3000 })
      .toBeGreaterThan(0);
    expect(alerts[0]).toContain("Error");
    // alert 之后对话框仍打开 (防 "alert 后再关" 类回归).
    await expect(dlg).toBeVisible();

    await page.locator('#provider-form-el button[value="cancel"]').click();
    await expect(dlg).not.toBeVisible();
  });

  test("#181: builder 校验失败 (base_url 缺失, #180) 时对话框保持打开", async ({ page }) => {
    await page.locator('a.tab[data-tab="providers"]').click();
    await expect(page.locator("#providers-body tr").first()).toBeVisible();

    await page.locator("button", { hasText: "+ new provider" }).click();
    const dlg = page.locator("#provider-form");
    await expect(dlg).toBeVisible();
    // 不填端点行 base_url (Direct 默认构造) → builder 返回 null (#180 的前端拦截分支).
    await page.locator("#p-id").fill("no-baseurl-provider");
    await addManualEndpoint(page);
    await endpointRow(page).locator(".ep-protocol").selectOption("openai");

    const alerts = autoAcceptAlerts(page);
    await page.locator('#provider-form-el button[value="save"]').click();

    await expect(dlg, "builder 校验失败后对话框应保持打开").toBeVisible();
    await expect(page.locator("#p-id")).toHaveValue("no-baseurl-provider");
    await expect
      .poll(() => alerts.length, { timeout: 3000 })
      .toBeGreaterThan(0);
    expect(alerts[0]).toContain("Base URL is required");
    // alert 之后对话框仍打开 (防 "alert 后再关" 类回归).
    await expect(dlg).toBeVisible();

    await page.locator('#provider-form-el button[value="cancel"]').click();
    await expect(dlg).not.toBeVisible();
  });

  test("webui_protocols: 存量 gemini provider 编辑 — experimental 选项 + 保存 round-trip 协议不漂移", async ({ page }) => {
    await page.goto("/");
    await page.locator('a.tab[data-tab="providers"]').click();
    // 等词表落地 (refreshProviders 完成 → select 已 populate, 同 2328 守卫 rationale).
    await expect(page.locator("#providers-body tr").first()).toBeVisible();
    const row = page.locator("#providers-body tr", { hasText: "mock-gemini" });
    await expect(row).toBeVisible();

    await row.locator('button[data-action="edit"]').click();
    const dlg = page.locator("#provider-form");
    await expect(dlg).toBeVisible();

    // gemini 不在新建词表 (webui_protocols 仅 codec 覆盖族) — 编辑回填时经
    // setEndpointProtocolValue 动态 append "(experimental)" 选项后选中.
    // multi-endpoint: 存量 gemini 条目的单端点回填为端点行 #0.
    const sel = endpointRow(page).locator(".ep-protocol");
    await expect(sel).toHaveValue("gemini");
    await expect(sel.locator('option[value="gemini"]')).toHaveText("gemini (experimental)");
    // 新建词表三族仍在 (append 不挤掉既有选项).
    for (const p of ["openai", "anthropic", "openai-responses"]) {
      await expect(sel.locator(`option[value="${p}"]`)).toBeAttached();
    }

    // 保存 round-trip: 协议必须仍是 gemini (回归形态 = select 落回首个 codec
    // 选项, 保存时静默把 gemini 改写成 openai — 数据完整性).
    await page.locator('#provider-form-el button[value="save"]').click();
    await expect(dlg).not.toBeVisible();
    await row.locator('button[data-action="edit"]').click();
    await expect(dlg).toBeVisible();
    await expect(endpointRow(page).locator(".ep-protocol")).toHaveValue("gemini");
    await page.locator('#provider-form-el button[value="cancel"]').click();
    await expect(dlg).not.toBeVisible();
  });

  test("#181: 成功路径对话框正常关闭 + 新条目出现 (守护正向流)", async ({ page }) => {
    await page.locator('a.tab[data-tab="providers"]').click();
    await expect(page.locator("#providers-body tr").first()).toBeVisible();

    // 唯一 id: 与其他测试隔离 (workers=1 共享 server state, 不清理也无害).
    const uid = `ok-provider-${Date.now()}`;
    await page.locator("button", { hasText: "+ new provider" }).click();
    const dlg = page.locator("#provider-form");
    await expect(dlg).toBeVisible();
    await page.locator("#p-id").fill(uid);
    await addManualEndpoint(page);
    await endpointRow(page).locator(".ep-protocol").selectOption("openai");
    await endpointRow(page).locator(".ep-base-url").fill("http://127.0.0.1:19999/v1");

    await page.locator('#provider-form-el button[value="save"]').click();

    // 修复后 dlg.close() 从 no-op 变为唯一关闭点: 成功路径必须关闭.
    await expect(dlg, "成功后对话框应关闭").not.toBeVisible();
    // 新条目渲染进表格.
    await expect(
      page.locator("#providers-body tr", { hasText: uid })
    ).toBeVisible();
  });
});

// ─── #348: 编辑动态 reset — 撤销 dynamic override 回 static 基线 ──────────
//
// 缺口 (issue #348): "编辑动态" 表单 (static_preferred / dynamic_override 行) 只有
// 更新/取消, 无法 "重置为空态 (未覆盖状态)". 本 describe 守卫:
//   1. 编辑动态表单渲染 reset 按钮 + hover title 语义说明;
//   2. confirm 取消不改状态 / 确认后条目回 static 基线 (override 按钮 + decision=default);
//   3. 无可重置场景 (static-only / 纯 dynamic) 不渲染 reset 按钮.
test.describe("#348: 编辑动态 reset (撤销 dynamic override)", () => {
  // 状态卫生: 还原被 fork 的 static 条目到基线 (reset 端点幂等, 已是基线时 no-op);
  // 清理本 describe 创建的 dynamic-only 条目 (DELETE 幂等, 404 无害).
  test.afterEach(async ({ request }) => {
    await request.delete(`${SG_API}/secrets/test-key/override`);
    await request.delete(`${SG_API}/providers/mock-gemini/override`);
    await request.delete(`${SG_API}/secrets/dyn-only-348`);
  });

  /** fork static secret: PUT 创建 dynamic override + PATCH prefer_static → static_preferred. */
  async function forkSecretToStaticPreferred(request: any, id: string, value: string) {
    const put = await request.put(`${SG_API}/secrets/${id}`, { data: { value } });
    expect(put.ok()).toBe(true);
    const patch = await request.patch(`${SG_API}/secrets/${id}/decision`, {
      data: { mode: "prefer_static" },
    });
    expect(patch.ok()).toBe(true);
  }

  test("secret: reset 可见+tooltip; confirm 取消保持, 确认后回 static 基线", async ({
    page,
    request,
  }) => {
    await forkSecretToStaticPreferred(request, "test-key", "reset-flow-override-value-348");
    await page.goto("/");
    await page.locator('a.tab[data-tab="secrets"]').click();
    const row = page.locator('#secrets-body tr[data-id="test-key"]');
    await expect(row).toBeVisible();
    // static_preferred 行的编辑按钮文案是 "edit dyn" (en locale).
    await expect(row.locator('button[data-action="edit"]')).toHaveText("edit dyn");

    await row.locator('button[data-action="edit"]').click();
    const dlg = page.locator("#secret-form");
    await expect(dlg).toBeVisible();

    // reset 按钮可见 + hover title 说明语义 (issue 要求: hover 说明操作语义).
    const resetBtn = page.locator('#secret-form button.btn-reset-override');
    await expect(resetBtn).toBeVisible();
    const title = await resetBtn.getAttribute("title");
    expect(title, "reset 按钮 title 必须非空 (hover 语义说明)").toBeTruthy();
    expect(title).toContain("static");

    // confirm 取消: 表单保持打开, 状态未变.
    let sawConfirm = false;
    let confirmMsg = "";
    page.once("dialog", async (d) => {
      sawConfirm = true;
      confirmMsg = d.message();
      await d.dismiss();
    });
    await resetBtn.click();
    await page.waitForTimeout(200);
    expect(sawConfirm, "reset 必须有 confirm 二次确认").toBe(true);
    // confirm 文案点名目标条目 (防误重置其他条目的歧义确认).
    expect(confirmMsg).toContain("test-key");
    await expect(dlg).toBeVisible();

    // confirm 确认: 表单关闭, 行回到 static 基线 — 按钮变 override, decision 回 default.
    page.once("dialog", async (d) => await d.accept());
    await resetBtn.click();
    await expect(dlg).not.toBeVisible();
    await expect(
      page.locator('#secrets-body tr[data-id="test-key"] button[data-action="edit"]')
    ).toHaveText("override");
    await expect(
      page.locator('#secrets-body tr[data-id="test-key"] select.decision-select')
    ).toHaveValue("default");
  });

  test("provider: 同型 reset — 撤销 override 回 static 基线", async ({ page, request }) => {
    // fork static provider mock-gemini (direct + gemini 端点全量回传) + prefer_static.
    const put = await request.put(`${SG_API}/providers/mock-gemini`, {
      data: {
        name: "gemini-override-348",
        endpoints: [{ protocol: "gemini", base_url: "http://127.0.0.1:19999" }],
      },
    });
    expect(put.ok()).toBe(true);
    const patch = await request.patch(`${SG_API}/providers/mock-gemini/decision`, {
      data: { mode: "prefer_static" },
    });
    expect(patch.ok()).toBe(true);

    await page.goto("/");
    await page.locator('a.tab[data-tab="providers"]').click();
    const row = page.locator('#providers-body tr[data-id="mock-gemini"]');
    await expect(row).toBeVisible();
    await expect(row.locator('button[data-action="edit"]')).toHaveText("edit dyn");

    await row.locator('button[data-action="edit"]').click();
    const dlg = page.locator("#provider-form");
    await expect(dlg).toBeVisible();
    const resetBtn = page.locator('#provider-form button.btn-reset-override');
    await expect(resetBtn).toBeVisible();

    page.once("dialog", async (d) => await d.accept());
    await resetBtn.click();
    await expect(dlg).not.toBeVisible();
    await expect(
      page.locator('#providers-body tr[data-id="mock-gemini"] button[data-action="edit"]')
    ).toHaveText("override");
  });

  test("无可重置场景不渲染 reset (static-only / 纯 dynamic)", async ({ page, request }) => {
    // 卫生: 确保 test-key 处于 static 基线 (前面用例的 afterEach 已还原, 双保险).
    await request.delete(`${SG_API}/secrets/test-key/override`);

    // static-only (override 按钮): 无覆盖可撤销 → reset 隐藏.
    await page.goto("/");
    await page.locator('a.tab[data-tab="secrets"]').click();
    const staticRow = page.locator('#secrets-body tr[data-id="test-key"]');
    await expect(staticRow.locator('button[data-action="edit"]')).toHaveText("override");
    await staticRow.locator('button[data-action="edit"]').click();
    await expect(page.locator("#secret-form")).toBeVisible();
    await expect(page.locator('#secret-form button.btn-reset-override')).toBeHidden();
    await page.locator('#secret-form-el button[value="cancel"]').click();

    // 纯 dynamic 条目: "空态" = 行级 Delete 的既有管辖, 表单内不渲染 reset.
    const r = await request.post(`${SG_API}/secrets`, {
      data: { id: "dyn-only-348", value: "pure-dynamic-value-348" },
    });
    expect(r.ok()).toBe(true);
    await page.locator('a.tab[data-tab="secrets"]').click(); // 显式点击 = 即时刷新
    const dynRow = page.locator('#secrets-body tr[data-id="dyn-only-348"]');
    await expect(dynRow).toBeVisible();
    await dynRow.locator('button[data-action="edit"]').click();
    await expect(page.locator("#secret-form")).toBeVisible();
    await expect(page.locator('#secret-form button.btn-reset-override')).toBeHidden();
    await page.locator('#secret-form-el button[value="cancel"]').click();
  });
});

test.describe("Provider 表单构造分野 (#190)", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(500);
    await page.locator('a.tab[data-tab="providers"]').click();
    await expect(page.locator("#providers-body tr").first()).toBeVisible();
  });

  test("#190: 新建 Direct — 默认构造, Direct 字段组可见 / Router 字段组隐藏", async ({ page }) => {
    await page.locator("button", { hasText: "+ new provider" }).click();
    const dlg = page.locator("#provider-form");
    await expect(dlg).toBeVisible();

    // 默认 direct: 检测台 URL 输入 / API Key / 添加协议按钮可见; 路由编辑器隐藏.
    // (#332: 新建不预置端点行 — 断言组内代表字段而非 display:contents wrapper,
    // 后者无盒, 可见性断言依赖浏览器实现细节.)
    await expect(page.locator("#p-detect-url")).toBeVisible();
    await expect(page.locator("#p-api-key")).toBeVisible();
    await expect(page.locator("#p-endpoint-add")).toBeVisible();
    await expect(page.locator(".endpoint-row")).toHaveCount(0);
    await expect(page.locator("#p-routes-list")).not.toBeVisible();

    const uid = `direct-${Date.now()}`;
    await page.locator("#p-id").fill(uid);
    await addManualEndpoint(page);
    await endpointRow(page).locator(".ep-protocol").selectOption("openai");
    await endpointRow(page).locator(".ep-base-url").fill("http://127.0.0.1:19998");

    await page.locator('#provider-form-el button[value="save"]').click();
    await expect(dlg).not.toBeVisible();

    const row = page.locator("#providers-body tr", { hasText: uid });
    await expect(row).toBeVisible();
    // Direct 行: 显示 base_url, 无 router pill.
    await expect(row).toContainText("127.0.0.1:19998");
    await expect(row.locator(".pill", { hasText: "router" })).toHaveCount(0);

    // 清理 (dynamic-only 可删): 注册 dialog handler 接受 confirm, DELETE 真实发出.
    autoAcceptAlerts(page);
    await row.locator('button[data-action="delete"]').click();
    await expect(row).not.toBeVisible();
  });

  test("#190: 新建 Router — 切构造后字段组对调, 路由行提交 + 列表渲染摘要", async ({ page }) => {
    await page.locator("button", { hasText: "+ new provider" }).click();
    const dlg = page.locator("#provider-form");
    await expect(dlg).toBeVisible();

    // 切 router: 字段组对调.
    await page.locator("#p-kind").selectOption("router");
    await expect(page.locator("#p-routes-list")).toBeVisible();
    await expect(page.locator("#p-detect-url")).not.toBeVisible();

    const uid = `router-${Date.now()}`;
    await page.locator("#p-id").fill(uid);
    // 默认一行空白路由: 填 model_pattern + 目标 (预置 static provider mock-openai).
    await page.locator(".route-row").nth(0).locator(".route-model-pattern").fill("gpt-*");
    await page.locator(".route-row").nth(0).locator(".route-target").selectOption("mock-openai");

    await page.locator('#provider-form-el button[value="save"]').click();
    await expect(dlg).not.toBeVisible();

    const row = page.locator("#providers-body tr", { hasText: uid });
    await expect(row).toBeVisible();
    await expect(row.locator(".pill", { hasText: "router" })).toBeVisible();
    // URL 列显示路由摘要 (model_pattern → target + per-route egress 后缀), 而非空.
    await expect(row).toContainText("gpt-* → mock-openai");
    await expect(row).toContainText("· openai");
    // protocol pill = 路由 egress 的去重集合 (单一 → 'openai'; Router 构造无 protocol).
    await expect(row.locator(".pill", { hasText: "openai" })).toBeVisible();

    autoAcceptAlerts(page);
    await row.locator('button[data-action="delete"]').click();
    await expect(row).not.toBeVisible();
  });

  test("#190: 构造内必填前置校验 — Router 路由行缺 model_pattern 时阻止提交", async ({ page }) => {
    await page.locator("button", { hasText: "+ new provider" }).click();
    const dlg = page.locator("#provider-form");
    await expect(dlg).toBeVisible();
    await page.locator("#p-kind").selectOption("router");

    const alerts = autoAcceptAlerts(page);
    // id 填了但路由行留空 (model_pattern 空 → 前端拦截).
    await page.locator("#p-id").fill(`no-target-${Date.now()}`);
    await page.locator('#provider-form-el button[value="save"]').click();

    await expect
      .poll(() => alerts.length, { timeout: 3000 })
      .toBeGreaterThan(0);
    expect(alerts[0]).toContain("model_pattern is required");
    await expect(dlg, "校验失败对话框保持打开").toBeVisible();

    await page.locator('#provider-form-el button[value="cancel"]').click();
  });

  test("#190: 编辑 Router 条目 — kind 初始化 + 切 Direct 触发 base_url 必填校验", async ({ page }) => {
    // 先建一个 router (复用 #190 创建路径).
    await page.locator("button", { hasText: "+ new provider" }).click();
    await page.locator("#p-kind").selectOption("router");
    const uid = `edit-${Date.now()}`;
    await page.locator("#p-id").fill(uid);
    await page.locator(".route-row").nth(0).locator(".route-model-pattern").fill("*");
    await page.locator(".route-row").nth(0).locator(".route-target").selectOption("mock-openai");
    await page.locator('#provider-form-el button[value="save"]').click();
    const row = page.locator("#providers-body tr", { hasText: uid });
    await expect(row).toBeVisible();

    // 编辑: kind 选择器初始化为 router, 路由行回填 (1 行, model_pattern '*').
    await row.locator('button[data-action="edit"]').click();
    const dlg = page.locator("#provider-form");
    await expect(dlg).toBeVisible();
    await expect(page.locator("#p-kind")).toHaveValue("router");
    await expect(page.locator(".route-row")).toHaveCount(1);
    await expect(page.locator(".route-row .route-model-pattern")).toHaveValue("*");

    // 切 Direct (#187 改回实体场景): 0 端点行 → "at least one endpoint" 拦截.
    const alerts = autoAcceptAlerts(page);
    await page.locator("#p-kind").selectOption("direct");
    await page.locator('#provider-form-el button[value="save"]').click();
    await expect
      .poll(() => alerts.length, { timeout: 3000 })
      .toBeGreaterThan(0);
    expect(alerts[0]).toContain("At least one endpoint is required");

    // 补上端点行后成功改回 Direct (kind 切换生效) — Direct 分支对 Router
    // 旧条目发空 routes 数组 ("显式改回实体"; PUT 省略 routes 会被后端回填旧路由
    // 停留在 Router).
    await addManualEndpoint(page);
    await endpointRow(page).locator(".ep-base-url").fill("http://127.0.0.1:19997");
    await page.locator("#p-api-key").fill("sk-after-switch");
    await page.locator('#provider-form-el button[value="save"]').click();
    await expect(dlg).not.toBeVisible();
    const updated = page.locator("#providers-body tr", { hasText: uid });
    await expect(updated).toContainText("127.0.0.1:19997");
    await expect(updated.locator(".pill", { hasText: "router" })).toHaveCount(0);

    await updated.locator('button[data-action="delete"]').click();
    await expect(updated).not.toBeVisible();
  });

  // ─── #179: 路由编辑器冒烟 — 增删行 / 禁用行 (checkbox) / PUT 后摘要渲染 ────
  test("#179: 路由编辑器 — 增删行 / 禁用行 / PUT 后列表渲染路由摘要", async ({ page }) => {
    await page.locator("button", { hasText: "+ new provider" }).click();
    const dlg = page.locator("#provider-form");
    await expect(dlg).toBeVisible();
    await page.locator("#p-kind").selectOption("router");
    const uid = `routes-${Date.now()}`;
    await page.locator("#p-id").fill(uid);

    // 行 1 (默认空白): gpt-* → mock-openai, 保持启用.
    await page.locator(".route-row").nth(0).locator(".route-model-pattern").fill("gpt-*");
    await page.locator(".route-row").nth(0).locator(".route-target").selectOption("mock-openai");
    // + Add route 增行: 第二条填好后取消启用 checkbox (priority null = 禁用).
    await page.locator("#p-route-add").click();
    await expect(page.locator(".route-row")).toHaveCount(2);
    await page.locator(".route-row").nth(1).locator(".route-model-pattern").fill("claude-*");
    await page.locator(".route-row").nth(1).locator(".route-target").selectOption("mock-openai");
    await page.locator(".route-row").nth(1).locator(".route-enabled").uncheck();
    // 再增一行又删掉 (行删除按钮冒烟).
    await page.locator("#p-route-add").click();
    await expect(page.locator(".route-row")).toHaveCount(3);
    await page.locator(".route-row").nth(2).locator(".route-del").click();
    await expect(page.locator(".route-row")).toHaveCount(2);

    await page.locator('#provider-form-el button[value="save"]').click();
    await expect(dlg).not.toBeVisible();

    // 列表摘要 (POST 后): ≤2 条不折叠, 两条都在; 禁用路由主文本 <s> 删除线; egress 后缀.
    const row = page.locator("#providers-body tr", { hasText: uid });
    await expect(row).toBeVisible();
    await expect(row).toContainText("gpt-* → mock-openai");
    await expect(row).toContainText("claude-*");
    await expect(row.locator("s")).toHaveCount(1);
    await expect(row).toContainText("· openai");

    // 编辑 (PUT): 回填 2 行, 禁用态保持; 再禁用第一行 → 摘要两条都删除线.
    await row.locator('button[data-action="edit"]').click();
    await expect(dlg).toBeVisible();
    await expect(page.locator(".route-row")).toHaveCount(2);
    await expect(page.locator(".route-row").nth(0).locator(".route-enabled")).toBeChecked();
    await expect(page.locator(".route-row").nth(1).locator(".route-enabled")).not.toBeChecked();
    await page.locator(".route-row").nth(0).locator(".route-enabled").uncheck();
    await page.locator('#provider-form-el button[value="save"]').click();
    await expect(dlg).not.toBeVisible();
    await expect(row.locator("s")).toHaveCount(2);

    autoAcceptAlerts(page);
    await row.locator('button[data-action="delete"]').click();
    await expect(row).not.toBeVisible();
  });

});

test.describe("Provider 多端点表单 (multi-endpoint)", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(500);
    await page.locator('a.tab[data-tab="providers"]').click();
    await expect(page.locator("#providers-body tr").first()).toBeVisible();
  });

  // multi-endpoint 主链路冒烟: 增删行 → 双端点保存 round-trip → 列表每端点一枚
  // pill + 第一端点 base_url (+N 角标) → 编辑回填两行协议不漂移 (声明序 = fallback
  // 序, 数据完整性). 途中覆盖 ≥1 行 / 重复协议两条前端前置拦截.
  test("端点行增删 + ≥1/重复协议拦截 + 保存 round-trip + 每端点 pill", async ({ page }) => {
    await page.locator("button", { hasText: "+ new provider" }).click();
    const dlg = page.locator("#provider-form");
    await expect(dlg).toBeVisible();
    // #332: 新建不预置协议行 (检测/手动添加产生行).
    await expect(page.locator(".endpoint-row")).toHaveCount(0);
    const uid = `multi-${Date.now()}`;
    await page.locator("#p-id").fill(uid);
    // 手动添加 → 行 1: openai (默认) + base_url.
    await addManualEndpoint(page);
    await expect(page.locator(".endpoint-row")).toHaveCount(1);
    await endpointRow(page).locator(".ep-base-url").fill("http://127.0.0.1:19999");
    // + 添加协议 → 行 2: anthropic + base_url.
    await page.locator("#p-endpoint-add").click();
    await expect(page.locator(".endpoint-row")).toHaveCount(2);
    await endpointRow(page, 1).locator(".ep-protocol").selectOption("anthropic");
    await endpointRow(page, 1).locator(".ep-base-url").fill("http://127.0.0.1:19999/anthropic");

    // 前置拦截 #1: 重复协议 (行 2 改回 openai → save → alert, 对话框保持).
    await endpointRow(page, 1).locator(".ep-protocol").selectOption("openai");
    const alerts = autoAcceptAlerts(page);
    await page.locator('#provider-form-el button[value="save"]').click();
    await expect.poll(() => alerts.length, { timeout: 3000 }).toBeGreaterThan(0);
    expect(alerts[0]).toContain("duplicate protocol");
    await expect(dlg, "重复协议拦截后对话框应保持打开").toBeVisible();

    // 行删除冒烟: 增第三行再删掉, 回到 2 行 (行 2 改回 anthropic).
    await endpointRow(page, 1).locator(".ep-protocol").selectOption("anthropic");
    await page.locator("#p-endpoint-add").click();
    await expect(page.locator(".endpoint-row")).toHaveCount(3);
    await endpointRow(page, 2).locator(".ep-del").click();
    await expect(page.locator(".endpoint-row")).toHaveCount(2);

    await page.locator('#provider-form-el button[value="save"]').click();
    await expect(dlg, "成功后对话框应关闭").not.toBeVisible();

    // 列表渲染: 每端点一枚 protocol pill + URL cell = 第一端点 base_url (+1 角标).
    const row = page.locator("#providers-body tr", { hasText: uid });
    await expect(row).toBeVisible();
    await expect(row.locator(".pill", { hasText: /^openai$/ })).toBeVisible();
    await expect(row.locator(".pill", { hasText: /^anthropic$/ })).toBeVisible();
    await expect(row).toContainText("127.0.0.1:19999");
    await expect(row.locator("td.cell-long .meta")).toHaveText("+1");

    // 编辑回填: 两行全量物化, 协议/base_url 不漂移 (声明序保持).
    await row.locator('button[data-action="edit"]').click();
    await expect(dlg).toBeVisible();
    await expect(page.locator(".endpoint-row")).toHaveCount(2);
    await expect(endpointRow(page).locator(".ep-protocol")).toHaveValue("openai");
    await expect(endpointRow(page).locator(".ep-base-url")).toHaveValue("http://127.0.0.1:19999");
    await expect(endpointRow(page, 1).locator(".ep-protocol")).toHaveValue("anthropic");
    await expect(endpointRow(page, 1).locator(".ep-base-url")).toHaveValue("http://127.0.0.1:19999/anthropic");
    await page.locator('#provider-form-el button[value="cancel"]').click();

    // 清理 (dynamic-only 可删): 注册 dialog handler 接受 confirm.
    await row.locator('button[data-action="delete"]').click();
    await expect(row).not.toBeVisible();
  });

  test("≥1 行约束: 删到 0 行后保存被前端拦截", async ({ page }) => {
    await page.locator("button", { hasText: "+ new provider" }).click();
    const dlg = page.locator("#provider-form");
    await expect(dlg).toBeVisible();
    await page.locator("#p-id").fill(`empty-eps-${Date.now()}`);
    await addManualEndpoint(page);
    await endpointRow(page).locator(".ep-base-url").fill("http://127.0.0.1:19999");
    await endpointRow(page).locator(".ep-del").click();
    await expect(page.locator(".endpoint-row")).toHaveCount(0);

    const alerts = autoAcceptAlerts(page);
    await page.locator('#provider-form-el button[value="save"]').click();
    await expect.poll(() => alerts.length, { timeout: 3000 }).toBeGreaterThan(0);
    expect(alerts[0]).toContain("At least one endpoint is required");
    await expect(dlg, "0 行拦截后对话框应保持打开").toBeVisible();

    await page.locator('#provider-form-el button[value="cancel"]').click();
    await expect(dlg).not.toBeVisible();
  });

  test("direct 条目 endpoints 弹窗: 每端点一行 (upstream ↤ 入口 URL + Models)", async ({ page }) => {
    // 动态建一个双端点 direct 条目 (复用上一用例的表单路径, 精简到最小).
    await page.locator("button", { hasText: "+ new provider" }).click();
    const uid = `eps-dlg-${Date.now()}`;
    await page.locator("#p-id").fill(uid);
    await addManualEndpoint(page);
    await endpointRow(page).locator(".ep-base-url").fill("http://127.0.0.1:19999");
    await page.locator("#p-endpoint-add").click();
    await endpointRow(page, 1).locator(".ep-protocol").selectOption("anthropic");
    await endpointRow(page, 1).locator(".ep-base-url").fill("http://127.0.0.1:19999/anthropic");
    await page.locator('#provider-form-el button[value="save"]').click();
    const row = page.locator("#providers-body tr", { hasText: uid });
    await expect(row).toBeVisible();

    // 弹窗: 每端点一行, data-short = 该端点协议 short; 行内 upstream base_url +
    // 入口 URL 并列, badge 恒 direct (同协议透传, 无 translate/unsupported 形态).
    await row.locator('button[data-action="endpoints"]').click();
    const dlg = page.locator("#provider-endpoints");
    await expect(dlg).toBeVisible();
    await expect(dlg.locator(".ep-row")).toHaveCount(2);
    await expect(dlg.locator('.ep-row[data-short="o"] .ep-proto')).toHaveText("openai");
    await expect(dlg.locator('.ep-row[data-short="o"] .badge')).toHaveText("direct");
    await expect(dlg.locator('.ep-row[data-short="o"] .ep-url')).toContainText("http://127.0.0.1:19999");
    await expect(dlg.locator('.ep-row[data-short="o"] .ep-url')).toContainText(`/${uid}`);
    await expect(dlg.locator('.ep-row[data-short="a"] .ep-proto')).toHaveText("anthropic");
    await expect(dlg.locator('.ep-row[data-short="a"] .badge')).toHaveText("direct");
    // 每行 Models 按钮 + fallback hint (body 直接子元素, 不受 dialog header 的
    // 静态 hint 干扰).
    await expect(dlg.locator(".ep-models-btn")).toHaveCount(2);
    await expect(dlg.locator("#provider-endpoints-body > .hint")).toContainText("fall back to the first endpoint");
    await dlg.locator('button[value="close"]').click();
    await expect(dlg).not.toBeVisible();

    autoAcceptAlerts(page);
    await row.locator('button[data-action="delete"]').click();
    await expect(row).not.toBeVisible();
  });
});

test.describe("Provider endpoints 弹窗 (M2 走查 + 行卡片重设计)", () => {
  // URL Copy / 模型 chip 复制断言需要 clipboard 权限 (headless Chromium 默认拒绝
  // → 复制走 catch 分支, flash 永不出现). 本 describe 顶层统一授予.
  test.use({ permissions: ["clipboard-write"] });
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.locator('a.tab[data-tab="providers"]').click();
    // 等表格渲染 (refreshProviders 完成 → state.providerShorts/Protocols 已填充).
    await expect(page.locator("#providers-body tr").first()).toBeVisible();
  });

  // M2 走查回归: translate 徽章的流式语义必须与实际行为一致 — codec 覆盖族
  // (openai/anthropic/openai-responses) 任意 pair 流式翻译均已接入 (StreamTranslate;
  // Responses 流式 writer 落地后统一, 不再按 pair 分化). 历史缺陷: tooltip 写死
  // "Non-streaming only" (过时的 #183 前文案), 且 CODEC_SUPPORTED 缺
  // openai-responses (Responses 行误显示 "not supported" — Responses⇄Chat
  // 翻译实际可用).
  // multi-endpoint 后 direct 条目的弹窗改为 per 端点行形态, 矩阵宿主 = mock-router
  // (种子 router 条目, 链尾 = mock-openai 的 openai 单端点 — 三态断言不变);
  // data-id 精确定位: mock-router 行 URL 列含 "mock-openai" 路由摘要, hasText
  // 会双匹配.
  test("router provider: direct/translate 三态矩阵 + 流式 tooltip 统一", async ({ page }) => {
    await page.locator('button[data-action="endpoints"][data-id="mock-router"]').click();
    const dlg = page.locator("#provider-endpoints");
    await expect(dlg).toBeVisible();

    const rowOf = (short: string) => dlg.locator(`.ep-row[data-short="${short}"]`);
    const badgeOf = (short: string) => rowOf(short).locator(".badge");

    // 主题行回显 provider id (重设计新增).
    await expect(dlg.locator("#provider-endpoints-subject")).toContainText("mock-router");

    // /o/ 同协议 → direct.
    await expect(badgeOf("o")).toHaveText("direct");
    // /a/ 跨协议 (OpenAI⇄Anthropic) → translate, 流式已接入 (不得再声称 non-streaming only).
    await expect(badgeOf("a")).toHaveText("translate");
    await expect(badgeOf("a")).toHaveAttribute("title", /streaming included/);
    await expect(badgeOf("a")).not.toHaveAttribute("title", /[Nn]on-streaming only/);
    // /r/ 跨协议 (Responses⇄Chat) → translate (非 not supported), 流式 tooltip
    // 统一 (Responses 流式落地后与 /a/ 同文案).
    await expect(badgeOf("r")).toHaveText("translate");
    await expect(badgeOf("r")).toHaveAttribute("title", /streaming included/);
    await expect(badgeOf("r")).not.toHaveAttribute("title", /[Nn]on-streaming only/);
    // /g/ /l/ 无 codec → not supported.
    await expect(rowOf("g").locator(".unsupported")).toHaveText("not supported");
    await expect(rowOf("l").locator(".unsupported")).toHaveText("not supported");

    // 行卡片结构回归 (重设计): 支持行 = URL code + Copy + Models 按钮;
    // 不支持行 = 三者皆无 (不引导不可用动作).
    for (const short of ["o", "a", "r"]) {
      await expect(rowOf(short).locator(".ep-url > code")).toBeVisible();
      await expect(rowOf(short).locator(".ep-copy")).toBeVisible();
      await expect(rowOf(short).locator(".ep-models-btn")).toBeVisible();
    }
    for (const short of ["g", "l"]) {
      await expect(rowOf(short).locator(".ep-copy")).toHaveCount(0);
      await expect(rowOf(short).locator(".ep-models-btn")).toHaveCount(0);
    }
  });

  // Models 预览 (GET /api/providers/{id}/models): direct provider 现场 fetch
  // 上游清单 → chips 渲染 + 点击复制 + 收起/展开命中会话级缓存 (不重复 fetch).
  // multi-endpoint: direct 弹窗行 = 端点行 (data-short = 该端点协议 short),
  // preview API 是条目级 (统一 OpenAI 视角选端点 — 后端 T1 微决策), 行内按钮
  // 拉同一 API. data-id 精确定位 (mock-router 行含 "mock-openai" 文本, hasText 双匹配).
  test("Models 预览: direct happy path + chip 复制 + 展开缓存", async ({ page }) => {
    await page.locator('button[data-action="endpoints"][data-id="mock-openai"]').click();
    const dlg = page.locator("#provider-endpoints");
    const oRow = dlg.locator('.ep-row[data-short="o"]');
    const btn = oRow.locator(".ep-models-btn");

    await btn.click();
    await expect(oRow.locator(".probe-models-title")).toContainText("Models (3)");
    // 来源标注: direct = 自身上游.
    await expect(oRow.locator(".probe-models-title")).toContainText("upstream: mock-openai");
    await expect(oRow.locator(".probe-chip")).toHaveCount(3);
    // chip 点击复制 (与 Detect 探测同款交互).
    await oRow.locator(".probe-chip").first().click();
    await expect(oRow.locator(".probe-chip").first()).toHaveText("✓ copied");

    // 收起 (active 态随之解除) → 再展开: dataset.loaded 缓存直接渲染.
    await btn.click();
    await expect(oRow.locator(".ep-models")).toBeHidden();
    await expect(btn).not.toHaveClass(/active/);
    await btn.click();
    await expect(oRow.locator(".probe-models-title")).toContainText("Models (3)");
  });

  // 失败是数据 (与 probe 同姿态): 上游无该协议的清单端点 (seeded gemini provider
  // 的上游不 serve /v1beta/models) → 面板内错误行, 不是 HTTP 错误弹窗.
  test("Models 预览: 上游清单端点缺失 → 面板内错误行", async ({ page }) => {
    await page.locator('button[data-action="endpoints"][data-id="mock-gemini"]').click();
    const dlg = page.locator("#provider-endpoints");
    const gRow = dlg.locator('.ep-row[data-short="g"]');
    await gRow.locator(".ep-models-btn").click();
    await expect(gRow.locator(".probe-line-err")).toContainText("upstream returned 404");
  });
});

test.describe("usage-stats (模型用量统计)", () => {
  // ─── usage-stats: Usage tab 冒烟 (数据流端到端 + 无脚本错误) ─────────────
  //
  // mock upstream 的 chat 响应带 usage (prompt 10 / completion 20, mock_upstream.py).
  // 发一个请求 → 切 Usage tab → 汇总卡应显示 requests=1 且 token 维度非零
  // (整条链: 回显采集 → store → /api/usage/summary → 前端渲染). 定价拉取在无外网
  // 环境为 offline (卡片仍渲染, ~cost 显示 $0), 不作断言对象.
  test("usage-stats: Usage tab 渲染请求与 token 汇总", async ({ page }) => {
    await page.goto("/");
    await sendChat(page, [{ role: "user", content: "hi for usage" }]);
    await page.locator('a.tab[data-tab="usage"]').click();
    // 按标签语义定位卡片 (不依赖 DOM 顺序, 抗未来卡片增删).
    const cardVal = (label: string) =>
      page.locator("#usage-cards .usage-card", { hasText: label }).locator(".v");
    // requests 卡: 至少 1 (轮询 5s 内到达; 给足 12s).
    await expect
      .poll(async () => cardVal("requests").innerText(), { timeout: 12_000 })
      .not.toBe("0");
    // token 卡非零 (input = 10: mock 回显归一化后).
    await expect
      .poll(async () => cardVal("input").innerText(), { timeout: 12_000 })
      .not.toBe("0");
    // by model 表出现行 (model 列含 mock 回显的 model 名).
    await expect
      .poll(async () => page.locator("#usage-by-model-body tr").count(), { timeout: 12_000 })
      .toBeGreaterThan(0);
    // 脚本零错误 (渲染路径无异常).
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(String(e)));
    await page.waitForTimeout(300);
    expect(errors).toEqual([]);
  });

  // ─── usage 表格溢出守卫: td 内容不溢出盒子 (redaction 文字重叠回归) ──────
  //
  // 历史 bug: usage 页 4 表 (class="secrets usage-table") 继承 table.secrets 的
  // per-column max-width 约束, 而 .usage-table td 是 white-space: nowrap; 渲染器
  // 未按 F1 约定包 .cell-ellipsis → 长 mock / 长 secret_id 溢出 td 盒子画到相邻列
  // (视觉上文字重叠).
  //
  // property (外部可观察行为, 不过拟合实现): 4 个 tbody 内所有 td 的
  // scrollWidth ≤ clientWidth (+1px 容差) — 浏览器原生的 paint 级溢出度量.
  // 前置: 发送含 static secret (fixtures.ts, 长值 → mock 决定性超宽) 的请求,
  // 并等 redactions / by-model 两表都有数据 — 防部分表空态 vacuous 通过.
  test("usage-stats: usage 表格 td 内容不溢出盒子 (redaction 文字重叠回归)", async ({ page }) => {
    await page.goto("/");
    await sendChat(page, [
      { role: "user", content: `usage-overlap-marker secret=${TEST_SECRET_VALUE}` },
    ]);
    await page.locator('a.tab[data-tab="usage"]').click();
    // tab 切换立即 refreshUsage; store writer 即时批量落库.
    const dataRows = (tbodyId: string) =>
      page.locator(`#${tbodyId} tr:not(:has(td.empty))`).count();
    await expect.poll(async () => dataRows("redact-by-secret-body"), { timeout: 15_000 })
      .toBeGreaterThan(0);
    await expect.poll(async () => dataRows("usage-by-model-body"), { timeout: 15_000 })
      .toBeGreaterThan(0);

    // 度量口径: scrollWidth vs clientWidth (浏览器原生的溢出度量, 反映 paint 级溢出).
    // 不用 Range.getBoundingClientRect — 它返回布局几何, 不被 overflow:hidden 裁剪,
    // 会把已正确截断的 .cell-ellipsis 内容误报为溢出.
    const overflows = await page.evaluate(() => {
      const bad: Array<{
        table: string; row: number; col: number;
        clientW: number; scrollW: number; text: string;
      }> = [];
      const tids = [
        "usage-by-model-body", "usage-by-provider-body",
        "redact-by-secret-body", "redact-recent-body",
      ];
      for (const tid of tids) {
        const tb = document.getElementById(tid);
        if (!tb) continue;
        tb.querySelectorAll("tr").forEach((tr, ri) => {
          Array.from(tr.querySelectorAll("td")).forEach((td, ci) => {
            if (td.scrollWidth > td.clientWidth + 1) {
              bad.push({
                table: tid, row: ri, col: ci,
                clientW: td.clientWidth, scrollW: td.scrollWidth,
                text: (td.textContent || "").slice(0, 30),
              });
            }
          });
        });
      }
      return bad;
    });
    expect(
      overflows,
      `td 内容溢出盒子 (= 文字重叠): ${JSON.stringify(overflows, null, 2)}`
    ).toEqual([]);
  });

  // ─── #244: 首拉失败后不切 range 也能自愈 (节流例外回归) ──────────────────
  //
  // 走查现象 (未复现): 首次进入 Usage tab 显示 "no data", 切 range 后恢复。
  // 机制: 旧 refreshUsage 在 fetch 前消耗节流配额, 首拉失败 (瞬时网络/服务未
  // 就绪) 后 4.5s 内所有触发被吞 — 再点 tab 无效, 只有 range 按钮 (重置节流)
  // 生效。修复: 从未成功渲染过节流不生效。
  //
  // 复现: 关 auto-refresh (文件级 beforeEach 已静音 SSE → 兜底 tick 3s, auto on
  // 时旧代码 ~6s 越过节流窗被 tick 自愈会遮蔽红灯; 关掉后 tick 分派为 no-op
  // (轮询链仍跳), 无自愈路径 — 也是 "auto off 永不自愈" 的最坏场景) → route
  // abort 首个 summary 请求 → 再点一次 tab (非 range 按钮)。旧代码该触发被
  // 节流吞 (不再发请求, no data 滞留); 新代码立即重发并渲染。全程不碰 #usage-range。
  test("usage-stats: 首拉失败后再点 tab 即恢复, 不需切 range (#244)", async ({ page }) => {
    await page.goto("/");
    await sendChat(page, [{ role: "user", content: "hi for usage retry" }]);
    await page.locator("#auto").uncheck();
    let usageFetches = 0;
    await page.route("**/api/usage/summary**", async (route) => {
      usageFetches += 1;
      if (usageFetches === 1) await route.abort("connectionfailed");
      else await route.continue();
    });
    await page.locator('a.tab[data-tab="usage"]').click();
    // 首拉失败落地 (setStatus 走 status-err class, 语言无关的确定性信号) —
    // 保证随后的 tab 再点击落在 "配额已耗" 窗口内 (旧代码红灯的确定性前提)。
    await expect(page.locator("#status.status-err")).toBeVisible({ timeout: 5_000 });
    // 用户动作 = 再点一次 tab (非 range 切换), 新代码绕过节流立即重发。
    await page.locator('a.tab[data-tab="usage"]').click();
    await expect
      .poll(async () => page.locator("#usage-by-model-body tr:not(:has(td.empty))").count(), { timeout: 8_000 })
      .toBeGreaterThan(0);
    // 重试真实发生 (≥2 个 summary 请求), 数据到达非 "no data" 占位。
    expect(usageFetches).toBeGreaterThanOrEqual(2);
  });
});

// ─── Provider 创建流程: 检测台 Detect + 端点行 Verify (#332) ──────────────
//
// mock probe 上游: 独立 node http server (与 webServer 的 mock_upstream.py /
// secret-guard 进程均无关). 探测链路是 浏览器 → sg 后端 POST /api/providers/probe
// → sg 后端 GET {base_url}/v1/models 等三路 — 场景由 base_url (端口) 键控:
// fast 端口 = openai shape 即答 (结果行 openai ✓ +/v1); slow 端口 = /v1/models
// 延迟后 anthropic shape (epoch 对账用例的在途窗口); versioned 端口 = bare
// /models 200 (common_uri "" 断言); dead 端口 = 恒 404 (全 absent).

type ProbeUpstream = { url: string; close: () => Promise<void> };

// respond 收 (pathname, method) — origin 探测的 POST 存在性路由 (如
// POST /anthropic/v1/messages) 需要按方法区分 (#332 mock 上游先例).
function startProbeUpstream(
  respond: (pathname: string, method: string) => { status: number; body: string; delayMs?: number }
): Promise<ProbeUpstream> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const { status, body, delayMs } = respond(req.url ?? "", req.method ?? "GET");
      const send = () => {
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(body);
      };
      if (delayMs) setTimeout(send, delayMs);
      else send();
    });
    // bind 失败 (如 fd 耗尽) 快速报错, 而非挂到全局超时.
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as { port: number };
      resolve({
        url: `http://127.0.0.1:${port}`,
        close: () =>
          new Promise<void>((done) => {
            // 掐断 keep-alive 连接 (sg 的 reqwest 连接池), 否则 close() 要等对端
            // socket 超时才回调.
            server.closeAllConnections();
            server.close(() => done());
          }),
      });
    });
  });
}

test.describe("Provider 创建流程 (#332: detect → add → verify)", () => {
  // badge 复制断言需要 clipboard 权限 (headless Chromium 默认拒绝 → 复制走
  // catch 分支, flash 永不出现). 本 describe 顶层统一授予.
  test.use({ permissions: ["clipboard-write"] });
  let fastUpstream: ProbeUpstream;
  let slowUpstream: ProbeUpstream;
  let versionedUpstream: ProbeUpstream;
  let deadUpstream: ProbeUpstream;
  let mimoUpstream: ProbeUpstream;

  test.beforeAll(async () => {
    // fast: /v1/models → openai shape (3 models, chips 数断言用); 其余端点 404
    // (absent) — openai 面 models 证据 + responses 镜像.
    fastUpstream = await startProbeUpstream((pathname) => {
      if (pathname === "/v1/models") {
        return {
          status: 200,
          body: JSON.stringify({
            object: "list",
            data: [
              { id: "m1", object: "model" },
              { id: "m2", object: "model" },
              { id: "m3", object: "model" },
            ],
          }),
        };
      }
      return { status: 404, body: "{}" };
    });
    // slow: /v1/models 延迟 800ms 后 openai shape; 其余端点 404 即答 (epoch
    // 对账用例的慢探测窗口).
    slowUpstream = await startProbeUpstream((pathname) => {
      if (pathname === "/v1/models") {
        return {
          status: 200,
          delayMs: 800,
          body: JSON.stringify({
            object: "list",
            data: [{ id: "slow-x", object: "model" }],
          }),
        };
      }
      return { status: 404, body: "{}" };
    });
    // versioned (智谱式布局): base 已含版本前缀 — /models 200 openai shape,
    // 其余 404. 检测应命中 openai bare 面 (uri "") → 快速添加 cu "" 断言.
    versionedUpstream = await startProbeUpstream((pathname) => {
      if (pathname === "/models") {
        return {
          status: 200,
          body: JSON.stringify({
            object: "list",
            data: [{ id: "glm-4.6", object: "model" }],
          }),
        };
      }
      return { status: 404, body: "{}" };
    });
    // dead: 所有路径恒 404 — 全 absent 形态 (UI-10 用例的 "检测失败不阻塞
    // 手动填写" 被测上游).
    deadUpstream = await startProbeUpstream(() => ({ status: 404, body: "{}" }));
    // mimo (issue #332 回归钉): openai 面 (/v1, models 证据) + anthropic 面
    // (/anthropic, tier3 存在性证据: models 404 / POST messages 400 / 对照 404);
    // gemini/ollama 无路由 → absent.
    mimoUpstream = await startProbeUpstream((pathname, method) => {
      if (pathname === "/v1/models" && method === "GET") {
        return {
          status: 200,
          body: JSON.stringify({
            object: "list",
            data: [
              { id: "mimo-a", object: "model" },
              { id: "mimo-b", object: "model" },
            ],
          }),
        };
      }
      if (pathname === "/anthropic/v1/messages" && method === "POST") {
        return { status: 400, body: JSON.stringify({ type: "error" }) };
      }
      // /anthropic/v1/models (GET) 404; 随机对照 GET 404; gemini/ollama 面 404.
      return { status: 404, body: "{}" };
    });
  });

  test.afterAll(async () => {
    await fastUpstream.close();
    await slowUpstream.close();
    await versionedUpstream.close();
    await deadUpstream.close();
    await mimoUpstream.close();
  });

  test("Detect 主径: URL+Key → 检测 → 结果行 → 快速添加 → 保存 (规格①-⑤)", async ({ page }) => {
    const uid = `flow-${Date.now()}`;
    await page.goto("/");
    await page.locator('a.tab[data-tab="providers"]').click();
    await openNewProviderForm(page);
    await page.locator("#p-id").fill(uid);
    await page.locator("#p-api-key").fill("sk-flow");
    // ① 用户填端点 URL 和密钥; ② 点击检测 (probe-origin 全景矩阵).
    await page.locator("#p-detect-url").fill(fastUpstream.url);
    await page.locator("#p-detect-btn").click();
    // 结果区首行声明被探测的 URL (不黑盒 — 检测台改过也能对照), 固定 5 行
    // (openai/anthropic/gemini/ollama + responses 镜像).
    await expect(page.locator("#p-detect-results .probe-line").first()).toContainText(fastUpstream.url);
    await expect(page.locator("#p-detect-results .dr-item")).toHaveCount(5);
    // openai 行: ✓ + 命中 URI +/v1 + 证据标签 (模型清单 · 3) + chips + 添加入口.
    const oa = page.locator('.dr-item[data-protocol="openai"]');
    await expect(oa.locator(".dr-status")).toHaveText("✓");
    await expect(oa.locator(".dr-uri")).toHaveText("+/v1");
    await expect(oa.locator(".dr-detail")).toContainText("model list · 3");
    await expect(oa.locator(".probe-chip")).toHaveCount(3);
    await expect(oa.locator(".dr-add")).toBeEnabled();
    // responses 镜像行: 同证据 + 共用注记子行 (诚实呈现探测边界).
    const resp = page.locator('.dr-item[data-protocol="openai-responses"]');
    await expect(resp.locator(".dr-status")).toHaveText("✓");
    await expect(resp.locator(".dr-sub")).toContainText("与 OpenAI 共用 /v1");
    // 非 ok 行无添加入口 (建议不冒充证据).
    for (const p of ["anthropic", "gemini", "ollama"]) {
      await expect(page.locator(`.dr-item[data-protocol="${p}"] .dr-add`)).toHaveCount(0);
    }
    // ③ 结果行点击添加 → 一条端点行: protocol/base_url(=origin)/URI(=/v1) +
    // verify ✓ (models 证据直填, 不重发请求), 该结果行按钮转 "已添加" 置灰
    // (每协议一条前移约束).
    await oa.locator(".dr-add").click();
    await expect(page.locator(".endpoint-row")).toHaveCount(1);
    await expect(endpointRow(page).locator(".ep-protocol")).toHaveValue("openai");
    await expect(endpointRow(page).locator(".ep-base-url")).toHaveValue(fastUpstream.url);
    await expect(endpointRow(page).locator(".ep-common-uri")).toHaveValue("/v1");
    await expect(endpointRow(page).locator(".ep-common-uri-badge")).toHaveText("+/v1");
    await expect(endpointRow(page).locator(".ep-verify")).toHaveClass(/v-ok/);
    await expect(oa.locator(".dr-add")).toBeDisabled();
    await expect(oa.locator(".dr-add")).toHaveText("Added ✓");
    // ⑤ 保存 → 列表出现该行.
    await page.locator('#provider-form-el button[value="save"]').click();
    await expect(page.locator("#provider-form")).not.toBeVisible();
    const row = page.locator("#providers-body tr", { hasText: uid });
    await expect(row).toBeVisible();
    // 重开编辑: 检测知识回读 (URI/徽标; 未重跑检测不丢知识).
    await row.locator('button[data-action="edit"]').click();
    await expect(page.locator("#provider-form")).toBeVisible();
    await expect(endpointRow(page).locator(".ep-common-uri")).toHaveValue("/v1");
    await expect(endpointRow(page).locator(".ep-common-uri-badge")).toHaveText("+/v1");
    await page.locator('#provider-form-el button[value="cancel"]').click();

    // 入口 URL 镜像的 **"/v1 追加" 方向** (prop_entry_url_mirrors_effective_
    // common_uri 双向覆盖的另一半, versioned 用例守 "" 不追加方向): 显式
    // cu "/v1" → endpoints 弹窗入口 URL = origin/o/{id}/v1 (复制即用为 SDK
    // base_url, 不缺 /v1).
    await row.locator('button[data-action="endpoints"]').click();
    const dlg = page.locator("#provider-endpoints");
    await expect(dlg).toBeVisible();
    const entryOrigin = new URL(page.url()).origin;
    await expect(dlg.locator('.ep-row[data-short="o"] .ep-url code').last())
      .toHaveText(`${entryOrigin}/o/${uid}/v1`);
    await dlg.locator('button[value="close"]').click();
    await expect(dlg).not.toBeVisible();

    autoAcceptAlerts(page);
    await row.locator('button[data-action="delete"]').click();
    await expect(row).not.toBeVisible();
  });

  test("Detect: dialog 关闭重开后在途响应不落地 + 检测按钮复位 (probeEpoch 对账)", async ({ page }) => {
    await page.goto("/");
    await page.locator('a.tab[data-tab="providers"]').click();
    await openNewProviderForm(page);
    // 先挂 response 监听再点击: 稍后 await 它 = "旧响应确已回到浏览器" 成为
    // 前置断言 (替代固定 sleep, 消除 CI 慢时空转通过窗口)。
    const staleResponse = page.waitForResponse(
      (r) => r.url().includes("/api/providers/probe-origin") && r.request().method() === "POST"
    );
    await page.locator("#p-detect-url").fill(slowUpstream.url);
    await page.locator("#p-detect-btn").click();
    // 立即关闭并重开 dialog (重开即 epoch bump; 新世界: 检测台/结果区清空) —
    // 800ms 延迟给 close+reopen 留足窗口. 检测按钮是 dialog 内静态单例, 在途
    // finally 恢复被 epoch 对账跳过后, openProviderForm 的重置块是唯一恢复
    // 路径 — 不还原则永久卡死 (review major).
    await page.locator('#provider-form-el button[value="cancel"]').click();
    await expect(page.locator("#provider-form")).not.toBeVisible();
    await openNewProviderForm(page);
    await staleResponse;
    // 旧响应已落地浏览器: 若无 epoch 守卫, 此刻结果区会渲染旧矩阵. 断言新世界
    // 全新 — 结果区空 + 检测台空 + 按钮已复位.
    await expect(page.locator("#p-detect-results")).toBeEmpty();
    await expect(page.locator("#p-detect-results .dr-item")).toHaveCount(0);
    await expect(page.locator("#p-detect-url")).toHaveValue("");
    await expect(page.locator("#p-detect-btn")).toBeEnabled();
    await expect(page.locator("#p-detect-btn")).toHaveText("Detect");
  });

  // ─── 智谱式布局 (版本前缀已含): bare 面命中 + common_uri "" 知识链 ──────

  test("Detect: versioned 上游 → bare 面命中 + 已含断言落盘 + 入口 URL 镜像", async ({ page }) => {
    const uid = `entry-url-bare-${Date.now()}`;
    await page.goto("/");
    await page.locator('a.tab[data-tab="providers"]').click();
    await openNewProviderForm(page);
    await page.locator("#p-detect-url").fill(versionedUpstream.url);
    await page.locator("#p-detect-btn").click();
    const oa = page.locator('.dr-item[data-protocol="openai"]');
    await expect(oa.locator(".dr-status")).toHaveText("✓");
    // "" (版本前缀已含) 的呈现: uri 列 "✓ included" (en).
    await expect(oa.locator(".dr-uri")).toHaveText("✓ included");
    await oa.locator(".dr-add").click();
    // "" 断言落端点行: URI 输入框视觉为空 + 徽标显式区分 + dataset 保存 "".
    await expect(endpointRow(page).locator(".ep-common-uri")).toHaveValue("");
    await expect(endpointRow(page).locator(".ep-common-uri-badge")).toHaveText("✓ included");
    await expect(endpointRow(page)).toHaveAttribute("data-common-uri", "");
    await page.locator("#p-id").fill(uid);
    await page.locator('#provider-form-el button[value="save"]').click();
    await expect(page.locator("#provider-form")).not.toBeVisible();

    // 重开编辑: 徽标仍在 (存量 common_uri="" 回读, 未重跑 detect 不丢知识).
    // data-id 精确定位 — 测试 server 的 state 跨用例共享, .first() 可能点到
    // 其他用例创建的 provider (无 common_uri → 徽标 hidden 假失败).
    await page.locator(`button[data-action="edit"][data-id="${uid}"]`).click();
    await expect(page.locator("#provider-form")).toBeVisible();
    await expect(endpointRow(page).locator(".ep-common-uri-badge")).toHaveText("✓ included");
    await expect(endpointRow(page)).toHaveAttribute("data-common-uri", "");
    await page.locator('#provider-form-el button[value="cancel"]').click();

    // endpoints 弹窗: 入口 URL 对 openai 族 short 镜像 effective common_uri
    // (""= 已含 → 不追加 /v1, 不双拼版本段).
    const row = page.locator("#providers-body tr", { hasText: uid });
    await expect(row).toBeVisible();
    await row.locator('button[data-action="endpoints"]').click();
    const dlg = page.locator("#provider-endpoints");
    await expect(dlg).toBeVisible();
    const origin = new URL(page.url()).origin;
    await expect(dlg.locator('.ep-row[data-short="o"] .ep-url code').last()).toHaveText(`${origin}/o/${uid}`);
    await dlg.locator('button[value="close"]').click();
    await expect(dlg).not.toBeVisible();

    autoAcceptAlerts(page);
    await row.locator('button[data-action="delete"]').click();
    await expect(row).not.toBeVisible();
  });

  test("快速添加的徽标: 点击复制 flash 复位 + base_url 编辑作废 (M-A/M1 守卫)", async ({ page }) => {
    await page.goto("/");
    await page.locator('a.tab[data-tab="providers"]').click();
    await openNewProviderForm(page);
    await page.locator("#p-detect-url").fill(fastUpstream.url);
    await page.locator("#p-detect-btn").click();
    await page.locator('.dr-item[data-protocol="openai"] .dr-add').click();
    const badge = endpointRow(page).locator(".ep-common-uri-badge");
    await expect(badge).toHaveText("+/v1");
    // 复制 flash 后 'copied' class 必须复位 (M-A 守卫: 反转色不得永久滞留).
    await badge.click();
    await expect(badge).toHaveText("✓ copied");
    await expect(badge).toHaveText("+/v1", { timeout: 3000 });
    await expect(badge).not.toHaveClass(/copied/);
    // 编辑 base_url → 探测断言对新 URL 不再成立: 徽标作废隐藏 + verify 证据
    // 同步失效 (M1 竞态: A 的布局断言不得随 B 落盘).
    await endpointRow(page).locator(".ep-base-url").fill("http://127.0.0.1:19996");
    await expect(badge).toBeHidden();
    await expect(endpointRow(page).locator(".ep-verify")).not.toHaveClass(/v-ok/);
  });

  // ─── UI-10: 检测失败不阻塞手动填写 (非阻塞不变量) ──────────────────────────

  test("Detect 全 404 (全 absent): 肯定式逃生口 + 手动添加协议保存不被阻塞 (UI-10)", async ({ page }) => {
    // 小米 MiMo 案例回归: 检测无 ok 面时, 失败呈现必须给肯定式逃生口 (不暗示
    // base_url 填错), 手动添加协议 + 填写 + 保存全程可用 — 本用例钉死该链路.
    const uid = `detect-fail-manual-${Date.now()}`;
    await page.goto("/");
    await page.locator('a.tab[data-tab="providers"]').click();
    await openNewProviderForm(page);
    // 裸根形态 URL, upstream 恒 404 → 5 行全 absent (tier3 存在性探测也 404).
    await page.locator("#p-detect-url").fill(deadUpstream.url);
    await page.locator("#p-detect-btn").click();
    await expect(page.locator("#p-detect-results .dr-status.st-ok")).toHaveCount(0);
    await expect(page.locator("#p-detect-results .dr-add")).toHaveCount(0);
    await expect(
      page.locator("#p-detect-results .hint", { hasText: "pick the protocol" })
    ).toBeVisible();
    // 手动逃生口 (#332 规格⑤): "+ Add protocol" → 手动选协议 (staging URL 已预填
    // 行 base_url) + key + 保存 — 全程不被检测失败阻塞.
    await addManualEndpoint(page);
    await endpointRow(page).locator(".ep-protocol").selectOption("anthropic");
    await expect(endpointRow(page).locator(".ep-base-url")).toHaveValue(deadUpstream.url);
    await page.locator("#p-id").fill(uid);
    await page.locator("#p-api-key").fill("sk-detect-fail-manual");
    await page.locator('#provider-form-el button[value="save"]').click();
    await expect(page.locator("#provider-form")).not.toBeVisible();
    const row = page.locator("#providers-body tr", { hasText: uid });
    await expect(row).toBeVisible();

    // 清理 (测试 server 的 state 跨用例共享).
    autoAcceptAlerts(page);
    await row.locator('button[data-action="delete"]').click();
    await expect(row).not.toBeVisible();
  });

  test("mimo 形态: anthropic 面存在性证据行可快速添加 (#332 回归钉)", async ({ page }) => {
    // issue #332 核心痛点的正面钉: Anthropic 兼容网关 (Xiaomi MiMo 等) 的
    // anthropic 面无 models 端点 — 旧 "协议先行 + 面 URL 先行" 流程下结构性
    // 不可见; 存在性梯 (POST 400 + 对照 404) 让它以 ok/existence 呈现并可添加.
    const uid = `mimo-${Date.now()}`;
    await page.goto("/");
    await page.locator('a.tab[data-tab="providers"]').click();
    await openNewProviderForm(page);
    await page.locator("#p-detect-url").fill(mimoUpstream.url);
    await page.locator("#p-detect-btn").click();
    // openai 面: ✓ models 证据 (2 个模型 chips).
    const oa = page.locator('.dr-item[data-protocol="openai"]');
    await expect(oa.locator(".dr-status")).toHaveText("✓");
    await expect(oa.locator(".dr-detail")).toContainText("model list · 2");
    await expect(oa.locator(".dr-add")).toBeEnabled();
    // anthropic 面可见且 ok/existence — 证据梯如实分层 + 详情子行.
    const an = page.locator('.dr-item[data-protocol="anthropic"]');
    await expect(an.locator(".dr-status")).toHaveText("✓");
    await expect(an.locator(".dr-uri")).toHaveText("+/anthropic");
    await expect(an.locator(".dr-detail")).toContainText("route exists");
    await expect(an.locator(".dr-sub")).toContainText("/anthropic/v1/messages");
    await expect(an.locator(".dr-add")).toBeEnabled();
    // gemini / ollama: absent (无添加入口).
    for (const p of ["gemini", "ollama"]) {
      await expect(page.locator(`.dr-item[data-protocol="${p}"] .dr-add`)).toHaveCount(0);
    }
    // 快速添加 anthropic 面: protocol/base_url(=origin+/anthropic), cu 留空
    // (anthropic 面路径是 base 段, 非 common_uri), 无 verify ✓ (existence 证据
    // 不冒充模型清单校验).
    await an.locator(".dr-add").click();
    await expect(endpointRow(page).locator(".ep-protocol")).toHaveValue("anthropic");
    await expect(endpointRow(page).locator(".ep-base-url")).toHaveValue(`${mimoUpstream.url}/anthropic`);
    await expect(endpointRow(page).locator(".ep-common-uri")).toHaveValue("");
    await expect(endpointRow(page).locator(".ep-common-uri-badge")).toBeHidden();
    await expect(endpointRow(page).locator(".ep-verify")).not.toHaveClass(/v-ok/);
    await page.locator("#p-id").fill(uid);
    await page.locator("#p-api-key").fill("sk-mimo");
    await page.locator('#provider-form-el button[value="save"]').click();
    await expect(page.locator("#provider-form")).not.toBeVisible();
    const row = page.locator("#providers-body tr", { hasText: uid });
    await expect(row).toBeVisible();
    await expect(row.locator(".pill", { hasText: /^anthropic$/ })).toBeVisible();

    autoAcceptAlerts(page);
    await row.locator('button[data-action="delete"]').click();
    await expect(row).not.toBeVisible();
  });

  test("[添加] 后按钮禁用「已添加」; 删行恢复", async ({ page }) => {
    await page.goto("/");
    await page.locator('a.tab[data-tab="providers"]').click();
    await openNewProviderForm(page);
    await page.locator("#p-detect-url").fill(mimoUpstream.url);
    await page.locator("#p-detect-btn").click();
    const addBtn = page.locator('.dr-item[data-protocol="openai"] .dr-add');
    await expect(addBtn).toBeEnabled();

    // 物化 openai 面 → 同协议按钮翻 "已添加" 并禁用.
    await addBtn.click();
    await expect(page.locator(".endpoint-row")).toHaveCount(1);
    await expect(addBtn).toBeDisabled();
    await expect(addBtn).toHaveText("Added ✓");
    // 手动物化的第二行选 anthropic 也触发同禁用语义 (协议集合判定).
    await page.locator("#p-endpoint-add").click();
    await endpointRow(page, 1).locator(".ep-protocol").selectOption("anthropic");
    await expect(page.locator('.dr-item[data-protocol="anthropic"] .dr-add')).toBeDisabled();

    // 删掉 openai 行 → 按钮恢复 "Add".
    await endpointRow(page).locator(".ep-del").click();
    await expect(addBtn).toBeEnabled();
    await expect(addBtn).toHaveText("Add");
  });

  // ─── 端点行 Verify ("二次检测", 规格④) ────────────────────────────────────

  test("Verify: 行内二次检测 ✓ → 改 URI 后 ✗, 但保存不被阻塞", async ({ page }) => {
    const uid = `verify-${Date.now()}`;
    await page.goto("/");
    await page.locator('a.tab[data-tab="providers"]').click();
    await openNewProviderForm(page);
    await addManualEndpoint(page);
    await endpointRow(page).locator(".ep-protocol").selectOption("openai");
    await endpointRow(page).locator(".ep-base-url").fill(fastUpstream.url);
    // URI 留空 (auto → 后端镜像尾段启发 /v1) → 校验通过.
    await endpointRow(page).locator(".ep-verify").click();
    await expect(endpointRow(page).locator(".ep-verify")).toHaveClass(/v-ok/);
    await expect(endpointRow(page).locator(".ep-probe-result .probe-line-ok")).toContainText("Verified — 3 models");
    await expect(endpointRow(page).locator(".ep-probe-result .probe-url").first()).toContainText("/v1/models");
    // 改 URI → ✓ 状态即失效 (校验只对被验证三元组成立); 再校验 → ✗ (404 absent).
    await endpointRow(page).locator(".ep-common-uri").fill("/wrong");
    await expect(endpointRow(page).locator(".ep-verify")).not.toHaveClass(/v-ok/);
    await expect(endpointRow(page).locator(".ep-verify")).not.toHaveClass(/v-fail/);
    await endpointRow(page).locator(".ep-verify").click();
    await expect(endpointRow(page).locator(".ep-verify")).toHaveClass(/v-fail/);
    await expect(endpointRow(page).locator(".ep-probe-result .probe-line-err")).toContainText("Unreachable");
    await expect(
      endpointRow(page).locator(".ep-probe-result .hint", { hasText: "never blocked" })
    ).toBeVisible();
    // 保存仍成功 — ✗ 仅提示, 绝不阻塞 (UI-10).
    await page.locator("#p-id").fill(uid);
    await page.locator('#provider-form-el button[value="save"]').click();
    await expect(page.locator("#provider-form")).not.toBeVisible();
    const row = page.locator("#providers-body tr", { hasText: uid });
    await expect(row).toBeVisible();

    autoAcceptAlerts(page);
    await row.locator('button[data-action="delete"]').click();
    await expect(row).not.toBeVisible();
  });

  // ─── 检测台输入辅助 (知识库 origin 建议 + Enter) 与归一化/extra_faces ─────

  test("检测台: 知识库 origin 建议 (点选回填) + Enter = 检测键盘等价", async ({ page }) => {
    await page.goto("/");
    await page.locator('a.tab[data-tab="providers"]').click();
    await openNewProviderForm(page);
    // 知识库条目直出 origin 建议 (UI-11 吸收): 'mimo' 命中两条 MiMo 知识库条目
    // (bare origin, 不含面路径 — 面的取舍交给检测结果).
    const input = page.locator("#p-detect-url");
    await input.pressSequentially("mimo");
    const items = page.locator(".detect-stage .ep-url-suggest-item");
    await expect(items).toHaveCount(2);
    await items.filter({ hasText: "Xiaomi MiMo Token Plan" }).first().click();
    await expect(input).toHaveValue("https://token-plan-cn.xiaomimimo.com");
    await expect(page.locator(".detect-stage .ep-url-suggest")).toHaveCount(0);
    // Enter 触发检测 (拦截 route — 不真正出网, 空矩阵走防御分支).
    await page.route("**/api/providers/probe-origin", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          origin: "https://token-plan-cn.xiaomimimo.com",
          typed_face_stripped: null,
          faces: [],
        }),
      })
    );
    const probed = page.waitForResponse(
      (r) => r.url().includes("/api/providers/probe-origin") && r.request().method() === "POST"
    );
    await input.press("Enter");
    await probed;
    await expect(page.locator("#p-detect-results .probe-line-err")).toContainText("No probes returned");
    await page.unroute("**/api/providers/probe-origin");
  });

  test("typed_face_stripped 归一化提示渲染 (输入含面尾段 → 提示剥离)", async ({ page }) => {
    // 契约形状单测: page.route 拦截 probe-origin 直喂冻结 wire 形状 (UI 渲染
    // 契约与后端探测实现解耦).
    await page.goto("/");
    await page.locator('a.tab[data-tab="providers"]').click();
    await openNewProviderForm(page);
    await page.route("**/api/providers/probe-origin", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          origin: "https://api.example.com",
          typed_face_stripped: "/anthropic",
          faces: [
            { protocol: "openai", uri: "/v1", base_url: "https://api.example.com", common_uri: "/v1", status: "ok", evidence: "models", models: ["a"], detail: null },
            { protocol: "anthropic", uri: "/anthropic", base_url: "https://api.example.com/anthropic", common_uri: null, status: "ok", evidence: "existence", models: null, detail: null },
            { protocol: "gemini", uri: null, base_url: null, common_uri: null, status: "absent", evidence: null, models: null, detail: null },
            { protocol: "ollama", uri: null, base_url: null, common_uri: null, status: "absent", evidence: null, models: null, detail: null },
            { protocol: "responses", uri: "/v1", base_url: "https://api.example.com", common_uri: "/v1", status: "ok", evidence: "models", models: ["a"], detail: "与 OpenAI 共用 /v1, 探测无法区分" },
          ],
        }),
      });
    });
    // 用户粘贴了带面尾段的 URL — 后端归一, 结果区顶部回显归一化提示.
    await page.locator("#p-detect-url").fill("https://api.example.com/anthropic");
    await page.locator("#p-detect-btn").click();
    const results = page.locator("#p-detect-results");
    await expect(results.locator(".hint").first()).toContainText("Normalized your input to https://api.example.com (stripped /anthropic)");
    // responses 行 detail (共用注记) 渲染在详情子行 (与模型名并存, muted).
    const respRow = results.locator('.dr-item[data-protocol="openai-responses"]');
    await expect(respRow.locator(".dr-status")).toHaveText("✓");
    await expect(respRow.locator(".dr-sub")).toContainText("与 OpenAI 共用 /v1");
    await page.unroute("**/api/providers/probe-origin");
  });

  test("preset origin 精确命中 → extra_faces 随请求发出; 未命中省略", async ({ page }) => {
    await page.goto("/");
    await page.locator('a.tab[data-tab="providers"]').click();
    await openNewProviderForm(page);
    const captured: string[] = [];
    await page.route("**/api/providers/probe-origin", async (route) => {
      captured.push(route.request().postData() ?? "");
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ origin: "https://api.xiaomimimo.com", typed_face_stripped: null, faces: [] }),
      });
    });
    // 命中: 大小写不敏感 + 尾斜杠容忍 (normalizeOrigin) — 知识库 MiMo 条目的
    // 两个已验证面作为 extra_faces 发出; origin 原样发送 (归一是后端职责).
    await page.locator("#p-detect-url").fill("https://API.XiaoMiMiMo.com/");
    await page.locator("#p-detect-btn").click();
    await page.locator("#p-detect-results .probe-line").first().waitFor();
    expect(captured).toHaveLength(1);
    const body1 = JSON.parse(captured[0]);
    expect(body1.origin).toBe("https://API.XiaoMiMiMo.com/");
    expect(body1.extra_faces).toEqual([
      { uri: "/v1", protocol: "openai" },
      { uri: "/anthropic", protocol: "anthropic" },
    ]);
    // 未命中: 未知 origin 不带 extra_faces 键 (后端按内置候选面探测).
    await page.locator("#p-detect-url").fill("https://unknown-vendor.example");
    await page.locator("#p-detect-btn").click();
    await page.locator("#p-detect-results .probe-line").nth(1).waitFor();
    expect(captured).toHaveLength(2);
    const body2 = JSON.parse(captured[1]);
    expect(body2.origin).toBe("https://unknown-vendor.example");
    expect("extra_faces" in body2).toBe(false);
    await page.unroute("**/api/providers/probe-origin");
  });
});

test.describe("端点 base_url 补全 (autocomplete)", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(500);
    await page.locator('a.tab[data-tab="providers"]').click();
    await expect(page.locator("#providers-body tr").first()).toBeVisible();
    await page.locator("button", { hasText: "+ new provider" }).click();
    await expect(page.locator("#provider-form")).toBeVisible();
  });

  test("输入 ≥3 字符出建议 + 继续输入收窄 + 点选回填 url 与 protocol 预填", async ({ page }) => {
    await addManualEndpoint(page);
    const input = endpointRow(page).locator(".ep-base-url");
    await input.pressSequentially("mimo");
    // 'mimo' 命中 4 条 Xiaomi MiMo 面 (api / token-plan × openai / anthropic),
    // 无其他供应商含该子串 (minimax/mistral 均不含 'mim').
    const items = endpointRow(page).locator(".ep-url-suggest-item");
    await expect(items).toHaveCount(4);
    await expect(items.filter({ hasText: "Xiaomi MiMo (Anthropic)" })).toHaveCount(1);
    // 继续输入实时收窄: 补 ' token' → 只剩 token-plan 两条.
    await input.pressSequentially(" token");
    await expect(items).toHaveCount(2);
    // 点选 anthropic 面: url 回填 + protocol 预填 (建议非命令, 走 select) +
    // 列表消失 (值精确等于条目 url → 重算无匹配).
    await items.filter({ hasText: "Xiaomi MiMo Token Plan (Anthropic)" }).click();
    await expect(input).toHaveValue("https://token-plan-cn.xiaomimimo.com/anthropic");
    await expect(endpointRow(page).locator(".ep-protocol")).toHaveValue("anthropic");
    await expect(endpointRow(page).locator(".ep-url-suggest")).toHaveCount(0);
  });

  test("无匹配串不出列表, 手填 + 保存成功 (UI-10 不阻塞)", async ({ page }) => {
    const uid = `nomatch-${Date.now()}`;
    await page.locator("#p-id").fill(uid);
    await addManualEndpoint(page);
    await endpointRow(page).locator(".ep-base-url").fill("https://no-such-vendor.example/v1");
    await expect(endpointRow(page).locator(".ep-url-suggest")).toHaveCount(0);
    // 手动填写全程不被辅助功能阻塞: 保存成功, dialog 关闭, 表格出现该行.
    await page.locator('#provider-form-el button[value="save"]').click();
    await expect(page.locator("#provider-form")).not.toBeVisible();
    const row = page.locator("#providers-body tr", { hasText: uid });
    await expect(row).toBeVisible();
    // 清理 (dynamic-only 可删).
    autoAcceptAlerts(page);
    await row.locator('button[data-action="delete"]').click();
    await expect(row).not.toBeVisible();
  });

  test("边界: <3 字符无列表, 满 3 字符出, 精确等于条目 url 无列表", async ({ page }) => {
    await addManualEndpoint(page);
    const input = endpointRow(page).locator(".ep-base-url");
    await input.pressSequentially("mi");
    await expect(endpointRow(page).locator(".ep-url-suggest")).toHaveCount(0);
    await input.pressSequentially("m");
    await expect(endpointRow(page).locator(".ep-url-suggest")).toBeVisible();
    await expect(endpointRow(page).locator(".ep-url-suggest-item")).toHaveCount(4);
    // 手输整条 URL 到底 → 与点选回填同态, 列表不滞留.
    await input.fill("https://api.x.ai/v1");
    await expect(endpointRow(page).locator(".ep-url-suggest")).toHaveCount(0);
  });

  test("点选建议作废 common_uri 暂存 (M1 竞态守卫: A 的布局断言不得随 B 落盘)", async ({ page }) => {
    // 先检测台 Detect + 快速添加拿到 common_uri 暂存 (fast 上游: /v1/models 200
    // openai shape → 徽标 '+/v1'), 再清空行 base_url 点选不同 URL 的建议 — 暂存
    // 必须被作废 (程序化回填不触发 input, 实现须手动补发; 残留 = 保存时旧布局
    // 断言随新 URL 落盘).
    const upstream = await startProbeUpstream((pathname) => {
      if (pathname === "/v1/models") {
        return {
          status: 200,
          body: JSON.stringify({
            object: "list",
            data: [{ id: "m1", object: "model" }],
          }),
        };
      }
      return { status: 404, body: "{}" };
    });
    try {
      await page.locator("#p-detect-url").fill(upstream.url);
      await page.locator("#p-detect-btn").click();
      await page.locator('.dr-item[data-protocol="openai"] .dr-add').click();
      await expect(endpointRow(page).locator(".ep-common-uri-badge")).toBeVisible();
      await expect(endpointRow(page).locator(".ep-common-uri-badge")).toHaveText("+/v1");
      // 清空 (input 事件作废暂存, 徽标即隐) 再输入 → 建议出现.
      const input = endpointRow(page).locator(".ep-base-url");
      await input.fill("");
      await expect(endpointRow(page).locator(".ep-common-uri-badge")).toBeHidden();
      await input.pressSequentially("mimo");
      await expect(endpointRow(page).locator(".ep-url-suggest-item")).toHaveCount(4);
      // 点选不同 URL: dataset.commonUri 无 + 徽标保持隐藏.
      await endpointRow(page)
        .locator(".ep-url-suggest-item", { hasText: "Xiaomi MiMo (Anthropic)" })
        .click();
      await expect(input).toHaveValue("https://api.xiaomimimo.com/anthropic");
      await expect(endpointRow(page)).not.toHaveAttribute("data-common-uri");
      await expect(endpointRow(page).locator(".ep-common-uri-badge")).toBeHidden();
    } finally {
      await upstream.close();
    }
  });

  test("Escape 只关建议列表, 输入框可继续输入 (dialog 不被 ESC 关闭)", async ({ page }) => {
    await addManualEndpoint(page);
    const input = endpointRow(page).locator(".ep-base-url");
    await input.pressSequentially("anthropic");
    await expect(endpointRow(page).locator(".ep-url-suggest")).toBeVisible();
    await input.press("Escape");
    await expect(endpointRow(page).locator(".ep-url-suggest")).toHaveCount(0);
    // ESC 被 preventDefault: modal dialog 未关, 值未变, 焦点仍可继续输入.
    await expect(page.locator("#provider-form")).toBeVisible();
    await expect(input).toHaveValue("anthropic");
    // 继续输入: 值变化重算, 新查询的建议正常出现 (Groq 单条命中).
    await input.fill("groq");
    await expect(endpointRow(page).locator(".ep-url-suggest-item")).toHaveCount(1);
    await expect(endpointRow(page).locator(".ep-url-suggest-item")).toContainText("api.groq.com");
  });
});

// ─── SSE 失效通知消费 (rt-push T3, UI-8) ──────────────────────────────────
//
// 前端契约 (index.html "SSE 失效通知 + 动态兜底轮询" 段; wire 契约见
// src/web/api/events.rs 头部): SSE 事件只是触发器 — 收到 poke (records tab +
// 无 #164-3 暂停) → 200ms trailing debounce → 既有 sync(); POST /api/sync 仍是
// 数据 SSOT. EventSource 原生自动重连; sseHealthy 驱动兜底轮询间隔 (健康 30s /
// 断开 3s).
//
// mock 手法 (Playwright 1.61 的 route.fulfill 不支持流式 body — 只接受一次性
// string/Buffer): 用 "retry: N" 控制重连节奏 + 每次重连投递一帧事件的一次性
// body 模拟受控事件流; body 结束连接关闭, 天然覆盖 onerror 路径. file-level
// 静音 route (见文件头) 由各用例 page.unroute 后覆盖.
test.describe("SSE 失效通知 (rt-push T3)", () => {
  /** 计数页面发出的 POST /api/sync (纯观察不拦截 — 不改变被测行为). */
  function countSyncRequests(page: Page): () => number {
    let n = 0;
    page.on("request", (r) => {
      if (r.method() === "POST" && new URL(r.url()).pathname === "/api/sync") n++;
    });
    return () => n;
  }

  /** 卸下 file-level 静音默认, 装受控事件流: 一次性 body ("retry: N" + 一帧事件),
   * body 结束连接关闭 → 天然覆盖 onerror 路径. retry 值是各用例唯一的控制变量
   * (重连节奏: 900000 = 单次事件后静默 / 300 = poke 以 300ms 节奏持续到达). */
  async function mockSseEvents(page: Page, body: string): Promise<void> {
    await page.unroute("**/api/events");
    await page.route("**/api/events", (route) =>
      route.fulfill({ status: 200, contentType: "text/event-stream", body }));
  }

  test("SSE poke 触发 sync (debounce 后, 3s 兜底 tick 前)", async ({ page }) => {
    // 受控事件流: 首次连接立即投递一帧事件后关闭; retry 15min → 不再重连.
    // 事件链: onmessage → 200ms debounce → sync (第 2 次). 对照: 无 poke 时下一
    // 次 sync 最早在首条兜底 tick (bootstrap+3s — EventSource 关闭 → sseHealthy
    // =false → 3s 档; 第 1 次是 bootstrap 首拉).
    await mockSseEvents(page, "retry: 900000\n\ndata: 1\n\n");
    const syncCount = countSyncRequests(page);
    await page.goto("/");
    // 断言窗口 2s < 3s: load 后 2s 内出现第 2 次 sync 只能由 poke 达成.
    await expect.poll(syncCount, { timeout: 2000 }).toBeGreaterThanOrEqual(2);
  });

  test("SSE 不可用时退化为轮询 (兜底 tick 持续拉 sync)", async ({ page }) => {
    // 全部 /api/events 请求 abort → onerror 恒触发 → sseHealthy 恒 false → 兜底
    // 轮询 3s 档. 只断言 "仍在轮询" 不断言精确间隔 (防计时 flaky): 9s 窗口内
    // ≥3 次 POST (bootstrap 首拉 + ~3s + ~6s 两记 tick).
    // 反向检测: 前端若把断连误判为健康 (30s 档) 或彻底停轮询, 计数停在 1 → 红.
    await page.unroute("**/api/events");
    await page.route("**/api/events", (route) => route.abort("failed"));
    const syncCount = countSyncRequests(page);
    await page.goto("/");
    await expect.poll(syncCount, { timeout: 9000 }).toBeGreaterThanOrEqual(3);
  });

  test("弹窗开启时 SSE poke 不触发 sync, 关闭后恢复 (#164-3)", async ({ page }) => {
    // 受控事件流: retry 300ms → EventSource 每 300ms 重连一次各收一帧事件,
    // poke 以 ~300ms 节奏持续到达 (debounce 200ms 只折叠, 不吞末次).
    await mockSseEvents(page, "retry: 300\n\ndata: 1\n\n");
    const syncCount = countSyncRequests(page);
    await page.goto("/");
    // 先证正向链路通: 无弹窗时 poke 应在 ~0.5s 内触发第 2 次 sync.
    await expect.poll(syncCount, { timeout: 2000 }).toBeGreaterThanOrEqual(2);
    // 开弹窗 (#164-3 暂停) + 排空在途 debounce (200ms) 后取冻结基线.
    await page.evaluate(() => document.getElementById("secret-form")!.showModal());
    await page.waitForTimeout(800);
    const frozen = syncCount();
    // ≥4 个 poke 周期 (1.5s) 无一触发 sync — 暂停语义必须覆盖 SSE poke 路径
    // (兜底 tick 同被暂停; 若暂停失效, 300ms 节奏的 poke 在窗口内必增计数).
    await page.waitForTimeout(1500);
    expect(syncCount(), "弹窗开启期间 poke 不得触发 sync").toBe(frozen);
    // 关闭弹窗 → 下一个 poke (≤300ms) + debounce (200ms) 恢复触发 — 证明跳过
    // 确因弹窗暂停, 而非事件流 mock 失效.
    await page.evaluate(() => document.getElementById("secret-form")!.close());
    await expect.poll(syncCount, { timeout: 2000 }).toBeGreaterThan(frozen);
  });
});

// ─── i18n: 语言自动选择 + 切换 + 持久化 (#298) ────────────────────────────
//
// 契约 (index.html i18n 段):
//   1. 默认 auto = 跟随浏览器: Playwright Chromium 默认 locale en-US → 英文界面.
//   2. 页头 #lang-switch 切到 zh → 关键文案即时变化 (不整页刷新), <html lang> 同步.
//   3. localStorage['sg-lang'] 持久化: 刷新后仍是中文.
// Playwright 每用例独立 context (localStorage 隔离), 无跨用例泄漏.
test.describe("i18n: 语言自动选择 + 切换 + 持久化 (#298)", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
  });

  test("默认跟随浏览器 (en-US → 英文界面)", async ({ page }) => {
    await expect(page.locator("nav.tabs a.tab[data-tab='secrets']")).toHaveText("Secrets");
    await expect(page.locator("nav.tabs a.tab[data-tab='usage']")).toHaveText("Usage");
    // 触发本 issue 的 "详细日志" 族在 en 下必须是英文 (不再混中文).
    const label = page.locator("label:has(#audit-capture) > span");
    await expect(label).toHaveText("Audit log");
    await expect(page.locator("#audit-capture option[value='off']")).toHaveText("Off");
    await expect(page.locator("#audit-capture option[value='latest']")).toHaveText("Latest only");
    await expect(page.locator("html")).toHaveAttribute("lang", "en");
    // 静态文案 (data-i18n): filter 按钮 + 未选会话的 detail 空态.
    // (不用 #record-list 空态 — 全量跑时前置用例已产生 session, 空 div 不存在.)
    await expect(page.locator("#filter-all > span[data-i18n]")).toHaveText("All");
    await expect(page.locator("#detail .empty")).toHaveText("Select a session on the left");
  });

  test("切换 zh 即时生效 + 刷新后持久化", async ({ page }) => {
    // 切到中文 → tab / filter / audit 标签 / detail 空态即时变化 (不刷新).
    await page.locator("#lang-switch").selectOption("zh");
    await expect(page.locator("nav.tabs a.tab[data-tab='secrets']")).toHaveText("密钥");
    await expect(page.locator("#filter-all > span[data-i18n]")).toHaveText("全部");
    await expect(page.locator("#detail .empty")).toHaveText("在左侧选择一个会话");
    const label = page.locator("label:has(#audit-capture) > span");
    await expect(label).toHaveText("详细日志");
    await expect(page.locator("html")).toHaveAttribute("lang", "zh");
    // select 值不受 option 文案替换影响 (服务端默认 latest, quant#307).
    await expect(page.locator("#audit-capture")).toHaveValue("latest");
    // 刷新后持久化 (localStorage) + 仍中文.
    await page.reload();
    await page.waitForLoadState("networkidle");
    await expect(page.locator("nav.tabs a.tab[data-tab='secrets']")).toHaveText("密钥");
    await expect(page.locator("html")).toHaveAttribute("lang", "zh");
    // 切回 en 显式档 (非 auto) 同样即时生效.
    await page.locator("#lang-switch").selectOption("en");
    await expect(page.locator("nav.tabs a.tab[data-tab='secrets']")).toHaveText("Secrets");
  });

  test("切换语言后已渲染轮次的动态文案跟随 (keyed 复用不残留)", async ({ page }) => {
    // 回归守卫 (review M1): keyed reconciliation 的复用分支不重绘已有轮次内容,
    // 若语言切换只失效 fingerprint, 轮内烙进 DOM 的文案 (详情按钮 title 等)
    // 会残留旧语言 — 契约: 切换后全量重建 timeline。
    await sendChat(page, [{ role: "user", content: "i18n-round-marker" }]);
    const sid = await findSessionLeafByPreview(page, "i18n-round-marker");
    await clickSessionByLeaf(page, sid);
    const detailBtn = page.locator("#detail .tl-actions button[data-action='detail']").first();
    await expect(detailBtn).toHaveAttribute("title", "Round details");
    await expect(page.locator("#detail > .detail-header")).toContainText("Timeline (");
    // 切 zh → 轮内按钮 title + timeline header 都换语言 (不刷新页面).
    await page.locator("#lang-switch").selectOption("zh");
    await expect(detailBtn).toHaveAttribute("title", "轮次详情");
    await expect(page.locator("#detail > .detail-header")).toContainText("时间线 (");
    // 轮次内容本体 (气泡) 不受重建影响。
    await expect(page.locator("#detail .request-pane .chat-bubble")).toContainText("i18n-round-marker");
  });
});

// ─── header 工具栏打磨: 选择框字号统一 + 语言选择器可发现性 (quant#306) ──────
//
// 契约 (index.html header CSS 段):
//   1. 原生 select 不继承页面字体 (UA 默认表单字体偏大) — header 工具栏的
//      #audit-capture / #lang-switch 显式对齐 toolbar 控件字号基准 12.5px
//      (基准锚点 = button.refresh, 同 bug 已修先例).
//   2. #lang-switch 有可见标签 (与 #audit-capture 的 label 同构), 不点开即知
//      是语言选择器 — 修复 "不知道候选框选的啥" 的可发现性问题.
test.describe("header 工具栏打磨 (quant#306)", () => {
  // en 默认前置显式化: 依赖 resolveLang('auto') → en 的行为, 防日后 config 级
  // locale 设置让本 describe 静默变红.
  test.use({ locale: "en-US" });

  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
  });

  test("选择框 computed 字号与 toolbar 基准控件一致", async ({ page }) => {
    // 基准锚点: button.refresh (12.5px, CSS 显式声明). 裸 select 若漏 font 修正
    // 会落在 UA 默认表单字号 (~13.33px) — 逐 px 相等断言即可捕获回退.
    const fontSize = (sel: string) =>
      page.locator(sel).evaluate((el) => getComputedStyle(el).fontSize);
    const base = await fontSize("button.refresh");
    expect(base).toBe("12.5px");
    expect(await fontSize("#audit-capture")).toBe(base);
    expect(await fontSize("#lang-switch")).toBe(base);
  });

  test("语言选择器可见标签: 不点开即知选的是语言", async ({ page }) => {
    // 可见标签 (与 #audit-capture 的 label 同构) + 隐式 label 关联提供
    // accessible name (select 不再依赖 aria-label 标注).
    const langLabel = page.locator("label:has(#lang-switch) > span");
    await expect(langLabel).toHaveText("Language");
    // 切 zh → 标签即时跟随 (data-i18n 重放).
    await page.locator("#lang-switch").selectOption("zh");
    await expect(langLabel).toHaveText("界面语言");
  });
});

// ─── #257 S0.5: 隐私旁路扫描 (疑似未登记面板 + 登记预填闭环) ────────────────
//
// server 配置 (playwright.config.ts) 开 [privacy_scan] mode = "batch".
// 覆盖: ① 未登记 AWS 形状 key → 面板出现 + 行内容 (value/pattern/context);
// ② 「登记」→ add-secret 表单预填 value + 建议 name (pattern + 日期);
// ③ 提交 (POST /api/secrets) 后告警行经视图过滤消失 — 「告警→登记」人回路闭环.
// 已登记 test-key (sk- 开头, 命中 openai pattern 形状) 不产生告警 (排除规则 +
// 视图过滤双层) — 由 ① 的 "AWS 行存在 + 面板不含 test-key 真值" 断言顺带守卫.
test.describe("#257 S0.5: privacy scan (unregistered candidates)", () => {
  const AWS_KEY = "AKIA" + "UIE2E5E7TESTKEY9";

  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
  });

  test("未登记 token 告警出现 → 登记预填 → 提交后告警消失", async ({ page }) => {
    // ① 发送含未登记 AWS 形状 key 的请求. secrets 表含已登记 test-key (非空)
    //    → same-proto 走 IR 路径, 扫描捕获挂在 redact seam (透传分支的旁路扫描
    //    由 Rust 集成测试 privacy_scan_batch_alerts_unregistered_key_in_passthrough
    //    单独覆盖 — 那里 secrets 表为空).
    await sendChat(page, [
      { role: "user", content: `privacy-scan-marker leaking ${AWS_KEY} in prose` },
    ]);

    // ② Secrets tab: 面板出现 (enabled) + 告警行 (value/pattern/context).
    await page.locator('a.tab[data-tab="secrets"]').click();
    const row = page.locator(
      `#privacy-alerts-body tr:has(td.mono-cell:text-is("${AWS_KEY}"))`
    );
    await expect(row).toBeVisible({ timeout: 10_000 });
    await expect(row).toContainText("AWS Access Key ID");
    await expect(row).toContainText("privacy-scan-marker");

    // 面板中不出现已登记 test-key 的值 (排除规则 + 视图过滤).
    const panelText = await page.locator("#privacy-scan-panel").textContent();
    expect(panelText).not.toContain(TEST_SECRET_VALUE);

    // ③ 「登记」→ 既有 add-secret 表单打开, value/name 预填 (建议 name =
    //    pattern + 日期). 显式填 id (便于末尾清理; 不填则服务端生成 UUID).
    await row.locator('button[data-action="register"]').click();
    const dlg = page.locator("dialog#secret-form");
    await expect(dlg).toBeVisible();
    await expect(dlg.locator("#f-value")).toHaveValue(AWS_KEY);
    const today = new Date().toISOString().slice(0, 10);
    await expect(dlg.locator("#f-name")).toHaveValue(`AWS Access Key ID ${today}`);
    await dlg.locator("#f-id").fill("privacy-scan-registered");

    // ④ 提交 → POST /api/secrets 成功 → 表单关闭 + 告警行经视图过滤消失
    //    (登记后人回路收口; 服务端已登记值被 alerts 视图过滤).
    await dlg.locator("#f-save").click();
    await expect(dlg).not.toBeVisible({ timeout: 10_000 });
    await expect(
      page.locator(`#privacy-alerts-body td.mono-cell:text-is("${AWS_KEY}")`)
    ).toHaveCount(0, { timeout: 10_000 });

  });

  // 清理: 删除本用例登记的 dynamic secret (workers=1 共享 state, 防泄漏到其他
  // 用例的 secrets 表断言 — 断言中途失败也能恢复; DELETE 对已删条目 404, 幂等
  // 判定只要求请求完成). 仿 B3 describe 的文件级 afterEach 卫生钩子先例.
  // R3 补充: 组开关恢复全开 (PUT 是 server 持久化共享态, 中途断言失败也不泄漏).
  test.afterEach(async ({ request }) => {
    await request.delete(`${SG_API}/secrets/privacy-scan-registered`);
    await request.put(`${SG_API}/privacy-scan/settings`, { data: { groups: {} } });
  });

  // ── R2 (PR #303 review): 告警状态机 + 「疑似已外发」语义 ──
  // 覆盖: ① active 告警存在时顶部警示横幅 + 行内 "Likely exposed" 徽章;
  // ② 「已轮换」动作 → 行移入折叠的 "resolved" 区 (徽章 Rotated), active 面
  //    下线; ③ 「忽略 (误报)」动作同型 (Ignored 徽章);
  // ④ 已处理行内「登记」仍可用 (预填闭环不因处置状态失效).
  // 注 1: 告警是 server 内存态且 workers=1 跨用例共享 — 断言一律锚定本用例
  // 的专属 KEY 行, 不做全局计数; 横幅断言用 "横幅可见 ⟺ active 行存在"
  // 不变式 (对残留告警免疫).
  // 注 2: resolved tbody 的 DOM 节点折叠时即存在 (仅 hidden), "从 active 消失"
  // 断言必须锚定 #privacy-alerts-body.

  // AKIA + 恰好 16 位大写字母数字尾串 (Exact(16) 形状; "ROTATEUI000000" = 14 + 2 位随机 = 16).
  const rotateKey = () => "AKIA" + "ROTATEUI000000" + String(Math.floor(Math.random() * 90 + 10));
  const activeRowOf = (page: Page, key: string) =>
    page.locator(`#privacy-alerts-body tr:has(td.mono-cell:text-is("${key}"))`);
  const anyRowOf = (page: Page, key: string) =>
    page.locator(`#privacy-scan-panel tr:has(td.mono-cell:text-is("${key}"))`);

  test("R2: 横幅 + 已轮换动作 → 行折叠进 resolved 区", async ({ page }) => {
    const KEY = rotateKey();
    await sendChat(page, [{ role: "user", content: `r2-rotate-marker ${KEY} in prose` }]);
    await page.locator('a.tab[data-tab="secrets"]').click();

    // ① active 行 + "Likely exposed" 徽章 + 顶部警示横幅.
    const row = activeRowOf(page, KEY);
    await expect(row).toBeVisible({ timeout: 10_000 });
    await expect(row.locator(".badge")).toHaveText("Likely exposed");
    await expect(page.locator("#privacy-exposed-banner")).toBeVisible();

    // ② 「已轮换」→ active 行消失; 横幅走不变式 (可见 ⟺ active 行 ≥1,
    //    对前序用例的残留告警免疫).
    await row.locator('button[data-action="rotate"]').click();
    await expect(activeRowOf(page, KEY)).toHaveCount(0, { timeout: 10_000 });
    const activeCount = await page.locator("#privacy-alerts-body tr:has(td.mono-cell)").count();
    const bannerVisible = await page.locator("#privacy-exposed-banner").isVisible();
    expect(bannerVisible).toBe(activeCount > 0);

    // ③ resolved 折叠区: 默认隐藏, 展开后行在场 + Rotated 徽章.
    await page.locator("#privacy-resolved-btn").click();
    await expect(anyRowOf(page, KEY)).toBeVisible();
    await expect(anyRowOf(page, KEY).locator(".badge")).toHaveText("Rotated");
  });

  test("R2: 忽略 (误报) 动作 + 已处理行内登记仍可用", async ({ page }) => {
    const KEY = rotateKey();
    await sendChat(page, [{ role: "user", content: `r2-ignore-marker ${KEY} in prose` }]);
    await page.locator('a.tab[data-tab="secrets"]').click();

    const row = activeRowOf(page, KEY);
    await expect(row).toBeVisible({ timeout: 10_000 });

    // ① 「忽略」→ active 行消失, resolved 区内 Ignored 徽章.
    await row.locator('button[data-action="ignore"]').click();
    await expect(activeRowOf(page, KEY)).toHaveCount(0, { timeout: 10_000 });
    await page.locator("#privacy-resolved-btn").click();
    const resolvedRow = anyRowOf(page, KEY);
    await expect(resolvedRow).toBeVisible();
    await expect(resolvedRow.locator(".badge")).toHaveText("Ignored");

    // ② 已处理行的「登记」仍打开预填表单 (与 active 行同闭环).
    await resolvedRow.locator('button[data-action="register"]').click();
    const dlg = page.locator("dialog#secret-form");
    await expect(dlg).toBeVisible();
    await expect(dlg.locator("#f-value")).toHaveValue(KEY);
    await page.keyboard.press("Escape");
  });

  // ── R3: 组开关 (检测分组) ──
  // 覆盖: ① 面板组开关行渲染 (5 组 checkbox); ② 关 vcs (代码托管) → 该组
  // 告警隐藏 (AWS/cloud 组仍报 — 关组只闸对应组); ③ 持久化: 刷新页面后
  // 组态保持 (state.toml); ④ 收尾恢复全开 (组态是 server 共享态, 防泄漏到
  // 其他用例). KEY 工厂注意 AKIA + 恰 16 位尾串.
  test("R3: 组开关切换 → 告警面变化 + 刷新持久化", async ({ page }) => {
    const KEY = "AKIA" + "GROUPUI" + "0".repeat(8) + "A"; // cloud 组 (aws-access-key-id, 尾串恰 16 位)
    await sendChat(page, [{ role: "user", content: `r3-group-marker ${KEY} in prose` }]);
    await page.locator('a.tab[data-tab="secrets"]').click();

    // ① 组开关行在场, 5 组全开.
    const toggles = page.locator("#privacy-group-toggles input[type='checkbox'][data-group]");
    await expect(toggles).toHaveCount(5, { timeout: 10_000 });
    for (const g of ["cloud", "ai", "vcs", "chat", "crypto"]) {
      await expect(page.locator(`#privacy-group-toggles input[data-group="${g}"]`)).toBeChecked();
    }

    // cloud 行在场 (本用例 KEY).
    await expect(activeRowOf(page, KEY)).toBeVisible({ timeout: 10_000 });

    // ② 关 vcs → 本用例 cloud 行不受影响 (关组只闸对应组).
    await page.locator('#privacy-group-toggles input[data-group="vcs"]').uncheck();
    await expect(activeRowOf(page, KEY)).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#privacy-group-toggles input[data-group="vcs"]')).not.toBeChecked();

    // ③ 刷新后组态保持 (state.toml 持久化), cloud 行经扫描重现.
    await page.reload();
    await page.waitForLoadState("networkidle");
    await page.locator('a.tab[data-tab="secrets"]').click();
    await expect(page.locator('#privacy-group-toggles input[data-group="vcs"]')).not.toBeChecked({ timeout: 10_000 });
    await expect(activeRowOf(page, KEY)).toBeVisible({ timeout: 10_000 });
    // ④ 组态恢复全开由 describe 级 afterEach 统一收口 (防中途失败泄漏共享态).
  });
});

// ─── 完整数据 tab 大文本分段渲染 (quant#308 性能修复的行为钉子) ──────────────
//
// 性能背景: 单个巨型 <pre> 的 layout+paint 是 raw 内容秒级卡顿的主导项
// (12MB body 初次渲染 ~700ms+, 弱 CPU 线性放大). 修复 = 超过阈值 (128KB) 的
// body 按 64KB 切段, 每段 content-visibility:auto (屏外段跳过渲染).
// 本组钉子守卫**观测语义不变**: 内容逐字符无损 (含 astral 字符跨段边界)、
// 小 body 不走分段路径. (quant#305 起原 raw 弹窗内容位于轮次详情的完整数据 tab,
// 分段虚拟化行为必须原样保留; 打开路径走共享 helper openRoundDetailTab.)

test.describe("完整数据 tab 分段渲染 (quant#308)", () => {
  // 前置: goto + 显式切回 records tab — sidebar 会话列表只在 records tab 可见
  // (共享 context 按声明顺序执行, 前序 describe 可能停在 secrets tab).
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.locator('a.tab[data-tab="records"]').click();
  });

  test("大 body: 分段生效 + 内容逐字符无损 (含 astral 字符)", async ({ page }) => {
    await setAuditCapture(page, "full");
    // 200KB 文本, astral 字符 (🚀 = surrogate pair) 密布全文 — 任何 64KB 切点
    // 都可能落在代理对中间; 切点回退逻辑若失效, DOM 文本会出现 U+FFFD.
    const pad = "seg-render-marker🚀" + "x🚀y".repeat(40); // ~200B/块, astral 密布
    const content = "seg-render-marker " + pad.repeat(1000); // ~200KB
    await sendChat(page, [{ role: "user", content }]);
    const sid = await findSessionLeafByPreview(page, "seg-render-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    const rawDialog = await openRoundDetailTab(page);
    await expect(rawDialog.locator(".raw-seg").first()).toBeVisible({ timeout: 10_000 });
    // Request Body (>128KB) 分段: 段数 > 1 (200KB / 64KB ≈ 4).
    const segCount = await rawDialog.locator(".raw-pre .raw-seg").count();
    expect(segCount).toBeGreaterThan(1);

    // 内容完整性: Request Body 区 (sections 顺序固定, 第 2 个 .raw-section —
    // 结构定位, 不依赖 i18n 文案) 的 DOM 文本 == API 返回的 req_body 原文
    // (分段/escape/surrogate 避让零损耗).
    const domText = await rawDialog
      .locator(".raw-section")
      .nth(1)
      .locator(".raw-pre")
      .textContent();
    const tl = await (
      await page.request.get(`/api/sessions/${sid}/timeline?limit=1`)
    ).json();
    const roundId = tl.rounds[tl.rounds.length - 1].id;
    const rec = (await (await page.request.get(`/api/records/${roundId}`)).json()).record;
    expect(rec.req_body.length).toBeGreaterThan(128 * 1024); // 确认走了分段路径的前提
    expect(domText).toBe(rec.req_body);
    // astral 完整性哨兵: DOM 文本不得出现 U+FFFD (切坏代理对的症状).
    expect(domText.includes("\uFFFD")).toBe(false);
    expect(domText).toContain("seg-render-marker");
  });

  test("小 body: 不分段 (原路径, 无 .raw-seg)", async ({ page }) => {
    await setAuditCapture(page, "full");
    await sendChat(page, [{ role: "user", content: "small-body-no-seg-marker" }]);
    const sid = await findSessionLeafByPreview(page, "small-body-no-seg");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);
    const rawDialog = await openRoundDetailTab(page);
    await expect(rawDialog.locator("pre.raw-pre").first()).toBeVisible({ timeout: 10_000 });
    // 小 body (<128KB) 全部走单 pre 原路径 — 零 .raw-seg.
    await expect(rawDialog.locator(".raw-seg")).toHaveCount(0);
    const rawText = await rawDialog.textContent();
    expect(rawText).toContain("small-body-no-seg-marker");
  });
});
