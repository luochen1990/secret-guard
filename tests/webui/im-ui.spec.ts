/**
 * IM 风格 WebUI 回归测试 for secret-guard (会话折叠 + timeline 版本).
 *
 * 适配会话两级树 sidebar (session-item → round-item) + timeline 右侧对话流.
 * 每条 sendChat 创建一个独立的单轮次会话 (无父上下文 → 各自成为 root+leaf).
 *
 * 覆盖原始 7 项需求 (在新的会话/timeline 结构下):
 *   1. 滚动重置修复: 自动刷新期间 timeline 内 scrollTop + bubble 展开状态保持.
 *   2. 三级展示气泡: 折叠 → 展开 → 弹框全文.
 *   3. response 打字框: 固定底部 + 独立滚动 + 不参与 request 滚动.
 *   4. timeline 选中轮次时 request-pane 初始滚到底.
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
 * 所有测试共享一个 browser context, 按声明顺序执行 (workers=1).
 */
import { test, expect, type Page } from "@playwright/test";

const SG_API = "/__sg/api";
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
 * 点击会话展开 + 加载 timeline (单轮次会话: 点击会话即选中该轮次).
 * 等待右侧 timeline 的 request-pane 出现.
 */
async function clickSessionByLeaf(page: Page, sid: string): Promise<void> {
  await page.locator(`.session-item[data-sid="${sid}"]`).click();
  await page.waitForSelector("#detail .request-pane", { timeout: 3000 });
}

// ─── 测试用例 ────────────────────────────────────────────────────────────

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
    const longSys = "You are a coding assistant. ".repeat(15);
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
      { role: "assistant", content: "2+2 equals 4. ".repeat(10) },
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
    // 复用上一个测试创建的多轮对话会话 (title = 第一轮首条 user msg, issue #36).
    const leaf = await findSessionLeafByPreview(page, "first long response question");
    // 点击会话条目 → toggleSession → selectRound(leaf, {scroll:'bottom'}).
    // 契约: "用户点会话条目" = IM 风格看最新消息, 应滚到底 (非 highlightRound 的 70% 定位).
    // 历史回归: DOM 倒序 bug 期间此契约被 highlightRound 的副作用巧合满足; 顺序修正后
    // 暴露了 selectRound 对已缓存会话只 highlight 不滚到底的不一致, 现由 scroll:'bottom' 修复.
    await clickSessionByLeaf(page, leaf);
    // 等 toggleSession 的 selectRound 完成 + 浏览器 layout 稳定 (placeholder 高度计算).
    await page.locator("#detail .drawer-placeholder").waitFor({ state: "visible", timeout: 3000 });
    await page.waitForTimeout(300);

    const scrollInfo = await page.locator("#detail").evaluate(
      (el) => ({
        scrollTop: el.scrollTop,
        scrollHeight: el.scrollHeight,
        clientHeight: el.clientHeight,
      })
    );
    if (scrollInfo.scrollHeight <= scrollInfo.clientHeight) {
      test.skip(true, "content fits viewport");
      return;
    }

    // 距底部应该 < 20px (选中会话 = IM 风格滚到最新一轮).
    const distanceToBottom =
      scrollInfo.scrollHeight - scrollInfo.scrollTop - scrollInfo.clientHeight;
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

    // 分组渲染: 用户轮次 (round1) 作为组首, 后续工具调用轮次 (round2/3) 折叠为小圆点.
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

  // ─── 三级条目小圆点: 工具调用轮次折叠为横向圆点 ──────────────────────────
  //
  // 验证 sidebar 分组渲染:
  //   - 用户轮次作为组首 (.round-item, 显示 preview).
  //   - 紧随的纯工具调用轮次折叠为 .sub-dot (横向排列, 颜色 = tool name hash).
  //   - 不同 tool name 产生不同颜色.
  test("三级圆点: 工具调用轮次折叠为彩色小圆点", async ({ page }) => {
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

    // 1 个组首 (.round-item = 用户轮次), 2 个小圆点 (.sub-dot = 工具调用轮次).
    await expect(page.locator(".round-item")).toHaveCount(1);
    await expect(page.locator(".sub-dot")).toHaveCount(2);

    // 两个圆点颜色不同 (tool name "ls" vs "cat" 哈希不同).
    const dots = page.locator(".sub-dot");
    const bg1 = await dots.nth(0).evaluate((el) => getComputedStyle(el).backgroundColor);
    const bg2 = await dots.nth(1).evaluate((el) => getComputedStyle(el).backgroundColor);
    expect(bg1, "不同 tool name 应产生不同颜色").not.toBe(bg2);

    // 圆点 tooltip 应含 tool name.
    const title1 = await dots.nth(0).getAttribute("title") || "";
    expect(title1).toContain("ls");
    const title2 = await dots.nth(1).getAttribute("title") || "";
    expect(title2).toContain("cat");

    // 点击圆点应选中对应轮次 (右侧 timeline 高亮).
    await dots.nth(1).click();
    await page.waitForTimeout(500);
    await expect(page.locator(".sub-dot.active")).toHaveCount(1);
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

  // ─── Raw view 恢复 + Info icon + Response 单气泡 ──────────────────────────
  //
  // 验证三个功能:
  //   1. 每轮 header 有 info (ℹ) + raw 按钮.
  //   2. info 按钮弹出传输层元数据 (method/path/status, 无需网络请求).
  //   3. raw 按钮弹出原始 req_body / resp_body (按需懒拉 /records/{id}).
  //   4. response 窗口内只有一个 assistant 气泡 (不再因 tool_calls 拆分多个).

  test("info icon + raw 按钮: 弹窗展示传输层信息和原始 body", async ({ page }) => {
    await sendChat(page, [{ role: "user", content: "info-raw-marker" }]);
    const sid = await findSessionLeafByPreview(page, "info-raw-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    // 每轮 header 应有 info + raw 按钮.
    await expect(page.locator("#detail .tl-actions button[data-action='info']")).toHaveCount(1);
    await expect(page.locator("#detail .tl-actions button[data-action='raw']")).toHaveCount(1);

    // 点击 info → 弹窗含传输层元数据 (method=POST, path 含 provider).
    await page.locator("#detail .tl-actions button[data-action='info']").click();
    await page.waitForTimeout(300);
    const infoDialog = page.locator("dialog.round-dialog");
    await expect(infoDialog).toBeVisible();
    const infoText = await infoDialog.textContent();
    expect(infoText).toContain("POST");
    expect(infoText).toContain("Path");
    expect(infoText).toContain("Status");
    expect(infoText).toContain("Elapsed");
    // 关闭.
    await page.locator("dialog.round-dialog .dialog-close").click();

    // 点击 raw → 弹窗含 req_body / resp_body (按需懒拉).
    await page.locator("#detail .tl-actions button[data-action='raw']").click();
    await page.waitForTimeout(500);  // 等待 fetch.
    const rawDialog = page.locator("dialog.round-dialog");
    await expect(rawDialog).toBeVisible();
    const rawText = await rawDialog.textContent();
    expect(rawText).toContain("Request Body");
    expect(rawText).toContain("Response Body");
    expect(rawText).toContain("Request Headers");
    // req_body 应含发送的 marker.
    expect(rawText).toContain("info-raw-marker");
    // 关闭.
    await page.locator("dialog.round-dialog .dialog-close").click();
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

  test("drawer phase 3 holds maxH before content enters drawer zone", async ({ page }) => {
    // bug #1 回归: 向下滚, 气泡滚出顶部后 drawer 应保持 maxH (40%),
    // 直到末轮底部真正进入抽屉遮挡区域才开始 phase 4 渐进扩展.
    const reply = "This is a long response for testing the typing box. ".repeat(15);
    const sys = "You are a coding assistant. ".repeat(5);
    // 3 轮长内容会话
    await sendChat(page, [{ role: "system", content: sys }, { role: "user", content: "phase3-hold-marker" }, { role: "assistant", content: reply }]);
    await sendChat(page, [{ role: "system", content: sys }, { role: "user", content: "phase3-hold-marker" }, { role: "assistant", content: reply }, { role: "user", content: "second" }, { role: "assistant", content: reply }]);
    await sendChat(page, [{ role: "system", content: sys }, { role: "user", content: "phase3-hold-marker" }, { role: "assistant", content: reply }, { role: "user", content: "second" }, { role: "assistant", content: reply }, { role: "user", content: "third" }, { role: "assistant", content: reply }]);
    const leaf = await findSessionLeafByPreview(page, "phase3-hold-marker");
    await clickSessionByLeaf(page, leaf);
    await page.waitForTimeout(500);
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
});
