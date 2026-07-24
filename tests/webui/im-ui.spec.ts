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

  test("需求 3: response 打字框固定底部 + 独立滚动", async ({ page }) => {
    await sendChat(page, [{ role: "user", content: "give me a long response" }]);

    const leaf = await findSessionLeafByPreview(page, "give me a long response");
    await clickSessionByLeaf(page, leaf);
    await page.waitForTimeout(500);

    // timeline 每轮都有 request-pane + response-pane.
    await expect(page.locator("#detail .request-pane")).toHaveCount(1);
    await expect(page.locator("#detail .response-pane")).toHaveCount(1);

    // response-pane 应该是固定高度 (~10 行 ≈ 200px).
    const respH = await page
      .locator("#detail .response-pane")
      .evaluate((el) => el.clientHeight);
    expect(respH).toBeGreaterThan(150);
    expect(respH).toBeLessThan(280);

    // response 内容应该非空.
    const respText = await page.locator("#detail .resp-body").textContent();
    expect(respText!.length).toBeGreaterThan(10);

    // 滚动 #detail (timeline 容器) 不应该影响 response-pane 的 scrollTop.
    await page
      .locator("#detail")
      .evaluate((el) => (el.scrollTop = 50));
    await page.waitForTimeout(200);
    const respScroll = await page
      .locator("#detail .response-pane")
      .evaluate((el) => el.scrollTop);
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

    // preview = 最后一条 user msg.
    const leaf = await findSessionLeafByPreview(page, "final-long-response-marker");
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
    // 复用上一个测试创建的多轮对话会话 (preview = 最后一条 user msg).
    const leaf = await findSessionLeafByPreview(page, "final-long-response-marker");
    // 重新点击会话 (先折叠再展开) 触发 timeline 重新加载 + 初始滚到底.
    await clickSessionByLeaf(page, leaf);
    await page.waitForTimeout(500);

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

    // 距底部应该 < 20px.
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

    // 找到该会话 (preview = 最后一条 = round2 user).
    const sid = await findSessionLeafByPreview(page, "phaseA-round2-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    // 应有 2 个 tl-round.
    await expect(page.locator("#detail .tl-round")).toHaveCount(2);

    // 只有 1 个 response-pane (末轮).
    await expect(page.locator("#detail .response-pane")).toHaveCount(1);

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

  // ─── "已经到顶了" 提示: 短会话首次加载不应显示 ──────────────────────────────
  //
  // 验证 Bug 修复: 之前 loadTimeline 在 records.length < limit 时直接置
  // timelineReachedTop=true, 导致短会话 (< 10 轮) 首屏即显示 "已经到顶了".
  // 修复后: 只有用户实际滚顶触发 loadOlder 探测后才可能置 true.
  test("短会话首屏不显示 \"已经到顶了\"", async ({ page }) => {
    // 单轮会话.
    await sendChat(page, [{ role: "user", content: "top-hint-single-marker" }]);
    const sid = await findSessionLeafByPreview(page, "top-hint-single-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    const hint = page.locator(".tl-top-hint");
    await expect(hint).toHaveText(/向上滚动加载更早的轮次/);
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

  test("response 单气泡: text + tool_calls 合并为一个 assistant 气泡", async ({ page }) => {
    // 模拟 LLM 返回 text + tool_calls 的混合 response.
    // 通过 mockito 的默认 mock upstream, response 是固定的.
    // 这里验证: response-pane 内只有 1 个 assistant 气泡.
    await sendChat(page, [{ role: "user", content: "single-bubble-marker" }]);
    const sid = await findSessionLeafByPreview(page, "single-bubble-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    // response-pane 内应只有 1 个 chat-bubble (assistant).
    const respBubbles = page.locator("#detail .response-pane .chat-bubble");
    await expect(respBubbles).toHaveCount(1);
  });
});
