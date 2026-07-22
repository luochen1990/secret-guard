/**
 * IM 风格 WebUI 回归测试 for secret-guard.
 *
 * 覆盖 PR #12 的 7 项需求, 每项至少一个断言:
 *   1. 滚动重置修复 (三段式 fingerprint): 自动刷新期间 scrollTop + bubble 展开状态保持.
 *   2. 三级展示气泡: 折叠 → 展开 → 弹框全文.
 *   3. response 打字框: 固定底部 + 独立滚动 + 不参与 request 滚动.
 *   4. request 初始滚到底: 切换 record 时 request-pane 自动滚到底.
 *   5. 气泡颜色 + sender icon 分类.
 *   6. sidebar preview 提取 (首条 user msg).
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
 * 等待 sidebar 出现包含指定 preview 子串的 record, 返回其 id.
 *
 * 用 Playwright locator 的 auto-retrying polling (不 reload 全页),
 * 依赖 WebUI 自身的 3s 自动刷新拉到新 record. 单测间状态隔离:
 * 每个测试用唯一 marker 子串, 不依赖其他测试创建的 record.
 */
async function findRecordIdByPreview(page: Page, previewSubstr: string): Promise<string> {
  const item = page.locator(".record-item", { hasText: previewSubstr }).first();
  await item.waitFor({ state: "visible", timeout: 5000 });
  const rid = await item.getAttribute("data-id");
  if (!rid) throw new Error(`record with preview '${previewSubstr}' has no data-id`);
  return rid;
}

async function clickRecordById(page: Page, rid: string): Promise<void> {
  await page.locator(`.record-item[data-id="${rid}"]`).click();
  await page.waitForSelector("#detail .request-pane", { timeout: 3000 });
}

/** 等待 bubble 加上指定 class (applyBubbleCollapse 异步测量后注入). */
async function expectBubbleClass(
  page: Page,
  selector: string,
  cls: string,
  timeout = 3000
): Promise<void> {
  await page.waitForFunction(
    ([sel, c]) => {
      const el = document.querySelector(sel);
      return el?.classList.contains(c) ?? false;
    },
    [selector, cls],
    { timeout }
  );
}

// ─── 测试用例 ────────────────────────────────────────────────────────────

test.describe("IM 风格 WebUI 回归", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(500);
  });

  test("需求 6+7: sidebar 显示首条 user msg 作为 preview, model 名在 line2", async ({
    page,
  }) => {
    await sendChat(page, [
      { role: "system", content: "system prompt" },
      { role: "user", content: "Hello unique-preview-text-12345" },
    ]);
    // locator 自动 polling 直到 sidebar 出现该 record (依赖 WebUI 3s 自动刷新).
    const previews = await page
      .locator(".record-item .ri-line1")
      .evaluateAll((els) => els.map((e) => e.textContent ?? ""));
    // 注: evaluateAll 不 auto-retry, 用 findRecordIdByPreview 确保 record 已落 sidebar.
    const rid = await findRecordIdByPreview(page, "Hello unique-preview-text-12345");
    expect(rid).toBeTruthy();

    const metas = await page.locator(".record-item .ri-line2").allTextContents();
    expect(metas.some((m) => m.includes("test-model-abc"))).toBe(true);
  });

  test("需求 2+5: sender icon 分类 + 气泡颜色", async ({ page }) => {
    await sendChat(page, [
      { role: "system", content: "sys" },
      { role: "user", content: "sender-icon-marker" },
    ]);

    const rid = await findRecordIdByPreview(page, "sender-icon-marker");
    await clickRecordById(page, rid);
    await page.waitForTimeout(500);

    // sender icons.
    const senderClasses = await page
      .locator("#detail .sender-icon")
      .evaluateAll((els) => els.map((e) => e.className.replace("sender-icon ", "")));
    expect(senderClasses).toContain("s-system");
    expect(senderClasses).toContain("s-user");

    // bubble 颜色 class.
    const bubbleClasses = await page
      .locator("#detail .chat-bubble")
      .evaluateAll((els) => els.map((e) => e.className));
    expect(bubbleClasses.some((c) => c.includes("bubble-system"))).toBe(true);
    expect(bubbleClasses.some((c) => c.includes("bubble-user"))).toBe(true);
  });

  test("需求 2: 三级展示气泡 (折叠 → 展开 → 弹框全文)", async ({ page }) => {
    // 超长 system prompt: 足够在任何 viewport 宽度下超过 15 行.
    const longSys = "You are a helpful assistant designed to test the secret-guard webui. ".repeat(50);
    await sendChat(page, [
      { role: "system", content: longSys },
      { role: "user", content: "three-tier-test-marker" },
    ]);

    const rid = await findRecordIdByPreview(page, "three-tier-test-marker");
    await clickRecordById(page, rid);
    // 等 applyBubbleCollapse 异步测量 + 注入 collapsed.
    await page.waitForTimeout(800);

    // 阶段 1: 折叠态.
    const sysBubble = page.locator("#detail .chat-bubble.bubble-system").first();
    await expectBubbleClass(page, "#detail .chat-bubble.bubble-system", "collapsed");

    const collapsedH = await sysBubble.evaluate((el) => el.clientHeight);
    expect(collapsedH).toBeLessThan(100);

    // 阶段 2: 点击 toggle 展开.
    await sysBubble.locator(".bubble-toggle").click();
    await page.waitForTimeout(300);
    await expectBubbleClass(page, "#detail .chat-bubble.bubble-system", "expanded");
    const expandedH = await sysBubble.evaluate((el) => el.clientHeight);
    expect(expandedH).toBeGreaterThan(collapsedH);

    // 阶段 3: 展开后超阈值应该出现 view-full 按钮.
    const viewFull = sysBubble.locator(".view-full-btn");
    await expect(viewFull).toBeVisible();

    // 点击 view-full 打开 dialog.
    await viewFull.click();
    await page.waitForTimeout(300);
    const dialog = page.locator("dialog#bubble-full-dialog");
    expect(await dialog.evaluate((el) => el.hasAttribute("open"))).toBe(true);

    // dialog 应包含完整文本.
    const bodyText = await dialog.locator(".full-body").innerText();
    expect(bodyText).toContain("helpful assistant");
  });

  test("需求 3: response 打字框固定底部 + 独立滚动", async ({ page }) => {
    await sendChat(page, [{ role: "user", content: "give me a long response" }]);

    const rid = await findRecordIdByPreview(page, "give me a long response");
    await clickRecordById(page, rid);
    await page.waitForTimeout(500);

    // 两个 pane 都应存在.
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

    // 滚动 request-pane 不应该影响 response-pane 的 scrollTop.
    await page
      .locator("#detail .request-pane")
      .evaluate((el) => (el.scrollTop = 50));
    await page.waitForTimeout(200);
    const respScroll = await page
      .locator("#detail .response-pane")
      .evaluate((el) => el.scrollTop);
    expect(respScroll).toBe(0);
  });

  test("需求 1 (B1/B2 根治): 自动刷新期间 scrollTop + bubble 展开状态保持", async ({
    page,
  }) => {
    // 多轮对话 + 长 system, 让 request-pane 有足够滚动空间.
    const longSys = "You are a coding assistant. ".repeat(15);
    await sendChat(page, [
      { role: "system", content: longSys },
      { role: "user", content: "What is 1+1?" },
      { role: "assistant", content: "1+1 equals 2." },
      { role: "user", content: "What about 2+2?" },
      { role: "assistant", content: "2+2 equals 4. ".repeat(10) },
      { role: "user", content: "Thanks" },
    ]);

    const rid = await findRecordIdByPreview(page, "What is 1+1");
    await clickRecordById(page, rid);
    await page.waitForTimeout(500);

    // 1. 展开 system bubble.
    const sysBubble = page.locator("#detail .chat-bubble.bubble-system").first();
    const toggle = sysBubble.locator(".bubble-toggle");
    if ((await toggle.count()) > 0) await toggle.click();
    await page.waitForTimeout(300);

    // 2. 设置 request-pane scrollTop 到中间.
    const canScroll = await page
      .locator("#detail .request-pane")
      .evaluate((el) => el.scrollHeight > el.clientHeight);
    if (!canScroll) {
      test.skip(true, "content fits viewport");
      return; // test.skip 会抛, 这行仅为 type-check 之后的 narrowing.
    }

    const expected = await page.locator("#detail .request-pane").evaluate(
      (el) => {
        el.scrollTop = Math.floor((el.scrollHeight - el.clientHeight) / 2);
        return el.scrollTop;
      }
    );
    expect(expected).toBeGreaterThan(0);

    // 3. 等 2 轮自动刷新 (间隔 3s).
    await page.waitForTimeout(7000);

    // 4. 验证 scrollTop 保持.
    const actual = await page
      .locator("#detail .request-pane")
      .evaluate((el) => el.scrollTop);
    expect(Math.abs(actual - expected)).toBeLessThan(10);

    // 5. 验证 bubble 仍 expanded.
    const classes = (await sysBubble.getAttribute("class")) ?? "";
    expect(classes).toContain("expanded");
  });

  test("需求 4: 切换 record 时 request-pane 初始滚到底", async ({ page }) => {
    // 复用上一个测试创建的多轮对话 record.
    const rid = await findRecordIdByPreview(page, "What is 1+1");
    await clickRecordById(page, rid);
    await page.waitForTimeout(500);

    const scrollInfo = await page.locator("#detail .request-pane").evaluate(
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
});
