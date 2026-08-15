/**
 * IM 风格 WebUI 回归测试 for secret-guard (会话折叠 + timeline 版本, session-aware sync API).
 *
 * 适配会话两级树 sidebar (session-item → round-item) + timeline 右侧对话流.
 * 每条 sendChat 创建一个独立的单轮次会话 (无父上下文 → 各自成为 root+leaf).
 *
 * 后端 API (session-aware sync):
 *   - POST /api/sync           统一轮询 (sidebar sessions + expanded rounds + timeline diff).
 *   - GET  /api/sessions/{sid}/timeline?before=&limit=  初始加载 + lazy load.
 *   - GET  /api/records/{id}   单条 record raw/parsed view (弹窗用, 保留).
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

    // 取消后: 下拉回滚为 default (refresh 重建, selected 复原).
    await expect(page.locator('select.decision-select[data-id="test-key"]')).toHaveValue(
      "default"
    );

    // 再测确认路径: confirm accept → PATCH 生效 (列表中该项消失 = disabled 语义).
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
    // disabled 后 secret 从 effective 列表消失 (表格不再渲染该行).
    await expect(
      page.locator('select.decision-select[data-id="test-key"]')
    ).toHaveCount(0);

    // 清理: 通过 API 切回 default, 不污染后续测试.
    await page.request.patch(`${SG_API}/secrets/test-key/decision`, {
      data: { mode: "default" },
    });
    await page.waitForTimeout(100);
  });

  test("#161: PATCH decision API 响应 disabled 时含 warning 字段", async ({ request }) => {
    const ack = await request.patch(`${SG_API}/secrets/test-key/decision`, {
      data: { mode: "disabled" },
    });
    expect(ack.status()).toBe(200);
    const body = await ack.json();
    expect(body.warning).toContain("plaintext");
    // 切回 default: warning 字段缺省 (向后兼容 shape).
    const ack2 = await request.patch(`${SG_API}/secrets/test-key/decision`, {
      data: { mode: "default" },
    });
    const body2 = await ack2.json();
    expect(body2.warning ?? null).toBeNull();
  });

  test("#164-1: raw 弹窗 Response Body 带 (LLM view) 标注", async ({ page }) => {
    await sendChat(page, [{ role: "user", content: "raw-llm-view-marker" }]);
    const sid = await findSessionLeafByPreview(page, "raw-llm-view-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    await page.locator("#detail .tl-actions button[data-action='raw']").click();
    await page.waitForTimeout(500);
    const rawText = await page.locator("dialog.round-dialog").textContent();
    // 非流式响应: Response Body 区段应带 LLM view 标注 (含 mock 视角提示).
    expect(rawText).toContain("Response Body (LLM view");
    await page.locator("dialog.round-dialog .dialog-close").click();
  });

  test("#164-2: info 弹窗 Time 为本地时间, title 保留 UTC RFC3339", async ({ page }) => {
    await sendChat(page, [{ role: "user", content: "info-time-marker" }]);
    const sid = await findSessionLeafByPreview(page, "info-time-marker");
    await clickSessionByLeaf(page, sid);
    await page.waitForTimeout(500);

    await page.locator("#detail .tl-actions button[data-action='info']").click();
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
