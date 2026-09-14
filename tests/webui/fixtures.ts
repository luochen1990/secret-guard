/** WebUI 测试夹具 SSOT: config 与 spec 共享的常量.
 *
 * 读者: tests/webui/ 下编写或修改 playwright 测试的人.
 * 动机: 分歧会静默失效的承重值必须单一来源 (port / provider id 分歧会响亮失败,
 * 不在此列, 沿用字面量先例). */

/** playwright.config.ts 写入 static secret (id = "test-key") / im-ui.spec.ts 构造
 *  redact 命中的共享值. 长值 (64 chars) 是刻意设计: Auto mock 长度 = secret 长度,
 *  长 mock 才能决定性触发 usage 表格溢出守卫 (远超 td 列宽 180/280px). */
export const TEST_SECRET_VALUE = "sk-test-" + "a1b2c3d4e5f6".repeat(4) + "a1b2c3d4";
