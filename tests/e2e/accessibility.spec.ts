import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { mkdir, writeFile } from "node:fs/promises";
test("WCAG AA checks in light, dark and policy dialog", async ({
  page,
}, testInfo) => {
  test.setTimeout(90000);
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  const results = [];
  for (const state of [
    "light",
    "dark",
    "report-dark",
    "report-light",
    "dialog",
  ]) {
    if (state === "dark" || state === "report-light")
      await page.getByRole("button", { name: "切换主题", exact: true }).click();
    if (state === "report-dark") {
      await page.getByRole("textbox", { name: "查询公网 IP" }).fill("8.8.8.8");
      await page.getByRole("button", { name: "查询 IP", exact: true }).click();
      await expect(page.locator(".ip-address")).toContainText("8.8.8.8");
    }
    if (state === "dialog")
      await page.getByRole("button", { name: "了解评分规则" }).click();
    const result = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
      .analyze();
    results.push({ state, violations: result.violations });
  }
  await mkdir("reports/accessibility", { recursive: true });
  await writeFile(
    `reports/accessibility/${testInfo.project.name}.json`,
    JSON.stringify(results, null, 2),
  );
  expect(
    results.flatMap((r) =>
      r.violations.map((v) => ({
        state: r.state,
        id: v.id,
        impact: v.impact,
        nodes: v.nodes.length,
      })),
    ),
  ).toEqual([]);
});
