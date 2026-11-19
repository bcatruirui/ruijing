import { test, expect } from "@playwright/test";
import { mkdir, writeFile } from "node:fs/promises";

test("real offline hosting report shows additive evidence, local flag and source coordinates", async ({ page }, testInfo) => {
  const external: string[] = [];
  page.on("request", request => {
    if (!request.url().startsWith("http://127.0.0.1:5173") && !request.url().startsWith("ws://127.0.0.1:5173")) external.push(request.url());
  });
  await page.goto("/");
  await page.getByRole("textbox", {name: "查询公网 IP"}).fill("104.251.123.25");
  const pending = page.waitForResponse(r => r.url().endsWith("/api/lookup") && r.status() === 200);
  await page.getByRole("button", {name: "查询 IP", exact: true}).click();
  const report = await (await pending).json();
  expect(report.info).toMatchObject({asn: 14315, networkType: "hosting", countryCode: "US", latitude: 33.4484, longitude: -112.074});
  expect(report.info.postalCode).toBeUndefined();
  expect(report.assessment).toMatchObject({riskScore: 25, riskLevel: "low", hasThreatEvidence: false, modelVersion: "ruijing-evidence-2.1.0"});
  expect(report.assessment.scoreDetails).toEqual(expect.arrayContaining([expect.objectContaining({ruleId: "network-context-hosting", amount: 25})]));
  const purity = page.getByRole("region", { name: "IP 纯净值" });
  await expect(purity.locator(".purity-number strong")).toHaveText(report.purity.score === null ? "—" : String(100 - report.assessment.riskScore));
  await expect(purity).not.toContainText("分数越高越好");
  await expect(purity).not.toContainText("覆盖有限 · 参考分");
  await expect(purity).not.toContainText("个威胁来源");
  await expect(purity).not.toContainText("低可信度");
  if (report.purity.score !== null) {
    await expect(purity).toHaveAttribute("data-risk", "lower");
    await expect(purity.locator(".purity-grade")).toHaveText("较低风险");
    await expect(purity.locator(".purity-grade")).toHaveCSS("color", "rgb(166, 220, 121)");
    await expect(purity).toContainText("机房托管扣 25 分");
  }
  const overview = page.getByRole("region", { name: "检测报告" });
  await expect(overview).toContainText("Phoenix");
  const fold = await overview.locator(".report-lead").boundingBox();
  expect(fold && fold.y + fold.height).toBeLessThan(page.viewportSize()!.height);
  await expect(page.locator(".ip-facts img")).toHaveAttribute("src", "/assets/flag-us.svg");
  expect(await page.locator(".ip-facts img").evaluate((image: HTMLImageElement) => image.complete && image.naturalWidth > 0)).toBe(true);
  await expect(page.locator(".geo-details")).toContainText("33.4484");
  await expect(page.locator(".geo-details")).toContainText("-112.0740");
  await expect(page.locator(".geo-details")).toContainText("当前离线库不提供邮编");
  await expect(page.locator("#evidence")).toContainText("+25");
  await expect(page.locator(".indicator")).toHaveCount(12);
  expect(page.url()).not.toContain(report.info.ip);
  expect(external).toEqual([]);
  await mkdir("reports/revision", {recursive: true});
  await writeFile(`reports/revision/${testInfo.project.name}-hosting.json`, JSON.stringify(report, null, 2));
  for (const theme of ["light", "dark"]) {
    if (theme === "dark") await page.getByRole("button", {name: "切换主题", exact: true}).click();
    await page.screenshot({path: `reports/screenshots/${testInfo.project.name}-hosting-${theme}.png`});
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  }
});

test("Mock missing coverage is unscored in the gauge and exported JSON", async ({page}) => {
  await page.route("**/api/lookup", async route => {
    const report = await (await route.fetch()).json();
    Object.assign(report.assessment, {
      riskScore: null, riskLevel: "insufficient", confidence: "insufficient", scoreKind: "insufficient",
      scoreDetails: [], evidence: [], sources: [], hasThreatEvidence: false,
      summary: {zh: "资料不足，无法可靠评分。", en: "Insufficient data for a reliable score."},
    });
    report.purity = { modelVersion: "ruijing-purity-1", score: null, status: "insufficient", checked: 0, independentSources: 0 };
    await route.fulfill({json: report});
  });
  await page.goto("/");
  await page.getByRole("textbox", {name: "查询公网 IP"}).fill("104.251.123.25");
  await page.getByRole("button", {name: "查询 IP", exact: true}).click();
  const purity = page.getByRole("region", { name: "IP 纯净值" });
  await expect(purity.locator(".purity-number strong")).toHaveText("—");
  await expect(purity).toContainText("资料不足");
  expect(await purity.getAttribute("data-risk")).toBeNull();
  const download = page.waitForEvent("download");
  await page.getByRole("button", {name: "JSON", exact: true}).click();
  const file = await (await download).path();
  const {readFile} = await import("node:fs/promises");
  const exported = JSON.parse(await readFile(file!, "utf8"));
  expect(exported.assessment.riskScore).toBeNull();
  expect(exported.purity.score).toBeNull();
  await page.getByRole("button", { name: "隐藏 IP", exact: true }).click();
  const redactedDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "JSON", exact: true }).click();
  const redacted = await readFile((await (await redactedDownload).path())!, "utf8");
  expect(redacted).not.toContain("104.251.123.25");
  expect(JSON.parse(redacted).summary.ip).toBe("IP 已隐藏");
});

test("Mock grades use distinct colors and list every deduction", async ({ page, request }) => {
  const fixture = await (await request.post("/api/lookup", { data: { ip: "104.251.123.25" } })).json();
  let score = 50;
  await page.route("**/api/lookup", route => route.fulfill({ json: {
    ...fixture,
    purity: { ...fixture.purity, score, status: "scored" },
    assessment: { ...fixture.assessment, riskScore: 100 - score, scoreDetails: [
      { ruleId: "network-context-hosting", amount: 25, label: { zh: "机房", en: "Hosting" }, explanation: { zh: "归属信号", en: "Network attribution" }, evidenceIds: [] },
      { ruleId: "threat-phishing", amount: 75 - score, label: { zh: "钓鱼", en: "Phishing" }, explanation: { zh: "公开情报", en: "Public intelligence" }, evidenceIds: [] },
    ] },
  } }));
  await page.goto("/");
  const purity = page.getByRole("region", { name: "IP 纯净值" });
  const grade = purity.locator(".purity-grade");
  await page.getByRole("textbox", { name: "查询公网 IP" }).fill("104.251.123.25");
  await page.getByRole("button", { name: "查询 IP", exact: true }).click();
  await expect(grade).toHaveText("中等风险");
  await expect(grade).toHaveCSS("color", "rgb(246, 200, 123)");
  await expect(purity.locator("li")).toHaveText(["机房托管扣 25 分", "钓鱼扣 25 分"]);
  score = 25;
  await page.getByRole("button", { name: "查询 IP", exact: true }).click();
  await expect(grade).toHaveText("较高风险");
  await expect(grade).toHaveCSS("color", "rgb(255, 173, 121)");
  await expect(purity.locator("li")).toHaveText(["机房托管扣 25 分", "钓鱼扣 50 分"]);
  score = 0;
  await page.getByRole("button", { name: "查询 IP", exact: true }).click();
  await expect(grade).toHaveText("高风险");
  await expect(grade).toHaveCSS("color", "rgb(255, 147, 159)");
  await expect(purity.locator("li")).toHaveText(["机房托管扣 25 分", "钓鱼扣 75 分"]);
});

test("Mock self DNS observations update the report and never carry into a manual lookup", async ({ page, request }) => {
  const fixture = await (await request.post("/api/lookup", { data: { ip: "104.251.123.25" } })).json();
  await page.route("**/api/self", route => route.fulfill({ json: { ...fixture, mode: "self" } }));
  await page.route("**/api/capabilities", async route => {
    const data = await (await route.fetch()).json();
    await route.fulfill({ json: { ...data, dns: { configured: true, status: "ready" } } });
  });
  const id = "a".repeat(32), secret = "s".repeat(43);
  const probeUrls = Array.from({ length: 4 }, (_, index) => `https://q${String(index).padStart(32, "0")}.probe.example.test/probe`);
  await page.route("https://*.probe.example.test/probe", route => route.fulfill({ status: 204 }));
  await page.route("**/api/dns/start", route => route.fulfill({ status: 201, json: { id, secret, probeUrls, expiresAt: new Date(Date.now() + 150_000).toISOString() } }));
  await page.route("**/api/dns/results", route => {
    const at = new Date().toISOString();
    return route.fulfill({ json: { id, resolvers: [{ ip: "8.8.8.8", asn: 15169, types: ["A"], probeCount: 2, firstObservedAt: at, lastObservedAt: at }] } });
  });
  await page.route("**/api/dns/delete", route => route.fulfill({ json: { deleted: true } }));
  await page.goto("/");
  const report = page.getByRole("region", { name: "检测报告" });
  await expect(report).toContainText("Asia/Shanghai");
  await expect(report).toContainText("待检测");
  await page.getByLabel(/预期递归解析器/).fill("AS13335");
  await page.getByRole("button", { name: "开始 DNS 检测", exact: true }).click();
  await expect(report).toContainText("疑似泄漏");
  await page.getByRole("textbox", { name: "查询公网 IP" }).fill("1.1.1.1");
  await page.getByRole("button", { name: "查询 IP", exact: true }).click();
  await expect(page.locator(".ip-address")).toHaveText("1.1.1.1");
  await expect(report).not.toContainText("Asia/Shanghai");
  await expect(report).not.toContainText("疑似泄漏");
});
