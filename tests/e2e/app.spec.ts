import { test, expect } from "@playwright/test";
import { readFile, mkdir } from "node:fs/promises";
test("capability API failure preserves the basic report and shows unknown service state (Mock failure)", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/api/capabilities", (route) =>
    route.fulfill({ status: 503, json: { error: "BUSY" } }),
  );
  await page.goto("/");
  await page.getByRole("textbox", { name: "查询公网 IP" }).fill("8.8.8.8");
  await page.getByRole("button", { name: "查询 IP", exact: true }).click();
  await expect(page.locator(".ip-address")).toContainText("8.8.8.8");
  await expect(page.locator("#dns")).toContainText("配置状态未知");
  expect(errors).toEqual([]);
});
test("mock controlled nodes compare egress and global privacy hiding stays reactive", async ({
  page,
}) => {
  await page.route("**/api/capabilities", async (route) => {
    const data = await (await route.fetch()).json();
    data.familyEndpoints = {
      ipv4: "https://v4.example.test/echo",
      ipv6: "https://v6.example.test/echo",
    };
    data.routingNodes = [
      {
        id: "v4",
        name: "Test IPv4",
        url: data.familyEndpoints.ipv4,
        family: 4,
      },
      {
        id: "v6",
        name: "Test IPv6",
        url: data.familyEndpoints.ipv6,
        family: 6,
      },
    ];
    await route.fulfill({ json: data });
  });
  await page.route("https://*.example.test/echo", (route) =>
    route.fulfill({
      json: {
        ip: route.request().url().includes("v4.")
          ? "8.8.8.8"
          : "2001:4860:4860::8888",
      },
    }),
  );
  await page.goto("/");
  await page.getByRole("textbox", { name: "查询公网 IP" }).fill("8.8.4.4");
  await page.getByRole("button", { name: "查询 IP", exact: true }).click();
  await expect(page.locator(".ip-address")).toContainText("8.8.4.4");
  await page.getByRole("button", { name: "运行双栈检测" }).click();
  await expect(page.locator(".dual-stack")).toContainText(
    "2001:4860:4860::8888",
  );
  await expect(page.locator('.connection-check-grid a[href="#dual-stack"]')).toContainText("已观测 2 个地址族");
  await page.getByRole("button", { name: "检测分流", exact: true }).click();
  await expect(page.locator("#routing .routing-summary")).toContainText(
    "观察到不同出口",
  );
  await expect(page.locator('.connection-check-grid a[href="#routing"]')).toContainText("观测到不同公网出口");
  await page.getByRole("button", { name: "隐藏 IP", exact: true }).click();
  await expect(page.locator(".dual-stack")).not.toContainText("8.8.8.8");
  await expect(page.locator(".dual-stack")).not.toContainText(
    "2001:4860:4860::8888",
  );
  await expect(page.locator("#routing")).not.toContainText(
    "2001:4860:4860::8888",
  );
  await page.getByRole("button", { name: "显示 IP", exact: true }).click();
  await expect(page.locator(".dual-stack")).toContainText("8.8.8.8");
});
test("diagnostics distinguish the lookup from browser checks, and clear current or pending results", async ({ page, request }) => {
  const external: string[] = [];
  page.on("request", request => {
    if (!request.url().startsWith("http://127.0.0.1:5173/")) external.push(request.url());
  });
  await page.goto("/");
  await expect(page.getByRole("complementary", { name: "瑞镜隐私承诺" })).toContainText("每个人都应该享有隐私权");
  await page.getByRole("button", { name: "隐私说明" }).click();
  await expect(page.getByRole("dialog")).toContainText("GitHub Pages");
  await page.getByRole("button", { name: "关闭", exact: true }).click();

  const lookup = page.getByRole("textbox", { name: "查询公网 IP" });
  const submit = page.getByRole("button", { name: "查询 IP", exact: true });
  await lookup.fill("104.251.123.25");
  await submit.click();
  const diagnostics = page.getByRole("region", { name: "IP 检测总览" });
  await expect(diagnostics).toContainText("当前查询的目标 IP");
  const ownership = diagnostics.locator(".diagnostic-ownership");
  await expect(ownership.locator("dl > div").filter({ hasText: "自治系统编号（ASN）" }).locator("dd")).toHaveText("AS14315");
  await expect(ownership.locator("dl > div").filter({ hasText: "ASN 归属组织" }).locator("dd")).toHaveText("1GSERVERS, LLC");
  await expect(ownership).toContainText("ASN 用于在互联网路由中识别网络");
  await expect(diagnostics.locator(".location-map canvas")).toBeVisible();

  const browser = page.getByRole("region", { name: "当前浏览器与连接" });
  await expect(browser.getByRole("link", { name: /DNS 解析路径/ })).toContainText("暂不可用");
  await expect(browser).toContainText("Asia/Shanghai");
  await browser.getByLabel("要验证的 IP").fill("2001:db8::4");
  const prefix = browser.getByLabel("CIDR 网段（可选）");
  await prefix.fill("2001:db8::/32");
  await expect(browser).toContainText("文档示例地址");
  await expect(browser).toContainText("此 IP 属于该网段");
  await prefix.fill("192.0.2.0/24");
  await expect(browser).toContainText("地址与网段的地址族不同");
  expect(external).toEqual([]);

  await page.getByRole("button", { name: "清除本次检测" }).click();
  await expect(lookup).toHaveValue("");
  await expect(diagnostics).toHaveCount(0);
  await expect(browser.getByLabel("要验证的 IP")).toHaveValue("");
  await expect(prefix).toHaveValue("");
  await expect(page.getByRole("button", { name: "JSON", exact: true })).toHaveCount(0);

  const fixture = await (await request.post("/api/lookup", { data: { ip: "104.251.123.25" } })).json();
  let resolveResponse!: () => void;
  const releaseResponse = new Promise<void>((resolve) => { resolveResponse = resolve; });
  await page.route("**/api/lookup", async (route) => {
    await releaseResponse;
    await route.fulfill({ json: fixture }).catch(() => {});
  });
  await lookup.fill("104.251.123.25");
  const started = page.waitForRequest("**/api/lookup");
  await submit.click();
  await started;
  await page.getByRole("button", { name: "清除本次检测" }).click();
  resolveResponse();
  await page.unrouteAll({ behavior: "wait" });
  await expect(page.getByRole("region", { name: "IP 纯净值" })).toContainText("等待检测");
  await expect(diagnostics).toHaveCount(0);
});
test("real offline report, exports, privacy, themes, language and layout", async ({
  page,
  context,
}, testInfo) => {
  const thirdParty: string[] = [],
    errors: string[] = [];
  page.on("request", (r) => {
    if (
      !r.url().startsWith("http://127.0.0.1:5173") &&
      !r.url().startsWith("ws://127.0.0.1:5173")
    )
      thirdParty.push(r.url());
  });
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText(
    "看清连接",
  );
  await expect(page.getByText("本地预览模式", { exact: true })).toBeVisible();
  await expect(
    page.getByRole("button", { name: "暂不可检测", exact: true }),
  ).toBeDisabled();
  expect(thirdParty).toEqual([]);
  await page.getByRole("textbox", { name: "查询公网 IP" }).fill("8.8.8.8");
  const response = page.waitForResponse(
    (r) => r.url().endsWith("/api/lookup") && r.status() === 200,
  );
  await page.getByRole("button", { name: "查询 IP", exact: true }).click();
  const data = await (await response).json();
  expect(data.info.ip).toBe("8.8.8.8");
  expect(data.info.asn).toBe(15169);
  expect(data.info.countryCode).toBe("US");
  expect(data.info.region).toBe("California");
  expect(data.info.city).toBe("Mountain View");
  expect(data.assessment.riskScore).toBeGreaterThanOrEqual(0);
  expect(data.assessment.riskScore).toBeLessThanOrEqual(100);
  await expect(page.locator(".ip-address")).toContainText("8.8.8.8");
  await expect(page.locator(".ip-facts")).toContainText("Mountain View");
  await expect(page.locator(".indicator")).toHaveCount(12);
  await expect(page.locator("#routing .routing-summary")).not.toContainText(
    "8.8.8.8",
  );
  await expect(page.locator(".dual-stack")).not.toContainText("8.8.8.8");
  expect(page.url()).not.toContain("8.8.8.8");
  expect(thirdParty).toEqual([]);
  await page.getByRole("button", { name: "隐藏 IP", exact: true }).click();
  await expect(page.locator(".ip-address")).not.toContainText("8.8.8.8");
  await expect(
    page.getByRole("textbox", { name: "查询公网 IP" }),
  ).toHaveAttribute("type", "password");
  await page.getByRole("button", { name: "显示 IP", exact: true }).click();
  const jsonDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "JSON", exact: true }).click();
  const jsonFile = await (await jsonDownload).path();
  expect(jsonFile).toBeTruthy();
  expect(JSON.parse(await readFile(jsonFile!, "utf8")).info.ip).toBe("8.8.8.8");
  const pngDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "PNG", exact: true }).click();
  const png = await pngDownload;
  const pngFile = await png.path();
  expect((await readFile(pngFile!)).subarray(0, 8).toString("hex")).toBe(
    "89504e470d0a1a0a",
  );
  await mkdir("reports/exports", { recursive: true });
  await png.saveAs(`reports/exports/${testInfo.project.name}-report.png`);
  if (testInfo.project.name === "chromium-desktop") {
    await page.evaluate(() => dispatchEvent(new Event("beforeprint")));
    await page.pdf({
      path: "reports/exports/report.pdf",
      format: "A4",
      printBackground: true,
    });
    await page.evaluate(() => dispatchEvent(new Event("afterprint")));
    expect(
      (await readFile("reports/exports/report.pdf")).subarray(0, 4).toString(),
    ).toBe("%PDF");
  }
  await page.getByRole("button", { name: "了解评分规则" }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.press("Tab");
  expect(
    await page.evaluate(
      () => document.activeElement?.closest('[role="dialog"]') !== null,
    ),
  ).toBe(true);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await mkdir("reports/screenshots", { recursive: true });
  await page.getByRole("button", { name: "切换主题", exact: true }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.locator(".brand-image-white")).toBeVisible();
  await expect(page.locator("#site-icon")).toHaveAttribute(
    "href",
    "/assets/ruijing-icon-white.png",
  );
  await page.screenshot({
    path: `reports/screenshots/${testInfo.project.name}-dark.png`,
  });
  await page.getByRole("button", { name: "切换主题", exact: true }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(page.locator(".brand-image-black")).toBeVisible();
  await expect(page.locator("#site-icon")).toHaveAttribute(
    "href",
    "/assets/ruijing-icon-black.png",
  );
  await page.getByRole("button", { name: "Switch to English" }).click();
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await expect(page.getByRole("heading", { level: 1 })).toContainText(
    "See your connection",
  );
  await page.getByRole("button", { name: "切换到中文" }).click();
  expect(await page.evaluate(() => Object.keys(localStorage).sort())).toEqual([
    "ruijing-language",
    "ruijing-theme",
  ]);
  const overflow = await page.evaluate(() => ({
    scroll: document.documentElement.scrollWidth,
    width: innerWidth,
  }));
  expect(overflow.scroll).toBeLessThanOrEqual(overflow.width + 1);
  await page.screenshot({
    path: `reports/screenshots/${testInfo.project.name}-light-full.png`,
    fullPage: true,
  });
  await page.screenshot({
    path: `reports/screenshots/${testInfo.project.name}-light.png`,
  });
  expect(errors).toEqual([]);
  expect(thirdParty).toEqual([]);
});

test("real browser WebRTC and truthful unconfigured routing", async ({
  page,
}) => {
  await page.goto("/");
  await expect(
    page.getByRole("button", { name: "检测 WebRTC", exact: true }),
  ).toBeEnabled();
  await page.getByRole("button", { name: "检测 WebRTC", exact: true }).click();
  await expect(page.locator("#webrtc .test-result")).toBeVisible({
    timeout: 12000,
  });
  await expect(page.locator("#webrtc")).toContainText("受限");
  await page.getByRole("button", { name: "检测分流", exact: true }).click();
  await expect(page.locator("#routing .inline-notice")).toContainText("未部署");
  await expect(page.locator("#routing")).toContainText("无法判断");
});

test("mock browser resources are only contacted after opt-in and never establish site egress", async ({
  page,
}) => {
  // This test deliberately mocks remote image resources. It is NOT an online reachability test.
  const seen: string[] = [];
  await page.route("https://**/*", async (route) => {
    seen.push(route.request().url());
    await route.fulfill({
      contentType: "image/png",
      body: Buffer.from(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jT6kAAAAASUVORK5CYII=",
        "base64",
      ),
    });
  });
  await page.goto("/");
  await expect(
    page.getByRole("button", { name: "开始连通性检测", exact: true }),
  ).toBeEnabled();
  expect(seen).toEqual([]);
  await page
    .getByRole("button", { name: "开始连通性检测", exact: true })
    .click();
  await expect(page.locator("#connectivity .site-card")).toHaveCount(8);
  await expect(page.locator("#connectivity .site-ok")).toHaveCount(8);
  expect(seen).toHaveLength(8);
  expect(seen.some((url) => url.includes("tiktok.com"))).toBe(true);
  await expect(page.locator("#routing tbody tr")).toHaveCount(8);
  for (const row of await page.locator("#routing tbody tr").all())
    await expect(row.locator("td").nth(2)).toHaveText("未知");
});
