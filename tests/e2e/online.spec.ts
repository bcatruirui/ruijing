import { test, expect } from "@playwright/test";
import { mkdir, writeFile } from "node:fs/promises";
test("ONLINE opt-in resource observations (not universal reachability or site egress)", async ({
  page,
}, testInfo) => {
  test.skip(
    process.env.RUN_ONLINE_PROBES !== "1",
    "Explicit separate online run only; default suite uses labeled mocks.",
  );
  test.skip(
    testInfo.project.name !== "chromium-desktop",
    "One online run avoids duplicate traffic.",
  );
  await page.goto("/");
  await page
    .getByRole("button", { name: "开始连通性检测", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "开始连通性检测", exact: true }),
  ).toBeVisible({ timeout: 25000 });
  const observations = await page
    .locator("#connectivity .site-card")
    .allTextContents();
  expect(observations).toHaveLength(8);
  expect(
    observations.some(
      (text) => text.includes("等待检测") || text.includes("检测中"),
    ),
  ).toBe(false);
  await mkdir("reports/online", { recursive: true });
  await writeFile(
    "reports/online/connectivity.json",
    JSON.stringify(
      {
        checkedAt: new Date().toISOString(),
        mode: "real-browser-resource-requests",
        observations,
        limits:
          "Resource load success is not service availability, account access, certificate-chain verification, ICMP ping, or site-specific egress. Observations apply only to this test environment.",
      },
      null,
      2,
    ),
  );
  await page
    .locator("#connectivity")
    .screenshot({ path: "reports/screenshots/online-connectivity.png" });
});
