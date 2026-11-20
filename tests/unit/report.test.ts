import { describe, expect, it } from "vitest";
import { assessRisk } from "../../shared/scoring.ts";
import type { IpReport, NetworkType } from "../../shared/contracts.ts";
import { reportText, reportView } from "../../src/lib/report.ts";
import { timezoneCountries } from "../../src/lib/timezone-territories.ts";
import { expectedResolvers, unexpectedResolver } from "../../src/lib/dns-expectation.ts";

const instant = "2026-11-19T08:00:00Z";
function fixture(mode: IpReport["mode"], type: NetworkType, countryCode: string, ip = "8.8.8.8"): IpReport {
  return {
    mode, info: { ip, family: 4, countryCode, city: "Example city", addressType: "public", networkType: type, attributes: [] },
    assessment: assessRisk({ ip, asOf: instant, datasetVersion: "fixture", evidence: [], sources: [], networkType: type, attributes: [] }),
    warnings: [], generatedAt: instant,
  };
}

describe("detection report boundaries", () => {
  it("shows the grade and the exact deduction in the report and summary export", () => {
    const report = fixture("lookup", "hosting", "US");
    report.purity = { modelVersion: "ruijing-purity-4", score: 75, status: "scored", checked: 2, independentSources: 2, coverage: "limited" };
    report.assessment.confidence = "low";
    report.assessment.scoreDetails = [{ ruleId: "network-context-hosting", amount: 25, label: { zh: "机房", en: "Hosting" }, explanation: { zh: "归属信号", en: "Network attribution" }, evidenceIds: [] }];
    const view = reportView(report, "zh");
    expect(view).toMatchObject({ scoreState: "较低风险", riskTier: "lower", scoreDeductions: ["机房托管扣 25 分"], riskEvidenceConfidence: "低可信度" });
    const summary = reportText(report, view);
    expect(summary).toContain("75 / 100 · 较低风险\n机房托管扣 25 分");
    expect(summary).not.toContain("覆盖有限 · 参考分");
    expect(summary).not.toContain("低可信度");
  });

  it.each([
    [0, "high"], [12, "high"], [13, "higher"], [37, "higher"], [38, "medium"],
    [62, "medium"], [63, "lower"], [87, "lower"], [88, "low"], [100, "low"],
  ] as const)("grades a purity score of %i as %s", (score, riskTier) => {
    const report = fixture("lookup", "hosting", "US");
    report.purity = { modelVersion: "ruijing-purity-4", score, status: "scored", checked: 2, independentSources: 2, coverage: "sufficient" };
    expect(reportView(report, "zh").riskTier).toBe(riskTier);
  });

  it("presents a zero-deduction residential 100 as low risk while retaining the report's check count", () => {
    const report = fixture("lookup", "residential", "CN");
    report.purity = { modelVersion: "ruijing-purity-3", score: 100, status: "scored", checked: 2, independentSources: 2, coverage: "limited" };
    const view = reportView(report, "zh");
    expect(view).toMatchObject({ scoreState: "低风险", scoreDeductions: ["本次无扣分项"], checked: 2 });
    expect(view.rows.some(row => row.value.includes("核查 2 个适用来源"))).toBe(true);
  });

  it("lists each deduction and reconciles the rounded total", () => {
    const report = fixture("lookup", "hosting", "US");
    report.purity = { modelVersion: "ruijing-purity-2", score: 38, status: "scored", checked: 2, independentSources: 2, coverage: "sufficient" };
    report.assessment.scoreDetails = [
      { ruleId: "network-context-hosting", amount: 20, label: { zh: "机房", en: "Hosting" }, explanation: { zh: "归属信号", en: "Network attribution" }, evidenceIds: [] },
      { ruleId: "threat-phishing", amount: 41.5, label: { zh: "钓鱼", en: "Phishing" }, explanation: { zh: "公开情报", en: "Public intelligence" }, evidenceIds: [] },
    ];
    expect(reportView(report, "zh").scoreDeductions).toEqual(["机房托管扣 20 分", "钓鱼扣 41.5 分", "证据扣分合计 62 分（取整）"]);
  });
  it("shows a weak hosting clue separately from confirmed deductions", () => {
    const report = fixture("lookup", "unknown", "US");
    report.purity = { modelVersion: "ruijing-purity-6", score: 75, status: "insufficient", checked: 1, independentSources: 1, coverage: "limited", limit: "network", reservedPoints: 25 };
    report.assessment.evidence.push({
      id: "weak-hosting", sourceId: "openasn", sourceName: "OpenASN", upstreamFamily: "openasn-core",
      sourceUrl: "https://github.com/openasn/openasn", category: "network", value: "hosting",
      confidence: "low", networkType: "hosting", description: { zh: "测试线索", en: "Test clue" },
    });
    expect(reportView(report, "zh")).toMatchObject({
      score: 75, riskTier: null, network: "疑似机房 · OpenASN 提供低置信线索",
      scoreDeductions: ["网络用途待核实，预留 25 分"],
    });
    report.assessment.evidence[0].stale = true;
    expect(reportView(report, "zh").network).toBe("类型未知");
  });
  it("keeps browser signals out of a manual lookup", () => {
    const view = reportView(fixture("lookup", "hosting", "JP"), "zh", { timezone: "Asia/Shanghai", dnsReady: true, hidden: true });
    expect(view.ip).toBe("IP 已隐藏");
    expect(view.rows).toHaveLength(2);
    expect(JSON.stringify(view)).not.toContain("Asia/Shanghai");
  });

  it("requires a uniquely supported device environment", () => {
    const self = fixture("self", "hosting", "JP");
    expect(reportView(self, "zh", { timezone: "Asia/Shanghai" }).judgment).toBe("");
    expect(reportView(self, "zh", { timezone: "Asia/Shanghai", alternate: fixture("lookup", "mobile", "CN", "1.1.1.1") }).judgment).toContain("可能关联中国");
    expect(timezoneCountries("UTC")).toEqual([]);
    expect(timezoneCountries("Asia/Calcutta")).toContain("IN");
  });

  it("requires two distinct query observations before marking a known path unexpected", () => {
    const expected = expectedResolvers("AS13335, 1.1.1.0/24")!;
    const observed = { ip: "8.8.8.8", firstObservedAt: instant, lastObservedAt: instant, types: ["A"], probeCount: 2 };
    expect(expectedResolvers("AS0 foo")).toBeNull();
    expect(unexpectedResolver(observed, expected)).toBe(false);
    expect(unexpectedResolver({ ...observed, asn: 15169 }, expected)).toBe(true);
    expect(unexpectedResolver({ ...observed, asn: 15169, probeCount: 1 }, expected)).toBe(false);
    expect(unexpectedResolver({ ...observed, asn: 13335 }, expected)).toBe(false);
  });
});
