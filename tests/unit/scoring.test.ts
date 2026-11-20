import { describe, expect, it } from "vitest";
import type {
  Evidence,
  ScoringInput,
  SourceStatus,
} from "../../shared/contracts";
import {
  assessRisk,
  assessPurity,
  eventFreshness,
  MODEL_VERSION,
  THREAT_WEIGHTS,
} from "../../shared/scoring";

// All labels and events in this file are synthetic fixtures. They do not make
// claims about the real addresses used to exercise the public-IP input gate.
const AS_OF = "2026-10-28T12:00:00.000Z";
const dateAgo = (days: number) =>
  new Date(Date.parse(AS_OF) - days * 86_400_000).toISOString();
const source = (
  id = "synthetic-a",
  patch: Partial<SourceStatus> = {},
): SourceStatus => ({
  id,
  name: `Synthetic test source ${id}`,
  url: "https://example.invalid/test-fixture",
  license: "test-fixture-only",
  state: "ready",
  confidence: "high",
  upstreamFamilies: [id],
  families: [4, 6],
  categories: ["c2", "malware", "scanner", "network", "vpn", "proxy", "tor"],
  publishedAt: dateAgo(0.1),
  fetchedAt: dateAgo(0.1),
  expiresAt: dateAgo(-1),
  count: 100,
  negativeCoverageEligible: false,
  matched: false,
  ...patch,
});
const evidence = (id = "event-a", patch: Partial<Evidence> = {}): Evidence => ({
  id,
  sourceId: "synthetic-a",
  sourceName: "Synthetic test source",
  sourceUrl: "https://example.invalid/test-fixture",
  upstreamFamily: "synthetic-a",
  category: "c2",
  value: true,
  confidence: "high",
  description: {
    zh: "仅用于单元测试的虚构活动",
    en: "Synthetic unit-test fixture only",
  },
  observedAt: dateAgo(1),
  matchedRange: "8.8.8.8/32",
  ...patch,
});
const input = (patch: Partial<ScoringInput> = {}): ScoringInput => ({
  ip: "8.8.8.8",
  evidence: [],
  sources: [],
  networkType: "unknown",
  attributes: [],
  asOf: AS_OF,
  datasetVersion: "synthetic-fixture-v1",
  ...patch,
});
function withThreat(
  patch: Partial<Evidence> = {},
  sourcePatch: Partial<SourceStatus> = {},
) {
  return input({
    sources: [source("synthetic-a", { matched: true, ...sourcePatch })],
    evidence: [evidence("event-a", patch)],
  });
}

describe("zero-based score and traceability", () => {
  it("keeps a missing assessment distinct from a checked zero", () => {
    expect(assessRisk(input())).toMatchObject({
      riskScore: null,
      scoreKind: "insufficient",
      riskLevel: "insufficient",
      confidence: "insufficient",
      hasThreatEvidence: false,
    });
    expect(assessRisk(input()).summary.zh).toContain("不能把未检测显示为 0 分");
  });

  it("returns zero for completed unmatched feeds with limited confidence", () => {
    const result = assessRisk(
      input({ sources: [source(), source("synthetic-b")] }),
    );
    expect(result.riskScore).toBe(0);
    expect(result.confidence).toBe("low");
    expect(result.indicators.find((item) => item.id === "threat")?.state).toBe(
      "not_found",
    );
  });

  it("keeps every adjustment traceable to rule IDs and evidence IDs", () => {
    const result = assessRisk(withThreat());
    expect(result.modelVersion).toBe(MODEL_VERSION);
    expect(result.datasetVersion).toBe("synthetic-fixture-v1");
    expect(result.evaluatedAt).toBe(AS_OF);
    expect(
      result.scoreDetails.find((item) => item.ruleId === "threat-c2")
        ?.evidenceIds,
    ).toEqual(["event-a"]);
    expect(result.evidence[0].sourceUrl).toBe(
      "https://example.invalid/test-fixture",
    );
    expect(result.summary.zh).toContain("不是欺诈概率");
    expect(
      result.indicators.find((item) => item.id === "malicious"),
    ).toMatchObject({ state: "detected", evidenceIds: ["event-a"] });
  });

  it("rejects invalid and nonpublic inputs", () => {
    expect(() => assessRisk(input({ ip: "1.2.3" }))).toThrow("INVALID_IP");
    expect(() => assessRisk(input({ ip: "127.0.0.1" }))).toThrow(
      "NON_PUBLIC_IP",
    );
    expect(() => assessRisk(input({ asOf: "invalid" }))).toThrow(
      "INVALID_EVALUATION_TIME",
    );
  });

  it("is deterministic, order independent and does not mutate its input", () => {
    const sources = [
      source("synthetic-a", { matched: true }),
      source("synthetic-b", { matched: true }),
    ];
    const records = [
      evidence("event-a", { eventId: "activity-a" }),
      evidence("event-b", {
        sourceId: "synthetic-b",
        upstreamFamily: "synthetic-b",
        category: "malware",
        eventId: "activity-b",
        independentEvent: true,
      }),
    ];
    const original = input({ sources, evidence: records });
    const before = structuredClone(original);
    const a = assessRisk(original);
    expect(assessRisk(original)).toEqual(a);
    expect(
      assessRisk(
        input({
          sources: [...sources].reverse(),
          evidence: [...records].reverse(),
        }),
      ),
    ).toEqual(a);
    expect(original).toEqual(before);
    expect(JSON.stringify(a)).toContain(MODEL_VERSION);
  });
});

describe("public purity evidence gate", () => {
  const classified = (networkType: "hosting" | "residential" | "business", sources: SourceStatus[]) => assessRisk(input({
    networkType,
    evidence: [evidence("network", { category: "network", networkType })],
    sources: [source("synthetic-a", { categories: ["network"], matched: true }), ...sources],
  }));
  const threatSource = (id: string, patch: Partial<SourceStatus> = {}) => source(id, { categories: ["c2"], ...patch });

  it("reserves points without independent coverage", () => {
    const one = classified("residential", [threatSource("b")]);
    expect(one.riskScore).toBe(0);
    expect(assessPurity(one, 4)).toMatchObject({ score: 85, reservedPoints: 15, checked: 1, coverage: "limited" });
    const correlated = classified("residential", [threatSource("b"), threatSource("c", { upstreamFamilies: ["b"] })]);
    expect(assessPurity(correlated, 4)).toMatchObject({ score: 85, independentSources: 1 });
    expect(assessPurity(classified("residential", [threatSource("b"), threatSource("c")]), 4)).toMatchObject({ score: 100, coverage: "sufficient" });
  });

  it("withholds full marks when the two independent checks only provide narrow coverage", () => {
    const clear = [threatSource("b", { limitedCoverage: true }), threatSource("c", { limitedCoverage: true })];
    const residential = classified("residential", clear);
    expect(assessPurity(residential, 4)).toMatchObject({ score: 85, coverage: "limited", checked: 2, independentSources: 2, limit: "threat_coverage" });
    expect(assessPurity(residential, 4, true)).toMatchObject({ score: 75, reservedPoints: 25, status: "conflict" });
    expect(assessPurity(classified("business", clear), 4).score).toBe(85);
  });

  it("requires two completed broadly covered checks without a match for full marks", () => {
    const first = threatSource("b");
    for (const patch of [{ matched: true }, { matched: undefined }, { state: "stale" as const }, { families: [6 as const] }]) {
      const residential = classified("residential", [first, threatSource("c", patch)]);
      expect(assessPurity(residential, 4).score).toBe(85);
    }
  });

  it("keeps weak residential hints out of classification and lets verified prefixes override ASN labels", () => {
    const sources = [source("synthetic-a", { categories: ["network"], matched: true }), threatSource("b"), threatSource("c")];
    const residential = evidence("home", { category: "network", networkType: "residential", confidence: "low" });
    const weak = assessRisk(input({ networkType: "residential", evidence: [residential], sources }));
    expect(weak.networkType).toBe("unknown");
    expect(assessPurity(weak, 4)).toMatchObject({ score: 75, coverage: "sufficient", limit: "network" });

    const prefix = evidence("cloud", {
      sourceId: "cloud", upstreamFamily: "cloud", category: "network", networkType: "cloud",
      networkBasis: "prefix", matchedRange: "8.8.8.0/24",
    });
    const verified = assessRisk(input({
      evidence: [{ ...residential, confidence: "medium" }, prefix],
      sources: [...sources, source("cloud", { categories: ["network"], matched: true })],
    }));
    expect(verified.networkType).toBe("cloud");
    expect(assessPurity(verified, 4)).toMatchObject({ score: 80, status: "scored" });
  });

  it("retains verified deductions when evidence is incomplete or conflicting", () => {
    expect(assessPurity(classified("hosting", [threatSource("b", { limitedCoverage: true }), threatSource("c", { limitedCoverage: true })]), 4)).toMatchObject({ score: 75, coverage: "limited", checked: 2, independentSources: 2 });
    expect(assessPurity(classified("hosting", [threatSource("b", { expiresAt: AS_OF })]), 4)).toMatchObject({ score: 50, reservedPoints: 25, coverage: "none" });
    expect(assessPurity(classified("hosting", [threatSource("b", { families: [6] })]), 4).score).toBe(50);
    expect(assessPurity(classified("hosting", [threatSource("b")]), 4, true)).toMatchObject({ score: 75, reservedPoints: 0, status: "conflict" });
    expect(assessPurity(assessRisk(withThreat()), 4)).toMatchObject({ score: 10, reservedPoints: 0 });
    expect(assessPurity(assessRisk(input()), 4)).toMatchObject({ score: 50, reservedPoints: 50 });
  });
});

describe("threat rules and independent-event caps", () => {
  it.each(Object.entries(THREAT_WEIGHTS))(
    "applies the public %s policy weight",
    (category, weight) => {
      expect(
        assessRisk(withThreat({ category: category as Evidence["category"] }))
          .riskScore,
      ).toBe(weight);
    },
  );

  it("uses the lower of source and record confidence", () => {
    expect(
      assessRisk(withThreat({ confidence: "high" }, { confidence: "medium" }))
        .riskScore,
    ).toBe(63);
    expect(assessRisk(withThreat({ confidence: "low" })).riskScore).toBe(36);
  });

  it("discounts unknown event dates and never reuses a vendor score", () => {
    const first = assessRisk(
      withThreat(
        { observedAt: undefined, value: 95, confidence: "low" },
        { confidence: "low" },
      ),
    );
    const second = assessRisk(
      withThreat(
        { observedAt: undefined, value: 100, confidence: "low" },
        { confidence: "low" },
      ),
    );
    expect(first.riskScore).toBe(18);
    expect(second.riskScore).toBe(18);
    expect(first.confidence).toBe("low");
    expect(
      first.scoreDetails.find((item) => item.ruleId === "threat-c2")
        ?.explanation.zh,
    ).toContain("不能证明近期活动");
  });

  it("does not add related categories, duplicates, or multiple feed mirrors", () => {
    const records = [
      evidence("c2"),
      evidence("botnet", { category: "botnet" }),
      evidence("malware", { category: "malware" }),
      evidence("repeat"),
    ];
    expect(
      assessRisk(
        input({
          sources: [source("synthetic-a", { matched: true })],
          evidence: records,
        }),
      ).riskScore,
    ).toBe(90);
  });

  it("requires an activity ID on the primary to admit an independent supplement", () => {
    const records = [
      evidence("a"),
      evidence("b", {
        sourceId: "synthetic-b",
        upstreamFamily: "synthetic-b",
        category: "malware",
        eventId: "b",
        independentEvent: true,
      }),
    ];
    expect(
      assessRisk(
        input({
          sources: [
            source("synthetic-a", { matched: true }),
            source("synthetic-b", { matched: true }),
          ],
          evidence: records,
        }),
      ).riskScore,
    ).toBe(90);
  });

  it("allows one explicitly independent supplementary activity, capped at 95", () => {
    const records = [
      evidence("a", { eventId: "activity-a" }),
      evidence("b", {
        sourceId: "synthetic-b",
        upstreamFamily: "synthetic-b",
        category: "malware",
        eventId: "activity-b",
        independentEvent: true,
      }),
    ];
    const result = assessRisk(
      input({
        sources: [
          source("synthetic-a", { matched: true }),
          source("synthetic-b", { matched: true }),
        ],
        evidence: records,
      }),
    );
    expect(result.riskScore).toBe(95);
    expect(
      result.scoreDetails
        .filter((item) => item.ruleId.startsWith("threat-"))
        .reduce((sum, item) => sum + item.amount, 0),
    ).toBe(95);
  });

  it("does not award independent activity or high confidence for shared provenance", () => {
    const records = [
      evidence("a", { eventId: "activity-a", upstreamFamily: "shared" }),
      evidence("b", {
        sourceId: "synthetic-b",
        upstreamFamily: "shared",
        category: "malware",
        eventId: "activity-b",
        independentEvent: true,
      }),
    ];
    const sources = [
      source("synthetic-a", { matched: true, upstreamFamilies: ["shared"] }),
      source("synthetic-b", { matched: true, upstreamFamilies: ["shared"] }),
    ];
    const result = assessRisk(input({ sources, evidence: records }));
    expect(result.riskScore).toBe(90);
    expect(result.confidence).toBe("medium");
    expect(result.coverage.independentSources).toBe(1);
  });

  it("does not award an independent supplement through transitive aggregator provenance", () => {
    const sources = [
      source("a", { matched: true, upstreamFamilies: ["x"] }),
      source("b", { matched: true, upstreamFamilies: ["y"] }),
      source("c", { matched: true, upstreamFamilies: ["x", "y"] }),
    ];
    const records = [
      evidence("a", { sourceId: "a", upstreamFamily: "x", eventId: "primary" }),
      evidence("b", {
        sourceId: "b",
        upstreamFamily: "y",
        category: "malware",
        eventId: "secondary",
        independentEvent: true,
      }),
      evidence("c", {
        sourceId: "c",
        upstreamFamily: "x",
        category: "scanner",
        eventId: "mirror",
        independentEvent: true,
      }),
    ];
    const result = assessRisk(input({ sources, evidence: records }));
    expect(result.riskScore).toBe(90);
    expect(result.confidence).toBe("medium");
    expect(result.coverage.independentSources).toBe(1);
  });

  it("raises confidence from independent confirmation without increasing severity", () => {
    const records = [
      evidence("a"),
      evidence("b", { sourceId: "synthetic-b", upstreamFamily: "synthetic-b" }),
    ];
    const result = assessRisk(
      input({
        sources: [
          source("synthetic-a", { matched: true }),
          source("synthetic-b", { matched: true }),
        ],
        evidence: records,
      }),
    );
    expect(result.riskScore).toBe(90);
    expect(result.confidence).toBe("high");
  });

  it("does not let an additional weak undated record downgrade a strong direct observation", () => {
    const records = [
      evidence("a"),
      evidence("b", {
        sourceId: "synthetic-b",
        upstreamFamily: "synthetic-b",
        confidence: "low",
        observedAt: undefined,
      }),
    ];
    const result = assessRisk(
      input({
        sources: [
          source("synthetic-a", { matched: true }),
          source("synthetic-b", { matched: true, confidence: "low" }),
        ],
        evidence: records,
      }),
    );
    expect(result.riskScore).toBe(90);
    expect(result.confidence).toBe("medium");
  });
});

describe("time, applicability and source failure", () => {
  it.each([
    [0, 1],
    [7, 1],
    [8, 0.75],
    [30, 0.75],
    [31, 0.4],
    [90, 0.4],
    [91, 0],
  ])("uses event age %s days with multiplier %s", (age, multiplier) => {
    expect(eventFreshness(dateAgo(age), AS_OF)).toBe(multiplier);
  });

  it("never treats publication/download time as activity time", () => {
    const result = assessRisk(
      withThreat({
        observedAt: undefined,
        publishedAt: dateAgo(0.01),
        fetchedAt: dateAgo(0),
      }),
    );
    expect(result.riskScore).toBe(45);
    expect(result.confidence).toBe("low");
  });

  it("uses explicit UTC/date-only timestamps and rejects ambiguous or impossible dates", () => {
    expect(eventFreshness("2026-10-28", AS_OF)).toBe(1);
    expect(eventFreshness("2026-10-28T20:00:00+08:00", AS_OF)).toBe(1);
    for (const date of [
      "10/28/2026",
      "2026-10-28T12:00:00",
      "2026-10-28 12:00:00",
      "2026-02-31T00:00:00Z",
      "2025-02-29T00:00:00Z",
      "2026-10-27T24:00:00Z",
    ]) {
      expect(eventFreshness(date, AS_OF)).toBe(0);
      expect(assessRisk(withThreat({ observedAt: date })).riskScore).toBe(null);
    }
  });

  it("excludes expired events while preserving a stale indicator", () => {
    const result = assessRisk(withThreat({ observedAt: dateAgo(91) }));
    expect(result).toMatchObject({
      riskScore: null,
      scoreKind: "insufficient",
      hasThreatEvidence: false,
    });
    expect(result.indicators.find((item) => item.id === "threat")?.state).toBe(
      "stale",
    );
  });

  it.each([
    { state: "unavailable" as const },
    { state: "unconfigured" as const },
    { state: "stale" as const },
    { families: [6] as [6] },
    { expiresAt: dateAgo(1) },
    { expiresAt: "bad" },
    { publishedAt: "bad" },
    { fetchedAt: dateAgo(-1) },
    { license: "" },
    { upstreamFamilies: [] },
  ])("excludes unusable source %j", (patch) => {
    const result = assessRisk(withThreat({}, patch));
    expect(result.riskScore).toBe(null);
    expect(result.hasThreatEvidence).toBe(false);
    expect(result.coverage.checked).toBe(0);
  });

  it.each([
    { observedAt: "bad" },
    { observedAt: dateAgo(-1) },
    { publishedAt: "bad" },
    { fetchedAt: dateAgo(-1) },
    { expiresAt: dateAgo(0) },
    { expiresAt: "bad" },
    { stale: true },
    { upstreamFamily: "unrelated" },
    { sourceId: "missing" },
    { matchedRange: "1.1.1.0/24" },
    { matchedRange: "garbage" },
    { value: false },
    { value: "" },
  ])("excludes invalid, out-of-range or negative evidence %j", (patch) => {
    const result = assessRisk(withThreat(patch));
    expect(result.riskScore).toBe(null);
    expect(result.hasThreatEvidence).toBe(false);
  });

  it("supports real IPv6 analysis without coercing it to IPv4", () => {
    const result = assessRisk(
      input({
        ip: "2001:4860:4860:0000:0000:0000:0000:8888",
        sources: [source("synthetic-a", { families: [6], matched: true })],
        evidence: [evidence("v6", { matchedRange: "2001:4860:4860::/48" })],
      }),
    );
    expect(result.ip).toBe("2001:4860:4860::8888");
    expect(result.riskScore).toBe(90);
  });

  it("downgrades confidence for contradictions between hit records and source status", () => {
    expect(assessRisk(withThreat({}, { matched: false })).confidence).toBe(
      "low",
    );
  });

  it("reports ASN agreement only with multiple valid comparable sources", () => {
    const result = assessRisk(
      input({
        sources: [
          source("a", { categories: ["asn"], matched: true }),
          source("b", { categories: ["asn"], matched: true }),
        ],
        evidence: [
          evidence("a", {
            sourceId: "a",
            upstreamFamily: "a",
            category: "asn",
            value: 64512,
          }),
          evidence("b", {
            sourceId: "b",
            upstreamFamily: "b",
            category: "asn",
            value: 64512,
          }),
        ],
      }),
    );
    expect(
      result.indicators.find((item) => item.id === "ownership_consistency"),
    ).toMatchObject({ state: "detected", evidenceIds: ["a", "b"] });
    expect(result.riskScore).toBe(null);
    expect(result.hasThreatEvidence).toBe(false);
  });

  it("marks ASN disagreement and lowers confidence without adding malicious risk", () => {
    const result = assessRisk(
      input({
        sources: [
          source("synthetic-a", { matched: true }),
          source("b", { matched: true }),
        ],
        evidence: [
          evidence("threat"),
          evidence("asn-a", { category: "asn", value: 64512 }),
          evidence("asn-b", {
            sourceId: "b",
            upstreamFamily: "b",
            category: "asn",
            value: 64513,
          }),
        ],
      }),
    );
    expect(
      result.indicators.find((item) => item.id === "ownership_consistency")
        ?.state,
    ).toBe("conflict");
    expect(result.riskScore).toBe(90);
    expect(result.confidence).toBe("low");
  });

  it("does not claim agreement by duplicating one ASN source or using expired evidence", () => {
    const result = assessRisk(
      input({
        sources: [
          source("synthetic-a", { matched: true }),
          source("b", { categories: ["asn"], state: "stale" }),
        ],
        evidence: [
          evidence("asn-a", { category: "asn", value: 64512 }),
          evidence("asn-a-duplicate", { category: "asn", value: 64512 }),
          evidence("asn-b", {
            sourceId: "b",
            upstreamFamily: "b",
            category: "asn",
            value: 64513,
          }),
        ],
      }),
    );
    expect(
      result.indicators.find((item) => item.id === "ownership_consistency")
        ?.state,
    ).toBe("unknown");
  });
});

describe("network context is not malicious activity", () => {
  const network = (id: string, patch: Partial<Evidence>): Evidence =>
    evidence(id, { category: "network", observedAt: undefined, ...patch });

  it("does not invent evidence from an input type or attribute", () => {
    const result = assessRisk(
      input({
        networkType: "hosting",
        attributes: ["vpn", "proxy", "tor", "residential_proxy"],
      }),
    );
    expect(result.riskScore).toBe(null);
    expect(result.scoreKind).toBe("insufficient");
    expect(result.hasThreatEvidence).toBe(false);
  });

  it("caps all contextual adjustments at forty and leaves confidence low", () => {
    const result = assessRisk(
      input({
        sources: [source("synthetic-a", { matched: true })],
        networkType: "cloud",
        attributes: ["vpn", "proxy", "tor"],
        evidence: [
          network("dc", { networkType: "cloud" }),
          network("vpn", { attribute: "vpn" }),
          network("proxy", { attribute: "proxy" }),
          network("tor", { attribute: "tor" }),
        ],
      }),
    );
    expect(result).toMatchObject({
      riskScore: 40,
      hasThreatEvidence: false,
      confidence: "low",
      riskLevel: "moderate",
    });
    expect(
      result.scoreDetails.find(
        (item) => item.ruleId.startsWith("network-context-"),
      )?.explanation.zh,
    ).toContain("不表示恶意活动");
  });

  it("deduplicates related proxy types and cloud/hosting membership", () => {
    const result = assessRisk(
      input({
        sources: [source("synthetic-a", { matched: true })],
        evidence: [
          network("proxy", { attribute: "proxy" }),
          network("public", { attribute: "public_proxy" }),
          network("res", { attribute: "residential_proxy" }),
          network("cloud", { networkType: "cloud" }),
          network("hosting", { networkType: "hosting" }),
        ],
      }),
    );
    expect(result.riskScore).toBe(40); // Related labels use maxima, then the shared context cap.
    expect(result.scoreDetails.filter(d => d.ruleId.startsWith("network-context-"))).toMatchObject([
      { ruleId: "network-context-proxy", amount: 35 },
      { ruleId: "network-context-hosting", amount: 5 },
    ]);
  });

  it.each([
    ["hosting", 25], ["cloud", 20], ["vpn", 15], ["tor", 25], ["public_proxy", 25], ["residential_proxy", 35],
  ] as const)("adds an explicit bounded contribution for %s", (type, expected) => {
    const e = network("context", type === "hosting" || type === "cloud" ? { networkType: type } : { attribute: type });
    const result = assessRisk(input({ sources: [source("synthetic-a", { matched: true })], evidence: [e] }));
    expect(result.riskScore).toBe(expected);
    expect(result.hasThreatEvidence).toBe(false);
    expect(result.riskLevel).not.toBe("high");
    expect(result.scoreDetails.at(-1)?.evidenceIds).toEqual(["context"]);
  });

  it("shows ASN sample evidence without labelling an individual IP or increasing its score", () => {
    const result = assessRisk(input({ sources: [source("synthetic-a", { matched: true, categories: ["asn_reputation"] })], evidence: [network("asn-sample", { category: "asn_reputation", value: 64512 })] }));
    expect(result.indicators.find(i => i.id === "asn_risk")?.state).toBe("detected");
    expect(result.hasThreatEvidence).toBe(false);
    expect(result.attributes).toEqual([]);
    expect(result.riskScore).toBe(null);
  });

  it("never penalizes relay or residential membership and suppresses underlying hosting", () => {
    const result = assessRisk(
      input({
        sources: [source("synthetic-a", { matched: true })],
        networkType: "hosting",
        attributes: ["relay"],
        evidence: [
          network("relay", { attribute: "relay" }),
          network("hosting", { networkType: "hosting" }),
          network("home", { networkType: "residential" }),
        ],
      }),
    );
    expect(result.riskScore).toBe(0);
    expect(result.scoreKind).toBe("evidence");
    expect(result.hasThreatEvidence).toBe(false);
    expect(
      result.indicators.find((item) => item.id === "residential_proxy")?.state,
    ).toBe("unknown");
  });

  it("does not interpret an ASN category/name as ASN-wide abuse", () => {
    const result = assessRisk(
      input({
        sources: [
          source("synthetic-a", { categories: ["asn"], matched: true }),
        ],
        evidence: [network("asn", { category: "asn", value: "hosting ASN" })],
      }),
    );
    expect(result.riskScore).toBe(null);
    expect(result.hasThreatEvidence).toBe(false);
    expect(
      result.indicators.find((item) => item.id === "asn_risk")?.state,
    ).toBe("unknown");
  });
});

describe("zero model ignores legacy negative-coverage flags", () => {
  it("never discounts unmatched datasets by default", () => {
    const result = assessRisk(
      input({
        sources: [source(), source("synthetic-b"), source("synthetic-c")],
      }),
    );
    expect(result.riskScore).toBe(0);
    expect(result.scoreDetails).toHaveLength(1);
  });

  it("never subtracts points even if old metadata opts into deductions", () => {
    const result = assessRisk(
      input({
        sources: [
          source("a", { negativeCoverageEligible: true }),
          source("b", { negativeCoverageEligible: true }),
          source("c", { negativeCoverageEligible: true }),
        ],
      }),
    );
    expect(result.riskScore).toBe(0);
    expect(result.confidence).toBe("low");
    expect(result.riskLevel).toBe("minimal");
  });

  it.each([
    { patch: { publishedAt: undefined }, expected: 0 },
    { patch: { publishedAt: dateAgo(2) }, expected: 0 },
    { patch: { expiresAt: undefined }, expected: 0 },
    { patch: { matched: undefined }, expected: null },
    { patch: { count: 0 }, expected: null },
    { patch: { families: [6] as [6] }, expected: null },
    { patch: { categories: ["vpn"] }, expected: 0 },
  ])("distinguishes valid checks from incomplete coverage without deductions %j", ({patch, expected}) => {
    const result = assessRisk(input({
      sources: [source("a", { negativeCoverageEligible: true, ...patch })],
    }));
    expect(result.riskScore).toBe(expected);
    expect(result.scoreDetails.every(item => item.amount >= 0)).toBe(true);
  });

  it("never offsets a positive threat with another source's absence", () => {
    const result = assessRisk(
      input({
        sources: [
          source("synthetic-a", { matched: true, confidence: "low" }),
          source("b", { negativeCoverageEligible: true }),
          source("c", { negativeCoverageEligible: true }),
        ],
        evidence: [
          evidence("undated", { observedAt: undefined, confidence: "low" }),
        ],
      }),
    );
    expect(result.riskScore).toBe(18);
    expect(
      result.scoreDetails.some(
        (item) => item.ruleId === "explicit-negative-coverage",
      ),
    ).toBe(false);
  });

  it("does not use the absence of a rejected old hit as clean evidence", () => {
    const result = assessRisk(
      input({
        sources: [source("synthetic-a", { negativeCoverageEligible: true })],
        evidence: [evidence("expired", { observedAt: dateAgo(100) })],
      }),
    );
    expect(result.riskScore).toBe(null);
  });

  it("groups transitively shared upstreams, not just different URLs", () => {
    const result = assessRisk(
      input({
        sources: [
          source("a", {
            upstreamFamilies: ["x"],
            negativeCoverageEligible: true,
          }),
          source("b", {
            upstreamFamilies: ["y"],
            negativeCoverageEligible: true,
          }),
          source("c", {
            upstreamFamilies: ["x", "y"],
            negativeCoverageEligible: true,
          }),
        ],
      }),
    );
    expect(result.riskScore).toBe(0);
    expect(result.coverage.independentSources).toBe(1);
  });
});

describe("coverage diagnostics and cumulative boundaries", () => {
  it.each([
    { sources: [], reason: "no_source" },
    { sources: [source("synthetic-a", { families: [6] })], reason: "unsupported_family" },
    { sources: [source("synthetic-a", { state: "unavailable" })], reason: "source_unavailable" },
    { sources: [source("synthetic-a", { state: "stale" })], reason: "source_stale" },
    { sources: [source("synthetic-a", { matched: undefined })], reason: "not_queried" },
    { sources: [source()], reason: "no_match" },
  ])("explains $reason without a false negative", ({ sources, reason }) => {
    const result = assessRisk(input({ sources }));
    expect(result.indicators.find(i => i.id === "threat")?.reason).toBe(reason);
    expect(result.riskScore).toBe(reason === "no_match" ? 0 : null);
  });

  it("does not turn invalid positive evidence into a no-match indicator", () => {
    const result = assessRisk(withThreat({ matchedRange: "1.1.1.1/32" }));
    expect(result.riskScore).toBe(null);
    expect(result.indicators.find(i => i.id === "threat")).toMatchObject({state: "unknown", reason: "insufficient_evidence"});
  });

  it("keeps a generic proxy observation separate from public and residential subtypes", () => {
    const result = assessRisk(input({
      sources: [source("synthetic-a", { categories: ["proxy"], matched: true })],
      evidence: [evidence("generic-proxy", { category: "proxy", attribute: "proxy" })],
    }));
    expect(result.riskScore).toBe(25);
    expect(result.indicators.find(i => i.id === "proxy")?.state).toBe("detected");
    for (const id of ["public_proxy", "web_proxy", "residential_proxy"])
      expect(result.indicators.find(i => i.id === id)).toMatchObject({state: "unknown", reason: "no_source"});
  });

  it("caps a combined threat and multiple network signals at 100 with additive traceability", () => {
    const result = assessRisk(input({
      sources: [source("synthetic-a", { matched: true }), source("b", { matched: true })],
      evidence: [
        evidence("c2", {eventId: "c2-event"}),
        evidence("malware", {sourceId: "b", upstreamFamily: "b", category: "malware", eventId: "malware-event", independentEvent: true}),
        evidence("hosting", {category: "network", networkType: "hosting"}),
        evidence("proxy", {category: "proxy", attribute: "public_proxy"}),
      ],
    }));
    expect(result.riskScore).toBe(100);
    expect(result.riskLevel).toBe("high");
    expect(result.scoreDetails.reduce((sum, item) => sum + item.amount, 0)).toBe(100);
    expect(result.scoreDetails.filter(item => item.amount > 0).every(item => item.evidenceIds.length > 0)).toBe(true);
  });

  it.each([
    ["spam", 20, "low"], ["web_attack", 50, "moderate"], ["phishing", 75, "elevated"], ["c2", 90, "high"],
  ] as const)("labels %s according to cumulative bands", (category, points, level) => {
    expect(assessRisk(withThreat({category}))).toMatchObject({riskScore: points, riskLevel: level});
  });
});
