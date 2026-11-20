import type {
  Confidence,
  Evidence,
  Indicator,
  LocalizedText,
  NetworkAttribute,
  PurityAssessment,
  PurityLimit,
  RiskAssessment,
  ScoreAdjustment,
  ScoringInput,
  SignalCategory,
  SourceStatus,
} from "./contracts.ts";
import { containsIp, requirePublicIp, type ParsedIp } from "./ip.ts";
import { PURITY_MODEL_VERSION, purityTier, scoreWithLimit } from "./purity-scale.ts";

export const MODEL_VERSION = "ruijing-evidence-2.3.0";
const DAY = 86_400_000;
const text = (zh: string, en: string): LocalizedText => ({ zh, en });

/** Policy weights are ordinal heuristics, never estimated fraud probabilities. */
export const THREAT_WEIGHTS: Readonly<Partial<Record<SignalCategory, number>>> =
  Object.freeze({
    c2: 90,
    botnet: 90,
    malware: 85,
    phishing: 75,
    brute_force: 55,
    web_attack: 50,
    scanner: 25,
    spam: 20,
    other_abuse: 25,
  });
const QUALITY = { high: 1, medium: 0.7, low: 0.4 } as const;
const CONTEXT: Readonly<
  Partial<Record<NetworkAttribute | "hosting" | "cloud", number>>
> = Object.freeze({
  hosting: 25,
  cloud: 20,
  vpn: 15,
  proxy: 25,
  public_proxy: 25,
  web_proxy: 25,
  tor: 25,
  residential_proxy: 35,
});
const THREAT_NAMES: Readonly<Partial<Record<SignalCategory, LocalizedText>>> = {
  c2: text("命令与控制", "Command and control"),
  botnet: text("僵尸网络", "Botnet"),
  malware: text("恶意软件", "Malware"),
  phishing: text("钓鱼", "Phishing"),
  brute_force: text("暴力破解", "Brute force"),
  web_attack: text("Web 攻击", "Web attack"),
  scanner: text("扫描活动", "Scanning"),
  spam: text("垃圾信息", "Spam"),
  other_abuse: text("其他已记录滥用", "Other recorded abuse"),
};

function timestamp(value: string | undefined): number | null {
  if (value === undefined) return null;
  // Offset-less local times and locale date formats vary across runtimes.
  // Keep date-only UTC observations, or ISO timestamps with explicit offset.
  const match =
    /^(\d{4})-(\d{2})-(\d{2})(?:T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d))?$/.exec(
      value,
    );
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1]) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function isThreat(evidence: Evidence): boolean {
  return THREAT_WEIGHTS[evidence.category] !== undefined;
}

function isPositive(evidence: Evidence): boolean {
  // API matches are positive observations. An explicit false or empty field is
  // never converted into an abuse hit; negative coverage lives on SourceStatus.
  return evidence.value !== false && evidence.value !== "";
}

function sourceMetadataUsable(
  source: SourceStatus,
  family: 4 | 6,
  now: number,
): boolean {
  if ((source.state !== "ready" && source.state !== "stale") || !source.families.includes(family))
    return false;
  if (!source.license.trim() || !source.upstreamFamilies.length) return false;
  for (const field of [source.publishedAt, source.fetchedAt]) {
    if (field !== undefined) {
      const value = timestamp(field);
      if (value === null || value > now) return false;
    }
  }
  if (source.expiresAt !== undefined) {
    const expiry = timestamp(source.expiresAt);
    if (expiry === null) return false;
  }
  return true;
}

function sourceUsable(source: SourceStatus, family: 4 | 6, now: number): boolean {
  return source.state === "ready" && sourceMetadataUsable(source, family, now) &&
    (source.expiresAt === undefined || timestamp(source.expiresAt)! > now);
}

type Eligibility = "valid" | "stale" | "invalid";
function evidenceEligibility(
  evidence: Evidence,
  source: SourceStatus | undefined,
  ip: ParsedIp,
  now: number,
): Eligibility {
  if (!source || !sourceMetadataUsable(source, ip.family, now) || !isPositive(evidence))
    return "invalid";
  if (!source.upstreamFamilies.includes(evidence.upstreamFamily))
    return "invalid";
  if (evidence.matchedRange && !containsIp(evidence.matchedRange, ip))
    return "invalid";
  for (const field of [
    evidence.publishedAt,
    evidence.fetchedAt,
    evidence.observedAt,
  ]) {
    if (field !== undefined) {
      const value = timestamp(field);
      if (value === null || value > now) return "invalid";
    }
  }
  if (evidence.expiresAt !== undefined) {
    const expiry = timestamp(evidence.expiresAt);
    if (expiry === null) return "invalid";
    if (expiry <= now) return "stale";
  }
  if (evidence.stale || !sourceUsable(source, ip.family, now)) return "stale";
  if (
    isThreat(evidence) &&
    evidence.observedAt !== undefined &&
    now - timestamp(evidence.observedAt)! > 90 * DAY
  )
    return "stale";
  return "valid";
}

export function eventFreshness(
  observedAt: string | undefined,
  asOf: string,
): number {
  const now = timestamp(asOf);
  if (now === null) throw new Error("INVALID_EVALUATION_TIME");
  if (observedAt === undefined) return 0.5;
  const observed = timestamp(observedAt);
  if (observed === null || observed > now) return 0;
  const days = (now - observed) / DAY;
  return days <= 7 ? 1 : days <= 30 ? 0.75 : days <= 90 ? 0.4 : 0;
}

/** Group connected provenance sets conservatively, rather than feed URLs. */
function sourceComponents(sources: readonly SourceStatus[]): SourceStatus[][] {
  const remaining = [...sources].sort((a, b) => a.id.localeCompare(b.id));
  const components: SourceStatus[][] = [];
  while (remaining.length) {
    const source = remaining.shift()!;
    if (!source.upstreamFamilies.length) continue;
    const members = [source];
    components.push(members);
    const component = new Set(source.upstreamFamilies);
    // A{x}, B{y}, C{x,y} form one correlated component, even if the
    // aggregator C sorts last. A simple greedy counter would overcount it.
    let expanded = true;
    while (expanded) {
      expanded = false;
      for (let index = remaining.length - 1; index >= 0; index--) {
        const candidate = remaining[index];
        if (!candidate.upstreamFamilies.some((family) => component.has(family)))
          continue;
        for (const family of candidate.upstreamFamilies) component.add(family);
        members.push(candidate);
        remaining.splice(index, 1);
        expanded = true;
      }
    }
  }
  return components;
}

function independentSources(sources: readonly SourceStatus[]): SourceStatus[] {
  return sourceComponents(sources).map((members) => members[0]);
}

/** Select network use based on eligible evidence, with explicit prefix assertions
 * taking precedence over whole-AS classifications. Low-confidence labels stay in the evidence. */
function classifyNetwork(evidence: Evidence[]) {
  const candidates = evidence.filter(item => item.category === "network" &&
    item.networkType && item.networkType !== "unknown" && item.confidence !== "low");
  const prefixes = candidates.filter(item => item.networkBasis === "prefix" && item.matchedRange);
  const specificity = (item: Evidence) => Number(item.matchedRange!.split("/")[1]);
  const longest = Math.max(...prefixes.map(specificity));
  const preferred = prefixes.length ? prefixes.filter(item => specificity(item) === longest) : candidates;
  const types = new Set(preferred.map(item => item.networkType!));
  const hosting = types.has("hosting") || types.has("cloud");
  const conflict = types.size > (types.has("hosting") && types.has("cloud") ? 2 : 1);
  return {
    conflict,
    type: conflict ? "unknown" as const
      : hosting ? (types.has("hosting") ? "hosting" as const : "cloud" as const)
        : types.values().next().value ?? "unknown" as const,
  };
}

export function assessPurity(
  assessment: RiskAssessment,
  family: 4 | 6,
  provenanceConflict = false,
): PurityAssessment {
  const now = Date.parse(assessment.evaluatedAt);
  const address = requirePublicIp(assessment.ip);
  const checks = assessment.sources.filter(source =>
    sourceUsable(source, family, now) && source.count > 0 &&
    source.matched !== undefined && source.expiresAt &&
    source.categories.some(category =>
      THREAT_WEIGHTS[category as SignalCategory] !== undefined &&
      !source.positiveOnlyCategories?.includes(category)),
  );
  const independent = independentSources(checks).length;
  const network = classifyNetwork(assessment.evidence.filter(evidence => {
    if (evidence.category !== "network") return false;
    const source = assessment.sources.find(source => source.id === evidence.sourceId && source.matched === true);
    return evidenceEligibility(evidence, source, address, now) === "valid";
  }));
  const conflict = provenanceConflict || network.conflict || assessment.indicators.some(indicator => indicator.state === "conflict");
  const risk = assessment.riskScore;
  const broadlyCovered = independentSources(checks.filter(source => !source.limitedCoverage)).length;
  const coverage = broadlyCovered >= 2 ? "sufficient" : independent > 0 ? "limited" : "none";
  const fullScoreSupported = independentSources(checks.filter(source => !source.limitedCoverage && source.matched === false)).length >= 2;
  const limit: PurityLimit | undefined = !independent && !assessment.hasThreatEvidence ? "no_threat_checks"
    : conflict ? "network_conflict"
    : network.type === "unknown" ? "network"
    : !fullScoreSupported ? "threat_coverage" : undefined;
  const score = scoreWithLimit(risk, limit, assessment.historicalRiskPoints);
  return {
    modelVersion: PURITY_MODEL_VERSION,
    coverage,
    ...score,
    status: conflict ? "conflict" : score.reservedPoints > 0 ? "insufficient" : "scored",
    ...(limit ? { limit } : {}),
    checked: checks.length,
    independentSources: independent,
  };
}

interface WeightedThreat {
  evidence: Evidence;
  weight: number;
  freshness: number;
  quality: number;
}
function orderedThreats(threats: WeightedThreat[]): WeightedThreat[] {
  return [...threats].sort(
    (a, b) => b.weight - a.weight || a.evidence.id.localeCompare(b.evidence.id),
  );
}

/** Use the strongest exact historical hit that does not duplicate current activity. */
function historicalThreat(
  evidence: Evidence[],
  eligibility: Map<string, Eligibility>,
  sourceById: Map<string, SourceStatus>,
  threats: WeightedThreat[],
  address: ParsedIp,
  now: number,
) {
  const exactRange = `${address.canonical}/${address.family === 4 ? 32 : 128}`;
  const candidates: WeightedThreat[] = [];
  for (const item of evidence) {
    if (eligibility.get(item.id) !== "stale" || !isThreat(item) || item.matchedRange !== exactRange) continue;
    const source = sourceById.get(item.sourceId)!;
    if (source.matched !== true || source.count <= 0 || !source.categories.includes(item.category)) continue;
    if (threats.some(({ evidence: current }) => current.category === item.category ||
      (item.eventId && current.eventId === item.eventId) ||
      sourceById.get(current.sourceId)!.upstreamFamilies.some(family => source.upstreamFamilies.includes(family)))) continue;
    const anchor = timestamp(item.observedAt ?? item.publishedAt ?? source.publishedAt);
    if (anchor === null) continue;
    const age = (now - anchor) / DAY;
    const decay = age <= 30 ? 0.25 : age <= 90 ? 0.15 : age <= 365 ? 0.08 : 0.04;
    const freshness = decay * (item.observedAt ? 1 : 0.5);
    const quality = Math.min(QUALITY[item.confidence], QUALITY[source.confidence]);
    candidates.push({ evidence: item, freshness, quality, weight: THREAT_WEIGHTS[item.category]! * quality * freshness });
  }
  return orderedThreats(candidates)[0];
}

function chooseThreats(
  threats: WeightedThreat[],
  sourceById: Map<string, SourceStatus>,
): WeightedThreat[] {
  const ordered = orderedThreats(threats);
  if (!ordered.length) return [];
  const primary = ordered[0];
  const selected = [primary];
  // Supplementary contributions require explicit distinct activity identifiers
  // and declared independence; a second category/name alone proves nothing.
  if (!primary.evidence.eventId) return selected;
  const usedEvents = new Set([primary.evidence.eventId]);
  const usedCategories = new Set([primary.evidence.category]);
  const contributingSources = [
    ...new Map(
      ordered.map((item) => [
        item.evidence.sourceId,
        sourceById.get(item.evidence.sourceId)!,
      ]),
    ).values(),
  ];
  const componentIds = new Map(
    sourceComponents(contributingSources).flatMap((members, index) =>
      members.map((source) => [source.id, index] as const),
    ),
  );
  const usedComponents = new Set([componentIds.get(primary.evidence.sourceId)]);
  for (const candidate of ordered.slice(1)) {
    const evidence = candidate.evidence;
    if (
      !evidence.independentEvent ||
      !evidence.eventId ||
      usedEvents.has(evidence.eventId) ||
      usedCategories.has(evidence.category)
    )
      continue;
    // Use the same transitive provenance grouping as confidence and coverage:
    // an aggregator hit linking two source families cannot supply a bonus.
    const component = componentIds.get(evidence.sourceId);
    if (usedComponents.has(component)) continue;
    selected.push(candidate);
    usedEvents.add(evidence.eventId);
    usedCategories.add(evidence.category);
    usedComponents.add(component);
    break; // Only the strongest independent supplement contributes, at 25%.
  }
  return selected;
}

const indicatorDefinitions: Array<{
  id: string;
  label: LocalizedText;
  categories?: SignalCategory[];
  attributes?: NetworkAttribute[];
  network?: boolean;
}> = [
  {
    id: "datacenter",
    label: text("数据中心 / 云网络", "Datacenter / cloud network"),
    network: true,
  },
  {
    id: "vpn",
    label: text("已知 VPN", "Known VPN"),
    attributes: ["vpn"],
    categories: ["vpn"],
  },
  {
    id: "tor",
    label: text("Tor 出口", "Tor exit"),
    attributes: ["tor"],
    categories: ["tor"],
  },
  {
    id: "proxy",
    label: text("代理服务线索", "Proxy service evidence"),
    attributes: ["proxy", "public_proxy", "web_proxy", "residential_proxy"],
    categories: ["proxy", "residential_proxy"],
  },
  {
    id: "public_proxy",
    label: text("公共代理", "Public proxy"),
    attributes: ["public_proxy"],
  },
  {
    id: "web_proxy",
    label: text("Web 代理", "Web proxy"),
    attributes: ["web_proxy"],
  },
  {
    id: "residential_proxy",
    label: text("住宅代理", "Residential proxy"),
    attributes: ["residential_proxy"],
    categories: ["residential_proxy"],
  },
  {
    id: "crawler",
    label: text("搜索引擎爬虫网络", "Search crawler network"),
    attributes: ["crawler"],
  },
  {
    id: "malicious",
    label: text("已知恶意 IP 情报", "Known malicious IP intelligence"),
    categories: Object.keys(THREAT_WEIGHTS) as SignalCategory[],
  },
  {
    id: "threat",
    label: text("威胁情报", "Threat intelligence"),
    categories: Object.keys(THREAT_WEIGHTS) as SignalCategory[],
  },
  {
    id: "asn_risk",
    label: text("ASN 风险证据", "ASN abuse evidence"),
    categories: ["asn_reputation"],
  },
  {
    id: "ownership_consistency",
    label: text("网络归属一致性", "Network ownership consistency"),
  },
];

function indicatorMatches(
  definition: (typeof indicatorDefinitions)[number],
  evidence: Evidence,
): boolean {
  if (definition.network)
    return (
      evidence.category === "network" &&
      (evidence.networkType === "hosting" || evidence.networkType === "cloud")
    );
  if (definition.id === "asn_risk") return evidence.category === "asn_reputation";
  return (
    !!definition.categories?.includes(evidence.category) ||
    !!(
      evidence.attribute && definition.attributes?.includes(evidence.attribute)
    )
  );
}

function sourceCoversIndicator(
  definition: (typeof indicatorDefinitions)[number],
  source: SourceStatus,
): boolean {
  // ASN membership alone is not an ASN reputation observation.
  if (definition.id === "asn_risk") return source.categories.includes("asn_reputation");
  if (definition.id === "ownership_consistency")
    return source.categories.includes("asn");
  if (definition.network) return source.categories.includes("network");
  return !!(
    definition.categories?.some((category) => source.categories.includes(category)) ||
    definition.attributes?.some((attribute) => source.categories.includes(attribute))
  );
}

function indicatorCoverage(
  definition: (typeof indicatorDefinitions)[number],
  input: ScoringInput,
  family: 4 | 6,
  now: number,
): NonNullable<Indicator["coverage"]> {
  const relevant = input.sources.filter((source) => sourceCoversIndicator(definition, source));
  const coverage: NonNullable<Indicator["coverage"]> = {
    sourceIds: relevant.map((source) => source.id).sort(),
    checkedSourceIds: [],
    unavailableSourceIds: [],
    staleSourceIds: [],
    unsupportedSourceIds: [],
  };
  for (const source of relevant) {
    if (!source.families.includes(family)) coverage.unsupportedSourceIds.push(source.id);
    else if (
      source.state === "stale" ||
      (source.expiresAt !== undefined && timestamp(source.expiresAt) !== null && timestamp(source.expiresAt)! <= now)
    ) coverage.staleSourceIds.push(source.id);
    else if (!sourceUsable(source, family, now)) coverage.unavailableSourceIds.push(source.id);
    else if (source.matched !== undefined && source.count > 0 &&
      sourceCoversIndicator(definition, { ...source, categories: source.categories.filter(category => !source.positiveOnlyCategories?.includes(category)) }))
      coverage.checkedSourceIds.push(source.id);
  }
  for (const ids of Object.values(coverage)) ids.sort();
  return coverage;
}

function coverageGap(
  definition: (typeof indicatorDefinitions)[number],
  coverage: NonNullable<Indicator["coverage"]>,
  family: 4 | 6,
): Pick<Indicator, "state" | "reason" | "description"> {
  if (!coverage.sourceIds.length) {
    const subtype = ["public_proxy", "web_proxy", "residential_proxy"].includes(definition.id);
    return {
      state: "unknown",
      reason: "no_source",
      description: definition.id === "asn_risk"
        ? text(
          "当前未接入可核验的 ASN 级滥用数据。ASN 编号、组织名称及机房归属只说明网络归属，不能证明该 ASN 有恶意活动。",
          "No verifiable ASN-wide abuse source is configured. ASN numbers, organization names and hosting membership establish ownership, not ASN-wide malicious activity.",
        )
        : subtype
          ? text(
            "当前没有覆盖此代理子类型的有效授权来源。通用代理标签、住宅宽带或机房归属都不能单独确认此项。",
            "No licensed source covering this proxy subtype is configured. A generic proxy label, residential access or hosting membership cannot establish this subtype.",
          )
          : text(
            "当前接入的数据源未覆盖此检测项，因此尚未检测；这不是否定结果。",
            "Configured datasets do not cover this indicator, so it has not been checked; this is not a negative result.",
          ),
    };
  }
  if (coverage.unsupportedSourceIds.length === coverage.sourceIds.length)
    return {
      state: "not_checked", reason: "unsupported_family",
      description: text(
        `相关来源不覆盖 IPv${family}，本次地址未检测。另一地址族的未命中不能用于此地址。`,
        `Relevant sources do not cover IPv${family}; this address was not checked. Results for the other address family do not apply.`,
      ),
    };
  if (coverage.staleSourceIds.length)
    return {
      state: "stale", reason: "source_stale",
      description: text(
        "相关来源已过期，本次缺少有效来源检查。只有通过校验的历史 IP 风险命中可以少量扣分。",
        "Relevant sources have expired, leaving no current check. Verified historical IP threat matches can make a small deduction.",
      ),
    };
  if (coverage.unavailableSourceIds.length)
    return {
      state: "not_checked", reason: "source_unavailable",
      description: text(
        "相关来源尚未配置、读取失败或元数据无效，本次未完成检查；不能视作未命中。",
        "Relevant sources are unconfigured, could not be read or have invalid metadata. This check did not complete and is not a non-match.",
      ),
    };
  return {
    state: "not_checked", reason: "not_queried",
    description: text(
      "来源存在，但没有完成适用的非空数据查询。当前没有可报告的检测结果。",
      "A source exists, but no applicable nonempty dataset query completed. There is no reportable result yet.",
    ),
  };
}

function makeIndicators(
  input: ScoringInput,
  valid: Evidence[],
  eligibility: Map<string, Eligibility>,
  family: 4 | 6,
  now: number,
): Indicator[] {
  return indicatorDefinitions.map((definition) => {
    const coverage = indicatorCoverage(definition, input, family, now);
    if (definition.id === "ownership_consistency") {
      const records = valid.filter(
        (evidence) =>
          evidence.category === "asn" &&
          typeof evidence.value === "number" &&
          Number.isInteger(evidence.value) &&
          evidence.value > 0,
      );
      const values = new Set(records.map((evidence) => evidence.value));
      const sources = new Set(records.map((evidence) => evidence.sourceId));
      const conflict = values.size > 1;
      const comparable = sources.size > 1;
      return {
        id: definition.id,
        label: definition.label,
        state: conflict ? "conflict" : comparable ? "detected" : "unknown",
        reason: conflict ? "conflicting_evidence" : comparable ? "matched" : "insufficient_evidence",
        coverage,
        description: conflict
          ? text(
              "有效来源给出的 ASN 归属存在差异；可能涉及路由变化或数据库时差，不确认哪一方正确。",
              "Valid sources disagree on origin ASN; routing changes or dataset timing may explain the difference, and neither is declared correct.",
            )
          : comparable
            ? text(
                "多个有效来源的 ASN 归属一致；这不验证地理位置、组织身份或使用者身份。",
                "Multiple valid sources agree on origin ASN; this does not validate location, organization identity or user identity.",
              )
            : text(
                "缺少可交叉比较的 ASN 来源，无法判断归属一致性。",
                "There are insufficient comparable ASN sources to assess ownership consistency.",
              ),
        evidenceIds: records.map((evidence) => evidence.id).sort(),
      };
    }
    const hits = valid.filter((evidence) =>
      indicatorMatches(definition, evidence),
    );
    const old = input.evidence.filter(
      (evidence) =>
        indicatorMatches(definition, evidence) &&
        eligibility.get(evidence.id) === "stale",
    );
    const rejected = input.evidence.filter(
      (evidence) => indicatorMatches(definition, evidence) && isPositive(evidence) && eligibility.get(evidence.id) === "invalid",
    );
    const checked = coverage.checkedSourceIds.length > 0;
    const gap = coverageGap(definition, coverage, family);
    return {
      id: definition.id,
      label: definition.label,
      state: hits.length ? "detected" : old.length ? "stale" : rejected.length ? "unknown" : checked ? "not_found" : gap.state,
      reason: hits.length ? "matched" : old.length ? "source_stale" : rejected.length ? "insufficient_evidence" : checked ? "no_match" : gap.reason,
      coverage,
      description: hits.length
        ? definition.id === "proxy" && hits.every((hit) => !hit.attribute || hit.attribute === "proxy")
          ? text(
            "公开数据标记了通用代理线索，但没有确认公共代理、Web 代理或住宅代理子类型。展开可查看实际来源；代理属性本身不是恶意记录。",
            "Public data contains a generic proxy label without confirming public, web or residential proxy subtype. Expand for actual sources; proxy membership alone is not an abuse record.",
          )
          : text(
            "存在适用的公开情报记录；展开查看来源、日期与限制。",
            "Applicable public intelligence records were found; expand for provenance, dates and limitations.",
          )
        : old.length
          ? definition.categories?.some(category => THREAT_WEIGHTS[category] !== undefined)
            ? text("仅发现历史风险记录。展开查看时效，实际扣分见评分明细。", "Only historical risk records were found. Expand for dates and see scoring details for applied points.")
            : text("仅有过期记录，未参与此项判断。", "Only expired records were found for this indicator.")
          : rejected.length
            ? text("匹配记录未通过范围、时效或来源校验，不能据此确认命中，也不能记作未命中。", "A record failed range, time or provenance validation. Neither a valid hit nor a non-match can be established from it.")
          : checked
            ? text(
                `已在 ${coverage.checkedSourceIds.length} 个适用来源完成此项查询，未发现匹配记录；不是确认不存在。${coverage.sourceIds.length > coverage.checkedSourceIds.length ? "其余来源未完成有效检查，可查看覆盖明细。" : ""}`,
                `Checked ${coverage.checkedSourceIds.length} applicable source(s) with no matching record; this does not prove absence.${coverage.sourceIds.length > coverage.checkedSourceIds.length ? " Other sources could not complete a valid check; see coverage details." : ""}`,
              )
            : gap.description,
      evidenceIds: [...hits, ...old, ...rejected].map((evidence) => evidence.id).sort(),
    };
  });
}

function riskConfidence(
  threats: WeightedThreat[],
  selected: WeightedThreat[],
  sourceById: Map<string, SourceStatus>,
  hasConflict: boolean,
): Confidence {
  if (!selected.length) return "insufficient";
  if (
    hasConflict ||
    selected.some((item) => item.freshness < 1 || item.quality <= QUALITY.low)
  )
    return "low";
  const highSources = threats
    .filter((item) => item.freshness === 1 && item.quality === 1)
    .map((item) => sourceById.get(item.evidence.sourceId)!);
  return independentSources([
    ...new Map(highSources.map((source) => [source.id, source])).values(),
  ]).length >= 2
    ? "high"
    : "medium";
}

export function assessRisk(input: ScoringInput): RiskAssessment {
  const address = requirePublicIp(input.ip);
  const now = timestamp(input.asOf);
  if (now === null) throw new Error("INVALID_EVALUATION_TIME");
  const sourceById = new Map(
    input.sources.map((source) => [source.id, source]),
  );
  const applicable = input.sources.filter((source) =>
    sourceUsable(source, address.family, now),
  );
  const eligibility = new Map(
    input.evidence.map((evidence) => [
      evidence.id,
      evidenceEligibility(
        evidence,
        sourceById.get(evidence.sourceId),
        address,
        now,
      ),
    ]),
  );
  const valid = input.evidence.filter(
    (evidence) => eligibility.get(evidence.id) === "valid",
  );
  const network = classifyNetwork(valid.filter(evidence => sourceById.get(evidence.sourceId)?.matched === true));
  const threats: WeightedThreat[] = valid
    .filter(isThreat)
    .map((evidence) => {
      const source = sourceById.get(evidence.sourceId)!;
      const quality = Math.min(
        QUALITY[evidence.confidence],
        QUALITY[source.confidence],
      );
      const freshness = eventFreshness(evidence.observedAt, input.asOf);
      return {
        evidence,
        quality,
        freshness,
        weight: THREAT_WEIGHTS[evidence.category]! * quality * freshness,
      };
    })
    .filter((item) => item.weight > 0);
  const selected = chooseThreats(threats, sourceById);
  const details: ScoreAdjustment[] = [
    {
      ruleId: "zero-baseline",
      amount: 0,
      evidenceIds: [],
      label: text("零分起点", "Zero starting point"),
      explanation: text(
        "仅累加通过校验的风险证据。有效和历史命中各按时效计分。",
        "Only verified risk evidence adds points. Current and historical matches use separate freshness weights.",
      ),
    },
  ];
  let threatTotal = 0;
  for (let index = 0; index < selected.length; index++) {
    const item = selected[index];
    const amount = Math.min(
      item.weight * (index === 0 ? 1 : 0.25),
      95 - threatTotal,
    );
    if (amount <= 0) continue;
    threatTotal += amount;
    const name = THREAT_NAMES[item.evidence.category]!;
    details.push({
      ruleId: `threat-${item.evidence.category}${index ? "-independent-supplement" : ""}`,
      label: name,
      amount,
      evidenceIds: [item.evidence.id],
      explanation: text(
        `类别权重 ${THREAT_WEIGHTS[item.evidence.category]} × 来源质量 ${item.quality} × 活动时效 ${item.freshness}${index ? " × 独立活动补充 0.25" : ""}。${item.evidence.observedAt ? "活动时间来自来源记录。" : "来源未提供活动日期，不能证明近期活动。"}`,
        `Category weight ${THREAT_WEIGHTS[item.evidence.category]} × source quality ${item.quality} × event freshness ${item.freshness}${index ? " × independent-activity supplement 0.25" : ""}. ${item.evidence.observedAt ? "Event time comes from the source record." : "The source provides no event date, so recent activity is not established."}`,
      ),
    });
  }

  // Privacy services and access networks are contextual characteristics, not
  // malicious activity. Every adjustment must trace to actual valid evidence.
  const contextGroups = new Map<
    string,
    { amount: number; evidenceIds: string[] }
  >();
  const hasRelay = valid.some((evidence) => evidence.attribute === "relay");
  for (const evidence of valid) {
    const type =
      evidence.attribute ??
      (evidence.category === "network" && evidence.networkType === network.type ? network.type : undefined);
    if (!type || (hasRelay && (type === "cloud" || type === "hosting")))
      continue;
    const amount = CONTEXT[type as keyof typeof CONTEXT];
    if (!amount) continue;
    const key = [
      "proxy",
      "public_proxy",
      "web_proxy",
      "residential_proxy",
    ].includes(type)
      ? "proxy"
      : ["cloud", "hosting"].includes(type)
        ? "hosting"
        : type;
    const previous = contextGroups.get(key);
    if (previous) {
      previous.amount = Math.max(previous.amount, amount);
      previous.evidenceIds.push(evidence.id);
    } else contextGroups.set(key, { amount, evidenceIds: [evidence.id] });
  }
  const context = Math.min(
    40,
    100 - threatTotal,
    [...contextGroups.values()].reduce((sum, item) => sum + item.amount, 0),
  );
  const contextNames: Record<string, LocalizedText> = {
    hosting: text("机房 / 云网络属性", "Hosting / cloud context"),
    proxy: text("代理属性", "Proxy context"),
    vpn: text("VPN 出口属性", "VPN exit context"),
    tor: text("Tor 出口属性", "Tor exit context"),
  };
  let contextRemaining = context;
  for (const [group, entry] of [...contextGroups].sort(
    ([nameA, a], [nameB, b]) => b.amount - a.amount || nameA.localeCompare(nameB),
  )) {
    const amount = Math.min(entry.amount, contextRemaining);
    contextRemaining -= amount;
    if (!amount) continue;
    details.push({
      ruleId: `network-context-${group}`,
      amount,
      label: contextNames[group],
      evidenceIds: [...new Set(entry.evidenceIds)].sort(),
      explanation: text(
        `此类属性规则上限 +${entry.amount}，本次贡献 +${amount}。同类来源取最强项，机房/云取最大值、代理子类型取最大值，全部网络属性合计最多 +40，总分最多 100。权重为未作统计校准的公开规则，不表示恶意活动或欺诈概率。`,
        `This group has a +${entry.amount} policy weight and contributes +${amount}. Duplicate hosting/cloud and proxy subtypes use their maximum; all context groups cap at +40 and the total at 100. These uncalibrated policy weights do not establish malicious activity or fraud probability.`,
      ),
    });
  }

  const currentScore = Math.round(
    details.reduce((sum, detail) => sum + detail.amount, 0),
  );
  const historical = historicalThreat(input.evidence, eligibility, sourceById, threats, address, now);
  const historicalRiskPoints = historical ? Math.min(15, 100 - currentScore, Math.max(1, Math.round(historical.weight))) : 0;
  if (historical && historicalRiskPoints > 0) {
    const name = THREAT_NAMES[historical.evidence.category]!;
    details.push({
      ruleId: "threat-historical",
      label: text(`历史${name.zh}记录（已过期）`, `Historical ${name.en.toLowerCase()} record (expired)`),
      amount: historicalRiskPoints,
      evidenceIds: [historical.evidence.id],
      explanation: text(
        `按类别、来源质量和历史权重 ${historical.freshness} 取整。历史最多计 15 分。${historical.evidence.observedAt ? "已按记录的活动日期衰减。" : "活动日期未知，按快照日期降低权重。"}`,
        `Rounded from category weight, source quality and historical weight ${historical.freshness}, capped at 15 points. ${historical.evidence.observedAt ? "Uses the recorded activity date." : "The activity date is unknown. The snapshot date limits its weight."}`,
      ),
    });
  }
  const score = currentScore + historicalRiskPoints;
  const hasThreatEvidence = threats.length > 0;
  const completedRiskChecks = applicable.filter(source => source.matched !== undefined && source.count > 0 && source.categories.some(category =>
    THREAT_WEIGHTS[category as SignalCategory] !== undefined || ["network", "vpn", "tor", "proxy", "public_proxy", "web_proxy", "residential_proxy"].includes(category)
  ) && (source.matched === false || valid.some(e => e.sourceId === source.id)) && !input.evidence.some(e => e.sourceId === source.id && eligibility.get(e.id) !== "valid" && isPositive(e)));
  const assessable = hasThreatEvidence || historicalRiskPoints > 0 || context > 0 || completedRiskChecks.length > 0;
  const indicators = makeIndicators(input, valid, eligibility, address.family, now);
  const hasConflict =
    network.conflict || indicators.some((indicator) => indicator.state === "conflict") ||
    input.evidence.some(
      (evidence) =>
        eligibility.get(evidence.id) === "invalid" &&
        isThreat(evidence) &&
        isPositive(evidence),
    ) ||
    input.sources.some(
      (source) =>
        source.matched === false &&
        threats.some((item) => item.evidence.sourceId === source.id),
    );
  let confidence = riskConfidence(threats, selected, sourceById, hasConflict);
  if (!hasThreatEvidence && assessable)
    confidence = "low";
  const checkedThreatSources = applicable.filter(
    (source) =>
      source.matched !== undefined &&
      source.categories.some(
        (category) => THREAT_WEIGHTS[category as SignalCategory] !== undefined,
      ),
  );
  const networkLabels: Record<string, LocalizedText> = {
    hosting: text("数据中心 / 托管网络", "a datacenter / hosting network"),
    cloud: text("云服务网络", "a cloud network"),
    residential: text("住宅接入网络", "a residential access network"),
    mobile: text("移动网络", "a mobile network"),
    business: text("企业网络", "a business network"),
    education: text("教育网络", "an education network"),
  };
  const networkSummary = networkLabels[network.type];
  const summary = hasThreatEvidence
    ? text(
        "该地址命中公开威胁情报。参考指数由具体类别、来源质量与活动时效生成；记录不代表当前使用者正在从事恶意行为，也不是欺诈概率。",
        "This address appears in public threat intelligence. The reference index uses recorded categories, source quality and event freshness; it does not establish current-user misconduct or a fraud probability.",
      )
    : historicalRiskPoints > 0
      ? text(`有已过期的公开风险记录，按历史权重计 ${historicalRiskPoints} 分。`, `Expired public risk evidence contributes ${historicalRiskPoints} historical point(s).`)
    : assessable
      ? text(
          `${networkSummary ? `公开来源将该地址归入${networkSummary.zh}。` : "已完成部分公开风险来源检查。"}${context ? `网络属性增加 ${context} 分。` : ""}当前没有可参与评分的该 IP 恶意活动命中；这不代表安全。住宅、公共代理等子类型需各自的情报依据，不能互相替代。`,
          `${networkSummary ? `Public data classifies this address as ${networkSummary.en}.` : "Some public risk-source checks completed."}${context ? ` Network context adds ${context} points.` : ""} No eligible malicious-activity hit for this IP is available; this does not establish safety. Public and residential proxy subtypes each need their own evidence.`,
        )
      : text(
          "资料不足，无法可靠评分。没有完成有效的风险来源检查，不能把未检测显示为 0 分或安全。",
          "Insufficient data for a reliable score. No valid risk-source check completed; an unperformed check cannot be reported as zero or safe.",
        );
  return {
    ip: address.canonical,
    riskScore: assessable ? Math.max(0, Math.min(100, score)) : null,
    scoreKind: assessable ? "evidence" : "insufficient",
    riskLevel: assessable ? purityTier(100 - score)!.assessmentLevel : "insufficient",
    confidence,
    networkType: network.type,
    attributes: [...new Set(input.attributes)].sort(),
    hasThreatEvidence,
    historicalRiskPoints,
    scoreDetails: (assessable ? details : []).map((detail) => ({
      ...detail,
      amount: Math.round(detail.amount * 100) / 100,
    })),
    indicators,
    evidence: input.evidence.map(evidence => ({
      ...evidence, evaluation: eligibility.get(evidence.id), stale: eligibility.get(evidence.id) === "stale",
    })).sort((a, b) => a.id.localeCompare(b.id)),
    sources: [...input.sources].sort((a, b) => a.id.localeCompare(b.id)),
    summary,
    datasetVersion: input.datasetVersion,
    modelVersion: MODEL_VERSION,
    evaluatedAt: input.asOf,
    coverage: {
      checked: checkedThreatSources.length,
      available: applicable.length,
      independentSources: independentSources(checkedThreatSources).length,
      note: text(
        "数量仅表示适用的来源检查，不是全网覆盖率；不支持、失效及过期来源不算未命中。",
        "Counts describe applicable source checks, not Internet-wide coverage; unsupported, unavailable and stale sources are not negative results.",
      ),
    },
  };
}
