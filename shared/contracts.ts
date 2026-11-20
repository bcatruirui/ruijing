export type LocalizedText = { zh: string; en: string };
export type Confidence = "high" | "medium" | "low" | "insufficient";
export type Family = 4 | 6;
export type NetworkType =
  | "residential"
  | "hosting"
  | "cloud"
  | "mobile"
  | "business"
  | "education"
  | "unknown";
export type NetworkAttribute =
  | "vpn"
  | "proxy"
  | "public_proxy"
  | "web_proxy"
  | "residential_proxy"
  | "tor"
  | "relay"
  | "crawler";
export type SignalCategory =
  | "c2"
  | "botnet"
  | "malware"
  | "phishing"
  | "brute_force"
  | "web_attack"
  | "scanner"
  | "spam"
  | "other_abuse"
  | "network"
  | "tor"
  | "vpn"
  | "proxy"
  | "residential_proxy"
  | "asn"
  | "asn_reputation"
  | "geo";
export type SourceState = "ready" | "stale" | "unavailable" | "unconfigured";
export interface SourceStatus {
  id: string;
  name: string;
  url: string;
  license: string;
  state: SourceState;
  confidence: Exclude<Confidence, "insufficient">;
  upstreamFamilies: string[];
  families: Family[];
  categories: string[];
  /** Matches are meaningful, but a miss does not cover this category. */
  positiveOnlyCategories?: string[];
  /** Small or narrowly sampled feed with limited general coverage. */
  limitedCoverage?: boolean;
  publishedAt?: string;
  fetchedAt?: string;
  expiresAt?: string;
  count: number;
  negativeCoverageEligible: boolean;
  matched?: boolean;
  error?: string;
}
export interface Evidence {
  id: string;
  sourceId: string;
  sourceName: string;
  sourceUrl: string;
  upstreamFamily: string;
  category: SignalCategory;
  value: string | number | boolean;
  confidence: Exclude<Confidence, "insufficient">;
  description: LocalizedText;
  observedAt?: string;
  publishedAt?: string;
  fetchedAt?: string;
  expiresAt?: string;
  matchedRange?: string;
  matchedRangeLabel?: string;
  eventId?: string;
  independentEvent?: boolean;
  networkType?: NetworkType;
  networkBasis?: "prefix";
  attribute?: NetworkAttribute;
  stale?: boolean;
  evaluation?: "valid" | "stale" | "invalid";
}
export interface Indicator {
  id: string;
  label: LocalizedText;
  state:
    "detected" | "not_found" | "unknown" | "not_checked" | "stale" | "conflict";
  description: LocalizedText;
  evidenceIds: string[];
  reason?: "matched" | "no_match" | "no_source" | "unsupported_family" | "source_unavailable" | "source_stale" | "not_queried" | "insufficient_evidence" | "conflicting_evidence";
  coverage?: {
    sourceIds: string[];
    checkedSourceIds: string[];
    unavailableSourceIds: string[];
    staleSourceIds: string[];
    unsupportedSourceIds: string[];
  };
}
export interface ScoreAdjustment {
  ruleId: string;
  label: LocalizedText;
  amount: number;
  evidenceIds: string[];
  explanation: LocalizedText;
}
export interface ScoringInput {
  ip: string;
  evidence: Evidence[];
  sources: SourceStatus[];
  networkType: NetworkType;
  attributes: NetworkAttribute[];
  asOf: string;
  datasetVersion: string;
}
export interface RiskAssessment {
  ip: string;
  riskScore: number | null;
  scoreKind: "insufficient" | "evidence";
  riskLevel: string;
  confidence: Confidence;
  networkType: NetworkType;
  attributes: NetworkAttribute[];
  hasThreatEvidence: boolean;
  historicalRiskPoints?: number;
  scoreDetails: ScoreAdjustment[];
  indicators: Indicator[];
  evidence: Evidence[];
  sources: SourceStatus[];
  summary: LocalizedText;
  datasetVersion: string;
  modelVersion: string;
  evaluatedAt: string;
  coverage: {
    checked: number;
    available: number;
    independentSources: number;
    note: LocalizedText;
  };
}
interface PurityScoreFields {
  score: number | null;
  status: "scored" | "insufficient" | "conflict";
  checked: number;
  independentSources: number;
}
export type PurityLimit = "no_threat_checks" | "network_conflict" | "network" | "threat_coverage";
export type PurityAssessment = PurityScoreFields & (
  | { modelVersion: "ruijing-purity-1" }
  | { modelVersion: "ruijing-purity-2" | "ruijing-purity-3" | "ruijing-purity-4"; coverage: "none" | "limited" | "sufficient" }
  | { modelVersion: "ruijing-purity-5"; coverage: "none" | "limited" | "sufficient"; reason?: "network" | "threat_coverage" }
  | { modelVersion: "ruijing-purity-6" | "ruijing-purity-7" | "ruijing-purity-8"; score: number; coverage: "none" | "limited" | "sufficient"; limit?: PurityLimit; reservedPoints: number }
);
export interface IpInfo {
  ip: string;
  family: Family;
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  /** Database estimates for an IP area, never device GPS coordinates. */
  latitude?: number;
  longitude?: number;
  postalCode?: string;
  timezone?: string;
  asn?: number;
  asOrganization?: string;
  isp?: string;
  network?: string;
  addressType: string;
  networkType: NetworkType;
  attributes: NetworkAttribute[];
  geoSource?: string;
  geoSourceUrl?: string;
  geoAccuracy?: "approximate";
  asnSource?: string;
  geoUpdatedAt?: string;
  asnUpdatedAt?: string;
  connectionProtocol?: string;
}
export interface IpReport {
  info: IpInfo;
  assessment: RiskAssessment;
  generatedAt: string;
  mode: "self" | "lookup";
  warnings: LocalizedText[];
  purity?: PurityAssessment;
  provenance?: {
    offline: Partial<IpInfo>;
    conflicts: ("country" | "asn")[];
  };
}
export interface IntelPayload {
  kind: "asn" | "geo" | "network" | "threat" | "tor";
  asn?: number;
  organization?: string;
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  postalCode?: string;
  timezone?: string;
  networkType?: NetworkType;
  networkBasis?: "prefix";
  attributes?: NetworkAttribute[];
  category?: SignalCategory;
  observedAt?: string;
  confidence?: Exclude<Confidence, "insufficient">;
  description?: string;
  prefix?: string;
  upstreamFamily?: string;
  eventId?: string;
}
export interface BuildRecord {
  family: Family;
  start: string;
  end: string;
  payload: IntelPayload;
}
export interface ShardEntry {
  id: string;
  path: string;
  family: Family;
  start: string;
  end: string;
  count: number;
  byteLength: number;
  sha256: string;
}
export interface SourceManifest extends SourceStatus {
  shards: ShardEntry[];
  sha256?: string;
  downloadUrl?: string;
  licenseUrl?: string;
  licenseAttribution?: string;
}
export interface DatasetManifest {
  schemaVersion: 1;
  version: string;
  builtAt: string;
  profile: string;
  sources: SourceManifest[];
}
export interface Capabilities {
  datasetVersion: string;
  builtAt?: string;
  sources: SourceStatus[];
  dns: { configured: boolean; status?: "ready" | "unavailable" };
  stun: { configured: boolean; url?: string };
  routingNodes: { id: string; name: string; url: string; family?: Family }[];
  familyEndpoints: { ipv4?: string; ipv6?: string };
  development: boolean;
}
