import type { PurityLimit } from "./contracts.ts";

export const PURITY_MODEL_VERSION = "ruijing-purity-8";
export const PURITY_CEILINGS: Record<PurityLimit, number> = {
  no_threat_checks: 50,
  network_conflict: 80,
  network: 80,
  threat_coverage: 85,
};

export function scoreWithLimit(riskScore: number | null, limit?: PurityLimit, historicalRiskPoints = 0) {
  const evidenceScore = 100 - (riskScore ?? 0);
  const score = limit ? Math.min(evidenceScore, Math.max(0, PURITY_CEILINGS[limit] - historicalRiskPoints)) : evidenceScore;
  return { score, reservedPoints: evidenceScore - score };
}

export const PURITY_TIERS = [
  { key: "low", minimum: 88, maximum: 100, assessmentLevel: "minimal", label: { zh: "低风险", en: "Low risk" } },
  { key: "lower", minimum: 63, maximum: 87, assessmentLevel: "low", label: { zh: "较低风险", en: "Lower risk" } },
  { key: "medium", minimum: 38, maximum: 62, assessmentLevel: "moderate", label: { zh: "中等风险", en: "Moderate risk" } },
  { key: "higher", minimum: 13, maximum: 37, assessmentLevel: "elevated", label: { zh: "较高风险", en: "Elevated risk" } },
  { key: "high", minimum: 0, maximum: 12, assessmentLevel: "high", label: { zh: "高风险", en: "High risk" } },
] as const;

export function purityTier(score: number | null) {
  if (score === null) return null;
  return PURITY_TIERS.find(({ minimum, maximum }) => score >= minimum && score <= maximum) ?? null;
}
