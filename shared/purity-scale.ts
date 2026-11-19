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
