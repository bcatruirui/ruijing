import type { Indicator } from "../../shared/contracts";
export function indicatorLabel(item: Indicator | undefined, lang: "zh" | "en") {
  const t = (zh: string, en: string) => lang === "zh" ? zh : en;
  if (!item) return t("等待查询", "Awaiting lookup");
  if (item.state === "detected") return item.id === "ownership_consistency" ? t("一致", "Consistent") : item.id === "asn_risk" ? t("有样本记录", "Sample record found") : t("已识别", "Detected");
  if (item.state === "not_found") return t("未发现记录", "No record found");
  if (item.state === "conflict") return t("存在差异", "Conflicting");
  if (item.reason === "no_source") return t("暂无覆盖来源", "No coverage source");
  if (item.reason === "unsupported_family") return t("地址族未覆盖", "Family not covered");
  if (item.state === "stale") return t("来源 / 记录过期", "Stale source / record");
  if (item.reason === "source_unavailable") return t("来源暂不可用", "Source unavailable");
  if (item.state === "not_checked") return t("本次未检测", "Not checked");
  return t("证据不足", "Insufficient evidence");
}
