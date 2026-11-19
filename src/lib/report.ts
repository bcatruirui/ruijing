import type { IpReport, LocalizedText } from "../../shared/contracts.ts";
import { purityTier } from "../../shared/purity-scale.ts";
import type { DnsLeakResult } from "../features/dns.ts";
import { timezoneCountries } from "./timezone-territories.ts";

export type ReportLanguage = keyof LocalizedText;
const confidenceNames = {
  high: { zh: "高可信度", en: "High confidence" },
  medium: { zh: "中可信度", en: "Medium confidence" },
  low: { zh: "低可信度", en: "Low confidence" },
  insufficient: { zh: "资料不足", en: "Insufficient data" },
};
const networkNames = {
  residential: { zh: "住宅接入", en: "Residential access" },
  hosting: { zh: "机房托管", en: "Datacenter hosting" },
  cloud: { zh: "云服务", en: "Cloud network" },
  mobile: { zh: "移动接入", en: "Mobile access" },
  business: { zh: "企业网络", en: "Business network" },
  education: { zh: "教育网络", en: "Education network" },
  unknown: { zh: "类型未知", en: "Type unknown" },
};
const proxyAttributes = ["proxy", "vpn", "tor", "public_proxy", "web_proxy", "residential_proxy", "relay"];

export function reportView(
  report: IpReport, lang: ReportLanguage,
  context: { hidden?: boolean; timezone?: string; dns?: DnsLeakResult | null; dnsReady?: boolean; alternate?: IpReport | null } = {},
) {
  const t = (zh: string, en: string) => lang === "zh" ? zh : en;
  const { info, assessment, purity } = report;
  const self = report.mode === "self";
  const localize = (code: string) => new Intl.DisplayNames([lang], { type: "region" }).of(code) ?? code;
  const country = info.countryCode && /^[A-Z]{2}$/.test(info.countryCode) ? localize(info.countryCode) : info.country;
  const place = [...new Set([country, info.region, info.city].filter(Boolean))].join(" · ");
  const timezone = self ? context.timezone : undefined;
  const territories = timezoneCountries(timezone);
  const candidate = territories.length === 1 ? territories[0] : undefined;
  const access = (another: IpReport) =>
    ["residential", "mobile"].includes(another.info.networkType) &&
    !another.info.attributes.some(attribute => proxyAttributes.includes(attribute)) &&
    !another.provenance?.conflicts.length &&
    !another.assessment.indicators.some(indicator => indicator.state === "conflict");
  const proxy = info.attributes.some(attribute => proxyAttributes.includes(attribute));
  const hosting = info.networkType === "hosting" || info.networkType === "cloud";
  const consistent = Boolean(candidate && candidate === info.countryCode && access(report));
  const alternative = context.alternate;
  const alternateCandidate = Boolean(candidate && alternative && !report.provenance?.conflicts.length &&
    alternative.info.family === info.family && alternative.info.ip !== info.ip &&
    alternative.info.countryCode === candidate && access(alternative) && (proxy || hosting));
  const location = self
    ? place ? t(`本站看到你的请求从 ${place} 的网络出口进入。`, `This site received your request from an exit in ${place}.`)
      : t("本站已读取公网出口，现有地理数据不足以定位该出口。", "We observed your public exit. Available data could not locate it.")
    : place ? t(`公开数据库将这个 IP 的网络出口定位在 ${place}。`, `Public databases place this IP's exit in ${place}.`)
      : t("公开数据库暂未提供这个 IP 的出口位置。", "Public databases did not provide a location for this IP.");
  const network = networkNames[info.networkType][lang];
  const classification = proxy ? t(`${network}，另有代理、中继或 VPN 类信号`, `${network} with proxy, relay or VPN signals`) : network;
  const judgment = self
    ? alternateCandidate && candidate
      ? t(`独立探测与浏览器时区一致，设备网络环境可能关联${localize(candidate)}。`, `A separate network observation agrees with your browser time zone. Your device's network environment may be associated with ${localize(candidate)}.`)
      : consistent ? t("公网接入类型与浏览器时区指向同一国家或地区，连接信号一致。", "Your public access network and browser time zone point to the same country or region.")
      : t("当前信号不足以判断设备所在地区。", "The available signals do not establish the device's region.")
    : t("下面的检查基于公开情报和该地址的网络归属。", "The checks below use public intelligence about this address and its network.");
  const dns = self ? context.dns : null;
  const dnsText = dns?.verdict === "unexpected"
    ? t("与预期 DNS 路径不符，疑似泄漏", "Unexpected DNS path · possible leak")
    : dns?.status === "complete" ? t(`已观测 ${dns.resolvers.length} 个递归解析器`, `${dns.resolvers.length} recursive resolvers observed`)
    : dns?.status === "inconclusive" ? t("未取得有效观测", "No usable observation")
    : dns?.status === "timeout" ? t("检测超时", "Probe timed out")
    : dns?.status === "error" ? t("检测失败", "Probe failed")
    : dns?.status === "cancelled" ? t("检测已取消", "Probe cancelled")
    : dns?.status === "unavailable" || !context.dnsReady ? t("暂不可用", "Unavailable")
    : t("待检测", "Ready to check");
  const checked = purity?.checked ?? 0;
  const score = purity?.score ?? null;
  const tier = purityTier(score);
  const riskTier = tier?.key ?? null;
  const scoreState = tier
    ? tier.label[lang]
    : purity?.status === "conflict" ? t("来源冲突 · 暂不评分", "Source conflict · unscored") : t("资料不足 · 暂不评分", "Insufficient data · unscored");
  const scoreDeductions: string[] = [];
  if (score === 100) scoreDeductions.push(t("本次无扣分项", "No deductions in this check"));
  else if (score !== null) {
    const deductions = assessment.scoreDetails.filter(detail => detail.amount > 0);
    const total = 100 - score;
    for (const detail of deductions) {
      const label = detail.ruleId === "network-context-hosting" && hosting ? network : detail.label[lang];
      scoreDeductions.push(t(`${label}扣 ${detail.amount} 分`, `${label} deducts ${detail.amount} points`));
    }
    if (!deductions.length) scoreDeductions.push(t("扣分明细暂不可用", "Deduction details unavailable"));
    else if (Math.round(deductions.reduce((sum, detail) => sum + detail.amount, 0) * 100) !== total * 100)
      scoreDeductions.push(t(`合计扣 ${total} 分（取整）`, `Total deduction: ${total} points (rounded)`));
  }
  const rows = [
    { label: t("网络属性", "Network"), value: classification + (report.provenance?.conflicts.length ? t(" · 来源存在分歧", " · sources disagree") : ""), tone: proxy || hosting || report.provenance?.conflicts.length ? "caution" : "default" },
    ...(self ? [{
      label: t("时区与 DNS", "Time zone & DNS"),
      value: `${timezone ?? t("时区未知", "Time zone unavailable")} · DNS ${dnsText}`,
      tone: dns?.verdict === "unexpected" ? "caution" : "default",
    }] : []),
    { label: t("公开风险记录", "Public risk records"),
      value: assessment.hasThreatEvidence
        ? t("发现公开威胁记录，可展开查看类别、来源与时效。", "Public threat records found. Expand evidence for categories, sources and dates.")
        : checked ? t(`本次核查 ${checked} 个适用来源，未发现有效威胁记录。`, `Checked ${checked} applicable source(s) without a valid threat hit.`)
        : t("暂无有效的地址级威胁检查。", "No valid IP-level threat checks."),
      tone: assessment.hasThreatEvidence ? "caution" : "default" },
  ];
  return {
    title: t("检测报告", "Detection report"),
    scoreLabel: t("IP 纯净值", "IP purity score"),
    score, scoreState, riskTier, scoreDeductions,
    riskEvidenceConfidence: confidenceNames[assessment.confidence][lang],
    ip: context.hidden ? t("IP 已隐藏", "IP hidden") : info.ip,
    location, judgment, rows, checked,
  };
}
export type ReportView = ReturnType<typeof reportView>;

function download(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function saveJson(report: IpReport, view: ReportView, hidden: boolean) {
  const body = hidden ? {
    mode: report.mode, generatedAt: report.generatedAt, purity: report.purity, summary: view,
    assessment: { riskScore: report.assessment.riskScore, datasetVersion: report.assessment.datasetVersion, modelVersion: report.assessment.modelVersion },
  } : { ...report, summary: view };
  download(new Blob([JSON.stringify(body, null, 2)], { type: "application/json" }), "ruijing-ip-report.json");
}
export function reportText(report: IpReport, view: ReportView) {
  return [
    "瑞镜 IP / Ruijing IP",
    view.ip,
    `${view.scoreLabel} · ${view.score === null ? view.scoreState : `${view.score} / 100 · ${view.scoreState}`}`,
    ...view.scoreDeductions,
    "",
    view.title,
    view.location,
    view.judgment,
    ...view.rows.map(row => `${row.label} · ${row.value}`),
    "",
    `${report.assessment.modelVersion} · ${report.assessment.datasetVersion}`,
    report.generatedAt,
    ...(report.info.geoSource === "DB-IP City Lite" ? ["Geolocation by DB-IP · https://db-ip.com/"] : []),
  ].join("\n");
}
export function savePng(report: IpReport, view: ReportView) {
  const canvas = document.createElement("canvas");
  const context = canvas.getContext("2d");
  if (!context) throw new Error("Canvas unavailable");
  canvas.width = 1400;
  const font = '30px system-ui, "Microsoft YaHei", sans-serif';
  context.font = font;
  const rows = reportText(report, view).split("\n").flatMap(text => {
    const lines: string[] = [];
    let line = "";
    for (const letter of text) {
      if (context.measureText(line + letter).width > 1150) {
        lines.push(line);
        line = "";
      }
      line += letter;
    }
    return [...lines, line];
  });
  canvas.height = 180 + rows.length * 50;
  context.fillStyle = "#f3f6fb";
  context.fillRect(0, 0, canvas.width, canvas.height);
  context.fillStyle = "#fff";
  context.beginPath();
  context.roundRect(55, 55, canvas.width - 110, canvas.height - 110, 24);
  context.fill();
  for (const [index, line] of rows.entries()) {
    context.font = index === 2 ? `bold ${font}` : font;
    context.fillStyle = index === 2 ? "#174ba9" : "#142742";
    context.fillText(line, 110, 125 + index * 50);
  }
  canvas.toBlob(blob => {
    if (blob) download(blob, "ruijing-ip-report.png");
  }, "image/png");
}
