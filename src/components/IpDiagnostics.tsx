import { useEffect, useRef } from "react";
import { ArrowUpRight, Check, CircleHelp, Database, Globe2, MapPin, Network, ShieldAlert, Waypoints } from "lucide-react";
import type { Indicator, IpReport } from "../../shared/contracts.ts";
import { indicatorLabel } from "../lib/indicator-label.ts";
import land from "../lib/world-land.json";

type Lang = "zh" | "en";

function LocationMap({ latitude, longitude }: { latitude: number; longitude: number }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const context = canvas.current?.getContext("2d");
    if (!context || typeof Path2D === "undefined") return;
    context.scale(1.5, 1.5);
    context.fillStyle = "#3986c9";
    context.fill(new Path2D(land.path), "evenodd");
    context.resetTransform();
  }, []);
  return (
    <div className="location-map" aria-hidden="true">
      <canvas ref={canvas} width={1080} height={540} />
      <span className="location-dot" style={{
        insetInlineStart: `${(longitude + 180) / 3.6}%`,
        insetBlockStart: `${(90 - latitude) / 1.8}%`,
      }} />
    </div>
  );
}

function SignalResult({ signal, lang }: { signal: Indicator | undefined; lang: Lang }) {
  const state = signal?.state;
  const Icon = state === "not_found" ? Check
    : state === "detected" || state === "conflict" ? ShieldAlert : CircleHelp;
  return (
    <span className="diagnostic-status" data-state={state}>
      <Icon size={13} aria-hidden="true" />
      {indicatorLabel(signal, lang)}
    </span>
  );
}

export function IpDiagnostics({
  report, lang, country, network, hidden,
}: {
  report: IpReport;
  lang: Lang;
  country?: string;
  network: string;
  hidden: boolean;
}) {
  const t = (zh: string, en: string) => lang === "zh" ? zh : en;
  const { info, assessment, provenance } = report;
  const { latitude, longitude } = info;
  const hasCoordinates = latitude !== undefined && longitude !== undefined &&
    Math.abs(latitude) <= 90 && Math.abs(longitude) <= 180;
  const place = [...new Set([country, info.region, info.city].filter(Boolean))].join(" · ");
  const indicators = new Map(assessment.indicators.map((item) => [item.id, item]));
  const threat = indicators.get("threat");
  const applicable = assessment.sources.filter((source) => source.families.includes(info.family));
  const sourceResults = applicable.filter((source) => source.state === "ready" && typeof source.matched === "boolean");
  const conflicts = provenance?.conflicts ?? [];
  const locationConflict = conflicts.includes("country");
  const asnConflict = conflicts.includes("asn");
  const unknown = t("未取得", "Unavailable");

  return (
    <section className="ip-diagnostics" id="diagnostics" aria-labelledby="diagnostics-heading">
      <div className="diagnostic-heading">
        <div>
          <h2 id="diagnostics-heading">{t("IP 检测总览", "IP diagnostics")}</h2>
          <p>{report.mode === "self" ? t("当前连接的公网出口", "Public egress for your current connection") : t("当前查询的目标 IP", "Public address from this lookup")}</p>
        </div>
        <a href="#connection-checks">{t("检测当前浏览器与连接", "Check this browser and connection")}<ArrowUpRight size={15} aria-hidden="true" /></a>
      </div>
      <div className="diagnostics-grid">
        <article className="diagnostic-card diagnostic-location">
          <h3><MapPin size={17} aria-hidden="true" />{t("出口位置", "Egress location")}</h3>
          <strong className="diagnostic-place">{place || unknown}</strong>
          {locationConflict && <p className="diagnostic-warning">{t("来源的国家或地区存在分歧", "Sources disagree on the country or region")}</p>}
          {hasCoordinates && <LocationMap latitude={latitude} longitude={longitude} />}
          <p className="location-caption">
            {hasCoordinates ? t("IP 估算位置 · Natural Earth 底图", "Approximate IP location · Natural Earth basemap")
              : t("当前来源未提供坐标", "Coordinates unavailable from the current source")}
          </p>
        </article>
        <article className="diagnostic-card diagnostic-ownership">
          <h3><Network size={17} aria-hidden="true" />{t("网络归属与地址", "Network ownership & address")}</h3>
          <dl className="diagnostic-rows">
            <div>
              <dt>{t("自治系统编号（ASN）", "Autonomous system number (ASN)")}</dt>
              <dd>{info.asn ? <code>{`AS${info.asn}`}</code> : unknown}</dd>
            </div>
            <div><dt>{t("ASN 归属组织", "ASN organization")}</dt><dd>{info.asOrganization || unknown}</dd></div>
            {info.isp && <div><dt>{t("接入服务商（ISP）", "Internet service provider (ISP)")}</dt><dd>{info.isp}</dd></div>}
            <div><dt>{t("网络类型", "Network type")}</dt><dd>{network}</dd></div>
            <div><dt>{t("地址族", "Address family")}</dt><dd><code>IPv{info.family}</code></dd></div>
            {info.network && <div><dt>{t("关联地址段", "Associated address range")}</dt><dd><code>{hidden ? "••••••" : info.network}</code></dd></div>}
            {info.connectionProtocol && <div><dt>{t("HTTP 协议", "HTTP protocol")}</dt><dd><code>{info.connectionProtocol}</code></dd></div>}
          </dl>
          {asnConflict && <p className="diagnostic-warning">{t("来源的 ASN 存在分歧", "Sources disagree on the ASN")}</p>}
          <p className="local-note">
            {t("ASN 用于在互联网路由中识别网络。归属组织是数据源记录的该网络运营方。",
              "An ASN identifies a network in internet routing. The organization is the network operator listed by the source.")}
          </p>
        </article>
        <article className="diagnostic-card diagnostic-routes">
          <h3><Waypoints size={17} aria-hidden="true" />{t("代理与匿名网络", "Proxies & anonymization")}</h3>
          <dl className="diagnostic-rows signal-rows">
            {["vpn", "proxy", "tor", "residential_proxy"].map((id) => {
              const signal = indicators.get(id);
              return <div key={id}><dt>{signal?.label[lang] ?? id}</dt><dd><SignalResult signal={signal} lang={lang} /></dd></div>;
            })}
          </dl>
        </article>
        <article className="diagnostic-card diagnostic-evidence">
          <h3><ShieldAlert size={17} aria-hidden="true" />{t("威胁情报", "Threat intelligence")}</h3>
          <dl className="diagnostic-rows signal-rows">
            <div><dt>{t("IP 威胁记录", "IP threat records")}</dt><dd><SignalResult signal={threat} lang={lang} /></dd></div>
            <div><dt>{t("ASN 滥用样本", "ASN abuse samples")}</dt><dd><SignalResult signal={indicators.get("asn_risk")} lang={lang} /></dd></div>
          </dl>
          <div className="diagnostic-coverage">
            <span><Database size={14} aria-hidden="true" />{t("本次完成的公开来源检查", "Public sources checked")}</span>
            <strong>{sourceResults.length} <small>/ {applicable.length}</small></strong>
            <div aria-hidden="true"><i style={{ inlineSize: `${applicable.length ? 100 * sourceResults.length / applicable.length : 0}%` }} /></div>
          </div>
        </article>
      </div>
      <div className="diagnostic-legend">
        <span><Globe2 size={14} aria-hidden="true" />{t("未发现记录仅适用于本次已检查的公开来源。", "No record found applies to the public sources checked in this lookup.")}</span>
        <a href="#evidence">{t("查看检测依据", "See evidence")}<ArrowUpRight size={14} aria-hidden="true" /></a>
      </div>
    </section>
  );
}
