import { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowDownUp,
  ArrowUpRight,
  Check,
  CircleHelp,
  Globe2,
  LoaderCircle,
  LockKeyhole,
  Network,
  Play,
  Radio,
  ShieldCheck,
  Square,
  Wifi,
} from "lucide-react";
import type { Capabilities, IpReport } from "../../shared/contracts.ts";
import type {
  ConnectivityResult,
  RoutingResult,
} from "../features/connectivity.ts";
import type { WebRtcResult } from "../features/webrtc.ts";
import type { DnsLeakResult, DnsProgress } from "../features/dns.ts";
import { expectedResolvers } from "../lib/dns-expectation.ts";
import { parseIp } from "../../shared/ip.ts";
import { LocalChecks } from "./LocalChecks.tsx";
type Props = {
  lang: "zh" | "en";
  caps: Capabilities | null;
  report: IpReport | null;
  hidden: boolean;
  dns: DnsLeakResult | null;
  dnsProgress: DnsProgress | null;
  dnsBusy: boolean;
  dnsReady: boolean;
  onDnsTest: (expected: string[]) => void;
  onAlternate: (ip: string | null) => void;
};
const targets = [
  ["baidu", "百度", "Baidu", "百", "#2e67df", "CN"],
  ["taobao", "淘宝", "Taobao", "淘", "#a7410c", "CN"],
  ["wechat", "微信", "WeChat", "微", "#087849", "CN"],
  ["google", "Google", "Google", "G", "#2462c4", "Global"],
  ["github", "GitHub", "GitHub", "GH", "#303b50", "Global"],
  ["cloudflare", "Cloudflare", "Cloudflare", "CF", "#9a4d0a", "Global"],
  ["youtube", "YouTube", "YouTube", "▶", "#c7233a", "Global"],
  ["tiktok", "TikTok", "TikTok", "♪", "#202b3d", "Global"],
];
export function NetworkTools({ lang, caps, report, hidden, dns, dnsProgress, dnsBusy, dnsReady, onDnsTest, onAlternate }: Props) {
  const selfReport = report?.mode === "self" ? report : null;
  const t = (zh: string, en: string) => (lang === "zh" ? zh : en);
  const [probes, setProbes] = useState<Record<string, ConnectivityResult>>({}),
    [running, setRunning] = useState(false),
    [rtc, setRtc] = useState<WebRtcResult | null>(null),
    [rtcBusy, setRtcBusy] = useState(false),
    [routing, setRouting] = useState<RoutingResult | null>(null),
    [routeBusy, setRouteBusy] = useState(false),
    [families, setFamilies] = useState<Record<string, { ip?: string }>>({}),
    [familyBusy, setFamilyBusy] = useState(false);
  const abort = useRef<AbortController | null>(null),
    rtcAbort = useRef<AbortController | null>(null),
    routeAbort = useRef<AbortController | null>(null);
  const [expected, setExpected] = useState("");
  const expectedEntries = expectedResolvers(expected);
  const familyAbort = useRef<AbortController | null>(null);
  useEffect(
    () => () => {
      abort.current?.abort();
      rtcAbort.current?.abort();
      routeAbort.current?.abort();
      familyAbort.current?.abort();
    },
    [],
  );
  async function probe() {
    if (running) {
      abort.current?.abort();
      return;
    }
    setRunning(true);
    setProbes({});
    abort.current = new AbortController();
    try {
      const m = await import("../features/connectivity.ts");
      await m.runConnectivityChecks({
        consent: true,
        signal: abort.current.signal,
        onResult: (r) => setProbes((old) => ({ ...old, [r.targetId]: r })),
      });
    } finally {
      setRunning(false);
    }
  }
  async function webRtc() {
    if (rtcBusy) {
      rtcAbort.current?.abort();
      return;
    }
    setRtcBusy(true);
    rtcAbort.current = new AbortController();
    try {
      const m = await import("../features/webrtc.ts");
      setRtc(
        await m.runWebRtcCheck({
          httpIp: selfReport?.info.ip,
          signal: rtcAbort.current.signal,
          iceServers: caps?.stun?.url ? [{ urls: caps.stun.url }] : [],
        }),
      );
    } finally {
      setRtcBusy(false);
    }
  }
  async function route() {
    setRouteBusy(true);
    onAlternate(null);
    const controller = new AbortController();
    routeAbort.current = controller;
    const nodes = caps?.routingNodes || [];
    try {
      const { checkRoutingNodes } = await import("../features/connectivity.ts");
      const options = { consent: true, signal: controller.signal };
      const first = await checkRoutingNodes(nodes, options);
      if (controller.signal.aborted) return;
      setRouting(first);
      if (!selfReport || !nodes.length) return;

      const otherExits = (result: RoutingResult) => [...new Set(result.results.flatMap(row => {
        const address = parseIp(row.observation?.ip);
        return row.status === "observed" && address?.isPublic &&
          address.family === selfReport.info.family && address.canonical !== selfReport.info.ip
          ? [address.canonical] : [];
      }))];
      const candidates = otherExits(first);
      if (candidates.length !== 1) return;
      const repeated = otherExits(await checkRoutingNodes(nodes, options));
      if (!controller.signal.aborted && repeated.length === 1 && repeated[0] === candidates[0])
        onAlternate(candidates[0]);
    } finally {
      setRouteBusy(false);
    }
  }
  async function familyTest() {
    if (familyBusy) return;
    setFamilyBusy(true);
    const controller = new AbortController();
    familyAbort.current = controller;
    const endpoints = caps?.familyEndpoints || {};
    const result: Record<string, { ip?: string }> = {};
    try {
      const m = await import("../features/connectivity.ts");
      for (const [name, url] of Object.entries(endpoints)) {
        if (!url) continue;
        const r = await m.checkRoutingNodes(
          [{ id: name, name, url, family: name === "ipv4" ? 4 : 6 }],
          { consent: true, signal: controller.signal },
        );
        const observed = r.results[0];
        result[name] =
          observed?.status === "observed"
            ? { ip: observed.observation!.ip }
            : {};
      }
      if (!controller.signal.aborted) setFamilies(result);
    } finally {
      setFamilyBusy(false);
    }
  }
  const familyValue = (name: "ipv4" | "ipv6", family: 4 | 6) => {
    const result = families[name];
    const ip = result
      ? result.ip
      : selfReport?.info.family === family
        ? selfReport.info.ip
        : undefined;
    return ip
      ? hidden
        ? "••••••"
        : ip
      : result
        ? t("结果不确定", "Inconclusive")
        : "—";
  };
  const success = Object.values(probes).filter(
    (p) => p.status === "resource-loaded",
  ).length;
  const familyAvailable = Boolean(caps?.familyEndpoints.ipv4 || caps?.familyEndpoints.ipv6);
  const observedFamilies = Object.values(families).filter((result) => result.ip).length;
  const observedNodes = routing?.results.filter((result) => result.status === "observed").length ?? 0;
  const webRtcAvailable = typeof RTCPeerConnection !== "undefined";
  const busy = t("检测中", "Running");
  const waiting = t("待检测", "Ready to check");
  const unavailable = t("暂不可用", "Unavailable");
  const noObservation = t("无有效观测", "No usable observation");
  const checks = [
    { id: "dns", icon: Network, name: t("DNS 解析路径", "DNS resolver path"),
      status: dnsBusy ? busy : dns?.verdict === "unexpected" ? t("疑似泄漏", "Possible leak")
        : dns?.status === "complete" ? t(`观测到 ${dns.resolvers.length} 个解析器`, `${dns.resolvers.length} resolvers observed`)
        : dns?.status === "timeout" ? t("检测超时", "Timed out")
        : dns?.status === "cancelled" ? t("已取消", "Cancelled")
        : dns?.status === "error" ? t("检测失败", "Check failed")
        : dns?.status === "inconclusive" ? noObservation
        : !caps ? t("配置状态未知", "Configuration unknown")
        : !dnsReady || dns?.status === "unavailable" ? unavailable
        : !selfReport ? t("需先检测我的 IP", "Check my IP first") : waiting,
      tone: dns?.verdict === "unexpected" ? "warning" : dns?.status === "complete" ? "observed" : "" },
    { id: "webrtc", icon: Radio, name: t("WebRTC 地址暴露", "WebRTC address exposure"),
      status: rtcBusy ? busy : !webRtcAvailable || rtc?.status === "unsupported" ? unavailable
        : rtc?.status === "error" ? t("检测失败", "Check failed")
        : rtc?.status === "cancelled" ? t("已取消", "Cancelled")
        : rtc?.differentPublicIps.length ? t("观测到不同公网出口", "Different public egress observed")
        : rtc?.mdnsDetected ? t("观察到 mDNS", "mDNS observed")
        : rtc?.candidates.length ? t(`观察到 ${rtc.candidates.length} 个候选`, `${rtc.candidates.length} candidates observed`)
        : rtc ? noObservation : waiting,
      tone: rtc?.differentPublicIps.length ? "warning" : rtc?.candidates.length ? "observed" : "" },
    { id: "dual-stack", icon: Globe2, name: t("IPv4 / IPv6 双栈", "IPv4 / IPv6 dual stack"),
      status: familyBusy ? busy : observedFamilies ? t(`已观测 ${observedFamilies} 个地址族`, `${observedFamilies} families observed`)
        : !familyAvailable ? unavailable : Object.keys(families).length ? noObservation : waiting,
      tone: observedFamilies ? "observed" : "" },
    { id: "routing", icon: ArrowDownUp, name: t("分流与出口", "Routing & egress"),
      status: routeBusy ? busy : (routing?.distinctExitIps.length ?? 0) > 1 ? t("观测到不同公网出口", "Different public egress observed")
        : observedNodes ? t(`已观测 ${observedNodes} 个节点`, `${observedNodes} nodes observed`)
        : !caps?.routingNodes.length ? unavailable : routing ? noObservation : waiting,
      tone: (routing?.distinctExitIps.length ?? 0) > 1 ? "warning" : observedNodes ? "observed" : "" },
    { id: "connectivity", icon: Wifi, name: t("站点 HTTPS 连通性", "Site HTTPS reachability"),
      status: running ? busy : success ? t(`${success} / ${targets.length} 项资源已加载`, `${success} / ${targets.length} resources loaded`)
        : Object.keys(probes).length ? noObservation : t("需同意后运行", "Requires consent"),
      tone: success ? "observed" : "" },
  ];
  return (
    <>
      <section className="connection-checks" id="connection-checks" aria-labelledby="connection-heading">
        <div className="diagnostic-heading">
          <div>
            <h2 id="connection-heading">{t("当前浏览器与连接", "This browser & connection")}</h2>
            <p>{t("以下检查针对你正在使用的浏览器和网络。", "These checks apply to the browser and network you are using.")}</p>
          </div>
        </div>
        <ul className="connection-check-grid">
          {checks.map(({ id, icon: Icon, name, status, tone }) => (
            <li key={id}>
              <a href={`#${id}`} data-tone={tone || undefined}>
                <Icon size={19} aria-hidden="true" />
                <strong>{name}</strong>
                <span><i aria-hidden="true" />{status}</span>
                <ArrowUpRight className="check-arrow" size={15} aria-hidden="true" />
              </a>
            </li>
          ))}
        </ul>
        <LocalChecks lang={lang} hidden={hidden} />
      </section>
      <section id="connectivity" className="panel connectivity-panel">
        <div className="panel-heading">
          <div>
            <div className="eyebrow">
              <Activity size={14} />
              {t("主动检测 · 可控连接", "ON-DEMAND · CONTROLLED CONNECTIONS")}
            </div>
            <h2>
              {t(
                "世界很大，连接看得见。",
                "A world of connections, made visible.",
              )}
            </h2>
            <p>
              {t(
                "国内外站点连通性，一次看清。所有请求都由你的浏览器真实发出。",
                "Check selected sites with real requests from your browser.",
              )}
            </p>
          </div>
          <button
            className={running ? "button secondary" : "button primary"}
            onClick={probe}
          >
            {running ? <Square size={14} /> : <Play size={14} />}{" "}
            {running
              ? t("停止检测", "Stop")
              : t("开始连通性检测", "Check connectivity")}
          </button>
        </div>
        <div className="privacy-notice">
          <LockKeyhole size={15} />
          <span>
            {t(
              "点击开始即会连接以下 8 个第三方站点，它们会看到出口 IP、请求元数据，以及浏览器按策略发送的该站 Cookie。默认不运行，不加载第三方脚本，不上传查询记录。",
              "Starting contacts these 8 sites, which receive your egress IP, request metadata, and any site cookies permitted by your browser. Nothing runs automatically; no third-party scripts or query history are sent.",
            )}
          </span>
        </div>
        <div className="site-grid">
          {targets.map(([id, zh, en, mark, color, region]) => {
            const r = probes[id],
              ok = r?.status === "resource-loaded",
              opaque = r?.status === "opaque-response";
            return (
              <div
                className={
                  "site-card " + (r ? (ok ? "site-ok" : "site-unknown") : "")
                }
                key={id}
              >
                <div className="site-title">
                  <span className="site-icon" style={{ background: color }}>
                    {mark}
                  </span>
                  <strong>{t(zh, en)}</strong>
                  <span className="tiny-tag">
                    {region === "CN" ? t("国内", "CN") : t("国际", "Global")}
                  </span>
                </div>
                <div className="site-measure">
                  <span
                    className={"state-dot " + (ok ? "green" : r ? "amber" : "")}
                  />
                  <span>
                    {ok
                      ? t("资源已加载", "Resource loaded")
                      : opaque
                        ? t("收到不透明响应", "Opaque response")
                        : r
                          ? t("结果不确定", "Inconclusive")
                          : running
                            ? t("检测中", "Checking")
                            : t("等待检测", "Not tested")}
                  </span>
                  {r?.elapsedMs != null ? (
                    <b>
                      {r.elapsedMs}
                      <small> ms</small>
                    </b>
                  ) : running ? (
                    <LoaderCircle className="spin" size={15} />
                  ) : (
                    <b className="muted">—</b>
                  )}
                </div>
                <div className="probe-track">
                  {Array.from({ length: 18 }, (_, i) => (
                    <i
                      key={i}
                      className={r ? (ok ? "good" : "uncertain") : ""}
                    />
                  ))}
                </div>
              </div>
            );
          })}
        </div>
        <div className="panel-foot">
          <span>
            <CircleHelp size={14} />
            {t(
              "耗时是 HTTPS 资源请求时间，受缓存、服务器和网络影响；不是 Ping。失败也不能直接证明封锁。",
              "Duration measures an HTTPS resource request, not ping. Failures do not establish blocking.",
            )}
          </span>
          {Object.keys(probes).length > 0 && (
            <strong>
              {success} / 8 {t("资源已加载", "loaded")}
            </strong>
          )}
        </div>
      </section>
      <div className="two-columns tools-grid">
        <section className="panel tool-panel" id="webrtc">
          <div className="tool-icon blue">
            <Radio size={22} />
          </div>
          <div className="tool-title">
            <h2>WebRTC {t("隐私检测", "privacy")}</h2>
            <span className="badge neutral">
              {caps?.stun?.url
                ? t("自建 STUN", "Self-hosted STUN")
                : t("本地 ICE", "Local ICE")}
            </span>
          </div>
          <p>
            {t(
              "查看浏览器实际暴露的候选地址与 mDNS 隐私保护。无需摄像头或麦克风权限。",
              "Inspect actual ICE candidates and mDNS protection without camera or microphone access.",
            )}
          </p>
          <div className="mini-stats">
            <div>
              <span>{t("浏览器支持", "Browser support")}</span>
              <b>
                {rtc
                  ? rtc.supported
                    ? t("支持", "Supported")
                    : t("不支持", "Unsupported")
                  : t("未检测", "Not tested")}
              </b>
            </div>
            <div>
              <span>mDNS {t("保护", "protection")}</span>
              <b>
                {rtc
                  ? rtc.mdnsDetected
                    ? t("已观察到", "Observed")
                    : t("未观察到", "Not observed")
                  : "—"}
              </b>
            </div>
          </div>
          {rtc && (
            <div className="test-result">
              <p>
                {rtc.message.split(" / ")[lang === "zh" ? 0 : 1] || rtc.message}
              </p>
              {rtc.candidates.map((c, i) => (
                <div className="candidate" key={i}>
                  <span>{c.type}</span>
                  <code>{hidden ? "••••••" : c.address || "unknown"}</code>
                  <small>{c.protocol}</small>
                </div>
              ))}
            </div>
          )}
          <div className="tool-bottom">
            <span>
              <span className={`state-dot ${caps?.stun?.url ? "" : "amber"}`} />
              {!caps
                ? t(
                    "尚未取得服务配置 · 仅检测本地 ICE",
                    "Configuration unavailable · local ICE only",
                  )
                : caps.stun?.url
                  ? t(
                      "已配置自建 STUN · 检测会向该节点发起连接",
                      "Self-hosted STUN configured · the test contacts this node",
                    )
                  : t(
                      "未配置自建 STUN · 公网候选检测受限",
                      "No self-hosted STUN · limited public candidates",
                    )}
            </span>
            <button className="button secondary" onClick={webRtc}>
              {rtcBusy ? <Square size={14} /> : <Play size={14} />}{" "}
              {rtcBusy ? t("停止", "Stop") : t("检测 WebRTC", "Check WebRTC")}
            </button>
          </div>
        </section>
        <section className="panel tool-panel" id="dns">
          <div className="tool-icon purple">
            <Network size={22} />
          </div>
          <div className="tool-title">
            <h2>DNS {t("泄漏检测", "leak test")}</h2>
            <span className="badge muted-badge">
              {!caps
                ? t("配置状态未知", "Configuration unknown")
                : dnsReady
                  ? t("已验证配置", "Verified configuration")
                  : t("暂不可用", "Unavailable")}
            </span>
          </div>
          <p>
            {t(
              "通过独立权威 DNS 观察实际递归解析器，随机测试记录仅在内存中短暂保留。",
              "An independent authoritative DNS service observes actual recursive resolvers using short-lived sessions.",
            )}
          </p>
          {dns ? (
            <div className="test-result">
              <p>
                {dns.message.split(" / ")[lang === "zh" ? 0 : 1] || dns.message}
              </p>
              {dns.resolvers.map((r) => (
                <div className="candidate" key={r.ip}>
                  <code>{hidden ? "••••••" : r.ip}</code>
                  <small>
                    {r.asn ? `AS${r.asn} ${r.organization || ""}` : t("ASN 未知", "ASN unknown")}
                    {r.country && " · " + r.country}
                  </small>
                </div>
              ))}
            </div>
          ) : (
            <div className="not-deployed">
              <LockKeyhole size={26} />
              <strong>
                {dnsBusy
                  ? t("正在观察真实解析请求", "Observing actual DNS requests")
                  : dnsReady
                    ? selfReport ? t("可开始检测", "Ready to check") : t("先检测当前连接", "Check your own connection first")
                    : caps?.dns.configured
                      ? t("DNS 探测服务暂不可用", "DNS probe service is unavailable")
                      : t("尚未接入 DNS 探测服务", "DNS probe service is not connected")}
              </strong>
              <span>
                {dnsProgress
                  ? `${dnsProgress.phase} · ${dnsProgress.completedProbes}/${dnsProgress.totalProbes}`
                  : t(
                      "需要独立权威 DNS 服务才能观测实际解析器。基础 IP 检测可正常使用。",
                      "An independent authoritative DNS service is needed to observe actual resolvers. Core IP analysis remains available.",
                    )}
              </span>
            </div>
          )}
          {dnsReady && selfReport && (
            <label className="dns-expectation">
              {t("预期递归解析器（可选 ASN 或 CIDR）", "Expected recursive resolver (optional ASN or CIDR)")}
              <input value={expected} onChange={event => setExpected(event.target.value)}
                maxLength={512} disabled={dnsBusy} aria-invalid={expectedEntries === null}
                placeholder="AS64500, 192.0.2.0/24" />
              {expectedEntries === null && <span role="status">{t("请输入有效 ASN 或网段。", "Enter a valid ASN or prefix.")}</span>}
            </label>
          )}
          <div className="tool-bottom">
            <span>
              {t(
                "会话仅存内存 · 最长 180 秒",
                "In-memory sessions · at most 180 seconds",
              )}
            </span>
            <button
              className="button secondary"
              disabled={!dnsBusy && (!dnsReady || !selfReport || expectedEntries === null)}
              onClick={() => onDnsTest(expectedEntries ?? [])}
            >
              {dnsBusy
                ? t("取消", "Cancel")
                : dnsReady && selfReport
                  ? t("开始 DNS 检测", "Start DNS test")
                  : t("暂不可检测", "Unavailable")}
            </button>
          </div>
        </section>
      </div>
      <section className="panel" id="routing">
        <div className="panel-heading">
          <div>
            <div className="eyebrow">
              <ArrowDownUp size={14} />
              {t("路由与出口观察", "ROUTING & EGRESS")}
            </div>
            <h2>
              {t(
                "分流测试，依据真实出口。",
                "Split routing, grounded in real egress.",
              )}
            </h2>
            <p>
              {t(
                "只有节点实际返回的 IP 才能用于比较。网站可访问，不等于已知该站看到的出口。",
                "Only an IP returned by a controlled node can establish egress. Reachability alone cannot.",
              )}
            </p>
          </div>
          <button
            className="button secondary"
            disabled={routeBusy}
            onClick={route}
          >
            {routeBusy ? (
              <LoaderCircle className="spin" size={14} />
            ) : (
              <Play size={14} />
            )}{" "}
            {t("检测分流", "Check routing")}
          </button>
        </div>
        <div className="routing-summary">
          <div>
            <span>{t("当前 HTTP 出口", "Current HTTP egress")}</span>
            <code>
              {selfReport
                ? hidden
                  ? "••••••"
                  : selfReport.info.ip
                : t("尚未取得", "Unavailable")}
            </code>
          </div>
          <div>
            <span>{t("受控测试节点", "Controlled nodes")}</span>
            <b>
              {caps?.routingNodes.length || 0}{" "}
              <small>{t("个已配置", "configured")}</small>
            </b>
          </div>
          <div>
            <span>{t("分流结论", "Routing conclusion")}</span>
            <b>
              {routing?.distinctExitIps && routing.distinctExitIps.length > 1
                ? t("观察到不同出口", "Different egress observed")
                : t("无法判断", "Undetermined")}
            </b>
          </div>
        </div>
        {routing && (
          <div className="inline-notice">
            {routing.message.split(" / ")[lang === "zh" ? 0 : 1] ||
              routing.message}
          </div>
        )}
        {routing?.results.map((r) => (
          <div className="routing-node" key={r.nodeId}>
            <strong>{r.name}</strong>
            <code>
              {r.observation
                ? hidden
                  ? "••••••"
                  : r.observation.ip
                : t("未知", "Unknown")}
            </code>
            <span>
              {r.observation?.asn
                ? "AS" + r.observation.asn
                : t("ASN 未知", "ASN unknown")}
            </span>
          </div>
        ))}
        <div
          className="table-wrap"
          tabIndex={0}
          role="region"
          aria-label={t(
            "网站分流观察表，可横向滚动",
            "Site routing observations, horizontally scrollable",
          )}
        >
          <table>
            <thead>
              <tr>
                <th>{t("目标网站", "Website")}</th>
                <th>{t("连通性观察", "Reachability")}</th>
                <th>
                  {t(
                    "该网站观察到的出口 IP",
                    "Egress observed by that website",
                  )}
                </th>
                <th>{t("证据", "Evidence")}</th>
              </tr>
            </thead>
            <tbody>
              {targets.map(([id, zh, en]) => (
                <tr key={id}>
                  <td>
                    <strong>{t(zh, en)}</strong>
                  </td>
                  <td>
                    <span
                      className={
                        "status " +
                        (probes[id]?.status === "resource-loaded"
                          ? "positive"
                          : "subtle")
                      }
                    >
                      {probes[id]?.status === "resource-loaded"
                        ? t("资源已加载", "Resource loaded")
                        : probes[id]
                          ? t("结果不确定", "Inconclusive")
                          : t("未检测", "Not tested")}
                    </span>
                  </td>
                  <td className="muted">{t("未知", "Unknown")}</td>
                  <td className="small muted">
                    {t(
                      "该站未提供已配置的可信出口回显",
                      "No configured, trusted site-specific echo",
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="panel-foot">
          <span>
            <ShieldCheck size={15} />
            {t(
              "不向第三方 IP 查询 API 发送你的地址；不把单一出口复制到所有网站。",
              "Your IP is not submitted to third-party lookup APIs. Egress is never fabricated.",
            )}
          </span>
        </div>
      </section>
      <section className="panel dual-stack" id="dual-stack">
        <div className="panel-heading">
          <div>
            <div className="eyebrow">
              <Globe2 size={14} />
              IPV4 / IPV6
            </div>
            <h2>{t("双栈连接能力", "Dual-stack connectivity")}</h2>
          </div>
          <span className="badge neutral">
            {selfReport
              ? "IPv" + selfReport.info.family
              : t("连接协议未知", "Protocol unknown")}
          </span>
        </div>
        <div className="two-columns">
          <div className="family-card">
            <div>
              <strong>IPv4</strong>
              <span className="badge muted-badge">
                {families.ipv4
                  ? t("已测试", "Tested")
                  : caps?.familyEndpoints.ipv4
                    ? t("待检测", "Ready")
                    : t("专用端点未配置", "Dedicated endpoint missing")}
              </span>
            </div>
            <code>{familyValue("ipv4", 4)}</code>
          </div>
          <div className="family-card">
            <div>
              <strong>IPv6</strong>
              <span className="badge muted-badge">
                {families.ipv6
                  ? t("已测试", "Tested")
                  : caps?.familyEndpoints.ipv6
                    ? t("待检测", "Ready")
                    : t("专用端点未配置", "Dedicated endpoint missing")}
              </span>
            </div>
            <code>{familyValue("ipv6", 6)}</code>
          </div>
        </div>
        <div className="panel-foot">
          <span>
            {t(
              "需要真实 A-only / AAAA-only HTTPS 节点。未检测到另一地址族，不代表你的网络不支持它。",
              "Real A-only / AAAA-only HTTPS nodes are required. An unobserved family is not evidence of unavailability.",
            )}
          </span>
          <button
            className="text-button"
            onClick={familyTest}
            disabled={
              familyBusy ||
              (!caps?.familyEndpoints.ipv4 && !caps?.familyEndpoints.ipv6)
            }
          >
            {t("运行双栈检测", "Run dual-stack test")}
            <ArrowUpRight size={14} />
          </button>
        </div>
      </section>
    </>
  );
}
