import { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowUpRight,
  Check,
  CheckCheck,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Clipboard,
  Code2,
  Database,
  Eye,
  EyeOff,
  FileJson,
  FileText,
  Globe2,
  Info,
  LoaderCircle,
  LockKeyhole,
  Moon,
  Network,
  RefreshCw,
  Search,
  ShieldCheck,
  Sun,
  Trash2,
  X,
} from "lucide-react";
import type {
  Capabilities,
  IpReport,
  LocalizedText,
} from "../shared/contracts.ts";
import { PURITY_TIERS } from "../shared/purity-scale.ts";
import { NetworkTools } from "./components/NetworkTools.tsx";
import { IpDiagnostics } from "./components/IpDiagnostics.tsx";
import { BrandMark } from "./components/BrandMark.tsx";
import { CountryFlag } from "./components/CountryFlag.tsx";
import { indicatorLabel } from "./lib/indicator-label.ts";
import { reportText, reportView, saveJson, savePng } from "./lib/report.ts";
import { apiFetch, assetPath } from "./lib/api.ts";
import type { DnsLeakResult, DnsProgress } from "./features/dns.ts";
type Lang = "zh" | "en";
type Theme = "system" | "light" | "dark";
const networkNames: Record<string, LocalizedText> = {
  residential: { zh: "住宅接入网络", en: "Residential network" },
  hosting: { zh: "数据中心 / 托管", en: "Hosting network" },
  cloud: { zh: "云服务网络", en: "Cloud network" },
  mobile: { zh: "移动网络", en: "Mobile network" },
  business: { zh: "企业网络", en: "Business network" },
  education: { zh: "教育网络", en: "Education network" },
  unknown: { zh: "网络类型待确认", en: "Network type unknown" },
};
const confidenceNames: Record<string, LocalizedText> = {
  high: { zh: "高可信度", en: "High confidence" },
  medium: { zh: "中可信度", en: "Medium confidence" },
  low: { zh: "低可信度", en: "Low confidence" },
  insufficient: { zh: "资料不足", en: "Insufficient data" },
};
const attributeNames: Record<string, LocalizedText> = {
  vpn: { zh: "已知 VPN", en: "Known VPN" },
  tor: { zh: "Tor 出口", en: "Tor exit" },
  proxy: { zh: "代理线索", en: "Proxy evidence" },
  public_proxy: { zh: "公共代理", en: "Public proxy" },
  web_proxy: { zh: "Web 代理", en: "Web proxy" },
  residential_proxy: { zh: "住宅代理", en: "Residential proxy" },
  relay: { zh: "隐私中继", en: "Private relay" },
  crawler: { zh: "爬虫网络", en: "Crawler network" },
};
const readPreference = (key: string, fallback: string) => {
  try {
    return localStorage.getItem(key) || fallback;
  } catch {
    return fallback;
  }
};
const date = (value?: string) =>
  value
    ? new Intl.DateTimeFormat("en-CA", {
        timeZone: "Asia/Shanghai",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
      }).format(new Date(value))
    : "—";
const sourceLabels: Record<string, LocalizedText> = {
  ready: { zh: "有效快照", en: "Valid snapshot" },
  stale: { zh: "数据已过期", en: "Stale data" },
  unavailable: { zh: "未检测", en: "Unavailable" },
  unconfigured: { zh: "未配置", en: "Not configured" },
};
function countryLabel(
  code: string | undefined,
  lang: Lang,
): string | undefined {
  if (!code || !/^[A-Z]{2}$/.test(code)) return code;
  try {
    return new Intl.DisplayNames([lang === "zh" ? "zh-CN" : "en"], {
      type: "region",
    }).of(code);
  } catch {
    return code;
  }
}
const threatCategories = new Set([
  "c2",
  "botnet",
  "malware",
  "phishing",
  "brute_force",
  "web_attack",
  "scanner",
  "spam",
  "other_abuse",
]);
const CHECK_TIMEOUT_MS = 8_000;
export function App() {
  const [lang, setLang] = useState<Lang>(() =>
      readPreference("ruijing-language", "zh") === "en" ? "en" : "zh",
    ),
    [theme, setTheme] = useState<Theme>(() => {
      const v = readPreference("ruijing-theme", "system");
      return v === "dark" || v === "light" ? v : "system";
    });
  const [caps, setCaps] = useState<Capabilities | null>(null),
    [report, setReport] = useState<IpReport | null>(null),
    [input, setInput] = useState(""),
    [hidden, setHidden] = useState(false),
    [loading, setLoading] = useState(true),
    [error, setError] = useState(""),
    [toast, setToast] = useState(""),
    [policy, setPolicy] = useState<string | null>(() =>
      /\/privacy\/?$/.test(location.pathname)
        ? "privacy"
        : /\/methodology\/?$/.test(location.pathname)
          ? "scoring"
          : /\/data-sources\/?$/.test(location.pathname)
            ? "sources"
            : null,
    );
  const [scan, setScan] = useState(0);
  const [dns, setDns] = useState<DnsLeakResult | null>(null);
  const [dnsProgress, setDnsProgress] = useState<DnsProgress | null>(null);
  const [dnsBusy, setDnsBusy] = useState(false);
  const [alternate, setAlternate] = useState<IpReport | null>(null);
  const sequence = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const queriedIp = useRef<string | undefined>(undefined);
  const dnsController = useRef<AbortController | null>(null);
  const alternateController = useRef<AbortController | null>(null);
  const t = (zh: string, en: string) => (lang === "zh" ? zh : en);
  useEffect(() => {
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    try {
      localStorage.setItem("ruijing-language", lang);
    } catch {}
  }, [lang]);
  useEffect(() => {
    const media = matchMedia("(prefers-color-scheme: dark)");
    const apply = () => {
      const active =
        theme === "system" ? (media.matches ? "dark" : "light") : theme;
      document.documentElement.dataset.theme = active;
      const icon = document.querySelector<HTMLLinkElement>("#site-icon");
      if (icon)
        icon.href =
          assetPath(active === "dark" ? "assets/ruijing-icon-white.png" : "assets/ruijing-icon-black.png");
    };
    apply();
    media.addEventListener("change", apply);
    try {
      localStorage.setItem("ruijing-theme", theme);
    } catch {}
    return () => media.removeEventListener("change", apply);
  }, [theme]);
  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(""), 3500);
    return () => clearTimeout(id);
  }, [toast]);
  useEffect(() => {
    const states = new Map<HTMLDetailsElement, boolean>();
    const before = () => {
      for (const el of document.querySelectorAll<HTMLDetailsElement>(
        "details",
      )) {
        states.set(el, el.open);
        el.open = true;
      }
    };
    const after = () => {
      for (const [el, open] of states) el.open = open;
      states.clear();
    };
    addEventListener("beforeprint", before);
    addEventListener("afterprint", after);
    return () => {
      removeEventListener("beforeprint", before);
      removeEventListener("afterprint", after);
    };
  }, []);
  useEffect(() => {
    const capabilityRequest = new AbortController();
    const timeout = setTimeout(() => capabilityRequest.abort(), CHECK_TIMEOUT_MS);
    apiFetch("/api/capabilities", { signal: capabilityRequest.signal })
      .then((r) => {
        if (!r.ok) throw new Error("Capabilities unavailable");
        return r.json();
      })
      .then((value) => {
        if (
          !value ||
          typeof value.datasetVersion !== "string" ||
          !Array.isArray(value.sources) ||
          !Array.isArray(value.routingNodes) ||
          !value.dns ||
          !value.stun ||
          !value.familyEndpoints
        )
          throw new Error("Invalid capabilities");
        if (!capabilityRequest.signal.aborted) setCaps(value);
      })
      .catch(() => {})
      .finally(() => clearTimeout(timeout));
    void query();
    return () => {
      clearTimeout(timeout);
      capabilityRequest.abort();
      ++sequence.current;
      controller.current?.abort();
      dnsController.current?.abort();
      alternateController.current?.abort();
    };
  }, []);
  useEffect(() => {
    if (!policy) return;
    const previous = document.activeElement as HTMLElement | null,
      overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") setPolicy(null);
      if (event.key === "Tab") {
        const elements = [
          ...document.querySelectorAll<HTMLElement>(
            ".policy-modal button:not(:disabled),.policy-modal a[href]",
          ),
        ];
        const first = elements[0],
          last = elements.at(-1);
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("keydown", close);
      document.body.style.overflow = overflow;
      previous?.focus();
    };
  }, [policy]);
  function resetDetection() {
    const id = ++sequence.current;
    controller.current?.abort();
    dnsController.current?.abort();
    alternateController.current?.abort();
    controller.current = null;
    queriedIp.current = undefined;
    dnsController.current = null;
    alternateController.current = null;
    setScan(id);
    setDns(null);
    setDnsBusy(false);
    setDnsProgress(null);
    setAlternate(null);
    setReport(null);
    setError("");
    return id;
  }
  function clearDetection() {
    resetDetection();
    setInput("");
    setLoading(false);
    setToast(t("已清除本次检测", "Current checks cleared"));
  }
  async function query(ip?: string) {
    const id = resetDetection();
    const ac = new AbortController();
    controller.current = ac;
    queriedIp.current = ip;
    setLoading(true);
    const timeout = setTimeout(() => {
      if (id !== sequence.current || ac.signal.aborted) return;
      ac.abort();
      setError("检测连接超时，请重试。 / The check timed out. Please retry.");
      setLoading(false);
    }, CHECK_TIMEOUT_MS);
    try {
      const r = await apiFetch(ip ? "/api/lookup" : "/api/self", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(ip ? { ip } : {}),
        cache: "no-store",
        signal: ac.signal,
      });
      const body = await r.json().catch(() => null);
      if (!r.ok) throw new Error(body?.message || (r.status === 429
        ? t("检测请求过多，请稍后重试", "Too many checks. Try again shortly.")
        : t("检测服务暂不可用，请稍后重试", "The assessment service is temporarily unavailable.")));
      if (id === sequence.current && !ac.signal.aborted) {
        if (body?.mode !== (ip ? "lookup" : "self") || !body.info || !body.assessment)
          throw new Error(t("检测响应无效", "Invalid report response"));
        setReport(body);
      }
    } catch (e) {
      if (!ac.signal.aborted && id === sequence.current) {
        setError(
          e instanceof Error && !(e instanceof TypeError) ? e.message : t("暂时无法连接检测服务", "Could not reach the assessment service"),
        );
        setReport(null);
      }
    } finally {
      clearTimeout(timeout);
      if (id === sequence.current) {
        controller.current = null;
        setLoading(false);
      }
    }
  }
  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setToast(t("已复制到剪贴板", "Copied to clipboard"));
    } catch {
      setToast(t("浏览器未允许访问剪贴板", "Clipboard permission unavailable"));
    }
  }
  const self = report?.mode === "self" ? report : null;
  const dnsReady = Boolean(caps?.dns.configured && caps.dns.status === "ready");
  const a = report?.assessment;
  const view = report && reportView(report, lang, {
    hidden, dns, dnsReady, alternate,
    timezone: self ? Intl.DateTimeFormat().resolvedOptions().timeZone : undefined,
  });
  const purity = view?.score ?? null;

  async function dnsTest(expected: string[]) {
    if (dnsBusy) {
      dnsController.current?.abort();
      return;
    }
    if (!self || !dnsReady) return;
    const id = sequence.current;
    const ac = new AbortController();
    dnsController.current = ac;
    setDnsBusy(true);
    setDns(null);
    setDnsProgress(null);
    try {
      const { runDnsLeakTest } = await import("./features/dns.ts");
      const result = await runDnsLeakTest({
        expected, signal: ac.signal,
        onProgress: progress => { if (sequence.current === id) setDnsProgress(progress); },
      });
      if (sequence.current === id) setDns(result.status === "cancelled" ? { ...result, resolvers: [] } : result);
    } finally {
      if (sequence.current === id) setDnsBusy(false);
    }
  }

  async function confirmAlternate(ip: string | null, id: number) {
    if (!self || id !== sequence.current) return;
    alternateController.current?.abort();
    const ac = new AbortController();
    alternateController.current = ac;
    setAlternate(null);
    if (!ip) return;
    try {
      const response = await apiFetch("/api/lookup", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }), signal: ac.signal,
      });
      if (!response.ok) return;
      const result: IpReport = await response.json();
      if (id === sequence.current && !ac.signal.aborted && result.mode === "lookup" && result.info.ip === ip)
        setAlternate(result);
    } catch {
      // A failed enrichment is not a location observation.
    }
  }
  const manualLoading = loading && queriedIp.current !== undefined;
  const visibleIp = report
    ? hidden
      ? "•••• · •••• · ••••"
      : report.info.ip
    : loading
      ? t("正在读取连接…", "Reading connection…")
      : error ? t("未获取检测结果", "No check result") : t("等待公网 IP", "Awaiting a public IP");
  const country =
    report?.info.country || countryLabel(report?.info.countryCode, lang);
  const sources = a?.sources || caps?.sources || [];
  const effectiveSources = sources.filter(source => source.state === "ready" &&
    (!report || source.families.includes(report.info.family))).length;
  const checkedIndicators = a?.indicators.filter(i => ["detected", "not_found", "conflict"].includes(i.state)).length || 0;
  return (
    <>
      <a href="#main" className="skip-link">
        {t("跳至主内容", "Skip to content")}
      </a>
      <header className="site-header" inert={Boolean(policy)}>
        <div className="header-inner">
          <a className="brand" href="#" aria-label="瑞镜 IP 首页">
            <BrandMark className="brand-mark" />
            <span>
              瑞镜<span className="brand-ip"> IP</span>
              <small>RUIJING</small>
            </span>
          </a>
          <nav aria-label={t("主导航", "Main navigation")}>
            <a href="#main" className="nav-active">
              {t("IP 总览", "Overview")}
            </a>
            <a href="#report">{t("检测报告", "Detection report")}</a>
            <a href="#connection-checks">{t("网络工具", "Network tools")}</a>
            <button onClick={() => setPolicy("scoring")}>
              {t("评分原理", "Methodology")}
              <ArrowUpRight size={12} />
            </button>
          </nav>
          <div className="header-actions">
            <span className="privacy-chip">
              <span className="state-dot green" />
              {t("隐私优先", "Privacy first")}
            </span>
            <button
              className="icon-button language-button"
              onClick={() => setLang(lang === "zh" ? "en" : "zh")}
              aria-label={t("Switch to English", "切换到中文")}
            >
              <Globe2 size={16} />
              <span>{lang === "zh" ? "EN" : "中文"}</span>
            </button>
            <button
              className="icon-button"
              onClick={() =>
                setTheme(
                  theme === "system"
                    ? "dark"
                    : theme === "dark"
                      ? "light"
                      : "system",
                )
              }
              aria-label={t("切换主题", "Switch theme")}
              title={`${t("主题", "Theme")}: ${theme}`}
            >
              {theme === "dark" ? (
                <Moon size={17} />
              ) : theme === "light" ? (
                <Sun size={17} />
              ) : (
                <span className="theme-system" />
              )}
            </button>
          </div>
        </div>
      </header>
      <main className="shell" id="main" inert={Boolean(policy)} data-redacted={hidden || undefined}>
        <section className="intro result-intro">
          <div>
            <h1>{t("看清连接", "See your connection")}</h1>
            <p>{t("公网 IP、纯净值与网络隐私检测。", "Public IP, purity score and network privacy checks.")}</p>
          </div>
          <aside className="privacy-promise" aria-label={t("瑞镜隐私承诺", "Ruijing privacy pledge")}>
            <LockKeyhole size={20} aria-hidden="true" />
            <div>
              <strong>{t("每个人都应该享有隐私权", "Everyone deserves the right to privacy")}</strong>
              <span>{t("瑞镜不会保存你的 IP 查询历史或检测报告。", "Ruijing never stores your IP lookup history or reports.")}</span>
            </div>
            <button type="button" className="text-button" onClick={() => setPolicy("privacy")}>
              {t("隐私说明", "Privacy details")}<ArrowUpRight size={13} aria-hidden="true" />
            </button>
          </aside>
        </section>
        <form
          className="search-bar"
          onSubmit={(event) => {
            event.preventDefault();
            if (input.trim()) void query(input.trim());
          }}
        >
          <div className="search-field">
            <Search size={19} />
            <input
              aria-label={t("查询公网 IP", "Public IP to query")}
              type={hidden ? "password" : "text"}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={t(
                "输入任意公网 IPv4 或 IPv6 地址",
                "Enter a public IPv4 or IPv6 address",
              )}
              autoComplete="off"
              spellCheck={false}
            />
            <kbd>IPv4 / IPv6</kbd>
          </div>
          <button
            type="submit"
            className="button primary"
            disabled={manualLoading || !input.trim()}
          >
            {manualLoading ? (
              <LoaderCircle className="spin" size={15} />
            ) : (
              <Search size={15} />
            )}{" "}
            {t("查询 IP", "Analyze IP")}
          </button>
          <button
            type="button"
            className="button search-self"
            disabled={loading}
            onClick={() => {
              setInput("");
              void query();
            }}
          >
            {t("检测我的 IP", "Check my IP")}
          </button>
        </form>
        {error && (
          <div className="api-notice">
            <Info size={18} aria-hidden="true" />
            <div>
              <div role="status">
                <strong>{caps?.development ? t("本地预览模式", "Local preview mode") : t("检测未完成", "Check incomplete")}</strong>
                <p>{error.includes(" / ") ? error.split(" / ")[lang === "zh" ? 0 : 1] : error}</p>
                {caps?.development && <span>{t("可直接输入公网 IP，使用已构建的真实离线情报进行分析。", "Enter a public IP above to analyze it using the real offline snapshots.")}</span>}
              </div>
              {!caps?.development && (
                <button type="button" className="text-button" onClick={() => void query(queriedIp.current)}>
                  <RefreshCw size={14} aria-hidden="true" />{t("重试检测", "Retry check")}
                </button>
              )}
            </div>
          </div>
        )}
        <section className="panel result-identity" aria-label={t("公网 IP", "Public IP")}>
          <div className="result-identity-main">
            <span className="eyebrow"><Globe2 size={15} />{report?.mode === "lookup" ? t("查询结果", "IP lookup") : t("当前连接", "Current connection")}</span>
            <div className="ip-address">{visibleIp}</div>
          </div>
          <div className="ip-facts">
            {report && <span className="result-family">IPv{report.info.family}</span>}
            {report?.info.city && <span>{report.info.city}</span>}
            <CountryFlag code={report?.info.countryCode} name={country} />
          </div>
          <div className="card-controls">
            <button className="icon-button result-self" disabled={loading}
              aria-label={t("检测我的 IP", "Check my IP")} onClick={() => { setInput(""); void query(); }}><RefreshCw size={16} /></button>
            <button className="icon-button" onClick={() => setHidden(!hidden)}
              aria-label={hidden ? t("显示 IP", "Show IP") : t("隐藏 IP", "Hide IP")}>
              {hidden ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
            <button className="icon-button" disabled={!report || hidden}
              aria-label={t("复制 IP", "Copy IP")}
              onClick={() => report && void copy(report.info.ip)}><Clipboard size={16} /></button>
          </div>
        </section>
        <section className="panel purity-panel" data-risk={view?.riskTier ?? undefined} data-provisional={view?.provisional || undefined} aria-label={t("IP 纯净值", "IP purity score")} aria-busy={loading}>
          <div className="purity-primary">
            <div className="eyebrow"><ShieldCheck size={17} />{t("IP 纯净值", "IP purity score")}</div>
            <div className="purity-number"><strong>{purity ?? "—"}</strong><span>/ 100</span></div>
          </div>
          <div className="purity-meta">
            <strong className="purity-grade">{loading ? t("正在检测", "Checking") : view?.scoreState ?? (error ? t("检测未完成", "Check incomplete") : t("等待检测", "Awaiting a check"))}</strong>
            {!!view?.scoreDeductions.length && <ul className="purity-deductions">
              {view.scoreDeductions.map(deduction => <li key={deduction}>{deduction}</li>)}
            </ul>}
            <div className="purity-track" aria-hidden="true"><i style={{ width: purity === null ? "0%" : purity + "%" }} /></div>
          </div>
        </section>
        <section className="panel detection-report" id="report" aria-labelledby="detection-heading" aria-busy={loading}>
          <h2 id="detection-heading">{t("检测报告", "Detection report")}</h2>
          {view ? <>
            <p className="report-lead"><strong>{view.location}</strong> {view.judgment}</p>
            <dl className="report-findings">
              {view.rows.map(row => <div key={row.label} className={row.tone}>
                <dt><Info size={15} />{row.label}</dt><dd>{row.value}</dd>
              </div>)}
            </dl>
          </> : <p className="report-lead">{loading ? t("正在读取可用信号。", "Reading available signals.") : t("输入公网 IPv4 或 IPv6，或检测当前连接。", "Enter a public IPv4 or IPv6 address or check your current connection.")}</p>}
          {view && <div className="report-footer">
            <div className="report-actions">
              <a href="#evidence">{t("查看证据与评分明细", "Evidence and score details")}</a>
              {self && dnsReady && <a href="#dns">{t(dnsBusy ? "查看 DNS 检测进度" : "运行 DNS 检测", dnsBusy ? "View DNS progress" : "Run DNS check")}</a>}
            </div>
            <div className="export-group">
              <button className="icon-button" disabled={!view} aria-label={t("复制摘要", "Copy summary")}
                onClick={() => report && view && void copy(reportText(report, view))}><Clipboard size={16} /></button>
              <button className="icon-button" disabled={!view} aria-label="JSON"
                onClick={() => report && view && saveJson(report, view, hidden)}><FileJson size={16} /></button>
              <button className="icon-button" disabled={!view} aria-label="PNG"
                onClick={() => report && view && savePng(report, view)}><ArrowDownToLine size={16} /></button>
              <button className="button secondary" disabled={!view} onClick={() => window.print()}><FileText size={15} /> PDF</button>
            </div>
          </div>}
        </section>
        <div className="detection-session">
          <button type="button" className="text-button" onClick={clearDetection}>
            <Trash2 size={15} aria-hidden="true" />{t("清除本次检测", "Clear current checks")}
          </button>
        </div>
        {report && view && <IpDiagnostics report={report} lang={lang} country={country}
          network={view.network} hidden={hidden} />}
        <section className="panel report-panel" id="evidence">
          <div className="panel-heading">
            <div>
              <h2>{t("证据与评分明细", "Evidence and scoring")}</h2>
              <p>{t("核对来源、命中记录和覆盖范围。", "Review sources, observed records and coverage.")}</p>
            </div>
            <button className="button secondary" onClick={() => setPolicy("scoring")}>{t("了解评分规则", "Scoring methodology")}</button>
          </div>
          {a && <div className="coverage-strip"><span><CheckCheck size={15} />{t("已有查询结果", "Checks with results")} <b>{checkedIndicators} / {a.indicators.length}</b></span><span>{t("其余项目会说明缺少来源、过期或读取失败的原因。未发现记录不等于确认安全。", "Other checks explain missing coverage, stale data or unavailable sources. No match does not establish safety.")}</span></div>}
          <div className="report-layout">
            <div className="indicator-list">
              {a?.indicators.length ? (
                a.indicators.map((item) => (
                  <details className="indicator" key={item.id}>
                    <summary>
                      <span className="indicator-icon">
                        {item.state === "detected" ? (
                          <Activity size={15} />
                        ) : item.state === "unknown" ? (
                          <CircleHelp size={15} />
                        ) : (
                          <ShieldCheck size={15} />
                        )}
                      </span>
                      <span>{item.label[lang]}</span>
                      <span
                        className={
                          "indicator-state " +
                          (item.state === "detected"
                            ? item.id === "ownership_consistency"
                              ? "consistent"
                              : "hit"
                            : "")
                        }
                      >
                        {indicatorLabel(item, lang)}
                        <ChevronDown size={13} />
                      </span>
                    </summary>
                    <div className="indicator-detail">
                      {item.description[lang]}
                      {!!item.coverage?.sourceIds.length && <small>{t("覆盖来源", "Coverage sources")}: {item.coverage.sourceIds.map(id => a.sources.find(s => s.id === id)?.name || id).join(" · ")}</small>}
                      {item.evidenceIds.length > 0 && (
                        <small>
                          {t("证据", "Evidence")}: {item.evidenceIds.join(", ")}
                        </small>
                      )}
                    </div>
                  </details>
                ))
              ) : (
                <div className="empty-report">
                  <span className="empty-report-icon">
                    <ShieldCheck size={32} />
                  </span>
                  <h3>
                    {t(
                      "一份可解释的报告，从真实 IP 开始",
                      "An explainable report starts with a real IP",
                    )}
                  </h3>
                  <p>
                    {t(
                      "检测后查看机房、VPN、Tor、代理、威胁情报与来源一致性等 12 项指标。",
                      "Analyze an IP to view 12 indicators covering hosting, VPN, Tor, proxies, threats and source consistency.",
                    )}
                  </p>
                  <a href="#main" className="text-button">
                    {t("输入 IP 开始分析", "Enter an IP to begin")}
                  </a>
                </div>
              )}
            </div>
            <aside className="scoring-breakdown">
              <div className="breakdown-title">
                <h3>
                  {t("这个数字如何得出？", "How is the index calculated?")}
                </h3>
                <Code2 size={16} />
              </div>
              <div className="baseline-row">
                <span>{t("零分起点 · 仅按证据加分", "Start at zero · add only evidence")}</span>
                <b>0</b>
              </div>
              {a?.scoreDetails
                .filter((r) => r.ruleId !== "zero-baseline")
                .map((r, i) => (
                  <details className="adjustment" key={r.ruleId + ":" + i}>
                    <summary>
                      <span>{r.label[lang]}</span>
                      <b>
                        {r.amount >= 0 ? "+" : ""}
                        {Number(r.amount.toFixed(2))}
                      </b>
                    </summary>
                    <p>{r.explanation[lang]}</p>
                  </details>
                ))}
              {!a && (
                <p className="breakdown-placeholder">
                  {t(
                    "暂无有效证据参与计算。来源不可用或缺少数据，不会被写成检测通过。",
                    "No valid evidence has been evaluated. Missing data is never presented as a passed check.",
                  )}
                </p>
              )}
              <div className="breakdown-total">
                <span>{t("风险参考指数", "Risk reference index")}</span>
                <strong>
                  {a?.riskScore ?? "—"}
                  <small> / 100</small>
                </strong>
              </div>
              {view && <p className="breakdown-placeholder">{t("风险证据可信度", "Risk evidence confidence")} · {view.riskEvidenceConfidence}</p>}
              <div className="breakdown-note">
                <Info size={14} />
                <p>
                  {t(
                    "使用住宅网络不自动减分；VPN、Tor 和机房属性本身不证明恶意。重复来源不能无限加分。",
                    "Residential networks earn no automatic safety credit. VPN, Tor and hosting do not establish abuse. Duplicated sources cannot inflate the index.",
                  )}
                </p>
              </div>
              <button
                className="text-button"
                onClick={() => setPolicy("scoring")}
              >
                {t("查看公开评分规则", "Read the scoring methodology")}
                <ArrowUpRight size={14} />
              </button>
            </aside>
          </div>
          {a?.evidence.length ? (
            <div className="evidence-section">
              <h3>
                {t("匹配证据", "Matched evidence")}
                <span className="tiny-tag">{a.evidence.length}</span>
              </h3>
              {a.evidence.map((e) => (
                <details className="evidence-item" key={e.id}>
                  <summary>
                    <span className="badge neutral">{e.category}</span>
                    <strong>{e.sourceName}</strong>
                    <span className="evidence-status" data-state={e.evaluation ?? (e.stale ? "stale" : undefined)}>
                      {e.stale
                        ? t("已过期", "Stale")
                        : e.evaluation === "valid" ? t("有效", "Valid")
                        : e.evaluation === "invalid" ? t("未通过校验", "Unverified")
                        : t("状态未知", "Unknown")}
                    </span>
                    <ChevronDown size={14} />
                  </summary>
                  <div>
                    <p>{e.description[lang]}</p>
                    <dl>
                      <dt>{t("匹配范围", "Matched range")}</dt>
                      <dd>
                        {hidden
                          ? "••••••"
                          : e.matchedRangeLabel ||
                            e.matchedRange ||
                            t("未提供", "Not provided")}
                      </dd>
                      <dt>{t("来源可信程度", "Source confidence")}</dt>
                      <dd>{e.confidence}</dd>
                      <dt>{t("快照时间", "Snapshot date")}</dt>
                      <dd>{date(e.publishedAt || e.fetchedAt)}</dd>
                      {threatCategories.has(e.category) && <>
                        <dt>{t("活动时间", "Activity date")}</dt>
                        <dd>{e.observedAt ? date(e.observedAt) : t("来源未提供", "Not supplied")}</dd>
                      </>}
                      {e.expiresAt && <>
                        <dt>{t("来源到期时间", "Source expires")}</dt>
                        <dd>{date(e.expiresAt)}</dd>
                      </>}
                    </dl>
                    <a
                      href={e.sourceUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-button"
                    >
                      {t("查看来源说明", "Source information")}
                      <ArrowUpRight size={13} />
                    </a>
                  </div>
                </details>
              ))}
            </div>
          ) : null}
        </section>
        <div className="two-columns context-grid">
          <section className="panel context-panel">
            <div className="eyebrow">
              <Network size={14} />
              {t("网络属性", "NETWORK CLASSIFICATION")}
            </div>
            <h2>
              {t("住宅、机房，还是代理？", "Residential, hosting, or proxy?")}
            </h2>
            <div className="classification-main">
              <span className="classification-icon">
                <Network size={27} />
              </span>
              <div>
                <strong>
                  {view?.network ?? networkNames.unknown[lang]}
                </strong>
                <span>
                  {report?.info.attributes.length
                    ? report.info.attributes
                        .map((at) => attributeNames[at]?.[lang] || at)
                        .join(" · ")
                    : t(
                        "没有足够证据确认代理类型",
                        "Insufficient evidence to identify proxy type",
                      )}
                </span>
              </div>
            </div>
            <div className="context-note">
              {t(
                "住宅 IP ≠ 住宅代理 IP。混合用途 ASN 不能单独证明具体地址的用途；没有住宅代理情报时诚实显示未知。",
                "Residential IP ≠ residential proxy. A mixed-use ASN alone cannot establish an address’s purpose.",
              )}
            </div>
            <div className="mini-stats">
              <div>
                <span>{t("住宅代理情报", "Residential proxy")}</span>
                <b>
                  {indicatorLabel(a?.indicators.find(i => i.id === "residential_proxy"), lang)}
                </b>
              </div>
              <div>
                <span>{t("代理供应商 / 历史", "Provider / history")}</span>
                <b>{t("无可验证数据", "No verifiable data")}</b>
              </div>
            </div>
            {!!report?.provenance?.conflicts.length && (
              <p className="inline-notice">{t("边缘与离线来源存在分歧。", "Edge and offline sources disagree.")}
                {" "}{report.provenance.offline.countryCode} {report.provenance.offline.asn && "AS" + report.provenance.offline.asn}
              </p>
            )}
            <div className="classification-checks">{["datacenter", "proxy", "public_proxy", "vpn", "tor"].map(id => { const item = a?.indicators.find(i => i.id === id); return item ? <details key={id}><summary><span>{item.label[lang]}</span><b>{indicatorLabel(item, lang)}</b><ChevronDown size={13} /></summary><p>{item.description[lang]}</p></details> : null; })}</div>
          </section>
          <section className="panel context-panel">
            <div className="eyebrow">
              <Globe2 size={14} />
              {t("地理与网络归属", "LOCATION & NETWORK OWNERSHIP")}
            </div>
            <h2>
              {t(
                "位置是推测，来源要清楚。",
                "An estimate, with a clear source.",
              )}
            </h2>
            <CountryFlag code={report?.info.countryCode} name={country} />
            <dl className="geo-details">
              <dt>{t("国家 / 地区", "Country / region")}</dt>
              <dd>{country || t("未知", "Unknown")}</dd>
              <dt>{t("国家 / 地区代码", "Country / region code")}</dt><dd>{report?.info.countryCode || "—"}</dd>
              <dt>{t("省州 · 城市", "State · city")}</dt>
              <dd>
                {[report?.info.region, report?.info.city]
                  .filter(Boolean)
                  .join(" · ") || t("未知", "Unknown")}
              </dd>
              <dt>{t("纬度（估算）", "Estimated latitude")}</dt><dd>{report?.info.latitude !== undefined ? `${report.info.latitude.toFixed(4)}°` : t("来源未提供", "Not supplied")}</dd>
              <dt>{t("经度（估算）", "Estimated longitude")}</dt><dd>{report?.info.longitude !== undefined ? `${report.info.longitude.toFixed(4)}°` : t("来源未提供", "Not supplied")}</dd>
              <dt>{t("邮政编码", "Postal code")}</dt><dd>{report?.info.postalCode || (report?.info.geoSource === "DB-IP City Lite" ? t("当前离线库不提供邮编", "Not included in this Lite database") : t("来源未提供", "Not supplied"))}</dd>
              <dt>{t("时区", "Time zone")}</dt><dd>{report?.info.timezone || t("来源未提供", "Not supplied")}</dd>
              <dt>{t("ASN 组织", "ASN organization")}</dt>
              <dd>{report?.info.asOrganization || t("未知", "Unknown")}</dd>
              <dt>{t("归属覆盖范围", "Attribution range")}</dt>
              <dd>
                {report?.info.network
                  ? hidden
                    ? "••••••"
                    : report.info.network
                  : t("未知", "Unknown")}
              </dd>
              <dt>{t("实际接入 ISP", "Actual access ISP")}</dt>
              <dd>
                {report?.info.isp ||
                  t(
                    "未知，不能等同于 ASN 组织",
                    "Unknown; not interchangeable with ASN",
                  )}
              </dd>
              <dt>{t("地理来源", "Geolocation source")}</dt>
              <dd>
                {report?.info.geoSource ||
                  t("未获得有效地理数据", "No valid geolocation data")}
              </dd>
              <dt>{t("地理数据日期", "Geolocation date")}</dt><dd>{report?.info.geoUpdatedAt ? date(report.info.geoUpdatedAt) : t("来源未给出版本日期", "Provider supplied no version date")}</dd>
            </dl>
            <p className="location-limit">{t("坐标表示数据库估算的 IP 所在区域，不是设备 GPS。城市不能唯一确定邮编；缺失字段不从其他地区记录拼凑。", "Coordinates estimate the IP area, not device GPS. Cities do not uniquely determine postcodes; missing fields are not borrowed from other location records.")}</p>
            <a
              className="attribution"
              href="https://db-ip.com/"
              target="_blank"
              rel="noopener noreferrer"
            >
              {t("地理数据使用时署名", "Geolocation attribution")}: DB-IP Lite ·
              CC BY 4.0
              <ArrowUpRight size={11} />
            </a>
          </section>
        </div>
        <NetworkTools
          lang={lang}
          caps={caps}
          key={scan}
          report={self}
          hidden={hidden}
          dns={dns}
          dnsProgress={dnsProgress}
          dnsBusy={dnsBusy}
          dnsReady={dnsReady}
          onDnsTest={dnsTest}
          onAlternate={ip => void confirmAlternate(ip, scan)}
        />
        <section className="panel sources-panel" id="sources">
          <div className="panel-heading">
            <div>
              <div className="eyebrow">
                <Database size={14} />
                {t("透明情报", "TRANSPARENT INTELLIGENCE")}
              </div>
              <h2>
                {t(
                  "你看到的每个结论，都有来处。",
                  "Every signal has a source.",
                )}
              </h2>
              <p>
                {t(
                  "只查询服务器中的合法公开快照。来源缺失、过期或不支持当前地址族时，会如实标注。",
                  "Queries use lawful snapshots on this server. Missing, stale and unsupported sources are identified.",
                )}
              </p>
            </div>
            <span className="badge neutral">
              {effectiveSources} {t("个有效来源", "valid sources")}
            </span>
          </div>
          <div className="source-grid">
            {sources.map((source) => (
              <div className="source-card" key={source.id}>
                <div>
                  <strong>{source.name}</strong>
                  <a
                    href={source.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label={source.name}
                  >
                    <ArrowUpRight size={14} />
                  </a>
                </div>
                <span
                  className={
                    "source-state " + (source.state === "ready" ? "ready" : "")
                  }
                >
                  <span
                    className={
                      "state-dot " +
                      (source.state === "ready"
                        ? "green"
                        : source.state === "stale"
                          ? "amber"
                          : "")
                    }
                  />
                  {sourceLabels[source.state]?.[lang]}
                </span>
                <small>
                  {source.families.map((f) => "IPv" + f).join(" · ")}
                  <span>{date(source.publishedAt || source.fetchedAt)}</span>
                </small>
                <small>{source.license}</small>
                <div className="source-match"><span>{t("本次查询", "This lookup")}</span><b>{!report ? t("等待查询", "Awaiting lookup") : !source.families.includes(report.info.family) ? t("地址族未覆盖", "Family not covered") : source.state !== "ready" ? t("未有效检测", "Not checked") : source.matched === true ? t("有记录命中", "Record matched") : source.matched === false ? t("未发现记录", "No match") : t("未检测", "Not checked")}</b></div>
                <small className="source-categories">{source.categories.join(" · ")}</small>
              </div>
            ))}
          </div>
          <div className="panel-foot">
            <span>
              {a?.coverage.note[lang] ||
                t(
                  "检查进度不等于全网覆盖率；未命中不代表安全。",
                  "Check completion is not global coverage. A missing match does not establish safety.",
                )}
            </span>
            <button
              className="text-button"
              onClick={() => setPolicy("sources")}
            >
              {t("数据与许可说明", "Data & licensing")}
              <ArrowUpRight size={13} />
            </button>
          </div>
        </section>
        <div className="report-provenance">
          <span>
            {t("分析模型", "Model")}:{" "}
            {a?.modelVersion || "—"} ·{" "}
            {t("数据版本", "Dataset")}:{" "}
            {a?.datasetVersion || caps?.datasetVersion || "unconfigured"}{caps?.builtAt && ` · ${date(caps.builtAt)}`}
          </span>
          <span>
            {report
              ? t("本次报告生成于", "Report generated") +
                ": " +
                new Date(report.generatedAt).toISOString()
              : t("尚未生成检测报告", "No assessment report generated")}
          </span>
        </div>
        <div className="trust-strip">
          <div>
            <LockKeyhole size={19} />
            <span>
              <strong>{t("隐私是默认选项", "Private by default")}</strong>
              <small>
                {t("不设账号，不存查询历史", "No accounts or query history")}
              </small>
            </span>
          </div>
          <div>
            <Code2 size={19} />
            <span>
              <strong>
                {t("独立、可解释的规则", "Independent, explainable rules")}
              </strong>
              <small>
                {t(
                  "不复制商业平台的专有评分",
                  "No repackaged proprietary scores",
                )}
              </small>
            </span>
          </div>
          <div>
            <ShieldCheck size={19} />
            <span>
              <strong>
                {t("不知道，就说不知道", "Unknown means unknown")}
              </strong>
              <small>
                {t(
                  "不伪造检测成功或情报数据",
                  "No fabricated evidence or passed checks",
                )}
              </small>
            </span>
          </div>
        </div>
      </main>
      <footer className="site-footer" inert={Boolean(policy)}>
        <div>
          <span className="footer-brand">
            瑞镜 IP <small>RUIJING</small>
          </span>
          <span>
            {t(
              "让连接更透明，让隐私有依据。",
              "Clarity for your connection. Evidence for your privacy.",
            )}
          </span>
        </div>
        <div>
          <button onClick={() => setPolicy("privacy")}>
            {t("隐私政策", "Privacy")}
          </button>
          <button onClick={() => setPolicy("scoring")}>
            {t("评分规则", "Scoring")}
          </button>
          <button onClick={() => setPolicy("sources")}>
            {t("数据来源", "Sources")}
          </button>
          <a href="https://github.com/bcatruirui/ruijing/issues" target="_blank" rel="noopener noreferrer">
            {t("问题反馈", "Report an issue")}
          </a>
          <span>
            {a?.modelVersion || "ruijing-v1"} ·{" "}
            {caps?.development
              ? t("本地预览", "Local preview")
              : t("免费运行", "Free to use")}
          </span>
        </div>
      </footer>
      {toast && (
        <div className="toast" role="status">
          <Check size={16} />
          {toast}
        </div>
      )}
      {policy && (
        <div className="modal-backdrop" onClick={() => setPolicy(null)}>
          <section
            role="dialog"
            aria-modal="true"
            aria-label={
              policy === "privacy"
                ? t("隐私政策", "Privacy policy")
                : t("评分与数据说明", "Methodology and data")
            }
            className="policy-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              className="icon-button modal-close"
              aria-label={t("关闭", "Close")}
              onClick={() => setPolicy(null)}
              autoFocus
            >
              <X size={20} />
            </button>
            <span className="eyebrow">RUIJING · OPEN BY DESIGN</span>
            <h2>
              {policy === "privacy"
                ? t("每个人都应该享有隐私权", "Everyone deserves the right to privacy")
                : policy === "scoring"
                  ? t("IP 纯净值评分规则", "IP purity scoring")
                  : t("公开数据，明确边界。", "Open data, explicit limits.")}
            </h2>
            {policy === "privacy" ? (
              <>
                <p>
                  {t(
                    "瑞镜不会保存你的 IP 查询历史或检测报告。本站不设账号，不生成浏览器指纹，不加载广告或追踪脚本。IP 查询由本站离线情报完成。",
                    "Ruijing never stores your IP lookup history or reports. The site has no accounts, browser fingerprinting, ads, or tracking scripts. Lookups use offline intelligence.",
                  )}
                </p>
                <p>
                  {t(
                    "检测结果存在当前页面内存，可随时清除。浏览器隐私信号和网段验证均在本地处理。主题和语言偏好保存在浏览器本地。你主动运行站点连通性检测时，所选站点会收到出口 IP 和请求元数据。",
                    "Results stay in page memory until you clear them or leave. Browser privacy signals and subnet validation are processed locally. Theme and language preferences persist in your browser. If you opt into site reachability checks, the selected sites receive your egress IP and request metadata.",
                  )}
                </p>
                <p>
                  {t(
                    "主动发起的 DNS 会话最多在探测服务内存中保留 180 秒。限流使用临时内存计数。GitHub Pages 会出于安全目的记录连接 IP，Cloudflare 等基础设施也可能依各自政策处理连接元数据。",
                    "Opt-in DNS sessions are held in probe-service memory for up to 180 seconds. Rate limiting uses temporary in-memory counters. GitHub Pages logs connection IP addresses for security. Cloudflare and other infrastructure providers may process connection metadata under their own policies.",
                  )}
                </p>
              </>
            ) : policy === "scoring" ? (
              <>
                <p>
                  {t(
                    "每次完成检测都会给分。已确认的网络与有效风险信号按规则扣分，证据覆盖决定分数上限。通过校验的过期 IP 风险记录按较低权重另扣，最多 15 分。",
                    "Every completed check receives a score. Verified network and current threat signals deduct points, and coverage caps the result. Verified historical IP threat records can deduct up to 15 points at a lower weight.",
                  )}
                </p>
                <ul className="purity-scale" aria-label={t("纯净值分档", "Purity score bands")}>
                  {PURITY_TIERS.map(({ key, minimum, maximum, label }) =>
                    <li data-risk={key} key={key}><strong>{label[lang]}</strong><code>{minimum}–{maximum}</code></li>)}
                </ul>
                <p>
                  {t(
                    "机房托管扣 25 分，云网络扣 20 分，VPN 扣 15 分，Tor 或普通代理扣 25 分，已核实的住宅代理扣 35 分。同类取最大值，网络属性合计最多扣 40 分。住宅或移动网络归属本身不扣分。",
                    "Hosting deducts 25, cloud 20, VPN 15, Tor or generic proxies 25, and verified residential proxies 35. Related attributes use their maximum and network context deducts up to 40. Residential and mobile network classification carry no deduction.",
                  )}
                </p>
                <p>{t(
                  "威胁扣分取决于类别、来源质量和活动时效。命令与控制和僵尸网络基础扣 90 分，恶意软件 85 分，钓鱼 75 分。DNS、时区和 WebRTC 只用于解释连接。各档描述当前覆盖范围内的公开信号。",
                  "Threat deductions depend on category, source quality and recency. Command and control or botnet activity starts at 90, malware at 85, and phishing at 75. DNS, time zone and WebRTC help explain your connection. Bands describe public signals within current coverage.",
                )}</p>
              </>
            ) : (
              <>
                <p>
                  {t(
                    "采用 IPtoASN、DB-IP Lite、OpenASN Tier A、Tor CollecTor、FFraud 开放 IP/ASN 文件、Monosans 公共代理快照和 Feodo 推荐列表。各来源分别受自己的许可证和署名要求约束。国旗使用本站托管的 flag-icons，不请求外部图片。",
                    "Sources include IPtoASN, DB-IP Lite, OpenASN Tier A, Tor CollecTor, FFraud IP/ASN open files, Monosans public proxies and Feodo. Each retains its own license. Country flags use locally hosted flag-icons assets.",
                  )}
                </p>
                <p>
                  {t(
                    "不会复制供应商专有评分。FFraud 免费文件没有活动日期，不能将它写成近期攻击；OpenASN 的上游不能重复计为独立来源。",
                    "Proprietary scores are not reused. FFraud open files have no activity dates and cannot establish recent activity. OpenASN upstream feeds cannot be counted twice.",
                  )}
                </p>
              </>
            )}
            <div className="modal-note">
              <Info size={16} />
              {t(
                "完整隐私、安全、评分与数据许可文档随项目源码提供。",
                "Full privacy, security, scoring and licensing documentation is included with the source.",
              )}
            </div>
          </section>
        </div>
      )}
    </>
  );
}
