import { useState } from "react";
import { Binary, Clock3, LockKeyhole, ShieldCheck } from "lucide-react";
import { containsIp, parseCidr, parseIp, type IpScope } from "../../shared/ip.ts";

type Lang = "zh" | "en";
const scopes: Record<IpScope, [string, string]> = {
  public: ["公网地址", "Public address"],
  private: ["私有地址", "Private address"],
  loopback: ["环回地址", "Loopback address"],
  "link-local": ["链路本地地址", "Link-local address"],
  shared: ["运营商共享地址", "Shared carrier address"],
  documentation: ["文档示例地址", "Documentation address"],
  multicast: ["组播地址", "Multicast address"],
  unspecified: ["未指定地址", "Unspecified address"],
  "ipv4-mapped": ["IPv4 映射地址", "IPv4-mapped address"],
  reserved: ["保留地址", "Reserved address"],
};

export function LocalChecks({ lang, hidden }: { lang: Lang; hidden: boolean }) {
  const t = (zh: string, en: string) => lang === "zh" ? zh : en;
  const [address, setAddress] = useState("");
  const [prefix, setPrefix] = useState("");
  const ip = parseIp(address);
  const cidr = parseCidr(prefix);
  const addressError = Boolean(address.trim() && !ip);
  const prefixError = Boolean(prefix.trim() && !cidr);
  const gpc = (navigator as Navigator & { globalPrivacyControl?: boolean }).globalPrivacyControl;
  const dnt = navigator.doNotTrack;
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const redact = (value: string) => hidden ? "••••••" : value;

  return (
    <div className="local-checks">
      <article className="diagnostic-card">
        <h3><ShieldCheck size={17} aria-hidden="true" />{t("浏览器隐私信号", "Browser privacy signals")}</h3>
        <dl className="diagnostic-rows">
          <div><dt>{t("连接到本站的协议", "Protocol to this site")}</dt><dd><code>{location.protocol === "https:" ? "HTTPS" : "HTTP"}</code></dd></div>
          <div><dt>{t("全局隐私控制（GPC）", "Global Privacy Control (GPC)")}</dt>
            <dd>{gpc === true ? t("已开启", "Enabled") : t("未声明", "Not signaled")}</dd></div>
          <div><dt>{t("请勿追踪（DNT）", "Do Not Track (DNT)")}</dt>
            <dd>{dnt === "1" ? t("已开启", "Enabled") : dnt === "0" ? t("已关闭", "Disabled") : t("未声明", "Not signaled")}</dd></div>
          <div><dt><Clock3 size={14} aria-hidden="true" />{t("浏览器时区", "Browser time zone")}</dt><dd><code>{timezone || "—"}</code></dd></div>
        </dl>
        <p className="local-note"><LockKeyhole size={14} aria-hidden="true" />{t("浏览器内读取，仅供当前页面查看。", "Read locally for this page only.")}</p>
      </article>
      <article className="diagnostic-card">
        <h3><Binary size={17} aria-hidden="true" />{t("IP 与网段验证", "IP & subnet validator")}</h3>
        <p className="local-note">{t("检查地址类型和网段归属。输入只在浏览器中处理。", "Inspect address type and subnet membership. Inputs are processed in your browser.")}</p>
        <div className="local-check-inputs">
          <label>
            <span>{t("要验证的 IP", "IP to validate")}</span>
            <input value={address} onChange={event => setAddress(event.target.value)} type={hidden ? "password" : "text"}
              placeholder="192.0.2.15" maxLength={64} autoComplete="off" spellCheck={false} aria-invalid={addressError}
              aria-describedby={addressError ? "local-ip-error" : undefined} />
          </label>
          <label>
            <span>{t("CIDR 网段（可选）", "CIDR subnet (optional)")}</span>
            <input value={prefix} onChange={event => setPrefix(event.target.value)} type={hidden ? "password" : "text"}
              placeholder="192.0.2.0/24" maxLength={68} autoComplete="off" spellCheck={false} aria-invalid={prefixError}
              aria-describedby={prefixError ? "local-cidr-error" : undefined} />
          </label>
        </div>
        <div className="local-check-result" aria-live="polite">
          {addressError && <p id="local-ip-error">{t("请输入有效的 IPv4 或 IPv6。", "Enter a valid IPv4 or IPv6 address.")}</p>}
          {prefixError && <p id="local-cidr-error">{t("请输入有效的 CIDR 网段。", "Enter a valid CIDR subnet.")}</p>}
          {ip && <p><code>{redact(ip.canonical)}</code> · IPv{ip.family} · {scopes[ip.scope][lang === "zh" ? 0 : 1]}</p>}
          {cidr && <p>{t("标准网段", "Canonical subnet")} <code>{redact(cidr.canonical)}</code></p>}
          {ip && cidr && <strong>{ip.family !== cidr.family ? t("地址与网段的地址族不同", "Address and subnet families differ")
            : containsIp(cidr, ip) ? t("此 IP 属于该网段", "IP belongs to this subnet") : t("此 IP 在该网段之外", "IP is outside this subnet")}</strong>}
        </div>
      </article>
    </div>
  );
}
