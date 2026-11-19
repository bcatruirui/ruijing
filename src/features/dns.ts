import { parseIp } from "../../shared/ip.ts";
import { apiFetch } from "../lib/api.ts";
import { unexpectedResolver } from "../lib/dns-expectation.ts";

export interface DnsResolverObservation {
  ip: string;
  firstObservedAt: string;
  lastObservedAt: string;
  types: string[];
  asn?: number;
  organization?: string;
  country?: string;
  probeCount?: number;
}
export interface DnsProgress {
  phase: "starting" | "probing" | "polling" | "finished";
  completedProbes: number;
  totalProbes: number;
  resolverCount: number;
}
export interface DnsLeakResult {
  status: "complete" | "unavailable" | "inconclusive" | "cancelled" | "error" | "timeout";
  resolvers: DnsResolverObservation[];
  verdict: "undetermined" | "unexpected";
  message: string;
  checkedAt: string;
  probeCount: number;
  cleanupConfirmed: boolean;
}
export interface DnsLeakOptions {
  signal?: AbortSignal;
  onProgress?: (progress: DnsProgress) => void;
  expected?: string[];
}

interface DnsSession {
  id: string;
  secret: string;
  expiresAt: string;
  probeUrls: string[];
}
const object = (value: unknown): value is Record<string, unknown> =>
  Boolean(value && typeof value === "object" && !Array.isArray(value));
class DnsRequestError extends Error {
  constructor(public readonly status: number) {
    super("DNS request failed.");
  }
}
async function post(
  path: string,
  body: unknown,
  signal?: AbortSignal,
): Promise<unknown> {
  const response = await apiFetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
    signal,
  });
  if (!response.ok) throw new DnsRequestError(response.status);
  if (!response.headers.get("content-type")?.includes("application/json"))
    throw new Error("Invalid DNS response.");
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Empty DNS response.");
  const decoder = new TextDecoder();
  let text = "";
  let bytes = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > 16_384) {
        await reader.cancel();
        throw new Error("DNS response too large.");
      }
      text += decoder.decode(value, { stream: true });
    }
    return JSON.parse(text + decoder.decode());
  } finally {
    reader.releaseLock();
  }
}
function sessionFrom(value: unknown): DnsSession | null {
  if (
    !object(value) ||
    typeof value.id !== "string" ||
    !/^[a-f0-9]{32}$/.test(value.id) ||
    typeof value.secret !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.secret) ||
    typeof value.expiresAt !== "string" ||
    !Number.isFinite(Date.parse(value.expiresAt)) ||
    !Array.isArray(value.probeUrls) ||
    value.probeUrls.length !== 4
  )
    return null;
  if (
    Date.parse(value.expiresAt) <= Date.now() ||
    Date.parse(value.expiresAt) > Date.now() + 180_000
  )
    return null;
  const urls: string[] = [];
  let suffix = "";
  for (const item of value.probeUrls) {
    if (typeof item !== "string" || item.length > 350) return null;
    let url;
    try {
      url = new URL(item);
    } catch {
      return null;
    }
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.port ||
      url.search ||
      url.hash ||
      url.pathname !== "/probe" ||
      !/^q[a-f0-9]{32}\./.test(url.hostname)
    )
      return null;
    const zone = url.hostname.slice(34);
    if (!zone || (suffix && zone !== suffix)) return null;
    suffix = zone;
    urls.push(url.href);
  }
  return new Set(urls).size === 4
    ? {
        id: value.id,
        secret: value.secret,
        expiresAt: value.expiresAt,
        probeUrls: urls,
      }
    : null;
}
function resolverList(
  value: unknown,
  session: DnsSession,
): DnsResolverObservation[] | null {
  if (
    !object(value) ||
    value.id !== session.id ||
    !Array.isArray(value.resolvers) ||
    value.resolvers.length > 16
  )
    return null;
  const resolvers: DnsResolverObservation[] = [];
  for (const item of value.resolvers) {
    if (!object(item)) return null;
    const ip = parseIp(item.ip);
    if (
      !ip ||
      typeof item.firstObservedAt !== "string" ||
      !Number.isFinite(Date.parse(item.firstObservedAt)) ||
      typeof item.lastObservedAt !== "string" ||
      !Number.isFinite(Date.parse(item.lastObservedAt)) ||
      Date.parse(item.firstObservedAt) > Date.parse(item.lastObservedAt) ||
      !Array.isArray(item.types) ||
      item.types.length > 32 ||
      item.types.some(
        (type) => typeof type !== "string" || !/^[A-Z0-9-]{1,16}$/.test(type),
      )
    )
      return null;
    const result: DnsResolverObservation = {
      ip: ip.canonical,
      firstObservedAt: item.firstObservedAt,
      lastObservedAt: item.lastObservedAt,
      types: item.types as string[],
    };
    if (
      typeof item.asn === "number" &&
      Number.isSafeInteger(item.asn) &&
      item.asn > 0 &&
      item.asn <= 0xffffffff
    )
      result.asn = item.asn;
    if (
      typeof item.organization === "string" &&
      item.organization.length <= 200
    )
      result.organization = item.organization;
    if (typeof item.country === "string" && item.country.length <= 80)
      result.country = item.country;
    if (typeof item.probeCount === "number" && Number.isInteger(item.probeCount) && item.probeCount >= 1 && item.probeCount <= session.probeUrls.length)
      result.probeCount = item.probeCount;
    resolvers.push(result);
  }
  return resolvers;
}
async function pause(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return;
  await new Promise<void>((resolve) => {
    const finish = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", finish);
      resolve();
    };
    const timer = setTimeout(finish, ms);
    signal.addEventListener("abort", finish, { once: true });
  });
}
async function triggerProbe(
  url: string,
  signal: AbortSignal,
): Promise<boolean> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(abort, 3500);
  let dispatched = false;
  try {
    if (!signal.aborted) {
      dispatched = true;
      await fetch(url, {
        method: "GET",
        mode: "no-cors",
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        redirect: "error",
        signal: controller.signal,
      });
    }
  } catch {
    /* A failed/opaque HTTP fetch is never fabricated into DNS evidence. Poll the authority instead. */
  } finally {
    clearTimeout(timer);
    controller.abort();
    signal.removeEventListener("abort", abort);
  }
  return dispatched;
}

/** Call only from the explicit DNS-start user action. Nothing runs on import or page load. */
export async function runDnsLeakTest(
  options: DnsLeakOptions = {},
): Promise<DnsLeakResult> {
  const result: DnsLeakResult = {
    status: "inconclusive",
    resolvers: [],
    verdict: "undetermined",
    message: "",
    checkedAt: new Date().toISOString(),
    probeCount: 0,
    cleanupConfirmed: false,
  };
  const controller = new AbortController();
  const abort = () => controller.abort();
  options.signal?.addEventListener("abort", abort, { once: true });
  if (options.signal?.aborted) controller.abort();
  const totalTimer = setTimeout(abort, 18_000);
  let session: DnsSession | null = null;
  let completedProbes = 0;
  const notify = (phase: DnsProgress["phase"]) => {
    try {
      options.onProgress?.({
        phase,
        completedProbes,
        totalProbes: session?.probeUrls.length ?? 0,
        resolverCount: result.resolvers.length,
      });
    } catch {
      /* UI observers cannot prevent privacy cleanup. */
    }
  };
  try {
    if (controller.signal.aborted) {
      result.status = "cancelled";
      result.message = "检测已取消 / Cancelled.";
      return result;
    }
    notify("starting");
    session = sessionFrom(await post("/api/dns/start", {}, controller.signal));
    if (!session) throw new Error("Invalid DNS session.");
    notify("probing");
    await Promise.all(
      session.probeUrls.map(async (url) => {
        if (await triggerProbe(url, controller.signal)) completedProbes++;
        notify("probing");
      }),
    );
    result.probeCount = completedProbes;
    for (
      let attempt = 0;
      attempt < 5 &&
      !controller.signal.aborted &&
      Date.now() < Date.parse(session.expiresAt);
      attempt++
    ) {
      notify("polling");
      const enrich = attempt === 4 || (attempt >= 1 && result.resolvers.length > 0);
      const observations = resolverList(
        await post(
          "/api/dns/results",
          { id: session.id, secret: session.secret, ...(enrich ? { enrich: true } : {}) },
          controller.signal,
        ),
        session,
      );
      if (!observations) throw new Error("Invalid resolver observations.");
      result.resolvers = observations;
      if (enrich && observations.length) break;
      if (attempt < 4) await pause(750, controller.signal);
    }
    if (controller.signal.aborted) {
      result.status = options.signal?.aborted ? "cancelled" : "timeout";
      result.message = options.signal?.aborted
        ? "检测已取消；已观察结果不构成泄漏结论。 / Cancelled; observations do not establish a leak."
        : "检测超时，无法完整判断。 / Test timed out; assessment is incomplete.";
    } else if (result.resolvers.length) {
      result.status = "complete";
      if (result.resolvers.some(resolver => unexpectedResolver(resolver, options.expected ?? [])))
        result.verdict = "unexpected";
      result.message =
        result.verdict === "unexpected"
          ? "多个探测域名观测到非预期递归解析器，疑似 DNS 泄漏。 / Multiple probe names observed an unexpected resolver. Possible DNS leak."
          : "已观察到真实递归解析器；ASN 或地区差异本身不能确认 DNS 泄漏。 / Actual recursive resolvers observed; ASN or country differences alone do not establish a DNS leak.";
    } else {
      result.status = "inconclusive";
      result.message =
        "权威服务暂未观察到有效解析请求；不能据此断言没有泄漏。 / No authoritative observations received; this does not prove absence of leaks.";
    }
  } catch (error) {
    result.status = options.signal?.aborted
      ? "cancelled"
      : controller.signal.aborted ? "timeout"
      : error instanceof DnsRequestError && error.status === 503
        ? "unavailable"
        : session
          ? "inconclusive"
          : "error";
    result.message =
      result.status === "unavailable"
        ? "独立 DNS 服务未部署或暂不可用；未生成模拟结果。 / Independent DNS service is not deployed or unavailable."
        : result.status === "cancelled"
          ? "检测已取消 / Cancelled."
          : result.status === "timeout" ? "检测超时 / Test timed out."
          : "未取得完整有效的 DNS 观测，无法判断。 / Valid DNS observations could not be completed.";
  } finally {
    clearTimeout(totalTimer);
    controller.abort();
    options.signal?.removeEventListener("abort", abort);
    if (session) {
      const cleanup = new AbortController();
      const timer = setTimeout(() => cleanup.abort(), 2000);
      try {
        const response = await post(
          "/api/dns/delete",
          { id: session.id, secret: session.secret },
          cleanup.signal,
        );
        result.cleanupConfirmed = object(response) && response.deleted === true;
      } catch {
        /* The independent store still expires sessions within its <=180-second hard limit. */
      } finally {
        clearTimeout(timer);
        cleanup.abort();
      }
    }
    if (session && !result.cleanupConfirmed)
      result.message +=
        " 未确认即时清除；服务端会话按不超过 180 秒的期限自动过期。 / Immediate deletion unconfirmed; server-side session expiry is capped at 180 seconds.";
    notify("finished");
  }
  return result;
}
