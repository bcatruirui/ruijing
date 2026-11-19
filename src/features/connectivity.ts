import { parseIp } from "../../shared/ip.ts";
/** Browser probes measure a selected HTTPS resource, never ICMP ping or site egress. */
export type ProbeMethod = "image" | "fetch-no-cors";
export interface ConnectivityTarget {
  id: string;
  name: string;
  url: string;
  method: ProbeMethod;
}
export interface ConnectivityResult {
  targetId: string;
  name: string;
  url: string;
  status: "resource-loaded" | "opaque-response" | "inconclusive" | "cancelled";
  method: ProbeMethod;
  elapsedMs: number | null;
  checkedAt: string;
  message: string;
  exitIp: null;
}
export interface ProbeOptions {
  consent: boolean;
  signal?: AbortSignal;
  timeoutMs?: number;
}
export const CONNECTIVITY_TARGETS: readonly ConnectivityTarget[] = [
  {
    id: "baidu",
    name: "百度",
    url: "https://www.baidu.com/favicon.ico",
    method: "image",
  },
  {
    id: "taobao",
    name: "淘宝",
    url: "https://www.taobao.com/favicon.ico",
    method: "image",
  },
  {
    id: "wechat",
    name: "微信",
    url: "https://weixin.qq.com/favicon.ico",
    method: "image",
  },
  {
    id: "google",
    name: "Google",
    url: "https://www.google.com/favicon.ico",
    method: "image",
  },
  {
    id: "github",
    name: "GitHub",
    url: "https://github.com/favicon.ico",
    method: "image",
  },
  {
    id: "cloudflare",
    name: "Cloudflare",
    url: "https://www.cloudflare.com/favicon.ico",
    method: "image",
  },
  {
    id: "youtube",
    name: "YouTube",
    url: "https://www.youtube.com/favicon.ico",
    method: "image",
  },
  {
    id: "tiktok",
    name: "TikTok",
    url: "https://www.tiktok.com/favicon.ico",
    method: "image",
  },
];

const elapsed = (started: number) =>
  Math.round(Math.max(0, performance.now() - started));
const timeout = (value?: number) =>
  Number.isFinite(value) ? Math.min(20_000, Math.max(500, value!)) : 8_000;
function assertConsent(options: ProbeOptions): void {
  if (options.consent !== true)
    throw new Error(
      "Explicit consent is required before contacting test sites.",
    );
}

export async function checkConnectivityTarget(
  targetOrId: ConnectivityTarget | string,
  options: ProbeOptions,
): Promise<ConnectivityResult> {
  assertConsent(options);
  const target =
    typeof targetOrId === "string"
      ? CONNECTIVITY_TARGETS.find((item) => item.id === targetOrId)
      : targetOrId;
  if (!target) throw new Error("Unknown connectivity target.");
  const url = new URL(target.url);
  if (url.protocol !== "https:" || url.username || url.password)
    throw new Error("Probes require a credential-free HTTPS URL.");
  const started = performance.now();
  const base = {
    targetId: target.id,
    name: target.name,
    url: target.url,
    method: target.method,
    checkedAt: new Date().toISOString(),
    exitIp: null,
  };
  if (options.signal?.aborted)
    return {
      ...base,
      status: "cancelled",
      elapsedMs: null,
      message: "检测已取消 / Cancelled.",
    };
  const timeoutMs = timeout(options.timeoutMs);
  if (target.method === "image") {
    return new Promise((resolve) => {
      const probe = new Image();
      let done = false;
      const finish = (
        status: ConnectivityResult["status"],
        message: string,
      ) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        options.signal?.removeEventListener("abort", cancel);
        probe.onload = null;
        probe.onerror = null;
        if (status !== "resource-loaded") probe.removeAttribute("src");
        resolve({ ...base, status, elapsedMs: elapsed(started), message });
      };
      const cancel = () => finish("cancelled", "检测已取消 / Cancelled.");
      const timer = setTimeout(
        () =>
          finish(
            "inconclusive",
            "资源请求超时；不能据此确认网站被封锁。 / Resource timed out; blocking cannot be inferred.",
          ),
        timeoutMs,
      );
      probe.referrerPolicy = "no-referrer";
      probe.onload = () =>
        finish(
          "resource-loaded",
          "所选 HTTPS 图像资源已加载；耗时包含连接、服务器响应与缓存影响，并非 ping。 / Selected HTTPS image loaded; request duration is not ping.",
        );
      probe.onerror = () =>
        finish(
          "inconclusive",
          "图像资源未能加载；原因可能是资源更改、网络、策略或浏览器限制。 / Resource failed; the cause is undetermined.",
        );
      options.signal?.addEventListener("abort", cancel, { once: true });
      // A nonce discourages cache reuse. The target may still use a service worker or intermediary cache.
      url.searchParams.set("_ruijing_probe", crypto.randomUUID());
      probe.src = url.href;
    });
  }
  const controller = new AbortController();
  const abort = () => controller.abort();
  options.signal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(abort, timeoutMs);
  try {
    const response = await fetch(url, {
      mode: "no-cors",
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      redirect: "follow",
      signal: controller.signal,
    });
    return {
      ...base,
      status: "opaque-response",
      elapsedMs: elapsed(started),
      message:
        response.type === "opaque"
          ? "请求已返回不可读响应；无法确认 HTTP 状态、内容或该站出口 IP。 / Opaque response received; HTTP status, content and egress IP are unknown."
          : "请求已返回；此探测不读取站点内容，也不能获知该站出口 IP。 / Request returned; this probe does not establish site egress IP.",
    };
  } catch {
    return {
      ...base,
      status: options.signal?.aborted ? "cancelled" : "inconclusive",
      elapsedMs: elapsed(started),
      message: options.signal?.aborted
        ? "检测已取消 / Cancelled."
        : "请求失败或超时；无法确定原因或判定封锁。 / Request failed or timed out; the cause is undetermined.",
    };
  } finally {
    clearTimeout(timer);
    controller.abort();
    options.signal?.removeEventListener("abort", abort);
  }
}

export async function runConnectivityChecks(
  options: ProbeOptions & { onResult?: (result: ConnectivityResult) => void },
): Promise<ConnectivityResult[]> {
  assertConsent(options);
  const results: ConnectivityResult[] = [];
  // Four concurrent probes bound browser and remote resource use.
  for (let index = 0; index < CONNECTIVITY_TARGETS.length; index += 4) {
    const batch = await Promise.all(
      CONNECTIVITY_TARGETS.slice(index, index + 4).map(async (target) => {
        const result = await checkConnectivityTarget(target, options);
        try {
          options.onResult?.(result);
        } catch {
          /* An observer cannot interrupt cleanup of the probe batch. */
        }
        return result;
      }),
    );
    results.push(...batch);
    if (options.signal?.aborted) break;
  }
  return results;
}

export interface EchoNodeConfig {
  id: string;
  name: string;
  url: string;
  family?: 4 | 6;
}
export interface EchoObservation {
  ip: string;
  asn?: number;
  country?: string;
  protocol?: string;
}
export interface EchoNodeResult {
  nodeId: string;
  name: string;
  status: "observed" | "inconclusive" | "cancelled";
  elapsedMs: number;
  observation: EchoObservation | null;
  message: string;
}
export interface RoutingResult {
  status: "complete" | "not-deployed";
  results: EchoNodeResult[];
  distinctExitIps: string[];
  message: string;
}
/** Explicit opt-in integration point. No external IP API is configured by default. */
export interface PublicCorsEgressAdapter {
  id: string;
  targetId: string;
  endpoint: string;
  authorizedForPublicUse: true;
  parse: (body: unknown) => EchoObservation | null;
}

function validIp(value: unknown): value is string {
  return typeof value === "string" && parseIp(value) !== null;
}
const canonicalIp = (ip: string) => parseIp(ip)!.canonical;
async function readSmallJson(response: Response): Promise<unknown> {
  if (
    !response.ok ||
    !response.headers
      .get("content-type")
      ?.toLowerCase()
      .includes("application/json")
  )
    throw new Error("Invalid echo response.");
  if (Number(response.headers.get("content-length") ?? 0) > 4096) {
    await response.body?.cancel();
    throw new Error("Echo response too large.");
  }
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Empty echo response.");
  const decoder = new TextDecoder();
  let text = "";
  let bytes = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > 4096) {
        await reader.cancel();
        throw new Error("Echo response too large.");
      }
      text += decoder.decode(value, { stream: true });
    }
    return JSON.parse(text + decoder.decode());
  } finally {
    reader.releaseLock();
  }
}

export async function checkRoutingNodes(
  nodes: readonly EchoNodeConfig[],
  options: ProbeOptions,
): Promise<RoutingResult> {
  assertConsent(options);
  if (!nodes.length)
    return {
      status: "not-deployed",
      results: [],
      distinctExitIps: [],
      message:
        "未部署受控出口回显节点，无法检测分流。 / Controlled egress echo nodes are not deployed.",
    };
  const results = await Promise.all(
    nodes.slice(0, 8).map(async (node) => {
      const started = performance.now();
      const controller = new AbortController();
      const abort = () => controller.abort();
      options.signal?.addEventListener("abort", abort, { once: true });
      const timer = setTimeout(abort, timeout(options.timeoutMs));
      try {
        if (options.signal?.aborted) throw new Error("Cancelled");
        const url = new URL(
          node.url,
          globalThis.location?.origin ?? "https://localhost",
        );
        if (
          url.protocol !== "https:" ||
          url.username ||
          url.password ||
          url.hash ||
          url.search
        )
          throw new Error("Invalid endpoint");
        const response = await fetch(url, {
          mode: "cors",
          credentials: "omit",
          cache: "no-store",
          referrerPolicy: "no-referrer",
          redirect: "error",
          signal: controller.signal,
        });
        const data = (await readSmallJson(
          response,
        )) as Partial<EchoObservation> | null;
        if (!data || typeof data !== "object" || Array.isArray(data))
          throw new Error("Invalid echo data");
        if (
          !validIp(data.ip) ||
          (node.family && (data.ip.includes(":") ? 6 : 4) !== node.family)
        )
          throw new Error("Echo address family mismatch");
        const observation: EchoObservation = { ip: canonicalIp(data.ip) };
        if (Number.isSafeInteger(data.asn) && (data.asn ?? 0) > 0)
          observation.asn = data.asn;
        if (typeof data.country === "string" && data.country.length <= 80)
          observation.country = data.country;
        if (typeof data.protocol === "string" && data.protocol.length <= 20)
          observation.protocol = data.protocol;
        return {
          nodeId: node.id,
          name: node.name,
          status: "observed" as const,
          elapsedMs: elapsed(started),
          observation,
          message:
            "受控节点返回实际 HTTP 出口；不代表其他任意网站出口。 / Observed by this controlled node only.",
        };
      } catch {
        return {
          nodeId: node.id,
          name: node.name,
          status: options.signal?.aborted
            ? ("cancelled" as const)
            : ("inconclusive" as const),
          elapsedMs: elapsed(started),
          observation: null,
          message:
            "未取得有效回显；可能是网络、TLS、CORS、超时或节点故障。 / No valid echo; cause is undetermined.",
        };
      } finally {
        clearTimeout(timer);
        controller.abort();
        options.signal?.removeEventListener("abort", abort);
      }
    }),
  );
  const distinctExitIps = [
    ...new Set(
      results.flatMap((result) =>
        result.observation ? [result.observation.ip] : [],
      ),
    ),
  ];
  return {
    status: "complete",
    results,
    distinctExitIps,
    message:
      distinctExitIps.length > 1
        ? "受控节点观察到不同出口，可能存在路由差异；不能仅凭 ASN 或地区差异确认泄漏。 / Different controlled-node exits observed; this does not establish a leak."
        : "仅反映成功响应的受控节点；相同出口不能保证所有流量走同一路由。 / Results cover responding controlled nodes only.",
  };
}

export async function checkPublicCorsEgress(
  adapter: PublicCorsEgressAdapter,
  options: ProbeOptions,
): Promise<EchoObservation | null> {
  assertConsent(options);
  if (adapter.authorizedForPublicUse !== true)
    throw new Error("Adapter authorization must be verified.");
  const url = new URL(adapter.endpoint);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  )
    throw new Error("Invalid adapter endpoint.");
  const controller = new AbortController();
  const abort = () => controller.abort();
  const timer = setTimeout(abort, timeout(options.timeoutMs));
  options.signal?.addEventListener("abort", abort, { once: true });
  try {
    if (options.signal?.aborted) return null;
    const response = await fetch(url, {
      mode: "cors",
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      redirect: "error",
      signal: controller.signal,
    });
    const result = adapter.parse(await readSmallJson(response));
    return result && validIp(result.ip)
      ? { ...result, ip: canonicalIp(result.ip) }
      : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
    controller.abort();
    options.signal?.removeEventListener("abort", abort);
  }
}
