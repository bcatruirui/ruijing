import { enrichResolvers, type IntelligenceEnv } from "../intelligence/query.ts";
import { parseIp } from "../../shared/ip.ts";

export interface DnsServiceEnv {
  DNS_SERVICE_URL?: string;
  DNS_SERVICE_SECRET?: string;
  DNS_PUBLIC_VERIFIED?: string;
}
const headers = {
  "Cache-Control": "no-store",
  "Content-Type": "application/json; charset=utf-8",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers });
const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value && typeof value === "object" && !Array.isArray(value));
const validId = (value: unknown): value is string =>
  typeof value === "string" && /^[a-f0-9]{32}$/.test(value);
const validSecret = (value: unknown): value is string =>
  typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
function endpoint(value: string): URL | null {
  try {
    const url = new URL(value);
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (
      (url.protocol !== "https:" && !(local && url.protocol === "http:")) ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      !["", "/"].includes(url.pathname)
    )
      return null;
    return url;
  } catch {
    return null;
  }
}
async function boundedText(
  body: ReadableStream<Uint8Array> | null,
  maximum: number,
): Promise<string | null> {
  if (!body) return "";
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let size = 0;
  let text = "";
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximum) {
        await reader.cancel();
        return null;
      }
      text += decoder.decode(value, { stream: true });
    }
    return text + decoder.decode();
  } finally {
    reader.releaseLock();
  }
}
const date = (value: unknown): value is string =>
  typeof value === "string" &&
  value.length <= 40 &&
  Number.isFinite(Date.parse(value));
function cleanSession(value: unknown): Record<string, unknown> | null {
  if (
    !isRecord(value) ||
    !validId(value.id) ||
    !validSecret(value.secret) ||
    !date(value.expiresAt) ||
    !Array.isArray(value.probeUrls) ||
    value.probeUrls.length !== 4
  )
    return null;
  const remaining = Date.parse(value.expiresAt) - Date.now();
  if (remaining <= 0 || remaining > 180_000) return null;
  const probes: string[] = [];
  let suffix = "";
  for (const entry of value.probeUrls) {
    if (typeof entry !== "string" || entry.length > 350) return null;
    let url;
    try {
      url = new URL(entry);
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
    probes.push(url.href);
  }
  if (new Set(probes).size !== 4) return null;
  return {
    id: value.id,
    secret: value.secret,
    expiresAt: value.expiresAt,
    probeUrls: probes,
  };
}
function cleanResults(
  value: unknown,
  requestedId: string,
): Record<string, unknown> | null {
  if (
    !isRecord(value) ||
    value.id !== requestedId ||
    !date(value.expiresAt) ||
    !Array.isArray(value.resolvers) ||
    value.resolvers.length > 16
  )
    return null;
  const resolvers: Record<string, unknown>[] = [];
  for (const item of value.resolvers) {
    if (!isRecord(item)) return null;
    const ip = parseIp(item.ip);
    if (
      !ip ||
      !date(item.firstObservedAt) ||
      !date(item.lastObservedAt) ||
      Date.parse(item.firstObservedAt) > Date.parse(item.lastObservedAt) ||
      !Array.isArray(item.types) ||
      item.types.length > 32 ||
      item.types.some(
        (type) => typeof type !== "string" || !/^[A-Z0-9-]{1,16}$/.test(type),
      )
    )
      return null;
    const resolver: Record<string, unknown> = {
      ip: ip.canonical,
      firstObservedAt: item.firstObservedAt,
      lastObservedAt: item.lastObservedAt,
      types: [...new Set(item.types)],
    };
    if (
      typeof item.asn === "number" &&
      Number.isSafeInteger(item.asn) &&
      item.asn > 0 &&
      item.asn <= 0xffffffff
    )
      resolver.asn = item.asn;
    if (
      typeof item.organization === "string" &&
      item.organization.length <= 200
    )
      resolver.organization = item.organization;
    if (typeof item.country === "string" && item.country.length <= 80)
      resolver.country = item.country;
    if (typeof item.probeCount === "number" && Number.isInteger(item.probeCount) && item.probeCount >= 1 && item.probeCount <= 4)
      resolver.probeCount = item.probeCount;
    resolvers.push(resolver);
  }
  return {
    id: value.id,
    expiresAt: value.expiresAt,
    resolvers,
    verdict: "undetermined",
    explanation:
      "Observed recursive resolvers only; ASN and country differences do not establish a DNS leak.",
  };
}

export async function dnsStatus(env: DnsServiceEnv): Promise<"ready" | "unavailable"> {
  const base = env.DNS_SERVICE_URL && endpoint(env.DNS_SERVICE_URL);
  if (!base || env.DNS_PUBLIC_VERIFIED !== "true" || (env.DNS_SERVICE_SECRET?.length ?? 0) < 32)
    return "unavailable";
  try {
    const response = await fetch(new URL("/v1/health", base), {
      method: "HEAD", redirect: "error", cache: "no-store",
      headers: { Authorization: `Bearer ${env.DNS_SERVICE_SECRET}` },
      signal: AbortSignal.timeout(1200),
    });
    return response.status === 204 && response.headers.get("X-Ruijing-DNS") === "authority-v1" ? "ready" : "unavailable";
  } catch {
    return "unavailable";
  }
}

/** The root Worker authorizes the origin and guards rate and concurrency. */
export async function handleDnsRequest(
  request: Request,
  env: DnsServiceEnv & Partial<IntelligenceEnv>,
  allowedCrossOrigin = false,
): Promise<Response> {
  const path = new URL(request.url).pathname;
  const routes: Record<string, string> = {
    "/api/dns/start": "/v1/session",
    "/api/dns/results": "/v1/results",
    "/api/dns/delete": "/v1/delete",
  };
  if (!routes[path]) return json({ error: "NOT_FOUND" }, 404);
  if (request.method !== "POST")
    return new Response(JSON.stringify({ error: "METHOD_NOT_ALLOWED" }), {
      status: 405,
      headers: { ...headers, Allow: "POST" },
    });
  if (
    !request.headers
      .get("content-type")
      ?.toLowerCase()
      .startsWith("application/json")
  )
    return json({ error: "JSON_REQUIRED" }, 415);
  if (Number(request.headers.get("content-length") || 0) > 1024)
    return json({ error: "BODY_TOO_LARGE" }, 413);
  const origin = new URL(request.url).origin;
  if (
    new URL(request.url).search ||
    (!allowedCrossOrigin && ((request.headers.get("origin") &&
      request.headers.get("origin") !== origin) ||
    request.headers.get("sec-fetch-site") === "cross-site"))
  )
    return json({ error: "REQUEST_NOT_ALLOWED" }, 403);
  let input: Record<string, unknown>;
  try {
    const text = await boundedText(request.body, 1024);
    if (text === null) return json({ error: "BODY_TOO_LARGE" }, 413);
    const parsed: unknown = JSON.parse(text || "{}");
    if (!isRecord(parsed)) return json({ error: "INVALID_INPUT" }, 400);
    input = parsed;
  } catch {
    return json({ error: "INVALID_INPUT" }, 400);
  }
  const isStart = path === "/api/dns/start";
  const isResults = path === "/api/dns/results";
  if (
    isStart
      ? Object.keys(input).length !== 0
      : !validId(input.id) ||
        !validSecret(input.secret) ||
        (input.enrich !== undefined && (!isResults || typeof input.enrich !== "boolean")) ||
        Object.keys(input).some((key) => !["id", "secret", "enrich"].includes(key))
  )
    return json({ error: "INVALID_INPUT" }, 400);
  const base = env.DNS_SERVICE_URL ? endpoint(env.DNS_SERVICE_URL) : null;
  if (!base || !env.DNS_SERVICE_SECRET || env.DNS_SERVICE_SECRET.length < 32 ||
    (env.DNS_PUBLIC_VERIFIED === "false" && env.DEVELOPMENT !== "true"))
    return json(
      { error: "DNS_SERVICE_UNAVAILABLE", status: "unavailable" },
      503,
    );
  const controller = new AbortController();
  const abort = () => controller.abort();
  request.signal.addEventListener("abort", abort, { once: true });
  if (request.signal.aborted) controller.abort();
  const timer = setTimeout(abort, 4000);
  try {
    const response = await fetch(new URL(routes[path], base), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${env.DNS_SERVICE_SECRET}`,
      },
      body: JSON.stringify(
        isStart ? {} : { id: input.id, secret: input.secret },
      ),
      redirect: "error",
      cache: "no-store",
      signal: controller.signal,
    });
    if (!response.ok)
      return json(
        {
          error:
            response.status === 404 && !isStart
              ? "DNS_SESSION_UNAVAILABLE"
              : "DNS_SERVICE_UNAVAILABLE",
        },
        response.status === 404 && !isStart ? 404 : 503,
      );
    if (
      !response.headers
        .get("content-type")
        ?.toLowerCase()
        .includes("application/json")
    )
      return json({ error: "DNS_INVALID_SERVICE_RESPONSE" }, 502);
    const text = await boundedText(response.body, 16_384);
    if (text === null)
      return json({ error: "DNS_INVALID_SERVICE_RESPONSE" }, 502);
    const value: unknown = JSON.parse(text);
    const cleaned = isStart
      ? cleanSession(value)
      : path.endsWith("/delete")
        ? isRecord(value) && value.deleted === true
          ? { deleted: true }
          : null
        : cleanResults(value, input.id as string);
    if (isResults && cleaned && input.enrich === true && env.ASSETS) {
      const resolvers = (cleaned as { resolvers: Record<string, unknown>[] }).resolvers;
      await enrichResolvers({ ...env, ASSETS: env.ASSETS }, resolvers);
    }
    return cleaned
      ? json(cleaned, isStart ? 201 : 200)
      : json({ error: "DNS_INVALID_SERVICE_RESPONSE" }, 502);
  } catch {
    return json({ error: "DNS_SERVICE_UNAVAILABLE" }, 503);
  } finally {
    clearTimeout(timer);
    controller.abort();
    request.signal.removeEventListener("abort", abort);
  }
}
