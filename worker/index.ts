import { parseIp } from "../shared/ip.ts";
import { parseCoordinate, validPostalCode, validTimezone } from "../shared/geo.ts";
import { assessPurity, assessRisk } from "../shared/scoring.ts";
import {
  loadManifest,
  queryIntelligence,
  sourceStatuses,
} from "./intelligence/query.ts";
import type { AssetBinding } from "./intelligence/query.ts";
import type { Capabilities, IpReport } from "../shared/contracts.ts";
import { dnsStatus, handleDnsRequest } from "./api/dns.ts";
export interface Env {
  ASSETS: AssetBinding;
  DEVELOPMENT?: string;
  USE_BUNDLED_SNAPSHOT?: string;
  ROUTING_NODES?: string;
  FAMILY_ENDPOINTS?: string;
  DNS_SERVICE_URL?: string;
  DNS_SERVICE_SECRET?: string;
  STUN_URL?: string;
  ALLOWED_ECHO_ORIGINS?: string;
  ALLOWED_APP_ORIGINS?: string;
  DNS_PUBLIC_VERIFIED?: string;
}
const commonHeaders: Record<string, string> = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Permissions-Policy":
    "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
};
const json = (
  body: unknown,
  status = 200,
  extra: Record<string, string> = {},
) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      ...commonHeaders,
      "Content-Type": "application/json; charset=utf-8",
      ...extra,
    },
  });
const buckets = new Map<string, { count: number; expires: number }>();
let hmacKey: Promise<CryptoKey> | undefined;
let inFlight = 0;
async function rateLimited(ip: string, now: number) {
  hmacKey ||= crypto.subtle.importKey(
    "raw",
    crypto.getRandomValues(new Uint8Array(32)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = await crypto.subtle.sign(
    "HMAC",
    await hmacKey,
    new TextEncoder().encode(ip),
  );
  const key = Array.from(new Uint8Array(digest).slice(0, 16), (x) =>
    x.toString(16).padStart(2, "0"),
  ).join("");
  if (buckets.size > 4096) {
    let removed = 0;
    for (const [k, v] of buckets) {
      if (v.expires < now) {
        buckets.delete(k);
        if (++removed > 32) break;
      }
    }
    if (buckets.size > 4096) buckets.delete(buckets.keys().next().value!);
  }
  const b = buckets.get(key);
  if (!b || b.expires <= now) {
    buckets.set(key, { count: 1, expires: now + 60000 });
    return false;
  }
  return ++b.count > 30;
}
function config<T>(value: string | undefined, fallback: T): T {
  try {
    return value ? JSON.parse(value) : fallback;
  } catch {
    return fallback;
  }
}
function safeHttps(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length > 350) return;
  try {
    const u = new URL(value);
    if (
      u.protocol === "https:" &&
      !u.username &&
      !u.password &&
      !u.hash &&
      !u.search
    )
      return u.href;
  } catch {}
  return;
}
function safeStun(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length > 300) return;
  const m =
    /^stuns?:([a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\])(?::([0-9]{1,5}))?$/.exec(value);
  return m && (!m[2] || (Number(m[2]) > 0 && Number(m[2]) <= 65535))
    ? value
    : undefined;
}
export async function handleRequest(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url),
    path = url.pathname;
  // No arbitrary asset fallback: encoded aliases and HTML navigation cannot expose intelligence.
  if (!path.startsWith("/api/")) {
    if (path === "/" || /^\/(privacy|methodology|data-sources)\/?$/.test(path))
      return env.ASSETS.fetch(
        new Request(new URL("/index.html", url), request),
      );
    if (
      path === "/index.html" ||
      path === "/favicon.svg" ||
      path === "/robots.txt" ||
      /^\/assets\/[a-zA-Z0-9_.-]+$/.test(path)
    )
      return env.ASSETS.fetch(request);
    return json({ error: "NOT_FOUND" }, 404);
  }
  const origin = request.headers.get("Origin");
  const methods: Record<string, string[]> = {
    "/api/capabilities": ["GET"],
    "/api/self": ["POST"],
    "/api/lookup": ["POST"],
    "/api/echo": ["GET", "POST"],
    "/api/dns/start": ["POST"],
    "/api/dns/results": ["POST"],
    "/api/dns/delete": ["POST"],
  };
  const allowedMethods = methods[path];
  const allowlist = config<unknown>(
    path === "/api/echo" ? env.ALLOWED_ECHO_ORIGINS : env.ALLOWED_APP_ORIGINS, [],
  );
  const crossOrigin = Boolean(allowedMethods && origin && origin !== "null" &&
    Array.isArray(allowlist) && allowlist.includes(origin));
  if (origin && origin !== url.origin && !crossOrigin)
    return json({ error: "ORIGIN_NOT_ALLOWED" }, 403, { Vary: "Origin" });
  if (request.headers.get("Sec-Fetch-Site") === "cross-site" && !crossOrigin)
    return json({ error: "CROSS_SITE_REQUEST" }, 403, { Vary: "Origin" });

  let response: Response;
  if (url.search) response = json({ error: "QUERY_PARAMETERS_NOT_ALLOWED" }, 400);
  else if (request.method === "OPTIONS") {
    const method = request.headers.get("Access-Control-Request-Method");
    const requestedHeaders = (request.headers.get("Access-Control-Request-Headers") || "")
      .split(",").map(header => header.trim().toLowerCase()).filter(Boolean);
    response = !allowedMethods ? json({ error: "NOT_FOUND" }, 404)
      : (method && !allowedMethods.includes(method)) || requestedHeaders.some(header => header !== "content-type")
      ? json({ error: "PREFLIGHT_NOT_ALLOWED" }, 403)
      : new Response(null, { status: 204, headers: {
          ...commonHeaders,
          "Access-Control-Allow-Origin": origin || url.origin,
          "Access-Control-Allow-Methods": allowedMethods.join(", "),
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Max-Age": "600",
          Vary: "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
        } });
  } else response = await handleApi(request, env, path, crossOrigin);
  if (!response.headers.has("Vary")) response.headers.set("Vary", "Origin");
  if (crossOrigin && origin) {
    response.headers.set("Access-Control-Allow-Origin", origin);
    response.headers.set("Access-Control-Expose-Headers", "Retry-After");
  }
  return response;
}

async function handleApi(request: Request, env: Env, path: string, crossOrigin: boolean): Promise<Response> {
  const client =
    env.DEVELOPMENT === "true"
      ? "local"
      : request.headers.get("CF-Connecting-IP") || "unavailable";
  // DEVELOPMENT is only set by the loopback development adapter, never Wrangler.
  if (env.DEVELOPMENT !== "true" && (await rateLimited(client, Date.now())))
    return json(
      {
        error: "RATE_LIMITED",
        message: "请求过于频繁，请稍后重试 / Too many requests",
      },
      429,
      { "Retry-After": "60" },
    );
  if (inFlight >= 16)
    return json({ error: "BUSY" }, 503, { "Retry-After": "5" });
  inFlight++;
  try {
    if (path === "/api/capabilities" && request.method === "GET") {
      const manifest = await loadManifest(env);
      const rawNodes = config<unknown>(env.ROUTING_NODES, []),
        rawFamilies = config<Record<string, unknown>>(env.FAMILY_ENDPOINTS, {}),
        stunUrl = safeStun(env.STUN_URL);
      const nodes = Array.isArray(rawNodes)
        ? rawNodes
            .flatMap((n) => {
              if (!n || typeof n !== "object") return [];
              const url = safeHttps(n.url);
              return url &&
                typeof n.id === "string" &&
                typeof n.name === "string"
                ? [
                    {
                      id: n.id.slice(0, 60),
                      name: n.name.slice(0, 100),
                      url,
                      ...(n.family === 4 || n.family === 6
                        ? { family: n.family as 4 | 6 }
                        : {}),
                    },
                  ]
                : [];
            })
            .slice(0, 8)
        : [];
      const caps: Capabilities = {
        datasetVersion: manifest.version,
        builtAt: manifest.builtAt,
        sources: sourceStatuses(manifest),
        dns: {
          configured: Boolean(env.DNS_SERVICE_URL && env.DNS_SERVICE_SECRET),
          status: await dnsStatus(env),
        },
        stun: {
          configured: Boolean(stunUrl),
          ...(stunUrl ? { url: stunUrl } : {}),
        },
        routingNodes: nodes,
        familyEndpoints: {
          ipv4: safeHttps(rawFamilies?.ipv4),
          ipv6: safeHttps(rawFamilies?.ipv6),
        },
        development: env.DEVELOPMENT === "true",
      };
      return json(caps);
    }
    if (path.startsWith("/api/dns/"))
      return await handleDnsRequest(request, { ...env, DNS_PUBLIC_VERIFIED: env.DNS_PUBLIC_VERIFIED ?? "false" }, crossOrigin);
    if (!["/api/self", "/api/lookup", "/api/echo"].includes(path))
      return json({ error: "NOT_FOUND" }, 404);
    if (path === "/api/echo" && request.method === "GET") {
      const cf = (request as Request & { cf?: Record<string, unknown> }).cf;
      const ip =
        env.DEVELOPMENT === "true"
          ? null
          : parseIp(request.headers.get("CF-Connecting-IP") || "");
      if (!cf || !ip?.isPublic)
        return json(
          { error: "SELF_IP_UNAVAILABLE" },
          503,
        );
      return json(
        {
          ip: ip.canonical,
          family: ip.family,
          asn: typeof cf.asn === "number" ? cf.asn : undefined,
          country: typeof cf.country === "string" ? cf.country : undefined,
          protocol:
            typeof cf.httpProtocol === "string" ? cf.httpProtocol : undefined,
          observedAt: new Date().toISOString(),
        },
        200,
      );
    }
    if (request.method !== "POST")
      return json({ error: "METHOD_NOT_ALLOWED" }, 405, { Allow: "POST" });
    if (!request.headers.get("content-type")?.startsWith("application/json"))
      return json({ error: "JSON_REQUIRED" }, 415);
    if (Number(request.headers.get("content-length") || 0) > 1024)
      return json({ error: "BODY_TOO_LARGE" }, 413);
    const reader = request.body?.getReader();
    let size = 0;
    const chunks: Uint8Array[] = [];
    if (reader) {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > 1024) {
          await reader.cancel();
          return json({ error: "BODY_TOO_LARGE" }, 413);
        }
        chunks.push(value);
      }
    }
    const joined = new Uint8Array(size);
    let offset = 0;
    for (const c of chunks) {
      joined.set(c, offset);
      offset += c.length;
    }
    let body: { ip?: unknown };
    try {
      body = JSON.parse(new TextDecoder().decode(joined) || "{}");
      if (!body || Array.isArray(body) || typeof body !== "object")
        throw new Error();
    } catch {
      return json({ error: "INVALID_JSON" }, 400);
    }
    const cf = (request as Request & { cf?: Record<string, unknown> }).cf;
    if (
      path !== "/api/lookup" &&
      (env.DEVELOPMENT === "true" ||
        !cf ||
        !request.headers.get("CF-Connecting-IP"))
    )
      return json(
        {
          error: "SELF_IP_UNAVAILABLE",
          message:
            "本地预览无法取得可信公网出口；请输入公网 IP 查询。部署至 Cloudflare 后自动读取真实连接。 / Trusted public egress is unavailable in local preview.",
        },
        503,
      );
    const raw =
      path === "/api/lookup"
        ? body.ip
        : request.headers.get("CF-Connecting-IP");
    if (typeof raw !== "string" || raw.length > 64)
      return json({ error: "INVALID_IP" }, 400);
    const parsed = parseIp(raw);
    if (!parsed || !parsed.isPublic)
      return json(
        {
          error: "PUBLIC_IP_REQUIRED",
          message:
            "请输入有效公网 IPv4 或 IPv6 / Enter a valid public IPv4 or IPv6",
        },
        400,
      );
    if (path === "/api/echo")
      return json({
        ip: parsed.canonical,
        family: parsed.family,
        observedAt: new Date().toISOString(),
      });
    const now = new Date(),
      manifest = await loadManifest(env),
      found = await queryIntelligence(env, manifest, parsed.canonical, now);
    const assessment = assessRisk({
      ip: parsed.canonical,
      evidence: found.evidence,
      sources: found.sources,
      networkType: found.info.networkType,
      attributes: found.info.attributes,
      asOf: now.toISOString(),
      datasetVersion: manifest.version,
    });
    found.info.networkType = assessment.networkType;
    const { ip: _ip, family: _family, attributes: _attributes, ...offline } = found.info;
    const conflicts: NonNullable<IpReport["provenance"]>["conflicts"] = [];
    if (path === "/api/self" && cf) {
      const s = (key: string) =>
        typeof cf[key] === "string" && cf[key].length > 0 && cf[key].length <= 200
          ? (cf[key] as string) : undefined;
      const countryCode = s("country");
      // cf is request metadata for this connection only, never arbitrary lookup input.
      // Use its location as an atomic record; absent fields must not inherit a
      // different database's coordinates, postcode or city.
      if (countryCode && /^[A-Z]{2}$/.test(countryCode) && !["XX", "ZZ"].includes(countryCode)) {
        const latitude = parseCoordinate(cf.latitude, "latitude");
        const longitude = parseCoordinate(cf.longitude, "longitude");
        const coordinatesAvailable = latitude !== undefined && longitude !== undefined;
        if (offline.countryCode && offline.countryCode !== countryCode) conflicts.push("country");
        found.info.country = undefined;
        found.info.countryCode = countryCode;
        found.info.region = s("region");
        found.info.city = s("city");
        found.info.latitude = coordinatesAvailable ? latitude : undefined;
        found.info.longitude = coordinatesAvailable ? longitude : undefined;
        found.info.postalCode = validPostalCode(cf.postalCode) ? cf.postalCode : undefined;
        found.info.timezone = validTimezone(cf.timezone) ? cf.timezone : undefined;
        found.info.geoSource = "Cloudflare connection metadata";
        found.info.geoSourceUrl = "https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties";
        found.info.geoAccuracy = "approximate";
        // Cloudflare supplies no database publication date. Receipt time is not
        // represented as an intelligence update timestamp.
        found.info.geoUpdatedAt = undefined;
      }
      if (typeof cf.asn === "number" && Number.isSafeInteger(cf.asn) && cf.asn > 0 && cf.asn <= 0xffffffff) {
        if (offline.asn && offline.asn !== cf.asn) conflicts.push("asn");
        found.info.asn = cf.asn;
        found.info.asOrganization = s("asOrganization");
        found.info.asnSource = "Cloudflare connection metadata";
        found.info.asnUpdatedAt = undefined;
        found.info.network = undefined;
      }
      found.info.connectionProtocol = s("httpProtocol");
    }
    if (conflicts.length && assessment.confidence !== "insufficient") assessment.confidence = "low";
    const report: IpReport = {
      info: found.info,
      assessment,
      purity: assessPurity(assessment, parsed.family, conflicts.length > 0),
      ...(path === "/api/self" && cf ? { provenance: { offline, conflicts } } : {}),
      generatedAt: now.toISOString(),
      mode: path === "/api/self" ? "self" : "lookup",
      warnings: [
        {
          zh: "地理位置为数据库推测，不是用户真实精确位置。ASN 组织不一定是接入 ISP。",
          en: "Geolocation is an estimate, not your precise location. ASN organization may differ from access ISP.",
        },
      ],
    };
    return json(report);
  } catch {
    return json(
      {
        error: "INTERNAL_ERROR",
        message:
          "检测暂不可用，未生成检测成功结果 / Assessment temporarily unavailable",
      },
      500,
    );
  } finally {
    inFlight--;
  }
}
export default { fetch: handleRequest };
