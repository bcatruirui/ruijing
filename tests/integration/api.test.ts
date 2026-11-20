import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  BuildRecord,
  DatasetManifest,
  IntelPayload,
  IpReport,
  SourceManifest,
} from "../../shared/contracts";
import { encodeShard } from "../../shared/dataset";

const NOW = new Date("2026-10-28T12:00:00.000Z");
const ORIGIN = "https://ruijing.example";
let sequence = 0;

function makeSource(
  id: string,
  patch: Partial<SourceManifest> = {},
): SourceManifest {
  return {
    id,
    name: `Synthetic fixture ${id}`,
    url: "https://example.invalid/source",
    license: "test-fixture-only",
    state: "ready",
    confidence: "high",
    upstreamFamilies: [id],
    families: [4, 6],
    categories: ["asn", "network", "c2"],
    publishedAt: "2026-10-28T10:00:00Z",
    fetchedAt: "2026-10-28T10:00:00Z",
    expiresAt: "2026-10-29T10:00:00Z",
    count: 1,
    negativeCoverageEligible: false,
    shards: [],
    ...patch,
  };
}

async function harness(
  definitions: Array<{
    source: SourceManifest;
    records?: BuildRecord[];
    failure?: number;
    bytes?: Uint8Array;
  }> = [],
  development = true,
) {
  // Each test uses a fresh Worker module/isolate: no artificial shared rate
  // buckets or asset cache leaks between otherwise independent environments.
  vi.resetModules();
  const blobs = new Map<string, Response>();
  const sources: SourceManifest[] = [];
  for (const definition of definitions) {
    const source = structuredClone(definition.source);
    if (definition.records || definition.bytes || definition.failure) {
      const bytes = definition.bytes ?? encodeShard(definition.records!);
      const family = definition.records?.[0]?.family ?? 4;
      const start = definition.records?.[0]?.start ?? "00000000";
      const end = definition.records?.at(-1)?.end ?? "ffffffff";
      const path = `/_intel/test-${++sequence}/${source.id}.bin`;
      const bodyBuffer = new ArrayBuffer(bytes.byteLength);
      new Uint8Array(bodyBuffer).set(bytes);
      const sha256 = Array.from(
        new Uint8Array(await crypto.subtle.digest("SHA-256", bodyBuffer)),
        (part) => part.toString(16).padStart(2, "0"),
      ).join("");
      source.shards = [
        {
          id: source.id,
          path,
          family,
          start,
          end,
          count: definition.records?.length ?? 1,
          byteLength: bytes.length,
          sha256,
        },
      ];
      blobs.set(
        path,
        new Response(definition.failure ? null : bodyBuffer, {
          status: definition.failure ?? 200,
        }),
      );
    }
    sources.push(source);
  }
  const manifest: DatasetManifest = {
    schemaVersion: 1,
    version: "synthetic-integration-v1",
    builtAt: NOW.toISOString(),
    profile: "test-only",
    sources,
  };
  blobs.set("/_intel/manifest.json", new Response(JSON.stringify(manifest)));
  const calls: string[] = [];
  const ASSETS = {
    fetch: vi.fn(async (request: Request | string) => {
      const url = new URL(typeof request === "string" ? request : request.url);
      calls.push(url.pathname);
      return (
        blobs.get(url.pathname)?.clone() ??
        new Response("synthetic static asset", {
          status: url.pathname.startsWith("/_intel/") ? 404 : 200,
        })
      );
    }),
  };
  const { handleRequest } = await import("../../worker/index");
  const env = { ASSETS, DEVELOPMENT: development ? "true" : "false" };
  const send = (path: string, body: unknown = {}, init: RequestInit = {}) => {
    const headers = new Headers({ "Content-Type": "application/json" });
    for (const [name, value] of new Headers(init.headers))
      headers.set(name, value);
    return handleRequest(
      new Request(ORIGIN + path, {
        method: "POST",
        body: JSON.stringify(body),
        ...init,
        headers,
      }),
      env,
    );
  };
  return { handleRequest, env, send, manifest, blobs, calls, ASSETS };
}

const v4 = (
  payload: IntelPayload,
  start = "08080808",
  end = start,
): BuildRecord => ({ family: 4, start, end, payload });
const v6 = (payload: IntelPayload): BuildRecord => ({
  family: 6,
  start: "20014860486000000000000000008888",
  end: "20014860486000000000000000008888",
  payload,
});

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
});

it("allows only configured app origins and decorates API errors and preflight", async () => {
  const h = await harness();
  const origin = "https://ruijing-preview.example";
  const headers = { Origin: origin, "Sec-Fetch-Site": "cross-site" };
  const env = { ...h.env, ALLOWED_APP_ORIGINS: JSON.stringify([origin]) };
  const preflight = (method: string) => h.handleRequest(new Request(ORIGIN + "/api/lookup", {
    method: "OPTIONS", headers: { ...headers, "Access-Control-Request-Method": method, "Access-Control-Request-Headers": "content-type" },
  }), env);
  expect(await preflight("POST")).toMatchObject({ status: 204 });
  expect(await preflight("GET")).toMatchObject({ status: 403 });
  const error = await h.handleRequest(new Request(ORIGIN + "/api/lookup", {
    method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: '{"ip":"not-an-ip"}',
  }), env);
  expect(error.status).toBe(400);
  expect(error.headers.get("Access-Control-Allow-Origin")).toBe(origin);
  expect(error.headers.get("Vary")).toBe("Origin");
  expect(error.headers.get("Access-Control-Allow-Credentials")).toBeNull();
  const denied = await h.handleRequest(new Request(ORIGIN + "/api/capabilities", { headers: { Origin: origin + ".invalid" } }), env);
  expect(denied.status).toBe(403);
  expect(denied.headers.get("Access-Control-Allow-Origin")).toBeNull();
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("private POST lookup API", () => {
  it("returns geographic estimates with the matched source, never invented postal data", async () => {
    const h = await harness([{
      source: makeSource("geo", { categories: ["geo"] }),
      records: [v4({ kind: "geo", countryCode: "US", region: "Arizona", city: "Phoenix", latitude: 33.4161, longitude: -112.009 })],
    }]);
    const result = await (await h.send("/api/lookup", { ip: "8.8.8.8" })).json() as IpReport;
    expect(result.info).toMatchObject({ latitude: 33.4161, longitude: -112.009, geoSource: "Synthetic fixture geo", geoSourceUrl: "https://example.invalid/source", geoAccuracy: "approximate" });
    expect(result.info.geoUpdatedAt).toBe("2026-10-28T10:00:00Z");
    expect(result.info.postalCode).toBeUndefined();
    expect(result.info.timezone).toBeUndefined();
  });

  it("does not mix a selected location record with fields from another geographic source", async () => {
    const h = await harness([
      { source: makeSource("geo-one", { categories: ["geo"] }), records: [v4({ kind: "geo", countryCode: "US", city: "Phoenix", latitude: 33.4161, longitude: -112.009, postalCode: "85040", timezone: "America/Phoenix" })] },
      { source: makeSource("geo-two", { categories: ["geo"] }), records: [v4({ kind: "geo", countryCode: "JP", city: "Tokyo" })] },
    ]);
    const result = await (await h.send("/api/lookup", { ip: "8.8.8.8" })).json() as IpReport;
    expect(result.info).toMatchObject({ countryCode: "JP", city: "Tokyo", geoSource: "Synthetic fixture geo-two" });
    for (const field of ["latitude", "longitude", "postalCode", "timezone"] as const) expect(result.info[field]).toBeUndefined();
  });
  it("queries real encoded in-memory ASSETS locally and returns an explainable report", async () => {
    const h = await harness([
      {
        source: makeSource("asn"),
        records: [
          v4({
            kind: "asn",
            asn: 64512,
            organization: "Synthetic fixture ASN",
            prefix: "8.8.8.8/32",
          }),
        ],
      },
      {
        source: makeSource("c2"),
        records: [
          v4({
            kind: "threat",
            category: "c2",
            observedAt: "2026-10-28T00:00:00Z",
            prefix: "8.8.8.8/32",
          }),
        ],
      },
    ]);
    const response = await h.send("/api/lookup", { ip: "8.8.8.8" });
    const result = (await response.json()) as IpReport;
    expect(response.status).toBe(200);
    expect(result.mode).toBe("lookup");
    expect(result.info).toMatchObject({
      ip: "8.8.8.8",
      family: 4,
      asn: 64512,
      asOrganization: "Synthetic fixture ASN",
    });
    expect(result.assessment).toMatchObject({
      riskScore: 90,
      hasThreatEvidence: true,
    });
    expect(
      result.assessment.evidence.some((item) => item.category === "c2"),
    ).toBe(true);
    expect(h.calls.every((path) => path.startsWith("/_intel/"))).toBe(true);
    expect(JSON.stringify(result)).not.toContain("sha256");
  });

  it("preserves a threat record alongside its VPN/proxy network attributes", async () => {
    const h = await harness([
      {
        source: makeSource("mixed"),
        records: [
          v4({
            kind: "threat",
            category: "c2",
            attributes: ["proxy"],
            confidence: "low",
            prefix: "8.8.8.8/32",
          }),
        ],
      },
    ]);
    const result = (await (
      await h.send("/api/lookup", { ip: "8.8.8.8" })
    ).json()) as IpReport;
    expect(result.info.attributes).toContain("proxy");
    expect(result.assessment.hasThreatEvidence).toBe(true);
    expect(
      result.assessment.evidence.some((item) => item.category === "c2"),
    ).toBe(true);
    expect(
      result.assessment.evidence.some((item) => item.attribute === "proxy"),
    ).toBe(true);
    expect(result.assessment.riskScore).toBe(43); // Undated low-quality C2 (18) + proxy context (25).
  });

  it("returns an explicitly unscored report when no data is configured", async () => {
    const h = await harness();
    const result = (await (
      await h.send("/api/lookup", { ip: "1.1.1.1" })
    ).json()) as IpReport;
    expect(result.assessment).toMatchObject({
      riskScore: null,
      scoreKind: "insufficient",
      confidence: "insufficient",
    });
    expect(result.info.country).toBeUndefined();
    expect(result.info.networkType).toBe("unknown");
  });

  it("makes no external query requests and never shares one lookup result with another", async () => {
    const h = await harness([
      { source: makeSource("asn"), records: [v4({ kind: "asn", asn: 64512 })] },
    ]);
    const externalFetch = vi
      .spyOn(globalThis, "fetch")
      .mockRejectedValue(new Error("External requests forbidden in this test"));
    const first = (await (
      await h.send("/api/lookup", { ip: "8.8.8.8" })
    ).json()) as IpReport;
    const second = (await (
      await h.send("/api/lookup", { ip: "1.1.1.1" })
    ).json()) as IpReport;
    expect(first.info.asn).toBe(64512);
    expect(second.info.ip).toBe("1.1.1.1");
    expect(second.info.asn).toBeUndefined();
    expect(externalFetch).not.toHaveBeenCalled();
  });

  it("keeps IPv6 lookup canonical and uses all 128 match bits", async () => {
    const h = await harness([
      {
        source: makeSource("v6"),
        records: [
          v6({ kind: "asn", asn: 64513, prefix: "2001:4860:4860::8888/128" }),
        ],
      },
    ]);
    const result = (await (
      await h.send("/api/lookup", { ip: "2001:4860:4860:0:0:0:0:8888" })
    ).json()) as IpReport;
    expect(result.info).toMatchObject({
      ip: "2001:4860:4860::8888",
      family: 6,
      asn: 64513,
    });
  });

  it("preserves stale Tor/VPN evidence without presenting stale attributes as current", async () => {
    const h = await harness([
      {
        source: makeSource("old-tor", {
          state: "stale",
          categories: ["tor"],
          expiresAt: "2026-10-27T00:00:00Z",
        }),
        records: [v4({ kind: "tor", category: "tor", attributes: ["tor"] })],
      },
      {
        source: makeSource("old-vpn", {
          state: "stale",
          categories: ["network", "vpn"],
          expiresAt: "2026-10-27T00:00:00Z",
        }),
        records: [
          v4({ kind: "network", networkType: "hosting", attributes: ["vpn"] }),
        ],
      },
    ]);
    const result = (await (
      await h.send("/api/lookup", { ip: "8.8.8.8" })
    ).json()) as IpReport;
    expect(result.info.attributes).toEqual([]);
    expect(result.info.networkType).toBe("unknown");
    expect(result.assessment.attributes).toEqual([]);
    expect(result.assessment.riskScore).toBe(null);
    expect(
      result.assessment.evidence.some(
        (item) => item.attribute === "tor" && item.stale,
      ),
    ).toBe(true);
    expect(
      result.assessment.evidence.some(
        (item) => item.attribute === "vpn" && item.stale,
      ),
    ).toBe(true);
    expect(
      result.assessment.indicators.find((item) => item.id === "tor")?.state,
    ).toBe("stale");
    expect(
      result.assessment.indicators.find((item) => item.id === "vpn")?.state,
    ).toBe("stale");
  });

  it("adds comparable ASN evidence from network records and labels actual range coverage", async () => {
    const h = await harness([
      {
        source: makeSource("asn", { categories: ["asn"] }),
        records: [v4({ kind: "asn", asn: 64512 }, "08080800", "080808ff")],
      },
      {
        source: makeSource("openasn", { categories: ["network"] }),
        records: [
          v4(
            { kind: "network", asn: 64512, networkType: "business" },
            "08080000",
            "0808ffff",
          ),
        ],
      },
    ]);
    const result = (await (
      await h.send("/api/lookup", { ip: "8.8.8.8" })
    ).json()) as IpReport;
    expect(result.info.network).toBe("8.8.8.0 – 8.8.8.255");
    const extra = result.assessment.evidence.find(
      (item) => item.sourceId === "openasn" && item.category === "asn",
    );
    expect(extra).toMatchObject({
      value: 64512,
      matchedRangeLabel: "8.8.0.0 – 8.8.255.255",
    });
    expect(extra?.matchedRange).toBeUndefined();
    expect(
      result.assessment.evidence.some(
        (item) => item.sourceId === "openasn" && item.category === "network",
      ),
    ).toBe(true);
    expect(
      result.assessment.indicators.find(
        (item) => item.id === "ownership_consistency",
      )?.state,
    ).toBe("detected");
  });

  it("labels a single-address match with a valid exact CIDR without inventing a route prefix", async () => {
    const h = await harness([
      {
        source: makeSource("exact"),
        records: [v4({ kind: "asn", asn: 64512 })],
      },
    ]);
    const result = (await (
      await h.send("/api/lookup", { ip: "8.8.8.8" })
    ).json()) as IpReport;
    expect(result.info.network).toBe("8.8.8.8");
    expect(result.assessment.evidence[0]).toMatchObject({
      matchedRange: "8.8.8.8/32",
      matchedRangeLabel: "8.8.8.8",
    });
  });

  it.each([
    "127.0.0.1",
    "10.0.0.1",
    "100.64.0.1",
    "192.0.2.1",
    "::1",
    "::ffff:127.0.0.1",
    "fc00::1",
    "2001:db8::1",
    "3fff::1",
    "1.1.1",
    "1.01.1.1",
  ])(
    "rejects invalid/nonpublic input %s before consulting intelligence",
    async (ip) => {
      const h = await harness();
      const response = await h.send("/api/lookup", { ip });
      expect(response.status).toBe(400);
      expect(h.calls).toEqual([]);
    },
  );

  it.each([undefined, null, 123, [], {}, true, "x".repeat(65)])(
    "rejects wrong input type/size %j",
    async (ip) => {
      const h = await harness();
      expect((await h.send("/api/lookup", { ip })).status).toBe(400);
    },
  );

  it.each(["null", "[]", "1", "false", '"ip"', "{bad"])(
    "rejects malformed JSON body %s",
    async (body) => {
      const h = await harness();
      const response = await h.send("/api/lookup", {}, { body });
      expect(response.status).toBe(400);
      expect((await response.json()).error).toBe("INVALID_JSON");
    },
  );

  it("requires POST and JSON, rejects query parameters and oversized streamed body", async () => {
    const h = await harness();
    const get = await h.handleRequest(
      new Request(ORIGIN + "/api/lookup"),
      h.env,
    );
    expect(get.status).toBe(405);
    expect(get.headers.get("Allow")).toBe("POST");
    expect(
      (
        await h.send(
          "/api/lookup",
          {},
          { headers: { "Content-Type": "text/plain" } },
        )
      ).status,
    ).toBe(415);
    expect(
      (await h.send("/api/lookup?ip=8.8.8.8", { ip: "8.8.8.8" })).status,
    ).toBe(400);
    expect(
      (
        await h.send("/api/lookup", {
          ip: "8.8.8.8",
          padding: "x".repeat(1100),
        })
      ).status,
    ).toBe(413);
    expect(
      (
        await h.send(
          "/api/lookup",
          { ip: "8.8.8.8" },
          { headers: { "Content-Length": "1025" } },
        )
      ).status,
    ).toBe(413);
  });

  it("emits no-store and security headers for success and errors without shared CORS", async () => {
    const h = await harness();
    for (const response of [
      await h.send("/api/lookup", { ip: "8.8.8.8" }),
      await h.send("/api/lookup", { ip: "10.0.0.1" }),
      await h.send(
        "/api/lookup",
        { ip: "8.8.8.8" },
        { headers: { Origin: "https://attacker.invalid" } },
      ),
    ]) {
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
      expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
      expect(response.headers.get("Access-Control-Allow-Origin")).not.toBe("*");
    }
  });

  it("rejects cross-origin and cross-site browser access but permits same-origin", async () => {
    const h = await harness();
    expect(
      (
        await h.send(
          "/api/lookup",
          { ip: "8.8.8.8" },
          { headers: { Origin: "https://attacker.invalid" } },
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await h.send(
          "/api/lookup",
          { ip: "8.8.8.8" },
          { headers: { "Sec-Fetch-Site": "cross-site" } },
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await h.send(
          "/api/lookup",
          { ip: "8.8.8.8" },
          { headers: { Origin: ORIGIN } },
        )
      ).status,
    ).toBe(200);
  });

  it("preflights narrowly and rate-limits repeated API requests without raw-IP logs", async () => {
    const h = await harness([], false);
    const log = vi.spyOn(console, "log");
    const error = vi.spyOn(console, "error");
    const options = await h.handleRequest(
      new Request(ORIGIN + "/api/lookup", {
        method: "OPTIONS",
        headers: { Origin: ORIGIN },
      }),
      h.env,
    );
    expect(options.status).toBe(204);
    expect(options.headers.get("Access-Control-Allow-Origin")).toBe(ORIGIN);
    let response: Response | undefined;
    for (let index = 0; index < 31; index++)
      response = await h.send("/api/lookup", { ip: "8.8.8.8" });
    expect(response?.status).toBe(429);
    expect(response?.headers.get("Retry-After")).toBe("60");
    expect(log).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
  });
});

describe("trusted self address and honest deployment state", () => {
  it("does not accept client headers or body as a local self address", async () => {
    const h = await harness();
    const response = await h.send(
      "/api/self",
      { ip: "8.8.8.8" },
      {
        headers: {
          "CF-Connecting-IP": "8.8.8.8",
          "X-Forwarded-For": "1.1.1.1",
          "X-Real-IP": "9.9.9.9",
        },
      },
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error).toBe("SELF_IP_UNAVAILABLE");
    expect(h.calls).toEqual([]);
  });

  it("does not trust a forged CF header outside the Cloudflare request context", async () => {
    const h = await harness([], false);
    expect(
      (
        await h.send(
          "/api/self",
          {},
          { headers: { "CF-Connecting-IP": "8.8.8.8" } },
        )
      ).status,
    ).toBe(503);
    expect(
      (
        await h.send(
          "/api/echo",
          {},
          { headers: { "CF-Connecting-IP": "8.8.8.8" } },
        )
      ).status,
    ).toBe(503);
  });

  it("uses trusted Cloudflare metadata for self and ignores spoofed alternate headers/body", async () => {
    const h = await harness([], false);
    const request = new Request(ORIGIN + "/api/self", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CF-Connecting-IP": "8.8.8.8",
        "X-Forwarded-For": "1.1.1.1",
        Forwarded: "for=9.9.9.9",
      },
      body: JSON.stringify({ ip: "1.1.1.1" }),
    });
    Object.defineProperty(request, "cf", {
      value: {
        country: "US",
        region: "Synthetic region",
        city: "Synthetic city",
        latitude: "33.4161",
        longitude: "-112.009",
        postalCode: "85040",
        timezone: "America/Phoenix",
        asn: 64512,
        asOrganization: "Synthetic CF fixture",
        httpProtocol: "HTTP/3",
      },
    });
    const response = await h.handleRequest(request, h.env);
    expect(response.status).toBe(200);
    const result = (await response.json()) as IpReport;
    expect(result).toMatchObject({
      mode: "self",
      info: {
        ip: "8.8.8.8",
        asn: 64512,
        geoSource: "Cloudflare connection metadata",
        connectionProtocol: "HTTP/3",
        latitude: 33.4161,
        longitude: -112.009,
        postalCode: "85040",
        timezone: "America/Phoenix",
        geoAccuracy: "approximate",
      },
    });
    expect(result.warnings[0].zh).toContain("推测");
    expect(result.info.geoUpdatedAt).toBeUndefined();
  });

  it("replaces self geolocation atomically and discards incomplete or invalid edge location fields", async () => {
    const h = await harness([{
      source: makeSource("geo", { categories: ["geo"] }),
      records: [v4({ kind: "geo", country: "United States", countryCode: "US", region: "Arizona", city: "Phoenix", latitude: 33.4161, longitude: -112.009, postalCode: "85040", timezone: "America/Phoenix" })],
    }], false);
    const request = new Request(ORIGIN + "/api/self", { method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": "8.8.8.8" }, body: "{}" });
    Object.defineProperty(request, "cf", { value: { country: "JP", city: "Tokyo", latitude: "35.68", longitude: "999", postalCode: "bad\ncode", timezone: "Asia/Invented" } });
    const result = await (await h.handleRequest(request, h.env)).json() as IpReport;
    expect(result.info).toMatchObject({ countryCode: "JP", city: "Tokyo", geoSource: "Cloudflare connection metadata" });
    for (const field of ["country", "region", "latitude", "longitude", "postalCode", "timezone", "geoUpdatedAt"] as const) expect(result.info[field]).toBeUndefined();
  });

  it("serves bodyless GET self and echo only to the configured app origin", async () => {
    const h = await harness([], false);
    const allowed = "https://ruijing.example";
    const env = { ...h.env, ALLOWED_APP_ORIGINS: JSON.stringify([allowed]) };
    for (const path of ["/api/echo", "/api/self"]) {
      const request = new Request(ORIGIN + path, { headers: {
        Origin: allowed, "Sec-Fetch-Site": "cross-site", "CF-Connecting-IP": "8.8.8.8",
      } });
      Object.defineProperty(request, "cf", { value: { country: "CN" } });
      const response = await h.handleRequest(request, env);
      expect(response.status).toBe(200);
      expect(response.headers.get("Access-Control-Allow-Origin")).toBe(allowed);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      const result = await response.json();
      expect(path === "/api/self" ? result.info.ip : result.ip).toBe("8.8.8.8");
      if (path === "/api/echo") expect(h.calls).toEqual([]);
      const denied = await h.handleRequest(new Request(ORIGIN + path, { headers: { Origin: `${allowed}.example` } }), env);
      expect(denied.status).toBe(403);
      expect(denied.headers.get("Access-Control-Allow-Origin")).toBeNull();
    }
  });

  it("keeps the complete local location record when edge country metadata is unavailable", async () => {
    const h = await harness([{
      source: makeSource("geo", { categories: ["geo"] }),
      records: [v4({ kind: "geo", countryCode: "US", city: "Phoenix", latitude: 33.4161, longitude: -112.009 })],
    }], false);
    const request = new Request(ORIGIN + "/api/self", { method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": "8.8.8.8" }, body: "{}" });
    Object.defineProperty(request, "cf", { value: { country: "XX", city: "Must not mix", postalCode: "10000" } });
    const result = await (await h.handleRequest(request, h.env)).json() as IpReport;
    expect(result.info).toMatchObject({ countryCode: "US", city: "Phoenix", latitude: 33.4161, longitude: -112.009, geoSource: "Synthetic fixture geo" });
    expect(result.info.postalCode).toBeUndefined();
  });

  it("does not use self CF geolocation for an arbitrary manual lookup", async () => {
    const h = await harness([], false);
    const request = new Request(ORIGIN + "/api/lookup", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CF-Connecting-IP": "1.1.1.1",
      },
      body: JSON.stringify({ ip: "8.8.8.8" }),
    });
    Object.defineProperty(request, "cf", {
      value: { city: "Must not leak to lookup", asn: 64512, country: "US", latitude: "33.4161", longitude: "-112.009", postalCode: "85040", timezone: "America/Phoenix" },
    });
    const result = (await (
      await h.handleRequest(request, h.env)
    ).json()) as IpReport;
    expect(result.info.city).toBeUndefined();
    expect(result.info.asn).toBeUndefined();
    for (const field of ["countryCode", "latitude", "longitude", "postalCode", "timezone", "geoSource"] as const) expect(result.info[field]).toBeUndefined();
  });

  it("permits cross-origin GET echo only for an exact configured origin and trusted edge context", async () => {
    const h = await harness([], false);
    const allowed = "https://controlled-node.example";
    const env = { ...h.env, ALLOWED_ECHO_ORIGINS: JSON.stringify([allowed]) };
    const request = new Request(ORIGIN + "/api/echo", {
      headers: {
        Origin: allowed,
        "Sec-Fetch-Site": "cross-site",
        "CF-Connecting-IP": "8.8.8.8",
        "X-Forwarded-For": "1.1.1.1",
      },
    });
    Object.defineProperty(request, "cf", {
      value: { asn: 64512, country: "US", httpProtocol: "HTTP/3" },
    });
    const response = await h.handleRequest(request, env);
    expect(response.status).toBe(200);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe(allowed);
    expect(response.headers.get("Vary")).toBe("Origin");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(await response.json()).toMatchObject({
      ip: "8.8.8.8",
      family: 4,
      asn: 64512,
      country: "US",
      protocol: "HTTP/3",
    });
    expect(h.calls).toEqual([]);
  });

  it("rejects arbitrary echo origins and does not apply echo permission to lookup", async () => {
    const h = await harness([], false);
    const allowed = "https://controlled-node.example";
    const env = { ...h.env, ALLOWED_ECHO_ORIGINS: JSON.stringify([allowed]) };
    for (const origin of [
      "https://attacker.invalid",
      "https://controlled-node.example.attacker.invalid",
      "http://controlled-node.example",
    ]) {
      const response = await h.handleRequest(
        new Request(ORIGIN + "/api/echo", {
          headers: { Origin: origin, "Sec-Fetch-Site": "cross-site" },
        }),
        env,
      );
      expect(response.status).toBe(403);
      expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
    }
    const lookup = new Request(ORIGIN + "/api/lookup", {
      method: "POST",
      headers: { Origin: allowed, "Content-Type": "application/json" },
      body: JSON.stringify({ ip: "8.8.8.8" }),
    });
    expect((await h.handleRequest(lookup, env)).status).toBe(403);
    expect(
      (
        await h.handleRequest(
          new Request(ORIGIN + "/api/echo", { headers: { Origin: allowed } }),
          h.env,
        )
      ).status,
    ).toBe(403);
  });

  it("retains unavailable state and narrow CORS for allowed echo before edge deployment", async () => {
    const h = await harness();
    const allowed = "https://controlled-node.example";
    const env = { ...h.env, ALLOWED_ECHO_ORIGINS: JSON.stringify([allowed]) };
    const response = await h.handleRequest(
      new Request(ORIGIN + "/api/echo", {
        headers: {
          Origin: allowed,
          "CF-Connecting-IP": "8.8.8.8",
          "Sec-Fetch-Site": "cross-site",
        },
      }),
      env,
    );
    expect(response.status).toBe(503);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe(allowed);
    expect((await response.json()).error).toBe("SELF_IP_UNAVAILABLE");
  });
});

describe("asset privacy, capabilities and partial failure", () => {
  it.each([
    "/_intel/manifest.json",
    "/_intel/test.bin",
    "/%5fintel/manifest.json",
    "/%5Fintel%2Fmanifest.json",
    "/_intel%2fmanifest.json",
    "/assets/../_intel/manifest.json",
    "/assets/%2e%2e/_intel/manifest.json",
    "/data/generated/manifest.json",
    "/worker/index.ts",
    "/.env",
    "/unknown",
  ])("blocks private or encoded asset path %s", async (path) => {
    const h = await harness();
    const response = await h.handleRequest(new Request(ORIGIN + path), h.env);
    expect(response.status).toBe(404);
    expect(h.ASSETS.fetch).not.toHaveBeenCalled();
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("allows only explicit public assets", async () => {
    const h = await harness();
    for (const path of [
      "/",
      "/index.html",
      "/privacy/",
      "/favicon.svg",
      "/robots.txt",
      "/assets/app-AbCd1234.js",
    ])
      expect(
        (await h.handleRequest(new Request(ORIGIN + path), h.env)).status,
      ).toBe(200);
    expect(h.calls).toEqual([
      "/index.html", "/index.html", "/index.html", "/favicon.svg", "/robots.txt", "/assets/app-AbCd1234.js",
    ]);
  });

  it("returns capability summaries without reading/returning the intelligence library", async () => {
    const h = await harness([
      { source: makeSource("asn"), records: [v4({ kind: "asn", asn: 64512 })] },
    ]);
    const response = await h.handleRequest(
      new Request(ORIGIN + "/api/capabilities"),
      h.env,
    );
    const body = await response.json();
    expect(response.status).toBe(200);
    expect(body).toMatchObject({
      datasetVersion: "synthetic-integration-v1",
      dns: { configured: false },
      stun: { configured: false },
      routingNodes: [],
      familyEndpoints: {},
    });
    expect(h.calls).toEqual(["/_intel/manifest.json"]);
    expect(JSON.stringify(body)).not.toContain("shards");
    expect(JSON.stringify(body)).not.toContain(".bin");
    expect(JSON.stringify(body)).not.toContain("Synthetic fixture ASN");
  });

  it("sanitizes controlled endpoints and STUN configuration before exposing capabilities", async () => {
    const h = await harness();
    const env = {
      ...h.env,
      ROUTING_NODES: JSON.stringify([
        {
          id: "good",
          name: "Controlled HTTPS node",
          url: "https://controlled-node.example/api/echo",
          family: 6,
        },
        {
          id: "http",
          name: "Invalid HTTP",
          url: "http://controlled-node.example/api/echo",
        },
        { id: "script", name: "Invalid script", url: "javascript:alert(1)" },
        {
          id: "credentials",
          name: "Invalid credentials",
          url: "https://secret:password@controlled-node.example/api/echo",
        },
        {
          id: "query",
          name: "Invalid query",
          url: "https://controlled-node.example/api/echo?key=secret",
        },
        {
          id: "fragment",
          name: "Invalid fragment",
          url: "https://controlled-node.example/api/echo#secret",
        },
        null,
        5,
      ]),
      FAMILY_ENDPOINTS: JSON.stringify({
        ipv4: "http://v4.example/api/echo",
        ipv6: "https://v6.example/api/echo",
        ignored: "https://unused.example",
      }),
      STUN_URL: "stun:owned-stun.example:3478",
    };
    const response = await h.handleRequest(
      new Request(ORIGIN + "/api/capabilities"),
      env,
    );
    const result = await response.json();
    expect(response.status).toBe(200);
    expect(result.routingNodes).toEqual([
      {
        id: "good",
        name: "Controlled HTTPS node",
        url: "https://controlled-node.example/api/echo",
        family: 6,
      },
    ]);
    expect(result.familyEndpoints).toEqual({
      ipv6: "https://v6.example/api/echo",
    });
    expect(result.stun).toEqual({
      configured: true,
      url: "stun:owned-stun.example:3478",
    });
    expect(JSON.stringify(result)).not.toContain("secret");
  });

  it.each([
    "https://third-party.example/stun",
    "stun:owned.example:0",
    "stun:owned.example:65536",
    "stun:user:password@owned.example",
    "stun:owned.example?transport=udp",
  ])("keeps invalid STUN configuration unavailable: %s", async (STUN_URL) => {
    const h = await harness();
    const response = await h.handleRequest(
      new Request(ORIGIN + "/api/capabilities"),
      { ...h.env, STUN_URL },
    );
    expect((await response.json()).stun).toEqual({ configured: false });
  });

  it("bounds configured node count and labels, strips unsupported family values and tolerates invalid JSON", async () => {
    const h = await harness();
    const ROUTING_NODES = JSON.stringify(
      Array.from({ length: 12 }, (_, index) => ({
        id: `${index}-` + "i".repeat(100),
        name: "n".repeat(160),
        url: `https://node${index}.example/api/echo`,
        family: 9,
      })),
    );
    const response = await h.handleRequest(
      new Request(ORIGIN + "/api/capabilities"),
      {
        ...h.env,
        ROUTING_NODES,
        FAMILY_ENDPOINTS: "{broken",
        STUN_URL: "stuns:[2001:db8::1]:5349",
      },
    );
    const result = await response.json();
    expect(result.routingNodes).toHaveLength(8);
    expect(
      result.routingNodes.every(
        (node: { id: string; name: string; family?: number }) =>
          node.id.length <= 60 &&
          node.name.length <= 100 &&
          node.family === undefined,
      ),
    ).toBe(true);
    expect(result.familyEndpoints).toEqual({});
    expect(result.stun).toEqual({
      configured: true,
      url: "stuns:[2001:db8::1]:5349",
    });
  });

  it("isolates a failed source from a successful source", async () => {
    const h = await harness([
      {
        source: makeSource("broken"),
        records: [v4({ kind: "threat", category: "c2" })],
        failure: 503,
      },
      {
        source: makeSource("working", { categories: ["asn"] }),
        records: [v4({ kind: "asn", asn: 64512 })],
      },
    ]);
    const response = await h.send("/api/lookup", { ip: "8.8.8.8" });
    const result = (await response.json()) as IpReport;
    expect(response.status).toBe(200);
    expect(result.info.asn).toBe(64512);
    expect(
      result.assessment.sources.find((item) => item.id === "broken"),
    ).toMatchObject({ state: "unavailable" });
    expect(
      result.assessment.sources.find((item) => item.id === "broken")?.matched,
    ).toBeUndefined();
    expect(result.assessment.riskScore).toBe(null);
  });

  it("marks corrupt matching data unavailable rather than manufacturing a clean result", async () => {
    const bytes = encodeShard([v4({ kind: "threat", category: "c2" })]);
    bytes[0] = 0;
    const h = await harness([{ source: makeSource("corrupt"), bytes }]);
    const result = (await (
      await h.send("/api/lookup", { ip: "8.8.8.8" })
    ).json()) as IpReport;
    expect(result.assessment.sources[0].state).toBe("unavailable");
    expect(result.assessment.sources[0].matched).toBeUndefined();
  });

  it("rejects a digest mismatch before trusting otherwise well-formed records", async () => {
    const h = await harness([
      {
        source: makeSource("tampered"),
        records: [v4({ kind: "asn", asn: 64512 })],
      },
    ]);
    h.manifest.sources[0].shards[0].sha256 = "0".repeat(64);
    h.blobs.set(
      "/_intel/manifest.json",
      new Response(JSON.stringify(h.manifest)),
    );
    const result = (await (
      await h.send("/api/lookup", { ip: "8.8.8.8" })
    ).json()) as IpReport;
    expect(result.info.asn).toBeUndefined();
    expect(result.assessment.sources[0].state).toBe("unavailable");
  });

  it("falls back to an unscored report if manifest parsing fails", async () => {
    const h = await harness();
    h.blobs.set("/_intel/manifest.json", new Response("{malformed"));
    const result = (await (
      await h.send("/api/lookup", { ip: "8.8.8.8" })
    ).json()) as IpReport;
    expect(result.assessment.datasetVersion).toBe("unconfigured");
    expect(result.assessment.riskScore).toBe(null);
  });

  it("holds the 16-request concurrency guard while optional DNS upstreams are pending and releases it afterward (Mock upstream)", async () => {
    const h = await harness();
    const env = {
      ...h.env,
      DNS_SERVICE_URL: "https://controlled-dns.example",
      DNS_SERVICE_SECRET: "private-service-key-".repeat(3),
    };
    const release: Array<() => void> = [];
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(
      async (_input, init) =>
        await new Promise<Response>((resolve, reject) => {
          const signal = init?.signal;
          const abort = () =>
            reject(new DOMException("Cancelled", "AbortError"));
          signal?.addEventListener("abort", abort, { once: true });
          release.push(() => {
            signal?.removeEventListener("abort", abort);
            resolve(new Response("{}", { status: 503 }));
          });
        }),
    );
    const send = () =>
      h.handleRequest(
        new Request(ORIGIN + "/api/dns/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}",
        }),
        env,
      );
    const pending = Array.from({ length: 16 }, send);
    let extra: Promise<Response> | undefined;
    try {
      await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(16));
      extra = send();
      const response = await Promise.race([
        extra,
        new Promise<never>((_resolve, reject) =>
          setTimeout(
            () =>
              reject(
                new Error(
                  "The seventeenth DNS request was not rejected promptly",
                ),
              ),
            500,
          ),
        ),
      ]);
      expect(response.status).toBe(503);
      expect(await response.json()).toMatchObject({ error: "BUSY" });
      expect(fetchMock).toHaveBeenCalledTimes(16);
    } finally {
      for (const complete of release) complete();
      await Promise.allSettled([...pending, ...(extra ? [extra] : [])]);
    }
    fetchMock.mockResolvedValueOnce(new Response("{}", { status: 503 }));
    const recovered = await send();
    expect(await recovered.json()).toMatchObject({
      error: "DNS_SERVICE_UNAVAILABLE",
    });
    expect(fetchMock).toHaveBeenCalledTimes(17);
  });
});
