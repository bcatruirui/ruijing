import { lookupVerifiedShardMatches } from "../../shared/dataset.ts";
import bundledManifest from "../../data/generated/worker-snapshot.ts";
import { parseIp } from "../../shared/ip.ts";
import type {
  DatasetManifest,
  Evidence,
  IntelPayload,
  IpInfo,
  SourceManifest,
  SourceStatus,
} from "../../shared/contracts.ts";
export interface AssetBinding {
  fetch(request: Request | string): Promise<Response>;
}
export interface IntelligenceEnv {
  ASSETS: AssetBinding;
  DEVELOPMENT?: string;
  USE_BUNDLED_SNAPSHOT?: string;
}
const rawCache = new Map<string, Uint8Array>();
let cacheSize = 0;
const pending = new Map<string, Promise<Uint8Array>>();
const manifestCache = new WeakMap<
  AssetBinding,
  { promise: Promise<DatasetManifest>; expires: number }
>();
async function loadBytes(
  env: IntelligenceEnv,
  path: string,
  expectedHash: string,
  expectedLength: number,
): Promise<Uint8Array> {
  const key = path + ":" + expectedHash;
  const cached = rawCache.get(key);
  if (cached) {
    if (cached.length !== expectedLength)
      throw new Error("Intelligence shard length mismatch");
    rawCache.delete(key);
    rawCache.set(key, cached);
    return cached;
  }
  const active = pending.get(key);
  if (active) return active;
  if (pending.size >= 16) throw new Error("Intelligence capacity reached");
  const promise = (async () => {
    const r = await env.ASSETS.fetch(
      new Request("https://assets.internal" + path),
    );
    if (!r.ok) throw new Error("Intelligence asset unavailable");
    const bytes = new Uint8Array(await r.arrayBuffer());
    if (bytes.length > 131072 || bytes.length !== expectedLength)
      throw new Error("Intelligence shard length mismatch");
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    const hash = Array.from(new Uint8Array(digest), (v) =>
      v.toString(16).padStart(2, "0"),
    ).join("");
    if (hash !== expectedHash)
      throw new Error("Intelligence checksum mismatch");
    while (cacheSize + bytes.length > 8 * 1024 * 1024 && rawCache.size) {
      const first = rawCache.keys().next().value!;
      cacheSize -= rawCache.get(first)!.length;
      rawCache.delete(first);
    }
    rawCache.set(key, bytes);
    cacheSize += bytes.length;
    return bytes;
  })();
  pending.set(key, promise);
  try {
    return await promise;
  } finally {
    pending.delete(key);
  }
}
export async function loadManifest(
  env: IntelligenceEnv,
): Promise<DatasetManifest> {
  if (env.USE_BUNDLED_SNAPSHOT === "true")
    return bundledManifest as DatasetManifest;
  const existing = manifestCache.get(env.ASSETS);
  if (existing && existing.expires > Date.now()) return existing.promise;
  const entry = {
    expires: env.DEVELOPMENT === "true" ? Date.now() + 5000 : Infinity,
    promise: Promise.resolve(null as unknown as DatasetManifest),
  };
  entry.promise = (async () => {
    try {
      const r = await env.ASSETS.fetch(
        new Request("https://assets.internal/_intel/manifest.json"),
      );
      if (!r.ok) throw new Error();
      const text = await r.text();
      if (text.length > 8 * 1024 * 1024) throw new Error();
      const data = JSON.parse(text) as DatasetManifest;
      if (data.schemaVersion !== 1 || !Array.isArray(data.sources))
        throw new Error();
      return data;
    } catch {
      entry.expires = Date.now() + 5000;
      return {
        schemaVersion: 1,
        version: "unconfigured",
        builtAt: "",
        profile: "none",
        sources: [],
      } as DatasetManifest;
    }
  })();
  manifestCache.set(env.ASSETS, entry);
  return entry.promise;
}
export function sourceStatuses(
  manifest: DatasetManifest,
  now = new Date(),
): SourceStatus[] {
  return manifest.sources.map(({ shards, ...s }) => ({
    ...s,
    state:
      s.state === "ready" &&
      s.expiresAt &&
      Date.parse(s.expiresAt) <= now.getTime()
        ? "stale"
        : s.state,
  }));
}
function addressLabel(hex: string, family: 4 | 6): string {
  if (family === 4)
    return hex
      .match(/../g)!
      .map((s) => Number.parseInt(s, 16))
      .join(".");
  return parseIp(hex.match(/.{4}/g)!.join(":"))!.canonical;
}
type Match = { payload: IntelPayload; start: string; end: string };
async function querySource(
  env: IntelligenceEnv,
  source: SourceManifest,
  ipHex: string,
  family: 4 | 6,
  budget: { remaining: number },
): Promise<Match[]> {
  const shards = source.shards.filter(
    (s) => s.family === family && s.start <= ipHex && s.end >= ipHex,
  );
  if (shards.length > budget.remaining)
    throw new Error("Intelligence query asset budget exceeded");
  budget.remaining -= shards.length;
  const found: Match[] = [];
  for (let at = 0; at < shards.length; at += 4) {
    const values = await Promise.all(
      shards
        .slice(at, at + 4)
        .map(async (s) =>
          lookupVerifiedShardMatches(
            await loadBytes(env, s.path, s.sha256, s.byteLength),
            ipHex,
          ),
        ),
    );
    found.push(...values.flat());
  }
  return found;
}
export async function queryIntelligence(
  env: IntelligenceEnv,
  manifest: DatasetManifest,
  ip: string,
  now = new Date(),
) {
  const parsed = parseIp(ip);
  if (!parsed) throw new Error("Invalid IP");
  const family = parsed.family,
    ipHex = parsed.value.toString(16).padStart(family === 4 ? 8 : 32, "0");
  const statuses = sourceStatuses(manifest, now),
    evidence: Evidence[] = [];
  const budget = { remaining: 12 }; // Bound shard reads separately from the Workers subrequest quota.
  const info: IpInfo = {
    ip: parsed.canonical,
    family,
    addressType: "public",
    networkType: "unknown",
    attributes: [],
  };
  // Sequential sources keep simultaneous asset connections bounded and isolate partial failures.
  const priority = (index: number) => statuses[index].state !== "ready" ? 2
    : statuses[index].id === "ipverse-network" ? 1 : 0;
  const ordered = manifest.sources.map((_, index) => index).sort((a, b) => priority(a) - priority(b));
  for (const index of ordered) {
    const source = manifest.sources[index],
      status = statuses[index];
    // Expired attribution cannot displace an active result. Preserve the source
    // status but reserve historical shard reads for threat and privacy evidence.
    const replacedAttribution = status.state === "stale" && source.categories.length > 0 &&
      ((info.asn !== undefined && source.categories.every(category => category === "asn" || category === "asn_reputation")) ||
       (info.geoSource !== undefined && source.categories.every(category => category === "geo")));
    if (
      !["ready", "stale"].includes(status.state) ||
      !source.families.includes(family) ||
      replacedAttribution
    )
      continue;
    try {
      const results = await querySource(env, source, ipHex, family, budget);
      status.matched = results.length > 0;
      results.forEach(({ payload: p, start, end }, i) => {
        const rangeLabel =
          start === end
            ? addressLabel(start, family)
            : `${addressLabel(start, family)} – ${addressLabel(end, family)}`;
        if (status.state === "ready") {
          if (p.kind === "asn" && info.asn === undefined) {
            info.asn = p.asn;
            info.asOrganization = p.organization;
            info.asnSource = source.name;
            info.asnUpdatedAt = source.publishedAt || source.fetchedAt;
            info.network = rangeLabel;
          }
          if (p.kind === "geo") {
            // Replace a complete location record, including missing fields.
            // Never combine one provider's city with another provider's postal code.
            info.country = p.country;
            info.countryCode = p.countryCode;
            info.region = p.region;
            info.city = p.city;
            info.latitude = p.latitude;
            info.longitude = p.longitude;
            info.postalCode = p.postalCode;
            info.timezone = p.timezone;
            info.geoSource = source.name;
            info.geoSourceUrl = source.url;
            info.geoAccuracy = "approximate";
            info.geoUpdatedAt = source.publishedAt || source.fetchedAt;
          }
          for (const a of p.attributes || [])
            if (!info.attributes.includes(a)) info.attributes.push(a);
          if (
            p.kind === "network" &&
            info.asn === undefined &&
            p.asn !== undefined
          ) {
            info.asn = p.asn;
            info.asOrganization = p.organization;
            info.asnSource = source.name;
            info.asnUpdatedAt = source.publishedAt || source.fetchedAt;
          }
        }
        const category = p.kind === "tor" ? "tor" : p.category || p.kind;
        const description =
          p.description ||
          `${source.name}: ${p.kind === "threat" ? p.category || "known abuse" : p.networkType || p.kind}`;
        const base: Evidence = {
          id: `${source.id}:${i}:${p.kind}`,
          sourceId: source.id,
          sourceName: source.name,
          sourceUrl: source.url,
          upstreamFamily:
            p.upstreamFamily || source.upstreamFamilies[0] || source.id,
          category: category as Evidence["category"],
          value:
            p.kind === "asn"
              ? (p.asn ?? 0)
              : p.networkType || p.category || true,
          confidence: p.confidence || source.confidence,
          description: { zh: description, en: description },
          observedAt: p.observedAt,
          publishedAt: source.publishedAt,
          fetchedAt: source.fetchedAt,
          expiresAt: source.expiresAt,
          matchedRange:
            p.prefix ||
            (start === end
              ? `${addressLabel(start, family)}/${family === 4 ? 32 : 128}`
              : undefined),
          matchedRangeLabel: rangeLabel,
          eventId: p.eventId,
          networkType: p.networkType,
          networkBasis: p.networkBasis,
          stale: status.state === "stale",
        };
        evidence.push(base);
        if (p.kind !== "asn" && p.asn !== undefined)
          evidence.push({
            ...base,
            id: base.id + ":asn",
            category: "asn",
            value: p.asn,
            networkType: undefined,
            networkBasis: undefined,
            attribute: undefined,
          });
        if (p.attributes?.length) {
          for (const a of p.attributes)
            evidence.push({
              ...base,
              id: base.id + ":" + a,
              attribute: a,
              category:
                a === "tor"
                  ? "tor"
                  : a === "vpn"
                    ? "vpn"
                    : a.includes("proxy")
                      ? "proxy"
                      : base.category,
            });
        }
      });
    } catch {
      status.state = "unavailable";
      status.matched = undefined;
      status.error =
        "The local snapshot could not be read / 本地情报快照无法读取";
    }
  }
  return { info, evidence, sources: statuses };
}

/** Resolve public DNS observations with one shared asset budget. */
export async function enrichResolvers(env: IntelligenceEnv, resolvers: Record<string, unknown>[]) {
  const manifest = await loadManifest(env);
  const statuses = sourceStatuses(manifest);
  const budget = { remaining: 8 };
  const seen = new Map<string, Record<string, unknown>>();
  for (const resolver of resolvers) {
    const ip = parseIp(resolver.ip);
    if (!ip?.isPublic) continue;
    if (!seen.has(ip.canonical)) {
      const details: Record<string, unknown> = {};
      const hex = ip.value.toString(16).padStart(ip.family === 4 ? 8 : 32, "0");
      for (const category of ["asn", "geo"] as const) {
        for (const [index, source] of manifest.sources.entries()) {
          if (!budget.remaining) break;
          if (statuses[index].state !== "ready" || !source.categories.includes(category) || !source.families.includes(ip.family)) continue;
          try {
            const hit = (await querySource(env, source, hex, ip.family, budget)).find(match => match.payload.kind === category)?.payload;
            if (!hit) continue;
            if (category === "asn") {
              details.asn = hit.asn;
              details.organization = hit.organization;
              details.asnSource = source.name;
            } else {
              details.country = hit.countryCode;
              details.geoSource = source.name;
            }
            break;
          } catch {
            // The observation remains usable if attribution fails.
          }
        }
      }
      seen.set(ip.canonical, details);
    }
    Object.assign(resolver, seen.get(ip.canonical));
  }
}
