import { appendFile, readFile } from "node:fs/promises";
import path from "node:path";
import { GENERATED } from "./data-utils.mjs";
import { parseIp } from "../shared/ip.ts";

const base = new URL(process.env.WORKER_API_BASE || "");
if (base.protocol !== "https:" || base.origin !== process.env.WORKER_API_BASE)
  throw new Error("WORKER_API_BASE must be an HTTPS origin without a path");
const origin = process.env.PAGES_ORIGIN;
if (origin && (new URL(origin).origin !== origin || !origin.startsWith("https://")))
  throw new Error("PAGES_ORIGIN must be an exact HTTPS origin");
const fresh = source => source.state === "ready" && Date.parse(source.expiresAt) > Date.now();
const hasCoreCoverage = sources => {
  const ready = sources.filter(fresh);
  return [4, 6].every(family => ready.some(source => source.categories?.includes("asn") && source.families?.includes(family))) &&
    ready.some(source => source.id === "dbip-city") && ready.some(source => ["openasn", "ipverse-network"].includes(source.id));
};
const local = process.argv.includes("--candidate") || process.argv.includes("--match")
  ? JSON.parse(await readFile(path.join(GENERATED, "manifest.json"), "utf8")) : null;
if (local && (local.profile !== "standard" || !hasCoreCoverage(local.sources)))
  throw new Error("Candidate missing a fresh IPv4 ASN, IPv6 ASN, network-classification or city source");
async function request(route, init) {
  return fetch(new URL(route, base), { redirect: "error", cache: "no-store", signal: AbortSignal.timeout(10000), ...init });
}
let published;
try {
  const response = await request("/api/capabilities");
  if (!response.ok) throw new Error(`Capabilities HTTP ${response.status}`);
  published = await response.json();
  if (!/^rj-[a-f0-9]{16}$/.test(published.datasetVersion) || !Array.isArray(published.sources))
    throw new Error("Invalid published snapshot metadata");
} catch (error) {
  if (!process.argv.includes("--bootstrap") || !process.argv.includes("--candidate")) throw error;
}
if (process.argv.includes("--candidate")) {
  const changed = local.version !== published?.datasetVersion;
  if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `changed=${changed}\n`);
  console.log(`Verified candidate ${local.version}. Currently published: ${published?.datasetVersion ?? "bootstrap"}.`);
} else {
  if (!hasCoreCoverage(published.sources)) throw new Error("The deployed dataset is missing fresh core coverage");
  const degraded = published.sources.filter(source => !fresh(source)).map(source => `${source.id} (${source.state})`);
  if (degraded.length) console.log(`Degraded public sources: ${degraded.join(", ")}`);
  if (local && published.datasetVersion !== local.version) throw new Error("Published dataset version differs from the tested candidate");
  if (origin) {
    const headers = { Origin: origin, "Sec-Fetch-Site": "cross-site" };
    const preflight = await request("/api/lookup", { method: "OPTIONS", headers: { ...headers, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "Content-Type" } });
    if (preflight.status !== 204 || preflight.headers.get("Access-Control-Allow-Origin") !== origin) throw new Error("Pages origin preflight failed");
    for (const ip of ["8.8.8.8", "2001:4860:4860::8888"]) {
      const response = await request("/api/lookup", { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: JSON.stringify({ ip }) });
      if (!response.ok || response.headers.get("Access-Control-Allow-Origin") !== origin || !response.headers.get("Cache-Control")?.includes("no-store"))
        throw new Error("Published cross-origin lookup failed");
      const report = await response.json();
      if (report.info?.ip !== ip || report.assessment?.datasetVersion !== published.datasetVersion || !report.purity)
        throw new Error("Published lookup returned inconsistent data");
    }
    const self = await request("/api/self", { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: "{}" });
    if (!self.ok || self.headers.get("Access-Control-Allow-Origin") !== origin) throw new Error("Published self detection failed");
    const report = await self.json();
    if (report.mode !== "self" || !parseIp(report.info?.ip)?.isPublic || report.assessment?.datasetVersion !== published.datasetVersion)
      throw new Error("Published self detection has missing or inconsistent edge metadata");
    for (const route of ["/api/self", "/api/echo"]) {
      const response = await request(route, { headers });
      if (!response.ok || response.headers.get("Access-Control-Allow-Origin") !== origin || !response.headers.get("Cache-Control")?.includes("no-store"))
        throw new Error(`Published direct ${route} failed`);
      const result = await response.json();
      const ip = route === "/api/self" ? result.info?.ip : result.ip;
      if (!parseIp(ip)?.isPublic || (route === "/api/self" && result.mode !== "self"))
        throw new Error(`Published direct ${route} has missing edge metadata`);
    }
  }
  console.log(`Published snapshot ${published.datasetVersion} passed its health checks.`);
}
