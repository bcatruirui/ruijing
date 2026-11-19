import { mkdir, readFile, writeFile, rename, rm, stat, cp, open, unlink } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { encodeShard } from "../shared/dataset.ts";
import { parseIp } from "../shared/ip.ts";
import { registerProxySources } from "./proxy-sources.mjs";
import { ffraudRelease, registerAsnReputation } from "./asn-reputation.mjs";
import { registerAttributionFallbacks } from "./attribution-sources.mjs";
import { registerDshield } from "./dshield-source.mjs";
import {
  ROOT,
  GENERATED,
  download,
  lines,
  csv,
  address,
  interval,
  ipRecord,
  sha256,
  now,
  isoDate,
  readSmallJson,
  externalSort,
  parseDbipCityLine,
} from "./data-utils.mjs";

const args = new Set(process.argv.slice(2));
const profileArg = process.argv
  .find((v) => v.startsWith("--profile="))
  ?.split("=")[1];
const profile = profileArg ?? (args.has("--quick") ? "quick" : "standard");
if (!["quick", "standard"].includes(profile))
  throw new Error("Use --profile=quick or --profile=standard");
const reuse = args.has("--reuse-cache");
const withCity = profile === "standard" && !args.has("--without-city");
const maxBytes = 128 * 1024;
const stage = path.join(ROOT, "data", `.staging-${process.pid}`);
const attributions = path.join(ROOT, "docs", "third-party");

async function safeRemove(target) {
  const root = path.resolve(ROOT, "data");
  const resolved = path.resolve(target);
  if (!resolved.startsWith(root + path.sep) || resolved === root)
    throw new Error("Refusing deletion outside project data");
  await rm(resolved, { recursive: true, force: true });
}
await mkdir(path.dirname(GENERATED), { recursive: true });
const lockPath = path.join(path.dirname(GENERATED), ".refresh.lock");
const lock = await open(lockPath, "wx").catch(error => {
  if (error.code === "EEXIST") throw new Error("A data refresh is already running. Check ownership of data/.refresh.lock before recovering an interrupted run.");
  throw error;
});
try {
await lock.writeFile(String(process.pid));
await mkdir(stage, { recursive: true });
await mkdir(attributions, { recursive: true });
const sources = [];
const onlyArg = process.argv.find(v => v.startsWith("--only="))?.slice(7);
const only = onlyArg ? new Set(onlyArg.split(",")) : undefined;
const loaded = await readFile(path.join(GENERATED, "manifest.json"), "utf8")
  .then(JSON.parse).catch(error => { if (error.code !== "ENOENT") throw error; });
const previousManifest = loaded?.profile === profile ? loaded : undefined;
if (only && (!previousManifest || [...only].some(id => !["iptoasn-v4", "iptoasn-v6", "openasn", "dbip-city", "tor", "ffraud", "feodo", "monosans-proxies", "ffraud-asn", "carpathian", "dbip-asn", "ipverse-network", "dshield"].includes(id)))) throw new Error("Partial refresh requires matching profile and recognized sources");
if (only && ["iptoasn-v4", "iptoasn-v6", "ffraud"].some(id => only.has(id))) only.add("ffraud-asn");
if (only?.has("dbip-asn")) only.add("ipverse-network");

class SourceWriter {
  constructor(source) {
    this.source = source;
    this.blocks = new Map();
    this.previous = new Map();
    this.index = 0;
  }
  async add(record) {
    if (!record || ![4, 6].includes(record.family) || record.start > record.end)
      throw new Error("Invalid normalized record");
    const prior = this.previous.get(record.family);
    if (prior && prior > record.start)
      throw new Error("Source intervals are not sorted");
    this.previous.set(record.family, record.start);
    let block = this.blocks.get(record.family);
    if (!block) {
      block = { rows: [], keys: new Set(), jsonBytes: 8 };
      this.blocks.set(record.family, block);
    }
    const key = JSON.stringify(record.payload);
    const extra = block.keys.has(key) ? 0 : Buffer.byteLength(key) + 4;
    const recordWidth = record.family === 4 ? 12 : 36;
    const countLimit = record.family === 4 ? 4096 : 2048;
    if (
      block.rows.length &&
      (block.rows.length >= countLimit ||
        16 + (block.rows.length + 1) * recordWidth + block.jsonBytes + extra >
          maxBytes)
    ) {
      await this.flush(record.family);
      block = this.blocks.get(record.family);
    }
    block.rows.push(record);
    if (!block.keys.has(key)) {
      // V2 has count + initial offset (8 bytes), then one u32 end-offset per payload.
      block.jsonBytes += Buffer.byteLength(key) + 4;
      block.keys.add(key);
    }
    this.source.count++;
  }
  async flush(family) {
    const block = this.blocks.get(family);
    if (!block?.rows.length) return;
    await this.write(block.rows);
    this.blocks.set(family, { rows: [], keys: new Set(), jsonBytes: 8 });
  }
  async write(rows) {
    let bytes;
    try {
      bytes = encodeShard(rows);
    } catch (error) {
      if (rows.length === 1 || error.message !== "Intelligence shard too large")
        throw error;
      const split = Math.floor(rows.length / 2);
      await this.write(rows.slice(0, split));
      await this.write(rows.slice(split));
      return;
    }
    if (bytes.byteLength > maxBytes) {
      if (rows.length === 1)
        throw new Error("A single payload exceeds shard budget");
      const split = Math.floor(rows.length / 2);
      await this.write(rows.slice(0, split));
      await this.write(rows.slice(split));
      return;
    }
    const id = String(this.index++).padStart(5, "0");
    const relative = `/_intel/${this.source.id}/${id}.bin`;
    const target = path.join(stage, relative.slice(1));
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, bytes);
    this.source.shards.push({
      id,
      path: relative,
      family: rows[0].family,
      start: rows[0].start,
      end: rows.reduce((m, r) => (r.end > m ? r.end : m), rows[0].end),
      count: rows.length,
      byteLength: bytes.byteLength,
      sha256: sha256(bytes),
    });
  }
  async done() {
    await this.flush(4);
    await this.flush(6);
    this.source.shards.sort(
      (a, b) => a.family - b.family || a.start.localeCompare(b.start),
    );
  }
}

function base(
  id,
  name,
  url,
  license,
  categories,
  upstreamFamilies,
  ttlHours,
  extra = {},
) {
  return {
    id,
    name,
    url,
    license,
    categories,
    upstreamFamilies,
    families: [4, 6],
    state: "unavailable",
    confidence: "medium",
    count: 0,
    negativeCoverageEligible: false,
    shards: [],
    ttlHours,
    ...extra,
  };
}
function meta(source, resource, publishedAt) {
  source.fetchedAt = resource.fetchedAt;
  source.publishedAt = isoDate(publishedAt) ?? resource.publishedAt;
  source.sha256 = resource.sha256;
  source.downloadUrl = resource.url;
}
async function run(source, build) {
  sources.push(source);
  const previous = previousManifest?.sources.find(s => s.id === source.id);
  const restore = async () => {
    const policy = source.positiveOnlyCategories;
    const limited = source.limitedCoverage;
    for (const key of Object.keys(source)) delete source[key];
    Object.assign(source, previous, policy ? { positiveOnlyCategories: policy } : {});
    if (limited) source.limitedCoverage = true;
    if (source.state === "ready" && Date.parse(source.expiresAt) <= Date.now()) source.state = "stale";
    if (source.shards.length) await cp(path.join(GENERATED, "_intel", source.id), path.join(stage, "_intel", source.id), { recursive: true, errorOnExist: true });
    process.stdout.write(`[data] ${source.id}: preserved existing snapshot\n`);
  };
  if (previous && only && !only.has(source.id)) {
    await restore();
    return;
  }
  const writer = new SourceWriter(source);
  process.stdout.write(`[data] ${source.id}: fetching public dataset\n`);
  try {
    if (await build(writer, source, previous) === "unchanged" && previous) {
      await restore();
      return;
    }
    await writer.done();
    source.families = [
      ...new Set(source.shards.map((shard) => shard.family)),
    ].sort();
    const anchor = source.publishedAt ?? source.fetchedAt;
    if (!anchor) throw new Error("Missing source timestamp");
    if (previous?.shards.length && Date.parse(anchor) < Date.parse(previous.publishedAt ?? previous.fetchedAt))
      throw new Error("Upstream publication regressed");
    if (["iptoasn-v4", "iptoasn-v6", "openasn", "dbip-city"].includes(source.id) && previous?.count &&
        (source.count < previous.count * 0.75 || previous.families.some(family => !source.families.includes(family))))
      throw new Error("Core coverage shrank; inspect the upstream schema and snapshot");
    if (Date.parse(anchor) > Date.now() + 86400000)
      throw new Error("Source timestamp is implausibly in the future");
    source.expiresAt = new Date(
      Date.parse(anchor) + source.ttlHours * 3600000,
    ).toISOString();
    source.state =
      Date.parse(source.expiresAt) < Date.now() ? "stale" : "ready";
    process.stdout.write(
      `[data] ${source.id}: ${source.state}, ${source.count} records, ${source.shards.length} shards\n`,
    );
  } catch (error) {
    source.state = "unavailable";
    source.error = String(error?.message ?? "Source build failed").slice(
      0,
      200,
    );
    source.count = 0;
    source.shards = [];
    await safeRemove(path.join(stage, "_intel", source.id));
    process.stdout.write(
      `[data] ${source.id}: unavailable (${source.error})\n`,
    );
    if (previous?.shards.length) {
      await restore();
      return;
    }
  }
  delete source.ttlHours;
}

for (const family of [4, 6]) {
  const s = base(
    `iptoasn-v${family}`,
    `IPtoASN IPv${family}`,
    "https://iptoasn.com/",
    "PDDL-1.0",
    ["asn"],
    ["iptoasn-bgp"],
    72,
    {
      families: [family],
      confidence: "high",
      licenseUrl: "https://opendatacommons.org/licenses/pddl/1-0/",
      licenseAttribution: "IPtoASN — Frank Denis; PDDL 1.0.",
    },
  );
  await run(s, async (writer, source) => {
    const resource = await download(
      `ip2asn-v${family}.tsv.gz`,
      `https://iptoasn.com/data/ip2asn-v${family}.tsv.gz`,
      { reuse },
    );
    meta(source, resource);
    for await (const line of lines(resource.path)) {
      if (!line || line.startsWith("#")) continue;
      const [start, end, asnText, countryCode, ...name] = line.split("\t");
      const asn = Number(asnText);
      if (!Number.isSafeInteger(asn) || asn < 0 || asn > 0xffffffff)
        throw new Error("Invalid ASN");
      if (!asn) continue; // Explicit unmapped ranges are not attribution evidence.
      const record = interval(start, end, {
        kind: "asn",
        asn,
        organization: name.join("\t").slice(0, 512),
        ...(countryCode && countryCode !== "ZZ" ? { countryCode } : {}),
        confidence: "high",
        upstreamFamily: "iptoasn-bgp",
      });
      if (record.family !== family)
        throw new Error("Unexpected address family");
      await writer.add(record);
    }
    if (source.count < 1000)
      throw new Error("ASN download is unexpectedly small");
  });
}

await registerAttributionFallbacks({ run, base, meta, sources, reuse });

await run(
  base(
    "openasn",
    "OpenASN Tier A",
    "https://github.com/openasn/openasn",
    "CC0-1.0 + upstream notices",
    ["network", "vpn"],
    ["openasn-core"],
    24 * 30,
    {
      licenseUrl: "https://github.com/openasn/openasn/blob/main/ATTRIBUTION.md",
      licenseAttribution:
        "OpenASN CC0 core; RouteViews CC BY 4.0; X4B and Brian Hamachek MIT. See docs/third-party/OPENASN_ATTRIBUTION.md.",
    },
  ),
  async (writer, source) => {
    const prefix =
      "https://github.com/openasn/openasn/releases/download/latest/";
    const receipt = await download(
      "openasn-manifest.json",
      prefix + "manifest.json",
      { reuse, maxBytes: 1024 * 1024 },
    );
    const manifest = await readSmallJson(receipt.path, 1024 * 1024);
    const file = manifest.files?.find((f) => f.name === "openasn.csv.gz");
    const e = file?.export;
    if (
      manifest.edition !== "core" ||
      manifest.format_version !== 1 ||
      e?.schema_version !== 1 ||
      e.classification_profile !== "core-v1" ||
      e.lookup_policy_version !== 1 ||
      e.scope !== "tier_a" ||
      e.tier_b_included !== false
    )
      throw new Error("Unsupported OpenASN core/export contract");
    const resource = await download(
      "openasn.csv.gz",
      prefix + "openasn.csv.gz",
      { reuse },
    );
    if (resource.sha256 !== file.sha256 || resource.byteLength !== file.bytes)
      throw new Error("OpenASN release SHA256 mismatch");
    const attribution = await download(
      "openasn-ATTRIBUTION.md",
      prefix + "ATTRIBUTION.md",
      { reuse, maxBytes: 128 * 1024 },
    );
    const attributionEntry = manifest.files.find(
      (f) => f.name === "ATTRIBUTION.md",
    );
    if (attribution.sha256 !== attributionEntry?.sha256)
      throw new Error("OpenASN attribution checksum mismatch");
    await writeFile(
      path.join(attributions, "OPENASN_ATTRIBUTION.md"),
      await readFile(attribution.path),
    );
    const commit = manifest.export_producer?.data_repo_commit;
    if (!/^[a-f0-9]{40}$/.test(commit ?? ""))
      throw new Error("OpenASN provenance commit missing");
    for (const id of [
      "routeviews",
      "x4bnet-lists_vpn",
      "brianhama-bad-asn-list",
    ]) {
      const receiptSource = manifest.sources?.find((s) => s.id === id);
      const notice = await download(
        `openasn-${id}-license.txt`,
        `https://raw.githubusercontent.com/openasn/openasn/${commit}/data/licenses/${id}.txt`,
        { reuse, maxBytes: 1024 * 1024 },
      );
      if (notice.sha256 !== receiptSource?.license_sha256)
        throw new Error(`OpenASN ${id} license receipt checksum mismatch`);
      await writeFile(
        path.join(attributions, `OPENASN_${id}_LICENSE.txt`),
        await readFile(notice.path),
      );
    }
    meta(source, resource, manifest.build_id);
    let headers;
    const verdicts = {
      residential_isp: "residential",
      mobile: "mobile",
      business: "business",
      hosting: "hosting",
      education: "education",
    };
    for await (const line of lines(resource.path)) {
      if (!line) continue;
      const fields = csv(line);
      if (!headers) {
        headers = fields;
        if (
          !headers.includes("core_verdict") ||
          !headers.includes("core_sources")
        )
          throw new Error("OpenASN CSV schema changed");
        continue;
      }
      const row = Object.fromEntries(headers.map((h, i) => [h, fields[i]]));
      const reasons = row.core_sources.split("|");
      // X4B's DC overlay also covers VPN/non-eyeball space; alone it is not a confirmed hosting verdict.
      const networkType =
        row.core_verdict === "hosting" &&
        reasons.length === 1 &&
        reasons[0] === "x4b_dc"
          ? "unknown"
          : (verdicts[row.core_verdict] ?? "unknown");
      await writer.add(
        interval(row.start_ip, row.end_ip, {
          kind: "network",
          ...(row.asn ? { asn: Number(row.asn) } : {}),
          ...(row.as_org ? { organization: row.as_org } : {}),
          networkType,
          ...(row.core_verdict === "vpn" ? { attributes: ["vpn"] } : {}),
          confidence:
            networkType === "residential" || reasons.includes("x4b_dc")
              ? "low"
              : "medium",
          description: `OpenASN core-v1: ${row.core_verdict}; ${reasons.join(", ")}`,
          upstreamFamily: "openasn-core",
        }),
      );
    }
    if (source.count !== file.records)
      throw new Error("OpenASN record count mismatch");
  },
);

const geo = base(
  "dbip-city",
  "DB-IP City Lite",
  "https://db-ip.com/db/download/ip-to-city-lite",
  "CC-BY-4.0",
  ["geo"],
  ["dbip-lite"],
  24 * 65,
  {
    licenseUrl: "https://creativecommons.org/licenses/by/4.0/",
    licenseAttribution:
      "IP Geolocation by DB-IP — https://db-ip.com ; transformed into range shards; reduced coverage/accuracy.",
  },
);
if (withCity) {
  await run(geo, async (writer, source, previous) => {
    const pageResource = await download("dbip-city-download.html", source.url, {
      reuse,
      maxBytes: 1024 * 1024,
    });
    const page = await readFile(pageResource.path, "utf8");
    const match = page.match(
      /https:\/\/download\.db-ip\.com\/free\/dbip-city-lite-(\d{4})-(\d{2})\.csv\.gz/,
    );
    if (!match) throw new Error("DB-IP free CSV download link not found");
    const resource = await download(
      `dbip-city-lite-${match[1]}-${match[2]}.csv.gz`,
      match[0],
      { reuse, maxBytes: 250 * 1024 * 1024 },
    );
    meta(source, resource, `${match[1]}-${match[2]}-01T00:00:00Z`);
    if (previous?.sha256 === source.sha256 && previous.publishedAt === source.publishedAt && previous.shards.length)
      return "unchanged";
    for await (const line of lines(resource.path)) {
      if (!line) continue;
      await writer.add(parseDbipCityLine(line));
    }
    if (source.count < 1000000)
      throw new Error("DB-IP global dataset unexpectedly small");
  });
} else {
  geo.state = "unconfigured";
  geo.error =
    "City database excluded by this build profile; current-connection edge geolocation can still be available.";
  delete geo.ttlHours;
  sources.push(geo);
}

await run(
  base(
    "tor",
    "Tor Project CollecTor exit observations",
    "https://collector.torproject.org/recent/exit-lists/",
    "CC0-1.0",
    ["tor"],
    ["tor-project"],
    48,
    {
      confidence: "high",
      negativeCoverageEligible: false,
      licenseUrl: "https://metrics.torproject.org/collector.html",
      licenseAttribution: "Tor Metrics / CollecTor; CC0.",
    },
  ),
  async (writer, source) => {
    const index = await download("tor-exit-index.html", source.url, {
      reuse,
      maxBytes: 4 * 1024 * 1024,
    });
    const listing = await readFile(index.path, "utf8");
    const filenames = [
      ...listing.matchAll(/href="(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})"/g),
    ]
      .map((m) => m[1])
      .sort();
    const latest = filenames.at(-1);
    if (!latest) throw new Error("No CollecTor exit observation files found");
    const resource = await download(
      `tor-exits-${latest}.txt`,
      source.url + latest,
      { reuse },
    );
    const [y, mo, d, h, mi, s] = latest.split("-");
    meta(source, resource, `${y}-${mo}-${d}T${h}:${mi}:${s}Z`);
    const records = new Map();
    for await (const line of lines(resource.path, false)) {
      if (!line.startsWith("ExitAddress ")) continue;
      const [, ip, day, time] = line.split(/\s+/);
      const observedAt = isoDate(`${day}T${time}Z`);
      if (!observedAt) throw new Error("Invalid Tor observation timestamp");
      const r = ipRecord(ip, {
        kind: "tor",
        attributes: ["tor"],
        category: "tor",
        observedAt,
        confidence: "high",
        upstreamFamily: "tor-project",
      });
      const previous = records.get(ip);
      if (!previous || previous.payload.observedAt < observedAt)
        records.set(ip, r);
    }
    if (!records.size) throw new Error("Tor observation file is empty");
    for (const r of [...records.values()].sort(compareRecords))
      await writer.add(r);
  },
);

await run(
  base(
    "ffraud",
    "FFraud confirmed abusive observations",
    "https://github.com/FFraud-com/ip-fraud-database",
    "MIT",
    [
      "network", "proxy", "vpn", "tor",
      "other_abuse",
      "c2",
      "malware",
      "botnet",
      "brute_force",
      "web_attack",
      "scanner",
      "phishing",
      "spam",
    ],
    ["ffraud-aggregate"],
    24 * 7,
    {
      licenseUrl:
        "https://github.com/FFraud-com/ip-fraud-database/blob/main/LICENSE",
      licenseAttribution:
        "FFraud-com / ip-fraud-database; MIT, see docs/third-party/FFRAUD_LICENSE.txt.",
      positiveOnlyCategories: ["network", "proxy", "vpn", "tor"],
    },
  ),
  async (writer, source) => {
    const release = await ffraudRelease(reuse);
    const resource = await download(
      "ffraud-confirmed-abusive.csv",
      release.base + "threat-ips/confirmed-abusive.csv",
      { reuse, maxBytes: 64 * 1024 * 1024 },
    );
    await writeFile(
      path.join(attributions, "FFRAUD_LICENSE.txt"),
      release.licenseText,
    );
    meta(source, resource, release.publishedAt);
    const aliases = {
      "brute-force": "brute_force",
      "web-attack": "web_attack",
      "command-and-control": "c2",
      command_control: "c2",
    };
    const supported = new Set([
      "spam",
      "phishing",
      "malware",
      "botnet",
      "c2",
      "brute_force",
      "web_attack",
      "scanner",
    ]);
    async function* normalized() {
      let headers;
      for await (const line of lines(resource.path, false)) {
        if (!line || line.startsWith("#")) continue;
        const fields = csv(line);
        if (!headers) {
          headers = fields;
          if (!headers.includes("ip") || !headers.includes("category"))
            throw new Error("FFraud schema changed");
          continue;
        }
        const row = Object.fromEntries(headers.map((h, i) => [h, fields[i]]));
        const raw = String(row.category ?? "").toLowerCase();
        const mapped = aliases[raw] ?? raw;
        const category = supported.has(mapped) ? mapped : "other_abuse";
        const attribute =
          { proxy: "proxy", vpn: "vpn", tor: "tor" }[row.type] ?? "";
        const parsed = address(row.ip);
        // No activity/event ID is invented. A compact sortable projection keeps temp I/O small.
        yield [parsed.family, parsed.hex, category, attribute];
      }
    }
    const temporarySort = path.join(stage, ".sort-ffraud");
    try {
      let previousKey;
      for await (const [family, hex, category, attribute] of externalSort(
        normalized(),
        temporarySort,
        (a, b) =>
          a[0] - b[0] ||
          a[1].localeCompare(b[1]) ||
          a[2].localeCompare(b[2]) ||
          a[3].localeCompare(b[3]),
      )) {
        const key = `${family}:${hex}:${category}:${attribute}`;
        if (key === previousKey) continue;
        previousKey = key;
        await writer.add({
          family,
          start: hex,
          end: hex,
          payload: {
            kind: "threat",
            category,
            ...(attribute ? { attributes: [attribute] } : {}),
            confidence: "medium",
            upstreamFamily: "ffraud-aggregate",
            description:
              "Confirmed-abusive list membership; observation time and independent underlying sources are not supplied. Vendor score and confirmations are not used.",
          },
        });
      }
    } finally {
      await safeRemove(temporarySort);
    }
    if (source.count !== release.counts?.confirmed_abusive_ips) throw new Error("FFraud data row count differs from the pinned publication metadata");
  },
);

await run(
  base(
    "feodo",
    "abuse.ch Feodo Tracker recommended C2 list",
    "https://feodotracker.abuse.ch/blocklist/",
    "CC0-1.0",
    ["c2"],
    ["abuse-ch-feodo"],
    48,
    {
      confidence: "high",
      licenseUrl: "https://abuse.ch/terms-of-use/",
      licenseAttribution:
        "abuse.ch / Feodo Tracker; CC0 as stated in terms §3.4.",
    },
  ),
  async (writer, source) => {
    const resource = await download(
      "feodo-recommended.json",
      "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
      { reuse, maxBytes: 16 * 1024 * 1024 },
    );
    meta(source, resource);
    const data = await readSmallJson(resource.path);
    if (!Array.isArray(data)) throw new Error("Feodo schema changed");
    const rows = [];
    for (const item of data) {
      if (item.status && item.status !== "online") continue;
      const observedAt = isoDate(
        String(item.last_online ?? "").replace(" ", "T") +
          (/Z$/.test(item.last_online ?? "") ? "" : "Z"),
      );
      rows.push(
        ipRecord(item.ip_address, {
          kind: "threat",
          category: "c2",
          ...(observedAt ? { observedAt } : {}),
          confidence: "high",
          upstreamFamily: "abuse-ch-feodo",
          eventId: `feodo:${item.ip_address}:${item.malware ?? "unknown"}`,
          description: `Feodo recommended list; ${String(item.malware ?? "unspecified malware").slice(0, 100)}. Last-online time is retained and must be aged separately from download time.`,
        }),
      );
    }
    for (const r of rows.sort(compareRecords)) await writer.add(r);
  },
);

await registerProxySources({ run, base, meta, reuse, attributions });
await registerAsnReputation({ run, base, meta, reuse, attributions, sources });

await run(base("carpathian", "Carpathian first-party IDS observations",
  "https://carpathian.ai/threat-intelligence", "CC-BY-4.0", ["other_abuse"], ["carpathian-first-party-ids"], 8,
  { licenseUrl: "https://creativecommons.org/licenses/by/4.0/", licenseAttribution: "Carpathian — https://carpathian.ai/threat-intelligence; normalized first-party IDS records only.", limitedCoverage: true }),
  async (writer, source, previous) => {
    const resource = await download("carpathian-blocklist.json", "https://api.carpathian.ai/public/threat-intel/blocklist.json", { reuse, maxBytes: 4 * 1024 * 1024 });
    const snapshot = await readSmallJson(resource.path, 4 * 1024 * 1024);
    const sourceTime = value => typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(value) && isoDate(value + "Z");
    // The feed publishes its generation time as UTC on its website and via HTTP.
    const published = sourceTime(snapshot.generated_at);
    if (!published || !/^CC(?:[ -])BY(?:[ -])4\.0$/i.test(snapshot.license) || !Array.isArray(snapshot.entries) || snapshot.entries.length !== snapshot.count || snapshot.count > 25000)
      throw new Error("Carpathian publication, license or schema changed");
    meta(source, resource, published);
    if (previous?.sha256 === source.sha256 && previous.publishedAt === published && previous.shards.length) return "unchanged";
    const records = [];
    for (const item of snapshot.entries) {
      if (typeof item.sources !== "string" || !item.sources.split(",").includes("ids") || !Number.isSafeInteger(item.event_count) || item.event_count < 2) continue;
      const approximate = sourceTime(item.last_seen);
      if (!approximate || Date.parse(approximate) > Date.parse(published) || Date.parse(published) - Date.parse(approximate) > 29 * 86_400_000) continue;
      const parsed = parseIp(item.ip_address);
      if (!parsed?.isPublic) continue;
      const ip = parsed.canonical;
      records.push(ipRecord(ip, {
        kind: "threat", category: "other_abuse", confidence: "medium",
        eventId: `carpathian:ids:${ip}:${item.last_seen}`,
        description: "Carpathian reports repeated IDS events on its own infrastructure. Coverage is limited to its sensors. The per-event time has no timezone and is excluded from freshness scoring.",
      }));
    }
    if (!records.length) throw new Error("Carpathian first-party coverage is empty");
    for (const record of records.sort(compareRecords)) await writer.add(record);
  });

if (withCity) await registerDshield({ run, base, meta, reuse, compareRecords });

function compareRecords(a, b) {
  return (
    a.family - b.family ||
    a.start.localeCompare(b.start) ||
    a.end.localeCompare(b.end)
  );
}

const builtAt = now();
const manifest = {
  schemaVersion: 1,
  encodingVersion: 2,
  version: "rj-" + sha256(JSON.stringify(sources)).slice(0, 16),
  builtAt,
  profile,
  sources,
};
await writeFile(
  path.join(stage, "manifest.json"),
  JSON.stringify(manifest) + "\n",
);
await writeFile(
  path.join(stage, "BUILD_SUMMARY.json"),
  JSON.stringify(
    {
      builtAt,
      profile,
      version: manifest.version,
      encodingVersion: 2,
      realData: true,
      sourceCount: sources.length,
      available: sources.filter((s) => s.state === "ready").length,
      records: sources.reduce((n, s) => n + s.count, 0),
      shards: sources.reduce((n, s) => n + s.shards.length, 0),
      sources: sources.map(({ shards, ...s }) => s),
    },
    null,
    2,
  ) + "\n",
);
const audit = spawnSync(process.execPath, [path.join(ROOT, "scripts/check-budget.mjs"), `--staging=${path.basename(stage)}`], { stdio: "inherit" });
if (audit.status !== 0) throw new Error("Candidate snapshot failed shard and asset validation");
const runtime = spawnSync(process.execPath, [path.join(ROOT, "scripts/prepare-runtime.mjs"), `--staging=${path.basename(stage)}`], { stdio: "inherit" });
if (runtime.status !== 0) throw new Error("Candidate snapshot failed Worker metadata validation");
if (manifest.version === previousManifest?.version) {
  process.stdout.write(`[data] no change: ${manifest.version}\n`);
} else {
const backup = path.join(ROOT, "data", `.previous-${process.pid}`);
let hadPrevious = false;
try {
  await stat(GENERATED);
  await rename(GENERATED, backup);
  hadPrevious = true;
} catch (e) {
  if (e.code !== "ENOENT") throw e;
}
try {
  await rename(stage, GENERATED);
} catch (error) {
  if (hadPrevious) await rename(backup, GENERATED);
  throw error;
}
if (hadPrevious) await safeRemove(backup);
}
process.stdout.write(
  `[data] built ${manifest.version}; ${sources.filter((s) => s.state === "ready").length}/${sources.length} ready; ${manifest.sources.reduce((n, s) => n + s.count, 0)} genuine records\n`,
);
if (![4, 6].every(family => sources.some(s => s.state === "ready" && s.categories.includes("asn") && s.families.includes(family))))
  process.exitCode = 1;
if (withCity && geo.state === "unavailable") process.exitCode = 1;
} finally {
  try { await safeRemove(stage); } finally {
    await lock.close();
    await unlink(lockPath);
  }
}
