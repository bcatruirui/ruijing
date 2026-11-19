import { readFile } from "node:fs/promises";
import { parseIp } from "../shared/ip.ts";
import { download, ipRecord, isoDate, lines } from "./data-utils.mjs";

const url = "https://www.dshield.org/feeds_doc.html";
const servicePorts = new Set(["22", "23", "445", "2375", "3389", "5900", "6379", "9200"]);
const schema = "# source IP\ttargetport\tprotocol\treports\ttargets\tfirstseen\tlastseen";

export async function registerDshield({ run, base, meta, reuse, compareRecords }) {
  await run(base("dshield", "SANS ISC DShield scanner observations", url, "DShield attribution terms", ["scanner"], ["sans-isc-dshield"], 54,
    { licenseUrl: url, licenseAttribution: "SANS Technology Institute, Internet Storm Center, https://isc.sans.edu. Transformed subset of daily_sources. No resale.", confidence: "low", limitedCoverage: true }),
    async (writer, source, previous) => {
      const receipt = await download("dshield-license.html", url, { reuse, maxBytes: 128 * 1024 });
      const license = await readFile(receipt.path, "utf8");
      if (!license.includes("Do not resell the data") || !license.includes("with attribution") || !license.includes("Other commercial uses are allowed"))
        throw new Error("DShield attribution terms changed; review required");
      const resource = await download("dshield-daily-sources.tsv", "https://feeds.dshield.org/feeds/daily_sources", { reuse, maxBytes: 220 * 1024 * 1024 });
      if (previous?.sha256 === resource.sha256 && previous.shards.length) return "unchanged";
      let published;
      let hasSchema = false;
      const addresses = new Map();
      for await (const line of lines(resource.path, false)) {
        if (line.startsWith("#")) {
          if (line === schema) hasSchema = true;
          const date = line.match(/^# updated (\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d) UTC$/);
          if (date) published = isoDate(`${date[1]}T${date[2]}Z`);
          continue;
        }
        if (!line) continue;
        if (!published || !hasSchema) throw new Error("DShield header changed");
        const columns = line.split("\t");
        if (columns.length !== 7) throw new Error("DShield row schema changed");
        const [address, port, protocol, reports, targets] = columns;
        if (!servicePorts.has(port) || protocol !== "6" || Number(reports) < 50 || Number(targets) < 20 ||
            !/^\d+$/.test(reports) || !/^\d+$/.test(targets)) continue;
        const ip = parseIp(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(address) ? address.split(".").map(Number).join(".") : address);
        if (!ip?.isPublic) continue;
        if ((addresses.get(ip.canonical) ?? 0) < Number(targets)) addresses.set(ip.canonical, Number(targets));
        if (addresses.size > 80_000) throw new Error("DShield normalized source exceeds deployment budget");
      }
      if (!published || addresses.size < 25) throw new Error("DShield high-volume observations unexpectedly sparse");
      meta(source, resource, published);
      const records = [...addresses].map(([address, targets]) => ipRecord(address, {
        kind: "threat", category: "scanner", confidence: "low",
        description: `SANS ISC DShield logged repeated TCP traffic to a watched service, reported by ${targets} targets. This is a scanner observation with possible false positives.`,
        eventId: `dshield:${address}:${published}`,
      }));
      for (const record of records.sort(compareRecords)) await writer.add(record);
    });
}
