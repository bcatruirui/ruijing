import { readFile } from "node:fs/promises";
import { csv, download, githubFileRevision, interval, lines, readSmallJson, sha256 } from "./data-utils.mjs";

const dbip = "https://db-ip.com/db/download/ip-to-asn-lite";
const dbipLicense = "https://creativecommons.org/licenses/by/4.0/";
const taxonomy = "https://github.com/ipverse/as-metadata";
const taxonomyTypes = new Map([["hosting", "hosting"], ["business", "business"], ["education_research", "education"]]);

async function* asnRanges(filename) {
  for await (const line of lines(filename)) {
    if (!line) continue;
    const fields = csv(line);
    const [start, end, integer, organization] = fields;
    if (fields.length !== 4 || !/^\d{1,10}$/.test(integer) || Number(integer) > 0xffffffff)
      throw new Error("DB-IP ASN Lite CSV schema changed");
    const asn = Number(integer);
    if (asn) yield { start, end, asn, organization: organization.slice(0, 200) };
  }
}

export async function registerAttributionFallbacks({ run, base, meta, sources, reuse }) {
  const getDownload = async () => {
    const page = await download("dbip-asn-download.html", dbip, { reuse, maxBytes: 1_048_576 });
    const edition = (await readFile(page.path, "utf8")).match(/https:\/\/download\.db-ip\.com\/free\/dbip-asn-lite-(\d{4})-(\d{2})\.csv\.gz/);
    if (!edition) throw new Error("DB-IP ASN Lite free edition not found");
    const resource = await download(`dbip-asn-lite-${edition[1]}-${edition[2]}.csv.gz`, edition[0], { reuse, maxBytes: 64 * 1024 * 1024 });
    return { resource, publishedAt: `${edition[1]}-${edition[2]}-01T00:00:00.000Z` };
  };
  let attachment;
  await run(base("dbip-asn", "DB-IP ASN Lite", dbip, "CC-BY-4.0", ["asn"], ["dbip-lite"], 24 * 65,
    { licenseUrl: dbipLicense, licenseAttribution: "ASN ranges by DB-IP — https://db-ip.com; transformed into range shards." }),
    async (writer, source, previous) => {
      attachment = await getDownload();
      const { resource, publishedAt } = attachment;
      meta(source, resource, publishedAt);
      if (previous?.sha256 === source.sha256 && previous.publishedAt === source.publishedAt && previous.shards.length) return "unchanged";
      for await (const { start, end, asn, organization } of asnRanges(resource.path))
        await writer.add(interval(start, end, { kind: "asn", asn, organization, confidence: "medium" }));
      if (source.count < 100_000) throw new Error("DB-IP ASN Lite coverage unexpectedly small");
    });

  await run(base("ipverse-network", "ipverse ASN categories · DB-IP prefix join", taxonomy, "CC0-1.0 + CC-BY-4.0",
    ["network"], ["ipverse-as-metadata", "dbip-lite"], 24 * 14, {
      licenseUrl: taxonomy + "/blob/master/LICENSE",
      licenseAttribution: "ipverse ASN categories (CC0) joined to DB-IP ASN Lite (CC BY 4.0, https://db-ip.com).",
      positiveOnlyCategories: ["network"],
    }), async (writer, source, previous) => {
      const mapping = sources.find(row => row.id === "dbip-asn" && row.state === "ready");
      if (!mapping) throw new Error("Verified DB-IP ASN mapping is unavailable");
      if (!attachment) {
        const filename = new URL(mapping.downloadUrl).pathname.split("/").at(-1);
        if (!/^dbip-asn-lite-\d{4}-\d{2}\.csv\.gz$/.test(filename)) throw new Error("Invalid ASN fallback receipt");
        attachment = { resource: await download(filename, mapping.downloadUrl, { reuse: true, maxBytes: 64 * 1024 * 1024 }) };
      }
      if (attachment.resource.sha256 !== mapping.sha256) throw new Error("ASN fallback join differs from the validated mapping");
      const revision = await githubFileRevision("ipverse-as-revision.atom", "ipverse/as-metadata", "master", "as.json", reuse);
      const license = await download("ipverse-CC0.txt", revision.raw + "LICENSE", { reuse, maxBytes: 64 * 1024 });
      if (!/CC0 1\.0 Universal/.test(await readFile(license.path, "utf8"))) throw new Error("ipverse data license changed");
      const resource = await download("ipverse-as.json", revision.raw + "as.json", { reuse, maxBytes: 110 * 1024 * 1024 });
      meta(source, resource, revision.publishedAt);
      source.sha256 = sha256(`${resource.sha256}:${mapping.sha256}:${license.sha256}`);
      source.ttlHours = Math.min(source.ttlHours, (Date.parse(mapping.expiresAt) - Date.parse(source.publishedAt)) / 3600000);
      if (previous?.sha256 === source.sha256 && previous.publishedAt === source.publishedAt && previous.shards.length) return "unchanged";
      const rows = await readSmallJson(resource.path, 110 * 1024 * 1024);
      if (!Array.isArray(rows) || rows.length < 10000 || rows.length > 250000) throw new Error("ipverse ASN metadata coverage unexpectedly changed");
      const types = new Map();
      for (const row of rows) {
        const type = taxonomyTypes.get(row.metadata?.category);
        if (Number.isInteger(row.asn) && row.asn > 0 && type) types.set(row.asn, type);
      }
      for await (const { start, end, asn } of asnRanges(attachment.resource.path)) {
        if (!types.has(asn)) continue;
        await writer.add(interval(start, end, { kind: "network", networkType: types.get(asn), confidence: "medium",
          description: "ipverse classifies the ASN's primary network function. The DB-IP ASN range does not establish individual use or proxy membership." }));
      }
      if (source.count < 1000) throw new Error("ipverse classification coverage unexpectedly small");
    });
}
