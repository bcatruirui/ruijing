import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { download, csv, lines, interval, readSmallJson, isoDate, githubFileRevision } from "./data-utils.mjs";

let release;
export function ffraudRelease(reuse) {
  return release ??= (async () => {
    const { raw: base } = await githubFileRevision("ffraud-revision.atom", "FFraud-com/ip-fraud-database", "main", "metadata.json", reuse);
    const metadata = await download("ffraud-metadata.json", base + "metadata.json", { reuse, maxBytes: 32 * 1024 });
    const descriptor = await readSmallJson(metadata.path, 32 * 1024);
    const publishedAt = typeof descriptor.generated_utc === "string" && descriptor.generated_utc.endsWith("Z") && isoDate(descriptor.generated_utc);
    if (!publishedAt || descriptor.license !== "MIT" || descriptor.project !== "ip-fraud-database") throw new Error("Invalid FFraud release metadata");
    const license = await download("ffraud-LICENSE.txt", base + "LICENSE", { reuse, maxBytes: 65536 });
    const licenseText = await readFile(license.path, "utf8");
    if (!licenseText.includes("MIT License") || !licenseText.includes("of this data")) throw new Error("FFraud data license changed; review required");
    return { base, publishedAt, licenseText, counts: descriptor.counts };
  })();
}

// ASN sample statistics are context, not an address-level abuse finding.
// Deliberately do not import ffraud_risk_score or infer proxy membership.
export function parseAsnReputation(text) {
  const rows = text.split(/\r?\n/).filter(line => line && !line.startsWith("#"));
  if (rows.shift() !== "asn,organization,ips_observed,abuse_rate_pct,proxy_rate_pct,ffraud_risk_score")
    throw new Error("ASN reputation CSV schema changed");
  if (rows.length > 10000) throw new Error("ASN reputation exceeds budget");
  const result = new Map();
  for (const line of rows) {
    const fields = csv(line);
    if (fields.length !== 6) throw new Error("Invalid ASN reputation columns");
    const [asn, observed, abuse, proxy] = [fields[0], fields[2], fields[3], fields[4]].map(Number);
    if (!/^[1-9]\d*$/.test(fields[0]) || asn > 0xffffffff ||
      !/^[1-9]\d*$/.test(fields[2]) || !Number.isSafeInteger(observed) ||
      ![abuse, proxy].every(n => Number.isFinite(n) && n >= 0 && n <= 100) ||
      !fields[3].trim() || !fields[4].trim() || result.has(asn)) throw new Error("Invalid ASN sample statistics");
    result.set(asn, { asn, observed, abuse, proxy });
  }
  if (!result.size) throw new Error("Empty ASN reputation snapshot");
  return result;
}

export async function registerAsnReputation({ run, base, meta, reuse, attributions, sources }) {
  await run(base("ffraud-asn", "FFraud ASN observed-sample reputation", "https://github.com/FFraud-com/ip-fraud-database", "MIT + PDDL-1.0", ["asn_reputation"], ["ffraud-aggregate", "iptoasn-bgp"], 72, {
    confidence: "low",
    licenseUrl: "https://github.com/FFraud-com/ip-fraud-database/blob/main/LICENSE",
    licenseAttribution: "FFraud MIT sample statistics joined offline to IPtoASN PDDL ranges. Vendor scores are excluded. No per-IP abuse or proxy conclusion.",
  }), async (writer, source) => {
    const { base, licenseText, publishedAt, counts } = await ffraudRelease(reuse);
    const resource = await download("ffraud-asn-reputation.csv", base + "asn-reputation/high-abuse-networks.csv", { reuse, maxBytes: 2 * 1024 * 1024 });
    await writeFile(path.join(attributions, "FFRAUD_LICENSE.txt"), licenseText);
    const samples = parseAsnReputation(await readFile(resource.path, "utf8"));
    if (samples.size !== counts?.high_abuse_networks) throw new Error("FFraud ASN release count differs from metadata");
    meta(source, resource, publishedAt);
    const anchors = [Date.parse(source.publishedAt || source.fetchedAt)];
    for (const family of [4, 6]) {
      const asnSource = sources.find(s => s.id === `iptoasn-v${family}` && ["ready", "stale"].includes(s.state));
      if (!asnSource) continue;
      const mapping = await download(`ip2asn-v${family}.tsv.gz`, `https://iptoasn.com/data/ip2asn-v${family}.tsv.gz`, { reuse: true });
      if (mapping.sha256 !== asnSource.sha256) throw new Error("ASN join mapping differs from its verified source snapshot");
      anchors.push(Date.parse(mapping.publishedAt || mapping.fetchedAt));
      for await (const line of lines(mapping.path)) {
        if (!line || line.startsWith("#")) continue;
        const [start, end, asnText] = line.split("\t"), sample = samples.get(Number(asnText));
        if (!sample) continue;
        await writer.add(interval(start, end, {
          kind: "network", category: "asn_reputation", asn: sample.asn,
          confidence: "low", upstreamFamily: "ffraud-aggregate",
          description: `FFraud ASN sample: AS${sample.asn}; ${sample.observed} IPs observed; ${sample.abuse}% abuse labels and ${sample.proxy}% proxy labels within the publisher's observed sample. This is not a population rate, does not identify this IP as abusive or a proxy, and does not affect the numeric score. Observation dates are not supplied.`,
        }));
      }
    }
    if (anchors.length === 1) throw new Error("ASN mapping unavailable for reputation join");
    // The joined snapshot expires when either mapping or reputation becomes old.
    source.ttlHours = Math.max(0, (Math.min(...anchors) + 72 * 3600000 - anchors[0]) / 3600000);
  });
}
