import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { ROOT, now } from "./data-utils.mjs";

// HEAD checks use fixed public URLs. This task never queries a visitor IP and never deploys.
const targets = [
  ["iptoasn-v4", "https://iptoasn.com/data/ip2asn-v4.tsv.gz"],
  ["iptoasn-v6", "https://iptoasn.com/data/ip2asn-v6.tsv.gz"],
  [
    "openasn-manifest",
    "https://github.com/openasn/openasn/releases/download/latest/manifest.json",
  ],
  [
    "openasn-license",
    "https://raw.githubusercontent.com/openasn/openasn/main/ATTRIBUTION.md",
  ],
  ["dbip-city-download-page", "https://db-ip.com/db/download/ip-to-city-lite"],
  ["dbip-asn-download-page", "https://db-ip.com/db/download/ip-to-asn-lite"],
  ["ipverse-network", "https://github.com/ipverse/as-metadata/commits/master/as.json.atom"],
  ["carpathian", "https://api.carpathian.ai/public/threat-intel/blocklist.json"],
  ["dshield", "https://feeds.dshield.org/feeds/daily_sources"],
  ["ffraud-publication", "https://raw.githubusercontent.com/FFraud-com/ip-fraud-database/main/metadata.json"],
  ["tor-collector", "https://collector.torproject.org/recent/exit-lists/"],
  [
    "ffraud",
    "https://raw.githubusercontent.com/FFraud-com/ip-fraud-database/main/threat-ips/confirmed-abusive.csv",
  ],
  [
    "ffraud-license",
    "https://raw.githubusercontent.com/FFraud-com/ip-fraud-database/main/LICENSE",
  ],
  [
    "feodo",
    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
  ],
  ["feodo-license", "https://abuse.ch/terms-of-use/"],
  ["monosans-proxies", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies.json"],
  ["monosans-license", "https://raw.githubusercontent.com/monosans/proxy-list/main/LICENSE"],
  ["ffraud-asn", "https://raw.githubusercontent.com/FFraud-com/ip-fraud-database/main/asn-reputation/high-abuse-networks.csv"],
];
const results = [];
for (let i = 0; i < targets.length; i += 3) {
  results.push(
    ...(await Promise.all(
      targets.slice(i, i + 3).map(async ([id, url]) => {
        try {
          let response = await fetch(url, {
            method: "HEAD",
            redirect: "follow",
            signal: AbortSignal.timeout(30000),
          });
          if ([403, 405, 501].includes(response.status)) {
            response = await fetch(url, {
              headers: { Range: "bytes=0-1023" },
              redirect: "follow",
              signal: AbortSignal.timeout(30000),
            });
            await response.body?.cancel();
          }
          return {
            id,
            url,
            checkedAt: now(),
            ok: response.ok,
            status: response.status,
            lastModified: response.headers.get("last-modified"),
            contentLength: response.headers.get("content-length"),
          };
        } catch (error) {
          return {
            id,
            url,
            checkedAt: now(),
            ok: false,
            error: String(error.message).slice(0, 120),
          };
        }
      }),
    )),
  );
}
const report = {
  checkedAt: now(),
  checkOnly: true,
  datasetsUpdated: false,
  deployed: false,
  note: "Availability checks do not verify current license meaning, accuracy, observations, or refresh the deployed data. Review license changes before the next build.",
  results,
};
await mkdir(path.join(ROOT, "reports"), { recursive: true });
await writeFile(
  path.join(ROOT, "reports", "upstream-check.json"),
  JSON.stringify(report, null, 2) + "\n",
);
process.stdout.write(JSON.stringify(report, null, 2) + "\n");
if (results.some((r) => !r.ok)) process.exitCode = 1;
