import { download, isoDate, readSmallJson } from "./data-utils.mjs";
import { readFile } from "node:fs/promises";
import { parseCidr, parseIp } from "../shared/ip.ts";

const aws = "https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html";
const gcp = "https://cloud.google.com/compute/docs/faq#find_ip_range";
const azure = "https://www.microsoft.com/en-us/download/details.aspx?id=56519";
export const cloudRangeIds = ["aws-cloud", "gcp-cloud", "azure-cloud"];

function records(values, provider) {
  const prefixes = new Map();
  for (const value of values) {
    const range = parseCidr(value);
    if (!range) throw new Error("Invalid provider CIDR");
    if (!parseIp(range.canonical.split("/")[0])?.isPublic) continue;
    const digits = range.family === 4 ? 8 : 32;
    prefixes.set(range.canonical, {
      family: range.family,
      start: range.network.toString(16).padStart(digits, "0"),
      end: range.last.toString(16).padStart(digits, "0"),
      payload: {
        kind: "network", networkType: "cloud", networkBasis: "prefix",
        prefix: range.canonical, confidence: "high",
        description: `${provider} publishes this exact prefix in its public cloud service ranges.`,
      },
    });
  }
  const rows = [...prefixes.values()];
  if (rows.length < 50 || rows.length > 100_000 || ![4, 6].every(family => rows.some(row => row.family === family)))
    throw new Error("Cloud ranges did not meet the IPv4/IPv6 coverage bounds");
  return rows;
}

export async function registerCloudRanges({ run, base, meta, reuse, compareRecords }) {
  const feeds = [
    {
      id: "aws-cloud", provider: "AWS EC2", page: aws, hours: 24 * 14,
      url: () => "https://ip-ranges.amazonaws.com/ip-ranges.json",
      prefixes: data => [...data.prefixes, ...data.ipv6_prefixes]
        .filter(row => row.service === "EC2")
        .map(row => row.ip_prefix ?? row.ipv6_prefix),
      published: data => /^\d{10}$/.test(data.syncToken) ? new Date(Number(data.syncToken) * 1000).toISOString() : undefined,
    },
    {
      id: "gcp-cloud", provider: "Google Cloud", page: gcp, hours: 24 * 14,
      url: () => "https://www.gstatic.com/ipranges/cloud.json",
      prefixes: data => data.prefixes.map(row => row.ipv4Prefix ?? row.ipv6Prefix),
      // The feed's timestamp omits an offset. Keep its release day only.
      published: data => /^(\d{4}-\d{2}-\d{2})T/.exec(data.creationTime)?.[1],
    },
    {
      id: "azure-cloud", provider: "Microsoft Azure", page: azure, hours: 24 * 21,
      url: async () => {
        const page = await download("azure-service-tags-download.html", azure, { reuse, maxBytes: 3 * 1024 * 1024 });
        const html = await readFile(page.path, "utf8");
        const url = html.match(/https:\/\/download\.microsoft\.com\/download\/[a-z0-9/-]+\/ServiceTags_Public_\d{8}\.json/i)?.[0];
        if (!url) throw new Error("Azure service tags download URL not found");
        return url;
      },
      prefixes: data => data.values.find(row => row.name === "AzureCloud").properties.addressPrefixes,
      published: (_data, url) => {
        const date = /ServiceTags_Public_(\d{4})(\d{2})(\d{2})\.json$/.exec(url);
        return date && `${date[1]}-${date[2]}-${date[3]}`;
      },
    },
  ];
  for (const feed of feeds) {
    await run(base(feed.id, `${feed.provider} published prefixes`, feed.page,
      "Provider-published address ranges", ["network"], [feed.id], feed.hours,
      { confidence: "high", licenseUrl: feed.page, licenseAttribution: feed.provider, positiveOnlyCategories: ["network"] }),
    async (writer, source, previous) => {
      const url = await feed.url();
      const resource = await download(`${feed.id}-ranges.json`, url, { reuse, maxBytes: 16 * 1024 * 1024 });
      const data = await readSmallJson(resource.path, 16 * 1024 * 1024);
      const published = isoDate(feed.published(data, url));
      if (!published) throw new Error("Missing provider publication date");
      meta(source, resource, published);
      if (previous?.sha256 === source.sha256 && previous.publishedAt === published && previous.shards.length) return "unchanged";
      for (const record of records(feed.prefixes(data), feed.provider).sort(compareRecords)) await writer.add(record);
    });
  }
}
