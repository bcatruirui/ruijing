import { parseIp } from "../shared/ip.ts";
import { ipRecord } from "./data-utils.mjs";

const PROTOCOLS = new Set(["http", "socks4", "socks5"]);
const MAX_ROWS = 50_000;

/**
 * Project only the publisher's proxy observations, never its MaxMind enrichment.
 * An ingress server is not automatically the exit seen by the destination.
 * No connection to a listed address and no DNS resolution happens here.
 */
export function parseMonosansProxySnapshot(value) {
  if (!Array.isArray(value) || value.length > MAX_ROWS)
    throw new Error("Unsupported or oversized Monosans snapshot");
  const observations = new Map();
  let ignored = 0;
  const add = (ip, protocol, role) => {
    const key = `${ip.family}:${ip.value.toString(16)}`;
    const item = observations.get(key) ?? {
      ip: ip.canonical,
      protocols: new Set(),
      roles: new Set(),
    };
    item.protocols.add(protocol);
    item.roles.add(role);
    observations.set(key, item);
  };
  for (const row of value) {
    if (!row || typeof row !== "object" || Array.isArray(row))
      throw new Error("Invalid Monosans row schema");
    if (
      !PROTOCOLS.has(row.protocol) ||
      !Number.isInteger(row.port) ||
      row.port < 1 ||
      row.port > 65_535
    ) {
      ignored++;
      continue;
    }
    const host = parseIp(row.host);
    const exit = parseIp(row.exit_ip);
    // Only actual public literals are indexed. Hostnames never trigger a lookup.
    if (!host?.isPublic) {
      ignored++;
      continue;
    }
    add(host, row.protocol, "ingress");
    if (exit?.isPublic) add(exit, row.protocol, "observed_exit");
  }
  const records = [...observations.values()].map(({ ip, protocols, roles }) => {
    const protocolText = [...protocols].sort().join(", ");
    const isIngress = roles.has("ingress");
    const isExit = roles.has("observed_exit");
    const roleText =
      isIngress && isExit
        ? "proxy ingress and observed exit"
        : isExit
          ? "observed proxy exit; an open listening port on this exit is not established"
          : "proxy ingress; destination-visible exit is not established for this address";
    return ipRecord(ip, {
      kind: "network",
      category: "proxy",
      attributes: ["public_proxy"],
      confidence: "medium",
      upstreamFamily: "monosans-verified-proxies",
      description:
        `Monosans: ${roleText}; protocols: ${protocolText}. ` +
        "Publisher's verified snapshot, not a live check. Exact per-address check time, residential status and provider are not supplied. This is not evidence of abuse.",
    });
  });
  records.sort(
    (a, b) => a.family - b.family || a.start.localeCompare(b.start),
  );
  if (value.length && !records.length)
    throw new Error("Monosans snapshot contains no usable public IP observations");
  return { records, inputRows: value.length, ignoredRows: ignored };
}

/** The commit timestamp describes publication; it is never an observedAt value. */
export function parseMonosansRevision(value, now = new Date()) {
  const item = Array.isArray(value) && value.length === 1 ? value[0] : undefined;
  const revision = item?.sha;
  const date = item?.commit?.committer?.date;
  const timestamp = typeof date === "string" ? Date.parse(date) : NaN;
  if (
    typeof revision !== "string" ||
    !/^[a-f0-9]{40}$/.test(revision) ||
    !Number.isFinite(timestamp) ||
    timestamp < Date.UTC(2000, 0, 1) ||
    timestamp > now.getTime() + 5 * 60_000
  )
    throw new Error("Invalid Monosans revision or publication timestamp");
  return { revision, publishedAt: new Date(timestamp).toISOString() };
}

export function parseMonosansAtom(text, now = new Date()) {
  if (typeof text !== "string" || text.length > 262144 || !text.includes("/monosans/proxy-list/commits/main/proxies.json")) throw new Error("Unexpected proxy revision feed");
  const entry = text.match(/<entry>([\s\S]*?)<\/entry>/)?.[1];
  const sha = entry?.match(/Grit::Commit\/([a-f0-9]{40})<\/id>/)?.[1];
  const date = entry?.match(/<updated>([^<]+)<\/updated>/)?.[1];
  return parseMonosansRevision([{ sha, commit: { committer: { date } } }], now);
}
