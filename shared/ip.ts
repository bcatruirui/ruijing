/** Strict, dependency-free IP parsing and CIDR matching for browser and Workers. */
export type IpScope =
  | "public"
  | "private"
  | "loopback"
  | "link-local"
  | "shared"
  | "documentation"
  | "multicast"
  | "unspecified"
  | "ipv4-mapped"
  | "reserved";

export interface ParsedIp {
  family: 4 | 6;
  canonical: string;
  value: bigint;
  isPublic: boolean;
  scope: IpScope;
}

export interface ParsedCidr {
  family: 4 | 6;
  prefix: number;
  network: bigint;
  last: bigint;
  canonical: string;
}

function parseV4(input: string): number[] | null {
  const parts = input.split(".");
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    // No octal-looking, signed, abbreviated, or hexadecimal IPv4 forms.
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    octets.push(octet);
  }
  return octets;
}

function parseV6(input: string): number[] | null {
  let text = input;
  if (!/^[\da-fA-F:.]+$/.test(text)) return null;
  if (text.includes(".")) {
    const split = text.lastIndexOf(":");
    if (split < 0) return null;
    const octets = parseV4(text.slice(split + 1));
    if (!octets) return null;
    text = `${text.slice(0, split + 1)}${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }
  const pieces = text.split("::");
  if (pieces.length > 2) return null;
  const read = (part: string): number[] | null => {
    if (!part) return [];
    const groups = part.split(":");
    return groups.every((group) => /^[\da-fA-F]{1,4}$/.test(group))
      ? groups.map((group) => Number.parseInt(group, 16))
      : null;
  };
  const left = read(pieces[0]);
  const right = pieces.length === 2 ? read(pieces[1]) : [];
  if (!left || !right) return null;
  if (pieces.length === 1) return left.length === 8 ? left : null;
  const missing = 8 - left.length - right.length;
  if (missing < 1) return null;
  return [...left, ...Array<number>(missing).fill(0), ...right];
}

function formatV6(groups: readonly number[]): string {
  let bestStart = -1;
  let bestLength = 1;
  for (let i = 0; i < groups.length;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let end = i;
    while (end < groups.length && groups[end] === 0) end++;
    // RFC 5952: compress the first longest run, and never one zero alone.
    if (end - i > bestLength) {
      bestStart = i;
      bestLength = end - i;
    }
    i = end;
  }
  if (bestStart < 0) return groups.map((group) => group.toString(16)).join(":");
  return `${groups
    .slice(0, bestStart)
    .map((group) => group.toString(16))
    .join(":")}::${groups
    .slice(bestStart + bestLength)
    .map((group) => group.toString(16))
    .join(":")}`;
}

function formatValue(value: bigint, family: 4 | 6): string {
  if (family === 4) {
    return [24n, 16n, 8n, 0n]
      .map((shift) => Number((value >> shift) & 255n))
      .join(".");
  }
  return formatV6(
    Array.from({ length: 8 }, (_, index) =>
      Number((value >> BigInt((7 - index) * 16)) & 65535n),
    ),
  );
}

function inPrefix(
  value: bigint,
  network: bigint,
  prefix: number,
  bits: number,
): boolean {
  const shift = BigInt(bits - prefix);
  return value >> shift === network >> shift;
}

// Non-globally reachable special-use blocks, checked most-specific first.
// IANA registries checked 2026-10-28 (registry revision 2025-10-09).
const v4Scopes: ReadonlyArray<readonly [number, number, IpScope]> = [
  [0x00000000, 32, "unspecified"],
  [0x00000000, 8, "reserved"],
  [0x0a000000, 8, "private"],
  [0x64400000, 10, "shared"],
  [0x7f000000, 8, "loopback"],
  [0xa9fe0000, 16, "link-local"],
  [0xac100000, 12, "private"],
  [0xc0000000, 24, "reserved"],
  [0xc0000200, 24, "documentation"],
  [0xc0586300, 24, "reserved"],
  [0xc0a80000, 16, "private"],
  [0xc6120000, 15, "reserved"],
  [0xc6336400, 24, "documentation"],
  [0xcb007100, 24, "documentation"],
  [0xe0000000, 4, "multicast"],
  [0xf0000000, 4, "reserved"],
];

function v6Literal(text: string): bigint {
  return parseV6(text)!.reduce(
    (value, group) => (value << 16n) | BigInt(group),
    0n,
  );
}

const v6Scopes: ReadonlyArray<readonly [bigint, number, IpScope]> = [
  [0n, 128, "unspecified"],
  [1n, 128, "loopback"],
  [v6Literal("::ffff:0:0"), 96, "ipv4-mapped"],
  [v6Literal("64:ff9b:1::"), 48, "reserved"],
  [v6Literal("100::"), 64, "reserved"],
  [v6Literal("100:0:0:1::"), 64, "reserved"],
  [v6Literal("2001:db8::"), 32, "documentation"],
  [v6Literal("2001::"), 23, "reserved"],
  [v6Literal("2002::"), 16, "reserved"],
  [v6Literal("3fff::"), 20, "documentation"],
  [v6Literal("5f00::"), 16, "reserved"],
  [v6Literal("fc00::"), 7, "private"],
  [v6Literal("fe80::"), 10, "link-local"],
  [v6Literal("fec0::"), 10, "reserved"],
  [v6Literal("ff00::"), 8, "multicast"],
];

const v6GlobalExceptions: ReadonlyArray<readonly [bigint, number]> = [
  [v6Literal("64:ff9b::"), 96],
  [v6Literal("2001:1::1"), 128],
  [v6Literal("2001:1::2"), 128],
  [v6Literal("2001:1::3"), 128],
  [v6Literal("2001:3::"), 32],
  [v6Literal("2001:4:112::"), 48],
  [v6Literal("2001:20::"), 28],
  [v6Literal("2001:30::"), 28],
];

function scopeOf(value: bigint, family: 4 | 6): IpScope {
  if (family === 4) {
    if (value === 0xc0000009n || value === 0xc000000an) return "public";
    const numeric = Number(value);
    return (
      v4Scopes.find(([network, prefix]) =>
        (numeric >>> (32 - prefix)) === (network >>> (32 - prefix)),
      )?.[2] ?? "public"
    );
  }
  if (
    v6GlobalExceptions.some(([network, prefix]) =>
      inPrefix(value, network, prefix, 128),
    )
  )
    return "public";
  const special = v6Scopes.find(([network, prefix]) =>
    inPrefix(value, network, prefix, 128),
  );
  if (special) return special[2];
  // Ordinary currently allocated global unicast; unallocated IPv6 is not
  // silently advertised as a usable public endpoint.
  return inPrefix(value, v6Literal("2000::"), 3, 128) ? "public" : "reserved";
}

export function parseIp(input: unknown): ParsedIp | null {
  if (typeof input !== "string") return null;
  const text = input.trim();
  if (!text || text.length > 45) return null;
  let family: 4 | 6;
  let value: bigint;
  let canonical: string;
  if (text.includes(":")) {
    const groups = parseV6(text);
    if (!groups) return null;
    family = 6;
    value = groups.reduce(
      (result, group) => (result << 16n) | BigInt(group),
      0n,
    );
    canonical = formatV6(groups);
  } else {
    const octets = parseV4(text);
    if (!octets) return null;
    family = 4;
    value = octets.reduce(
      (result, octet) => (result << 8n) | BigInt(octet),
      0n,
    );
    canonical = octets.join(".");
  }
  const scope = scopeOf(value, family);
  return { family, canonical, value, scope, isPublic: scope === "public" };
}

export function isPublicIp(input: unknown): boolean {
  return parseIp(input)?.isPublic ?? false;
}

export const parseIpCanonical = parseIp;

export function requirePublicIp(input: unknown): ParsedIp {
  const parsed = parseIp(input);
  if (!parsed) throw new Error("INVALID_IP");
  if (!parsed.isPublic) throw new Error("NON_PUBLIC_IP");
  return parsed;
}

export function parseCidr(input: unknown): ParsedCidr | null {
  if (typeof input !== "string") return null;
  const parts = input.trim().split("/");
  if (parts.length !== 2 || !/^(?:0|[1-9]\d{0,2})$/.test(parts[1])) return null;
  const ip = parseIp(parts[0]);
  if (!ip) return null;
  const prefix = Number(parts[1]);
  const bits = ip.family === 4 ? 32 : 128;
  if (prefix > bits) return null;
  const hostBits = BigInt(bits - prefix);
  const network = (ip.value >> hostBits) << hostBits;
  const last = network | ((1n << hostBits) - 1n);
  return {
    family: ip.family,
    prefix,
    network,
    last,
    canonical: `${formatValue(network, ip.family)}/${prefix}`,
  };
}

export function containsIp(
  cidr: string | ParsedCidr,
  ip: string | ParsedIp,
): boolean {
  const range = typeof cidr === "string" ? parseCidr(cidr) : cidr;
  const address = typeof ip === "string" ? parseIp(ip) : ip;
  return (
    !!range &&
    !!address &&
    range.family === address.family &&
    address.value >= range.network &&
    address.value <= range.last
  );
}

export const cidrContains = containsIp;

export function compareIp(
  left: string | ParsedIp,
  right: string | ParsedIp,
): -1 | 0 | 1 {
  const a = typeof left === "string" ? parseIp(left) : left;
  const b = typeof right === "string" ? parseIp(right) : right;
  if (!a || !b) throw new Error("INVALID_IP");
  if (a.family !== b.family) return a.family < b.family ? -1 : 1;
  return a.value < b.value ? -1 : a.value > b.value ? 1 : 0;
}

/** Small-shard matcher; first entry wins when equally specific. */
export function longestPrefixMatch<T extends { cidr: string }>(
  ip: string | ParsedIp,
  entries: readonly T[],
): T | null {
  const address = typeof ip === "string" ? parseIp(ip) : ip;
  if (!address) return null;
  let result: T | null = null;
  let bestPrefix = -1;
  for (const entry of entries) {
    const range = parseCidr(entry.cidr);
    if (range && range.prefix > bestPrefix && containsIp(range, address)) {
      result = entry;
      bestPrefix = range.prefix;
    }
  }
  return result;
}

/** Precompiled prefix tables avoid reparsing all CIDRs for repeated lookups. */
export class CidrIndex<T> {
  private readonly families = new Map<4 | 6, Map<number, Map<bigint, T>>>();
  private readonly lengths = new Map<4 | 6, number[]>();

  constructor(entries: readonly { cidr: string; value: T }[]) {
    for (const entry of entries) {
      const cidr = parseCidr(entry.cidr);
      if (!cidr) throw new Error(`INVALID_CIDR: ${entry.cidr}`);
      let family = this.families.get(cidr.family);
      if (!family) {
        family = new Map();
        this.families.set(cidr.family, family);
      }
      let length = family.get(cidr.prefix);
      if (!length) {
        length = new Map();
        family.set(cidr.prefix, length);
      }
      if (!length.has(cidr.network)) length.set(cidr.network, entry.value);
    }
    for (const [family, prefixes] of this.families)
      this.lengths.set(
        family,
        [...prefixes.keys()].sort((a, b) => b - a),
      );
  }

  lookup(input: string | ParsedIp): T | null {
    const ip = typeof input === "string" ? parseIp(input) : input;
    if (!ip) return null;
    const tables = this.families.get(ip.family);
    for (const prefix of this.lengths.get(ip.family) ?? []) {
      const shift = BigInt((ip.family === 4 ? 32 : 128) - prefix);
      const network = (ip.value >> shift) << shift;
      const entry = tables!.get(prefix)!.get(network);
      if (entry !== undefined) return entry;
    }
    return null;
  }
}
