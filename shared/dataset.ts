import type { BuildRecord, IntelPayload } from "./contracts.ts";
import { parseCidr } from "./ip.ts";
import { parseCoordinate, validPostalCode, validTimezone } from "./geo.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const MAX_BYTES = 131_072;
const MAX_RECORDS = 65_536;
// The asset loader owns these byte arrays and must keep them immutable. Only
// validation identity is cached: decoded payload objects are not retained.
const validated = new WeakSet<Uint8Array>();
const validatedIndexes = new WeakSet<Uint8Array>();
const kinds = new Set(["asn", "geo", "network", "threat", "tor"]);
const networkTypes = new Set([
  "residential",
  "hosting",
  "cloud",
  "mobile",
  "business",
  "education",
  "unknown",
]);
const attributes = new Set([
  "vpn",
  "proxy",
  "public_proxy",
  "web_proxy",
  "residential_proxy",
  "tor",
  "relay",
  "crawler",
]);
const threatCategories = new Set([
  "c2",
  "botnet",
  "malware",
  "phishing",
  "brute_force",
  "web_attack",
  "scanner",
  "spam",
  "other_abuse",
]);
const categories = new Set([
  ...threatCategories,
  "network",
  "tor",
  "vpn",
  "proxy",
  "residential_proxy",
  "asn",
  "asn_reputation",
  "geo",
]);
const confidences = new Set(["high", "medium", "low"]);
const stringFields = [
  "organization",
  "country",
  "countryCode",
  "region",
  "city",
  "postalCode",
  "timezone",
  "description",
  "prefix",
  "upstreamFamily",
  "eventId",
  "observedAt",
] as const;
const allowedFields = new Set([
  "kind",
  "asn",
  "networkType",
  "networkBasis",
  "attributes",
  "category",
  "confidence",
  "latitude",
  "longitude",
  ...stringFields,
]);

export function normalizeHex(value: string, family: 4 | 6): string {
  if ((family !== 4 && family !== 6) || typeof value !== "string")
    throw new Error("Invalid address family or encoding");
  const hex = value.toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]+$/.test(hex) || hex.length > (family === 4 ? 8 : 32))
    throw new Error("Invalid address encoding");
  return hex.padStart(family === 4 ? 8 : 32, "0");
}

function validPayload(value: unknown, family: 4 | 6): value is IntelPayload {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  if (Object.keys(item).some((key) => !allowedFields.has(key))) return false;
  if (item.networkBasis !== undefined &&
    (item.networkBasis !== "prefix" || item.kind !== "network" || !item.networkType || typeof item.prefix !== "string"))
    return false;
  if (typeof item.kind !== "string" || !kinds.has(item.kind)) return false;
  if (
    stringFields.some(
      (field) => item[field] !== undefined && typeof item[field] !== "string",
    )
  )
    return false;
  if (
    (item.latitude === undefined) !== (item.longitude === undefined) ||
    (item.latitude !== undefined &&
      (typeof item.latitude !== "number" || parseCoordinate(item.latitude, "latitude") === undefined)) ||
    (item.longitude !== undefined &&
      (typeof item.longitude !== "number" || parseCoordinate(item.longitude, "longitude") === undefined)) ||
    (item.postalCode !== undefined && !validPostalCode(item.postalCode)) ||
    (item.timezone !== undefined && !validTimezone(item.timezone))
  ) return false;
  if (
    item.asn !== undefined &&
    (typeof item.asn !== "number" ||
      !Number.isInteger(item.asn) ||
      item.asn < 0 ||
      item.asn > 4_294_967_295)
  )
    return false;
  if (
    item.networkType !== undefined &&
    (typeof item.networkType !== "string" ||
      !networkTypes.has(item.networkType))
  )
    return false;
  if (
    item.category !== undefined &&
    (typeof item.category !== "string" || !categories.has(item.category))
  )
    return false;
  if (
    item.confidence !== undefined &&
    (typeof item.confidence !== "string" || !confidences.has(item.confidence))
  )
    return false;
  if (
    item.attributes !== undefined &&
    (!Array.isArray(item.attributes) ||
      item.attributes.length > attributes.size ||
      item.attributes.some(
        (attribute) =>
          typeof attribute !== "string" || !attributes.has(attribute),
      ))
  )
    return false;
  if (
    item.kind === "threat" &&
    (typeof item.category !== "string" || !threatCategories.has(item.category))
  )
    return false;
  if (
    item.observedAt !== undefined &&
    !Number.isFinite(Date.parse(item.observedAt as string))
  )
    return false;
  if (item.prefix !== undefined) {
    const prefix = parseCidr(item.prefix);
    if (!prefix || prefix.family !== family) return false;
  }
  return true;
}

function readDictionary(
  bytes: Uint8Array,
  offset: number,
  family: 4 | 6,
): IntelPayload[] {
  const data: unknown = JSON.parse(decoder.decode(bytes.subarray(offset)));
  if (
    !Array.isArray(data) ||
    !data.length ||
    !data.every((item) => validPayload(item, family))
  )
    throw new Error("Invalid shard dictionary or payload");
  return data;
}

export function encodeShard(records: BuildRecord[]): Uint8Array {
  if (
    !Array.isArray(records) ||
    !records.length ||
    records.length > MAX_RECORDS
  )
    throw new Error("Invalid shard record count");
  const family = records[0].family;
  if (family !== 4 && family !== 6) throw new Error("Invalid address family");
  const addressWidth = family === 4 ? 4 : 16;
  const width = addressWidth * 2 + 4;
  const dictionary: IntelPayload[] = [];
  const values = new Map<string, number>();
  let previousStart = "";
  const normalized = records.map((record) => {
    if (record.family !== family) throw new Error("Mixed families");
    const start = normalizeHex(record.start, family);
    const end = normalizeHex(record.end, family);
    if (start > end) throw new Error("Reversed shard interval");
    if (previousStart && start < previousStart)
      throw new Error("Unsorted shard intervals");
    previousStart = start;
    if (!validPayload(record.payload, family))
      throw new Error("Invalid payload");
    const key = JSON.stringify(record.payload);
    let id = values.get(key);
    if (id === undefined) {
      id = dictionary.length;
      values.set(key, id);
      dictionary.push(record.payload);
    }
    return { start, end, id };
  });
  const payloadBytes = dictionary.map((payload) => encoder.encode(JSON.stringify(payload)));
  const offset = 16 + records.length * width;
  const blobStart = offset + 4 + (dictionary.length + 1) * 4;
  const blobLength = payloadBytes.reduce((sum, payload) => sum + payload.length, 0);
  if (blobStart + blobLength > MAX_BYTES)
    throw new Error("Intelligence shard too large");
  const bytes = new Uint8Array(blobStart + blobLength);
  const view = new DataView(bytes.buffer);
  bytes.set([82, 74, 73, 49]);
  bytes[4] = family;
  bytes[5] = 2;
  view.setUint16(6, width, true);
  view.setUint32(8, records.length, true);
  view.setUint32(12, offset, true);
  normalized.forEach((record, index) => {
    const at = 16 + index * width;
    [record.start, record.end].forEach((hex, part) => {
      for (let byte = 0; byte < addressWidth; byte++)
        bytes[at + part * addressWidth + byte] = Number.parseInt(
          hex.slice(byte * 2, byte * 2 + 2),
          16,
        );
    });
    view.setUint32(at + addressWidth * 2, record.id, true);
  });
  view.setUint32(offset, dictionary.length, true);
  let blobOffset = 0;
  payloadBytes.forEach((payload, index) => {
    view.setUint32(offset + 4 + index * 4, blobOffset, true);
    bytes.set(payload, blobStart + blobOffset);
    blobOffset += payload.length;
  });
  view.setUint32(offset + 4 + dictionary.length * 4, blobOffset, true);
  return bytes;
}

function compareAddresses(
  bytes: Uint8Array,
  left: number,
  right: number,
  width: number,
): number {
  for (let byte = 0; byte < width; byte++) {
    const difference = bytes[left + byte] - bytes[right + byte];
    if (difference) return difference;
  }
  return 0;
}

export interface ShardMatch {
  payload: IntelPayload;
  start: string;
  end: string;
}

function addressHex(bytes: Uint8Array, at: number, width: number): string {
  let result = "";
  for (let index = 0; index < width; index++)
    result += bytes[at + index].toString(16).padStart(2, "0");
  return result;
}

interface ShardLayout {
  version: 1 | 2; family: 4 | 6; width: number; view: DataView;
  stride: number; count: number; offset: number;
  dictionaryCount: number; blobStart: number;
}

function readLayout(bytes: Uint8Array): ShardLayout {
  if (
    !(bytes instanceof Uint8Array) ||
    bytes.length < 16 ||
    bytes.length > MAX_BYTES ||
    bytes[0] !== 82 ||
    bytes[1] !== 74 ||
    bytes[2] !== 73 ||
    bytes[3] !== 49 ||
    (bytes[5] !== 1 && bytes[5] !== 2)
  )
    throw new Error("Invalid intelligence shard");
  const family = bytes[4];
  if (family !== 4 && family !== 6) throw new Error("Invalid address family");
  const width = family === 4 ? 4 : 16;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const stride = view.getUint16(6, true);
  const count = view.getUint32(8, true);
  const offset = view.getUint32(12, true);
  if (
    stride !== width * 2 + 4 ||
    !count ||
    count > MAX_RECORDS ||
    offset !== 16 + count * stride ||
    offset >= bytes.length
  )
    throw new Error("Invalid shard bounds");

  const version = bytes[5] as 1 | 2;
  let dictionaryCount = 0;
  let blobStart = offset;
  if (version === 2) {
    if (offset + 8 > bytes.length) throw new Error("Invalid dictionary bounds");
    dictionaryCount = view.getUint32(offset, true);
    blobStart = offset + 4 + (dictionaryCount + 1) * 4;
    if (!dictionaryCount || dictionaryCount > count || blobStart >= bytes.length) throw new Error("Invalid dictionary bounds");
    if (!validatedIndexes.has(bytes)) {
      const blobLength = bytes.length - blobStart;
      let previous = -1;
      for (let index = 0; index <= dictionaryCount; index++) {
        const current = view.getUint32(offset + 4 + index * 4, true);
        if ((index === 0 && current !== 0) || current <= previous || current > blobLength || (index === dictionaryCount && current !== blobLength)) throw new Error("Invalid dictionary index");
        previous = current;
      }
      validatedIndexes.add(bytes);
    }
  }
  return { version, family, width, view, stride, count, offset, dictionaryCount, blobStart };
}

function readIndexedPayload(bytes: Uint8Array, layout: ShardLayout, id: number): IntelPayload {
  if (!Number.isInteger(id) || id < 0 || id >= layout.dictionaryCount) throw new Error("Invalid payload reference");
  const start = layout.view.getUint32(layout.offset + 4 + id * 4, true);
  const end = layout.view.getUint32(layout.offset + 4 + (id + 1) * 4, true);
  const payload: unknown = JSON.parse(decoder.decode(bytes.subarray(layout.blobStart + start, layout.blobStart + end)));
  if (!validPayload(payload, layout.family)) throw new Error("Invalid payload");
  return payload;
}

function matchShard(bytes: Uint8Array, rawIpHex: string, verifiedOwnBuild: boolean): ShardMatch[] {
  const layout = readLayout(bytes);
  const { family, width, view, stride, count, offset, version } = layout;
  const ipHex = normalizeHex(rawIpHex, family);
  const ip = Uint8Array.from(ipHex.match(/../g)!.map((part) => Number.parseInt(part, 16)));
  let dictionary: IntelPayload[] | undefined;
  // The trusted fast path is solely for RJI2 bytes whose hash was already
  // matched to this application's own validated build manifest. It must never
  // populate the strict-validation cache without doing the full validation.
  if (!validated.has(bytes) && !(version === 2 && verifiedOwnBuild)) {
    dictionary = version === 1 ? readDictionary(bytes, offset, family) : Array.from({ length: layout.dictionaryCount }, (_, id) => readIndexedPayload(bytes, layout, id));
    for (let index = 0; index < count; index++) {
      const at = 16 + index * stride;
      if (compareAddresses(bytes, at, at + width, width) > 0) throw new Error("Reversed shard interval");
      if (index && compareAddresses(bytes, at - stride, at, width) > 0) throw new Error("Unsorted shard intervals");
      if (view.getUint32(at + 2 * width, true) >= dictionary.length) throw new Error("Invalid payload reference");
    }
    validated.add(bytes);
  }

  const compare = (at: number) => {
    for (let byte = 0; byte < width; byte++) {
      const difference = bytes[at + byte] - ip[byte];
      if (difference) return difference;
    }
    return 0;
  };
  let low = 0;
  let high = count;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if (compare(16 + mid * stride) <= 0) low = mid + 1;
    else high = mid;
  }
  const matches: Array<{ id: number; at: number }> = [];
  for (let index = low - 1; index >= 0; index--) {
    const at = 16 + index * stride;
    if (compare(at + width) >= 0)
      matches.push({ id: view.getUint32(at + 2 * width, true), at });
  }
  if (!matches.length) return [];
  if (version === 1) dictionary ??= readDictionary(bytes, offset, family);
  const hitPayloads = new Map<number, IntelPayload>();
  const payloadFor = (id: number) => {
    if (dictionary) return dictionary[id];
    let payload = hitPayloads.get(id);
    if (!payload) { payload = readIndexedPayload(bytes, layout, id); hitPayloads.set(id, payload); }
    return payload;
  };
  return matches.map(({ id, at }) => ({
    payload: payloadFor(id),
    start: addressHex(bytes, at, width),
    end: addressHex(bytes, at + width, width),
  }));
}

/** Strict default: validates all rows and payloads on the first read. */
export function lookupShardMatches(bytes: Uint8Array, rawIpHex: string): ShardMatch[] {
  return matchShard(bytes, rawIpHex, false);
}

/** Requires prior SHA-256 verification against this application's own build. */
export function lookupVerifiedShardMatches(bytes: Uint8Array, rawIpHex: string): ShardMatch[] {
  return matchShard(bytes, rawIpHex, true);
}

/** Compatibility interface: one payload per matching dictionary entry. */
export function lookupShard(
  bytes: Uint8Array,
  rawIpHex: string,
): IntelPayload[] {
  return [
    ...new Set(
      lookupShardMatches(bytes, rawIpHex).map((match) => match.payload),
    ),
  ];
}
