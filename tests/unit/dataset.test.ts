import { describe, expect, it, vi } from "vitest";
import type { BuildRecord, IntelPayload } from "../../shared/contracts";
import {
  encodeShard,
  lookupShard,
  lookupShardMatches,
  lookupVerifiedShardMatches,
  normalizeHex,
} from "../../shared/dataset";

// Binary fixtures are synthetic and confined to tests; they are never served.
const record = (
  start: string,
  end = start,
  payload: IntelPayload = { kind: "network", networkType: "unknown" },
  family: 4 | 6 = 4,
): BuildRecord => ({ family, start, end, payload });
const corruption = (change: (bytes: Uint8Array, view: DataView) => void) => {
  const bytes = encodeShard([
    record("08080808", "08080808", {
      kind: "asn",
      asn: 64512,
      organization: "Synthetic fixture",
    }),
  ]);
  change(bytes, new DataView(bytes.buffer));
  return bytes;
};
function replaceDictionary(value: unknown): Uint8Array {
  const original = encodeShard([record("08080808")]);
  const offset = new DataView(original.buffer).getUint32(12, true);
  const json = new TextEncoder().encode(JSON.stringify(value));
  const bytes = new Uint8Array(offset + json.length);
  bytes.set(original.subarray(0, offset));
  bytes[5] = 1; // Deliberately construct the legacy array dictionary format.
  bytes.set(json, offset);
  return bytes;
}

function legacyShard(records: BuildRecord[]): Uint8Array {
  const current = encodeShard(records);
  const view = new DataView(current.buffer);
  const offset = view.getUint32(12, true);
  const count = view.getUint32(offset, true);
  const blobStart = offset + 4 + (count + 1) * 4;
  const dictionary = Array.from({ length: count }, (_, id) => JSON.parse(new TextDecoder().decode(current.subarray(blobStart + view.getUint32(offset + 4 + id * 4, true), blobStart + view.getUint32(offset + 8 + id * 4, true)))));
  const json = new TextEncoder().encode(JSON.stringify(dictionary));
  const bytes = new Uint8Array(offset + json.length);
  bytes.set(current.subarray(0, offset)); bytes[5] = 1; bytes.set(json, offset);
  return bytes;
}

function corruptIndexedPayload(bytes: Uint8Array, id: number): void {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const offset = view.getUint32(12, true);
  const count = view.getUint32(offset, true);
  const blobStart = offset + 4 + (count + 1) * 4;
  bytes.fill(0xff, blobStart + view.getUint32(offset + 4 + id * 4, true), blobStart + view.getUint32(offset + 8 + id * 4, true));
}

describe("binary address dictionary format", () => {
  it("round trips optional geographic fields in both shard encodings", () => {
    const payload: IntelPayload = {
      kind: "geo", countryCode: "US", city: "Synthetic city",
      latitude: 33.4161, longitude: -112.009, postalCode: "85040", timezone: "America/Phoenix",
    };
    for (const encode of [encodeShard, legacyShard]) {
      expect(lookupShard(encode([record("08080808", "08080808", payload)]), "08080808")).toEqual([payload]);
      expect(lookupShard(encode([record("08080808", "08080808", { kind: "geo", countryCode: "US" })]), "08080808")).toEqual([{ kind: "geo", countryCode: "US" }]);
    }
  });
  it.each([
    { latitude: 91, longitude: 0 }, { latitude: 0, longitude: -181 },
    { latitude: "33", longitude: 0 }, { latitude: 0 }, { longitude: 0 },
    { latitude: NaN, longitude: 0 }, { latitude: Infinity, longitude: 0 },
    { postalCode: "" }, { postalCode: "123\n456" }, { postalCode: 85040 },
    { timezone: "America/Imaginary" }, { timezone: "+08:00" },
  ])("rejects invalid geographic payload %j", (fields) => {
    expect(() => encodeShard([record("08080808", "08080808", { kind: "geo", ...fields } as IntelPayload)])).toThrow(/payload/);
  });
  it("normalizes fixed-width hexadecimal addresses without Number precision loss", () => {
    expect(normalizeHex("0xAbC", 4)).toBe("00000abc");
    expect(normalizeHex("20014860486000000000000000008888", 6)).toBe(
      "20014860486000000000000000008888",
    );
    expect(normalizeHex("0", 6)).toBe("00000000000000000000000000000000");
  });

  it.each(["", "0x", "-1", "+1", "1.5", "xyz", "fffffffff", " 1 "])(
    "rejects invalid IPv4 hex %j",
    (value) => expect(() => normalizeHex(value, 4)).toThrow(),
  );

  it("round trips dictionary sharing, Unicode and optional metadata", () => {
    const payload: IntelPayload = {
      kind: "threat",
      category: "scanner",
      description: "仅测试 / fixture",
      upstreamFamily: "synthetic",
      observedAt: "2026-10-28T00:00:00Z",
    };
    const bytes = encodeShard([
      record("08080808", "08080809", payload),
      record("08080810", "08080811", payload),
    ]);
    expect(lookupShard(bytes, "08080808")).toEqual([payload]);
    expect(lookupShard(bytes, "08080811")).toEqual([payload]);
    expect(lookupShard(bytes, "0808080a")).toEqual([]);
    const view = new DataView(bytes.buffer);
    const offset = view.getUint32(12, true);
    expect(bytes[5]).toBe(2);
    expect(view.getUint32(offset, true)).toBe(1);
    expect(view.getUint32(offset + 4, true)).toBe(0);
    const blobStart = offset + 12;
    expect(view.getUint32(offset + 8, true)).toBe(bytes.length - blobStart);
    expect(
      JSON.parse(new TextDecoder().decode(bytes.subarray(blobStart))),
    ).toEqual(payload);
  });

  it("returns all distinct matching overlays and deduplicates dictionary IDs", () => {
    const wide: IntelPayload = { kind: "asn", asn: 64512 };
    const specific: IntelPayload = { kind: "network", networkType: "hosting" };
    const bytes = encodeShard([
      record("08080000", "0808ffff", wide),
      record("08080800", "080808ff", specific),
      record("08080808", "08080808", wide),
    ]);
    expect(lookupShard(bytes, "08080808")).toEqual(
      expect.arrayContaining([wide, specific]),
    );
    expect(lookupShard(bytes, "08080808")).toHaveLength(2);
    expect(lookupShard(bytes, "080807ff")).toEqual([wide]);
    expect(lookupShard(bytes, "08090000")).toEqual([]);
  });

  it("returns actual IPv4 match intervals while preserving payload-only deduplication", () => {
    const shared: IntelPayload = { kind: "asn", asn: 64512 };
    const overlay: IntelPayload = { kind: "network", networkType: "hosting" };
    const bytes = encodeShard([
      record("08080000", "0808ffff", shared),
      record("08080800", "080808ff", overlay),
      record("08080808", "08080808", shared),
    ]);
    expect(lookupShardMatches(bytes, "08080808")).toEqual([
      { payload: shared, start: "08080808", end: "08080808" },
      { payload: overlay, start: "08080800", end: "080808ff" },
      { payload: shared, start: "08080000", end: "0808ffff" },
    ]);
    expect(lookupShard(bytes, "08080808")).toEqual([shared, overlay]);
  });

  it("returns complete 128-bit IPv6 intervals without fabricating a BGP prefix", () => {
    const payload: IntelPayload = { kind: "network", networkType: "unknown" };
    const start = "20014860486000000000000000008887";
    const end = "2001486048600000000000000000888a";
    const bytes = encodeShard([record(start, end, payload, 6)]);
    expect(lookupShardMatches(bytes, end)).toEqual([{ payload, start, end }]);
    expect(
      lookupShardMatches(bytes, "2001486048600000000000000000888b"),
    ).toEqual([]);
  });

  it("handles IPv4 zero and maximum inclusive boundaries", () => {
    const first: IntelPayload = {
      kind: "network",
      networkType: "unknown",
      description: "first",
    };
    const last: IntelPayload = {
      kind: "network",
      networkType: "unknown",
      description: "last",
    };
    const bytes = encodeShard([
      record("00000000", "00000000", first),
      record("ffffffff", "ffffffff", last),
    ]);
    expect(lookupShard(bytes, "0")).toEqual([first]);
    expect(lookupShard(bytes, "ffffffff")).toEqual([last]);
    expect(lookupShard(bytes, "00000001")).toEqual([]);
    expect(lookupShard(bytes, "fffffffe")).toEqual([]);
  });

  it("compares all 128 bits, including adjacent high IPv6 addresses", () => {
    const first: IntelPayload = { kind: "network", description: "first" };
    const last: IntelPayload = { kind: "network", description: "last" };
    const bytes = encodeShard([
      record(
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        first,
        6,
      ),
      record(
        "fffffffffffffffffffffffffffffffe",
        "ffffffffffffffffffffffffffffffff",
        last,
        6,
      ),
    ]);
    expect(lookupShard(bytes, "0")).toEqual([first]);
    expect(lookupShard(bytes, "fffffffffffffffffffffffffffffffd")).toEqual([]);
    expect(lookupShard(bytes, "fffffffffffffffffffffffffffffffe")).toEqual([
      last,
    ]);
    expect(lookupShard(bytes, "ffffffffffffffffffffffffffffffff")).toEqual([
      last,
    ]);
    expect(() =>
      lookupShard(bytes, "1ffffffffffffffffffffffffffffffff"),
    ).toThrow();
  });

  it("handles a view with a nonzero byte offset", () => {
    const bytes = encodeShard([
      record("08080808", "08080808", { kind: "asn", asn: 64512 }),
    ]);
    const framed = new Uint8Array(bytes.length + 17);
    framed.set(bytes, 11);
    expect(
      lookupShard(framed.subarray(11, 11 + bytes.length), "08080808"),
    ).toEqual([{ kind: "asn", asn: 64512 }]);
  });

  it("validates a shared byte buffer once without retaining mutable decoded payloads", () => {
    const bytes = encodeShard([
      record("08080808", "08080808", { kind: "asn", asn: 64512 }),
    ]);
    expect(lookupShard(bytes, "09090909")).toEqual([]);
    const first = lookupShard(bytes, "08080808");
    first[0].asn = 64513;
    expect(lookupShard(bytes, "08080808")).toEqual([
      { kind: "asn", asn: 64512 },
    ]);
    expect(lookupShard(bytes, "09090909")).toEqual([]);
  });

  it("rejects empty and mixed-family encoder input", () => {
    expect(() => encodeShard([])).toThrow();
    expect(() =>
      encodeShard([record("0"), record("1", "1", { kind: "network" }, 6)]),
    ).toThrow();
  });

  it("rejects reversed intervals instead of silently treating them as clean", () => {
    expect(() => {
      const bytes = encodeShard([record("08080809", "08080808")]);
      lookupShard(bytes, "08080808");
    }).toThrow();
  });

  it("rejects or correctly normalizes unsorted intervals before binary search", () => {
    let bytes: Uint8Array;
    try {
      bytes = encodeShard([
        record("09090909", "09090909", { kind: "asn", asn: 64512 }),
        record("08080808", "08080808", { kind: "asn", asn: 64513 }),
      ]);
    } catch {
      return;
    }
    // Either sorting or fail-closed validation is safe; a silent false negative is not.
    let first: IntelPayload[];
    let second: IntelPayload[];
    try {
      first = lookupShard(bytes, "09090909");
      second = lookupShard(bytes, "08080808");
    } catch {
      return;
    }
    expect(first).toEqual([{ kind: "asn", asn: 64512 }]);
    expect(second).toEqual([{ kind: "asn", asn: 64513 }]);
  });

  it("does not silently miss a low interval placed after a higher search pivot", () => {
    let bytes: Uint8Array;
    try {
      bytes = encodeShard([
        record("09090909"),
        record("0a0a0a0a"),
        record("08080808", "08080808", { kind: "asn", asn: 64514 }),
      ]);
    } catch {
      return;
    }
    let result: IntelPayload[];
    try {
      result = lookupShard(bytes, "08080808");
    } catch {
      return;
    }
    expect(result).toEqual([{ kind: "asn", asn: 64514 }]);
  });
});

describe("binary corruption fails closed", () => {
  it.each([0, 1, 2, 3, 5])(
    "rejects invalid magic/version byte %s",
    (offset) => {
      expect(() =>
        lookupShard(
          corruption((bytes) => {
            bytes[offset] = 255;
          }),
          "08080808",
        ),
      ).toThrow();
    },
  );

  it.each([
    (bytes: Uint8Array) => {
      bytes[4] = 5;
    },
    (_bytes: Uint8Array, view: DataView) => {
      view.setUint16(6, 0, true);
    },
    (_bytes: Uint8Array, view: DataView) => {
      view.setUint32(8, 65537, true);
    },
    (_bytes: Uint8Array, view: DataView) => {
      view.setUint32(12, 0, true);
    },
    (_bytes: Uint8Array, view: DataView) => {
      view.setUint32(12, 0xffffffff, true);
    },
    (_bytes: Uint8Array, view: DataView) => {
      view.setUint32(24, 0xffffffff, true);
    },
  ])("rejects invalid family, bounds and dictionary references", (change) => {
    expect(() => lookupShard(corruption(change), "08080808")).toThrow();
  });

  it("rejects truncation and oversized shards", () => {
    expect(() => lookupShard(new Uint8Array(15), "0")).toThrow();
    const bytes = encodeShard([record("08080808")]);
    const oversized = new Uint8Array(131073);
    oversized.set(bytes);
    expect(() => lookupShard(oversized, "08080808")).toThrow();
  });

  it("rejects malformed JSON and invalid UTF-8 dictionary even on a miss", () => {
    const malformed = legacyShard([record("08080808")]);
    malformed.fill(0xff, new DataView(malformed.buffer).getUint32(12, true));
    expect(() => lookupShard(malformed, "08080808")).toThrow();
    expect(() => lookupShard(malformed, "09090909")).toThrow();
  });

  it("validates all row boundaries and dictionary references before a miss", () => {
    const reversed = corruption((bytes) => {
      bytes[23] = 7;
    });
    const badReference = corruption((_bytes, view) => {
      view.setUint32(24, 1234, true);
    });
    expect(() => lookupShard(reversed, "09090909")).toThrow();
    expect(() => lookupShard(badReference, "09090909")).toThrow();
  });

  it.each(
    [
      {},
      [],
      [null],
      [[]],
      [{ kind: "unknown" }],
      [{ kind: "network" }, { kind: "threat", category: "invented" }],
    ].map((dictionary) => ({ dictionary })),
  )(
    "rejects malformed or unreferenced invalid dictionary entries $dictionary on first miss",
    ({ dictionary }) => {
      expect(() =>
        lookupShard(replaceDictionary(dictionary), "09090909"),
      ).toThrow();
    },
  );

  it("rejects raw unsorted binary records even when they bypass the encoder", () => {
    const bytes = encodeShard([record("08080808"), record("09090909")]);
    const first = bytes.slice(16, 28);
    bytes.copyWithin(16, 28, 40);
    bytes.set(first, 28);
    expect(() => lookupShard(bytes, "07070707")).toThrow();
  });

  it.each([
    { kind: "invalid" },
    { kind: "asn", asn: "64512" },
    { kind: "asn", asn: -1 },
    { kind: "network", attributes: "vpn" },
    { kind: "network", networkType: "invented" },
    { kind: "threat", category: "invented" },
    { kind: "threat", category: "c2", confidence: "definite" },
  ])("rejects invalid typed payload %j", (payload) => {
    expect(() => {
      const bytes = encodeShard([
        record("08080808", "08080808", payload as unknown as IntelPayload),
      ]);
      lookupShard(bytes, "08080808");
    }).toThrow();
    expect(() =>
      lookupShard(replaceDictionary([payload]), "08080808"),
    ).toThrow();
    expect(() =>
      lookupShard(replaceDictionary([payload]), "09090909"),
    ).toThrow();
  });
});

describe("RJI2 indexed payloads and explicitly verified fast path", () => {
  const rows = () => [
    record("08080808", "08080808", { kind: "asn", asn: 64512, organization: "测试 fixture" }),
    record("09090909", "09090909", { kind: "network", networkType: "business" }),
  ];

  it("keeps RJI1 strict-reading compatibility including verified-call fallback", () => {
    const bytes = legacyShard(rows());
    expect(bytes[5]).toBe(1);
    expect(lookupShardMatches(bytes, "08080808")).toMatchObject([{ payload: { asn: 64512 }, start: "08080808", end: "08080808" }]);
    expect(lookupVerifiedShardMatches(bytes, "09090909")).toMatchObject([{ payload: { networkType: "business" } }]);
    const corrupt = legacyShard(rows());
    corrupt.fill(0xff, new DataView(corrupt.buffer).getUint32(12, true));
    expect(() => lookupVerifiedShardMatches(corrupt, "07070707")).toThrow();
  });

  it("uses UTF-8 byte offsets rather than character offsets between separate JSON payloads", () => {
    const bytes = encodeShard(rows());
    const view = new DataView(bytes.buffer);
    const offset = view.getUint32(12, true);
    const firstLength = new TextEncoder().encode(JSON.stringify(rows()[0].payload)).length;
    expect(view.getUint32(offset, true)).toBe(2);
    expect(view.getUint32(offset + 8, true)).toBe(firstLength);
    expect(lookupVerifiedShardMatches(bytes, "09090909")[0].payload).toEqual(rows()[1].payload);
  });

  it("strictly validates every indexed payload even for an address miss", () => {
    const bytes = encodeShard(rows()); corruptIndexedPayload(bytes, 1);
    expect(() => lookupShardMatches(bytes, "07070707")).toThrow();
  });

  it("verified V2 reads only matching JSON, without marking the shard strictly validated", () => {
    const bytes = encodeShard(rows()); corruptIndexedPayload(bytes, 1);
    expect(lookupVerifiedShardMatches(bytes, "07070707")).toEqual([]);
    expect(lookupVerifiedShardMatches(bytes, "08080808")[0].payload).toEqual(rows()[0].payload);
    expect(() => lookupVerifiedShardMatches(bytes, "09090909")).toThrow();
    expect(() => lookupShardMatches(bytes, "08080808")).toThrow();
  });

  it("never silently accepts an invalid matched payload or dictionary reference", () => {
    const payloadInvalid = encodeShard(rows());
    const view = new DataView(payloadInvalid.buffer);
    const offset = view.getUint32(12, true);
    const count = view.getUint32(offset, true);
    const blobStart = offset + 4 + (count + 1) * 4;
    const firstStart = blobStart + view.getUint32(offset + 4, true);
    const firstEnd = blobStart + view.getUint32(offset + 8, true);
    const json = new TextDecoder().decode(payloadInvalid.subarray(firstStart, firstEnd)).replace('"asn":64512', '"asn":"bad"');
    const changed = new TextEncoder().encode(json);
    expect(changed.length).toBe(firstEnd - firstStart);
    payloadInvalid.set(changed, firstStart);
    expect(() => lookupVerifiedShardMatches(payloadInvalid, "08080808")).toThrow();
    const referenceInvalid = encodeShard(rows());
    new DataView(referenceInvalid.buffer).setUint32(24, 12345, true);
    expect(() => lookupVerifiedShardMatches(referenceInvalid, "08080808")).toThrow();
  });

  it("subsequent strict queries decode only hit payloads and a miss decodes nothing", () => {
    const bytes = encodeShard(rows());
    expect(lookupShardMatches(bytes, "07070707")).toEqual([]);
    const parse = vi.spyOn(JSON, "parse");
    try {
      expect(lookupShardMatches(bytes, "08080808")).toHaveLength(1);
      expect(parse).toHaveBeenCalledTimes(1);
      expect(lookupShardMatches(bytes, "07070707")).toEqual([]);
      expect(parse).toHaveBeenCalledTimes(1);
    } finally { parse.mockRestore(); }
  });

  it.each(["zero-count", "excess-count", "nonzero-first", "empty-payload", "past-end", "short-terminal"])("rejects malformed V2 index %s even in the verified path", (kind) => {
    const bytes = encodeShard(rows());
    const view = new DataView(bytes.buffer);
    const offset = view.getUint32(12, true);
    if (kind === "zero-count") view.setUint32(offset, 0, true);
    if (kind === "excess-count") view.setUint32(offset, 65536, true);
    if (kind === "nonzero-first") view.setUint32(offset + 4, 1, true);
    if (kind === "empty-payload") view.setUint32(offset + 8, 0, true);
    if (kind === "past-end") view.setUint32(offset + 8, 0xffffffff, true);
    if (kind === "short-terminal") view.setUint32(offset + 12, view.getUint32(offset + 12, true) - 1, true);
    expect(() => lookupVerifiedShardMatches(bytes, "07070707")).toThrow();
    expect(() => lookupShardMatches(bytes, "07070707")).toThrow();
  });

  it("keeps the 128 KiB encoder guard and its identifiable oversize error", () => {
    expect(() => encodeShard([record("08080808", "08080808", { kind: "network", description: "x".repeat(131072) })])).toThrow("Intelligence shard too large");
  });
});
