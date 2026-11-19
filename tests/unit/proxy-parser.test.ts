import { describe, expect, it } from "vitest";
import { encodeShard, lookupShardMatches } from "../../shared/dataset.ts";
// @ts-ignore Native Node ESM ingestion utility.
import { parseMonosansProxySnapshot, parseMonosansRevision, parseMonosansAtom } from "../../scripts/proxy-parser.mjs";

// All records below are synthetic parser fixtures, not live detection claims.
const row = (overrides: Record<string, unknown> = {}) => ({
  protocol: "socks5",
  host: "8.8.8.8",
  port: 1080,
  exit_ip: "8.8.8.8",
  ...overrides,
});

describe("Monosans observation projection", () => {
  it("preserves distinct ingress and destination-visible exit roles", () => {
    const { records } = parseMonosansProxySnapshot([
      row({ exit_ip: "1.1.1.1" }),
    ]);
    expect(records).toHaveLength(2);
    expect(records[0].payload.description).toContain("observed proxy exit");
    expect(records[0].payload.description).toContain("open listening port");
    expect(records[1].payload.description).toContain("proxy ingress;");
    expect(records[1].payload.description).toContain("not established");
  });
  it("deduplicates addresses, ports and protocols without multiplying risk evidence", () => {
    const { records } = parseMonosansProxySnapshot([
      row(), row(), row({ port: 1081 }), row({ protocol: "http" }),
    ]);
    expect(records).toHaveLength(1);
    expect(records[0].payload.description).toContain("ingress and observed exit");
    expect(records[0].payload.description).toContain("protocols: http, socks5");
    expect(records[0].payload.attributes).toEqual(["public_proxy"]);
  });
  it("discards credentials, MaxMind enrichment, latency and unknown extra fields", () => {
    const { records } = parseMonosansProxySnapshot([row({
      username: "fixture-user", password: "fixture-secret", timeout: 0.1,
      asn: { autonomous_system_number: 1234 },
      geolocation: { country: "US", location: { latitude: 11, longitude: 22 } },
      provider: "invented-provider", first_seen: "2026-01-01", residential: true,
    })]);
    const text = JSON.stringify(records);
    for (const token of ["fixture-user", "fixture-secret", "1234", "latitude", "longitude", "invented-provider", "observedAt", "residential_proxy"])
      expect(text).not.toContain(token);
    expect(records[0].payload).toMatchObject({kind: "network", category: "proxy"});
    expect(records[0].payload.networkType).toBeUndefined();
  });
  it("normalizes IPv6 and supports the strict production binary codec", () => {
    const { records } = parseMonosansProxySnapshot([
      row({ host: "2606:4700:4700:0:0:0:0:1111", exit_ip: "2606:4700:4700::1111" }),
    ]);
    expect(records).toHaveLength(1);
    expect(records[0].family).toBe(6);
    const matches = lookupShardMatches(encodeShard(records), records[0].start);
    expect(matches[0].payload.attributes).toEqual(["public_proxy"]);
  });
  it("never resolves hostnames or indexes private, reserved or mapped addresses", () => {
    const { records, ignoredRows } = parseMonosansProxySnapshot([
      row({ host: "example.test", exit_ip: "1.1.1.1" }),
      row({ host: "127.0.0.1" }), row({ host: "10.0.0.1" }),
      row({ host: "192.0.2.1" }), row({ host: "::ffff:8.8.8.8" }),
      row({ exit_ip: "192.168.0.1" }),
    ]);
    expect(ignoredRows).toBe(5);
    expect(records).toHaveLength(1);
    expect(records[0].payload.description).toContain("proxy ingress;");
  });
  it("supports a missing exit without claiming a measured exit", () => {
    const { records } = parseMonosansProxySnapshot([row({ exit_ip: null })]);
    expect(records[0].payload.description).toContain("proxy ingress;");
    expect(records[0].payload.description).not.toContain("ingress and observed exit");
  });
  it("rejects invalid documents and bounds input rather than silently accepting a broken feed", () => {
    expect(() => parseMonosansProxySnapshot({})).toThrow(/snapshot/);
    expect(() => parseMonosansProxySnapshot([null])).toThrow(/schema/);
    expect(() => parseMonosansProxySnapshot(Array(50_001).fill(row()))).toThrow(/oversized/);
    expect(() => parseMonosansProxySnapshot([row({ port: 0 })])).toThrow(/no usable/);
    expect(() => parseMonosansProxySnapshot([row({ protocol: "unexpected" })])).toThrow(/no usable/);
    expect(parseMonosansProxySnapshot([]).records).toEqual([]);
  });
});

describe("Monosans source publication provenance", () => {
  const fixture = [{sha: "a".repeat(40), commit: {committer: {date: "2026-10-29T08:00:00Z"}}}];
  it("pins a valid revision and publication date without inventing an observation date", () => {
    expect(parseMonosansRevision(fixture, new Date("2026-10-29T09:00:00Z"))).toEqual({
      revision: "a".repeat(40), publishedAt: "2026-10-29T08:00:00.000Z",
    });
  });
  it("rejects missing, malformed and future source metadata", () => {
    expect(() => parseMonosansRevision([], new Date())).toThrow(/revision/);
    expect(() => parseMonosansRevision([{sha: "main"}], new Date())).toThrow(/revision/);
    expect(() => parseMonosansRevision(fixture, new Date("2026-10-28T00:00:00Z"))).toThrow(/timestamp/);
  });
  const atom = `<feed><link href="https://github.com/monosans/proxy-list/commits/main/proxies.json.atom"/><entry><id>tag:github.com,2008:Grit::Commit/${"a".repeat(40)}</id><updated>2026-10-29T08:00:00Z</updated></entry></feed>`;
  it("reads the file-specific Atom revision without a GitHub API quota", () => {
    expect(parseMonosansAtom(atom, new Date("2026-10-29T09:00:00Z"))).toEqual({
      revision: "a".repeat(40), publishedAt: "2026-10-29T08:00:00.000Z",
    });
  });
  it("rejects other repository feeds, oversized feeds, bad hashes and future revisions", () => {
    expect(() => parseMonosansAtom(atom.replace("monosans", "unrelated"))).toThrow(/feed/);
    expect(() => parseMonosansAtom(atom + " ".repeat(262144))).toThrow(/feed/);
    expect(() => parseMonosansAtom(atom.replace("a".repeat(40), "main"))).toThrow(/revision/);
    expect(() => parseMonosansAtom(atom, new Date("2026-10-28T00:00:00Z"))).toThrow(/timestamp/);
  });
});
