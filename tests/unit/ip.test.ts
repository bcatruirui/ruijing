import { describe, expect, it } from "vitest";
import {
  CidrIndex,
  cidrContains,
  compareIp,
  containsIp,
  isPublicIp,
  longestPrefixMatch,
  parseCidr,
  parseIp,
  parseIpCanonical,
  requirePublicIp,
} from "../../shared/ip";

describe("strict IP parsing and canonical form", () => {
  it.each(["8.8.8.8", "1.1.1.1", "255.255.255.255", "0.0.0.0"])(
    "round trips IPv4 %s",
    (ip) => {
      const parsed = parseIp(ip)!;
      expect(parsed.family).toBe(4);
      expect(parsed.canonical).toBe(ip);
      expect(parseIp(parsed.canonical)).toEqual(parsed);
    },
  );

  it.each([
    ["2001:0DB8:0000:0000:0001:0000:0000:0001", "2001:db8::1:0:0:1"],
    ["2001:0:0:1:0:0:1:1", "2001::1:0:0:1:1"],
    ["2001:db8:0:1:2:3:4:5", "2001:db8:0:1:2:3:4:5"],
    ["0:0:0:0:0:0:0:0", "::"],
    ["0:0:0:0:0:0:0:1", "::1"],
    ["2001:4860:4860:0:0:0:0:8888", "2001:4860:4860::8888"],
    ["::ffff:192.0.2.1", "::ffff:c000:201"],
    ["2001:db8:1:2:3:4:192.0.2.1", "2001:db8:1:2:3:4:c000:201"],
  ])("normalizes %s", (input, canonical) => {
    const parsed = parseIp(input)!;
    expect(parsed.family).toBe(6);
    expect(parsed.canonical).toBe(canonical);
    expect(parseIp(canonical)).toEqual(parsed);
  });

  it("accepts surrounding whitespace only and exposes an alias", () => {
    expect(parseIpCanonical(" 8.8.8.8 \n")?.canonical).toBe("8.8.8.8");
  });

  it.each([
    "",
    " ",
    "8.8.8",
    "8.8.8.8.8",
    "256.1.2.3",
    "1.2.3.-1",
    "01.2.3.4",
    "1.02.3.4",
    "+1.2.3.4",
    "0x7f.0.0.1",
    "2130706433",
    "1.2.3.4:443",
    "https://8.8.8.8/",
    "8.8.8.8/32",
    "[2001:4860::1]",
    "fe80::1%eth0",
    "2001:::1",
    "2001::1::2",
    ":1:2:3:4:5:6:7",
    "1:2:3:4:5:6:7:",
    "1:2:3:4:5:6:7",
    "1:2:3:4:5:6:7:8:9",
    "1:2:3:4:5:6:7::8",
    "12345::",
    "gggg::1",
    "::ffff:192.168.001.1",
    "::ffff:256.1.2.3",
    "::ffff:1.2.3.4.5",
    "::ffff:1.2.3",
    "1.2.3.４",
    "8.8.8.8\u0000",
    "2001:db8::1\nX-Forwarded-For:8.8.8.8",
  ])("rejects ambiguous or malformed address %j", (value) =>
    expect(parseIp(value)).toBeNull(),
  );

  it.each([null, undefined, 123, {}, ["8.8.8.8"]])(
    "rejects non-string %j",
    (value) => expect(parseIp(value)).toBeNull(),
  );
});

describe("public versus special-use classification", () => {
  it.each([
    ["0.0.0.0", "unspecified"],
    ["0.1.2.3", "reserved"],
    ["10.1.2.3", "private"],
    ["100.64.0.0", "shared"],
    ["100.127.255.255", "shared"],
    ["127.255.255.254", "loopback"],
    ["169.254.1.1", "link-local"],
    ["172.16.0.1", "private"],
    ["172.31.255.255", "private"],
    ["192.168.255.255", "private"],
    ["192.0.0.8", "reserved"],
    ["192.0.2.1", "documentation"],
    ["192.88.99.2", "reserved"],
    ["198.18.0.1", "reserved"],
    ["198.19.255.255", "reserved"],
    ["198.51.100.1", "documentation"],
    ["203.0.113.1", "documentation"],
    ["224.0.0.1", "multicast"],
    ["239.255.255.255", "multicast"],
    ["240.0.0.1", "reserved"],
    ["255.255.255.255", "reserved"],
    ["::", "unspecified"],
    ["::1", "loopback"],
    ["::ffff:8.8.8.8", "ipv4-mapped"],
    ["::ffff:127.0.0.1", "ipv4-mapped"],
    ["fc00::1", "private"],
    ["fdff::1", "private"],
    ["fe80::1", "link-local"],
    ["febf::1", "link-local"],
    ["ff02::1", "multicast"],
    ["2001:db8::1", "documentation"],
    ["3fff::1", "documentation"],
    ["100::1", "reserved"],
    ["100:0:0:1::1", "reserved"],
    ["5f00::1", "reserved"],
    ["2002:808:808::1", "reserved"],
    ["2001:2::1", "reserved"],
    ["4000::1", "reserved"],
    ["64:ff9b:1::1", "reserved"],
  ])("classifies %s as %s", (ip, scope) => {
    expect(parseIp(ip)).toMatchObject({ isPublic: false, scope });
    expect(isPublicIp(ip)).toBe(false);
    expect(() => requirePublicIp(ip)).toThrow("NON_PUBLIC_IP");
  });

  it.each([
    "8.8.8.8",
    "172.15.255.255",
    "172.32.0.0",
    "100.63.255.255",
    "100.128.0.0",
    "192.0.0.9",
    "192.0.0.10",
    "192.31.196.1",
    "2001:4860:4860::8888",
    "2606:4700:4700::1111",
    "64:ff9b::808:808",
    "2001:1::3",
    "2001:3::1",
  ])("accepts globally reachable %s", (ip) => {
    expect(isPublicIp(ip)).toBe(true);
    expect(requirePublicIp(ip).canonical).toBe(parseIp(ip)!.canonical);
  });

  it("distinguishes invalid input from nonpublic input", () =>
    expect(() => requirePublicIp("not-an-ip")).toThrow("INVALID_IP"));
});

describe("CIDR arithmetic and longest prefix", () => {
  it("normalizes host bits for both families without precision loss", () => {
    expect(parseCidr("8.8.8.99/24")?.canonical).toBe("8.8.8.0/24");
    expect(
      parseCidr("2001:4860:1234:5678:abcd:ffff:1234:5678/64")?.canonical,
    ).toBe("2001:4860:1234:5678::/64");
    expect(parseCidr("::/0")?.last).toBe((1n << 128n) - 1n);
    expect(parseCidr("0.0.0.0/0")?.last).toBe((1n << 32n) - 1n);
  });

  it.each([
    "8.8.8.8/-1",
    "8.8.8.8/33",
    "8.8.8.8/1.2",
    "8.8.8.8/01",
    "8.8.8.8/+8",
    "8.8.8.8/",
    "8.8.8.8",
    "2001:db8::/129",
    "8.8.8.8/24/2",
    "invalid/24",
  ])("rejects invalid CIDR %s", (cidr) => expect(parseCidr(cidr)).toBeNull());

  it("includes both boundary addresses and no neighboring addresses", () => {
    const range = parseCidr("8.8.8.0/24")!;
    expect(containsIp(range, "8.8.8.0")).toBe(true);
    expect(containsIp(range, "8.8.8.255")).toBe(true);
    expect(containsIp(range, "8.8.7.255")).toBe(false);
    expect(containsIp(range, "8.8.9.0")).toBe(false);
    expect(
      cidrContains("2001:db8::/32", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
    ).toBe(true);
    expect(cidrContains("2001:db8::1/128", "2001:db8::2")).toBe(false);
  });

  it("does not confuse IPv4 with the same numeric value in IPv6", () => {
    expect(containsIp("0.0.0.0/0", "::1")).toBe(false);
    expect(containsIp("::/0", "0.0.0.1")).toBe(false);
    expect(containsIp("invalid", "8.8.8.8")).toBe(false);
  });

  it("uses longest-prefix matching independent of input order", () => {
    const rows = [
      { cidr: "0.0.0.0/0", id: "default" },
      { cidr: "8.0.0.0/8", id: "wide" },
      { cidr: "8.8.8.0/24", id: "specific" },
    ];
    expect(longestPrefixMatch("8.8.8.8", rows)?.id).toBe("specific");
    expect(longestPrefixMatch("8.8.8.8", [...rows].reverse())?.id).toBe(
      "specific",
    );
    expect(longestPrefixMatch("2001:4860::1", rows)).toBeNull();
    expect(longestPrefixMatch("invalid", rows)).toBeNull();
  });

  it("compiles overlapping IPv6 prefixes and retains first equal match", () => {
    const rows = [
      { cidr: "::/0", value: "default" },
      { cidr: "2001:4860::/32", value: "wide" },
      { cidr: "2001:4860:4860::/48", value: "specific" },
      { cidr: "2001:4860:4860::/48", value: "duplicate" },
    ];
    const index = new CidrIndex(rows);
    expect(index.lookup("2001:4860:4860::8888")).toBe("specific");
    expect(index.lookup("2001:4860::1")).toBe("wide");
    expect(index.lookup("2606:4700::1")).toBe("default");
    expect(index.lookup("8.8.8.8")).toBeNull();
    expect(index.lookup("invalid")).toBeNull();
    expect(() => new CidrIndex([{ cidr: "invalid", value: true }])).toThrow(
      "INVALID_CIDR",
    );
  });

  it("agrees between simple and precompiled matchers over a boundary grid", () => {
    const entries = Array.from({ length: 16 }, (_, index) => ({
      cidr: `8.8.8.${index * 16}/28`,
      value: index,
    }));
    const index = new CidrIndex(entries);
    for (let octet = 0; octet < 256; octet++) {
      const ip = `8.8.8.${octet}`;
      expect(index.lookup(ip)).toBe(longestPrefixMatch(ip, entries)?.value);
    }
  });

  it("compares full IPv6 precision and orders families explicitly", () => {
    expect(
      compareIp(
        "2001:4860::ffff:ffff:ffff:fffe",
        "2001:4860::ffff:ffff:ffff:ffff",
      ),
    ).toBe(-1);
    expect(compareIp("2001:4860::1", "2001:4860:0:0:0:0:0:1")).toBe(0);
    expect(compareIp("8.8.8.9", "8.8.8.8")).toBe(1);
    expect(compareIp("255.255.255.255", "::1")).toBe(-1);
    expect(() => compareIp("invalid", "8.8.8.8")).toThrow("INVALID_IP");
  });
});
