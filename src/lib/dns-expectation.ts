import { containsIp, parseCidr, parseIp } from "../../shared/ip.ts";

export function expectedResolvers(value: string) {
  const entries = value.trim().split(/[\s,，]+/).filter(Boolean);
  return entries.length <= 16 && entries.every(entry => parseCidr(entry) || /^AS[1-9]\d{0,9}$/i.test(entry) && Number(entry.slice(2)) <= 0xffffffff)
    ? entries : null;
}

export function unexpectedResolver(resolver: { ip: string; asn?: number; probeCount?: number }, expected: string[]) {
  if (!expected.length || (resolver.probeCount ?? 0) < 2 || !parseIp(resolver.ip)?.isPublic) return false;
  if (!resolver.asn && expected.some(entry => /^AS/i.test(entry))) return false;
  return !expected.some(entry => /^AS/i.test(entry)
    ? resolver.asn === Number(entry.slice(2)) : containsIp(entry, resolver.ip));
}
