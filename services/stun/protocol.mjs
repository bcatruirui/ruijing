import { isIP } from "node:net";
export const STUN_COOKIE = 0x2112a442;
const crcTable = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit++)
    value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});
export function crc32(buffer) {
  let value = 0xffffffff;
  for (const byte of buffer)
    value = crcTable[(value ^ byte) & 255] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

export function addressBytes(address) {
  const family = isIP(address);
  if (family === 4) return Buffer.from(address.split(".").map(Number));
  if (family !== 6 || address.includes("%"))
    throw new Error("Invalid IP address.");
  let text = address.toLowerCase();
  if (text.includes(".")) {
    const lastColon = text.lastIndexOf(":");
    const ipv4 = addressBytes(text.slice(lastColon + 1));
    text = `${text.slice(0, lastColon)}:${ipv4.readUInt16BE(0).toString(16)}:${ipv4.readUInt16BE(2).toString(16)}`;
  }
  const [left, right] = text.split("::");
  const before = left ? left.split(":") : [];
  const after = right ? right.split(":") : [];
  const groups = text.includes("::")
    ? [
        ...before,
        ...Array(8 - before.length - after.length).fill("0"),
        ...after,
      ]
    : before;
  if (groups.length !== 8) throw new Error("Invalid IPv6 address.");
  const bytes = Buffer.alloc(16);
  groups.forEach((group, index) =>
    bytes.writeUInt16BE(parseInt(group, 16), index * 2),
  );
  return bytes;
}

/** Restricted anonymous Binding only. Never allocates a relay or contacts another host. */
export function bindingResponse(packet, address, port) {
  if (
    !Buffer.isBuffer(packet) ||
    packet.length < 20 ||
    packet.length > 512 ||
    !isIP(address) ||
    address.includes("%") ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65535
  )
    return null;
  if (
    packet.readUInt16BE(0) !== 0x0001 ||
    packet.readUInt32BE(4) !== STUN_COOKIE
  )
    return null;
  const bodyLength = packet.readUInt16BE(2);
  if (bodyLength % 4 || bodyLength + 20 !== packet.length) return null;
  let fingerprint = false;
  for (let offset = 20; offset < packet.length;) {
    if (offset + 4 > packet.length) return null;
    const type = packet.readUInt16BE(offset);
    const length = packet.readUInt16BE(offset + 2);
    if (offset + 4 + length > packet.length) return null;
    // Address-changing extensions can turn a tiny service into a reflector: not supported.
    if (type === 0x0003 || type === 0x000f) return null;
    if (
      (type === 0x0024 && length !== 4) ||
      (type === 0x0025 && length !== 0) ||
      ([0x8029, 0x802a].includes(type) && length !== 8)
    )
      return null;
    if (type === 0x8028) {
      if (
        length !== 4 ||
        offset + 8 !== packet.length ||
        packet.readUInt32BE(offset + 4) !==
          (crc32(packet.subarray(0, offset)) ^ 0x5354554e) >>> 0
      )
        return null;
      fingerprint = true;
    } else if (
      type < 0x8000 &&
      ![
        0x0006, 0x0008, 0x0014, 0x0015, 0x0024, 0x0025, 0x001c, 0x001d,
      ].includes(type)
    )
      return null;
    // Authentication attributes cannot be meaningfully verified by this anonymous probe endpoint.
    // Fail closed instead of appearing to authenticate an ICE connectivity request.
    if ([0x0006, 0x0008, 0x0014, 0x0015, 0x001c, 0x001d].includes(type))
      return null;
    offset += 4 + Math.ceil(length / 4) * 4;
    if (offset > packet.length) return null;
  }
  let bytes = addressBytes(address);
  // A dual-stack UDP6 socket can report an IPv4 packet as ::ffff:a.b.c.d.
  // Its actual transport endpoint is IPv4, not a new public IPv6 endpoint.
  if (
    bytes.length === 16 &&
    bytes.subarray(0, 10).every((byte) => byte === 0) &&
    bytes.readUInt16BE(10) === 0xffff
  )
    bytes = bytes.subarray(12);
  const family = bytes.length === 4 ? 1 : 2;
  const attribute = Buffer.alloc(8 + bytes.length);
  attribute.writeUInt16BE(0x0020);
  attribute.writeUInt16BE(4 + bytes.length, 2);
  attribute[5] = family;
  attribute.writeUInt16BE(port ^ (STUN_COOKIE >>> 16), 6);
  const mask = Buffer.concat([packet.subarray(4, 8), packet.subarray(8, 20)]);
  for (let index = 0; index < bytes.length; index++)
    attribute[index + 8] = bytes[index] ^ mask[index];
  const result = Buffer.alloc(20 + attribute.length + (fingerprint ? 8 : 0));
  result.writeUInt16BE(0x0101);
  result.writeUInt16BE(result.length - 20, 2);
  result.writeUInt32BE(STUN_COOKIE, 4);
  packet.copy(result, 8, 8, 20);
  attribute.copy(result, 20);
  if (fingerprint) {
    const offset = result.length - 8;
    result.writeUInt16BE(0x8028, offset);
    result.writeUInt16BE(4, offset + 2);
    result.writeUInt32BE(
      (crc32(result.subarray(0, offset)) ^ 0x5354554e) >>> 0,
      offset + 4,
    );
  }
  return result;
}
