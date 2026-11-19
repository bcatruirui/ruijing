import { afterEach, describe, expect, it } from "vitest";
import dgram from "node:dgram";
import { randomBytes } from "node:crypto";
import {
  STUN_COOKIE,
  addressBytes,
  bindingResponse,
  crc32,
} from "../../services/stun/protocol.mjs";
import { startStunService } from "../../services/stun/server.mjs";
const resources = [];
afterEach(async () => {
  while (resources.length) await resources.pop()();
});
function request(withFingerprint = false) {
  const packet = Buffer.alloc(withFingerprint ? 28 : 20);
  packet.writeUInt16BE(1);
  packet.writeUInt16BE(packet.length - 20, 2);
  packet.writeUInt32BE(STUN_COOKIE, 4);
  randomBytes(12).copy(packet, 8);
  if (withFingerprint) {
    packet.writeUInt16BE(0x8028, 20);
    packet.writeUInt16BE(4, 22);
    packet.writeUInt32BE(
      (crc32(packet.subarray(0, 20)) ^ 0x5354554e) >>> 0,
      24,
    );
  }
  return packet;
}
describe("restricted STUN Binding codec", () => {
  it.each(["198.51.100.8", "2001:db8::1234", "::ffff:192.0.2.3"])(
    "XOR encodes %s and preserves the transaction",
    (ip) => {
      const packet = request(true);
      const response = bindingResponse(packet, ip, 54321);
      expect(response.readUInt16BE(0)).toBe(0x0101);
      expect(response.subarray(8, 20)).toEqual(packet.subarray(8, 20));
      expect(response.readUInt16BE(26) ^ (STUN_COOKIE >>> 16)).toBe(54321);
      const expected = addressBytes(
        ip.startsWith("::ffff:") ? ip.slice(7) : ip,
      );
      const mask = Buffer.concat([
        packet.subarray(4, 8),
        packet.subarray(8, 20),
      ]);
      expect(response[25]).toBe(expected.length === 4 ? 1 : 2);
      const decoded = Buffer.from(response.subarray(28, 28 + expected.length));
      for (let index = 0; index < decoded.length; index++)
        decoded[index] ^= mask[index];
      expect(decoded).toEqual(expected);
      const fp = response.length - 8;
      expect(response.readUInt32BE(fp + 4)).toBe(
        (crc32(response.subarray(0, fp)) ^ 0x5354554e) >>> 0,
      );
      expect(response.length).toBeLessThanOrEqual(52);
    },
  );
  it("drops malformed, oversized, allocation, invalid fingerprint and address-changing packets", () => {
    expect(bindingResponse(Buffer.alloc(19), "127.0.0.1", 1234)).toBeNull();
    expect(bindingResponse(Buffer.alloc(513), "127.0.0.1", 1234)).toBeNull();
    const allocation = request();
    allocation.writeUInt16BE(3);
    expect(bindingResponse(allocation, "127.0.0.1", 1234)).toBeNull();
    const fingerprint = request(true);
    fingerprint[27] ^= 1;
    expect(bindingResponse(fingerprint, "127.0.0.1", 1234)).toBeNull();
    const change = Buffer.concat([
      request(),
      Buffer.from([0, 3, 0, 4, 0, 0, 0, 0]),
    ]);
    change.writeUInt16BE(8, 2);
    expect(bindingResponse(change, "127.0.0.1", 1234)).toBeNull();
    expect(bindingResponse(request(), "fe80::1%1", 1234)).toBeNull();
  });
});
describe("real loopback STUN (not public deployment)", () => {
  it("requires enablement and replies with the actual UDP client source port", async () => {
    await expect(startStunService()).rejects.toThrow("explicit");
    await expect(
      startStunService({ enabled: true, host: "0.0.0.0" }),
    ).rejects.toThrow("Public");
    const service = await startStunService({ enabled: true, port: 0 });
    resources.push(() => service.close());
    const client = dgram.createSocket("udp4");
    resources.push(() => new Promise((resolve) => client.close(resolve)));
    const response = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("UDP timeout")), 2000);
      client.once("message", (packet) => {
        clearTimeout(timer);
        resolve(packet);
      });
      client.send(request(), service.socket.address().port, "127.0.0.1");
    });
    expect(response.readUInt16BE(26) ^ (STUN_COOKIE >>> 16)).toBe(
      client.address().port,
    );
  });
  it("handles a real IPv6 loopback datagram", async () => {
    const service = await startStunService({
      enabled: true,
      host: "::1",
      port: 0,
    });
    resources.push(() => service.close());
    const client = dgram.createSocket("udp6");
    resources.push(() => new Promise((resolve) => client.close(resolve)));
    const packet = request();
    const response = await new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error("IPv6 UDP timeout")),
        2000,
      );
      client.once("message", (data) => {
        clearTimeout(timer);
        resolve(data);
      });
      client.once("error", reject);
      client.send(packet, service.socket.address().port, "::1");
    });
    expect(response[25]).toBe(2);
    expect(response.readUInt16BE(26) ^ (STUN_COOKIE >>> 16)).toBe(
      client.address().port,
    );
    const decoded = Buffer.from(response.subarray(28, 44));
    const mask = packet.subarray(4, 20);
    for (let index = 0; index < decoded.length; index++)
      decoded[index] ^= mask[index];
    expect(decoded).toEqual(addressBytes("::1"));
  });
});
