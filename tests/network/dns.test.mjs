import { afterEach, describe, expect, it } from "vitest";
import dgram from "node:dgram";
import net from "node:net";
import { Readable } from "node:stream";
import dnsPacket from "dns-packet";
import {
  SessionStore,
  RateLimiter,
  createAuthority,
  handleSessionRequest,
} from "../../services/authoritative-dns/core.mjs";
import { startDnsService } from "../../services/authoritative-dns/server.mjs";

const resources = [];
afterEach(async () => {
  while (resources.length) await resources.pop()();
});
const config = {
  zone: "probe.example.com",
  nameserver: "ns1.example.com",
  ipv4: "192.0.2.10",
  ipv6: "2001:db8::10",
};
const query = (name, type = "A", flags = dnsPacket.RECURSION_DESIRED) =>
  dnsPacket.encode({
    type: "query",
    id: 42,
    flags,
    questions: [{ name, type, class: "IN" }],
  });

describe("DNS session isolation and retention (synthetic clock)", () => {
  it("separates public DNS names from read credentials, bounds TTL and expires all associations", () => {
    let now = 1000;
    const store = new SessionStore({
      ...config,
      ttlMs: 999_999,
      clock: () => now,
    });
    const session = store.create();
    const host = new URL(session.probeUrls[0]).hostname;
    expect(Date.parse(session.expiresAt) - now).toBe(180_000);
    expect(store.read(session.id, session.secret)).not.toBeNull();
    expect(store.read(session.id, host)).toBeNull();
    expect(store.read(session.id, "wrong")).toBeNull();
    store.observe(host, "198.51.100.53", "A");
    expect(store.read(session.id, session.secret).resolvers[0].ip).toBe(
      "198.51.100.53",
    );
    now += 180_000;
    expect(store.read(session.id, session.secret)).toBeNull();
    expect(store.findQuery(host)).toBeNull();
    expect(store.sessions.size).toBe(0);
    expect(store.queries.size).toBe(0);
  });
  it("limits capacity, resolver count and actively deletes data", () => {
    const store = new SessionStore({
      ...config,
      maxSessions: 1,
      maxResolvers: 1,
    });
    const session = store.create();
    expect(() => store.create()).toThrow("CAPACITY");
    const name = new URL(session.probeUrls[0]).hostname;
    store.observe(name, "192.0.2.1", "A");
    store.observe(name, "192.0.2.2", "AAAA");
    expect(store.read(session.id, session.secret).resolvers).toHaveLength(1);
    expect(store.delete(session.id, "wrong")).toBe(false);
    expect(store.delete(session.id, session.secret)).toBe(true);
    expect(store.queries.size).toBe(0);
  });
  it("bounds source counters and resets them on expiry", () => {
    let now = 0;
    const limiter = new RateLimiter({
      limit: 1,
      intervalMs: 100,
      maxKeys: 1,
      clock: () => now,
    });
    expect(limiter.allow("a")).toBe(true);
    expect(limiter.allow("a")).toBe(false);
    expect(limiter.allow("b")).toBe(false);
    now = 100;
    expect(limiter.allow("b")).toBe(true);
    expect(limiter.entries.size).toBe(1);
  });
  it("rejects non-finite retention and bounds observed query types without schema poisoning", () => {
    expect(() => new SessionStore({ ...config, ttlMs: NaN })).toThrow(
      "bounded",
    );
    expect(() => new SessionStore({ ...config, ttlMs: Infinity })).toThrow(
      "bounded",
    );
    expect(() => new RateLimiter({ intervalMs: Infinity })).toThrow("bounded");
    const store = new SessionStore(config);
    const session = store.create();
    const name = new URL(session.probeUrls[0]).hostname;
    for (let type = 60000; type < 60100; type++)
      store.observe(name, "::ffff:192.0.2.53", `UNKNOWN_${type}`);
    const resolver = store.read(session.id, session.secret).resolvers[0];
    expect(resolver.ip).toBe("192.0.2.53");
    expect(resolver.types).toHaveLength(32);
    expect(resolver.types[0]).toBe("TYPE60000");
    expect(resolver.probeCount).toBe(1);
    store.observe(new URL(session.probeUrls[1]).hostname, "192.0.2.53", "A");
    expect(store.read(session.id, session.secret).resolvers[0].probeCount).toBe(2);
    expect(store.observe(name, "not an address", "A")).toBe(false);
  });
  it("isolates authenticated session API budget from anonymous requests and public probes (unit HTTP mock)", async () => {
    const store = new SessionStore(config);
    const session = store.create();
    const name = new URL(session.probeUrls[0]).hostname;
    const apiLimiter = new RateLimiter({ limit: 1, maxKeys: 1 });
    const invoke = async (path, key, host = "localhost", body = {}) => {
      const request = Readable.from([Buffer.from(JSON.stringify(body))]);
      Object.assign(request, {
        url: path,
        method: path === "/probe" ? "GET" : "POST",
        socket: { remoteAddress: "127.0.0.1" },
        headers: {
          host,
          authorization: `Bearer ${key}`,
          "content-type": "application/json",
        },
      });
      const response = {
        status: 0,
        writeHead(status) {
          this.status = status;
        },
        end() {},
      };
      await handleSessionRequest(request, response, {
        store,
        apiKey: "private",
        apiLimiter,
      });
      return response.status;
    };
    for (let attempt = 0; attempt < 4; attempt++)
      expect(await invoke("/v1/session", "wrong")).toBe(403);
    for (let attempt = 0; attempt < 4; attempt++)
      expect(await invoke("/probe", "", name)).toBe(204);
    expect(apiLimiter.entries.size).toBe(0);
    expect(await invoke("/v1/session", "private")).toBe(201);
    expect(await invoke("/v1/session", "private")).toBe(429);
    expect(
      await invoke("/v1/delete", "private", "localhost", {
        id: session.id,
        secret: session.secret,
      }),
    ).toBe(200);
    expect(
      await invoke(`/v1/session?secret=${session.secret}`, "private"),
    ).toBe(400);
  });
});

describe("authoritative DNS packet behavior", () => {
  it("returns real configured A/AAAA and observes resolver source, never enables recursion", () => {
    const store = new SessionStore(config);
    const session = store.create();
    const host = new URL(session.probeUrls[0]).hostname;
    const answer = createAuthority({ ...config, store });
    for (const type of ["A", "AAAA"]) {
      const response = dnsPacket.decode(
        answer(query(host, type), "198.51.100.53"),
      );
      expect(response.answers[0].data).toBe(
        type === "A" ? config.ipv4 : config.ipv6,
      );
      expect(response.flag_aa).toBe(true);
      expect(response.flag_ra).toBe(false);
      expect(response.id).toBe(42);
    }
    expect(store.read(session.id, session.secret).resolvers[0].types).toEqual([
      "A",
      "AAAA",
    ]);
  });
  it("returns valid NODATA for HTTPS, NXDOMAIN for inactive names and REFUSED for outside/AXFR/ANY", () => {
    const store = new SessionStore(config);
    const session = store.create();
    const host = new URL(session.probeUrls[0]).hostname;
    const answer = createAuthority({ ...config, store });
    const https = dnsPacket.decode(answer(query(host, "HTTPS"), "192.0.2.53"));
    expect(https.rcode).toBe("NOERROR");
    expect(https.answers).toHaveLength(0);
    expect(https.authorities[0].type).toBe("SOA");
    const unknown = dnsPacket.decode(
      answer(query("unknown.probe.example.com"), "192.0.2.53"),
    );
    expect(unknown.rcode).toBe("NXDOMAIN");
    for (const [name, type] of [
      ["example.net", "A"],
      [config.zone, "AXFR"],
      [config.zone, "ANY"],
    ]) {
      const response = dnsPacket.decode(
        answer(query(name, type), "192.0.2.53"),
      );
      expect(response.rcode).toBe("REFUSED");
      expect(response.answers).toHaveLength(0);
      expect(response.flag_ra).toBe(false);
    }
    expect(answer(Buffer.alloc(4), "192.0.2.53")).toBeNull();
    expect(answer(Buffer.alloc(4097), "192.0.2.53")).toBeNull();
    const allocationBomb = Buffer.alloc(12);
    allocationBomb.writeUInt16BE(1, 4);
    allocationBomb.writeUInt16BE(65535, 10);
    expect(answer(allocationBomb, "192.0.2.53")).toBeNull();
  });
  it("accepts unknown numeric QTYPE as bounded, faithful TYPE evidence and limits UDP response size", () => {
    const store = new SessionStore(config);
    const session = store.create();
    const name = new URL(session.probeUrls[0]).hostname;
    const answer = createAuthority({ ...config, store });
    const response = answer(query(name, "UNKNOWN_65000"), "192.0.2.53");
    expect(response.length).toBeLessThanOrEqual(512);
    expect(dnsPacket.decode(response).rcode).toBe("NOERROR");
    expect(store.read(session.id, session.secret).resolvers[0].types).toEqual([
      "TYPE65000",
    ]);
    const wrongZone = dnsPacket.decode(
      answer(query(`evil${config.zone}`, "A"), "192.0.2.53"),
    );
    expect(wrongZone.rcode).toBe("REFUSED");
  });
});

describe("real loopback protocol integration (not public deployment)", () => {
  it("starts only with explicit permission, receives UDP/TCP DNS and isolates HTTP session access", async () => {
    await expect(
      startDnsService({ ...config, apiKey: "k".repeat(32) }),
    ).rejects.toThrow("explicit");
    await expect(
      startDnsService({
        ...config,
        enabled: true,
        host: "0.0.0.0",
        apiKey: "k".repeat(32),
      }),
    ).rejects.toThrow("Public");
    await expect(
      startDnsService({
        ...config,
        enabled: true,
        ipv4: "invalid",
        apiKey: "k".repeat(32),
      }),
    ).rejects.toThrow("Every configured");
    const service = await startDnsService({
      ...config,
      enabled: true,
      apiKey: "k".repeat(32),
      dnsPort: 0,
      httpPort: 0,
    });
    resources.push(() => service.close());
    const base = `http://127.0.0.1:${service.web.address().port}`;
    const request = (path, body, key = "k".repeat(32)) =>
      fetch(`${base}${path}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${key}`,
        },
        body: JSON.stringify(body),
      });
    expect((await request("/v1/session", {}, "wrong")).status).toBe(403);
    const created = await request("/v1/session", {});
    expect(created.headers.get("cache-control")).toBe("no-store");
    const session = await created.json();
    const name = new URL(session.probeUrls[0]).hostname;
    expect(
      (await request("/v1/results", { id: session.id, secret: name })).status,
    ).toBe(404);
    const client = dgram.createSocket("udp4");
    resources.push(() => new Promise((resolve) => client.close(resolve)));
    const udpResponse = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("UDP timeout")), 2000);
      client.once("message", (packet) => {
        clearTimeout(timer);
        resolve(dnsPacket.decode(packet));
      });
      client.send(query(name), service.udp.address().port, "127.0.0.1");
    });
    expect(udpResponse.answers[0].data).toBe(config.ipv4);
    const tcpResponse = await new Promise((resolve, reject) => {
      const socket = net.connect(service.tcp.address().port, "127.0.0.1");
      let received = Buffer.alloc(0);
      socket.setTimeout(2000, () => {
        socket.destroy();
        reject(new Error("TCP timeout"));
      });
      socket.once("error", reject);
      socket.once("connect", () => {
        const frame = dnsPacket.streamEncode({
          type: "query",
          id: 43,
          questions: [{ name, type: "AAAA" }],
        });
        socket.write(frame.subarray(0, 2));
        setTimeout(() => socket.write(frame.subarray(2)), 10);
      });
      socket.on("data", (chunk) => {
        received = Buffer.concat([received, chunk]);
        if (
          received.length >= 2 &&
          received.length >= received.readUInt16BE(0) + 2
        ) {
          const decoded = dnsPacket.streamDecode(received);
          socket.end();
          resolve(decoded);
        }
      });
    });
    expect(tcpResponse.answers[0].data).toBe(config.ipv6);
    const result = await (
      await request("/v1/results", { id: session.id, secret: session.secret })
    ).json();
    expect(result.resolvers[0].ip).toBe("127.0.0.1");
    expect(result.verdict).toBe("undetermined");
    expect(
      (await request("/v1/delete", { id: session.id, secret: session.secret }))
        .status,
    ).toBe(200);
    expect(
      (await request("/v1/results", { id: session.id, secret: session.secret }))
        .status,
    ).toBe(404);
  });
  it("closes a slow partial TCP frame at the absolute lifetime limit", async () => {
    const service = await startDnsService({
      ...config,
      enabled: true,
      apiKey: "k".repeat(32),
      dnsPort: 0,
      httpPort: 0,
    });
    resources.push(() => service.close());
    const started = Date.now();
    await new Promise((resolve, reject) => {
      const socket = net.connect(service.tcp.address().port, "127.0.0.1");
      let interval;
      const watchdog = setTimeout(() => {
        socket.destroy();
        reject(new Error("Absolute TCP lifetime was not enforced"));
      }, 8000);
      socket.once("error", reject);
      socket.once("connect", () => {
        socket.write(Buffer.from([0x10, 0]));
        interval = setInterval(() => socket.write(Buffer.from([0])), 400);
      });
      socket.once("close", () => {
        clearInterval(interval);
        clearTimeout(watchdog);
        resolve();
      });
    });
    expect(Date.now() - started).toBeLessThan(8000);
  });
});
