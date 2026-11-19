import { randomBytes, createHash, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import dnsPacket from "dns-packet";

const digest = (value) => createHash("sha256").update(value).digest();
const safeEqual = (left, right) =>
  typeof left === "string" &&
  typeof right === "string" &&
  timingSafeEqual(digest(left), digest(right));
export function canonicalZone(zone) {
  const value = String(zone ?? "")
    .toLowerCase()
    .replace(/\.$/, "");
  if (
    value.length > 200 ||
    !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value)
  )
    throw new Error("A valid delegated DNS zone is required.");
  return value;
}

/** This store never receives HTTP visitor IPs. Query names are NOT read credentials. */
export class SessionStore {
  constructor({
    zone,
    ttlMs = 150_000,
    maxSessions = 256,
    maxResolvers = 16,
    clock = Date.now,
  } = {}) {
    if (
      !Number.isFinite(ttlMs) ||
      !Number.isInteger(maxSessions) ||
      maxSessions < 1 ||
      maxSessions > 1024 ||
      !Number.isInteger(maxResolvers) ||
      maxResolvers < 1 ||
      maxResolvers > 16
    )
      throw new Error("Invalid bounded session-store configuration.");
    this.zone = canonicalZone(zone);
    this.ttlMs = Math.max(1000, Math.min(180_000, ttlMs));
    this.maxSessions = maxSessions;
    this.maxResolvers = maxResolvers;
    this.clock = clock;
    this.sessions = new Map();
    this.queries = new Map();
  }
  sweep() {
    const now = this.clock();
    for (const [id, session] of this.sessions)
      if (session.expiresAt <= now) this.remove(id);
  }
  remove(id) {
    const session = this.sessions.get(id);
    if (session) for (const name of session.names) this.queries.delete(name);
    this.sessions.delete(id);
  }
  create() {
    this.sweep();
    if (this.sessions.size >= this.maxSessions) throw new Error("CAPACITY");
    const id = randomBytes(16).toString("hex");
    const secret = randomBytes(32).toString("base64url");
    const names = Array.from(
      { length: 4 },
      () => `q${randomBytes(16).toString("hex")}.${this.zone}`,
    );
    const expiresAt = this.clock() + this.ttlMs;
    this.sessions.set(id, {
      secretHash: digest(secret),
      names,
      expiresAt,
      resolvers: new Map(),
    });
    for (const name of names) this.queries.set(name, id);
    return {
      id,
      secret,
      expiresAt: new Date(expiresAt).toISOString(),
      probeUrls: names.map((name) => `https://${name}/probe`),
    };
  }
  findQuery(name) {
    const normalized = String(name).toLowerCase().replace(/\.$/, "");
    const id = this.queries.get(normalized);
    const session = id && this.sessions.get(id);
    if (!session || session.expiresAt <= this.clock()) {
      if (id) this.remove(id);
      return null;
    }
    return session;
  }
  observe(name, resolverIp, type) {
    const session = this.findQuery(name);
    if (!session) return false;
    // Scope IDs are interface metadata, not part of an IP. Canonicalize transport
    // addresses so a dual-stack listener does not mislabel IPv4-mapped peers.
    const rawIp = String(resolverIp).split("%")[0];
    if (!isIP(rawIp)) return false;
    resolverIp = rawIp.includes(":")
      ? new URL(`http://[${rawIp}]/`).hostname.slice(1, -1)
      : rawIp;
    const mapped = resolverIp.match(/^::ffff:([\da-f]{1,4}):([\da-f]{1,4})$/);
    if (mapped) {
      const high = parseInt(mapped[1], 16),
        low = parseInt(mapped[2], 16);
      resolverIp = `${high >>> 8}.${high & 255}.${low >>> 8}.${low & 255}`;
    }
    // dns-packet represents unassigned numeric QTYPEs as UNKNOWN_n. Keep the
    // real numeric type without allowing a query to poison the result schema.
    type = String(type).replace(/^UNKNOWN_(\d{1,5})$/, "TYPE$1");
    if (!/^[A-Z0-9-]{1,16}$/.test(type)) return false;
    const existing = session.resolvers.get(resolverIp);
    if (existing) {
      existing.lastObservedAt = new Date(this.clock()).toISOString();
      if (existing.types.size < 32) existing.types.add(type);
      existing.names.add(name);
    } else if (session.resolvers.size < this.maxResolvers)
      session.resolvers.set(resolverIp, {
        ip: resolverIp,
        firstObservedAt: new Date(this.clock()).toISOString(),
        lastObservedAt: new Date(this.clock()).toISOString(),
        types: new Set([type]),
        names: new Set([name]),
      });
    return true;
  }
  read(id, secret) {
    if (
      typeof id !== "string" ||
      typeof secret !== "string" ||
      id.length > 64 ||
      secret.length > 128
    )
      return null;
    const session = this.sessions.get(id);
    if (!session || session.expiresAt <= this.clock()) {
      if (session) this.remove(id);
      return null;
    }
    if (!timingSafeEqual(session.secretHash, digest(secret))) return null;
    return {
      id,
      expiresAt: new Date(session.expiresAt).toISOString(),
      resolvers: [...session.resolvers.values()].map(({ names, types, ...item }) => ({
        ...item,
        types: [...types],
        probeCount: names.size,
      })),
      verdict: "undetermined",
      explanation:
        "Observed recursive resolver addresses only. ASN or country differences do not establish a DNS leak.",
    };
  }
  delete(id, secret) {
    if (!this.read(id, secret)) return false;
    this.remove(id);
    return true;
  }
  close() {
    this.sessions.clear();
    this.queries.clear();
  }
}

/** Bounded in-memory counters: no logs, no history, and fixed expiry. */
export class RateLimiter {
  constructor({
    limit = 30,
    intervalMs = 10_000,
    maxKeys = 2048,
    clock = Date.now,
  } = {}) {
    if (
      !Number.isInteger(limit) ||
      limit < 1 ||
      !Number.isFinite(intervalMs) ||
      intervalMs < 1 ||
      intervalMs > 180_000 ||
      !Number.isInteger(maxKeys) ||
      maxKeys < 1 ||
      maxKeys > 4096
    )
      throw new Error("Invalid bounded rate-limiter configuration.");
    this.limit = limit;
    this.intervalMs = intervalMs;
    this.maxKeys = maxKeys;
    this.clock = clock;
    this.entries = new Map();
  }
  allow(key) {
    const now = this.clock();
    let bucket = this.entries.get(key);
    if (!bucket || bucket.expiresAt <= now) {
      if (this.entries.size >= this.maxKeys)
        for (const [entryKey, value] of this.entries)
          if (value.expiresAt <= now) this.entries.delete(entryKey);
      if (!bucket && this.entries.size >= this.maxKeys) return false;
      bucket = { count: 0, expiresAt: now + this.intervalMs };
      this.entries.set(key, bucket);
    }
    return ++bucket.count <= this.limit;
  }
  sweep() {
    const now = this.clock();
    for (const [key, value] of this.entries)
      if (value.expiresAt <= now) this.entries.delete(key);
  }
  clear() {
    this.entries.clear();
  }
}

export function createAuthority({ zone, nameserver, ipv4, ipv6, store }) {
  zone = canonicalZone(zone);
  nameserver = canonicalZone(nameserver);
  const soa = {
    name: zone,
    type: "SOA",
    ttl: 0,
    data: {
      mname: nameserver,
      rname: `hostmaster.${zone}`,
      serial: 1,
      refresh: 60,
      retry: 60,
      expire: 180,
      minimum: 0,
    },
  };
  return function answer(buffer, resolverIp) {
    // Large packets, malformed messages and query batches are dropped before an answer is built.
    if (!Buffer.isBuffer(buffer) || buffer.length < 12 || buffer.length > 4096)
      return null;
    // Inspect counts before the codec allocates arrays from an untrusted header.
    // A normal standard query contains one question and optionally one EDNS OPT.
    const wireFlags = buffer.readUInt16BE(2);
    if (
      (wireFlags & 0xf800) !== 0 ||
      buffer.readUInt16BE(4) !== 1 ||
      buffer.readUInt16BE(6) !== 0 ||
      buffer.readUInt16BE(8) !== 0 ||
      buffer.readUInt16BE(10) > 1
    )
      return null;
    let request;
    try {
      request = dnsPacket.decode(buffer);
    } catch {
      return null;
    }
    if (
      request.type !== "query" ||
      request.opcode !== "QUERY" ||
      request.questions?.length !== 1
    )
      return null;
    const question = request.questions[0];
    const name = question.name.toLowerCase().replace(/\.$/, "");
    if (question.class && question.class !== "IN") return null;
    const inZone = name === zone || name.endsWith(`.${zone}`);
    let flags = request.flags & dnsPacket.RECURSION_DESIRED; // RA deliberately absent.
    if (inZone) flags |= dnsPacket.AUTHORITATIVE_ANSWER;
    const response = {
      type: "response",
      id: request.id,
      flags,
      questions: request.questions,
      answers: [],
      authorities: [],
      additionals: [],
    };
    if (!inZone || ["ANY", "AXFR", "IXFR"].includes(question.type))
      response.flags |= dnsPacket.REFUSED ?? 5;
    else if (name === zone && question.type === "SOA")
      response.answers.push(soa);
    else if (name === zone && question.type === "NS")
      response.answers.push({
        name: zone,
        type: "NS",
        ttl: 60,
        data: nameserver,
      });
    else if (name === nameserver && question.type === "A" && ipv4)
      response.answers.push({ name, type: "A", ttl: 60, data: ipv4 });
    else if (name === nameserver && question.type === "AAAA" && ipv6)
      response.answers.push({ name, type: "AAAA", ttl: 60, data: ipv6 });
    else if (store.findQuery(name)) {
      // Record the DNS packet's source, never EDNS Client Subnet or forwarded HTTP headers.
      store.observe(name, resolverIp, question.type);
      if (question.type === "A" && ipv4)
        response.answers.push({ name, type: "A", ttl: 0, data: ipv4 });
      else if (question.type === "AAAA" && ipv6)
        response.answers.push({ name, type: "AAAA", ttl: 0, data: ipv6 });
      else response.authorities.push(soa); // Includes HTTPS/SVCB: valid NODATA.
    } else if (name === zone || name === nameserver)
      response.authorities.push(soa);
    else {
      response.flags |= 3;
      response.authorities.push(soa);
    } // NXDOMAIN with SOA.
    try {
      let encoded = dnsPacket.encode(response);
      if (encoded.length > 512)
        encoded = dnsPacket.encode({
          ...response,
          flags: response.flags | dnsPacket.TRUNCATED_RESPONSE,
          answers: [],
          authorities: [],
        });
      return encoded.length <= 512 ? encoded : null;
    } catch {
      return null;
    }
  };
}

export async function handleSessionRequest(
  request,
  response,
  {
    store,
    apiKey,
    originAllowlist = [],
    apiLimiter,
    probeLimiter,
    probeGlobalLimiter,
  },
) {
  const headers = {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  };
  const reply = (status, body) => {
    response.writeHead(status, headers);
    response.end(JSON.stringify(body));
  };
  let path;
  try {
    const url = new URL(request.url, "http://localhost");
    if (url.search) {
      reply(400, { error: "QUERY_PARAMETERS_NOT_ALLOWED" });
      return;
    }
    path = url.pathname;
  } catch {
    reply(400, { error: "INVALID_INPUT" });
    return;
  }
  const host = String(request.headers.host ?? "")
    .split(":")[0]
    .toLowerCase();
  if (
    path === "/probe" &&
    ["GET", "HEAD"].includes(request.method) &&
    store.findQuery(host)
  ) {
    if (
      (probeGlobalLimiter && !probeGlobalLimiter.allow("all")) ||
      (probeLimiter && !probeLimiter.allow(request.socket.remoteAddress))
    ) {
      reply(429, { error: "RATE_LIMITED" });
      return;
    }
    response.writeHead(204, {
      ...headers,
      "Cross-Origin-Resource-Policy": "cross-origin",
    });
    response.end();
    return;
  }
  if (path === "/v1/health" && request.method === "HEAD") {
    const authorized = safeEqual(request.headers.authorization, `Bearer ${apiKey}`);
    response.writeHead(authorized ? 204 : 403, {
      ...headers, ...(authorized ? { "X-Ruijing-DNS": "authority-v1" } : {}),
    });
    response.end();
    return;
  }
  if (
    request.method !== "POST" ||
    !["/v1/session", "/v1/results", "/v1/delete"].includes(path)
  ) {
    reply(404, { error: "NOT_FOUND" });
    return;
  }
  const origin = request.headers.origin;
  if (origin && !originAllowlist.includes(origin)) {
    reply(403, { error: "ORIGIN_DENIED" });
    return;
  }
  if (!safeEqual(request.headers.authorization, `Bearer ${apiKey}`)) {
    reply(403, { error: "FORBIDDEN" });
    return;
  }
  // Unauthenticated requests and probe fetches cannot exhaust the private
  // session API's budget. Creation and reads remain bounded after auth.
  if (path !== "/v1/delete" && apiLimiter && !apiLimiter.allow("all")) {
    reply(429, { error: "RATE_LIMITED" });
    return;
  }
  if (
    !String(request.headers["content-type"] ?? "").startsWith(
      "application/json",
    )
  ) {
    reply(415, { error: "JSON_REQUIRED" });
    return;
  }
  let body = "";
  let bodyBytes = 0;
  try {
    for await (const chunk of request) {
      bodyBytes += chunk.length;
      if (bodyBytes > 2048) {
        reply(413, { error: "TOO_LARGE" });
        return;
      }
      body += chunk.toString();
    }
    const data = body ? JSON.parse(body) : {};
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      reply(400, { error: "INVALID_INPUT" });
      return;
    }
    if (path === "/v1/session") {
      reply(201, store.create());
      return;
    }
    if (path === "/v1/delete") {
      const deleted = store.delete(data.id, data.secret);
      reply(deleted ? 200 : 404, { deleted });
      return;
    }
    const result = store.read(data.id, data.secret);
    reply(result ? 200 : 404, result ?? { error: "SESSION_UNAVAILABLE" });
  } catch (error) {
    reply(error.message === "CAPACITY" ? 503 : 400, {
      error: error.message === "CAPACITY" ? "CAPACITY" : "INVALID_INPUT",
    });
  }
}
