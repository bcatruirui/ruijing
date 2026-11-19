import dgram from "node:dgram";
import net from "node:net";
import http from "node:http";
import https from "node:https";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import {
  SessionStore,
  RateLimiter,
  createAuthority,
  handleSessionRequest,
} from "./core.mjs";

export async function startDnsService(config) {
  if (config.enabled !== true)
    throw new Error("DNS service requires explicit enablement.");
  const host = config.host ?? "127.0.0.1";
  if (!["127.0.0.1", "::1"].includes(host) && config.allowPublic !== true)
    throw new Error("Public listening requires explicit allowPublic.");
  if (!config.apiKey || config.apiKey.length < 32)
    throw new Error("A private API key of at least 32 characters is required.");
  if (
    (!config.ipv4 && !config.ipv6) ||
    (config.ipv4 && net.isIP(config.ipv4) !== 4) ||
    (config.ipv6 && (net.isIP(config.ipv6) !== 6 || config.ipv6.includes("%")))
  )
    throw new Error(
      "Every configured probe address must be valid and at least one is required.",
    );
  if (
    config.allowPublic &&
    !(config.tls?.key && config.tls?.cert) &&
    !config.trustedTlsProxy
  )
    throw new Error(
      "Public probes require TLS or an explicitly configured TLS reverse proxy.",
    );
  const store = new SessionStore({ zone: config.zone, ttlMs: config.ttlMs });
  const answer = createAuthority({ ...config, store });
  const limiter = new RateLimiter({ limit: 40 });
  const globalLimiter = new RateLimiter({ limit: 2000 });
  const apiLimiter = new RateLimiter({
    limit: 120,
    intervalMs: 60_000,
    maxKeys: 1,
  });
  const probeLimiter = new RateLimiter({ limit: 40 });
  const probeGlobalLimiter = new RateLimiter({ limit: 2000, maxKeys: 1 });
  const udp = dgram.createSocket(host.includes(":") ? "udp6" : "udp4");
  udp.on("error", () => {}); // Bind failures are also observed by the startup promise below.
  udp.on("message", (message, peer) => {
    if (!globalLimiter.allow("all") || !limiter.allow(peer.address)) return;
    const result = answer(message, peer.address);
    if (result) udp.send(result, peer.port, peer.address, () => {});
  });
  let connectionCount = 0;
  const tcp = net.createServer((socket) => {
    if (connectionCount >= 64) {
      socket.destroy();
      return;
    }
    connectionCount++;
    let buffer = Buffer.alloc(0);
    let processed = 0;
    const lifetime = setTimeout(() => socket.destroy(), 5000);
    lifetime.unref();
    socket.on("close", () => {
      connectionCount--;
      clearTimeout(lifetime);
    });
    socket.on("error", () => {});
    socket.setTimeout(3000, () => socket.destroy());
    socket.on("data", (chunk) => {
      if (buffer.length + chunk.length > 8192) {
        socket.destroy();
        return;
      }
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 2) {
        const length = buffer.readUInt16BE(0);
        if (length < 12 || length > 4096 || ++processed > 32) {
          socket.destroy();
          return;
        }
        if (buffer.length < length + 2) {
          processed--;
          break;
        }
        if (
          !globalLimiter.allow("all") ||
          !limiter.allow(socket.remoteAddress)
        ) {
          socket.destroy();
          return;
        }
        const result = answer(
          buffer.subarray(2, length + 2),
          socket.remoteAddress,
        );
        buffer = buffer.subarray(length + 2);
        if (result) {
          const frame = Buffer.alloc(result.length + 2);
          frame.writeUInt16BE(result.length);
          result.copy(frame, 2);
          socket.write(frame);
        }
      }
    });
  });
  const listener = (request, response) => {
    void handleSessionRequest(request, response, {
      store,
      apiKey: config.apiKey,
      originAllowlist: config.originAllowlist ?? [],
      apiLimiter,
      probeLimiter,
      probeGlobalLimiter,
    }).catch(() => {
      if (!response.headersSent)
        response.writeHead(500, { "Cache-Control": "no-store" });
      response.end();
    });
  };
  const webOptions = {
    requestTimeout: 5000,
    headersTimeout: 5000,
    connectionsCheckingInterval: 1000,
    keepAliveTimeout: 1000,
    maxHeaderSize: 8192,
  };
  const web = config.tls
    ? https.createServer({ ...webOptions, ...config.tls }, listener)
    : http.createServer(webOptions, listener);
  web.maxConnections = 64;
  const cleanup = setInterval(() => {
    store.sweep();
    limiter.sweep();
    globalLimiter.sweep();
    apiLimiter.sweep();
    probeLimiter.sweep();
    probeGlobalLimiter.sweep();
  }, 1000);
  cleanup.unref();
  const listen = (server, port) =>
    new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, host, () => {
        server.removeListener("error", reject);
        resolve();
      });
    });
  try {
    await new Promise((resolve, reject) => {
      udp.once("error", reject);
      udp.bind(config.dnsPort ?? 5353, host, () => {
        udp.removeListener("error", reject);
        resolve();
      });
    });
    await listen(tcp, config.dnsPort ?? 5353);
    await listen(web, config.httpPort ?? 8789);
  } catch (error) {
    clearInterval(cleanup);
    store.close();
    try {
      udp.close();
    } catch {}
    tcp.close();
    web.close();
    throw error;
  }
  return {
    store,
    udp,
    tcp,
    web,
    close: async () => {
      clearInterval(cleanup);
      store.close();
      limiter.clear();
      globalLimiter.clear();
      apiLimiter.clear();
      probeLimiter.clear();
      probeGlobalLimiter.clear();
      web.closeAllConnections();
      await Promise.all([
        new Promise((resolve) => udp.close(resolve)),
        new Promise((resolve) => tcp.close(resolve)),
        new Promise((resolve) => web.close(resolve)),
      ]);
    },
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const env = process.env;
  if (env.ENABLE_DNS_SERVICE !== "true")
    throw new Error(
      "Set ENABLE_DNS_SERVICE=true only after reviewing deployment prerequisites.",
    );
  const config = {
    enabled: true,
    zone: env.DNS_ZONE,
    nameserver: env.DNS_NAMESERVER,
    ipv4: env.PROBE_IPV4,
    ipv6: env.PROBE_IPV6,
    apiKey: env.DNS_API_KEY,
    host: env.LISTEN_HOST ?? "127.0.0.1",
    dnsPort: Number(env.DNS_PORT ?? 5353),
    httpPort: Number(env.HTTP_PORT ?? 8789),
    allowPublic: env.ALLOW_PUBLIC_LISTEN === "true",
    trustedTlsProxy: env.TRUSTED_TLS_PROXY === "true",
    originAllowlist: (env.ORIGIN_ALLOWLIST ?? "").split(",").filter(Boolean),
    tls:
      env.TLS_KEY_FILE && env.TLS_CERT_FILE
        ? {
            key: readFileSync(env.TLS_KEY_FILE),
            cert: readFileSync(env.TLS_CERT_FILE),
          }
        : undefined,
  };
  await startDnsService(config);
  // Deliberately no packet, address, session, token, or request logging.
  console.info(
    "Authoritative DNS service started. Connection metadata logging is disabled.",
  );
}
