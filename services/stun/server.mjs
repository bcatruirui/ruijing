import dgram from "node:dgram";
import { pathToFileURL } from "node:url";
import { RateLimiter } from "../authoritative-dns/core.mjs";
import { bindingResponse } from "./protocol.mjs";

export async function startStunService({
  enabled = false,
  host = "127.0.0.1",
  port = 3478,
  allowPublic = false,
} = {}) {
  if (!enabled) throw new Error("STUN service requires explicit enablement.");
  if (!["127.0.0.1", "::1"].includes(host) && !allowPublic)
    throw new Error("Public listening requires explicit allowPublic.");
  const socket = dgram.createSocket(host.includes(":") ? "udp6" : "udp4");
  socket.on("error", () => {}); // Bind failures still reject the startup promise.
  const perSource = new RateLimiter({
    limit: 20,
    intervalMs: 10_000,
    maxKeys: 2048,
  });
  const global = new RateLimiter({
    limit: 1000,
    intervalMs: 10_000,
    maxKeys: 1,
  });
  socket.on("message", (packet, peer) => {
    if (!global.allow("all") || !perSource.allow(peer.address)) return;
    const response = bindingResponse(packet, peer.address, peer.port);
    if (response) socket.send(response, peer.port, peer.address, () => {});
  });
  const sweep = setInterval(() => {
    perSource.sweep();
    global.sweep();
  }, 1000);
  sweep.unref();
  try {
    await new Promise((resolve, reject) => {
      socket.once("error", reject);
      socket.bind(port, host, () => {
        socket.removeListener("error", reject);
        resolve();
      });
    });
  } catch (error) {
    clearInterval(sweep);
    try {
      socket.close();
    } catch {}
    throw error;
  }
  return {
    socket,
    close: () =>
      new Promise((resolve) => {
        clearInterval(sweep);
        perSource.clear();
        global.clear();
        socket.close(resolve);
      }),
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  await startStunService({
    enabled: process.env.ENABLE_STUN_SERVICE === "true",
    host: process.env.LISTEN_HOST ?? "127.0.0.1",
    port: Number(process.env.STUN_PORT ?? 3478),
    allowPublic: process.env.ALLOW_PUBLIC_LISTEN === "true",
  });
  console.info(
    "Restricted STUN Binding service started. Packet and address logging is disabled.",
  );
}
