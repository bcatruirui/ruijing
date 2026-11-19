import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { resolve, extname, sep } from "node:path";
import { handleRequest } from "../worker/index.ts";
const root = resolve(import.meta.dirname, ".."),
  production = process.argv.includes("--production");
const mime: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".json": "application/json",
  ".bin": "application/octet-stream",
  ".txt": "text/plain",
};
const assets = {
  async fetch(r: Request | string) {
    const url = new URL(typeof r === "string" ? r : r.url);
    let path: string;
    if (url.pathname === "/_intel/manifest.json")
      path = resolve(root, "data/generated/manifest.json");
    else if (url.pathname.startsWith("/_intel/"))
      path = resolve(root, "data/generated", "." + url.pathname);
    else
      path = resolve(
        root,
        "dist",
        "." + (url.pathname === "/" ? "/index.html" : url.pathname),
      );
    if (!path.startsWith(root + sep))
      return new Response(null, { status: 404 });
    try {
      return new Response(await readFile(path), {
        headers: {
          "Content-Type": mime[extname(path)] || "application/octet-stream",
        },
      });
    } catch {
      return new Response(null, { status: 404 });
    }
  },
};
const server = createServer(async (req, res) => {
  try {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(chunk);
      if (chunks.reduce((n, b) => n + b.length, 0) > 2048) {
        res.writeHead(413);
        res.end();
        return;
      }
    }
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers))
      if (v) headers.set(k, Array.isArray(v) ? v.join(",") : v);
    const host =
      req.headers.host || (production ? "127.0.0.1:5173" : "127.0.0.1:8788");
    if (!/^(127\.0\.0\.1|localhost):(5173|8788)$/.test(host)) {
      res.writeHead(400);
      res.end();
      return;
    }
    const request = new Request("http://" + host + (req.url || "/"), {
      method: req.method,
      headers,
      body: chunks.length ? Buffer.concat(chunks) : undefined,
    });
    const response = await handleRequest(request, {
      ASSETS: assets,
      DEVELOPMENT: "true",
    });
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch {
    res.writeHead(500, { "Cache-Control": "no-store" });
    res.end("Local server error");
  }
});
server.listen(production ? 5173 : 8788, "127.0.0.1", () => {
  if (production) console.log("Local: http://127.0.0.1:5173");
});
if (!production) {
  const { createServer: vite } = await import("vite");
  const dev = await vite();
  await dev.listen();
  dev.printUrls();
}
process.on("SIGTERM", () => server.close());
