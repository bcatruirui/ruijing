import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { cp, mkdir, readFile, writeFile } from "node:fs/promises";

function httpsOrigin(value: string) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.origin !== value || url.hostname.includes("*"))
    throw new Error("Configure a canonical HTTPS API origin without a path");
  return url.origin;
}

export default defineConfig(({ mode }) => {
  const pages = mode === "pages";
  const env = loadEnv(mode, process.cwd(), "");
  const base = pages ? env.PAGES_BASE || "/" : "/";
  if (!/^\/(?:[a-zA-Z0-9_.-]+\/)?$/.test(base) || base.split("/").some(part => part === "." || part === ".."))
    throw new Error("PAGES_BASE must be / or /repository/");
  const api = pages ? httpsOrigin(env.VITE_API_BASE || "") : "";
  const routing = pages ? (env.VITE_ROUTING_ORIGINS || "").split(/\s+/).filter(Boolean).map(httpsOrigin) : [];
  const probe = pages && env.VITE_DNS_PROBE_ZONE;
  if (probe && !/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i.test(probe)) throw new Error("Invalid probe DNS zone");
  return {
  base,
  publicDir: pages ? false : "public",
  plugins: [
    react(),
    tailwindcss(),
    {
      name: "ruijing-release-assets",
      transformIndexHtml() {
        if (!pages) return;
        const connect = ["'self'", api, ...routing, ...(probe ? [`https://*.${probe}`] : [])].join(" ");
        return [{ tag: "meta", injectTo: "head-prepend", attrs: {
          "http-equiv": "Content-Security-Policy",
          content: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src ${connect}; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'`,
        } }];
      },
      async closeBundle() {
        if (pages) {
          await cp("public/assets", "dist-pages/assets", { recursive: true });
          await cp("public/robots.txt", "dist-pages/robots.txt");
          const page = await readFile("dist-pages/index.html", "utf8");
          for (const route of ["privacy", "methodology", "data-sources"]) {
            const directory = `dist-pages/${route}`;
            await mkdir(directory, { recursive: true });
            await writeFile(`${directory}/index.html`, page);
          }
          return;
        }
        await mkdir("dist/_intel", { recursive: true });
        try {
          await cp("data/generated/_intel", "dist/_intel", { recursive: true });
          await cp("data/generated/manifest.json", "dist/_intel/manifest.json");
        } catch {
          const manifest = {
            schemaVersion: 1,
            version: "unconfigured",
            builtAt: new Date().toISOString(),
            profile: "none",
            sources: [],
          };
          await import("node:fs/promises").then((fs) =>
            fs.writeFile("dist/_intel/manifest.json", JSON.stringify(manifest)),
          );
        }
      },
    },
  ],
  server: {
    host: "127.0.0.1",
    port: 5173,
    watch: {
      ignored: [
        "**/data/**",
        "**/.cache/**",
        "**/docs/**",
        "**/reports/**",
        "**/tests/**",
      ],
    },
    proxy: { "/api": { target: "http://127.0.0.1:8788" } },
  },
  build: { outDir: pages ? "dist-pages" : "dist", target: "es2022", sourcemap: false, chunkSizeWarningLimit: 400 },
  };
});
