import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { spawn } from "node:child_process";
import "./prepare-runtime.mjs";
const root = resolve(import.meta.dirname, "..");
await mkdir(resolve(root, ".cache/tmp"), { recursive: true });
const env = {
  ...process.env,
  TEMP: resolve(root, ".cache/tmp"),
  TMP: resolve(root, ".cache/tmp"),
  WRANGLER_SEND_METRICS: "false",
  WRANGLER_LOG_PATH: resolve(root, ".cache/wrangler/logs"),
  XDG_CONFIG_HOME: resolve(root, ".cache/config"),
  PLAYWRIGHT_BROWSERS_PATH: resolve(root, ".cache/browsers"),
};
const child = spawn(
  process.execPath,
  ["--import", "tsx", "scripts/dev-server.ts", ...process.argv.slice(2)],
  { cwd: root, env, stdio: "inherit" },
);
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => child.kill(signal));
child.on("exit", (code) => process.exit(code || 0));
