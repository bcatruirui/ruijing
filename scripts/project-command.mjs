import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { spawn } from "node:child_process";
import "./prepare-runtime.mjs";
const root = resolve(import.meta.dirname, "..");
const env = {
  ...process.env,
  TEMP: resolve(root, ".cache/tmp"),
  TMP: resolve(root, ".cache/tmp"),
  XDG_CONFIG_HOME: resolve(root, ".cache/config"),
  WRANGLER_SEND_METRICS: "false",
  WRANGLER_LOG_PATH: resolve(root, ".cache/wrangler/logs"),
  PLAYWRIGHT_BROWSERS_PATH: resolve(root, ".cache/browsers"),
};
await mkdir(env.TEMP, { recursive: true });
const [task, ...args] = process.argv.slice(2);
const paths = {
  test: "node_modules/vitest/vitest.mjs",
  e2e: "node_modules/@playwright/test/cli.js",
  worker: "node_modules/wrangler/bin/wrangler.js",
  vite: "node_modules/vite/bin/vite.js",
  tsc: "node_modules/typescript/bin/tsc",
};
async function run(file, args = []) {
  const child = spawn(process.execPath, [file, ...args], {
    cwd: root,
    env,
    stdio: "inherit",
  });
  return await new Promise((resolve) => {
    child.once("error", () => resolve(1));
    child.once("exit", (code) => resolve(code ?? 1));
  });
}
if (task === "build-pages") {
  process.exit(await run(paths.vite, ["build", "--mode", "pages"]));
} else if (task === "build") {
  for (const [file, args] of [
    [paths.tsc, ["-p", "tsconfig.json", "--noEmit"]],
    [paths.vite, ["build"]],
    ["scripts/check-budget.mjs", []],
  ]) {
    const result = await run(file, args);
    if (result) process.exit(result);
  }
} else if (paths[task]) process.exit(await run(paths[task], args));
else throw new Error("Unknown project command");
