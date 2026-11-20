import { readFile, writeFile, mkdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { CACHE, GENERATED, ROOT } from "./data-utils.mjs";
import { cloudRangeIds } from "./cloud-ranges.mjs";

const cadence = {
  ...Object.fromEntries(cloudRangeIds.map(id => [id, 24])),
  tor: 2, "monosans-proxies": 2, carpathian: 2,
  "iptoasn-v4": 24, "iptoasn-v6": 24, openasn: 24,
  "dbip-city": 24, "dbip-asn": 24, "ipverse-network": 24, ffraud: 24, feodo: 24, dshield: 24,
};
const stateFile = path.join(CACHE, "refresh-state.json");
const optionalJson = file => readFile(file, "utf8").then(JSON.parse).catch(error => {
  if (error.code !== "ENOENT") throw error;
  return null;
});
const previous = await optionalJson(path.join(GENERATED, "manifest.json"));
const state = await optionalJson(stateFile) || {};
const now = Date.now();
const force = process.argv.includes("--force");
const full = force || previous?.profile !== "standard";
const due = Object.entries(cadence).filter(([id, hours]) => {
  const last = state[id];
  return full || typeof last !== "number" || last > now || now - last >= hours * 3600000;
}).map(([id]) => id);
if (!due.length) {
  console.log("All public sources are within their scheduled check interval.");
  process.exit(0);
}
const args = [path.join(ROOT, "scripts/build-data.mjs"), "--profile=standard"];
if (!full) args.push(`--only=${due.join(",")}`);
const result = spawnSync(process.execPath, [...process.execArgv, ...args], { cwd: ROOT, stdio: "inherit" });
if (result.status !== 0) process.exit(result.status ?? 1);
for (const id of due) state[id] = now;
await mkdir(CACHE, { recursive: true });
await writeFile(stateFile, JSON.stringify(state) + "\n");
