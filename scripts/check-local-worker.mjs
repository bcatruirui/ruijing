import { readFile, mkdir, writeFile } from "node:fs/promises";
import { PURITY_MODEL_VERSION } from "../shared/scoring.ts";

// Deliberately chosen public test addresses; never records a visitor's connection.
const base = "http://127.0.0.1:8787";
const manifest = JSON.parse(
  await readFile("data/generated/manifest.json", "utf8"),
);
const torStart = manifest.sources
  .find((s) => s.id === "tor")
  ?.shards.find((s) => s.family === 4)?.start;
const torIp = torStart
  ?.match(/../g)
  .map((byte) => parseInt(byte, 16))
  .join(".");
const results = [];
for (const path of [
  "/_intel/manifest.json",
  "/_intel/dbip-city/00000.bin",
  "/%5fintel/manifest.json",
  "/assets/%2e%2e/_intel/manifest.json",
  "/assets/%252e%252e%252f_intel/manifest.json",
  "/assets/..%2f_intel/manifest.json",
  "//_intel//manifest.json",
]) {
  const r = await fetch(base + path);
  results.push({
    kind: "asset-isolation",
    path,
    status: r.status,
    passed: r.status === 404,
  });
  await r.arrayBuffer();
}
for (const ip of [
  "8.8.8.8",
  "2001:4860:4860::8888",
  "2607:ff10:c8:594::a",
  ...(torIp ? [torIp] : []),
]) {
  const r = await fetch(base + "/api/lookup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip }),
  });
  const body = await r.json();
  results.push({
    kind: "real-offline-lookup",
    ip,
    status: r.status,
    noStore: r.headers.get("Cache-Control"),
    datasetVersion: body.assessment?.datasetVersion,
    info: body.info,
    score: body.assessment?.riskScore,
    purity: body.purity,
    confidence: body.assessment?.confidence,
    evidence: body.assessment?.evidence,
    passed:
      r.status === 200 &&
      r.headers.get("Cache-Control") === "no-store" &&
      body.assessment?.datasetVersion === manifest.version &&
      body.purity?.modelVersion === PURITY_MODEL_VERSION &&
      body.info?.ip === ip,
  });
}
for (const [name, headers, body, status] of [
  [
    "reject-private-ip",
    { "Content-Type": "application/json" },
    { ip: "127.0.0.1" },
    400,
  ],
  [
    "reject-cross-origin",
    { "Content-Type": "application/json", Origin: "https://attacker.example" },
    { ip: "8.8.8.8" },
    403,
  ],
]) {
  const r = await fetch(base + "/api/lookup", {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  results.push({
    kind: name,
    status: r.status,
    passed:
      r.status === status && r.headers.get("Cache-Control") === "no-store",
  });
  await r.arrayBuffer();
}
await mkdir("reports/runtime", { recursive: true });
await writeFile(
  "reports/runtime/worker-final.json",
  JSON.stringify(
    {
      checkedAt: new Date().toISOString(),
      runtime: "local-workerd-not-public-deployment",
      datasetVersion: manifest.version,
      results,
    },
    null,
    2,
  ),
);
console.log(
  JSON.stringify(
    results.map(({ evidence, info, ...r }) => ({
      ...r,
      evidenceCount: evidence?.length,
    })),
    null,
    2,
  ),
);
if (results.some((r) => !r.passed)) process.exitCode = 1;
