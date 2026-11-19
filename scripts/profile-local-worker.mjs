// Local V8 sampling evidence only. This does not certify production CPU quotas.
import { mkdir, writeFile } from "node:fs/promises";
import WebSocket from "ws";
const inspector = process.env.WORKER_INSPECTOR || "http://127.0.0.1:9231/json";
const targets = await (await fetch(inspector)).json();
const ws = new WebSocket(targets[0].webSocketDebuggerUrl, {
  origin: "http://localhost",
});
await new Promise((resolve, reject) => {
  ws.addEventListener("open", resolve, { once: true });
  ws.addEventListener("error", reject, { once: true });
});
let id = 0;
const pending = new Map();
ws.addEventListener("message", (event) => {
  const message = JSON.parse(String(event.data));
  const handler = pending.get(message.id);
  if (handler) {
    pending.delete(message.id);
    message.error
      ? handler.reject(new Error(message.error.message))
      : handler.resolve(message.result);
  }
});
function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    const current = ++id;
    pending.set(current, { resolve, reject });
    ws.send(JSON.stringify({ id: current, method, params }));
  });
}
const results = [];
try {
  await send("Profiler.enable");
  await send("Profiler.setSamplingInterval", { interval: 100 });
  for (const [label, ip] of [
    ["first-ipv4", "8.8.8.8"],
    ["warm-ipv4", "8.8.8.8"],
    ["first-ipv6", "2607:ff10:c8:594::a"],
    ["warm-ipv6", "2607:ff10:c8:594::a"],
  ]) {
    await send("Profiler.start");
    const started = performance.now();
    const response = await fetch("http://127.0.0.1:8787/api/lookup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    });
    const body = await response.json();
    const elapsedMs = performance.now() - started;
    const { profile } = await send("Profiler.stop");
    const nodes = new Map(profile.nodes.map((n) => [n.id, n]));
    let activeUs = 0;
    const byFunction = new Map();
    for (let i = 0; i < (profile.samples || []).length; i++) {
      const node = nodes.get(profile.samples[i]),
        name = node?.callFrame.functionName || "(anonymous)",
        delta = profile.timeDeltas?.[i] || 0;
      if (!["(idle)", "(root)", "(program)"].includes(name)) {
        activeUs += delta;
        byFunction.set(name, (byFunction.get(name) || 0) + delta);
      }
    }
    results.push({
      label,
      ip,
      status: response.status,
      score: body.assessment?.riskScore,
      wallMs: Math.round(elapsedMs * 100) / 100,
      sampledActiveJsMs: Math.round(activeUs / 10) / 100,
      samplingIntervalUs: 100,
      topFunctions: [...byFunction]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([name, us]) => ({ name, ms: Math.round(us / 10) / 100 })),
    });
  }
} finally {
  ws.terminate();
}
await mkdir("reports/runtime", { recursive: true });
await writeFile(
  "reports/runtime/local-v8-profile.json",
  JSON.stringify(
    {
      checkedAt: new Date().toISOString(),
      runtime: "local-workerd-v8-sampling",
      limits:
        "Sampling includes profiler overhead, is not a direct production CPU-time measurement, and cannot certify the 10ms Free quota. First means first lookup of this sample in this profiling run, not a guaranteed fresh production isolate.",
      results,
    },
    null,
    2,
  ),
);
console.log(JSON.stringify(results, null, 2));
