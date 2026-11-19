import { readdir, readFile, stat, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { ROOT, GENERATED as CURRENT, sha256, now } from "./data-utils.mjs";

const stage = process.argv.find(value => value.startsWith("--staging="))?.slice(10);
const GENERATED = stage ? path.resolve(ROOT, "data", stage) : CURRENT;
if (stage && !/^\.staging-\d+$/.test(stage)) throw new Error("Invalid staging directory");

const failures = [],
  notes = [];
const manifest = JSON.parse(
  await readFile(path.join(GENERATED, "manifest.json"), "utf8"),
);
if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.sources))
  throw new Error("Unsupported dataset manifest");
let totalBytes = 0,
  shards = 0,
  largestShard = 0;
const encodingVersions = { 1: 0, 2: 0 };
function inspectEncoding(bytes, entry) {
  if (
    bytes.length < 18 ||
    bytes.toString("ascii", 0, 4) !== "RJI1" ||
    ![1, 2].includes(bytes[5])
  )
    throw new Error("unsupported magic/version");
  const family = bytes[4],
    width = family === 4 ? 12 : family === 6 ? 36 : 0;
  const count = bytes.readUInt32LE(8),
    offset = bytes.readUInt32LE(12);
  if (
    !width ||
    family !== entry.family ||
    bytes.readUInt16LE(6) !== width ||
    !count ||
    count !== entry.count ||
    offset !== 16 + count * width ||
    offset >= bytes.length
  )
    throw new Error("invalid record layout");
  if (bytes[5] === 2) {
    if (offset + 8 > bytes.length)
      throw new Error("truncated indexed dictionary");
    const items = bytes.readUInt32LE(offset),
      blob = offset + 4 + (items + 1) * 4;
    if (
      !items ||
      items > count ||
      blob > bytes.length ||
      bytes.readUInt32LE(offset + 4) !== 0
    )
      throw new Error("invalid dictionary index");
    let previous = 0;
    for (let i = 1; i <= items; i++) {
      const value = bytes.readUInt32LE(offset + 4 + i * 4);
      if (value <= previous || blob + value > bytes.length)
        throw new Error("invalid payload boundaries");
      previous = value;
    }
    if (blob + previous !== bytes.length)
      throw new Error("trailing dictionary data");
  }
  encodingVersions[bytes[5]]++;
}
for (const source of manifest.sources) {
  const previous = new Map();
  if (!source.license || !source.url || !source.licenseUrl)
    failures.push(`${source.id}: missing license receipt`);
  if (
    source.state === "ready" &&
    (!source.fetchedAt || !source.expiresAt || !source.sha256)
  )
    failures.push(`${source.id}: incomplete provenance`);
  for (const entry of source.shards) {
    if (
      !entry.path.startsWith(`/_intel/${source.id}/`) ||
      entry.path.includes("..")
    ) {
      failures.push(`${source.id}: unsafe shard path`);
      continue;
    }
    const target = path.resolve(GENERATED, "." + entry.path);
    if (!target.startsWith(path.resolve(GENERATED) + path.sep))
      throw new Error("Shard outside generated directory");
    const bytes = await readFile(target);
    shards++;
    totalBytes += bytes.byteLength;
    largestShard = Math.max(largestShard, bytes.byteLength);
    if (bytes.byteLength > 128 * 1024 || bytes.byteLength !== entry.byteLength)
      failures.push(
        `${source.id}/${entry.id}: shard size mismatch or >128 KiB`,
      );
    if (sha256(bytes) !== entry.sha256)
      failures.push(`${source.id}/${entry.id}: SHA256 mismatch`);
    try {
      inspectEncoding(bytes, entry);
    } catch (error) {
      failures.push(`${source.id}/${entry.id}: ${error.message}`);
    }
    if (
      entry.start > entry.end ||
      (previous.get(entry.family) && previous.get(entry.family) > entry.start)
    )
      failures.push(`${source.id}: unsorted interval index`);
    previous.set(entry.family, entry.start);
  }
}
if (manifest.encodingVersion === 2 && encodingVersions[1])
  failures.push("Format-2 manifest contains legacy format-1 shards");
if (encodingVersions[1])
  notes.push(
    "Legacy format-1 dictionaries remain; offline upgrade-data-encoding.mjs provides indexed payload decoding.",
  );

async function walk(dir) {
  const files = [];
  for (const item of await readdir(dir, { withFileTypes: true })) {
    if (item.isSymbolicLink()) {
      failures.push("Static output contains a symbolic link");
      continue;
    }
    if (item.isDirectory())
      files.push(...(await walk(path.join(dir, item.name))));
    else if (item.isFile()) files.push(path.join(dir, item.name));
  }
  return files;
}
const dist = path.join(ROOT, "dist");
let assetFiles;
try {
  if (stage) throw Object.assign(new Error("Staging only"), { code: "ENOENT" });
  await stat(dist);
  assetFiles = await walk(dist);
  try {
    const deployed = JSON.parse(
      await readFile(path.join(dist, "_intel", "manifest.json"), "utf8"),
    );
    if (deployed.version !== manifest.version)
      failures.push(
        "dist data version differs from generated data; rebuild frontend assets before deployment",
      );
  } catch {
    failures.push(
      "dist/_intel/manifest.json is absent or invalid; build must copy the server-side dataset",
    );
  }
} catch {
  assetFiles = await walk(GENERATED);
  notes.push(
    stage ? "Staged dataset checks only; repeat after the Worker asset build." : "dist/ is absent: dataset budget checked; repeat after the Worker asset build.",
  );
}
for (const filename of assetFiles)
  if ((await stat(filename)).size > 25 * 1024 * 1024)
    failures.push(
      `${path.relative(ROOT, filename)} exceeds official 25 MiB asset limit`,
    );
if (assetFiles.length > 18000 || shards > 18000)
  failures.push(
    "Asset file count exceeds project 18,000 budget (official Free limit 20,000)",
  );

const runtimeIndex = manifest.sources.reduce(
  (n, s) =>
    n +
    Buffer.byteLength(
      JSON.stringify(
        s.shards.map(({ family, start, end, id }) => [family, start, end, id]),
      ),
    ),
  0,
);
if (runtimeIndex > 1024 * 1024)
  failures.push(
    "Compact runtime interval index exceeds project 1 MiB total budget; split/load indexes by source instead of bundling",
  );
notes.push(
  "Full provenance and compact runtime index sizes differ. The deployment build preloads a server-side snapshot; actual bundled size/startup must be checked with Wrangler.",
);
notes.push(
  "Official Worker bundle limit checked 2026-10-28: 64 MiB uncompressed, no compressed limit. Use wrangler deploy --dry-run for the actual bundle and startup validation.",
);
notes.push(
  "10 ms CPU and 128 MB per-isolate are production runtime limits; this static budget check does not certify CPU performance.",
);
const result = {
  checkedAt: now(),
  datasetVersion: manifest.version,
  profile: manifest.profile,
  realData: true,
  sourceStates: manifest.sources.map((s) => ({
    id: s.id,
    state: s.state,
    count: s.count,
  })),
  assetFiles: assetFiles.length,
  shardFiles: shards,
  shardBytes: totalBytes,
  largestShardBytes: largestShard,
  encodingVersions,
  compactRuntimeIndexBytes: runtimeIndex,
  manifestBytes: (await stat(path.join(GENERATED, "manifest.json"))).size,
  failures,
  notes,
};
if (!stage) {
  await mkdir(path.join(ROOT, "reports"), { recursive: true });
  await writeFile(path.join(ROOT, "reports", "budget.json"), JSON.stringify(result, null, 2) + "\n");
}
process.stdout.write(JSON.stringify(result, null, 2) + "\n");
if (failures.length) process.exitCode = 1;
