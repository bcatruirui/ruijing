import {
  mkdir,
  readFile,
  writeFile,
  rename,
  rm,
  stat,
  lstat,
  realpath,
} from "node:fs/promises";
import path from "node:path";
import { encodeShard } from "../shared/dataset.ts";
import { ROOT, GENERATED, sha256, now } from "./data-utils.mjs";

// Offline migration of this project's authenticated snapshot: no fetch,
// credentials, cloud resource or deployment API exists in this script.
const MAX_BYTES = 131072;
const dataRoot = path.resolve(ROOT, "data");
const input = path.resolve(GENERATED);
const stage = path.join(dataRoot, `.encoding-${process.pid}`);
const backup = path.join(dataRoot, `.encoding-previous-${process.pid}`);
function withinData(value) {
  const resolved = path.resolve(value);
  if (!resolved.startsWith(dataRoot + path.sep) || resolved === dataRoot)
    throw new Error("Refusing path outside project data");
  return resolved;
}
async function existingDirectory(value) {
  const resolved = withinData(value),
    info = await lstat(resolved);
  if (
    !info.isDirectory() ||
    info.isSymbolicLink() ||
    (await realpath(resolved)) !== resolved
  )
    throw new Error("Refusing symlink or invalid snapshot directory");
  return resolved;
}
await existingDirectory(input);
await mkdir(stage, { recursive: false });
const original = JSON.parse(
  await readFile(path.join(input, "manifest.json"), "utf8"),
);
if (
  original.schemaVersion !== 1 ||
  !Array.isArray(original.sources) ||
  original.sources.length > 100
)
  throw new Error("Unsupported input manifest");
const manifest = structuredClone(original);
const inputFormats = { 1: 0, 2: 0 };
let rewritten = 0,
  migrated = 0;

function payload(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !["asn", "geo", "network", "threat", "tor"].includes(value.kind)
  )
    throw new Error("Invalid existing payload");
  return value;
}
function decode(bytes, entry) {
  if (
    bytes.length < 18 ||
    bytes.toString("ascii", 0, 4) !== "RJI1" ||
    ![1, 2].includes(bytes[5]) ||
    ![4, 6].includes(bytes[4])
  )
    throw new Error("Invalid existing shard header");
  const version = bytes[5],
    family = bytes[4],
    width = family === 4 ? 4 : 16;
  const stride = bytes.readUInt16LE(6),
    count = bytes.readUInt32LE(8),
    offset = bytes.readUInt32LE(12);
  if (
    family !== entry.family ||
    stride !== width * 2 + 4 ||
    !count ||
    count !== entry.count ||
    offset !== 16 + count * stride ||
    offset >= bytes.length
  )
    throw new Error("Existing shard layout does not match manifest");
  let dictionary;
  if (version === 1) {
    dictionary = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(offset)),
    );
    if (
      !Array.isArray(dictionary) ||
      !dictionary.length ||
      dictionary.length > count
    )
      throw new Error("Invalid existing dictionary");
    dictionary.forEach(payload);
  } else {
    if (offset + 8 > bytes.length)
      throw new Error("Truncated indexed dictionary");
    const items = bytes.readUInt32LE(offset),
      blobStart = offset + 4 + (items + 1) * 4;
    if (
      !items ||
      items > count ||
      blobStart > bytes.length ||
      bytes.readUInt32LE(offset + 4) !== 0
    )
      throw new Error("Invalid existing dictionary index");
    dictionary = [];
    for (let i = 0; i < items; i++) {
      const start = bytes.readUInt32LE(offset + 4 + i * 4),
        end = bytes.readUInt32LE(offset + 8 + i * 4);
      if (end <= start || blobStart + end > bytes.length)
        throw new Error("Invalid existing payload offsets");
      dictionary.push(
        payload(
          JSON.parse(
            new TextDecoder("utf-8", { fatal: true }).decode(
              bytes.subarray(blobStart + start, blobStart + end),
            ),
          ),
        ),
      );
    }
    if (blobStart + bytes.readUInt32LE(offset + 4 + items * 4) !== bytes.length)
      throw new Error("Dictionary trailing data");
  }
  const rows = [];
  let previous;
  for (let i = 0; i < count; i++) {
    const at = 16 + i * stride,
      start = bytes.subarray(at, at + width).toString("hex"),
      end = bytes.subarray(at + width, at + width * 2).toString("hex");
    const id = bytes.readUInt32LE(at + width * 2);
    if (
      start > end ||
      (previous && previous > start) ||
      id >= dictionary.length
    )
      throw new Error("Invalid existing record");
    rows.push({ family, start, end, payload: dictionary[id] });
    previous = start;
  }
  const maximum = rows.reduce((m, r) => (r.end > m ? r.end : m), rows[0].end);
  if (rows[0].start !== entry.start || maximum !== entry.end)
    throw new Error("Existing record bounds do not match manifest");
  inputFormats[version]++;
  return rows;
}

for (const source of manifest.sources) {
  if (!/^[a-zA-Z0-9_-]+$/.test(source.id) || !Array.isArray(source.shards))
    throw new Error("Invalid source identity");
  const entries = source.shards;
  source.shards = [];
  let sourceRecords = 0,
    index = 0;
  async function emit(rows) {
    let bytes;
    try {
      bytes = encodeShard(rows);
    } catch (error) {
      if (rows.length === 1 || error.message !== "Intelligence shard too large")
        throw error;
      const mid = Math.floor(rows.length / 2);
      await emit(rows.slice(0, mid));
      await emit(rows.slice(mid));
      return;
    }
    if (bytes[5] !== 2)
      throw new Error(
        "Default encoder is not wire format 2; wait for the codec update",
      );
    if (bytes.length > MAX_BYTES) {
      if (rows.length === 1)
        throw new Error("One payload exceeds shard budget");
      const mid = Math.floor(rows.length / 2);
      await emit(rows.slice(0, mid));
      await emit(rows.slice(mid));
      return;
    }
    const id = String(index++).padStart(5, "0"),
      relative = `/_intel/${source.id}/${id}.bin`;
    const filename = withinData(path.join(stage, relative.slice(1)));
    await mkdir(path.dirname(filename), { recursive: true });
    await writeFile(filename, bytes);
    source.shards.push({
      id,
      path: relative,
      family: rows[0].family,
      start: rows[0].start,
      end: rows.reduce((m, r) => (r.end > m ? r.end : m), rows[0].end),
      count: rows.length,
      byteLength: bytes.length,
      sha256: sha256(bytes),
    });
    rewritten++;
  }
  for (const entry of entries) {
    if (
      !entry.path.startsWith(`/_intel/${source.id}/`) ||
      entry.path.includes("..") ||
      !/^\/_intel\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+\.bin$/.test(entry.path)
    )
      throw new Error("Invalid source asset path");
    const filename = withinData(path.resolve(input, "." + entry.path)),
      info = await lstat(filename);
    if (!info.isFile() || info.isSymbolicLink())
      throw new Error("Refusing non-regular source shard");
    const bytes = await readFile(filename);
    if (
      bytes.length > MAX_BYTES ||
      bytes.length !== entry.byteLength ||
      sha256(bytes) !== entry.sha256
    )
      throw new Error(
        `Existing checksum/size mismatch: ${source.id}/${entry.id}`,
      );
    const records = decode(bytes, entry);
    sourceRecords += records.length;
    await emit(records);
    migrated++;
  }
  if (sourceRecords !== source.count)
    throw new Error(`Source record count changed: ${source.id}`);
  source.shards.sort(
    (a, b) => a.family - b.family || a.start.localeCompare(b.start),
  );
  process.stdout.write(
    `[encoding] ${source.id}: ${entries.length} -> ${source.shards.length} shards, ${sourceRecords} records retained\n`,
  );
}

if (rewritten > 18000)
  throw new Error(
    "New encoding exceeds project asset budget; original snapshot retained",
  );
manifest.encodingVersion = 2;
manifest.version =
  "rj-" + sha256(JSON.stringify(manifest.sources)).slice(0, 16);
manifest.builtAt = now();
await writeFile(
  path.join(stage, "manifest.json"),
  JSON.stringify(manifest) + "\n",
);
const summary = {
  builtAt: manifest.builtAt,
  profile: manifest.profile,
  version: manifest.version,
  encodingVersion: 2,
  upgradedFrom: original.version,
  realData: true,
  sourceCount: manifest.sources.length,
  available: manifest.sources.filter((s) => s.state === "ready").length,
  records: manifest.sources.reduce((n, s) => n + s.count, 0),
  shards: rewritten,
  inputFormats,
  sources: manifest.sources.map(({ shards, ...s }) => s),
};
await writeFile(
  path.join(stage, "BUILD_SUMMARY.json"),
  JSON.stringify(summary, null, 2) + "\n",
);
await writeFile(
  path.join(stage, "ENCODING_UPGRADE.json"),
  JSON.stringify(
    {
      completedAt: manifest.builtAt,
      from: original.version,
      to: manifest.version,
      originalShardCount: migrated,
      outputShardCount: rewritten,
      inputFormats,
      downloaded: false,
      sourceMetadataChanged: false,
    },
    null,
    2,
  ) + "\n",
);
if (
  JSON.parse(await readFile(path.join(input, "manifest.json"), "utf8"))
    .version !== original.version
)
  throw new Error("Input snapshot changed during upgrade; original retained");
await existingDirectory(input);
await existingDirectory(stage);
withinData(backup);
try {
  await stat(backup);
  throw new Error("Backup already exists; original retained");
} catch (error) {
  if (error.code !== "ENOENT") throw error;
}
try {
  await rename(input, backup);
} catch (error) {
  throw new Error(
    `Local snapshot is locked; stop preview/watchers and retain ${stage} for recovery. ${error.code}`,
  );
}
try {
  await rename(stage, input);
} catch (error) {
  await rename(backup, input);
  throw error;
}
await existingDirectory(backup);
await rm(backup, { recursive: true });
process.stdout.write(
  `[encoding] promoted local snapshot ${manifest.version}; ${rewritten} format-2 shards. No downloads or cloud deployment.\n`,
);
