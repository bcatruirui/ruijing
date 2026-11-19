import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, readFile, writeFile, rename, stat, unlink } from "node:fs/promises";
import { createHash } from "node:crypto";
import { pipeline } from "node:stream/promises";
import { Readable, Transform } from "node:stream";
import { createGunzip } from "node:zlib";
import { createInterface } from "node:readline";
import { isIP } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
export const CACHE = path.join(ROOT, "data", "cache");
export const GENERATED = path.join(ROOT, "data", "generated");
export const sha256 = (value) =>
  createHash("sha256").update(value).digest("hex");
export const now = () => new Date().toISOString();
export const isoDate = (value) => {
  const n = Date.parse(value);
  return Number.isFinite(n) ? new Date(n).toISOString() : undefined;
};

export async function githubFileRevision(id, repository, branch, filename, reuse) {
  const route = `/${repository}/commits/${branch}/${filename}`;
  const receipt = await download(id, `https://github.com${route}.atom`, { reuse, maxBytes: 256 * 1024 });
  const feed = await readFile(receipt.path, "utf8");
  const entry = feed.match(/<entry>([\s\S]*?)<\/entry>/)?.[1];
  const sha = entry?.match(/Grit::Commit\/([a-f0-9]{40})<\/id>/)?.[1];
  const publishedAt = isoDate(entry?.match(/<updated>([^<]+)<\/updated>/)?.[1]);
  if (!feed.includes(route) || !sha || !publishedAt || Date.parse(publishedAt) > Date.now() + 300_000)
    throw new Error("Invalid GitHub file release feed");
  return { raw: `https://raw.githubusercontent.com/${repository}/${sha}/`, publishedAt };
}

/** Download only public, allow-listed datasets. No visitor request or IP is passed here. */
export async function download(
  id,
  url,
  { maxBytes = 64 * 1024 * 1024, reuse = false } = {},
) {
  if (!/^https:\/\//.test(url))
    throw new Error("Dataset downloads require HTTPS");
  await mkdir(CACHE, { recursive: true });
  const target = path.join(CACHE, id.replace(/[^a-zA-Z0-9._-]/g, "_"));
  const metaPath = target + ".metadata.json";
  let previous;
  try {
    const cached = JSON.parse(await readFile(metaPath, "utf8"));
    if (cached.url === url && cached.byteLength <= maxBytes && (await stat(target)).size === cached.byteLength)
      previous = cached;
  } catch { /* A cache miss is fetched again. */ }
  const validated = async () => {
    if (!previous) return false;
    try {
      const digest = createHash("sha256");
      for await (const bytes of createReadStream(target)) digest.update(bytes);
      return digest.digest("hex") === previous.sha256;
    } catch { return false; }
  };
  if (reuse && await validated()) return { path: target, ...previous, cache: true };
  const validators = previous?.etag ? { "If-None-Match": previous.etag }
    : previous?.publishedAt ? { "If-Modified-Since": new Date(previous.publishedAt).toUTCString() } : {};
  const request = (headers) => fetch(url, {
    redirect: "follow",
    signal: AbortSignal.timeout(300_000),
    headers: {
      "User-Agent":
        "Ruijing-IP-DataBuilder/1.0 (public-dataset-download; no visitor data)",
      ...headers,
    },
  });
  let response = await request(validators);
  if (response.status === 304) {
    if (await validated()) return { path: target, ...previous, cache: true };
    response = await request({});
  }
  if (!response.ok || !response.body)
    throw new Error(`Download HTTP ${response.status}`);
  const announced = Number(response.headers.get("content-length"));
  if (announced > maxBytes) {
    await response.body.cancel();
    throw new Error("Download exceeds size budget");
  }
  const digest = createHash("sha256");
  let byteLength = 0;
  const guard = new Transform({
    transform(chunk, _encoding, done) {
      byteLength += chunk.length;
      if (byteLength > maxBytes)
        return done(new Error("Download exceeds size budget"));
      digest.update(chunk);
      done(null, chunk);
    },
  });
  const temporary = target + `.${process.pid}.partial`;
  try {
    await pipeline(Readable.fromWeb(response.body), guard, createWriteStream(temporary));
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
  const hash = digest.digest("hex");
  const meta = {
    url,
    finalUrl: response.url,
    fetchedAt: previous?.sha256 === hash ? previous.fetchedAt : now(),
    publishedAt: isoDate(response.headers.get("last-modified")),
    etag: response.headers.get("etag") ?? undefined,
    byteLength,
    sha256: hash,
  };
  await rename(temporary, target);
  await writeFile(metaPath, JSON.stringify(meta, null, 2) + "\n");
  return { path: target, ...meta, cache: false };
}

export async function* lines(filename, gzip = filename.endsWith(".gz")) {
  const file = createReadStream(filename);
  const input = gzip ? file.pipe(createGunzip()) : file;
  const reader = createInterface({ input, crlfDelay: Infinity });
  let failure;
  const onError = (error) => {
    failure = error;
    reader.close();
    input.destroy();
  };
  file.on("error", onError);
  if (input !== file) input.on("error", onError);
  try {
    for await (const line of reader) {
      if (line.length > 1024 * 1024)
        throw new Error("Input line exceeds 1 MiB");
      yield line;
    }
    if (failure) throw failure;
  } finally {
    reader.close();
    input.destroy();
    file.destroy();
  }
}

export function csv(line) {
  const result = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') {
      if (quoted && line[i + 1] === '"') {
        field += '"';
        i++;
      } else quoted = !quoted;
    } else if (c === "," && !quoted) {
      result.push(field);
      field = "";
    } else field += c;
  }
  if (quoted)
    throw new Error("Multiline or unterminated CSV field is unsupported");
  result.push(field);
  result[0] = result[0].replace(/^\uFEFF/, "");
  return result;
}

export function address(ip) {
  const family = isIP(ip);
  if (!family || ip.includes("%"))
    throw new Error("Invalid dataset IP address");
  if (family === 4)
    return {
      family: 4,
      hex: ip
        .split(".")
        .map((n) => Number(n).toString(16).padStart(2, "0"))
        .join(""),
    };
  let text = ip.toLowerCase();
  if (text.includes(".")) {
    const end = text.lastIndexOf(":");
    const v4 = address(text.slice(end + 1)).hex;
    text = text.slice(0, end + 1) + v4.slice(0, 4) + ":" + v4.slice(4);
  }
  const sides = text.split("::");
  const left = sides[0] ? sides[0].split(":") : [];
  const right = sides[1] ? sides[1].split(":") : [];
  const groups =
    sides.length === 2
      ? [...left, ...Array(8 - left.length - right.length).fill("0"), ...right]
      : left;
  return { family: 6, hex: groups.map((n) => n.padStart(4, "0")).join("") };
}

export function interval(start, end, payload) {
  const a = address(start),
    b = address(end);
  if (a.family !== b.family || a.hex > b.hex)
    throw new Error("Invalid dataset interval");
  return { family: a.family, start: a.hex, end: b.hex, payload };
}

export function ipRecord(ip, payload) {
  return interval(ip, ip, payload);
}

/** Reviewed DB-IP City Lite CSV schema; continent and country are separate columns. */
export function parseDbipCityLine(line) {
  const fields = csv(line);
  if (fields.length !== 8)
    throw new Error("DB-IP City Lite requires the reviewed 8-column schema");
  const [
    start,
    end,
    continent,
    countryCode,
    region,
    city,
    latitude,
    longitude,
  ] = fields;
  if (
    !["AF", "AN", "AS", "EU", "NA", "OC", "SA", "ZZ"].includes(continent) ||
    !/^[A-Z]{2}$/.test(countryCode)
  )
    throw new Error("Invalid DB-IP continent/country columns");
  if (
    !/^[+-]?(?:\d+(?:\.\d+)?|\.\d+)$/.test(latitude) ||
    !/^[+-]?(?:\d+(?:\.\d+)?|\.\d+)$/.test(longitude) ||
    !Number.isFinite(Number(latitude)) ||
    !Number.isFinite(Number(longitude)) ||
    Math.abs(Number(latitude)) > 90 ||
    Math.abs(Number(longitude)) > 180
  )
    throw new Error("Invalid DB-IP coordinates or column positions");
  return interval(start, end, {
    kind: "geo",
    countryCode,
    ...(region ? { region } : {}),
    ...(city ? { city } : {}),
    latitude: Number(latitude),
    longitude: Number(longitude),
    confidence: "medium",
    upstreamFamily: "dbip-lite",
  });
}

export async function readSmallJson(file, maxBytes = 16 * 1024 * 1024) {
  if ((await stat(file)).size > maxBytes)
    throw new Error("JSON exceeds memory budget");
  return JSON.parse(await readFile(file, "utf8"));
}

/** Bounded offline external sort. Only one 15k-row run and one row per run are held. */
export async function* externalSort(records, directory, compare) {
  await mkdir(directory, { recursive: true });
  const runs = [];
  let batch = [];
  const spill = async () => {
    if (!batch.length) return;
    batch.sort(compare);
    const filename = path.join(directory, `run-${runs.length}.ndjson`);
    await writeFile(
      filename,
      batch.map((row) => JSON.stringify(row)).join("\n") + "\n",
    );
    runs.push(filename);
    batch = [];
    if (runs.length > 256)
      throw new Error("External sorter exceeds 3.84-million row import budget");
  };
  for await (const record of records) {
    batch.push(record);
    if (batch.length >= 15000) await spill();
  }
  await spill();
  const readers = runs.map((filename) =>
    lines(filename, false)[Symbol.asyncIterator](),
  );
  const heap = [];
  const push = (item) => {
    heap.push(item);
    let i = heap.length - 1;
    while (i > 0) {
      const parent = (i - 1) >> 1;
      if (compare(heap[parent].value, item.value) <= 0) break;
      heap[i] = heap[parent];
      i = parent;
    }
    heap[i] = item;
  };
  const pop = () => {
    const first = heap[0],
      last = heap.pop();
    if (heap.length) {
      let i = 0;
      while (i * 2 + 1 < heap.length) {
        let child = i * 2 + 1;
        if (
          child + 1 < heap.length &&
          compare(heap[child + 1].value, heap[child].value) < 0
        )
          child++;
        if (compare(last.value, heap[child].value) <= 0) break;
        heap[i] = heap[child];
        i = child;
      }
      heap[i] = last;
    }
    return first;
  };
  try {
    for (let i = 0; i < readers.length; i++) {
      const row = await readers[i].next();
      if (!row.done) push({ run: i, value: JSON.parse(row.value) });
    }
    while (heap.length) {
      const current = pop();
      yield current.value;
      const row = await readers[current.run].next();
      if (!row.done) push({ run: current.run, value: JSON.parse(row.value) });
    }
  } finally {
    await Promise.all(readers.map((reader) => reader.return?.()));
  }
}
