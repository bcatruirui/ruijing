import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { download, readSmallJson } from "./data-utils.mjs";
import {
  parseMonosansProxySnapshot,
  parseMonosansAtom,
} from "./proxy-parser.mjs";

// Reviewed 2026-10-29: README explicitly licenses the proxy observations under
// MIT. ASN/geolocation are separately licensed MaxMind data and are discarded.
const LICENSE_SHA256 =
  "f0214b6cf7a99766c90f7007fbddcc8df43df7ab6299c40c84c3ae10458d58ca";
const MAX_JSON_BYTES = 16 * 1024 * 1024;

export async function registerProxySources({ run, base, meta, reuse, attributions }) {
  await run(
    base(
      "monosans-proxies",
      "Monosans verified public proxy observations",
      "https://github.com/monosans/proxy-list",
      "MIT",
      ["proxy", "public_proxy"],
      ["monosans-verified-proxies"],
      6,
      {
        licenseUrl: "https://github.com/monosans/proxy-list/blob/main/LICENSE",
        licenseAttribution:
          "Copyright (c) 2022 monosans; MIT. Only proxy IP/protocol observations are used; MaxMind ASN/geolocation fields are excluded. See docs/third-party/MONOSANS_PROXY_LICENSE.txt.",
      },
    ),
    async (writer, source) => {
      // A single public metadata request pins the files and their true publication
      // time together. No IP under analysis is ever included in these URLs.
      const revisionReceipt = await download(
        "monosans-proxy-revision.atom",
        "https://github.com/monosans/proxy-list/commits/main/proxies.json.atom",
        { reuse, maxBytes: 256 * 1024 },
      );
      const { revision, publishedAt } = parseMonosansAtom(
        await readFile(revisionReceipt.path, "utf8"),
      );
      const prefix = `https://raw.githubusercontent.com/monosans/proxy-list/${revision}/`;
      const license = await download(
        "monosans-proxy-LICENSE.txt",
        prefix + "LICENSE",
        { reuse, maxBytes: 64 * 1024 },
      );
      if (license.sha256 !== LICENSE_SHA256)
        throw new Error("Monosans proxy license changed; review required");
      const readme = await download(
        "monosans-proxy-README.md",
        prefix + "README.md",
        { reuse, maxBytes: 128 * 1024 },
      );
      const readmeText = await readFile(readme.path, "utf8");
      if (!/proxy lists are available under the \[MIT License\]\(LICENSE\)/.test(readmeText))
        throw new Error("Monosans proxy data licensing statement changed");
      await writeFile(
        path.join(attributions, "MONOSANS_PROXY_LICENSE.txt"),
        await readFile(license.path),
      );
      await writeFile(
        path.join(attributions, "MONOSANS_PROXY_README.md"),
        readmeText,
      );
      const resource = await download(
        "monosans-proxies.json",
        prefix + "proxies.json",
        { reuse, maxBytes: MAX_JSON_BYTES },
      );
      meta(source, resource, publishedAt);
      const { records } = parseMonosansProxySnapshot(
        await readSmallJson(resource.path, MAX_JSON_BYTES),
      );
      for (const record of records) await writer.add(record);
    },
  );
}
