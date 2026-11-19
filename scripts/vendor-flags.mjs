import { readdir, readFile, writeFile, copyFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { resolve } from "node:path";

// Run after: npm pack flag-icons@7.3.2 --pack-destination .cache --ignore-scripts
// and extract package/flags/4x3 and package/LICENSE into .cache/flag-icons-7.3.2.
const root = resolve(import.meta.dirname, "..");
const archive = await readFile(resolve(root, ".cache/flag-icons-7.3.2.tgz"));
if (createHash("sha512").update(archive).digest("base64") !== "QkaZ6Zvai8LIjx+UNAHUJ5Dhz9OLZpBDwCRWxF6YErxIcR16jTkIFm3bFu54EkvKQy4+wicW+Gm7/0631wVQyQ==") throw new Error("Flag package integrity mismatch");
const base = resolve(root, ".cache/flag-icons-7.3.2/package");
const codes = [];
for (const name of await readdir(resolve(base, "flags/4x3"))) {
  if (!/^[a-z]{2}\.svg$/.test(name) || name === "xx.svg") continue;
  const svg = await readFile(resolve(base, "flags/4x3", name), "utf8");
  if (/<(?:script|foreignObject|image|iframe)\b|\bon\w+\s*=|(?:href|url)\s*[=(]\s*["']?(?:https?:|\/\/|data:)/i.test(svg)) throw new Error("Unexpected active SVG content");
  await writeFile(resolve(root, "public/assets/flag-" + name), svg);
  codes.push(name.slice(0, 2).toUpperCase());
}
await copyFile(resolve(base, "LICENSE"), resolve(root, "docs/third-party/FLAG_ICONS_LICENSE.txt"));
await writeFile(resolve(root, "src/lib/flag-codes.ts"), `// flag-icons 7.3.2, MIT; local static assets, no CDN requests.\nexport const flagCodes = new Set(${JSON.stringify(codes.sort())});\n`);
console.log(`Vendored ${codes.length} local flags, verified MIT package.`);
