import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";

const directory = path.resolve(import.meta.dirname, "../dist-pages");
const files = await readdir(directory, { recursive: true, withFileTypes: true });
let total = 0;
for (const file of files) {
  if (file.isSymbolicLink() || /^(?:_intel|_headers|\.env.*|node_modules|\.git.*|ruijing-logo-(?:black|white)-large\.png)$/.test(file.name) || /\.(?:bin|map|pem|key)$/.test(file.name))
    throw new Error(`Private or unsupported file in Pages build: ${file.name}`);
  if (file.isFile()) total += (await stat(path.join(file.parentPath, file.name))).size;
}
const base = process.env.PAGES_BASE || "/";
const api = process.env.VITE_API_BASE;
for (const route of ["", "privacy", "methodology", "data-sources"]) {
  const html = await readFile(path.join(directory, route, "index.html"), "utf8");
  if (!html.includes(`src="${base}assets/`) || !html.includes(api || "http://invalid") || !html.includes("Content-Security-Policy"))
    throw new Error(`Pages route /${route} is missing its asset base or API policy`);
}
if (total > 7 * 1024 * 1024) throw new Error("Pages build exceeds the 7 MiB frontend budget");
console.log(`Pages build verified: ${files.filter(file => file.isFile()).length} files, ${total} bytes.`);
