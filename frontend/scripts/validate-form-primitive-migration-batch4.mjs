import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const targets = [
  "src/pages/AlarmPage.tsx",
  "src/pages/CustomerPage.tsx",
  "src/pages/DiscoveryResults.tsx",
];
const raw = /<(?:button|input|select|textarea)\b/g;
const primitiveImport = /from\s+["']\.\.\/design-system\/primitives["']/;

for (const rel of targets) {
  const full = path.join(root, rel);
  if (!fs.existsSync(full)) throw new Error(`FR6-D5 target missing: ${rel}`);
  const text = fs.readFileSync(full, "utf8");
  const hits = [...text.matchAll(raw)];
  if (hits.length) throw new Error(`${rel} still owns ${hits.length} raw form control(s)`);
  if (!primitiveImport.test(text)) throw new Error(`${rel} does not import canonical primitives directly`);
  if (!/(?:<Button|<Input|<Select|<Checkbox|<Textarea)\s+unstyled/.test(text)) {
    throw new Error(`${rel} does not use the compatibility-preserving unstyled primitive bridge`);
  }
}

console.log("[PASS] FR6-D5 page-level form primitive migration guard.");
