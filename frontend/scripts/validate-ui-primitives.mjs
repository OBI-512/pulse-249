import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const required = ["Button", "IconButton", "Input", "Select", "Checkbox", "Badge", "Tooltip", "Spinner", "Textarea"];
const errors = [];

for (const name of required) {
  const dir = path.join(root, "src", "design-system", "primitives", name);
  for (const file of [`${name}.tsx`, `${name}.module.css`, "index.ts"]) {
    if (!fs.existsSync(path.join(dir, file))) errors.push(`missing primitive file: ${name}/${file}`);
  }
}

const barrel = path.join(root, "src", "design-system", "primitives", "index.ts");
if (!fs.existsSync(barrel)) errors.push("missing primitive catalogue barrel");
else {
  const source = fs.readFileSync(barrel, "utf8");
  for (const name of required) if (!source.includes(`./${name}`)) errors.push(`primitive barrel does not export ${name}`);
}

const sortOwner = path.join(root, "src", "design-system", "data", "SortHeader", "SortHeader.tsx");
const sortSource = fs.readFileSync(sortOwner, "utf8");
if (!sortSource.includes('\\u25B2') || !sortSource.includes('\\u25BC')) errors.push("SortHeader must use ASCII-safe Unicode escapes for sort arrows");

const multiOwner = path.join(root, "src", "design-system", "composites", "MultiSelect", "MultiSelectDropdown.tsx");
const multiSource = fs.readFileSync(multiOwner, "utf8");
if (!multiSource.includes('\\u25BE') || !multiSource.includes('\\u00D7')) errors.push("MultiSelectDropdown must keep encoding-safe glyph escapes");

if (errors.length) {
  console.error("[FAIL] FR3 UI primitive architecture");
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}
console.log("[PASS] FR3 UI primitive architecture: 9 isolated canonical primitives.");
