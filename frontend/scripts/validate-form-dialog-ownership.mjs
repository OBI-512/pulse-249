import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const src = path.join(root, "src");
const required = [
  "src/design-system/composites/Dialog/Dialog.tsx",
  "src/design-system/composites/Dialog/Dialog.test.tsx",
  "src/design-system/composites/Dialog/index.ts",
  "architecture/FR6D1_DIALOG_OWNERSHIP_STANDARD.md",
];
for (const rel of required) {
  if (!fs.existsSync(path.join(root, rel))) throw new Error(`FR6-D1 missing required file: ${rel}`);
}

const expectedConsumers = [
  "src/components/common/DialogSystem.tsx",
  "src/components/common/FeedbackSystem.tsx",
];
for (const rel of expectedConsumers) {
  const text = fs.readFileSync(path.join(root, rel), "utf8");
  if (!text.includes("design-system/composites/Dialog")) {
    throw new Error(`FR6-D1 canonical Dialog import missing: ${rel}`);
  }
}

const rawDialogClass = /className\s*=\s*(?:"[^"]*dialog-(?:backdrop|card|header|message|body|actions|close)[^"]*"|\{`[^`]*dialog-(?:backdrop|card|header|message|body|actions|close)[^`]*`\})/;
const offenders = [];
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (/\.tsx$/.test(entry.name)) {
      const rel = path.relative(root, full).replaceAll(path.sep, "/");
      if (rel.startsWith("src/design-system/composites/Dialog/")) continue;
      const text = fs.readFileSync(full, "utf8");
      if (rawDialogClass.test(text)) offenders.push(rel);
    }
  }
}
walk(src);
if (offenders.length) {
  throw new Error(`FR6-D1 raw dialog structural class ownership remains outside canonical Dialog:\n${offenders.join("\n")}`);
}

console.log("[PASS] FR6-D1 canonical dialog ownership guard.");
