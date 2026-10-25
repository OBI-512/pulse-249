import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import crypto from "node:crypto";

const root = path.resolve(process.cwd());
const tokenDir = path.join(root, "src", "design-system", "tokens");
const required = ["theme-base.css", "theme-refinements.css", "layout.css"];
const errors = [];
const tokenFreezeFile = path.join(root, "architecture", "fr2-token-value-baseline.json");

function canonicalFreezeBytes(file) {
  // Git stores these text files with LF, while Windows checkouts may expose CRLF.
  // Freeze token values against canonical LF text so validation is checkout-platform independent.
  const text = fs.readFileSync(file, "utf8").replace(/\r\n?/g, "\n");
  return Buffer.from(text, "utf8");
}

if (!fs.existsSync(tokenFreezeFile)) {
  errors.push("missing FR2 token value baseline");
} else {
  const freeze = JSON.parse(fs.readFileSync(tokenFreezeFile, "utf8"));
  for (const [relative, expected] of Object.entries(freeze.files || {})) {
    const file = path.join(root, relative);
    if (!fs.existsSync(file)) {
      errors.push(`token freeze target missing: ${relative}`);
      continue;
    }
    const actual = crypto.createHash("sha256").update(canonicalFreezeBytes(file)).digest("hex");
    if (actual !== expected.sha256) errors.push(`token value freeze mismatch: ${relative}`);
  }
}

for (const name of required) {
  if (!fs.existsSync(path.join(tokenDir, name))) errors.push(`missing token file: ${name}`);
}

const stylesFile = path.join(root, "src", "styles.css");
const imports = fs.readFileSync(stylesFile, "utf8");
for (const name of required) {
  if (!imports.includes(`./design-system/tokens/${name}`)) errors.push(`styles.css does not import ${name}`);
}

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
}

// Global theme declarations must not drift back into legacy style files.
const legacyStyles = path.join(root, "src", "styles");
const cssFiles = walk(legacyStyles).filter((f) => f.endsWith(".css"));
for (const file of cssFiles) {
  const text = fs.readFileSync(file, "utf8");
  const globalBlocks = text.match(/(?::root|html\[data-theme=[^\]]+\])\s*\{[\s\S]*?\}/g) || [];
  for (const block of globalBlocks) {
    if (/--nms-[A-Za-z0-9_-]+\s*:/.test(block)) {
      errors.push(`legacy global --nms token declaration remains in ${path.relative(root, file).replaceAll("\\", "/")}`);
      break;
    }
  }
}

// Token files must remain CSS-only and UTF-8 readable; key themes must exist.
const base = fs.readFileSync(path.join(tokenDir, "theme-base.css"), "utf8");
for (const theme of ["operations", "light", "night"]) {
  if (!base.includes(`data-theme="${theme}"`)) errors.push(`base tokens missing ${theme} theme`);
}
for (const token of ["--nms-bg", "--nms-surface", "--nms-text", "--nms-accent", "--nms-border", "--nms-success", "--nms-danger"]) {
  if (!base.includes(token)) errors.push(`base tokens missing ${token}`);
}

if (errors.length) {
  console.error("[FR2 tokens] FAIL");
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}
console.log("[FR2 tokens] PASS - global theme/layout token authority is isolated under src/design-system/tokens.");
