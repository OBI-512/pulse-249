import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const frontendRoot = path.resolve(process.cwd());
const srcRoot = path.join(frontendRoot, "src");
const baselineFile = path.join(frontendRoot, "architecture", "style-coupling-baseline.json");

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
}

const cssFiles = walk(srcRoot).filter((file) => file.endsWith(".css") && !/\.bak$/i.test(file));
let importantCount = 0;
let hardCodedColorCount = 0;
const selectors = new Map();

for (const file of cssFiles) {
  const text = fs.readFileSync(file, "utf8");
  importantCount += (text.match(/!important\b/g) || []).length;
  hardCodedColorCount += (text.match(/#[0-9a-fA-F]{3,8}\b|\brgba?\s*\(|\bhsla?\s*\(/g) || []).length;

  // CSS Modules are locally scoped by the build and therefore cannot create
  // cross-file global-selector coupling. Keep !important/color debt visible for
  // every CSS file, but measure duplicate selectors only in global stylesheets.
  if (!file.endsWith(".module.css")) {
    const withoutComments = text.replace(/\/\*[\s\S]*?\*\//g, "");
    const blockPattern = /([^{}]+)\{/g;
    let match;
    while ((match = blockPattern.exec(withoutComments))) {
      const header = match[1].trim();
      if (!header || header.startsWith("@")) continue;
      for (const raw of header.split(",")) {
        const selector = raw.trim().replace(/\s+/g, " ");
        if (!selector || selector.includes(":" + "root") || selector === "from" || selector === "to" || /^\d+(?:\.\d+)?%$/.test(selector)) continue;
        const files = selectors.get(selector) || new Set();
        files.add(path.relative(frontendRoot, file).replaceAll("\\", "/"));
        selectors.set(selector, files);
      }
    }
  }
}

const duplicatedAcrossFiles = [...selectors.entries()]
  .filter(([, files]) => files.size > 1)
  .sort((a, b) => b[1].size - a[1].size || a[0].localeCompare(b[0]));

const report = {
  schema: 1,
  css_files: cssFiles.length,
  important_count: importantCount,
  hard_coded_color_count: hardCodedColorCount,
  selectors_defined_in_multiple_files: duplicatedAcrossFiles.length,
  top_cross_file_selectors: duplicatedAcrossFiles.slice(0, 40).map(([selector, files]) => ({ selector, files: [...files].sort() })),
};

if (process.argv.includes("--write-baseline")) {
  fs.mkdirSync(path.dirname(baselineFile), { recursive: true });
  fs.writeFileSync(baselineFile, JSON.stringify(report, null, 2) + "\n", "utf8");
  console.log(`[FR1 style coupling] Baseline written: ${path.relative(frontendRoot, baselineFile)}`);
  console.log(JSON.stringify(report, null, 2));
  process.exit(0);
}

if (!fs.existsSync(baselineFile)) {
  console.error(`[FR1 style coupling] FAIL - baseline missing: ${baselineFile}`);
  process.exit(1);
}

const baseline = JSON.parse(fs.readFileSync(baselineFile, "utf8"));
const regressions = [];
if (report.important_count > baseline.important_count) regressions.push(`!important increased ${baseline.important_count} -> ${report.important_count}`);
if (report.hard_coded_color_count > baseline.hard_coded_color_count) regressions.push(`hard-coded colors increased ${baseline.hard_coded_color_count} -> ${report.hard_coded_color_count}`);
if (report.selectors_defined_in_multiple_files > baseline.selectors_defined_in_multiple_files) regressions.push(`cross-file duplicate selectors increased ${baseline.selectors_defined_in_multiple_files} -> ${report.selectors_defined_in_multiple_files}`);

if (regressions.length) {
  console.error("[FR1 style coupling] FAIL - global style debt increased");
  for (const regression of regressions) console.error(`- ${regression}`);
  process.exit(1);
}

console.log(`[FR1 style coupling] PASS - debt did not increase (!important=${report.important_count}, hard-coded colors=${report.hard_coded_color_count}, cross-file duplicated selectors=${report.selectors_defined_in_multiple_files}).`);
