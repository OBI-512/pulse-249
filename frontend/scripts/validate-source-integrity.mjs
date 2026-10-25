import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { TextDecoder } from "node:util";

const frontendRoot = path.resolve(process.cwd());
const srcRoot = path.join(frontendRoot, "src");
const decoder = new TextDecoder("utf-8", { fatal: true });
const sourceExtensions = new Set([".ts", ".tsx", ".css", ".json", ".html"]);
const backupPattern = /(?:\.bak|\.orig|\.rej|~)$/i;
const mojibake = [
  { label: "UTF-8 replacement character", pattern: /�/g },
  { label: "Windows-1252 UTF-8 mojibake", pattern: /â(?:€|€“|€”|€™|€œ|€\x9d|–|—|™|œ|ž)/g },
  { label: "triangle/arrow mojibake", pattern: /â[–—]/g },
  { label: "Latin-1 UTF-8 mojibake", pattern: /(?:Ã.|Â.)/g },
  { label: "Arabic-decoded middle dot", pattern: /آ·/g },
  { label: "Arabic-decoded multiplication sign", pattern: /أ—/g },
];

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
}

const problems = [];
const files = walk(srcRoot);
const backups = files.filter((file) => backupPattern.test(path.basename(file)));
for (const file of backups) {
  problems.push(`${path.relative(frontendRoot, file)}: backup artifact is not allowed inside active src`);
}

let checked = 0;
for (const file of files) {
  if (!sourceExtensions.has(path.extname(file).toLowerCase()) || backupPattern.test(path.basename(file))) continue;
  checked += 1;
  const buffer = fs.readFileSync(file);
  if (buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) {
    problems.push(`${path.relative(frontendRoot, file)}: UTF-8 BOM is not allowed`);
  }

  let text;
  try {
    text = decoder.decode(buffer);
  } catch {
    problems.push(`${path.relative(frontendRoot, file)}: invalid UTF-8 byte sequence`);
    continue;
  }

  for (const rule of mojibake) {
    rule.pattern.lastIndex = 0;
    if (rule.pattern.test(text)) {
      problems.push(`${path.relative(frontendRoot, file)}: ${rule.label}`);
    }
  }
}

if (problems.length) {
  console.error("[FR1 source integrity] FAIL");
  for (const problem of problems) console.error(`- ${problem}`);
  process.exit(1);
}

console.log(`[FR1 source integrity] PASS - ${checked} active source files are strict UTF-8, BOM-free, mojibake-free, and src contains no backup artifacts.`);
