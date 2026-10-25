import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const srcRoot = path.join(root, 'src');
const errors = [];

const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
  const full = path.join(dir, entry.name);
  if (entry.isDirectory()) return walk(full);
  return /\.(ts|tsx)$/.test(entry.name) ? [full] : [];
});

const normalize = (file) => path.relative(root, file).replaceAll('\\', '/');
const files = walk(srcRoot);
const featureFiles = files.filter((file) => {
  const rel = normalize(file);
  return !rel.startsWith('src/design-system/') && !rel.endsWith('.test.ts') && !rel.endsWith('.test.tsx');
});

let canonicalClearConsumers = 0;
let canonicalSearchConsumers = 0;
let canonicalMultiConsumers = 0;

for (const file of featureFiles) {
  const rel = normalize(file);
  const source = fs.readFileSync(file, 'utf8');
  if (/from\s+["'][^"']*common\/Ui["']/.test(source)) {
    const imports = source.match(/import\s*\{[^}]*\}\s*from\s*["'][^"']*common\/Ui["'];?/gs) || [];
    for (const statement of imports) {
      if (/\bClearFiltersButton\b|\bMultiSelectDropdown\b|\bSelectOption\b/.test(statement)) {
        errors.push(`${rel}: filter/select ownership still routed through common/Ui`);
      }
    }
  }

  if (/from\s+["'][^"']*common\/(?:SearchableCombobox|SearchableMultiSelect|LocalSearchableCombobox)["']/.test(source) ||
      /from\s+["']\.\/SearchableCombobox["']/.test(source)) {
    errors.push(`${rel}: searchable selector ownership still routed through compatibility facade`);
  }

  if (/design-system\/composites\/FilterBar/.test(source) && /\bClearFiltersButton\b/.test(source)) canonicalClearConsumers++;
  if (/design-system\/composites\/SearchableSelect/.test(source) && /\b(?:SearchableCombobox|SearchableMultiSelect|LocalSearchableCombobox)\b/.test(source)) canonicalSearchConsumers++;
  if (/design-system\/composites\/MultiSelect/.test(source) && /\bMultiSelectDropdown\b/.test(source)) canonicalMultiConsumers++;
}

const canonicalLocal = path.join(srcRoot, 'design-system/composites/SearchableSelect/LocalSearchableCombobox.tsx');
if (!fs.existsSync(canonicalLocal)) errors.push('Canonical LocalSearchableCombobox owner is missing.');
const searchIndex = fs.readFileSync(path.join(srcRoot, 'design-system/composites/SearchableSelect/index.ts'), 'utf8');
if (!searchIndex.includes('LocalSearchableCombobox')) errors.push('SearchableSelect barrel does not export LocalSearchableCombobox.');

if (canonicalClearConsumers < 20) errors.push(`Expected at least 20 direct ClearFiltersButton consumers; found ${canonicalClearConsumers}.`);
if (canonicalSearchConsumers < 14) errors.push(`Expected at least 14 direct searchable-selector consumers; found ${canonicalSearchConsumers}.`);
if (canonicalMultiConsumers < 1) errors.push('Expected at least one direct MultiSelectDropdown consumer.');

if (errors.length) {
  console.error('[FAIL] FR6-C1 filter/selector ownership guard.');
  for (const error of errors) console.error(` - ${error}`);
  process.exit(1);
}

console.log('[PASS] FR6-C1 filter/selector ownership guard.');
console.log(` - direct ClearFilters consumers: ${canonicalClearConsumers}`);
console.log(` - direct searchable-selector consumers: ${canonicalSearchConsumers}`);
console.log(` - direct MultiSelectDropdown consumers: ${canonicalMultiConsumers}`);
console.log(' - legacy compatibility facades are retired by CP4.');
