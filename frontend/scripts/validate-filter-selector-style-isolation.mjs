import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const src = path.join(root, 'src');
const errors = [];

const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');
const exists = (rel) => fs.existsSync(path.join(root, rel));

const searchCss = 'src/design-system/composites/SearchableSelect/SearchableSelect.module.css';
const multiCss = 'src/design-system/composites/MultiSelect/MultiSelect.module.css';
const searchSingle = 'src/design-system/composites/SearchableSelect/SearchableCombobox.tsx';
const searchMulti = 'src/design-system/composites/SearchableSelect/SearchableMultiSelect.tsx';
const canonicalMulti = 'src/design-system/composites/MultiSelect/MultiSelectDropdown.tsx';

for (const rel of [searchCss, multiCss, searchSingle, searchMulti, canonicalMulti]) {
  if (!exists(rel)) errors.push(`missing canonical selector style owner: ${rel}`);
}

if (exists(searchSingle) && !read(searchSingle).includes('SearchableSelect.module.css')) {
  errors.push('SearchableCombobox does not import its CSS Module owner.');
}
if (exists(searchMulti) && !read(searchMulti).includes('SearchableSelect.module.css')) {
  errors.push('SearchableMultiSelect does not import its CSS Module owner.');
}
if (exists(canonicalMulti) && !read(canonicalMulti).includes('MultiSelect.module.css')) {
  errors.push('MultiSelectDropdown does not import its CSS Module owner.');
}

for (const rel of [searchSingle, searchMulti]) {
  if (!exists(rel)) continue;
  const source = read(rel);
  for (const legacy of ['searchable-combobox', 'combobox-', 'searchable-multi-']) {
    if (source.includes(`className=\"${legacy}`) || source.includes(`className={\`${legacy}`)) {
      errors.push(`${rel}: contains legacy global selector class ownership (${legacy}).`);
    }
  }
}
if (exists(canonicalMulti)) {
  const source = read(canonicalMulti);
  for (const legacy of ['className="multi-select', 'className="selection-chip']) {
    if (source.includes(legacy)) errors.push(`${canonicalMulti}: still uses legacy global multi-select classes.`);
  }
}

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
}
const globalCss = walk(src).filter((file) => file.endsWith('.css') && !file.endsWith('.module.css'));
const forbidden = [
  /\.searchable-combobox(?:[\s.{:#>]|$)/,
  /\.searchable-combobox-control(?:[\s.{:#>]|$)/,
  /\.combobox-(?:search-icon|chevron|check|clear|spinner|option|option-copy|state|menu-footer)(?:[\s.{:#>]|$)/,
  /\.searchable-multi-(?:select|trigger|menu|search|actions|options|option)(?:[\s.{:#>]|$)/,
];
for (const file of globalCss) {
  const text = fs.readFileSync(file, 'utf8');
  for (const pattern of forbidden) {
    if (pattern.test(text)) errors.push(`${path.relative(root, file).replaceAll('\\','/')}: legacy searchable selector style remains global (${pattern}).`);
  }
}

// FR6-C2 originally deferred GroupPage child-group selectors. After FR6-C3, accept the
// canonical feature-owned CSS-Module implementation instead of requiring the legacy surface.
const groupSource = read('src/pages/GroupPage.tsx');
const groupFeatureOwner = 'src/features/groups/components/ChildGroupSelectors.tsx';
const legacyGroupSelector = groupSource.includes('child-group-selector') && groupSource.includes('multi-select-trigger');
const migratedGroupSelector = exists(groupFeatureOwner) && groupSource.includes('from "../features/groups/components"');
if (!legacyGroupSelector && !migratedGroupSelector) {
  errors.push('Group child-selector ownership is neither the FR6-C2 deferred legacy surface nor the FR6-C3 feature owner.');
}

if (errors.length) {
  console.error('[FAIL] FR6-C2 filter/selector CSS isolation guard.');
  for (const error of errors) console.error(` - ${error}`);
  process.exit(1);
}

console.log('[PASS] FR6-C2 filter/selector CSS isolation guard.');
console.log(' - searchable single/multi selector special styles are CSS-Module owned');
console.log(' - canonical MultiSelectDropdown special styles are CSS-Module owned');
console.log(' - global searchable selector class families retired');
console.log(migratedGroupSelector ? ' - GroupPage child-group selector is FR6-C3 feature-owned' : ' - GroupPage legacy child-group multi-select remains explicitly deferred to FR6-C3');
