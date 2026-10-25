import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const src = path.join(root, "src");
const errors = [];

const retired = [
  "src/components/common/Ui.tsx",
  "src/components/common/WorkspacePatterns.tsx",
  "src/components/common/WorkspacePatterns.test.tsx",
  "src/components/common/Pagination.tsx",
  "src/components/common/ServerPagination.tsx",
  "src/components/common/LocalSearchableCombobox.tsx",
  "src/components/common/SearchableCombobox.tsx",
  "src/components/common/SearchableMultiSelect.tsx",
  "src/components/common/CustomerSearchSelect.tsx",
  "src/components/common/SectorSearchSelect.tsx",
  "src/components/common/ui",
];
for (const rel of retired) if (fs.existsSync(path.join(root, rel))) errors.push(`retired compatibility path still exists: ${rel}`);

const forbiddenImport = /components\/common\/(?:Ui|WorkspacePatterns|Pagination|ServerPagination|LocalSearchableCombobox|SearchableCombobox|SearchableMultiSelect|CustomerSearchSelect|SectorSearchSelect)|components\/common\/ui\//;
function walk(dir) {
  const out=[];
  for (const entry of fs.readdirSync(dir,{withFileTypes:true})) {
    const full=path.join(dir,entry.name);
    if(entry.isDirectory()) out.push(...walk(full));
    else if(/\.(?:ts|tsx)$/.test(entry.name)) out.push(full);
  }
  return out;
}
for (const file of walk(src)) {
  const rel=path.relative(root,file).replaceAll(path.sep,"/");
  const text=fs.readFileSync(file,"utf8");
  if(forbiddenImport.test(text)) errors.push(`${rel}: imports a retired compatibility path`);
}

for (const primitive of ["Button","Input","Select","Textarea"]) {
  const tsx=fs.readFileSync(path.join(src,`design-system/primitives/${primitive}/${primitive}.tsx`),"utf8");
  const css=fs.readFileSync(path.join(src,`design-system/primitives/${primitive}/${primitive}.module.css`),"utf8");
  if(tsx.includes("styles.compat")) errors.push(`${primitive}: unstyled path still injects compatibility presentation`);
  if(/\.compat\b/.test(css)) errors.push(`${primitive}: dormant CP2 .compat CSS remains`);
}

const pageCss=fs.readFileSync(path.join(src,"design-system/layouts/PageLayout/PageLayout.module.css"),"utf8");
const pageRoot=pageCss.match(/\.root\s*\{([^}]*)\}/)?.[1] || "";
if(/\bdisplay\s*:/.test(pageRoot)) errors.push("PageLayout root still overrides feature-owned display model");

const requiredDocs=[
  "architecture/FRONTEND_DESIGN_SYSTEM_BLUEPRINT.md",
  "architecture/CP4_DESIGN_SYSTEM_LOCK.md",
];
for(const rel of requiredDocs) if(!fs.existsSync(path.join(root,rel))) errors.push(`missing CP4 architecture document: ${rel}`);

if(errors.length){
  console.error("[FAIL] CP4 design-system lock guard");
  for(const e of errors) console.error(`- ${e}`);
  process.exit(1);
}
console.log("[PASS] CP4 design-system lock guard.");
console.log("- retired compatibility facades: absent");
console.log("- dormant CP2 primitive compatibility presentation: absent");
console.log("- PageLayout display model: caller-owned");
