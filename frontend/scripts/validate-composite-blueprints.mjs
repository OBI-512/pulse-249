import fs from "node:fs";
import path from "node:path";
const root=process.cwd();
const required=[
"src/design-system/data/DataTable/DataTable.tsx",
"src/design-system/data/Pagination/Pagination.tsx",
"src/design-system/data/SortHeader/SortHeader.tsx",
"src/design-system/data/TableExport/TableExportButton.tsx",
"src/design-system/composites/Tabs/Tabs.tsx",
"src/design-system/composites/Menu/ContextMenu.tsx",
"src/design-system/composites/FilterBar/FilterBar.tsx",
"src/design-system/composites/AsyncState/EmptyState.tsx",
"src/design-system/composites/SearchableSelect/SearchableCombobox.tsx",
"src/design-system/composites/MultiSelect/MultiSelectDropdown.tsx",
"architecture/FR4_COMPOSITE_BLUEPRINT_STANDARD.md",
];
for(const rel of required){ if(!fs.existsSync(path.join(root,rel))) throw new Error(`FR4 missing composite owner: ${rel}`); }
const sort=fs.readFileSync(path.join(root,"src/design-system/data/SortHeader/SortHeader.tsx"),"utf8");
const exp=fs.readFileSync(path.join(root,"src/design-system/data/TableExport/TableExportButton.tsx"),"utf8");
if(sort.includes("TableExport")||exp.includes("SortHeader")) throw new Error("FR4 cross-owner coupling detected between SortHeader and TableExport");
for(const rel of ["src/design-system/data/SortHeader/SortHeader.tsx","src/design-system/data/TableExport/TableExportButton.tsx","src/design-system/data/Pagination/Pagination.tsx","src/design-system/composites/Tabs/Tabs.tsx","src/design-system/composites/Menu/ContextMenu.tsx"]){ const text=fs.readFileSync(path.join(root,rel),"utf8"); if(!text.includes(".module.css")) throw new Error(`FR4 core owner lacks CSS Module: ${rel}`); }
console.log("[PASS] FR4 composite blueprint ownership guard.");
