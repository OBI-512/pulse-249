# FR6-B4 — Legacy Table Style Retirement Standard

## Scope
Frontend only. No backend, API, database, worker, scheduler, or business-behavior changes.

## Goal
Retire only global table-tool CSS proven dead after FR6-B1/B2/B3 established canonical CSS-Module ownership.

## Canonical owners
- `src/design-system/data/DataTable/DataTable.module.css`
- `src/design-system/data/SortHeader/SortHeader.module.css`
- `src/design-system/data/Pagination/Pagination.module.css`
- `src/design-system/data/TableExport/TableExport.module.css`

## Retired legacy class families
- sorting: `table-sort`, `sort-indicator`, `sort-triangle`
- pagination controls: `pagination-viewport`, `pagination-center-track`, `pagination-bar`, `pagination-size`, `pagination-icon`, `pagination-current`, `server-pagination`
- export UI: `table-export-control`, `table-export-trigger`, `table-export-chevron`, `table-export-menu`

## Preserved compatibility rules
FR6-B4 does **not** remove a legacy rule merely because it looks old. Rules still referenced by active feature markup remain, including:
- `table-wrap` and feature-specific table visual classes
- `pagination-table-row` used by Recycle Bin footer composition
- `table-toolbar-actions` used by Device inventory actions
- feature-specific alarm/maintenance/customer/management table classes

## Retirement rule
A global selector may be removed only when all of the following are true:
1. no active TS/TSX source references its legacy class;
2. its behavior/style has a canonical design-system owner;
3. source/style/unit/build guards pass after removal;
4. the affected UI is visually sampled after deployment.

## Expected behavior
No intended visual or functional change. Sorting, pagination, export, filters, permissions, and table data behavior remain unchanged.
