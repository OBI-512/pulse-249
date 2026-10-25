# FR6-B3 — Table Tools Ownership Standard

## Scope
Frontend only. This batch completes source ownership for table-adjacent controls after the canonical DataTable shell migration.

## Canonical owners
- `src/design-system/data/DataTable` — table shell and optional table-toolbar composition.
- `src/design-system/data/SortHeader` — sortable header rendering only.
- `src/design-system/data/Pagination` — client/server pagination controls and locked page sizes.
- `src/design-system/data/TableExport` — full filtered-result CSV/XLSX export control.

## Rules
1. Operator features import SortHeader, Pagination and TableExport directly from their design-system owners.
2. `components/common/Ui.tsx`, `components/common/Pagination.tsx` and `components/common/ServerPagination.tsx` are compatibility facades only; operator feature code must not use them for table tools.
3. DataTable must remain presentation-only and must not absorb sorting, pagination, export, filtering, API, authorization or query behavior.
4. Export remains owned by the view/toolbar so active filters, sort state and scope remain explicit.
5. Pagination remains independent from DataTable so both client- and server-paginated tables continue to work.
6. Locked page sizes remain `50, 100, 200, 300, 400, 500`.
7. Universal operator table export remains CSV/XLSX only and exports the complete authorized filtered population, independent of the visible page.
8. Existing global visual compatibility selectors are retained in FR6-B3. They are inventoried for a later guarded dead-style retirement batch rather than deleted speculatively.

## Blast-radius rule
A future change to sorting, pagination, or export styling/behavior must be made in the owning design-system module and must not rewrite unrelated table components or global source files.
