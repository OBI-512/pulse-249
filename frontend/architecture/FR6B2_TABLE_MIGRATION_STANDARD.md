# FR6-B2 Canonical DataTable Migration Standard

## Scope
Frontend only. No backend, API, database, worker or scheduler changes.

## Canonical ownership
- `src/design-system/data/DataTable/DataTable.tsx` owns the semantic `<table>` shell and scroll viewport.
- Operator pages/components consume `DataTable`; they do not directly render raw `<table>` shells.
- `viewportClassName` and `className` remain temporary compatibility hooks while approved legacy visuals are preserved.
- Sorting remains owned by `SortHeader`.
- Pagination remains owned by the pagination blueprints.
- Export remains owned by `TableExport` and the owning view/toolbar.
- Filters and authorization semantics remain owned by their existing feature logic.

## FR6-B2 completion rule
All current operator table surfaces are migrated to canonical `DataTable`. A source guard fails if any operator TSX file outside the DataTable blueprint itself reintroduces a raw `<table>` element.

## Blast-radius rule
Migration MUST NOT change row data, columns, filter semantics, sorting semantics, pagination, export population, permissions, API calls or business logic. It changes only table-shell ownership.

## Visual compatibility
Existing `table-wrap`, `management-table-wrap`, `clickable-table`, `compact-table` and other approved page-specific compatibility classes remain in place during FR6-B2. Legacy table CSS is not removed until table migration receives visual acceptance.
