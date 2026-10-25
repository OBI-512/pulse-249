# FR6-B1 Canonical DataTable Migration Standard

## Scope
Frontend only. No backend, API, database, worker or scheduler changes.

## Canonical ownership
- `src/design-system/data/DataTable/DataTable.tsx` owns the scroll viewport and semantic `<table>` shell.
- `viewportClassName` is a temporary compatibility hook that preserves approved legacy page-specific visuals while markup ownership migrates.
- `className` remains table-element styling compatibility only.
- Sorting remains owned by `SortHeader`.
- Pagination remains owned by `Pagination`.
- Export remains owned by `TableExport`.

## FR6-B1 migrated surfaces
- Alarm queue
- Maintenance windows
- Notification delivery log
- Discovery jobs
- Discovery results/evidence
- Device Management filtered device inventory

## Blast-radius rule
FR6-B1 MUST NOT change row data, columns, filters, sort semantics, pagination semantics, export filters, permission checks, API calls, or business logic. It only changes table-shell ownership.

## Visual compatibility
Existing `table-wrap` and table-specific classes are deliberately retained on the canonical component during migration. Legacy CSS is retired only after the full table migration is visually accepted.
