# FR6-C1 — Filter / Selector Ownership Standard

Scope: frontend only. No backend, API, database, worker, scheduler, or authorization changes.

## Canonical owners

- Clear Filters action: `src/design-system/composites/FilterBar`
- Server-search / paged selector: `src/design-system/composites/SearchableSelect`
- Local searchable adapter: `src/design-system/composites/SearchableSelect/LocalSearchableCombobox.tsx`
- Multi-select dropdown: `src/design-system/composites/MultiSelect`

Feature code must import these owners directly. `components/common` re-exports are compatibility facades only and must not be used by active migrated feature code.

## Locked behavior

- Server-backed selectors remain paged and server-filtered.
- Default lookup page remains approximately 50.
- Search remains debounced.
- Stale requests remain ignored through request identity protection.
- Clear Filters remains an explicit shared action.
- Clear Filters behavior in feature state remains unchanged: clear filter/search state, clear dependent selections, reset page 1 where implemented, preserve sorting.
- No backend authorization or scope behavior changes.

## FR6-C sequencing

FR6-C1 establishes direct source ownership only. Existing global selector/filter CSS remains intact for visual equivalence.

Subsequent batches will:
1. move searchable-selector styling into local CSS-module owners;
2. migrate raw filter-row composition to `FilterBar` blueprints;
3. retire only legacy filter/select CSS proven unused.
