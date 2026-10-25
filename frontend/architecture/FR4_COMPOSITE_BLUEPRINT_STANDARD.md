# FR4 Composite Blueprint Standard

FR4 establishes reusable frontend composite ownership without backend/API/database changes.

## Canonical owners
- DataTable / TableToolbar: `src/design-system/data/DataTable`
- Pagination: `src/design-system/data/Pagination`
- SortHeader: `src/design-system/data/SortHeader`
- TableExport: `src/design-system/data/TableExport`
- Tabs: `src/design-system/composites/Tabs`
- ContextMenu: `src/design-system/composites/Menu`
- FilterBar / ClearFilters: `src/design-system/composites/FilterBar`
- Empty state: `src/design-system/composites/AsyncState`
- Searchable selectors: `src/design-system/composites/SearchableSelect`
- MultiSelect: `src/design-system/composites/MultiSelect`

## Ownership rule
New modules must consume these owners rather than recreate equivalent UI contracts. Core cross-cutting controls use colocated CSS Modules. Searchable selector and MultiSelect markup is centralized in FR4 while legacy global CSS compatibility is retained until feature migration (FR6), because existing feature-specific layout overrides depend on those compatibility hooks.

## Blast-radius rule
A change to SortHeader, TableExport, Pagination, Tabs, Menu, or FilterBar must be made in its owning directory and qualified by the FR4 architecture guard plus unit/build gates. Legacy `components/common` paths are compatibility barrels only for migrated owners.

## No-behavior-change contract
FR4 changes source/style ownership only. It must not change API requests, authorization, table filtering, sorting semantics, pagination policy, export semantics, or backend/database behavior.
