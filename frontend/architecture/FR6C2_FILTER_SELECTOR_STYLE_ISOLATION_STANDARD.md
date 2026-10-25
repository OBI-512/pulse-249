# FR6-C2 — Filter / Selector Style Isolation Standard

Scope: frontend only. No backend, API, database, worker, scheduler, authorization, or filter-query behavior changes.

## Canonical style owners

- Searchable single-select + local searchable adapter + server-paged selector:
  - `src/design-system/composites/SearchableSelect/SearchableSelect.module.css`
- Searchable multi-select:
  - same `SearchableSelect.module.css` owner
- Permission/direct multi-select dropdown:
  - `src/design-system/composites/MultiSelect/MultiSelect.module.css`
- Filter-bar layout + Clear Filters placement:
  - `src/design-system/composites/FilterBar/FilterBar.module.css`

## Isolation rule

Searchable selector implementation classes are locally scoped through CSS Modules. Global stylesheets must not define:

- `.searchable-combobox*`
- `.combobox-*`
- `.searchable-multi-*`

The canonical `MultiSelectDropdown` also uses CSS Modules and no longer depends on the legacy global `.multi-select*` classes.

The remaining global `.multi-select*` rules are temporarily retained only for GroupPage's custom child-group selectors. They are not canonical design-system styling and are scheduled for migration/retirement in FR6-C3.

## Locked behavior

- server-side selector search/paging unchanged;
- default page size unchanged;
- debounce unchanged;
- stale-request protection unchanged;
- outside-click close unchanged;
- keyboard selection unchanged;
- required/invalid selector presentation preserved;
- Clear Filters state semantics unchanged;
- sorting remains independent from filters;
- no backend authorization/scope behavior changes.

## Visual equivalence

FR6-C2 moves existing selector presentation under locally scoped owners. Existing theme tokens, dimensions, menu geometry, option states, responsive max-height, and Night-theme menu border treatment are preserved.
