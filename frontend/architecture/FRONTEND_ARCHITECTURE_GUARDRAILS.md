# FTTW Frontend Architecture Guardrails

Status: **FR1 safety foundation**

These rules protect the frozen Phase-D frontend while the design-system refactor proceeds. They do not change application behavior.

## 1. Blast radius

- Small UI changes must modify the owning component/module only.
- Do not rewrite a shared file to change an unrelated component.
- Shared-component changes require targeted regression of every consumer class affected by that shared component.
- Broad search/replace across `frontend/src` is prohibited unless performed by a guarded migration with an explicit changed-file manifest.

## 2. Source encoding

- Active frontend source is UTF-8 without BOM.
- Do not use Windows PowerShell 5.1 `Get-Content` + `Set-Content -Encoding UTF8` to round-trip complete TS/TSX/CSS files.
- Prefer patching exact source ranges, Node/Python UTF-8-safe transformations, or guarded payload replacement.
- User-visible symbols should prefer CSS-drawn icons, SVG/icon components, or ASCII source with Unicode escapes where appropriate.
- `npm run validate:source` is mandatory after frontend source modifications.

## 3. Backups

- Backup copies must not live under `frontend/src`.
- Store rollback copies under the project `Backup` hierarchy.
- `.bak`, `.orig`, `.rej`, editor backup files, and timestamped source duplicates are prohibited in active `src`.

## 4. Style ownership

Until FR2-FR7 complete the migration:

- Existing global CSS is legacy compatibility surface, not the location for new reusable component styling.
- Do not introduce a new global selector when a component-local owner can be used.
- Do not increase `!important`, hard-coded color usage, or selectors duplicated across multiple global CSS files.
- `npm run audit:styles` enforces a non-regression ceiling based on the FR1 baseline.
- Future reusable components will own their styles through CSS Modules and semantic design tokens.

## 5. Component ownership target

The refactor will make ownership explicit:

- `SortHeader` owns sort indicators and sort interaction styling.
- `TableExport` owns export trigger/menu styling and behavior.
- `DataTable` owns shared table shell/row/header behavior.
- `Tabs`, `Menu`, `Button`, `Input`, `Select`, `Pagination`, charts, filters, cards, and layouts each receive their own reusable blueprint.

No component may rely on editing another unrelated component's implementation to change its appearance.

## 6. Validation minimum

For every frontend refactor batch:

1. source-integrity guard;
2. style-debt non-regression guard;
3. targeted unit tests;
4. full frontend unit suite when shared primitives change;
5. production TypeScript/Vite build;
6. frontend-only deployment unless another service is explicitly required;
7. targeted visual/human UAT;
8. rollback evidence.

Backend source, database schema/data, workers, and scheduler are out of scope for FR1-FR7.
