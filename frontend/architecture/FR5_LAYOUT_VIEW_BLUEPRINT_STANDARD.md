# FR5 — Layout & View Blueprint Standard

## Scope
Frontend only. FR5 establishes canonical page/view composition without intentionally changing application appearance or behavior.

## Canonical ownership
- `design-system/layouts/PageLayout` — page root/content spacing contract.
- `design-system/layouts/ViewLayouts` — list, detail, dashboard, settings and split-view composition.
- `design-system/layouts/Headers` — page headers, section headers and action bars.
- `design-system/layouts/Surface` — panel, card and section-stack composition.

## Compatibility strategy
Existing pages are not bulk-rewritten in FR5. `components/common/WorkspacePatterns.tsx` becomes a compatibility facade over the canonical layout owners. Feature-by-feature migration belongs to FR6.

## Style ownership
Layout modules may own geometry/composition only. Colors, typography, border values and elevation must come from existing semantic tokens or the preserved legacy surface classes during migration. New global selectors are prohibited.

## Blast-radius rule
A layout change must target the owning layout module. It must not rewrite unrelated feature/page files. Full-file encoding transformations are prohibited for small changes.

## Intended visual change
NONE.
