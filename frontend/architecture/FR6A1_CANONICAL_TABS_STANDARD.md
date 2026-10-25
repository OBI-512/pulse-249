# FR6-A1 — Canonical Tabs Migration Standard

## Scope
Frontend only. This sub-batch establishes the approved segmented inner-tab design as the canonical `Tabs` blueprint and migrates the two reference surfaces first: Networks & Geography and Data & Reports.

## Ownership
- Structure/behavior: `src/design-system/composites/Tabs/Tabs.tsx`
- Styling: `src/design-system/composites/Tabs/Tabs.module.css`
- Feature pages may control only tab data, visibility, disabled state, current value, and layout spacing via an optional feature class.
- Feature pages must not restyle canonical tab internals or add legacy `view-tabs`, `management-tabs`, `device-workspace-tabs`, `log-tabs`, or `settings-view-tabs` classes to the canonical component.

## Visual language
The canonical blueprint preserves the approved NMS segmented-tab language: one rounded surface, deterministic per-position accent identity, connected left/top accent contour, subtle selected gradient, theme-aware text/surface/border tokens, and horizontal scrolling on narrow screens.

## Accessibility
The blueprint owns `tablist`/`tab` roles, `aria-selected`, disabled state, and button semantics.

## Migration strategy
FR6-A1 migrates Networks & Geography and Data & Reports. Remaining legacy tab surfaces are migrated in later FR6-A sub-batches after targeted visual equivalence checks. Legacy global CSS is not removed until its final consumer is migrated.
