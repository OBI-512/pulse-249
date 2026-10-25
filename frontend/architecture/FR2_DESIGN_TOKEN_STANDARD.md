# FR2 — Design Token & Theme Foundation

Status: implemented by the FR2 guarded package; human visual equivalence gate required before closure.

## Goal

Create one explicit authority for global visual tokens without intentionally changing rendering.

## Rules

1. Global theme custom properties (`--nms-*` on `:root` or `html[data-theme]`) are owned by `src/design-system/tokens/`.
2. Component-local custom properties remain local to the owning component/feature stylesheet.
3. Existing token values are preserved in FR2. Redesign is out of scope.
4. New reusable components consume semantic tokens instead of adding hard-coded theme colors.
5. Component styling extraction begins in FR3; FR2 does not move component selectors.
6. Backend/API/database code is out of scope.

## Cascade preservation

The three token files are imported at the exact legacy cascade positions from which their declarations were extracted. This preserves current theme behavior while separating token authority from selector styling.

## Visual gate

Operations, Light and Night themes must show no intended visual change. Check shell/header/navigation, panels, forms/buttons, tables/sorters, tabs, export menu and scrolling surfaces.
