# FTTW Design Tokens — FR2

This directory is the canonical authority for application-level design tokens.

## Files

- `theme-base.css` — base Operations, Light and Night theme tokens.
- `theme-refinements.css` — later semantic theme refinements (titles, tabs, navigation, table and scrollbar states).
- `layout.css` — application-wide fixed chrome/layout dimensions.

## Ownership rule

Application-wide `:root` / `html[data-theme=...]` `--nms-*` declarations belong here. Feature/component-scoped custom properties remain with the component that owns them. FR2 intentionally does not redesign token values or visual behavior.

Future blueprint components must consume these tokens rather than add new hard-coded application colors or create new global theme declarations in legacy stylesheets.
