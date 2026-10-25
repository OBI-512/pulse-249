# FR6-C3 Group Child Selector Standard

- Group child selectors are feature-owned under `src/features/groups/components/`.
- Feature-specific selector composition must not leak global `.multi-select-*` or `.child-group-*` class families.
- Reusable generic multi-select/searchable-select behavior remains owned by the design system.
- The Group feature may compose its domain-specific all-child and eligible-child behavior locally, using semantic design tokens and CSS Modules.
- Outside-click closing, search thresholds, selected counts, all-child semantics, server-search state, and disabled behavior are preserved.
- Unicode UI glyphs in TS/TSX source use ASCII-safe escape sequences.
- Backend/API/database contracts are out of scope.
