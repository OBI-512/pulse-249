# CP4 Design-System Lock

CP4 retires compatibility architecture only when active-consumer count is zero.

Locked rules:

1. Application features import canonical design-system owners directly.
2. `components/common/Ui`, `WorkspacePatterns`, pagination/searchable-selector facades, and `components/common/ui/*` are retired and must not return.
3. `Button`, `Input`, `Select`, and `Textarea` with `unstyled` set provide semantics/behavior only; caller classes own presentation.
4. `PageLayout` may provide structural containment but must not override the feature page's `display` model.
5. Raw application tables and raw application form controls remain prohibited outside canonical design-system ownership.
6. Global CSS is retained where it still has active visual contracts. CP4 does not remove a global rule merely because a design-system replacement exists.
7. UTF-8/source-integrity, style-debt, token, primitive, composite, layout, tab, table, filter, dialog, and form-control guards remain mandatory.
