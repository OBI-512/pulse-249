# FR6-D1 Dialog Ownership Standard

Scope: frontend only.

Canonical dialog markup ownership lives under `src/design-system/composites/Dialog`.

Rules:
- Common application dialog systems must compose `DialogBackdrop`, `DialogCard`, `DialogHeader`, `DialogMessage`, `DialogBody`, and `DialogActions` from the canonical owner.
- Feature/common consumers must not reproduce `dialog-*` structural class markup directly.
- Existing global dialog CSS remains temporarily authoritative for visual equivalence during FR6-D1.
- Dialog CSS isolation and legacy style retirement are deferred to a later FR6-D sub-batch after visual acceptance.
- Existing confirm/prompt/modal behavior, outside-click close, Escape handling, focus behavior, feedback behavior, and authorization/business logic must not change.
- Backend, database, API contracts, workers, scheduler, and UAT data are out of scope.
