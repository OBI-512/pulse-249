# CP2 — FR6-D9 + FR6-E Style / Layout Standard

Scope: frontend only. No backend, API, worker, scheduler, or database changes.

## Locked ownership
- All operator page roots are owned by `PageLayout`.
- Dialog structure and baseline presentation are owned by `design-system/composites/Dialog`.
- Migrated legacy Button/Input/Select/Textarea presentations receive a local CSS-Module compatibility owner even while legacy global CSS remains temporarily available.
- Legacy global form/dialog/layout CSS is not blindly deleted in CP2; retirement is reserved for CP4 after CP3 completes the remaining feature migration.

## Compatibility rule
The legacy class names remain attached as feature hooks so existing page-specific visual rules continue to work. CP2 changes ownership, not intended appearance or behavior.
