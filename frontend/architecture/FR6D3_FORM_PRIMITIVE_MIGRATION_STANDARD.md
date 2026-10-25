# FR6-D3 Page-Level Form Primitive Migration Standard

## Scope

FR6-D3 continues the frontend-only migration of page-level native form controls onto canonical design-system primitives.

This batch owns:

- `src/pages/AccountPage.tsx`
- `src/pages/MaintenancePage.tsx`
- `src/pages/RestorePointsPage.tsx`

## Rules

1. Active feature/page code must use canonical `Button`, `Input`, `Select`, `Checkbox`, or `Textarea` primitives instead of directly owning equivalent raw HTML controls once migrated.
2. The `unstyled` bridge is permitted during FR6 feature migration to preserve exact legacy visual behavior while ownership moves to the design system.
3. Business logic, validation, disabled/loading behavior, permissions, API contracts, filter semantics, sorting, pagination, and export behavior must not change as part of this ownership migration.
4. Backend, database, worker, scheduler, and migration code are outside FR6-D scope.
5. Legacy visual classes are retained until a later evidence-driven style-isolation/retirement batch proves they can be removed safely.
