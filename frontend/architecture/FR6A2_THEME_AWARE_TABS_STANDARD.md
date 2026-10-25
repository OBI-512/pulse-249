# FR6-A2 — Theme-Aware Canonical Tabs + Remaining Surface Migration

## Scope
Frontend only. This batch completes source migration of operator inner-tab surfaces to the canonical `Tabs` blueprint and establishes the final theme mapping.

## Final theme mapping
- **Light:** structured/legacy-approved segmented treatment.
- **Operations:** minimal/current canonical treatment.
- **Night:** minimal/current canonical treatment using Night semantic tokens.

Theme variation is automatic. Feature pages MUST NOT choose a visual tab variant manually.

## Single ownership
- Structure/behavior/accessibility: `src/design-system/composites/Tabs/Tabs.tsx`
- Styling/theme variation: `src/design-system/composites/Tabs/Tabs.module.css`
- Feature pages own only tab IDs, labels, visibility, disabled state, current value, and feature-specific outer spacing.

## Migrated surfaces
- Networks & Geography (FR6-A1)
- Data & Reports (FR6-A1)
- Network Topology
- Devices workspace
- Device Groups
- Settings
- Logs
- User Management

## Compatibility
The legacy global tab CSS remains present but has no operator TSX consumers after this batch. It is intentionally retired in a later cleanup batch only after visual acceptance, avoiding a large deletion blast radius in the migration step.

## Guardrails
- No `view-tabs`, `management-tabs`, `device-workspace-tabs`, `log-tabs`, or `settings-view-tabs` class may remain in operator TSX.
- No operator page may implement its own `role="tablist"`; that belongs to canonical `Tabs`.
- Theme-specific tab geometry must remain inside `Tabs.module.css`.
- No backend/database/API changes.
