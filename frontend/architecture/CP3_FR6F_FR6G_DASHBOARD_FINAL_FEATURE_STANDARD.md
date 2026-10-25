# CP3 — FR6-F + FR6-G Dashboard / States / Final Feature Migration

Scope: frontend only. No backend, API, database, worker, scheduler, or operational-data changes.

## Canonical ownership locked by CP3
- Domain status badges: `design-system/composites/Status`
- Compact statistic cards: `design-system/composites/Metric`
- NOC dashboard icon, animated number, availability gauge, metric-card and availability-state-bar helpers: `design-system/visualizations/Dashboard`
- Empty states: `design-system/composites/AsyncState`
- Context menus: `design-system/composites/Menu`
- Page/section headers: `design-system/layouts/Headers`
- Tabs: `design-system/composites/Tabs`

## Compatibility policy
CP3 changes ownership, not visual design. Existing semantic CSS class contracts remain in place for CP4 evidence-driven CSS/facade retirement.

## End-state guard
Active application/feature source must not import `components/common/Ui` or `components/common/WorkspacePatterns`. Overview dashboard visualization helpers must not be page-owned.
