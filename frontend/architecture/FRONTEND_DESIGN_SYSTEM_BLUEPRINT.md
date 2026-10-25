# FTTW Frontend Design-System Blueprint

## Tokens
Canonical theme/layout values live under `src/design-system/tokens`.

## Primitives
`Button`, `IconButton`, `Input`, `Select`, `Checkbox`, `Badge`, `Tooltip`, `Spinner`, and `Textarea` own low-level semantics and locally scoped styles.

## Composites
Canonical reusable interaction blueprints include Tabs, Dialog, Menu, FilterBar/Clear Filters, SearchableSelect, MultiSelect, Status, Metric, and AsyncState.

## Data
Canonical data presentation owns DataTable, SortHeader, Pagination, and TableExport. Export operates on the full authorized filtered result set, not the visible page.

## Layouts
Canonical page/view composition owns PageLayout, view layouts, headers, and surfaces. PageLayout must not dictate a feature's flex/grid/block display model.

## Visualizations
Dashboard visualization helpers live under `src/design-system/visualizations`.

## Feature rule
Features compose these owners and retain feature-specific classes only where the visual contract is genuinely feature-specific. New shared UI behavior or styling must be implemented in the owning design-system component rather than by cross-cutting global overrides.

## Theme-aware Tabs
Light uses the structured tab treatment. Operations and Night use the minimal treatment. The component owner is singular; theme selects presentation.

## Safety
Small edits must be granular, source-guarded, UTF-8 safe, and validated for blast radius. Backend/database are outside the frontend refactor scope.
