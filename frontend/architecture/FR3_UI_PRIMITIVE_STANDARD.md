# FR3 — UI Primitive & Ownership Standard

## Scope
FR3 introduces reusable, isolated frontend primitives and decomposes the legacy `components/common/Ui.tsx` implementation barrel. It is frontend-only and has no intended visual or behavioral change to existing features.

## Primitive authority
Canonical primitives live under:

`src/design-system/primitives/<Primitive>/`

Each primitive owns:
- React implementation;
- TypeScript public props;
- one colocated CSS Module;
- one local `index.ts` export.

The primitive catalogue is exported by `src/design-system/primitives/index.ts`.

## FR3 primitive catalogue
- Button
- IconButton
- Input
- Select
- Checkbox
- Badge
- Tooltip
- Spinner
- Textarea

## Style ownership rule
A primitive's appearance is controlled by its own CSS Module. Feature CSS must not target hashed primitive internals. Feature layout may position a primitive through a caller-supplied `className`, but must not redefine the primitive's internal states.

## Legacy compatibility rule
Existing feature pages are intentionally not bulk-migrated in FR3. Migration happens in later controlled batches. `components/common/Ui.tsx` remains as a compatibility barrel only.

Its former implementations are now individually owned by:

`src/components/common/ui/`

This immediately prevents unrelated shared controls (for example TableExport and SortHeader) from being edited in the same implementation file.

## Blast-radius rule
A small visual change must modify only:
1. the owning component;
2. that component's CSS Module or explicitly owned legacy style block;
3. component-specific tests/fixtures.

A change to Export must not rewrite SortHeader source. A change to SortHeader must not rewrite Export source.

## Migration rule
Existing raw buttons/inputs/selects are migrated feature-by-feature only after visual equivalence is demonstrated. FR3 does not perform a global search-and-replace conversion.
