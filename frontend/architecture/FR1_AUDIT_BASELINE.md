# FR1 Frontend Safety Baseline

Frozen source basis: Phase-D-closed frontend, 28 August 2026.

This document records the pre-design-system technical debt ceiling. FR2-FR7 should reduce these values; they must not increase without an explicit architecture decision.

## Active source size

- TSX: 51 files / 8,485 lines
- TS: 26 files / 2,842 lines
- CSS: 21 files / 10,332 lines

## Global style debt baseline

- `!important`: 636
- hard-coded color declarations: 1,444
- selectors defined in more than one active CSS file: 376

The machine-readable baseline is `style-coupling-baseline.json` and is enforced by `npm run audit:styles`.

## FR1 source hygiene

FR1 establishes the following invariant for active `frontend/src`:

- strict UTF-8;
- no UTF-8 BOM;
- no known mojibake sequences;
- no `.bak`, `.orig`, `.rej`, or editor backup artifacts;
- user-facing repaired symbols encoded safely in source;
- Playwright retains trace/screenshot evidence on failure.

## Known architecture debt to resolve in FR2-FR7

- numbered global stylesheet cascade and late override layers;
- reusable selectors owned by multiple CSS files;
- unrelated UI responsibilities co-located in `components/common/Ui.tsx`;
- extensive `!important` use;
- extensive hard-coded colors instead of semantic tokens;
- component style ownership not explicit;
- no design-system blueprint catalogue yet.

FR1 does not restructure those areas. It establishes the guardrails required to do so safely.
