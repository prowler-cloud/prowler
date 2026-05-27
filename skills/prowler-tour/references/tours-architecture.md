# Tours Architecture

The product-tour abstraction lives under [`ui/lib/tours/`](../../../ui/lib/tours/).
This skill operates on tour definitions that follow this architecture.

## Source of truth

- **Design rationale (decisions, alternatives, trade-offs):**
  [`openspec/changes/add-product-tour-driverjs-poc/design.md`](../../../openspec/changes/add-product-tour-driverjs-poc/design.md)
- **Spec requirements (binding rules + scenarios):**
  [`openspec/specs/ui-product-tour/spec.md`](../../../openspec/specs/ui-product-tour/spec.md)
  (delta in `openspec/changes/add-product-tour-driverjs-poc/specs/ui-product-tour/spec.md` until archived)

## Code map

| File | Purpose |
|---|---|
| `ui/lib/tours/tour-types.ts` | Public type surface: `TourDefinition`, `TourStep`, `TourId`, `TourCompletionRecord`, completion-state const map. |
| `ui/lib/tours/tour-config.ts` | `baseDriverConfig`, `getDriverConfig(theme, overrides?)`, overlay-color map. |
| `ui/lib/tours/store/tour-completion-store.ts` | Persistence interface — the swap point for future API adapters. |
| `ui/lib/tours/store/local-storage-adapter.ts` | The only adapter in the PoC. Key format: `prowler.tour.<id>.v<version>`. |
| `ui/lib/tours/use-driver-tour.ts` | React hook. Initializes driver.js, derives `overlayColor` from `useTheme()`, persists completion. |
| `ui/lib/tours/<id>.tour.ts` | One file per tour. Exports a `TourDefinition` and is imported by the page that opts the user in. |
| `ui/styles/tours.css` | `.driver-popover.prowler-theme` — every color resolved via `var(--...)` from `globals.css`. |

## Selector convention

Tour steps anchor via `data-tour-id="<tour-id>-<step.target>"`. The hook
composes the CSS selector at runtime; tour authors only provide the step
name in `step.target`. Class-based, ID-based, structural selectors are
forbidden — they couple tours to styling decisions that legitimately
change.

## Identity and versioning

A tour is `{ id, version }`. The localStorage key composes both. A
**material content change** bumps `version`; cosmetic edits do not. The
decision tree lives in the parent SKILL.md.

## Persistence scope

Per-user, cross-tenant. A user who completed `attack-paths@v1` in tenant
A does not see the tour again in tenant B, even if they can access the
feature there. The future `UserTourState` model (documented in
`design.md`, not built) is FK to `User`, not `Membership`.

## Drift = #1 risk

Without the maintenance skill + the optional CI gate
(`ui/scripts/check-tour-alignment.mjs`), tours decay silently as the
covered UI evolves. The parent SKILL.md enumerates the six drift
categories the skill checks for.
