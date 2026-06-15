# Onboarding system (developer guide)

The onboarding system runs short, anchored driver.js tours and orchestrates a
cross-route **guided sequence** after a user connects their first provider.
Everything lives in client state and localStorage — there is **zero backend
coupling**.

## Building blocks

| Concern                                | File                                                                  |
| -------------------------------------- | --------------------------------------------------------------------- |
| Flow registry (single source of truth) | `ui/lib/onboarding/registry.ts`                                       |
| Flow type (`OnboardingFlow`)           | `ui/lib/onboarding/onboarding-types.ts`                               |
| Tour definitions (`*.tour.ts`)         | `ui/lib/tours/`                                                       |
| Driver primitive (`useDriverTour`)     | `ui/lib/tours/use-driver-tour.ts`                                     |
| Per-route trigger                      | `ui/components/onboarding/onboarding-trigger.tsx`                     |
| Ephemeral sequence slice               | `ui/store/onboarding-sequence.ts`                                     |
| Checkpoint watcher + dialog            | `ui/components/onboarding/onboarding-checkpoint-{watcher,dialog}.tsx` |
| Mandatory new-user gate                | `ui/components/onboarding/onboarding-gate.tsx`                        |
| Manual replay list                     | `ui/components/ui/user-nav/user-nav.tsx`                              |

## How the guided sequence works

1. The `(prowler)/layout.tsx` derives a tri-state `hasProviders` on every
   navigation and mounts `<OnboardingCheckpointWatcher />` (sibling to the gate).
2. When the watcher observes a concrete `false → true` `hasProviders` flip (the
   user actually connected a provider), it opens the checkpoint dialog **once**.
   An `undefined → true` (user already had providers) never fires. A localStorage
   marker (`prowler.onboarding.checkpoint`) prevents re-appearance.
3. "Continue the tour" calls `startSequence(nextFlowId)` on the ephemeral
   `useOnboardingSequenceStore` and navigates to that flow's route.
4. Each route mounts an `<OnboardingTrigger flow={...} />`. The trigger force
   starts the flow when `slice.currentFlowId === flow.id` (sequence) **or** when
   the `?onboarding=<id>` param matches (replay). The StrictMode-safe latch /
   keyed runner / empty-deps force-start is preserved verbatim.
5. On tour close, `useDriverTour`'s `onClosed(state)` reports the outcome:
   `completed` → `advance()` (navigate to the next flow), `skipped`/`dismissed`
   → `stop()` (the sequence ends; closing any tour ends the sequence).
6. The slice is **ephemeral** (plain Zustand `create`, no `persist`). It carries
   `currentFlowId` across client navigations but resets on a hard reload, so a
   mid-sequence refresh never re-fires.

`attack-paths` is special: its page already owns a driver, so its registry entry
sets `ownsAutoOpen: true`, the trigger does **not** mount a runner for it, and
the page wires `onClosed` to the slice itself (single-fire).

## Add a new flow (the extensibility contract)

A new flow is **one registry entry + one tour file + its anchors + a trigger
mount** — no gate, modal, or nav edits.

1. **Tour file** — `ui/lib/tours/<flow-id>.tour.ts` via `defineTour<Target>` and
   the `assets/tour-template.ts`. Keep it shallow: a centered welcome step plus
   1–2 anchored steps. `coversFiles` scopes the drift check.
2. **Anchors** — add `data-tour-id="<flow-id>-<target>"` on the page-specific
   **client** component for each anchored step (never the shared Navbar).
   The tour file and its anchors MUST ship in the SAME PR (`tour:check`
   hard-fails a tour target with no matching anchor).
3. **Registry entry** — add `{ id, order, title, description, route, tour }` to
   `onboardingFlows` in `registry.ts`. Ordering is data (`order`).
4. **Trigger mount** — render `<OnboardingTrigger flow={getFlowById("<id>")!} />`
   inside the route's client host. Pass `stepHandlers`/`configOverrides` only if
   the flow needs them (e.g. add-provider opens the wizard).

The avatar "Product tour" submenu and `advance()` both derive from
`getOrderedFlows()`, so a new flow appears in the replay list and participates in
the sequence automatically.

## CI gates

- `pnpm run tour:check` (`ui/scripts/check-tour-alignment.mjs`) — every tour
  `target` must resolve to a real `data-tour-id` anchor within its `coversFiles`.
- `pnpm exec vitest run --project unit` — pure logic (slice, helpers, registry,
  tour shapes). The driver primitive short-circuits in `NODE_ENV==="test"`.
- `pnpm run test:e2e tests/onboarding/` — full-system behavior (sequence,
  checkpoint, replay, single-fire, refresh). Requires the Prowler stack.
