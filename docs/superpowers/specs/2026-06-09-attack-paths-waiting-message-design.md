# Attack Paths — adaptive waiting message

**Date:** 2026-06-09
**Branch:** `fix/improve-attack-path-copy-waiting`
**Scope:** UI-only (`ui/`). No API changes.

## Problem

The Attack Paths page (`/attack-paths`) shows a single full-page message —
**"No scans available" + "Go to Scan Jobs"** — whenever no graph is queryable.
It conflates distinct situations the user wants told apart:

1. **No scans at all** — correct as-is.
2. **A scan is launched but not finished** — should say "scan in progress".
3. **Scan finished, but the post-scan Cartography graph build (queued job) hasn't
   completed** — should say "preparing data / almost ready", *if detectable*.

It additionally mis-fires on a **fetch/auth error** (the loader's catch sets
`scans = []`, which renders the same "No scans available" message).

## Feasibility (verified)

All three states are detectable **today, client-side**, from data the page
already fetches once on mount via `getAttackPathScans()` →
`GET /attack-paths-scans` (latest `AttackPathsScan` row per provider). Each row
carries `state`, `progress`, and **`graph_data_ready`** — the same boolean the API
uses to hard-gate querying (HTTP 400 when false).

- Scenario 3's signal **already exists**: `graph_data_ready === false` while the
  Cartography build runs. No new API field or endpoint is required.
- The `AttackPathsScan` row is **pre-created when a scan starts** (`views.py:2623`
  for manual, `beat.py:43` for scheduled) — **but only for AWS** (the sole provider
  with a Cartography ingestion function today). For any other provider
  `create_attack_paths_scan` returns `None` and no row is created.

Consequence of pre-creation: for AWS, scenarios 2 & 3 **never reach the current
full-page message** — the page shows the scan *table* with a disabled row whose
status lives only in a hover tooltip. So this work makes the full-page message
**own the waiting states** (replacing the table when *nothing* is queryable),
not merely reword scenario 1.

### Row state semantics (AttackPathsScan.state)

- `SCHEDULED` — row created; compute scan running, or graph job queued (not started).
- `EXECUTING` — Cartography graph build actively running (`progress` 1→99).
- `COMPLETED` — graph job finished (`graph_data_ready` true on success; false only
  for the unsupported/failure-recovered edge).
- `FAILED` — graph build failed.
- `AVAILABLE` — initial default (rare for attack-paths rows; created as `SCHEDULED`).

## In scope

- Full-page message adapts to **3 states**: no-scans / scan-running / graph-building
  (with `progress%`).
- **Split the load-error** out of "no scans" into a distinct error state with a
  **Retry**.
- A **5th terminal state** (`no-graph-data`) so a *failed/unsupported* build does not
  sit forever on "almost ready". Reuses wording already present in the per-row
  tooltips.
- **Polling / auto-advance**: keep the existing `<AutoRefresh>` behaviour — it
  already polls (~5s) while `hasExecutingScan` is true and no scan is selected, so
  the view auto-reveals the workflow when `graph_data_ready` flips. No new polling
  code.

## Out of scope (follow-ups)

- **Non-AWS honesty** ("you have providers but none supports Attack Paths"): needs the
  UI to know which provider types support attack paths — deferred.
- Per-provider status changes in the scan table (unchanged).

## Architecture

Three units, all co-located in the `query-builder` feature directory (following the
existing `_components/` pattern). **No barrel files** — direct imports.

1. **`getAttackPathsViewState({ scansLoading, loadError, scans })`** — pure function
   returning a discriminated union (the "view state"). Unit-testable in isolation.
2. **`<AttackPathsStatusPanel state={…} progress={…} onRetry={…} />`** —
   presentational; renders the right `<Alert>` + copy + CTA per state. New file under
   `_components/`.
3. **`attack-paths-page.tsx`** — replaces the ternary at lines 389–406; adds a
   `loadError` flag in the mount loader; renders the panel **or** the existing
   workflow; leaves `<AutoRefresh>` mounted (already unconditional at lines 372–375).

### View-state derivation (priority order)

Inputs: `scansLoading: boolean`, `loadError: boolean`, `scans: AttackPathScan[]`.

| State            | Condition                                                                 | Polls? |
|------------------|---------------------------------------------------------------------------|--------|
| `loading`        | `scansLoading`                                                            | —      |
| `error`          | `loadError` (loader returned `undefined`)                                 | on Retry |
| `no-scans`       | `scans.length === 0`                                                       | no     |
| `ready`          | `scans.some(s => s.attributes.graph_data_ready)` → render workflow         | n/a    |
| `graph-building` | none ready, some `state === EXECUTING` (show max `progress` of those rows) | yes    |
| `scan-running`   | none ready, some `state ∈ {SCHEDULED, AVAILABLE}`                          | yes    |
| `no-graph-data`  | none ready, all `state ∈ {COMPLETED, FAILED}`                              | no     |

`ready` is evaluated **before** the non-ready states: if *any* provider has a
queryable graph, the full-page message yields to the normal workflow (table +
builder + graph), and per-provider status for the still-building providers stays in
the table. This is the multi-provider rule: the full-page message takes over **only
when nothing is queryable**.

### Proposed copy (editable; English, inline — no i18n layer exists)

| State            | Title                          | Body / CTA                                                                                  |
|------------------|--------------------------------|---------------------------------------------------------------------------------------------|
| `error`          | "Couldn't load scans"          | "Something went wrong loading your scans." + **[Retry]**                                     |
| `no-scans`       | "No scans available"           | "You need to run a scan before you can analyze attack paths." + **[Go to Scan Jobs]** *(unchanged)* |
| `scan-running`   | "Scan in progress"             | "Your scan is running. Attack Paths will be available once it completes."                    |
| `graph-building` | "Preparing Attack Paths data"  | "We're building the graph from your latest scan ({progress}%). This will be ready shortly."  |
| `no-graph-data`  | "No Attack Paths data"         | "Your scan completed but didn't produce graph data."                                         |

(`loading` keeps "Loading scans…".)

## Data flow

Unchanged. Single `getAttackPathScans()` on mount + the existing 5s `<AutoRefresh>`.

- The mount loader sets `loadError = true` when `getAttackPathScans()` resolves to
  `undefined`; clears it on a successful (re)load. A successful load with
  `{ data: [] }` is **not** an error → `no-scans`.
- **Retry** re-runs the same mount loader (toggles loading, sets/clears `loadError`).
  The background `refreshScans` poll keeps its current silent-on-error behaviour.

## Testing (TDD — mandatory)

- **Vitest** unit tests for `getAttackPathsViewState`: one case per state, plus
  multi-provider precedence (e.g. one `EXECUTING` + one `FAILED` → `graph-building`;
  one ready + one building → `ready`).
- **RTL** test for `<AttackPathsStatusPanel>`: correct title/body/CTA per state;
  Retry invokes `onRetry`; `graph-building` renders `progress%`.
- **Fixtures** in `attack-paths-page.fixtures.ts`: add `scanRunning` (rows
  `SCHEDULED`, none ready), `graphBuilding` (rows `EXECUTING`, `graph_data_ready:false`,
  `progress` mid-range), `noGraphData` (rows `COMPLETED`/`FAILED`, none ready); register
  them in the existing `fixtures` aggregator. `emptyScans()` already covers `no-scans`.
- **Error state**: the pure deriver test covers `loadError`; the panel RTL test covers
  the error UI. A full-page browser/MSW error fixture is optional (the harness's
  `PageFixture` doesn't model a failing scans endpoint today).
- `ui/CHANGELOG.md` entry (changelog gate).

## Files

- `ui/app/(prowler)/attack-paths/(workflow)/query-builder/attack-paths-page.tsx` — modify
- `ui/app/(prowler)/attack-paths/(workflow)/query-builder/_components/attack-paths-status-panel.tsx` — new
- pure helper `getAttackPathsViewState` — new, local to the feature dir, placed per CLAUDE.md's local-util convention (`{feature}/utils/`, or alongside `_components/` to match the existing layout — confirm at implementation)
- `ui/app/(prowler)/attack-paths/(workflow)/query-builder/attack-paths-page.fixtures.ts` — extend
- Vitest specs for the helper + panel — new
- `ui/CHANGELOG.md` — entry
