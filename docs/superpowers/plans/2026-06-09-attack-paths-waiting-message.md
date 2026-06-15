# Attack Paths Adaptive Waiting Message — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single full-page "No scans available" message on the Attack Paths page with a message that adapts to the real state — no scans / scan running / graph building / load error / completed-without-graph — and auto-advances to the graph when ready.

**Architecture:** A pure deriver (`getAttackPathsViewState`) maps `{ scansLoading, loadError, scans }` to a discriminated view-state; a presentational `<AttackPathsStatusPanel>` renders the copy/CTA per state; `attack-paths-page.tsx` renders the panel or the existing workflow. Polling/auto-advance is already provided by the always-mounted `<AutoRefresh>` (polls while `hasExecutingScan`), so no new polling code. UI-only — no API changes.

**Tech Stack:** Next.js 16 (App Router, client component), React 19 (compiler — no `useMemo`/`useCallback`), TypeScript (const-object enums), shadcn `Alert`/`Button`, Vitest (`unit` jsdom + `browser` projects), Testing Library, MSW.

**Spec:** `docs/superpowers/specs/2026-06-09-attack-paths-waiting-message-design.md`

**Conventions (from CLAUDE.md + user memory):**
- Const-object enums: `const X = {...} as const; type T = typeof X[keyof typeof X]`. Never bare union types.
- No `useMemo`/`useCallback`. No `import React`.
- **No barrel files** — import the new helper/panel from their direct file paths, do NOT add them to the existing `_lib/index.ts` or `_components/index.ts` barrels.
- Local-to-feature code lives in `_lib/` (pure utils) and `_components/` (components), matching the existing layout.
- TDD: failing test first, then minimal implementation.

---

## File Structure

| File | Responsibility | Action |
|------|----------------|--------|
| `ui/app/(prowler)/attack-paths/(workflow)/query-builder/_lib/get-attack-paths-view-state.ts` | Pure deriver + progress helper + view-state enum | Create |
| `…/_lib/get-attack-paths-view-state.test.ts` | Unit tests (all states, precedence, progress) | Create |
| `…/_components/attack-paths-status-panel.tsx` | Presentational panel (copy/CTA per state) | Create |
| `…/_components/attack-paths-status-panel.test.tsx` | RTL tests (copy/CTA/Retry/progress) | Create |
| `…/attack-paths-page.fixtures.ts` | Add `scanRunning`/`graphBuilding`/`noGraphData` fixtures | Modify |
| `…/attack-paths-page.browser.test.tsx` | Full-page browser tests for the new states | Modify |
| `…/attack-paths-page.tsx` | Wire deriver + panel; add `loadError`; lift `loadScans`; drop unused `Link` import | Modify |
| `ui/CHANGELOG.md` | Changelog entry | Modify |

All commands below are run from `ui/` unless stated otherwise.

---

### Task 1: Pure view-state deriver

**Files:**
- Create: `ui/app/(prowler)/attack-paths/(workflow)/query-builder/_lib/get-attack-paths-view-state.ts`
- Test: `ui/app/(prowler)/attack-paths/(workflow)/query-builder/_lib/get-attack-paths-view-state.test.ts`

- [ ] **Step 1: Write the failing test**

Create `…/_lib/get-attack-paths-view-state.test.ts`:

```ts
import { describe, expect, it } from "vitest";

import type { AttackPathScan, ScanState } from "@/types/attack-paths";

import {
  ATTACK_PATHS_VIEW_STATES,
  getAttackPathsViewState,
  getGraphBuildingProgress,
} from "./get-attack-paths-view-state";

const scan = (
  state: ScanState,
  graph_data_ready: boolean,
  progress = 0,
): AttackPathScan => ({
  type: "attack-paths-scans",
  id: `${state}-${String(graph_data_ready)}-${progress}`,
  attributes: {
    state,
    progress,
    graph_data_ready,
    provider_alias: "Provider",
    provider_type: "aws",
    provider_uid: "123456789012",
    inserted_at: "2026-04-21T10:00:00Z",
    started_at: "2026-04-21T10:00:00Z",
    completed_at: null,
    duration: null,
  },
  relationships: {
    provider: { data: { type: "providers", id: "p" } },
    scan: { data: { type: "scans", id: "s" } },
    task: { data: { type: "tasks", id: "t" } },
  },
});

describe("getAttackPathsViewState", () => {
  it("returns loading while scans are loading, regardless of other inputs", () => {
    expect(
      getAttackPathsViewState({ scansLoading: true, loadError: true, scans: [] }),
    ).toBe(ATTACK_PATHS_VIEW_STATES.LOADING);
  });

  it("returns error on load failure (error wins over empty scans)", () => {
    expect(
      getAttackPathsViewState({ scansLoading: false, loadError: true, scans: [] }),
    ).toBe(ATTACK_PATHS_VIEW_STATES.ERROR);
  });

  it("returns no-scans for an empty list", () => {
    expect(
      getAttackPathsViewState({ scansLoading: false, loadError: false, scans: [] }),
    ).toBe(ATTACK_PATHS_VIEW_STATES.NO_SCANS);
  });

  it("returns ready when any provider has a queryable graph", () => {
    expect(
      getAttackPathsViewState({
        scansLoading: false,
        loadError: false,
        scans: [scan("executing", false, 50), scan("completed", true, 100)],
      }),
    ).toBe(ATTACK_PATHS_VIEW_STATES.READY);
  });

  it("returns graph-building when none ready and some scan is executing (wins over scheduled)", () => {
    expect(
      getAttackPathsViewState({
        scansLoading: false,
        loadError: false,
        scans: [scan("scheduled", false), scan("executing", false, 30)],
      }),
    ).toBe(ATTACK_PATHS_VIEW_STATES.GRAPH_BUILDING);
  });

  it("returns scan-running when none ready and some scan is scheduled/available", () => {
    expect(
      getAttackPathsViewState({
        scansLoading: false,
        loadError: false,
        scans: [scan("scheduled", false)],
      }),
    ).toBe(ATTACK_PATHS_VIEW_STATES.SCAN_RUNNING);
    expect(
      getAttackPathsViewState({
        scansLoading: false,
        loadError: false,
        scans: [scan("available", false)],
      }),
    ).toBe(ATTACK_PATHS_VIEW_STATES.SCAN_RUNNING);
  });

  it("returns no-graph-data when none ready and all scans are terminal", () => {
    expect(
      getAttackPathsViewState({
        scansLoading: false,
        loadError: false,
        scans: [scan("completed", false), scan("failed", false)],
      }),
    ).toBe(ATTACK_PATHS_VIEW_STATES.NO_GRAPH_DATA);
  });
});

describe("getGraphBuildingProgress", () => {
  it("returns the max progress among executing scans", () => {
    expect(
      getGraphBuildingProgress([
        scan("executing", false, 30),
        scan("executing", false, 70),
        scan("scheduled", false, 99),
      ]),
    ).toBe(70);
  });

  it("returns 0 when no scan is executing", () => {
    expect(getGraphBuildingProgress([scan("scheduled", false, 50)])).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run --project unit "app/(prowler)/attack-paths/(workflow)/query-builder/_lib/get-attack-paths-view-state.test.ts"`
Expected: FAIL — cannot resolve `./get-attack-paths-view-state`.

- [ ] **Step 3: Write minimal implementation**

Create `…/_lib/get-attack-paths-view-state.ts`:

```ts
import type { AttackPathScan } from "@/types/attack-paths";
import { SCAN_STATES } from "@/types/attack-paths";

export const ATTACK_PATHS_VIEW_STATES = {
  LOADING: "loading",
  ERROR: "error",
  NO_SCANS: "no-scans",
  SCAN_RUNNING: "scan-running",
  GRAPH_BUILDING: "graph-building",
  NO_GRAPH_DATA: "no-graph-data",
  READY: "ready",
} as const;

export type AttackPathsViewState =
  (typeof ATTACK_PATHS_VIEW_STATES)[keyof typeof ATTACK_PATHS_VIEW_STATES];

interface GetAttackPathsViewStateInput {
  scansLoading: boolean;
  loadError: boolean;
  scans: AttackPathScan[];
}

/**
 * Single source of truth for what the Attack Paths page shows. The full-page
 * message owns every "not queryable yet" state; the workflow renders only once
 * at least one provider's graph is ready.
 */
export const getAttackPathsViewState = ({
  scansLoading,
  loadError,
  scans,
}: GetAttackPathsViewStateInput): AttackPathsViewState => {
  if (scansLoading) return ATTACK_PATHS_VIEW_STATES.LOADING;
  if (loadError) return ATTACK_PATHS_VIEW_STATES.ERROR;
  if (scans.length === 0) return ATTACK_PATHS_VIEW_STATES.NO_SCANS;

  if (scans.some((s) => s.attributes.graph_data_ready)) {
    return ATTACK_PATHS_VIEW_STATES.READY;
  }
  if (scans.some((s) => s.attributes.state === SCAN_STATES.EXECUTING)) {
    return ATTACK_PATHS_VIEW_STATES.GRAPH_BUILDING;
  }
  if (
    scans.some(
      (s) =>
        s.attributes.state === SCAN_STATES.SCHEDULED ||
        s.attributes.state === SCAN_STATES.AVAILABLE,
    )
  ) {
    return ATTACK_PATHS_VIEW_STATES.SCAN_RUNNING;
  }
  return ATTACK_PATHS_VIEW_STATES.NO_GRAPH_DATA;
};

/** Highest progress among scans whose graph is actively building. */
export const getGraphBuildingProgress = (scans: AttackPathScan[]): number =>
  scans
    .filter((s) => s.attributes.state === SCAN_STATES.EXECUTING)
    .reduce((max, s) => Math.max(max, s.attributes.progress), 0);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run --project unit "app/(prowler)/attack-paths/(workflow)/query-builder/_lib/get-attack-paths-view-state.test.ts"`
Expected: PASS (9 tests).

- [ ] **Step 5: Commit**

```bash
git add "ui/app/(prowler)/attack-paths/(workflow)/query-builder/_lib/get-attack-paths-view-state.ts" "ui/app/(prowler)/attack-paths/(workflow)/query-builder/_lib/get-attack-paths-view-state.test.ts"
git commit -m "feat(ui): derive attack-paths page view-state from scan status"
```

---

### Task 2: Status panel component

**Files:**
- Create: `ui/app/(prowler)/attack-paths/(workflow)/query-builder/_components/attack-paths-status-panel.tsx`
- Test: `ui/app/(prowler)/attack-paths/(workflow)/query-builder/_components/attack-paths-status-panel.test.tsx`

- [ ] **Step 1: Write the failing test**

Create `…/_components/attack-paths-status-panel.test.tsx`:

```tsx
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ATTACK_PATHS_VIEW_STATES } from "../_lib/get-attack-paths-view-state";

import { AttackPathsStatusPanel } from "./attack-paths-status-panel";

describe("AttackPathsStatusPanel", () => {
  it("renders the no-scans message with a link to Scan Jobs", () => {
    render(<AttackPathsStatusPanel state={ATTACK_PATHS_VIEW_STATES.NO_SCANS} />);
    expect(screen.getByText(/no scans available/i)).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /go to scan jobs/i }),
    ).toHaveAttribute("href", "/scans");
  });

  it("renders the scan-running message", () => {
    render(
      <AttackPathsStatusPanel state={ATTACK_PATHS_VIEW_STATES.SCAN_RUNNING} />,
    );
    expect(screen.getByText(/scan in progress/i)).toBeInTheDocument();
  });

  it("renders the graph-building message with progress", () => {
    render(
      <AttackPathsStatusPanel
        state={ATTACK_PATHS_VIEW_STATES.GRAPH_BUILDING}
        progress={45}
      />,
    );
    expect(screen.getByText(/preparing attack paths data/i)).toBeInTheDocument();
    expect(screen.getByText(/45%/)).toBeInTheDocument();
  });

  it("renders the no-graph-data message", () => {
    render(
      <AttackPathsStatusPanel state={ATTACK_PATHS_VIEW_STATES.NO_GRAPH_DATA} />,
    );
    expect(screen.getByText(/no attack paths data/i)).toBeInTheDocument();
  });

  it("renders the error message and calls onRetry when Retry is clicked", () => {
    const onRetry = vi.fn();
    render(
      <AttackPathsStatusPanel
        state={ATTACK_PATHS_VIEW_STATES.ERROR}
        onRetry={onRetry}
      />,
    );
    expect(screen.getByText(/couldn.t load scans/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /retry/i }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it("renders nothing for the ready state", () => {
    const { container } = render(
      <AttackPathsStatusPanel state={ATTACK_PATHS_VIEW_STATES.READY} />,
    );
    expect(container).toBeEmptyDOMElement();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run --project unit "app/(prowler)/attack-paths/(workflow)/query-builder/_components/attack-paths-status-panel.test.tsx"`
Expected: FAIL — cannot resolve `./attack-paths-status-panel`.

- [ ] **Step 3: Write minimal implementation**

Create `…/_components/attack-paths-status-panel.tsx`:

```tsx
import { CircleAlert, Info } from "lucide-react";
import Link from "next/link";

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
} from "@/components/shadcn";

import {
  ATTACK_PATHS_VIEW_STATES,
  type AttackPathsViewState,
} from "../_lib/get-attack-paths-view-state";

interface AttackPathsStatusPanelProps {
  state: AttackPathsViewState;
  progress?: number;
  onRetry?: () => void;
}

/**
 * Full-page status message shown whenever the Attack Paths graph is not yet
 * queryable. The page renders the normal workflow instead once `state` is
 * `READY` (this component renders nothing for `READY`/`LOADING`).
 */
export const AttackPathsStatusPanel = ({
  state,
  progress = 0,
  onRetry,
}: AttackPathsStatusPanelProps) => {
  if (state === ATTACK_PATHS_VIEW_STATES.ERROR) {
    return (
      <Alert variant="error">
        <CircleAlert className="size-4" />
        <AlertTitle>Couldn&apos;t load scans</AlertTitle>
        <AlertDescription className="flex flex-col items-start gap-3">
          <span>Something went wrong loading your scans.</span>
          {onRetry ? (
            <Button variant="outline" size="sm" onClick={onRetry}>
              Retry
            </Button>
          ) : null}
        </AlertDescription>
      </Alert>
    );
  }

  if (state === ATTACK_PATHS_VIEW_STATES.NO_SCANS) {
    return (
      <Alert variant="info">
        <Info className="size-4" />
        <AlertTitle>No scans available</AlertTitle>
        <AlertDescription>
          <span>
            You need to run a scan before you can analyze attack paths.{" "}
            <Link href="/scans" className="font-medium underline">
              Go to Scan Jobs
            </Link>
          </span>
        </AlertDescription>
      </Alert>
    );
  }

  if (state === ATTACK_PATHS_VIEW_STATES.SCAN_RUNNING) {
    return (
      <Alert variant="info">
        <Info className="size-4" />
        <AlertTitle>Scan in progress</AlertTitle>
        <AlertDescription>
          <span>
            Your scan is running. Attack Paths will be available once it
            completes.
          </span>
        </AlertDescription>
      </Alert>
    );
  }

  if (state === ATTACK_PATHS_VIEW_STATES.GRAPH_BUILDING) {
    return (
      <Alert variant="info">
        <Info className="size-4" />
        <AlertTitle>Preparing Attack Paths data</AlertTitle>
        <AlertDescription>
          <span>
            We&apos;re building the graph from your latest scan ({progress}%).
            This will be ready shortly.
          </span>
        </AlertDescription>
      </Alert>
    );
  }

  if (state === ATTACK_PATHS_VIEW_STATES.NO_GRAPH_DATA) {
    return (
      <Alert variant="info">
        <Info className="size-4" />
        <AlertTitle>No Attack Paths data</AlertTitle>
        <AlertDescription>
          <span>Your scan completed but didn&apos;t produce graph data.</span>
        </AlertDescription>
      </Alert>
    );
  }

  return null;
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run --project unit "app/(prowler)/attack-paths/(workflow)/query-builder/_components/attack-paths-status-panel.test.tsx"`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add "ui/app/(prowler)/attack-paths/(workflow)/query-builder/_components/attack-paths-status-panel.tsx" "ui/app/(prowler)/attack-paths/(workflow)/query-builder/_components/attack-paths-status-panel.test.tsx"
git commit -m "feat(ui): add attack-paths status panel for waiting states"
```

---

### Task 3: Add fixtures for the new states

**Files:**
- Modify: `ui/app/(prowler)/attack-paths/(workflow)/query-builder/attack-paths-page.fixtures.ts`

- [ ] **Step 1: Add three fixture builders**

In `attack-paths-page.fixtures.ts`, insert these builders immediately after `emptyScans` (after its closing `});`, currently line 144):

```ts
export const scanRunning = (): PageFixture => ({
  scans: [
    buildScan(TYPICAL_SCAN_ID, {
      state: "scheduled",
      progress: 0,
      graph_data_ready: false,
      completed_at: null,
      duration: null,
    }),
  ],
  scanId: TYPICAL_SCAN_ID,
  queries: [],
  queryId: DEFAULT_QUERY_ID,
  queryResult: null,
});

export const graphBuilding = (): PageFixture => ({
  scans: [
    buildScan(TYPICAL_SCAN_ID, {
      state: "executing",
      progress: 45,
      graph_data_ready: false,
      completed_at: null,
      duration: null,
    }),
  ],
  scanId: TYPICAL_SCAN_ID,
  queries: [],
  queryId: DEFAULT_QUERY_ID,
  queryResult: null,
});

export const noGraphData = (): PageFixture => ({
  scans: [
    buildScan(TYPICAL_SCAN_ID, {
      state: "completed",
      progress: 100,
      graph_data_ready: false,
    }),
  ],
  scanId: TYPICAL_SCAN_ID,
  queries: [],
  queryId: DEFAULT_QUERY_ID,
  queryResult: null,
});
```

- [ ] **Step 2: Register them in the `fixtures` aggregator**

Replace the existing `fixtures` object at the bottom of the file:

```ts
export const fixtures = {
  typical,
  emptyScans,
  emptyGraph,
  singleNode,
  findingsOnly,
  resourcesOnly,
  disconnected,
  large,
  edgeCases,
};
```

with:

```ts
export const fixtures = {
  typical,
  emptyScans,
  scanRunning,
  graphBuilding,
  noGraphData,
  emptyGraph,
  singleNode,
  findingsOnly,
  resourcesOnly,
  disconnected,
  large,
  edgeCases,
};
```

- [ ] **Step 3: Typecheck the fixtures**

Run: `pnpm run typecheck`
Expected: PASS (no errors). This only verifies the new builders compile; they're exercised in Task 4.

- [ ] **Step 4: Commit**

```bash
git add "ui/app/(prowler)/attack-paths/(workflow)/query-builder/attack-paths-page.fixtures.ts"
git commit -m "test(ui): add attack-paths fixtures for running/building/no-graph states"
```

---

### Task 4: Wire the deriver + panel into the page (TDD via browser tests)

**Files:**
- Modify: `ui/app/(prowler)/attack-paths/(workflow)/query-builder/attack-paths-page.browser.test.tsx`
- Modify: `ui/app/(prowler)/attack-paths/(workflow)/query-builder/attack-paths-page.tsx`

- [ ] **Step 1: Write the failing browser tests**

In `attack-paths-page.browser.test.tsx`, add this `describe` block immediately after the existing `describe("loading the page", …)` block (after its closing `});`, currently line 76):

```tsx
describe("waiting states", () => {
  test("a running scan shows the scan-in-progress message", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.scanRunning());
    expect(await graph.emptyStateMessage()).toMatch(/scan in progress/i);
  });

  test("a building graph shows the preparing message with progress", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.graphBuilding());
    const message = await graph.emptyStateMessage();
    expect(message).toMatch(/preparing attack paths data/i);
    expect(message).toMatch(/45%/);
  });

  test("a completed scan with no graph shows the no-data message", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.noGraphData());
    expect(await graph.emptyStateMessage()).toMatch(/no attack paths data/i);
  });
});
```

- [ ] **Step 2: Run the browser tests to verify they fail**

Run: `pnpm vitest run --project browser "app/(prowler)/attack-paths/(workflow)/query-builder/attack-paths-page.browser.test.tsx" -t "waiting states"`
Expected: FAIL — the page currently renders the scan table for these fixtures, so no matching `[role="alert"]` message appears (`emptyStateMessage` times out / text mismatch).

> If the browser project can't launch Chromium locally, install it once: `pnpm run test:e2e:install`.

- [ ] **Step 3: Add the `loadError` state**

In `attack-paths-page.tsx`, after the `scans` state declaration (line 72), add:

```tsx
  const [loadError, setLoadError] = useState(false);
```

- [ ] **Step 4: Lift `loadScans` to component scope and set/clear `loadError`**

Replace the mount effect (currently lines 100–120):

```tsx
  // Load available scans on mount
  useEffect(() => {
    const loadScans = async () => {
      setScansLoading(true);
      try {
        const scansData = await getAttackPathScans();
        if (scansData?.data) {
          setScans(scansData.data);
        } else {
          setScans([]);
        }
      } catch (error) {
        console.error("Failed to load scans:", error);
        setScans([]);
      } finally {
        setScansLoading(false);
      }
    };

    loadScans();
  }, []);
```

with:

```tsx
  // Load available scans; reused by the error-state Retry action.
  const loadScans = async () => {
    setScansLoading(true);
    setLoadError(false);
    try {
      const scansData = await getAttackPathScans();
      if (scansData?.data) {
        setScans(scansData.data);
      } else {
        setScans([]);
        setLoadError(true);
      }
    } catch (error) {
      console.error("Failed to load scans:", error);
      setScans([]);
      setLoadError(true);
    } finally {
      setScansLoading(false);
    }
  };

  useEffect(() => {
    loadScans();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps -- run loadScans once on mount
```

- [ ] **Step 5: Compute the view-state**

In `attack-paths-page.tsx`, immediately after the `hasExecutingScan` declaration (currently ends at line 127), add:

```tsx
  const viewState = getAttackPathsViewState({ scansLoading, loadError, scans });
```

- [ ] **Step 6: Replace the empty-state ternary head with the panel branch**

Replace this block (currently lines 389–406):

```tsx
      {scansLoading ? (
        <div className="minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full flex-col gap-4 overflow-auto border p-4">
          <p className="text-sm">Loading scans...</p>
        </div>
      ) : scans.length === 0 ? (
        <Alert variant="info">
          <Info className="size-4" />
          <AlertTitle>No scans available</AlertTitle>
          <AlertDescription>
            <span>
              You need to run a scan before you can analyze attack paths.{" "}
              <Link href="/scans" className="font-medium underline">
                Go to Scan Jobs
              </Link>
            </span>
          </AlertDescription>
        </Alert>
      ) : (
```

with:

```tsx
      {viewState === ATTACK_PATHS_VIEW_STATES.LOADING ? (
        <div className="minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full flex-col gap-4 overflow-auto border p-4">
          <p className="text-sm">Loading scans...</p>
        </div>
      ) : viewState !== ATTACK_PATHS_VIEW_STATES.READY ? (
        <AttackPathsStatusPanel
          state={viewState}
          progress={getGraphBuildingProgress(scans)}
          onRetry={loadScans}
        />
      ) : (
```

(The large workflow `<>…</>` block — the final ternary branch and everything after it — is unchanged.)

- [ ] **Step 7: Add the new imports and drop the now-unused `Link` import**

Delete this line (currently line 4):

```tsx
import Link from "next/link";
```

Add these imports (placement is not critical — `pnpm run lint:fix` re-sorts imports in Step 9):

```tsx
import { AttackPathsStatusPanel } from "./_components/attack-paths-status-panel";
import {
  ATTACK_PATHS_VIEW_STATES,
  getAttackPathsViewState,
  getGraphBuildingProgress,
} from "./_lib/get-attack-paths-view-state";
```

> Do NOT add these to the `./_components` or `./_lib` barrels — import from the direct file paths above (no-barrel rule).

- [ ] **Step 8: Run the browser tests to verify they pass**

Run: `pnpm vitest run --project browser "app/(prowler)/attack-paths/(workflow)/query-builder/attack-paths-page.browser.test.tsx"`
Expected: PASS — the new "waiting states" tests pass AND the pre-existing "an account with no scans shows the empty state" test still passes (NO_SCANS → panel renders "No scans available").

- [ ] **Step 9: Typecheck, lint, and confirm no unused imports**

Run: `pnpm run typecheck && pnpm run lint:fix`
Expected: typecheck PASS; lint reports no `Link`-unused error and re-sorts the new imports. If lint flags `Link` as still imported, re-check Step 7.

- [ ] **Step 10: Commit**

```bash
git add "ui/app/(prowler)/attack-paths/(workflow)/query-builder/attack-paths-page.tsx" "ui/app/(prowler)/attack-paths/(workflow)/query-builder/attack-paths-page.browser.test.tsx"
git commit -m "fix(ui): show adaptive Attack Paths message for running, building and error states"
```

---

### Task 5: Changelog entry

**Files:**
- Modify: `ui/CHANGELOG.md`

- [ ] **Step 1: Invoke the changelog skill**

Invoke the `prowler-changelog` skill (auto-invoke rule for changelog edits). Follow its format: describe the user-visible WHAT, not the implementation HOW.

- [ ] **Step 2: Add a `### 🐞 Fixed` entry under the UNRELEASED section**

In `ui/CHANGELOG.md`, under `## [1.30.0] (Prowler UNRELEASED)` (which currently has only `### 🚀 Added`), add a `### 🐞 Fixed` subsection:

```markdown
### 🐞 Fixed

- Attack Paths now shows distinct messages while a scan is running or its graph is being built, plus a separate "couldn't load scans" error, instead of always showing "No scans available" [(#PR_NUMBER)](https://github.com/prowler-cloud/prowler/pull/PR_NUMBER)
```

Replace `PR_NUMBER` with the real pull request number when the PR is opened.

- [ ] **Step 3: Commit**

```bash
git add ui/CHANGELOG.md
git commit -m "docs(ui): changelog for adaptive attack-paths waiting message"
```

---

### Task 6: Full verification

- [ ] **Step 1: Run the full UI QA gate**

Run: `pnpm run healthcheck`
Expected: PASS (`typecheck` + `lint:check` + `format:check`). If `format:check` fails, run `pnpm run format:write` and re-commit.

- [ ] **Step 2: Run the affected unit + browser tests**

Run: `pnpm vitest run --project unit "app/(prowler)/attack-paths/(workflow)/query-builder/_lib/get-attack-paths-view-state.test.ts" "app/(prowler)/attack-paths/(workflow)/query-builder/_components/attack-paths-status-panel.test.tsx"`
Expected: PASS.

Run: `pnpm vitest run --project browser "app/(prowler)/attack-paths/(workflow)/query-builder/attack-paths-page.browser.test.tsx"`
Expected: PASS.

- [ ] **Step 3: Commit any formatting fixes**

```bash
git add -A && git commit -m "style(ui): formatting for attack-paths waiting message" || echo "nothing to commit"
```

---

## Self-Review

**1. Spec coverage:**
- 3 adaptive states (no-scans / scan-running / graph-building) → Tasks 1, 2, 4. ✅
- Split load-error → `loadError` state + `ERROR` view-state + panel error branch + Retry → Tasks 1, 2, 4. ✅
- `no-graph-data` 5th terminal state → Tasks 1, 2, 4. ✅
- Polling / auto-advance → unchanged `<AutoRefresh>` (mounted unconditionally; `hasExecutingScan` true for `SCHEDULED`/`EXECUTING`); recompute of `viewState` flips to `READY` when `graph_data_ready` turns true. No code needed — verified, not a gap. ✅
- Multi-provider rule (`READY` if any provider ready) → deriver `scans.some(graph_data_ready)` checked before non-ready states; test covers it. ✅
- Out of scope (non-AWS honesty) → intentionally excluded. ✅
- Changelog gate → Task 5. ✅

**2. Placeholder scan:** Only intentional placeholder is `PR_NUMBER` in the changelog (resolved at PR time) — flagged explicitly. No `TODO`/`TBD`/"handle edge cases"/uncoded references. ✅

**3. Type/name consistency:** `ATTACK_PATHS_VIEW_STATES`, `AttackPathsViewState`, `getAttackPathsViewState`, `getGraphBuildingProgress`, `AttackPathsStatusPanel` (props `state`/`progress`/`onRetry`), and fixture names `scanRunning`/`graphBuilding`/`noGraphData` are used identically across Tasks 1, 2, 3, 4. The deriver returns the const-object values; the panel and page import the same enum. ✅
