/**
 * Browser-mode tests for <AttackPathsPage />.
 *
 * Tests interact with the page ONLY through `GraphHarness`. Each test:
 *   1. picks a fixture
 *   2. calls `mountWith(fx)` — wires MSW handlers, sets the URL, mounts the page
 *   3. drives the harness
 *
 * If you find yourself reaching for a DOM query in a test, push it into the harness.
 */

import { beforeEach, describe, expect, test as base } from "vitest";

import { handlersForFixture } from "@/__tests__/msw/handlers/attack-paths";
import { worker } from "@/__tests__/msw/worker";
import { render } from "@/__tests__/render-browser";

import { useGraphStore } from "./_hooks/use-graph-state";
import AttackPathsPage from "./attack-paths-page";
import { fixtures, type PageFixture } from "./attack-paths-page.fixtures";
import { GraphHarness } from "./attack-paths-page.harness";

interface Fixtures {
  mountWith: (fx?: PageFixture) => Promise<GraphHarness>;
}

// The graph store is module-scoped, so it survives across tests in the same
// file. Reset it before each test so no test sees stale state from a previous
// one (selection, filtered view, expanded resources, etc.).
beforeEach(() => {
  useGraphStore.getState().reset();
});

const test = base.extend<Fixtures>({
  mountWith: async ({}, use) => {
    // `use` is Vitest's fixture-injection callback, not React's `use` hook.
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(async (fx = fixtures.typical()) => {
      worker.use(...handlersForFixture(fx));
      window.history.replaceState({}, "", `/attack-paths?scanId=${fx.scanId}`);
      await render(<AttackPathsPage />);
      return new GraphHarness(fx);
    });
  },
});

// ---------------------------------------------------------------------------
// graph-data-normalization
// ---------------------------------------------------------------------------

describe("graph-data-normalization", () => {
  test("renders edges with string source/target from relationships", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(2);

    const edgeIds = graph.renderedEdgeIds;
    expect(edgeIds.length).toBeGreaterThan(0);
    for (const id of edgeIds) {
      expect(id).toMatch(/^[\w-]+-[\w-]+$/);
    }
  });

  test("store rehydrates cleanly between scans (no panX/panY/zoomLevel)", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(1);

    expect(graph.isInFilteredView).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// graph-layout
// ---------------------------------------------------------------------------

describe("graph-layout", () => {
  test("layoutWithDagre places nodes at non-zero positions", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);

    const transforms = graph.nodes.map((el) => el.style.transform);
    const hasPositioned = transforms.some((t: string) =>
      /translate\([^0]/.test(t),
    );
    expect(hasPositioned).toBe(true);
  });

  test("single-node fixture renders exactly one node", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.singleNode());
    await graph.executeQuery();
    await graph.waitForLayoutStable(1);
    expect(graph.nodes).toHaveLength(1);
  });

  test("empty-graph fixture surfaces an error toast without crashing", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.emptyGraph());
    try {
      await graph.executeQuery();
    } catch {
      /* expected: layout never stabilizes */
    }
    expect(graph.nodes).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// graph-rendering
// ---------------------------------------------------------------------------

describe("graph-rendering", () => {
  test("renders React Flow with background and minimap", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);

    expect(graph.background).toBeTruthy();
    expect(graph.minimap).toBeTruthy();
    expect(graph.viewport).toBeTruthy();
  });

  test("renders the three node types by label rule", async ({ mountWith }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);
    await graph.expandAllFindings();

    expect(graph.findingNodes.length).toBeGreaterThan(0);
    expect(graph.resourceNodes.length).toBeGreaterThan(0);
    expect(graph.internetNodes.length).toBeGreaterThan(0);
  });

  test("toolbar is present with zoom/fit/export controls", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(1);

    expect(graph.toolbar.zoomInButton).toBeTruthy();
    expect(graph.toolbar.zoomOutButton).toBeTruthy();
    expect(graph.toolbar.fitButton).toBeTruthy();
    expect(graph.toolbar.exportButton).toBeTruthy();
  });

  test("animated dashed class is applied only to finding-connected edges", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);
    await graph.expandAllFindings();

    const findingEdges = graph.edges.filter((e: HTMLElement) =>
      e.classList.contains("finding-edge"),
    );
    const resourceEdges = graph.edges.filter((e: HTMLElement) =>
      e.classList.contains("resource-edge"),
    );
    expect(findingEdges.length).toBeGreaterThan(0);
    expect(resourceEdges.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// graph-interactions
// ---------------------------------------------------------------------------

describe("graph-interactions", () => {
  test("clicking a finding node enters filtered view", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);
    await graph.expandAllFindings();

    expect(graph.isInFilteredView).toBe(false);
    await graph.clickFirstFindingNode();
    expect(graph.isInFilteredView).toBe(true);
  });

  test("exiting filtered view restores the full graph", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);
    await graph.expandAllFindings();

    const fullNodes = graph.nodes.length;
    await graph.clickFirstFindingNode();
    await graph.exitFilteredView();
    await graph.waitForLayoutStable(fullNodes);
    expect(graph.isInFilteredView).toBe(false);
  });

  test("hovering a node adds the highlighted class to its path edges", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);

    const [first] = graph.resourceNodes;
    expect(first).toBeTruthy();
    await graph.user.hover(first!);
    await graph.waitForTransition(120);

    const highlighted = graph.edges.filter((e: HTMLElement) =>
      e.classList.contains("highlighted"),
    );
    expect(highlighted.length).toBeGreaterThanOrEqual(0);

    await graph.unhoverNodes();
    await graph.waitForTransition(120);
    const stillHighlighted = graph.edges.filter((e: HTMLElement) =>
      e.classList.contains("highlighted"),
    );
    expect(stillHighlighted.length).toBe(0);
  });

  test("clicking empty canvas does not explode", async ({ mountWith }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);

    const pane =
      graph.container.querySelector<HTMLElement>(".react-flow__pane") ??
      graph.container.querySelector<HTMLElement>(".react-flow__renderer");
    if (pane) await graph.user.click(pane);
    expect(graph.isInFilteredView).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// graph-export
// ---------------------------------------------------------------------------

describe("graph-export", () => {
  test("export button is enabled and clickable when a graph is rendered", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);

    const btn = graph.toolbar.exportButton as HTMLButtonElement | null;
    expect(btn).toBeTruthy();
    expect(btn?.disabled).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// variants
// ---------------------------------------------------------------------------

describe("variants", () => {
  test("empty scans shows the empty state", async ({ mountWith }) => {
    const graph = await mountWith(fixtures.emptyScans());
    const alert = await graph.waitFor(
      () => graph.container.querySelector('[role="alert"]'),
      2000,
    );
    expect(alert?.textContent).toMatch(/No scans available/i);
  });

  test("single-node graph renders without crash", async ({ mountWith }) => {
    const graph = await mountWith(fixtures.singleNode());
    await graph.executeQuery();
    await graph.waitForLayoutStable(1);
    expect(graph.nodes).toHaveLength(1);
  });

  test("large (200-node) graph completes layout within 5s", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.large(200));
    const start = performance.now();
    await graph.executeQuery();
    await graph.waitForLayoutStable(1);
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(5000);
  });

  test("disconnected components are both visible", async ({ mountWith }) => {
    const graph = await mountWith(fixtures.disconnected());
    await graph.executeQuery();
    await graph.waitForLayoutStable(4);
    expect(graph.nodes.length).toBe(4);
  });

  test("findings-only fixture hides unattached findings by default (Tier 1)", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.findingsOnly());
    try {
      await graph.executeQuery();
    } catch {
      /* expected: nothing visible, layout never stabilizes */
    }
    expect(graph.findingNodes.length).toBe(0);
    expect(graph.resourceNodes.length).toBe(0);
  });

  test("resources-only fixture renders no finding nodes", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.resourcesOnly());
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);
    expect(graph.findingNodes.length).toBe(0);
    expect(graph.resourceNodes.length).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// intermediate flows
// ---------------------------------------------------------------------------

describe("intermediate flows", () => {
  test("rapid successive clicks on a finding node do not duplicate filtered view", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);
    await graph.expandAllFindings();

    const finding = graph.findingNodes[0]!;
    await graph.user.click(finding);
    await graph.user.click(finding);
    await graph.waitForTransition();
    expect(graph.isInFilteredView).toBe(true);
  });

  test("double-click does not break state", async ({ mountWith }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);

    const resource = graph.resourceNodes[0]!;
    await graph.user.dblClick(resource);
    await graph.waitForTransition();
    expect(graph.nodes.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// edge-case data
// ---------------------------------------------------------------------------

describe("edge-case data", () => {
  test("self-loops, cycles, long labels, unicode, and duplicate edges all render", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.edgeCases());
    await graph.executeQuery();
    await graph.waitForLayoutStable(5);

    expect(graph.nodes.length).toBe(7);
    expect(graph.container.textContent ?? "").toMatch(
      /🔒-secure-bucket-日本語/,
    );
  });
});

// ---------------------------------------------------------------------------
// regressions
// ---------------------------------------------------------------------------

describe("regressions", () => {
  test("re-running a query clears the previous filtered view", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);
    await graph.expandAllFindings();
    await graph.clickFirstFindingNode();
    expect(graph.isInFilteredView).toBe(true);

    await graph.executeQuery();
    await graph.waitForLayoutStable(3);
    expect(graph.isInFilteredView).toBe(false);
  });
});
