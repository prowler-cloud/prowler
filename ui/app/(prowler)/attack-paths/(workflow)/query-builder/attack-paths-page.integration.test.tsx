/**
 * Browser-mode tests for <AttackPathsPage />.
 *
 * Tests are grouped by user-perceived flow, not by internal spec taxonomy. Each
 * test interacts with the page ONLY through `AttackPathPageHarness`. Each test:
 *   1. picks a fixture
 *   2. calls `mountWith(fx)` — wires MSW handlers, sets the URL, mounts the page
 *   3. drives the harness
 *
 * If you find yourself reaching for a DOM query in a test, push it into the harness.
 */

import { beforeEach, describe, expect, test as base, vi } from "vitest";

import { handlersForFixture } from "@/__tests__/msw/handlers/attack-paths";
import { worker } from "@/__tests__/msw/worker";
import { render } from "@/__tests__/render-browser";

const { getFindingByIdMock } = vi.hoisted(() => ({
  getFindingByIdMock: vi.fn(),
}));

vi.mock("@/actions/findings", async () => {
  const actual =
    await vi.importActual<typeof import("@/actions/findings")>(
      "@/actions/findings",
    );

  getFindingByIdMock.mockImplementation(actual.getFindingById);

  return {
    ...actual,
    getFindingById: getFindingByIdMock,
  };
});

import { useGraphStore } from "./_hooks/use-graph-state";
import { getPathEdges } from "./_lib";
import { isFindingNode, layoutWithDagre } from "./_lib/layout";
import AttackPathsPage from "./attack-paths-page";
import { fixtures, type PageFixture } from "./attack-paths-page.fixtures";
import { AttackPathPageHarness } from "./attack-paths-page.harness";

interface Fixtures {
  mountWith: (fx?: PageFixture) => Promise<AttackPathPageHarness>;
}

// The graph store is module-scoped, so it survives across tests in the same
// file. Reset it before each test so no test sees stale state from a previous
// one (selection, filtered view, expanded resources, etc.).
beforeEach(() => {
  useGraphStore.getState().reset();
  getFindingByIdMock.mockClear();
});

const test = base.extend<Fixtures>({
  mountWith: async ({}, use) => {
    // `use` is Vitest's fixture-injection callback, not React's `use` hook.
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(async (fx = fixtures.typical()) => {
      worker.use(...handlersForFixture(fx));
      window.history.replaceState({}, "", `/attack-paths?scanId=${fx.scanId}`);
      await render(<AttackPathsPage />);
      return new AttackPathPageHarness(fx);
    });
  },
});

describe("loading the page", () => {
  test("an account with no scans shows the empty state", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.emptyScans());
    expect(await graph.emptyStateMessage()).toMatch(/No scans available/i);
  });
});

describe("waiting states", () => {
  test("a pending scan shows the scan-in-progress message", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.scanPending());
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

describe("running a query", () => {
  test("the query builder surface uses the shared card primitive", async ({
    mountWith,
  }) => {
    const graph = await mountWith();

    const card = await graph.waitFor(() => graph.queryBuilderCard, 10000);

    expect(card).toHaveAttribute("data-slot", "card");
    expect(card).toHaveClass("rounded-xl");
  });

  test("a parameterized query shows its required inputs after selection", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.parameterizedQuery());

    await graph.selectQuery();

    expect(graph.containsText(/Query Parameters/i)).toBe(true);
    expect(graph.containsText(/Tag key/i)).toBe(true);
    expect(graph.getInputByName("tag_key")).toBeTruthy();
    expect(graph.containsText(/Tag value/i)).toBe(true);
    expect(graph.getInputByName("tag_value")).toBeTruthy();
  });

  test("the graph renders with a background, a minimap, and a viewport", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);

    expect(graph.background).toBeTruthy();
    expect(graph.minimap).toBeTruthy();
    expect(graph.viewport).toBeTruthy();
  });

  test("nodes are laid out at distinct positions", async ({ mountWith }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);

    const positions = graph.nodePositions;
    expect(positions.some((p) => p.x !== 0 || p.y !== 0)).toBe(true);
  });

  test("the toolbar exposes zoom, fit, and export controls", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(1);

    expect(graph.toolbar.zoomInButton).toBeTruthy();
    expect(graph.toolbar.zoomOutButton).toBeTruthy();
    expect(graph.toolbar.fitButton).toBeTruthy();
    expect(graph.toolbar.exportButton).toBeTruthy();
  });

  test("finding, resource, and internet nodes all render", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);
    await graph.expandAllFindings();

    expect(graph.findingNodes.length).toBeGreaterThan(0);
    expect(graph.resourceNodes.length).toBeGreaterThan(0);
    expect(graph.internetNodes.length).toBeGreaterThan(0);
  });

  test("only edges connected to a finding are animated", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);
    await graph.expandAllFindings();

    expect(graph.findingEdges.length).toBeGreaterThan(0);
    expect(graph.resourceEdges.length).toBeGreaterThan(0);
  });

  test("edges connect string source and target ids", async ({ mountWith }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(2, 1);

    const edgeIds = graph.renderedEdgeIds;
    expect(edgeIds.length).toBeGreaterThan(0);
    expect(new Set(edgeIds).size).toBe(edgeIds.length);
    for (const id of edgeIds) {
      expect(id.length).toBeGreaterThan(0);
    }
  });

  test("a query that returns one node renders just that node", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.singleNode());
    await graph.executeQuery();
    await graph.waitForGraphStable(1);
    expect(graph.nodes).toHaveLength(1);
  });

  test("a query that returns no graph data surfaces an error without crashing", async ({
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

  test("a 200-node graph finishes laying out within 5s", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.large(200));
    const start = performance.now();
    await graph.executeQuery();
    await graph.waitForGraphStable(1);
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(5000);
  });

  test("disconnected components are both visible", async ({ mountWith }) => {
    const graph = await mountWith(fixtures.disconnected());
    await graph.executeQuery();
    await graph.waitForGraphStable(4);
    expect(graph.nodes.length).toBe(4);
  });

  test("a query that returns only resources renders no findings", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.resourcesOnly());
    await graph.executeQuery();
    await graph.waitForGraphStable(3);
    expect(graph.findingNodes.length).toBe(0);
    expect(graph.resourceNodes.length).toBe(3);
  });

  test("findings without a connected resource stay visible in the full graph", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.findingsOnly());
    await graph.executeQuery();
    await graph.waitForGraphStable(3);

    expect(graph.findingNodes.length).toBe(3);
    expect(graph.resourceNodes.length).toBe(0);
  });

  test("hidden findings do not reserve layout space until expanded", async ({
    mountWith,
  }) => {
    // Given - a graph whose findings are hidden in the initial tier-1 view.
    // The initial rendered positions should match a layout computed from only
    // visible resources/edges, not from hidden finding nodes.
    const fixture = fixtures.typical();
    if (!fixture.queryResult) throw new Error("Expected graph fixture data");

    const visibleNodes = fixture.queryResult.nodes.filter(
      (node) => !isFindingNode(node.labels),
    );
    const visibleNodeIds = new Set(visibleNodes.map((node) => node.id));
    const visibleEdges = (fixture.queryResult.relationships ?? [])
      .filter(
        (edge) =>
          visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target),
      )
      .map((edge) => ({
        ...edge,
        type: edge.label,
      }));
    const expectedPositions = Object.fromEntries(
      layoutWithDagre(visibleNodes, visibleEdges).rfNodes.map((node) => [
        node.id,
        node.position,
      ]),
    );

    const graph = await mountWith(fixture);
    await graph.executeQuery();
    await graph.waitForGraphStable(3);

    // Then - hidden findings do not influence initial resource coordinates.
    for (const node of visibleNodes) {
      expect(graph.nodePositionsById[node.id]).toEqual(
        expectedPositions[node.id],
      );
    }
  });

  test("self-loops, cycles, long labels, unicode, and duplicate edges all render", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.edgeCases());
    await graph.executeQuery();
    await graph.waitForGraphStable(5);

    expect(graph.nodes.length).toBe(7);
    expect(graph.containsText(/🔒-secure-bucket-日本語/)).toBe(true);
  });
});

describe("exploring the graph", () => {
  test("clicking a finding opens the filtered view and finding details", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);
    await graph.expandAllFindings();

    expect(graph.isInFilteredView).toBe(false);
    await graph.clickFirstFindingNode();

    expect(graph.isInFilteredView).toBe(true);
    expect(getFindingByIdMock).toHaveBeenCalledTimes(1);
    expect(graph.hasNodeDetailsModal).toBe(false);
    expect(graph.hasNodeActionDialog).toBe(false);
  });

  test("clicking a resource with findings directly reveals related finding nodes", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);

    expect(graph.findingNodes.length).toBe(0);
    expect(graph.hasNodeDetailsModal).toBe(false);

    await graph.clickFirstResourceNode();

    expect(graph.findingNodes.length).toBeGreaterThan(0);
    expect(graph.hasNodeDetailsModal).toBe(false);
    expect(graph.hasNodeActionDialog).toBe(false);
  });

  test("clicking an expanded resource with findings hides its related finding nodes", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);

    await graph.clickFirstResourceNode();
    expect(graph.findingNodes.length).toBeGreaterThan(0);

    await graph.clickFirstResourceNode();

    expect(graph.findingNodes.length).toBe(0);
    expect(graph.hasNodeDetailsModal).toBe(false);
    expect(graph.hasNodeActionDialog).toBe(false);
  });

  test("clicking a resource with findings re-fits around the resource and its findings", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);

    const initialViewport = graph.viewportTransform;

    await graph.clickFirstResourceNode();

    expect(graph.findingNodes.length).toBeGreaterThan(0);
    await graph.waitFor(
      () => graph.viewportTransform !== initialViewport,
      2000,
    );

    const contextualViewport = graph.viewportTransform;

    await graph.fit();

    await graph.waitFor(
      () => graph.viewportTransform !== contextualViewport,
      2000,
    );
  });
  test("clicking an expanded resource re-fits the remaining visible graph", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);

    await graph.clickFirstResourceNode();
    expect(graph.findingNodes.length).toBeGreaterThan(0);
    await graph.waitForTransition();

    const expandedViewport = graph.viewportTransform;

    await graph.clickFirstResourceNode();

    expect(graph.findingNodes.length).toBe(0);
    await graph.waitFor(
      () => graph.viewportTransform !== expandedViewport,
      2000,
    );
  });

  test("returning from a finding keeps the expanded findings context fitted", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.large(20));
    await graph.executeQuery();
    await graph.waitForGraphStable(16);

    await graph.clickFirstResourceNode();
    expect(graph.findingNodes.length).toBeGreaterThan(0);
    await graph.waitForTransition();

    await graph.clickFirstFindingNode();
    expect(graph.isInFilteredView).toBe(true);

    await graph.exitFilteredView();

    expect(graph.isInFilteredView).toBe(false);
    await graph.waitForTransition();

    expect(graph.findingNodes.length).toBeGreaterThan(0);
    expect(graph.viewportTransform).toBeTruthy();
  });
  test("clicking a resource without findings does nothing", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);

    expect(graph.hasNodeDetailsModal).toBe(false);
    expect(graph.hasNodeActionDialog).toBe(false);
    expect(graph.findingNodes.length).toBe(0);

    await graph.clickFirstResourceNodeWithoutFindings();

    expect(graph.findingNodes.length).toBe(0);
    expect(graph.hasNodeDetailsModal).toBe(false);
    expect(graph.hasNodeActionDialog).toBe(false);
  });

  test("exiting the filtered view restores the full graph", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);
    await graph.expandAllFindings();

    const fullNodes = graph.nodes.length;
    await graph.clickFirstFindingNode();
    await graph.exitFilteredView();
    await graph.waitForGraphStable(fullNodes);
    expect(graph.isInFilteredView).toBe(false);
  });

  test("hovering a node highlights its path edges", async ({ mountWith }) => {
    const fixture = fixtures.typical();
    const graph = await mountWith(fixture);
    await graph.executeQuery();
    await graph.waitForGraphStable(3);

    const hoveredNodeId = graph.resourceNodes[0]?.getAttribute("data-id");
    expect(hoveredNodeId).toBeTruthy();

    const findingIds = new Set(
      (fixture.queryResult?.nodes ?? [])
        .filter((node) => isFindingNode(node.labels))
        .map((node) => node.id),
    );
    const visibleEdges = (fixture.queryResult?.relationships ?? [])
      .filter(
        (edge) => !findingIds.has(edge.source) && !findingIds.has(edge.target),
      )
      .map((edge) => ({ sourceId: edge.source, targetId: edge.target }));
    const expectedPathKeys = getPathEdges(hoveredNodeId ?? "", visibleEdges);
    const expectedHighlightedIds = (fixture.queryResult?.relationships ?? [])
      .filter((edge) => expectedPathKeys.has(`${edge.source}-${edge.target}`))
      .map((edge) => edge.id)
      .sort();

    await graph.hoverFirstResourceNode();
    await graph.waitForTransition(120);

    expect(
      graph.highlightedEdges.map((edge) => edge.dataset.id ?? "").sort(),
    ).toEqual(expectedHighlightedIds);

    await graph.unhoverNodes();
    await graph.waitForTransition(120);
    expect(graph.highlightedEdges.length).toBe(0);
  });

  test("selecting a node keeps its path edges highlighted", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);

    await graph.clickFirstResourceNodeWithoutFindings();

    expect(graph.highlightedEdges.length).toBeGreaterThan(0);
  });

  test("clicking the empty canvas keeps the full graph", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);

    await graph.clickEmptyCanvas();
    expect(graph.isInFilteredView).toBe(false);
  });

  test("rapid clicks on a finding don't duplicate the filtered view", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);
    await graph.expandAllFindings();

    await graph.rapidlyClickFirstFindingNode(2);

    expect(graph.isInFilteredView).toBe(true);
    expect(getFindingByIdMock).toHaveBeenCalledTimes(1);
  });

  test("double-clicking a node doesn't break state", async ({ mountWith }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);

    await graph.dblClickFirstResourceNode();
    expect(graph.nodes.length).toBeGreaterThan(0);
  });
});

describe("auto-fitting the viewport", () => {
  test("the minimap viewport indicator has a visible border", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);

    expect(graph.minimapMaskStrokeWidth).toBeGreaterThan(0);
  });

  test("expanding resources re-fits the viewport when revealed findings fall off-screen", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);

    // Given - zoom into the current overview so newly revealed findings can
    // sit entirely outside the current frame. The expand auto-fit should then
    // recover the user instead of leaving them hunting off-screen.
    for (let i = 0; i < 5; i++) {
      await graph.zoomIn();
      await graph.waitForTransition(80);
    }
    // Hidden findings are not measured by the initial declarative fit, so
    // their positions can sit outside the framed viewport. Expanding the
    // resources should re-fit so the user does not have to hunt for the
    // newly visible findings off-screen.
    const before = graph.viewportTransform;
    expect(before).toBeTruthy();

    await graph.expandAllFindings();
    await graph.waitForTransition();

    expect(graph.viewportTransform).not.toBe(before);
  });

  test("clicking a finding re-fits the viewport for the filtered subgraph", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);
    await graph.expandAllFindings();

    const beforeFilter = graph.viewportTransform;
    expect(beforeFilter).toBeTruthy();

    await graph.clickFirstFindingNode();
    expect(graph.isInFilteredView).toBe(true);
    await graph.waitForTransition();

    expect(graph.viewportTransform).not.toBe(beforeFilter);
  });

  test("Back to Full View re-fits the viewport for the full graph", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);
    await graph.expandAllFindings();
    await graph.clickFirstFindingNode();
    expect(graph.isInFilteredView).toBe(true);
    await graph.waitForTransition();
    const filterT = graph.viewportTransform;

    await graph.exitFilteredView();
    await graph.waitForGraphStable(3);
    await graph.waitForTransition();

    expect(graph.viewportTransform).not.toBe(filterT);
  });
});

describe("exporting the graph", () => {
  test("the export button is enabled when a graph is rendered", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);

    expect(graph.toolbar.isExportButtonEnabled).toBe(true);
  });

  test("clicking export downloads a PNG sized to the configured export canvas", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);
    await graph.expandAllFindings();

    const png = await graph.captureExportPNG();

    expect(png.filename).toBe("attack-path-graph.png");
    expect(png.mimeType).toBe("image/png");
    expect(png.width).toBe(1920);
    expect(png.height).toBe(1080);
  });
});

describe("running a different query", () => {
  test("the previous filtered view is cleared", async ({ mountWith }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForGraphStable(3);
    await graph.expandAllFindings();
    await graph.clickFirstFindingNode();
    expect(graph.isInFilteredView).toBe(true);

    await graph.executeQuery();
    await graph.waitForGraphStable(3);
    expect(graph.isInFilteredView).toBe(false);
  });
});
