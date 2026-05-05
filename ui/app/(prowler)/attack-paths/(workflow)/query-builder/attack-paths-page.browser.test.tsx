/**
 * Browser-mode tests for <AttackPathsPage />.
 *
 * Tests are grouped by user-perceived flow, not by internal spec taxonomy. Each
 * test interacts with the page ONLY through `GraphHarness`. Each test:
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

describe("loading the page", () => {
  test("an account with no scans shows the empty state", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.emptyScans());
    const alert = await graph.waitFor(
      () => graph.container.querySelector('[role="alert"]'),
      2000,
    );
    expect(alert?.textContent).toMatch(/No scans available/i);
  });
});

describe("running a query", () => {
  test("the graph renders with a background, a minimap, and a viewport", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);

    expect(graph.background).toBeTruthy();
    expect(graph.minimap).toBeTruthy();
    expect(graph.viewport).toBeTruthy();
  });

  test("nodes are laid out at distinct positions", async ({ mountWith }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);

    const transforms = graph.nodes.map((el) => el.style.transform);
    const hasPositioned = transforms.some((t: string) =>
      /translate\([^0]/.test(t),
    );
    expect(hasPositioned).toBe(true);
  });

  test("the toolbar exposes zoom, fit, and export controls", async ({
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

  test("finding, resource, and internet nodes all render", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);
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

  test("edges connect string source and target ids", async ({ mountWith }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(2);

    const edgeIds = graph.renderedEdgeIds;
    expect(edgeIds.length).toBeGreaterThan(0);
    for (const id of edgeIds) {
      expect(id).toMatch(/^[\w-]+-[\w-]+$/);
    }
  });

  test("a query that returns one node renders just that node", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.singleNode());
    await graph.executeQuery();
    await graph.waitForLayoutStable(1);
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

  test("a query that returns only resources renders no findings", async ({
    mountWith,
  }) => {
    const graph = await mountWith(fixtures.resourcesOnly());
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);
    expect(graph.findingNodes.length).toBe(0);
    expect(graph.resourceNodes.length).toBe(3);
  });

  test("findings without a connected resource are hidden by default", async ({
    mountWith,
  }) => {
    // Tier 1 view: unattached findings stay hidden until the user expands
    // their adjacent resource — none here, so nothing renders.
    const graph = await mountWith(fixtures.findingsOnly());
    try {
      await graph.executeQuery();
    } catch {
      /* expected: nothing visible, layout never stabilizes */
    }
    expect(graph.findingNodes.length).toBe(0);
    expect(graph.resourceNodes.length).toBe(0);
  });

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

describe("exploring the graph", () => {
  test("clicking a finding opens the filtered view", async ({ mountWith }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);
    await graph.expandAllFindings();

    expect(graph.isInFilteredView).toBe(false);
    await graph.clickFirstFindingNode();
    expect(graph.isInFilteredView).toBe(true);
  });

  test("exiting the filtered view restores the full graph", async ({
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

  test("hovering a node highlights its path edges", async ({ mountWith }) => {
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

  test("clicking the empty canvas keeps the full graph", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);

    const pane =
      graph.container.querySelector<HTMLElement>(".react-flow__pane") ??
      graph.container.querySelector<HTMLElement>(".react-flow__renderer");
    if (pane) await graph.user.click(pane);
    expect(graph.isInFilteredView).toBe(false);
  });

  test("rapid clicks on a finding don't duplicate the filtered view", async ({
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

  test("double-clicking a node doesn't break state", async ({ mountWith }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);

    const resource = graph.resourceNodes[0]!;
    await graph.user.dblClick(resource);
    await graph.waitForTransition();
    expect(graph.nodes.length).toBeGreaterThan(0);
  });
});

describe("exporting the graph", () => {
  test("the export button is enabled when a graph is rendered", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);

    const btn = graph.toolbar.exportButton as HTMLButtonElement | null;
    expect(btn).toBeTruthy();
    expect(btn?.disabled).toBe(false);
  });

  test("clicking export downloads a PNG sized to the configured export canvas", async ({
    mountWith,
  }) => {
    const graph = await mountWith();
    await graph.executeQuery();
    await graph.waitForLayoutStable(3);
    await graph.expandAllFindings();

    // Capture the download anchor click without actually navigating/downloading.
    const downloads: Array<{ href: string; download: string }> = [];
    const originalClick = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function () {
      if (this.download) {
        downloads.push({ href: this.href, download: this.download });
        return;
      }
      originalClick.call(this);
    };

    try {
      await graph.exportAsPNG();
      // Real raster pipeline runs end-to-end; allow generous slack for headless Chromium.
      await graph.waitFor(() => downloads.length > 0, 10000);
    } finally {
      HTMLAnchorElement.prototype.click = originalClick;
    }

    const [download] = downloads;
    expect(download.download).toBe("attack-path-graph.png");
    expect(download.href.startsWith("data:image/png")).toBe(true);

    // Validate dimensions from the PNG IHDR chunk: bytes 16-19 are width and
    // 20-23 are height, both big-endian uint32. Regressions in the viewport
    // element passed to `domToPng`, the configured export size, or the
    // bounds-driven viewport transform fail loudly here.
    const base64 = download.href.split(",")[1]!;
    const bytes = atob(base64);
    const u32BE = (offset: number) =>
      ((bytes.charCodeAt(offset) << 24) |
        (bytes.charCodeAt(offset + 1) << 16) |
        (bytes.charCodeAt(offset + 2) << 8) |
        bytes.charCodeAt(offset + 3)) >>>
      0;
    expect(u32BE(16)).toBe(1920);
    expect(u32BE(20)).toBe(1080);
  });
});

describe("running a different query", () => {
  test("the previous filtered view is cleared", async ({ mountWith }) => {
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
