/**
 * Test harness for <AttackPathsPage /> browser-mode tests.
 *
 * Selectors + flows only. Mounting and MSW setup live in the test file.
 */

import { vi } from "vitest";
import { userEvent } from "vitest/browser";

import type { PageFixture } from "./attack-paths-page.fixtures";

export class GraphHarness {
  private static readonly NODE_SEL = ".react-flow__node";
  private static readonly EDGE_SEL = ".react-flow__edge";
  private static readonly VIEWPORT_SEL = ".react-flow__viewport";
  private static readonly MINIMAP_SEL = ".react-flow__minimap";
  private static readonly BACKGROUND_SEL = ".react-flow__background";

  private static isFindingElement(el: Element): boolean {
    return (
      el.classList.contains("react-flow__node-finding") ||
      el.getAttribute("data-nodetype") === "finding"
    );
  }

  private static isResourceElement(el: Element): boolean {
    return (
      el.classList.contains("react-flow__node-resource") ||
      el.getAttribute("data-nodetype") === "resource"
    );
  }

  private static isInternetElement(el: Element): boolean {
    return (
      el.classList.contains("react-flow__node-internet") ||
      el.getAttribute("data-nodetype") === "internet"
    );
  }

  readonly user = userEvent;

  constructor(readonly fixture: PageFixture) {}

  // --- Container ---

  get container(): HTMLElement {
    return document.body;
  }

  // --- Collections ---

  get nodes(): HTMLElement[] {
    return Array.from(
      this.container.querySelectorAll<HTMLElement>(GraphHarness.NODE_SEL),
    );
  }

  get edges(): HTMLElement[] {
    return Array.from(
      this.container.querySelectorAll<HTMLElement>(GraphHarness.EDGE_SEL),
    );
  }

  get findingNodes(): HTMLElement[] {
    return this.nodes.filter(GraphHarness.isFindingElement);
  }

  get resourceNodes(): HTMLElement[] {
    return this.nodes.filter(GraphHarness.isResourceElement);
  }

  get internetNodes(): HTMLElement[] {
    return this.nodes.filter(GraphHarness.isInternetElement);
  }

  get renderedNodeIds(): string[] {
    return this.nodes.map((el) => el.getAttribute("data-id") ?? "");
  }

  get renderedEdgeIds(): string[] {
    return this.edges.map((el) => el.getAttribute("data-id") ?? "");
  }

  // --- Predicates ---

  get isInFilteredView(): boolean {
    return !!this.container.querySelector(
      '[aria-label="Return to full graph view"]',
    );
  }

  isNodeSelected(nodeId: string): boolean {
    const el = this.getNodeById(nodeId);
    return !!el && el.classList.contains("selected");
  }

  isEdgeHighlighted(edgeId: string): boolean {
    const el = this.getEdgeById(edgeId);
    return !!el && el.classList.contains("highlighted");
  }

  isNodeHidden(nodeId: string): boolean {
    return !this.getNodeById(nodeId);
  }

  // --- Lookups ---

  getNodeById(id: string): HTMLElement | null {
    return this.container.querySelector<HTMLElement>(
      `${GraphHarness.NODE_SEL}[data-id="${id}"]`,
    );
  }

  getEdgeById(id: string): HTMLElement | null {
    return this.container.querySelector<HTMLElement>(
      `${GraphHarness.EDGE_SEL}[data-id="${id}"]`,
    );
  }

  // --- Handles ---

  private q(selector: string): HTMLElement | null {
    return this.container.querySelector<HTMLElement>(selector);
  }

  get toolbar() {
    return {
      zoomInButton: this.q('button[aria-label="Zoom in"]'),
      zoomOutButton: this.q('button[aria-label="Zoom out"]'),
      fitButton: this.q('button[aria-label="Fit graph to view"]'),
      exportButton:
        this.q('button[aria-label="Export graph"]') ??
        this.q('button[aria-label="Export available soon"]'),
      backToFullViewButton: this.q(
        'button[aria-label="Return to full graph view"]',
      ),
      fullscreenButton: this.q('button[aria-label="Fullscreen"]'),
    };
  }

  get minimap(): HTMLElement | null {
    return this.q(GraphHarness.MINIMAP_SEL);
  }

  get background(): HTMLElement | null {
    return this.q(GraphHarness.BACKGROUND_SEL);
  }

  get viewport(): HTMLElement | null {
    return this.q(GraphHarness.VIEWPORT_SEL);
  }

  get fullscreenDialog(): HTMLElement | null {
    return document.querySelector<HTMLElement>('[role="dialog"]');
  }

  // --- Sync helpers ---

  /** Wait until React Flow has rendered at least `expected` node elements. */
  async waitForLayoutStable(expected = 1, timeoutMs = 3000): Promise<void> {
    await vi.waitFor(
      () => {
        if (this.nodes.length < expected) {
          throw new Error(
            `expected ${expected} nodes, got ${this.nodes.length}`,
          );
        }
      },
      { timeout: timeoutMs, interval: 16 },
    );
  }

  /** Wait until the predicate returns truthy and return that value. */
  async waitFor<T>(
    fn: () => T | null | undefined | false,
    timeoutMs = 3000,
  ): Promise<T> {
    return vi.waitFor(
      () => {
        const v = fn();
        if (!v) throw new Error("waitFor predicate not yet truthy");
        return v;
      },
      { timeout: timeoutMs, interval: 16 },
    ) as Promise<T>;
  }

  async waitForTransition(ms = 350): Promise<void> {
    await new Promise((r) => setTimeout(r, ms));
  }

  // --- Action methods ---

  async selectQuery(queryId?: string): Promise<void> {
    const trigger = await this.waitFor<HTMLButtonElement>(
      () =>
        this.container.querySelector<HTMLButtonElement>(
          'button[role="combobox"]',
        ),
      10000,
    );
    await this.user.click(trigger);

    const targetId = queryId ?? this.fixture.queryId;
    const targetName = this.fixture.queries.find((q) => q.id === targetId)
      ?.attributes.name;

    const option = await this.waitFor<HTMLElement>(
      () =>
        document.querySelector<HTMLElement>(
          `[role="option"][data-value="${targetId}"]`,
        ) ??
        Array.from(
          document.querySelectorAll<HTMLElement>('[role="option"]'),
        ).find((el) => targetName && el.textContent?.includes(targetName)),
      10000,
    );
    await this.user.click(option);
    await this.waitForTransition();
  }

  async executeQuery(options: { selectFirst?: boolean } = {}): Promise<void> {
    if (options.selectFirst !== false) {
      await this.selectQuery();
    }

    const button = await this.waitFor<HTMLButtonElement>(
      () =>
        Array.from(
          this.container.querySelectorAll<HTMLButtonElement>("button"),
        ).find(
          (b) =>
            !b.disabled &&
            /execute query/i.test(b.textContent ?? "") &&
            !/executing/i.test(b.textContent ?? ""),
        ),
      10000,
    );
    await this.user.click(button);
    await this.waitForLayoutStable(1, 10000);
  }

  async clickNode(nodeId: string): Promise<void> {
    const el = this.getNodeById(nodeId);
    if (!el) throw new Error(`clickNode: node "${nodeId}" not found`);
    await this.user.click(el);
    await this.waitForTransition();
  }

  async clickFirstFindingNode(): Promise<HTMLElement> {
    const [finding] = this.findingNodes;
    if (!finding) throw new Error("clickFirstFindingNode: no finding rendered");
    await this.user.click(finding);
    await this.waitForTransition();
    return finding;
  }

  async clickFirstResourceNode(): Promise<HTMLElement> {
    const [resource] = this.resourceNodes;
    if (!resource)
      throw new Error("clickFirstResourceNode: no resource rendered");
    await this.user.click(resource);
    await this.waitForTransition();
    return resource;
  }

  /**
   * Click every resource that the fixture's relationships connect to a finding.
   * Findings are hidden by default in the full graph view (Tier 1) — clicking
   * their adjacent resources reveals them.
   */
  async expandAllFindings(): Promise<void> {
    const findingIds = new Set(
      (this.fixture.queryResult?.nodes ?? [])
        .filter((n) =>
          n.labels.some((l) => l.toLowerCase().includes("finding")),
        )
        .map((n) => n.id),
    );
    const resourceWithFindingIds = new Set<string>();
    for (const rel of this.fixture.queryResult?.relationships ?? []) {
      if (findingIds.has(rel.source)) resourceWithFindingIds.add(rel.target);
      if (findingIds.has(rel.target)) resourceWithFindingIds.add(rel.source);
    }
    for (const id of Array.from(resourceWithFindingIds)) {
      const el = this.getNodeById(id);
      if (el) {
        await this.user.click(el);
        await this.waitForTransition(50);
      }
    }
  }

  async hoverNode(nodeId: string): Promise<void> {
    const el = this.getNodeById(nodeId);
    if (!el) throw new Error(`hoverNode: node "${nodeId}" not found`);
    await this.user.hover(el);
    await this.waitForTransition(80);
  }

  async unhoverNodes(): Promise<void> {
    const canvas =
      this.q(".react-flow__pane") ?? this.q(".react-flow__renderer");
    if (canvas) await this.user.hover(canvas);
    await this.waitForTransition(80);
  }

  async zoomIn(): Promise<void> {
    const btn = this.toolbar.zoomInButton;
    if (!btn) throw new Error("zoomIn: toolbar not rendered");
    await this.user.click(btn);
  }

  async zoomOut(): Promise<void> {
    const btn = this.toolbar.zoomOutButton;
    if (!btn) throw new Error("zoomOut: toolbar not rendered");
    await this.user.click(btn);
  }

  async fit(): Promise<void> {
    const btn = this.toolbar.fitButton;
    if (!btn) throw new Error("fit: toolbar not rendered");
    await this.user.click(btn);
  }

  async exitFilteredView(): Promise<void> {
    const btn = this.toolbar.backToFullViewButton;
    if (!btn) throw new Error("exitFilteredView: not in filtered view");
    await this.user.click(btn);
    await this.waitForTransition();
  }

  async openFullscreen(): Promise<void> {
    const btn = this.toolbar.fullscreenButton;
    if (!btn) throw new Error("openFullscreen: button not found");
    await this.user.click(btn);
    await this.waitFor(() => this.fullscreenDialog, 3000);
    await this.waitForTransition();
  }

  async closeFullscreen(): Promise<void> {
    const dialog = this.fullscreenDialog;
    if (!dialog) return;
    const close = dialog.querySelector<HTMLButtonElement>(
      'button[aria-label="Close"]',
    );
    if (close) await this.user.click(close);
    else await this.user.keyboard("{Escape}");
    await this.waitForTransition();
  }

  async exportAsPNG(target: "main" | "fullscreen" = "main"): Promise<void> {
    const scope =
      target === "fullscreen" ? this.fullscreenDialog : this.container;
    if (!scope) throw new Error("exportAsPNG: target scope missing");
    const btn = scope.querySelector<HTMLButtonElement>(
      'button[aria-label="Export graph"]',
    );
    if (!btn) throw new Error("exportAsPNG: export button disabled or missing");
    await this.user.click(btn);
    await this.waitForTransition(300);
  }
}
