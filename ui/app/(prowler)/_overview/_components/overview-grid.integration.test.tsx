import { describe, expect, it } from "vitest";
import { page } from "vitest/browser";

import { render } from "@/__tests__/render-browser";

import { OverviewSamplePreview } from "../sample-preview/overview-sample-preview";

// Card titles of the top row, in DOM order.
const CLOUD_CARDS = [
  "Prowler ThreatScore",
  "Exploitability",
  "Check Findings",
  "Risk Severity",
];
const OSS_CARDS = ["Prowler ThreatScore", "Check Findings", "Risk Severity"];
const ATTACK_SURFACE_ITEMS = 4;

// Cards that start on the same line, left to right.
function groupIntoRows(rects: DOMRect[]): DOMRect[][] {
  const rows = new Map<number, DOMRect[]>();
  for (const rect of rects) {
    const top = Math.round(rect.top);
    rows.set(top, [...(rows.get(top) ?? []), rect]);
  }
  return Array.from(rows.values(), (row) =>
    row.sort((a, b) => a.left - b.left),
  );
}

function cardRect(title: string): DOMRect {
  const heading = Array.from(
    document.querySelectorAll('[data-slot="card-title"]'),
  )
    .filter((node) => node.textContent?.trim() === title)
    .at(0);
  const card = heading?.closest('[data-slot="card"]');
  if (!card) throw new Error(`No card titled ${title}`);
  return card.getBoundingClientRect();
}

async function renderAt(width: number, showIssues: boolean) {
  // Wide enough for every case, so only the container decides the layout.
  await page.viewport(2000, 1000);
  await render(
    // Same marker <main> carries: sm..2xl resolve against this width.
    <div data-responsive-container className="@container" style={{ width }}>
      <OverviewSamplePreview showIssues={showIssues} />
    </div>,
  );
  await expect.element(page.getByText("Risk Severity")).toBeVisible();
  return document.querySelector("[data-responsive-container]")!;
}

function expectRowsFillTheWidth(rows: DOMRect[][], container: Element) {
  const { left, right } = container.getBoundingClientRect();
  for (const row of rows) {
    expect(Math.round(row[0].left)).toBe(Math.round(left));
    expect(Math.round(row.at(-1)!.right)).toBe(Math.round(right));
  }
}

describe("OverviewGrid top row", () => {
  it.each([
    { width: 375, columns: [1, 1, 1, 1] },
    { width: 700, columns: [2, 2] },
    { width: 1100, columns: [2, 2] },
    // A 16" MacBook Pro window with the sidebar open.
    { width: 1160, columns: [4] },
    { width: 1600, columns: [4] },
  ])(
    "lays out the Cloud cards as $columns at $width px with no gap on the right",
    async ({ width, columns }) => {
      // Given - Arrange
      const container = await renderAt(width, true);

      // When - Act
      const rows = groupIntoRows(CLOUD_CARDS.map(cardRect));

      // Then - Assert
      expect(rows.map((row) => row.length)).toEqual(columns);
      expectRowsFillTheWidth(rows, container);
    },
  );

  it.each([
    { width: 375, columns: [1, 1, 1] },
    { width: 700, columns: [2, 1] },
    { width: 1000, columns: [2, 1] },
    { width: 1100, columns: [3] },
  ])(
    "lays out the OSS cards as $columns at $width px with no gap on the right",
    async ({ width, columns }) => {
      // Given - Arrange
      const container = await renderAt(width, false);

      // When - Act
      const rows = groupIntoRows(OSS_CARDS.map(cardRect));

      // Then - Assert
      expect(rows.map((row) => row.length)).toEqual(columns);
      expectRowsFillTheWidth(rows, container);
    },
  );

  it("keeps the narrow cards wide enough for the ThreatScore gauge", async () => {
    // Given - Arrange
    await renderAt(1160, true);

    // When - Act
    const threatScore = cardRect("Prowler ThreatScore");
    const exploitability = cardRect("Exploitability");

    // Then - Assert
    expect(threatScore.width).toBeGreaterThanOrEqual(272);
    expect(exploitability.width).toBeGreaterThanOrEqual(272);
  });

  it.each([
    { width: 375, showIssues: true },
    { width: 700, showIssues: true },
    { width: 1160, showIssues: true },
    { width: 1600, showIssues: true },
    { width: 1100, showIssues: false },
  ])(
    "keeps every card's content inside its card at $width px",
    async ({ width, showIssues }) => {
      // Given - Arrange
      await renderAt(width, showIssues);

      // When - Act
      const cards = (showIssues ? CLOUD_CARDS : OSS_CARDS).map(
        (title) =>
          Array.from(document.querySelectorAll('[data-slot="card"]')).find(
            (node) =>
              node.querySelector('[data-slot="card-title"]')?.textContent ===
              title,
          )!,
      );
      const spilling = cards.flatMap((card) => {
        const bounds = card.getBoundingClientRect();
        return Array.from(card.querySelectorAll("*"))
          .map((node) => node.getBoundingClientRect())
          .filter(
            (rect) =>
              rect.width > 0 &&
              (rect.left < bounds.left - 0.5 ||
                rect.right > bounds.right + 0.5),
          );
      });

      // Then - Assert
      expect(spilling).toHaveLength(0);
    },
  );

  it.each([375, 640, 1160, 1600])(
    "keeps the Risk Severity bars readable in a %i px layout",
    async (width) => {
      // Given - Arrange
      await renderAt(width, true);

      // When - Act
      const card = Array.from(
        document.querySelectorAll('[data-slot="card"]'),
      ).find(
        (node) =>
          node.querySelector('[data-slot="card-title"]')?.textContent ===
          "Risk Severity",
      )!;
      // Each severity row is label | bar track | value.
      const tracks = Array.from(card.querySelectorAll('[role="button"]')).map(
        (row) => row.children[1].getBoundingClientRect().width,
      );

      // Then - Assert
      expect(tracks).toHaveLength(5);
      for (const track of tracks) expect(track).toBeGreaterThanOrEqual(60);
    },
  );
});

describe("Attack Surface", () => {
  it.each([
    { width: 375, columns: [1, 1, 1, 1] },
    { width: 900, columns: [2, 2] },
    { width: 1100, columns: [4] },
  ])(
    "never leaves an item alone on a row at $width px",
    async ({ width, columns }) => {
      // Given - Arrange
      await renderAt(width, true);

      // When - Act
      const items = Array.from(
        document.querySelectorAll('[aria-label*="failed findings"]'),
      ).map((item) => item.getBoundingClientRect());

      // Then - Assert
      expect(items).toHaveLength(ATTACK_SURFACE_ITEMS);
      expect(groupIntoRows(items).map((row) => row.length)).toEqual(columns);
    },
  );
});
