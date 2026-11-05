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
    { width: 1400, columns: [2, 2] },
    { width: 1600, columns: [4] },
  ])(
    "lays out the Cloud cards as $columns at $width px with no gap on the right",
    async ({ width, columns }) => {
      const container = await renderAt(width, true);
      const rows = groupIntoRows(CLOUD_CARDS.map(cardRect));

      expect(rows.map((row) => row.length)).toEqual(columns);
      expectRowsFillTheWidth(rows, container);
    },
  );

  it.each([
    { width: 375, columns: [1, 1, 1] },
    { width: 700, columns: [2, 1] },
    { width: 1100, columns: [2, 1] },
    { width: 1300, columns: [3] },
  ])(
    "lays out the OSS cards as $columns at $width px with no gap on the right",
    async ({ width, columns }) => {
      const container = await renderAt(width, false);
      const rows = groupIntoRows(OSS_CARDS.map(cardRect));

      expect(rows.map((row) => row.length)).toEqual(columns);
      expectRowsFillTheWidth(rows, container);
    },
  );

  it("keeps the narrow cards at their 312px design width beside the wide ones", async () => {
    await renderAt(1600, true);

    expect(cardRect("Prowler ThreatScore").width).toBe(312);
    expect(cardRect("Exploitability").width).toBe(312);
    expect(cardRect("Check Findings").width).toBeGreaterThanOrEqual(420);
  });

  it.each([375, 640, 1100, 1600])(
    "keeps the Risk Severity bars readable in a %i px layout",
    async (width) => {
      await renderAt(width, true);
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

      expect(tracks).toHaveLength(5);
      for (const track of tracks) expect(track).toBeGreaterThanOrEqual(80);
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
      await renderAt(width, true);
      const items = Array.from(
        document.querySelectorAll('[aria-label*="failed findings"]'),
      ).map((item) => item.getBoundingClientRect());

      expect(items).toHaveLength(ATTACK_SURFACE_ITEMS);
      expect(groupIntoRows(items).map((row) => row.length)).toEqual(columns);
    },
  );
});
