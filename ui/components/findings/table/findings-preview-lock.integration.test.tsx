import type { ColumnDef } from "@tanstack/react-table";
import { afterEach, describe, expect, it, vi } from "vitest";
import { page } from "vitest/browser";

import { render } from "@/__tests__/render-browser";
import { DataTable } from "@/components/shadcn/table/data-table";
import { useCloudUpgradeStore } from "@/store";
import { PAID_PLAN_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { FindingsPreviewLock } from "./findings-preview-lock";

interface PreviewRow {
  name: string;
}

const columns: ColumnDef<PreviewRow>[] = [
  { accessorKey: "name", header: "Finding group" },
];

describe("Findings preview layout", () => {
  afterEach(async () => {
    useCloudUpgradeStore.getState().closeCloudUpgrade();
    await page.viewport(1280, 800);
  });

  it.each([
    { count: 11, width: 1280 },
    { count: 13, width: 1280 },
    { count: 20, width: 1280 },
    { count: 11, width: 375 },
    { count: 13, width: 375 },
    { count: 20, width: 375 },
  ])(
    "keeps the unlock card above pagination with $count groups at $width px",
    async ({ count, width }) => {
      // Given: filtered results may leave too few blurred rows to contain the card.
      await page.viewport(width, 1400);
      const screen = await render(
        <DataTable
          columns={columns}
          data={Array.from({ length: count }, (_, index) => ({
            name: `Finding ${index + 1}`,
          }))}
          metadata={{
            pagination: { page: 1, pages: 1, count },
            version: "v1",
          }}
          previewLock={{
            visibleRowCount: 10,
            overlay: <FindingsPreviewLock totalCount={count} />,
            onLockedInteraction: vi.fn(),
          }}
        />,
      );

      // When
      const card = screen.getByRole("region", { name: "Findings preview" });
      await expect.element(card).toBeVisible();
      const tableScrollport = screen
        .getByRole("table")
        .element().parentElement!;

      // Then: the CTA needs no hidden vertical scroll inside the table.
      await expect
        .poll(
          () =>
            card.element().getBoundingClientRect().bottom -
            tableScrollport.getBoundingClientRect().bottom,
        )
        .toBeLessThanOrEqual(0);
      expect(tableScrollport.scrollHeight).toBeLessThanOrEqual(
        tableScrollport.clientHeight,
      );

      await screen.getByRole("button", { name: "Unlock All Findings" }).click();
      expect(useCloudUpgradeStore.getState().activeFeature).toBe(
        PAID_PLAN_UPGRADE_FEATURE.FINDINGS_PREVIEW,
      );
    },
  );

  it("keeps the card visible when a wide table scrolls and the viewport shrinks", async () => {
    // Given
    await page.viewport(1280, 1400);
    const screen = await render(
      <DataTable
        columns={[
          {
            accessorKey: "name",
            header: "Finding group",
            cell: ({ row }) => (
              <span className="block min-w-[1600px]">{row.original.name}</span>
            ),
          },
        ]}
        data={Array.from({ length: 11 }, (_, index) => ({
          name: `Finding ${index + 1}`,
        }))}
        previewLock={{
          visibleRowCount: 10,
          overlay: <FindingsPreviewLock totalCount={11} />,
          onLockedInteraction: vi.fn(),
        }}
      />,
    );
    const card = screen.getByRole("region", { name: "Findings preview" });
    await expect.element(card).toBeVisible();
    const tableScrollport = screen.getByRole("table").element().parentElement!;
    const originalLeft = card.element().getBoundingClientRect().left;

    // When
    tableScrollport.scrollLeft = 400;

    // Then: horizontal scrolling preserves the card's position.
    expect(tableScrollport.scrollLeft).toBeGreaterThan(0);
    await expect
      .poll(() => card.element().getBoundingClientRect().left)
      .toBe(originalLeft);

    // When: wrapping makes the card taller after mount.
    await page.viewport(375, 1400);

    // Then: both the horizontal pin and the reserved height follow the resize.
    await expect
      .poll(
        () =>
          card.element().getBoundingClientRect().right -
          tableScrollport.getBoundingClientRect().right,
      )
      .toBeLessThanOrEqual(0);
    await expect
      .poll(
        () =>
          card.element().getBoundingClientRect().bottom -
          tableScrollport.getBoundingClientRect().bottom,
      )
      .toBeLessThanOrEqual(0);
    expect(tableScrollport.scrollHeight).toBeLessThanOrEqual(
      tableScrollport.clientHeight,
    );
    await screen.getByRole("button", { name: "Unlock All Findings" }).click();
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      PAID_PLAN_UPGRADE_FEATURE.FINDINGS_PREVIEW,
    );
  });
});
