import type { ColumnDef } from "@tanstack/react-table";
import { afterEach, describe, expect, it, vi } from "vitest";
import { page, userEvent } from "vitest/browser";

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

  it("opens the upgrade prompt when clicking a blurred row without firing its actions", async () => {
    // Given
    await page.viewport(1280, 1800);
    const onLockedInteraction = vi.fn();
    const onRowAction = vi.fn();
    const onRowClick = vi.fn();
    const screen = await render(
      <div>
        <DataTable
          columns={[
            {
              accessorKey: "name",
              header: "Finding group",
              cell: ({ row }) => (
                <button type="button" onClick={onRowAction}>
                  {row.original.name}
                </button>
              ),
            },
          ]}
          data={Array.from({ length: 20 }, (_, index) => ({
            name: `Finding ${index + 1}`,
          }))}
          onRowClick={onRowClick}
          previewLock={{
            visibleRowCount: 10,
            overlay: <FindingsPreviewLock totalCount={20} />,
            onLockedInteraction,
          }}
        />
        <button type="button">After table</button>
      </div>,
    );

    // When: a real pointer click at the inert content's position, outside the card.
    await screen
      .getByText("Finding 20", { exact: true })
      .click({ force: true });

    // Then
    expect(onLockedInteraction).toHaveBeenCalledOnce();
    expect(onRowAction).not.toHaveBeenCalled();
    expect(onRowClick).not.toHaveBeenCalled();

    // When / Then: keyboard focus skips every blurred action, keeping the CTA usable.
    (
      screen
        .getByRole("button", { name: "Finding 10", exact: true })
        .element() as HTMLButtonElement
    ).focus();
    await userEvent.tab();
    await expect
      .element(screen.getByRole("button", { name: "Unlock All Findings" }))
      .toHaveFocus();
    await userEvent.tab();
    await expect
      .element(screen.getByRole("button", { name: "After table" }))
      .toHaveFocus();

    // Visible row actions still work.
    await screen
      .getByRole("button", { name: "Finding 1", exact: true })
      .click();
    expect(onRowAction).toHaveBeenCalledOnce();
  });
});
