import { describe, expect, it } from "vitest";

import { localPage, matchesFilter, toTableMetadata } from "./demo-list";

const rows = Array.from({ length: 7 }, (_, index) => ({
  id: `row-${index}`,
  status: index % 2 === 0 ? "violation" : "compliant",
}));

describe("localPage", () => {
  it("filters, then pages the rows that are left", () => {
    const page = localPage(rows, {
      keep: (row) => row.status === "violation",
      page: 2,
      pageSize: 3,
    });
    expect(page.items.map((row) => row.id)).toEqual(["row-6"]);
    expect(page).toMatchObject({ page: 2, pages: 2, count: 4 });
  });

  it("clamps a page past the end to the last one", () => {
    const page = localPage(rows, { page: 9, pageSize: 5 });
    expect(page.page).toBe(2);
    expect(page.items).toHaveLength(2);
  });

  it("keeps one empty page when nothing matches", () => {
    const page = localPage(rows, { keep: () => false, page: 1, pageSize: 5 });
    expect(page).toEqual({ items: [], page: 1, pages: 1, count: 0 });
  });
});

describe("matchesFilter", () => {
  it("treats an empty filter as everything", () => {
    expect(matchesFilter([], "anything")).toBe(true);
    expect(matchesFilter(["high"], "high")).toBe(true);
    expect(matchesFilter(["high"], "low")).toBe(false);
  });
});

describe("toTableMetadata", () => {
  it("maps a Realtime page to the table's pagination", () => {
    expect(
      toTableMetadata({ items: [], page: 3, pages: 4, count: 61 }),
    ).toEqual({ pagination: { page: 3, pages: 4, count: 61 }, version: "1" });
  });
});
