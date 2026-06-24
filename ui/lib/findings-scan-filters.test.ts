import { describe, expect, it, vi } from "vitest";

import {
  buildFindingScanDateFilters,
  resolveFindingScanDateFilters,
} from "./findings-scan-filters";

describe("buildFindingScanDateFilters", () => {
  it("uses an exact inserted_at filter when all selected scans belong to the same day", () => {
    expect(
      buildFindingScanDateFilters([
        "2026-04-07T10:00:00Z",
        "2026-04-07T18:30:00Z",
      ]),
    ).toEqual({
      "filter[inserted_at]": "2026-04-07",
    });
  });

  it("ignores whitespace-only date strings", () => {
    expect(buildFindingScanDateFilters(["  ", "2026-04-07T10:00:00Z"])).toEqual(
      {
        "filter[inserted_at]": "2026-04-07",
      },
    );
  });

  it("uses a date range when selected scans span multiple days", () => {
    expect(
      buildFindingScanDateFilters([
        "2026-04-03T10:00:00Z",
        "2026-04-07T18:30:00Z",
        "2026-04-05T12:00:00Z",
      ]),
    ).toEqual({
      "filter[inserted_at__gte]": "2026-04-03",
      "filter[inserted_at__lte]": "2026-04-07",
    });
  });
});

describe("resolveFindingScanDateFilters", () => {
  it("adds the required inserted_at filter for a selected scan when the URL only contains scan__in", async () => {
    const result = await resolveFindingScanDateFilters({
      filters: {
        "filter[muted]": "false",
        "filter[scan__in]": "scan-1",
      },
      scans: [
        {
          id: "scan-1",
          attributes: {
            completed_at: "2026-04-07T10:00:00Z",
          },
        },
      ],
      loadScan: vi.fn(),
    });

    expect(result).toEqual({
      "filter[muted]": "false",
      "filter[scan__in]": "scan-1",
      "filter[inserted_at]": "2026-04-07",
    });
  });

  it("fetches missing scan details when the selected scan is not present in the prefetched scans list", async () => {
    const loadScan = vi.fn().mockResolvedValue({
      id: "scan-2",
      attributes: {
        completed_at: "2026-04-05T08:00:00Z",
      },
    });

    const result = await resolveFindingScanDateFilters({
      filters: {
        "filter[scan__in]": "scan-2",
      },
      scans: [],
      loadScan,
    });

    expect(loadScan).toHaveBeenCalledWith("scan-2");
    expect(result).toEqual({
      "filter[scan__in]": "scan-2",
      "filter[inserted_at]": "2026-04-05",
    });
  });

  it("does not override an explicit inserted_at filter already chosen in the frontend", async () => {
    const result = await resolveFindingScanDateFilters({
      filters: {
        "filter[scan__in]": "scan-1",
        "filter[inserted_at__gte]": "2026-04-01",
      },
      scans: [
        {
          id: "scan-1",
          attributes: {
            completed_at: "2026-04-07T10:00:00Z",
          },
        },
      ],
      loadScan: vi.fn(),
    });

    expect(result).toEqual({
      "filter[scan__in]": "scan-1",
      "filter[inserted_at__gte]": "2026-04-01",
    });
  });
});
