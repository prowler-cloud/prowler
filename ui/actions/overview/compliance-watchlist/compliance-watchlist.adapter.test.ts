import { describe, expect, it } from "vitest";

import { adaptComplianceWatchlistResponse } from "./compliance-watchlist.adapter";
import type { ComplianceWatchlistResponse } from "./compliance-watchlist.types";

describe("adaptComplianceWatchlistResponse", () => {
  it("returns no items on a 4xx error shape", () => {
    // handleApiResponse resolves truthy {error, status} objects for 4xx.
    const errorResponse = {
      error: "Invalid filter",
      status: 400,
    } as unknown as ComplianceWatchlistResponse;

    expect(adaptComplianceWatchlistResponse(errorResponse)).toEqual([]);
  });

  it("returns no items on an empty-body success shape", () => {
    // handleApiResponse resolves {success, status} for 204 and empty bodies.
    const emptyResponse = {
      success: true,
      status: 204,
    } as unknown as ComplianceWatchlistResponse;

    expect(adaptComplianceWatchlistResponse(emptyResponse)).toEqual([]);
  });

  it("returns no items when the fetch failed with undefined", () => {
    expect(adaptComplianceWatchlistResponse(undefined)).toEqual([]);
  });
});
