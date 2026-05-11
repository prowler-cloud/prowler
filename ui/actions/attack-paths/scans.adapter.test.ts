import { describe, expect, it } from "vitest";

import {
  type AttackPathScan,
  type AttackPathScansResponse,
  SCAN_STATES,
} from "@/types/attack-paths";

import { adaptAttackPathScansResponse } from "./scans.adapter";

const makeScan = (
  id: string,
  overrides: Partial<AttackPathScan["attributes"]> = {},
): AttackPathScan => ({
  type: "attack-paths-scans",
  id,
  attributes: {
    state: SCAN_STATES.COMPLETED,
    progress: 100,
    graph_data_ready: true,
    provider_alias: `alias-${id}`,
    provider_type: "aws",
    provider_uid: id,
    inserted_at: "2026-04-23T10:00:00Z",
    started_at: "2026-04-23T10:00:00Z",
    completed_at: "2026-04-23T10:10:00Z",
    duration: 600,
    ...overrides,
  },
  relationships: {} as AttackPathScan["relationships"],
});

describe("adaptAttackPathScansResponse", () => {
  it("returns an empty list when the response is undefined", () => {
    // When
    const result = adaptAttackPathScansResponse(undefined);

    // Then
    expect(result).toEqual({ data: [] });
  });

  it("enriches each scan with durationLabel and isRecent", () => {
    // Given a scan that completed recently
    const recentCompletion = new Date(
      Date.now() - 60 * 60 * 1000,
    ).toISOString();
    const response: AttackPathScansResponse = {
      data: [makeScan("s1", { completed_at: recentCompletion, duration: 90 })],
      links: { first: "", last: "", next: null, prev: null },
      meta: { pagination: { page: 1, pages: 1, count: 1 } },
    };

    // When
    const result = adaptAttackPathScansResponse(response);

    // Then
    expect(result.data).toHaveLength(1);
    const enriched = result.data[0]
      .attributes as (typeof result.data)[0]["attributes"] & {
      durationLabel: string | null;
      isRecent: boolean;
    };
    expect(enriched.durationLabel).toBeDefined();
    expect(enriched.isRecent).toBe(true);
  });

  it("surfaces meta.pagination values unchanged in the adapted metadata", () => {
    // Given a paginated API response
    const response: AttackPathScansResponse = {
      data: [makeScan("s1"), makeScan("s2")],
      links: { first: "", last: "", next: null, prev: null },
      meta: { pagination: { page: 3, pages: 5, count: 42 }, version: "2.0" },
    };

    // When
    const result = adaptAttackPathScansResponse(response);

    // Then
    expect(result.metadata).toEqual({
      pagination: {
        page: 3,
        pages: 5,
        count: 42,
        itemsPerPage: [5, 10, 25, 50, 100],
      },
      version: "2.0",
    });
  });

  it("omits metadata when the response has no pagination info", () => {
    // Given
    const response: AttackPathScansResponse = {
      data: [makeScan("s1")],
      links: { first: "", last: "", next: null, prev: null },
    };

    // When
    const result = adaptAttackPathScansResponse(response);

    // Then
    expect(result.metadata).toBeUndefined();
  });
});
