import { describe, expect, it } from "vitest";

import { buildCurrentLighthouseContext } from "./use-lighthouse-context";

describe("buildCurrentLighthouseContext", () => {
  it("should compile route metadata with current scoped contributions", () => {
    // Given
    const contributions = [
      {
        kind: "finding" as const,
        id: "findings-summary",
        source: "automatic" as const,
        scopeKey: "findings:/findings",
        label: "Visible findings",
        findingId: "summary",
        total: 42,
      },
      {
        kind: "resource" as const,
        id: "old-resource",
        source: "selection" as const,
        scopeKey: "resources:/resources",
        label: "Old resource",
        resourceId: "old-resource",
      },
    ];

    // When
    const current = buildCurrentLighthouseContext(
      "/findings",
      new URLSearchParams("filter%5Bseverity__in%5D=critical"),
      contributions,
    );

    // Then
    expect(current.context?.items.map((item) => item.id)).toEqual([
      "findings",
      "findings-summary",
    ]);
    expect(current.page.label).toBe("Findings");
    expect(current.selectionCount).toBe(0);
  });

  it("should combine the page, focused detail, and parent attack path", () => {
    // Given
    const parentContext = {
      kind: "attack_path" as const,
      id: "current-query",
      source: "automatic" as const,
      scopeKey: "attack-paths:/attack-paths",
      label: "Internet-exposed resources",
      scanId: "scan-1",
      queryId: "query-1",
    };
    const focusedContext = {
      kind: "finding" as const,
      id: "finding-1",
      source: "focused" as const,
      scopeKey: "attack-paths:/attack-paths",
      label: "Focused finding",
      findingId: "finding-1",
      checkId: "aws_s3_bucket_public_access",
    };

    // When
    const current = buildCurrentLighthouseContext(
      "/attack-paths",
      new URLSearchParams("scanId=scan-1"),
      [parentContext],
      focusedContext,
    );

    // Then
    expect(current.context?.items.map((item) => item.id)).toEqual([
      "attack-paths",
      "finding-1",
      "current-query",
    ]);
    expect(current.context?.items[0]).toMatchObject({
      kind: "page",
      filters: { scanId: ["scan-1"] },
    });
    expect(current.selectionCount).toBe(1);
  });
});
