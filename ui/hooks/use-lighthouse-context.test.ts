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
});
