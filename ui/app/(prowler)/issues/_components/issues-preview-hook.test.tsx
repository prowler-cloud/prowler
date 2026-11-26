import { beforeEach, describe, expect, it, vi } from "vitest";

const { getFindingsBySeverity } = vi.hoisted(() => ({
  getFindingsBySeverity: vi.fn(),
}));
vi.mock("@/actions/overview/findings/findings", () => ({
  getFindingsBySeverity,
}));

import { IssuesPreviewHook } from "./issues-preview-hook";

describe("IssuesPreviewHook", () => {
  beforeEach(() => {
    getFindingsBySeverity.mockReset();
  });

  it("names the user's critical and high FAIL counts", async () => {
    // Given
    getFindingsBySeverity.mockResolvedValue({
      data: { attributes: { critical: 3, high: 5 } },
    });

    // When
    const hook = await IssuesPreviewHook();

    // Then
    expect(hook).toMatch(/3 critical and 5 high FAIL findings/);
  });

  it("falls back to the generic copy when the severity request fails", async () => {
    // Given
    getFindingsBySeverity.mockRejectedValue(new Error("Server error (500)"));

    // When
    const hook = await IssuesPreviewHook();

    // Then
    expect(hook).toMatch(/Once your Local Server has scan results/);
  });
});
