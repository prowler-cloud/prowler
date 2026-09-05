import { describe, expect, it } from "vitest";

import { extractTourTargets } from "./check-tour-alignment.mjs";

describe("tour target extraction", () => {
  it("should include primary and fallback targets", () => {
    // Given
    const source = `
      {
        target: "volatile-row",
        fallbackTarget: "stable-tabs",
      }
    `;

    // When
    const targets = extractTourTargets(source);

    // Then
    expect(targets).toEqual(["volatile-row", "stable-tabs"]);
  });

  it("should include a target used only as a fallback", () => {
    // Given
    const source = `
      {
        fallbackTarget: "fallback-only-anchor",
        title: "Fallback-only step",
      }
    `;

    // When
    const targets = extractTourTargets(source);

    // Then
    expect(targets).toEqual(["fallback-only-anchor"]);
  });
});
