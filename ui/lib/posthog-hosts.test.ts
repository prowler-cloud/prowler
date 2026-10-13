import { describe, expect, it } from "vitest";

import { resolvePosthogUiHost } from "./posthog-hosts";

describe("resolvePosthogUiHost", () => {
  it("prefers an explicitly configured app host", () => {
    // Given
    const ingestionHost = "https://eu.i.posthog.com";
    const uiHost = "https://posthog.example.com/";

    // When / Then
    expect(resolvePosthogUiHost(ingestionHost, uiHost)).toBe(
      "https://posthog.example.com",
    );
  });

  it.each([
    ["https://eu.i.posthog.com", "https://eu.posthog.com"],
    ["https://us.i.posthog.com/", "https://us.posthog.com"],
  ])("derives the Cloud app host from %s", (ingestionHost, expected) => {
    expect(resolvePosthogUiHost(ingestionHost, null)).toBe(expected);
  });

  it("uses the ingestion host for a self-hosted instance", () => {
    expect(
      resolvePosthogUiHost("https://posthog.internal.example/", null),
    ).toBe("https://posthog.internal.example");
  });
});
