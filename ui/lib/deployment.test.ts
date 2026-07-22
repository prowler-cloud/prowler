import { afterEach, describe, expect, it, vi } from "vitest";

const importFresh = async () => {
  vi.resetModules();
  return import("./deployment");
};

describe("enterprise feature flags", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("should keep grouped Jira dispatch disabled by default", async () => {
    // Given / When
    const { isGroupedJiraDispatchEnabled } = await importFresh();

    // Then
    expect(isGroupedJiraDispatchEnabled()).toBe(false);
  });

  it("should enable grouped Jira dispatch from the enterprise env flag in cloud", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_PROWLER_DEPLOYMENT_MODE", "cloud");
    vi.stubEnv(
      "NEXT_PUBLIC_PROWLER_ENTERPRISE_GROUPED_JIRA_DISPATCH_ENABLED",
      "true",
    );

    // When
    const { isGroupedJiraDispatchEnabled } = await importFresh();

    // Then
    expect(isGroupedJiraDispatchEnabled()).toBe(true);
  });

  it("should keep grouped Jira dispatch disabled outside cloud", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_PROWLER_DEPLOYMENT_MODE", "onpremise");
    vi.stubEnv(
      "NEXT_PUBLIC_PROWLER_ENTERPRISE_GROUPED_JIRA_DISPATCH_ENABLED",
      "true",
    );

    // When
    const { isGroupedJiraDispatchEnabled } = await importFresh();

    // Then
    expect(isGroupedJiraDispatchEnabled()).toBe(false);
  });
});
