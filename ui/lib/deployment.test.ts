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
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

    // When
    const { isGroupedJiraDispatchEnabled } = await importFresh();

    // Then
    expect(isGroupedJiraDispatchEnabled()).toBe(false);
  });

  it("should enable grouped Jira dispatch in cloud without an enterprise flag", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");

    // When
    const { isGroupedJiraDispatchEnabled } = await importFresh();

    // Then
    expect(isGroupedJiraDispatchEnabled()).toBe(true);
  });

  it("should keep grouped Jira dispatch disabled outside cloud", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

    // When
    const { isGroupedJiraDispatchEnabled } = await importFresh();

    // Then
    expect(isGroupedJiraDispatchEnabled()).toBe(false);
  });
});
