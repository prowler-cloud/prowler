import { afterEach, describe, expect, it, vi } from "vitest";

const importFresh = async () => {
  vi.resetModules();
  return import("./deployment");
};

describe("enterprise feature flags", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("should enable billing and PostHog by default", async () => {
    // Given / When
    const { isBillingEnabled, isPostHogEnabled } = await importFresh();

    // Then
    expect(isBillingEnabled()).toBe(true);
    expect(isPostHogEnabled()).toBe(true);
  });

  it("should disable billing independently from PostHog", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_PROWLER_ENTERPRISE_BILLING_ENABLED", "false");
    vi.stubEnv("NEXT_PUBLIC_PROWLER_ENTERPRISE_POSTHOG_ENABLED", "true");

    // When
    const { isBillingEnabled, isPostHogEnabled } = await importFresh();

    // Then
    expect(isBillingEnabled()).toBe(false);
    expect(isPostHogEnabled()).toBe(true);
  });

  it("should disable PostHog when billing and PostHog are disabled", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_PROWLER_ENTERPRISE_BILLING_ENABLED", "false");
    vi.stubEnv("NEXT_PUBLIC_PROWLER_ENTERPRISE_POSTHOG_ENABLED", "false");

    // When
    const { isBillingEnabled, isPostHogEnabled } = await importFresh();

    // Then
    expect(isBillingEnabled()).toBe(false);
    expect(isPostHogEnabled()).toBe(false);
  });

  it("should force PostHog on when billing is enabled", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_PROWLER_ENTERPRISE_BILLING_ENABLED", "true");
    vi.stubEnv("NEXT_PUBLIC_PROWLER_ENTERPRISE_POSTHOG_ENABLED", "false");

    // When
    const { isBillingEnabled, isPostHogEnabled } = await importFresh();

    // Then
    expect(isBillingEnabled()).toBe(true);
    expect(isPostHogEnabled()).toBe(true);
  });

  it("should keep grouped Jira dispatch disabled by default", async () => {
    // Given / When
    const { isGroupedJiraDispatchEnabled } = await importFresh();

    // Then
    expect(isGroupedJiraDispatchEnabled()).toBe(false);
  });

  it("should enable grouped Jira dispatch from the enterprise env flag in cloud", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
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
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
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
