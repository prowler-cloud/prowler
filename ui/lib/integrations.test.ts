import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  assertGatedIntegrations,
  readGatedEnv,
  warnGatedIntegrationsMisconfig,
} from "./integrations";

// Every env var any gated integration reads. Cleared before each test so the
// assertions never depend on ambient shell/CI env.
const GATED_ENV_VARS = [
  "UI_SENTRY_ENABLE",
  "UI_SENTRY_DSN",
  "NEXT_PUBLIC_SENTRY_DSN",
  "UI_SENTRY_ENVIRONMENT",
  "NEXT_PUBLIC_SENTRY_ENVIRONMENT",
  "UI_GOOGLE_TAG_MANAGER_ENABLE",
  "UI_GOOGLE_TAG_MANAGER_ID",
  "NEXT_PUBLIC_GOOGLE_TAG_MANAGER_ID",
  "UI_POSTHOG_ENABLE",
  "POSTHOG_KEY",
  "POSTHOG_HOST",
] as const;

beforeEach(() => {
  for (const key of GATED_ENV_VARS) {
    vi.stubEnv(key, undefined);
  }
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("readGatedEnv", () => {
  it("returns the primary value when the integration is enabled", () => {
    // Given
    vi.stubEnv("UI_SENTRY_ENABLE", "true");
    vi.stubEnv("UI_SENTRY_DSN", "https://dsn.example");

    // When / Then
    expect(
      readGatedEnv(
        "UI_SENTRY_ENABLE",
        "UI_SENTRY_DSN",
        "NEXT_PUBLIC_SENTRY_DSN",
      ),
    ).toBe("https://dsn.example");
  });

  it("falls back to the legacy value when enabled and the primary is unset", () => {
    // Given
    vi.stubEnv("UI_SENTRY_ENABLE", "true");
    vi.stubEnv("NEXT_PUBLIC_SENTRY_DSN", "https://legacy.example");

    // When / Then
    expect(
      readGatedEnv(
        "UI_SENTRY_ENABLE",
        "UI_SENTRY_DSN",
        "NEXT_PUBLIC_SENTRY_DSN",
      ),
    ).toBe("https://legacy.example");
  });

  it("returns null when disabled even if the value is set", () => {
    // Given
    vi.stubEnv("UI_SENTRY_ENABLE", "false");
    vi.stubEnv("UI_SENTRY_DSN", "https://dsn.example");
    vi.stubEnv("NEXT_PUBLIC_SENTRY_DSN", "https://legacy.example");

    // When / Then
    expect(
      readGatedEnv(
        "UI_SENTRY_ENABLE",
        "UI_SENTRY_DSN",
        "NEXT_PUBLIC_SENTRY_DSN",
      ),
    ).toBeNull();
  });

  it("returns null when the enable flag is unset", () => {
    // Given
    vi.stubEnv("UI_SENTRY_DSN", "https://dsn.example");

    // When / Then
    expect(readGatedEnv("UI_SENTRY_ENABLE", "UI_SENTRY_DSN")).toBeNull();
  });
});

describe("assertGatedIntegrations", () => {
  it("does not throw when every integration is disabled (the default)", () => {
    expect(() => assertGatedIntegrations()).not.toThrow();
  });

  it("throws when Sentry is enabled but the DSN is unset", () => {
    // Given
    vi.stubEnv("UI_SENTRY_ENABLE", "true");

    // When / Then
    expect(() => assertGatedIntegrations()).toThrow("UI_SENTRY_DSN");
  });

  it("does not throw when Sentry is enabled and the DSN is present", () => {
    // Given
    vi.stubEnv("UI_SENTRY_ENABLE", "true");
    vi.stubEnv("UI_SENTRY_DSN", "https://dsn.example");

    // When / Then
    expect(() => assertGatedIntegrations()).not.toThrow();
  });

  it("accepts the legacy DSN name when Sentry is enabled", () => {
    // Given
    vi.stubEnv("UI_SENTRY_ENABLE", "true");
    vi.stubEnv("NEXT_PUBLIC_SENTRY_DSN", "https://legacy.example");

    // When / Then
    expect(() => assertGatedIntegrations()).not.toThrow();
  });

  it("does not require the optional Sentry environment when enabled", () => {
    // Given - DSN present, UI_SENTRY_ENVIRONMENT intentionally unset
    vi.stubEnv("UI_SENTRY_ENABLE", "true");
    vi.stubEnv("UI_SENTRY_DSN", "https://dsn.example");

    // When / Then
    expect(() => assertGatedIntegrations()).not.toThrow();
  });

  it("throws when GTM is enabled without an id", () => {
    // Given
    vi.stubEnv("UI_GOOGLE_TAG_MANAGER_ENABLE", "true");

    // When / Then
    expect(() => assertGatedIntegrations()).toThrow("UI_GOOGLE_TAG_MANAGER_ID");
  });

  it("requires BOTH POSTHOG_KEY and POSTHOG_HOST when PostHog is enabled", () => {
    // Given - key set, host missing
    vi.stubEnv("UI_POSTHOG_ENABLE", "true");
    vi.stubEnv("POSTHOG_KEY", "phc_key");

    // When / Then
    expect(() => assertGatedIntegrations()).toThrow("POSTHOG_HOST");
  });

  it("does not throw when PostHog is enabled with both key and host", () => {
    // Given
    vi.stubEnv("UI_POSTHOG_ENABLE", "true");
    vi.stubEnv("POSTHOG_KEY", "phc_key");
    vi.stubEnv("POSTHOG_HOST", "https://eu.i.posthog.com");

    // When / Then
    expect(() => assertGatedIntegrations()).not.toThrow();
  });
});

describe("warnGatedIntegrationsMisconfig", () => {
  it("warns when a config value is set but its enable flag is not 'true'", () => {
    // Given
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.stubEnv("UI_SENTRY_DSN", "https://dsn.example");

    // When
    warnGatedIntegrationsMisconfig();

    // Then
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toContain("UI_SENTRY_ENABLE");
  });

  it("does not warn when the integration is enabled", () => {
    // Given
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.stubEnv("UI_SENTRY_ENABLE", "true");
    vi.stubEnv("UI_SENTRY_DSN", "https://dsn.example");

    // When
    warnGatedIntegrationsMisconfig();

    // Then
    expect(warn).not.toHaveBeenCalled();
  });

  it("does not warn when nothing is configured", () => {
    // Given
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    // When
    warnGatedIntegrationsMisconfig();

    // Then
    expect(warn).not.toHaveBeenCalled();
  });
});
