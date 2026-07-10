import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  assertGatedIntegrations,
  readGatedEnv,
  warnGatedIntegrationsMisconfig,
} from "./integrations";

// Every env var any gated integration reads. Cleared before each test so the
// assertions never depend on ambient shell/CI env.
const GATED_ENV_VARS = [
  "UI_SENTRY_ENABLED",
  "UI_SENTRY_DSN",
  "NEXT_PUBLIC_SENTRY_DSN",
  "UI_SENTRY_ENVIRONMENT",
  "NEXT_PUBLIC_SENTRY_ENVIRONMENT",
  "UI_GOOGLE_TAG_MANAGER_ENABLED",
  "UI_GOOGLE_TAG_MANAGER_ID",
  "NEXT_PUBLIC_GOOGLE_TAG_MANAGER_ID",
  "UI_POSTHOG_ENABLED",
  "UI_POSTHOG_KEY",
  "POSTHOG_KEY",
  "UI_POSTHOG_HOST",
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
    vi.stubEnv("UI_SENTRY_ENABLED", "true");
    vi.stubEnv("UI_SENTRY_DSN", "https://dsn.example");

    // When / Then
    expect(
      readGatedEnv(
        "UI_SENTRY_ENABLED",
        "UI_SENTRY_DSN",
        "NEXT_PUBLIC_SENTRY_DSN",
      ),
    ).toBe("https://dsn.example");
  });

  it("falls back to the legacy value when enabled and the primary is unset", () => {
    // Given
    vi.stubEnv("UI_SENTRY_ENABLED", "true");
    vi.stubEnv("NEXT_PUBLIC_SENTRY_DSN", "https://legacy.example");

    // When / Then
    expect(
      readGatedEnv(
        "UI_SENTRY_ENABLED",
        "UI_SENTRY_DSN",
        "NEXT_PUBLIC_SENTRY_DSN",
      ),
    ).toBe("https://legacy.example");
  });

  it("ignores the primary (new) value when disabled and no legacy is set", () => {
    // Given - the new UI_* name only counts when the enable flag is "true"
    vi.stubEnv("UI_SENTRY_ENABLED", "false");
    vi.stubEnv("UI_SENTRY_DSN", "https://dsn.example");

    // When / Then
    expect(
      readGatedEnv(
        "UI_SENTRY_ENABLED",
        "UI_SENTRY_DSN",
        "NEXT_PUBLIC_SENTRY_DSN",
      ),
    ).toBeNull();
  });

  it("returns the legacy value when disabled (legacy ignores the enable flag)", () => {
    // Given - legacy names stay backward compatible: they work without the flag
    vi.stubEnv("UI_SENTRY_ENABLED", "false");
    vi.stubEnv("NEXT_PUBLIC_SENTRY_DSN", "https://legacy.example");

    // When / Then
    expect(
      readGatedEnv(
        "UI_SENTRY_ENABLED",
        "UI_SENTRY_DSN",
        "NEXT_PUBLIC_SENTRY_DSN",
      ),
    ).toBe("https://legacy.example");
  });

  it("returns the legacy value when disabled even if the new value is also set", () => {
    // Given - new value is ignored without the flag; legacy still activates
    vi.stubEnv("UI_SENTRY_ENABLED", "false");
    vi.stubEnv("UI_SENTRY_DSN", "https://dsn.example");
    vi.stubEnv("NEXT_PUBLIC_SENTRY_DSN", "https://legacy.example");

    // When / Then
    expect(
      readGatedEnv(
        "UI_SENTRY_ENABLED",
        "UI_SENTRY_DSN",
        "NEXT_PUBLIC_SENTRY_DSN",
      ),
    ).toBe("https://legacy.example");
  });

  it("returns null when the enable flag is unset and only the new name is set", () => {
    // Given
    vi.stubEnv("UI_SENTRY_DSN", "https://dsn.example");

    // When / Then
    expect(readGatedEnv("UI_SENTRY_ENABLED", "UI_SENTRY_DSN")).toBeNull();
  });
});

describe("assertGatedIntegrations", () => {
  it("does not throw when every integration is disabled (the default)", () => {
    expect(() => assertGatedIntegrations()).not.toThrow();
  });

  it("throws when Sentry is enabled but the DSN is unset", () => {
    // Given
    vi.stubEnv("UI_SENTRY_ENABLED", "true");

    // When / Then
    expect(() => assertGatedIntegrations()).toThrow("UI_SENTRY_DSN");
  });

  it("does not throw when Sentry is enabled and the DSN is present", () => {
    // Given
    vi.stubEnv("UI_SENTRY_ENABLED", "true");
    vi.stubEnv("UI_SENTRY_DSN", "https://dsn.example");

    // When / Then
    expect(() => assertGatedIntegrations()).not.toThrow();
  });

  it("accepts the legacy DSN name when Sentry is enabled", () => {
    // Given
    vi.stubEnv("UI_SENTRY_ENABLED", "true");
    vi.stubEnv("NEXT_PUBLIC_SENTRY_DSN", "https://legacy.example");

    // When / Then
    expect(() => assertGatedIntegrations()).not.toThrow();
  });

  it("does not require the optional Sentry environment when enabled", () => {
    // Given - DSN present, UI_SENTRY_ENVIRONMENT intentionally unset
    vi.stubEnv("UI_SENTRY_ENABLED", "true");
    vi.stubEnv("UI_SENTRY_DSN", "https://dsn.example");

    // When / Then
    expect(() => assertGatedIntegrations()).not.toThrow();
  });

  it("throws when GTM is enabled without an id", () => {
    // Given
    vi.stubEnv("UI_GOOGLE_TAG_MANAGER_ENABLED", "true");

    // When / Then
    expect(() => assertGatedIntegrations()).toThrow("UI_GOOGLE_TAG_MANAGER_ID");
  });

  it("requires BOTH UI_POSTHOG_KEY and UI_POSTHOG_HOST when PostHog is enabled", () => {
    // Given - key set, host missing
    vi.stubEnv("UI_POSTHOG_ENABLED", "true");
    vi.stubEnv("UI_POSTHOG_KEY", "phc_key");

    // When / Then
    expect(() => assertGatedIntegrations()).toThrow("UI_POSTHOG_HOST");
  });

  it("does not throw when PostHog is enabled with both key and host", () => {
    // Given
    vi.stubEnv("UI_POSTHOG_ENABLED", "true");
    vi.stubEnv("UI_POSTHOG_KEY", "phc_key");
    vi.stubEnv("UI_POSTHOG_HOST", "https://eu.i.posthog.com");

    // When / Then
    expect(() => assertGatedIntegrations()).not.toThrow();
  });

  it("accepts the legacy Sentry DSN without the enable flag", () => {
    // Given - backward compat: legacy presence activates without the flag
    vi.stubEnv("NEXT_PUBLIC_SENTRY_DSN", "https://legacy.example");

    // When / Then
    expect(() => assertGatedIntegrations()).not.toThrow();
  });

  it("accepts the legacy PostHog names without the enable flag", () => {
    // Given - both legacy names present, no UI_POSTHOG_ENABLED
    vi.stubEnv("POSTHOG_KEY", "phc_key");
    vi.stubEnv("POSTHOG_HOST", "https://eu.i.posthog.com");

    // When / Then
    expect(() => assertGatedIntegrations()).not.toThrow();
  });

  it("throws when a partial legacy PostHog config is set without the enable flag", () => {
    // Given - one legacy name present; the full legacy set is then required
    vi.stubEnv("POSTHOG_KEY", "phc_key");

    // When / Then
    expect(() => assertGatedIntegrations()).toThrow("POSTHOG_HOST");
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
    expect(warn.mock.calls[0][0]).toContain("UI_SENTRY_ENABLED");
  });

  it("does not warn when the integration is enabled", () => {
    // Given
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.stubEnv("UI_SENTRY_ENABLED", "true");
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

  it("does not warn when only a legacy name is set without the enable flag", () => {
    // Given - legacy stays backward compatible, so it loads and is not a misconfig
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.stubEnv("NEXT_PUBLIC_SENTRY_DSN", "https://legacy.example");

    // When
    warnGatedIntegrationsMisconfig();

    // Then
    expect(warn).not.toHaveBeenCalled();
  });
});
