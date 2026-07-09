import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

describe("lib/env boot assertion", () => {
  beforeEach(() => {
    // Re-evaluate the module per case so its top-level assertion re-runs.
    vi.resetModules();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("throws a clear error when a required env var is missing", async () => {
    // Given - UI_API_BASE_URL and its legacy empty, the others present
    vi.stubEnv("UI_API_BASE_URL", "");
    vi.stubEnv("NEXT_PUBLIC_API_BASE_URL", "");
    vi.stubEnv("AUTH_URL", "http://localhost:3000");
    vi.stubEnv("AUTH_SECRET", "secret");

    // When / Then
    await expect(import("@/lib/env")).rejects.toThrow(
      "Missing required env: UI_API_BASE_URL",
    );
  });

  it("does not throw when every required env var is present", async () => {
    // Given
    vi.stubEnv("UI_API_BASE_URL", "https://api.example.com/api/v1");
    vi.stubEnv("AUTH_URL", "http://localhost:3000");
    vi.stubEnv("AUTH_SECRET", "secret");

    // When / Then
    await expect(import("@/lib/env")).resolves.toBeDefined();
  });

  it("accepts the deprecated NEXT_PUBLIC_API_BASE_URL as a fallback", async () => {
    // Given - the new name is unset but the legacy name is configured
    vi.stubEnv("UI_API_BASE_URL", undefined);
    vi.stubEnv("NEXT_PUBLIC_API_BASE_URL", "https://api.example.com/api/v1");
    vi.stubEnv("AUTH_URL", "http://localhost:3000");
    vi.stubEnv("AUTH_SECRET", "secret");

    // When / Then
    await expect(import("@/lib/env")).resolves.toBeDefined();
  });
});

describe("lib/env gated integration validation", () => {
  // Clear every gated flag/config so ambient shell env cannot affect assertions,
  // then satisfy the unconditional REQUIRED vars (they are checked first).
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
    vi.resetModules();
    for (const key of GATED_ENV_VARS) {
      vi.stubEnv(key, undefined);
    }
    vi.stubEnv("UI_API_BASE_URL", "https://api.example.com/api/v1");
    vi.stubEnv("AUTH_URL", "http://localhost:3000");
    vi.stubEnv("AUTH_SECRET", "secret");
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it("throws when UI_SENTRY_ENABLED is true but the DSN is unset", async () => {
    vi.stubEnv("UI_SENTRY_ENABLED", "true");

    await expect(import("@/lib/env")).rejects.toThrow("UI_SENTRY_DSN");
  });

  it("resolves when UI_SENTRY_ENABLED is true and the DSN is present", async () => {
    vi.stubEnv("UI_SENTRY_ENABLED", "true");
    vi.stubEnv("UI_SENTRY_DSN", "https://key@o0.ingest.sentry.io/1");

    await expect(import("@/lib/env")).resolves.toBeDefined();
  });

  it("does not throw when an integration is disabled and its config is unset", async () => {
    // No enable flags set — the highest-value non-regression: a default
    // deployment that never opted into any integration must still boot.
    await expect(import("@/lib/env")).resolves.toBeDefined();
  });

  it("throws when UI_GOOGLE_TAG_MANAGER_ENABLED is true without an id", async () => {
    vi.stubEnv("UI_GOOGLE_TAG_MANAGER_ENABLED", "true");

    await expect(import("@/lib/env")).rejects.toThrow(
      "UI_GOOGLE_TAG_MANAGER_ID",
    );
  });

  it("throws on UI_POSTHOG_HOST when PostHog is enabled with only the key", async () => {
    vi.stubEnv("UI_POSTHOG_ENABLED", "true");
    vi.stubEnv("UI_POSTHOG_KEY", "phc_key");

    await expect(import("@/lib/env")).rejects.toThrow("UI_POSTHOG_HOST");
  });

  it("resolves when PostHog is enabled with both key and host", async () => {
    vi.stubEnv("UI_POSTHOG_ENABLED", "true");
    vi.stubEnv("UI_POSTHOG_KEY", "phc_key");
    vi.stubEnv("UI_POSTHOG_HOST", "https://eu.i.posthog.com");

    await expect(import("@/lib/env")).resolves.toBeDefined();
  });

  it("resolves when the legacy Sentry DSN is set without the enable flag", async () => {
    // Legacy names stay backward compatible: they activate without the flag.
    vi.stubEnv("NEXT_PUBLIC_SENTRY_DSN", "https://key@o0.ingest.sentry.io/1");

    await expect(import("@/lib/env")).resolves.toBeDefined();
  });

  it("resolves when the legacy PostHog names are set without the enable flag", async () => {
    vi.stubEnv("POSTHOG_KEY", "phc_key");
    vi.stubEnv("POSTHOG_HOST", "https://eu.i.posthog.com");

    await expect(import("@/lib/env")).resolves.toBeDefined();
  });

  it("throws on a partial legacy PostHog config set without the enable flag", async () => {
    vi.stubEnv("POSTHOG_KEY", "phc_key");

    await expect(import("@/lib/env")).rejects.toThrow("POSTHOG_HOST");
  });
});
