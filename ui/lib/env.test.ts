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
    "CLOUD_BILLING_ENABLED",
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

  it("throws when CLOUD_BILLING_ENABLED is metronome but PostHog is not enabled", async () => {
    // metronome billing routes per tenant via the BILLING_SYSTEM_METRONOME
    // PostHog flag, so PostHog must be enabled.
    vi.stubEnv("CLOUD_BILLING_ENABLED", "metronome");

    await expect(import("@/lib/env")).rejects.toThrow(
      "PostHog is required for per-tenant billing routing",
    );
  });

  it("resolves when CLOUD_BILLING_ENABLED is metronome and PostHog is enabled", async () => {
    vi.stubEnv("CLOUD_BILLING_ENABLED", "metronome");
    vi.stubEnv("UI_POSTHOG_ENABLED", "true");
    vi.stubEnv("UI_POSTHOG_KEY", "phc_key");
    vi.stubEnv("UI_POSTHOG_HOST", "https://eu.i.posthog.com");

    await expect(import("@/lib/env")).resolves.toBeDefined();
  });

  it("resolves when CLOUD_BILLING_ENABLED is legacy without PostHog", async () => {
    // legacy billing forces V1 and never touches PostHog.
    vi.stubEnv("CLOUD_BILLING_ENABLED", "legacy");

    await expect(import("@/lib/env")).resolves.toBeDefined();
  });
});

describe("lib/env billing and Stripe boot warnings", () => {
  // Clear billing, cloud, Stripe and gated flags so ambient shell env cannot
  // affect assertions, then satisfy the unconditional REQUIRED vars.
  const CLEARED_ENV_VARS = [
    "UI_CLOUD_ENABLED",
    "CLOUD_BILLING_ENABLED",
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
    "UI_CLOUD_STRIPE_PUBLISHABLE_KEY",
    "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY",
    "UI_CLOUD_STRIPE_PUBLISHABLE_KEY_V2",
    "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY_V2",
  ] as const;

  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.resetModules();
    for (const key of CLEARED_ENV_VARS) {
      vi.stubEnv(key, undefined);
    }
    vi.stubEnv("UI_API_BASE_URL", "https://api.example.com/api/v1");
    vi.stubEnv("AUTH_URL", "http://localhost:3000");
    vi.stubEnv("AUTH_SECRET", "secret");
    warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it('warns when billing is "legacy" without the cloud flag', async () => {
    vi.stubEnv("CLOUD_BILLING_ENABLED", "legacy");

    await import("@/lib/env");

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        'CLOUD_BILLING_ENABLED is "legacy" but UI_CLOUD_ENABLED is not "true"',
      ),
    );
  });

  it('warns when billing is "metronome" (PostHog enabled) without the cloud flag', async () => {
    vi.stubEnv("CLOUD_BILLING_ENABLED", "metronome");
    vi.stubEnv("UI_POSTHOG_ENABLED", "true");
    vi.stubEnv("UI_POSTHOG_KEY", "phc_key");
    vi.stubEnv("UI_POSTHOG_HOST", "https://eu.i.posthog.com");

    await import("@/lib/env");

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        'CLOUD_BILLING_ENABLED is "metronome" but UI_CLOUD_ENABLED is not "true"',
      ),
    );
  });

  it("does not warn about billing when the cloud flag is set", async () => {
    vi.stubEnv("CLOUD_BILLING_ENABLED", "legacy");
    vi.stubEnv("UI_CLOUD_ENABLED", "true");

    await import("@/lib/env");

    expect(warnSpy).not.toHaveBeenCalled();
  });

  it("does not warn when billing is off and no Stripe keys are set", async () => {
    await import("@/lib/env");

    expect(warnSpy).not.toHaveBeenCalled();
  });

  it("warns when a Stripe key is set without billing enabled", async () => {
    vi.stubEnv("UI_CLOUD_STRIPE_PUBLISHABLE_KEY", "pk_test_123");

    await import("@/lib/env");

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        "UI_CLOUD_STRIPE_PUBLISHABLE_KEY is set but CLOUD_BILLING_ENABLED is not enabled; Stripe will not load.",
      ),
    );
  });

  it("does not warn about Stripe when cloud, billing, and Stripe are all set", async () => {
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    vi.stubEnv("CLOUD_BILLING_ENABLED", "legacy");
    vi.stubEnv("UI_CLOUD_STRIPE_PUBLISHABLE_KEY", "pk_test_123");

    await import("@/lib/env");

    expect(warnSpy).not.toHaveBeenCalled();
  });
});
