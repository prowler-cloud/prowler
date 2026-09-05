import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("next/server", () => ({ connection: () => Promise.resolve() }));

const POSTHOG_ENV_VARS = [
  "UI_POSTHOG_ENABLED",
  "UI_POSTHOG_KEY",
  "POSTHOG_KEY",
  "UI_POSTHOG_HOST",
  "POSTHOG_HOST",
  "UI_POSTHOG_UI_HOST",
] as const;

const importFresh = async () => {
  vi.resetModules();
  return import("./runtime-config");
};

describe("getRuntimePublicConfig PostHog hosts", () => {
  beforeEach(() => {
    for (const key of POSTHOG_ENV_VARS) vi.stubEnv(key, undefined);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("returns separate ingestion and app hosts when PostHog is enabled", async () => {
    // Given
    vi.stubEnv("UI_POSTHOG_ENABLED", "true");
    vi.stubEnv("UI_POSTHOG_KEY", "phc_key");
    vi.stubEnv("UI_POSTHOG_HOST", "https://us.i.posthog.com");
    vi.stubEnv("UI_POSTHOG_UI_HOST", "https://us.posthog.com");

    // When
    const { getRuntimePublicConfig } = await importFresh();
    const config = await getRuntimePublicConfig();

    // Then
    expect(config.posthogIngestionHost).toBe("https://us.i.posthog.com");
    expect(config.posthogUiHost).toBe("https://us.posthog.com");
  });

  it("keeps legacy PostHog config working without an explicit app host", async () => {
    // Given
    vi.stubEnv("POSTHOG_KEY", "phc_key");
    vi.stubEnv("POSTHOG_HOST", "https://posthog.internal.example");

    // When
    const { getRuntimePublicConfig } = await importFresh();
    const config = await getRuntimePublicConfig();

    // Then
    expect(config.posthogIngestionHost).toBe(
      "https://posthog.internal.example",
    );
    expect(config.posthogUiHost).toBeNull();
  });

  it("returns null hosts when PostHog is disabled", async () => {
    // Given
    vi.stubEnv("UI_POSTHOG_HOST", "https://eu.i.posthog.com");
    vi.stubEnv("UI_POSTHOG_UI_HOST", "https://eu.posthog.com");

    // When
    const { getRuntimePublicConfig } = await importFresh();
    const config = await getRuntimePublicConfig();

    // Then
    expect(config.posthogIngestionHost).toBeNull();
    expect(config.posthogUiHost).toBeNull();
  });
});
