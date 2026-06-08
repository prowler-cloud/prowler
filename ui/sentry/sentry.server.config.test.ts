import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Stable mock that survives resetModules (which clears the module registry).
const { initMock } = vi.hoisted(() => ({ initMock: vi.fn() }));

vi.mock("@sentry/nextjs", () => ({
  init: initMock,
  extraErrorDataIntegration: vi.fn(() => ({})),
}));

describe("sentry.server.config", () => {
  beforeEach(() => {
    // Re-evaluate the module per case so its top-level init guard re-runs.
    vi.resetModules();
    initMock.mockClear();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("should initialize with the resolved environment and production sampling", async () => {
    // Given
    vi.stubEnv("UI_SENTRY_DSN", "https://key@o0.ingest.sentry.io/1");
    vi.stubEnv("UI_SENTRY_ENVIRONMENT", "pro");

    // When
    await import("./sentry.server.config");

    // Then
    expect(initMock).toHaveBeenCalledTimes(1);
    expect(initMock.mock.calls[0][0]).toMatchObject({
      dsn: "https://key@o0.ingest.sentry.io/1",
      environment: "pro",
      tracesSampleRate: 0.5,
      profilesSampleRate: 0.5,
    });
  });

  it("should not initialize when the DSN is absent", async () => {
    // Given no DSN

    // When
    await import("./sentry.server.config");

    // Then
    expect(initMock).not.toHaveBeenCalled();
  });

  it("should default to a non-dev environment so an unset UI_SENTRY_ENVIRONMENT does not enable dev sampling (R6)", async () => {
    // Given - DSN set but environment unset
    vi.stubEnv("UI_SENTRY_DSN", "https://key@o0.ingest.sentry.io/1");

    // When
    await import("./sentry.server.config");

    // Then
    const options = initMock.mock.calls[0][0];
    expect(options.environment).toBe("production");
    expect(options.tracesSampleRate).toBe(0.5);
    expect(options.profilesSampleRate).toBe(0.5);
  });
});
