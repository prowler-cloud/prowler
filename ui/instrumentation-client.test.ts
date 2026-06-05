import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { EMPTY_RUNTIME_PUBLIC_CONFIG } from "@/lib/runtime-config.shared";

// Stable mock fns shared across module re-evaluations (resetModules clears the
// module registry but these hoisted fns survive, so assertions stay reliable).
const { initMock, setUserMock, captureMock, getConfigMock } = vi.hoisted(
  () => ({
    initMock: vi.fn(),
    setUserMock: vi.fn(),
    captureMock: vi.fn(),
    getConfigMock: vi.fn(),
  }),
);

vi.mock("@sentry/nextjs", () => ({
  init: initMock,
  setUser: setUserMock,
  captureRouterTransitionStart: captureMock,
  browserTracingIntegration: vi.fn(() => ({})),
}));

vi.mock("@/lib/get-runtime-config.client", () => ({
  getRuntimeConfigClient: getConfigMock,
}));

vi.mock("@/components/ui/navigation-progress/use-navigation-progress", () => ({
  startProgress: vi.fn(),
  cancelProgress: vi.fn(),
}));

describe("instrumentation-client Sentry init", () => {
  beforeEach(() => {
    // Re-evaluate the module per case so its top-level init guard re-runs.
    vi.resetModules();
    initMock.mockClear();
    setUserMock.mockClear();
    captureMock.mockClear();
    getConfigMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("initializes Sentry with the runtime DSN and the build-time release when a DSN is present", async () => {
    // Given
    getConfigMock.mockReturnValue({
      ...EMPTY_RUNTIME_PUBLIC_CONFIG,
      sentryDsn: "https://key@o0.ingest.sentry.io/1",
      sentryEnvironment: "pro",
    });
    // The browser release comes from the build-time public version (D10);
    // SENTRY_RELEASE is non-public and never reaches the client.
    vi.stubEnv("NEXT_PUBLIC_PROWLER_RELEASE_VERSION", "1.30.0");

    // When
    await import("@/instrumentation-client");

    // Then
    expect(initMock).toHaveBeenCalledTimes(1);
    expect(initMock.mock.calls[0][0]).toMatchObject({
      dsn: "https://key@o0.ingest.sentry.io/1",
      environment: "pro",
      release: "1.30.0",
    });
  });

  it("does not initialize Sentry when the DSN is absent", async () => {
    // Given
    getConfigMock.mockReturnValue({ ...EMPTY_RUNTIME_PUBLIC_CONFIG });

    // When
    await import("@/instrumentation-client");

    // Then
    expect(initMock).not.toHaveBeenCalled();
  });

  it("defaults to a non-dev environment so an unset WEB_APP_SENTRY_ENVIRONMENT does not enable dev mode (R6)", async () => {
    // Given - DSN set but environment unset
    getConfigMock.mockReturnValue({
      ...EMPTY_RUNTIME_PUBLIC_CONFIG,
      sentryDsn: "https://key@o0.ingest.sentry.io/1",
    });

    // When
    await import("@/instrumentation-client");

    // Then
    const options = initMock.mock.calls[0][0];
    expect(options.environment).toBe("production");
    expect(options.debug).toBe(false);
    expect(options.tracesSampleRate).toBe(0.5);
    expect(setUserMock).not.toHaveBeenCalled();
  });
});
