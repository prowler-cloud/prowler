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
    // Given - WEB_APP_API_BASE_URL empty, the others present
    vi.stubEnv("WEB_APP_API_BASE_URL", "");
    vi.stubEnv("AUTH_URL", "http://localhost:3000");
    vi.stubEnv("AUTH_SECRET", "secret");

    // When / Then
    await expect(import("@/lib/env")).rejects.toThrow(
      "Missing required env: WEB_APP_API_BASE_URL",
    );
  });

  it("does not throw when every required env var is present", async () => {
    // Given
    vi.stubEnv("WEB_APP_API_BASE_URL", "https://api.example.com/api/v1");
    vi.stubEnv("AUTH_URL", "http://localhost:3000");
    vi.stubEnv("AUTH_SECRET", "secret");

    // When / Then
    await expect(import("@/lib/env")).resolves.toBeDefined();
  });
});
