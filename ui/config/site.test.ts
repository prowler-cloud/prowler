import { afterEach, describe, expect, it, vi } from "vitest";

describe("siteConfig", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it.each(["false", "true"])(
    "names the application Cloudy whatever UI_CLOUD_ENABLED is (%s)",
    async (cloudEnabled) => {
      // Given
      vi.stubEnv("UI_CLOUD_ENABLED", cloudEnabled);

      // When
      const { siteConfig } = await import("./site");

      // Then
      expect(siteConfig.name).toBe("Cloudy");
      expect(siteConfig.description).not.toMatch(/Prowler Cloud/);
    },
  );
});
