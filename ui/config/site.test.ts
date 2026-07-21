import { afterEach, describe, expect, it, vi } from "vitest";

describe("siteConfig", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it("names the open-source application Prowler Local Server", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    // When
    const { siteConfig } = await import("./site");

    // Then
    expect(siteConfig.name).toBe("Prowler Local Server");
  });

  it("keeps the Prowler Cloud name in Cloud", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    // When
    const { siteConfig } = await import("./site");

    // Then
    expect(siteConfig.name).toBe("Prowler Cloud");
  });
});
