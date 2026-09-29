import { afterEach, describe, expect, it, vi } from "vitest";

import {
  getRegistryPresentation,
  readRegistryPresentation,
} from "./presentation";

describe("Registry presentation configuration", () => {
  const urlWithCredentials = new URL("https://registry.test");
  urlWithCredentials.username = "user";
  urlWithCredentials.password = "pass";

  it("uses the configured Registry and media origins", () => {
    expect(
      getRegistryPresentation(
        "https://registry.private.test/",
        "https://assets.private.test/media/",
      ),
    ).toEqual({
      registryUrl: "https://registry.private.test/",
      imageOrigins: [
        "https://registry.private.test",
        "https://assets.private.test",
      ],
    });
  });

  it("does not guess a Registry environment when configuration is missing", () => {
    expect(getRegistryPresentation()).toEqual({
      registryUrl: undefined,
      imageOrigins: [],
    });
  });

  it.each([
    "javascript:alert(1)",
    urlWithCredentials.href,
    "https://registry.test; img-src *",
    "invalid",
  ])("rejects unsafe configuration: %s", (value) => {
    expect(getRegistryPresentation(value, value)).toEqual({
      registryUrl: undefined,
      imageOrigins: [],
    });
  });
});

describe("Registry presentation from the runtime environment", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("links to the Registry the backend installs from", () => {
    // Given
    vi.stubEnv("PROWLER_REGISTRY_INDEX_URL", "https://registry.internal.test");
    vi.stubEnv("UI_REGISTRY_MEDIA_URL", "https://media.internal.test");

    // When / Then
    expect(readRegistryPresentation()).toEqual({
      registryUrl: "https://registry.internal.test/",
      imageOrigins: [
        "https://registry.internal.test",
        "https://media.internal.test",
      ],
    });
  });

  it("ignores the retired UI_REGISTRY_URL variable", () => {
    // Given
    vi.stubEnv("PROWLER_REGISTRY_INDEX_URL", "");
    vi.stubEnv("UI_REGISTRY_MEDIA_URL", "");
    vi.stubEnv("UI_REGISTRY_URL", "https://registry.prowler.com");

    // When / Then
    expect(readRegistryPresentation()).toEqual({
      registryUrl: undefined,
      imageOrigins: [],
    });
  });
});
