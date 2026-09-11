import { describe, expect, it } from "vitest";

import { getRegistryPresentation } from "./presentation";

describe("Registry presentation configuration", () => {
  it("uses the configured Registry and media origins", () => {
    expect(
      getRegistryPresentation(
        "https://registry.private.test/keys",
        "https://assets.private.test/media/",
      ),
    ).toEqual({
      keyUrl: "https://registry.private.test/keys",
      imageOrigins: [
        "https://registry.private.test",
        "https://assets.private.test",
      ],
    });
  });

  it("does not guess a Registry environment when configuration is missing", () => {
    expect(getRegistryPresentation()).toEqual({
      keyUrl: undefined,
      imageOrigins: [],
    });
  });

  it.each([
    "javascript:alert(1)",
    "https://user:password@registry.test",
    "https://registry.test; img-src *",
    "invalid",
  ])("rejects unsafe configuration: %s", (value) => {
    expect(getRegistryPresentation(value, value)).toEqual({
      keyUrl: undefined,
      imageOrigins: [],
    });
  });
});
