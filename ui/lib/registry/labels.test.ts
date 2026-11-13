import { describe, expect, it } from "vitest";

import { formatRegistryLabel } from "./labels";

describe("formatRegistryLabel", () => {
  it("capitalizes plain identifiers and keeps any other value as written", () => {
    // When
    const labels = ["token", "service_account", "us-east-1", "OAuth2"].map(
      formatRegistryLabel,
    );

    // Then
    expect(labels).toEqual(["Token", "Service account", "us-east-1", "OAuth2"]);
  });
});
