import { describe, expect, it } from "vitest";

import {
  adaptProviderSchemas,
  normalizeProviderType,
} from "./provider-schemas.adapter";

describe("provider schemas adapter", () => {
  it("adapts a matching provider schema resource without interpreting schema keywords", () => {
    // Given
    const payload = {
      data: {
        type: "provider-schemas",
        id: "acme",
        attributes: {
          secret_types: {
            credentials: {
              type: "object",
              properties: { access_key: { type: "string" } },
            },
          },
        },
      },
    };

    // When
    const result = adaptProviderSchemas(payload, "acme");

    // Then
    expect(result).toEqual({
      status: "success",
      providerType: "acme",
      secretTypes: payload.data.attributes.secret_types,
    });
  });

  it.each([
    ["null", null],
    ["string scalar", "secret"],
    ["number scalar", 1],
    ["boolean scalar", true],
  ])("rejects %s secret_types values", (_description, secretType) => {
    // Given
    const payload = {
      data: {
        type: "provider-schemas",
        id: "acme",
        attributes: { secret_types: { credentials: secretType } },
      },
    };

    // When
    const result = adaptProviderSchemas(payload, "acme");

    // Then
    expect(result).toBeNull();
  });

  it("rejects malformed or contradictory documents without reading schema keywords", () => {
    // Given
    const document = {
      data: {
        type: "provider-schemas",
        id: "aws",
        attributes: { secret_types: {} },
      },
    };

    // When
    const results = [
      { ...document, errors: [] },
      { data: { ...document.data, id: "aws " } },
      { data: { ...document.data, type: "providers" } },
      { data: { ...document.data, attributes: { secret_types: { key: [] } } } },
    ].map((payload) => adaptProviderSchemas(payload, "aws"));

    // Then
    expect(results).toEqual([null, null, null, null]);
    expect(normalizeProviderType(" AWS ")).toBe("aws");
    expect(normalizeProviderType(" ")).toBeNull();
    expect(normalizeProviderType("a".repeat(51))).toBeNull();
  });
});
