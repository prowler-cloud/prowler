import { describe, expect, it } from "vitest";

import { ProviderProps } from "@/types/providers";

import {
  filterProvidersByScope,
  parseFilterIds,
  scopeProvidersByGroup,
} from "./provider-scope";

const makeProvider = (
  id: string,
  provider: string,
  groupIds: string[] = [],
): ProviderProps =>
  ({
    id,
    attributes: { provider },
    relationships: {
      provider_groups: {
        data: groupIds.map((gid) => ({ type: "provider-groups", id: gid })),
      },
    },
  }) as unknown as ProviderProps;

describe("parseFilterIds", () => {
  it("returns an empty array for undefined", () => {
    // Given / When / Then
    expect(parseFilterIds(undefined)).toEqual([]);
  });

  it("returns an empty array for an empty string", () => {
    // Given an empty param value (e.g. "filter[provider_groups__in]=")
    // When / Then it must not produce a [""] match
    expect(parseFilterIds("")).toEqual([]);
  });

  it("drops whitespace-only and empty segments", () => {
    // Given a blank/whitespace value
    // When / Then
    expect(parseFilterIds("   ")).toEqual([]);
    expect(parseFilterIds(",")).toEqual([]);
    expect(parseFilterIds("a,,b")).toEqual(["a", "b"]);
  });

  it("splits and trims comma-separated ids", () => {
    expect(parseFilterIds(" a , b ")).toEqual(["a", "b"]);
  });

  it("normalizes array param values", () => {
    expect(parseFilterIds(["a", "", "b"])).toEqual(["a", "b"]);
  });
});

describe("scopeProvidersByGroup", () => {
  const providers = [
    makeProvider("p1", "aws", ["g1"]),
    makeProvider("p2", "gcp", ["g2"]),
    makeProvider("p3", "azure", []),
  ];

  it("returns every provider when no group is selected", () => {
    expect(scopeProvidersByGroup(providers, [])).toEqual(providers);
  });

  it("keeps only providers that belong to a selected group", () => {
    // When scoping to g1
    const result = scopeProvidersByGroup(providers, ["g1"]);

    // Then only the g1 member remains
    expect(result.map((p) => p.id)).toEqual(["p1"]);
  });

  it("excludes providers with no group memberships", () => {
    expect(scopeProvidersByGroup(providers, ["g2"]).map((p) => p.id)).toEqual([
      "p2",
    ]);
  });
});

describe("filterProvidersByScope", () => {
  const providers = [
    makeProvider("p1", "aws", ["g1"]),
    makeProvider("p2", "gcp", ["g1"]),
    makeProvider("p3", "aws", ["g2"]),
    makeProvider("p4", "azure", []),
  ];

  it("returns every provider when no dimension is set", () => {
    const result = filterProvidersByScope(providers, {
      providerIds: [],
      providerTypes: [],
      providerGroupIds: [],
    });

    expect(result).toEqual(providers);
  });

  it("filters by provider id", () => {
    const result = filterProvidersByScope(providers, {
      providerIds: ["p2"],
      providerTypes: [],
      providerGroupIds: [],
    });

    expect(result.map((p) => p.id)).toEqual(["p2"]);
  });

  it("filters by provider type case-insensitively", () => {
    const result = filterProvidersByScope(providers, {
      providerIds: [],
      providerTypes: ["AWS"],
      providerGroupIds: [],
    });

    expect(result.map((p) => p.id)).toEqual(["p1", "p3"]);
  });

  it("filters by provider group", () => {
    const result = filterProvidersByScope(providers, {
      providerIds: [],
      providerTypes: [],
      providerGroupIds: ["g1"],
    });

    expect(result.map((p) => p.id)).toEqual(["p1", "p2"]);
  });

  it("composes group AND type (the risk-plot regression)", () => {
    // Given both a group and a type filter are active
    // When combining group g1 with type aws
    const result = filterProvidersByScope(providers, {
      providerIds: [],
      providerTypes: ["aws"],
      providerGroupIds: ["g1"],
    });

    // Then only providers matching BOTH survive (p1), not all aws or all g1
    expect(result.map((p) => p.id)).toEqual(["p1"]);
  });

  it("composes id AND group", () => {
    // p3 is aws/g2; selecting it together with group g1 yields nothing
    const result = filterProvidersByScope(providers, {
      providerIds: ["p3"],
      providerTypes: [],
      providerGroupIds: ["g1"],
    });

    expect(result).toEqual([]);
  });

  it("composes all three dimensions", () => {
    const result = filterProvidersByScope(providers, {
      providerIds: ["p1", "p2"],
      providerTypes: ["aws"],
      providerGroupIds: ["g1"],
    });

    expect(result.map((p) => p.id)).toEqual(["p1"]);
  });
});
