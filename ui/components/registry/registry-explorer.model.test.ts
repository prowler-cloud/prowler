import { describe, expect, it } from "vitest";

import type { RegistryCatalogArtifact } from "@/types/registry";

import { buildRegistryMarketplaceModel } from "./registry-explorer.model";

// prettier-ignore
const artifact = (normalizedName: string, overrides: Partial<RegistryCatalogArtifact> = {}): RegistryCatalogArtifact => ({ normalizedName, name: normalizedName, providers: [], isVerified: false, isOfficial: false, isBuiltin: false, isMeta: false, hasProvider: false, hasChecks: false, hasCompliance: false, versionCount: 0, totalDownloads: 0, owners: [], ...overrides });

describe("Registry marketplace model", () => {
  it("keeps the full catalog visible with tenant membership merged in", () => {
    // Given
    // prettier-ignore
    const catalog = { status: "complete" as const, artifacts: [artifact("zeta", { providers: ["azure"], hasProvider: true }), artifact("core", { providers: ["aws"], isOfficial: true }), artifact("global", { name: "Global insight", description: "Security checks", providers: ["aws", "gcp"], hasChecks: true, isOfficial: true })] };
    // prettier-ignore
    const mine = [{ normalizedName: "core", versionSpec: "latest" }, { normalizedName: "manual", versionSpec: "1.2.3" }];

    // When
    const model = buildRegistryMarketplaceModel(catalog, mine, {}, "name");

    // Then
    // prettier-ignore
    expect(model).toMatchObject({ isComplete: true, canExplore: true, providers: ["aws", "azure", "gcp"], metrics: { providers: 3, availableArtifacts: 2, myArtifacts: 2, officialArtifacts: 2 } });
    if (!model.isComplete) throw new Error("expected complete model");
    // prettier-ignore
    expect(model.artifacts.map(({ normalizedName, isAdded, addedVersionSpec }) => ({ normalizedName, isAdded, addedVersionSpec }))).toEqual([
      { normalizedName: "core", isAdded: true, addedVersionSpec: "latest" },
      { normalizedName: "global", isAdded: false, addedVersionSpec: undefined },
      { normalizedName: "zeta", isAdded: false, addedVersionSpec: undefined },
    ]);
    // prettier-ignore
    expect(model.myArtifacts).toEqual([
      { normalizedName: "core", versionSpec: "latest", catalogArtifact: expect.objectContaining({ normalizedName: "core", isAdded: true }) },
      { normalizedName: "manual", versionSpec: "1.2.3", catalogArtifact: undefined },
    ]);
  });

  it("applies search, provider, and capability filters together", () => {
    // Given
    // prettier-ignore
    const catalog = { status: "complete" as const, artifacts: [artifact("core", { providers: ["aws"] }), artifact("global", { name: "Global insight", description: "Security checks", providers: ["aws", "gcp"], hasChecks: true }), artifact("zeta", { providers: ["azure"], hasProvider: true })] };

    // When
    // prettier-ignore
    const model = buildRegistryMarketplaceModel(catalog, [], { search: "security", provider: "aws", capabilities: ["checks"] }, "name");

    // Then
    if (!model.isComplete) throw new Error("expected complete model");
    expect(model.artifacts.map(({ normalizedName }) => normalizedName)).toEqual(
      ["global"],
    );
  });

  it("sorts by downloads descending with name as the tiebreak", () => {
    // Given
    // prettier-ignore
    const catalog = { status: "complete" as const, artifacts: [artifact("alpha", { totalDownloads: 5 }), artifact("delta", { totalDownloads: 9 }), artifact("beta", { totalDownloads: 5 })] };

    // When
    const model = buildRegistryMarketplaceModel(catalog, [], {}, "downloads");

    // Then
    if (!model.isComplete) throw new Error("expected complete model");
    expect(model.artifacts.map(({ normalizedName }) => normalizedName)).toEqual(
      ["delta", "alpha", "beta"],
    );
  });

  it("keeps non-member built-ins discoverable without counting them as available", () => {
    // Given
    const catalog = {
      status: "complete" as const,
      artifacts: [
        artifact("built-in-provider", {
          isBuiltin: true,
          providers: ["aws"],
          hasProvider: true,
        }),
      ],
    };

    // When
    const model = buildRegistryMarketplaceModel(
      catalog,
      [],
      { search: "built", provider: "aws", capabilities: ["provider"] },
      "name",
    );

    // Then
    if (!model.isComplete) throw new Error("expected complete model");
    expect(model.artifacts).toEqual([
      expect.objectContaining({
        normalizedName: "built-in-provider",
        isAdded: false,
        isBuiltin: true,
      }),
    ]);
    expect(model.metrics.availableArtifacts).toBe(0);
    expect(model.myArtifacts).toEqual([]);
  });

  it("preserves authoritative membership for a built-in artifact", () => {
    // Given
    const catalog = {
      status: "complete" as const,
      artifacts: [
        artifact("built-in-member", {
          isBuiltin: true,
          isOfficial: true,
          providers: ["aws"],
        }),
      ],
    };

    // When
    const model = buildRegistryMarketplaceModel(
      catalog,
      [{ normalizedName: "built-in-member", versionSpec: "2.0.0" }],
      {},
      "name",
    );

    // Then
    if (!model.isComplete) throw new Error("expected complete model");
    expect(model.artifacts).toEqual([
      expect.objectContaining({
        normalizedName: "built-in-member",
        isAdded: true,
        isBuiltin: true,
        addedVersionSpec: "2.0.0",
      }),
    ]);
    expect(model.myArtifacts).toEqual([
      expect.objectContaining({
        normalizedName: "built-in-member",
        versionSpec: "2.0.0",
        catalogArtifact: expect.objectContaining({
          isAdded: true,
          isBuiltin: true,
        }),
      }),
    ]);
    expect(model.metrics).toEqual({
      providers: 1,
      availableArtifacts: 0,
      myArtifacts: 1,
      officialArtifacts: 1,
    });
  });

  it("keeps incomplete catalogs out of complete-only controls and selectors", () => {
    // Given
    // prettier-ignore
    const catalog = { status: "incomplete" as const, reason: "page_failed" as const, collectedCount: 3 };

    // When
    const model = buildRegistryMarketplaceModel(
      catalog,
      [],
      { search: "core" },
      "name",
    );

    // Then
    // prettier-ignore
    expect(model).toEqual({ isComplete: false, canExplore: false, canRetry: true, controls: { search: false, filters: false, hierarchy: false, metrics: false } });
  });
});
