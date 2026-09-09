import { describe, expect, it } from "vitest";

import type { RegistryCatalogArtifact } from "@/types/registry";

import { buildRegistryMarketplaceModel } from "./registry-explorer.model";

const artifact = (
  normalizedName: string,
  overrides: Partial<RegistryCatalogArtifact> = {},
): RegistryCatalogArtifact => ({
  normalizedName,
  name: normalizedName,
  providers: [],
  isVerified: false,
  isOfficial: false,
  isBuiltin: false,
  isMeta: false,
  hasProvider: false,
  hasChecks: false,
  hasCompliance: false,
  versionCount: 0,
  totalDownloads: 0,
  owners: [],
  ...overrides,
});

describe("Registry marketplace model", () => {
  it("keeps the full catalog visible with tenant membership merged in", () => {
    // Given

    const catalog = {
      status: "complete" as const,
      artifacts: [
        artifact("zeta", { providers: ["azure"], hasProvider: true }),
        artifact("core", { providers: ["aws"], isOfficial: true }),
        artifact("global", {
          name: "Global insight",
          description: "Security checks",
          providers: ["aws", "gcp"],
          hasChecks: true,
          isOfficial: true,
        }),
      ],
    };

    const mine = [
      { normalizedName: "core", versionSpec: "latest" },
      { normalizedName: "manual", versionSpec: "1.2.3" },
    ];

    // When
    const model = buildRegistryMarketplaceModel(catalog, mine, {}, "name");

    // Then

    expect(model).toMatchObject({
      isComplete: true,
      providers: ["aws", "azure", "gcp"],
    });
    if (!model.isComplete) throw new Error("expected complete model");

    expect(
      model.artifacts.map(({ normalizedName, isAdded }) => ({
        normalizedName,
        isAdded,
      })),
    ).toEqual([
      { normalizedName: "core", isAdded: true },
      { normalizedName: "global", isAdded: false },
      { normalizedName: "zeta", isAdded: false },
    ]);

    expect(model.myArtifacts).toEqual([
      {
        normalizedName: "core",
        versionSpec: "latest",
        catalogArtifact: expect.objectContaining({
          normalizedName: "core",
          isAdded: true,
        }),
      },
      {
        normalizedName: "manual",
        versionSpec: "1.2.3",
        catalogArtifact: undefined,
      },
    ]);
  });

  it("applies search, provider, and capability filters together", () => {
    // Given

    const catalog = {
      status: "complete" as const,
      artifacts: [
        artifact("core", { providers: ["aws"] }),
        artifact("global", {
          name: "Global insight",
          description: "Security checks",
          providers: ["aws", "gcp"],
          hasChecks: true,
        }),
        artifact("zeta", { providers: ["azure"], hasProvider: true }),
      ],
    };

    // When

    const model = buildRegistryMarketplaceModel(
      catalog,
      [],
      { search: "security", providers: ["aws"], capabilities: ["checks"] },
      "name",
    );

    // Then
    if (!model.isComplete) throw new Error("expected complete model");
    expect(model.artifacts.map(({ normalizedName }) => normalizedName)).toEqual(
      ["global"],
    );
  });

  it("unions providers and capabilities within each filter", () => {
    // Given
    const catalog = {
      status: "complete" as const,
      artifacts: [
        artifact("aws-checks", { providers: ["aws"], hasChecks: true }),
        artifact("gcp-provider", { providers: ["gcp"], hasProvider: true }),
        artifact("azure-checks", { providers: ["azure"], hasChecks: true }),
      ],
    };
    // When
    const model = buildRegistryMarketplaceModel(
      catalog,
      [],
      { providers: ["aws", "gcp"], capabilities: ["checks", "provider"] },
      "name",
    );
    // Then
    expect(model).toMatchObject({
      artifacts: [
        expect.objectContaining({ normalizedName: "aws-checks" }),
        expect.objectContaining({ normalizedName: "gcp-provider" }),
      ],
    });
  });

  it("sorts by downloads descending with name as the tiebreak", () => {
    // Given

    const catalog = {
      status: "complete" as const,
      artifacts: [
        artifact("alpha", { totalDownloads: 5 }),
        artifact("delta", { totalDownloads: 9 }),
        artifact("beta", { totalDownloads: 5 }),
      ],
    };

    // When
    const model = buildRegistryMarketplaceModel(catalog, [], {}, "downloads");

    // Then
    if (!model.isComplete) throw new Error("expected complete model");
    expect(model.artifacts.map(({ normalizedName }) => normalizedName)).toEqual(
      ["delta", "alpha", "beta"],
    );
  });

  it("keeps incomplete catalogs out of complete-only controls and selectors", () => {
    // Given

    const catalog = {
      status: "incomplete" as const,
      reason: "page_failed" as const,
      collectedCount: 3,
    };

    // When
    const model = buildRegistryMarketplaceModel(
      catalog,
      [],
      { search: "core" },
      "name",
    );

    // Then

    expect(model).toEqual({
      isComplete: false,
    });
  });
});
