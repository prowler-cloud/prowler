import { describe, expect, it } from "vitest";

import type { RegistryCatalogArtifact } from "@/types/registry";

import {
  buildRegistryExplorerModel,
  getRegistryArtifactDetail,
} from "./registry-explorer.model";

// prettier-ignore
const artifact = (normalizedName: string, overrides: Partial<RegistryCatalogArtifact> = {}): RegistryCatalogArtifact => ({ normalizedName, name: normalizedName, providers: [], isVerified: false, isOfficial: false, isMeta: false, hasProvider: false, hasChecks: false, hasCompliance: false, versionCount: 0, totalDownloads: 0, owners: [], ...overrides });

describe("Registry explorer model", () => {
  it("derives complete Available data, hierarchy, filters, details, and metrics", () => {
    // Given
    // prettier-ignore
    const catalog = { status: "complete" as const, artifacts: [artifact("core", { providers: ["aws"], isOfficial: true }), artifact("global", { name: "Global insight", description: "Security checks", providers: ["aws", "gcp"], hasChecks: true, isOfficial: true }), artifact("zeta", { providers: ["azure"], hasProvider: true })] };
    // prettier-ignore
    const mine = [{ normalizedName: "core", versionSpec: "latest" }, { normalizedName: "manual", versionSpec: "1.2.3" }];

    // When
    // prettier-ignore
    const model = buildRegistryExplorerModel(catalog, mine, { search: "security", provider: "aws", capabilities: ["checks"] });

    // Then
    // prettier-ignore
    expect(model).toMatchObject({ isComplete: true, canExplore: true, available: [{ normalizedName: "global" }], hierarchy: { providers: expect.arrayContaining([expect.objectContaining({ provider: "aws" }), expect.objectContaining({ provider: "gcp" })]), multiProvider: [{ normalizedName: "global" }] }, metrics: { providers: 3, availableArtifacts: 2, myArtifacts: 2, officialArtifacts: 2 } });
    // prettier-ignore
    expect(getRegistryArtifactDetail("manual", catalog.artifacts, mine)).toEqual({ catalogArtifact: undefined, tenantArtifact: mine[1] });
  });

  it("keeps incomplete catalogs out of complete-only controls and selectors", () => {
    // Given
    // prettier-ignore
    const catalog = { status: "incomplete" as const, reason: "page_failed" as const, collectedCount: 3 };

    // When
    const model = buildRegistryExplorerModel(catalog, [], { search: "core" });

    // Then
    // prettier-ignore
    expect(model).toEqual({ isComplete: false, canExplore: false, canRetry: true, controls: { search: false, filters: false, hierarchy: false, metrics: false } });
  });
});
