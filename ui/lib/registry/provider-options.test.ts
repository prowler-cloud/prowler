import { describe, expect, it } from "vitest";

import { collectCompleteRegistryCatalog } from "@/actions/registry/registry.adapter";
import type { RegistryCatalogArtifact } from "@/types/registry";

import { buildRegistryProviderOptions } from "./provider-options";

const provider: RegistryCatalogArtifact = {
  normalizedName: "acme-package",
  name: "Acme",
  providers: ["acme"],
  providerSlug: "acme",
  hasProvider: true,
  isBuiltin: false,
  isVerified: false,
  isOfficial: false,
  isMeta: false,
  hasChecks: true,
  hasCompliance: false,
  versionCount: 1,
  totalDownloads: 0,
  owners: [],
};

describe("installed Registry provider options", () => {
  it("does not infer a provider from checks targets in merged catalog records", async () => {
    // Given: only the checks record names a target provider.
    const catalog = await collectCompleteRegistryCatalog(async () => ({
      data: [
        {
          type: "registry-artifacts",
          id: "external-package",
          attributes: { has_provider: true },
        },
        {
          type: "registry-artifacts",
          id: "external-package",
          attributes: {
            has_provider: false,
            providers: ["target-only"],
            has_checks: true,
          },
        },
      ],
      meta: { pagination: { page: 1, pages: 1, count: 2 } },
    }));
    expect(catalog.status).toBe("complete");
    if (catalog.status !== "complete") throw new Error("Incomplete fixture");

    // When / Then: installed membership cannot manufacture a declared type.
    expect(
      buildRegistryProviderOptions(
        catalog.artifacts,
        [{ normalizedName: "external-package", versionSpec: "latest" }],
        [],
      ),
    ).toEqual([]);
  });

  it("joins confirmed membership, uses backend slugs and excludes non-providers and built-ins", () => {
    const catalog = [
      provider,
      { ...provider, normalizedName: "other-package", providers: ["acme"] },
      {
        ...provider,
        normalizedName: "checks",
        hasProvider: false,
        providers: ["checks"],
      },
      {
        ...provider,
        normalizedName: "builtin",
        isBuiltin: true,
        providers: ["builtin"],
      },
      {
        ...provider,
        normalizedName: "known",
        providers: ["aws"],
        providerSlug: "aws",
      },
      {
        ...provider,
        normalizedName: "uninstalled",
        providers: ["uninstalled"],
      },
    ];
    const installed = catalog
      .slice(0, -1)
      .map(({ normalizedName }) => ({ normalizedName, versionSpec: "latest" }));
    expect(
      buildRegistryProviderOptions(catalog, installed, [
        {
          type: "acme",
          label: "Acme Cloud",
          logoUrl: "https://media.registry.dev.prowler.com/acme.svg",
        },
      ]),
    ).toEqual([
      {
        type: "acme",
        label: "Acme Cloud",
        logoUrl: "https://media.registry.dev.prowler.com/acme.svg",
      },
    ]);
    expect(buildRegistryProviderOptions(catalog, [], [])).toEqual([]);
  });
  it("uses the declared provider rather than other providers targeted by the package", () => {
    const catalog = [
      { ...provider, providerSlug: "zeta", providers: ["acme", "zeta"] },
    ];
    expect(
      buildRegistryProviderOptions(
        catalog,
        [{ normalizedName: provider.normalizedName, versionSpec: "latest" }],
        [],
      ).map((option) => option.type),
    ).toEqual(["zeta"]);
  });
});
