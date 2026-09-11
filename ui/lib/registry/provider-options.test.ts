import { describe, expect, it } from "vitest";

import type { RegistryCatalogArtifact } from "@/types/registry";

import { buildRegistryProviderOptions } from "./provider-options";

const provider: RegistryCatalogArtifact = {
  normalizedName: "acme-package",
  name: "Acme",
  providers: ["acme"],
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
      { ...provider, normalizedName: "known", providers: ["aws"] },
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
