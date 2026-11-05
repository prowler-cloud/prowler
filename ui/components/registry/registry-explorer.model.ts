import {
  REGISTRY_CATALOG,
  type RegistryCatalogArtifact,
  type RegistryCatalogResult,
  type RegistryTenantArtifact,
} from "@/types/registry";

export const REGISTRY_CATALOG_CAPABILITY = {
  CHECKS: "checks",
  COMPLIANCE: "compliance",
  PROVIDER: "provider",
} as const;

export type RegistryCatalogCapability =
  (typeof REGISTRY_CATALOG_CAPABILITY)[keyof typeof REGISTRY_CATALOG_CAPABILITY];

export const REGISTRY_CAPABILITY_LABELS = {
  checks: "Checks",
  compliance: "Compliance",
  provider: "Provider",
} as const satisfies Record<RegistryCatalogCapability, string>;

export interface RegistryExplorerFilters {
  search?: string;
  providers?: string[];
  capabilities?: RegistryCatalogCapability[];
}

export const REGISTRY_MARKETPLACE_SORT = {
  NAME: "name",
  DOWNLOADS: "downloads",
} as const;

export type RegistryMarketplaceSort =
  (typeof REGISTRY_MARKETPLACE_SORT)[keyof typeof REGISTRY_MARKETPLACE_SORT];

export interface RegistryMarketplaceArtifact extends RegistryCatalogArtifact {
  isAdded: boolean;
  resolvedVersion?: string;
  updateAvailable: boolean;
  /** Built-in providers the install adds checks to; empty until installed. */
  extendsProviderSlugs: string[];
}

export interface RegistryMarketplaceMyArtifact extends RegistryTenantArtifact {
  catalogArtifact?: RegistryMarketplaceArtifact;
}

export interface RegistryMarketplaceIncompleteModel {
  isComplete: false;
}

export interface RegistryMarketplaceCompleteModel {
  isComplete: true;
  artifacts: RegistryMarketplaceArtifact[];
  providers: string[];
  myArtifacts: RegistryMarketplaceMyArtifact[];
}

export type RegistryMarketplaceModel =
  | RegistryMarketplaceIncompleteModel
  | RegistryMarketplaceCompleteModel;

export function buildRegistryMarketplaceModel(
  catalog: RegistryCatalogResult,
  myArtifacts: RegistryTenantArtifact[],
  filters: RegistryExplorerFilters,
  sort: RegistryMarketplaceSort,
): RegistryMarketplaceModel {
  if (catalog.status !== REGISTRY_CATALOG.COMPLETE)
    return {
      isComplete: false,
    };
  const installedArtifacts = new Map(
    myArtifacts.map((artifact) => [artifact.normalizedName, artifact]),
  );
  const merged = new Map(
    catalog.artifacts.map((artifact) => {
      const installed = installedArtifacts.get(artifact.normalizedName);
      const resolvedVersion = installed?.resolvedVersion?.trim() || undefined;
      const latestVersion = artifact.latestVersion?.trim() || undefined;
      return [
        artifact.normalizedName,
        {
          ...artifact,
          latestVersion,
          resolvedVersion,
          isAdded: Boolean(installed),
          // Versions alone: a checks artifact defines no provider yet updates.
          updateAvailable: Boolean(
            resolvedVersion &&
              latestVersion &&
              resolvedVersion !== latestVersion,
          ),
          extendsProviderSlugs: installed?.extendsProviderSlugs ?? [],
        },
      ];
    }),
  );
  const artifacts = Array.from(merged.values())
    .filter((artifact) => matches(artifact, filters))
    .sort((left, right) =>
      sort === REGISTRY_MARKETPLACE_SORT.DOWNLOADS
        ? right.totalDownloads - left.totalDownloads ||
          compare(left.normalizedName, right.normalizedName)
        : compare(left.normalizedName, right.normalizedName),
    );
  return {
    isComplete: true,
    artifacts,
    providers: Array.from(
      new Set(catalog.artifacts.flatMap((artifact) => artifact.providers)),
    ).sort(compare),
    myArtifacts: myArtifacts
      .map((installed) => ({
        normalizedName: installed.normalizedName,
        versionSpec: installed.versionSpec,
        resolvedVersion: installed.resolvedVersion?.trim() || undefined,
        extendsProviderSlugs: installed.extendsProviderSlugs ?? [],
        catalogArtifact: merged.get(installed.normalizedName),
      }))
      .sort((left, right) =>
        compare(left.normalizedName, right.normalizedName),
      ),
  };
}

function matches(
  artifact: RegistryCatalogArtifact,
  filters: RegistryExplorerFilters,
) {
  const search = filters.search?.trim().toLowerCase();
  const providers = (filters.providers ?? []).map((provider) =>
    provider.trim().toLowerCase(),
  );
  const text =
    `${artifact.normalizedName} ${artifact.name ?? ""} ${artifact.description ?? ""}`.toLowerCase();
  return (
    (!search || text.includes(search)) &&
    (providers.length === 0 ||
      providers.some((provider) => artifact.providers.includes(provider))) &&
    (filters.capabilities?.length ? filters.capabilities : [undefined]).some(
      (capability) =>
        !capability ||
        (capability === REGISTRY_CATALOG_CAPABILITY.CHECKS &&
          artifact.hasChecks) ||
        (capability === REGISTRY_CATALOG_CAPABILITY.COMPLIANCE &&
          artifact.hasCompliance) ||
        (capability === REGISTRY_CATALOG_CAPABILITY.PROVIDER &&
          artifact.hasProvider),
    )
  );
}
function compare(left: string, right: string) {
  return left < right ? -1 : left > right ? 1 : 0;
}
