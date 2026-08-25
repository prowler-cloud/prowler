// prettier-ignore
import { REGISTRY_CATALOG, type RegistryCatalogArtifact, type RegistryCatalogResult, type RegistryTenantArtifact } from "@/types/registry";

// prettier-ignore
export const REGISTRY_CATALOG_CAPABILITY = { CHECKS: "checks", COMPLIANCE: "compliance", PROVIDER: "provider" } as const;
// prettier-ignore
export type RegistryCatalogCapability = (typeof REGISTRY_CATALOG_CAPABILITY)[keyof typeof REGISTRY_CATALOG_CAPABILITY];
// prettier-ignore
export const REGISTRY_CAPABILITY_LABELS = { checks: "Checks", compliance: "Compliance", provider: "Provider" } as const satisfies Record<RegistryCatalogCapability, string>;
// prettier-ignore
export interface RegistryExplorerFilters { search?: string; provider?: string; capabilities?: RegistryCatalogCapability[]; }

// prettier-ignore
export const REGISTRY_MARKETPLACE_SORT = { NAME: "name", DOWNLOADS: "downloads" } as const;
// prettier-ignore
export type RegistryMarketplaceSort = (typeof REGISTRY_MARKETPLACE_SORT)[keyof typeof REGISTRY_MARKETPLACE_SORT];
// prettier-ignore
export interface RegistryMarketplaceArtifact extends RegistryCatalogArtifact { isAdded: boolean; addedVersionSpec?: string }
// prettier-ignore
export interface RegistryMarketplaceMyArtifact { normalizedName: string; versionSpec: string; catalogArtifact?: RegistryMarketplaceArtifact }
// prettier-ignore
export interface RegistryMarketplaceControls { search: boolean; filters: boolean; hierarchy: boolean; metrics: boolean }
// prettier-ignore
export interface RegistryMarketplaceMetrics { providers: number; availableArtifacts: number; myArtifacts: number; officialArtifacts: number }
// prettier-ignore
export interface RegistryMarketplaceIncompleteModel { isComplete: false; canExplore: false; canRetry: true; controls: RegistryMarketplaceControls }
// prettier-ignore
export interface RegistryMarketplaceCompleteModel { isComplete: true; canExplore: true; artifacts: RegistryMarketplaceArtifact[]; providers: string[]; myArtifacts: RegistryMarketplaceMyArtifact[]; metrics: RegistryMarketplaceMetrics }
// prettier-ignore
export type RegistryMarketplaceModel = RegistryMarketplaceIncompleteModel | RegistryMarketplaceCompleteModel;

// prettier-ignore
export function buildRegistryMarketplaceModel(catalog: RegistryCatalogResult, myArtifacts: RegistryTenantArtifact[], filters: RegistryExplorerFilters, sort: RegistryMarketplaceSort): RegistryMarketplaceModel {
  if (catalog.status !== REGISTRY_CATALOG.COMPLETE) return { isComplete: false, canExplore: false, canRetry: true, controls: { search: false, filters: false, hierarchy: false, metrics: false } };
  const specs = new Map(myArtifacts.map(({ normalizedName, versionSpec }) => [normalizedName, versionSpec]));
  const merged = new Map(catalog.artifacts.map((artifact) => [artifact.normalizedName, { ...artifact, isAdded: specs.has(artifact.normalizedName), addedVersionSpec: specs.get(artifact.normalizedName) }]));
  const artifacts = Array.from(merged.values()).filter((artifact) => matches(artifact, filters)).sort((left, right) =>
    sort === REGISTRY_MARKETPLACE_SORT.DOWNLOADS
      ? right.totalDownloads - left.totalDownloads || compare(left.normalizedName, right.normalizedName)
      : compare(left.normalizedName, right.normalizedName));
  return { isComplete: true, canExplore: true, artifacts,
    providers: Array.from(new Set(catalog.artifacts.flatMap((artifact) => artifact.providers))).sort(compare),
    myArtifacts: myArtifacts.map(({ normalizedName, versionSpec }) => ({ normalizedName, versionSpec, catalogArtifact: merged.get(normalizedName) })).sort((left, right) => compare(left.normalizedName, right.normalizedName)),
    metrics: { providers: new Set(catalog.artifacts.flatMap((artifact) => artifact.providers)).size, availableArtifacts: catalog.artifacts.filter(({ normalizedName }) => !specs.has(normalizedName)).length, myArtifacts: myArtifacts.length, officialArtifacts: catalog.artifacts.filter((artifact) => artifact.isOfficial).length },
  };
}

// prettier-ignore
export function getRegistryArtifactDetail(normalizedName: string, artifacts: RegistryCatalogArtifact[], myArtifacts: RegistryTenantArtifact[]) {
  const catalogArtifact = artifacts.find((artifact) => artifact.normalizedName === normalizedName);
  const tenantArtifact = myArtifacts.find((artifact) => artifact.normalizedName === normalizedName);
  return catalogArtifact || tenantArtifact ? { catalogArtifact, tenantArtifact } : null;
}

// prettier-ignore
function matches(artifact: RegistryCatalogArtifact, filters: RegistryExplorerFilters) {
  const search = filters.search?.trim().toLowerCase();
  const provider = filters.provider?.trim().toLowerCase();
  const text = `${artifact.normalizedName} ${artifact.name ?? ""} ${artifact.description ?? ""}`.toLowerCase();
  return (!search || text.includes(search)) && (!provider || artifact.providers.includes(provider)) && (filters.capabilities ?? []).every((capability) => (capability === REGISTRY_CATALOG_CAPABILITY.CHECKS && artifact.hasChecks) || (capability === REGISTRY_CATALOG_CAPABILITY.COMPLIANCE && artifact.hasCompliance) || (capability === REGISTRY_CATALOG_CAPABILITY.PROVIDER && artifact.hasProvider));
}
function compare(left: string, right: string) {
  return left < right ? -1 : left > right ? 1 : 0;
}
