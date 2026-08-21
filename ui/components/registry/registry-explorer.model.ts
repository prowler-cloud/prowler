// prettier-ignore
import type { RegistryCatalogArtifact, RegistryCatalogResult, RegistryTenantArtifact } from "@/types/registry";

// prettier-ignore
export const REGISTRY_CATALOG_CAPABILITY = { CHECKS: "checks", COMPLIANCE: "compliance", PROVIDER: "provider" } as const;
// prettier-ignore
export type RegistryCatalogCapability = (typeof REGISTRY_CATALOG_CAPABILITY)[keyof typeof REGISTRY_CATALOG_CAPABILITY];
// prettier-ignore
export interface RegistryExplorerFilters { search?: string; provider?: string; capabilities?: RegistryCatalogCapability[]; }

// prettier-ignore
export function buildRegistryExplorerModel(catalog: RegistryCatalogResult, myArtifacts: RegistryTenantArtifact[], filters: RegistryExplorerFilters) {
  if (catalog.status !== "complete") return { isComplete: false as const, canExplore: false, canRetry: true, controls: { search: false, filters: false, hierarchy: false, metrics: false } };
  const available = getAvailableArtifacts(catalog.artifacts, myArtifacts).filter((artifact) => matches(artifact, filters));
  const providers = Array.from(new Set(available.flatMap((artifact) => artifact.providers))).sort(compare).map((provider) => ({ provider, artifacts: available.filter((artifact) => artifact.providers.includes(provider)) }));
  return { isComplete: true as const, canExplore: true, available,
    hierarchy: { providers, multiProvider: available.filter((artifact) => artifact.providers.length > 1) },
    metrics: { providers: new Set(catalog.artifacts.flatMap((artifact) => artifact.providers)).size, availableArtifacts: getAvailableArtifacts(catalog.artifacts, myArtifacts).length, myArtifacts: myArtifacts.length, officialArtifacts: catalog.artifacts.filter((artifact) => artifact.isOfficial).length },
  };
}

// prettier-ignore
export function getAvailableArtifacts(artifacts: RegistryCatalogArtifact[], myArtifacts: RegistryTenantArtifact[]) {
  const mine = new Set(myArtifacts.map(({ normalizedName }) => normalizedName));
  return artifacts.filter(({ normalizedName }) => !mine.has(normalizedName)).sort((left, right) => compare(left.normalizedName, right.normalizedName));
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
  return (!search || text.includes(search)) && (!provider || artifact.providers.includes(provider)) && (filters.capabilities ?? []).every((capability) => (capability === "checks" && artifact.hasChecks) || (capability === "compliance" && artifact.hasCompliance) || (capability === "provider" && artifact.hasProvider));
}
function compare(left: string, right: string) {
  return left < right ? -1 : left > right ? 1 : 0;
}
