import { isKnownProviderType } from "@/types/providers";
import type {
  RegistryCatalogArtifact,
  RegistryTenantArtifact,
} from "@/types/registry";

export interface RegistryProviderOption {
  type: string;
  label: string;
  logoUrl?: string;
}

export const REGISTRY_PROVIDER_DISCOVERY = {
  READY: "ready",
  ACCESS_DENIED: "access_denied",
  /** Access could not be evaluated: keep Registry hidden but retryable. */
  UNKNOWN: "unknown",
  ERROR: "error",
} as const;

export type RegistryProviderDiscoveryResult =
  | {
      status: typeof REGISTRY_PROVIDER_DISCOVERY.READY;
      options: RegistryProviderOption[];
    }
  | { status: typeof REGISTRY_PROVIDER_DISCOVERY.ACCESS_DENIED }
  | { status: typeof REGISTRY_PROVIDER_DISCOVERY.UNKNOWN }
  | { status: typeof REGISTRY_PROVIDER_DISCOVERY.ERROR };

export function buildRegistryProviderOptions(
  catalog: RegistryCatalogArtifact[],
  installed: RegistryTenantArtifact[],
  metadata: RegistryProviderOption[],
): RegistryProviderOption[] {
  const membership = new Set(
    installed.map((artifact) => artifact.normalizedName),
  );
  const providers = new Map(
    metadata.map((provider) => [provider.type, provider]),
  );
  const options = new Map<string, RegistryProviderOption>();
  for (const artifact of catalog) {
    // Defining a provider type, not installability: checks artifacts install too.
    if (!membership.has(artifact.normalizedName) || !artifact.hasProvider)
      continue;
    const declaredType = artifact.providerSlug;
    for (const type of declaredType ? [declaredType] : []) {
      if (
        isKnownProviderType(type) ||
        !/^[a-z][a-z0-9_-]{0,49}$/.test(type) ||
        options.has(type)
      )
        continue;
      options.set(
        type,
        providers.get(type) ?? {
          type,
          label: artifact.name || type,
          ...(artifact.owners[0]?.logoUrl
            ? { logoUrl: artifact.owners[0].logoUrl }
            : {}),
        },
      );
    }
  }
  return Array.from(options.values()).sort((left, right) =>
    left.label.localeCompare(right.label),
  );
}
