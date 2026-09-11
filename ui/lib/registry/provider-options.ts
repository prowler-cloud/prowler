import { isKnownProviderType } from "@/types/providers";
import type {
  RegistryCatalogArtifact,
  RegistryTenantArtifact,
} from "@/types/registry";

import { isRegistryArtifactInstallable } from "./artifacts";

export interface RegistryProviderOption {
  type: string;
  label: string;
  logoUrl?: string;
}

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
    if (
      !membership.has(artifact.normalizedName) ||
      !isRegistryArtifactInstallable(artifact)
    )
      continue;
    const declaredType = artifact.providerSlug ?? artifact.providers[0];
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
