import { ProviderProps } from "@/types/providers";
import { ScanConfigurationData } from "@/types/scan-configurations";

export interface SelectableProvidersResult {
  selectableProviders: ProviderProps[];
  /** Providers eligible for a Scan Configuration at all (i.e. non-dynamic). */
  configurableCount: number;
  /** Configurable providers hidden because another config already owns them. */
  lockedCount: number;
}

/**
 * Providers that can be attached to a Scan Configuration.
 *
 * Dynamic providers are SDK-defined and have no `config.yaml` baseline to
 * override, so a Scan Configuration can't apply to them — they are never
 * selectable. A provider can also belong to only one config at a time, so those
 * already attached to *another* config are excluded (the one being edited is
 * kept selectable).
 */
export function getSelectableProviders(
  richProviders: ProviderProps[],
  existingConfigs: ScanConfigurationData[],
  currentConfigId: string | null,
): SelectableProvidersResult {
  const attachedElsewhere = new Set<string>();
  for (const c of existingConfigs) {
    if (currentConfigId && c.id === currentConfigId) continue;
    for (const pid of c.attributes.providers || []) {
      attachedElsewhere.add(pid);
    }
  }

  const configurableProviders = richProviders.filter(
    (p) => !p.attributes.is_dynamic,
  );
  const selectableProviders = configurableProviders.filter(
    (p) => !attachedElsewhere.has(p.id),
  );

  return {
    selectableProviders,
    configurableCount: configurableProviders.length,
    lockedCount: configurableProviders.length - selectableProviders.length,
  };
}
