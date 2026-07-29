import { ProviderProps } from "@/types/providers";

export interface ProviderScopeFilters {
  providerIds: string[];
  providerTypes: string[];
  providerGroupIds: string[];
}

/**
 * Normalize a comma-separated filter param into trimmed, non-empty ids.
 * Guards against blank values (e.g. an empty "filter[...]=" param) so they are
 * treated as "no filter" instead of matching against an empty-string id.
 */
export const parseFilterIds = (
  value: string | string[] | undefined,
): string[] => {
  if (value === undefined) return [];
  const raw = Array.isArray(value) ? value.join(",") : value;
  return raw
    .split(",")
    .map((id) => id.trim())
    .filter((id) => id.length > 0);
};

const belongsToGroup = (provider: ProviderProps, groupIds: string[]): boolean =>
  provider.relationships.provider_groups?.data?.some((group) =>
    groupIds.includes(group.id),
  ) ?? false;

/**
 * Keep only providers belonging to one of the selected groups. An empty group
 * list means "no group filter" and returns every provider unchanged.
 */
export const scopeProvidersByGroup = (
  providers: ProviderProps[],
  groupIds: string[],
): ProviderProps[] =>
  groupIds.length === 0
    ? providers
    : providers.filter((p) => belongsToGroup(p, groupIds));

/**
 * Filter providers by every active scope dimension (id, type, group) combined
 * with AND. Each empty dimension is skipped, so a provider is kept only when it
 * satisfies all the filters that are actually set.
 */
export const filterProvidersByScope = (
  providers: ProviderProps[],
  { providerIds, providerTypes, providerGroupIds }: ProviderScopeFilters,
): ProviderProps[] => {
  const normalizedTypes = providerTypes.map((type) => type.toLowerCase());

  return providers.filter((provider) => {
    if (providerIds.length > 0 && !providerIds.includes(provider.id)) {
      return false;
    }
    if (
      normalizedTypes.length > 0 &&
      !normalizedTypes.includes(provider.attributes.provider.toLowerCase())
    ) {
      return false;
    }
    if (
      providerGroupIds.length > 0 &&
      !belongsToGroup(provider, providerGroupIds)
    ) {
      return false;
    }
    return true;
  });
};
