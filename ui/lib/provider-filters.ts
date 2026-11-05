export type ProviderFilterValue = string | string[] | undefined;
export type ProviderFilters = Record<string, ProviderFilterValue>;

interface AppendProviderFiltersOptions {
  excludedKeys?: string[];
  excludedKeyIncludes?: string[];
}

export const PROVIDER_IN_FILTER_KEY = "filter[provider__in]";
export const PROVIDER_TYPE_IN_FILTER_KEY = "filter[provider_type__in]";

export const appendSanitizedProviderFilters = (
  url: URL,
  filters: ProviderFilters = {},
  {
    excludedKeys = ["filter[search]"],
    excludedKeyIncludes = [],
  }: AppendProviderFiltersOptions = {},
): void => {
  const excludedKeysSet = new Set(excludedKeys);

  Object.entries(filters).forEach(([key, value]) => {
    if (
      value === undefined ||
      excludedKeysSet.has(key) ||
      excludedKeyIncludes.some((excludedKey) => key.includes(excludedKey))
    ) {
      return;
    }

    url.searchParams.append(key, String(value));
  });
};

// Named aliases so call sites read by intent (provider-type vs provider-id
// filters). Both forward to appendSanitizedProviderFilters unchanged: the UI no
// longer forces a provider allowlist, so neither injects a default filter.
export const appendSanitizedProviderTypeFilters = (
  url: URL,
  filters: ProviderFilters = {},
  options: AppendProviderFiltersOptions = {},
): void => appendSanitizedProviderFilters(url, filters, options);

export const appendSanitizedProviderInFilters = (
  url: URL,
  filters: ProviderFilters = {},
  options: AppendProviderFiltersOptions = {},
): void => appendSanitizedProviderFilters(url, filters, options);
