export type ProviderFilterValue = string | string[] | undefined;
export type ProviderFilters = Record<string, ProviderFilterValue>;

interface AppendProviderFiltersOptions {
  ensuredInFilterKey?: string;
  excludedKeys?: string[];
  excludedKeyIncludes?: string[];
}

type AppendSanitizedProviderTypeFiltersOptions = Omit<
  AppendProviderFiltersOptions,
  "ensuredInFilterKey"
>;

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

export const appendSanitizedProviderTypeFilters = (
  url: URL,
  filters: ProviderFilters = {},
  options: AppendSanitizedProviderTypeFiltersOptions = {},
): void =>
  appendSanitizedProviderFilters(url, filters, {
    ...options,
    ensuredInFilterKey: PROVIDER_TYPE_IN_FILTER_KEY,
  });

export const appendSanitizedProviderInFilters = (
  url: URL,
  filters: ProviderFilters = {},
  options: AppendSanitizedProviderTypeFiltersOptions = {},
): void =>
  appendSanitizedProviderFilters(url, filters, {
    ...options,
    ensuredInFilterKey: PROVIDER_IN_FILTER_KEY,
  });
