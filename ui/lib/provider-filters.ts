import { PROVIDER_TYPES, type ProviderType } from "@/types/providers";

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

const SUPPORTED_PROVIDER_TYPES_CSV = PROVIDER_TYPES.join(",");
export const PROVIDER_IN_FILTER_KEY = "filter[provider__in]";
export const PROVIDER_TYPE_IN_FILTER_KEY = "filter[provider_type__in]";

const PROVIDER_TYPE_IN_KEYS = new Set([
  PROVIDER_TYPE_IN_FILTER_KEY,
  "provider_type__in",
]);

const PROVIDER_SINGLE_KEYS = new Set([
  "filter[provider_type]",
  "provider_type",
]);

const toCsvString = (value: unknown): string => {
  if (Array.isArray(value)) return value.join(",");
  if (typeof value === "string") return value;
  return "";
};

const isSupportedProviderType = (value: string): value is ProviderType =>
  (PROVIDER_TYPES as readonly string[]).includes(value);

export const sanitizeProviderTypesCsv = (value?: unknown): string => {
  const rawValue = toCsvString(value);
  if (!rawValue.trim()) return SUPPORTED_PROVIDER_TYPES_CSV;

  const supportedProviderTypes = Array.from(
    new Set(
      rawValue
        .split(",")
        .map((providerType) => providerType.trim())
        .filter(isSupportedProviderType),
    ),
  );

  return supportedProviderTypes.length > 0
    ? supportedProviderTypes.join(",")
    : SUPPORTED_PROVIDER_TYPES_CSV;
};

export const sanitizeProviderType = (
  value?: unknown,
): ProviderType | undefined => {
  const rawValue = toCsvString(value);
  if (!rawValue.trim()) return undefined;

  return rawValue
    .split(",")
    .map((providerType) => providerType.trim())
    .find(isSupportedProviderType);
};

export const sanitizeProviderFilters = (
  filters: ProviderFilters = {},
  ensuredInFilterKey?: string,
): ProviderFilters => {
  const sanitizedFilters: ProviderFilters = { ...filters };

  Object.keys(sanitizedFilters).forEach((key) => {
    if (PROVIDER_TYPE_IN_KEYS.has(key)) {
      sanitizedFilters[key] = sanitizeProviderTypesCsv(sanitizedFilters[key]);
      return;
    }

    if (PROVIDER_SINGLE_KEYS.has(key)) {
      const providerType = sanitizeProviderType(sanitizedFilters[key]);
      if (providerType) {
        sanitizedFilters[key] = providerType;
      } else {
        delete sanitizedFilters[key];
      }
    }
  });

  if (ensuredInFilterKey) {
    sanitizedFilters[ensuredInFilterKey] = sanitizeProviderTypesCsv(
      sanitizedFilters[ensuredInFilterKey],
    );
  }

  return sanitizedFilters;
};

export const appendSanitizedProviderFilters = (
  url: URL,
  filters: ProviderFilters = {},
  {
    ensuredInFilterKey,
    excludedKeys = ["filter[search]"],
    excludedKeyIncludes = [],
  }: AppendProviderFiltersOptions = {},
): void => {
  const sanitizedFilters = sanitizeProviderFilters(filters, ensuredInFilterKey);
  const excludedKeysSet = new Set(excludedKeys);

  Object.entries(sanitizedFilters).forEach(([key, value]) => {
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
