import { FILTER_FIELD, FilterParam } from "@/types/filters";
import { PROVIDERS_PAGE_FILTER } from "@/types/providers-table";

/**
 * URL filter param keys the providers list supports, e.g. `filter[provider__in]`.
 * Provider scope plus its providers-only extras (`provider__in` API param,
 * `connected` status).
 */
export type ProvidersFilterParam = FilterParam<
  | (typeof FILTER_FIELD)["PROVIDER_TYPE" | "PROVIDER_GROUPS" | "PROVIDER_UID"]
  | (typeof PROVIDERS_PAGE_FILTER)["PROVIDER" | "STATUS"]
>;

/** `filter[...]` keys used when mapping the provider-type filter to the API param. */
export const PROVIDERS_FILTER_PARAM = {
  PROVIDER: `filter[${PROVIDERS_PAGE_FILTER.PROVIDER}]`,
  PROVIDER_TYPE: `filter[${PROVIDERS_PAGE_FILTER.PROVIDER_TYPE}]`,
} as const satisfies Record<string, ProvidersFilterParam>;
