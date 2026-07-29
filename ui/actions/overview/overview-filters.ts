import { FILTER_FIELD, FilterParam } from "@/types/filters";

/**
 * URL filter param keys the overview dashboard scopes its widgets by. Overview has
 * no single action; its widgets read these keys from the URL filters.
 */
export type OverviewFilterParam = FilterParam<
  (typeof FILTER_FIELD)["PROVIDER_TYPE" | "PROVIDER_ID" | "PROVIDER_GROUPS"]
>;

/** The `filter[...]` keys overview widgets read from the URL. */
export const OVERVIEW_FILTER_PARAM = {
  PROVIDER_TYPE: `filter[${FILTER_FIELD.PROVIDER_TYPE}]`,
  PROVIDER_ID: `filter[${FILTER_FIELD.PROVIDER_ID}]`,
  PROVIDER_GROUPS: `filter[${FILTER_FIELD.PROVIDER_GROUPS}]`,
} as const satisfies Record<string, OverviewFilterParam>;
