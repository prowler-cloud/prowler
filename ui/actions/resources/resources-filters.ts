import { FILTER_FIELD, FilterParam } from "@/types/filters";

/**
 * URL filter param keys the resources view supports, e.g. `filter[type__in]`.
 * The shared core plus its resources-only dimensions (`type__in`, `groups__in`).
 */
export type ResourcesFilterParam = FilterParam<
  | (typeof FILTER_FIELD)[
      | "PROVIDER_TYPE"
      | "PROVIDER_ID"
      | "PROVIDER_GROUPS"
      | "REGION"
      | "SERVICE"]
  | "type__in"
  | "groups__in"
>;
