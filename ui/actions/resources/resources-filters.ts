import { FILTER_FIELD, FilterParam } from "@/types/filters";

/** Resources-only filter fields not shared with other views. */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const RESOURCES_EXTRA_FIELD = {
  TYPE: "type__in",
  GROUPS: "groups__in",
} as const;

type ResourcesExtraField =
  (typeof RESOURCES_EXTRA_FIELD)[keyof typeof RESOURCES_EXTRA_FIELD];

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
  | ResourcesExtraField
>;
