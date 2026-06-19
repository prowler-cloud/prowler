import { FILTER_FIELD, FilterParam } from "@/types/filters";

/**
 * URL filter param keys the findings view supports, e.g. `filter[severity__in]`.
 * Composed from the shared fields it uses plus a few findings-only extras
 * (alternate scan/date/delta forms not used by other views).
 */
export type FindingsFilterParam = FilterParam<
  // findings uses provider_id, not provider_uid
  | (typeof FILTER_FIELD)[
      | "PROVIDER_TYPE"
      | "PROVIDER_ID"
      | "PROVIDER_GROUPS"
      | "REGION"
      | "SERVICE"
      | "SEVERITY"
      | "STATUS"
      | "DELTA"
      | "RESOURCE_TYPE"
      | "CATEGORY"
      | "RESOURCE_GROUPS"
      | "SCAN"]
  // findings-only extras
  | "delta__in"
  | "scan"
  | "scan_id"
  | "scan_id__in"
  | "inserted_at"
  | "inserted_at__gte"
  | "inserted_at__lte"
  | "muted"
>;
