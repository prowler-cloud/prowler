import { FILTER_FIELD, FilterParam } from "@/types/filters";

/** Findings-only filter fields not shared with other views. */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const FINDINGS_EXTRA_FIELD = {
  DELTA_IN: "delta__in",
  SCAN_EXACT: "scan",
  SCAN_ID: "scan_id",
  SCAN_ID_IN: "scan_id__in",
  INSERTED_AT: "inserted_at",
  INSERTED_AT_GTE: "inserted_at__gte",
  INSERTED_AT_LTE: "inserted_at__lte",
  MUTED: "muted",
} as const;

type FindingsExtraField =
  (typeof FINDINGS_EXTRA_FIELD)[keyof typeof FINDINGS_EXTRA_FIELD];

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
  | FindingsExtraField
>;
