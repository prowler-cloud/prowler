import { FILTER_FIELD, FilterParam } from "@/types/filters";

/**
 * Provider filter fields used to match/clear synthetic pending scan rows — the
 * `__in` forms (shared with real scan rows) plus the exact forms, and the
 * provider-group `__in` form so pending rows honor the group filter too.
 */
export const SCANS_PROVIDER_FILTER_FIELD = {
  PROVIDER_IN: FILTER_FIELD.PROVIDER,
  PROVIDER: "provider",
  PROVIDER_TYPE_IN: FILTER_FIELD.PROVIDER_TYPE,
  PROVIDER_TYPE: "provider_type",
  PROVIDER_GROUPS_IN: FILTER_FIELD.PROVIDER_GROUPS,
} as const;

/** Scans-only filter fields not shared with other views. */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const SCANS_EXTRA_FIELD = {
  STATE: "state__in",
  TRIGGER: "trigger",
} as const;

type ScansExtraField =
  (typeof SCANS_EXTRA_FIELD)[keyof typeof SCANS_EXTRA_FIELD];

/**
 * URL filter param keys the scans view supports, e.g. `filter[state__in]`.
 * Provider scope (scans filters accounts by provider id) including provider
 * groups and the exact pending-row provider forms, plus the scans-only dimensions.
 */
export type ScansFilterParam = FilterParam<
  | (typeof SCANS_PROVIDER_FILTER_FIELD)[keyof typeof SCANS_PROVIDER_FILTER_FIELD]
  | ScansExtraField
>;
