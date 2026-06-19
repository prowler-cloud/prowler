import {
  GroupFilterEntity,
  ProviderConnectionStatus,
  ProviderEntity,
} from "./providers";
import { ScanEntity } from "./scans";

export type FilterEntity =
  | ProviderEntity
  | ScanEntity
  | ProviderConnectionStatus
  | GroupFilterEntity;

export interface FilterOption {
  key: string;
  labelCheckboxGroup: string;
  values: string[];
  width?: "default" | "wide";
  valueLabelMapping?: Array<{ [uid: string]: FilterEntity }>;
  labelFormatter?: (value: string) => string;
  index?: number;
  showSelectAll?: boolean;
  defaultToSelectAll?: boolean;
  defaultValues?: string[];
}

export interface CustomDropdownFilterProps {
  filter: FilterOption;
  onFilterChange: (key: string, values: string[]) => void;
}

/**
 * Filter field names — the inner part of a `filter[...]` URL param key, and the
 * `key` values used to build `FilterOption` dropdown configs. Single source of
 * truth for the `FilterParam` template; per-view modules compose their own field
 * set from these plus their own extras.
 */
export const FILTER_FIELD = {
  // core — provider scope + shared resource dimensions (used across views)
  PROVIDER_TYPE: "provider_type__in",
  PROVIDER_ID: "provider_id__in",
  PROVIDER_UID: "provider_uid__in",
  PROVIDER_GROUPS: "provider_groups__in",
  REGION: "region__in",
  SERVICE: "service__in",
  // view dimensions — dropdown configs (mostly findings; `provider__in` is the
  // providers-list type filter)
  PROVIDER: "provider__in",
  SCAN: "scan__in",
  RESOURCE_TYPE: "resource_type__in",
  SEVERITY: "severity__in",
  STATUS: "status__in",
  // The API only registers `delta` (exact, singular). `delta__in` is silently
  // dropped, so the dropdown, URL, and backend must all use `delta`.
  DELTA: "delta",
  CATEGORY: "category__in",
  RESOURCE_GROUPS: "resource_groups__in",
} as const;

export type FilterField = (typeof FILTER_FIELD)[keyof typeof FILTER_FIELD];

/**
 * Controls the filter dispatch behavior of DataTableFilterCustom.
 * - "instant": every selection immediately updates the URL (legacy/default behavior)
 * - "batch":   selections accumulate in pending state; URL only updates on explicit apply
 */
export const DATA_TABLE_FILTER_MODE = {
  INSTANT: "instant",
  BATCH: "batch",
} as const;

export type DataTableFilterMode =
  (typeof DATA_TABLE_FILTER_MODE)[keyof typeof DATA_TABLE_FILTER_MODE];

/**
 * URL filter param key template — wraps a field name in `filter[...]`.
 * Parameterize with a view's own field union (e.g. `FilterParam<FindingsFilterField>`)
 * so each view's param-keyed records stay in sync with the filters it supports.
 */
export type FilterParam<Field extends string = FilterField> =
  `filter[${Field}]`;
