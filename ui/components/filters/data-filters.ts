import { CONNECTION_STATUS_MAPPING } from "@/lib/helper-filters";
import { FilterOption, FilterType } from "@/types/filters";
import { PROVIDER_TYPES } from "@/types/providers";

export const filterProviders: FilterOption[] = [
  {
    key: "connected",
    labelCheckboxGroup: "Connection",
    values: ["true", "false"],
    valueLabelMapping: CONNECTION_STATUS_MAPPING,
  },
  {
    key: "provider__in",
    labelCheckboxGroup: "Cloud Provider",
    values: [...PROVIDER_TYPES],
  },
  // Add more filter categories as needed
];

export const filterScans = [
  {
    key: "provider_type__in",
    labelCheckboxGroup: "Cloud Provider",
    values: [...PROVIDER_TYPES],
    index: 0,
  },
  {
    key: "state__in",
    labelCheckboxGroup: "Status",
    values: [
      "available",
      "scheduled",
      "executing",
      "completed",
      "failed",
      "cancelled",
    ],
    index: 2,
  },
  {
    key: "trigger",
    labelCheckboxGroup: "Trigger",
    values: ["scheduled", "manual"],
    index: 3,
  },
  // Add more filter categories as needed
];

//Static filters for findings
export const filterFindings = [
  {
    key: FilterType.SEVERITY,
    labelCheckboxGroup: "Severity",
    values: ["critical", "high", "medium", "low", "informational"],
    index: 0,
  },
  {
    key: FilterType.STATUS,
    labelCheckboxGroup: "Status",
    values: ["PASS", "FAIL", "MANUAL"],
    index: 1,
  },
  {
    key: FilterType.PROVIDER_TYPE,
    labelCheckboxGroup: "Cloud Provider",
    values: [...PROVIDER_TYPES],
    index: 5,
  },
  {
    key: FilterType.DELTA,
    labelCheckboxGroup: "Delta",
    values: ["new", "changed"],
    index: 2,
  },
];

export const filterUsers = [
  {
    key: "is_active",
    labelCheckboxGroup: "Status",
    values: ["true", "false"],
  },
];

export const filterInvitations = [
  {
    key: "state",
    labelCheckboxGroup: "State",
    values: ["pending", "accepted", "expired", "revoked"],
  },
];

export const filterRoles = [
  {
    key: "permission_state",
    labelCheckboxGroup: "Permissions",
    values: ["unlimited", "limited", "none"],
  },
];
