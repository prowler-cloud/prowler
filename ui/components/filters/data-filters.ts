import { FilterType } from "@/types/filters";

export const filterProviders = [
  {
    key: "connected",
    labelCheckboxGroup: "Connection",
    values: ["false", "true"],
  },
  // Add more filter categories as needed
];

export const filterScans = [
  {
    key: "provider_type__in",
    labelCheckboxGroup: "Cloud Provider",
    values: ["aws", "azure", "m365", "gcp", "kubernetes"],
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
    values: ["aws", "azure", "m365", "gcp", "kubernetes"],
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
