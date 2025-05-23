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
  },
  {
    key: "trigger",
    labelCheckboxGroup: "Trigger",
    values: ["scheduled", "manual"],
  },
  {
    key: "provider_uid__in",
    labelCheckboxGroup: "Provider UID",
    values: [],
  },
  // Add more filter categories as needed
];

export const filterFindings = [
  {
    key: "severity__in",
    labelCheckboxGroup: "Severity",
    values: ["critical", "high", "medium", "low", "informational"],
    index: 1,
  },
  {
    key: "status__in",
    labelCheckboxGroup: "Status",
    values: ["PASS", "FAIL", "MANUAL"],
    index: 2,
  },
  {
    key: "provider_type__in",
    labelCheckboxGroup: "Cloud Provider",
    values: ["aws", "azure", "m365", "gcp", "kubernetes"],
    index: 4,
  },
  {
    key: "provider_uid__in",
    labelCheckboxGroup: "Provider UID",
    values: [],
    index: 8,
  },
  {
    key: "delta__in",
    labelCheckboxGroup: "Delta",
    values: ["new", "changed"],
    index: 3,
  },
  // Add more filter categories as needed
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
