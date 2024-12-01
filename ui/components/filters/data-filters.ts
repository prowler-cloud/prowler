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
    values: ["aws", "azure", "gcp", "kubernetes"],
  },
  {
    key: "state",
    labelCheckboxGroup: "State",
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
    labelCheckboxGroup: "Schedule",
    values: ["scheduled", "manual"],
  },
  // Add more filter categories as needed
];

export const filterFindings = [
  {
    key: "severity__in",
    labelCheckboxGroup: "Severity",
    values: ["critical", "high", "medium", "low", "informational"],
  },
  {
    key: "status__in",
    labelCheckboxGroup: "Status",
    values: ["PASS", "FAIL", "MANUAL", "MUTED"],
  },
  {
    key: "delta__in",
    labelCheckboxGroup: "Delta",
    values: ["new", "changed"],
  },
  {
    key: "provider_type__in",
    labelCheckboxGroup: "Cloud Provider",
    values: ["aws", "azure", "gcp", "kubernetes"],
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
