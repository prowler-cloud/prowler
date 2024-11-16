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
    labelCheckboxGroup: "Provider",
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
    key: "severity",
    labelCheckboxGroup: "Severity",
    values: ["critical", "high", "medium", "low", "informational"],
  },
  {
    key: "status",
    labelCheckboxGroup: "Status",
    values: ["PASS", "FAIL", "MANUAL", "MUTED"],
  },
  {
    key: "delta",
    labelCheckboxGroup: "Delta",
    values: ["new", "changed"],
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
