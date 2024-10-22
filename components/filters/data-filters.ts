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
    values: ["informational", "low", "medium", "high", "critical"],
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
