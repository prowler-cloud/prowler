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
