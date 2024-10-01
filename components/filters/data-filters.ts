export const filtersProviders = [
  {
    key: "provider__in",
    labelCheckboxGroup: "Select a Provider",
    values: ["aws", "gcp", "azure", "kubernetes"],
  },
  {
    key: "connected",
    labelCheckboxGroup: "Connection",
    values: ["false", "true"],
  },
  // Add more filter categories as needed
];
