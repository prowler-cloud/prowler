export const filtersProviders = [
  {
    key: "provider__in",
    labelCheckboxGroup: "Select a Provider",
    values: ["aws", "gcp", "azure", "kubernetes"],
  },
  {
    key: "connected",
    labelCheckboxGroup: "Status provider",
    values: ["false", "true"],
  },
  // Add more filter categories as needed
];
