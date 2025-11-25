export const GRAPH_TABS = [
  {
    id: "findings",
    label: "Findings",
  },
  {
    id: "risk-pipeline",
    label: "Risk Pipeline",
  },
  // TODO: Uncomment when ready to enable other tabs
  // {
  //   id: "threat-map",
  //   label: "Threat Map",
  // },
  // {
  //   id: "risk-radar",
  //   label: "Risk Radar",
  // },
  // {
  //   id: "risk-plot",
  //   label: "Risk Plot",
  // },
] as const;

export type TabId = (typeof GRAPH_TABS)[number]["id"];
