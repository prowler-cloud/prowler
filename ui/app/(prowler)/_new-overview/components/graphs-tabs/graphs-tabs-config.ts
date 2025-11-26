export const GRAPH_TABS = [
  {
    id: "findings",
    label: "Findings",
  },
  {
    id: "risk-pipeline",
    label: "Risk Pipeline",
  },
  {
    id: "threat-map",
    label: "Threat Map",
  },
  // TODO: Uncomment when ready to enable other tabs
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
