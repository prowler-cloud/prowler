export const GRAPH_TABS = [
  {
    id: "findings",
    label: "New Findings",
  },
  {
    id: "threat-map",
    label: "Threat Map",
  },
  {
    id: "risk-radar",
    label: "Risk Radar",
  },
  {
    id: "risk-pipeline",
    label: "Risk Pipeline",
  },
  {
    id: "risk-plot",
    label: "Risk Plot",
  },
] as const;

export type TabId = (typeof GRAPH_TABS)[number]["id"];
