export const GRAPH_TABS = [
  {
    id: "findings",
    label: "New Findings",
  },
  {
    id: "risk-pipeline",
    label: "Risk Pipeline",
  },
  {
    id: "threat-map",
    label: "Threat Map",
  },
  {
    id: "risk-plot",
    label: "Risk Plot",
  },
  {
    id: "risk-radar",
    label: "Risk Radar",
  },
] as const;

export type TabId = (typeof GRAPH_TABS)[number]["id"];
