import { Skeleton } from "@heroui/skeleton";
import { Suspense } from "react";

import { SearchParamsProps } from "@/types";

import { FindingsViewSSR } from "./findings-view";
import { GraphsTabsClient } from "./graphs-tabs-client";
import { GRAPH_TABS, type TabId } from "./graphs-tabs-config";
import { RiskPipelineViewSSR } from "./risk-pipeline-view/risk-pipeline-view.ssr";
import { ThreatMapViewSSR } from "./threat-map-view/threat-map-view.ssr";
// TODO: Uncomment when ready to enable other tabs
// import { RiskPlotView } from "./risk-plot/risk-plot-view";
// import { RiskRadarViewSSR } from "./risk-radar-view/risk-radar-view.ssr";

const LoadingFallback = () => (
  <div className="border-border-neutral-primary bg-bg-neutral-secondary flex w-full flex-col space-y-4 rounded-lg border p-4">
    <Skeleton className="bg-bg-neutral-tertiary h-6 w-1/3 rounded" />
    <Skeleton className="bg-bg-neutral-tertiary h-[457px] w-full rounded" />
  </div>
);

type GraphComponent = React.ComponentType<{ searchParams: SearchParamsProps }>;

const GRAPH_COMPONENTS: Record<TabId, GraphComponent> = {
  findings: FindingsViewSSR as GraphComponent,
  "risk-pipeline": RiskPipelineViewSSR as GraphComponent,
  "threat-map": ThreatMapViewSSR as GraphComponent,
  // TODO: Uncomment when ready to enable other tabs
  // "risk-radar": RiskRadarViewSSR as GraphComponent,
  // "risk-plot": RiskPlotView as GraphComponent,
};

interface GraphsTabsWrapperProps {
  searchParams: SearchParamsProps;
}

export const GraphsTabsWrapper = async ({
  searchParams,
}: GraphsTabsWrapperProps) => {
  const tabsContent = Object.fromEntries(
    GRAPH_TABS.map((tab) => {
      const Component = GRAPH_COMPONENTS[tab.id];
      return [
        tab.id,
        <Suspense key={tab.id} fallback={<LoadingFallback />}>
          <Component searchParams={searchParams} />
        </Suspense>,
      ];
    }),
  ) as Record<TabId, React.ReactNode>;

  return <GraphsTabsClient tabsContent={tabsContent} />;
};
