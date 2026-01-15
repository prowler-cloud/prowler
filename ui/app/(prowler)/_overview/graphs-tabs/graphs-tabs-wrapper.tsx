import { Skeleton } from "@heroui/skeleton";
import { Suspense } from "react";

import { SearchParamsProps } from "@/types";

import { GraphsTabsClient } from "./_components/graphs-tabs-client";
import { GRAPH_TABS, type TabId } from "./_config/graphs-tabs-config";
import { FindingsViewSSR } from "./findings-view";
import { RiskPipelineViewSSR } from "./risk-pipeline-view/risk-pipeline-view.ssr";
import { RiskPlotSSR } from "./risk-plot/risk-plot.ssr";
import { RiskRadarViewSSR } from "./risk-radar-view/risk-radar-view.ssr";
import { ThreatMapViewSSR } from "./threat-map-view/threat-map-view.ssr";

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
  "risk-plot": RiskPlotSSR as GraphComponent,
  "risk-radar": RiskRadarViewSSR as GraphComponent,
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
