import { Skeleton } from "@heroui/skeleton";
import { Suspense } from "react";

import { SearchParamsProps } from "@/types";

import { GraphsTabsClient } from "./graphs-tabs-client";
import { GRAPH_TABS, type TabId } from "./graphs-tabs-config";
import { RiskPipelineViewSSR } from "./risk-pipeline-view/risk-pipeline-view.ssr";
import { RiskPlotView } from "./risk-plot/risk-plot-view";
import { RiskRadarViewSSR } from "./risk-radar-view/risk-radar-view.ssr";
import { ThreatMapViewSSR } from "./threat-map-view/threat-map-view.ssr";

const LoadingFallback = () => (
  <div
    className="flex w-full flex-col space-y-4 rounded-lg border p-4"
    style={{
      borderColor: "var(--border-neutral-primary)",
      backgroundColor: "var(--bg-neutral-secondary)",
    }}
  >
    <Skeleton
      className="h-6 w-1/3 rounded"
      style={{ backgroundColor: "var(--bg-neutral-tertiary)" }}
    />
    <Skeleton
      className="h-[457px] w-full rounded"
      style={{ backgroundColor: "var(--bg-neutral-tertiary)" }}
    />
  </div>
);

type GraphComponent = React.ComponentType<{ searchParams: SearchParamsProps }>;

const GRAPH_COMPONENTS: Record<TabId, GraphComponent> = {
  "threat-map": ThreatMapViewSSR as GraphComponent,
  "risk-radar": RiskRadarViewSSR as GraphComponent,
  "risk-pipeline": RiskPipelineViewSSR as GraphComponent,
  "risk-plot": RiskPlotView as GraphComponent,
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
