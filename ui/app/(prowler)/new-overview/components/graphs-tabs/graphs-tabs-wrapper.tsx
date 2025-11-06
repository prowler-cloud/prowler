import { Skeleton } from "@heroui/skeleton";
import { Suspense } from "react";

import {
  BaseCard,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/shadcn";

import { GraphsTabsClient } from "./graphs-tabs-client";
import { GRAPH_TABS, type TabId } from "./graphs-tabs-config";
import { RiskPipelineViewSSR } from "./risk-pipeline-view.ssr";
import { RiskPlotView } from "./risk-plot-view";
import { RiskRadarViewSSR } from "./risk-radar-view.ssr";
import { ThreatMapViewSSR } from "./threat-map-view.ssr";

const LoadingFallback = () => (
  <div className="w-full flex-1 space-y-4 rounded-lg border border-slate-700 bg-slate-800/50 p-4">
    <Skeleton className="h-6 w-1/3 rounded bg-slate-700" />
    <div className="space-y-3">
      <Skeleton className="h-40 w-full rounded bg-slate-700" />
      <Skeleton className="h-40 w-full rounded bg-slate-700" />
      <Skeleton className="h-40 w-full rounded bg-slate-700" />
    </div>
  </div>
);

const GRAPH_COMPONENTS = {
  "threat-map": ThreatMapViewSSR,
  "risk-radar": RiskRadarViewSSR,
  "risk-pipeline": RiskPipelineViewSSR,
  "risk-plot": RiskPlotView,
} as const satisfies Record<TabId, React.ComponentType<Record<string, never>>>;

export const GraphsTabsWrapper = async () => {
  const tabsContent = Object.fromEntries(
    GRAPH_TABS.map((tab) => {
      const Component = GRAPH_COMPONENTS[tab.id as TabId];
      return [
        tab.id,
        <Suspense key={tab.id} fallback={<LoadingFallback />}>
          <Component />
        </Suspense>,
      ];
    }),
  ) as Record<TabId, React.ReactNode>;

  return (
    <BaseCard className="flex flex-col">
      <CardHeader>
        <CardTitle>Risk Analysis</CardTitle>
      </CardHeader>

      <CardContent className="flex flex-1 flex-col overflow-hidden px-6">
        <GraphsTabsClient tabsContent={tabsContent} />
      </CardContent>
    </BaseCard>
  );
};
