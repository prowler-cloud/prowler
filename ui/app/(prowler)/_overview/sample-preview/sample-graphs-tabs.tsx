import { type ReactNode } from "react";

import { SankeyChart } from "@/components/graphs/sankey-chart";
import { ThreatMap } from "@/components/graphs/threat-map";
import { LinkToFindings } from "@/components/overview";
import { LatestFindingsTable } from "@/components/overview/new-findings-table/table";
import { CardTitle } from "@/components/shadcn";
import {
  SAMPLE_NEW_FINDINGS,
  SAMPLE_RADAR_DATA,
  SAMPLE_RISK_PLOT_POINTS,
  SAMPLE_SANKEY_DATA,
  SAMPLE_THREAT_MAP_DATA,
} from "@/lib/sample-preview/sample-graphs";

import { GraphsTabsClient } from "../graphs-tabs/_components/graphs-tabs-client";
import type { TabId } from "../graphs-tabs/_config/graphs-tabs-config";
import { RiskPlotClient } from "../graphs-tabs/risk-plot/risk-plot-client";
import { RiskRadarViewClient } from "../graphs-tabs/risk-radar-view/risk-radar-view-client";

const SAMPLE_TABS_CONTENT: Record<TabId, ReactNode> = {
  findings: (
    <div className="flex w-full flex-1">
      <div className="flex w-full flex-col">
        <LatestFindingsTable
          data={SAMPLE_NEW_FINDINGS}
          header={
            <div className="flex w-full items-center justify-between gap-4">
              <div className="flex flex-col gap-0.5">
                <CardTitle>Latest New Failed Findings</CardTitle>
                <p className="text-text-neutral-tertiary text-xs">
                  Showing the latest 10 sorted by severity
                </p>
              </div>
              <LinkToFindings />
            </div>
          }
        />
      </div>
    </div>
  ),
  "threat-map": (
    <div className="flex w-full flex-1">
      <div className="w-full flex-1 overflow-hidden">
        <ThreatMap
          disableNavigation
          data={SAMPLE_THREAT_MAP_DATA}
          height={460}
        />
      </div>
    </div>
  ),
  "risk-radar": (
    <div className="flex w-full flex-1">
      <RiskRadarViewClient disableNavigation data={SAMPLE_RADAR_DATA} />
    </div>
  ),
  "risk-pipeline": (
    <div className="flex w-full flex-1">
      <div className="w-full flex-1 overflow-visible">
        <SankeyChart
          disableNavigation
          data={SAMPLE_SANKEY_DATA}
          zeroDataProviders={SAMPLE_SANKEY_DATA.zeroDataProviders}
          height={460}
        />
      </div>
    </div>
  ),
  "risk-plot": (
    <div className="flex w-full flex-1">
      <div className="w-full flex-1 overflow-visible">
        <RiskPlotClient disableNavigation data={SAMPLE_RISK_PLOT_POINTS} />
      </div>
    </div>
  ),
};

export const SampleGraphsTabs = () => (
  <GraphsTabsClient tabsContent={SAMPLE_TABS_CONTENT} />
);
