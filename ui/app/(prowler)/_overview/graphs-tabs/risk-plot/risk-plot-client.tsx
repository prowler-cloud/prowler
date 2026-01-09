"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import type { RiskPlotPoint } from "@/actions/overview/risk-plot";
import { HorizontalBarChart } from "@/components/graphs/horizontal-bar-chart";
import { ScatterPlot } from "@/components/graphs/scatter-plot";
import { AlertPill } from "@/components/graphs/shared/alert-pill";
import type { BarDataPoint } from "@/components/graphs/types";
import { mapProviderFiltersForFindings } from "@/lib/provider-helpers";
import { SEVERITY_FILTER_MAP } from "@/types/severities";

// Score color thresholds (0-100 scale, higher = better)
const SCORE_COLORS = {
  DANGER: "var(--bg-fail-primary)", // 0-30
  WARNING: "var(--bg-warning-primary)", // 31-60
  SUCCESS: "var(--bg-pass-primary)", // 61-100
} as const;

function getScoreColor(score: number): string {
  if (score > 60) return SCORE_COLORS.SUCCESS;
  if (score > 30) return SCORE_COLORS.WARNING;
  return SCORE_COLORS.DANGER;
}

interface RiskPlotClientProps {
  data: RiskPlotPoint[];
}

export function RiskPlotClient({ data }: RiskPlotClientProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [selectedPoint, setSelectedPoint] = useState<RiskPlotPoint | null>(
    null,
  );
  const [selectedProvider, setSelectedProvider] = useState<string | null>(null);

  const handleBarClick = (dataPoint: BarDataPoint) => {
    if (!selectedPoint) return;

    // Build the URL with current filters
    const params = new URLSearchParams(searchParams.toString());

    // Transform provider filters (provider_id__in -> provider__in)
    mapProviderFiltersForFindings(params);

    // Add severity filter
    const severity = SEVERITY_FILTER_MAP[dataPoint.name];
    if (severity) {
      params.set("filter[severity__in]", severity);
    }

    // Add provider filter for the selected point
    params.set("filter[provider__in]", selectedPoint.providerId);

    // Add exclude muted findings filter
    params.set("filter[muted]", "false");

    // Filter by FAIL findings
    params.set("filter[status__in]", "FAIL");

    // Navigate to findings page
    router.push(`/findings?${params.toString()}`);
  };

  const renderTooltip = (point: RiskPlotPoint) => {
    const scoreColor = getScoreColor(point.x);

    return (
      <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary pointer-events-none min-w-[200px] rounded-xl border p-3 shadow-lg">
        <p className="text-text-neutral-primary mb-2 text-sm font-semibold">
          {point.name}
        </p>
        <p className="text-text-neutral-secondary text-sm font-medium">
          <span style={{ color: scoreColor, fontWeight: "bold" }}>
            {point.x}%
          </span>{" "}
          Prowler ThreatScore
        </p>
        <div className="mt-2">
          <AlertPill value={point.y} />
        </div>
      </div>
    );
  };

  return (
    <div className="flex h-full w-full flex-col gap-4">
      <div className="flex flex-1 gap-12">
        {/* Plot Section - in Card */}
        <div className="flex basis-[70%] flex-col">
          <div className="border-border-neutral-primary bg-bg-neutral-secondary flex flex-1 flex-col rounded-lg border p-4">
            <div className="mb-4">
              <h3 className="text-text-neutral-primary text-lg font-semibold">
                Risk Plot
              </h3>
              <p className="text-text-neutral-tertiary mt-1 text-xs">
                Prowler ThreatScore is severity-weighted, not quantity-based.
                Higher severity findings have greater impact on the score.
              </p>
            </div>

            <ScatterPlot<RiskPlotPoint>
              data={data}
              xAxis={{ label: "Fail Findings", dataKey: "y" }}
              yAxis={{
                label: "Prowler ThreatScore",
                dataKey: "x",
                domain: [0, 100],
              }}
              selectedPoint={selectedPoint}
              onSelectPoint={setSelectedPoint}
              selectedProvider={selectedProvider}
              onProviderClick={setSelectedProvider}
              gradient={{
                id: "riskPlotGradient",
                color: "#7D1A1A",
                fromBottom: true,
              }}
              renderTooltip={renderTooltip}
            />
          </div>
        </div>

        {/* Details Section - No Card */}
        <div className="flex basis-[30%] flex-col items-center justify-center overflow-hidden">
          {selectedPoint && selectedPoint.severityData ? (
            <div className="flex w-full flex-col">
              <div className="mb-4">
                <h4 className="text-text-neutral-primary text-base font-semibold">
                  {selectedPoint.name}
                </h4>
                <p className="text-text-neutral-tertiary text-xs">
                  Prowler ThreatScore: {selectedPoint.x}% | Fail Findings:{" "}
                  {selectedPoint.y}
                </p>
              </div>
              <HorizontalBarChart
                data={selectedPoint.severityData}
                onBarClick={handleBarClick}
              />
            </div>
          ) : (
            <div className="flex w-full items-center justify-center text-center">
              <p className="text-text-neutral-tertiary text-sm">
                Select a point on the plot to view details
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
