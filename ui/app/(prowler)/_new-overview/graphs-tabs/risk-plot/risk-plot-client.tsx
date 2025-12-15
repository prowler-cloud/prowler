"use client";

/**
 * Risk Plot Client Component
 *
 * NOTE: This component uses CSS variables (var()) for Recharts styling.
 * Recharts SVG-based components (Scatter, XAxis, YAxis, CartesianGrid, etc.)
 * do not support Tailwind classes and require raw color values or CSS variables.
 * This is a documented limitation of the Recharts library.
 * @see https://recharts.org/en-US/api
 */

import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import {
  CartesianGrid,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { RiskPlotPoint } from "@/actions/overview/risk-plot";
import { HorizontalBarChart } from "@/components/graphs/horizontal-bar-chart";
import { AlertPill } from "@/components/graphs/shared/alert-pill";
import { ChartLegend } from "@/components/graphs/shared/chart-legend";
import {
  AXIS_FONT_SIZE,
  CustomXAxisTick,
} from "@/components/graphs/shared/custom-axis-tick";
import type { BarDataPoint } from "@/components/graphs/types";
import { mapProviderFiltersForFindings } from "@/lib/provider-helpers";
import { SEVERITY_FILTER_MAP } from "@/types/severities";

// ThreatScore colors (0-100 scale, higher = better)
const THREAT_COLORS = {
  DANGER: "var(--bg-fail-primary)", // 0-30
  WARNING: "var(--bg-warning-primary)", // 31-60
  SUCCESS: "var(--bg-pass-primary)", // 61-100
} as const;

/**
 * Get color based on ThreatScore (0-100 scale, higher = better)
 */
function getThreatScoreColor(score: number): string {
  if (score > 60) return THREAT_COLORS.SUCCESS;
  if (score > 30) return THREAT_COLORS.WARNING;
  return THREAT_COLORS.DANGER;
}

// Provider colors from globals.css
const PROVIDER_COLORS: Record<string, string> = {
  AWS: "var(--bg-data-aws)",
  Azure: "var(--bg-data-azure)",
  "Google Cloud": "var(--bg-data-gcp)",
  Kubernetes: "var(--bg-data-kubernetes)",
  "Microsoft 365": "var(--bg-data-m365)",
  GitHub: "var(--bg-data-github)",
  "MongoDB Atlas": "var(--bg-data-azure)",
  "Infrastructure as Code": "var(--bg-data-kubernetes)",
  "Oracle Cloud Infrastructure": "var(--bg-data-gcp)",
};

interface RiskPlotClientProps {
  data: RiskPlotPoint[];
}

interface TooltipProps {
  active?: boolean;
  payload?: Array<{ payload: RiskPlotPoint }>;
}

// Props that Recharts passes to the shape component
interface RechartsScatterDotProps {
  cx: number;
  cy: number;
  payload: RiskPlotPoint;
}

// Extended props for our custom scatter dot component
interface ScatterDotProps extends RechartsScatterDotProps {
  selectedPoint: RiskPlotPoint | null;
  onSelectPoint: (point: RiskPlotPoint) => void;
  allData: RiskPlotPoint[];
  selectedProvider: string | null;
}

const CustomTooltip = ({ active, payload }: TooltipProps) => {
  if (!active || !payload?.length) return null;

  const { name, x, y } = payload[0].payload;
  const scoreColor = getThreatScoreColor(x);

  return (
    <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary pointer-events-none min-w-[200px] rounded-xl border p-3 shadow-lg">
      <p className="text-text-neutral-primary mb-2 text-sm font-semibold">
        {name}
      </p>
      <p className="text-text-neutral-secondary text-sm font-medium">
        <span style={{ color: scoreColor, fontWeight: "bold" }}>{x}%</span>{" "}
        Prowler ThreatScore
      </p>
      <div className="mt-2">
        <AlertPill value={y} />
      </div>
    </div>
  );
};

const CustomScatterDot = ({
  cx,
  cy,
  payload,
  selectedPoint,
  onSelectPoint,
  allData,
  selectedProvider,
}: ScatterDotProps) => {
  const isSelected = selectedPoint?.name === payload.name;
  const size = isSelected ? 18 : 8;
  const selectedColor = "var(--bg-button-primary)";
  const fill = isSelected
    ? selectedColor
    : PROVIDER_COLORS[payload.provider] || "var(--color-text-neutral-tertiary)";
  const isFaded =
    selectedProvider !== null && payload.provider !== selectedProvider;

  const handleClick = () => {
    const fullDataItem = allData?.find((d) => d.name === payload.name);
    onSelectPoint?.(fullDataItem || payload);
  };

  return (
    <g
      style={{
        cursor: "pointer",
        opacity: isFaded ? 0.2 : 1,
        transition: "opacity 0.2s",
      }}
      onClick={handleClick}
    >
      {isSelected && (
        <>
          <circle
            cx={cx}
            cy={cy}
            r={size / 2 + 4}
            fill="none"
            stroke={selectedColor}
            strokeWidth={1}
            opacity={0.4}
          />
          <circle
            cx={cx}
            cy={cy}
            r={size / 2 + 8}
            fill="none"
            stroke={selectedColor}
            strokeWidth={1}
            opacity={0.2}
          />
        </>
      )}
      <circle
        cx={cx}
        cy={cy}
        r={size / 2}
        fill={fill}
        stroke={isSelected ? selectedColor : "transparent"}
        strokeWidth={2}
      />
    </g>
  );
};

/**
 * Factory function that creates a scatter dot shape component with closure over selection state.
 * Recharts shape prop types the callback parameter as `unknown` due to its flexible API.
 * We safely cast to RechartsScatterDotProps since we know the actual shape of props passed by Scatter.
 * @see https://recharts.org/en-US/api/Scatter#shape
 */
function createScatterDotShape(
  selectedPoint: RiskPlotPoint | null,
  onSelectPoint: (point: RiskPlotPoint) => void,
  allData: RiskPlotPoint[],
  selectedProvider: string | null,
): (props: unknown) => React.JSX.Element {
  const ScatterDotShape = (props: unknown) => (
    <CustomScatterDot
      {...(props as RechartsScatterDotProps)}
      selectedPoint={selectedPoint}
      onSelectPoint={onSelectPoint}
      allData={allData}
      selectedProvider={selectedProvider}
    />
  );
  ScatterDotShape.displayName = "ScatterDotShape";
  return ScatterDotShape;
}

export function RiskPlotClient({ data }: RiskPlotClientProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [selectedPoint, setSelectedPoint] = useState<RiskPlotPoint | null>(
    null,
  );
  const [selectedProvider, setSelectedProvider] = useState<string | null>(null);

  // Group data by provider for separate Scatter series
  const dataByProvider = data.reduce<Record<string, RiskPlotPoint[]>>(
    (acc, point) => {
      (acc[point.provider] ??= []).push(point);
      return acc;
    },
    {},
  );

  const providers = Object.keys(dataByProvider);

  const handleSelectPoint = (point: RiskPlotPoint) => {
    setSelectedPoint((current) =>
      current?.name === point.name ? null : point,
    );
  };

  const handleProviderClick = (provider: string) => {
    setSelectedProvider((current) => (current === provider ? null : provider));
  };

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

            <div className="relative min-h-[400px] w-full flex-1">
              <ResponsiveContainer width="100%" height="100%">
                <ScatterChart
                  margin={{ top: 20, right: 30, bottom: 60, left: 60 }}
                >
                  <CartesianGrid
                    horizontal={true}
                    vertical={false}
                    strokeOpacity={1}
                    stroke="var(--border-neutral-secondary)"
                  />
                  <XAxis
                    type="number"
                    dataKey="x"
                    name="Prowler ThreatScore"
                    label={{
                      value: "Prowler ThreatScore",
                      position: "bottom",
                      offset: 10,
                      fill: "var(--color-text-neutral-secondary)",
                    }}
                    tick={CustomXAxisTick}
                    tickLine={false}
                    domain={[0, 100]}
                    axisLine={false}
                  />
                  <YAxis
                    type="number"
                    dataKey="y"
                    name="Fail Findings"
                    label={{
                      value: "Fail Findings",
                      angle: -90,
                      position: "left",
                      offset: 10,
                      fill: "var(--color-text-neutral-secondary)",
                    }}
                    tick={{
                      fill: "var(--color-text-neutral-secondary)",
                      fontSize: AXIS_FONT_SIZE,
                    }}
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip content={<CustomTooltip />} />
                  {Object.entries(dataByProvider).map(([provider, points]) => (
                    <Scatter
                      key={provider}
                      name={provider}
                      data={points}
                      fill={
                        PROVIDER_COLORS[provider] ||
                        "var(--color-text-neutral-tertiary)"
                      }
                      shape={createScatterDotShape(
                        selectedPoint,
                        handleSelectPoint,
                        data,
                        selectedProvider,
                      )}
                    />
                  ))}
                </ScatterChart>
              </ResponsiveContainer>
            </div>

            {/* Interactive Legend - below chart */}
            <div className="mt-4 flex flex-col items-start gap-2">
              <p className="text-text-neutral-tertiary pl-2 text-xs">
                Click to filter by provider
              </p>
              <ChartLegend
                items={providers.map((p) => ({
                  label: p,
                  color:
                    PROVIDER_COLORS[p] || "var(--color-text-neutral-tertiary)",
                  dataKey: p,
                }))}
                selectedItem={selectedProvider}
                onItemClick={handleProviderClick}
              />
            </div>
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
