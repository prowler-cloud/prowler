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

// Risk Score colors using Threat Score system (same as threat-score component)
// Risk Score is 0-10 where higher = better (same as ThreatScore 0-100)
const RISK_COLORS = {
  DANGER: "var(--bg-fail-primary)", // High risk (0-3)
  WARNING: "var(--bg-warning-primary)", // Moderate risk (3.1-6)
  SUCCESS: "var(--bg-pass-primary)", // Low risk (6.1-10)
} as const;

/**
 * Get color based on Risk Score (0-10 scale, higher = better)
 * Uses same color scheme as Threat Score component
 */
function getRiskScoreColor(riskScore: number): string {
  if (riskScore > 6) return RISK_COLORS.SUCCESS;
  if (riskScore > 3) return RISK_COLORS.WARNING;
  return RISK_COLORS.DANGER;
}

// Map display names to CSS variables from globals.css
const PROVIDER_COLORS: Record<string, string> = {
  AWS: "var(--bg-data-aws)",
  Azure: "var(--bg-data-azure)",
  "Google Cloud": "var(--bg-data-gcp)",
  Kubernetes: "var(--bg-data-kubernetes)",
  "Microsoft 365": "var(--bg-data-m365)",
  GitHub: "var(--bg-data-github)",
  // Fallback for providers without specific colors
  "MongoDB Atlas": "var(--bg-data-azure)", // Using azure as fallback
  "Infrastructure as Code": "var(--bg-data-kubernetes)", // Using kubernetes as fallback
  "Oracle Cloud Infrastructure": "var(--bg-data-gcp)", // Using gcp as fallback
};

export interface ScatterPoint {
  x: number;
  y: number;
  provider: string;
  name: string;
  providerId: string;
  severityData?: BarDataPoint[];
}

interface RiskPlotClientProps {
  data: ScatterPoint[];
}

interface TooltipProps {
  active?: boolean;
  payload?: Array<{ payload: ScatterPoint }>;
}

// Props that Recharts passes to the shape component
interface RechartsScatterDotProps {
  cx: number;
  cy: number;
  payload: ScatterPoint;
}

// Extended props for our custom scatter dot component
interface ScatterDotProps extends RechartsScatterDotProps {
  selectedPoint: ScatterPoint | null;
  onSelectPoint: (point: ScatterPoint) => void;
  allData: ScatterPoint[];
  selectedProvider: string | null;
}

interface LegendProps {
  providers: string[];
  selectedProvider: string | null;
  onProviderClick: (provider: string) => void;
}

const CustomTooltip = ({ active, payload }: TooltipProps) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    const riskColor = getRiskScoreColor(data.x);

    return (
      <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary pointer-events-none min-w-[200px] rounded-xl border p-3 shadow-lg">
        <p className="text-text-neutral-primary mb-2 text-sm font-semibold">
          {data.name}
        </p>
        <p className="text-text-neutral-secondary text-sm font-medium">
          {/* Dynamic color based on risk level - required inline style */}
          <span style={{ color: riskColor, fontWeight: "bold" }}>
            {data.x}
          </span>{" "}
          Risk Score
        </p>
        <div className="mt-2">
          <AlertPill value={data.y} />
        </div>
      </div>
    );
  }
  return null;
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
  const selectedColor = "var(--bg-button-primary)"; // emerald-400
  const fill = isSelected
    ? selectedColor
    : PROVIDER_COLORS[payload.provider] || "var(--color-text-neutral-tertiary)";

  // Check if this point should be faded (when a provider is selected in legend)
  const isFaded =
    selectedProvider !== null && payload.provider !== selectedProvider;
  const opacity = isFaded ? 0.2 : 1;

  const handleClick = () => {
    const fullDataItem = allData?.find(
      (d: ScatterPoint) => d.name === payload.name,
    );
    onSelectPoint?.(fullDataItem || payload);
  };

  return (
    <g
      style={{ cursor: "pointer", opacity, transition: "opacity 0.2s" }}
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

const CustomLegend = ({
  providers,
  selectedProvider,
  onProviderClick,
}: LegendProps) => {
  // Build legend items from actual providers with correct colors
  const items = providers.map((provider) => ({
    label: provider,
    color: PROVIDER_COLORS[provider] || "var(--color-text-neutral-tertiary)",
    dataKey: provider,
  }));

  return (
    <ChartLegend
      items={items}
      selectedItem={selectedProvider}
      onItemClick={onProviderClick}
    />
  );
};

/**
 * Factory function that creates a scatter dot shape component with closure over selection state.
 * Recharts shape prop types the callback parameter as `unknown` due to its flexible API.
 * We safely cast to RechartsScatterDotProps since we know the actual shape of props passed by Scatter.
 * @see https://recharts.org/en-US/api/Scatter#shape
 */
function createScatterDotShape(
  selectedPoint: ScatterPoint | null,
  onSelectPoint: (point: ScatterPoint) => void,
  allData: ScatterPoint[],
  selectedProvider: string | null,
): (props: unknown) => React.JSX.Element {
  const ScatterDotShape = (props: unknown) => {
    const rechartsProps = props as RechartsScatterDotProps;
    return (
      <CustomScatterDot
        {...rechartsProps}
        selectedPoint={selectedPoint}
        onSelectPoint={onSelectPoint}
        allData={allData}
        selectedProvider={selectedProvider}
      />
    );
  };
  ScatterDotShape.displayName = "ScatterDotShape";
  return ScatterDotShape;
}

export function RiskPlotClient({ data }: RiskPlotClientProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [selectedPoint, setSelectedPoint] = useState<ScatterPoint | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<string | null>(null);

  const dataByProvider = data.reduce(
    (acc, point) => {
      const provider = point.provider;
      if (!acc[provider]) {
        acc[provider] = [];
      }
      acc[provider].push(point);
      return acc;
    },
    {} as Record<string, typeof data>,
  );

  // Get unique providers for legend
  const providers = Object.keys(dataByProvider);

  const handleSelectPoint = (point: ScatterPoint) => {
    if (selectedPoint?.name === point.name) {
      setSelectedPoint(null);
    } else {
      setSelectedPoint(point);
    }
  };

  const handleProviderClick = (provider: string) => {
    // Toggle selection: if already selected, deselect; otherwise select
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
                    name="Risk Score"
                    label={{
                      value: "Risk Score",
                      position: "bottom",
                      offset: 10,
                      fill: "var(--color-text-neutral-secondary)",
                    }}
                    tick={CustomXAxisTick}
                    tickLine={false}
                    domain={[0, 10]}
                    axisLine={false}
                  />
                  <YAxis
                    type="number"
                    dataKey="y"
                    name="Failed Findings"
                    label={{
                      value: "Failed Findings",
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
                Click to filter by provider.
              </p>
              <CustomLegend
                providers={providers}
                selectedProvider={selectedProvider}
                onProviderClick={handleProviderClick}
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
                  Risk Score: {selectedPoint.x} | Failed Findings:{" "}
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
