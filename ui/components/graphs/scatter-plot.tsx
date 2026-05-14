"use client";

/**
 * ScatterPlot Component
 *
 * A reusable scatter chart component with provider-based coloring,
 * point selection, legend filtering, and optional gradient background.
 *
 * NOTE: This component uses CSS variables (var()) for Recharts styling.
 * Recharts SVG-based components do not support Tailwind classes and require
 * raw color values or CSS variables. This is a documented limitation.
 * @see https://recharts.org/en-US/api
 */

import {
  CartesianGrid,
  ReferenceArea,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { AlertPill } from "./shared/alert-pill";
import { ChartLegend } from "./shared/chart-legend";
import { AXIS_FONT_SIZE, CustomXAxisTick } from "./shared/custom-axis-tick";
import type { ScatterDataPoint } from "./types";

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
  Google: "var(--bg-data-gcp)",
  Default: "var(--color-text-neutral-tertiary)",
};

const SELECTED_COLOR = "var(--bg-button-primary)";

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

interface GradientConfig {
  /** Gradient ID (must be unique if multiple charts on page) */
  id?: string;
  /** Hex color for gradient (CSS variables don't work in SVG defs) */
  color?: string;
  /** Whether gradient goes from bottom (true) or top (false) */
  fromBottom?: boolean;
}

interface AxisConfig {
  /** Axis label */
  label: string;
  /** Data key to use ('x' or 'y') */
  dataKey: "x" | "y";
  /** Fixed domain [min, max] - if not provided, auto-scales */
  domain?: [number, number];
}

export interface ScatterPlotProps<
  T extends ScatterDataPoint = ScatterDataPoint,
> {
  /** Data points to render */
  data: T[];
  /** X-axis configuration */
  xAxis?: AxisConfig;
  /** Y-axis configuration */
  yAxis?: AxisConfig;
  /** Chart height */
  height?: number | string;
  /** Currently selected point */
  selectedPoint?: T | null;
  /** Callback when a point is selected/deselected */
  onSelectPoint?: (point: T | null) => void;
  /** Currently selected provider for filtering */
  selectedProvider?: string | null;
  /** Callback when a provider is selected/deselected in legend */
  onProviderClick?: (provider: string | null) => void;
  /** Whether to show the legend */
  showLegend?: boolean;
  /** Legend helper text */
  legendHelperText?: string;
  /** Gradient background configuration (null to disable) */
  gradient?: GradientConfig | null;
  /** Custom tooltip render function */
  renderTooltip?: (point: T) => React.ReactNode;
}

interface TooltipProps<T extends ScatterDataPoint> {
  active?: boolean;
  payload?: Array<{ payload: T }>;
  renderTooltip?: (point: T) => React.ReactNode;
}

function DefaultTooltip<T extends ScatterDataPoint>({
  active,
  payload,
  renderTooltip,
}: TooltipProps<T>) {
  if (!active || !payload?.length) return null;

  const point = payload[0].payload;

  if (renderTooltip) {
    return <>{renderTooltip(point)}</>;
  }

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
        Score
      </p>
      <div className="mt-2">
        <AlertPill value={point.y} />
      </div>
    </div>
  );
}

// Props that Recharts passes to the shape component
interface RechartsScatterDotProps<T extends ScatterDataPoint> {
  cx: number;
  cy: number;
  payload: T;
}

// Extended props for our custom scatter dot component
interface ScatterDotProps<T extends ScatterDataPoint>
  extends RechartsScatterDotProps<T> {
  selectedPoint: T | null;
  onSelectPoint: (point: T) => void;
  allData: T[];
  selectedProvider: string | null;
}

function CustomScatterDot<T extends ScatterDataPoint>({
  cx,
  cy,
  payload,
  selectedPoint,
  onSelectPoint,
  allData,
  selectedProvider,
}: ScatterDotProps<T>) {
  const isSelected = selectedPoint?.name === payload.name;
  const size = isSelected ? 18 : 8;
  const fill = isSelected
    ? SELECTED_COLOR
    : PROVIDER_COLORS[payload.provider] || PROVIDER_COLORS.Default;
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
            stroke={SELECTED_COLOR}
            strokeWidth={1}
            opacity={0.4}
          />
          <circle
            cx={cx}
            cy={cy}
            r={size / 2 + 8}
            fill="none"
            stroke={SELECTED_COLOR}
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
        stroke={isSelected ? SELECTED_COLOR : "transparent"}
        strokeWidth={2}
      />
    </g>
  );
}

/**
 * Factory function that creates a scatter dot shape component with closure over selection state.
 * Recharts shape prop types the callback parameter as `unknown` due to its flexible API.
 * @see https://recharts.org/en-US/api/Scatter#shape
 */
function createScatterDotShape<T extends ScatterDataPoint>(
  selectedPoint: T | null,
  onSelectPoint: (point: T) => void,
  allData: T[],
  selectedProvider: string | null,
): (props: unknown) => React.JSX.Element {
  const ScatterDotShape = (props: unknown) => (
    <CustomScatterDot<T>
      {...(props as RechartsScatterDotProps<T>)}
      selectedPoint={selectedPoint}
      onSelectPoint={onSelectPoint}
      allData={allData}
      selectedProvider={selectedProvider}
    />
  );
  ScatterDotShape.displayName = "ScatterDotShape";
  return ScatterDotShape;
}

const DEFAULT_GRADIENT: GradientConfig = {
  id: "scatterPlotGradient",
  color: "#7D1A1A",
  fromBottom: true,
};

export function ScatterPlot<T extends ScatterDataPoint = ScatterDataPoint>({
  data,
  xAxis = { label: "Fail Findings", dataKey: "y" },
  yAxis = { label: "Score", dataKey: "x", domain: [0, 100] },
  height = "100%",
  selectedPoint = null,
  onSelectPoint,
  selectedProvider = null,
  onProviderClick,
  showLegend = true,
  legendHelperText = "Click to filter by provider",
  gradient = DEFAULT_GRADIENT,
  renderTooltip,
}: ScatterPlotProps<T>) {
  // Group data by provider for separate Scatter series
  const dataByProvider = data.reduce<Record<string, T[]>>((acc, point) => {
    (acc[point.provider] ??= []).push(point);
    return acc;
  }, {});

  const providers = Object.keys(dataByProvider);

  // ReferenceArea bounds - use very large values and let ifOverflow="hidden" clip to chart area
  // This ensures the gradient always covers exactly the visible chart area regardless of data
  const minX = xAxis.domain?.[0] ?? 0;
  const maxX = xAxis.domain?.[1] ?? Number.MAX_SAFE_INTEGER;
  const minY = yAxis.domain?.[0] ?? 0;
  const maxY = yAxis.domain?.[1] ?? Number.MAX_SAFE_INTEGER;

  const handleSelectPoint = (point: T) => {
    if (onSelectPoint) {
      if (selectedPoint?.name === point.name) {
        onSelectPoint(null);
      } else {
        onSelectPoint(point);
      }
    }
  };

  const handleProviderClick = (provider: string) => {
    if (onProviderClick) {
      onProviderClick(selectedProvider === provider ? null : provider);
    }
  };

  const gradientId = gradient?.id ?? DEFAULT_GRADIENT.id;

  return (
    <div className="flex h-full w-full flex-col">
      <div className="relative min-h-[400px] w-full flex-1">
        <ResponsiveContainer width="100%" height={height}>
          <ScatterChart margin={{ top: 20, right: 30, bottom: 60, left: 60 }}>
            {/* SVG gradient requires hex colors - CSS variables don't resolve properly in SVG defs */}
            <defs>
              {gradient && (
                <linearGradient
                  id={gradientId}
                  x1="0"
                  y1={gradient.fromBottom ? "1" : "0"}
                  x2="0"
                  y2={gradient.fromBottom ? "0" : "1"}
                >
                  <stop
                    offset="0%"
                    stopColor={gradient.color ?? DEFAULT_GRADIENT.color}
                    stopOpacity={0.6}
                  />
                  <stop
                    offset="40%"
                    stopColor={gradient.color ?? DEFAULT_GRADIENT.color}
                    stopOpacity={0.3}
                  />
                  <stop offset="100%" stopColor="transparent" stopOpacity={0} />
                </linearGradient>
              )}
            </defs>
            {gradient && (
              <ReferenceArea
                x1={minX}
                x2={maxX}
                y1={minY}
                y2={maxY}
                fill={`url(#${gradientId})`}
                ifOverflow="hidden"
              />
            )}
            <CartesianGrid
              horizontal={true}
              vertical={true}
              strokeOpacity={1}
              stroke="var(--border-neutral-secondary)"
            />
            <XAxis
              type="number"
              dataKey={xAxis.dataKey}
              name={xAxis.label}
              label={{
                value: xAxis.label,
                position: "bottom",
                offset: 10,
                fill: "var(--color-text-neutral-secondary)",
              }}
              tick={CustomXAxisTick}
              tickLine={false}
              axisLine={false}
              domain={xAxis.domain}
            />
            <YAxis
              type="number"
              dataKey={yAxis.dataKey}
              name={yAxis.label}
              label={{
                value: yAxis.label,
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
              domain={yAxis.domain}
            />
            <Tooltip
              content={<DefaultTooltip<T> renderTooltip={renderTooltip} />}
            />
            {Object.entries(dataByProvider).map(([provider, points]) => (
              <Scatter
                key={provider}
                name={provider}
                data={points}
                fill={PROVIDER_COLORS[provider] || PROVIDER_COLORS.Default}
                shape={createScatterDotShape<T>(
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

      {showLegend && (
        <div className="mt-4 flex flex-col items-start gap-2">
          {legendHelperText && (
            <p className="text-text-neutral-tertiary pl-2 text-xs">
              {legendHelperText}
            </p>
          )}
          <ChartLegend
            items={providers.map((p) => ({
              label: p,
              color: PROVIDER_COLORS[p] || PROVIDER_COLORS.Default,
              dataKey: p,
            }))}
            selectedItem={selectedProvider}
            onItemClick={handleProviderClick}
          />
        </div>
      )}
    </div>
  );
}
