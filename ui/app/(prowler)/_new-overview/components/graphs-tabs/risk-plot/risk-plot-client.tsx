"use client";

import { useState } from "react";
import {
  CartesianGrid,
  Legend,
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
import { getSeverityColorByRiskScore } from "@/components/graphs/shared/utils";
import type { BarDataPoint } from "@/components/graphs/types";

const PROVIDER_COLORS = {
  AWS: "var(--color-bg-data-aws)",
  Azure: "var(--color-bg-data-azure)",
  Google: "var(--color-bg-data-gcp)",
};

export interface ScatterPoint {
  x: number;
  y: number;
  provider: string;
  name: string;
  severityData?: BarDataPoint[];
}

interface RiskPlotClientProps {
  data: ScatterPoint[];
}

interface TooltipProps {
  active?: boolean;
  payload?: Array<{ payload: ScatterPoint }>;
}

interface ScatterDotProps {
  cx: number;
  cy: number;
  payload: ScatterPoint;
  selectedPoint: ScatterPoint | null;
  onSelectPoint: (point: ScatterPoint) => void;
  allData: ScatterPoint[];
}

interface LegendProps {
  payload?: Array<{ value: string; color: string }>;
}

const CustomTooltip = ({ active, payload }: TooltipProps) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    const severityColor = getSeverityColorByRiskScore(data.x);

    return (
      <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary pointer-events-none min-w-[200px] rounded-xl border p-3 shadow-lg">
        <p className="text-text-neutral-primary mb-2 text-sm font-semibold">
          {data.name}
        </p>
        <p className="text-text-neutral-secondary text-sm font-medium">
          {/* Dynamic color from getSeverityColorByRiskScore - required inline style */}
          <span style={{ color: severityColor, fontWeight: "bold" }}>
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
}: ScatterDotProps) => {
  const isSelected = selectedPoint?.name === payload.name;
  const size = isSelected ? 18 : 8;
  const selectedColor = "var(--bg-button-primary)"; // emerald-400
  const fill = isSelected
    ? selectedColor
    : PROVIDER_COLORS[payload.provider as keyof typeof PROVIDER_COLORS] ||
      "var(--color-text-neutral-tertiary)";

  const handleClick = () => {
    const fullDataItem = allData?.find(
      (d: ScatterPoint) => d.name === payload.name,
    );
    onSelectPoint?.(fullDataItem || payload);
  };

  return (
    <g style={{ cursor: "pointer" }} onClick={handleClick}>
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

const CustomLegend = ({ payload }: LegendProps) => {
  const items =
    payload?.map((entry: { value: string; color: string }) => ({
      label: entry.value,
      color: entry.color,
    })) || [];

  return <ChartLegend items={items} />;
};

function createScatterDotShape(
  selectedPoint: ScatterPoint | null,
  onSelectPoint: (point: ScatterPoint) => void,
  allData: ScatterPoint[],
) {
  const ScatterDotShape = (props: unknown) => {
    const dotProps = props as Omit<
      ScatterDotProps,
      "selectedPoint" | "onSelectPoint" | "allData"
    >;
    return (
      <CustomScatterDot
        {...dotProps}
        selectedPoint={selectedPoint}
        onSelectPoint={onSelectPoint}
        allData={allData}
      />
    );
  };
  ScatterDotShape.displayName = "ScatterDotShape";
  return ScatterDotShape;
}

export function RiskPlotClient({ data }: RiskPlotClientProps) {
  const [selectedPoint, setSelectedPoint] = useState<ScatterPoint | null>(null);

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

  const handleSelectPoint = (point: ScatterPoint) => {
    if (selectedPoint?.name === point.name) {
      setSelectedPoint(null);
    } else {
      setSelectedPoint(point);
    }
  };

  return (
    <div className="flex h-full w-full flex-col gap-4">
      <div className="flex flex-1 gap-12">
        {/* Plot Section - in Card */}
        <div className="flex basis-[70%] flex-col">
          <div
            className="flex flex-1 flex-col rounded-lg border p-4"
            style={{
              borderColor: "var(--border-neutral-primary)",
              backgroundColor: "var(--bg-neutral-secondary)",
            }}
          >
            <div className="mb-4">
              <h3
                className="text-lg font-semibold"
                style={{ color: "var(--text-neutral-primary)" }}
              >
                Risk Plot
              </h3>
            </div>

            <div
              className="relative w-full flex-1"
              style={{ minHeight: "400px" }}
            >
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
                  <Legend
                    content={<CustomLegend />}
                    wrapperStyle={{ paddingTop: "40px" }}
                  />
                  {Object.entries(dataByProvider).map(([provider, points]) => (
                    <Scatter
                      key={provider}
                      name={provider}
                      data={points}
                      fill={
                        PROVIDER_COLORS[
                          provider as keyof typeof PROVIDER_COLORS
                        ] || "var(--color-text-neutral-tertiary)"
                      }
                      shape={createScatterDotShape(
                        selectedPoint,
                        handleSelectPoint,
                        data,
                      )}
                    />
                  ))}
                </ScatterChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Details Section - No Card */}
        <div className="flex basis-[30%] flex-col items-center justify-center overflow-hidden">
          {selectedPoint && selectedPoint.severityData ? (
            <div className="flex w-full flex-col">
              <div className="mb-4">
                <h4
                  className="text-base font-semibold"
                  style={{ color: "var(--text-neutral-primary)" }}
                >
                  {selectedPoint.name}
                </h4>
                <p
                  className="text-xs"
                  style={{ color: "var(--text-neutral-tertiary)" }}
                >
                  Risk Score: {selectedPoint.x} | Failed Findings:{" "}
                  {selectedPoint.y}
                </p>
              </div>
              <HorizontalBarChart data={selectedPoint.severityData} />
            </div>
          ) : (
            <div className="flex w-full items-center justify-center text-center">
              <p
                className="text-sm"
                style={{ color: "var(--text-neutral-tertiary)" }}
              >
                Select a point on the plot to view details
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
